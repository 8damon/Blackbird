<h1 align="center">BLACKBIRD</h1>
<p align="center"><b>EDR-class kernel sensor and analyst platform for single-target Windows process instrumentation</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/-00599C?logo=c&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/-00599C?logo=c%2B%2B&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/.NET-512BD4?style=for-the-badge" />
  <img src="https://img.shields.io/badge/KMDF-000000?style=for-the-badge" />
  <a href="https://discord.gg/yUWyvT9JyP">
    <img src="https://img.shields.io/discord/1240608336005828668?label=TITAN%20Softworks&logo=discord&color=5865F2&style=for-the-badge" />
  </a>
</p>

<p align="center">
  <img src="./media/MAIN_INTERFACE.png" width="980" alt="Blackbird main interface" />
</p>

# [BLACKBIRD](https://titansoftwork.com/capability/blackbird/)

Blackbird is a signed KMDF kernel driver and analyst platform that instruments a target process with EDR-class depth: eight OS notification callback types, a WFP network callout, real-time ETW streaming, and an injected hook DLL covering NT API, Winsock, and exception dispatch — running as three independent telemetry paths with kernel-side trampoline integrity verification.

It is not a sandbox or an ETW wrapper. Blackbird operates at the same instrumentation layer as commercial EDR products — kernel callbacks, per-client IOCTL queues, in-kernel correlation, process execution control, and kernel-enforced process protection — but targets a single process or small process set for deep behavioral analysis rather than fleet-wide endpoint coverage. There is no response component, no cloud telemetry, and no automated remediation. All signal goes directly to the analyst.

---

## ARCHITECTURE

Blackbird is composed of six binaries across the kernel and user-mode layers:

| Binary | Layer | Role |
|---|---|---|
| `blackbird.sys` | Kernel | Signed KMDF driver. Root of trust. OS callbacks, IOCTL surface, per-client event queues, process control, process protection, hook integrity verification, hollowing detection engine. |
| `BlackbirdController.exe` | User-mode | IPC broker. ETW consumer. Hook injection host. Launch gate. Multi-source event correlation. |
| `SR71.dll` | User-mode (injected) | Hook DLL injected into target. NT API, Winsock, KiUserExceptionDispatcher, and module hooks. Launch gate runtime. Integrity watchdog. |
| `J58.dll` | User-mode | Shared IOCTL/ETW sensor library used by controller, test harness, and tooling. |
| `BlackbirdInterface.exe` | User-mode | WPF analyst workstation. Unified event surface, time-travel controls, YARA/SignatureIntel scanning, session export. |
| `BlackbirdOperator.exe` | User-mode | Optional. Multi-node remote orchestration with AES-256-GCM + ECDH + ECDSA transport. |

### Kernel Driver (`blackbird.sys`)

The driver registers eight OS notification callback types and a WFP callout, maintaining a per-client circular event queue (1024 depth) across up to 256 concurrent subscribers:

- `PsSetCreateProcessNotifyRoutineEx` — process create/terminate, launch-bootstrap PID ring
- `PsSetCreateThreadNotifyRoutine` — thread create/terminate, creator/start address
- `ObRegisterCallbacks` — handle open, duplicate, query; access mask; caller stack
- `PsSetLoadImageNotifyRoutine` — image load, module base, path, hash
- FltMgr minifilter — file create/read/write/rename/delete
- `CmRegisterCallback` — registry key/value create, delete, rename, set
- Kernel APC callbacks — APCs queued against foreign threads
- WFP callout (`FwpmCalloutAdd`) — inbound/outbound connect, send, recv

Beyond telemetry, the driver exposes 15 IOCTL codes covering subscription management, process execution control (suspend/resume any PID), kernel-enforced process protection (DACL on controller and interface processes), hook page registration for trampoline integrity verification, and runtime configuration: self-hide, anti-virtualization, network sinkhole/quarantine, and NTAPI hooks disarm.

An in-kernel intent store and process hollowing detection engine correlate event sequences without relying on user-mode components.

### Three Telemetry Paths

Kernel IOCTL, ETW, and hook telemetry operate independently — a failure or evasion in any one path does not blind the sensor:

- **Path A (kernel → interface):** Direct IOCTL poll of `GET_EVENT`. Authoritative.
- **Path B (kernel + ETW → controller → interface):** Controller merges IOCTL-sourced, ETW-sourced, and hook-sourced events into a unified correlated ring delivered over `\\.\pipe\BlackbirdController`.
- **Path C (SR71.dll → controller):** Hook DLL publishes structured records to `\\.\pipe\BlackbirdHookIngest` on every intercepted call; controller classifies caller origin and merges into the broker stream.

### Hook Library (`SR71.dll`)

SR71.dll is injected into the target process and installs hooks on:

- `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory` — memory operations
- `NtCreateThreadEx`, `NtQueueApcThread` — remote thread and APC injection
- `NtOpenProcess` — sensitive process access
- `connect`, `send`, `recv` (Winsock) — network activity
- `KiUserExceptionDispatcher` — exception chain interception
- Module load/unlink — image-backed integrity tracking

Each hook reports: caller address, resolved module, SSN (direct syscall number if applicable), stack frames (up to 8), and a 64-byte memory sample at the call site. The kernel verifies hook trampoline bytes via `REGISTER_HOOK_PAGES` — hook reports are advisory, kernel telemetry is authoritative.

The launch gate (v1.9) arms a deferred-entry page before the target's first user-mode instruction, enabling pre-execution control and deferred open via `ARM_PENDING_LAUNCH`.

---

## OPERATOR PANEL

The analyst interface consolidates all telemetry into one shell:

- Events & event log (with grouped event compaction)
- ETW feed
- Heuristics and detection lanes
- Filesystem events
- Process relations
- API call graph with hook origin validation
- Performance counters and Tempus timing breakdown
- Network observation
- Thread observation
- Memory observation, inspector (floating) & treemap
- Module and PE information
- Uplink / IPC diagnostics
- Child process graph
- SignatureIntel / YARA scanning

---

## EVIDENCE & INSPECTOR VIEWS

Double-clicking grouped detections opens dedicated inspector windows:

- **ETW Inspector** — grouped ETW occurrences with enriched detail fields
- **Handle Evidence** — handle activity, access masks, origin context, stack frames, memory region metadata
- **Thread Stack** — register state, resolved stack frames; live and historical snapshot modes
- **Process Relations** — actor-to-target relationships: handle opens, remote threads, injection intent chains
- **Detection Chain** — correlated detection evidence grouped by event key and detection key
- **Direct Syscall Suspects** — per-syscall drill-down with call-site disassembly
- **Memory Inspector** — memory region inspection for flagged allocations (v1.9)
- **Child Process Graph** — process DAG visualization for spawn and injection trees
- **Parallel Stacks** — multi-thread stack comparison

---

## DETECTION COVERAGE

Representative detections:

- Direct syscalls (SSN-based origin detection outside `ntdll.exe` export range)
- Handle open, memory query, cross-process read/write
- RWX allocation, W→X protection flip
- Manual mapping and unbacked executable regions
- AMSI/ETW patch detection
- Hook trampoline integrity violations
- Remote thread creation, remote APC queuing
- Thread hijack and thread-context abuse
- Process hollowing and injection intent chains
- Suspicious `ntdll` image path or multiple `ntdll` mappings
- File drop, open, create, read, special attribute operations
- Registry activity (key/value create, delete, rename, set)
- Stack integrity anomalies (non-image-backed return addresses)

---

## DOCUMENTATION

- [Blackbird Docs](https://docs.titansoftwork.com/blackbird/)

Repository docs:

- [SECURITY.md](./SECURITY.md) — security policy and disclosure process
- [API.md](./API.md) — ABI reference bridge and source file pointers
- [UserMode/sensor/README.md](./UserMode/sensor/README.md) — sensor component notes
- [UserMode/controller/core/README.md](./UserMode/controller/core/README.md) — controller core notes

Session archives are stored as `.bkcap` (SQLite + LZ4). Detection reference scenarios are in `DetectionExamples.exe`.

<p align="center">
  <img src="./media/BLACKBIRD_DIAGRAM.png" width="980" alt="Blackbird platform diagram" />
</p>
