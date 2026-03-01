<h1 align="center">SLEEPWALKER</h1>
<p align="center"><b>Windows Kernel Telemetry for High-Signal Threat Triage, Forensics & Malware Analysis</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-C-00599C?logo=c&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/Framework-KMDF-0A0A0A?style=for-the-badge" />
</p>

<p align="center">
  <img src="./diagram/SLEEPWALKER_DIA.png" width="900" />
</p>

## Detections

- Process injection activity, including remote-thread execution patterns.
- Thread hijack behavior (suspend/set-context/resume style intent chains).
- APC-based injection indicators, including remote APC and hijack-adjacent APC patterns.
- Process hollowing mark-chains (medium/strong) and TxF-suspect hollowing chains.
- Direct-syscall abuse indicators versus normal syscall paths.
- Suspicious process/thread handle operations with exact access rights (for example `PROCESS_VM_WRITE`, `PROCESS_CREATE_THREAD`, `THREAD_SET_CONTEXT`).
- Memory abuse patterns such as alloc/write/protect sequences and writable-to-executable transitions.
- Thread start addresses outside expected image ranges or in non-image executable regions.
- Suspicious `ntdll` image path/mapping anomalies.
- High-value registry activity tied to persistence/evasion surfaces.
- Driver dispatch/object tamper drift and tamper-clear transitions.

## Detection Preview

```ps1
[HANDLE] DIRECT-SYSCALL-SUSPECT  0000000000002978 -> 0000000000001088  access=0x00001032 (CREATE_THREAD|VM_READ|VM_WRITE|QUERY_LIMITED_INFO)
Meta   event=HandleTelemetry pid=4 tid=5192 cpu=5 lvl=4 op=0 ver=0 ts=0x01DCA7C573BE0D3D dt=0x14
Actor  callerImage=R:\.NIGHTDAY\TTK\DirectSyscallTest.exe
       targetImage=\Device\HarddiskVolume5\.NIGHTDAY\TTK\DirectSyscallTest.exe
Origin addr=0x00007FF6DF2DF1DA (DirectSyscallTest.exe)
       path=\Device\HarddiskVolume5\.NIGHTDAY\TTK\DirectSyscallTest.exe
       protect=0x00000040 (XRW) exec=1 fromNtdll=0 fromExe=1
Status open=SUCCESS(0x00000000) basic=SUCCESS(0x00000000) section=SUCCESS(0x00000000)
Deep   allocBase=0x00007FF6DF2C0000 regionSize=0x1000 protect=0x00000040 (XRW) state=COMMIT type=IMAGE
       backing=image committed=1 privateCommit=0 imageCommit=1 mappedCommit=0
       sampleSize=64 entropy=0.691 opcodes=04 75 42 63 D7 1D 00 00 00 00 00 00 00 00 00 00 ...
Stack  frames=8
       #0 0x00007FF6DF2DF1DA (DirectSyscallTest.exe)
       #1 0x00007FF6DF2D2C91 (DirectSyscallTest.exe)
       #2 0x00007FF6DF2D3A09 (DirectSyscallTest.exe)
       #3 0x00007FF6DF2D38B2 (DirectSyscallTest.exe)
       #4 0x00007FF6DF2D376E (DirectSyscallTest.exe)
       #5 0x00007FF6DF2D3A9E (DirectSyscallTest.exe)
       #6 0x00007FFDF6F87374 (KERNEL32!BaseThreadInitThunk+0x14)
       #7 0x00007FFDF745CC91 (ntdll!RtlUserThreadStart+0x21)
Alert  direct-syscall-suspect classification observed
```

```ps1
[HANDLE] LEGITIMATE-SYSCALL  0000000000002978 -> 0000000000001088  access=0x00001000 (QUERY_LIMITED_INFO)
Meta   event=HandleTelemetry pid=4 tid=5192 cpu=5 lvl=4 op=0 ver=0 ts=0x01DCA7C573BE1898 dt=0xB5B
Actor  callerImage=R:\.NIGHTDAY\TTK\DirectSyscallTest.exe
       targetImage=\Device\HarddiskVolume5\.NIGHTDAY\TTK\DirectSyscallTest.exe
Origin addr=0x00007FFDF74ADD24 (ntdll!NtDuplicateObject+0x14)
       path=\Device\HarddiskVolume3\Windows\System32\ntdll.dll
       protect=0x00000020 (XR) exec=1 fromNtdll=1 fromExe=0
Status open=SUCCESS(0x00000000) basic=SUCCESS(0x00000000) section=SUCCESS(0x00000000)
Deep   allocBase=0x00007FFDF7410000 regionSize=0x80000 protect=0x00000020 (XR) state=COMMIT type=IMAGE
       backing=image committed=1 privateCommit=0 imageCommit=1 mappedCommit=0
       sampleSize=0 entropy=0.000 opcodes=<none>
Stack  frames=8
       #0 0x00007FFDF74ADD24 (ntdll!NtDuplicateObject+0x14)
       #1 0x00007FFDF746F4EE (ntdll!RtlReportSilentProcessExit+0xDE)
       #2 0x00007FFDF4D2E2AF (KERNELBASE!TerminateProcess+0x1F)
       #3 0x00007FF6DF2D2D60 (DirectSyscallTest.exe)
       #4 0x00007FF6DF2D3A09 (DirectSyscallTest.exe)
       #5 0x00007FF6DF2D38B2 (DirectSyscallTest.exe)
       #6 0x00007FF6DF2D376E (DirectSyscallTest.exe)
       #7 0x00007FF6DF2D3A9E (DirectSyscallTest.exe)
```

---

## Platform Summary

Sleepwalker is a KMDF kernel telemetry driver plus a user-mode service/client stack for process-scoped monitoring and correlated detection.

It captures low-level events (handle, thread, process, image, registry, APC, optional TI API-call surface), then emits detections with severity and reason strings over IOCTL and ETW.

## What Sleepwalker Detects

### Injection and Hollowing Correlation

Kernel detections:
- `REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT`
- `REMOTE_THREAD_START_IN_NON_IMAGE_EXECUTABLE_REGION`
- `REMOTE_THREAD_OUTSIDE_MAIN_IMAGE`
- `THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT`
- `THREAD_HIJACK_INTENT`
- `REMOTE_APC_CREATION_SUSPECT`
- `POSSIBLE_PROCESS_HOLLOWING_OR_INJECTION_INTENT_CHAIN`
- `POSSIBLE_MANUAL_MAP_OR_HOLLOWING_EXECUTION`
- `KERNEL_PROCESS_HOLLOWING_MARK_CHAIN_MEDIUM`
- `KERNEL_PROCESS_HOLLOWING_MARK_CHAIN_STRONG`

Controller synthetic detections (ETW/TI-assisted mark-chain):
- `PROCESS_HOLLOWING_MARK_CHAIN_MEDIUM`
- `PROCESS_HOLLOWING_MARK_CHAIN_STRONG`
- `PROCESS_HOLLOWING_TXF_SUSPECT_CHAIN`

### Direct-Syscall and Stack Integrity

- `DIRECT_SYSCALL_SUSPECT_HANDLE_OPERATION`
- `STACK_INTEGRITY_ANOMALY_ON_HANDLE_OP`
- `SUSPICIOUS_NTDLL_IMAGE_PATH`
- `MULTIPLE_NTDLL_IMAGE_MAPPINGS`

### Registry and Tamper Surface

- `HIGH_VALUE_REGISTRY_ACTIVITY`
- `DRIVER_DISPATCH_OR_OBJECT_TAMPER`
- `DRIVER_DISPATCH_OR_OBJECT_TAMPER_CLEARED`

## Telemetry It Emits

Raw telemetry families:
- `HandleTelemetry` with access masks, origin address/module, memory protections, deep sample metadata, and stack frames
- `ThreadTelemetry` with creator PID, start address, image-range checks, correlation flags, and stack frames
- `ProcessTelemetry`
- `ImageTelemetry`
- `RegistryTelemetry`
- `ApcTelemetry`
- `DetectionTelemetry`

Optional TI task categories (when provider access is available through the controller):
- `ALLOCVM`
- `WRITEVM`
- `PROTECTVM`
- syscall usage metadata from TI task records

## Detection Model

1. Monitors emit intent/signal marks from handle, thread, APC, image, registry, and memory-surface events.
2. Correlation layers combine those marks into detections with stronger confidence.
3. Output is available through:
   - IOCTL queues (`\\.\Global\SleepwalkerCtl`) for per-client targeted pull
   - ETW provider `Sleepwalker.Kernel` for scalable streaming

---

## Interfaces

### Shared User-Mode SDK

Preferred integration surface for user-mode consumers:
- `user/sensor/sleepwalker_sensor_core.h`
- `SleepwalkerSensorCore.dll`

Exports:
- `SLEEPWALKERSCOpenControlDevice`
- `SLEEPWALKERSCSubscribe`
- `SLEEPWALKERSCUnsubscribe`
- `SLEEPWALKERSCSetPids`
- `SLEEPWALKERSCGetEvent`
- `SLEEPWALKERSCGetStats`
- `SLEEPWALKERSCQueryProcessImagePath`
- `SLEEPWALKERSCSetShutdownMode`
- `SLEEPWALKERSCParseStreamMaskA`
- `SLEEPWALKERSCStopSessionByName`
- `SLEEPWALKERSCStartEtwSession`
- `SLEEPWALKERSCStartSleepwalkerEtwSession`
- `SwkStartDetectionEtwSession`
- `SLEEPWALKERSCRunEtwSession`
- `SLEEPWALKERSCStopEtwSession`

Typed detection callback surface:
- `SwkDetectionEvent`
- `SwkDetectionCallback`

### Device Endpoints
- Preferred: `\\.\Global\SleepwalkerCtl`
- Legacy: `\\.\SleepwalkerCtl`

### IOCTL Model (Targeted Pull)
- Subscribe per client handle (PID + stream mask)
- Poll `GET_EVENT` until queue is empty (`NO_MORE_ENTRIES`)
- Query health via `GET_STATS`

### ETW Model (Scalable Push)
- Provider: `Sleepwalker.Kernel`
- GUID: `{D6C73F8A-6AD8-4F4B-A363-3D2FA31CD0E2}`
- Event families: `HandleTelemetry`, `ThreadTelemetry`, `ProcessTelemetry`, `ImageTelemetry`, `RegistryTelemetry`, `ApcTelemetry`, `DetectionTelemetry`

(Full contract in `API.md` and `abi/sleepwalker_ioctl.h`.)

---

## Validation and Test Coverage

`SleepwalkerTestSuite` performs end-to-end verification:
- IOCTL subscription + event delivery
- Handle/thread intent correlation flags
- Multi-client parallel fanout
- ETW ingestion coverage across core event families
- Per-check timing/cycle telemetry for incident-grade run profiling

Default suite mode reflects architecture boundaries:
- Kernel correlation-dependent checks are optional (reported as skip by default)
- APC ETW coverage is optional (reported as skip by default)
- Strict modes are available through `SLEEPWALKER_TEST_REQUIRE_KERNEL_CORRELATION=1` and `SLEEPWALKER_TEST_REQUIRE_APC=1`

Example successful run:
- `[OK] SleepwalkerTestSuite complete. tests-passed=X/Y tests-failed=0 tests-skipped=S polls=Z`

---

## Security and Scope

- Control device ACL restricted to **SYSTEM** and **Administrators**
- IOCTL control path rejects non-user-mode requestors
- Sleepwalker is **telemetry + detection aid**, not a prevention platform
- Symbol enrichment depends on symbol availability and environment policy

---

## Repository Layout

- `kernel/`
  - `core/`: driver lifecycle and IOCTL control plane
  - `monitors/`: handle/thread/process/image/registry monitoring and correlation
  - `telemetry/`: ETW provider emission
- `abi/`
  - `sleepwalker_ioctl.h`: shared IOCTL ABI contract
  - `sleepwalker_ipc.h`: service/client IPC ABI contract
- `user/sensor/`
  - `sleepwalker_sensor_core.c/.h`: shared user-mode SDK (IOCTL + ETW session helpers)
  - `SleepwalkerClient`: manual subscriber (broker-first; optional ETW uplink output)
  - `SleepwalkerTestSuite`: end-to-end validation
- `user/controller/`
  - `sleepwalker_controller.c`: Session 0 broker service (single driver handle + ETW TI session + IPC)
- `vcxproj/`
  - `SleepwalkerSensorCore.vcxproj`: shared user-mode DLL project
  - `SleepwalkerController.vcxproj`: controller service executable

---

## Build and Run (Lab / VM)

1. Open `Sleepwalker.slnx` in Visual Studio.
2. Build `vcxproj/Sleepwalker.vcxproj` (`x64`).
3. Install and start the driver.
4. Install/start `SleepwlkrController` (recommended) via `usage/install-controller-service.ps1`.
5. Run:
   - `SleepwalkerSensorCore.dll` (built automatically by dependent projects)
   - `SleepwalkerTestSuite.exe` for full validation
   - `SleepwalkerClient.exe <pid> handle,memory,thread` for targeted IOCTL capture
   - `SleepwalkerClient.exe <pid> handle,memory,thread,etw` to include broker ETW uplink output

Documentation:
- `INSTALL.md` (install/runtime workflow)
- `API.md` (IOCTL + ETW contract)
- `USAGE.md` (practical usage guide + examples)
- `user/sensor/README.md` (tooling details)
