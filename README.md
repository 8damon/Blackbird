<h1 align="center">SLEEPWALKER</h1>
<p align="center"><b>Windows Kernel Telemetry for High-Signal Threat Triage, Forensics & Malware Analysis</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-C-00599C?logo=c&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/Framework-KMDF-0A0A0A?style=for-the-badge" />
</p>

<p align="center">
  <img src="./diagram/SLEEPWALKER_DIA.png" width="900" />
</p>

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

## Executive Summary

**Sleepwalker is a KMDF kernel telemetry driver + user-mode tooling that exposes high-value execution signals commonly associated with injection and post-exploitation.**  
It is designed for **triage, forensics, malware analysis, and threat emulation in labs/VMs** where teams need kernel-level visibility **without deploying a full EDR stack or attaching a kernel debugger**.

Sleepwalker provides:
- **High-signal telemetry**
- **Correlation**
- **Two consumption paths**:
  - **IOCTL per-client queues** for targeted, process-scoped capture
  - **ETW provider (`Sleepwalker.Kernel`)** for scalable ingestion and tooling

---

## What Gap It Covers

In many environments, teams end up choosing between:

1) **Generic telemetry** (high volume, hard to operationalize quickly), or  
2) **EDR detections** (high level, but hides the low-level context needed to validate intent)

**Sleepwalker bridges that gap** by emitting telemetry that is:
- Low-level enough to preserve forensic context (access masks, addresses, call stacks, outcomes)
- Structured and testable (stable ABI, deterministic records, validation suite)
- Focused on a narrow, high-signal threat surface (injection-adjacent behavior)

> Sleepwalker is not a replacement for an EDR.  
> It’s an **inspectable kernel telemetry plane** suitable for labs/VMs/IR triage and engineering workflows.

---

## What Questions Sleepwalker Answers

- Which process opened another process/thread, with **what access rights**, and **from where**?
- Did a thread appear to be created remotely, and does its **start address** look suspicious relative to loaded image boundaries?
- Was there **recent intent** (process memory / thread context / duplicate handle activity) before thread execution?
- Was high-value persistence-oriented **registry activity** observed in the same run?
- What **correlated detections** can be produced when intent and execution line up?

---

## Core Signals (High Value Surface)

Sleepwalker focuses on behavior commonly observed in:
- Direct-syscalls
- Syscall monitoring
- Process injection workflows
- Post-exploitation handle acquisition
- Remote thread creation + suspicious start regions
- Persistence-oriented registry activity

**Telemetry families:**
- Handle operations (process/thread handles, access masks, origin metadata)
- Thread execution (remote creator, start-address heuristics, execution-region context)
- Process lifecycle context
- Image load context
- High-value registry activity
- Correlated detection events (intent -> execution)

---

## Technical Highlights (for engineers)

- **KMDF control plane** with per-handle client contexts and independent event queues
- **Stable ABI header** (`abi/sleepwalker_ioctl.h`) defining IOCTL codes + record layouts
- **Per-client subscription model**: PID + stream mask
- **Per-client sequencing + bounded queues** with drop accounting and rate-limited drop logging
- **Multi-client fanout** validated under parallel polling (`SleepwalkerTestSuite`)
- Dual output plane:
  - **IOCTL**: low-latency, targeted pull model
  - **ETW**: scalable push model for broader pipelines

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
- Event families: `HandleTelemetry`, `ThreadTelemetry`, `ProcessTelemetry`, `ImageTelemetry`, `RegistryTelemetry`, `DetectionTelemetry`

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
- Strict modes are available through:
- `SLEEPWALKER_TEST_REQUIRE_KERNEL_CORRELATION=1`
- `SLEEPWALKER_TEST_REQUIRE_APC=1`

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
  - `SleepwalkerClient`: manual IOCTL subscriber
  - `SleepwalkerTestSuite`: end-to-end validation
- `user/controller/`
  - `sleepwalker_controller.c`: Session 0 broker service (single driver handle + ETW TI session + IPC)
- `vcxproj/`
  - `SleepwalkerSensorCore.vcxproj`: shared user-mode DLL project
  - `SleepwalkerController.vcxproj`: controller service executable

---

## Build and Run (Lab / VM)

1. Open `Sleepwalker.slnx` in Visual Studio.
2. Build `vcxproj/Sleepwalker.vcxproj` (`x64` or `ARM64`).
3. Install and start the driver.
4. Install/start `SleepwlkrController` (recommended) via `usage/install-controller-service.ps1`.
5. Run:
   - `SleepwalkerSensorCore.dll` (built automatically by dependent projects)
   - `SleepwalkerTestSuite.exe` for full validation
   - `SleepwalkerClient.exe <pid> handle,memory,thread` for targeted IOCTL capture

Documentation:
- `INSTALL.md` (install/runtime workflow)
- `API.md` (IOCTL + ETW contract)
- `USAGE.md` (practical usage guide + examples)
- `user/sensor/README.md` (tooling details)
