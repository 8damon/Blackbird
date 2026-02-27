# Usage Guide

This document is a practical, task-oriented guide for using Sleepwalker in labs/VMs.

## Output Examples

Representative operator/test outputs:

```ps1
[IOCTL][EVENT] seq=4 type=HANDLE stream=0x00000003(HANDLE|MEMORY) size=768 qpc=3404675185
[IOCTL][HANDLE] class=UNKNOWN(0) caller=6948 target=6948 access=0x001FFFFF
Flags  ExecProtect FromNtdll MemoryRelated ThreadObject
Path   \Device\HarddiskVolume3\Windows\System32\ntdll.dll
Mem    protect=0x00000020
Origin 0x7FFDF74AEDD4 ntdll!NtCreateThreadEx+0x14
Status open=0x00000000 basic=0x00000000 section=0x00000000
Stack  frames=8
       #0 0x7FFDF74AEDD4 ntdll!NtCreateThreadEx+0x14
       #1 0x7FFDF4CD506F KERNELBASE!CreateRemoteThreadEx+0x29F
       #2 0x7FFDF6F8B91D KERNEL32!CreateThread+0x3D
       #3 0x7FF7AC3750A4 SleepwalkerTestSuite+0x150A4
       #4 0x7FF7AC37BEC9 SleepwalkerTestSuite+0x1BEC9
       #5 0x7FF7AC37E3F9 SleepwalkerTestSuite+0x1E3F9
       #6 0x7FF7AC37E2A2 SleepwalkerTestSuite+0x1E2A2
       #7 0x7FF7AC37E15E SleepwalkerTestSuite+0x1E15E
```

```ps1
[INFO] suiteTiming elapsedMs=1944.390 polls=17
[OK] SleepwalkerTestSuite complete. tests-passed=48/48 tests-failed=0 tests-skipped=13 polls=17
```

Contents:

- See `usage/README.md` for example workflows and code snippets.

Quick Start (IOCTL)

1. Install and start the driver.
2. Open the control device (`\\.\Global\SleepwalkerCtl`).
3. Subscribe to a PID and stream mask.
4. Poll for events until the queue is empty.
5. Unsubscribe and close.

Quick Start (ETW)

1. Start a real-time session for `Sleepwalker.Kernel`.
2. Enable the provider.
3. Consume events via `ProcessTrace`.
4. Stop the session and clean up.

Preferred Integration Surface

Use the shared SDK in `user/sensor/sleepwalker_sensor_core.h` and link against `SleepwalkerSensorCore.dll`:

- `SLEEPWALKERSCOpenControlDevice`
- `SLEEPWALKERSCSubscribe`
- `SLEEPWALKERSCUnsubscribe`
- `SLEEPWALKERSCSetPids`
- `SLEEPWALKERSCGetEvent`
- `SLEEPWALKERSCGetStats`
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
