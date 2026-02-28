# Sleepwalker API Guide

This document describes the current Sleepwalker control-plane and telemetry contract for engineers, detection content authors, and integrators.

## Telemetry Contract Visual

<p align="center">
  <img src="./diagram/Sleepwalker_KM_Telemetry_Arch.png" width="900" />
</p>

## IOCTL Record Example

<p align="center">
  <img src="./diagram/IOCTL_EVENT_HANDLE.png" width="900" />
</p>

## Revision and Scope

- Document revision: `2026-02-27`
- ABI source of truth: `abi/sleepwalker_ioctl.h`
- Compatibility note: no explicit in-band ABI version field is currently exposed; pin integration by commit/date and validate with `SleepwalkerTestSuite`.

## At a Glance

- Control device:
  - NT: `\Device\SleepwalkerCtl`
  - DOS: `\\.\Global\SleepwalkerCtl` (preferred), `\\.\SleepwalkerCtl` (legacy)
- IOCTL operations:
  - subscribe
  - unsubscribe
  - get event
  - get stats
  - set pids
  - query process image
  - set shutdown mode
- IOCTL event families:
  - handle
  - thread
- Shared user-mode SDK:
  - `SleepwalkerSensorCore.dll` / `user/sensor/sleepwalker_sensor_core.h`
  - exported `SLEEPWALKERSC*` APIs for IOCTL and ETW session management
  - typed `Swk*` detection callback surface for ETW detection events
- ETW provider:
  - name: `Sleepwalker.Kernel`
  - GUID: `{D6C73F8A-6AD8-4F4B-A363-3D2FA31CD0E2}`

## Shared User-Mode SDK (`SleepwalkerSensorCore`)

The preferred integration surface for user-mode consumers is:

- header: `user/sensor/sleepwalker_sensor_core.h`
- binary: `SleepwalkerSensorCore.dll`

Current exports:

- Protocol selection helpers:
  - `SLEEPWALKERSCUseServiceProtocol`
  - `SLEEPWALKERSCUseClientProtocol`
  - `SLEEPWALKERSCGetProtocolMode`
- IOCTL control-plane wrappers:
  - `SLEEPWALKERSCOpenControlDevice`
  - `SLEEPWALKERSCSubscribe`
  - `SLEEPWALKERSCUnsubscribe`
  - `SLEEPWALKERSCSetPids`
  - `SLEEPWALKERSCGetEvent`
  - `SLEEPWALKERSCGetStats`
  - `SLEEPWALKERSCQueryProcessImagePath`
  - `SLEEPWALKERSCSetShutdownMode`
  - `SLEEPWALKERSCParseStreamMaskA`
- ETW session wrappers:
  - `SLEEPWALKERSCStopSessionByName`
  - `SLEEPWALKERSCStartEtwSession`
  - `SLEEPWALKERSCStartSleepwalkerEtwSession`
  - `SwkStartDetectionEtwSession`
  - `SLEEPWALKERSCRunEtwSession`
  - `SLEEPWALKERSCStopEtwSession`
- Typed detection callback types:
  - `SwkDetectionEvent`
  - `SwkDetectionCallback`

Consumers currently using these exports:

- `SleepwalkerClient`
- `SleepwalkerTestSuite`
- `SleepwlkrController`

## IOCTL Interface

### Request/Response Matrix

- `IOCTL_SLEEPWALKER_SUBSCRIBE`
  - In: `SLEEPWALKER_SUBSCRIBE_REQUEST`
  - Out: none
- `IOCTL_SLEEPWALKER_UNSUBSCRIBE`
  - In: `SLEEPWALKER_UNSUBSCRIBE_REQUEST`
  - Out: none
- `IOCTL_SLEEPWALKER_GET_EVENT`
  - In: none
  - Out: `SLEEPWALKER_EVENT_RECORD`
- `IOCTL_SLEEPWALKER_GET_STATS`
  - In: none
  - Out: `SLEEPWALKER_STATS_RESPONSE`
- `IOCTL_SLEEPWALKER_SET_PIDS`
  - In: `SLEEPWALKER_SET_PIDS_REQUEST`
  - Out: none
- `IOCTL_SLEEPWALKER_QUERY_PROCESS_IMAGE`
  - In: `SLEEPWALKER_QUERY_PROCESS_IMAGE_REQUEST`
  - Out: `SLEEPWALKER_QUERY_PROCESS_IMAGE_RESPONSE`
- `IOCTL_SLEEPWALKER_SET_SHUTDOWN_MODE`
  - In: none
  - Out: none

### Stream Flags

- `SLEEPWALKER_STREAM_HANDLE`
- `SLEEPWALKER_STREAM_MEMORY`
- `SLEEPWALKER_STREAM_THREAD`

`StreamMask` is bitwise-composable.

## Subscription and Delivery Semantics

- Subscriptions are scoped to each opened file handle to the control device.
- One client can subscribe multiple `(ProcessId, StreamMask)` entries.
- Current limits:
  - max subscriptions per client: `64`
  - max queue depth per client: `1024`
  - max concurrent clients: `256`
- Each client has isolated:
  - subscription table
  - FIFO event queue
  - sequence counter
  - dropped-event counter

### Routing Rules

- Handle events route on `(CallerPid OR TargetPid)` + stream-mask intersection.
- Thread events route on `(ProcessId OR CreatorPid)` + stream-mask intersection.
- Per-client dedupe guarantees at most one queued copy of a given emitted record.

## Event Record Structure

`SLEEPWALKER_EVENT_RECORD` contains:

- `SLEEPWALKER_EVENT_HEADER`
  - `Size`
  - `Type`
  - `StreamMask`
  - `Sequence` (per-client monotonic)
  - `TimestampQpc`
- Union payload:
  - `SLEEPWALKER_HANDLE_EVENT`
  - `SLEEPWALKER_THREAD_EVENT`

Event type values:

- `SleepwalkerEventTypeHandle`
- `SleepwalkerEventTypeThread`

## Handle Event Contract

`SLEEPWALKER_HANDLE_EVENT` fields:

- `CallerPid`, `TargetPid`
- `DesiredAccess`
- `ClassId` (`SLEEPWALKER_HANDLE_CLASS`)
- `OriginAddress`, `OriginProtect`, `OriginPath`
- `StatusOpenProcess`, `StatusBasicInfo`, `StatusSectionName`
- Deep-path capture metadata:
  - `DeepAllocationBase`
  - `DeepRegionSize`
  - `DeepRegionProtect`
  - `DeepRegionState`
  - `DeepRegionType`
  - `DeepSampleSize`
  - `DeepSample[SLEEPWALKER_MAX_DEEP_SAMPLE_BYTES]`
- `FrameCount`, `Frames[SLEEPWALKER_MAX_EVENT_FRAMES]`

### Handle Classes

- `SleepwalkerHandleClassUnknown`
- `SleepwalkerHandleClassLegitimateSyscall`
- `SleepwalkerHandleClassDirectSyscallSuspect`

### Handle Flags

- `SLEEPWALKER_HANDLE_FLAG_EXEC_PROTECT`
- `SLEEPWALKER_HANDLE_FLAG_FROM_NTDLL`
- `SLEEPWALKER_HANDLE_FLAG_FROM_EXE`
- `SLEEPWALKER_HANDLE_FLAG_MEMORY_RELATED`
- `SLEEPWALKER_HANDLE_FLAG_THREAD_OBJECT`
- `SLEEPWALKER_HANDLE_FLAG_DUPLICATE_OPERATION`
- `SLEEPWALKER_HANDLE_FLAG_DEEP_PATH_CANDIDATE`
- `SLEEPWALKER_HANDLE_FLAG_DEEP_PATH_CAPTURED`
- `SLEEPWALKER_HANDLE_FLAG_DEEP_PATH_CACHE_HIT`

## Thread Event Contract

`SLEEPWALKER_THREAD_EVENT` fields:

- `ProcessId`, `ThreadId`, `CreatorPid`
- `StartAddress`
- `ImageBase`, `ImageSize`
- `Flags`
- `FrameCount`, `Frames[SLEEPWALKER_MAX_EVENT_FRAMES]`

### Thread Flags

- `SLEEPWALKER_THREAD_FLAG_GOT_START`
- `SLEEPWALKER_THREAD_FLAG_GOT_RANGE`
- `SLEEPWALKER_THREAD_FLAG_REMOTE_CREATOR`
- `SLEEPWALKER_THREAD_FLAG_OUTSIDE_MAIN_IMG`
- `SLEEPWALKER_THREAD_FLAG_CORRELATED_INTENT`
- `SLEEPWALKER_THREAD_FLAG_CORR_MEMORY`
- `SLEEPWALKER_THREAD_FLAG_CORR_THREAD_CTX`
- `SLEEPWALKER_THREAD_FLAG_CORR_DUP_HANDLE`
- `SLEEPWALKER_THREAD_FLAG_START_REGION_EXEC`

## Stats Contract

`SLEEPWALKER_STATS_RESPONSE`:

- `SubscriptionCount`
- `QueueDepth`
- `DroppedEvents`
- `Reserved`

## ETW Contract

Provider:

- Name: `Sleepwalker.Kernel`
- GUID: `{D6C73F8A-6AD8-4F4B-A363-3D2FA31CD0E2}`

Current event names:

- `HandleTelemetry`
- `ThreadTelemetry`
- `ProcessTelemetry`
- `ImageTelemetry`
- `RegistryTelemetry`
- `DetectionTelemetry`

### Key ETW-Only Fields

- Thread correlation:
  - `correlationFlags`
  - `correlationAccessMask`
  - `correlationAgeMs`
- Thread start-region metadata:
  - `startRegionProtect`
  - `startRegionState`
  - `startRegionType`
  - `startRegionStatus`
- Process metadata:
  - parent/creator IDs
  - `processStartKey`
  - image path and command line
- Image metadata:
  - signature level/type where available
  - system-mode image indicator
- Registry metadata:
  - operation, notify class, data type/size
  - key path and value name
  - high-value path marker
- Detection metadata:
  - detection name
  - severity
  - reason
  - correlation context

### Current Detection Names

- `REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT`
- `REMOTE_THREAD_START_IN_NON_IMAGE_EXECUTABLE_REGION`
- `REMOTE_THREAD_OUTSIDE_MAIN_IMAGE`
- `THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT`
- `HIGH_VALUE_REGISTRY_ACTIVITY`
- `DIRECT_SYSCALL_SUSPECT_HANDLE_OPERATION`
- `POSSIBLE_PROCESS_HOLLOWING_OR_INJECTION_INTENT_CHAIN`
- `POSSIBLE_MANUAL_MAP_OR_HOLLOWING_EXECUTION`
- `SUSPICIOUS_NTDLL_IMAGE_PATH`
- `MULTIPLE_NTDLL_IMAGE_MAPPINGS`

## Quick Integration Flow (IOCTL)

1. `CreateFile("\\\\.\\Global\\SleepwalkerCtl", ...)`
2. Subscribe one or more PIDs with chosen stream mask
3. Poll `IOCTL_SLEEPWALKER_GET_EVENT` in a loop
4. Handle `NO_MORE_ENTRIES` as empty queue
5. Query `IOCTL_SLEEPWALKER_GET_STATS` for health and drops
6. Unsubscribe and close handle

Using `SleepwalkerSensorCore` helpers, the same flow is:

1. `SLEEPWALKERSCOpenControlDevice`
2. `SLEEPWALKERSCSubscribe`
3. loop on `SLEEPWALKERSCGetEvent`
4. `SLEEPWALKERSCGetStats` for queue/drop health
5. `SLEEPWALKERSCUnsubscribe` and close handle

## Minimal Pseudocode

```c
HANDLE h = CreateFileW(L"\\\\.\\Global\\SleepwalkerCtl", ...);
SLEEPWALKER_SUBSCRIBE_REQUEST sub = { .ProcessId = pid, .StreamMask = SLEEPWALKER_STREAM_HANDLE | SLEEPWALKER_STREAM_THREAD };
DeviceIoControl(h, IOCTL_SLEEPWALKER_SUBSCRIBE, &sub, sizeof(sub), NULL, 0, &bytes, NULL);

for (;;) {
    SLEEPWALKER_EVENT_RECORD rec = {0};
    if (!DeviceIoControl(h, IOCTL_SLEEPWALKER_GET_EVENT, NULL, 0, &rec, sizeof(rec), &bytes, NULL)) {
        if (GetLastError() == ERROR_NO_MORE_ITEMS) {
            Sleep(25);
            continue;
        }
        break;
    }

    switch (rec.Header.Type) {
    case SleepwalkerEventTypeHandle:
        /* consume handle payload */
        break;
    case SleepwalkerEventTypeThread:
        /* consume thread payload */
        break;
    }
}
```

## Error and Status Expectations

Common NTSTATUS results mapped to Win32 errors on IOCTL calls:

- `STATUS_SUCCESS`
- `STATUS_NO_MORE_ENTRIES` (empty queue)
- `STATUS_INVALID_PARAMETER` (invalid stream mask/request)
- `STATUS_NOT_FOUND` (unsubscribe for unknown PID)
- `STATUS_ACCESS_DENIED` (non-user-mode request denied)
- `STATUS_BUFFER_TOO_SMALL`

## Operational Notes

- Symbol enrichment is user-mode responsibility (see sensor/test tooling).
- Current sensor formatting uses:
  - symbol-first resolution (DbgHelp)
  - module-range fallback from ETW image metadata cache
  - final context-only process image fallback when symbol ownership is unknown
- Kernel addresses may remain unresolved depending on symbol policy/hardening.
- High event rates can produce queue drops; monitor `DroppedEvents` and ETW counters.
- Use `SleepwalkerTestSuite` to verify environment health and coverage after driver changes.
- `SleepwalkerTestSuite` strictness knobs:
  - `SLEEPWALKER_TEST_REQUIRE_KERNEL_CORRELATION=1` to require kernel correlation-dependent checks.
  - `SLEEPWALKER_TEST_REQUIRE_APC=1` to require APC ETW coverage.
- Test output includes per-check elapsed timing (`ms`) and cycle deltas (`rdtsc` when available), plus suite total elapsed time.
