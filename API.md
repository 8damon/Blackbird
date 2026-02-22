# Stinger API Guide

This document describes the current Stinger control-plane and telemetry contract for engineers, detection content authors, and integrators.

## Revision and Scope

- Document revision: `2026-02-22`
- ABI source of truth: `abi/stinger_ioctl.h`
- Compatibility note: no explicit in-band ABI version field is currently exposed; pin integration by commit/date and validate with `StingerTestSuite`.

## At a Glance

- Control device:
  - NT: `\Device\StingerCtl`
  - DOS: `\\.\Global\StingerCtl` (preferred), `\\.\StingerCtl` (legacy)
- IOCTL operations:
  - subscribe
  - unsubscribe
  - get event
  - get stats
- IOCTL event families:
  - handle
  - thread
- ETW provider:
  - name: `Stinger.Kernel`
  - GUID: `{D6C73F8A-6AD8-4F4B-A363-3D2FA31CD0E2}`

## IOCTL Interface

### Request/Response Matrix

- `IOCTL_STINGER_SUBSCRIBE`
  - In: `STINGER_SUBSCRIBE_REQUEST`
  - Out: none
- `IOCTL_STINGER_UNSUBSCRIBE`
  - In: `STINGER_UNSUBSCRIBE_REQUEST`
  - Out: none
- `IOCTL_STINGER_GET_EVENT`
  - In: none
  - Out: `STINGER_EVENT_RECORD`
- `IOCTL_STINGER_GET_STATS`
  - In: none
  - Out: `STINGER_STATS_RESPONSE`

### Stream Flags

- `STINGER_STREAM_HANDLE`
- `STINGER_STREAM_MEMORY`
- `STINGER_STREAM_THREAD`

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

- Handle events route on `CallerPid` + stream-mask intersection.
- Thread events route on `ProcessId` + stream-mask intersection.

## Event Record Structure

`STINGER_EVENT_RECORD` contains:

- `STINGER_EVENT_HEADER`
  - `Size`
  - `Type`
  - `StreamMask`
  - `Sequence` (per-client monotonic)
  - `TimestampQpc`
- Union payload:
  - `STINGER_HANDLE_EVENT`
  - `STINGER_THREAD_EVENT`

Event type values:

- `StingerEventTypeHandle`
- `StingerEventTypeThread`

## Handle Event Contract

`STINGER_HANDLE_EVENT` fields:

- `CallerPid`, `TargetPid`
- `DesiredAccess`
- `ClassId` (`STINGER_HANDLE_CLASS`)
- `OriginAddress`, `OriginProtect`, `OriginPath`
- `StatusOpenProcess`, `StatusBasicInfo`, `StatusSectionName`
- `FrameCount`, `Frames[STINGER_MAX_EVENT_FRAMES]`

### Handle Classes

- `StingerHandleClassUnknown`
- `StingerHandleClassLegitimateSyscall`
- `StingerHandleClassDirectSyscallSuspect`

### Handle Flags

- `STINGER_HANDLE_FLAG_EXEC_PROTECT`
- `STINGER_HANDLE_FLAG_FROM_NTDLL`
- `STINGER_HANDLE_FLAG_FROM_EXE`
- `STINGER_HANDLE_FLAG_MEMORY_RELATED`
- `STINGER_HANDLE_FLAG_THREAD_OBJECT`
- `STINGER_HANDLE_FLAG_DUPLICATE_OPERATION`

## Thread Event Contract

`STINGER_THREAD_EVENT` fields:

- `ProcessId`, `ThreadId`, `CreatorPid`
- `StartAddress`
- `ImageBase`, `ImageSize`
- `Flags`
- `FrameCount`, `Frames[STINGER_MAX_EVENT_FRAMES]`

### Thread Flags

- `STINGER_THREAD_FLAG_GOT_START`
- `STINGER_THREAD_FLAG_GOT_RANGE`
- `STINGER_THREAD_FLAG_REMOTE_CREATOR`
- `STINGER_THREAD_FLAG_OUTSIDE_MAIN_IMG`
- `STINGER_THREAD_FLAG_CORRELATED_INTENT`
- `STINGER_THREAD_FLAG_CORR_MEMORY`
- `STINGER_THREAD_FLAG_CORR_THREAD_CTX`
- `STINGER_THREAD_FLAG_CORR_DUP_HANDLE`
- `STINGER_THREAD_FLAG_START_REGION_EXEC`

## Stats Contract

`STINGER_STATS_RESPONSE`:

- `SubscriptionCount`
- `QueueDepth`
- `DroppedEvents`
- `Reserved`

## ETW Contract

Provider:

- Name: `Stinger.Kernel`
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
- `REMOTE_THREAD_OUTSIDE_MAIN_IMAGE`
- `THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT`
- `HIGH_VALUE_REGISTRY_ACTIVITY`

## Quick Integration Flow (IOCTL)

1. `CreateFile("\\\\.\\Global\\StingerCtl", ...)`
2. Subscribe one or more PIDs with chosen stream mask
3. Poll `IOCTL_STINGER_GET_EVENT` in a loop
4. Handle `NO_MORE_ENTRIES` as empty queue
5. Query `IOCTL_STINGER_GET_STATS` for health and drops
6. Unsubscribe and close handle

## Minimal Pseudocode

```c
HANDLE h = CreateFileW(L"\\\\.\\Global\\StingerCtl", ...);
STINGER_SUBSCRIBE_REQUEST sub = { .ProcessId = pid, .StreamMask = STINGER_STREAM_HANDLE | STINGER_STREAM_THREAD };
DeviceIoControl(h, IOCTL_STINGER_SUBSCRIBE, &sub, sizeof(sub), NULL, 0, &bytes, NULL);

for (;;) {
    STINGER_EVENT_RECORD rec = {0};
    if (!DeviceIoControl(h, IOCTL_STINGER_GET_EVENT, NULL, 0, &rec, sizeof(rec), &bytes, NULL)) {
        if (GetLastError() == ERROR_NO_MORE_ITEMS) {
            Sleep(25);
            continue;
        }
        break;
    }

    switch (rec.Header.Type) {
    case StingerEventTypeHandle:
        /* consume handle payload */
        break;
    case StingerEventTypeThread:
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
- Kernel addresses may remain unresolved depending on symbol policy/hardening.
- High event rates can produce queue drops; monitor `DroppedEvents` and ETW counters.
- Use `StingerTestSuite` to verify environment health and coverage after driver changes.
