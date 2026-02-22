# Stinger API Reference

All shared constants and IOCTL structures are defined in `abi/stinger_ioctl.h`.

## Revision

- Document revision: `2026-02-22`
- ABI versioning note: the current ABI does not expose an in-band version field; track revision by repo commit/date plus this document.

## Device Endpoints

- NT device: `\Device\StingerCtl`
- DOS links:
  - `\\.\Global\StingerCtl` (preferred)
  - `\\.\StingerCtl` (legacy compatibility)

## IOCTL Contract

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

## Stream Flags

- `STINGER_STREAM_HANDLE`
- `STINGER_STREAM_MEMORY`
- `STINGER_STREAM_THREAD`

`StreamMask` is bitwise-composable.

## Event Envelope

`STINGER_EVENT_RECORD` carries:

- `STINGER_EVENT_HEADER`
  - `Size`
  - `Type`
  - `StreamMask`
  - `Sequence` (per-client monotonic)
  - `TimestampQpc`
- Union payload:
  - `STINGER_HANDLE_EVENT`
  - `STINGER_THREAD_EVENT`

Event types:

- `StingerEventTypeHandle`
- `StingerEventTypeThread`

## Handle Payload

`STINGER_HANDLE_EVENT` fields include:

- `CallerPid`, `TargetPid`
- `DesiredAccess`
- `ClassId` (`STINGER_HANDLE_CLASS`)
- `OriginAddress`, `OriginProtect`, `OriginPath`
- `StatusOpenProcess`, `StatusBasicInfo`, `StatusSectionName`
- `FrameCount`, `Frames[STINGER_MAX_EVENT_FRAMES]`

Handle class IDs:

- `StingerHandleClassUnknown`
- `StingerHandleClassLegitimateSyscall`
- `StingerHandleClassDirectSyscallSuspect`

Handle flags:

- `STINGER_HANDLE_FLAG_EXEC_PROTECT`
- `STINGER_HANDLE_FLAG_FROM_NTDLL`
- `STINGER_HANDLE_FLAG_FROM_EXE`
- `STINGER_HANDLE_FLAG_MEMORY_RELATED`
- `STINGER_HANDLE_FLAG_THREAD_OBJECT`
- `STINGER_HANDLE_FLAG_DUPLICATE_OPERATION`

## Thread Payload

`STINGER_THREAD_EVENT` fields include:

- `ProcessId`, `ThreadId`, `CreatorPid`
- `StartAddress`
- `ImageBase`, `ImageSize`
- `FrameCount`, `Frames[STINGER_MAX_EVENT_FRAMES]`
- `Flags`

Thread flags:

- `STINGER_THREAD_FLAG_GOT_START`
- `STINGER_THREAD_FLAG_GOT_RANGE`
- `STINGER_THREAD_FLAG_REMOTE_CREATOR`
- `STINGER_THREAD_FLAG_OUTSIDE_MAIN_IMG`
- `STINGER_THREAD_FLAG_CORRELATED_INTENT`
- `STINGER_THREAD_FLAG_CORR_MEMORY`
- `STINGER_THREAD_FLAG_CORR_THREAD_CTX`
- `STINGER_THREAD_FLAG_CORR_DUP_HANDLE`
- `STINGER_THREAD_FLAG_START_REGION_EXEC`

## Subscription and Delivery Semantics

- Subscriptions are scoped to each open control-device handle.
- Each client has an independent queue, sequence counter, subscription set, and drop counter.
- A subscription key is `(ProcessId, StreamMask)`.
- Event routing:
  - Handle events are matched on `CallerPid` and stream overlap.
  - Thread events are matched on `ProcessId` and stream overlap.
- Queue and client limits in current driver:
  - Max subscriptions per client: `64`
  - Max queue depth per client: `1024`
  - Max simultaneous clients: `256`

## Stats Contract

`STINGER_STATS_RESPONSE`:

- `SubscriptionCount`
- `QueueDepth`
- `DroppedEvents`
- `Reserved`

## ETW Provider Contract

- Provider name: `Stinger.Kernel`
- Provider GUID: `{D6C73F8A-6AD8-4F4B-A363-3D2FA31CD0E2}`

Event names emitted by current driver:

- `HandleTelemetry`
- `ThreadTelemetry`
- `ProcessTelemetry`
- `ImageTelemetry`
- `RegistryTelemetry`
- `DetectionTelemetry`

Representative ETW-only properties added in the expanded surface:

- Thread correlation: `correlationFlags`, `correlationAccessMask`, `correlationAgeMs`
- Thread start-region telemetry: `startRegionProtect`, `startRegionState`, `startRegionType`, `startRegionStatus`
- Process lifecycle metadata: parent/creator IDs, `processStartKey`, command line
- Image-load metadata: signature level/type and `isSystemModeImage`
- Registry telemetry: operation, notify class, key/value path, data type/size, high-value-path bit
- Detection event metadata: detection name, severity, reason, and correlation context

Current detection names emitted by monitors:

- `REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT`
- `REMOTE_THREAD_OUTSIDE_MAIN_IMAGE`
- `THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT`
- `HIGH_VALUE_REGISTRY_ACTIVITY`

## Typical Client Flow

1. `CreateFile("\\\\.\\Global\\StingerCtl", ...)`
2. `IOCTL_STINGER_SUBSCRIBE` for one or more PIDs
3. Poll `IOCTL_STINGER_GET_EVENT`
4. Query health via `IOCTL_STINGER_GET_STATS`
5. `IOCTL_STINGER_UNSUBSCRIBE`
6. `CloseHandle`

## Common Status Mapping

- `STATUS_SUCCESS`
- `STATUS_NO_MORE_ENTRIES` (empty queue)
- `STATUS_INVALID_PARAMETER` (invalid mask/request)
- `STATUS_NOT_FOUND` (unsubscribe PID not present)
- `STATUS_ACCESS_DENIED` (non-user-mode request to control IOCTL path)
- `STATUS_BUFFER_TOO_SMALL`
