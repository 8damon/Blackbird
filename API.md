# Stinger API / IOCTL Contract

All API constants and data structures are defined in `abi/stinger_ioctl.h`.

## Device Endpoints

- NT device: `\Device\StingerCtl`
- DOS links:
  - `\\.\StingerCtl`
  - `\\.\Global\StingerCtl`

## IOCTL Interface

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

## Stream Model

Available stream flags:

- `STINGER_STREAM_HANDLE`
- `STINGER_STREAM_MEMORY`
- `STINGER_STREAM_THREAD`

`StreamMask` is bitwise-composable.

## Event Types

- `StingerEventTypeHandle`
- `StingerEventTypeThread`

`STINGER_EVENT_HEADER` fields:

- `Size`
- `Type`
- `StreamMask`
- `Sequence` (per-client)
- `TimestampQpc`

## Handle Event Payload

`STINGER_HANDLE_EVENT` contains:

- caller PID / target PID
- desired access mask
- classification (`STINGER_HANDLE_CLASS`)
- origin address / page protection / section path
- stack frames (up to `STINGER_MAX_EVENT_FRAMES`)
- NTSTATUS telemetry fields for origin lookups

Handle flags:

- `STINGER_HANDLE_FLAG_EXEC_PROTECT`
- `STINGER_HANDLE_FLAG_FROM_NTDLL`
- `STINGER_HANDLE_FLAG_FROM_EXE`
- `STINGER_HANDLE_FLAG_MEMORY_RELATED`

## Thread Event Payload

`STINGER_THREAD_EVENT` contains:

- process/thread/creator identifiers
- start address
- main image base and size
- worker stack frames (up to `STINGER_MAX_EVENT_FRAMES`)

Thread flags:

- `STINGER_THREAD_FLAG_GOT_START`
- `STINGER_THREAD_FLAG_GOT_RANGE`
- `STINGER_THREAD_FLAG_REMOTE_CREATOR`
- `STINGER_THREAD_FLAG_OUTSIDE_MAIN_IMG`

## Delivery Semantics

- Subscriptions are scoped to each opened control-device handle.
- Each client owns an independent queue, sequence counter, and dropped-event counter.
- Events are delivered when:
  - subscribed PID matches event PID, and
  - event stream intersects subscribed stream mask.

## Typical Client Flow

1. `CreateFile("\\\\.\\StingerCtl", ...)`
2. `IOCTL_STINGER_SUBSCRIBE` with PID + stream mask
3. Poll `IOCTL_STINGER_GET_EVENT`
4. Query queue health with `IOCTL_STINGER_GET_STATS`
5. `IOCTL_STINGER_UNSUBSCRIBE`
6. `CloseHandle`

## Common Status Mapping

- `STATUS_SUCCESS`
- `STATUS_NO_MORE_ENTRIES` (empty queue)
- `STATUS_INVALID_PARAMETER` (invalid request)
- `STATUS_ACCESS_DENIED` (ACL/requestor policy)
- `STATUS_BUFFER_TOO_SMALL` (insufficient output buffer)
