# Blackbird API Guide

This document describes the current Blackbird control-plane and telemetry contract for engineers, detection content authors, and integrators.

## Telemetry Contract Visual

<p align="center">
  <img src="./diagram/Blackbird_DIA.png" width="900" />
</p>

## IOCTL Record Example

<p align="center">
  <img src="./diagram/IOCTL_EVENT_HANDLE.png" width="900" />
</p>

## Revision and Scope

- Document revision: `2026-03-06`
- ABI source of truth: `abi/blackbird_ioctl.h`
- Compatibility note: no explicit in-band ABI version field is currently exposed; pin integration by commit/date and validate with `BlackbirdTestSuite`.

## At a Glance

- Control device:
  - NT: `\Device\BlackbirdCtl`
  - DOS: `\\.\Global\BlackbirdCtl` (preferred), `\\.\BlackbirdCtl` (legacy)
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
  - `BlackbirdSensorCore.dll` / `user/sensor/blackbird_sensor_core.h`
  - exported `BLACKBIRDSC*` APIs for IOCTL and ETW session management
  - typed `Swk*` detection callback surface for ETW detection events
- ETW provider:
  - name: `Blackbird.Kernel`
  - GUID: `{D6C73F8A-6AD8-4F4B-A363-3D2FA31CD0E2}`

## Shared User-Mode SDK (`BlackbirdSensorCore`)

The preferred integration surface for user-mode consumers is:

- header: `user/sensor/blackbird_sensor_core.h`
- binary: `BlackbirdSensorCore.dll`

Current exports:

- Protocol selection helpers:
  - `BLACKBIRDSCUseServiceProtocol`
  - `BLACKBIRDSCUseClientProtocol`
  - `BLACKBIRDSCGetProtocolMode`
  - `BLACKBIRDSCGetBrokerThreatIntelEnableError`
- IOCTL control-plane wrappers:
  - `BLACKBIRDSCOpenControlDevice`
  - `BLACKBIRDSCSubscribe`
  - `BLACKBIRDSCUnsubscribe`
  - `BLACKBIRDSCSetPids`
  - `BLACKBIRDSCGetEvent`
  - `BLACKBIRDSCGetStats`
  - `BLACKBIRDSCQueryProcessImagePath`
  - `BLACKBIRDSCSetShutdownMode`
  - `BLACKBIRDSCParseStreamMaskA`
- ETW session wrappers:
  - `BLACKBIRDSCStopSessionByName`
  - `BLACKBIRDSCStartEtwSession`
  - `BLACKBIRDSCStartBlackbirdEtwSession`
  - `SwkStartDetectionEtwSession`
  - `BLACKBIRDSCRunEtwSession`
  - `BLACKBIRDSCStopEtwSession`
- Typed detection callback types:
  - `SwkDetectionEvent`
  - `SwkDetectionCallback`

Consumers currently using these exports:

- `BlackbirdClient`
- `BlackbirdTestSuite`
- `BlackbirdController`

## IOCTL Interface

### Request/Response Matrix

- `IOCTL_BLACKBIRD_SUBSCRIBE`
  - In: `BLACKBIRD_SUBSCRIBE_REQUEST`
  - Out: none
- `IOCTL_BLACKBIRD_UNSUBSCRIBE`
  - In: `BLACKBIRD_UNSUBSCRIBE_REQUEST`
  - Out: none
- `IOCTL_BLACKBIRD_GET_EVENT`
  - In: none
  - Out: `BLACKBIRD_EVENT_RECORD`
- `IOCTL_BLACKBIRD_GET_STATS`
  - In: none
  - Out: `BLACKBIRD_STATS_RESPONSE`
- `IOCTL_BLACKBIRD_SET_PIDS`
  - In: `BLACKBIRD_SET_PIDS_REQUEST`
  - Out: none
- `IOCTL_BLACKBIRD_QUERY_PROCESS_IMAGE`
  - In: `BLACKBIRD_QUERY_PROCESS_IMAGE_REQUEST`
  - Out: `BLACKBIRD_QUERY_PROCESS_IMAGE_RESPONSE`
- `IOCTL_BLACKBIRD_SET_SHUTDOWN_MODE`
  - In: none
  - Out: none

### Stream Flags

- `BLACKBIRD_STREAM_HANDLE`
- `BLACKBIRD_STREAM_MEMORY`
- `BLACKBIRD_STREAM_THREAD`

`StreamMask` is bitwise-composable.

## Subscription and Delivery Semantics

- Subscriptions are scoped to each opened file handle to the control device.
- One client can subscribe multiple `(ProcessId, StreamMask)` entries.
- Current limits:
  - max subscriptions per client: `256`
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

### Service-Broker Dynamic Expansion

When using `BlackbirdController` broker mode (`BLACKBIRDSCUseClientProtocol`), the controller can expand monitoring
beyond the initially seeded PID list by building a relation graph per client:

- Relation edges considered for expansion:
  - handle events: `callerPid -> targetPid`
  - thread events: `creatorPid -> processId`
  - process telemetry: `creator/parent -> child process`
  - broker ETW events: resolved from the explicit IPC ETW family fields (`caller/creator/process -> target/process`)
- Dynamic entries inherit the source subscription stream mask.
- Guardrails:
  - max dynamic depth from explicit seed: `3`
  - dynamic entry inactivity TTL: `120000 ms`
- Cleanup behavior:
  - explicit `unsubscribe(rootPid)` drops dynamic descendants rooted at that PID for that client.
  - explicit `subscribe(pid)` upgrades an existing dynamic entry for `pid` to explicit.
  - `set-pids` replaces the explicit seed set; dynamic entries are rebuilt from fresh runtime relations.

## Event Record Structure

`BLACKBIRD_EVENT_RECORD` contains:

- `BLACKBIRD_EVENT_HEADER`
  - `Size`
  - `Type`
  - `StreamMask`
  - `Sequence` (per-client monotonic)
  - `TimestampQpc`
- Union payload:
  - `BLACKBIRD_HANDLE_EVENT`
  - `BLACKBIRD_THREAD_EVENT`

Event type values:

- `BlackbirdEventTypeHandle`
- `BlackbirdEventTypeThread`

## Handle Event Contract

`BLACKBIRD_HANDLE_EVENT` fields:

- `CallerPid`, `TargetPid`
- `DesiredAccess`
- `ClassId` (`BLACKBIRD_HANDLE_CLASS`)
- `OriginAddress`, `OriginProtect`, `OriginPath`
- `StatusOpenProcess`, `StatusBasicInfo`, `StatusSectionName`
- Deep-path capture metadata:
  - `DeepAllocationBase`
  - `DeepRegionSize`
  - `DeepRegionProtect`
  - `DeepRegionState`
  - `DeepRegionType`
  - `DeepSampleSize`
  - `DeepSample[BLACKBIRD_MAX_DEEP_SAMPLE_BYTES]`
- `FrameCount`, `Frames[BLACKBIRD_MAX_EVENT_FRAMES]`

### Handle Classes

- `BlackbirdHandleClassUnknown`
- `BlackbirdHandleClassLegitimateSyscall`
- `BlackbirdHandleClassDirectSyscallSuspect`

### Handle Flags

- `BLACKBIRD_HANDLE_FLAG_EXEC_PROTECT`
- `BLACKBIRD_HANDLE_FLAG_FROM_NTDLL`
- `BLACKBIRD_HANDLE_FLAG_FROM_EXE`
- `BLACKBIRD_HANDLE_FLAG_MEMORY_RELATED`
- `BLACKBIRD_HANDLE_FLAG_THREAD_OBJECT`
- `BLACKBIRD_HANDLE_FLAG_DUPLICATE_OPERATION`
- `BLACKBIRD_HANDLE_FLAG_DEEP_PATH_CANDIDATE`
- `BLACKBIRD_HANDLE_FLAG_DEEP_PATH_CAPTURED`
- `BLACKBIRD_HANDLE_FLAG_DEEP_PATH_CACHE_HIT`

## Thread Event Contract

`BLACKBIRD_THREAD_EVENT` fields:

- `ProcessId`, `ThreadId`, `CreatorPid`
- `StartAddress`
- `ImageBase`, `ImageSize`
- `Flags`
- `FrameCount`, `Frames[BLACKBIRD_MAX_EVENT_FRAMES]`

### Thread Flags

- `BLACKBIRD_THREAD_FLAG_GOT_START`
- `BLACKBIRD_THREAD_FLAG_GOT_RANGE`
- `BLACKBIRD_THREAD_FLAG_REMOTE_CREATOR`
- `BLACKBIRD_THREAD_FLAG_OUTSIDE_MAIN_IMG`
- `BLACKBIRD_THREAD_FLAG_CORRELATED_INTENT`
- `BLACKBIRD_THREAD_FLAG_CORR_MEMORY`
- `BLACKBIRD_THREAD_FLAG_CORR_THREAD_CTX`
- `BLACKBIRD_THREAD_FLAG_CORR_DUP_HANDLE`
- `BLACKBIRD_THREAD_FLAG_START_REGION_EXEC`

## Stats Contract

`BLACKBIRD_STATS_RESPONSE`:

- `SubscriptionCount`
- `QueueDepth`
- `DroppedEvents`
- `Reserved`

## ETW Contract

Provider:

- Name: `Blackbird.Kernel`
- GUID: `{D6C73F8A-6AD8-4F4B-A363-3D2FA31CD0E2}`

Current event names:

- `HandleTelemetry`
- `ThreadTelemetry`
- `ProcessTelemetry`
- `ImageTelemetry`
- `RegistryTelemetry`
- `DetectionTelemetry`
- `SystemInformationTelemetry`
- `NtApiTelemetry`

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

### IPC ETW Uplink Surface

The broker ETW IPC model (`BLACKBIRD_IPC_ETW_EVENT`) now carries both the generic ETW envelope and
event-family-specific fields so clients can build richer inspectors without reparsing raw ETW:

- Generic envelope:
  - source, family, task/opcode/id
  - ETW header process/thread IDs
  - actor/target relation PIDs
  - detection name, reason, severity
  - correlation flags/access/age
- Handle/APC enrichment:
  - class name, desired access
  - origin address/protect/path
  - frame list
  - deep-path allocation/region/sample metadata
  - APC duplicate-operation marker
- Thread enrichment:
  - process/thread/creator IDs
  - start address, image base/size
  - start-region protection/state/type/status
  - worker stack frames
  - got-start/got-range/remote/outside-image flags
- Process/Image enrichment:
  - parent/creator IDs
  - creator thread ID
  - process start key
  - session ID
  - create status / create marker
  - image path and command line
  - signature level/type and system-mode marker for image events
- Registry enrichment:
  - operation
  - session ID
  - notify class
  - data type/size
  - key path and value name
  - high-value path marker

### Current Detection Names

- `REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT`
- `REMOTE_THREAD_START_IN_NON_IMAGE_EXECUTABLE_REGION`
- `REMOTE_THREAD_OUTSIDE_MAIN_IMAGE`
- `THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT`
- `THREAD_HIJACK_INTENT`
- `REMOTE_APC_CREATION_SUSPECT`
- `HIGH_VALUE_REGISTRY_ACTIVITY`
- `DIRECT_SYSCALL_SUSPECT_HANDLE_OPERATION`
- `POSSIBLE_PROCESS_HOLLOWING_OR_INJECTION_INTENT_CHAIN`
- `POSSIBLE_MANUAL_MAP_OR_HOLLOWING_EXECUTION`
- `KERNEL_PROCESS_HOLLOWING_MARK_CHAIN_MEDIUM`
- `KERNEL_PROCESS_HOLLOWING_MARK_CHAIN_STRONG`
- `STACK_INTEGRITY_ANOMALY_ON_HANDLE_OP`
- `SUSPICIOUS_NTDLL_IMAGE_PATH`
- `MULTIPLE_NTDLL_IMAGE_MAPPINGS`
- `DRIVER_DISPATCH_OR_OBJECT_TAMPER`
- `DRIVER_DISPATCH_OR_OBJECT_TAMPER_CLEARED`
- broker-synthesized correlation detections (controller ETW uplink):
  - `PROCESS_HOLLOWING_MARK_CHAIN_MEDIUM`
  - `PROCESS_HOLLOWING_MARK_CHAIN_STRONG`
  - `PROCESS_HOLLOWING_TXF_SUSPECT_CHAIN`

## Quick Integration Flow (IOCTL)

1. `CreateFile("\\\\.\\Global\\BlackbirdCtl", ...)`
2. Subscribe one or more PIDs with chosen stream mask
3. Poll `IOCTL_BLACKBIRD_GET_EVENT` in a loop
4. Handle `NO_MORE_ENTRIES` as empty queue
5. Query `IOCTL_BLACKBIRD_GET_STATS` for health and drops
6. Unsubscribe and close handle

Using `BlackbirdSensorCore` helpers, the same flow is:

1. `BLACKBIRDSCOpenControlDevice`
2. `BLACKBIRDSCSubscribe`
3. loop on `BLACKBIRDSCGetEvent`
4. `BLACKBIRDSCGetStats` for queue/drop health
5. `BLACKBIRDSCUnsubscribe` and close handle

## Minimal Pseudocode

```c
HANDLE h = CreateFileW(L"\\\\.\\Global\\BlackbirdCtl", ...);
BLACKBIRD_SUBSCRIBE_REQUEST sub = { .ProcessId = pid, .StreamMask = BLACKBIRD_STREAM_HANDLE | BLACKBIRD_STREAM_THREAD };
DeviceIoControl(h, IOCTL_BLACKBIRD_SUBSCRIBE, &sub, sizeof(sub), NULL, 0, &bytes, NULL);

for (;;) {
    BLACKBIRD_EVENT_RECORD rec = {0};
    if (!DeviceIoControl(h, IOCTL_BLACKBIRD_GET_EVENT, NULL, 0, &rec, sizeof(rec), &bytes, NULL)) {
        if (GetLastError() == ERROR_NO_MORE_ITEMS) {
            Sleep(25);
            continue;
        }
        break;
    }

    switch (rec.Header.Type) {
    case BlackbirdEventTypeHandle:
        /* consume handle payload */
        break;
    case BlackbirdEventTypeThread:
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
- Use `BlackbirdTestSuite` to verify environment health and coverage after driver changes.
- `BlackbirdTestSuite` strictness knobs:
  - `BLACKBIRD_TEST_REQUIRE_KERNEL_CORRELATION=1` to require kernel correlation-dependent checks.
  - `BLACKBIRD_TEST_REQUIRE_APC=1` to require APC ETW coverage.
- Test output includes per-check elapsed timing (`ms`) and cycle deltas (`rdtsc` when available), plus suite total elapsed time.
