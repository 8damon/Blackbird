## User-Mode Tools

Document revision: `2026-02-28`

## Shared Library: BlackbirdSensorCore

`J58.dll` is the common user-mode integration layer used by:

- `BlackbirdTestSuite.exe`

What it provides:

- IOCTL helpers (`open/subscribe/unsubscribe/get-event/get-stats`)
- Stream-mask parsing helper
- ETW real-time session lifecycle (start/run/stop)
- Multi-provider ETW enablement and callback dispatch with event-name resolution

Exports:

- `BLACKBIRDSCOpenControlDevice`
- `BLACKBIRDSCUseServiceProtocol`
- `BLACKBIRDSCUseClientProtocol`
- `BLACKBIRDSCGetProtocolMode`
- `BLACKBIRDSCSubscribe`
- `BLACKBIRDSCUnsubscribe`
- `BLACKBIRDSCSetPids`
- `BLACKBIRDSCGetEvent`
- `BLACKBIRDSCGetStats`
- `BLACKBIRDSCQueryProcessImagePath`
- `BLACKBIRDSCSetShutdownMode`
- `BLACKBIRDSCParseStreamMaskA`
- `BLACKBIRDSCGetBrokerThreatIntelEnableError`
- `BLACKBIRDSCStopSessionByName`
- `BLACKBIRDSCStartEtwSession`
- `BLACKBIRDSCStartBlackbirdEtwSession`
- `SwkStartDetectionEtwSession`
- `BLACKBIRDSCRunEtwSession`
- `BLACKBIRDSCStopEtwSession`

Typed detection callback surface:

- `SwkDetectionEvent`
- `SwkDetectionCallback`

Build project `vcxproj/BlackbirdSensorCore.vcxproj`.

## BlackbirdTestSuite (IOCTL + ETW Validation)

`BlackbirdTestSuite.exe` (from `user/sensor/blackbird_ioctl_test.c`) is the current end-to-end validation harness.

Build project `vcxproj/BlackbirdIoctlTest.vcxproj` (depends on `BlackbirdSensorCore` and emits `BlackbirdTestSuite.exe`).

What it validates:

- Control-device open path
- Broker transport contract (`service-broker` required)
- Invalid subscription mask rejection
- Self + broker-dynamic child coverage
- IOCTL stats query
- IOCTL handle/thread event delivery and detailed decoding
- Correlation/intent flags (`MemoryRelated`, `ThreadObject`, `DuplicateOperation`)
- Thread correlation flags when strict correlation mode is enabled
- ETW family coverage (`HandleTelemetry`, `ThreadTelemetry`, `ProcessTelemetry`, `ImageTelemetry`, `RegistryTelemetry`, `DetectionTelemetry`)
- ETW APC surface coverage (`ApcTelemetry`) when APC-required mode is enabled
- Detection coverage for APC/hijack/tamper signals when strict correlation mode is enabled
- Fast multi-client parallel IOCTL fanout (3 parallel subscribers)
- Deep-path enrichment fields (`Deep*`) and sample-backed user-mode entropy/opcode formatting

Runtime knobs:

- `BLACKBIRD_TEST_BROKER_PIPE=\\\\.\\pipe\\<name>`
  - Overrides broker pipe name for the client protocol handshake.
- `BLACKBIRD_TEST_REQUIRE_KERNEL_CORRELATION=1`
  - Enforces kernel correlation-dependent checks (IOCTL thread correlation flags + related ETW detections).
  - Default is off; those checks are reported as `[SKIP]` to align with user-mode correlation architecture.
- `BLACKBIRD_TEST_REQUIRE_APC=1`
  - Enforces APC ETW coverage.
  - Default is off; APC coverage is optional and reported as `[SKIP]` if absent.

Pass/fail summary is emitted as:

- `[OK] BlackbirdTestSuite complete. tests-passed=X/Y tests-failed=0 tests-skipped=S polls=Z`
- `[FAIL] BlackbirdTestSuite complete. tests-passed=X/Y tests-failed=F tests-skipped=S polls=Z`

Per-check timing and cycle deltas are emitted as:

- `[PASS][T0001] <check text> [+0.742ms suite=7.615ms +26314 cyc]`
- Suite total timing summary:
- `[INFO] suiteTiming elapsedMs=<total> polls=<count>`

Result artifact:

- Timestamped UTC reports are written to:
- `test-results/BlackbirdTestSuite-YYYYMMDD-HHMMSSZ.txt`
- `test-results/BlackbirdTestSuite-YYYYMMDD-HHMMSSZ.html`
- ETW-TI checks are explicitly logged as `[SKIP]` when the TI provider is unavailable.
- The report includes environment metadata: OS version/build, kernel image version, code-integrity flags, and kernel-debugger state.
- The suite requires an active `BlackbirdCtl` device; without the loaded driver it will fail at control-device open.

## Security Model

- Control device ACL is restricted to `SYSTEM` and `Administrators`.
- IOCTL control path enforces user-mode origin (`WdfRequestGetRequestorMode == UserMode`).
- IOCTL interface is telemetry/control-plane only (subscribe/unsubscribe/read/stats).
- ETW is one-way kernel-to-user telemetry.


