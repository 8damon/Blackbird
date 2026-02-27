## User-Mode Tools

Document revision: `2026-02-27`

## Shared Library: SleepwalkerSensorCore

`SleepwalkerSensorCore.dll` is the common user-mode integration layer used by:

- `SleepwalkerClient.exe`
- `SleepwalkerTestSuite.exe`

What it provides:

- IOCTL helpers (`open/subscribe/unsubscribe/get-event/get-stats`)
- Stream-mask parsing helper
- ETW real-time session lifecycle (start/run/stop)
- Multi-provider ETW enablement and callback dispatch with event-name resolution

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

Build project `vcxproj/SleepwalkerSensorCore.vcxproj`.

## SleepwalkerClient (IOCTL Consumer)

`SleepwalkerClient.exe` subscribes directly to the control plane and drains queued IOCTL events.

Build project `vcxproj/SleepwalkerClient.vcxproj` (depends on `SleepwalkerSensorCore`), then run elevated:

```bat
SleepwalkerClient.exe 4242 handle,memory,thread
```

Optional scope argument:

```bat
SleepwalkerClient.exe 4242 handle,memory,thread local
SleepwalkerClient.exe 4242 handle,memory,thread remote
SleepwalkerClient.exe 4242 handle,memory,thread both
```

Path-launch watch mode is also supported:

```bat
SleepwalkerClient.exe path:<full-path-to-target.exe> handle,memory,thread
```

Deterministic launch/attach mode (start suspended, attach, then resume):

```bat
SleepwalkerClient.exe launch:<full-path-to-target.exe> handle,memory,thread
```

When a `path:` target is not currently running, the client listens for Sleepwalker `ProcessTelemetry` / `ImageTelemetry`, resolves the first matching PID, and subscribes automatically.

`SleepwalkerClient` runs in strict target mode: it programs `IOCTL_SLEEPWALKER_SET_PIDS` with the resolved target PID and filters printed IOCTL/ETW output by scope (`local`, `remote`, `both`).

## SleepwalkerTestSuite (IOCTL + ETW Validation)

`SleepwalkerTestSuite.exe` (from `user/sensor/sleepwalker_ioctl_test.c`) is the current end-to-end validation harness.

Build project `vcxproj/SleepwalkerIoctlTest.vcxproj` (depends on `SleepwalkerSensorCore`).

What it validates:

- Control-device open path
- Invalid subscription mask rejection
- Self + child PID subscriptions
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

- `SLEEPWALKER_TEST_REQUIRE_KERNEL_CORRELATION=1`
  - Enforces kernel correlation-dependent checks (IOCTL thread correlation flags + related ETW detections).
  - Default is off; those checks are reported as `[SKIP]` to align with user-mode correlation architecture.
- `SLEEPWALKER_TEST_REQUIRE_APC=1`
  - Enforces APC ETW coverage.
  - Default is off; APC coverage is optional and reported as `[SKIP]` if absent.

Pass/fail summary is emitted as:

- `[OK] SleepwalkerTestSuite complete. tests-passed=X/Y tests-failed=0 tests-skipped=S polls=Z`
- `[FAIL] SleepwalkerTestSuite complete. tests-passed=X/Y tests-failed=F tests-skipped=S polls=Z`

Per-check timing and cycle deltas are emitted as:

- `[PASS][T0001] <check text> [+0.742ms suite=7.615ms +26314 cyc]`
- Suite total timing summary:
- `[INFO] suiteTiming elapsedMs=<total> polls=<count>`

Result artifact:

- Timestamped UTC reports are written to:
- `test-results/SleepwalkerTestSuite-YYYYMMDD-HHMMSSZ.txt`
- `test-results/SleepwalkerTestSuite-YYYYMMDD-HHMMSSZ.html`
- ETW-TI checks are explicitly logged as `[SKIP]` when the TI provider is unavailable.
- The report includes environment metadata: OS version/build, kernel image version, code-integrity flags, and kernel-debugger state.
- The suite requires an active `SleepwalkerCtl` device; without the loaded driver it will fail at control-device open.

## Security Model

- Control device ACL is restricted to `SYSTEM` and `Administrators`.
- IOCTL control path enforces user-mode origin (`WdfRequestGetRequestorMode == UserMode`).
- IOCTL interface is telemetry/control-plane only (subscribe/unsubscribe/read/stats).
- ETW is one-way kernel-to-user telemetry.
