## User-Mode Tools

Document revision: `2026-02-22`

## StingerEtwProc (ETW Consumer)

`StingerEtwProc.exe` is the read-only ETW consumer for provider `Stinger.Kernel`:

- Provider GUID: `D6C73F8A-6AD8-4F4B-A363-3D2FA31CD0E2`
- Decodes handle/thread/process/image/registry/detection events
- Resolves stack, origin, and start addresses using user+kernel symbols when available
- Prints triage-focused metadata (`pid/tid/cpu/opcode/version/timestamp delta`)

### Build

Build Visual Studio project `vcxproj/StingerEtwProc.vcxproj`.

### Run

Run elevated:

```bat
StingerEtwProc.exe
```

Press `Ctrl+C` to stop.

Optional symbol path:

```powershell
$env:_NT_SYMBOL_PATH = "srv*C:\symbols*https://msdl.microsoft.com/download/symbols"
```

## StingerClient (IOCTL Consumer)

`StingerClient.exe` subscribes directly to the control plane and drains queued IOCTL events.

Build project `vcxproj/StingerClient.vcxproj`, then run elevated:

```bat
StingerClient.exe 4242 handle,memory,thread
```

## StingerTestSuite (IOCTL + ETW Validation)

`StingerTestSuite.exe` (from `user/sensor/stinger_ioctl_test.c`) is the current end-to-end validation harness.

Build project `vcxproj/StingerIoctlTest.vcxproj`.

What it validates:

- Control-device open path
- Invalid subscription mask rejection
- Self + child PID subscriptions
- IOCTL stats query
- IOCTL handle/thread event delivery and detailed decoding
- Correlation/intent flags (`MemoryRelated`, `ThreadObject`, `DuplicateOperation`, and thread correlation flags)
- ETW family coverage (`HandleTelemetry`, `ThreadTelemetry`, `ProcessTelemetry`, `ImageTelemetry`, `RegistryTelemetry`, `DetectionTelemetry`)
- Fast multi-client parallel IOCTL fanout (3 parallel subscribers)

Pass/fail summary is emitted as:

- `[OK] StingerTestSuite complete. tests-passed=X/Y polls=Z`
- `[FAIL] StingerTestSuite complete. tests-passed=X/Y polls=Z`

## Security Model

- Control device ACL is restricted to `SYSTEM` and `Administrators`.
- IOCTL control path enforces user-mode origin (`WdfRequestGetRequestorMode == UserMode`).
- IOCTL interface is telemetry/control-plane only (subscribe/unsubscribe/read/stats).
- ETW is one-way kernel-to-user telemetry.
