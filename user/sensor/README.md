## Stinger Sensor

`stinger_sensor.exe` is a read-only user-mode ETW consumer for the kernel driver provider:

- Provider: `Stinger.Kernel`
- GUID: `D6C73F8A-6AD8-4F4B-A363-3D2FA31CD0E2`
- decodes detailed handle/thread telemetry fields (access masks, status codes, image paths)
- resolves stack/origin/start addresses with user+kernel symbol enrichment when available
- prints event metadata useful for triage (`pid/tid/cpu/opcode/version/timestamp delta`)

### Build

From Visual Studio project `projects/StingerEtwProc.vcxproj`, or from a Visual Studio Developer Command Prompt:

```bat
cd C:\$ARSENAL\Kernel\Tartan\user\sensor
build_sensor.cmd
```

### Run

Run elevated:

```bat
stinger_sensor.exe
```

Press `Ctrl+C` to stop.

For richer symbol resolution:

```powershell
$env:_NT_SYMBOL_PATH = "srv*C:\symbols*https://msdl.microsoft.com/download/symbols"
```

## Stinger Client (IOCTL)

`stinger_client.exe` subscribes directly to the driver control plane and receives queued events.

Build from Visual Studio project `projects/StingerClient.vcxproj`, or:

```bat
cd C:\$ARSENAL\Kernel\Tartan\user\sensor
build_client.cmd
```

Run elevated:

```bat
stinger_client.exe 4242 handle,memory,thread
```

## Stinger IOCTL Test

`stinger_ioctl_test.exe` runs a smoke/integration check against `\\.\StingerCtl`:

- verifies invalid subscribe input rejection
- subscribes current PID
- validates stats path
- attempts to generate and read thread/handle events
- prints decoded event payload fields from IOCTL records
- resolves user/kernel addresses to `module!symbol+offset` when symbols are available
- unsubscribes and exits with pass/fail status

Build from Visual Studio project `projects/StingerIoctlTest.vcxproj`.

Optional symbol path setup for richer kernel/user symbol resolution:

```powershell
$env:_NT_SYMBOL_PATH = "srv*C:\symbols*https://msdl.microsoft.com/download/symbols"
```

### Security Model

- Driver control device is ACL-restricted (`SYSTEM` and `Administrators`).
- Driver enforces user-mode request origin for IOCTL control operations.
- IOCTLs only configure per-handle subscriptions and read telemetry; no mutation/path to disable protections.
- ETW path remains one-way kernel-to-user telemetry.
