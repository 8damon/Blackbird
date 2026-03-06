# Getting Started

This guide is the shortest path to a working Sleepwalker alpha deployment in a lab or VM.

## 1. Prerequisites

- Windows analysis VM
- administrative shell
- Visual Studio with WDK/KMDF tooling
- test-signing enabled if you are using a non-production certificate

## 2. Build The Components

Build these projects:

- `vcxproj/Sleepwalker.vcxproj`
- `vcxproj/SleepwalkerController.vcxproj`
- `vcxproj/SleepwalkerSensorCore.vcxproj`
- `vcxproj/SleepwalkerClient.vcxproj`
- `vcxproj/SleepwalkerIoctlTest.vcxproj`
- `interface/SleepwalkerInterface.csproj`

Typical artifacts:

- `x64\Debug\sleepwlkr.sys`
- `x64\Debug\SleepwlkrController.exe`
- `x64\Debug\SleepwalkerSensorCore.dll`
- `x64\Debug\SleepwalkerClient.exe`
- `x64\Debug\SleepwalkerIoctlTest.exe`
- `interface\bin\x64\Debug\net9.0-windows\SleepwalkerInterface.exe`

## 3. Install And Start The Driver

From an elevated shell:

```bat
pnputil /add-driver "Sleepwalker.inf" /install
sc start sleepwlkr
```

Check state:

```bat
sc query sleepwlkr
```

## 4. Install And Start The Controller

Recommended service install:

```powershell
powershell -ExecutionPolicy Bypass -File .\usage\install-controller-service.ps1
sc query SleepwlkrController
```

If you are iterating quickly, you can also run `SleepwlkrController.exe` directly in your VM instead of installing it as a service.

## 5. Validate The Stack

Run the validation harness before opening the interface:

```bat
.\x64\Debug\SleepwalkerIoctlTest.exe
```

Expected outcome:

- driver opens cleanly
- broker handshake succeeds
- IOCTL and ETW test coverage passes or reports expected optional skips

## 6. Launch The Interface

Start:

```bat
.\interface\bin\x64\Debug\net9.0-windows\SleepwalkerInterface.exe
```

If you deployed the interface output somewhere else, make sure `SleepwalkerSensorCore.dll` beside the interface is from the same build as the controller.

## 7. First Operator Workflow

1. Use `Select Target` to attach to a process.
2. Confirm uplink/backend status in the main shell.
3. Watch the timeline, event log, heuristics, and ETW panes populate.
4. Open `Detection Chain` or an inspector by double-clicking grouped telemetry.
5. Use the time-travel slider to move from live view into historical view.
6. Open `Thread Stack` or `Handle Evidence` when you need capture-time context.
7. Save or export the session when the review is complete.

## 8. Session Files And Export

The interface supports:

- opening saved session archives
- importing a second archive into the current workspace
- saving a session archive
- exporting to:
  - JSON Lines
  - CSV
  - CEF
  - ATT&CK-ready CSV

## 9. Common Failure Modes

### `OpenControlDevice failed (win32=233)`

Usually means the interface-side `SleepwalkerSensorCore.dll` does not match the running controller ABI, or the broker dropped the pipe during handshake.

### Interface connects but no live data appears

Check:

- target PID is valid
- driver service is running
- controller is using the expected broker/service protocol
- target exited before sampling began

### Time travel shows `No data`

That is expected if you scrub to a point with no captured sample for memory or thread-stack history.

## 10. Where To Go Next

- [README.md](./README.md) for architecture and UI tour
- [USAGE.md](./USAGE.md) for CLI examples
- [INSTALL.md](./INSTALL.md) for install/deployment details
- [API.md](./API.md) for IOCTL/IPC/ETW contract details
