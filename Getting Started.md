# Getting Started

This guide is the shortest path to a working Blackbird beta v1.2 deployment in a lab or VM.

## 1. Prerequisites

- Windows analysis VM
- administrative shell
- Visual Studio with WDK/KMDF tooling
- test-signing enabled if you are using a non-production certificate

## 2. Build The Components

Build these projects:

- `vcxproj/Blackbird.vcxproj`
- `vcxproj/BlackbirdController.vcxproj`
- `vcxproj/BlackbirdSensorCore.vcxproj`
- `vcxproj/BlackbirdClient.vcxproj`
- `vcxproj/BlackbirdIoctlTest.vcxproj`
- `interface/BlackbirdInterface.csproj`

Typical artifacts:

- `x64\<Configuration>\blackbird.sys`
- `x64\<Configuration>\BlackbirdController.exe`
- `x64\<Configuration>\BlackbirdSensorCore.dll`
- `x64\<Configuration>\BlackbirdClient.exe`
- `x64\<Configuration>\BlackbirdTestSuite.exe`
- `interface\bin\<Configuration>\net9.0-windows\BlackbirdInterface.exe`

## 3. Install And Start The Driver

From an elevated shell:

```bat
pnputil /add-driver "Blackbird.inf" /install
sc start blackbird
```

Check state:

```bat
sc query blackbird
```

## 4. Install And Start The Controller

Recommended service install:

```powershell
powershell -ExecutionPolicy Bypass -File .\usage\install-controller-service.ps1
sc query BlackbirdController
```

If you are iterating quickly, you can also run `BlackbirdController.exe` directly in your VM instead of installing it as a service.

## 5. Validate The Stack

Run the validation harness before opening the interface:

```bat
.\x64\Debug\BlackbirdTestSuite.exe
```

Expected outcome:

- driver opens cleanly
- broker handshake succeeds
- IOCTL and ETW test coverage passes or reports expected optional skips

## 6. Launch The Interface

Start:

```bat
.\interface\bin\Debug\net9.0-windows\BlackbirdInterface.exe
```

If you deployed the interface output somewhere else, make sure `BlackbirdSensorCore.dll` beside the interface is from the same build as the controller.

## 7. First Operator Workflow

1. Use `Select Target` to attach to a process or launch a new one.
2. Confirm options in the `Launch Parameters` dialog.
3. Confirm uplink/backend status in the main shell.
4. Watch the timeline, event log, heuristics, and ETW panes populate.
5. Open `Detection Chain` or an inspector by double-clicking grouped telemetry.
6. Use the time-travel slider to move from live view into historical view.
7. Open `Thread Stack` or `Handle Evidence` when you need capture-time context.
8. Save or export the session when the review is complete.

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

Usually means the interface-side `BlackbirdSensorCore.dll` does not match the running controller ABI, or the broker dropped the pipe during handshake.

### Interface connects but no live data appears

Check:

- target PID is valid
- driver service is running
- controller is using the expected broker/service protocol
- target exited before sampling began
- `Launch Parameters` disabled hooks or selected an attach-only mode where `EarlyBird APC` is unavailable

### Time travel shows `No data`

That is expected if you scrub to a point with no captured sample for memory or thread-stack history.

## 10. Where To Go Next

- [README.md](./README.md) for architecture and UI tour
- [USAGE.md](./USAGE.md) for CLI examples
- [INSTALL.md](./INSTALL.md) for install/deployment details
- [API.md](./API.md) for IOCTL/IPC/ETW contract details
