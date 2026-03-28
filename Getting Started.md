# Getting Started

This is the shortest path to a working Blackbird v1.7 lab deployment.

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
- `vcxproj/BlackbirdIoctlTest.vcxproj`
- `vcxproj/BlackbirdInterface.csproj`
- `vcxproj/BlackbirdExamples.vcxproj`

Typical artifacts:

- `x64\<Configuration>\blackbird.sys`
- `x64\<Configuration>\BlackbirdController.exe`
- `x64\<Configuration>\J58.dll`
- `x64\<Configuration>\BlackbirdTestSuite.exe`
- `x64\<Configuration>\DetectionExamples\DetectionExamples.exe`
- `interface\analysis\bin\<Configuration>\net9.0-windows\BlackbirdInterface.exe`

## 3. Install The Driver And Controller

From an elevated shell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\installer.ps1
```

Useful flags:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\installer.ps1 -EnableAntiVirtualization -EnableControllerHiding
```

Check state:

```bat
sc query blackbird
sc query BlackbirdController
```

## 4. Validate The Stack

Run the validation harness before opening the interface:

```bat
.\x64\Debug\BlackbirdTestSuite.exe
```

Expected outcome:

- driver opens cleanly
- broker handshake succeeds
- IOCTL and ETW coverage passes or reports expected optional skips
- runtime/debugger and DetectionExamples smoke checks pass

## 5. Launch The Interface

```bat
.\interface\analysis\bin\Debug\net9.0-windows\BlackbirdInterface.exe
```

The startup window now lets you seed runtime behavior such as:

- anti-virtualization masking
- controller concealment
- interface handle protection
- controller handle protection

## 6. First Operator Workflow

1. Use `Target` to attach to a process or launch a new one.
2. Confirm options in the `Launch Parameters` dialog.
3. Confirm uplink/backend status in the main shell.
4. Watch the timeline, event log, heuristics, ETW, filesystem, and process relations views populate.
5. Open inspectors or `Detection Chain` from grouped telemetry.
6. Use the time-travel slider to move from live view into historical view.
7. Save or export the session when review is complete.

## 7. Detection Examples

The example runner now lives in one dispatcher binary:

```bat
.\x64\Debug\DetectionExamples\DetectionExamples.exe
```

Use it to run detection scenarios and benign baselines. These are intentional trigger cases, not normal operator workflows.

## 8. Common Failure Modes

### `OpenControlDevice failed`

Usually means the interface-side `J58.dll` does not match the running controller/driver ABI, or the controller pipe is unavailable.

### Interface connects but no live data appears

Check:

- target PID is valid
- driver service is running
- controller is running
- target exited before sampling began
- launch parameters disabled the path you expected to use

## 9. Where To Go Next

- [README.md](./README.md)
- [INSTALL.md](./INSTALL.md)
- [USAGE.md](./USAGE.md)
- [API.md](./API.md)