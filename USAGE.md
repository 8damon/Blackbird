# Usage

This is the operator and tooling quick reference for Blackbird v1.7.

## Core Runtime Pieces

- `blackbird.sys`: KMDF driver
- `BlackbirdController.exe`: broker/controller service
- `J58.dll`: shared user-mode SDK
- `SR71.dll`: target-side hook/instrumentation DLL
- `BlackbirdTestSuite.exe`: validation harness
- `BlackbirdInterface.exe`: analyst GUI
- `DetectionExamples.exe`: detection and benign scenario runner

## BlackbirdTestSuite

`BlackbirdTestSuite.exe` is the end-to-end validation harness.

### Run

```bat
BlackbirdTestSuite.exe
```

### What It Checks

- broker handshake
- driver open path
- IOCTL subscription and event delivery
- grouped telemetry and detection surfaces
- ETW family coverage
- runtime/debugger concealment
- `DetectionExamples --list` smoke

## Controller Service

Install or update:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\installer.ps1
```

Remove:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\remover.ps1
```

Check status:

```bat
sc query BlackbirdController
```

## Interface

Launch the GUI after the driver and controller are up:

```bat
BlackbirdInterface.exe
```

Startup/runtime toggles now include:

- anti-virtualization masking
- controller concealment
- interface handle protection
- controller handle protection

If the interface launched the target, closing the interface now terminates that launch-owned target.

## Detection Examples

Run the dispatcher with no arguments for the interactive menu:

```bat
DetectionExamples.exe
```

Other useful modes:

```bat
DetectionExamples.exe --list
DetectionExamples.exe --run <scenario>
DetectionExamples.exe --run-all-detection
DetectionExamples.exe --run-all-benign
```

These scenarios are deliberate trigger and baseline cases used to validate detections and false-positive behavior.

## Session Export

The interface can export session data to:

- `.bkcap`
- `.jsonl`
- `.csv`
- `.cef`
- `.attack.csv`

Legacy `.swlkr` and `.blackbird` bundles can still be opened/imported.

## More Detail

- [Getting Started.md](./Getting%20Started.md)
- [README.md](./README.md)
- [INSTALL.md](./INSTALL.md)
- [API.md](./API.md)
- [user/sensor/README.md](./user/sensor/README.md)