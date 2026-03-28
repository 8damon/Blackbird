# Usage

This is the CLI and operator quick reference for Blackbird v1.5.

## Core Runtime Pieces

- `blackbird.sys`
  - KMDF driver
- `BlackbirdController.exe`
  - broker/controller service
- `J58.dll`
  - shared user-mode SDK used by the controller, test suite, and interface-side integration
- `BlackbirdTestSuite.exe`
  - validation harness
- `BlackbirdInterface.exe`
  - primary GUI

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
- multi-client fanout
- deep-path enrichment and capture-backed evidence fields

### Useful Runtime Knobs

```bat
set BLACKBIRD_TEST_BROKER_PIPE=\\.\pipe\<name>
set BLACKBIRD_TEST_REQUIRE_KERNEL_CORRELATION=1
set BLACKBIRD_TEST_REQUIRE_APC=1
```

## Controller Service

Install or update:

```powershell
powershell -ExecutionPolicy Bypass -File .\usage\install-controller-service.ps1
```

Remove:

```powershell
powershell -ExecutionPolicy Bypass -File .\usage\install-controller-service.ps1 -Uninstall
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

Main workflow:

1. `Target`
2. confirm choices in `Launch Parameters`
3. review the timeline, events, ETW, heuristics, filesystem, and relations views
4. scrub the time-travel slider when needed
5. open `Detection Chain`, `ETW Inspector`, `Handle Evidence`, `Thread Stack`, `Child Process Graph`, or `Diagnostics Cockpit`
6. save/export the session

Notes:

- attaching to a running process cannot use `EarlyBird APC`; that option is only available when launching a new process
- interface command icons are loaded from `interface/Resources/*.png` and embedded automatically by the interface project

## Session Export

The interface can export session data to:

- `.bkcap`
- `.jsonl`
- `.csv`
- `.cef`
- `.attack.csv`

The interface can still open/import legacy `.swlkr` and `.blackbird` bundles.

## More Detail

- [Getting Started.md](./Getting%20Started.md)
- [README.md](./README.md)
- [INSTALL.md](./INSTALL.md)
- [API.md](./API.md)
- [user/sensor/README.md](./user/sensor/README.md)


