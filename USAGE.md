# Usage

This is the CLI and operator quick reference for Blackbird beta v1.2.

## Core Runtime Pieces

- `blackbird.sys`
  - KMDF driver
- `BlackbirdController.exe`
  - broker/controller service
- `BlackbirdSensorCore.dll`
  - shared user-mode SDK used by the client tools and interface
- `BlackbirdClient.exe`
  - broker-backed operator CLI
- `BlackbirdTestSuite.exe`
  - validation harness
- `BlackbirdInterface.exe`
  - primary GUI

## BlackbirdClient

`BlackbirdClient.exe` is the main CLI for targeted observation and structured output.

### Syntax

```bat
BlackbirdClient.exe <target> <streams> [scope]
BlackbirdClient.exe path:<full-path-to-target.exe> <streams> [scope]
BlackbirdClient.exe launch:<full-path-to-target.exe> <streams> [scope]
BlackbirdClient.exe --config <policy-file>
```

### Target Forms

- `<pid>`
  - attach to an existing process
- `path:<full-path>`
  - wait for the first matching process path and attach
- `launch:<full-path>`
  - launch, attach, and resume deterministically

### Stream Sets

```text
handle,memory,thread
handle,memory,thread,etw
```

- `handle,memory,thread`
  - IOCTL telemetry
- `handle,memory,thread,etw`
  - IOCTL telemetry plus broker ETW uplink

### Scope

```text
local
remote
both
```

Examples:

```bat
BlackbirdClient.exe 4242 handle,memory,thread
BlackbirdClient.exe 4242 handle,memory,thread,etw both
BlackbirdClient.exe path:C:\Lab\sample.exe handle,memory,thread remote
BlackbirdClient.exe launch:C:\Lab\sample.exe handle,memory,thread
```

### Structured Logging

```bat
BlackbirdClient.exe --log-format jsonl --log-file events.swk.jsonl --high-priority-file high_priority.swk.jsonl --high-priority-min-severity 4 <target> <streams> [scope]
```

### Policy File Mode

```bat
BlackbirdClient.exe --config user\sensor\blackbird_client.policy.example.yaml
```

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

1. `Select Target`
2. confirm choices in `Launch Parameters`
3. review timeline, events, ETW, heuristics, and relations
4. scrub the time-travel slider when needed
5. open `Detection Chain`, `ETW Inspector`, `Handle Evidence`, or `Thread Stack`
6. save/export the session

Notes:

- attaching to a running process cannot use `EarlyBird APC`; that option is only available when launching a new process
- interface command icons are loaded from `interface/Resources/*.png` and embedded automatically by the interface project

## Session Export

The interface can export session data to:

- `.jsonl`
- `.csv`
- `.cef`
- `.attack.csv`
- `.swlkr` / `.blackbird`

## More Detail

- [Getting Started.md](./Getting%20Started.md)
- [README.md](./README.md)
- [INSTALL.md](./INSTALL.md)
- [API.md](./API.md)
- [user/sensor/README.md](./user/sensor/README.md)
