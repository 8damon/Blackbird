# Usage

This is the CLI and operator quick reference for the current Sleepwalker alpha.

## Core Runtime Pieces

- `sleepwlkr.sys`
  - KMDF driver
- `SleepwlkrController.exe`
  - broker/controller service
- `SleepwalkerSensorCore.dll`
  - shared user-mode SDK used by the client tools and interface
- `SleepwalkerClient.exe`
  - broker-backed operator CLI
- `SleepwalkerIoctlTest.exe`
  - validation harness
- `SleepwalkerInterface.exe`
  - primary GUI

## SleepwalkerClient

`SleepwalkerClient.exe` is the main CLI for targeted observation and structured output.

### Syntax

```bat
SleepwalkerClient.exe <target> <streams> [scope]
SleepwalkerClient.exe path:<full-path-to-target.exe> <streams> [scope]
SleepwalkerClient.exe launch:<full-path-to-target.exe> <streams> [scope]
SleepwalkerClient.exe --config <policy-file>
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
SleepwalkerClient.exe 4242 handle,memory,thread
SleepwalkerClient.exe 4242 handle,memory,thread,etw both
SleepwalkerClient.exe path:C:\Lab\sample.exe handle,memory,thread remote
SleepwalkerClient.exe launch:C:\Lab\sample.exe handle,memory,thread
```

### Structured Logging

```bat
SleepwalkerClient.exe --log-format jsonl --log-file events.swk.jsonl --high-priority-file high_priority.swk.jsonl --high-priority-min-severity 4 <target> <streams> [scope]
```

### Policy File Mode

```bat
SleepwalkerClient.exe --config user\sensor\sleepwalker_client.policy.example.yaml
```

## SleepwalkerIoctlTest

`SleepwalkerIoctlTest.exe` is the end-to-end validation harness.

### Run

```bat
SleepwalkerIoctlTest.exe
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
set SLEEPWALKER_TEST_BROKER_PIPE=\\.\pipe\<name>
set SLEEPWALKER_TEST_REQUIRE_KERNEL_CORRELATION=1
set SLEEPWALKER_TEST_REQUIRE_APC=1
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
sc query SleepwlkrController
```

## Interface

Launch the GUI after the driver and controller are up:

```bat
SleepwalkerInterface.exe
```

Main workflow:

1. `Select Target`
2. review timeline, events, ETW, heuristics, and relations
3. scrub the time-travel slider when needed
4. open `Detection Chain`, `ETW Inspector`, `Handle Evidence`, or `Thread Stack`
5. save/export the session

## Session Export

The interface can export session data to:

- `.jsonl`
- `.csv`
- `.cef`
- `.attack.csv`
- `.swlkr` / `.sleepwlkr`

## More Detail

- [Getting Started.md](./Getting%20Started.md)
- [README.md](./README.md)
- [INSTALL.md](./INSTALL.md)
- [API.md](./API.md)
- [user/sensor/README.md](./user/sensor/README.md)
