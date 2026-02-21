<h1 align="center">Stinger</h1>
<p align="center"><b>Kernel Telemetry Driver for Malware Analysis</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-C-00599C?logo=c&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/Framework-KMDF-0A0A0A?style=for-the-badge" />
</p>

## Operatives

- Captures high-value process/thread telemetry from kernel context.
- Supports targeted IOCTL subscriptions for mission-specific monitoring.
- Exposes ETW output for integration into analyst workflows and SIEM-style pipelines.
- Built for defensive research labs, reverse-engineering teams, and contractor-grade security operations.

## Core Capabilities

- Process-scoped subscription model (`\\.\StingerCtl`).
- Handle telemetry with origin context and stack frame capture.
- Thread creation telemetry with start-address/image-range heuristics.
- Per-client queueing, sequence tracking, and stats reporting.
- Read-only ETW provider: `Stinger.Kernel`.

## Repository Layout

- `kernel/`
  - `core/`: driver lifecycle and IOCTL control plane
  - `monitors/`: handle/thread monitoring logic
  - `telemetry/`: ETW provider emitters
- `abi/`
  - `stinger_ioctl.h`: shared ABI contract for kernel and user-mode clients
- `user/sensor/`
  - `stinger_client.c`: operator IOCTL subscriber
  - `stinger_ioctl_test.c`: IOCTL smoke/integration test
  - `stinger_sensor.c`: ETW real-time consumer
- `projects/`
  - `Stinger.vcxproj`: kernel driver
  - `StingerClient.vcxproj`: user-mode IOCTL client
  - `StingerIoctlTest.vcxproj`: IOCTL validation harness
  - `StingerEtwProc.vcxproj`: ETW consumer

## Build and Run

1. Open `Stinger.slnx` in Visual Studio.
2. Build `projects/Stinger.vcxproj` (x64).
3. Install/start the driver in your VM.
4. Build and run:
   - `StingerIoctlTest.exe` for health validation.
   - `StingerClient.exe <pid> handle,memory,thread` for targeted operations.
   - `StingerEtwProc.exe` for ETW stream monitoring.

## Documentation

- `INSTALL.md`: installation and execution workflow
- `API.md`: IOCTL and event contract
- `user/sensor/README.md`: user-mode tool details
