<h1 align="center">Stinger</h1>
<p align="center"><b>Kernel Telemetry Driver for Forensic and Malware Analysis</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-C-00599C?logo=c&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/Framework-KMDF-0A0A0A?style=for-the-badge" />
</p>

## Current Revision

- Doc/API revision date: `2026-02-22`
- IOCTL streams: `HANDLE`, `MEMORY`, `THREAD`
- ETW event families: `HandleTelemetry`, `ThreadTelemetry`, `ProcessTelemetry`, `ImageTelemetry`, `RegistryTelemetry`, `DetectionTelemetry`
- Validation harness: `StingerTestSuite.exe` (IOCTL + ETW + multi-client fanout)

## Core Capabilities

- Process-scoped, per-client IOCTL subscriptions on `\\.\Global\StingerCtl` / `\\.\StingerCtl`.
- Handle telemetry with origin address, protection, path, status fields, and stack frames.
- Thread telemetry with start-address and image-range heuristics plus handle-intent correlation flags.
- Additional ETW-only surfaces for process, image-load, registry activity, and detection events.
- Per-client queueing with sequence counters, queue depth, and dropped-event stats.
- Rate-limited debug tracing for queue drops and monitor callback failures in debug builds.

## Repository Layout

- `kernel/`
  - `core/`: driver lifecycle and IOCTL control plane
  - `monitors/`: handle/thread/process/image/registry monitors and intent correlation
  - `telemetry/`: ETW provider emitters
- `abi/`
  - `stinger_ioctl.h`: shared IOCTL ABI
- `user/sensor/`
  - `stinger_client.c`: manual IOCTL subscriber
  - `stinger_ioctl_test.c`: `StingerTestSuite` source
  - `stinger_sensor.c`: ETW real-time consumer (`StingerEtwProc`)
- `vcxproj/`
  - `Stinger.vcxproj`: kernel driver
  - `StingerClient.vcxproj`: IOCTL client
  - `StingerIoctlTest.vcxproj`: `StingerTestSuite` binary
  - `StingerEtwProc.vcxproj`: ETW console consumer

## Build and Run

1. Open `Stinger.slnx` in Visual Studio.
2. Build `vcxproj/Stinger.vcxproj` for your target (`x64` or `ARM64`).
3. Install/start the driver.
4. Build and run tools:
   - `StingerTestSuite.exe` for end-to-end validation.
   - `StingerClient.exe <pid> handle,memory,thread` for targeted IOCTL consumption.
   - `StingerEtwProc.exe` for enriched ETW output.

## Documentation

- `INSTALL.md`: install/run workflow
- `API.md`: IOCTL and ETW contract reference
- `user/sensor/README.md`: user-mode tool usage and symbol guidance
