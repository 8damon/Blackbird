<h1 align="center">SLEEPWALKER Alpha</h1>
<p align="center"><b>Kernel Telemetry & Detection Platform for Windows</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/-00599C?logo=c&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/-00599C?logo=c%2B%2B&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/.NET-512BD4?style=for-the-badge" />
  <img src="https://img.shields.io/badge/KMDF-000000?style=for-the-badge" />
  <a href="https://discord.gg/yUWyvT9JyP">
    <img src="https://img.shields.io/discord/1240608336005828668?label=TITAN%20Softworks&logo=discord&color=5865F2&style=for-the-badge" />
  </a>
</p>

<p align="center">
  <img src="./diagram/MAIN_INTERFACE.png" width="980" alt="Sleepwalker main interface" />
</p>

## What Sleepwalker Is For

Sleepwalker is built for:

- malware analysis
- suspicious process investigation
- endpoint telemetry review
- evidence-heavy detection triage

It captures process, thread, handle, image, registry, APC, and detection telemetry, then groups related activity into operator-facing detections and evidence views.

## Why It Exists

Most telemetry tools are good at collecting data and bad at helping an analyst work through it.

Sleepwalker is meant to close that gap:

- the **main operator panel** gives a live view of what matters now
- the **detection chain** groups related events into something reviewable
- the **inspectors** let you drill into the actual evidence when a detection needs validation

The point is not just to log activity. The point is to help an operator move from signal to evidence quickly.

## Main Operator Panel

The main interface is the primary workspace for live triage and session review.

It brings together:

- event timeline
- event log
- ETW activity
- heuristics
- process relations
- backend/session state
- time-travel controls for historical review

This is where an operator attaches to a target, watches activity arrive, and pivots into deeper evidence when something suspicious shows up.

## Detection Chain

The detection chain is the most important investigation view in the platform.

<p align="center">
  <img src="./diagram/DETECTION_CHAIN.png" width="980" alt="Sleepwalker detection chain" />
</p>

It groups detections by event and detection key so the operator can review related activity as a single chain instead of a pile of disconnected records.

This is where Sleepwalker becomes useful instead of just noisy.

The detection chain helps answer:

- what happened
- why it was flagged
- which events belong together
- what evidence supports the detection

From there, the operator can pivot into the raw underlying records and supporting inspectors.

## Evidence Views

When a detection needs validation, Sleepwalker exposes the underlying evidence through dedicated inspectors.

Key views include:

- **ETW Inspector**  
  Review grouped ETW occurrences and inspect enriched event details.

- **Handle Evidence**  
  Inspect suspicious handle activity, access masks, origin context, captured frames, memory region details, and related payload data.

- **Thread Stack**  
  Review stack snapshots during live capture or while moving through historical samples.

- **Process Relations**  
  See actor-to-target relationships such as suspicious opens, remote thread activity, and linked intent chains.

These views exist to support investigation, not decoration. Which is a rare design goal these days.

## Detection Coverage

Representative detections include:

- direct syscall suspect handle activity
- stack integrity anomalies on handle operations
- remote thread creation
- remote thread start in non-image executable memory
- remote thread activity outside the main image
- thread hijack and thread-context abuse
- remote APC creation suspects
- process hollowing and injection intent chains
- suspicious `ntdll` image path or mapping behavior
- multiple `ntdll` image mappings
- high-value registry activity
- driver dispatch or object tamper drift

For the full contract and field-level details, see [API.md](./API.md).

## Architecture

Sleepwalker is split into a few main parts:

- `kernel/`  
  KMDF driver, kernel telemetry, ETW emission, and kernel-side correlation

- `user/controller/`  
  broker/controller service, IPC, ETW handling, and runtime correlation

- `user/sensor/`  
  `SleepwalkerSensorCore.dll`, `SleepwalkerClient.exe`, `SleepwalkerTestSuite.exe`

- `interface/`  
  WPF analyst interface for live capture, time travel, and evidence review

- `abi/`  
  shared IOCTL and IPC contracts

## How It Works

1. The operator selects or launches a target process.
2. The interface talks to `SleepwalkerSensorCore.dll`.
3. The sensor core reaches the controller over broker IPC.
4. The controller owns the driver handle and ETW ingestion path.
5. Telemetry is collected, correlated, and sent back to the interface.
6. The main panel updates live, and the operator can pivot into detections and evidence views.
7. Sessions can be saved, reopened, imported, or exported for later review.

<p align="center">
  <img src="./diagram/SLEEPWALKER_DIA.png" width="980" alt="Sleepwalker detection chain" />
</p>

## Build Outputs

Common projects:

- `vcxproj/Sleepwalker.vcxproj`
- `vcxproj/SleepwalkerController.vcxproj`
- `vcxproj/SleepwalkerSensorCore.vcxproj`
- `vcxproj/SleepwalkerClient.vcxproj`
- `vcxproj/SleepwalkerIoctlTest.vcxproj`
- `interface/SleepwalkerInterface.csproj`

Common runtime artifacts:

- `sleepwlkr.sys`
- `SleepwlkrController.exe`
- `SleepwalkerSensorCore.dll`
- `SleepwalkerClient.exe`
- `SleepwalkerIoctlTest.exe`
- `SleepwalkerInterface.exe`

## Quick Start

See these docs for setup and usage:

- [Getting Started.md](./Getting%20Started.md)
- [INSTALL.md](./INSTALL.md)
- [USAGE.md](./USAGE.md)
- [API.md](./API.md)

## Documentation Map

- [Getting Started.md](./Getting%20Started.md)
- [USAGE.md](./USAGE.md)
- [INSTALL.md](./INSTALL.md)
- [API.md](./API.md)
- [user/sensor/README.md](./user/sensor/README.md)
- [user/controller/core/README.md](./user/controller/core/README.md)
