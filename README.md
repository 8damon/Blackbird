<h1 align="center">BLACKBIRD Beta v1.2</h1>
<p align="center"><b>DFIR Kernel Telemetry & Detection Platform for Windows</b></p>

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
  <img src="./diagram/MAIN_INTERFACE.png.png" width="980" alt="Blackbird main interface" />
</p>

## What Blackbird Is For

Blackbird is built for:

- malware analysis
- suspicious process investigation
- endpoint telemetry review
- evidence-heavy detection triage

It captures process, file, thread, handle, image, registry, network, APC, and detection telemetry, then groups related activity into operator-facing detections and evidence views.

## Why It Exists

Most telemetry tools are good at collecting data and bad at helping an analyst work through it.

Blackbird is meant to close that gap:

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
- file access
- backend/session state
- time-travel controls for historical review
- resource usage
- network monitoring

This is where an operator attaches to a target, watches activity arrive, and pivots into deeper evidence when something suspicious shows up.

Operator UX behavior in this panel:

- timeline timestamps stay layered above event markers for readability
- horizontal timeline scrubber tracks true latest-event position during live follow
- timeline event selection stays synced with the event log grid and persists across live updates when the event remains in-view

## Detection Chain

The detection chain is the most important investigation view in the platform.

<p align="center">
  <img src="./diagram/DETECTION_CHAIN.png" width="980" alt="Blackbird detection chain" />
</p>

It groups detections by event and detection key so the operator can review related activity as a single chain instead of a pile of disconnected records.

This is where Blackbird becomes useful instead of just noisy.

The detection chain helps answer:

- what happened
- why it was flagged
- which events belong together
- what evidence supports the detection

From there, the operator can pivot into the raw underlying records and supporting inspectors.

## Evidence Views

When a detection needs validation, Blackbird exposes the underlying evidence through dedicated inspectors.

Key views include:

- **ETW Inspector**  
  Review grouped ETW occurrences and inspect enriched event details.

- **Handle Evidence**  
  Inspect suspicious handle activity, access masks, origin context, captured frames, memory region details, and related payload data.

- **Thread Stack**  
  Review stack snapshots during live capture or while moving through historical samples.

- **Process Relations**  
  See actor-to-target relationships such as suspicious opens, remote thread activity, and linked intent chains.

- **File Inpsector**
  See files accessed and created by the target.

These views exist to support investigation, not decoration. Which is a rare design goal these days.

## Detection Coverage

Representative detections include:

- direct syscall suspect handle activity
- file opens, reads, creations, special attributes
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

Blackbird is split into a few main parts:

- `kernel/`  
  KMDF driver, kernel telemetry, ETW emission, and kernel-side correlation

- `user/controller/`  
  broker/controller service, IPC, ETW handling, and runtime correlation

- `user/sensor/`  
  `BlackbirdSensorCore.dll`, `BlackbirdClient.exe`, `BlackbirdTestSuite.exe`

- `interface/`  
  WPF analyst interface for live capture, time travel, and evidence review

- `abi/`  
  shared IOCTL and IPC contracts

## How It Works

1. The operator selects or launches a target process.
2. The interface talks to `BlackbirdSensorCore.dll`.
3. The sensor core reaches the controller over broker IPC.
4. The controller owns the driver handle and ETW ingestion path.
5. Telemetry is collected, correlated, and sent back to the interface.
6. The main panel updates live, and the operator can pivot into detections and evidence views.
7. Sessions can be saved, reopened, imported, or exported for later review.

<p align="center">
  <img src="./diagram/Blackbird_DIA.png" width="980" alt="Blackbird platform diagram" />
</p>

## Build Outputs

Common projects:

- `vcxproj/Blackbird.vcxproj`
- `vcxproj/BlackbirdController.vcxproj`
- `vcxproj/BlackbirdSensorCore.vcxproj`
- `vcxproj/BlackbirdClient.vcxproj`
- `vcxproj/BlackbirdIoctlTest.vcxproj`
- `interface/BlackbirdInterface.csproj`

Common runtime artifacts:

- `blackbird.sys`
- `BlackbirdController.exe`
- `BlackbirdSensorCore.dll`
- `BlackbirdClient.exe`
- `BlackbirdTestSuite.exe`
- `BlackbirdInterface.exe`

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
