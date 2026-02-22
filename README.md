<h1 align="center">Stinger</h1>
<p align="center"><b>Kernel Telemetry Driver for Threat Detection, Malware Analysis, Forensics & Threat-Emulation</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-C-00599C?logo=c&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/Framework-KMDF-0A0A0A?style=for-the-badge" />
</p>

## What Is Stinger?

Stinger is a Windows kernel telemetry driver and companion user-mode tooling that captures high-value execution signals for malware analysis and threat triage.  
It focuses on behavior that often appears in process injection and post-exploitation workflows:

- Sensitive process/thread handle operations
- Remote thread activity and start-address heuristics
- Process and image lifecycle context
- High-value registry path activity
- Correlated detection events tying intent to execution

## Why Stinger Was Written

Many teams have one of two options:

- Raw telemetry that is too noisy and hard to operationalize quickly
- High-level detections that hide low-level context analysts need to verify intent

Stinger is designed to bridge that gap by emitting telemetry that is:

- Low enough level to preserve forensic context (addresses, access masks, call stacks)
- Structured enough to consume in tools and tests
- Focused on a narrow, high-signal threat surface instead of broad indiscriminate logging

## What Problem It Helps Solve

Stinger helps teams answer questions such as:

- Which process opened another process/thread, with what access rights, and from where?
- Was a thread created remotely, and did its start address look suspicious relative to image boundaries?
- Was there recent handle intent (process memory, thread context, duplicate handle) before thread activity?
- Was high-value persistence-oriented registry activity observed in the same run?

## How Stinger Works (High Level)

1. Kernel monitors capture events from process, image, registry, handle, and thread paths.
2. Handle and thread paths produce IOCTL-deliverable records for subscribed clients.
3. All monitor families emit ETW events through `Stinger.Kernel`.
4. Correlation logic links recent handle intent to later thread activity.
5. Detection telemetry is emitted when heuristics indicate suspicious combinations.
6. User-mode tools consume either:
   - IOCTL queue (`StingerClient`, `StingerTestSuite`)
   - ETW stream (`StingerEtwProc`, `StingerTestSuite`)

## Core Capabilities

- Process-scoped, per-client IOCTL subscriptions on `\\.\Global\StingerCtl` / `\\.\StingerCtl`
- Handle telemetry with origin address, protection, path, status fields, and stack frames
- Thread telemetry with:
  - remote creator checks
  - start-address and image-range heuristics
  - intent correlation flags
  - start-region execution context
- ETW telemetry for process, image, registry, and detection surfaces
- Rate-limited debug tracing for queue drops and callback/monitor failure conditions
- Multi-client IOCTL fanout validation in `StingerTestSuite`

## Repository Layout

- `kernel/`
  - `core/`: driver lifecycle and IOCTL control plane
  - `monitors/`: handle/thread/process/image/registry monitoring and intent correlation
  - `telemetry/`: ETW provider emission
- `abi/`
  - `stinger_ioctl.h`: shared IOCTL ABI
- `user/sensor/`
  - `stinger_client.c`: manual IOCTL subscriber
  - `stinger_ioctl_test.c`: `StingerTestSuite` source
  - `stinger_sensor.c`: ETW consumer (`StingerEtwProc`)
- `vcxproj/`
  - `Stinger.vcxproj`: kernel driver
  - `StingerClient.vcxproj`: IOCTL client
  - `StingerIoctlTest.vcxproj`: `StingerTestSuite` binary
  - `StingerEtwProc.vcxproj`: ETW consumer

## Build and Run

1. Open `Stinger.slnx` in Visual Studio.
2. Build `vcxproj/Stinger.vcxproj` (`x64` or `ARM64` as needed).
3. Install and start the driver.
4. Build and run:
   - `StingerTestSuite.exe` for end-to-end validation and coverage checks
   - `StingerClient.exe <pid> handle,memory,thread` for focused IOCTL consumption
   - `StingerEtwProc.exe` for enriched ETW output

## Example Validation Outcome

Successful full-surface run pattern:

- `[OK] StingerTestSuite complete. tests-passed=33/33 polls=15`
- Includes verification of:
  - IOCTL core paths
  - intent/correlation flags
  - multi-client parallel fanout
  - ETW core families (`handle/thread/process/image/registry/detection`)

## Security and Scope Notes

- Control device ACL is restricted (`SYSTEM` and `Administrators`)
- IOCTL control path accepts user-mode callers only
- Stinger is telemetry and detection aid, not a prevention/response platform by itself
- Kernel stack symbol resolution depends on symbol availability and environment policy

## Documentation

- `INSTALL.md`: installation and runtime workflow
- `API.md`: IOCTL + ETW contract and usage guide
- `user/sensor/README.md`: user-mode tool details
