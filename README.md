<h1 align="center">BLACKBIRD COMMUNITY</h1>
<p align="center"><b>Community edition of the Blackbird real-time malware analysis platform (RTMA), software reverse-engineering (SRE) suite and Intrusion Detection System (IDS).</b></p>

<p align="center">
  <a href="https://titansoftwork.com/capability/blackbird/download/">
    <img src="https://img.shields.io/badge/Download-3C8D40?style=for-the-badge&logo=microsoft&logoColor=white" />
  </a>
  <a href="https://titansoftwork.com/blackbird">
    <img src="https://img.shields.io/badge/Website-0A0A0A?style=for-the-badge&logo=google-chrome&logoColor=white" />
  </a>
  <a href="https://github.com/users/8damon/projects/3/views/1">
    <img src="https://img.shields.io/badge/Project%20Board-6B7280?style=for-the-badge&logo=githubprojects&logoColor=white" />
  </a>
  <img src="https://img.shields.io/badge/.NET-512BD4?style=for-the-badge" />
  <img src="https://img.shields.io/badge/KMDF-000000?style=for-the-badge" />
  <img src="https://img.shields.io/badge/-00599C?logo=c&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/-00599C?logo=c%2B%2B&logoColor=white&style=for-the-badge" />
</p>

<p align="center">
  <img src="https://titansoftwork.com/content/capabilities/blackbird/MAIN_INTERFACE.png" width="980" alt="Blackbird main interface" />
</p>

## REQUIREMENTS

A virtual machine on Windows 10 22H2 or higher, 64-bit.

> [!IMPORTANT]
> Blackbird performs kernel-level instrumentation and may affect system stability depending on configuration.
> Always use it within a controlled virtual machine environment and not on systems containing important data.

## FEATURES

- Fully fledged analysis interface
- Kernel-backed
- Integrated heuristics & detections
- Detailed overview and inspection of process-activity
- WPA-like event-viewing graph
- Target execution control
- Target API hooking
- API call analyzer & graph
- API call argument observation
- Full symbol resolution
- Thread & Thread-stack analyzers
- Process memory attribution telemetry
- Registry activity overview
- File activity overview
- Process-relations & child processes overview
- Handles overview
- Network overview
- ETW overview
- COM overview
- Performance analytics
- Configurable/importable local rules with SIEM detection exports
- Diagnostics suite

Community includes the shared local capture and detection pipeline. Enterprise
adds BlackbirdVisor/hypervisor control, NetSvc/server orchestration, the full
memory inspector and disassembly workbench, WFP callout support, and active
bugcheck/crash-payload extensions.

## BUGS & ENHANCEMENTS

Please use [this](https://github.com/users/8damon/projects/3) project board to open issues & enhancements. This also loosely tracks live-development.

## DOCUMENTATION

The public local-stack introduction, installation, architecture, security notes,
and UI manual are provided here:

- [Blackbird Docs](https://docs.titansoftwork.com/blackbird/)

Session archives are stored as `.bkcap` (SQLite + LZ4). Detections can be exported as SIEM JSON Lines, Splunk HEC JSON, Elastic ECS NDJSON, CEF, or CSV. Detection reference scenarios are in `DetectionExamples.exe`.

## COMPILATION

You need **Visual Studio 2022+** with **Windows Driver Kit (WDK)** and **.NET (Desktop Development)**.

Clone Blackbird:

``git clone https://github.com/8damon/Blackbird``

Open the ``Blackbird.slnx`` file & select ``Release`` & build.

## KNOWN ISSUES

- Rules Intel supports local rule evaluation, MITRE attribution where available, and memory/page sample scanning in the analysis interface. External third-party rule packs are not part of the public tree until reviewed.

- Some executables when launched present with `ERROR_BAD_IMPERSONATION_LEVEL (1346)`, this is a known bug and the root cause is being identified.

- "Uplink Failed" / "Service Not Found", this is due to you not running the installer script `Scripts\IsolatedInstaller.ps1`, which installs and starts the driver and controller services.

- Memory attribution is heuristic when direct allocator telemetry is unavailable. Thread execution through a region is shown as an ownership clue, not definitive ownership proof.

- Raw telemetry can appear before a protected launch is resumed. Detection
  promotion is gated until resume so SR71 staging, launch-gate/TLS traps, OS
  broker startup, console setup, and WER activity do not appear as target-authored
  injection.

> [!NOTE]
> Some instability or unexpected behavior may occur due to the low-level nature of the platform. This is expected during development.
