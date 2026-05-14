<h1 align="center">BLACKBIRD</h1>

<p align="center"><b>A powerful, instrumentable, real-time malware analysis platform, software reverse-engineering suite & IDS.</b></p>

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
<p align="center">
  <img src="https://titansoftwork.com/content/capabilities/blackbird/MAIN_ALT.png" width="980" alt="Blackbird main interface" />
</p>

## REQUIREMENTS

A virtual machine on Windows 10 22H2 or higher, 64-bit.

> [!IMPORTANT]
> Blackbird performs kernel-level instrumentation and may affect system stability depending on configuration.
> Always use it within a controlled virtual machine environment and not on systems containing important data.

## FEATURES

- Full local analysis interface for malware detonation, reverse engineering, and triage
- Kernel-backed capture for process, thread, image, handle, memory, registry, filesystem, network, ETW, and timing telemetry
- Target launch and attach workflows for EXE and DLL subjects, including suspended launch, deferred resume, and execution control
- SR71 usermode instrumentation with launch-gate readiness, hook-health reporting, stack capture, and hook-integrity diagnostics
- Usermode API telemetry for NT, module, and Winsock activity, with API call graphs, argument observation, caller attribution, and symbol resolution
- Memory attribution for allocation, protection, write, section-map, unmap, and thread-execution evidence
- Memory behavior detections for executable allocation, remote memory activity, repeated protection flips, high-entropy regions, and unpacking/packer indicators
- Integrated heuristics and detection views with process relations, child process tracking, handles, registry, file, network, ETW, COM, and performance panes
- Thread and thread-stack analyzers with observed hook stacks and fallback stack snapshots where available
- Rules Intel for local Sigma/YARA-style rules, including file, page, memory-sample, and process-memory YARA scans
- Automatic Signature Intel enrichment on launch, memory events, direct-syscall traits, page samples, and target-process scan triggers
- Session capture archives (`.bkcap`) with detection export formats for JSON Lines, Splunk HEC JSON, Elastic ECS NDJSON, CEF, and CSV
- Local diagnostics and preflight checks for controller, driver, hook DLL, hook ingest, ETW, service state, and runtime integrity

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

> [!NOTE]
> Some instability or unexpected behavior may occur due to the low-level nature of the platform. This is expected during development.
