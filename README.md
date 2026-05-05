<h1 align="center">BLACKBIRD</h1>
<p align="center"><b>A defensive software reverse-engineering (SRE) / IDS and real-time malware analysis platform</b></p>

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

Blackbird is an on-prem defensive software reverse-engineering (SRE) / IDS-style malware analysis platform designed for samples that evade conventional sandboxes. It combines targeted kernel instrumentation, early usermode sensors, anti-evasion controls, ETW/IOCTL capture, behavioral correlation, and portable capture files so security teams can run malware safely inside managed VMs without sending data to a third party.

Blackbird is intended for authorized security research, malware reverse engineering, incident response, detection engineering, and controlled lab analysis. It is not provided as offensive tooling, malware, an intrusion platform, a remote access capability, or a cyber weapon. Some components necessarily use low-level kernel monitoring, usermode instrumentation, process-control, and protected telemetry paths so that analysts can observe hostile samples; those mechanisms must only be used in isolated environments and on systems you own or are explicitly authorized to test.

Public visibility of this repository does not grant permission to use Blackbird against third-party systems, to develop or validate evasion for unauthorized activity, to bypass security controls outside a defensive lab, or to conduct offensive cyber operations. Users are responsible for complying with applicable law, export-control rules, organizational policy, and any permit or authorization requirements before using, modifying, distributing, or publishing derivative work.

The public repository is the local defensive analysis stack. Remote node service/server code, WFP endpoint protection, active bugcheck monitoring, secondary crash-dump callback code, and external third-party rule packs are private optional extensions unless explicitly included in a release.

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
- Memory analyzer & Disassembler
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
- Optional private remote control via the self-hosted server
- Optional private self-hosted server for VM enrollment, node inventory, artifact jobs, captures, RBAC, SSO, and audit

## BUGS & ENHANCEMENTS

Please use [this](https://github.com/users/8damon/projects/3) project board to open issues & enhancements. This also loosely tracks live-development.

## DOCUMENTATION

The introduction, installation, architecture, security, optional server operations, and UI manual are provided here:

- [Blackbird Docs](https://docs.titansoftwork.com/blackbird/)
- Local engineering docs under `Docs/` when included in an internal working tree
- Private self-hosted server docs when the optional server tree is included

Session archives are stored as `.bkcap` (SQLite + LZ4). Detections can be exported as SIEM JSON Lines, Splunk HEC JSON, Elastic ECS NDJSON, CEF, or CSV. Detection reference scenarios are in `DetectionExamples.exe`.

## COMPILATION

You need **Visual Studio 2022+** with **Windows Driver Kit (WDK)** and **.NET (Desktop Development)**.

Clone Blackbird:

``git clone https://github.com/8damon/Blackbird``

Open the ``Blackbird.slnx`` file & select ``Release`` & build.

## KNOWN ISSUES

- The optional private self-hosted server and operator transport use the secure node command channel. Discovery/status metadata is not identity proof; secure control requires pinned node identity and VM enrollment/trusted operator fingerprints.

- Rules Intel supports local rule evaluation, MITRE attribution where available, and memory/page sample scanning in the analysis interface. External third-party rule packs are not part of the public tree until reviewed.

- Some executables when launched present with `ERROR_BAD_IMPERSONATION_LEVEL (1346)`, this is a known bug and the root cause is being identified.

- "Uplink Failed" / "Service Not Found", this is due to you not running the installer script `Scripts\installer.ps1`, which installs and starts the driver and controller services.

- Memory attribution is heuristic when direct allocator telemetry is unavailable. Thread execution through a region is shown as an ownership clue, not definitive ownership proof.

> [!NOTE]
> Some instability or unexpected behavior may occur due to the low-level nature of the platform. This is expected during development.
