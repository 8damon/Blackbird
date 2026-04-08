# Security Policy

## Overview

**Blackbird** is a Windows kernel-mode telemetry and analysis sensor designed for malware detonation in isolated guest VMs. Its primary security objective is strong **guest-to-host isolation**: a compromise of the guest VM (or of Blackbird itself) must **not** provide a path to VM escape, host code execution, host filesystem access outside approved channels, or degradation of the host/hypervisor.

We take security seriously and maintain a formal threat model (STRIDE-based) and an adapted Microsoft SDL process.

- [Threat Model (STRIDE per component, trust boundaries, residual risks)](https://docs.titansoftwork.com/blackbird/#security/threat-model)
- [Secure Development Lifecycle (SDL) assessment and action items](https://docs.titansoftwork.com/blackbird/#security/sdl)

## Supported Versions

We provide security updates for the latest stable release and the immediately preceding minor version. Older versions may receive limited support only for critical issues.

See the [Releases page](https://github.com/8damon/blackbird/releases) for version history.

## Reporting a Vulnerability

If you discover a potential security vulnerability in Blackbird (kernel driver, usermode components, IPC, operator protocol, or deployment model), please report it **privately** so we can investigate and coordinate disclosure.

**Preferred reporting method:**  
Email us at **[security@titansoftwork.com](mailto:security@titansoftwork.com)**.

Please include as much of the following as possible:

- Description of the vulnerability and its potential impact (e.g., kernel EoP, privesc, info disclosure, guest-to-host escape path, tampering of session archives, etc.)
- Affected component(s) and version(s)
- Steps to reproduce
- Any proof-of-concept or logs (avoid sending full exploits in the initial email if possible)
- Reference to relevant parts of the [threat model](https://docs.titansoftwork.com/blackbird/#security/threat-model) or [SDL](https://docs.titansoftwork.com/blackbird/#security/sdl) if applicable

We also support **GitHub Private Vulnerability Reporting** (recommended for researchers who prefer the GitHub interface). This creates a private draft security advisory that only repository maintainers can see.

### What to Expect

- **Acknowledgment**: We aim to acknowledge valid reports within **72 hours**.
- **Triage & Updates**: We will provide regular status updates (typically every 7–14 days depending on severity).
- **Fix Timeline**: Critical issues will be addressed with high priority. We target a patch within **30–90 days** depending on complexity, followed by coordinated public disclosure.
- **Credit**: We will credit reporters in the advisory and release notes unless you prefer to remain anonymous.

We follow **coordinated responsible disclosure**: we will not publish details until a fix is available and you have agreed on the timeline.

## Security Advisories & CVEs

When a confirmed vulnerability is fixed, we will publish a **GitHub Security Advisory**. This may include:
- CVE-ID assignment
- Description of the issue and impact
- Affected / patched versions
- Mitigation or workaround steps
- Link back to the threat model for context

## Questions or Non-Security Issues

For general questions, feature requests, or non-vulnerability bug reports, please use the repository's Issues or Discussions.
