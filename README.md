Hi, It's been a while...

*Here are some previews from 11/17/2026 (latest). Everything in the attachments shown is real data produced by Blackbird and synthesized by Blackbird's infrastructure. This is a pre-alpha version of Blackbird.*

<img width="2243" height="1354" alt="brave-SIKU_D17-M11-Y2026_7bad78788" src="https://github.com/user-attachments/assets/fb2ec324-6f73-4053-a5b7-3c43b5f4b014" />
<img width="2243" height="1354" alt="brave-SIKU_D17-M11-Y2026_2aa3dd4ee" src="https://github.com/user-attachments/assets/cf6dfde4-b07c-49d1-85d2-e1d6d6e47a65" />
<img width="2243" height="1354" alt="brave-SIKU_D17-M11-Y2026_e86d4003b" src="https://github.com/user-attachments/assets/0738f9c2-e381-4eb7-a59a-cf4620ec03c1" />
<img width="2243" height="1354" alt="brave-SIKU_D17-M11-Y2026_bc7cd33f2" src="https://github.com/user-attachments/assets/366887ec-3b0e-4e3c-b525-b45630b2ea33" />

***Blackbird*** is currently going through extensive development and has no planned release date (hopefully Q1-Q2 2027). This community repository is going to be re-designed into a blackbird capture file `(.bkcap)` offline analysis tool & SIEM. There are no planned future releases for the live analysis platform that are going to be open-source.

The closed-source, proper version of Blackbird (approximately ~9 months ahead of this current version), is going to be released as a product for Malware Analysts's, Security Analysts, and Reverse-engineer's to use to analyze a binary's full, system-wide behaviour using hypervisor-backed infrastructure. The goal & intention of Blackbird is to provide a modular, configurable malware-analysis platform that can in real-time modify itself to avoid being detected by malware, pick up on specific detections, and synthetically transform the malware's view of the operating system.

Blackbird is not going to be web-based, like for example VirusTotal, or ANY.RUN. It is also not going to be a DBI, or Disassembler, I do not claim that. Blackbird is explicitly designed and targets advanced persistent threat (APT) malware, and aggressive malicious samples that will not be picked up on, or will intentionally evade generic virus analyzers and EDR. Blackbird also plans to provide the most in-depth view of the processes execution as possible, tracing everything from the lowest level Native-API usage, to Networking. 

What sets Blackbird apart from an EDR/AV? ; Targeting. EDR & AV products must constantly balance system performance & detection value, they run in consumer, or enterprise systems which require high-performance and low-noise. Since Blackbird is intended to be used in controlled-labs, it is designed for sole-process targeting, meaning the entire system will target all sensors for the malicious sample, all child-processes and relevant processes to said sample.

Now that's a lot of talk, so how much of this is actually implemented? Well, from what my team can confidently say and provide, about 80%. The hypervisor has been rigorously tested again and again across multiple different systems (Intel, on KVM/QEMU), and according to our current benchmarks (approximate) the hypervisor slows down system performance by 3-15% dependent on system-load. Detections have been worked on for months, and we can confidently say that the [Adversary Emulation Suite](https://github.com/Ryftenius/Blackbird-Adversary-Emulation-Suite) (AES) Breach & Attack Simulation, is passing all required detections, while producing no noise/overflow detections. Blackbird is now entering the extended testing phase where it will be tested on real-world malware, normal applications, and will be put into real MA's & SOC's workflows. The best way to put it would be saying that the underlying infrastructure is concrete and the rest is tuning, packaging, security, UX and performance improvements.

We are also planning to set up a public event where select security researchers & VR's will receive a up-to-date version of Blackbird & conduct a pentest, this will be hosted live on [Ryftenius](https://ryftenius.com/) and the results will be displayed publicly, and credit researchers. Alongside this we are also planning to release live videos, benchmarks & detection results on the latest malicious samples.

> The pentest will be a two phase attack simulation. Phase 1 will be attempting to find any LPE, RCE or DoS vulnerabilities within Blackbird. Phase 2 will be trying to find any observability gaps within Blackbird that would expose its presence within the system.

If you'd like early updates, pre-release news or invitations to events, sign up here: [Blackbird Newsletter](https://ryftenius.com/Blackbird/subscribe/)
