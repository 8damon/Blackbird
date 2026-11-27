#include "../include/detection_examples.h"

static const AesScenarioDefinition kDetectionScenarios[] = {
    {"direct-syscall-ntqueryvm", "detection",
     "Direct syscalls for NtQueryVirtualMemory and NtOpenProcess against a remote child.",
     "Direct-syscall handle / process recon style detection.", false, ExampleRunDirectSyscallNtQueryVm},
    {"remote-thread-rwx", "detection",
     "Allocates RWX memory in a remote child, writes a stub, and starts a remote thread.",
     "Injection, non-image executable region, remote thread, shellcode-stage style detections.", false,
     ExampleRunRemoteThread},
    {"ppid-spoof", "detection", "Creates a child with an overridden parent process attribute.",
     "PARENT_PID_SPOOF_SUSPECT / process telemetry anomaly.", false, ExampleRunPpidSpoof},
    {"nt-system-recon", "detection", "Queries system process/module information via NtQuerySystemInformation.",
     "USERMODE_PROCESS_RECON / recon-oriented telemetry.", false, ExampleRunNtSystemRecon},
    {"anti-virt-vm-check", "detection",
     "Runs classic VM artifact checks against adapter MAC prefixes and BIOS manufacturer strings.",
     "Anti-virtualization masking validation / environment artifact checks.", false, ExampleRunVmCheck},
    {"cpu-timing-qpc", "detection",
     "Samples QPC, TSC, Sleep, and CPUID latency for timing anomalies often exposed by virtualized analysis hosts.",
     "Anti-virtualization timing telemetry / QPC and CPU timing anomaly checks.", false, ExampleRunCpuTimingQpc},
    {"ntallocate-stack-trace", "detection",
     "Calls NtAllocateVirtualMemory in the current process, then dumps return-address stack frames.",
     "User-mode API interception / ntdll hook validation around NtAllocateVirtualMemory.", false,
     ExampleRunNtAllocateStackTrace},
};

const AesModuleDefinition* AesGetDetectionModule()
{
    static const AesModuleDefinition module = {
        "detection",
        "detection",
        "Scenarios intended to exercise MDR detection and telemetry paths.",
        kDetectionScenarios,
        ARRAYSIZE(kDetectionScenarios),
        DetectionExamplesInternalDetectionMain,
    };

    return &module;
}
