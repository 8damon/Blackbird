#pragma once

#include <Windows.h>
#include <cstdint>

enum class BkRuntimeFaultCode : std::uint32_t
{
    LaunchGatePrepareFailed = 1,
    LaunchGateReadyEventCreateFailed = 2,
    LaunchGateDeferredEventNameFailed = 3,
    LaunchGateNoParkSlot = 4,
    LaunchGateContextStageFailed = 5,
    LaunchGateResumeRejected = 6,
    RuntimeInitializeFailed = 7,
    IpcInitializeTimedOut = 8,
    HookReadyTimedOut = 9,
    CoreHookInitFailed = 10,
    BootstrapThreadCreateFailed = 11,
    FailClosedTriggered = 12,
    NtHookInitFault = 13,
    ModuleHookInitFault = 14,
    InstrumentationRangeRegisterFailed = 15,
    HookPatchRegisterFailed = 16,
    ProcessInstrumentationCallbackInstallFailed = 17,
    ProcessInstrumentationCallbackProtectFailed = 18,
    ControlFlowCallTargetRegisterFailed = 19,
};

DWORD WINAPI BkRuntimeThreadProc(LPVOID);

void BkRuntimePrimeHooks() noexcept;

void BkDbgLog(_In_z_ _Printf_format_string_ PCSTR format, ...) noexcept;
void BkRuntimeReportFault(BkRuntimeFaultCode code, std::uint64_t arg0 = 0, std::uint64_t arg1 = 0) noexcept;

HANDLE BkRuntimeCreateBootstrapThread(LPTHREAD_START_ROUTINE startRoutine, LPVOID parameter) noexcept;

void BkRuntimeCloseHandle(HANDLE handle) noexcept;

void BkRuntimeFailClosed(DWORD exitStatus) noexcept;

bool BkInitializeSubsystems() noexcept;

void BkRuntimeSignalLaunchGateReady() noexcept;

void BkRuntimeShutdown();
