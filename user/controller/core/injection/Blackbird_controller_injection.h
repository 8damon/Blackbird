#ifndef BLACKBIRD_CONTROLLER_INJECTION_H
#define BLACKBIRD_CONTROLLER_INJECTION_H

#include <windows.h>
#include <stddef.h>

#include "../../../../abi/blackbird_ipc.h"

#define BLACKBIRD_CONTROLLER_INJECTION_VERIFY_TIMEOUT_MS 20000u

BOOL ControllerInjectionPathPointsToFile(_In_z_ PCWSTR Path);

BOOL ControllerInjectionResolveHookDllPath(
    _In_ const BLACKBIRD_IPC_SET_USER_HOOK_TARGET_REQUEST *Request,
    _Out_writes_z_(OutputChars) PWSTR Output,
    _In_ size_t OutputChars);

BOOL ControllerInjectionVerifyHookLoaded(_In_ DWORD ProcessId, _In_z_ PCWSTR HookDllPath, _In_ DWORD TimeoutMs);

DWORD ControllerInjectionAttachAndVerify(
    _In_ DWORD ProcessId,
    _In_z_ PCWSTR HookDllPath,
    _In_ DWORD VerifyTimeoutMs);

DWORD ControllerInjectionLaunchSuspendedAndStage(
    _In_ HANDLE ClientPipe,
    _In_z_ PCWSTR ImagePath,
    _In_z_ PCWSTR HookDllPath,
    _In_ DWORD Flags,
    _Out_ PROCESS_INFORMATION *ProcessInfoOut);

DWORD ControllerInjectionResumeAndVerifyLaunchedProcess(
    _Inout_ PROCESS_INFORMATION *ProcessInfo,
    _In_z_ PCWSTR HookDllPath,
    _In_ DWORD VerifyTimeoutMs);

#endif
