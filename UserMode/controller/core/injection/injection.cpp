#include "internal.h"

static DWORD ControllerInjectionResumeThreadForQueuedApc(_In_ HANDLE ThreadHandle)
{
    using NtAlertResumeThreadFn = LONG(NTAPI *)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    NtAlertResumeThreadFn ntAlertResumeThread =
        (ntdll != NULL) ? reinterpret_cast<NtAlertResumeThreadFn>(GetProcAddress(ntdll, "NtAlertResumeThread")) : NULL;
    ULONG previousSuspendCount = 0;

    if (ntAlertResumeThread != NULL)
    {
        LONG status = ntAlertResumeThread(ThreadHandle, &previousSuspendCount);
        if (status >= 0)
        {
            ControllerLog("[INJ] NtAlertResumeThread succeeded thread=%p previousSuspend=%lu\n", ThreadHandle,
                          (unsigned long)previousSuspendCount);
            return ERROR_SUCCESS;
        }

        DWORD err = ControllerInjectionNtStatusToWin32(status);
        ControllerLog("[INJ][WARN] NtAlertResumeThread failed thread=%p status=0x%08lX err=%lu; falling back\n",
                      ThreadHandle, (unsigned long)status, (unsigned long)err);
    }
    else
    {
        ControllerLog("[INJ][WARN] NtAlertResumeThread unavailable; falling back to ResumeThread\n");
    }

    if (ResumeThread(ThreadHandle) == (DWORD)-1)
    {
        DWORD err = GetLastError();
        return err == ERROR_SUCCESS ? ERROR_GEN_FAILURE : err;
    }

    ControllerLog("[INJ] ResumeThread fallback succeeded thread=%p\n", ThreadHandle);
    return ERROR_SUCCESS;
}

static bool ControllerInjectionVectorContains(_In_ const std::vector<DWORD> &Pids, _In_ DWORD ProcessId)
{
    return std::find(Pids.begin(), Pids.end(), ProcessId) != Pids.end();
}

static VOID ControllerInjectionCollectProcessTree(_In_ DWORD RootProcessId, _Out_ std::vector<DWORD> &ProcessIds)
{
    bool added = true;

    ProcessIds.clear();
    if (RootProcessId == 0)
    {
        return;
    }

    ProcessIds.push_back(RootProcessId);
    while (added)
    {
        HANDLE snapshot;
        PROCESSENTRY32W entry;

        added = false;
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            ControllerLog("[INJ][WARN] process-tree snapshot failed rootPid=%lu err=%lu\n",
                          (unsigned long)RootProcessId, (unsigned long)GetLastError());
            return;
        }

        ZeroMemory(&entry, sizeof(entry));
        entry.dwSize = sizeof(entry);
        if (!Process32FirstW(snapshot, &entry))
        {
            ControllerLog("[INJ][WARN] process-tree snapshot enumerate failed rootPid=%lu err=%lu\n",
                          (unsigned long)RootProcessId, (unsigned long)GetLastError());
            CloseHandle(snapshot);
            return;
        }

        do
        {
            DWORD pid = entry.th32ProcessID;
            DWORD parentPid = entry.th32ParentProcessID;
            if (pid != 0 && !ControllerInjectionVectorContains(ProcessIds, pid) &&
                ControllerInjectionVectorContains(ProcessIds, parentPid))
            {
                ProcessIds.push_back(pid);
                added = true;
            }
        } while (Process32NextW(snapshot, &entry));

        CloseHandle(snapshot);
    }
}

static VOID ControllerInjectionTerminatePidBestEffort(_In_ DWORD ProcessId, _In_z_ PCSTR Reason)
{
    HANDLE process;

    if (ProcessId == 0 || ProcessId == GetCurrentProcessId())
    {
        return;
    }

    process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, ProcessId);
    if (process == NULL)
    {
        DWORD err = GetLastError();
        if (err != ERROR_INVALID_PARAMETER && err != ERROR_NOT_FOUND)
        {
            ControllerLog("[INJ][WARN] abort open failed pid=%lu reason=%s err=%lu\n", (unsigned long)ProcessId,
                          Reason, (unsigned long)err);
        }
        return;
    }

    if (!TerminateProcess(process, 1))
    {
        ControllerLog("[INJ][WARN] abort terminate failed pid=%lu reason=%s err=%lu\n", (unsigned long)ProcessId,
                      Reason, (unsigned long)GetLastError());
        CloseHandle(process);
        return;
    }

    (void)WaitForSingleObject(process, 1000);
    ControllerLog("[INJ] abort terminated pid=%lu reason=%s\n", (unsigned long)ProcessId, Reason);
    CloseHandle(process);
}

static VOID ControllerInjectionAbortLaunchedProcessTree(_In_opt_ HANDLE ProcessHandle, _In_ DWORD RootProcessId,
                                                        _In_z_ PCSTR Reason)
{
    std::vector<DWORD> processTree;

    if (RootProcessId == 0)
    {
        return;
    }

    ControllerInjectionCollectProcessTree(RootProcessId, processTree);

    if (ProcessHandle != NULL && ProcessHandle != INVALID_HANDLE_VALUE)
    {
        if (!TerminateProcess(ProcessHandle, 1))
        {
            DWORD err = GetLastError();
            if (err != ERROR_ACCESS_DENIED && err != ERROR_INVALID_PARAMETER)
            {
                ControllerLog("[INJ][WARN] abort root terminate failed pid=%lu reason=%s err=%lu\n",
                              (unsigned long)RootProcessId, Reason, (unsigned long)err);
            }
        }
        else
        {
            ControllerLog("[INJ] abort signaled root pid=%lu reason=%s\n", (unsigned long)RootProcessId, Reason);
        }
        (void)WaitForSingleObject(ProcessHandle, 1000);
    }

    for (auto it = processTree.rbegin(); it != processTree.rend(); ++it)
    {
        if (*it != RootProcessId)
        {
            ControllerInjectionTerminatePidBestEffort(*it, Reason);
        }
    }

    if (ProcessHandle == NULL || ProcessHandle == INVALID_HANDLE_VALUE)
    {
        ControllerInjectionTerminatePidBestEffort(RootProcessId, Reason);
    }
}

VOID ControllerInjectionTerminateProcessTreeBestEffort(_In_ DWORD RootProcessId, _In_z_ PCSTR Reason)
{
    ControllerInjectionAbortLaunchedProcessTree(NULL, RootProcessId,
                                                (Reason != NULL && Reason[0] != '\0') ? Reason
                                                                                      : "analysis-teardown");
}

DWORD ControllerInjectionAttachAndVerify(_In_ DWORD ProcessId, _In_z_ PCWSTR HookDllPath, _In_ DWORD VerifyTimeoutMs)
{
    HANDLE processHandle = NULL;
    DWORD err;

    if (ProcessId == 0 || HookDllPath == NULL || HookDllPath[0] == L'\0')
    {
        return ERROR_INVALID_PARAMETER;
    }

    processHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                                    PROCESS_VM_WRITE | PROCESS_VM_READ,
                                FALSE, ProcessId);
    if (processHandle == NULL)
    {
        return GetLastError();
    }

    err = ControllerInjectionValidateHookArchitecture(processHandle, HookDllPath);
    if (err != ERROR_SUCCESS)
    {
        CloseHandle(processHandle);
        return err;
    }

    err = ControllerInjectionInjectHookDllIntoProcessHandle(processHandle, HookDllPath);
    CloseHandle(processHandle);
    processHandle = NULL;
    if (err != ERROR_SUCCESS)
    {
        return err;
    }

    if (ControllerInjectionIsStealthHookModule(HookDllPath))
    {
        return ERROR_SUCCESS;
    }

    if (!ControllerInjectionVerifyHookLoaded(ProcessId, HookDllPath, VerifyTimeoutMs))
    {
        err = GetLastError();
        return (err == ERROR_SUCCESS) ? ERROR_DLL_NOT_FOUND : err;
    }

    return ERROR_SUCCESS;
}

DWORD ControllerInjectionLaunchAndVerify(_In_ HANDLE ClientPipe, _In_ const BKIPC_SET_USER_HOOK_TARGET_REQUEST *Request,
                                         _In_z_ PCWSTR HookDllPath, _In_ DWORD VerifyTimeoutMs,
                                         _Out_ DWORD *ProcessIdOut)
{
    PROCESS_INFORMATION processInfo;
    HANDLE deferredLaunchGateEvent = NULL;
    WCHAR deferredLaunchGateEventName[128];
    bool deferLaunchGate = false;
    DWORD err = ERROR_SUCCESS;

    if (ClientPipe == NULL || ClientPipe == INVALID_HANDLE_VALUE || Request == NULL || Request->ImagePath[0] == L'\0' ||
        HookDllPath == NULL || HookDllPath[0] == L'\0' || ProcessIdOut == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    *ProcessIdOut = 0;
    ZeroMemory(&processInfo, sizeof(processInfo));
    ZeroMemory(deferredLaunchGateEventName, sizeof(deferredLaunchGateEventName));
    deferLaunchGate = (Request->Flags & BKIPC_USER_HOOK_FLAG_DEFER_LAUNCH_GATE_RELEASE) != 0;

    if (!ControllerInjectionPathPointsToFile(Request->ImagePath))
    {
        return ERROR_FILE_NOT_FOUND;
    }

    if (deferLaunchGate)
    {
        if (ControllerInjectionEnvironmentHasName(Request->EnvironmentOverrides, L"BK_HOOK_LAUNCH_GATE_EVENT"))
        {
            ControllerLog("[INJ][WARN] protected launch rejected user launch-gate event override image=%ws\n",
                          Request->ImagePath);
            return ERROR_ACCESS_DENIED;
        }

        if (!ControllerInjectionBuildDeferredLaunchGateEventName(deferredLaunchGateEventName,
                                                                 RTL_NUMBER_OF(deferredLaunchGateEventName)))
        {
            err = GetLastError();
            return err == ERROR_SUCCESS ? ERROR_GEN_FAILURE : err;
        }

        deferredLaunchGateEvent = ControllerInjectionCreateDeferredLaunchGateEvent(deferredLaunchGateEventName, 0);
        if (deferredLaunchGateEvent == NULL)
        {
            err = GetLastError();
            return err == ERROR_SUCCESS ? ERROR_GEN_FAILURE : err;
        }
    }

    if (!ControllerInjectionLaunchTargetProcess(ClientPipe, Request,
                                                deferLaunchGate ? deferredLaunchGateEventName : NULL, &processInfo))
    {
        err = GetLastError();
        if (deferredLaunchGateEvent != NULL)
        {
            CloseHandle(deferredLaunchGateEvent);
        }
        return err == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : err;
    }
    *ProcessIdOut = processInfo.dwProcessId;
    if (deferredLaunchGateEvent != NULL)
    {
        ControllerLog("[INJ] deferred launch gate event bound pid=%lu name=%ws\n",
                      (unsigned long)processInfo.dwProcessId, deferredLaunchGateEventName);
    }

    err = ControllerInjectionValidateHookArchitecture(processInfo.hProcess, HookDllPath);
    if (err != ERROR_SUCCESS)
    {
        ControllerInjectionAbortLaunchedProcessTree(processInfo.hProcess, processInfo.dwProcessId,
                                                    "architecture-validation-failed");
        if (deferredLaunchGateEvent != NULL)
        {
            CloseHandle(deferredLaunchGateEvent);
        }
        (void)CloseHandle(processInfo.hThread);
        (void)CloseHandle(processInfo.hProcess);
        return err;
    }

    err = ControllerInjectionQueueHookDllEarlyBirdApc(processInfo.hProcess, processInfo.hThread, HookDllPath);
    if (err != ERROR_SUCCESS)
    {
        ControllerInjectionAbortLaunchedProcessTree(processInfo.hProcess, processInfo.dwProcessId,
                                                    "early-bird-apc-queue-failed");
        if (deferredLaunchGateEvent != NULL)
        {
            CloseHandle(deferredLaunchGateEvent);
        }
        (void)CloseHandle(processInfo.hThread);
        (void)CloseHandle(processInfo.hProcess);
        return err;
    }

    err = ControllerInjectionResumeThreadForQueuedApc(processInfo.hThread);
    if (err != ERROR_SUCCESS)
    {
        ControllerInjectionAbortLaunchedProcessTree(processInfo.hProcess, processInfo.dwProcessId,
                                                    "resume-for-apc-failed");
        if (deferredLaunchGateEvent != NULL)
        {
            CloseHandle(deferredLaunchGateEvent);
        }
        (void)CloseHandle(processInfo.hThread);
        (void)CloseHandle(processInfo.hProcess);
        return err == ERROR_SUCCESS ? ERROR_GEN_FAILURE : err;
    }

    err = ControllerWaitForHookReady(processInfo.dwProcessId);
    if (err != ERROR_SUCCESS)
    {
        ControllerInjectionLogSr71Diagnostics(processInfo.dwProcessId);
        ControllerInjectionAbortLaunchedProcessTree(processInfo.hProcess, processInfo.dwProcessId,
                                                    "hook-ready-timeout");
        if (deferredLaunchGateEvent != NULL)
        {
            CloseHandle(deferredLaunchGateEvent);
        }
        (void)CloseHandle(processInfo.hThread);
        (void)CloseHandle(processInfo.hProcess);
        return err;
    }

    err = ControllerInjectionSuspendProcessHandle(processInfo.hProcess);
    if (err != ERROR_SUCCESS)
    {
        const bool mustLeaveSuspended = (Request->Flags & BKIPC_USER_HOOK_FLAG_DEFER_LAUNCH_GATE_RELEASE) != 0;
        ControllerLog("[INJ][WARN] post-ready suspend failed pid=%lu err=%lu leaveSuspended=%u\n",
                      (unsigned long)processInfo.dwProcessId, (unsigned long)err, mustLeaveSuspended ? 1u : 0u);
        if (mustLeaveSuspended)
        {
            ControllerInjectionAbortLaunchedProcessTree(processInfo.hProcess, processInfo.dwProcessId,
                                                        "post-ready-suspend-failed");
            if (deferredLaunchGateEvent != NULL)
            {
                CloseHandle(deferredLaunchGateEvent);
            }
            (void)CloseHandle(processInfo.hThread);
            (void)CloseHandle(processInfo.hProcess);
            return err;
        }
        err = ERROR_SUCCESS;
    }
    else
    {
        ControllerLog("[INJ] post-ready suspend succeeded pid=%lu\n", (unsigned long)processInfo.dwProcessId);
    }

    if (deferredLaunchGateEvent != NULL && !SetEvent(deferredLaunchGateEvent))
    {
        err = GetLastError();
        ControllerLog("[INJ] deferred launch gate release failed pid=%lu err=%lu\n",
                      (unsigned long)processInfo.dwProcessId, (unsigned long)err);
        ControllerInjectionAbortLaunchedProcessTree(processInfo.hProcess, processInfo.dwProcessId,
                                                    "deferred-gate-release-failed");
        CloseHandle(deferredLaunchGateEvent);
        (void)CloseHandle(processInfo.hThread);
        (void)CloseHandle(processInfo.hProcess);
        return err == ERROR_SUCCESS ? ERROR_GEN_FAILURE : err;
    }

    if (ControllerInjectionIsStealthHookModule(HookDllPath))
    {
        *ProcessIdOut = processInfo.dwProcessId;
        if (deferredLaunchGateEvent != NULL)
        {
            CloseHandle(deferredLaunchGateEvent);
        }
        (void)CloseHandle(processInfo.hThread);
        (void)CloseHandle(processInfo.hProcess);
        return ERROR_SUCCESS;
    }

    if (!ControllerInjectionVerifyHookLoaded(processInfo.dwProcessId, HookDllPath, VerifyTimeoutMs))
    {
        err = GetLastError();
        ControllerInjectionAbortLaunchedProcessTree(processInfo.hProcess, processInfo.dwProcessId,
                                                    "hook-module-verify-failed");
        if (deferredLaunchGateEvent != NULL)
        {
            CloseHandle(deferredLaunchGateEvent);
        }
        (void)CloseHandle(processInfo.hThread);
        (void)CloseHandle(processInfo.hProcess);
        return (err == ERROR_SUCCESS) ? ERROR_DLL_NOT_FOUND : err;
    }

    *ProcessIdOut = processInfo.dwProcessId;
    if (deferredLaunchGateEvent != NULL)
    {
        CloseHandle(deferredLaunchGateEvent);
    }
    (void)CloseHandle(processInfo.hThread);
    (void)CloseHandle(processInfo.hProcess);
    return ERROR_SUCCESS;
}
