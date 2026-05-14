#include "internal.h"

DWORD ControllerInjectionInjectHookDllIntoProcessHandle(_In_ HANDLE ProcessHandle, _In_z_ PCWSTR HookDllPath)
{
    SIZE_T pathBytes;
    HMODULE kernel32Module = NULL;
    FARPROC loadLibraryProc = NULL;
    LPVOID remotePath = NULL;
    HANDLE threadHandle = NULL;
    DWORD waitResult;
    DWORD remoteExit = 0;
    SIZE_T bytesWritten = 0;
    DWORD err = ERROR_SUCCESS;

    if (ProcessHandle == NULL || ProcessHandle == INVALID_HANDLE_VALUE || HookDllPath == NULL ||
        HookDllPath[0] == L'\0')
    {
        return ERROR_INVALID_PARAMETER;
    }

    pathBytes = (wcslen(HookDllPath) + 1u) * sizeof(WCHAR);
    kernel32Module = GetModuleHandleW(L"kernel32.dll");
    loadLibraryProc = (kernel32Module != NULL) ? GetProcAddress(kernel32Module, "LoadLibraryW") : NULL;
    if (loadLibraryProc == NULL)
    {
        return GetLastError() != ERROR_SUCCESS ? GetLastError() : ERROR_PROC_NOT_FOUND;
    }

    remotePath = VirtualAllocEx(ProcessHandle, NULL, pathBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remotePath == NULL)
    {
        return GetLastError();
    }

    if (!WriteProcessMemory(ProcessHandle, remotePath, HookDllPath, pathBytes, &bytesWritten) ||
        bytesWritten != pathBytes)
    {
        err = GetLastError();
        (void)VirtualFreeEx(ProcessHandle, remotePath, 0, MEM_RELEASE);
        return err == ERROR_SUCCESS ? ERROR_WRITE_FAULT : err;
    }

    threadHandle =
        CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryProc, remotePath, 0, NULL);
    if (threadHandle == NULL)
    {
        err = GetLastError();
        (void)VirtualFreeEx(ProcessHandle, remotePath, 0, MEM_RELEASE);
        return err;
    }

    waitResult = WaitForSingleObject(threadHandle, 20000);
    if (waitResult != WAIT_OBJECT_0)
    {
        err = (waitResult == WAIT_TIMEOUT) ? ERROR_TIMEOUT : GetLastError();
        CloseHandle(threadHandle);
        (void)VirtualFreeEx(ProcessHandle, remotePath, 0, MEM_RELEASE);
        return err == ERROR_SUCCESS ? ERROR_GEN_FAILURE : err;
    }

    if (!GetExitCodeThread(threadHandle, &remoteExit))
    {
        err = GetLastError();
        CloseHandle(threadHandle);
        (void)VirtualFreeEx(ProcessHandle, remotePath, 0, MEM_RELEASE);
        return err == ERROR_SUCCESS ? ERROR_GEN_FAILURE : err;
    }

    CloseHandle(threadHandle);
    (void)VirtualFreeEx(ProcessHandle, remotePath, 0, MEM_RELEASE);

    if (remoteExit == 0)
    {
        return ERROR_DLL_INIT_FAILED;
    }

    return ERROR_SUCCESS;
}

DWORD ControllerInjectionQueueHookDllEarlyBirdApc(_In_ HANDLE ProcessHandle, _In_ HANDLE ThreadHandle,
                                                  _In_z_ PCWSTR HookDllPath)
{
#if !defined(_M_X64)
    UNREFERENCED_PARAMETER(ProcessHandle);
    UNREFERENCED_PARAMETER(ThreadHandle);
    UNREFERENCED_PARAMETER(HookDllPath);
    return ERROR_NOT_SUPPORTED;
#else
    SIZE_T pathBytes;
    HMODULE kernel32Module = NULL;
    FARPROC loadLibraryProc = NULL;
    LPVOID remotePath = NULL;
    SIZE_T bytesWritten = 0;
    DWORD err = ERROR_SUCCESS;

    if (ProcessHandle == NULL || ProcessHandle == INVALID_HANDLE_VALUE || ThreadHandle == NULL ||
        ThreadHandle == INVALID_HANDLE_VALUE || HookDllPath == NULL || HookDllPath[0] == L'\0')
    {
        return ERROR_INVALID_PARAMETER;
    }

    pathBytes = (wcslen(HookDllPath) + 1u) * sizeof(WCHAR);
    kernel32Module = GetModuleHandleW(L"kernel32.dll");
    loadLibraryProc = (kernel32Module != NULL) ? GetProcAddress(kernel32Module, "LoadLibraryW") : NULL;
    if (loadLibraryProc == NULL)
    {
        return GetLastError() != ERROR_SUCCESS ? GetLastError() : ERROR_PROC_NOT_FOUND;
    }

    remotePath = VirtualAllocEx(ProcessHandle, NULL, pathBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remotePath == NULL)
    {
        return GetLastError();
    }

    if (!WriteProcessMemory(ProcessHandle, remotePath, HookDllPath, pathBytes, &bytesWritten) ||
        bytesWritten != pathBytes)
    {
        err = GetLastError();
        (void)VirtualFreeEx(ProcessHandle, remotePath, 0, MEM_RELEASE);
        return err == ERROR_SUCCESS ? ERROR_WRITE_FAULT : err;
    }

    if (QueueUserAPC((PAPCFUNC)(ULONG_PTR)loadLibraryProc, ThreadHandle, (ULONG_PTR)remotePath) == 0)
    {
        err = GetLastError();
        (void)VirtualFreeEx(ProcessHandle, remotePath, 0, MEM_RELEASE);
        return err == ERROR_SUCCESS ? ERROR_GEN_FAILURE : err;
    }

    ControllerLog("[INJ] early-bird LoadLibraryW APC queued thread=%p loadLibrary=%p remotePath=%p pathBytes=%llu\n",
                  ThreadHandle, loadLibraryProc, remotePath, (unsigned long long)pathBytes);
    return ERROR_SUCCESS;
#endif
}

static BOOL ControllerInjectionProbeHookLoaded(_In_ DWORD ProcessId, _In_z_ PCWSTR HookDllPath)
{
    HANDLE snapshot = INVALID_HANDLE_VALUE;
    MODULEENTRY32W module;
    PCWSTR expectedName;
    BOOL found = FALSE;
    DWORD probeErr = ERROR_NOT_FOUND;

    expectedName = ControllerInjectionFileNameFromPath(HookDllPath);

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    ZeroMemory(&module, sizeof(module));
    module.dwSize = sizeof(module);

    if (Module32FirstW(snapshot, &module))
    {
        do
        {
            if ((module.szModule[0] != L'\0' && _wcsicmp(module.szModule, expectedName) == 0) ||
                (module.szExePath[0] != L'\0' && _wcsicmp(module.szExePath, HookDllPath) == 0))
            {
                found = TRUE;
                break;
            }
        } while (Module32NextW(snapshot, &module));
    }
    probeErr = GetLastError();
    if (probeErr == ERROR_SUCCESS || probeErr == ERROR_NO_MORE_FILES || probeErr == ERROR_BAD_LENGTH ||
        probeErr == ERROR_PARTIAL_COPY)
    {
        probeErr = ERROR_NOT_FOUND;
    }

    CloseHandle(snapshot);
    if (found)
    {
        SetLastError(ERROR_SUCCESS);
    }
    else
    {
        SetLastError(probeErr);
    }
    return found;
}

BOOL ControllerInjectionIsStealthHookModule(_In_z_ PCWSTR HookDllPath)
{
    PCWSTR fileName;

    if (HookDllPath == NULL || HookDllPath[0] == L'\0')
    {
        return FALSE;
    }

    fileName = ControllerInjectionFileNameFromPath(HookDllPath);
    if (fileName == NULL || fileName[0] == L'\0')
    {
        return FALSE;
    }

    return (_wcsicmp(fileName, L"SR71.dll") == 0);
}

BOOL ControllerInjectionVerifyHookLoaded(_In_ DWORD ProcessId, _In_z_ PCWSTR HookDllPath, _In_ DWORD TimeoutMs)
{
    ULONGLONG startTick;
    ULONGLONG now;
    DWORD pollSleepMs = 75;
    DWORD lastErr = ERROR_NOT_FOUND;

    if (ProcessId == 0 || HookDllPath == NULL || HookDllPath[0] == L'\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    startTick = GetTickCount64();
    now = startTick;
    do
    {
        if (ControllerInjectionProbeHookLoaded(ProcessId, HookDllPath))
        {
            return TRUE;
        }

        lastErr = GetLastError();
        if (lastErr == ERROR_PARTIAL_COPY || lastErr == ERROR_BAD_LENGTH || lastErr == ERROR_NO_MORE_FILES ||
            lastErr == ERROR_SUCCESS)
        {
            lastErr = ERROR_NOT_FOUND;
        }

        Sleep(pollSleepMs);
        now = GetTickCount64();
    } while (now - startTick < (ULONGLONG)TimeoutMs);

    SetLastError(lastErr == ERROR_SUCCESS ? ERROR_NOT_FOUND : lastErr);
    return FALSE;
}
