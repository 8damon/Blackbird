#include "blackbird_controller_injection.h"

#include <stdlib.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <wchar.h>

DWORD ControllerWaitForHookReady(_In_ DWORD ProcessId);

typedef struct _BLACKBIRD_LAUNCH_ENV_ENTRY
{
    PWSTR Buffer;
} BLACKBIRD_LAUNCH_ENV_ENTRY;

static PCWSTR ControllerInjectionFileNameFromPath(_In_z_ PCWSTR Path)
{
    PCWSTR slash = NULL;
    PCWSTR fileName = Path;

    if (Path == NULL)
    {
        return L"";
    }

    slash = wcsrchr(Path, L'\\');
    if (slash != NULL && slash[1] != L'\0')
    {
        fileName = slash + 1;
    }

    slash = wcsrchr(fileName, L'/');
    if (slash != NULL && slash[1] != L'\0')
    {
        fileName = slash + 1;
    }

    return fileName;
}

static BOOL ControllerInjectionEnvironmentNamesEqual(_In_z_ PCWSTR Left, _In_z_ PCWSTR Right)
{
    PCWSTR leftEquals = wcschr(Left, L'=');
    PCWSTR rightEquals = wcschr(Right, L'=');
    size_t leftChars = (leftEquals != NULL) ? (size_t)(leftEquals - Left) : wcslen(Left);
    size_t rightChars = (rightEquals != NULL) ? (size_t)(rightEquals - Right) : wcslen(Right);

    if (leftChars != rightChars)
    {
        return FALSE;
    }

    return _wcsnicmp(Left, Right, leftChars) == 0;
}

static int __cdecl ControllerInjectionCompareEnvironmentEntries(_In_ const void *Left, _In_ const void *Right)
{
    const BLACKBIRD_LAUNCH_ENV_ENTRY *leftEntry = (const BLACKBIRD_LAUNCH_ENV_ENTRY *)Left;
    const BLACKBIRD_LAUNCH_ENV_ENTRY *rightEntry = (const BLACKBIRD_LAUNCH_ENV_ENTRY *)Right;

    return _wcsicmp(leftEntry->Buffer, rightEntry->Buffer);
}

static VOID ControllerInjectionFreeEnvironmentEntries(_Inout_updates_(Count) BLACKBIRD_LAUNCH_ENV_ENTRY *Entries,
                                                      _In_ size_t Count)
{
    size_t index;

    if (Entries == NULL)
    {
        return;
    }

    for (index = 0; index < Count; index += 1)
    {
        if (Entries[index].Buffer != NULL)
        {
            HeapFree(GetProcessHeap(), 0, Entries[index].Buffer);
            Entries[index].Buffer = NULL;
        }
    }
}

static BOOL ControllerInjectionAddEnvironmentEntry(_Inout_ BLACKBIRD_LAUNCH_ENV_ENTRY **Entries,
                                                   _Inout_ size_t *Capacity, _Inout_ size_t *Count, _In_z_ PCWSTR Value)
{
    size_t chars;
    PWSTR copy = NULL;
    BLACKBIRD_LAUNCH_ENV_ENTRY *resized = NULL;

    if (Entries == NULL || Capacity == NULL || Count == NULL || Value == NULL || Value[0] == L'\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    chars = wcslen(Value) + 1;
    copy = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, chars * sizeof(WCHAR));
    if (copy == NULL)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    if (FAILED(StringCchCopyW(copy, chars, Value)))
    {
        HeapFree(GetProcessHeap(), 0, copy);
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    if (*Count >= *Capacity)
    {
        size_t newCapacity = (*Capacity == 0) ? 16 : (*Capacity * 2);
        resized = (*Entries == NULL)
                      ? (BLACKBIRD_LAUNCH_ENV_ENTRY *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                                                newCapacity * sizeof(BLACKBIRD_LAUNCH_ENV_ENTRY))
                      : (BLACKBIRD_LAUNCH_ENV_ENTRY *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *Entries,
                                                                  newCapacity * sizeof(BLACKBIRD_LAUNCH_ENV_ENTRY));
        if (resized == NULL)
        {
            HeapFree(GetProcessHeap(), 0, copy);
            SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }

        *Entries = resized;
        *Capacity = newCapacity;
    }

    (*Entries)[*Count].Buffer = copy;
    *Count += 1;
    return TRUE;
}

static BOOL ControllerInjectionBuildEnvironmentBlock(_In_reads_or_z_(OverrideChars) PCWSTR Overrides,
                                                     _Outptr_result_nullonfailure_ PWSTR *EnvironmentBlockOut)
{
    LPWCH currentEnvironment = NULL;
    PWSTR writeCursor = NULL;
    PCWSTR cursor;
    BLACKBIRD_LAUNCH_ENV_ENTRY *entries = NULL;
    size_t capacity = 0;
    size_t count = 0;
    PWSTR environmentBlock = NULL;
    DWORD err = ERROR_SUCCESS;
    size_t index;
    size_t totalChars;

    if (EnvironmentBlockOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *EnvironmentBlockOut = NULL;
    if (Overrides == NULL || Overrides[0] == L'\0')
    {
        return TRUE;
    }

    currentEnvironment = GetEnvironmentStringsW();
    if (currentEnvironment == NULL)
    {
        return FALSE;
    }

    cursor = currentEnvironment;
    while (*cursor != L'\0')
    {
        if (!ControllerInjectionAddEnvironmentEntry(&entries, &capacity, &count, cursor))
        {
            err = GetLastError();
            goto Cleanup;
        }
        cursor += wcslen(cursor) + 1;
    }

    cursor = Overrides;
    while (*cursor != L'\0')
    {
        PCWSTR lineStart = cursor;
        PCWSTR lineEnd = cursor;
        PCWSTR equals = NULL;
        size_t lineChars;
        PWSTR lineCopy = NULL;
        size_t overrideIndex;
        BOOL replaced = FALSE;

        while (*lineEnd != L'\0' && *lineEnd != L'\r' && *lineEnd != L'\n')
        {
            lineEnd += 1;
        }

        while (lineStart < lineEnd && (*lineStart == L' ' || *lineStart == L'\t'))
        {
            lineStart += 1;
        }
        while (lineEnd > lineStart && (lineEnd[-1] == L' ' || lineEnd[-1] == L'\t'))
        {
            lineEnd -= 1;
        }

        lineChars = (size_t)(lineEnd - lineStart);
        if (lineChars != 0)
        {
            lineCopy = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (lineChars + 1) * sizeof(WCHAR));
            if (lineCopy == NULL)
            {
                err = ERROR_OUTOFMEMORY;
                goto Cleanup;
            }

            if (FAILED(StringCchCopyNW(lineCopy, lineChars + 1, lineStart, lineChars)))
            {
                HeapFree(GetProcessHeap(), 0, lineCopy);
                err = ERROR_INSUFFICIENT_BUFFER;
                goto Cleanup;
            }

            equals = wcschr(lineCopy, L'=');
            if (equals == NULL || equals == lineCopy)
            {
                HeapFree(GetProcessHeap(), 0, lineCopy);
                err = ERROR_INVALID_PARAMETER;
                goto Cleanup;
            }

            for (overrideIndex = 0; overrideIndex < count; overrideIndex += 1)
            {
                if (entries[overrideIndex].Buffer != NULL &&
                    ControllerInjectionEnvironmentNamesEqual(entries[overrideIndex].Buffer, lineCopy))
                {
                    HeapFree(GetProcessHeap(), 0, entries[overrideIndex].Buffer);
                    entries[overrideIndex].Buffer = lineCopy;
                    replaced = TRUE;
                    break;
                }
            }

            if (!replaced)
            {
                if (!ControllerInjectionAddEnvironmentEntry(&entries, &capacity, &count, lineCopy))
                {
                    err = GetLastError();
                    HeapFree(GetProcessHeap(), 0, lineCopy);
                    goto Cleanup;
                }
                HeapFree(GetProcessHeap(), 0, entries[count - 1].Buffer);
                entries[count - 1].Buffer = lineCopy;
            }
        }

        cursor = lineEnd;
        while (*cursor == L'\r' || *cursor == L'\n')
        {
            cursor += 1;
        }
    }

    if (count > 1)
    {
        qsort(entries, count, sizeof(entries[0]), ControllerInjectionCompareEnvironmentEntries);
    }

    totalChars = 1;
    for (index = 0; index < count; index += 1)
    {
        totalChars += wcslen(entries[index].Buffer) + 1;
    }

    environmentBlock = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, totalChars * sizeof(WCHAR));
    if (environmentBlock == NULL)
    {
        err = ERROR_OUTOFMEMORY;
        goto Cleanup;
    }

    writeCursor = environmentBlock;
    for (index = 0; index < count; index += 1)
    {
        size_t chars = wcslen(entries[index].Buffer);
        CopyMemory(writeCursor, entries[index].Buffer, chars * sizeof(WCHAR));
        writeCursor += chars + 1;
    }
    *writeCursor = L'\0';
    *EnvironmentBlockOut = environmentBlock;
    environmentBlock = NULL;

Cleanup:
    if (environmentBlock != NULL)
    {
        HeapFree(GetProcessHeap(), 0, environmentBlock);
    }
    ControllerInjectionFreeEnvironmentEntries(entries, count);
    if (entries != NULL)
    {
        HeapFree(GetProcessHeap(), 0, entries);
    }
    if (currentEnvironment != NULL)
    {
        FreeEnvironmentStringsW(currentEnvironment);
    }
    if (err != ERROR_SUCCESS)
    {
        SetLastError(err);
        return FALSE;
    }

    return TRUE;
}

static DWORD ControllerInjectionMapPriorityClass(_In_ UINT32 PriorityClass)
{
    switch (PriorityClass)
    {
    case IDLE_PRIORITY_CLASS:
    case BELOW_NORMAL_PRIORITY_CLASS:
    case NORMAL_PRIORITY_CLASS:
    case ABOVE_NORMAL_PRIORITY_CLASS:
    case HIGH_PRIORITY_CLASS:
    case REALTIME_PRIORITY_CLASS:
        return PriorityClass;
    default:
        return 0;
    }
}

static BOOL ControllerInjectionBuildParentProcessAttribute(
    _In_ DWORD ParentProcessId, _Outptr_result_nullonfailure_ LPPROC_THREAD_ATTRIBUTE_LIST *AttributeListOut,
    _Out_ HANDLE *ParentHandleOut)
{
    SIZE_T attributeBytes = 0;
    HANDLE parentHandle = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attributeList = NULL;

    if (AttributeListOut == NULL || ParentHandleOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *AttributeListOut = NULL;
    *ParentHandleOut = NULL;
    if (ParentProcessId == 0)
    {
        return TRUE;
    }

    parentHandle = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                               ParentProcessId);
    if (parentHandle == NULL)
    {
        return FALSE;
    }

    (void)InitializeProcThreadAttributeList(NULL, 1, 0, &attributeBytes);
    attributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeBytes);
    if (attributeList == NULL)
    {
        CloseHandle(parentHandle);
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    if (!InitializeProcThreadAttributeList(attributeList, 1, 0, &attributeBytes))
    {
        DWORD err = GetLastError();
        HeapFree(GetProcessHeap(), 0, attributeList);
        CloseHandle(parentHandle);
        SetLastError(err);
        return FALSE;
    }

    if (!UpdateProcThreadAttribute(attributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentHandle,
                                   sizeof(parentHandle), NULL, NULL))
    {
        DWORD err = GetLastError();
        DeleteProcThreadAttributeList(attributeList);
        HeapFree(GetProcessHeap(), 0, attributeList);
        CloseHandle(parentHandle);
        SetLastError(err);
        return FALSE;
    }

    *AttributeListOut = attributeList;
    *ParentHandleOut = parentHandle;
    return TRUE;
}

static BOOL ControllerInjectionReadImageMachine(_In_z_ PCWSTR ImagePath, _Out_ USHORT *MachineOut)
{
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    IMAGE_DOS_HEADER dosHeader;
    DWORD signature = 0;
    IMAGE_FILE_HEADER fileHeader;
    LARGE_INTEGER ntHeaderOffset;
    DWORD bytesRead = 0;
    DWORD err = ERROR_SUCCESS;

    if (ImagePath == NULL || ImagePath[0] == L'\0' || MachineOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *MachineOut = IMAGE_FILE_MACHINE_UNKNOWN;
    ZeroMemory(&dosHeader, sizeof(dosHeader));
    ZeroMemory(&fileHeader, sizeof(fileHeader));

    fileHandle = CreateFileW(ImagePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    if (!ReadFile(fileHandle, &dosHeader, sizeof(dosHeader), &bytesRead, NULL) || bytesRead != sizeof(dosHeader))
    {
        err = GetLastError();
        goto Cleanup;
    }
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew <= 0)
    {
        err = ERROR_BAD_EXE_FORMAT;
        goto Cleanup;
    }

    ntHeaderOffset.QuadPart = dosHeader.e_lfanew;
    if (!SetFilePointerEx(fileHandle, ntHeaderOffset, NULL, FILE_BEGIN))
    {
        err = GetLastError();
        goto Cleanup;
    }

    if (!ReadFile(fileHandle, &signature, sizeof(signature), &bytesRead, NULL) || bytesRead != sizeof(signature))
    {
        err = GetLastError();
        goto Cleanup;
    }
    if (signature != IMAGE_NT_SIGNATURE)
    {
        err = ERROR_BAD_EXE_FORMAT;
        goto Cleanup;
    }

    if (!ReadFile(fileHandle, &fileHeader, sizeof(fileHeader), &bytesRead, NULL) || bytesRead != sizeof(fileHeader))
    {
        err = GetLastError();
        goto Cleanup;
    }
    if (fileHeader.Machine == IMAGE_FILE_MACHINE_UNKNOWN)
    {
        err = ERROR_BAD_EXE_FORMAT;
        goto Cleanup;
    }

    *MachineOut = fileHeader.Machine;
    CloseHandle(fileHandle);
    return TRUE;

Cleanup:
    CloseHandle(fileHandle);
    SetLastError((err == ERROR_SUCCESS) ? ERROR_BAD_EXE_FORMAT : err);
    return FALSE;
}

typedef BOOL(WINAPI *BLACKBIRD_IS_WOW64_PROCESS2_FN)(_In_ HANDLE ProcessHandle, _Out_ USHORT *ProcessMachine,
                                                     _Out_ USHORT *NativeMachine);

static BOOL ControllerInjectionQueryProcessMachine(_In_ HANDLE ProcessHandle, _Out_ USHORT *ProcessMachineOut,
                                                   _Out_opt_ USHORT *NativeMachineOut)
{
    HMODULE kernel32Module = NULL;
    BLACKBIRD_IS_WOW64_PROCESS2_FN isWow64Process2Fn = NULL;
    USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    BOOL wow64 = FALSE;

    if (ProcessHandle == NULL || ProcessHandle == INVALID_HANDLE_VALUE || ProcessMachineOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    kernel32Module = GetModuleHandleW(L"kernel32.dll");
    isWow64Process2Fn = (kernel32Module != NULL)
                            ? (BLACKBIRD_IS_WOW64_PROCESS2_FN)GetProcAddress(kernel32Module, "IsWow64Process2")
                            : NULL;
    if (isWow64Process2Fn != NULL)
    {
        if (!isWow64Process2Fn(ProcessHandle, &processMachine, &nativeMachine))
        {
            return FALSE;
        }
    }
    else
    {
        if (!IsWow64Process(ProcessHandle, &wow64))
        {
            return FALSE;
        }

#if defined(_WIN64)
        processMachine = wow64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64;
        nativeMachine = IMAGE_FILE_MACHINE_AMD64;
#elif defined(_M_IX86)
        processMachine = IMAGE_FILE_MACHINE_I386;
        nativeMachine = IMAGE_FILE_MACHINE_I386;
#elif defined(_M_ARM64)
        processMachine = wow64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_ARM64;
        nativeMachine = IMAGE_FILE_MACHINE_ARM64;
#else
        processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
#endif
    }

    *ProcessMachineOut = processMachine;
    if (NativeMachineOut != NULL)
    {
        *NativeMachineOut = nativeMachine;
    }
    return TRUE;
}

static DWORD ControllerInjectionValidateHookArchitecture(_In_ HANDLE ProcessHandle, _In_z_ PCWSTR HookDllPath)
{
    USHORT hookMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT effectiveProcessMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    DWORD err;

    if (ProcessHandle == NULL || ProcessHandle == INVALID_HANDLE_VALUE || HookDllPath == NULL ||
        HookDllPath[0] == L'\0')
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (!ControllerInjectionReadImageMachine(HookDllPath, &hookMachine))
    {
        err = GetLastError();
        return (err == ERROR_SUCCESS) ? ERROR_BAD_EXE_FORMAT : err;
    }

    if (!ControllerInjectionQueryProcessMachine(ProcessHandle, &processMachine, &nativeMachine))
    {
        err = GetLastError();
        return (err == ERROR_SUCCESS) ? ERROR_GEN_FAILURE : err;
    }

    effectiveProcessMachine = (processMachine != IMAGE_FILE_MACHINE_UNKNOWN) ? processMachine : nativeMachine;
#if defined(_WIN64)
    if (effectiveProcessMachine == IMAGE_FILE_MACHINE_UNKNOWN)
    {
        effectiveProcessMachine = IMAGE_FILE_MACHINE_AMD64;
    }
#endif

    if (hookMachine != IMAGE_FILE_MACHINE_UNKNOWN && effectiveProcessMachine != IMAGE_FILE_MACHINE_UNKNOWN &&
        hookMachine != effectiveProcessMachine)
    {
        return ERROR_BAD_EXE_FORMAT;
    }

    return ERROR_SUCCESS;
}

BOOL ControllerInjectionPathPointsToFile(_In_z_ PCWSTR Path)
{
    DWORD attrs;

    if (Path == NULL || Path[0] == L'\0')
    {
        return FALSE;
    }

    attrs = GetFileAttributesW(Path);
    if (attrs == INVALID_FILE_ATTRIBUTES)
    {
        return FALSE;
    }

    return ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0);
}

BOOL ControllerInjectionResolveHookDllPath(_In_ const BLACKBIRD_IPC_SET_USER_HOOK_TARGET_REQUEST *Request,
                                           _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars)
{
    WCHAR modulePath[BLACKBIRD_MAX_IMAGE_PATH_CHARS];
    PWSTR slash;
    DWORD chars;

    if (Request == NULL || Output == NULL || OutputChars == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Output[0] = L'\0';
    if (Request->HookDllPath[0] != L'\0' && ControllerInjectionPathPointsToFile(Request->HookDllPath))
    {
        return SUCCEEDED(StringCchCopyW(Output, OutputChars, Request->HookDllPath));
    }

    ZeroMemory(modulePath, sizeof(modulePath));
    chars = GetModuleFileNameW(NULL, modulePath, RTL_NUMBER_OF(modulePath));
    if (chars == 0 || chars >= RTL_NUMBER_OF(modulePath))
    {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }

    slash = wcsrchr(modulePath, L'\\');
    if (slash == NULL)
    {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }
    slash[1] = L'\0';

    if (FAILED(StringCchCatW(modulePath, RTL_NUMBER_OF(modulePath), L"SR71.dll")))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    if (!ControllerInjectionPathPointsToFile(modulePath))
    {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return FALSE;
    }

    if (FAILED(StringCchCopyW(Output, OutputChars, modulePath)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return TRUE;
}

static BOOL ControllerInjectionAcquirePrimaryTokenFromPipe(_In_ HANDLE PipeHandle, _Out_ HANDLE *TokenOut)
{
    HANDLE token = NULL;
    HANDLE primaryToken = NULL;

    if (TokenOut == NULL || PipeHandle == NULL || PipeHandle == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *TokenOut = NULL;
    if (!ImpersonateNamedPipeClient(PipeHandle))
    {
        return FALSE;
    }

    if (!OpenThreadToken(GetCurrentThread(),
                         TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT |
                             TOKEN_ADJUST_SESSIONID,
                         FALSE, &token))
    {
        DWORD err = GetLastError();
        (void)RevertToSelf();
        SetLastError(err);
        return FALSE;
    }

    if (!RevertToSelf())
    {
        DWORD err = GetLastError();
        CloseHandle(token);
        SetLastError(err);
        return FALSE;
    }

    if (!DuplicateTokenEx(
            token, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
            NULL, SecurityImpersonation, TokenPrimary, &primaryToken))
    {
        DWORD err = GetLastError();
        CloseHandle(token);
        SetLastError(err);
        return FALSE;
    }

    CloseHandle(token);
    *TokenOut = primaryToken;
    return TRUE;
}

static DWORD ControllerInjectionInjectHookDllIntoProcessHandle(_In_ HANDLE ProcessHandle, _In_z_ PCWSTR HookDllPath)
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

static DWORD ControllerInjectionQueueHookDllEarlyBirdApc(_In_ HANDLE ProcessHandle, _In_ HANDLE ThreadHandle,
                                                         _In_z_ PCWSTR HookDllPath)
{
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

    return ERROR_SUCCESS;
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

static BOOL ControllerInjectionIsStealthHookModule(_In_z_ PCWSTR HookDllPath)
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

static BOOL ControllerInjectionLaunchTargetProcess(_In_ HANDLE ClientPipe,
                                                   _In_ const BLACKBIRD_IPC_SET_USER_HOOK_TARGET_REQUEST *Request,
                                                   _Out_ PROCESS_INFORMATION *ProcessInformation)
{
    STARTUPINFOEXW startupInfo;
    PROCESS_INFORMATION processInfo;
    WCHAR commandLine[BLACKBIRD_MAX_IMAGE_PATH_CHARS + 4];
    HANDLE clientToken = NULL;
    HANDLE parentHandle = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attributeList = NULL;
    PWSTR environmentBlock = NULL;
    BOOL launched = FALSE;
    BOOL inheritHandles = FALSE;
    DWORD err = ERROR_SUCCESS;
    DWORD priorityClass = 0;
    DWORD creationFlags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
    PCWSTR currentDirectory = NULL;
    PCWSTR imagePath = NULL;

    if (ClientPipe == NULL || ClientPipe == INVALID_HANDLE_VALUE || Request == NULL || Request->ImagePath[0] == L'\0' ||
        ProcessInformation == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    imagePath = Request->ImagePath;
    inheritHandles = (Request->InheritHandles != 0);
    currentDirectory = (Request->WorkingDirectory[0] != L'\0') ? Request->WorkingDirectory : NULL;
    priorityClass = ControllerInjectionMapPriorityClass(Request->PriorityClass);

    ZeroMemory(&startupInfo, sizeof(startupInfo));
    ZeroMemory(&processInfo, sizeof(processInfo));
    startupInfo.StartupInfo.cb = sizeof(startupInfo);
    ZeroMemory(commandLine, sizeof(commandLine));
    (void)StringCchPrintfW(commandLine, RTL_NUMBER_OF(commandLine), L"\"%s\"", imagePath);

    if (!ControllerInjectionBuildParentProcessAttribute(Request->ParentProcessId, &attributeList, &parentHandle))
    {
        return FALSE;
    }

    if (attributeList != NULL)
    {
        startupInfo.lpAttributeList = attributeList;
        creationFlags |= EXTENDED_STARTUPINFO_PRESENT;
    }

    if (!ControllerInjectionBuildEnvironmentBlock(Request->EnvironmentOverrides, &environmentBlock))
    {
        err = GetLastError();
        goto Cleanup;
    }

    if (ControllerInjectionAcquirePrimaryTokenFromPipe(ClientPipe, &clientToken))
    {
        launched = CreateProcessAsUserW(clientToken, imagePath, commandLine, NULL, NULL, inheritHandles, creationFlags,
                                        environmentBlock, currentDirectory, &startupInfo.StartupInfo, &processInfo);
        if (!launched)
        {
            err = GetLastError();
            if (err == ERROR_PRIVILEGE_NOT_HELD)
            {
                launched =
                    CreateProcessWithTokenW(clientToken, LOGON_WITH_PROFILE, imagePath, commandLine, creationFlags,
                                            environmentBlock, currentDirectory, &startupInfo.StartupInfo, &processInfo);
                if (!launched)
                {
                    err = GetLastError();
                }
            }
        }

        CloseHandle(clientToken);
        clientToken = NULL;
    }
    else
    {
        err = GetLastError();
    }

    if (!launched)
    {
        launched = CreateProcessW(imagePath, commandLine, NULL, NULL, inheritHandles, creationFlags, environmentBlock,
                                  currentDirectory, &startupInfo.StartupInfo, &processInfo);
        if (!launched)
        {
            DWORD fallbackErr = GetLastError();
            if (fallbackErr != ERROR_SUCCESS)
            {
                err = fallbackErr;
            }
            SetLastError(err == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : err);
            goto Cleanup;
        }
    }

    if (priorityClass != 0 && !SetPriorityClass(processInfo.hProcess, priorityClass))
    {
        err = GetLastError();
        (void)TerminateProcess(processInfo.hProcess, 1);
        (void)CloseHandle(processInfo.hThread);
        (void)CloseHandle(processInfo.hProcess);
        processInfo.hThread = NULL;
        processInfo.hProcess = NULL;
        SetLastError(err == ERROR_SUCCESS ? ERROR_GEN_FAILURE : err);
        goto Cleanup;
    }

    if (Request->AffinityMask != 0 && !SetProcessAffinityMask(processInfo.hProcess, (DWORD_PTR)Request->AffinityMask))
    {
        err = GetLastError();
        (void)TerminateProcess(processInfo.hProcess, 1);
        (void)CloseHandle(processInfo.hThread);
        (void)CloseHandle(processInfo.hProcess);
        processInfo.hThread = NULL;
        processInfo.hProcess = NULL;
        SetLastError(err == ERROR_SUCCESS ? ERROR_GEN_FAILURE : err);
        goto Cleanup;
    }

    *ProcessInformation = processInfo;
    processInfo.hProcess = NULL;
    processInfo.hThread = NULL;
    err = ERROR_SUCCESS;

Cleanup:
    if (processInfo.hThread != NULL)
    {
        CloseHandle(processInfo.hThread);
    }
    if (processInfo.hProcess != NULL)
    {
        CloseHandle(processInfo.hProcess);
    }
    if (environmentBlock != NULL)
    {
        HeapFree(GetProcessHeap(), 0, environmentBlock);
    }
    if (attributeList != NULL)
    {
        DeleteProcThreadAttributeList(attributeList);
        HeapFree(GetProcessHeap(), 0, attributeList);
    }
    if (parentHandle != NULL)
    {
        CloseHandle(parentHandle);
    }
    if (err != ERROR_SUCCESS)
    {
        SetLastError(err);
        return FALSE;
    }

    return TRUE;
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

DWORD ControllerInjectionLaunchAndVerify(_In_ HANDLE ClientPipe,
                                         _In_ const BLACKBIRD_IPC_SET_USER_HOOK_TARGET_REQUEST *Request,
                                         _In_z_ PCWSTR HookDllPath, _In_ DWORD VerifyTimeoutMs,
                                         _Out_ DWORD *ProcessIdOut)
{
    PROCESS_INFORMATION processInfo;
    DWORD err = ERROR_SUCCESS;
    BOOL useEarlyBirdApc = FALSE;
    BOOL primaryThreadResumed = FALSE;

    if (ClientPipe == NULL || ClientPipe == INVALID_HANDLE_VALUE || Request == NULL || Request->ImagePath[0] == L'\0' ||
        HookDllPath == NULL || HookDllPath[0] == L'\0' || ProcessIdOut == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    *ProcessIdOut = 0;
    ZeroMemory(&processInfo, sizeof(processInfo));

    if (!ControllerInjectionPathPointsToFile(Request->ImagePath))
    {
        return ERROR_FILE_NOT_FOUND;
    }

    if (!ControllerInjectionLaunchTargetProcess(ClientPipe, Request, &processInfo))
    {
        return GetLastError();
    }

    err = ControllerInjectionValidateHookArchitecture(processInfo.hProcess, HookDllPath);
    if (err != ERROR_SUCCESS)
    {
        (void)TerminateProcess(processInfo.hProcess, 1);
        (void)CloseHandle(processInfo.hThread);
        (void)CloseHandle(processInfo.hProcess);
        return err;
    }

    // Honor requested launch mode exactly, including SR71.dll.
    useEarlyBirdApc = ((Request->Flags & BLACKBIRD_IPC_USER_HOOK_FLAG_LAUNCH_EARLYBIRD_APC) != 0u);

    if (useEarlyBirdApc)
    {
        err = ControllerInjectionQueueHookDllEarlyBirdApc(processInfo.hProcess, processInfo.hThread, HookDllPath);
        if (err == ERROR_SUCCESS)
        {
            if (ResumeThread(processInfo.hThread) == (DWORD)-1)
            {
                err = GetLastError();
            }
            else
            {
                primaryThreadResumed = TRUE;
            }
        }
    }
    else
    {
        err = ControllerInjectionInjectHookDllIntoProcessHandle(processInfo.hProcess, HookDllPath);
        if (err == ERROR_DLL_INIT_FAILED)
        {
            DWORD apcErr =
                ControllerInjectionQueueHookDllEarlyBirdApc(processInfo.hProcess, processInfo.hThread, HookDllPath);
            if (apcErr == ERROR_SUCCESS)
            {
                useEarlyBirdApc = TRUE;
                err = ERROR_SUCCESS;
                if (ResumeThread(processInfo.hThread) == (DWORD)-1)
                {
                    err = GetLastError();
                }
                else
                {
                    primaryThreadResumed = TRUE;
                }
            }
        }
    }
    if (err != ERROR_SUCCESS)
    {
        (void)TerminateProcess(processInfo.hProcess, 1);
        (void)CloseHandle(processInfo.hThread);
        (void)CloseHandle(processInfo.hProcess);
        return err;
    }

    err = ControllerWaitForHookReady(processInfo.dwProcessId);
    if (err != ERROR_SUCCESS)
    {
        (void)TerminateProcess(processInfo.hProcess, 1);
        (void)CloseHandle(processInfo.hThread);
        (void)CloseHandle(processInfo.hProcess);
        return err;
    }

    /*
     * Hold launch targets behind a full ready gate. For normal remote-thread
     * launch the primary thread
     * never resumed, so the image is still suspended
     * here. For EarlyBird APC the thread must briefly run to
     * execute the APC;
     * suspend it again before handing the PID back so the interface can attach
     * the
     * backend session and explicitly release execution afterwards.
     */
    if (primaryThreadResumed)
    {
        if (SuspendThread(processInfo.hThread) == (DWORD)-1)
        {
            err = GetLastError();
            (void)TerminateProcess(processInfo.hProcess, 1);
            (void)CloseHandle(processInfo.hThread);
            (void)CloseHandle(processInfo.hProcess);
            return err == ERROR_SUCCESS ? ERROR_GEN_FAILURE : err;
        }
        primaryThreadResumed = FALSE;
    }

    if (ControllerInjectionIsStealthHookModule(HookDllPath))
    {
        *ProcessIdOut = processInfo.dwProcessId;
        (void)CloseHandle(processInfo.hThread);
        (void)CloseHandle(processInfo.hProcess);
        return ERROR_SUCCESS;
    }

    if (!ControllerInjectionVerifyHookLoaded(processInfo.dwProcessId, HookDllPath, VerifyTimeoutMs))
    {
        err = GetLastError();
        (void)TerminateProcess(processInfo.hProcess, 1);
        (void)CloseHandle(processInfo.hThread);
        (void)CloseHandle(processInfo.hProcess);
        return (err == ERROR_SUCCESS) ? ERROR_DLL_NOT_FOUND : err;
    }

    *ProcessIdOut = processInfo.dwProcessId;
    (void)CloseHandle(processInfo.hThread);
    (void)CloseHandle(processInfo.hProcess);
    return ERROR_SUCCESS;
}
