#include "internal.h"

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

BOOL ControllerInjectionReadImageSubsystem(_In_z_ PCWSTR ImagePath, _Out_ USHORT *SubsystemOut)
{
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    IMAGE_DOS_HEADER dosHeader;
    DWORD signature = 0;
    IMAGE_FILE_HEADER fileHeader;
    WORD optionalMagic = 0;
    USHORT subsystem = 0;
    LARGE_INTEGER offset;
    DWORD bytesRead = 0;
    DWORD err = ERROR_SUCCESS;

    if (ImagePath == NULL || ImagePath[0] == L'\0' || SubsystemOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *SubsystemOut = IMAGE_SUBSYSTEM_UNKNOWN;
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

    offset.QuadPart = dosHeader.e_lfanew;
    if (!SetFilePointerEx(fileHandle, offset, NULL, FILE_BEGIN) ||
        !ReadFile(fileHandle, &signature, sizeof(signature), &bytesRead, NULL) || bytesRead != sizeof(signature) ||
        signature != IMAGE_NT_SIGNATURE || !ReadFile(fileHandle, &fileHeader, sizeof(fileHeader), &bytesRead, NULL) ||
        bytesRead != sizeof(fileHeader))
    {
        err = GetLastError();
        if (err == ERROR_SUCCESS)
        {
            err = ERROR_BAD_EXE_FORMAT;
        }
        goto Cleanup;
    }

    if (fileHeader.SizeOfOptionalHeader < sizeof(WORD) ||
        !ReadFile(fileHandle, &optionalMagic, sizeof(optionalMagic), &bytesRead, NULL) ||
        bytesRead != sizeof(optionalMagic))
    {
        err = GetLastError();
        if (err == ERROR_SUCCESS)
        {
            err = ERROR_BAD_EXE_FORMAT;
        }
        goto Cleanup;
    }

    if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        if (fileHeader.SizeOfOptionalHeader < FIELD_OFFSET(IMAGE_OPTIONAL_HEADER32, Subsystem) + sizeof(subsystem))
        {
            err = ERROR_BAD_EXE_FORMAT;
            goto Cleanup;
        }
        offset.QuadPart = dosHeader.e_lfanew + sizeof(signature) + sizeof(fileHeader) +
                          FIELD_OFFSET(IMAGE_OPTIONAL_HEADER32, Subsystem);
    }
    else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        if (fileHeader.SizeOfOptionalHeader < FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, Subsystem) + sizeof(subsystem))
        {
            err = ERROR_BAD_EXE_FORMAT;
            goto Cleanup;
        }
        offset.QuadPart = dosHeader.e_lfanew + sizeof(signature) + sizeof(fileHeader) +
                          FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, Subsystem);
    }
    else
    {
        err = ERROR_BAD_EXE_FORMAT;
        goto Cleanup;
    }

    if (!SetFilePointerEx(fileHandle, offset, NULL, FILE_BEGIN) ||
        !ReadFile(fileHandle, &subsystem, sizeof(subsystem), &bytesRead, NULL) || bytesRead != sizeof(subsystem))
    {
        err = GetLastError();
        if (err == ERROR_SUCCESS)
        {
            err = ERROR_BAD_EXE_FORMAT;
        }
        goto Cleanup;
    }

    *SubsystemOut = subsystem;
    CloseHandle(fileHandle);
    return TRUE;

Cleanup:
    CloseHandle(fileHandle);
    SetLastError((err == ERROR_SUCCESS) ? ERROR_BAD_EXE_FORMAT : err);
    return FALSE;
}

typedef BOOL(WINAPI *BK_IS_WOW64_PROCESS2_FN)(_In_ HANDLE ProcessHandle, _Out_ USHORT *ProcessMachine,
                                              _Out_ USHORT *NativeMachine);

static BOOL ControllerInjectionQueryProcessMachine(_In_ HANDLE ProcessHandle, _Out_ USHORT *ProcessMachineOut,
                                                   _Out_opt_ USHORT *NativeMachineOut)
{
    HMODULE kernel32Module = NULL;
    BK_IS_WOW64_PROCESS2_FN isWow64Process2Fn = NULL;
    USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    BOOL wow64 = FALSE;

    if (ProcessHandle == NULL || ProcessHandle == INVALID_HANDLE_VALUE || ProcessMachineOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    kernel32Module = GetModuleHandleW(L"kernel32.dll");
    isWow64Process2Fn =
        (kernel32Module != NULL) ? (BK_IS_WOW64_PROCESS2_FN)GetProcAddress(kernel32Module, "IsWow64Process2") : NULL;
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

DWORD ControllerInjectionValidateHookArchitecture(_In_ HANDLE ProcessHandle, _In_z_ PCWSTR HookDllPath)
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

BOOL ControllerInjectionResolveHookDllPath(_In_ const BKIPC_SET_USER_HOOK_TARGET_REQUEST *Request,
                                           _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars)
{
    WCHAR modulePath[BK_MAX_IMAGE_PATH_CHARS];
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
