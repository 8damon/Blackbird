#include "internal.h"

DWORD ControllerInjectionNtStatusToWin32(_In_ LONG Status)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    RtlNtStatusToDosErrorFn mapStatus = NULL;

    if (Status >= 0)
    {
        return ERROR_SUCCESS;
    }
    if (ntdll != NULL)
    {
        mapStatus = reinterpret_cast<RtlNtStatusToDosErrorFn>(GetProcAddress(ntdll, "RtlNtStatusToDosError"));
        if (mapStatus != NULL)
        {
            DWORD mapped = static_cast<DWORD>(mapStatus(Status));
            if (mapped != ERROR_MR_MID_NOT_FOUND && mapped != ERROR_SUCCESS)
            {
                return mapped;
            }
        }
    }
    return ERROR_GEN_FAILURE;
}

VOID ControllerInjectionInitUnicodeString(_Out_ PBB_UNICODE_STRING String, _In_opt_z_ PCWSTR Buffer)
{
    size_t chars = 0;

    ZeroMemory(String, sizeof(*String));
    if (Buffer == NULL)
    {
        return;
    }

    chars = wcslen(Buffer);
    {
        size_t byteLength = chars * sizeof(WCHAR);
        size_t maxByteLength = (chars + 1u) * sizeof(WCHAR);
        String->Length = (USHORT)(byteLength > (size_t)0xFFFE ? (size_t)0xFFFE : byteLength);
        String->MaximumLength = (USHORT)(maxByteLength > (size_t)0xFFFF ? (size_t)0xFFFF : maxByteLength);
    }
    String->Buffer = const_cast<PWSTR>(Buffer);
}

VOID ControllerInjectionLogSr71Diagnostics(_In_ DWORD ProcessId)
{
    WCHAR programData[MAX_PATH];
    WCHAR logPath[MAX_PATH];
    DWORD chars;
    HANDLE fileHandle;
    LARGE_INTEGER fileSize;
    DWORD bytesToRead;
    DWORD bytesRead = 0;
    LARGE_INTEGER readOffset;
    std::vector<char> buffer;

    if (ProcessId == 0)
    {
        return;
    }

    ZeroMemory(programData, sizeof(programData));
    chars = GetEnvironmentVariableW(L"ProgramData", programData, RTL_NUMBER_OF(programData));
    if (chars == 0 || chars >= RTL_NUMBER_OF(programData))
    {
        (void)StringCchCopyW(programData, RTL_NUMBER_OF(programData), L"C:\\ProgramData");
    }

    if (FAILED(StringCchPrintfW(logPath, RTL_NUMBER_OF(logPath), L"%s\\Blackbird\\Node\\logs\\sr71-%lu.log",
                                programData, ProcessId)))
    {
        return;
    }

    fileHandle = CreateFileW(logPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        ControllerLog("[SR71][DIAG] no launch trace for pid=%lu path=%ws err=%lu\n", ProcessId, logPath,
                      GetLastError());
        return;
    }

    if (!GetFileSizeEx(fileHandle, &fileSize) || fileSize.QuadPart <= 0)
    {
        CloseHandle(fileHandle);
        return;
    }

    bytesToRead = (fileSize.QuadPart > 4096) ? 4096u : (DWORD)fileSize.QuadPart;
    readOffset.QuadPart = fileSize.QuadPart - bytesToRead;
    buffer.resize((size_t)bytesToRead + 1u);
    if (SetFilePointerEx(fileHandle, readOffset, NULL, FILE_BEGIN) &&
        ReadFile(fileHandle, buffer.data(), bytesToRead, &bytesRead, NULL) && bytesRead != 0)
    {
        buffer[bytesRead] = '\0';
        ControllerLog("[SR71][DIAG] launch trace pid=%lu tail:\n%.*s\n", ProcessId, bytesRead, buffer.data());
    }
    CloseHandle(fileHandle);
}

PCWSTR ControllerInjectionFileNameFromPath(_In_z_ PCWSTR Path)
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

DWORD ControllerInjectionSuspendProcessHandle(_In_ HANDLE ProcessHandle)
{
    HMODULE ntdll = NULL;
    NtSuspendProcessFn suspendProcess = nullptr;
    RtlNtStatusToDosErrorFn mapStatus = nullptr;
    LONG status;

    if (ProcessHandle == NULL || ProcessHandle == INVALID_HANDLE_VALUE)
    {
        return ERROR_INVALID_HANDLE;
    }

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL)
    {
        return GetLastError() != ERROR_SUCCESS ? GetLastError() : ERROR_MOD_NOT_FOUND;
    }

    suspendProcess = reinterpret_cast<NtSuspendProcessFn>(GetProcAddress(ntdll, "NtSuspendProcess"));
    if (suspendProcess == nullptr)
    {
        return ERROR_PROC_NOT_FOUND;
    }

    status = suspendProcess(ProcessHandle);
    if (status >= 0)
    {
        return ERROR_SUCCESS;
    }

    mapStatus = reinterpret_cast<RtlNtStatusToDosErrorFn>(GetProcAddress(ntdll, "RtlNtStatusToDosError"));
    if (mapStatus != nullptr)
    {
        DWORD mapped = static_cast<DWORD>(mapStatus(status));
        if (mapped != ERROR_MR_MID_NOT_FOUND && mapped != ERROR_SUCCESS)
        {
            return mapped;
        }
    }

    return ERROR_GEN_FAILURE;
}
