#include "../include/detection_examples.h"

#include <algorithm>
#include <cstdarg>

void ExamplePrint(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

std::wstring ExampleGetSelfPath()
{
    wchar_t path[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, path, ARRAYSIZE(path));
    return (len != 0 && len < ARRAYSIZE(path)) ? std::wstring(path, len) : std::wstring();
}

bool ExampleLaunchInternalChild(const wchar_t *mode, PROCESS_INFORMATION *pi, DWORD creationFlags)
{
    STARTUPINFOW si;
    std::wstring selfPath;
    wchar_t commandLine[(MAX_PATH * 2) + 128];

    if (mode == nullptr || pi == nullptr)
    {
        return false;
    }

    selfPath = ExampleGetSelfPath();
    if (selfPath.empty())
    {
        return false;
    }

    ZeroMemory(pi, sizeof(*pi));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    if (FAILED(
            StringCchPrintfW(commandLine, ARRAYSIZE(commandLine), L"\"%ls\" --internal %ls", selfPath.c_str(), mode)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return false;
    }

    return CreateProcessW(nullptr, commandLine, nullptr, nullptr, FALSE, creationFlags, nullptr, nullptr, &si, pi) ==
           TRUE;
}

void ExampleCleanupProcess(PROCESS_INFORMATION *pi, bool terminate, DWORD waitMs)
{
    if (pi == nullptr)
    {
        return;
    }

    if (pi->hProcess != nullptr)
    {
        if (terminate)
        {
            (void)TerminateProcess(pi->hProcess, 0);
        }
        (void)WaitForSingleObject(pi->hProcess, waitMs);
        CloseHandle(pi->hProcess);
        pi->hProcess = nullptr;
    }
    if (pi->hThread != nullptr)
    {
        CloseHandle(pi->hThread);
        pi->hThread = nullptr;
    }
}

DWORD ExampleFindProcessIdByName(const wchar_t *name)
{
    HANDLE snapshot;
    PROCESSENTRY32W entry;

    if (name == nullptr || name[0] == L'\0')
    {
        return 0;
    }

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry))
    {
        CloseHandle(snapshot);
        return 0;
    }

    do
    {
        if (_wcsicmp(entry.szExeFile, name) == 0)
        {
            CloseHandle(snapshot);
            return entry.th32ProcessID;
        }
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return 0;
}
