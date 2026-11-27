#include "../include/detection_examples.h"

#include <algorithm>
#include <cstdarg>

void ExamplePrint(const char* format, ...)
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
    if (len == 0 || len >= ARRAYSIZE(path))
    {
        AES_LOG_ERROR("GetModuleFileNameW failed len=%lu err=%lu", len, GetLastError());
        return std::wstring();
    }

    AES_LOG_DEBUG("Resolved self path=%ls", path);
    return std::wstring(path, len);
}

bool ExampleLaunchInternalChild(const wchar_t* mode, PROCESS_INFORMATION* pi, DWORD creationFlags)
{
    STARTUPINFOW si;
    std::wstring selfPath;
    wchar_t commandLine[(MAX_PATH * 2) + 128];

    if (mode == nullptr || pi == nullptr)
    {
        AES_LOG_ERROR("LaunchInternalChild invalid args mode=%p pi=%p", mode, pi);
        return false;
    }

    selfPath = ExampleGetSelfPath();
    if (selfPath.empty())
    {
        AES_LOG_ERROR("LaunchInternalChild failed because self path is empty");
        return false;
    }

    ZeroMemory(pi, sizeof(*pi));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    if (FAILED(
            StringCchPrintfW(commandLine, ARRAYSIZE(commandLine), L"\"%ls\" --internal %ls", selfPath.c_str(), mode)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        AES_LOG_ERROR("LaunchInternalChild command line buffer too small mode=%ls", mode);
        return false;
    }

    AES_LOG_DEBUG("CreateProcessW internal mode=%ls flags=0x%08lX commandLine=%ls", mode, creationFlags, commandLine);
    if (CreateProcessW(nullptr, commandLine, nullptr, nullptr, FALSE, creationFlags, nullptr, nullptr, &si, pi) != TRUE)
    {
        AES_LOG_ERROR("CreateProcessW internal mode=%ls failed err=%lu", mode, GetLastError());
        return false;
    }

    AES_LOG_INFO("Created internal child mode=%ls pid=%lu tid=%lu", mode, pi->dwProcessId, pi->dwThreadId);
    return true;
}

void ExampleCleanupProcess(PROCESS_INFORMATION* pi, bool terminate, DWORD waitMs)
{
    if (pi == nullptr)
    {
        AES_LOG_WARN("CleanupProcess called with null PROCESS_INFORMATION");
        return;
    }

    AES_LOG_DEBUG("CleanupProcess pid=%lu tid=%lu terminate=%d waitMs=%lu hProcess=%p hThread=%p", pi->dwProcessId,
                  pi->dwThreadId, terminate ? 1 : 0, waitMs, pi->hProcess, pi->hThread);
    if (pi->hProcess != nullptr)
    {
        if (terminate)
        {
            if (!TerminateProcess(pi->hProcess, 0))
            {
                AES_LOG_WARN("TerminateProcess pid=%lu failed err=%lu", pi->dwProcessId, GetLastError());
            }
            else
            {
                AES_LOG_DEBUG("TerminateProcess pid=%lu requested", pi->dwProcessId);
            }
        }
        AES_LOG_DEBUG("WaitForSingleObject pid=%lu waitMs=%lu result=0x%08lX", pi->dwProcessId, waitMs,
                      WaitForSingleObject(pi->hProcess, waitMs));
        CloseHandle(pi->hProcess);
        pi->hProcess = nullptr;
    }
    if (pi->hThread != nullptr)
    {
        CloseHandle(pi->hThread);
        pi->hThread = nullptr;
    }
}

DWORD ExampleFindProcessIdByName(const wchar_t* name)
{
    HANDLE snapshot;
    PROCESSENTRY32W entry;

    if (name == nullptr || name[0] == L'\0')
    {
        AES_LOG_ERROR("FindProcessIdByName called with empty name");
        return 0;
    }

    AES_LOG_DEBUG("Creating process snapshot for name=%ls", name);
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        AES_LOG_ERROR("CreateToolhelp32Snapshot failed err=%lu", GetLastError());
        return 0;
    }

    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry))
    {
        AES_LOG_ERROR("Process32FirstW failed err=%lu", GetLastError());
        CloseHandle(snapshot);
        return 0;
    }

    do
    {
        if (_wcsicmp(entry.szExeFile, name) == 0)
        {
            AES_LOG_INFO("Found process name=%ls pid=%lu", name, entry.th32ProcessID);
            CloseHandle(snapshot);
            return entry.th32ProcessID;
        }
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    AES_LOG_WARN("Process not found name=%ls", name);
    return 0;
}
