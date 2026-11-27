#include "bkaes_common.h"

void BkaesPrint(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void BkaesSettleTelemetry(DWORD waitMs)
{
    Sleep(waitMs);
}

std::wstring BkaesSelfPath()
{
    wchar_t path[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, path, ARRAYSIZE(path));
    if (len == 0 || len >= ARRAYSIZE(path))
    {
        return std::wstring();
    }
    return std::wstring(path, len);
}

std::wstring BkaesSelfDirectory()
{
    std::wstring path = BkaesSelfPath();
    size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
    {
        return L".";
    }
    return path.substr(0, slash);
}

std::wstring BkaesTempPath(const wchar_t* fileName)
{
    wchar_t temp[MAX_PATH];
    wchar_t path[MAX_PATH];
    if (GetTempPathW(ARRAYSIZE(temp), temp) == 0)
    {
        return std::wstring();
    }
    if (FAILED(StringCchPrintfW(path, ARRAYSIZE(path), L"%ls%ls", temp, fileName)))
    {
        return std::wstring();
    }
    return std::wstring(path);
}

bool BkaesWriteTextFile(const std::wstring& path, const char* text)
{
    DWORD written = 0;
    HANDLE file =
        CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    const DWORD bytes = (DWORD)strlen(text);
    bool ok = WriteFile(file, text, bytes, &written, nullptr) && written == bytes;
    CloseHandle(file);
    return ok;
}

std::vector<wchar_t> BkaesMutableCommandLine(const std::wstring& commandLine)
{
    std::vector<wchar_t> buffer(commandLine.begin(), commandLine.end());
    buffer.push_back(L'\0');
    return buffer;
}

bool BkaesLaunchSelfChild(PROCESS_INFORMATION* pi, DWORD creationFlags)
{
    STARTUPINFOW si;
    std::wstring self = BkaesSelfPath();
    wchar_t cmd[(MAX_PATH * 2) + 64];

    if (self.empty() || pi == nullptr)
    {
        return false;
    }

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(pi, sizeof(*pi));
    si.cb = sizeof(si);
    if (FAILED(StringCchPrintfW(cmd, ARRAYSIZE(cmd), L"\"%ls\" --child-sleep", self.c_str())))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return false;
    }

    return CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, creationFlags, nullptr, nullptr, &si, pi) == TRUE;
}

int BkaesMaybeRunChildMode(int argc, wchar_t** argv)
{
    if (argc >= 2 && _wcsicmp(argv[1], L"--child-sleep") == 0)
    {
        Sleep(15000);
        return 0;
    }
    return INT_MIN;
}

void BkaesCleanupProcess(PROCESS_INFORMATION* pi, bool terminate, DWORD waitMs)
{
    if (pi == nullptr)
    {
        return;
    }
    if (pi->hProcess != nullptr)
    {
        if (terminate)
        {
            TerminateProcess(pi->hProcess, 0);
        }
        WaitForSingleObject(pi->hProcess, waitMs);
        CloseHandle(pi->hProcess);
        pi->hProcess = nullptr;
    }
    if (pi->hThread != nullptr)
    {
        CloseHandle(pi->hThread);
        pi->hThread = nullptr;
    }
}

DWORD BkaesFindProcessIdByName(const wchar_t* imageName)
{
    HANDLE snapshot;
    PROCESSENTRY32W entry;

    if (imageName == nullptr || imageName[0] == L'\0')
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
    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (_wcsicmp(entry.szExeFile, imageName) == 0)
            {
                DWORD pid = entry.th32ProcessID;
                CloseHandle(snapshot);
                return pid;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

bool BkaesCreateSuspendedProcess(const std::wstring& commandLine, PROCESS_INFORMATION* pi)
{
    STARTUPINFOW si;
    std::vector<wchar_t> mutableCommand = BkaesMutableCommandLine(commandLine);

    if (pi == nullptr)
    {
        return false;
    }

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(pi, sizeof(*pi));
    si.cb = sizeof(si);
    return CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW,
                          nullptr, nullptr, &si, pi) == TRUE;
}

void BkaesTerminateAfterCreateTelemetry(PROCESS_INFORMATION* pi)
{
    if (pi == nullptr)
    {
        return;
    }
    BkaesSettleTelemetry();
    BkaesCleanupProcess(pi, true, 2500);
}

bool BkaesIsSensitiveEnabled(int argc, wchar_t** argv)
{
    wchar_t value[8];
    DWORD len = GetEnvironmentVariableW(L"BKAES_ENABLE_SENSITIVE", value, ARRAYSIZE(value));
    if (len > 0 && (_wcsicmp(value, L"1") == 0 || _wcsicmp(value, L"true") == 0))
    {
        return true;
    }

    for (int i = 1; i < argc; ++i)
    {
        if (_wcsicmp(argv[i], L"--enable-sensitive") == 0)
        {
            return true;
        }
    }
    return false;
}
