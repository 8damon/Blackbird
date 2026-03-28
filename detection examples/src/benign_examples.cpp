#include "../include/detection_examples.h"

static int RunInternalSleeper()
{
    Sleep(15000);
    return 0;
}

int ExampleRunBenignLaunch(int argc, wchar_t **argv)
{
    PROCESS_INFORMATION pi;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    if (!ExampleLaunchInternalChild(L"sleep-child", &pi))
    {
        ExamplePrint("[FAIL] benign-launch CreateProcess failed err=%lu\n", GetLastError());
        return 1;
    }

    ExamplePrint("[OK] benign-launch childPid=%lu launched and terminated cleanly\n", pi.dwProcessId);
    ExampleCleanupProcess(&pi, true, 2000);
    return 0;
}

int ExampleRunBenignFileIo(int argc, wchar_t **argv)
{
    wchar_t tempPath[MAX_PATH];
    wchar_t filePath[MAX_PATH];
    HANDLE file;
    const char payload[] = "blackbird benign file io\n";
    char buffer[64];
    DWORD written = 0;
    DWORD read = 0;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    if (GetTempPathW(ARRAYSIZE(tempPath), tempPath) == 0)
    {
        ExamplePrint("[FAIL] benign-file-io GetTempPathW err=%lu\n", GetLastError());
        return 1;
    }
    if (FAILED(StringCchPrintfW(filePath, ARRAYSIZE(filePath), L"%lsBlackbird.BenignFileIo.tmp", tempPath)))
    {
        ExamplePrint("[FAIL] benign-file-io path build failed\n");
        return 1;
    }

    file = CreateFileW(filePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        ExamplePrint("[FAIL] benign-file-io CreateFileW err=%lu\n", GetLastError());
        return 1;
    }

    if (!WriteFile(file, payload, (DWORD)strlen(payload), &written, nullptr) || written != strlen(payload))
    {
        ExamplePrint("[FAIL] benign-file-io WriteFile err=%lu\n", GetLastError());
        CloseHandle(file);
        DeleteFileW(filePath);
        return 1;
    }

    SetFilePointer(file, 0, nullptr, FILE_BEGIN);
    ZeroMemory(buffer, sizeof(buffer));
    if (!ReadFile(file, buffer, sizeof(buffer) - 1, &read, nullptr))
    {
        ExamplePrint("[FAIL] benign-file-io ReadFile err=%lu\n", GetLastError());
        CloseHandle(file);
        DeleteFileW(filePath);
        return 1;
    }

    CloseHandle(file);
    DeleteFileW(filePath);
    ExamplePrint("[OK] benign-file-io wrote=%lu read=%lu\n", written, read);
    return 0;
}

int ExampleRunBenignMemory(int argc, wchar_t **argv)
{
    BYTE *buffer;
    DWORD oldProtect = 0;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    buffer = (BYTE *)VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (buffer == nullptr)
    {
        ExamplePrint("[FAIL] benign-memory VirtualAlloc err=%lu\n", GetLastError());
        return 1;
    }

    memset(buffer, 0x41, 4096);
    if (!VirtualProtect(buffer, 4096, PAGE_READONLY, &oldProtect))
    {
        ExamplePrint("[FAIL] benign-memory VirtualProtect err=%lu\n", GetLastError());
        VirtualFree(buffer, 0, MEM_RELEASE);
        return 1;
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    ExamplePrint("[OK] benign-memory self allocation/write/protect completed\n");
    return 0;
}

int ExampleRunBenignProcessEnum(int argc, wchar_t **argv)
{
    HANDLE snapshot;
    PROCESSENTRY32W entry;
    int count = 0;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        ExamplePrint("[FAIL] benign-process-enum snapshot err=%lu\n", GetLastError());
        return 1;
    }

    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            count += 1;
        } while (Process32NextW(snapshot, &entry) && count < 64);
    }

    CloseHandle(snapshot);
    ExamplePrint("[OK] benign-process-enum enumerated=%d processes\n", count);
    return 0;
}

int DetectionExamplesInternalBenignMain(const wchar_t *mode)
{
    if (_wcsicmp(mode, L"sleep-child") == 0)
    {
        return RunInternalSleeper();
    }
    return -1;
}
