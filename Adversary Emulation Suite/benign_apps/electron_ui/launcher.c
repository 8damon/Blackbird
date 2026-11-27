#define UNICODE
#define _UNICODE
#include <windows.h>
#include <strsafe.h>

static void assertion(const char *reason)
{
    wchar_t dir[MAX_PATH], path[MAX_PATH];
    if (GetEnvironmentVariableW(L"BKAES_AUDIT_JOB_DIR", dir, ARRAYSIZE(dir)) == 0 ||
        FAILED(StringCchPrintfW(path, ARRAYSIZE(path), L"%s\\bkaes-assertions.txt", dir))) return;
    HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return;
    const char prefix[] = "[BKAES_ASSERT_FAIL] electron_launcher ";
    DWORD written;
    WriteFile(file, prefix, sizeof(prefix) - 1, &written, NULL);
    WriteFile(file, reason, (DWORD)strlen(reason), &written, NULL);
    WriteFile(file, "\r\n", 2, &written, NULL);
    CloseHandle(file);
}

int wmain(void)
{
    wchar_t cwd[MAX_PATH], exe[MAX_PATH], command[MAX_PATH + 4];
    if (GetCurrentDirectoryW(ARRAYSIZE(cwd), cwd) == 0 ||
        FAILED(StringCchPrintfW(exe, ARRAYSIZE(exe), L"%s\\BlackbirdBenignElectron.exe", cwd)) ||
        FAILED(StringCchPrintfW(command, ARRAYSIZE(command), L"\"%s\"", exe))) {
        assertion("path setup failed"); return 1;
    }
    STARTUPINFOW startup = { sizeof(startup) };
    PROCESS_INFORMATION process = {0};
    if (!CreateProcessW(exe, command, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT, NULL, cwd, &startup, &process)) {
        assertion("CreateProcess failed"); return 2;
    }
    CloseHandle(process.hThread);
    DWORD wait = WaitForSingleObject(process.hProcess, 20000);
    DWORD exitCode = 1;
    if (wait == WAIT_TIMEOUT) {
        TerminateProcess(process.hProcess, 124);
        assertion("child timeout");
        exitCode = 124;
    } else {
        GetExitCodeProcess(process.hProcess, &exitCode);
        if (exitCode != 0) assertion("child returned nonzero");
    }
    CloseHandle(process.hProcess);
    return (int)exitCode;
}
