#define UNICODE
#define _UNICODE
#include <windows.h>
#include <strsafe.h>
#include <stdio.h>

static void write_audit_line(const wchar_t *file_name, const char *line)
{
    wchar_t job_dir[MAX_PATH];
    wchar_t path[MAX_PATH];
    DWORD length = GetEnvironmentVariableW(L"BKAES_AUDIT_JOB_DIR", job_dir, ARRAYSIZE(job_dir));
    if (length == 0 || length >= ARRAYSIZE(job_dir) ||
        FAILED(StringCchPrintfW(path, ARRAYSIZE(path), L"%s\\%s", job_dir, file_name))) {
        return;
    }
    HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD written = 0;
    WriteFile(file, line, (DWORD)strlen(line), &written, NULL);
    CloseHandle(file);
}

int wmain(void)
{
    wchar_t temp_root[MAX_PATH];
    wchar_t work_dir[MAX_PATH];
    wchar_t settings_path[MAX_PATH];
    char payload[512];
    char readback[512] = {0};
    DWORD temp_len = GetTempPathW(ARRAYSIZE(temp_root), temp_root);
    if (temp_len == 0 || temp_len >= ARRAYSIZE(temp_root) ||
        FAILED(StringCchPrintfW(work_dir, ARRAYSIZE(work_dir), L"%sbkaes-c-normal-%lu",
                                temp_root, GetCurrentProcessId())) ||
        FAILED(StringCchPrintfW(settings_path, ARRAYSIZE(settings_path), L"%s\\settings.json", work_dir))) {
        write_audit_line(L"bkaes-assertions.txt", "[BKAES_ASSERT_FAIL] c_native path setup failed\r\n");
        return 1;
    }

    CreateDirectoryW(work_dir, NULL);
    SYSTEM_INFO system_info;
    SYSTEMTIME now;
    wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD computer_len = ARRAYSIZE(computer);
    GetNativeSystemInfo(&system_info);
    GetSystemTime(&now);
    GetComputerNameW(computer, &computer_len);

    int payload_len = sprintf_s(payload, sizeof(payload),
        "{\"schema\":1,\"workers\":%lu,\"year\":%u,\"mode\":\"normal\"}\r\n",
        system_info.dwNumberOfProcessors, now.wYear);
    HANDLE file = CreateFileW(settings_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_ARCHIVE, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        write_audit_line(L"bkaes-assertions.txt", "[BKAES_ASSERT_FAIL] c_native create failed\r\n");
        RemoveDirectoryW(work_dir);
        return 2;
    }
    DWORD written = 0;
    BOOL wrote = WriteFile(file, payload, (DWORD)payload_len, &written, NULL);
    FlushFileBuffers(file);
    CloseHandle(file);

    file = CreateFileW(settings_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    DWORD read = 0;
    BOOL read_ok = file != INVALID_HANDLE_VALUE &&
                   ReadFile(file, readback, sizeof(readback) - 1, &read, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }
    unsigned long checksum = 5381;
    for (DWORD i = 0; i < read; ++i) {
        checksum = ((checksum << 5) + checksum) ^ (unsigned char)readback[i];
    }

    Sleep(350);
    DeleteFileW(settings_path);
    RemoveDirectoryW(work_dir);
    if (!wrote || written != (DWORD)payload_len || !read_ok || read != (DWORD)payload_len) {
        write_audit_line(L"bkaes-assertions.txt", "[BKAES_ASSERT_FAIL] c_native readback mismatch\r\n");
        return 3;
    }

    char outcome[512];
    sprintf_s(outcome, sizeof(outcome),
              "[BKAES_OUTCOME] benign_c_native=passed bytes=%lu checksum=0x%08lX workers=%lu\r\n",
              read, checksum, system_info.dwNumberOfProcessors);
    write_audit_line(L"bkaes-protection-outcome.txt", outcome);
    printf("%s", outcome);
    return 0;
}
