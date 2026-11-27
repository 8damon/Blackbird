#include "../include/detection_examples.h"

static int RunInternalSleeper()
{
    AES_LOG_DEBUG("Benign internal sleeper entering Sleep");
    Sleep(15000);
    AES_LOG_DEBUG("Benign internal sleeper exiting");
    return 0;
}

int ExampleRunBenignLaunch(int argc, wchar_t** argv)
{
    PROCESS_INFORMATION pi;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    AES_LOG_DEBUG("Launching benign child process");
    if (!ExampleLaunchInternalChild(L"benign-sleep-child", &pi))
    {
        ExamplePrint("[FAIL] benign-launch CreateProcess failed err=%lu\n", GetLastError());
        return 1;
    }

    AES_LOG_INFO("Benign child launched pid=%lu tid=%lu", pi.dwProcessId, pi.dwThreadId);
    ExamplePrint("[OK] benign-launch childPid=%lu launched and terminated cleanly\n", pi.dwProcessId);
    ExampleCleanupProcess(&pi, true, 2000);
    return 0;
}

int ExampleRunBenignFileIo(int argc, wchar_t** argv)
{
    wchar_t tempPath[MAX_PATH];
    wchar_t filePath[MAX_PATH];
    HANDLE file;
    const char payload[] = "aes benign file io\n";
    char buffer[64];
    DWORD written = 0;
    DWORD read = 0;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    AES_LOG_DEBUG("Resolving temp path for benign file IO");
    if (GetTempPathW(ARRAYSIZE(tempPath), tempPath) == 0)
    {
        AES_LOG_ERROR("GetTempPathW failed err=%lu", GetLastError());
        ExamplePrint("[FAIL] benign-file-io GetTempPathW err=%lu\n", GetLastError());
        return 1;
    }
    if (FAILED(StringCchPrintfW(filePath, ARRAYSIZE(filePath), L"%lsBkaes.BenignFileIo.tmp", tempPath)))
    {
        AES_LOG_ERROR("Failed to build benign temp file path tempPath=%ls", tempPath);
        ExamplePrint("[FAIL] benign-file-io path build failed\n");
        return 1;
    }
    AES_LOG_DEBUG("Benign temp file path=%ls", filePath);

    file = CreateFileW(filePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY,
                       nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        AES_LOG_ERROR("CreateFileW path=%ls failed err=%lu", filePath, GetLastError());
        ExamplePrint("[FAIL] benign-file-io CreateFileW err=%lu\n", GetLastError());
        return 1;
    }
    AES_LOG_DEBUG("CreateFileW path=%ls handle=%p", filePath, file);

    AES_LOG_DEBUG("Writing benign payload bytes=%zu", strlen(payload));
    if (!WriteFile(file, payload, (DWORD)strlen(payload), &written, nullptr) || written != strlen(payload))
    {
        AES_LOG_ERROR("WriteFile path=%ls wrote=%lu expected=%zu err=%lu", filePath, written, strlen(payload),
                      GetLastError());
        ExamplePrint("[FAIL] benign-file-io WriteFile err=%lu\n", GetLastError());
        CloseHandle(file);
        DeleteFileW(filePath);
        return 1;
    }
    AES_LOG_DEBUG("WriteFile path=%ls wrote=%lu", filePath, written);

    SetFilePointer(file, 0, nullptr, FILE_BEGIN);
    ZeroMemory(buffer, sizeof(buffer));
    AES_LOG_DEBUG("Reading benign payload back");
    if (!ReadFile(file, buffer, sizeof(buffer) - 1, &read, nullptr))
    {
        AES_LOG_ERROR("ReadFile path=%ls failed err=%lu", filePath, GetLastError());
        ExamplePrint("[FAIL] benign-file-io ReadFile err=%lu\n", GetLastError());
        CloseHandle(file);
        DeleteFileW(filePath);
        return 1;
    }
    AES_LOG_DEBUG("ReadFile path=%ls read=%lu buffer=%s", filePath, read, buffer);

    CloseHandle(file);
    if (!DeleteFileW(filePath))
    {
        AES_LOG_WARN("DeleteFileW path=%ls failed err=%lu", filePath, GetLastError());
    }
    else
    {
        AES_LOG_DEBUG("Deleted benign temp file path=%ls", filePath);
    }
    ExamplePrint("[OK] benign-file-io wrote=%lu read=%lu\n", written, read);
    return 0;
}

int ExampleRunBenignMemory(int argc, wchar_t** argv)
{
    BYTE* buffer;
    DWORD oldProtect = 0;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    AES_LOG_DEBUG("Allocating local benign memory bytes=4096");
    buffer = (BYTE*)VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (buffer == nullptr)
    {
        AES_LOG_ERROR("VirtualAlloc local benign memory failed err=%lu", GetLastError());
        ExamplePrint("[FAIL] benign-memory VirtualAlloc err=%lu\n", GetLastError());
        return 1;
    }
    AES_LOG_DEBUG("VirtualAlloc local benign memory base=%p", buffer);

    memset(buffer, 0x41, 4096);
    AES_LOG_DEBUG("Filled benign memory base=%p bytes=4096", buffer);
    if (!VirtualProtect(buffer, 4096, PAGE_READONLY, &oldProtect))
    {
        AES_LOG_ERROR("VirtualProtect local benign memory base=%p failed err=%lu", buffer, GetLastError());
        ExamplePrint("[FAIL] benign-memory VirtualProtect err=%lu\n", GetLastError());
        VirtualFree(buffer, 0, MEM_RELEASE);
        return 1;
    }
    AES_LOG_DEBUG("VirtualProtect local benign memory base=%p oldProtect=0x%08lX", buffer, oldProtect);

    if (!VirtualFree(buffer, 0, MEM_RELEASE))
    {
        AES_LOG_WARN("VirtualFree local benign memory base=%p failed err=%lu", buffer, GetLastError());
    }
    else
    {
        AES_LOG_DEBUG("VirtualFree local benign memory base=%p", buffer);
    }
    ExamplePrint("[OK] benign-memory self allocation/write/protect completed\n");
    return 0;
}

int ExampleRunBenignProcessEnum(int argc, wchar_t** argv)
{
    HANDLE snapshot;
    PROCESSENTRY32W entry;
    int count = 0;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    AES_LOG_DEBUG("Creating benign process snapshot");
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        AES_LOG_ERROR("CreateToolhelp32Snapshot benign process enum failed err=%lu", GetLastError());
        ExamplePrint("[FAIL] benign-process-enum snapshot err=%lu\n", GetLastError());
        return 1;
    }
    AES_LOG_DEBUG("Created process snapshot handle=%p", snapshot);

    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            AES_LOG_TRACE("Process entry index=%d pid=%lu name=%ls", count, entry.th32ProcessID, entry.szExeFile);
            count += 1;
        } while (Process32NextW(snapshot, &entry) && count < 64);
    }
    else
    {
        AES_LOG_WARN("Process32FirstW benign enum failed err=%lu", GetLastError());
    }

    CloseHandle(snapshot);
    AES_LOG_INFO("Benign process enum count=%d", count);
    ExamplePrint("[OK] benign-process-enum enumerated=%d processes\n", count);
    return 0;
}

int ExampleRunBenignRegistryIo(int argc, wchar_t** argv)
{
    static const wchar_t kKeyPath[] = L"Software\\Bkaes\\BenignRegistryIo";
    static const wchar_t kValueName[] = L"TestValue";
    static const wchar_t kValueData[] = L"aes benign registry io";
    static const wchar_t kSubKeyName[] = L"SubKey";
    HKEY hKey = nullptr;
    HKEY hSubKey = nullptr;
    DWORD disposition = 0;
    DWORD dataSize = 0;
    wchar_t readBuf[64];
    DWORD readSize = sizeof(readBuf);
    wchar_t enumBuf[64];
    DWORD enumSize = ARRAYSIZE(enumBuf);
    int result = 0;
    LSTATUS status = ERROR_SUCCESS;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    AES_LOG_DEBUG("Creating registry key HKCU\\%ls", kKeyPath);
    status = RegCreateKeyExW(HKEY_CURRENT_USER, kKeyPath, 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &hKey, &disposition);
    if (status != ERROR_SUCCESS)
    {
        AES_LOG_ERROR("RegCreateKeyExW key=%ls failed status=%ld", kKeyPath, status);
        ExamplePrint("[FAIL] benign-registry-io RegCreateKeyExW err=%ld\n", status);
        return 1;
    }
    AES_LOG_DEBUG("RegCreateKeyExW key=%ls handle=%p disposition=%lu", kKeyPath, hKey, disposition);

    dataSize = (DWORD)((wcslen(kValueData) + 1) * sizeof(wchar_t));
    AES_LOG_DEBUG("Setting registry value name=%ls bytes=%lu", kValueName, dataSize);
    status = RegSetValueExW(hKey, kValueName, 0, REG_SZ, (const BYTE*)kValueData, dataSize);
    if (status != ERROR_SUCCESS)
    {
        AES_LOG_ERROR("RegSetValueExW name=%ls failed status=%ld", kValueName, status);
        ExamplePrint("[FAIL] benign-registry-io RegSetValueExW err=%ld\n", status);
        result = 1;
        goto cleanup_key;
    }

    AES_LOG_DEBUG("Querying registry value name=%ls", kValueName);
    status = RegQueryValueExW(hKey, kValueName, nullptr, nullptr, (BYTE*)readBuf, &readSize);
    if (status != ERROR_SUCCESS)
    {
        AES_LOG_ERROR("RegQueryValueExW name=%ls failed status=%ld", kValueName, status);
        ExamplePrint("[FAIL] benign-registry-io RegQueryValueExW err=%ld\n", status);
        result = 1;
        goto cleanup_value;
    }
    AES_LOG_DEBUG("RegQueryValueExW name=%ls bytes=%lu value=%ls", kValueName, readSize, readBuf);

    AES_LOG_DEBUG("Creating registry subkey name=%ls", kSubKeyName);
    status = RegCreateKeyExW(hKey, kSubKeyName, 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &hSubKey, &disposition);
    if (status != ERROR_SUCCESS)
    {
        AES_LOG_ERROR("RegCreateKeyExW subkey=%ls failed status=%ld", kSubKeyName, status);
        ExamplePrint("[FAIL] benign-registry-io RegCreateKeyExW (subkey) err=%ld\n", status);
        result = 1;
        goto cleanup_value;
    }
    AES_LOG_DEBUG("RegCreateKeyExW subkey=%ls handle=%p disposition=%lu", kSubKeyName, hSubKey, disposition);
    RegCloseKey(hSubKey);
    hSubKey = nullptr;

    enumSize = ARRAYSIZE(enumBuf);
    status = RegEnumKeyExW(hKey, 0, enumBuf, &enumSize, nullptr, nullptr, nullptr, nullptr);
    if (status == ERROR_SUCCESS)
    {
        AES_LOG_DEBUG("RegEnumKeyExW firstSubkey=%ls chars=%lu", enumBuf, enumSize);
    }
    else
    {
        AES_LOG_WARN("RegEnumKeyExW failed status=%ld", status);
    }

cleanup_value:
    status = RegDeleteValueW(hKey, kValueName);
    if (status == ERROR_SUCCESS)
    {
        AES_LOG_DEBUG("Deleted registry value name=%ls", kValueName);
    }

cleanup_key:
    RegCloseKey(hKey);
    hKey = nullptr;
    status = RegDeleteKeyW(HKEY_CURRENT_USER, (std::wstring(kKeyPath) + L"\\" + kSubKeyName).c_str());
    if (status == ERROR_SUCCESS)
    {
        AES_LOG_DEBUG("Deleted registry subkey HKCU\\%ls\\%ls", kKeyPath, kSubKeyName);
    }
    status = RegDeleteKeyW(HKEY_CURRENT_USER, kKeyPath);
    if (status == ERROR_SUCCESS)
    {
        AES_LOG_DEBUG("Deleted registry key HKCU\\%ls", kKeyPath);
    }

    if (result == 0)
    {
        ExamplePrint("[OK] benign-registry-io create/set/query/enumerate/delete completed\n");
    }
    return result;
}

int DetectionExamplesInternalBenignMain(const wchar_t* mode)
{
    if (_wcsicmp(mode, L"benign-sleep-child") == 0)
    {
        return RunInternalSleeper();
    }
    return -1;
}
