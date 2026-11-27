#include "..\common\bkaes_sample.h"

int RunOkFileRegistry()
{
    std::wstring file = BkaesTempPath(L"bkaes-ok-file.tmp");
    BkaesWriteTextFile(file, "BKAES benign file IO\r\n");
    HANDLE h = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (h != INVALID_HANDLE_VALUE)
    {
        char buffer[64];
        DWORD read = 0;
        ReadFile(h, buffer, sizeof(buffer), &read, nullptr);
        CloseHandle(h);
    }
    DeleteFileW(file.c_str());

    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Benign", L"Value", L"benign");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Benign", L"Value");
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\BKAES\\Benign");
    BkaesPrint("[OK] benign file and registry sample completed\n");
    return 0;
}
