#include "..\common\bkaes_sample.h"

int RunFuzzRegistryPaths()
{
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\SECURITY\\Policy\\Secrets\\FuzzSecret", L"CurrVal",
                        L"redacted");
    const wchar_t* paths[] = {
        L"SOFTWARE\\BKAES\\DoesNotExist",
        L"Software\\BKAES\\SECURITY\\Policy\\Secrets",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        L"SYSTEM\\CurrentControlSet\\Services",
        L"SECURITY\\Policy\\Secrets",
        L"SAM",
        L"SOFTWARE\\Classes\\CLSID",
        L"SOFTWARE\\Microsoft\\Windows Script Host\\Settings",
    };
    for (const wchar_t* path : paths)
    {
        BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, path, nullptr);
        BkaesQueryKeyValue(HKEY_CURRENT_USER, path, nullptr);
    }
    BkaesSettleTelemetry();
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\BKAES\\SECURITY\\Policy\\Secrets\\FuzzSecret");
    BkaesPrint("[OK] registry path fuzzer completed\n");
    return 0;
}
