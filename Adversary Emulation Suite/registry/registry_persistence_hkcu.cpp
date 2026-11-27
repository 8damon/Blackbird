#include "..\common\bkaes_sample.h"

int RunRegistryPersistenceHkcu()
{
    const wchar_t* benign = L"C:\\Windows\\System32\\cmd.exe /c exit";
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Microsoft\\Windows\\CurrentVersion\\Run", L"BKAES_Run",
                        benign);
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                        L"BKAES_RunOnce", benign);
    BkaesSetStringValue(
        HKEY_CURRENT_USER,
        L"Software\\BKAES\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\bkaes-target.exe",
        L"Debugger", benign);
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                        L"Shell", L"explorer.exe");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                        L"AppInit_DLLs", L"bkaes.dll");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Control\\Session Manager",
                        L"BootExecute", L"autocheck autochk *");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Services\\BKAESBench",
                        L"ImagePath", benign);
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\Classes\\CLSID\\{11111111-1111-1111-1111-111111111111}\\InprocServer32",
                        nullptr, L"bkaes.dll");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Microsoft\\WMI\\Security", L"BKAES", L"1");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\BKAES",
                        L"Id", L"{11111111-1111-1111-1111-111111111111}");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Microsoft\\Windows Defender\\Exclusions\\Paths", L"BKAES",
                        L"C:\\BKAES");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Control\\Lsa",
                        L"Authentication Packages", L"msv1_0");

    BkaesSettleTelemetry();
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\BKAES");
    BkaesPrint("[OK] HKCU persistence surface writes completed and cleanup requested\n");
    return 0;
}
