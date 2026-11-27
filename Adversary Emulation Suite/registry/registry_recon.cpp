#include "..\common\bkaes_sample.h"

int RunRegistryRecon()
{
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\SAM", nullptr, L"1");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\SECURITY\\Lsa\\Secrets", nullptr, L"1");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\SECURITY\\Lsa\\Credentials", nullptr, L"1");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Control\\Lsa",
                        L"Authentication Packages", L"msv1_0");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Control\\Lsa\\Kerberos",
                        nullptr, L"1");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0", nullptr,
                        L"1");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Services\\Kdc", nullptr, L"1");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Microsoft\\Windows Defender\\Exclusions", nullptr, L"1");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Policies\\Microsoft\\Windows\\PowerShell", nullptr, L"1");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters", nullptr, L"1");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Control\\Session Manager",
                        L"BootExecute", L"autocheck autochk *");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                        nullptr, L"1");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", nullptr,
                        L"1");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Services", nullptr, L"1");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Classes\\CLSID\\{11111111-1111-1111-1111-111111111111}",
                        nullptr, L"1");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Microsoft\\Windows Script Host\\Settings", nullptr, L"1");

    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SAM", nullptr);
    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SECURITY\\Lsa\\Secrets", nullptr);
    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SECURITY\\Lsa\\Credentials", nullptr);
    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages");
    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos", nullptr);
    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", nullptr);
    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Kdc", nullptr);
    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions", nullptr);
    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell", nullptr);
    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters", nullptr);
    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", L"BootExecute");
    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE,
                       L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", nullptr);
    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", nullptr);
    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", nullptr);
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\Classes\\CLSID", nullptr);
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows Script Host\\Settings", nullptr);
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\SAM", nullptr);
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\SECURITY\\Lsa\\Secrets", nullptr);
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\SECURITY\\Lsa\\Credentials", nullptr);
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Control\\Lsa",
                       L"Authentication Packages");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Control\\Lsa\\Kerberos",
                       nullptr);
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0", nullptr);
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Services\\Kdc", nullptr);
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Microsoft\\Windows Defender\\Exclusions", nullptr);
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Policies\\Microsoft\\Windows\\PowerShell", nullptr);
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters",
                       nullptr);
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Control\\Session Manager",
                       L"BootExecute");
    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                       nullptr);
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", nullptr);
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Services", nullptr);
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Classes\\CLSID\\{11111111-1111-1111-1111-111111111111}",
                       nullptr);
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\Microsoft\\Windows Script Host\\Settings", nullptr);
    BkaesSettleTelemetry();
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\BKAES");
    BkaesPrint("[OK] registry recon queries issued\n");
    return 0;
}
