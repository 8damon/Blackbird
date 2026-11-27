#include "..\common\bkaes_sample.h"

int RunAntiDebugVmQueries()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntQueryInformationProcess = (NtQueryInformationProcessFn)GetProcAddress(ntdll, "NtQueryInformationProcess");
    auto ntQuerySystemInformation = (NtQuerySystemInformationFn)GetProcAddress(ntdll, "NtQuerySystemInformation");
    ULONG ret = 0;
    ULONG value = 0;
    BYTE buffer[512] = {};

    if (ntQueryInformationProcess != nullptr)
    {
        ntQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)7, &value, sizeof(value), &ret);
        ntQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)30, &value, sizeof(value), &ret);
        ntQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)31, &value, sizeof(value), &ret);
    }
    if (ntQuerySystemInformation != nullptr)
    {
        ntQuerySystemInformation((SYSTEM_INFORMATION_CLASS)35, buffer, sizeof(buffer), &ret);
        ntQuerySystemInformation((SYSTEM_INFORMATION_CLASS)76, buffer, sizeof(buffer), &ret);
    }

    GetSystemFirmwareTable('RSMB', 0, buffer, sizeof(buffer));
    GetFileAttributesW(L"C:\\Windows\\System32\\drivers\\vmmouse.sys");
    GetFileAttributesW(L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys");
    std::wstring vmMouse = BkaesTempPath(L"vmmouse.sys");
    std::wstring vboxMouse = BkaesTempPath(L"VBoxMouse.sys");
    BkaesWriteTextFile(vmMouse, "BKAES inert VMware driver artifact probe\r\n");
    BkaesWriteTextFile(vboxMouse, "BKAES inert VirtualBox driver artifact probe\r\n");
    GetFileAttributesW(vmMouse.c_str());
    GetFileAttributesW(vboxMouse.c_str());

    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Services\\VBoxGuest",
                        L"ImagePath", L"VBoxGuest");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Services\\vmhgfs",
                        L"ImagePath", L"vmhgfs");
    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", nullptr);
    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs", nullptr);
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Services\\VBoxGuest",
                       L"ImagePath");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Services\\vmhgfs",
                       L"ImagePath");
    BkaesSettleTelemetry();
    DeleteFileW(vmMouse.c_str());
    DeleteFileW(vboxMouse.c_str());
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Services\\VBoxGuest");
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\BKAES\\System\\CurrentControlSet\\Services\\vmhgfs");

    BkaesPrint("[OK] anti-debug and anti-VM queries issued\n");
    return 0;
}
