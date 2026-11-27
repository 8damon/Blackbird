#include "..\common\bkaes_sample.h"

static void BkaesTryEnableTokenPrivilege(const wchar_t* privilegeName)
{
    HANDLE token = nullptr;
    TOKEN_PRIVILEGES privileges = {};

    if (privilegeName == nullptr || privilegeName[0] == L'\0')
    {
        return;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_DUPLICATE, &token))
    {
        return;
    }

    privileges.PrivilegeCount = 1;
    if (LookupPrivilegeValueW(nullptr, privilegeName, &privileges.Privileges[0].Luid))
    {
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
    }

    CloseHandle(token);
}

static void BkaesProbePrivilegedProcessHandle()
{
    DWORD pid = BkaesFindProcessIdByName(L"services.exe");
    HANDLE process = nullptr;

    if (pid == 0)
    {
        return;
    }

    process = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process != nullptr)
    {
        CloseHandle(process);
    }
}

int RunLpeSurface()
{
    const wchar_t* benign = L"C:\\Windows\\System32\\cmd.exe /c exit";

    BkaesTryEnableTokenPrivilege(L"SeDebugPrivilege");
    BkaesTryEnableTokenPrivilege(L"SeImpersonatePrivilege");
    BkaesProbePrivilegedProcessHandle();

    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\LPE\\System\\CurrentControlSet\\Services\\BKAESLpeProbe",
                        L"ImagePath", benign);
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\LPE\\System\\CurrentControlSet\\Services\\BKAESLpeProbe",
                        L"Type", L"16");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\LPE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution "
                        L"Options\\bkaes-lpe-target.exe",
                        L"Debugger", benign);
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\LPE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                        L"Userinit", L"userinit.exe,");

    BkaesSettleTelemetry();
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\BKAES\\LPE");
    BkaesPrint("[OK] LPE surface probes completed without privileged writes or escalation\n");
    return 0;
}
