#include "..\common\bkaes_sample.h"

int RunEdrAvProductProbes()
{
    const wchar_t* base = L"Software\\BKAES\\EdrAvProbe";

    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\EdrAvProbe\\Microsoft\\Windows Defender\\Real-Time Protection",
                        L"DisableRealtimeMonitoring", L"0");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\Microsoft\\Windows Defender\\Features",
                        L"TamperProtection", L"5");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\EdrAvProbe\\Microsoft\\Windows Defender\\Signature Updates",
                        L"SignatureVersion", L"1.0.0.0");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\Microsoft\\Security Center\\Provider\\Av",
                        L"Provider", L"Defender");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\EdrAvProbe\\System\\CurrentControlSet\\Services\\WinDefend", L"ImagePath",
                        L"WinDefend");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\EdrAvProbe\\System\\CurrentControlSet\\Services\\WdNisSvc", L"ImagePath",
                        L"WdNisSvc");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\System\\CurrentControlSet\\Services\\Sense",
                        L"ImagePath", L"Sense");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\EdrAvProbe\\Microsoft\\Windows Advanced Threat Protection\\Status",
                        L"OnboardingState", L"1");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\Microsoft\\Sense", L"OrgId", L"BKAES");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\System\\CurrentControlSet\\Services\\CSAgent",
                        L"ImagePath", L"CSAgent");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\CrowdStrike\\Falcon Sensor", L"Product",
                        L"Falcon");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\KasperskyLab\\AVP", L"Product", L"Kaspersky");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\System\\CurrentControlSet\\Services\\AVP",
                        L"ImagePath", L"AVP");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\SentinelOne", L"Product", L"SentinelOne");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\EdrAvProbe\\System\\CurrentControlSet\\Services\\SentinelAgent",
                        L"ImagePath", L"SentinelAgent");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\CarbonBlack", L"Product", L"CarbonBlack");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\EdrAvProbe\\System\\CurrentControlSet\\Services\\CbDefense", L"ImagePath",
                        L"CbDefense");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\Sophos", L"Product", L"Sophos");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\System\\CurrentControlSet\\Services\\Sophos",
                        L"ImagePath", L"Sophos");

    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\EdrAvProbe\\Microsoft\\Windows Defender\\Real-Time Protection",
                       L"DisableRealtimeMonitoring");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\Microsoft\\Windows Defender\\Features",
                       L"TamperProtection");
    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\EdrAvProbe\\Microsoft\\Windows Defender\\Signature Updates",
                       L"SignatureVersion");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\Microsoft\\Security Center\\Provider\\Av",
                       L"Provider");
    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\EdrAvProbe\\System\\CurrentControlSet\\Services\\WinDefend", L"ImagePath");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\System\\CurrentControlSet\\Services\\WdNisSvc",
                       L"ImagePath");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\System\\CurrentControlSet\\Services\\Sense",
                       L"ImagePath");
    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\EdrAvProbe\\Microsoft\\Windows Advanced Threat Protection\\Status",
                       L"OnboardingState");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\Microsoft\\Sense", L"OrgId");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\System\\CurrentControlSet\\Services\\CSAgent",
                       L"ImagePath");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\CrowdStrike\\Falcon Sensor", L"Product");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\KasperskyLab\\AVP", L"Product");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\System\\CurrentControlSet\\Services\\AVP",
                       L"ImagePath");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\SentinelOne", L"Product");
    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\EdrAvProbe\\System\\CurrentControlSet\\Services\\SentinelAgent",
                       L"ImagePath");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\CarbonBlack", L"Product");
    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\EdrAvProbe\\System\\CurrentControlSet\\Services\\CbDefense", L"ImagePath");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\Sophos", L"Product");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\EdrAvProbe\\System\\CurrentControlSet\\Services\\Sophos",
                       L"ImagePath");

    const wchar_t* services[] = {
        L"WinDefend", L"WdNisSvc",      L"Sense",     L"CSAgent", L"CSFalconService",
        L"AVP",       L"SentinelAgent", L"CbDefense", L"Sophos",
    };
    for (const wchar_t* serviceName : services)
    {
        BkaesQueryServicePresence(serviceName);
    }

    const wchar_t* commands[] = {
        L"powershell.exe -NoProfile -Command \"Get-MpComputerStatus; Get-MpPreference\"",
        L"powershell.exe -NoProfile -Command \"Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName "
        L"AntiVirusProduct\"",
        L"sc.exe query WinDefend",
        L"sc.exe query Sense",
        L"sc.exe query CSAgent",
        L"sc.exe query AVP",
    };
    int rc = BkaesRunSuspendedCmdlines(commands, ARRAYSIZE(commands));

    RegDeleteTreeW(HKEY_CURRENT_USER, base);
    BkaesPrint("[OK] EDR/AV product discovery probes issued and cleanup requested\n");
    return rc;
}
