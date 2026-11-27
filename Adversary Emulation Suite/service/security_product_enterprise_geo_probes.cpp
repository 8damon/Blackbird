#include "..\common\bkaes_sample.h"

int RunSecurityProductEnterpriseGeoProbes()
{
    const wchar_t* base = L"Software\\BKAES\\SecurityProductProbe";

    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\SecurityProductProbe\\Microsoft\\Windows Defender\\Real-Time Protection",
                        L"DisableRealtimeMonitoring", L"0");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\SecurityProductProbe\\Microsoft\\Windows Defender\\Signature Updates",
                        L"SignatureVersion", L"1.0.0.0");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\SecurityProductProbe\\System\\CurrentControlSet\\Services\\Sense",
                        L"ImagePath", L"Sense");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\SecurityProductProbe\\Microsoft\\Windows Advanced Threat Protection\\Status",
                        L"OnboardingState", L"1");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\SecurityProductProbe\\System\\CurrentControlSet\\Services\\CSAgent",
                        L"ImagePath", L"CSAgent");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\SecurityProductProbe\\CrowdStrike\\Falcon Sensor",
                        L"Product", L"Falcon");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\SecurityProductProbe\\KasperskyLab\\AVP", L"Product",
                        L"Kaspersky");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\SecurityProductProbe\\System\\CurrentControlSet\\Services\\AVP",
                        L"ImagePath", L"AVP");
    BkaesSetStringValue(HKEY_CURRENT_USER, L"Software\\BKAES\\SecurityProductProbe\\SentinelOne", L"Product",
                        L"SentinelOne");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\SecurityProductProbe\\System\\CurrentControlSet\\Services\\SentinelAgent",
                        L"ImagePath", L"SentinelAgent");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\SecurityProductProbe\\CapabilityAccessManager\\ConsentStore\\location",
                        L"Value", L"Allow");
    BkaesSetStringValue(
        HKEY_CURRENT_USER,
        L"Software\\BKAES\\SecurityProductProbe\\System\\CurrentControlSet\\Services\\lfsvc\\Service\\Configuration",
        L"Status", L"1");
    BkaesSetStringValue(
        HKEY_CURRENT_USER,
        L"Software\\BKAES\\SecurityProductProbe\\Microsoft\\Enrollments\\{11111111-1111-1111-1111-111111111111}",
        L"EnrollmentType", L"6");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\SecurityProductProbe\\Microsoft\\Provisioning\\OMADM\\Accounts",
                        L"AccountId", L"BKAES");
    BkaesSetStringValue(
        HKEY_CURRENT_USER,
        L"Software\\BKAES\\SecurityProductProbe\\System\\CurrentControlSet\\Control\\CloudDomainJoin\\JoinInfo",
        L"TenantId", L"BKAES");
    BkaesSetStringValue(
        HKEY_CURRENT_USER,
        L"Software\\BKAES\\SecurityProductProbe\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters",
        L"JoinDomain", L"corp.example");
    BkaesSetStringValue(
        HKEY_CURRENT_USER,
        L"Software\\BKAES\\SecurityProductProbe\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"Domain",
        L"corp.example");

    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\SecurityProductProbe\\Microsoft\\Windows Defender\\Real-Time Protection",
                       L"DisableRealtimeMonitoring");
    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\SecurityProductProbe\\Microsoft\\Windows Defender\\Signature Updates",
                       L"SignatureVersion");
    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\SecurityProductProbe\\System\\CurrentControlSet\\Services\\Sense",
                       L"ImagePath");
    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\SecurityProductProbe\\Microsoft\\Windows Advanced Threat Protection\\Status",
                       L"OnboardingState");
    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\SecurityProductProbe\\System\\CurrentControlSet\\Services\\CSAgent",
                       L"ImagePath");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\SecurityProductProbe\\CrowdStrike\\Falcon Sensor",
                       L"Product");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\SecurityProductProbe\\KasperskyLab\\AVP", L"Product");
    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\SecurityProductProbe\\System\\CurrentControlSet\\Services\\AVP",
                       L"ImagePath");
    BkaesQueryKeyValue(HKEY_CURRENT_USER, L"Software\\BKAES\\SecurityProductProbe\\SentinelOne", L"Product");
    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\SecurityProductProbe\\System\\CurrentControlSet\\Services\\SentinelAgent",
                       L"ImagePath");
    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\SecurityProductProbe\\CapabilityAccessManager\\ConsentStore\\location",
                       L"Value");
    BkaesQueryKeyValue(
        HKEY_CURRENT_USER,
        L"Software\\BKAES\\SecurityProductProbe\\System\\CurrentControlSet\\Services\\lfsvc\\Service\\Configuration",
        L"Status");
    BkaesQueryKeyValue(
        HKEY_CURRENT_USER,
        L"Software\\BKAES\\SecurityProductProbe\\Microsoft\\Enrollments\\{11111111-1111-1111-1111-111111111111}",
        L"EnrollmentType");
    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\SecurityProductProbe\\Microsoft\\Provisioning\\OMADM\\Accounts",
                       L"AccountId");
    BkaesQueryKeyValue(
        HKEY_CURRENT_USER,
        L"Software\\BKAES\\SecurityProductProbe\\System\\CurrentControlSet\\Control\\CloudDomainJoin\\JoinInfo",
        L"TenantId");
    BkaesQueryKeyValue(
        HKEY_CURRENT_USER,
        L"Software\\BKAES\\SecurityProductProbe\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters",
        L"JoinDomain");
    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\SecurityProductProbe\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                       L"Domain");

    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) == 0)
    {
        BkaesResolveProbeDomain(L"api.ipify.org.invalid");
        BkaesResolveProbeDomain(L"ipinfo.io.invalid");
        BkaesResolveProbeDomain(L"enterpriseregistration.windows.net.invalid");
        BkaesResolveProbeDomain(L"enterpriseenrollment.manage.microsoft.com.invalid");
        WSACleanup();
    }

    RegDeleteTreeW(HKEY_CURRENT_USER, base);
    BkaesPrint("[OK] security product, enterprise, and geolocation probes issued and cleanup requested\n");
    return 0;
}
