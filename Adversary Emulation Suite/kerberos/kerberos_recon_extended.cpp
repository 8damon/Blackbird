#include "..\common\bkaes_sample.h"

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <sspi.h>

int RunKerberosReconExtended()
{
    PSecPkgInfoW packageInfo = nullptr;
    PSecPkgInfoW packages = nullptr;
    ULONG packageCount = 0;

    QuerySecurityPackageInfoW((SEC_WCHAR*)L"Kerberos", &packageInfo);
    if (packageInfo != nullptr)
    {
        FreeContextBuffer(packageInfo);
    }
    if (EnumerateSecurityPackagesW(&packageCount, &packages) == SEC_E_OK && packages != nullptr)
    {
        FreeContextBuffer(packages);
    }

    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\Kerberos\\System\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters",
                        L"SupportedEncryptionTypes", L"0x7fffffff");
    BkaesSetStringValue(HKEY_CURRENT_USER,
                        L"Software\\BKAES\\Kerberos\\System\\CurrentControlSet\\Services\\Kdc\\Parameters",
                        L"KdcUseRequestedEtypesForTickets", L"1");

    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters",
                       L"SupportedEncryptionTypes");
    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Kdc\\Parameters",
                       L"KdcUseRequestedEtypesForTickets");
    BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", L"NtlmMinClientSec");
    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\Kerberos\\System\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters",
                       L"SupportedEncryptionTypes");
    BkaesQueryKeyValue(HKEY_CURRENT_USER,
                       L"Software\\BKAES\\Kerberos\\System\\CurrentControlSet\\Services\\Kdc\\Parameters",
                       L"KdcUseRequestedEtypesForTickets");

    BkaesSettleTelemetry();
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\BKAES\\Kerberos");
    BkaesPrint("[OK] Kerberos package and registry recon probes completed packages=%lu\n", packageCount);
    return 0;
}
