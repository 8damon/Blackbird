#include "..\common\bkaes_sample.h"

int RunFuzzNtapiQueries()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntQueryInformationProcess = (NtQueryInformationProcessFn)GetProcAddress(ntdll, "NtQueryInformationProcess");
    auto ntQuerySystemInformation = (NtQuerySystemInformationFn)GetProcAddress(ntdll, "NtQuerySystemInformation");
    BYTE buffer[4096];
    ULONG ret = 0;
    if (ntQueryInformationProcess != nullptr)
    {
        for (ULONG cls = 0; cls < 64; ++cls)
        {
            ntQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)cls, buffer, sizeof(buffer), &ret);
        }
    }
    if (ntQuerySystemInformation != nullptr)
    {
        for (ULONG cls = 0; cls < 96; ++cls)
        {
            ntQuerySystemInformation((SYSTEM_INFORMATION_CLASS)cls, buffer, sizeof(buffer), &ret);
        }
    }
    BkaesSettleTelemetry();
    BkaesPrint("[OK] NTAPI query fuzzer completed\n");
    return 0;
}
