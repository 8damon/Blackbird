#include "..\common\bkaes_sample.h"

int RunSensitiveCredentialHandles(int argc, wchar_t** argv)
{
    if (!BkaesIsSensitiveEnabled(argc, argv))
    {
        BkaesPrint(
            "[SKIP] set BKAES_ENABLE_SENSITIVE=1 or pass --enable-sensitive to open credential-process handles\n");
        return 2;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntOpenProcess = (NtOpenProcessFn)GetProcAddress(ntdll, "NtOpenProcess");
    if (ntOpenProcess == nullptr)
    {
        BkaesPrint("[FAIL] NtOpenProcess unavailable for sensitive handle probe\n");
        return 1;
    }

    const wchar_t* targets[] = {L"lsass.exe", L"winlogon.exe"};
    for (const wchar_t* target : targets)
    {
        DWORD pid = BkaesFindProcessIdByName(target);
        if (pid == 0)
        {
            continue;
        }
        HANDLE process = nullptr;
        OBJECT_ATTRIBUTES oa;
        BkaesClientId cid;
        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
        cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
        cid.UniqueThread = nullptr;
        NTSTATUS status = ntOpenProcess(&process, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, &oa, &cid);
        BkaesPrint("[OK] sensitive handle target=%ls pid=%lu status=0x%08X handle=%p err=%lu\n", target, pid,
                   (unsigned)status, process, GetLastError());
        if (process != nullptr)
        {
            CloseHandle(process);
        }
    }
    BkaesSettleTelemetry();
    return 0;
}
