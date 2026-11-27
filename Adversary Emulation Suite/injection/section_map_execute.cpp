#include "..\common\bkaes_sample.h"

int RunSectionMapExecute()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntCreateSection = (NtCreateSectionFn)GetProcAddress(ntdll, "NtCreateSection");
    auto ntMapViewOfSection = (NtMapViewOfSectionFn)GetProcAddress(ntdll, "NtMapViewOfSection");
    PROCESS_INFORMATION child;
    HANDLE process = nullptr;
    HANDLE section = nullptr;
    LARGE_INTEGER maxSize;
    PVOID remoteBase = nullptr;
    SIZE_T viewSize = 0;

    if (ntCreateSection == nullptr || ntMapViewOfSection == nullptr || !BkaesOpenChildForInjection(&child, &process))
    {
        BkaesPrint("[FAIL] section setup err=%lu\n", GetLastError());
        return 1;
    }

    maxSize.QuadPart = 0x1000;
    NTSTATUS status =
        ntCreateSection(&section, SECTION_ALL_ACCESS, nullptr, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);
    if (status >= 0)
    {
        status = ntMapViewOfSection(section, process, &remoteBase, 0, 0, nullptr, &viewSize, 2, 0, PAGE_EXECUTE_READ);
    }

    BkaesPrint("[OK] section execute map status=0x%08X targetPid=%lu base=%p\n", (unsigned)status, child.dwProcessId,
               remoteBase);
    BkaesSettleTelemetry();
    if (section != nullptr)
    {
        CloseHandle(section);
    }
    CloseHandle(process);
    BkaesCleanupProcess(&child);
    return status >= 0 ? 0 : 1;
}
