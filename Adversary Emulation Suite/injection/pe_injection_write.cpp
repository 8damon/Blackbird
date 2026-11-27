#include "..\common\bkaes_sample.h"

int RunPeInjectionWrite()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntAllocateVirtualMemory = (NtAllocateVirtualMemoryFn)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    auto ntWriteVirtualMemory = (NtWriteVirtualMemoryFn)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    PROCESS_INFORMATION child;
    HANDLE process = nullptr;
    PVOID remote = nullptr;
    SIZE_T written = 0;
    SIZE_T regionSize = 0x1000;
    BYTE imageLike[512] = {};

    imageLike[0] = 'M';
    imageLike[1] = 'Z';
    imageLike[0x3C] = 0x80;
    imageLike[0x80] = 'P';
    imageLike[0x81] = 'E';
    for (size_t i = 0x90; i < sizeof(imageLike); ++i)
    {
        imageLike[i] = (BYTE)((i * 131u) ^ (i >> 1));
    }

    if (!BkaesOpenChildForInjection(&child, &process))
    {
        BkaesPrint("[FAIL] pe write child/open err=%lu\n", GetLastError());
        return 1;
    }

    NTSTATUS status = (NTSTATUS)0xC0000001;
    if (ntAllocateVirtualMemory != nullptr && ntWriteVirtualMemory != nullptr)
    {
        status = ntAllocateVirtualMemory(process, &remote, 0, &regionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (status >= 0)
        {
            status = ntWriteVirtualMemory(process, remote, imageLike, sizeof(imageLike), &written);
        }
    }
    else
    {
        remote = VirtualAllocEx(process, nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (remote != nullptr && WriteProcessMemory(process, remote, imageLike, sizeof(imageLike), &written))
        {
            status = 0;
        }
    }
    if (status < 0)
    {
        BkaesPrint("[FAIL] PE-like remote write status=0x%08X err=%lu\n", (unsigned)status, GetLastError());
        if (remote != nullptr)
        {
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        }
        CloseHandle(process);
        BkaesCleanupProcess(&child);
        return 1;
    }

    BkaesPrint("[OK] wrote inert PE-like bytes targetPid=%lu remote=%p bytes=%zu\n", child.dwProcessId, remote,
               written);
    BkaesSettleTelemetry();
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    CloseHandle(process);
    BkaesCleanupProcess(&child);
    return 0;
}
