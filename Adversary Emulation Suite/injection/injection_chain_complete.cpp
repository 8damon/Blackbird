#include "..\common\bkaes_sample.h"

int RunInjectionChainComplete()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntAllocateVirtualMemory = (NtAllocateVirtualMemoryFn)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    auto ntWriteVirtualMemory = (NtWriteVirtualMemoryFn)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    auto ntProtectVirtualMemory = (NtProtectVirtualMemoryFn)GetProcAddress(ntdll, "NtProtectVirtualMemory");
    auto ntCreateThreadEx = (NtCreateThreadExFn)GetProcAddress(ntdll, "NtCreateThreadEx");
    PROCESS_INFORMATION child;
    HANDLE process = nullptr;
    PVOID remote = nullptr;
    HANDLE thread = nullptr;
    SIZE_T written = 0;
    ULONG oldProtect = 0;
    SIZE_T regionSize = 0x1000;
    BYTE stub[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};

    if (ntAllocateVirtualMemory == nullptr || ntWriteVirtualMemory == nullptr || ntProtectVirtualMemory == nullptr)
    {
        BkaesPrint("[FAIL] injection NTAPI resolution failed\n");
        return 1;
    }

    if (!BkaesOpenChildForInjection(&child, &process))
    {
        BkaesPrint("[FAIL] injection child/open err=%lu\n", GetLastError());
        return 1;
    }

    NTSTATUS status =
        ntAllocateVirtualMemory(process, &remote, 0, &regionSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (status >= 0)
    {
        status = ntWriteVirtualMemory(process, remote, stub, sizeof(stub), &written);
    }
    if (status >= 0)
    {
        PVOID protectBase = remote;
        SIZE_T protectSize = regionSize;
        status = ntProtectVirtualMemory(process, &protectBase, &protectSize, PAGE_EXECUTE_READ, &oldProtect);
    }
    if (status < 0)
    {
        BkaesPrint("[FAIL] injection staging status=0x%08X err=%lu\n", (unsigned)status, GetLastError());
        if (remote != nullptr)
        {
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        }
        CloseHandle(process);
        BkaesCleanupProcess(&child);
        return 1;
    }

    if (ntCreateThreadEx != nullptr)
    {
        status = ntCreateThreadEx(&thread, THREAD_ALL_ACCESS, nullptr, process, remote, nullptr, 0, 0, 0, 0, nullptr);
    }
    else
    {
        thread = CreateRemoteThread(process, nullptr, 0, (LPTHREAD_START_ROUTINE)remote, nullptr, 0, nullptr);
        status = thread != nullptr ? 0 : (NTSTATUS)0xC0000001;
    }
    if (thread != nullptr)
    {
        WaitForSingleObject(thread, 2000);
        CloseHandle(thread);
    }

    BkaesPrint("[OK] injection chain complete targetPid=%lu remote=%p\n", child.dwProcessId, remote);
    BkaesSettleTelemetry();
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    CloseHandle(process);
    BkaesCleanupProcess(&child);
    return thread != nullptr ? 0 : 1;
}
