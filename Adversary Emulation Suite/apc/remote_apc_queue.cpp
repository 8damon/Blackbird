#include "..\common\bkaes_sample.h"

int RunRemoteApcQueue()
{
    PROCESS_INFORMATION child;
    HANDLE process = nullptr;
    HANDLE thread = nullptr;
    PVOID remote = nullptr;
    SIZE_T written = 0;
    DWORD oldProtect = 0;
    BYTE inertRoutine[] = {0xEB, 0xFE};
    NTSTATUS status = (NTSTATUS)0xC0000001;

    ZeroMemory(&child, sizeof(child));

    if (!BkaesLaunchSelfChild(&child, CREATE_SUSPENDED | CREATE_NO_WINDOW))
    {
        BkaesPrint("[FAIL] APC suspended child create err=%lu\n", GetLastError());
        return 1;
    }

    process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE,
                          child.dwProcessId);
    if (process == nullptr)
    {
        BkaesPrint("[FAIL] APC target process handle err=%lu\n", GetLastError());
        BkaesCleanupProcess(&child);
        return 1;
    }

    remote = VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote != nullptr && WriteProcessMemory(process, remote, inertRoutine, sizeof(inertRoutine), &written) &&
        written == sizeof(inertRoutine) && VirtualProtectEx(process, remote, 0x1000, PAGE_EXECUTE_READ, &oldProtect))
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto ntQueueApcThread =
            ntdll != nullptr ? (NtQueueApcThreadFn)GetProcAddress(ntdll, "NtQueueApcThread") : nullptr;
        thread =
            OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, child.dwThreadId);
        FlushInstructionCache(process, remote, sizeof(inertRoutine));
        if (ntQueueApcThread != nullptr && thread != nullptr)
        {
            status = ntQueueApcThread(thread, remote, nullptr, nullptr, nullptr);
        }
    }

    BkaesPrint("[OK] remote APC queue targetPid=%lu targetTid=%lu routine=%p status=0x%08X\n", child.dwProcessId,
               child.dwThreadId, remote, (unsigned)status);
    BkaesSettleTelemetry();
    if (remote != nullptr)
    {
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    }
    if (thread != nullptr)
    {
        CloseHandle(thread);
    }
    CloseHandle(process);
    BkaesCleanupProcess(&child);
    return status >= 0 ? 0 : 1;
}
