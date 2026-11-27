#include "..\common\bkaes_sample.h"

int RunContextHijackTf()
{
#if !defined(_M_X64)
    BkaesPrint("[SKIP] x64-only sample\n");
    return 2;
#else
    PROCESS_INFORMATION child;
    HANDLE process = nullptr;
    PVOID remote = nullptr;
    BYTE loop[] = {0xEB, 0xFE};
    SIZE_T written = 0;
    DWORD oldProtect = 0;
    CONTEXT ctx = {};
    bool ok = false;

    if (!BkaesLaunchSelfChild(&child, CREATE_SUSPENDED | CREATE_NO_WINDOW))
    {
        return 1;
    }

    process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE,
                          child.dwProcessId);
    if (process != nullptr)
    {
        remote = VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (remote != nullptr && WriteProcessMemory(process, remote, loop, sizeof(loop), &written) &&
        written == sizeof(loop) && VirtualProtectEx(process, remote, 0x1000, PAGE_EXECUTE_READ, &oldProtect))
    {
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(child.hThread, &ctx))
        {
            ctx.Rip = (DWORD64)(ULONG_PTR)remote;
            ctx.EFlags |= 0x100u;
            ok = SetThreadContext(child.hThread, &ctx) == TRUE;
        }
    }

    if (ok)
    {
        ResumeThread(child.hThread);
        WaitForSingleObject(child.hProcess, 500);
    }

    BkaesSettleTelemetry();
    BkaesPrint("[OK] context hijack TF targetPid=%lu remote=%p ok=%u\n", child.dwProcessId, remote, ok ? 1u : 0u);
    BkaesCleanupProcess(&child);
    if (remote != nullptr)
    {
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    }
    if (process != nullptr)
    {
        CloseHandle(process);
    }
    return ok ? 0 : 1;
#endif
}
