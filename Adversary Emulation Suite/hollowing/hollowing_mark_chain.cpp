#include "..\common\bkaes_sample.h"

int RunHollowingMarkChain()
{
    PROCESS_INFORMATION child;
    HANDLE process = nullptr;
    PVOID remote = nullptr;
    SIZE_T written = 0;
    DWORD oldProtect = 0;
    const SIZE_T regionSize = 0x20000;
    const SIZE_T stubOffset = 0x200;
    BYTE payload[4096] = {};
    CONTEXT context = {};
    bool contextSet = false;
    bool resumed = false;

    ZeroMemory(&child, sizeof(child));

    if (!BkaesLaunchSelfChild(&child, CREATE_SUSPENDED | CREATE_NO_WINDOW))
    {
        BkaesPrint("[FAIL] hollowing suspended child create err=%lu\n", GetLastError());
        return 1;
    }

    process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD |
                              PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
                          FALSE, child.dwProcessId);
    if (process == nullptr)
    {
        BkaesPrint("[FAIL] hollowing OpenProcess targetPid=%lu err=%lu\n", child.dwProcessId, GetLastError());
        BkaesCleanupProcess(&child);
        return 1;
    }

    payload[0] = 'M';
    payload[1] = 'Z';
    payload[0x3C] = 0x80;
    payload[0x80] = 'P';
    payload[0x81] = 'E';
    payload[stubOffset] = 0xEB;
    payload[stubOffset + 1] = 0xFE;
    for (SIZE_T i = 0x90; i < sizeof(payload); ++i)
    {
        if (i == stubOffset || i == stubOffset + 1)
        {
            continue;
        }
        payload[i] = (BYTE)((i * 29u) ^ (i >> 2) ^ 0x5Au);
    }

    remote = VirtualAllocEx(process, nullptr, regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote == nullptr)
    {
        BkaesPrint("[FAIL] hollowing VirtualAllocEx targetPid=%lu err=%lu\n", child.dwProcessId, GetLastError());
        CloseHandle(process);
        BkaesCleanupProcess(&child);
        return 1;
    }

    if (!WriteProcessMemory(process, remote, payload, sizeof(payload), &written) || written != sizeof(payload))
    {
        BkaesPrint("[FAIL] hollowing WriteProcessMemory targetPid=%lu err=%lu\n", child.dwProcessId, GetLastError());
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        CloseHandle(process);
        BkaesCleanupProcess(&child);
        return 1;
    }

    if (!VirtualProtectEx(process, remote, regionSize, PAGE_EXECUTE_READ, &oldProtect))
    {
        BkaesPrint("[FAIL] hollowing VirtualProtectEx targetPid=%lu err=%lu\n", child.dwProcessId, GetLastError());
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        CloseHandle(process);
        BkaesCleanupProcess(&child);
        return 1;
    }

    FlushInstructionCache(process, remote, sizeof(payload));
    context.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(child.hThread, &context))
    {
#if defined(_M_X64)
        context.Rip = (DWORD64)((BYTE*)remote + stubOffset);
#elif defined(_M_IX86)
        context.Eip = (DWORD)((BYTE*)remote + stubOffset);
#else
#error Unsupported architecture for hollowing mark-chain sample
#endif
        contextSet = SetThreadContext(child.hThread, &context) == TRUE;
    }

    if (contextSet)
    {
        resumed = ResumeThread(child.hThread) != (DWORD)-1;
        if (resumed)
        {
            WaitForSingleObject(child.hProcess, 400);
        }
    }

    BkaesPrint("[OK] hollowing mark-chain targetPid=%lu remote=%p contextSet=%u resumed=%u\n", child.dwProcessId,
               remote, contextSet ? 1u : 0u, resumed ? 1u : 0u);
    BkaesSettleTelemetry();
    BkaesCleanupProcess(&child);
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    CloseHandle(process);
    return contextSet ? 0 : 1;
}
