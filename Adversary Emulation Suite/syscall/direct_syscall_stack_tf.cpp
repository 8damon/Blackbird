#include "..\common\bkaes_sample.h"

using NtContinueFn = NTSTATUS(NTAPI*)(PCONTEXT, BOOLEAN);

static bool BkaesScanSsn(const BYTE* stub, size_t bytes, DWORD* ssn)
{
    if (stub == nullptr || ssn == nullptr || bytes < 12)
    {
        return false;
    }

    for (size_t i = 0; i + 6 < bytes; ++i)
    {
        if (stub[i] != 0xB8)
        {
            continue;
        }
        DWORD value = 0;
        memcpy(&value, stub + i + 1, sizeof(value));
        for (size_t j = i + 5; j + 1 < bytes && j < i + 32; ++j)
        {
            if (stub[j] == 0x0F && stub[j + 1] == 0x05)
            {
                *ssn = value;
                return true;
            }
        }
    }
    return false;
}

static BYTE* BkaesCreateDirectOpenProcessThunk(DWORD ssn)
{
    BYTE thunk[] = {
        0x48, 0x83, 0xEC, 0x28,    // sub rsp, 28h
        0x4C, 0x8B, 0xD1,          // mov r10, rcx
        0xB8, 0,    0,    0,    0, // mov eax, ssn
        0x0F, 0x05,                // syscall
        0x48, 0x83, 0xC4, 0x28,    // add rsp, 28h
        0xC3,                      // ret
        0x90, 0x90, 0x90, 0x90,
    };
    memcpy(thunk + 8, &ssn, sizeof(ssn));

    BYTE* mem = (BYTE*)VirtualAlloc(nullptr, sizeof(thunk), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (mem != nullptr)
    {
        memcpy(mem, thunk, sizeof(thunk));
        FlushInstructionCache(GetCurrentProcess(), mem, sizeof(thunk));
    }
    return mem;
}

static LONG CALLBACK BkaesSingleStepVeh(PEXCEPTION_POINTERS info)
{
    if (info != nullptr && info->ExceptionRecord != nullptr &&
        info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        info->ContextRecord->EFlags &= ~0x100u;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void BkaesTriggerTrapFlagOnce()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntContinue = ntdll != nullptr ? (NtContinueFn)GetProcAddress(ntdll, "NtContinue") : nullptr;
    void* veh = AddVectoredExceptionHandler(1, BkaesSingleStepVeh);
    volatile LONG resumed = 0;
    CONTEXT ctx = {};

    if (ntContinue != nullptr && veh != nullptr)
    {
        RtlCaptureContext(&ctx);
        if (InterlockedCompareExchange((volatile LONG*)&resumed, 1, 0) == 0)
        {
            ctx.EFlags |= 0x100u;
            ntContinue(&ctx, FALSE);
        }
    }
    else
    {
        RaiseException(EXCEPTION_SINGLE_STEP, 0, 0, nullptr);
    }

    if (veh != nullptr)
    {
        RemoveVectoredExceptionHandler(veh);
    }
}

int RunDirectSyscallStackTf()
{
#if !defined(_M_X64)
    BkaesPrint("[SKIP] x64-only sample\n");
    return 2;
#else
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntOpenProcess = ntdll != nullptr ? (NtOpenProcessFn)GetProcAddress(ntdll, "NtOpenProcess") : nullptr;
    DWORD ssn = 0;
    BYTE* thunk = nullptr;
    PROCESS_INFORMATION child;
    HANDLE opened = nullptr;
    OBJECT_ATTRIBUTES oa;
    BkaesClientId cid;

    if (ntOpenProcess == nullptr || !BkaesScanSsn((const BYTE*)ntOpenProcess, 96, &ssn))
    {
        BkaesPrint("[FAIL] NtOpenProcess SSN extraction failed\n");
        return 1;
    }

    if (!BkaesLaunchSelfChild(&child))
    {
        BkaesPrint("[FAIL] child launch err=%lu\n", GetLastError());
        return 1;
    }

    BkaesTriggerTrapFlagOnce();
    thunk = BkaesCreateDirectOpenProcessThunk(ssn);
    if (thunk == nullptr)
    {
        BkaesCleanupProcess(&child);
        return 1;
    }

    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)child.dwProcessId;
    cid.UniqueThread = nullptr;
    ((NtOpenProcessFn)(void*)thunk)(&opened,
                                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                                        PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
                                    &oa, &cid);
    if (opened != nullptr)
    {
        CloseHandle(opened);
    }

    BkaesSettleTelemetry(3000);
    VirtualFree(thunk, 0, MEM_RELEASE);
    BkaesCleanupProcess(&child);
    BkaesPrint("[OK] direct syscall private thunk with trap-flag exception targetPid=%lu\n", child.dwProcessId);
    return 0;
#endif
}
