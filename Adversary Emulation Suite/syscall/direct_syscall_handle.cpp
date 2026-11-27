#include "..\common\bkaes_sample.h"

static bool ScanStubForSsn(const BYTE* stub, size_t stubBytes, DWORD* ssn)
{
    if (stub == nullptr || ssn == nullptr || stubBytes < 12)
    {
        return false;
    }
    for (size_t i = 0; i + 6 < stubBytes; ++i)
    {
        if (stub[i] != 0xB8)
        {
            continue;
        }
        DWORD value = 0;
        memcpy(&value, &stub[i + 1], sizeof(value));
        for (size_t j = i + 5; j + 1 < stubBytes && j < i + 32; ++j)
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

static const BYTE* ResolveJumpTarget(const BYTE* stub)
{
    if (stub == nullptr)
    {
        return nullptr;
    }
    if (stub[0] == 0xE9)
    {
        int32_t rel32 = 0;
        memcpy(&rel32, &stub[1], sizeof(rel32));
        return stub + 5 + rel32;
    }
    if (stub[0] == 0xEB)
    {
        return stub + 2 + (int8_t)stub[1];
    }
    if (stub[0] == 0xFF && stub[1] == 0x25)
    {
        int32_t disp32 = 0;
        const BYTE* target = nullptr;
        memcpy(&disp32, &stub[2], sizeof(disp32));
        memcpy(&target, stub + 6 + disp32, sizeof(target));
        return target;
    }
    return nullptr;
}

static bool ExtractSsn(const BYTE* stub, DWORD* ssn)
{
    const BYTE* candidate = stub;
    for (int depth = 0; depth < 3 && candidate != nullptr; ++depth)
    {
        if (ScanStubForSsn(candidate, 96, ssn))
        {
            return true;
        }
        candidate = ResolveJumpTarget(candidate);
    }
    return false;
}

static BYTE* CreateSyscallStub(DWORD ssn)
{
    BYTE* stub = (BYTE*)VirtualAlloc(nullptr, 16, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (stub == nullptr)
    {
        return nullptr;
    }
    stub[0] = 0x4C;
    stub[1] = 0x8B;
    stub[2] = 0xD1;
    stub[3] = 0xB8;
    memcpy(&stub[4], &ssn, sizeof(ssn));
    stub[8] = 0x0F;
    stub[9] = 0x05;
    stub[10] = 0xC3;
    for (int i = 11; i < 16; ++i)
    {
        stub[i] = 0x90;
    }
    return stub;
}

static BYTE* CreateSyscallCallerThunk(void* target, DWORD ssn)
{
    if (target == nullptr)
    {
        return nullptr;
    }

    BYTE thunkBytes[] = {
        0x48, 0xB8, 0,    0, 0, 0, 0, 0, 0, 0, // mov rax, imm64
        0xFF, 0xD0,                            // call rax
        0xEB, 0x0B,                            // jmp done
        0x4C, 0x8B, 0xD1,                      // mov r10, rcx
        0xB8, 0,    0,    0, 0,                // mov eax, ssn
        0x0F, 0x05,                            // syscall
        0xC3,                                  // ret
        0xC3                                   // done: ret
    };
    memcpy(&thunkBytes[2], &target, sizeof(target));
    memcpy(&thunkBytes[18], &ssn, sizeof(ssn));

    BYTE* thunk = (BYTE*)VirtualAlloc(nullptr, sizeof(thunkBytes), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (thunk == nullptr)
    {
        return nullptr;
    }
    memcpy(thunk, thunkBytes, sizeof(thunkBytes));
    FlushInstructionCache(GetCurrentProcess(), thunk, sizeof(thunkBytes));
    return thunk;
}

int RunDirectSyscallHandle()
{
#if !defined(_M_X64)
    BkaesPrint("[SKIP] x64-only sample\n");
    return 2;
#else
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntQueryVirtualMemory = (NtQueryVirtualMemoryFn)GetProcAddress(ntdll, "NtQueryVirtualMemory");
    auto ntOpenProcess = (NtOpenProcessFn)GetProcAddress(ntdll, "NtOpenProcess");
    DWORD querySsn = 0;
    DWORD openSsn = 0;
    PROCESS_INFORMATION child;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T outLen = 0;

    if (ntdll == nullptr || ntQueryVirtualMemory == nullptr || ntOpenProcess == nullptr ||
        !ExtractSsn((const BYTE*)ntQueryVirtualMemory, &querySsn) || !ExtractSsn((const BYTE*)ntOpenProcess, &openSsn))
    {
        BkaesPrint("[FAIL] could not resolve syscall stubs\n");
        return 1;
    }

    if (!BkaesLaunchSelfChild(&child))
    {
        BkaesPrint("[FAIL] child launch err=%lu\n", GetLastError());
        return 1;
    }

    BYTE* queryStub = CreateSyscallStub(querySsn);
    BYTE* openStub = CreateSyscallStub(openSsn);
    BYTE* openThunk = CreateSyscallCallerThunk(openStub, openSsn);
    if (queryStub == nullptr || openStub == nullptr || openThunk == nullptr)
    {
        if (queryStub != nullptr)
        {
            VirtualFree(queryStub, 0, MEM_RELEASE);
        }
        if (openStub != nullptr)
        {
            VirtualFree(openStub, 0, MEM_RELEASE);
        }
        if (openThunk != nullptr)
        {
            VirtualFree(openThunk, 0, MEM_RELEASE);
        }
        BkaesCleanupProcess(&child);
        return 1;
    }

    ((NtQueryVirtualMemoryFn)(void*)queryStub)(GetCurrentProcess(), (PVOID)(ULONG_PTR)&RunDirectSyscallHandle, 0, &mbi,
                                               sizeof(mbi), &outLen);

    HANDLE opened = nullptr;
    OBJECT_ATTRIBUTES oa;
    BkaesClientId cid;
    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)child.dwProcessId;
    cid.UniqueThread = nullptr;
    ((NtOpenProcessFn)(void*)openThunk)(&opened,
                                        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                                            PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
                                        &oa, &cid);
    if (opened != nullptr)
    {
        CloseHandle(opened);
    }

    Sleep(8000);
    VirtualFree(queryStub, 0, MEM_RELEASE);
    VirtualFree(openStub, 0, MEM_RELEASE);
    VirtualFree(openThunk, 0, MEM_RELEASE);
    BkaesPrint("[OK] direct syscall handle sample targetPid=%lu\n", child.dwProcessId);
    BkaesCleanupProcess(&child);
    return 0;
#endif
}
