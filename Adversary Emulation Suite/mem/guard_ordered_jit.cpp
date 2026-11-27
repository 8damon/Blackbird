#include "..\common\bkaes_sample.h"

static LONG CALLBACK BkaesGuardVeh(PEXCEPTION_POINTERS info)
{
    if (info != nullptr && info->ExceptionRecord != nullptr &&
        info->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int RunGuardOrderedJit()
{
    BYTE* region = (BYTE*)VirtualAlloc(nullptr, 0x40000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    DWORD oldProtect = 0;
    void* veh = nullptr;

    if (region == nullptr)
    {
        return 1;
    }

    for (SIZE_T offset = 0; offset < 0x40000; ++offset)
    {
        region[offset] = (offset % 4096 == 0) ? 0xC3 : 0x90;
    }

    veh = AddVectoredExceptionHandler(1, BkaesGuardVeh);
    for (int round = 0; round < 8; ++round)
    {
        BYTE* page = region + ((round % 8) * 0x1000);
        VirtualProtect(page, 0x1000, PAGE_READWRITE, &oldProtect);
        page[0] = 0xC3;
        VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ, &oldProtect);
        ((void (*)())page)();
        VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProtect);
        ((void (*)())page)();
        VirtualProtect(page, 0x1000, PAGE_NOACCESS, &oldProtect);
        VirtualProtect(page, 0x1000, PAGE_READWRITE, &oldProtect);
    }

    BkaesSettleTelemetry();
    if (veh != nullptr)
    {
        RemoveVectoredExceptionHandler(veh);
    }
    VirtualFree(region, 0, MEM_RELEASE);
    BkaesPrint("[OK] ordered guard/JIT protection cycle completed\n");
    return 0;
}
