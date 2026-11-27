#include "..\common\bkaes_sample.h"

int RunDynamicFunctionTable()
{
#if !defined(_M_X64)
    BkaesPrint("[SKIP] x64-only sample\n");
    return 2;
#else
    BYTE* region = (BYTE*)VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (region == nullptr)
    {
        return 1;
    }
    RUNTIME_FUNCTION fn = {};
    fn.BeginAddress = 0;
    fn.EndAddress = 1;
    fn.UnwindInfoAddress = 0;
    BOOLEAN ok = RtlAddFunctionTable(&fn, 1, (DWORD64)region);
    if (ok)
    {
        BkaesSettleTelemetry();
        RtlDeleteFunctionTable(&fn);
    }
    BkaesPrint("[OK] dynamic function table privateExecBase=%p status=%u\n", region, ok ? 1u : 0u);
    VirtualFree(region, 0, MEM_RELEASE);
    return 0;
#endif
}
