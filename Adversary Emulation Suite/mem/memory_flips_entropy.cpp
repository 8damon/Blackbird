#include "..\common\bkaes_sample.h"

int RunMemoryFlipsEntropy()
{
    BYTE* region = (BYTE*)VirtualAlloc(nullptr, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (region == nullptr)
    {
        return 1;
    }

    DWORD oldProtect = 0;
    uint32_t state = 0xB10B1D5u;
    for (int round = 0; round < 12; ++round)
    {
        BYTE block[1024];
        for (BYTE& b : block)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            b = (BYTE)state;
        }
        SIZE_T written = 0;
        WriteProcessMemory(GetCurrentProcess(), region + ((round * 1024) % 0x8000), block, sizeof(block), &written);
        VirtualProtect(region, 0x10000, PAGE_EXECUTE_READWRITE, &oldProtect);
        VirtualProtect(region, 0x10000, PAGE_NOACCESS, &oldProtect);
        VirtualProtect(region, 0x10000, PAGE_READWRITE | PAGE_GUARD, &oldProtect);
        VirtualProtect(region, 0x10000, PAGE_READWRITE, &oldProtect);
    }

    BkaesPrint("[OK] memory protection flips and high-entropy writes issued base=%p\n", region);
    BkaesSettleTelemetry();
    VirtualFree(region, 0, MEM_RELEASE);
    return 0;
}
