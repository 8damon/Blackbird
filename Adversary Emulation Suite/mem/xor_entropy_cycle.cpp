#include "..\common\bkaes_sample.h"

int RunXorEntropyCycle()
{
    BYTE* region = (BYTE*)VirtualAlloc(nullptr, 0x20000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    DWORD oldProtect = 0;
    uint32_t state = 0xC0DEC0DEu;

    if (region == nullptr)
    {
        return 1;
    }

    memset(region, 'A', 0x20000);
    for (int round = 0; round < 16; ++round)
    {
        BYTE block[4096];
        for (size_t i = 0; i < sizeof(block); ++i)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            block[i] = (BYTE)(state ^ (uint32_t)i ^ (uint32_t)(round * 31));
        }

        BYTE* target = region + ((round % 16) * 4096);
        for (size_t i = 0; i < sizeof(block); ++i)
        {
            target[i] ^= block[i];
        }
        VirtualProtect(target, 4096, PAGE_EXECUTE_READWRITE, &oldProtect);
        VirtualProtect(target, 4096, PAGE_READWRITE, &oldProtect);
        for (size_t i = 0; i < sizeof(block); ++i)
        {
            target[i] ^= block[i];
        }
    }

    BkaesSettleTelemetry();
    VirtualFree(region, 0, MEM_RELEASE);
    BkaesPrint("[OK] XOR high-entropy encrypt/decrypt memory cycle completed\n");
    return 0;
}
