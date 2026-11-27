#include "..\common\bkaes_sample.h"

static bool BkaesLooksLikeSyscallStub(const BYTE* bytes, size_t count, DWORD* ssn)
{
    if (bytes == nullptr || count < 11)
    {
        return false;
    }

    for (size_t i = 0; i + 10 < count; ++i)
    {
        if (bytes[i] == 0x4C && bytes[i + 1] == 0x8B && bytes[i + 2] == 0xD1 && bytes[i + 3] == 0xB8)
        {
            if (ssn != nullptr)
            {
                memcpy(ssn, bytes + i + 4, sizeof(*ssn));
            }
            return true;
        }
    }
    return false;
}

int RunNtStubIntegrityCheck()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const char* exports[] = {
        "NtOpenProcess", "NtProtectVirtualMemory", "NtQueueApcThread", "NtSetContextThread", "NtQuerySystemInformation",
    };
    BYTE* scratch = (BYTE*)VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    DWORD oldProtect = 0;
    size_t copied = 0;

    if (ntdll == nullptr || scratch == nullptr)
    {
        if (scratch != nullptr)
        {
            VirtualFree(scratch, 0, MEM_RELEASE);
        }
        return 1;
    }

    for (const char* name : exports)
    {
        FARPROC fn = GetProcAddress(ntdll, name);
        DWORD ssn = 0;
        BYTE local[64] = {};
        if (fn == nullptr)
        {
            continue;
        }

        memcpy(local, fn, sizeof(local));
        BkaesLooksLikeSyscallStub(local, sizeof(local), &ssn);
        memcpy(scratch + copied, local, sizeof(local));
        copied += sizeof(local);
        BkaesPrint("[OK] ntdll stub check export=%s addr=%p first=%02X %02X ssn=0x%08lX\n", name, fn, local[0],
                   local[1], ssn);
    }

    {
        BYTE inertSignatureStub[] = {
            0x4C, 0x8B, 0xD1, 0xB8, 0x55, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
        };
        memcpy(scratch + copied, inertSignatureStub, sizeof(inertSignatureStub));
        copied += sizeof(inertSignatureStub);
    }

    VirtualProtect(scratch, 0x1000, PAGE_EXECUTE_READ, &oldProtect);
    BkaesSettleTelemetry();
    VirtualFree(scratch, 0, MEM_RELEASE);
    BkaesPrint("[OK] Nt* stub integrity bytes copied to private RX scratch page bytes=%zu\n", copied);
    return copied != 0 ? 0 : 1;
}
