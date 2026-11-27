#include "..\common\bkaes_sample.h"

int RunOkMemoryProcess()
{
    BYTE* buffer = (BYTE*)VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (buffer != nullptr)
    {
        memset(buffer, 0x41, 4096);
        DWORD oldProtect = 0;
        VirtualProtect(buffer, 4096, PAGE_READONLY, &oldProtect);
        VirtualFree(buffer, 0, MEM_RELEASE);
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot, &entry))
        {
            int count = 0;
            while (Process32NextW(snapshot, &entry) && ++count < 32)
            {
            }
        }
        CloseHandle(snapshot);
    }
    BkaesPrint("[OK] benign memory/process sample completed\n");
    return 0;
}
