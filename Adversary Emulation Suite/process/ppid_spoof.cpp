#include "..\common\bkaes_sample.h"

int RunPpidSpoof()
{
    STARTUPINFOEXW siex;
    PROCESS_INFORMATION pi;
    SIZE_T attrSize = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = nullptr;
    HANDLE parent = nullptr;
    DWORD parentPid = BkaesFindProcessIdByName(L"explorer.exe");
    std::wstring self = BkaesSelfPath();
    wchar_t cmd[(MAX_PATH * 2) + 64];

    if (parentPid == 0 || self.empty())
    {
        BkaesPrint("[FAIL] explorer.exe or self path not found\n");
        return 1;
    }

    parent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
    if (parent == nullptr)
    {
        BkaesPrint("[FAIL] parent open err=%lu\n", GetLastError());
        return 1;
    }

    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
    attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
    ZeroMemory(&siex, sizeof(siex));
    ZeroMemory(&pi, sizeof(pi));
    siex.StartupInfo.cb = sizeof(siex);
    if (attrs == nullptr || !InitializeProcThreadAttributeList(attrs, 1, 0, &attrSize) ||
        !UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parent, sizeof(parent), nullptr,
                                   nullptr) ||
        FAILED(StringCchPrintfW(cmd, ARRAYSIZE(cmd), L"\"%ls\" --child-sleep", self.c_str())))
    {
        BkaesPrint("[FAIL] attribute setup err=%lu\n", GetLastError());
        if (attrs != nullptr)
        {
            HeapFree(GetProcessHeap(), 0, attrs);
        }
        CloseHandle(parent);
        return 1;
    }

    siex.lpAttributeList = attrs;
    BOOL ok = CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                             nullptr, nullptr, &siex.StartupInfo, &pi);
    if (ok)
    {
        BkaesPrint("[OK] PPID spoof childPid=%lu declaredParent=%lu\n", pi.dwProcessId, parentPid);
        BkaesSettleTelemetry();
        BkaesCleanupProcess(&pi);
    }
    DeleteProcThreadAttributeList(attrs);
    HeapFree(GetProcessHeap(), 0, attrs);
    CloseHandle(parent);
    return ok ? 0 : 1;
}
