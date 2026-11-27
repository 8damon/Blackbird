#include "..\common\bkaes_sample.h"

int RunRemoteApcLoadLibrary()
{
    PROCESS_INFORMATION child;
    HANDLE process = nullptr;
    PVOID remotePath = nullptr;
    std::wstring dllPath = BkaesJoinPath(BkaesSelfDirectory(), L"bb_unsigned_plugin.dll");
    SIZE_T pathBytes = (dllPath.size() + 1) * sizeof(wchar_t);
    SIZE_T written = 0;
    auto loadLibraryW = (PAPCFUNC)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    DWORD queued = 0;

    if (loadLibraryW == nullptr || !BkaesLaunchSelfChild(&child, CREATE_SUSPENDED | CREATE_NO_WINDOW))
    {
        return 1;
    }

    process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE,
                          child.dwProcessId);
    if (process != nullptr)
    {
        remotePath = VirtualAllocEx(process, nullptr, pathBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (remotePath != nullptr && WriteProcessMemory(process, remotePath, dllPath.c_str(), pathBytes, &written) &&
        written == pathBytes)
    {
        queued = QueueUserAPC(loadLibraryW, child.hThread, (ULONG_PTR)remotePath);
    }

    ResumeThread(child.hThread);
    WaitForSingleObject(child.hProcess, 1500);
    BkaesSettleTelemetry();
    BkaesPrint("[OK] APC LoadLibrary targetPid=%lu dll=%ls queued=%lu\n", child.dwProcessId, dllPath.c_str(), queued);
    if (remotePath != nullptr)
    {
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
    }
    if (process != nullptr)
    {
        CloseHandle(process);
    }
    BkaesCleanupProcess(&child);
    return queued != 0 ? 0 : 1;
}
