#include "..\common\bkaes_sample.h"

int RunLoadLibraryRemoteThread()
{
    PROCESS_INFORMATION child;
    HANDLE process = nullptr;
    HANDLE thread = nullptr;
    PVOID remotePath = nullptr;
    std::wstring dllPath = BkaesJoinPath(BkaesSelfDirectory(), L"bb_unsigned_plugin.dll");
    SIZE_T pathBytes = (dllPath.size() + 1) * sizeof(wchar_t);
    SIZE_T written = 0;
    auto loadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");

    if (loadLibraryW == nullptr || !BkaesLaunchSelfChild(&child))
    {
        return 1;
    }

    process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                              PROCESS_VM_READ,
                          FALSE, child.dwProcessId);
    if (process != nullptr)
    {
        remotePath = VirtualAllocEx(process, nullptr, pathBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (remotePath != nullptr && WriteProcessMemory(process, remotePath, dllPath.c_str(), pathBytes, &written) &&
        written == pathBytes)
    {
        thread = CreateRemoteThread(process, nullptr, 0, loadLibraryW, remotePath, 0, nullptr);
    }

    if (thread != nullptr)
    {
        WaitForSingleObject(thread, 5000);
        CloseHandle(thread);
    }

    BkaesSettleTelemetry();
    BkaesPrint("[OK] LoadLibrary remote thread targetPid=%lu dll=%ls thread=%p\n", child.dwProcessId, dllPath.c_str(),
               thread);
    if (remotePath != nullptr)
    {
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
    }
    if (process != nullptr)
    {
        CloseHandle(process);
    }
    BkaesCleanupProcess(&child);
    return thread != nullptr ? 0 : 1;
}
