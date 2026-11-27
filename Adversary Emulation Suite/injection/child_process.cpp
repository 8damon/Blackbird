#include "..\common\bkaes_sample.h"

bool BkaesOpenChildForInjection(PROCESS_INFORMATION* child, HANDLE* process)
{
    if (!BkaesLaunchSelfChild(child))
    {
        return false;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntOpenProcess = ntdll != nullptr ? (NtOpenProcessFn)GetProcAddress(ntdll, "NtOpenProcess") : nullptr;
    ACCESS_MASK access =
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;
    if (ntOpenProcess != nullptr)
    {
        OBJECT_ATTRIBUTES oa;
        BkaesClientId cid;
        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
        cid.UniqueProcess = (HANDLE)(ULONG_PTR)child->dwProcessId;
        cid.UniqueThread = nullptr;
        NTSTATUS status = ntOpenProcess(process, access, &oa, &cid);
        if (status >= 0 && *process != nullptr)
        {
            return true;
        }
    }

    *process = OpenProcess(access, FALSE, child->dwProcessId);
    return *process != nullptr;
}
