#include "../include/detection_examples.h"

#include <algorithm>
static int RunInternalSleepChild()
{
    AES_LOG_DEBUG("Detection internal sleep child entering Sleep");
    Sleep(15000);
    AES_LOG_DEBUG("Detection internal sleep child exiting");
    return 0;
}

static int RunInternalReconChild()
{
    AES_LOG_DEBUG("Detection internal recon child entering Sleep");
    Sleep(8000);
    AES_LOG_DEBUG("Detection internal recon child exiting");
    return 0;
}

typedef NTSTATUS(NTAPI* NtQueryVirtualMemoryFn)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* NtOpenProcessFn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID);
typedef NTSTATUS(NTAPI* NtQuerySystemInformationFn)(ULONG, PVOID, ULONG, PULONG);

typedef struct _AesClientIdCompat
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} AesClientIdCompat;

static BOOL ScanStubForSsn(const BYTE* stub, size_t stubBytes, DWORD* ssn)
{
    size_t i;
    size_t j;

    if (stub == nullptr || ssn == nullptr || stubBytes < 8)
    {
        return FALSE;
    }

    for (i = 0; i + 4 < stubBytes; ++i)
    {
        if (stub[i] == 0xB8)
        {
            DWORD value = 0;
            memcpy(&value, &stub[i + 1], sizeof(value));
            for (j = i + 5; j + 1 < stubBytes && j < (i + 32); ++j)
            {
                if (stub[j] == 0x0F && stub[j + 1] == 0x05)
                {
                    *ssn = value;
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

static const BYTE* TryResolveJumpTarget(const BYTE* stub)
{
    if (stub == nullptr)
    {
        return nullptr;
    }
    if (stub[0] == 0xE9)
    {
        int32_t rel32 = 0;
        memcpy(&rel32, &stub[1], sizeof(rel32));
        return stub + 5 + rel32;
    }
    if (stub[0] == 0xEB)
    {
        return stub + 2 + (int8_t)stub[1];
    }
    if (stub[0] == 0xFF && stub[1] == 0x25)
    {
        int32_t disp32 = 0;
        const BYTE* tablePtr;
        const BYTE* target = nullptr;
        memcpy(&disp32, &stub[2], sizeof(disp32));
        tablePtr = stub + 6 + disp32;
        memcpy(&target, tablePtr, sizeof(target));
        return target;
    }
    return nullptr;
}

static BOOL ExtractSsn(const BYTE* stub, DWORD* ssn)
{
    const BYTE* candidate = stub;
    for (int depth = 0; depth < 3 && candidate != nullptr; ++depth)
    {
        if (ScanStubForSsn(candidate, 96, ssn))
        {
            return TRUE;
        }
        candidate = TryResolveJumpTarget(candidate);
    }
    return FALSE;
}

static void BuildSyscallStub(BYTE* stub, DWORD ssn)
{
    stub[0] = 0x4C;
    stub[1] = 0x8B;
    stub[2] = 0xD1;
    stub[3] = 0xB8;
    memcpy(&stub[4], &ssn, sizeof(ssn));
    stub[8] = 0x0F;
    stub[9] = 0x05;
    stub[10] = 0xC3;
    for (int i = 11; i < 16; ++i)
    {
        stub[i] = 0x90;
    }
}

int ExampleRunDirectSyscallNtQueryVm(int argc, wchar_t** argv)
{
#if !defined(_M_X64)
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    AES_LOG_WARN("direct-syscall-ntqueryvm skipped because build is not x64");
    ExamplePrint("[SKIP] direct-syscall-ntqueryvm is x64-only\n");
    return 1;
#else
    HMODULE ntdll;
    NtQueryVirtualMemoryFn ntQueryVirtualMemory;
    NtOpenProcessFn ntOpenProcess;
    DWORD ssnQueryVm = 0;
    DWORD ssnOpenProcess = 0;
    BYTE queryStub[16];
    BYTE openStub[16];
    DWORD oldProtect = 0;
    PROCESS_INFORMATION child;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T outLen = 0;
    DWORD targetPid;
    NTSTATUS statusQueryVm;
    NTSTATUS statusOpenProcessDirect;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    AES_LOG_DEBUG("Resolving ntdll exports for direct syscall scenario");
    ntdll = GetModuleHandleW(L"ntdll.dll");
    ntQueryVirtualMemory = (NtQueryVirtualMemoryFn)GetProcAddress(ntdll, "NtQueryVirtualMemory");
    ntOpenProcess = (NtOpenProcessFn)GetProcAddress(ntdll, "NtOpenProcess");
    if (ntdll == nullptr || ntQueryVirtualMemory == nullptr || ntOpenProcess == nullptr)
    {
        AES_LOG_ERROR("Failed to resolve ntdll exports ntdll=%p NtQueryVirtualMemory=%p NtOpenProcess=%p err=%lu",
                      ntdll, ntQueryVirtualMemory, ntOpenProcess, GetLastError());
        ExamplePrint("[FAIL] direct-syscall-ntqueryvm resolve ntdll exports failed\n");
        return 1;
    }
    AES_LOG_DEBUG("Resolved ntdll=%p NtQueryVirtualMemory=%p NtOpenProcess=%p", ntdll, ntQueryVirtualMemory,
                  ntOpenProcess);
    if (!ExtractSsn((const BYTE*)ntQueryVirtualMemory, &ssnQueryVm) ||
        !ExtractSsn((const BYTE*)ntOpenProcess, &ssnOpenProcess))
    {
        AES_LOG_ERROR("SSN extraction failed ssnQueryVm=0x%08lX ssnOpenProcess=0x%08lX", ssnQueryVm, ssnOpenProcess);
        ExamplePrint("[FAIL] direct-syscall-ntqueryvm SSN extraction failed\n");
        return 1;
    }
    AES_LOG_DEBUG("Extracted syscall IDs NtQueryVirtualMemory=0x%08lX NtOpenProcess=0x%08lX", ssnQueryVm,
                  ssnOpenProcess);
    if (!ExampleLaunchInternalChild(L"detection-sleep-child", &child))
    {
        ExamplePrint("[FAIL] direct-syscall-ntqueryvm launch child err=%lu\n", GetLastError());
        return 1;
    }
    targetPid = child.dwProcessId;
    AES_LOG_DEBUG("Launched target child pid=%lu for direct syscall scenario", targetPid);
    Sleep(150);

    BuildSyscallStub(queryStub, ssnQueryVm);
    BuildSyscallStub(openStub, ssnOpenProcess);
    AES_LOG_DEBUG("Built syscall stubs queryStub=%p openStub=%p", queryStub, openStub);
    if (!VirtualProtect(queryStub, sizeof(queryStub), PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        AES_LOG_ERROR("VirtualProtect queryStub failed err=%lu", GetLastError());
        ExampleCleanupProcess(&child, true, 2000);
        return 1;
    }
    AES_LOG_DEBUG("VirtualProtect queryStub oldProtect=0x%08lX", oldProtect);
    if (!VirtualProtect(openStub, sizeof(openStub), PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        AES_LOG_ERROR("VirtualProtect openStub failed err=%lu", GetLastError());
        ExampleCleanupProcess(&child, true, 2000);
        return 1;
    }
    AES_LOG_DEBUG("VirtualProtect openStub oldProtect=0x%08lX", oldProtect);

    AES_LOG_DEBUG("Issuing direct NtQueryVirtualMemory against current process");
    statusQueryVm = ((NtQueryVirtualMemoryFn)(void*)queryStub)(
        GetCurrentProcess(), (PVOID)(ULONG_PTR)&ExampleRunDirectSyscallNtQueryVm, 0, &mbi, sizeof(mbi), &outLen);
    AES_LOG_DEBUG("Direct NtQueryVirtualMemory status=0x%08X", (unsigned)statusQueryVm);
    AES_LOG_DEBUG("Direct NtQueryVirtualMemory returnLength=%zu allocationBase=%p protect=0x%08lX", outLen,
                  mbi.AllocationBase, mbi.Protect);
    {
        HANDLE opened = nullptr;
        OBJECT_ATTRIBUTES oa;
        AesClientIdCompat cid;
        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
        cid.UniqueProcess = (HANDLE)(ULONG_PTR)targetPid;
        cid.UniqueThread = nullptr;
        AES_LOG_DEBUG("Issuing direct NtOpenProcess targetPid=%lu", targetPid);
        statusOpenProcessDirect = ((NtOpenProcessFn)(void*)openStub)(
            &opened, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
            &oa, &cid);
        AES_LOG_DEBUG("Direct NtOpenProcess status=0x%08X", (unsigned)statusOpenProcessDirect);
        if (opened != nullptr)
        {
            AES_LOG_DEBUG("Direct NtOpenProcess returned handle=%p", opened);
            CloseHandle(opened);
        }
    }

    ExamplePrint("[OK] direct-syscall-ntqueryvm targetPid=%lu issued direct NtQueryVirtualMemory and NtOpenProcess\n",
                 targetPid);
    ExampleCleanupProcess(&child, true, 2000);
    return 0;
#endif
}

int ExampleRunRemoteThread(int argc, wchar_t** argv)
{
    PROCESS_INFORMATION child;
    HANDLE process = nullptr;
    LPVOID remote = nullptr;
    HANDLE thread = nullptr;
    SIZE_T written = 0;
    BYTE stub[] = {0x31, 0xC0, 0xC3};
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    AES_LOG_DEBUG("Launching target child for remote thread scenario");
    if (!ExampleLaunchInternalChild(L"detection-sleep-child", &child))
    {
        ExamplePrint("[FAIL] remote-thread launch child err=%lu\n", GetLastError());
        return 1;
    }

    AES_LOG_DEBUG("Opening target process pid=%lu", child.dwProcessId);
    process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
                          FALSE, child.dwProcessId);
    if (process == nullptr)
    {
        AES_LOG_ERROR("OpenProcess targetPid=%lu failed err=%lu", child.dwProcessId, GetLastError());
        ExamplePrint("[FAIL] remote-thread OpenProcess err=%lu\n", GetLastError());
        ExampleCleanupProcess(&child, true, 2000);
        return 1;
    }
    AES_LOG_DEBUG("OpenProcess targetPid=%lu handle=%p", child.dwProcessId, process);

    AES_LOG_DEBUG("Allocating remote RWX memory targetPid=%lu size=0x1000", child.dwProcessId);
    remote = VirtualAllocEx(process, nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (remote == nullptr)
    {
        AES_LOG_ERROR("VirtualAllocEx targetPid=%lu failed err=%lu", child.dwProcessId, GetLastError());
        ExamplePrint("[FAIL] remote-thread VirtualAllocEx err=%lu\n", GetLastError());
        CloseHandle(process);
        ExampleCleanupProcess(&child, true, 2000);
        return 1;
    }
    AES_LOG_DEBUG("VirtualAllocEx targetPid=%lu remote=%p", child.dwProcessId, remote);

    AES_LOG_DEBUG("Writing stub to remote process targetPid=%lu remote=%p bytes=%zu", child.dwProcessId, remote,
                  sizeof(stub));
    if (!WriteProcessMemory(process, remote, stub, sizeof(stub), &written) || written != sizeof(stub))
    {
        AES_LOG_ERROR("WriteProcessMemory targetPid=%lu remote=%p wrote=%zu expected=%zu err=%lu", child.dwProcessId,
                      remote, written, sizeof(stub), GetLastError());
        ExamplePrint("[FAIL] remote-thread WriteProcessMemory err=%lu\n", GetLastError());
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        CloseHandle(process);
        ExampleCleanupProcess(&child, true, 2000);
        return 1;
    }
    AES_LOG_DEBUG("WriteProcessMemory targetPid=%lu remote=%p wrote=%zu", child.dwProcessId, remote, written);

    AES_LOG_DEBUG("Creating remote thread targetPid=%lu start=%p", child.dwProcessId, remote);
    thread = CreateRemoteThread(process, nullptr, 0, (LPTHREAD_START_ROUTINE)remote, nullptr, 0, nullptr);
    if (thread == nullptr)
    {
        AES_LOG_ERROR("CreateRemoteThread targetPid=%lu start=%p failed err=%lu", child.dwProcessId, remote,
                      GetLastError());
        ExamplePrint("[FAIL] remote-thread CreateRemoteThread err=%lu\n", GetLastError());
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        CloseHandle(process);
        ExampleCleanupProcess(&child, true, 2000);
        return 1;
    }
    AES_LOG_DEBUG("CreateRemoteThread targetPid=%lu thread=%p", child.dwProcessId, thread);

    AES_LOG_DEBUG("Remote thread wait result=0x%08lX", WaitForSingleObject(thread, 2000));
    ExamplePrint("[OK] remote-thread targetPid=%lu remoteStart=%p wrote=%zu bytes\n", child.dwProcessId, remote,
                 written);
    CloseHandle(thread);
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    CloseHandle(process);
    ExampleCleanupProcess(&child, true, 2000);
    return 0;
}

int ExampleRunPpidSpoof(int argc, wchar_t** argv)
{
    STARTUPINFOEXW siex;
    PROCESS_INFORMATION pi;
    SIZE_T attrSize = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = nullptr;
    HANDLE parent = nullptr;
    DWORD parentPid;
    std::wstring selfPath;
    wchar_t cmd[(MAX_PATH * 2) + 128];
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    AES_LOG_DEBUG("Resolving parent process for PPID spoof scenario");
    parentPid = ExampleFindProcessIdByName(L"explorer.exe");
    if (parentPid == 0)
    {
        ExamplePrint("[FAIL] ppid-spoof explorer.exe not found\n");
        return 1;
    }

    AES_LOG_DEBUG("Opening parent process pid=%lu for PROCESS_CREATE_PROCESS", parentPid);
    parent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
    if (parent == nullptr)
    {
        AES_LOG_ERROR("OpenProcess parentPid=%lu failed err=%lu", parentPid, GetLastError());
        ExamplePrint("[FAIL] ppid-spoof OpenProcess(parent=%lu) err=%lu\n", parentPid, GetLastError());
        return 1;
    }
    AES_LOG_DEBUG("OpenProcess parentPid=%lu handle=%p", parentPid, parent);

    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
    AES_LOG_DEBUG("PROC_THREAD_ATTRIBUTE_LIST required bytes=%zu", attrSize);
    attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
    if (attrs == nullptr || !InitializeProcThreadAttributeList(attrs, 1, 0, &attrSize))
    {
        AES_LOG_ERROR("InitializeProcThreadAttributeList failed attrs=%p err=%lu", attrs, GetLastError());
        ExamplePrint("[FAIL] ppid-spoof attribute list init err=%lu\n", GetLastError());
        if (attrs != nullptr)
            HeapFree(GetProcessHeap(), 0, attrs);
        CloseHandle(parent);
        return 1;
    }
    AES_LOG_DEBUG("Initialized attribute list attrs=%p", attrs);
    if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parent, sizeof(parent), nullptr,
                                   nullptr))
    {
        AES_LOG_ERROR("UpdateProcThreadAttribute parentPid=%lu failed err=%lu", parentPid, GetLastError());
        ExamplePrint("[FAIL] ppid-spoof UpdateProcThreadAttribute err=%lu\n", GetLastError());
        DeleteProcThreadAttributeList(attrs);
        HeapFree(GetProcessHeap(), 0, attrs);
        CloseHandle(parent);
        return 1;
    }
    AES_LOG_DEBUG("Updated parent process attribute parentPid=%lu", parentPid);

    ZeroMemory(&siex, sizeof(siex));
    ZeroMemory(&pi, sizeof(pi));
    siex.StartupInfo.cb = sizeof(siex);
    siex.lpAttributeList = attrs;
    selfPath = ExampleGetSelfPath();
    if (FAILED(StringCchPrintfW(cmd, ARRAYSIZE(cmd), L"\"%ls\" --internal detection-recon-child", selfPath.c_str())))
    {
        AES_LOG_ERROR("PPID spoof command line buffer too small");
        DeleteProcThreadAttributeList(attrs);
        HeapFree(GetProcessHeap(), 0, attrs);
        CloseHandle(parent);
        return 1;
    }
    AES_LOG_DEBUG("Creating spoofed child commandLine=%ls", cmd);
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr,
                        nullptr, &siex.StartupInfo, &pi))
    {
        AES_LOG_ERROR("CreateProcessW spoofed parentPid=%lu failed err=%lu", parentPid, GetLastError());
        ExamplePrint("[FAIL] ppid-spoof CreateProcessW err=%lu\n", GetLastError());
        DeleteProcThreadAttributeList(attrs);
        HeapFree(GetProcessHeap(), 0, attrs);
        CloseHandle(parent);
        return 1;
    }
    AES_LOG_INFO("Created PPID spoof childPid=%lu parentPid=%lu", pi.dwProcessId, parentPid);

    ExamplePrint("[OK] ppid-spoof created childPid=%lu with spoofed parentPid=%lu\n", pi.dwProcessId, parentPid);
    ExampleCleanupProcess(&pi, true, 2000);
    DeleteProcThreadAttributeList(attrs);
    HeapFree(GetProcessHeap(), 0, attrs);
    CloseHandle(parent);
    return 0;
}

int ExampleRunNtSystemRecon(int argc, wchar_t** argv)
{
    HMODULE ntdll;
    NtQuerySystemInformationFn ntQuerySystemInformation;
    BYTE buffer[0x4000];
    ULONG returnLength = 0;
    NTSTATUS status1;
    NTSTATUS status2;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    AES_LOG_DEBUG("Resolving NtQuerySystemInformation");
    ntdll = GetModuleHandleW(L"ntdll.dll");
    ntQuerySystemInformation = (NtQuerySystemInformationFn)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (ntdll == nullptr || ntQuerySystemInformation == nullptr)
    {
        AES_LOG_ERROR("Failed to resolve NtQuerySystemInformation ntdll=%p fn=%p err=%lu", ntdll,
                      ntQuerySystemInformation, GetLastError());
        ExamplePrint("[FAIL] nt-system-recon failed to resolve NtQuerySystemInformation\n");
        return 1;
    }
    AES_LOG_DEBUG("Resolved NtQuerySystemInformation=%p", ntQuerySystemInformation);

    AES_LOG_DEBUG("Querying SystemProcessInformation class=5 bufferBytes=%zu", sizeof(buffer));
    status1 = ntQuerySystemInformation(5, buffer, sizeof(buffer), &returnLength);
    AES_LOG_DEBUG("NtQuerySystemInformation class=5 status=0x%08X returnLength=%lu", (unsigned)status1, returnLength);
    returnLength = 0;
    AES_LOG_DEBUG("Querying SystemModuleInformation class=11 bufferBytes=%zu", sizeof(buffer));
    status2 = ntQuerySystemInformation(11, buffer, sizeof(buffer), &returnLength);
    AES_LOG_DEBUG("NtQuerySystemInformation class=11 status=0x%08X returnLength=%lu", (unsigned)status2, returnLength);
    ExamplePrint("[OK] nt-system-recon NtQuerySystemInformation status{class5=0x%08X class11=0x%08X}\n",
                 (unsigned)status1, (unsigned)status2);
    return 0;
}

static int contains_vm_string(const char* s)
{
    static const char* keywords[] = {"vmware",          "virtualbox",       "vbox",     "kvm", "qemu", "xen", "hyper-v",
                                     "virtual machine", "virtual platform", "parallels"};
    if (s == nullptr)
    {
        return 0;
    }
    std::string lower(s);
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return (char)tolower(c); });
    for (const char* keyword : keywords)
    {
        if (lower.find(keyword) != std::string::npos)
        {
            return 1;
        }
    }
    return 0;
}

static int check_vm_mac(const BYTE* mac)
{
    static const BYTE prefixes[][3] = {{0x00, 0x05, 0x69}, {0x00, 0x0C, 0x29}, {0x00, 0x1C, 0x14}, {0x00, 0x50, 0x56},
                                       {0x08, 0x00, 0x27}, {0x52, 0x54, 0x00}, {0x00, 0x15, 0x5D}, {0x00, 0x16, 0x3E}};
    for (size_t i = 0; i < ARRAYSIZE(prefixes); ++i)
    {
        if (memcmp(mac, prefixes[i], 3) == 0)
        {
            return 1;
        }
    }
    return 0;
}

int ExampleRunVmCheck(int argc, wchar_t** argv)
{
    ULONG size = 0;
    DWORD score = 0;
    char bios[256] = {0};
    DWORD biosSize = sizeof(bios);
    PIP_ADAPTER_INFO info = nullptr;
    LSTATUS regStatus;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    AES_LOG_DEBUG("Querying adapter info required size");
    DWORD adaptersStatus = GetAdaptersInfo(nullptr, &size);
    AES_LOG_DEBUG("GetAdaptersInfo sizing status=%lu requiredBytes=%lu", adaptersStatus, size);
    info = (PIP_ADAPTER_INFO)malloc(size);
    if (info != nullptr && GetAdaptersInfo(info, &size) == NO_ERROR)
    {
        for (PIP_ADAPTER_INFO a = info; a != nullptr; a = a->Next)
        {
            DWORD adapterScore = 0;
            if (check_vm_mac(a->Address))
            {
                score += 3;
                adapterScore += 3;
            }
            if (contains_vm_string(a->Description))
            {
                score += 2;
                adapterScore += 2;
            }
            AES_LOG_DEBUG("Adapter name=%s description=%s mac=%02X:%02X:%02X:%02X:%02X:%02X score=%lu", a->AdapterName,
                          a->Description, a->AddressLength > 0 ? a->Address[0] : 0,
                          a->AddressLength > 1 ? a->Address[1] : 0, a->AddressLength > 2 ? a->Address[2] : 0,
                          a->AddressLength > 3 ? a->Address[3] : 0, a->AddressLength > 4 ? a->Address[4] : 0,
                          a->AddressLength > 5 ? a->Address[5] : 0, adapterScore);
        }
        free(info);
    }
    else
    {
        AES_LOG_WARN("GetAdaptersInfo failed or allocation failed info=%p err=%lu status=%lu", info, GetLastError(),
                     adaptersStatus);
        if (info != nullptr)
        {
            free(info);
        }
    }

    regStatus = RegGetValueA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemManufacturer",
                             RRF_RT_REG_SZ, nullptr, bios, &biosSize);
    if (regStatus == ERROR_SUCCESS)
    {
        AES_LOG_DEBUG("BIOS SystemManufacturer=%s", bios);
        if (contains_vm_string(bios))
            score += 3;
    }
    else
    {
        AES_LOG_WARN("RegGetValueA BIOS SystemManufacturer failed status=%ld", regStatus);
    }

    AES_LOG_INFO("VM check evidenceScore=%lu", score);
    ExamplePrint("[OK] anti-virt-vm-check evidenceScore=%lu\n", score);
    return 0;
}

int DetectionExamplesInternalDetectionMain(const wchar_t* mode)
{
    if (_wcsicmp(mode, L"detection-sleep-child") == 0)
    {
        return RunInternalSleepChild();
    }
    if (_wcsicmp(mode, L"detection-recon-child") == 0)
    {
        return RunInternalReconChild();
    }
    return -1;
}
