#include "../include/detection_examples.h"

#include <cinttypes>

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemoryFn)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

static const char* BaseNameFromPath(const char* path)
{
    const char* base = path;

    if (path == nullptr)
    {
        return "";
    }

    for (const char* p = path; *p != '\0'; ++p)
    {
        if (*p == '\\' || *p == '/')
        {
            base = p + 1;
        }
    }
    return base;
}

static void PrintStackFrames(const char* label)
{
    static const USHORT kMaxFrames = 32;
    PVOID frames[kMaxFrames];
    USHORT captured;

    captured = RtlCaptureStackBackTrace(0, kMaxFrames, frames, nullptr);
    ExamplePrint("[%s] captured=%hu stack frames\n", label, captured);
    AES_LOG_DEBUG("%s captured=%hu stack frames", label, captured);

    for (USHORT i = 0; i < captured; ++i)
    {
        HMODULE module = nullptr;
        char path[MAX_PATH] = {0};
        const char* name = "<unknown>";
        uintptr_t offset = 0;

        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)frames[i], &module))
        {
            offset = (uintptr_t)frames[i] - (uintptr_t)module;
            if (GetModuleFileNameA(module, path, ARRAYSIZE(path)) != 0)
            {
                name = BaseNameFromPath(path);
            }
        }

        ExamplePrint("  #%02hu %p %s+0x%" PRIxPTR "\n", i, frames[i], name, offset);
        AES_LOG_DEBUG("stackFrame index=%hu address=%p module=%s offset=0x%" PRIxPTR, i, frames[i], name, offset);
    }
}

int ExampleRunNtAllocateStackTrace(int argc, wchar_t** argv)
{
    HMODULE ntdll;
    NtAllocateVirtualMemoryFn ntAllocateVirtualMemory;
    PVOID baseAddress = nullptr;
    SIZE_T regionSize = 0x4000;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    AES_LOG_DEBUG("Resolving NtAllocateVirtualMemory");
    ntdll = GetModuleHandleW(L"ntdll.dll");
    ntAllocateVirtualMemory =
        ntdll != nullptr ? (NtAllocateVirtualMemoryFn)GetProcAddress(ntdll, "NtAllocateVirtualMemory") : nullptr;
    if (ntAllocateVirtualMemory == nullptr)
    {
        AES_LOG_ERROR("Failed to resolve NtAllocateVirtualMemory ntdll=%p err=%lu", ntdll, GetLastError());
        ExamplePrint("[FAIL] ntallocate-stack-trace failed to resolve NtAllocateVirtualMemory\n");
        return 1;
    }
    AES_LOG_DEBUG("Resolved NtAllocateVirtualMemory=%p", ntAllocateVirtualMemory);

    AES_LOG_DEBUG("Calling NtAllocateVirtualMemory process=current requestedSize=%zu", regionSize);
    status = ntAllocateVirtualMemory(GetCurrentProcess(), &baseAddress, 0, &regionSize, MEM_RESERVE | MEM_COMMIT,
                                     PAGE_READWRITE);
    AES_LOG_DEBUG("NtAllocateVirtualMemory status=0x%08X base=%p size=%zu", (unsigned)status, baseAddress, regionSize);
    ExamplePrint("[OK] ntallocate-stack-trace NtAllocateVirtualMemory status=0x%08X base=%p size=%zu\n",
                 (unsigned)status, baseAddress, regionSize);
    PrintStackFrames("ntallocate-stack-trace");

    if (status < 0 || baseAddress == nullptr)
    {
        AES_LOG_ERROR("NtAllocateVirtualMemory returned failure status=0x%08X base=%p", (unsigned)status, baseAddress);
        return 1;
    }

    if (!VirtualFree(baseAddress, 0, MEM_RELEASE))
    {
        AES_LOG_ERROR("VirtualFree base=%p failed err=%lu", baseAddress, GetLastError());
        ExamplePrint("[FAIL] ntallocate-stack-trace VirtualFree err=%lu\n", GetLastError());
        return 1;
    }
    AES_LOG_DEBUG("VirtualFree base=%p completed", baseAddress);

    return 0;
}
