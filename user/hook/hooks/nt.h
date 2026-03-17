#pragma once

#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>

enum class NtOperation : std::uint32_t
{
    NtCreateThread = 0,
    NtCreateThreadEx,
    NtWriteVirtualMemory,
    NtAllocateVirtualMemory,
    NtProtectVirtualMemory,
    NtReadVirtualMemory,
    NtQueryVirtualMemory,
    NtQuerySystemInformation,
    NtCreateSection,
    NtTerminateProcess,
    NtOpenProcessToken,
    NtOpenThreadToken,
    NtOpenFile,
    NtQueryInformationProcess,
    NtQueryInformationThread,
    NtSetContextThread,
    NtQuerySection,
    NtQueryBootOptions,
    NtOpenProcess,
    NtOpenThread,
    NtDuplicateObject,
    NtGetContextThread,
    NtSuspendThread,
    NtResumeThread,
    NtQueueApcThread,
};

struct NtHookContext
{
    NtOperation Operation;
    const char* FunctionName;
    void* Caller;
    std::uint64_t Args[8];
};
using NtHookCallback = void(*)(const NtHookContext& context) noexcept;
bool KeSetNtHook(NtHookCallback callback) noexcept;
void KeRemoveNtHook() noexcept;

bool KeCheckNtHookIntegrity(std::uint32_t* mismatchCount) noexcept;

