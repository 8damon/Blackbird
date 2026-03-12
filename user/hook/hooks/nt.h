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
};

struct NtHookContext
{
    NtOperation Operation;
    const char* FunctionName;
    void* Caller;

    // First 8 args of the Nt* call, encoded as raw 64-bit values
    // For ptrs: reinterpret_cast<std::uint64_t>(ptr)
    // For integral params: static_cast<std::uint64_t>(value)
    std::uint64_t Args[8];
};

// Callback invoked on every Nt* call
using NtHookCallback = void(*)(const NtHookContext& context) noexcept;

// Install inline hooks for a predefined set of Nt* funcs (TBE)
// Returns true if at least one hook was installed
bool KeSetNtHook(NtHookCallback callback) noexcept;

// Remove all Nt* hooks and restore original bytes
void KeRemoveNtHook() noexcept;

bool KeCheckNtHookIntegrity(std::uint32_t* mismatchCount) noexcept;
