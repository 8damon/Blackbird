#pragma once

#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>

#include "../instrument/stacktrace.h"

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
    NtAllocateVirtualMemoryEx,
    NtMapViewOfSectionEx,
    NtQueueApcThreadEx,
    NtOpenProcessTokenEx,
    NtOpenThreadTokenEx,
    NtQuerySystemInformationEx,
    NtGetNextThread,
};

struct NtHookContext
{
    NtOperation Operation;
    const char *FunctionName;
    void *Caller;
    NTSTATUS Status;
    std::uint64_t Args[8];
    std::uint32_t DataSize;
    std::uint8_t DataSample[64];
    IC_STACKTRACE::Trace Stack;
};
using NtHookCallback = void (*)(const NtHookContext &context) noexcept;

enum class NtHookInitFaultCode : std::uint32_t
{
    None = 0,
    NtdllMissing,
    NtdllTextMissing,
    NtdllExportDirectoryMissing,
    ExportMissing,
    ExportOutsideImage,
    ExportOutsideText,
    ExportRedirectedOutsideImage,
    UnexpectedStubBytes,
    SyscallStubAllocFailed,
    HookEntryMissing,
    PatchInstallFailed,
};

struct NtHookInitFault
{
    NtHookInitFaultCode Code;
    const char *FunctionName;
    void *Address;
    void *RedirectTarget;
    std::uint32_t SyscallIndex;
    std::uint8_t Sample[16];
};

bool KeSetNtHook(NtHookCallback callback) noexcept;
void KeRemoveNtHook() noexcept;

bool KeCheckNtHookIntegrity(std::uint32_t *mismatchCount) noexcept;
bool KeGetLastNtHookInitFault(NtHookInitFault *faultOut) noexcept;

// Register/unregister a thread ID to be hidden from NtQuerySystemInformation(Ex)
// SystemProcessInformation results. Thread entries matching a registered TID are
// compacted out of the caller's view. Safe to call from any thread at any time.
void KeRegisterConcealedThread(DWORD tid) noexcept;
void KeUnregisterConcealedThread(DWORD tid) noexcept;
