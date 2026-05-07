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
    NtMapViewOfSection,
    NtMapViewOfSectionEx,
    NtQueueApcThreadEx,
    NtOpenProcessTokenEx,
    NtOpenThreadTokenEx,
    NtQuerySystemInformationEx,
    NtGetNextThread,
    NtUnmapViewOfSection,
    NtUnmapViewOfSectionEx,
    NtQueueApcThreadEx2,
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

inline constexpr std::uint64_t kNtHookSr71WriteBlockedMarker = 0x5352373157424C4Bull;
inline constexpr std::uint64_t kNtHookSr71ProtectBlockedMarker = 0x5352373150424C4Bull;
inline constexpr std::uint64_t kNtHookTerminateBreakpointMarker = 0x535237315445524Dull;

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

/* Returns the base address and 16-byte size of every allocated syscall stub so the
   IPC layer can register them with the controller as BK-owned pages.
   Each entry: {stubBase (16-byte alloc), hookName (null-terminated)}.
   Returns the number of entries written; outCount is the capacity on entry. */
struct NtHookStubInfo
{
    void *StubBase;
    std::size_t StubSize;
    const char *HookName;
};
std::size_t KeCollectNtHookStubInfos(_Out_writes_(capacity) NtHookStubInfo *out, _In_ std::size_t capacity) noexcept;

struct NtHookPatchInfo
{
    void *PatchAddress;
    std::size_t PatchSize;
    std::uint8_t OriginalBytes[16];
    const char *HookName;
};
std::size_t KeCollectNtHookPatchInfos(_Out_writes_(capacity) NtHookPatchInfo *out, _In_ std::size_t capacity) noexcept;

// Register/unregister a thread ID to be hidden from NtQuerySystemInformation(Ex)
// SystemProcessInformation results. Thread entries matching a registered TID are
// compacted out of the caller's view. Safe to call from any thread at any time.
void KeRegisterConcealedThread(DWORD tid) noexcept;
void KeUnregisterConcealedThread(DWORD tid) noexcept;
