#include "nt.h"

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <intrin.h>

#pragma intrinsic(_ReturnAddress)

#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#endif

#ifdef _WIN64

namespace RYX_NT
{
    static bool ShouldEnableNtMemoryHooks() noexcept
    {
        char value[8]{};
        DWORD read =
            GetEnvironmentVariableA("BLACKBIRD_NT_HOOK_MEMORY", value, static_cast<DWORD>(RTL_NUMBER_OF(value)));
        if (read == 0 || read >= RTL_NUMBER_OF(value))
        {
            return false;
        }

        return value[0] == '1' || value[0] == 'y' || value[0] == 'Y' || value[0] == 't' || value[0] == 'T';
    }

    static bool IsNtMemoryHookName(const char *name) noexcept
    {
        if (name == nullptr)
        {
            return false;
        }

        return (std::strcmp(name, "NtAllocateVirtualMemory") == 0) ||
               (std::strcmp(name, "NtProtectVirtualMemory") == 0) ||
               (std::strcmp(name, "NtAllocateVirtualMemoryEx") == 0) ||
               (std::strcmp(name, "NtMapViewOfSectionEx") == 0);
    }

    typedef struct _CLIENT_ID
    {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    } CLIENT_ID, *PCLIENT_ID;

    typedef struct _INITIAL_TEB
    {
        PVOID StackBase;
        PVOID StackLimit;
        PVOID StackAllocation;
    } INITIAL_TEB, *PINITIAL_TEB;

    using NtCreateThread_t = NTSTATUS(NTAPI *)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                               POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                                               PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb,
                                               BOOLEAN CreateSuspended);

    using NtCreateThreadEx_t = NTSTATUS(NTAPI *)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                                 POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                                                 PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits,
                                                 SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);

    using NtWriteVirtualMemory_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
                                                     SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);

    using NtAllocateVirtualMemory_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
                                                        PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

    using NtProtectVirtualMemory_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
                                                       ULONG NewProtect, PULONG OldProtect);

    using NtReadVirtualMemory_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
                                                    SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);

    using NtQueryVirtualMemory_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PVOID BaseAddress,
                                                     ULONG MemoryInformationClass, PVOID MemoryInformation,
                                                     SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

    using NtQuerySystemInformation_t = NTSTATUS(NTAPI *)(ULONG SystemInformationClass, PVOID SystemInformation,
                                                         ULONG SystemInformationLength, PULONG ReturnLength);

    using NtCreateSection_t = NTSTATUS(NTAPI *)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
                                                POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
                                                ULONG SectionPageProtection, ULONG AllocationAttributes,
                                                HANDLE FileHandle);

    using NtTerminateProcess_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, NTSTATUS ExitStatus);

    using NtOpenProcessToken_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                                   PHANDLE TokenHandle);

    using NtOpenThreadToken_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf,
                                                  PHANDLE TokenHandle);

    using NtOpenFile_t = NTSTATUS(NTAPI *)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                                           POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
                                           ULONG ShareAccess, ULONG OpenOptions);

    using NtQueryInformationProcess_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, ULONG ProcessInformationClass,
                                                          PVOID ProcessInformation, ULONG ProcessInformationLength,
                                                          PULONG ReturnLength);

    using NtQueryInformationThread_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, ULONG ThreadInformationClass,
                                                         PVOID ThreadInformation, ULONG ThreadInformationLength,
                                                         PULONG ReturnLength);

    using NtSetContextThread_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, PCONTEXT ThreadContext);

    using NtQuerySection_t = NTSTATUS(NTAPI *)(HANDLE SectionHandle, ULONG SectionInformationClass,
                                               PVOID InformationBuffer, ULONG InformationBufferSize,
                                               PULONG ResultLength);

    using NtQueryBootOptions_t = NTSTATUS(NTAPI *)(PVOID BootOptions, PULONG BootOptionsLength);

    using NtOpenProcess_t = NTSTATUS(NTAPI *)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                              POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

    using NtOpenThread_t = NTSTATUS(NTAPI *)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                             POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

    using NtDuplicateObject_t = NTSTATUS(NTAPI *)(HANDLE SourceProcessHandle, HANDLE SourceHandle,
                                                  HANDLE TargetProcessHandle, PHANDLE TargetHandle,
                                                  ACCESS_MASK DesiredAccess, ULONG Attributes, ULONG Options);

    using NtGetContextThread_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, PCONTEXT ThreadContext);

    using NtSuspendThread_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

    using NtResumeThread_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

    using NtQueueApcThread_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArgument1,
                                                 PVOID ApcArgument2, PVOID ApcArgument3);

    using NtAllocateVirtualMemoryEx_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
                                                          PSIZE_T RegionSize, ULONG AllocationType,
                                                          PVOID ExtendedParameters, ULONG ExtendedParameterCount);

    using NtMapViewOfSectionEx_t = NTSTATUS(NTAPI *)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
                                                     PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize,
                                                     ULONG AllocationType, ULONG Win32Protect, PVOID ExtendedParameters,
                                                     ULONG ExtendedParameterCount);

    using NtQueueApcThreadEx_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, HANDLE UserApcReserveHandle, PVOID ApcRoutine,
                                                   PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

    using NtOpenProcessTokenEx_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                                     ULONG HandleAttributes, PHANDLE TokenHandle);

    using NtOpenThreadTokenEx_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf,
                                                    ULONG HandleAttributes, PHANDLE TokenHandle);

    static NtCreateThread_t g_NtCreateThreadStub = nullptr;
    static NtCreateThreadEx_t g_NtCreateThreadExStub = nullptr;
    static NtWriteVirtualMemory_t g_NtWriteVirtualMemoryStub = nullptr;
    static NtAllocateVirtualMemory_t g_NtAllocateVirtualMemoryStub = nullptr;
    static NtProtectVirtualMemory_t g_NtProtectVirtualMemoryStub = nullptr;
    static NtReadVirtualMemory_t g_NtReadVirtualMemoryStub = nullptr;
    static NtQueryVirtualMemory_t g_NtQueryVirtualMemoryStub = nullptr;
    static NtQuerySystemInformation_t g_NtQuerySystemInformationStub = nullptr;
    static NtCreateSection_t g_NtCreateSectionStub = nullptr;
    static NtTerminateProcess_t g_NtTerminateProcessStub = nullptr;
    static NtOpenProcessToken_t g_NtOpenProcessTokenStub = nullptr;
    static NtOpenThreadToken_t g_NtOpenThreadTokenStub = nullptr;
    static NtOpenFile_t g_NtOpenFileStub = nullptr;
    static NtQueryInformationProcess_t g_NtQueryInformationProcessStub = nullptr;
    static NtQueryInformationThread_t g_NtQueryInformationThreadStub = nullptr;
    static NtSetContextThread_t g_NtSetContextThreadStub = nullptr;
    static NtQuerySection_t g_NtQuerySectionStub = nullptr;
    static NtQueryBootOptions_t g_NtQueryBootOptionsStub = nullptr;
    static NtOpenProcess_t g_NtOpenProcessStub = nullptr;
    static NtOpenThread_t g_NtOpenThreadStub = nullptr;
    static NtDuplicateObject_t g_NtDuplicateObjectStub = nullptr;
    static NtGetContextThread_t g_NtGetContextThreadStub = nullptr;
    static NtSuspendThread_t g_NtSuspendThreadStub = nullptr;
    static NtResumeThread_t g_NtResumeThreadStub = nullptr;
    static NtQueueApcThread_t g_NtQueueApcThreadStub = nullptr;
    static NtAllocateVirtualMemoryEx_t g_NtAllocateVirtualMemoryExStub = nullptr;
    static NtMapViewOfSectionEx_t g_NtMapViewOfSectionExStub = nullptr;
    static NtQueueApcThreadEx_t g_NtQueueApcThreadExStub = nullptr;
    static NtOpenProcessTokenEx_t g_NtOpenProcessTokenExStub = nullptr;
    static NtOpenThreadTokenEx_t g_NtOpenThreadTokenExStub = nullptr;

    struct NtTargetHook
    {
        const char *Name;
        NtOperation Operation;
        void *TargetAddress;
        void *SyscallStubCode;
        std::uint32_t SyscallIndex;
        std::uint8_t OriginalBytes[16];
        bool Installed;
    };

    static NtHookCallback g_ActiveNtCallback = nullptr;

    static NtTargetHook g_NtHooks[] = {
        {"NtCreateThread", NtOperation::NtCreateThread, nullptr, nullptr, 0u, {}, false},
        {"NtCreateThreadEx", NtOperation::NtCreateThreadEx, nullptr, nullptr, 0u, {}, false},
        {"NtWriteVirtualMemory", NtOperation::NtWriteVirtualMemory, nullptr, nullptr, 0u, {}, false},
        {"NtAllocateVirtualMemory", NtOperation::NtAllocateVirtualMemory, nullptr, nullptr, 0u, {}, false},
        {"NtProtectVirtualMemory", NtOperation::NtProtectVirtualMemory, nullptr, nullptr, 0u, {}, false},
        {"NtReadVirtualMemory", NtOperation::NtReadVirtualMemory, nullptr, nullptr, 0u, {}, false},
        {"NtQueryVirtualMemory", NtOperation::NtQueryVirtualMemory, nullptr, nullptr, 0u, {}, false},
        {"NtQuerySystemInformation", NtOperation::NtQuerySystemInformation, nullptr, nullptr, 0u, {}, false},
        {"NtCreateSection", NtOperation::NtCreateSection, nullptr, nullptr, 0u, {}, false},
        {"NtTerminateProcess", NtOperation::NtTerminateProcess, nullptr, nullptr, 0u, {}, false},
        {"NtOpenProcessToken", NtOperation::NtOpenProcessToken, nullptr, nullptr, 0u, {}, false},
        {"NtOpenThreadToken", NtOperation::NtOpenThreadToken, nullptr, nullptr, 0u, {}, false},
        {"NtOpenFile", NtOperation::NtOpenFile, nullptr, nullptr, 0u, {}, false},
        {"NtQueryInformationProcess", NtOperation::NtQueryInformationProcess, nullptr, nullptr, 0u, {}, false},
        {"NtQueryInformationThread", NtOperation::NtQueryInformationThread, nullptr, nullptr, 0u, {}, false},
        {"NtSetContextThread", NtOperation::NtSetContextThread, nullptr, nullptr, 0u, {}, false},
        {"NtQuerySection", NtOperation::NtQuerySection, nullptr, nullptr, 0u, {}, false},
        {"NtQueryBootOptions", NtOperation::NtQueryBootOptions, nullptr, nullptr, 0u, {}, false},
        {"NtOpenProcess", NtOperation::NtOpenProcess, nullptr, nullptr, 0u, {}, false},
        {"NtOpenThread", NtOperation::NtOpenThread, nullptr, nullptr, 0u, {}, false},
        {"NtDuplicateObject", NtOperation::NtDuplicateObject, nullptr, nullptr, 0u, {}, false},
        {"NtGetContextThread", NtOperation::NtGetContextThread, nullptr, nullptr, 0u, {}, false},
        {"NtSuspendThread", NtOperation::NtSuspendThread, nullptr, nullptr, 0u, {}, false},
        {"NtResumeThread", NtOperation::NtResumeThread, nullptr, nullptr, 0u, {}, false},
        {"NtQueueApcThread", NtOperation::NtQueueApcThread, nullptr, nullptr, 0u, {}, false},
        {"NtAllocateVirtualMemoryEx", NtOperation::NtAllocateVirtualMemoryEx, nullptr, nullptr, 0u, {}, false},
        {"NtMapViewOfSectionEx", NtOperation::NtMapViewOfSectionEx, nullptr, nullptr, 0u, {}, false},
        {"NtQueueApcThreadEx", NtOperation::NtQueueApcThreadEx, nullptr, nullptr, 0u, {}, false},
        {"NtOpenProcessTokenEx", NtOperation::NtOpenProcessTokenEx, nullptr, nullptr, 0u, {}, false},
        {"NtOpenThreadTokenEx", NtOperation::NtOpenThreadTokenEx, nullptr, nullptr, 0u, {}, false},
    };

    static bool ExtractSyscallIndex(void *targetAddress, std::uint32_t &outIndex) noexcept
    {
        auto *bytes = static_cast<std::uint8_t *>(targetAddress);

        if (bytes[0] != 0x4C || bytes[1] != 0x8B || bytes[2] != 0xD1)
            return false;

        if (bytes[3] != 0xB8)
            return false;

        outIndex = *reinterpret_cast<std::uint32_t *>(&bytes[4]);
        return true;
    }

    static void *BuildSyscallStub(std::uint32_t syscallIndex) noexcept
    {
        constexpr std::size_t StubSize = 16;

        void *memory = VirtualAlloc(nullptr, StubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (!memory)
            return nullptr;

        auto *code = static_cast<std::uint8_t *>(memory);
        code[0] = 0x4C;
        code[1] = 0x8B;
        code[2] = 0xD1;
        code[3] = 0xB8;
        *reinterpret_cast<std::uint32_t *>(&code[4]) = syscallIndex;
        code[8] = 0x0F;
        code[9] = 0x05;
        code[10] = 0xC3;
        for (std::size_t i = 11; i < StubSize; ++i)
            code[i] = 0xCC;

        return memory;
    }

    static bool InstallInlineHook(void *target, void *hook, std::uint8_t original[16]) noexcept
    {
        auto *dst = static_cast<std::uint8_t *>(target);

        DWORD oldProtect = 0;
        if (!VirtualProtect(dst, 16, PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;

        std::memcpy(original, dst, 16);
        dst[0] = 0x48;
        dst[1] = 0xB8;
        *reinterpret_cast<void **>(&dst[2]) = hook;
        dst[10] = 0xFF;
        dst[11] = 0xE0;
        dst[12] = 0xCC;
        dst[13] = 0xCC;
        dst[14] = 0xCC;
        dst[15] = 0xCC;

        DWORD tmp = 0;
        VirtualProtect(dst, 16, oldProtect, &tmp);
        FlushInstructionCache(GetCurrentProcess(), dst, 16);

        return true;
    }

    static void RemoveInlineHook(void *target, const std::uint8_t original[16]) noexcept
    {
        auto *dst = static_cast<std::uint8_t *>(target);

        DWORD oldProtect = 0;
        if (!VirtualProtect(dst, 16, PAGE_EXECUTE_READWRITE, &oldProtect))
            return;

        std::memcpy(dst, original, 16);

        DWORD tmp = 0;
        VirtualProtect(dst, 16, oldProtect, &tmp);
        FlushInstructionCache(GetCurrentProcess(), dst, 16);
    }

    NTSTATUS NTAPI NtCreateThread_Hook(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                       POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId,
                                       PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtCreateThread;
            ctx.FunctionName = "NtCreateThread";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ObjectAttributes);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ClientId);
            ctx.Args[5] = reinterpret_cast<std::uint64_t>(ThreadContext);
            ctx.Args[6] = reinterpret_cast<std::uint64_t>(InitialTeb);
            ctx.Args[7] = static_cast<std::uint64_t>(CreateSuspended);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtCreateThreadStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtCreateThreadStub(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId,
                                    ThreadContext, InitialTeb, CreateSuspended);
    }

    NTSTATUS NTAPI NtCreateThreadEx_Hook(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                         POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine,
                                         PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
                                         SIZE_T MaximumStackSize, PVOID AttributeList)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtCreateThreadEx;
            ctx.FunctionName = "NtCreateThreadEx";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(StartRoutine);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(Argument);
            ctx.Args[5] = static_cast<std::uint64_t>(CreateFlags);
            ctx.Args[6] = static_cast<std::uint64_t>(StackSize);
            ctx.Args[7] = static_cast<std::uint64_t>(MaximumStackSize);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtCreateThreadExStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtCreateThreadExStub(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine,
                                      Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
    }

    NTSTATUS NTAPI NtWriteVirtualMemory_Hook(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize,
                                             PSIZE_T NumberOfBytesWritten)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtWriteVirtualMemory;
            ctx.FunctionName = "NtWriteVirtualMemory";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(Buffer);
            ctx.Args[3] = static_cast<std::uint64_t>(BufferSize);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(NumberOfBytesWritten);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtWriteVirtualMemoryStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtWriteVirtualMemoryStub(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
    }

    NTSTATUS NTAPI NtAllocateVirtualMemory_Hook(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
                                                PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtAllocateVirtualMemory;
            ctx.FunctionName = "NtAllocateVirtualMemory";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[2] = static_cast<std::uint64_t>(ZeroBits);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(RegionSize);
            ctx.Args[4] = static_cast<std::uint64_t>(AllocationType);
            ctx.Args[5] = static_cast<std::uint64_t>(Protect);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtAllocateVirtualMemoryStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtAllocateVirtualMemoryStub(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    }

    NTSTATUS NTAPI NtProtectVirtualMemory_Hook(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
                                               ULONG NewProtect, PULONG OldProtect)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtProtectVirtualMemory;
            ctx.FunctionName = "NtProtectVirtualMemory";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(RegionSize);
            ctx.Args[3] = static_cast<std::uint64_t>(NewProtect);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(OldProtect);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtProtectVirtualMemoryStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtProtectVirtualMemoryStub(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
    }

    NTSTATUS NTAPI NtReadVirtualMemory_Hook(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize,
                                            PSIZE_T NumberOfBytesRead)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtReadVirtualMemory;
            ctx.FunctionName = "NtReadVirtualMemory";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(Buffer);
            ctx.Args[3] = static_cast<std::uint64_t>(BufferSize);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(NumberOfBytesRead);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtReadVirtualMemoryStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtReadVirtualMemoryStub(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
    }

    NTSTATUS NTAPI NtQueryVirtualMemory_Hook(HANDLE ProcessHandle, PVOID BaseAddress, ULONG MemoryInformationClass,
                                             PVOID MemoryInformation, SIZE_T MemoryInformationLength,
                                             PSIZE_T ReturnLength)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQueryVirtualMemory;
            ctx.FunctionName = "NtQueryVirtualMemory";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[2] = static_cast<std::uint64_t>(MemoryInformationClass);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(MemoryInformation);
            ctx.Args[4] = static_cast<std::uint64_t>(MemoryInformationLength);
            ctx.Args[5] = reinterpret_cast<std::uint64_t>(ReturnLength);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtQueryVirtualMemoryStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtQueryVirtualMemoryStub(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation,
                                          MemoryInformationLength, ReturnLength);
    }

    NTSTATUS NTAPI NtQuerySystemInformation_Hook(ULONG SystemInformationClass, PVOID SystemInformation,
                                                 ULONG SystemInformationLength, PULONG ReturnLength)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQuerySystemInformation;
            ctx.FunctionName = "NtQuerySystemInformation";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = static_cast<std::uint64_t>(SystemInformationClass);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(SystemInformation);
            ctx.Args[2] = static_cast<std::uint64_t>(SystemInformationLength);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(ReturnLength);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtQuerySystemInformationStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtQuerySystemInformationStub(SystemInformationClass, SystemInformation, SystemInformationLength,
                                              ReturnLength);
    }

    NTSTATUS NTAPI NtCreateSection_Hook(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
                                        POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
                                        ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtCreateSection;
            ctx.FunctionName = "NtCreateSection";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(SectionHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ObjectAttributes);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(MaximumSize);
            ctx.Args[4] = static_cast<std::uint64_t>(SectionPageProtection);
            ctx.Args[5] = static_cast<std::uint64_t>(AllocationAttributes);
            ctx.Args[6] = reinterpret_cast<std::uint64_t>(FileHandle);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtCreateSectionStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtCreateSectionStub(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection,
                                     AllocationAttributes, FileHandle);
    }

    NTSTATUS NTAPI NtTerminateProcess_Hook(HANDLE ProcessHandle, NTSTATUS ExitStatus)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtTerminateProcess;
            ctx.FunctionName = "NtTerminateProcess";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(ExitStatus);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtTerminateProcessStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtTerminateProcessStub(ProcessHandle, ExitStatus);
    }

    NTSTATUS NTAPI NtOpenProcessToken_Hook(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtOpenProcessToken;
            ctx.FunctionName = "NtOpenProcessToken";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(TokenHandle);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtOpenProcessTokenStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtOpenProcessTokenStub(ProcessHandle, DesiredAccess, TokenHandle);
    }

    NTSTATUS NTAPI NtOpenThreadToken_Hook(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf,
                                          PHANDLE TokenHandle)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtOpenThreadToken;
            ctx.FunctionName = "NtOpenThreadToken";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = static_cast<std::uint64_t>(OpenAsSelf);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(TokenHandle);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtOpenThreadTokenStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtOpenThreadTokenStub(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);
    }

    NTSTATUS NTAPI NtOpenFile_Hook(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                   PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtOpenFile;
            ctx.FunctionName = "NtOpenFile";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(FileHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ObjectAttributes);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(IoStatusBlock);
            ctx.Args[4] = static_cast<std::uint64_t>(ShareAccess);
            ctx.Args[5] = static_cast<std::uint64_t>(OpenOptions);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtOpenFileStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtOpenFileStub(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
    }

    NTSTATUS NTAPI NtQueryInformationProcess_Hook(HANDLE ProcessHandle, ULONG ProcessInformationClass,
                                                  PVOID ProcessInformation, ULONG ProcessInformationLength,
                                                  PULONG ReturnLength)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQueryInformationProcess;
            ctx.FunctionName = "NtQueryInformationProcess";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(ProcessInformationClass);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ProcessInformation);
            ctx.Args[3] = static_cast<std::uint64_t>(ProcessInformationLength);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ReturnLength);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtQueryInformationProcessStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtQueryInformationProcessStub(ProcessHandle, ProcessInformationClass, ProcessInformation,
                                               ProcessInformationLength, ReturnLength);
    }

    NTSTATUS NTAPI NtQueryInformationThread_Hook(HANDLE ThreadHandle, ULONG ThreadInformationClass,
                                                 PVOID ThreadInformation, ULONG ThreadInformationLength,
                                                 PULONG ReturnLength)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQueryInformationThread;
            ctx.FunctionName = "NtQueryInformationThread";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(ThreadInformationClass);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ThreadInformation);
            ctx.Args[3] = static_cast<std::uint64_t>(ThreadInformationLength);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ReturnLength);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtQueryInformationThreadStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtQueryInformationThreadStub(ThreadHandle, ThreadInformationClass, ThreadInformation,
                                              ThreadInformationLength, ReturnLength);
    }

    NTSTATUS NTAPI NtSetContextThread_Hook(HANDLE ThreadHandle, PCONTEXT ThreadContext)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtSetContextThread;
            ctx.FunctionName = "NtSetContextThread";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(ThreadContext);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtSetContextThreadStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtSetContextThreadStub(ThreadHandle, ThreadContext);
    }

    NTSTATUS NTAPI NtQuerySection_Hook(HANDLE SectionHandle, ULONG SectionInformationClass, PVOID InformationBuffer,
                                       ULONG InformationBufferSize, PULONG ResultLength)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQuerySection;
            ctx.FunctionName = "NtQuerySection";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(SectionHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(SectionInformationClass);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(InformationBuffer);
            ctx.Args[3] = static_cast<std::uint64_t>(InformationBufferSize);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ResultLength);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtQuerySectionStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtQuerySectionStub(SectionHandle, SectionInformationClass, InformationBuffer, InformationBufferSize,
                                    ResultLength);
    }

    NTSTATUS NTAPI NtQueryBootOptions_Hook(PVOID BootOptions, PULONG BootOptionsLength)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQueryBootOptions;
            ctx.FunctionName = "NtQueryBootOptions";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(BootOptions);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BootOptionsLength);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtQueryBootOptionsStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtQueryBootOptionsStub(BootOptions, BootOptionsLength);
    }

    NTSTATUS NTAPI NtOpenProcess_Hook(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                      POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            const std::uint64_t targetProcessId =
                (ClientId != nullptr) ? static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(ClientId->UniqueProcess))
                                      : 0ull;
            const std::uint64_t targetThreadId =
                (ClientId != nullptr) ? static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(ClientId->UniqueThread))
                                      : 0ull;
            ctx.Operation = NtOperation::NtOpenProcess;
            ctx.FunctionName = "NtOpenProcess";
            ctx.Caller = _ReturnAddress();
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = targetProcessId;
            ctx.Args[3] = targetThreadId;
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ObjectAttributes);
            g_ActiveNtCallback(ctx);
        }

        if (!g_NtOpenProcessStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtOpenProcessStub(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }

    NTSTATUS NTAPI NtOpenThread_Hook(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                     POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            const std::uint64_t targetProcessId =
                (ClientId != nullptr) ? static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(ClientId->UniqueProcess))
                                      : 0ull;
            const std::uint64_t targetThreadId =
                (ClientId != nullptr) ? static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(ClientId->UniqueThread))
                                      : 0ull;
            ctx.Operation = NtOperation::NtOpenThread;
            ctx.FunctionName = "NtOpenThread";
            ctx.Caller = _ReturnAddress();
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = targetProcessId;
            ctx.Args[3] = targetThreadId;
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ObjectAttributes);
            g_ActiveNtCallback(ctx);
        }

        if (!g_NtOpenThreadStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtOpenThreadStub(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
    }

    NTSTATUS NTAPI NtDuplicateObject_Hook(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle,
                                          PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG Attributes,
                                          ULONG Options)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtDuplicateObject;
            ctx.FunctionName = "NtDuplicateObject";
            ctx.Caller = _ReturnAddress();
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(SourceProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(SourceHandle);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(TargetProcessHandle);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(TargetHandle);
            ctx.Args[4] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[5] = static_cast<std::uint64_t>(Attributes);
            ctx.Args[6] = static_cast<std::uint64_t>(Options);
            g_ActiveNtCallback(ctx);
        }

        if (!g_NtDuplicateObjectStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtDuplicateObjectStub(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle,
                                       DesiredAccess, Attributes, Options);
    }

    NTSTATUS NTAPI NtGetContextThread_Hook(HANDLE ThreadHandle, PCONTEXT ThreadContext)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtGetContextThread;
            ctx.FunctionName = "NtGetContextThread";
            ctx.Caller = _ReturnAddress();
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(ThreadContext);
            g_ActiveNtCallback(ctx);
        }

        if (!g_NtGetContextThreadStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtGetContextThreadStub(ThreadHandle, ThreadContext);
    }

    NTSTATUS NTAPI NtSuspendThread_Hook(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtSuspendThread;
            ctx.FunctionName = "NtSuspendThread";
            ctx.Caller = _ReturnAddress();
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(PreviousSuspendCount);
            g_ActiveNtCallback(ctx);
        }

        if (!g_NtSuspendThreadStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtSuspendThreadStub(ThreadHandle, PreviousSuspendCount);
    }

    NTSTATUS NTAPI NtResumeThread_Hook(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtResumeThread;
            ctx.FunctionName = "NtResumeThread";
            ctx.Caller = _ReturnAddress();
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(PreviousSuspendCount);
            g_ActiveNtCallback(ctx);
        }

        if (!g_NtResumeThreadStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtResumeThreadStub(ThreadHandle, PreviousSuspendCount);
    }

    NTSTATUS NTAPI NtQueueApcThread_Hook(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2,
                                         PVOID ApcArgument3)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQueueApcThread;
            ctx.FunctionName = "NtQueueApcThread";
            ctx.Caller = _ReturnAddress();
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(ApcRoutine);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ApcArgument1);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(ApcArgument2);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ApcArgument3);
            g_ActiveNtCallback(ctx);
        }

        if (!g_NtQueueApcThreadStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtQueueApcThreadStub(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
    }

    NTSTATUS NTAPI NtAllocateVirtualMemoryEx_Hook(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
                                                  PSIZE_T RegionSize, ULONG AllocationType, PVOID ExtendedParameters,
                                                  ULONG ExtendedParameterCount)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtAllocateVirtualMemoryEx;
            ctx.FunctionName = "NtAllocateVirtualMemoryEx";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[2] = static_cast<std::uint64_t>(ZeroBits);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(RegionSize);
            ctx.Args[4] = static_cast<std::uint64_t>(AllocationType);
            ctx.Args[5] = reinterpret_cast<std::uint64_t>(ExtendedParameters);
            ctx.Args[6] = static_cast<std::uint64_t>(ExtendedParameterCount);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtAllocateVirtualMemoryExStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtAllocateVirtualMemoryExStub(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType,
                                               ExtendedParameters, ExtendedParameterCount);
    }

    NTSTATUS NTAPI NtMapViewOfSectionEx_Hook(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
                                             PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG AllocationType,
                                             ULONG Win32Protect, PVOID ExtendedParameters, ULONG ExtendedParameterCount)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtMapViewOfSectionEx;
            ctx.FunctionName = "NtMapViewOfSectionEx";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(SectionHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(SectionOffset);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ViewSize);
            ctx.Args[5] = static_cast<std::uint64_t>(AllocationType);
            ctx.Args[6] = static_cast<std::uint64_t>(Win32Protect);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtMapViewOfSectionExStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtMapViewOfSectionExStub(SectionHandle, ProcessHandle, BaseAddress, SectionOffset, ViewSize,
                                          AllocationType, Win32Protect, ExtendedParameters, ExtendedParameterCount);
    }

    NTSTATUS NTAPI NtQueueApcThreadEx_Hook(HANDLE ThreadHandle, HANDLE UserApcReserveHandle, PVOID ApcRoutine,
                                           PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQueueApcThreadEx;
            ctx.FunctionName = "NtQueueApcThreadEx";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(UserApcReserveHandle);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ApcRoutine);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(ApcArgument1);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ApcArgument2);
            ctx.Args[5] = reinterpret_cast<std::uint64_t>(ApcArgument3);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtQueueApcThreadExStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtQueueApcThreadExStub(ThreadHandle, UserApcReserveHandle, ApcRoutine, ApcArgument1, ApcArgument2,
                                        ApcArgument3);
    }

    NTSTATUS NTAPI NtOpenProcessTokenEx_Hook(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes,
                                             PHANDLE TokenHandle)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtOpenProcessTokenEx;
            ctx.FunctionName = "NtOpenProcessTokenEx";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = static_cast<std::uint64_t>(HandleAttributes);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(TokenHandle);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtOpenProcessTokenExStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtOpenProcessTokenExStub(ProcessHandle, DesiredAccess, HandleAttributes, TokenHandle);
    }

    NTSTATUS NTAPI NtOpenThreadTokenEx_Hook(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf,
                                            ULONG HandleAttributes, PHANDLE TokenHandle)
    {
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtOpenThreadTokenEx;
            ctx.FunctionName = "NtOpenThreadTokenEx";
            ctx.Caller = _ReturnAddress();

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = static_cast<std::uint64_t>(OpenAsSelf);
            ctx.Args[3] = static_cast<std::uint64_t>(HandleAttributes);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(TokenHandle);

            g_ActiveNtCallback(ctx);
        }

        if (!g_NtOpenThreadTokenExStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtOpenThreadTokenExStub(ThreadHandle, DesiredAccess, OpenAsSelf, HandleAttributes, TokenHandle);
    }

    static void *GetHookEntry(const char *name) noexcept
    {
        if (std::strcmp(name, "NtCreateThread") == 0)
            return reinterpret_cast<void *>(&NtCreateThread_Hook);
        if (std::strcmp(name, "NtCreateThreadEx") == 0)
            return reinterpret_cast<void *>(&NtCreateThreadEx_Hook);
        if (std::strcmp(name, "NtWriteVirtualMemory") == 0)
            return reinterpret_cast<void *>(&NtWriteVirtualMemory_Hook);
        if (std::strcmp(name, "NtAllocateVirtualMemory") == 0)
            return reinterpret_cast<void *>(&NtAllocateVirtualMemory_Hook);
        if (std::strcmp(name, "NtProtectVirtualMemory") == 0)
            return reinterpret_cast<void *>(&NtProtectVirtualMemory_Hook);
        if (std::strcmp(name, "NtReadVirtualMemory") == 0)
            return reinterpret_cast<void *>(&NtReadVirtualMemory_Hook);
        if (std::strcmp(name, "NtQueryVirtualMemory") == 0)
            return reinterpret_cast<void *>(&NtQueryVirtualMemory_Hook);
        if (std::strcmp(name, "NtQuerySystemInformation") == 0)
            return reinterpret_cast<void *>(&NtQuerySystemInformation_Hook);
        if (std::strcmp(name, "NtCreateSection") == 0)
            return reinterpret_cast<void *>(&NtCreateSection_Hook);
        if (std::strcmp(name, "NtTerminateProcess") == 0)
            return reinterpret_cast<void *>(&NtTerminateProcess_Hook);
        if (std::strcmp(name, "NtOpenProcessToken") == 0)
            return reinterpret_cast<void *>(&NtOpenProcessToken_Hook);
        if (std::strcmp(name, "NtOpenThreadToken") == 0)
            return reinterpret_cast<void *>(&NtOpenThreadToken_Hook);
        if (std::strcmp(name, "NtOpenFile") == 0)
            return reinterpret_cast<void *>(&NtOpenFile_Hook);
        if (std::strcmp(name, "NtQueryInformationProcess") == 0)
            return reinterpret_cast<void *>(&NtQueryInformationProcess_Hook);
        if (std::strcmp(name, "NtQueryInformationThread") == 0)
            return reinterpret_cast<void *>(&NtQueryInformationThread_Hook);
        if (std::strcmp(name, "NtSetContextThread") == 0)
            return reinterpret_cast<void *>(&NtSetContextThread_Hook);
        if (std::strcmp(name, "NtQuerySection") == 0)
            return reinterpret_cast<void *>(&NtQuerySection_Hook);
        if (std::strcmp(name, "NtQueryBootOptions") == 0)
            return reinterpret_cast<void *>(&NtQueryBootOptions_Hook);
        if (std::strcmp(name, "NtOpenProcess") == 0)
            return reinterpret_cast<void *>(&NtOpenProcess_Hook);
        if (std::strcmp(name, "NtOpenThread") == 0)
            return reinterpret_cast<void *>(&NtOpenThread_Hook);
        if (std::strcmp(name, "NtDuplicateObject") == 0)
            return reinterpret_cast<void *>(&NtDuplicateObject_Hook);
        if (std::strcmp(name, "NtGetContextThread") == 0)
            return reinterpret_cast<void *>(&NtGetContextThread_Hook);
        if (std::strcmp(name, "NtSuspendThread") == 0)
            return reinterpret_cast<void *>(&NtSuspendThread_Hook);
        if (std::strcmp(name, "NtResumeThread") == 0)
            return reinterpret_cast<void *>(&NtResumeThread_Hook);
        if (std::strcmp(name, "NtQueueApcThread") == 0)
            return reinterpret_cast<void *>(&NtQueueApcThread_Hook);
        if (std::strcmp(name, "NtAllocateVirtualMemoryEx") == 0)
            return reinterpret_cast<void *>(&NtAllocateVirtualMemoryEx_Hook);
        if (std::strcmp(name, "NtMapViewOfSectionEx") == 0)
            return reinterpret_cast<void *>(&NtMapViewOfSectionEx_Hook);
        if (std::strcmp(name, "NtQueueApcThreadEx") == 0)
            return reinterpret_cast<void *>(&NtQueueApcThreadEx_Hook);
        if (std::strcmp(name, "NtOpenProcessTokenEx") == 0)
            return reinterpret_cast<void *>(&NtOpenProcessTokenEx_Hook);
        if (std::strcmp(name, "NtOpenThreadTokenEx") == 0)
            return reinterpret_cast<void *>(&NtOpenThreadTokenEx_Hook);
        return nullptr;
    }
} // namespace RYX_NT

#endif

bool KeSetNtHook(NtHookCallback callback) noexcept
{
#ifndef _WIN64
    (void)callback;
    return false;
#else
    using namespace RYX_NT;

    if (!callback)
        return false;

    g_ActiveNtCallback = callback;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return false;

    const bool enableNtMemoryHooks = ShouldEnableNtMemoryHooks();
    bool anyInstalled = false;

    for (auto &hook : g_NtHooks)
    {
        if (!enableNtMemoryHooks && IsNtMemoryHookName(hook.Name))
        {
            continue;
        }

        if (hook.Installed)
        {
            anyInstalled = true;
            continue;
        }

        FARPROC addr = GetProcAddress(ntdll, hook.Name);
        if (!addr)
            continue;

        hook.TargetAddress = reinterpret_cast<void *>(addr);

        std::uint32_t sysIndex = 0;
        if (!ExtractSyscallIndex(hook.TargetAddress, sysIndex))
            continue;

        hook.SyscallIndex = sysIndex;
        void *stubCode = BuildSyscallStub(sysIndex);
        if (!stubCode)
            continue;

        hook.SyscallStubCode = stubCode;
        if (std::strcmp(hook.Name, "NtCreateThread") == 0)
            g_NtCreateThreadStub = reinterpret_cast<NtCreateThread_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtCreateThreadEx") == 0)
            g_NtCreateThreadExStub = reinterpret_cast<NtCreateThreadEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtWriteVirtualMemory") == 0)
            g_NtWriteVirtualMemoryStub = reinterpret_cast<NtWriteVirtualMemory_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtAllocateVirtualMemory") == 0)
            g_NtAllocateVirtualMemoryStub = reinterpret_cast<NtAllocateVirtualMemory_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtProtectVirtualMemory") == 0)
            g_NtProtectVirtualMemoryStub = reinterpret_cast<NtProtectVirtualMemory_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtReadVirtualMemory") == 0)
            g_NtReadVirtualMemoryStub = reinterpret_cast<NtReadVirtualMemory_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQueryVirtualMemory") == 0)
            g_NtQueryVirtualMemoryStub = reinterpret_cast<NtQueryVirtualMemory_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQuerySystemInformation") == 0)
            g_NtQuerySystemInformationStub = reinterpret_cast<NtQuerySystemInformation_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtCreateSection") == 0)
            g_NtCreateSectionStub = reinterpret_cast<NtCreateSection_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtTerminateProcess") == 0)
            g_NtTerminateProcessStub = reinterpret_cast<NtTerminateProcess_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtOpenProcessToken") == 0)
            g_NtOpenProcessTokenStub = reinterpret_cast<NtOpenProcessToken_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtOpenThreadToken") == 0)
            g_NtOpenThreadTokenStub = reinterpret_cast<NtOpenThreadToken_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtOpenFile") == 0)
            g_NtOpenFileStub = reinterpret_cast<NtOpenFile_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQueryInformationProcess") == 0)
            g_NtQueryInformationProcessStub = reinterpret_cast<NtQueryInformationProcess_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQueryInformationThread") == 0)
            g_NtQueryInformationThreadStub = reinterpret_cast<NtQueryInformationThread_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtSetContextThread") == 0)
            g_NtSetContextThreadStub = reinterpret_cast<NtSetContextThread_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQuerySection") == 0)
            g_NtQuerySectionStub = reinterpret_cast<NtQuerySection_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQueryBootOptions") == 0)
            g_NtQueryBootOptionsStub = reinterpret_cast<NtQueryBootOptions_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtOpenProcess") == 0)
            g_NtOpenProcessStub = reinterpret_cast<NtOpenProcess_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtOpenThread") == 0)
            g_NtOpenThreadStub = reinterpret_cast<NtOpenThread_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtDuplicateObject") == 0)
            g_NtDuplicateObjectStub = reinterpret_cast<NtDuplicateObject_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtGetContextThread") == 0)
            g_NtGetContextThreadStub = reinterpret_cast<NtGetContextThread_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtSuspendThread") == 0)
            g_NtSuspendThreadStub = reinterpret_cast<NtSuspendThread_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtResumeThread") == 0)
            g_NtResumeThreadStub = reinterpret_cast<NtResumeThread_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQueueApcThread") == 0)
            g_NtQueueApcThreadStub = reinterpret_cast<NtQueueApcThread_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtAllocateVirtualMemoryEx") == 0)
            g_NtAllocateVirtualMemoryExStub = reinterpret_cast<NtAllocateVirtualMemoryEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtMapViewOfSectionEx") == 0)
            g_NtMapViewOfSectionExStub = reinterpret_cast<NtMapViewOfSectionEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQueueApcThreadEx") == 0)
            g_NtQueueApcThreadExStub = reinterpret_cast<NtQueueApcThreadEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtOpenProcessTokenEx") == 0)
            g_NtOpenProcessTokenExStub = reinterpret_cast<NtOpenProcessTokenEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtOpenThreadTokenEx") == 0)
            g_NtOpenThreadTokenExStub = reinterpret_cast<NtOpenThreadTokenEx_t>(stubCode);

        void *hookEntry = GetHookEntry(hook.Name);
        if (!hookEntry)
            continue;

        if (!InstallInlineHook(hook.TargetAddress, hookEntry, hook.OriginalBytes))
            continue;

        hook.Installed = true;
        anyInstalled = true;
    }

    return anyInstalled;
#endif
}

void KeRemoveNtHook() noexcept
{
#ifdef _WIN64
    using namespace RYX_NT;

    for (auto &hook : g_NtHooks)
    {
        if (!hook.Installed || !hook.TargetAddress)
            continue;

        RemoveInlineHook(hook.TargetAddress, hook.OriginalBytes);
        hook.Installed = false;
    }

    g_ActiveNtCallback = nullptr;
#else
    (void)0;
#endif
}

bool KeCheckNtHookIntegrity(std::uint32_t *mismatchCount) noexcept
{
#ifndef _WIN64
    if (mismatchCount != nullptr)
    {
        *mismatchCount = 0;
    }
    return true;
#else
    using namespace RYX_NT;

    std::uint32_t mismatches = 0;

    for (const auto &hook : g_NtHooks)
    {
        if (!hook.Installed || hook.TargetAddress == nullptr)
        {
            continue;
        }

        const auto *bytes = static_cast<const std::uint8_t *>(hook.TargetAddress);
        void *expectedHook = GetHookEntry(hook.Name);
        if (expectedHook == nullptr)
        {
            ++mismatches;
            continue;
        }

        void *patchedTarget = nullptr;
        std::memcpy(&patchedTarget, &bytes[2], sizeof(patchedTarget));
        bool intact = bytes[0] == 0x48 && bytes[1] == 0xB8 && patchedTarget == expectedHook && bytes[10] == 0xFF &&
                      bytes[11] == 0xE0;
        if (!intact)
        {
            ++mismatches;
        }
    }

    if (mismatchCount != nullptr)
    {
        *mismatchCount = mismatches;
    }

    return mismatches == 0;
#endif
}
