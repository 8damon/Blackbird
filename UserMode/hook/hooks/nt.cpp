#include "nt.h"
#include "runtime_private.h"
#include "../../include/native_peb.h"

#include <atomic>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <intrin.h>
#include <algorithm>
#include <utility>

#pragma intrinsic(_ReturnAddress)

#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

#ifdef _WIN64

namespace BK_NT
{
    static NtHookInitFault g_LastNtHookInitFault{};

    static void ResetNtHookInitFault() noexcept
    {
        std::memset(&g_LastNtHookInitFault, 0, sizeof(g_LastNtHookInitFault));
        g_LastNtHookInitFault.Code = NtHookInitFaultCode::None;
    }

    static void CaptureFaultSample(const void *address, std::uint8_t sample[16]) noexcept
    {
        std::memset(sample, 0, 16);
        if (address == nullptr)
        {
            return;
        }

        __try
        {
            std::memcpy(sample, address, 16);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            std::memset(sample, 0, 16);
        }
    }

    static void SetNtHookInitFault(NtHookInitFaultCode code, const char *functionName, void *address,
                                   void *redirectTarget = nullptr, std::uint32_t syscallIndex = 0) noexcept
    {
        ResetNtHookInitFault();
        g_LastNtHookInitFault.Code = code;
        g_LastNtHookInitFault.FunctionName = functionName;
        g_LastNtHookInitFault.Address = address;
        g_LastNtHookInitFault.RedirectTarget = redirectTarget;
        g_LastNtHookInitFault.SyscallIndex = syscallIndex;
        CaptureFaultSample(address, g_LastNtHookInitFault.Sample);
    }

    static bool ShouldEnableNtMemoryHooks() noexcept
    {
        char value[8]{};
        DWORD read = GetEnvironmentVariableA("BK_NT_HOOK_MEMORY", value, static_cast<DWORD>(RTL_NUMBER_OF(value)));
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
               (std::strcmp(name, "NtMapViewOfSection") == 0) || (std::strcmp(name, "NtMapViewOfSectionEx") == 0);
    }

    typedef struct _CLIENT_ID
    {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    } CLIENT_ID, *PCLIENT_ID;

    using NtCreateThread_t = NTSTATUS(NTAPI *)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                               POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                                               PCLIENT_ID ClientId, PCONTEXT ThreadContext, PBB_INITIAL_TEB InitialTeb,
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

    using NtAllocateVirtualMemoryEx_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
                                                          ULONG AllocationType, ULONG PageProtection,
                                                          PVOID ExtendedParameters, ULONG ExtendedParameterCount);

    using NtMapViewOfSection_t = NTSTATUS(NTAPI *)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
                                                   ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
                                                   PSIZE_T ViewSize, ULONG InheritDisposition, ULONG AllocationType,
                                                   ULONG Win32Protect);

    using NtMapViewOfSectionEx_t = NTSTATUS(NTAPI *)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
                                                     PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize,
                                                     ULONG AllocationType, ULONG Win32Protect, PVOID ExtendedParameters,
                                                     ULONG ExtendedParameterCount);

    using NtUnmapViewOfSection_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PVOID BaseAddress);

    using NtUnmapViewOfSectionEx_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG Flags);

    using NtQueueApcThreadEx_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, HANDLE UserApcReserveHandle, PVOID ApcRoutine,
                                                   PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

    using NtQueueApcThreadEx2_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, HANDLE UserApcReserveHandle,
                                                    ULONG QueueUserApcFlags, PVOID ApcRoutine, PVOID ApcArgument1,
                                                    PVOID ApcArgument2, PVOID ApcArgument3);

    using NtOpenProcessTokenEx_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                                     ULONG HandleAttributes, PHANDLE TokenHandle);

    using NtOpenThreadTokenEx_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf,
                                                    ULONG HandleAttributes, PHANDLE TokenHandle);

    using NtQuerySystemInformationEx_t = NTSTATUS(NTAPI *)(ULONG SystemInformationClass, PVOID InputBuffer,
                                                           ULONG InputBufferLength, PVOID SystemInformation,
                                                           ULONG SystemInformationLength, PULONG ReturnLength);

    static std::uint64_t PointerCodecCookie() noexcept
    {
        static std::uint64_t cookie = 0;
        if (cookie != 0)
        {
            return cookie;
        }

        LARGE_INTEGER counter{};
        (void)QueryPerformanceCounter(&counter);
        std::uint64_t value = static_cast<std::uint64_t>(counter.QuadPart);
        value ^= __rdtsc();
        value ^= reinterpret_cast<std::uintptr_t>(&cookie);
        value ^= static_cast<std::uint64_t>(GetCurrentProcessId()) << 23;
        value ^= static_cast<std::uint64_t>(GetCurrentThreadId()) << 7;
        value = (value << 19) | (value >> 45);
        cookie = value != 0 ? value : 0x71D15A5E5AFE1107ull;
        return cookie;
    }

    template <typename T> struct EncodedProc
    {
        std::uint64_t Encoded = 0;

        EncodedProc() noexcept = default;
        EncodedProc(std::nullptr_t) noexcept
        {
        }

        EncodedProc &operator=(std::nullptr_t) noexcept
        {
            Encoded = 0;
            return *this;
        }

        EncodedProc &operator=(T value) noexcept
        {
            Encoded = value == nullptr ? 0 : (reinterpret_cast<std::uint64_t>(value) ^ PointerCodecCookie());
            return *this;
        }

        T Get() const noexcept
        {
            return Encoded == 0 ? nullptr : reinterpret_cast<T>(Encoded ^ PointerCodecCookie());
        }

        explicit operator bool() const noexcept
        {
            return Get() != nullptr;
        }

        template <typename... Args> auto operator()(Args... args) const noexcept -> decltype(std::declval<T>()(args...))
        {
            T fn = Get();
            return fn(args...);
        }
    };

    // Minimal layout of SYSTEM_THREAD_INFORMATION as documented in ntdll symbols.
    // x64 natural alignment yields 80 bytes; x86 is not supported (KeSetNtHook
    // returns false on x86) so no 32-bit variant is needed.
    struct BkSystemThreadInformation
    {
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER CreateTime;
        ULONG WaitTime;
        ULONG Pad0; // alignment padding before pointer field
        PVOID StartAddress;
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
        LONG Priority;
        LONG BasePriority;
        ULONG ContextSwitches;
        ULONG ThreadState;
        ULONG WaitReason;
        ULONG Pad1;
    };
    static_assert(sizeof(BkSystemThreadInformation) == 80, "BkSystemThreadInformation size mismatch");

    inline constexpr ULONG kSystemProcessInformation = 5u;
    inline constexpr ULONG kSystemHandleInformation = 16u;
    inline constexpr ULONG kSystemKernelDebuggerInformation = 35u;
    inline constexpr ULONG kSystemExtendedHandleInformation = 64u;
    inline constexpr ULONG kSystemBootEnvironmentInformation = 90u;
    inline constexpr ULONG kSystemHypervisorInformation = 91u;
    inline constexpr ULONG kSystemCodeIntegrityInformation = 103u;
    inline constexpr ULONG kSystemKernelVaShadowInformation = 196u;
    inline constexpr ULONG kSystemSpeculationControlInformation = 201u;
    inline constexpr ULONG kCodeIntegrityOptionTestSign = 0x00000002u;
    inline constexpr ULONG kProcessDebugPort = 7u;
    inline constexpr ULONG kProcessDebugObjectHandle = 30u;
    inline constexpr ULONG kProcessDebugFlags = 31u;
    inline constexpr int32_t kMaxConcealedThreads = 16;

    struct BkSystemKernelDebuggerInformation
    {
        BOOLEAN KernelDebuggerEnabled;
        BOOLEAN KernelDebuggerNotPresent;
    };

    struct BkSystemCodeIntegrityInformation
    {
        ULONG Length;
        ULONG CodeIntegrityOptions;
    };

    struct BkSystemHandleTableEntryInfo
    {
        USHORT UniqueProcessId;
        USHORT CreatorBackTraceIndex;
        UCHAR ObjectTypeIndex;
        UCHAR HandleAttributes;
        USHORT HandleValue;
        PVOID Object;
        ULONG GrantedAccess;
    };

    struct BkSystemHandleInformation
    {
        ULONG NumberOfHandles;
        BkSystemHandleTableEntryInfo Handles[1];
    };

    struct BkSystemHandleTableEntryInfoEx
    {
        PVOID Object;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR HandleValue;
        ULONG GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    };

    struct BkSystemHandleInformationEx
    {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
        BkSystemHandleTableEntryInfoEx Handles[1];
    };

    static bool IsCurrentProcessHandle(HANDLE processHandle) noexcept;
    static bool TryReadPointerArgument(PVOID *value, std::uint64_t &outValue) noexcept;
    static bool TryReadSizeArgument(PSIZE_T value, std::uint64_t &outValue) noexcept;
    static void FilterConcealedThreadsInBuffer(PVOID buf, ULONG len) noexcept;
    static void SanitizeSystemHandleInformation(PVOID buffer, ULONG length) noexcept;
    static void SanitizeSystemExtendedHandleInformation(PVOID buffer, ULONG length) noexcept;

    static ULONG EffectiveOutputLength(ULONG requestedLength, PULONG returnLength) noexcept
    {
        if (returnLength == nullptr || *returnLength == 0)
        {
            return requestedLength;
        }

        return (*returnLength < requestedLength) ? *returnLength : requestedLength;
    }

    static void ZeroSystemQueryPayload(PVOID buffer, ULONG bufferLength, PULONG returnLength) noexcept
    {
        if (buffer == nullptr || bufferLength == 0)
        {
            return;
        }

        std::memset(buffer, 0, EffectiveOutputLength(bufferLength, returnLength));
    }

    static void SanitizeSystemInformationResult(ULONG systemInformationClass, PVOID systemInformation,
                                                ULONG systemInformationLength, PULONG returnLength) noexcept
    {
        if (systemInformation == nullptr || systemInformationLength == 0)
        {
            return;
        }

        switch (systemInformationClass)
        {
        case kSystemProcessInformation:
            FilterConcealedThreadsInBuffer(systemInformation, systemInformationLength);
            break;
        case kSystemHandleInformation:
            SanitizeSystemHandleInformation(systemInformation, systemInformationLength);
            break;
        case kSystemExtendedHandleInformation:
            SanitizeSystemExtendedHandleInformation(systemInformation, systemInformationLength);
            break;
        case kSystemKernelDebuggerInformation:
            if (EffectiveOutputLength(systemInformationLength, returnLength) >=
                sizeof(BkSystemKernelDebuggerInformation))
            {
                auto *info = static_cast<BkSystemKernelDebuggerInformation *>(systemInformation);
                info->KernelDebuggerEnabled = FALSE;
                info->KernelDebuggerNotPresent = TRUE;
            }
            break;
        case kSystemCodeIntegrityInformation:
            if (EffectiveOutputLength(systemInformationLength, returnLength) >=
                sizeof(BkSystemCodeIntegrityInformation))
            {
                auto *info = static_cast<BkSystemCodeIntegrityInformation *>(systemInformation);
                info->CodeIntegrityOptions &= ~kCodeIntegrityOptionTestSign;
            }
            break;
        case kSystemHypervisorInformation:
        case kSystemBootEnvironmentInformation:
        case kSystemKernelVaShadowInformation:
        case kSystemSpeculationControlInformation:
            ZeroSystemQueryPayload(systemInformation, systemInformationLength, returnLength);
            break;
        default:
            break;
        }
    }

    static void SanitizeProcessInformationResult(ULONG processInformationClass, PVOID processInformation,
                                                 ULONG processInformationLength, PULONG returnLength) noexcept
    {
        if (processInformation == nullptr || processInformationLength == 0)
        {
            return;
        }

        ULONG effectiveLength = EffectiveOutputLength(processInformationLength, returnLength);
        switch (processInformationClass)
        {
        case kProcessDebugPort:
        case kProcessDebugObjectHandle:
            if (effectiveLength >= sizeof(ULONG_PTR))
            {
                *static_cast<ULONG_PTR *>(processInformation) = 0;
            }
            break;
        case kProcessDebugFlags:
            if (effectiveLength >= sizeof(ULONG))
            {
                *static_cast<ULONG *>(processInformation) = 1u;
            }
            break;
        default:
            break;
        }
    }

    // Acquire-load for count reads, relaxed store + InterlockedIncrement for
    // writes. Array entries are always written before the count is incremented
    // (InterlockedIncrement provides a full barrier), so a reader that sees
    // count == N is guaranteed to see all N entries.
    static std::atomic<int32_t> g_ConcealedTidCount{0};
    static DWORD g_ConcealedTids[kMaxConcealedThreads]{};

    // Cached at first call — PID never changes for the lifetime of the process.
    static HANDLE g_CurrentPid = nullptr;

    static HANDLE GetCurrentPidCached() noexcept
    {
        if (g_CurrentPid == nullptr)
            g_CurrentPid = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(GetCurrentProcessId()));
        return g_CurrentPid;
    }

    static bool IsThreadConcealed(DWORD tid) noexcept
    {
        int32_t count = g_ConcealedTidCount.load(std::memory_order_acquire);
        for (int32_t i = 0; i < count; ++i)
        {
            if (g_ConcealedTids[i] == tid)
                return true;
        }
        return false;
    }

    // Remove concealed threads from a single SYSTEM_PROCESS_INFORMATION entry.
    // Compacts the thread array in-place; zeroes vacated tail slots; updates
    // NumberOfThreads. Does NOT touch NextEntryOffset — process entry positions
    // in the buffer are fixed by the kernel allocation.
    static void FilterConcealedThreadsFromEntry(PSYSTEM_PROCESS_INFORMATION entry, ULONG availableBytes) noexcept
    {
        if (entry == nullptr || entry->NumberOfThreads == 0)
            return;

        // Bounds-check: reject if the claimed thread array exceeds the buffer.
        ULONG threadArrayBytes = entry->NumberOfThreads * static_cast<ULONG>(sizeof(BkSystemThreadInformation));
        if (sizeof(SYSTEM_PROCESS_INFORMATION) + threadArrayBytes > availableBytes)
            return;

        auto *threads = reinterpret_cast<BkSystemThreadInformation *>(entry + 1);
        ULONG src = 0, dst = 0;

        for (; src < entry->NumberOfThreads; ++src)
        {
            DWORD tid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(threads[src].UniqueThread));
            if (IsThreadConcealed(tid))
                continue;
            if (dst != src)
                threads[dst] = threads[src];
            ++dst;
        }

        if (dst < src)
        {
            std::memset(&threads[dst], 0, (src - dst) * sizeof(BkSystemThreadInformation));
            entry->NumberOfThreads = dst;
        }
    }

    // Walk a SystemProcessInformation buffer and filter concealed threads from
    // the entry that matches the current process. Exits as soon as the current
    // process entry is found and filtered — PIDs are unique, no need to scan
    // further. Guards against corrupt/hostile NextEntryOffset values.
    static void FilterConcealedThreadsInBuffer(PVOID buf, ULONG len) noexcept
    {
        if (buf == nullptr || len < sizeof(SYSTEM_PROCESS_INFORMATION))
            return;
        if (g_ConcealedTidCount.load(std::memory_order_relaxed) == 0)
            return;

        const HANDLE currentPid = GetCurrentPidCached();
        auto *entry = static_cast<PSYSTEM_PROCESS_INFORMATION>(buf);
        ULONG offset = 0;

        for (;;)
        {
            if (entry->UniqueProcessId == currentPid)
            {
                FilterConcealedThreadsFromEntry(entry, len - offset);
                break; // PID is unique — no need to keep scanning
            }

            if (entry->NextEntryOffset == 0)
                break;

            // Guard against overflow: reject if NextEntryOffset would push us
            // past the buffer boundary or wrap the offset accumulator.
            if (entry->NextEntryOffset > len - offset)
                break;

            offset += entry->NextEntryOffset;
            if (offset + sizeof(SYSTEM_PROCESS_INFORMATION) > len)
                break;

            entry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(static_cast<BYTE *>(buf) + offset);
        }
    }

    static void SanitizeSystemHandleInformation(PVOID buffer, ULONG length) noexcept
    {
        if (buffer == nullptr || length < sizeof(BkSystemHandleInformation))
            return;

        __try
        {
            auto *info = static_cast<BkSystemHandleInformation *>(buffer);
            ULONG count = info->NumberOfHandles;
            ULONG maxCount =
                (length - FIELD_OFFSET(BkSystemHandleInformation, Handles)) / sizeof(BkSystemHandleTableEntryInfo);
            if (count > maxCount)
                count = maxCount;

            ULONG dst = 0;
            const USHORT currentPid = static_cast<USHORT>(GetCurrentProcessId());
            for (ULONG src = 0; src < count; ++src)
            {
                const auto &entry = info->Handles[src];
                bool hide = entry.UniqueProcessId == currentPid &&
                            BKIPC::IsProtectedIpcHandleValue(static_cast<UINT64>(entry.HandleValue));
                if (hide)
                    continue;
                if (dst != src)
                    info->Handles[dst] = entry;
                ++dst;
            }
            if (dst < count)
            {
                std::memset(&info->Handles[dst], 0, (count - dst) * sizeof(BkSystemHandleTableEntryInfo));
                info->NumberOfHandles = dst;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    static void SanitizeSystemExtendedHandleInformation(PVOID buffer, ULONG length) noexcept
    {
        if (buffer == nullptr || length < sizeof(BkSystemHandleInformationEx))
            return;

        __try
        {
            auto *info = static_cast<BkSystemHandleInformationEx *>(buffer);
            ULONG_PTR count = info->NumberOfHandles;
            ULONG_PTR maxCount =
                (length - FIELD_OFFSET(BkSystemHandleInformationEx, Handles)) / sizeof(BkSystemHandleTableEntryInfoEx);
            if (count > maxCount)
                count = maxCount;

            ULONG_PTR dst = 0;
            const ULONG_PTR currentPid = static_cast<ULONG_PTR>(GetCurrentProcessId());
            for (ULONG_PTR src = 0; src < count; ++src)
            {
                const auto &entry = info->Handles[src];
                bool hide = entry.UniqueProcessId == currentPid &&
                            BKIPC::IsProtectedIpcHandleValue(static_cast<UINT64>(entry.HandleValue));
                if (hide)
                    continue;
                if (dst != src)
                    info->Handles[dst] = entry;
                ++dst;
            }
            if (dst < count)
            {
                std::memset(&info->Handles[dst], 0,
                            static_cast<std::size_t>(count - dst) * sizeof(BkSystemHandleTableEntryInfoEx));
                info->NumberOfHandles = dst;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    static EncodedProc<NtCreateThread_t> g_NtCreateThreadStub;
    static EncodedProc<NtCreateThreadEx_t> g_NtCreateThreadExStub;
    static EncodedProc<NtWriteVirtualMemory_t> g_NtWriteVirtualMemoryStub;
    static EncodedProc<NtAllocateVirtualMemory_t> g_NtAllocateVirtualMemoryStub;
    static EncodedProc<NtProtectVirtualMemory_t> g_NtProtectVirtualMemoryStub;
    static EncodedProc<NtReadVirtualMemory_t> g_NtReadVirtualMemoryStub;
    static EncodedProc<NtQueryVirtualMemory_t> g_NtQueryVirtualMemoryStub;
    static EncodedProc<NtQuerySystemInformation_t> g_NtQuerySystemInformationStub;
    static EncodedProc<NtCreateSection_t> g_NtCreateSectionStub;
    static EncodedProc<NtTerminateProcess_t> g_NtTerminateProcessStub;
    static EncodedProc<NtOpenProcessToken_t> g_NtOpenProcessTokenStub;
    static EncodedProc<NtOpenThreadToken_t> g_NtOpenThreadTokenStub;
    static EncodedProc<NtOpenFile_t> g_NtOpenFileStub;
    static EncodedProc<NtQueryInformationProcess_t> g_NtQueryInformationProcessStub;
    static EncodedProc<NtQueryInformationThread_t> g_NtQueryInformationThreadStub;
    static EncodedProc<NtSetContextThread_t> g_NtSetContextThreadStub;
    static EncodedProc<NtQuerySection_t> g_NtQuerySectionStub;
    static EncodedProc<NtQueryBootOptions_t> g_NtQueryBootOptionsStub;
    static EncodedProc<NtOpenProcess_t> g_NtOpenProcessStub;
    static EncodedProc<NtOpenThread_t> g_NtOpenThreadStub;
    static EncodedProc<NtDuplicateObject_t> g_NtDuplicateObjectStub;
    static EncodedProc<NtGetContextThread_t> g_NtGetContextThreadStub;
    static EncodedProc<NtSuspendThread_t> g_NtSuspendThreadStub;
    static EncodedProc<NtResumeThread_t> g_NtResumeThreadStub;
    static EncodedProc<NtQueueApcThread_t> g_NtQueueApcThreadStub;
    static EncodedProc<NtAllocateVirtualMemoryEx_t> g_NtAllocateVirtualMemoryExStub;
    static EncodedProc<NtMapViewOfSection_t> g_NtMapViewOfSectionStub;
    static EncodedProc<NtMapViewOfSectionEx_t> g_NtMapViewOfSectionExStub;
    static EncodedProc<NtUnmapViewOfSection_t> g_NtUnmapViewOfSectionStub;
    static EncodedProc<NtUnmapViewOfSectionEx_t> g_NtUnmapViewOfSectionExStub;
    static EncodedProc<NtQueueApcThreadEx_t> g_NtQueueApcThreadExStub;
    static EncodedProc<NtQueueApcThreadEx2_t> g_NtQueueApcThreadEx2Stub;
    static EncodedProc<NtOpenProcessTokenEx_t> g_NtOpenProcessTokenExStub;
    static EncodedProc<NtOpenThreadTokenEx_t> g_NtOpenThreadTokenExStub;
    static EncodedProc<NtQuerySystemInformationEx_t> g_NtQuerySystemInformationExStub;

    using NtGetNextThread_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                                ULONG HandleAttributes, ULONG Flags, PHANDLE NewThreadHandle);
    static EncodedProc<NtGetNextThread_t> g_NtGetNextThreadStub;

    // Minimal THREAD_BASIC_INFORMATION — only fields needed to extract the TID.
    struct BkThreadBasicInformation
    {
        NTSTATUS ExitStatus;
        ULONG Pad; // x64 alignment before pointer
        PVOID TebBaseAddress;
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
        ULONG_PTR AffinityMask;
        LONG Priority;
        LONG BasePriority;
    };

    static DWORD GetThreadTid(HANDLE threadHandle) noexcept
    {
        if (!g_NtQueryInformationThreadStub || threadHandle == NULL)
            return 0;
        BkThreadBasicInformation info{};
        ULONG retLen = 0;
        NTSTATUS st = g_NtQueryInformationThreadStub(threadHandle, 0, &info, static_cast<ULONG>(sizeof(info)), &retLen);
        if (!NT_SUCCESS(st))
            return 0;
        return static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(info.UniqueThread));
    }

    static DWORD GetProcessPid(HANDLE processHandle) noexcept
    {
        if (IsCurrentProcessHandle(processHandle))
        {
            return GetCurrentProcessId();
        }

        return (processHandle != NULL) ? GetProcessId(processHandle) : 0;
    }

    static bool IsCurrentProcessQuery(HANDLE processHandle) noexcept
    {
        DWORD pid = GetProcessPid(processHandle);
        return pid != 0 && pid == GetCurrentProcessId();
    }

    static bool TryReadThreadIdentity(HANDLE threadHandle, DWORD &processId, DWORD &threadId) noexcept
    {
        processId = 0;
        threadId = 0;
        if (!g_NtQueryInformationThreadStub || threadHandle == NULL)
        {
            return false;
        }

        BkThreadBasicInformation info{};
        ULONG retLen = 0;
        NTSTATUS st = g_NtQueryInformationThreadStub(threadHandle, 0, &info, static_cast<ULONG>(sizeof(info)), &retLen);
        if (!NT_SUCCESS(st))
        {
            return false;
        }

        processId = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(info.UniqueProcess));
        threadId = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(info.UniqueThread));
        return (processId != 0 || threadId != 0);
    }

    struct NtTargetHook
    {
        const char *Name;
        NtOperation Operation;
        BK_RUNTIME_INTERNAL::Sr71IhrToken TargetToken;
        BK_RUNTIME_INTERNAL::Sr71IhrToken SyscallStubToken;
        std::uint32_t SyscallIndex;
        std::uint8_t OriginalBytes[16];
        std::uint8_t CloakBytes[16];
        bool Installed;
    };

    static NtHookCallback g_ActiveNtCallback = nullptr;

    struct ModuleRange
    {
        std::uintptr_t Base;
        std::uintptr_t End;
    };

    static bool TryResolveModuleImageRange(HMODULE module, ModuleRange &range) noexcept
    {
        auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(module);
        if (module == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }

        auto *nt =
            reinterpret_cast<const IMAGE_NT_HEADERS *>(reinterpret_cast<const std::uint8_t *>(module) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.SizeOfImage == 0)
        {
            return false;
        }

        range.Base = reinterpret_cast<std::uintptr_t>(module);
        range.End = range.Base + nt->OptionalHeader.SizeOfImage;
        return true;
    }

    static bool HasExportDirectory(HMODULE module) noexcept
    {
        auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(module);
        if (module == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }

        auto *nt =
            reinterpret_cast<const IMAGE_NT_HEADERS *>(reinterpret_cast<const std::uint8_t *>(module) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        {
            return false;
        }

        const auto &entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        return entry.VirtualAddress != 0 && entry.Size >= sizeof(IMAGE_EXPORT_DIRECTORY);
    }

    static bool AddressWithinRange(void *address, const ModuleRange &range) noexcept
    {
        std::uintptr_t value = reinterpret_cast<std::uintptr_t>(address);
        return value >= range.Base && value < range.End;
    }

    static void *ResolveNtHookToken(BK_RUNTIME_INTERNAL::Sr71IhrToken token,
                                    BK_RUNTIME_INTERNAL::Sr71IhrType type) noexcept
    {
        BK_RUNTIME_INTERNAL::Sr71IhrResolved resolved{};
        if (!BK_RUNTIME_INTERNAL::ResolveIndirectHandle(token, type, resolved))
        {
            return nullptr;
        }
        return resolved.Pointer;
    }

    static void *ResolveNtHookTarget(const NtTargetHook &hook) noexcept
    {
        return ResolveNtHookToken(hook.TargetToken, BK_RUNTIME_INTERNAL::Sr71IhrType::NtHookTarget);
    }

    static void *ResolveNtHookStub(const NtTargetHook &hook) noexcept
    {
        return ResolveNtHookToken(hook.SyscallStubToken, BK_RUNTIME_INTERNAL::Sr71IhrType::NtSyscallStub);
    }

    static BK_RUNTIME_INTERNAL::Sr71IhrToken RegisterNtHookPointer(void *pointer, BK_RUNTIME_INTERNAL::Sr71IhrType type,
                                                                   const char *tag, std::uint32_t flags = 0) noexcept
    {
        return BK_RUNTIME_INTERNAL::RegisterIndirectHandle(pointer, 16u, type, flags, tag);
    }

    static bool TryDecodeAbsoluteTarget(void *entry, void *&target) noexcept
    {
        target = nullptr;
        if (entry == nullptr)
        {
            return false;
        }

        auto *bytes = static_cast<std::uint8_t *>(entry);
        __try
        {
            if (bytes[0] == 0xE9)
            {
                std::int32_t rel = *reinterpret_cast<std::int32_t *>(&bytes[1]);
                target = bytes + 5 + rel;
                return true;
            }

            if (bytes[0] == 0xFF && bytes[1] == 0x25)
            {
                std::int32_t disp = *reinterpret_cast<std::int32_t *>(&bytes[2]);
                auto **slot = reinterpret_cast<void **>(bytes + 6 + disp);
                target = *slot;
                return true;
            }

            if (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0)
            {
                target = *reinterpret_cast<void **>(&bytes[2]);
                return true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            target = nullptr;
            return false;
        }

        return false;
    }

    static NtTargetHook g_NtHooks[] = {
        {"NtCreateThread", NtOperation::NtCreateThread, 0, 0, 0u, {}, false},
        {"NtCreateThreadEx", NtOperation::NtCreateThreadEx, 0, 0, 0u, {}, false},
        {"NtWriteVirtualMemory", NtOperation::NtWriteVirtualMemory, 0, 0, 0u, {}, false},
        {"NtAllocateVirtualMemory", NtOperation::NtAllocateVirtualMemory, 0, 0, 0u, {}, false},
        {"NtProtectVirtualMemory", NtOperation::NtProtectVirtualMemory, 0, 0, 0u, {}, false},
        {"NtReadVirtualMemory", NtOperation::NtReadVirtualMemory, 0, 0, 0u, {}, false},
        {"NtQueryVirtualMemory", NtOperation::NtQueryVirtualMemory, 0, 0, 0u, {}, false},
        {"NtQuerySystemInformation", NtOperation::NtQuerySystemInformation, 0, 0, 0u, {}, false},
        {"NtCreateSection", NtOperation::NtCreateSection, 0, 0, 0u, {}, false},
        {"NtTerminateProcess", NtOperation::NtTerminateProcess, 0, 0, 0u, {}, false},
        {"NtOpenProcessToken", NtOperation::NtOpenProcessToken, 0, 0, 0u, {}, false},
        {"NtOpenThreadToken", NtOperation::NtOpenThreadToken, 0, 0, 0u, {}, false},
        {"NtOpenFile", NtOperation::NtOpenFile, 0, 0, 0u, {}, false},
        {"NtQueryInformationProcess", NtOperation::NtQueryInformationProcess, 0, 0, 0u, {}, false},
        {"NtQueryInformationThread", NtOperation::NtQueryInformationThread, 0, 0, 0u, {}, false},
        {"NtSetContextThread", NtOperation::NtSetContextThread, 0, 0, 0u, {}, false},
        {"NtQuerySection", NtOperation::NtQuerySection, 0, 0, 0u, {}, false},
        {"NtQueryBootOptions", NtOperation::NtQueryBootOptions, 0, 0, 0u, {}, false},
        {"NtOpenProcess", NtOperation::NtOpenProcess, 0, 0, 0u, {}, false},
        {"NtOpenThread", NtOperation::NtOpenThread, 0, 0, 0u, {}, false},
        {"NtDuplicateObject", NtOperation::NtDuplicateObject, 0, 0, 0u, {}, false},
        {"NtGetContextThread", NtOperation::NtGetContextThread, 0, 0, 0u, {}, false},
        {"NtSuspendThread", NtOperation::NtSuspendThread, 0, 0, 0u, {}, false},
        {"NtResumeThread", NtOperation::NtResumeThread, 0, 0, 0u, {}, false},
        {"NtQueueApcThread", NtOperation::NtQueueApcThread, 0, 0, 0u, {}, false},
        {"NtAllocateVirtualMemoryEx", NtOperation::NtAllocateVirtualMemoryEx, 0, 0, 0u, {}, false},
        {"NtMapViewOfSection", NtOperation::NtMapViewOfSection, 0, 0, 0u, {}, false},
        {"NtMapViewOfSectionEx", NtOperation::NtMapViewOfSectionEx, 0, 0, 0u, {}, false},
        {"NtUnmapViewOfSection", NtOperation::NtUnmapViewOfSection, 0, 0, 0u, {}, false},
        {"NtUnmapViewOfSectionEx", NtOperation::NtUnmapViewOfSectionEx, 0, 0, 0u, {}, false},
        {"NtQueueApcThreadEx", NtOperation::NtQueueApcThreadEx, 0, 0, 0u, {}, false},
        {"NtQueueApcThreadEx2", NtOperation::NtQueueApcThreadEx2, 0, 0, 0u, {}, false},
        {"NtOpenProcessTokenEx", NtOperation::NtOpenProcessTokenEx, 0, 0, 0u, {}, false},
        {"NtOpenThreadTokenEx", NtOperation::NtOpenThreadTokenEx, 0, 0, 0u, {}, false},
        {"NtQuerySystemInformationEx", NtOperation::NtQuerySystemInformationEx, 0, 0, 0u, {}, false},
        {"NtGetNextThread", NtOperation::NtGetNextThread, 0, 0, 0u, {}, false},
    };

    static std::uint32_t HookWalkSeed() noexcept
    {
        LARGE_INTEGER counter{};
        (void)QueryPerformanceCounter(&counter);
        std::uint64_t value = static_cast<std::uint64_t>(counter.QuadPart);
        value ^= __rdtsc();
        value ^= static_cast<std::uint64_t>(GetCurrentProcessId()) << 17;
        value ^= static_cast<std::uint64_t>(GetCurrentThreadId()) << 3;
        value ^= reinterpret_cast<std::uintptr_t>(&value);
        value ^= value >> 32;
        std::uint32_t seed = static_cast<std::uint32_t>(value);
        return seed != 0 ? seed : 0x71C0FFEEu;
    }

    static std::uint32_t NextHookWalkValue(std::uint32_t &state) noexcept
    {
        state = (state * 1664525u) + 1013904223u;
        return state;
    }

    static void BuildHookWalkOrder(std::uint8_t *order, std::size_t count) noexcept
    {
        if (order == nullptr || count == 0)
        {
            return;
        }

        for (std::size_t i = 0; i < count; ++i)
        {
            order[i] = static_cast<std::uint8_t>(i);
        }

        std::uint32_t state = HookWalkSeed();
        for (std::size_t i = count - 1; i > 0; --i)
        {
            std::size_t j = NextHookWalkValue(state) % (i + 1);
            std::uint8_t tmp = order[i];
            order[i] = order[j];
            order[j] = tmp;
        }
    }

    static bool RangeOverlaps(std::uintptr_t leftBase, std::size_t leftSize, std::uintptr_t rightBase,
                              std::uintptr_t rightEnd) noexcept
    {
        if (leftBase == 0 || leftSize == 0 || rightBase >= rightEnd)
        {
            return false;
        }

        std::uintptr_t leftEnd = leftBase + leftSize;
        if (leftEnd <= leftBase)
        {
            leftEnd = UINTPTR_MAX;
        }

        return leftBase < rightEnd && rightBase < leftEnd;
    }

    static bool ReadRangeTouchesSr71Image(std::uintptr_t base, std::size_t size) noexcept
    {
        HMODULE sr71 = nullptr;
        MEMORY_BASIC_INFORMATION selfMbi{};
        if (VirtualQuery(reinterpret_cast<const void *>(&ReadRangeTouchesSr71Image), &selfMbi, sizeof(selfMbi)) ==
            sizeof(selfMbi))
        {
            sr71 = static_cast<HMODULE>(selfMbi.AllocationBase);
        }
        if (sr71 == nullptr)
        {
            sr71 = GetModuleHandleW(L"SR71.dll");
        }
        ModuleRange image{};
        return sr71 != nullptr && TryResolveModuleImageRange(sr71, image) &&
               RangeOverlaps(base, size, image.Base, image.End);
    }

    static bool ReadRangeTouchesNtHookStub(std::uintptr_t base, std::size_t size) noexcept
    {
        for (const auto &hook : g_NtHooks)
        {
            void *stubCode = ResolveNtHookStub(hook);
            if (stubCode == nullptr)
            {
                continue;
            }

            std::uintptr_t stubBase = reinterpret_cast<std::uintptr_t>(stubCode);
            if (RangeOverlaps(base, size, stubBase, stubBase + 16u))
            {
                return true;
            }
        }

        return false;
    }

    static bool RangeTouchesNtHookPatch(std::uintptr_t base, std::size_t size) noexcept
    {
        for (const auto &hook : g_NtHooks)
        {
            void *target = ResolveNtHookTarget(hook);
            if (!hook.Installed || target == nullptr)
            {
                continue;
            }

            std::uintptr_t patchBase = reinterpret_cast<std::uintptr_t>(target);
            if (RangeOverlaps(base, size, patchBase, patchBase + sizeof(hook.OriginalBytes)))
            {
                return true;
            }
        }

        return false;
    }

    static bool RangeTouchesAuxiliaryHookPatch(std::uintptr_t base, std::size_t size) noexcept
    {
        constexpr std::size_t kMaxWinsockPatches = 640;
        WinsockHookPatchInfo winsockPatches[kMaxWinsockPatches]{};
        std::size_t winsockCount = KeCollectWinsockHookPatchInfos(winsockPatches, kMaxWinsockPatches);
        for (std::size_t i = 0; i < winsockCount; ++i)
        {
            std::uintptr_t patchBase = reinterpret_cast<std::uintptr_t>(winsockPatches[i].PatchAddress);
            if (RangeOverlaps(base, size, patchBase, patchBase + winsockPatches[i].PatchSize))
            {
                return true;
            }
        }

        constexpr std::size_t kMaxKiPatches = 4;
        KiHookPatchInfo kiPatches[kMaxKiPatches]{};
        std::size_t kiCount = KeCollectKiHookPatchInfos(kiPatches, kMaxKiPatches);
        for (std::size_t i = 0; i < kiCount; ++i)
        {
            std::uintptr_t patchBase = reinterpret_cast<std::uintptr_t>(kiPatches[i].PatchAddress);
            if (RangeOverlaps(base, size, patchBase, patchBase + kiPatches[i].PatchSize))
            {
                return true;
            }
        }

        constexpr std::size_t kMaxModulePatches = 64;
        ModuleHookPatchInfo modulePatches[kMaxModulePatches]{};
        std::size_t moduleCount = KeCollectModuleHookPatchInfos(modulePatches, kMaxModulePatches);
        for (std::size_t i = 0; i < moduleCount; ++i)
        {
            std::uintptr_t patchBase = reinterpret_cast<std::uintptr_t>(modulePatches[i].PatchAddress);
            if (RangeOverlaps(base, size, patchBase, patchBase + modulePatches[i].PatchSize))
            {
                return true;
            }
        }

        return false;
    }

    static bool RangeTouchesSr71ProtectedMemory(std::uintptr_t base, std::size_t size) noexcept
    {
        return ReadRangeTouchesSr71Image(base, size) || ReadRangeTouchesNtHookStub(base, size) ||
               RangeTouchesNtHookPatch(base, size) || RangeTouchesAuxiliaryHookPatch(base, size);
    }

    static bool ShouldDenySr71Write(HANDLE processHandle, PVOID baseAddress, SIZE_T size) noexcept
    {
        if (BkSr71IsInternalCall() || !IsCurrentProcessHandle(processHandle) || baseAddress == nullptr || size == 0)
        {
            return false;
        }

        return RangeTouchesSr71ProtectedMemory(reinterpret_cast<std::uintptr_t>(baseAddress), size);
    }

    static bool ShouldDenySr71ProtectWrite(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize,
                                           ULONG newProtect) noexcept
    {
        if (BkSr71IsInternalCall() || !IsCurrentProcessHandle(processHandle) || baseAddress == nullptr ||
            regionSize == nullptr)
        {
            return false;
        }

        ULONG baseProtect = newProtect & 0xFFu;
        bool enablesWrite = baseProtect == PAGE_READWRITE || baseProtect == PAGE_WRITECOPY ||
                            baseProtect == PAGE_EXECUTE_READWRITE || baseProtect == PAGE_EXECUTE_WRITECOPY;
        if (!enablesWrite)
        {
            return false;
        }

        std::uint64_t targetBaseValue = 0;
        std::uint64_t targetSizeValue = 0;
        if (!TryReadPointerArgument(baseAddress, targetBaseValue) || !TryReadSizeArgument(regionSize, targetSizeValue))
        {
            return false;
        }

        return targetBaseValue != 0 && targetSizeValue != 0 &&
               RangeTouchesSr71ProtectedMemory(static_cast<std::uintptr_t>(targetBaseValue),
                                               static_cast<std::size_t>(targetSizeValue));
    }

    static bool ShouldDenySr71Read(HANDLE processHandle, PVOID baseAddress, SIZE_T bufferSize) noexcept
    {
        if (BkSr71IsInternalCall() || !IsCurrentProcessHandle(processHandle) || baseAddress == nullptr ||
            bufferSize == 0)
        {
            return false;
        }

        std::uintptr_t base = reinterpret_cast<std::uintptr_t>(baseAddress);
        return RangeTouchesSr71ProtectedMemory(base, bufferSize);
    }

    static bool OverlayOriginalPatchBytes(std::uintptr_t readBase, SIZE_T bytesRead, PVOID outputBuffer,
                                          std::uintptr_t patchBase, std::size_t patchSize,
                                          const std::uint8_t originalBytes[16]) noexcept
    {
        if (!RangeOverlaps(readBase, bytesRead, patchBase, patchBase + patchSize))
        {
            return false;
        }

        std::uintptr_t readEnd = readBase + bytesRead;
        if (readEnd <= readBase)
        {
            readEnd = UINTPTR_MAX;
        }

        std::uintptr_t copyStart = (readBase > patchBase) ? readBase : patchBase;
        std::uintptr_t copyEnd = (readEnd < patchBase + patchSize) ? readEnd : patchBase + patchSize;
        std::size_t sourceOffset = static_cast<std::size_t>(copyStart - patchBase);
        std::size_t destOffset = static_cast<std::size_t>(copyStart - readBase);
        std::size_t copySize = static_cast<std::size_t>(copyEnd - copyStart);
        if (sourceOffset + copySize > 16)
        {
            return false;
        }

        __try
        {
            std::memcpy(static_cast<std::uint8_t *>(outputBuffer) + destOffset, originalBytes + sourceOffset, copySize);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    static bool OverlayNtHookOriginalBytes(std::uintptr_t readBase, SIZE_T bytesRead, PVOID outputBuffer) noexcept
    {
        if (readBase == 0 || bytesRead == 0 || outputBuffer == nullptr)
        {
            return false;
        }

        bool overlaid = false;
        std::uintptr_t readEnd = readBase + bytesRead;
        if (readEnd <= readBase)
        {
            readEnd = UINTPTR_MAX;
        }

        for (const auto &hook : g_NtHooks)
        {
            void *target = ResolveNtHookTarget(hook);
            if (!hook.Installed || target == nullptr)
            {
                continue;
            }

            std::uintptr_t patchBase = reinterpret_cast<std::uintptr_t>(target);
            std::uintptr_t patchEnd = patchBase + sizeof(hook.OriginalBytes);
            if (!RangeOverlaps(readBase, bytesRead, patchBase, patchEnd))
            {
                continue;
            }

            (void)patchEnd;
            if (OverlayOriginalPatchBytes(readBase, bytesRead, outputBuffer, patchBase, sizeof(hook.CloakBytes),
                                          hook.CloakBytes))
            {
                overlaid = true;
            }
        }

        constexpr std::size_t kMaxWinsockPatches = 640;
        WinsockHookPatchInfo winsockPatches[kMaxWinsockPatches]{};
        std::size_t winsockCount = KeCollectWinsockHookPatchInfos(winsockPatches, kMaxWinsockPatches);
        for (std::size_t i = 0; i < winsockCount; ++i)
        {
            std::uintptr_t patchBase = reinterpret_cast<std::uintptr_t>(winsockPatches[i].PatchAddress);
            if (OverlayOriginalPatchBytes(readBase, bytesRead, outputBuffer, patchBase, winsockPatches[i].PatchSize,
                                          winsockPatches[i].OriginalBytes))
            {
                overlaid = true;
            }
        }

        constexpr std::size_t kMaxKiPatches = 4;
        KiHookPatchInfo kiPatches[kMaxKiPatches]{};
        std::size_t kiCount = KeCollectKiHookPatchInfos(kiPatches, kMaxKiPatches);
        for (std::size_t i = 0; i < kiCount; ++i)
        {
            std::uintptr_t patchBase = reinterpret_cast<std::uintptr_t>(kiPatches[i].PatchAddress);
            if (OverlayOriginalPatchBytes(readBase, bytesRead, outputBuffer, patchBase, kiPatches[i].PatchSize,
                                          kiPatches[i].OriginalBytes))
            {
                overlaid = true;
            }
        }

        constexpr std::size_t kMaxModulePatches = 64;
        ModuleHookPatchInfo modulePatches[kMaxModulePatches]{};
        std::size_t moduleCount = KeCollectModuleHookPatchInfos(modulePatches, kMaxModulePatches);
        for (std::size_t i = 0; i < moduleCount; ++i)
        {
            std::uintptr_t patchBase = reinterpret_cast<std::uintptr_t>(modulePatches[i].PatchAddress);
            if (OverlayOriginalPatchBytes(readBase, bytesRead, outputBuffer, patchBase, modulePatches[i].PatchSize,
                                          modulePatches[i].OriginalBytes))
            {
                overlaid = true;
            }
        }
        return overlaid;
    }

    static void SetSizeTValue(PSIZE_T destination, SIZE_T value) noexcept
    {
        if (destination == nullptr)
        {
            return;
        }

        __try
        {
            *destination = value;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    static void ApplyNtHookCloakWrite(std::uintptr_t writeBase, SIZE_T writeSize, const void *sourceBuffer) noexcept
    {
        if (writeBase == 0 || writeSize == 0 || sourceBuffer == nullptr)
        {
            return;
        }

        std::uintptr_t writeEnd = writeBase + writeSize;
        if (writeEnd <= writeBase)
        {
            writeEnd = UINTPTR_MAX;
        }

        for (auto &hook : g_NtHooks)
        {
            void *target = ResolveNtHookTarget(hook);
            if (!hook.Installed || target == nullptr)
            {
                continue;
            }

            std::uintptr_t patchBase = reinterpret_cast<std::uintptr_t>(target);
            std::uintptr_t patchEnd = patchBase + sizeof(hook.CloakBytes);
            if (!RangeOverlaps(writeBase, writeSize, patchBase, patchEnd))
            {
                continue;
            }

            std::uintptr_t copyStart = (writeBase > patchBase) ? writeBase : patchBase;
            std::uintptr_t copyEnd = (writeEnd < patchEnd) ? writeEnd : patchEnd;
            std::size_t sourceOffset = static_cast<std::size_t>(copyStart - writeBase);
            std::size_t cloakOffset = static_cast<std::size_t>(copyStart - patchBase);
            std::size_t copySize = static_cast<std::size_t>(copyEnd - copyStart);
            if (cloakOffset + copySize > sizeof(hook.CloakBytes))
            {
                continue;
            }

            __try
            {
                std::memcpy(hook.CloakBytes + cloakOffset,
                            static_cast<const std::uint8_t *>(sourceBuffer) + sourceOffset, copySize);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
        }
    }

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

    static bool TryResolveModuleTextRange(HMODULE module, ModuleRange &range) noexcept
    {
        auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(module);
        if (module == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }

        auto *nt =
            reinterpret_cast<const IMAGE_NT_HEADERS *>(reinterpret_cast<const std::uint8_t *>(module) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
        {
            return false;
        }

        auto *section = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
        {
            char name[9]{};
            std::memcpy(name, section->Name, std::min<std::size_t>(sizeof(section->Name), 8));
            if (std::strcmp(name, ".text") != 0)
            {
                continue;
            }

            std::size_t size = std::max<std::size_t>(section->Misc.VirtualSize, section->SizeOfRawData);
            if (size == 0)
            {
                return false;
            }

            range.Base = reinterpret_cast<std::uintptr_t>(module) + section->VirtualAddress;
            range.End = range.Base + size;
            return true;
        }

        return false;
    }

    static bool IsCurrentProcessHandle(HANDLE processHandle) noexcept
    {
        if (processHandle == nullptr || processHandle == reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1)) ||
            processHandle == GetCurrentProcess())
        {
            return true;
        }

        DWORD pid = GetProcessId(processHandle);
        return pid != 0 && pid == GetCurrentProcessId();
    }

    static bool ContainsSyscallSequence(const std::uint8_t *bytes, std::size_t size) noexcept
    {
        if (bytes == nullptr || size < 2)
        {
            return false;
        }

        for (std::size_t i = 0; i + 1 < size; ++i)
        {
            if (bytes[i] == 0x0F && bytes[i + 1] == 0x05)
            {
                return true;
            }

            if (i + 9 < size && bytes[i] == 0x4C && bytes[i + 1] == 0x8B && bytes[i + 2] == 0xD1 &&
                bytes[i + 3] == 0xB8 && bytes[i + 8] == 0x0F && bytes[i + 9] == 0x05)
            {
                return true;
            }
        }

        return false;
    }

    static void TryAnnotateProtectTarget(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize,
                                         NtHookContext &ctx) noexcept
    {
        UNREFERENCED_PARAMETER(regionSize);

        if (!IsCurrentProcessHandle(processHandle) || baseAddress == nullptr || *baseAddress == nullptr)
        {
            return;
        }

        auto *page = static_cast<const std::uint8_t *>(*baseAddress);
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(page, &mbi, sizeof(mbi)) == 0)
        {
            return;
        }

        std::size_t readable = std::min<std::size_t>(sizeof(ctx.DataSample), mbi.RegionSize);
        if (readable == 0)
        {
            return;
        }

        __try
        {
            std::memcpy(ctx.DataSample, page, readable);
            ctx.DataSize = static_cast<std::uint32_t>(readable);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ctx.DataSize = 0;
            return;
        }

        ctx.Args[6] = reinterpret_cast<std::uint64_t>(*baseAddress);
        if (!ContainsSyscallSequence(ctx.DataSample, ctx.DataSize))
        {
            return;
        }

        ModuleRange ntdllText{};
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!TryResolveModuleTextRange(ntdll, ntdllText))
        {
            return;
        }

        std::uintptr_t address = reinterpret_cast<std::uintptr_t>(*baseAddress);
        if (address < ntdllText.Base || address >= ntdllText.End)
        {
            ctx.Args[5] = 1;
        }
    }

    static inline void PublishNtEventIfSuccessful(NtHookContext &ctx, NTSTATUS status) noexcept
    {
        if (!g_ActiveNtCallback || status != STATUS_SUCCESS)
        {
            return;
        }

        ctx.Status = status;
        __try
        {
            (void)IC_STACKTRACE::Capture(ctx.Stack, 1);
            g_ActiveNtCallback(ctx);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    static inline void PublishNtEventAlways(NtHookContext &ctx, NTSTATUS status) noexcept
    {
        if (!g_ActiveNtCallback)
        {
            return;
        }

        ctx.Status = status;
        __try
        {
            (void)IC_STACKTRACE::Capture(ctx.Stack, 1);
            g_ActiveNtCallback(ctx);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    static bool TryReadPointerArgument(PVOID *value, std::uint64_t &outValue) noexcept
    {
        outValue = 0;
        if (value == nullptr)
        {
            return false;
        }

        __try
        {
            outValue = reinterpret_cast<std::uint64_t>(*value);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            outValue = 0;
            return false;
        }
    }

    static bool TryReadSizeArgument(PSIZE_T value, std::uint64_t &outValue) noexcept
    {
        outValue = 0;
        if (value == nullptr)
        {
            return false;
        }

        __try
        {
            outValue = static_cast<std::uint64_t>(*value);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            outValue = 0;
            return false;
        }
    }

    static bool TryReadUlongArgument(PULONG value, std::uint64_t &outValue) noexcept
    {
        outValue = 0;
        if (value == nullptr)
        {
            return false;
        }

        __try
        {
            outValue = static_cast<std::uint64_t>(*value);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            outValue = 0;
            return false;
        }
    }

    static bool TryReadClientIdArgument(PCLIENT_ID value, std::uint64_t &processId, std::uint64_t &threadId) noexcept
    {
        processId = 0;
        threadId = 0;
        if (value == nullptr)
        {
            return false;
        }

        __try
        {
            processId = static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(value->UniqueProcess));
            threadId = static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(value->UniqueThread));
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            processId = 0;
            threadId = 0;
            return false;
        }
    }

    static bool TryReadContextArgument(PCONTEXT value, std::uint64_t &instructionPointer, std::uint64_t &stackPointer,
                                       std::uint64_t &contextFlags) noexcept
    {
        instructionPointer = 0;
        stackPointer = 0;
        contextFlags = 0;
        if (value == nullptr)
        {
            return false;
        }

        __try
        {
            contextFlags = static_cast<std::uint64_t>(value->ContextFlags);
            instructionPointer = static_cast<std::uint64_t>(value->Rip);
            stackPointer = static_cast<std::uint64_t>(value->Rsp);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            instructionPointer = 0;
            stackPointer = 0;
            contextFlags = 0;
            return false;
        }
    }

    static void TryCopyBufferSample(const void *buffer, std::size_t bufferSize, NtHookContext &ctx) noexcept
    {
        ctx.DataSize = 0;
        if (buffer == nullptr || bufferSize == 0)
        {
            return;
        }

        std::size_t sampleBytes = std::min<std::size_t>(sizeof(ctx.DataSample), bufferSize);
        __try
        {
            std::memcpy(ctx.DataSample, buffer, sampleBytes);
            ctx.DataSize = static_cast<std::uint32_t>(sampleBytes);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ctx.DataSize = 0;
        }
    }

    NTSTATUS NTAPI NtCreateThread_Hook(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                       POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId,
                                       PCONTEXT ThreadContext, PBB_INITIAL_TEB InitialTeb, BOOLEAN CreateSuspended)
    {
        if (!g_NtCreateThreadStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtCreateThreadStub(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId,
                                               ThreadContext, InitialTeb, CreateSuspended);
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
            ctx.Args[6] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            ctx.Args[7] = static_cast<std::uint64_t>(CreateSuspended);
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtCreateThreadEx_Hook(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                         POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine,
                                         PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
                                         SIZE_T MaximumStackSize, PVOID AttributeList)
    {
        if (!g_NtCreateThreadExStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status =
            g_NtCreateThreadExStub(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument,
                                   CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
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
            ctx.Args[6] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            ctx.Args[7] = static_cast<std::uint64_t>(MaximumStackSize);
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtWriteVirtualMemory_Hook(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize,
                                             PSIZE_T NumberOfBytesWritten)
    {
        if (!g_NtWriteVirtualMemoryStub)
            return STATUS_NOT_IMPLEMENTED;
        bool deniedSr71Write = ShouldDenySr71Write(ProcessHandle, BaseAddress, BufferSize);
        NTSTATUS status = STATUS_SUCCESS;
        if (!deniedSr71Write)
        {
            status = g_NtWriteVirtualMemoryStub(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
        }
        else
        {
            ApplyNtHookCloakWrite(reinterpret_cast<std::uintptr_t>(BaseAddress), BufferSize, Buffer);
            SetSizeTValue(NumberOfBytesWritten, BufferSize);
        }
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
            ctx.Args[5] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            ctx.Args[6] = deniedSr71Write ? kNtHookSr71WriteBlockedMarker : 0u;
            TryCopyBufferSample(Buffer, BufferSize, ctx);
            if (deniedSr71Write)
            {
                PublishNtEventAlways(ctx, status);
            }
            else
            {
                PublishNtEventIfSuccessful(ctx, status);
            }
        }
        return status;
    }

    NTSTATUS NTAPI NtAllocateVirtualMemory_Hook(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
                                                PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
    {
        if (!g_NtAllocateVirtualMemoryStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status =
            g_NtAllocateVirtualMemoryStub(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
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
            ctx.Args[6] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            (void)TryReadPointerArgument(BaseAddress, ctx.Args[1]);
            (void)TryReadSizeArgument(RegionSize, ctx.Args[3]);
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtProtectVirtualMemory_Hook(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
                                               ULONG NewProtect, PULONG OldProtect)
    {
        if (!g_NtProtectVirtualMemoryStub)
            return STATUS_NOT_IMPLEMENTED;
        bool deniedSr71Protect = ShouldDenySr71ProtectWrite(ProcessHandle, BaseAddress, RegionSize, NewProtect);
        NTSTATUS status = STATUS_ACCESS_DENIED;
        if (!deniedSr71Protect)
        {
            status = g_NtProtectVirtualMemoryStub(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
        }
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
            ctx.Args[7] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            (void)TryReadPointerArgument(BaseAddress, ctx.Args[1]);
            (void)TryReadSizeArgument(RegionSize, ctx.Args[2]);
            (void)TryReadUlongArgument(OldProtect, ctx.Args[4]);
            ctx.Args[6] = deniedSr71Protect ? kNtHookSr71ProtectBlockedMarker : 0u;
            if (!deniedSr71Protect)
            {
                TryAnnotateProtectTarget(ProcessHandle, BaseAddress, RegionSize, ctx);
                PublishNtEventIfSuccessful(ctx, status);
            }
            else
            {
                PublishNtEventAlways(ctx, status);
            }
        }
        return status;
    }

    NTSTATUS NTAPI NtReadVirtualMemory_Hook(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize,
                                            PSIZE_T NumberOfBytesRead)
    {
        if (!g_NtReadVirtualMemoryStub)
            return STATUS_NOT_IMPLEMENTED;
        DWORD targetPid = 0;
        if (ProcessHandle == nullptr || ProcessHandle == reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1)))
        {
            targetPid = GetCurrentProcessId();
        }
        else
        {
            targetPid = GetProcessId(ProcessHandle);
        }
        NTSTATUS status = g_NtReadVirtualMemoryStub(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
        SIZE_T bytesRead = 0;
        if (NT_SUCCESS(status))
        {
            if (NumberOfBytesRead != nullptr)
            {
                __try
                {
                    bytesRead = *NumberOfBytesRead;
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    bytesRead = BufferSize;
                }
            }
            else
            {
                bytesRead = BufferSize;
            }
        }

        bool overlaidHookPatch =
            !BkSr71IsInternalCall() && NT_SUCCESS(status) &&
            OverlayNtHookOriginalBytes(reinterpret_cast<std::uintptr_t>(BaseAddress), bytesRead, Buffer);
        bool deniedSr71Read = !overlaidHookPatch && ShouldDenySr71Read(ProcessHandle, BaseAddress, BufferSize);
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
            ctx.Args[5] = deniedSr71Read ? 1u : 0u;
            ctx.Args[6] = overlaidHookPatch ? 1u : 0u;
            ctx.Args[7] = static_cast<std::uint64_t>(targetPid);
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtQueryVirtualMemory_Hook(HANDLE ProcessHandle, PVOID BaseAddress, ULONG MemoryInformationClass,
                                             PVOID MemoryInformation, SIZE_T MemoryInformationLength,
                                             PSIZE_T ReturnLength)
    {
        if (!g_NtQueryVirtualMemoryStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtQueryVirtualMemoryStub(ProcessHandle, BaseAddress, MemoryInformationClass,
                                                     MemoryInformation, MemoryInformationLength, ReturnLength);
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
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtQuerySystemInformation_Hook(ULONG SystemInformationClass, PVOID SystemInformation,
                                                 ULONG SystemInformationLength, PULONG ReturnLength)
    {
        if (!g_NtQuerySystemInformationStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtQuerySystemInformationStub(SystemInformationClass, SystemInformation,
                                                         SystemInformationLength, ReturnLength);
        if (NT_SUCCESS(status))
            SanitizeSystemInformationResult(SystemInformationClass, SystemInformation, SystemInformationLength,
                                            ReturnLength);
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
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtQuerySystemInformationEx_Hook(ULONG SystemInformationClass, PVOID InputBuffer,
                                                   ULONG InputBufferLength, PVOID SystemInformation,
                                                   ULONG SystemInformationLength, PULONG ReturnLength)
    {
        if (!g_NtQuerySystemInformationExStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtQuerySystemInformationExStub(SystemInformationClass, InputBuffer, InputBufferLength,
                                                           SystemInformation, SystemInformationLength, ReturnLength);
        if (NT_SUCCESS(status))
            SanitizeSystemInformationResult(SystemInformationClass, SystemInformation, SystemInformationLength,
                                            ReturnLength);
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQuerySystemInformationEx;
            ctx.FunctionName = "NtQuerySystemInformationEx";
            ctx.Caller = _ReturnAddress();
            ctx.Args[0] = static_cast<std::uint64_t>(SystemInformationClass);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(InputBuffer);
            ctx.Args[2] = static_cast<std::uint64_t>(InputBufferLength);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(SystemInformation);
            ctx.Args[4] = static_cast<std::uint64_t>(SystemInformationLength);
            ctx.Args[5] = reinterpret_cast<std::uint64_t>(ReturnLength);
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtGetNextThread_Hook(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                        ULONG HandleAttributes, ULONG Flags, PHANDLE NewThreadHandle)
    {
        if (!g_NtGetNextThreadStub || !NewThreadHandle)
            return STATUS_NOT_IMPLEMENTED;

        // Fast path — concealment inactive, no filtering needed.
        if (g_ConcealedTidCount.load(std::memory_order_relaxed) == 0 || !IsCurrentProcessQuery(ProcessHandle))
        {
            NTSTATUS status = g_NtGetNextThreadStub(ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags,
                                                    NewThreadHandle);
            if (g_ActiveNtCallback && NT_SUCCESS(status))
            {
                NtHookContext ctx{};
                ctx.Operation = NtOperation::NtGetNextThread;
                ctx.FunctionName = "NtGetNextThread";
                ctx.Caller = _ReturnAddress();
                ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
                ctx.Args[1] = reinterpret_cast<std::uint64_t>(ThreadHandle);
                ctx.Args[2] = static_cast<std::uint64_t>(DesiredAccess);
                ctx.Args[3] = reinterpret_cast<std::uint64_t>(NewThreadHandle);
                PublishNtEventIfSuccessful(ctx, status);
            }
            return status;
        }

        // Slow path — walk threads, skipping any whose TID is concealed.
        // We use the returned handle as the cursor for the next iteration
        // rather than closing and re-opening, which avoids a handle-count
        // spike and keeps the loop tight. The previous cursor handle (when
        // it is not the caller-supplied ThreadHandle) is closed once we have
        // advanced past it.
        HANDLE cursor = ThreadHandle;
        bool cursorOwned = false; // true when cursor is a handle we opened

        for (;;)
        {
            HANDLE candidate = NULL;
            NTSTATUS status =
                g_NtGetNextThreadStub(ProcessHandle, cursor, DesiredAccess, HandleAttributes, Flags, &candidate);
            if (cursorOwned)
                CloseHandle(cursor);

            if (!NT_SUCCESS(status))
                return status; // STATUS_NO_MORE_ENTRIES or real error

            DWORD tid = GetThreadTid(candidate);
            if (!IsThreadConcealed(tid))
            {
                if (g_ActiveNtCallback)
                {
                    NtHookContext ctx{};
                    ctx.Operation = NtOperation::NtGetNextThread;
                    ctx.FunctionName = "NtGetNextThread";
                    ctx.Caller = _ReturnAddress();
                    ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
                    ctx.Args[1] = reinterpret_cast<std::uint64_t>(ThreadHandle);
                    ctx.Args[2] = static_cast<std::uint64_t>(DesiredAccess);
                    ctx.Args[3] = reinterpret_cast<std::uint64_t>(NewThreadHandle);
                    PublishNtEventIfSuccessful(ctx, status);
                }
                *NewThreadHandle = candidate;
                return STATUS_SUCCESS;
            }

            // Concealed — advance cursor without exposing this handle.
            cursor = candidate;
            cursorOwned = true;
        }
    }

    NTSTATUS NTAPI NtCreateSection_Hook(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
                                        POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
                                        ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
    {
        if (!g_NtCreateSectionStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtCreateSectionStub(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize,
                                                SectionPageProtection, AllocationAttributes, FileHandle);
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
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
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
            ctx.Args[6] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            ctx.Args[7] = kNtHookTerminateBreakpointMarker;

            PublishNtEventAlways(ctx, STATUS_SUCCESS);
            BK_RUNTIME_INTERNAL::FlushHookEvents();
            (void)BKIPC::DrainPendingHookEventsSynchronously(64);
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

            PublishNtEventAlways(ctx, STATUS_SUCCESS);
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

            PublishNtEventAlways(ctx, STATUS_SUCCESS);
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

            PublishNtEventAlways(ctx, STATUS_SUCCESS);
        }

        if (!g_NtOpenFileStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtOpenFileStub(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
    }

    NTSTATUS NTAPI NtQueryInformationProcess_Hook(HANDLE ProcessHandle, ULONG ProcessInformationClass,
                                                  PVOID ProcessInformation, ULONG ProcessInformationLength,
                                                  PULONG ReturnLength)
    {
        if (!g_NtQueryInformationProcessStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtQueryInformationProcessStub(ProcessHandle, ProcessInformationClass, ProcessInformation,
                                                          ProcessInformationLength, ReturnLength);
        if (NT_SUCCESS(status) && IsCurrentProcessQuery(ProcessHandle))
            SanitizeProcessInformationResult(ProcessInformationClass, ProcessInformation, ProcessInformationLength,
                                             ReturnLength);
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
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtQueryInformationThread_Hook(HANDLE ThreadHandle, ULONG ThreadInformationClass,
                                                 PVOID ThreadInformation, ULONG ThreadInformationLength,
                                                 PULONG ReturnLength)
    {
        if (!g_NtQueryInformationThreadStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtQueryInformationThreadStub(ThreadHandle, ThreadInformationClass, ThreadInformation,
                                                         ThreadInformationLength, ReturnLength);
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
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtSetContextThread_Hook(HANDLE ThreadHandle, PCONTEXT ThreadContext)
    {
        if (!g_NtSetContextThreadStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtSetContextThreadStub(ThreadHandle, ThreadContext);
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtSetContextThread;
            ctx.FunctionName = "NtSetContextThread";
            ctx.Caller = _ReturnAddress();
            DWORD targetPid = 0;
            DWORD targetTid = 0;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(ThreadContext);
            (void)TryReadContextArgument(ThreadContext, ctx.Args[2], ctx.Args[3], ctx.Args[4]);
            if (TryReadThreadIdentity(ThreadHandle, targetPid, targetTid))
            {
                ctx.Args[5] = static_cast<std::uint64_t>(targetTid);
                ctx.Args[6] = static_cast<std::uint64_t>(targetPid);
            }
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
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

            PublishNtEventAlways(ctx, STATUS_SUCCESS);
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

            PublishNtEventAlways(ctx, STATUS_SUCCESS);
        }

        if (!g_NtQueryBootOptionsStub)
            return STATUS_NOT_IMPLEMENTED;

        return g_NtQueryBootOptionsStub(BootOptions, BootOptionsLength);
    }

    NTSTATUS NTAPI NtOpenProcess_Hook(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                      POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
    {
        if (!g_NtOpenProcessStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtOpenProcessStub(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            std::uint64_t targetProcessId = 0;
            std::uint64_t targetThreadId = 0;
            (void)TryReadClientIdArgument(ClientId, targetProcessId, targetThreadId);
            ctx.Operation = NtOperation::NtOpenProcess;
            ctx.FunctionName = "NtOpenProcess";
            ctx.Caller = _ReturnAddress();
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = targetProcessId;
            ctx.Args[3] = targetThreadId;
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ObjectAttributes);
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtOpenThread_Hook(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                     POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
    {
        if (!g_NtOpenThreadStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtOpenThreadStub(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            std::uint64_t targetProcessId = 0;
            std::uint64_t targetThreadId = 0;
            (void)TryReadClientIdArgument(ClientId, targetProcessId, targetThreadId);
            ctx.Operation = NtOperation::NtOpenThread;
            ctx.FunctionName = "NtOpenThread";
            ctx.Caller = _ReturnAddress();
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = targetProcessId;
            ctx.Args[3] = targetThreadId;
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ObjectAttributes);
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtDuplicateObject_Hook(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle,
                                          PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG Attributes,
                                          ULONG Options)
    {
        if (!g_NtDuplicateObjectStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtDuplicateObjectStub(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle,
                                                  DesiredAccess, Attributes, Options);
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
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtGetContextThread_Hook(HANDLE ThreadHandle, PCONTEXT ThreadContext)
    {
        if (!g_NtGetContextThreadStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtGetContextThreadStub(ThreadHandle, ThreadContext);
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtGetContextThread;
            ctx.FunctionName = "NtGetContextThread";
            ctx.Caller = _ReturnAddress();
            DWORD targetPid = 0;
            DWORD targetTid = 0;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(ThreadContext);
            (void)TryReadContextArgument(ThreadContext, ctx.Args[2], ctx.Args[3], ctx.Args[4]);
            if (TryReadThreadIdentity(ThreadHandle, targetPid, targetTid))
            {
                ctx.Args[5] = static_cast<std::uint64_t>(targetTid);
                ctx.Args[6] = static_cast<std::uint64_t>(targetPid);
            }
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtSuspendThread_Hook(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
    {
        if (!g_NtSuspendThreadStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtSuspendThreadStub(ThreadHandle, PreviousSuspendCount);
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            DWORD targetPid = 0;
            DWORD targetTid = 0;
            ctx.Operation = NtOperation::NtSuspendThread;
            ctx.FunctionName = "NtSuspendThread";
            ctx.Caller = _ReturnAddress();
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(PreviousSuspendCount);
            (void)TryReadUlongArgument(PreviousSuspendCount, ctx.Args[2]);
            if (TryReadThreadIdentity(ThreadHandle, targetPid, targetTid))
            {
                ctx.Args[3] = static_cast<std::uint64_t>(targetTid);
                ctx.Args[4] = static_cast<std::uint64_t>(targetPid);
            }
            PublishNtEventIfSuccessful(ctx, status);
        }

        return status;
    }

    NTSTATUS NTAPI NtResumeThread_Hook(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
    {
        if (!g_NtResumeThreadStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtResumeThreadStub(ThreadHandle, PreviousSuspendCount);
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            DWORD targetPid = 0;
            DWORD targetTid = 0;
            ctx.Operation = NtOperation::NtResumeThread;
            ctx.FunctionName = "NtResumeThread";
            ctx.Caller = _ReturnAddress();
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(PreviousSuspendCount);
            (void)TryReadUlongArgument(PreviousSuspendCount, ctx.Args[2]);
            if (TryReadThreadIdentity(ThreadHandle, targetPid, targetTid))
            {
                ctx.Args[3] = static_cast<std::uint64_t>(targetTid);
                ctx.Args[4] = static_cast<std::uint64_t>(targetPid);
            }
            PublishNtEventIfSuccessful(ctx, status);
        }

        return status;
    }

    NTSTATUS NTAPI NtQueueApcThread_Hook(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2,
                                         PVOID ApcArgument3)
    {
        if (!g_NtQueueApcThreadStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtQueueApcThreadStub(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQueueApcThread;
            ctx.FunctionName = "NtQueueApcThread";
            ctx.Caller = _ReturnAddress();
            DWORD targetPid = 0;
            DWORD targetTid = 0;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(ApcRoutine);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ApcArgument1);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(ApcArgument2);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ApcArgument3);
            if (TryReadThreadIdentity(ThreadHandle, targetPid, targetTid))
            {
                ctx.Args[5] = static_cast<std::uint64_t>(targetTid);
                ctx.Args[6] = static_cast<std::uint64_t>(targetPid);
            }
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtAllocateVirtualMemoryEx_Hook(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
                                                  ULONG AllocationType, ULONG PageProtection, PVOID ExtendedParameters,
                                                  ULONG ExtendedParameterCount)
    {
        if (!g_NtAllocateVirtualMemoryExStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtAllocateVirtualMemoryExStub(ProcessHandle, BaseAddress, RegionSize, AllocationType,
                                                          PageProtection, ExtendedParameters, ExtendedParameterCount);
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtAllocateVirtualMemoryEx;
            ctx.FunctionName = "NtAllocateVirtualMemoryEx";
            ctx.Caller = _ReturnAddress();
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(RegionSize);
            ctx.Args[3] = static_cast<std::uint64_t>(AllocationType);
            ctx.Args[4] = static_cast<std::uint64_t>(PageProtection);
            ctx.Args[5] = reinterpret_cast<std::uint64_t>(ExtendedParameters);
            ctx.Args[6] = static_cast<std::uint64_t>(ExtendedParameterCount);
            ctx.Args[7] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            (void)TryReadPointerArgument(BaseAddress, ctx.Args[1]);
            (void)TryReadSizeArgument(RegionSize, ctx.Args[2]);
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtMapViewOfSectionEx_Hook(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
                                             PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG AllocationType,
                                             ULONG Win32Protect, PVOID ExtendedParameters, ULONG ExtendedParameterCount)
    {
        if (!g_NtMapViewOfSectionExStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status =
            g_NtMapViewOfSectionExStub(SectionHandle, ProcessHandle, BaseAddress, SectionOffset, ViewSize,
                                       AllocationType, Win32Protect, ExtendedParameters, ExtendedParameterCount);
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
            ctx.Args[7] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            (void)TryReadPointerArgument(BaseAddress, ctx.Args[2]);
            (void)TryReadSizeArgument(ViewSize, ctx.Args[4]);
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtMapViewOfSection_Hook(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
                                           ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
                                           PSIZE_T ViewSize, ULONG InheritDisposition, ULONG AllocationType,
                                           ULONG Win32Protect)
    {
        if (!g_NtMapViewOfSectionStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status =
            g_NtMapViewOfSectionStub(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset,
                                     ViewSize, InheritDisposition, AllocationType, Win32Protect);
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtMapViewOfSection;
            ctx.FunctionName = "NtMapViewOfSection";
            ctx.Caller = _ReturnAddress();
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(SectionHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(ViewSize);
            ctx.Args[4] = static_cast<std::uint64_t>(InheritDisposition);
            ctx.Args[5] = static_cast<std::uint64_t>(AllocationType);
            ctx.Args[6] = static_cast<std::uint64_t>(Win32Protect);
            ctx.Args[7] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            (void)TryReadPointerArgument(BaseAddress, ctx.Args[2]);
            (void)TryReadSizeArgument(ViewSize, ctx.Args[3]);
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtUnmapViewOfSection_Hook(HANDLE ProcessHandle, PVOID BaseAddress)
    {
        if (!g_NtUnmapViewOfSectionStub)
            return STATUS_NOT_IMPLEMENTED;
        DWORD targetPid = GetProcessPid(ProcessHandle);
        NTSTATUS status = g_NtUnmapViewOfSectionStub(ProcessHandle, BaseAddress);
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtUnmapViewOfSection;
            ctx.FunctionName = "NtUnmapViewOfSection";
            ctx.Caller = _ReturnAddress();
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[2] = static_cast<std::uint64_t>(targetPid);
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtUnmapViewOfSectionEx_Hook(HANDLE ProcessHandle, PVOID BaseAddress, ULONG Flags)
    {
        if (!g_NtUnmapViewOfSectionExStub)
            return STATUS_NOT_IMPLEMENTED;
        DWORD targetPid = GetProcessPid(ProcessHandle);
        NTSTATUS status = g_NtUnmapViewOfSectionExStub(ProcessHandle, BaseAddress, Flags);
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtUnmapViewOfSectionEx;
            ctx.FunctionName = "NtUnmapViewOfSectionEx";
            ctx.Caller = _ReturnAddress();
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[2] = static_cast<std::uint64_t>(targetPid);
            ctx.Args[3] = static_cast<std::uint64_t>(Flags);
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtQueueApcThreadEx_Hook(HANDLE ThreadHandle, HANDLE UserApcReserveHandle, PVOID ApcRoutine,
                                           PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3)
    {
        if (!g_NtQueueApcThreadExStub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtQueueApcThreadExStub(ThreadHandle, UserApcReserveHandle, ApcRoutine, ApcArgument1,
                                                   ApcArgument2, ApcArgument3);
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQueueApcThreadEx;
            ctx.FunctionName = "NtQueueApcThreadEx";
            ctx.Caller = _ReturnAddress();
            DWORD targetPid = 0;
            DWORD targetTid = 0;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(UserApcReserveHandle);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ApcRoutine);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(ApcArgument1);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ApcArgument2);
            ctx.Args[5] = reinterpret_cast<std::uint64_t>(ApcArgument3);
            if (TryReadThreadIdentity(ThreadHandle, targetPid, targetTid))
            {
                ctx.Args[6] = static_cast<std::uint64_t>(targetTid);
                ctx.Args[7] = static_cast<std::uint64_t>(targetPid);
            }
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
    }

    NTSTATUS NTAPI NtQueueApcThreadEx2_Hook(HANDLE ThreadHandle, HANDLE UserApcReserveHandle, ULONG QueueUserApcFlags,
                                            PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2,
                                            PVOID ApcArgument3)
    {
        if (!g_NtQueueApcThreadEx2Stub)
            return STATUS_NOT_IMPLEMENTED;
        NTSTATUS status = g_NtQueueApcThreadEx2Stub(ThreadHandle, UserApcReserveHandle, QueueUserApcFlags, ApcRoutine,
                                                    ApcArgument1, ApcArgument2, ApcArgument3);
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQueueApcThreadEx2;
            ctx.FunctionName = "NtQueueApcThreadEx2";
            ctx.Caller = _ReturnAddress();
            DWORD targetPid = 0;
            DWORD targetTid = 0;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(UserApcReserveHandle);
            ctx.Args[2] = static_cast<std::uint64_t>(QueueUserApcFlags);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(ApcRoutine);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ApcArgument1);
            ctx.Args[5] = reinterpret_cast<std::uint64_t>(ApcArgument2);
            if (TryReadThreadIdentity(ThreadHandle, targetPid, targetTid))
            {
                ctx.Args[6] = static_cast<std::uint64_t>(targetTid);
                ctx.Args[7] = static_cast<std::uint64_t>(targetPid);
            }
            PublishNtEventIfSuccessful(ctx, status);
        }
        return status;
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

            PublishNtEventAlways(ctx, STATUS_SUCCESS);
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

            PublishNtEventAlways(ctx, STATUS_SUCCESS);
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
        if (std::strcmp(name, "NtMapViewOfSection") == 0)
            return reinterpret_cast<void *>(&NtMapViewOfSection_Hook);
        if (std::strcmp(name, "NtMapViewOfSectionEx") == 0)
            return reinterpret_cast<void *>(&NtMapViewOfSectionEx_Hook);
        if (std::strcmp(name, "NtUnmapViewOfSection") == 0)
            return reinterpret_cast<void *>(&NtUnmapViewOfSection_Hook);
        if (std::strcmp(name, "NtUnmapViewOfSectionEx") == 0)
            return reinterpret_cast<void *>(&NtUnmapViewOfSectionEx_Hook);
        if (std::strcmp(name, "NtQueueApcThreadEx") == 0)
            return reinterpret_cast<void *>(&NtQueueApcThreadEx_Hook);
        if (std::strcmp(name, "NtQueueApcThreadEx2") == 0)
            return reinterpret_cast<void *>(&NtQueueApcThreadEx2_Hook);
        if (std::strcmp(name, "NtOpenProcessTokenEx") == 0)
            return reinterpret_cast<void *>(&NtOpenProcessTokenEx_Hook);
        if (std::strcmp(name, "NtOpenThreadTokenEx") == 0)
            return reinterpret_cast<void *>(&NtOpenThreadTokenEx_Hook);
        if (std::strcmp(name, "NtQuerySystemInformationEx") == 0)
            return reinterpret_cast<void *>(&NtQuerySystemInformationEx_Hook);
        if (std::strcmp(name, "NtGetNextThread") == 0)
            return reinterpret_cast<void *>(&NtGetNextThread_Hook);
        return nullptr;
    }
} // namespace BK_NT

#endif

bool KeSetNtHook(NtHookCallback callback) noexcept
{
#ifndef _WIN64
    (void)callback;
    return false;
#else
    using namespace BK_NT;

    if (!callback)
        return false;

    g_ActiveNtCallback = callback;
    ResetNtHookInitFault();

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
    {
        SetNtHookInitFault(NtHookInitFaultCode::NtdllMissing, "ntdll.dll", nullptr);
        return false;
    }

    ModuleRange ntdllImage{};
    if (!TryResolveModuleImageRange(ntdll, ntdllImage))
    {
        SetNtHookInitFault(NtHookInitFaultCode::ExportOutsideImage, "ntdll.dll", ntdll);
        return false;
    }

    ModuleRange ntdllText{};
    if (!TryResolveModuleTextRange(ntdll, ntdllText))
    {
        SetNtHookInitFault(NtHookInitFaultCode::NtdllTextMissing, "ntdll.dll", ntdll);
        return false;
    }

    if (!HasExportDirectory(ntdll))
    {
        SetNtHookInitFault(NtHookInitFaultCode::NtdllExportDirectoryMissing, "ntdll.dll", ntdll);
        return false;
    }

    const bool enableNtMemoryHooks = ShouldEnableNtMemoryHooks();
    bool anyInstalled = false;

    std::uint8_t hookOrder[RTL_NUMBER_OF(g_NtHooks)]{};
    BuildHookWalkOrder(hookOrder, RTL_NUMBER_OF(g_NtHooks));

    for (std::size_t walkIndex = 0; walkIndex < RTL_NUMBER_OF(g_NtHooks); ++walkIndex)
    {
        auto &hook = g_NtHooks[hookOrder[walkIndex]];
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
        {
            SetNtHookInitFault(NtHookInitFaultCode::ExportMissing, hook.Name, nullptr);
            continue;
        }

        void *targetAddress = reinterpret_cast<void *>(addr);
        if (!AddressWithinRange(targetAddress, ntdllImage))
        {
            SetNtHookInitFault(NtHookInitFaultCode::ExportOutsideImage, hook.Name, targetAddress);
            continue;
        }

        if (!AddressWithinRange(targetAddress, ntdllText))
        {
            SetNtHookInitFault(NtHookInitFaultCode::ExportOutsideText, hook.Name, targetAddress);
            continue;
        }

        std::uint32_t sysIndex = 0;
        if (!ExtractSyscallIndex(targetAddress, sysIndex))
        {
            void *redirectTarget = nullptr;
            if (TryDecodeAbsoluteTarget(targetAddress, redirectTarget) && redirectTarget != nullptr &&
                !AddressWithinRange(redirectTarget, ntdllImage))
            {
                SetNtHookInitFault(NtHookInitFaultCode::ExportRedirectedOutsideImage, hook.Name, targetAddress,
                                   redirectTarget);
            }
            else
            {
                SetNtHookInitFault(NtHookInitFaultCode::UnexpectedStubBytes, hook.Name, targetAddress);
            }
            continue;
        }

        hook.SyscallIndex = sysIndex;
        hook.TargetToken =
            RegisterNtHookPointer(targetAddress, BK_RUNTIME_INTERNAL::Sr71IhrType::NtHookTarget, hook.Name);
        if (hook.TargetToken == 0)
        {
            SetNtHookInitFault(NtHookInitFaultCode::PatchInstallFailed, hook.Name, targetAddress, nullptr, sysIndex);
            continue;
        }

        void *stubCode = BuildSyscallStub(sysIndex);
        if (!stubCode)
        {
            SetNtHookInitFault(NtHookInitFaultCode::SyscallStubAllocFailed, hook.Name, targetAddress, nullptr,
                               sysIndex);
            continue;
        }

        hook.SyscallStubToken = RegisterNtHookPointer(
            stubCode, BK_RUNTIME_INTERNAL::Sr71IhrType::NtSyscallStub, hook.Name,
            BK_RUNTIME_INTERNAL::kSr71IhrFlagExecutable | BK_RUNTIME_INTERNAL::kSr71IhrFlagSr71Owned);
        if (hook.SyscallStubToken == 0)
        {
            SetNtHookInitFault(NtHookInitFaultCode::SyscallStubAllocFailed, hook.Name, targetAddress, nullptr,
                               sysIndex);
            continue;
        }

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
        else if (std::strcmp(hook.Name, "NtMapViewOfSection") == 0)
            g_NtMapViewOfSectionStub = reinterpret_cast<NtMapViewOfSection_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtMapViewOfSectionEx") == 0)
            g_NtMapViewOfSectionExStub = reinterpret_cast<NtMapViewOfSectionEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtUnmapViewOfSection") == 0)
            g_NtUnmapViewOfSectionStub = reinterpret_cast<NtUnmapViewOfSection_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtUnmapViewOfSectionEx") == 0)
            g_NtUnmapViewOfSectionExStub = reinterpret_cast<NtUnmapViewOfSectionEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQueueApcThreadEx") == 0)
            g_NtQueueApcThreadExStub = reinterpret_cast<NtQueueApcThreadEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQueueApcThreadEx2") == 0)
            g_NtQueueApcThreadEx2Stub = reinterpret_cast<NtQueueApcThreadEx2_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtOpenProcessTokenEx") == 0)
            g_NtOpenProcessTokenExStub = reinterpret_cast<NtOpenProcessTokenEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtOpenThreadTokenEx") == 0)
            g_NtOpenThreadTokenExStub = reinterpret_cast<NtOpenThreadTokenEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQuerySystemInformationEx") == 0)
            g_NtQuerySystemInformationExStub = reinterpret_cast<NtQuerySystemInformationEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtGetNextThread") == 0)
            g_NtGetNextThreadStub = reinterpret_cast<NtGetNextThread_t>(stubCode);

        void *hookEntry = GetHookEntry(hook.Name);
        if (!hookEntry)
        {
            SetNtHookInitFault(NtHookInitFaultCode::HookEntryMissing, hook.Name, targetAddress, nullptr, sysIndex);
            continue;
        }

        if (!InstallInlineHook(targetAddress, hookEntry, hook.OriginalBytes))
        {
            SetNtHookInitFault(NtHookInitFaultCode::PatchInstallFailed, hook.Name, targetAddress, nullptr, sysIndex);
            continue;
        }

        std::memcpy(hook.CloakBytes, hook.OriginalBytes, sizeof(hook.CloakBytes));
        hook.Installed = true;
        anyInstalled = true;
    }

    return anyInstalled;
#endif
}

void KeRegisterConcealedThread(DWORD tid) noexcept
{
#ifdef _WIN64
    using namespace BK_NT;
    int32_t count = g_ConcealedTidCount.load(std::memory_order_acquire);
    for (int32_t i = 0; i < count; ++i)
    {
        if (g_ConcealedTids[i] == tid)
            return; // already registered
    }
    if (count < kMaxConcealedThreads)
    {
        // Write the entry before incrementing the count. The fetch_add
        // acts as a release fence so no reader can observe count == N
        // without also seeing g_ConcealedTids[N-1] written.
        g_ConcealedTids[count] = tid;
        g_ConcealedTidCount.fetch_add(1, std::memory_order_release);
    }
#else
    (void)tid;
#endif
}

void KeUnregisterConcealedThread(DWORD tid) noexcept
{
#ifdef _WIN64
    using namespace BK_NT;
    int32_t count = g_ConcealedTidCount.load(std::memory_order_acquire);
    for (int32_t i = 0; i < count; ++i)
    {
        if (g_ConcealedTids[i] != tid)
            continue;
        // Swap with last entry, decrement count. Decrement first so that
        // concurrent readers either see the old entry at slot i or miss it
        // entirely — they won't read off the end of the live range.
        int32_t last = g_ConcealedTidCount.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (i < last)
            g_ConcealedTids[i] = g_ConcealedTids[last];
        g_ConcealedTids[last] = 0;
        return;
    }
#else
    (void)tid;
#endif
}

void KeRemoveNtHook() noexcept
{
#ifdef _WIN64
    using namespace BK_NT;

    for (auto &hook : g_NtHooks)
    {
        void *targetAddress = ResolveNtHookTarget(hook);
        if (!hook.Installed || targetAddress == nullptr)
            continue;

        RemoveInlineHook(targetAddress, hook.OriginalBytes);
        BK_RUNTIME_INTERNAL::ReleaseIndirectHandle(hook.TargetToken);
        BK_RUNTIME_INTERNAL::ReleaseIndirectHandle(hook.SyscallStubToken);
        hook.TargetToken = 0;
        hook.SyscallStubToken = 0;
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
    using namespace BK_NT;

    std::uint32_t mismatches = 0;

    for (const auto &hook : g_NtHooks)
    {
        void *targetAddress = ResolveNtHookTarget(hook);
        if (!hook.Installed || targetAddress == nullptr)
        {
            continue;
        }

        const auto *bytes = static_cast<const std::uint8_t *>(targetAddress);
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

bool KeGetLastNtHookInitFault(NtHookInitFault *faultOut) noexcept
{
#ifndef _WIN64
    if (faultOut != nullptr)
    {
        std::memset(faultOut, 0, sizeof(*faultOut));
        faultOut->Code = NtHookInitFaultCode::None;
    }
    return false;
#else
    if (faultOut == nullptr)
    {
        return false;
    }

    *faultOut = BK_NT::g_LastNtHookInitFault;
    return faultOut->Code != NtHookInitFaultCode::None;
#endif
}

std::size_t KeCollectNtHookStubInfos(NtHookStubInfo *out, std::size_t capacity) noexcept
{
#ifndef _WIN64
    (void)out;
    (void)capacity;
    return 0;
#else
    if (out == nullptr || capacity == 0)
        return 0;

    std::size_t count = 0;
    for (const auto &hook : BK_NT::g_NtHooks)
    {
        if (count >= capacity)
            break;
        void *stubCode = BK_NT::ResolveNtHookStub(hook);
        if (stubCode == nullptr)
            continue;
        out[count].StubBase = stubCode;
        out[count].StubSize = 16u; /* BuildSyscallStub always allocates exactly 16 bytes */
        out[count].HookName = hook.Name;
        ++count;
    }
    return count;
#endif
}

std::size_t KeCollectNtHookPatchInfos(NtHookPatchInfo *out, std::size_t capacity) noexcept
{
#ifndef _WIN64
    (void)out;
    (void)capacity;
    return 0;
#else
    if (out == nullptr || capacity == 0)
        return 0;

    std::size_t count = 0;
    for (const auto &hook : BK_NT::g_NtHooks)
    {
        if (count >= capacity)
            break;
        void *targetAddress = BK_NT::ResolveNtHookTarget(hook);
        if (!hook.Installed || targetAddress == nullptr)
            continue;
        out[count].PatchAddress = targetAddress;
        out[count].PatchSize = sizeof(hook.OriginalBytes);
        std::memcpy(out[count].OriginalBytes, hook.CloakBytes, sizeof(hook.CloakBytes));
        out[count].HookName = hook.Name;
        ++count;
    }
    return count;
#endif
}
