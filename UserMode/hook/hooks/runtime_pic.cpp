#include "runtime_private.h"
#include "../instrument/stacktrace.h"

#include <intrin.h>
#include <strsafe.h>
#include <cstring>

#if defined(_M_X64)
#pragma intrinsic(__readgsqword)
#pragma intrinsic(_InterlockedIncrement)
#endif

namespace BK_RUNTIME_INTERNAL
{
    namespace
    {
#if defined(_M_X64)
        inline constexpr ULONG kProcessInstrumentationCallbackClass = 40u;
        inline constexpr ULONG kProcessInstrumentationCallbackVersion = 0u;
        inline constexpr DWORD kPicStubAllocationSize = 0x1000u;
        inline constexpr std::uint64_t kTebInstrumentationPreviousPc = 0x2D8u;
        inline constexpr std::uint64_t kTebInstrumentationPreviousSp = 0x2E0u;
        inline constexpr std::uint64_t kTebInstrumentationCallbackDisabled = 0x2ECu;
        inline constexpr std::uint64_t kTebClientIdUniqueThread = 0x48u;
        inline constexpr std::uint32_t kPicReturnAbiLegacyTeb = 0u;
        inline constexpr LONG kPicSampleRingMask = 127;
        inline constexpr ULONGLONG kPicPublishMinIntervalMs = 500ull;
        inline constexpr bool kPicRuntimeDisabledForTest = true;

        struct ProcessInstrumentationCallbackInformation
        {
            ULONG Version;
            ULONG Reserved;
            PVOID Callback;
        };

        using NtSetInformationProcessFn = NTSTATUS(NTAPI *)(HANDLE, ULONG, PVOID, ULONG);

        struct PicRange
        {
            std::uint64_t Base = 0;
            std::uint64_t End = 0;
        };

        struct PicSample
        {
            volatile LONG Sequence = 0;
            std::uint64_t PreviousPc = 0;
            std::uint64_t PreviousSp = 0;
            std::uint64_t ThreadId = 0;
        };

        volatile LONG g_PicInstallState = 0;
        volatile LONG g_PicProtectRegistered = 0;
        volatile LONG g_PicWriteSequence = 0;
        volatile LONG g_PicReadSequence = 0;
        volatile LONG g_PicDroppedSamples = 0;
        volatile LONG g_PicLegacyAbiObserved = 0;
        volatile LONG g_PicZeroPreviousPcObserved = 0;
        volatile LONG g_PicLegacyAbiLogged = 0;
        volatile LONG g_PicZeroPreviousPcLogged = 0;
        volatile LONG g_PicDisabledLogged = 0;
        PicSample g_PicSamples[kPicSampleRingMask + 1]{};
        PicRange g_PicNtdllRange{};
        PicRange g_PicWin32uRange{};
        PicRange g_PicSr71Range{};
        PicRange g_PicStubRange{};
        void *g_PicStub = nullptr;
        ULONGLONG g_PicLastPublishTick = 0;

        bool PicAddressInRange(std::uint64_t address, const PicRange &range) noexcept
        {
            return range.Base != 0 && address >= range.Base && address < range.End;
        }

        bool PicAddressIsKnownSystemReturn(std::uint64_t address) noexcept
        {
            return PicAddressInRange(address, g_PicNtdllRange) || PicAddressInRange(address, g_PicWin32uRange) ||
                   PicAddressInRange(address, g_PicSr71Range) || PicAddressInRange(address, g_PicStubRange);
        }

        std::uint64_t ImageSizeFromBase(void *moduleBase) noexcept
        {
            if (moduleBase == nullptr)
            {
                return 0;
            }

            __try
            {
                const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(moduleBase);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                {
                    return 0;
                }

                const auto *ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(
                    reinterpret_cast<const std::uint8_t *>(moduleBase) + static_cast<std::size_t>(dos->e_lfanew));
                if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
                {
                    return 0;
                }

                return ntHeaders->OptionalHeader.SizeOfImage;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return 0;
            }
        }

        PicRange ImageRangeForModule(const wchar_t *moduleName) noexcept
        {
            PicRange range{};
            void *base = FindLoadedModuleBaseByName(moduleName);
            std::uint64_t size = ImageSizeFromBase(base);
            if (base != nullptr && size != 0)
            {
                range.Base = reinterpret_cast<std::uint64_t>(base);
                range.End = range.Base + size;
            }
            return range;
        }

        void RefreshPicKnownRanges() noexcept
        {
            g_PicNtdllRange = ImageRangeForModule(L"ntdll.dll");
            g_PicWin32uRange = ImageRangeForModule(L"win32u.dll");

            MEMORY_BASIC_INFORMATION selfMbi{};
            if (VirtualQuery(reinterpret_cast<const void *>(&RefreshPicKnownRanges), &selfMbi, sizeof(selfMbi)) ==
                    sizeof(selfMbi) &&
                selfMbi.AllocationBase != nullptr)
            {
                const auto base = reinterpret_cast<std::uint64_t>(selfMbi.AllocationBase);
                const std::uint64_t size = ImageSizeFromBase(selfMbi.AllocationBase);
                if (size != 0)
                {
                    g_PicSr71Range.Base = base;
                    g_PicSr71Range.End = base + size;
                }
            }
        }

        void LogPicAbiObservations() noexcept
        {
            if (InterlockedCompareExchange(&g_PicLegacyAbiObserved, 0, 0) != 0 &&
                InterlockedCompareExchange(&g_PicLegacyAbiLogged, 1, 0) == 0)
            {
                BkDbgLog("ProcessInstrumentationCallback: observed x64 r10/TEB thunk callback ABI");
            }
            if (InterlockedCompareExchange(&g_PicZeroPreviousPcObserved, 0, 0) != 0 &&
                InterlockedCompareExchange(&g_PicZeroPreviousPcLogged, 1, 0) == 0)
            {
                BkDbgLog("ProcessInstrumentationCallback: callback fired without a recoverable previous PC");
            }
        }

        extern "C" __declspec(noinline) void Sr71PicCallbackDispatch(std::uint64_t previousPc, std::uint64_t previousSp,
                                                                     std::uint32_t returnAbi) noexcept
        {
            UNREFERENCED_PARAMETER(returnAbi);
            InterlockedCompareExchange(&g_PicLegacyAbiObserved, 1, 0);

            if (BkSr71IsInternalCall())
            {
                return;
            }

            if (previousPc == 0)
            {
                InterlockedCompareExchange(&g_PicZeroPreviousPcObserved, 1, 0);
                return;
            }

            if (PicAddressIsKnownSystemReturn(previousPc))
            {
                return;
            }

            const LONG sequence = _InterlockedIncrement(&g_PicWriteSequence);
            PicSample &slot = g_PicSamples[sequence & kPicSampleRingMask];
            slot.PreviousPc = previousPc;
            slot.PreviousSp = previousSp;
            slot.ThreadId = __readgsqword(kTebClientIdUniqueThread);
            slot.Sequence = sequence;
        }

        bool BuildPicCallbackStub() noexcept
        {
            if (g_PicStub != nullptr)
            {
                return true;
            }

            void *stub = VirtualAlloc(nullptr, kPicStubAllocationSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (stub == nullptr)
            {
                BkRuntimeReportFault(BkRuntimeFaultCode::ProcessInstrumentationCallbackInstallFailed, GetLastError());
                return false;
            }

            /*
             * x64 PIC enters with r10 holding the original return PC and rsp
             * already pointing at the original user stack. The thunk must seed
             * the TEB previous-PC/SP slots itself before saving registers. This
             * mirrors the standard PIC thunk shape and avoids guessing that the
             * callback stack contains a return frame.
             */
            const std::uint8_t templateBytes[] = {
                0x65, 0x48, 0x89, 0x24, 0x25, 0xE0, 0x02, 0x00, 0x00, 0x65, 0x4C, 0x89, 0x14, 0x25, 0xD8, 0x02, 0x00,
                0x00, 0x49, 0x89, 0xCA, 0x9C, 0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41,
                0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x89, 0xE5, 0x65, 0xC6, 0x04,
                0x25, 0xEC, 0x02, 0x00, 0x00, 0x01, 0x65, 0x48, 0x8B, 0x0C, 0x25, 0xD8, 0x02, 0x00, 0x00, 0x65, 0x48,
                0x8B, 0x14, 0x25, 0xE0, 0x02, 0x00, 0x00, 0x45, 0x31, 0xC0, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC,
                0x20, 0x48, 0xB8, 0,    0,    0,    0,    0,    0,    0,    0,    0xFF, 0xD0, 0x48, 0x89, 0xEC, 0x65,
                0xC6, 0x04, 0x25, 0xEC, 0x02, 0x00, 0x00, 0x00, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41,
                0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58, 0x9D, 0x65, 0x48,
                0x8B, 0x24, 0x25, 0xE0, 0x02, 0x00, 0x00, 0x65, 0xFF, 0x24, 0x25, 0xD8, 0x02, 0x00, 0x00};
            static_assert(sizeof(templateBytes) < kPicStubAllocationSize, "PIC stub must fit in one page.");

            std::memcpy(stub, templateBytes, sizeof(templateBytes));
            *reinterpret_cast<std::uint64_t *>(reinterpret_cast<std::uint8_t *>(stub) + 0x58u) =
                reinterpret_cast<std::uint64_t>(&Sr71PicCallbackDispatch);

            DWORD oldProtect = 0;
            if (!VirtualProtect(stub, kPicStubAllocationSize, PAGE_EXECUTE_READ, &oldProtect))
            {
                DWORD err = GetLastError();
                (void)VirtualFree(stub, 0, MEM_RELEASE);
                BkRuntimeReportFault(BkRuntimeFaultCode::ProcessInstrumentationCallbackInstallFailed, err);
                return false;
            }

            (void)FlushInstructionCache(GetCurrentProcess(), stub, sizeof(templateBytes));
            if (!RegisterControlFlowGuardCallTarget(stub, Sr71CfgCallTargetMode::CfgOnly, "rt.pic"))
            {
                (void)VirtualFree(stub, 0, MEM_RELEASE);
                BkRuntimeReportFault(BkRuntimeFaultCode::ProcessInstrumentationCallbackInstallFailed,
                                     reinterpret_cast<std::uint64_t>(stub));
                return false;
            }
            IC_STACKTRACE::RegisterOwnExecutableRange(stub, kPicStubAllocationSize);
            g_PicStub = stub;
            g_PicStubRange.Base = reinterpret_cast<std::uint64_t>(stub);
            g_PicStubRange.End = g_PicStubRange.Base + kPicStubAllocationSize;
            BkDbgLog("BuildPicCallbackStub: stub=%p dispatch=%p size=0x%lX", g_PicStub,
                     reinterpret_cast<void *>(&Sr71PicCallbackDispatch),
                     static_cast<unsigned long>(sizeof(templateBytes)));
            return true;
        }

        bool RegisterPicProtection() noexcept
        {
            if (InterlockedCompareExchange(&g_PicProtectRegistered, 0, 0) != 0)
            {
                return true;
            }

            const UINT64 callbackAddress = reinterpret_cast<UINT64>(g_PicStub);
            BkDbgLog("RegisterPicProtection: begin callback=0x%llX size=0x%lX",
                     static_cast<unsigned long long>(callbackAddress),
                     static_cast<unsigned long>(kPicStubAllocationSize));
            if (!BKIPC::RegisterInstrumentationRange(callbackAddress, kPicStubAllocationSize,
                                                     BK_INSTRUMENTATION_FLAG_PROCESS_CALLBACK, "rt.pic"))
            {
                BkRuntimeReportFault(BkRuntimeFaultCode::ProcessInstrumentationCallbackProtectFailed, callbackAddress,
                                     kPicStubAllocationSize);
                return false;
            }

            if (!BKIPC::RegisterProcessInstrumentationCallback(callbackAddress, kPicStubAllocationSize,
                                                               BK_PROCESS_INSTRUMENTATION_CALLBACK_FLAG_X64 |
                                                                   BK_PROCESS_INSTRUMENTATION_CALLBACK_FLAG_SR71))
            {
                BkRuntimeReportFault(BkRuntimeFaultCode::ProcessInstrumentationCallbackProtectFailed, callbackAddress,
                                     kPicStubAllocationSize);
                return false;
            }

            InterlockedExchange(&g_PicProtectRegistered, 1);
            BkDbgLog("RegisterPicProtection: registered callback=0x%llX size=0x%lX",
                     static_cast<unsigned long long>(callbackAddress),
                     static_cast<unsigned long>(kPicStubAllocationSize));
            return true;
        }

        bool PublishPicDirectSyscallSample(const PicSample &sample, const MEMORY_BASIC_INFORMATION &mbi,
                                           ULONG protect) noexcept
        {
            BKIPC_HOOK_EVENT record{};
            record.Kind = BlackbirdIpcHookEventIntegrity;
            record.ProcessId = GetCurrentProcessId();
            record.ThreadId = static_cast<UINT32>(sample.ThreadId & 0xFFFFFFFFull);
            record.Operation = BK_HOOK_EVENT_OP_PIC_DIRECT_SYSCALL;
            record.Caller = sample.PreviousPc;
            record.Context0 = sample.PreviousPc;
            record.Context1 = sample.PreviousSp;
            record.Context2 = protect;
            record.Context3 = static_cast<UINT64>(InterlockedCompareExchange(&g_PicDroppedSamples, 0, 0));
            record.ArgCount = 4;
            record.Args[0] = sample.ThreadId;
            record.Args[1] = reinterpret_cast<UINT64>(mbi.AllocationBase);
            record.Args[2] = static_cast<UINT64>(mbi.RegionSize);
            record.Args[3] = sample.PreviousSp;
            record.CallerFlags =
                (BK_HOOK_COMPONENT_INTEGRITY << BK_HOOK_CALLER_COMPONENT_SHIFT) |
                ((mbi.Type == MEM_IMAGE ? BK_HOOK_CALLER_KIND_NONSYSTEM_DLL : BK_HOOK_CALLER_KIND_UNMAPPED)
                 << BK_HOOK_CALLER_IMMED_SHIFT);
            (void)StringCchCopyA(record.ApiName, RTL_NUMBER_OF(record.ApiName), "ProcessInstrumentationCallback");
            (void)StringCchCopyA(record.ModuleName, RTL_NUMBER_OF(record.ModuleName), "Runtime");
            return BKIPC::PublishHookEvent(record);
        }

        bool PicProtectIsExecutable(ULONG protect) noexcept
        {
            protect &= 0xFFu;
            return protect == PAGE_EXECUTE || protect == PAGE_EXECUTE_READ || protect == PAGE_EXECUTE_READWRITE ||
                   protect == PAGE_EXECUTE_WRITECOPY;
        }
#endif
    } // namespace

    bool EnsureProcessInstrumentationCallbackInstalled(bool allowInstallNow) noexcept
    {
#if defined(_M_X64)
        UNREFERENCED_PARAMETER(allowInstallNow);
        if (kPicRuntimeDisabledForTest)
        {
            if (InterlockedCompareExchange(&g_PicDisabledLogged, 1, 0) == 0)
            {
                BkDbgLog("EnsureProcessInstrumentationCallbackInstalled: disabled for stability test");
            }
            return false;
        }

        if (InterlockedCompareExchange(&g_PicInstallState, 0, 0) == 2)
        {
            return true;
        }
        if (!allowInstallNow)
        {
            return false;
        }

        LONG expected = 0;
        if (InterlockedCompareExchange(&g_PicInstallState, 1, expected) != expected)
        {
            return false;
        }

        BkDbgLog("EnsureProcessInstrumentationCallbackInstalled: begin allowInstallNow=%u", allowInstallNow ? 1u : 0u);
        RefreshPicKnownRanges();

        bool ok = false;
        __try
        {
            if (!BuildPicCallbackStub() || !RegisterPicProtection())
            {
                ok = false;
            }
            else
            {
                auto ntSetInformationProcess = ResolveNtdllExport<NtSetInformationProcessFn>("NtSetInformationProcess");
                if (ntSetInformationProcess == nullptr)
                {
                    BkRuntimeReportFault(BkRuntimeFaultCode::ProcessInstrumentationCallbackInstallFailed, 0);
                    ok = false;
                }
                else
                {
                    ProcessInstrumentationCallbackInformation info{};
                    info.Version = kProcessInstrumentationCallbackVersion;
                    info.Callback = g_PicStub;

                    BkDbgLog("EnsureProcessInstrumentationCallbackInstalled: installing callback=%p", g_PicStub);
                    const NTSTATUS status = ntSetInformationProcess(
                        CurrentProcessHandle(), kProcessInstrumentationCallbackClass, &info, sizeof(info));
                    ok = NtSucceeded(status);
                    BkDbgLog("EnsureProcessInstrumentationCallbackInstalled: NtSetInformationProcess status=0x%08lX",
                             static_cast<unsigned long>(status));
                    if (!ok)
                    {
                        BkRuntimeReportFault(BkRuntimeFaultCode::ProcessInstrumentationCallbackInstallFailed,
                                             static_cast<std::uint32_t>(status),
                                             reinterpret_cast<std::uint64_t>(g_PicStub));
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            BkRuntimeReportFault(BkRuntimeFaultCode::ProcessInstrumentationCallbackInstallFailed, GetExceptionCode());
            ok = false;
        }

        InterlockedExchange(&g_PicInstallState, ok ? 2 : 0);
        if (ok)
        {
            BkDbgLog("EnsureProcessInstrumentationCallbackInstalled: callback=%p", g_PicStub);
        }
        LogPicAbiObservations();
        return ok;
#else
        UNREFERENCED_PARAMETER(allowInstallNow);
        return false;
#endif
    }

    void FlushProcessInstrumentationCallbackSamples() noexcept
    {
#if defined(_M_X64)
        if (kPicRuntimeDisabledForTest)
        {
            return;
        }

        LogPicAbiObservations();
        RefreshPicKnownRanges();

        const LONG writeSequence = InterlockedCompareExchange(&g_PicWriteSequence, 0, 0);
        LONG readSequence = InterlockedCompareExchange(&g_PicReadSequence, 0, 0);
        if (writeSequence - readSequence > static_cast<LONG>(RTL_NUMBER_OF(g_PicSamples)))
        {
            const LONG dropped = writeSequence - readSequence - static_cast<LONG>(RTL_NUMBER_OF(g_PicSamples));
            InterlockedExchangeAdd(&g_PicDroppedSamples, dropped);
            readSequence = writeSequence - static_cast<LONG>(RTL_NUMBER_OF(g_PicSamples));
        }

        while (readSequence < writeSequence)
        {
            readSequence += 1;
            PicSample sample = g_PicSamples[readSequence & kPicSampleRingMask];
            if (sample.Sequence != readSequence || sample.PreviousPc == 0 ||
                PicAddressIsKnownSystemReturn(sample.PreviousPc))
            {
                continue;
            }

            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<const void *>(sample.PreviousPc), &mbi, sizeof(mbi)) != sizeof(mbi))
            {
                continue;
            }

            if (mbi.Type == MEM_IMAGE || !PicProtectIsExecutable(mbi.Protect))
            {
                continue;
            }

            const ULONGLONG now = GetTickCount64();
            if (now - g_PicLastPublishTick < kPicPublishMinIntervalMs)
            {
                continue;
            }

            if (PublishPicDirectSyscallSample(sample, mbi, mbi.Protect))
            {
                g_PicLastPublishTick = now;
            }
        }

        InterlockedExchange(&g_PicReadSequence, writeSequence);
#endif
    }

    void ResetProcessInstrumentationCallbackState() noexcept
    {
#if defined(_M_X64)
        InterlockedExchange(&g_PicInstallState, 0);
        InterlockedExchange(&g_PicProtectRegistered, 0);
        InterlockedExchange(&g_PicWriteSequence, 0);
        InterlockedExchange(&g_PicReadSequence, 0);
        InterlockedExchange(&g_PicDroppedSamples, 0);
        InterlockedExchange(&g_PicLegacyAbiObserved, 0);
        InterlockedExchange(&g_PicZeroPreviousPcObserved, 0);
        InterlockedExchange(&g_PicLegacyAbiLogged, 0);
        InterlockedExchange(&g_PicZeroPreviousPcLogged, 0);
        InterlockedExchange(&g_PicDisabledLogged, 0);
        g_PicLastPublishTick = 0;
        g_PicStub = nullptr;
        g_PicStubRange = {};
#endif
    }
} // namespace BK_RUNTIME_INTERNAL
