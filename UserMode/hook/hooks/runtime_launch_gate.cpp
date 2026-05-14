#include "runtime_private.h"

#include <strsafe.h>
#include <cstring>

namespace BK_RUNTIME_INTERNAL
{
    enum LaunchGateTrapKind : std::uint32_t
    {
        LaunchGateTrapEntryPoint = 1,
        LaunchGateTrapTlsCallback = 2
    };

    const char *LaunchGateTrapTag(std::uint32_t kind) noexcept
    {
        return (kind == LaunchGateTrapTlsCallback) ? "rt.tls" : "rt.entry";
    }

    const char *LaunchGateTrapApiName(std::uint32_t kind) noexcept
    {
        return (kind == LaunchGateTrapTlsCallback) ? "TlsCallbackTrap" : "LaunchGateEntryTrap";
    }

    std::uint32_t LaunchGateTrapOperation(std::uint32_t kind) noexcept
    {
        return (kind == LaunchGateTrapTlsCallback) ? BK_HOOK_EVENT_OP_LAUNCH_GATE_TLS_CALLBACK
                                                   : BK_HOOK_EVENT_OP_LAUNCH_GATE_ENTRY;
    }

    void PublishLaunchGateTrapEvent(const LaunchGateParkContext &park) noexcept
    {
        if (park.TrapAddress == nullptr)
        {
            return;
        }

        BKIPC_HOOK_EVENT record{};
        record.Kind = BlackbirdIpcHookEventIntegrity;
        record.ProcessId = GetCurrentProcessId();
        record.ThreadId = park.ThreadId != 0 ? park.ThreadId : GetCurrentThreadId();
        record.Operation = LaunchGateTrapOperation(park.TrapKind);
        record.Caller = reinterpret_cast<std::uint64_t>(park.TrapAddress);
        record.Context0 = reinterpret_cast<std::uint64_t>(park.TrapAddress);
        record.Context1 = reinterpret_cast<std::uint64_t>(park.TrapPage);
        record.Context2 = park.TrapKind;
        record.Context3 = park.TrapIndex;
        record.ArgCount = 3;
        record.Args[0] = static_cast<std::uint64_t>(GetTickCount64());
        record.Args[1] = reinterpret_cast<std::uint64_t>(park.TrapPage);
        record.Args[2] = park.TrapIndex;
        record.CallerFlags =
            ((BK_HOOK_COMPONENT_INTEGRITY << BK_HOOK_CALLER_COMPONENT_SHIFT) & BK_HOOK_CALLER_COMPONENT_MASK);
        (void)strncpy_s(record.ApiName, LaunchGateTrapApiName(park.TrapKind), _TRUNCATE);
        (void)strncpy_s(record.ModuleName, "Runtime", _TRUNCATE);

        BkSr71InternalScope scope;
        (void)BKIPC::PublishHookEvent(record);
    }

    bool ShouldDeferLaunchGateOpen() noexcept
    {
        char value[8]{};
        static constexpr Sr71EncodedAnsiLiteral kEnvName{"BK_HOOK_LAUNCH_GATE_DEFER_OPEN", 0x99u};
        Sr71ScopedAnsiLiteral envName(kEnvName);
        DWORD read = GetEnvironmentVariableA(envName.c_str(), value, (DWORD)RTL_NUMBER_OF(value));
        if (read == 0 || read >= RTL_NUMBER_OF(value))
        {
            return false;
        }

        return (value[0] == '1' || value[0] == 'y' || value[0] == 'Y' || value[0] == 't' || value[0] == 'T');
    }

    bool BuildLaunchGateDeferredEventName(_Out_writes_z_(MAX_PATH) wchar_t *buffer, size_t cchBuffer) noexcept
    {
        if (buffer == nullptr || cchBuffer == 0)
        {
            return false;
        }

        static constexpr Sr71EncodedWideLiteral kEnvName{L"BK_HOOK_LAUNCH_GATE_EVENT", 0x1A9u};
        Sr71ScopedWideLiteral envName(kEnvName);
        DWORD envRead = GetEnvironmentVariableW(envName.c_str(), buffer, (DWORD)cchBuffer);
        if (envRead > 0 && envRead < cchBuffer)
        {
            BkDbgLog("BuildLaunchGateDeferredEventName: using controller-provided name=%ls", buffer);
            return true;
        }

        BkDbgLog("BuildLaunchGateDeferredEventName: missing controller-provided event name envRead=%lu gle=%lu",
                 static_cast<unsigned long>(envRead), static_cast<unsigned long>(GetLastError()));
        buffer[0] = L'\0';
        return false;
    }

    void *AlignLaunchGatePage(void *address) noexcept
    {
        ULONG_PTR value = reinterpret_cast<ULONG_PTR>(address);
        return reinterpret_cast<void *>(value & ~static_cast<ULONG_PTR>(kLaunchGatePageSize - 1u));
    }

    void *ResolveLaunchGatePageBase(const LaunchGatePage &page) noexcept
    {
        Sr71IhrResolved resolved{};
        if (!ResolveIndirectHandle(page.BaseToken, Sr71IhrType::LaunchGatePage, resolved))
        {
            return nullptr;
        }
        return resolved.Pointer;
    }

    bool IsLaunchGatePageArmed(void *address) noexcept
    {
        void *pageBase = AlignLaunchGatePage(address);
        for (std::uint32_t i = 0; i < g_LaunchGatePageCount; ++i)
        {
            if (ResolveLaunchGatePageBase(g_LaunchGatePages[i]) == pageBase)
            {
                return true;
            }
        }
        return false;
    }

    bool ArmLaunchGatePage(void *address, std::uint32_t kind, std::uint32_t index) noexcept
    {
        if (address == nullptr)
        {
            BkDbgLog("ArmLaunchGatePage: null address");
            return false;
        }

        void *pageBase = AlignLaunchGatePage(address);
        if (pageBase == nullptr)
        {
            BkDbgLog("ArmLaunchGatePage: null page base address=%p", address);
            return false;
        }

        for (std::uint32_t i = 0; i < g_LaunchGatePageCount; ++i)
        {
            if (ResolveLaunchGatePageBase(g_LaunchGatePages[i]) == pageBase)
            {
                if (kind == LaunchGateTrapTlsCallback && g_LaunchGatePages[i].TrapKind != LaunchGateTrapTlsCallback)
                {
                    g_LaunchGatePages[i].TrapAddress = address;
                    g_LaunchGatePages[i].TrapKind = kind;
                    g_LaunchGatePages[i].TrapIndex = index;
                }
                BkDbgLog("ArmLaunchGatePage: already armed address=%p page=%p kind=%lu index=%lu", address, pageBase,
                         static_cast<unsigned long>(kind), static_cast<unsigned long>(index));
                return true;
            }
        }

        if (g_LaunchGatePageCount >= kLaunchGateMaxPages)
        {
            BkDbgLog("ArmLaunchGatePage: page capacity reached address=%p page=%p count=%lu", address, pageBase,
                     static_cast<unsigned long>(g_LaunchGatePageCount));
            return false;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        if (!NativeQueryMemory(pageBase, &mbi) || mbi.State != MEM_COMMIT)
        {
            BkDbgLog("ArmLaunchGatePage: query/commit failed address=%p page=%p state=0x%08lX gle=%lu", address,
                     pageBase, static_cast<unsigned long>(mbi.State), static_cast<unsigned long>(GetLastError()));
            return false;
        }

        DWORD baseProtect = mbi.Protect & ~PAGE_GUARD;
        if (baseProtect == 0 || baseProtect == PAGE_NOACCESS)
        {
            BkDbgLog("ArmLaunchGatePage: unusable protection address=%p page=%p protect=0x%08lX", address, pageBase,
                     static_cast<unsigned long>(mbi.Protect));
            return false;
        }

        ULONG oldProtect = 0;
        if (!NativeProtect(pageBase, kLaunchGatePageSize, baseProtect | PAGE_GUARD, &oldProtect))
        {
            BkDbgLog("ArmLaunchGatePage: protect failed address=%p page=%p baseProtect=0x%08lX gle=%lu", address,
                     pageBase, static_cast<unsigned long>(baseProtect), static_cast<unsigned long>(GetLastError()));
            return false;
        }

        Sr71IhrToken pageToken = RegisterIndirectHandle(
            pageBase, kLaunchGatePageSize, Sr71IhrType::LaunchGatePage,
            kSr71IhrFlagExecutable | kSr71IhrFlagSr71Owned | kSr71IhrFlagGuarded, LaunchGateTrapTag(kind));
        if (pageToken == 0)
        {
            ULONG ignored = 0;
            (void)NativeProtect(pageBase, kLaunchGatePageSize, baseProtect, &ignored);
            BkDbgLog("ArmLaunchGatePage: IHR token registration failed address=%p page=%p", address, pageBase);
            return false;
        }

        g_LaunchGatePages[g_LaunchGatePageCount].BaseToken = pageToken;
        g_LaunchGatePages[g_LaunchGatePageCount].OriginalProtect = baseProtect;
        g_LaunchGatePages[g_LaunchGatePageCount].TrapAddress = address;
        g_LaunchGatePages[g_LaunchGatePageCount].TrapKind = kind;
        g_LaunchGatePages[g_LaunchGatePageCount].TrapIndex = index;
        g_LaunchGatePageCount += 1;
        BkDbgLog(
            "ArmLaunchGatePage: armed address=%p page=%p kind=%lu index=%lu protect=0x%08lX oldProtect=0x%08lX token=0x%llX count=%lu",
            address, pageBase, static_cast<unsigned long>(kind), static_cast<unsigned long>(index),
            static_cast<unsigned long>(baseProtect), static_cast<unsigned long>(oldProtect),
            static_cast<unsigned long long>(pageToken), static_cast<unsigned long>(g_LaunchGatePageCount));
        return true;
    }

    void RestoreLaunchGatePages() noexcept
    {
        for (std::uint32_t i = 0; i < g_LaunchGatePageCount; ++i)
        {
            void *pageBase = ResolveLaunchGatePageBase(g_LaunchGatePages[i]);
            if (pageBase == nullptr || g_LaunchGatePages[i].OriginalProtect == 0)
            {
                continue;
            }

            ULONG ignored = 0;
            (void)NativeProtect(pageBase, kLaunchGatePageSize, g_LaunchGatePages[i].OriginalProtect, &ignored);
        }
    }

    void SanitizeLaunchGateRestoreContext(_Inout_ CONTEXT &context) noexcept
    {
#if defined(_M_X64)
        context.ContextFlags = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER;
        context.Dr0 = 0;
        context.Dr1 = 0;
        context.Dr2 = 0;
        context.Dr3 = 0;
        context.Dr6 = 0;
        context.Dr7 = 0;
        context.EFlags &= ~0x100u;
#endif
    }

    [[noreturn]] void ResumeOriginalThread(_Inout_ LaunchGateParkContext *park, _In_ const char *source) noexcept
    {
        UNREFERENCED_PARAMETER(source);

        CONTEXT context{};
        NtContinueFn ntContinue = ResolveNtdllExport<NtContinueFn>("NtContinue");
        RtlRestoreContextFn restore = ResolveNtdllExport<RtlRestoreContextFn>("RtlRestoreContext");

        if (park == nullptr)
        {
            BkRuntimeReportFault(BkRuntimeFaultCode::LaunchGateResumeRejected);
            BkRuntimeFailClosed(ERROR_INVALID_PARAMETER);
        }

        context = park->Context;
        park->State = 0;
        SanitizeLaunchGateRestoreContext(context);

        if (ntContinue != nullptr)
        {
            NTSTATUS status = ntContinue(&context, FALSE);
            BkRuntimeReportFault(BkRuntimeFaultCode::LaunchGateResumeRejected, static_cast<std::uint32_t>(status),
                                 context.ContextFlags);
        }

        if (restore != nullptr)
        {
            restore(&context, nullptr);
        }

        BkRuntimeReportFault(BkRuntimeFaultCode::LaunchGateResumeRejected, context.Rip, context.Rsp);
        BkRuntimeFailClosed(ERROR_INVALID_STATE);
    }

    __declspec(noinline) void WINAPI LaunchGateParkThunk(void *parameter) noexcept
    {
        auto *park = static_cast<LaunchGateParkContext *>(parameter);
        if (g_LaunchGateReadyEvent != nullptr)
        {
            (void)NativeWaitForSingleObject(g_LaunchGateReadyEvent);
        }
        PublishLaunchGateTrapEvent(*park);

        if (g_LaunchGateDeferredOpen.load(std::memory_order_acquire))
        {
            bool expected = false;
            if (g_LaunchGateReady.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
            {
                RestoreLaunchGatePages();
            }
        }

        ResumeOriginalThread(park, "LaunchGateParkThunk");
    }

    __declspec(noinline) void WINAPI LaunchGateInitializeThunk(void *parameter) noexcept
    {
        auto *park = static_cast<LaunchGateParkContext *>(parameter);
        const bool deferredOpen = g_LaunchGateDeferredOpen.load(std::memory_order_acquire);

        if (g_LaunchGateCallbacks.InitializeRuntime == nullptr ||
            !g_LaunchGateCallbacks.InitializeRuntime(false, false))
        {
            BkRuntimeReportFault(BkRuntimeFaultCode::RuntimeInitializeFailed);
            if (g_LaunchGateCallbacks.FailClosed != nullptr)
            {
                g_LaunchGateCallbacks.FailClosed(WAIT_TIMEOUT);
            }
            BkRuntimeFailClosed(WAIT_TIMEOUT);
        }

        if (park->TrapKind == LaunchGateTrapEntryPoint)
        {
            (void)EnsureProcessInstrumentationCallbackInstalled(true);
        }
        PublishLaunchGateTrapEvent(*park);

        if (deferredOpen)
        {
            if (g_LaunchGateReadyEvent != nullptr)
            {
                (void)NativeWaitForSingleObject(g_LaunchGateReadyEvent);
            }

            bool expected = false;
            if (g_LaunchGateReady.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
            {
                RestoreLaunchGatePages();
            }
        }
        else
        {
            LaunchGateRelease();
        }

        if (!EnsureRuntimeWorkerThreadStarted())
        {
            BkDbgLog("LaunchGateInitializeThunk: worker start deferred");
        }

        ResumeOriginalThread(park, "LaunchGateInitializeThunk");
    }

    LaunchGateParkContext *AcquireLaunchGateParkContext() noexcept
    {
        for (std::size_t i = 0; i < RTL_NUMBER_OF(g_LaunchGateParkContexts); ++i)
        {
            auto *park = &g_LaunchGateParkContexts[i];
            if (InterlockedCompareExchange(&park->State, 1, 0) == 0)
            {
                park->ThreadId = GetCurrentThreadId();
                return park;
            }
        }
        return nullptr;
    }

    bool ArmLaunchGateForProcessEntry() noexcept
    {
        void *processModule = FindProcessImageBase();
        if (processModule == nullptr)
        {
            BkDbgLog("ArmLaunchGateForProcessEntry: process image base not found");
            return false;
        }

        const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(processModule);
        if (dos == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            BkDbgLog("ArmLaunchGateForProcessEntry: invalid DOS header image=%p magic=0x%04X", processModule,
                     dos != nullptr ? dos->e_magic : 0u);
            return false;
        }

        const auto *ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(
            reinterpret_cast<const std::uint8_t *>(processModule) + static_cast<std::size_t>(dos->e_lfanew));
        if (ntHeaders == nullptr || ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            BkDbgLog("ArmLaunchGateForProcessEntry: invalid NT headers image=%p e_lfanew=0x%lX signature=0x%08lX",
                     processModule, static_cast<unsigned long>(dos->e_lfanew),
                     ntHeaders != nullptr ? static_cast<unsigned long>(ntHeaders->Signature) : 0ul);
            return false;
        }

        bool armedAny = false;
        BkDbgLog(
            "ArmLaunchGateForProcessEntry: image=%p entryRva=0x%lX tlsRva=0x%lX tlsSize=0x%lX", processModule,
            static_cast<unsigned long>(ntHeaders->OptionalHeader.AddressOfEntryPoint),
            ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS
                ? static_cast<unsigned long>(
                      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
                : 0ul,
            ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS
                ? static_cast<unsigned long>(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
                : 0ul);
        if (ntHeaders->OptionalHeader.AddressOfEntryPoint != 0)
        {
            armedAny |= ArmLaunchGatePage(reinterpret_cast<void *>(reinterpret_cast<ULONG_PTR>(processModule) +
                                                                   ntHeaders->OptionalHeader.AddressOfEntryPoint),
                                          LaunchGateTrapEntryPoint, 0);
        }

#ifdef _WIN64
        if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
            ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS)
        {
            const IMAGE_DATA_DIRECTORY &tlsDirectory =
                ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            if (tlsDirectory.VirtualAddress != 0 && tlsDirectory.Size >= sizeof(IMAGE_TLS_DIRECTORY64))
            {
                __try
                {
                    const auto *tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY64 *>(
                        reinterpret_cast<const std::uint8_t *>(processModule) + tlsDirectory.VirtualAddress);
                    auto **callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK *>(tls->AddressOfCallBacks);
                    if (callbacks != nullptr)
                    {
                        std::size_t tlsCallbackCount = 0;
                        for (std::size_t i = 0; i < kLaunchGateMaxPages && callbacks[i] != nullptr; ++i)
                        {
                            tlsCallbackCount += 1;
                            BkDbgLog("ArmLaunchGateForProcessEntry: TLS callback[%zu]=%p", i,
                                     reinterpret_cast<void *>(callbacks[i]));
                            armedAny |= ArmLaunchGatePage(reinterpret_cast<void *>(callbacks[i]),
                                                          LaunchGateTrapTlsCallback, static_cast<std::uint32_t>(i));
                        }
                        BkDbgLog("ArmLaunchGateForProcessEntry: TLS callbacks armed=%zu", tlsCallbackCount);
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    BkDbgLog("ArmLaunchGateForProcessEntry: TLS callback probe exception=0x%08lX",
                             static_cast<unsigned long>(GetExceptionCode()));
                }
            }
        }
#endif

        BkDbgLog("ArmLaunchGateForProcessEntry: armedAny=%u count=%lu", armedAny ? 1u : 0u,
                 static_cast<unsigned long>(g_LaunchGatePageCount));
        return armedAny;
    }

    bool LaunchGatePrepare() noexcept
    {
        bool expected = false;
        if (!g_LaunchGatePrepared.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        {
            return true;
        }

        g_LaunchGateDeferredOpen.store(ShouldDeferLaunchGateOpen(), std::memory_order_release);
        if (g_LaunchGateReadyEvent == nullptr)
        {
            if (g_LaunchGateDeferredOpen.load(std::memory_order_acquire))
            {
                wchar_t eventName[MAX_PATH]{};
                if (!BuildLaunchGateDeferredEventName(eventName, RTL_NUMBER_OF(eventName)))
                {
                    BkRuntimeReportFault(BkRuntimeFaultCode::LaunchGateDeferredEventNameFailed);
                    g_LaunchGatePrepared.store(false, std::memory_order_release);
                    return false;
                }

                g_LaunchGateReadyEvent = NativeCreateEvent(true, false, eventName, SYNCHRONIZE);
            }
            else
            {
                g_LaunchGateReadyEvent = NativeCreateEvent(true, false);
            }

            if (g_LaunchGateReadyEvent == nullptr)
            {
                BkRuntimeReportFault(BkRuntimeFaultCode::LaunchGateReadyEventCreateFailed, GetLastError());
                g_LaunchGatePrepared.store(false, std::memory_order_release);
                return false;
            }
        }

        g_LaunchGateReady.store(false, std::memory_order_release);
        g_LaunchGatePageCount = 0;
        g_LaunchGateInitializerAssigned = 0;

        if (!ArmLaunchGateForProcessEntry())
        {
            RestoreLaunchGatePages();
            g_LaunchGatePageCount = 0;
            g_LaunchGatePrepared.store(false, std::memory_order_release);
            BkRuntimeReportFault(BkRuntimeFaultCode::LaunchGatePrepareFailed);
            BkDbgLog("LaunchGatePrepare: failed to arm any launch-gate pages");
            return false;
        }

        BkDbgLog("LaunchGatePrepare: prepared count=%lu deferredOpen=%u",
                 static_cast<unsigned long>(g_LaunchGatePageCount),
                 g_LaunchGateDeferredOpen.load(std::memory_order_acquire) ? 1u : 0u);
        return true;
    }

    void LaunchGateRelease() noexcept
    {
        if (!g_LaunchGatePrepared.load(std::memory_order_acquire))
        {
            return;
        }

        if (g_LaunchGateDeferredOpen.load(std::memory_order_acquire))
        {
            return;
        }

        g_LaunchGateReady.store(true, std::memory_order_release);
        RestoreLaunchGatePages();
        if (g_LaunchGateReadyEvent != nullptr)
        {
            (void)NativeSetEvent(g_LaunchGateReadyEvent);
        }
    }

    bool LaunchGateHandleFault(EXCEPTION_POINTERS *ep) noexcept
    {
        if (!g_LaunchGatePrepared.load(std::memory_order_acquire) ||
            g_LaunchGateReady.load(std::memory_order_acquire) || ep == nullptr || ep->ExceptionRecord == nullptr ||
            ep->ContextRecord == nullptr || ep->ExceptionRecord->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION)
        {
            return false;
        }

#if defined(_M_X64)
        void *faultAddress = ep->ExceptionRecord->ExceptionAddress;
        if (ep->ExceptionRecord->NumberParameters >= 2 && ep->ExceptionRecord->ExceptionInformation[1] != 0)
        {
            faultAddress = reinterpret_cast<void *>(ep->ExceptionRecord->ExceptionInformation[1]);
        }

        if (!IsLaunchGatePageArmed(faultAddress))
        {
            return false;
        }

        BkDbgLog("LaunchGateHandleFault: fault=%p exception=%p", faultAddress, ep->ExceptionRecord->ExceptionAddress);

        void *pageBase = AlignLaunchGatePage(faultAddress);
        LaunchGatePage *matchedPage = nullptr;
        for (std::uint32_t i = 0; i < g_LaunchGatePageCount; ++i)
        {
            if (ResolveLaunchGatePageBase(g_LaunchGatePages[i]) == pageBase &&
                g_LaunchGatePages[i].OriginalProtect != 0)
            {
                matchedPage = &g_LaunchGatePages[i];
                ULONG ignored = 0;
                (void)NativeProtect(pageBase, kLaunchGatePageSize, g_LaunchGatePages[i].OriginalProtect | PAGE_GUARD,
                                    &ignored);
                break;
            }
        }

        LaunchGateParkContext *park = AcquireLaunchGateParkContext();
        if (park == nullptr)
        {
            BkDbgLog("LaunchGateHandleFault: no park slots available");
            BkRuntimeReportFault(BkRuntimeFaultCode::LaunchGateNoParkSlot);
            return false;
        }

        ULONG_PTR thunkRsp = (ep->ContextRecord->Rsp - 0x28ull) & ~static_cast<ULONG_PTR>(0x0full);
        thunkRsp |= 0x8ull;
        if (thunkRsp > (ep->ContextRecord->Rsp - 0x28ull))
        {
            thunkRsp -= 0x10ull;
        }

        __try
        {
            park->Context = *ep->ContextRecord;
            park->ThreadId = GetCurrentThreadId();
            park->InitializeRuntime = (InterlockedCompareExchange(&g_LaunchGateInitializerAssigned, 1, 0) == 0) ? 1 : 0;
            park->TrapAddress = (matchedPage != nullptr && matchedPage->TrapAddress != nullptr)
                                    ? matchedPage->TrapAddress
                                    : faultAddress;
            park->TrapPage = pageBase;
            park->TrapKind = matchedPage != nullptr ? matchedPage->TrapKind : LaunchGateTrapEntryPoint;
            park->TrapIndex = matchedPage != nullptr ? matchedPage->TrapIndex : 0;
            *reinterpret_cast<ULONG_PTR *>(thunkRsp) = 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            park->State = 0;
            BkDbgLog("LaunchGateHandleFault: failed to stage park context");
            BkRuntimeReportFault(BkRuntimeFaultCode::LaunchGateContextStageFailed, GetExceptionCode());
            return false;
        }

        ep->ContextRecord->Rsp = thunkRsp;
        ep->ContextRecord->Rip =
            reinterpret_cast<DWORD64>(park->InitializeRuntime ? &LaunchGateInitializeThunk : &LaunchGateParkThunk);
        ep->ContextRecord->Rcx = reinterpret_cast<DWORD64>(park);
        BkDbgLog("LaunchGateHandleFault: redirected park=%p slotTid=%lu init=%ld newRip=%p newRsp=%p", park,
                 (unsigned long)park->ThreadId, park->InitializeRuntime,
                 reinterpret_cast<void *>(ep->ContextRecord->Rip), reinterpret_cast<void *>(ep->ContextRecord->Rsp));
        return true;
#else
        UNREFERENCED_PARAMETER(ep);
        return false;
#endif
    }

    void LaunchGateShutdown() noexcept
    {
        LaunchGateRelease();
        if (g_LaunchGateReadyEvent != nullptr)
        {
            NativeCloseHandle(g_LaunchGateReadyEvent);
            g_LaunchGateReadyEvent = nullptr;
        }

        RestoreLaunchGatePages();
        g_LaunchGatePageCount = 0;
        g_LaunchGateInitializerAssigned = 0;
        g_LaunchGatePrepared.store(false, std::memory_order_release);
        g_LaunchGateReady.store(false, std::memory_order_release);
        g_LaunchGateDeferredOpen.store(false, std::memory_order_release);
        for (auto &park : g_LaunchGateParkContexts)
        {
            park = {};
        }
        ResetIndirectHandles();
    }

    bool LaunchGateIsPrepared() noexcept
    {
        return g_LaunchGatePrepared.load(std::memory_order_acquire);
    }
} // namespace BK_RUNTIME_INTERNAL
