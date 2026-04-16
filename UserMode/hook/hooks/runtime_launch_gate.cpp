#include "runtime_private.h"

#include <strsafe.h>
#include <cstring>

namespace BK_RUNTIME_INTERNAL
{
    bool ShouldDeferLaunchGateOpen() noexcept
    {
        char value[8]{};
        DWORD read =
            GetEnvironmentVariableA("BLACKBIRD_HOOK_LAUNCH_GATE_DEFER_OPEN", value, (DWORD)RTL_NUMBER_OF(value));
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

        return SUCCEEDED(StringCchPrintfW(buffer, cchBuffer, L"%s%lu", kLaunchGateDeferredEventPrefix,
                                          (unsigned long)GetCurrentProcessId()));
    }

    void *AlignLaunchGatePage(void *address) noexcept
    {
        ULONG_PTR value = reinterpret_cast<ULONG_PTR>(address);
        return reinterpret_cast<void *>(value & ~static_cast<ULONG_PTR>(kLaunchGatePageSize - 1u));
    }

    bool IsLaunchGatePageArmed(void *address) noexcept
    {
        void *pageBase = AlignLaunchGatePage(address);
        for (std::uint32_t i = 0; i < g_LaunchGatePageCount; ++i)
        {
            if (g_LaunchGatePages[i].Base == pageBase)
            {
                return true;
            }
        }
        return false;
    }

    bool ArmLaunchGatePage(void *address) noexcept
    {
        if (address == nullptr)
        {
            return false;
        }

        void *pageBase = AlignLaunchGatePage(address);
        if (pageBase == nullptr)
        {
            return false;
        }

        for (std::uint32_t i = 0; i < g_LaunchGatePageCount; ++i)
        {
            if (g_LaunchGatePages[i].Base == pageBase)
            {
                return true;
            }
        }

        if (g_LaunchGatePageCount >= kLaunchGateMaxPages)
        {
            return false;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        if (!NativeQueryMemory(pageBase, &mbi) || mbi.State != MEM_COMMIT)
        {
            return false;
        }

        DWORD baseProtect = mbi.Protect & ~PAGE_GUARD;
        if (baseProtect == 0 || baseProtect == PAGE_NOACCESS)
        {
            return false;
        }

        ULONG oldProtect = 0;
        if (!NativeProtect(pageBase, kLaunchGatePageSize, baseProtect | PAGE_GUARD, &oldProtect))
        {
            return false;
        }

        g_LaunchGatePages[g_LaunchGatePageCount].Base = pageBase;
        g_LaunchGatePages[g_LaunchGatePageCount].OriginalProtect = baseProtect;
        g_LaunchGatePageCount += 1;
        return true;
    }

    void RestoreLaunchGatePages() noexcept
    {
        for (std::uint32_t i = 0; i < g_LaunchGatePageCount; ++i)
        {
            if (g_LaunchGatePages[i].Base == nullptr || g_LaunchGatePages[i].OriginalProtect == 0)
            {
                continue;
            }

            ULONG ignored = 0;
            (void)NativeProtect(g_LaunchGatePages[i].Base, kLaunchGatePageSize, g_LaunchGatePages[i].OriginalProtect,
                                &ignored);
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

        if (g_LaunchGateCallbacks.InitializeRuntime == nullptr ||
            !g_LaunchGateCallbacks.InitializeRuntime(!g_LaunchGateDeferredOpen.load(std::memory_order_acquire), true))
        {
            BkRuntimeReportFault(BkRuntimeFaultCode::RuntimeInitializeFailed);
            if (g_LaunchGateCallbacks.FailClosed != nullptr)
            {
                g_LaunchGateCallbacks.FailClosed(WAIT_TIMEOUT);
            }
            BkRuntimeFailClosed(WAIT_TIMEOUT);
        }

        if (g_LaunchGateDeferredOpen.load(std::memory_order_acquire))
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
            return false;
        }

        const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(processModule);
        if (dos == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }

        const auto *ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(
            reinterpret_cast<const std::uint8_t *>(processModule) + static_cast<std::size_t>(dos->e_lfanew));
        if (ntHeaders == nullptr || ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            return false;
        }

        bool armedAny = false;
        if (ntHeaders->OptionalHeader.AddressOfEntryPoint != 0)
        {
            armedAny |= ArmLaunchGatePage(reinterpret_cast<void *>(
                reinterpret_cast<ULONG_PTR>(processModule) + ntHeaders->OptionalHeader.AddressOfEntryPoint));
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
                        for (std::size_t i = 0; i < kLaunchGateMaxPages && callbacks[i] != nullptr; ++i)
                        {
                            armedAny |= ArmLaunchGatePage(reinterpret_cast<void *>(callbacks[i]));
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                }
            }
        }
#endif

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

                g_LaunchGateReadyEvent = NativeCreateEvent(true, false, eventName);
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
            return false;
        }

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
        if (!g_LaunchGatePrepared.load(std::memory_order_acquire) || g_LaunchGateReady.load(std::memory_order_acquire) ||
            ep == nullptr || ep->ExceptionRecord == nullptr || ep->ContextRecord == nullptr ||
            ep->ExceptionRecord->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION)
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

        BkDbgLog("LaunchGateHandleFault: fault=%p exception=%p", faultAddress,
                          ep->ExceptionRecord->ExceptionAddress);

        void *pageBase = AlignLaunchGatePage(faultAddress);
        for (std::uint32_t i = 0; i < g_LaunchGatePageCount; ++i)
        {
            if (g_LaunchGatePages[i].Base == pageBase && g_LaunchGatePages[i].OriginalProtect != 0)
            {
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
                          reinterpret_cast<void *>(ep->ContextRecord->Rip),
                          reinterpret_cast<void *>(ep->ContextRecord->Rsp));
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
    }

    bool LaunchGateIsPrepared() noexcept
    {
        return g_LaunchGatePrepared.load(std::memory_order_acquire);
    }
} // namespace BK_RUNTIME_INTERNAL
