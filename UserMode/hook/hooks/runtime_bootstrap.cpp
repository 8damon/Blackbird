#include "runtime_private.h"

namespace BK_RUNTIME_INTERNAL
{
    const char *DescribeNtHookInitFaultCode(NtHookInitFaultCode code) noexcept
    {
        switch (code)
        {
        case NtHookInitFaultCode::None:
            return "none";
        case NtHookInitFaultCode::NtdllMissing:
            return "ntdll-missing";
        case NtHookInitFaultCode::NtdllTextMissing:
            return "ntdll-text-missing";
        case NtHookInitFaultCode::NtdllExportDirectoryMissing:
            return "ntdll-export-dir-missing";
        case NtHookInitFaultCode::ExportMissing:
            return "export-missing";
        case NtHookInitFaultCode::ExportOutsideImage:
            return "export-outside-image";
        case NtHookInitFaultCode::ExportOutsideText:
            return "export-outside-text";
        case NtHookInitFaultCode::ExportRedirectedOutsideImage:
            return "export-redirected-outside-image";
        case NtHookInitFaultCode::UnexpectedStubBytes:
            return "unexpected-stub-bytes";
        case NtHookInitFaultCode::SyscallStubAllocFailed:
            return "syscall-stub-alloc-failed";
        case NtHookInitFaultCode::HookEntryMissing:
            return "hook-entry-missing";
        case NtHookInitFaultCode::PatchInstallFailed:
            return "patch-install-failed";
        default:
            return "unknown";
        }
    }

    const char *DescribeModuleHookInitFaultCode(ModuleHookInitFaultCode code) noexcept
    {
        switch (code)
        {
        case ModuleHookInitFaultCode::None:
            return "none";
        case ModuleHookInitFaultCode::ModuleMissing:
            return "module-missing";
        case ModuleHookInitFaultCode::ExportMissing:
            return "export-missing";
        case ModuleHookInitFaultCode::ExportOutsideImage:
            return "export-outside-image";
        case ModuleHookInitFaultCode::ExportRedirectedOutsideImage:
            return "export-redirected-outside-image";
        case ModuleHookInitFaultCode::PatchInstallFailed:
            return "patch-install-failed";
        default:
            return "unknown";
        }
    }

    void LogNtHookInitFault() noexcept
    {
        NtHookInitFault fault{};
        if (!KeGetLastNtHookInitFault(&fault))
        {
            return;
        }

        BkDbgLog(
            "EnsureCoreHookControllersReady: NtHook fault=%s function=%s address=%p redirect=%p syscall=%lu "
            "sample=%02X %02X %02X %02X %02X %02X %02X %02X",
            DescribeNtHookInitFaultCode(fault.Code), fault.FunctionName != nullptr ? fault.FunctionName : "",
            fault.Address, fault.RedirectTarget, static_cast<unsigned long>(fault.SyscallIndex), fault.Sample[0],
            fault.Sample[1], fault.Sample[2], fault.Sample[3], fault.Sample[4], fault.Sample[5], fault.Sample[6],
            fault.Sample[7]);
        BkRuntimeReportFault(BkRuntimeFaultCode::NtHookInitFault, reinterpret_cast<std::uint64_t>(fault.Address),
                             static_cast<std::uint64_t>(fault.Code));
    }

    void LogModuleHookInitFault() noexcept
    {
        ModuleHookInitFault fault{};
        if (!KeGetLastModuleHookInitFault(&fault))
        {
            return;
        }

        BkDbgLog(
            "EnsureCoreHookControllersReady: ModuleHook fault=%s module=%ws export=%s address=%p redirect=%p "
            "sample=%02X %02X %02X %02X %02X %02X %02X %02X",
            DescribeModuleHookInitFaultCode(fault.Code), fault.ModuleName != nullptr ? fault.ModuleName : L"",
            fault.ExportName != nullptr ? fault.ExportName : "", fault.Address, fault.RedirectTarget, fault.Sample[0],
            fault.Sample[1], fault.Sample[2], fault.Sample[3], fault.Sample[4], fault.Sample[5], fault.Sample[6],
            fault.Sample[7]);
        BkRuntimeReportFault(BkRuntimeFaultCode::ModuleHookInitFault, reinterpret_cast<std::uint64_t>(fault.Address),
                             static_cast<std::uint64_t>(fault.Code));
    }

    bool EnsureCoreHookControllersReady() noexcept
    {
        if (!g_NtInitialized)
        {
            __try
            {
                g_NtInitialized = g_NtHookController.Initialize();
                BkDbgLog("EnsureCoreHookControllersReady: NtHook=%u", g_NtInitialized ? 1u : 0u);
                if (!g_NtInitialized)
                {
                    LogNtHookInitFault();
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                g_NtInitialized = false;
                BkDbgLog("EnsureCoreHookControllersReady: NtHook exception=0x%08lX",
                                  (unsigned long)GetExceptionCode());
            }
        }
        if (!g_KiInitialized)
        {
            __try
            {
                g_KiInitialized = g_KiHookController.Initialize();
                BkDbgLog("EnsureCoreHookControllersReady: KiHook=%u", g_KiInitialized ? 1u : 0u);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                g_KiInitialized = false;
                BkDbgLog("EnsureCoreHookControllersReady: KiHook exception=0x%08lX",
                                  (unsigned long)GetExceptionCode());
            }
            if (!g_KiInitialized && !KeIsKiHookSupported())
            {
                g_KiInitialized = true;
                BkDbgLog("EnsureCoreHookControllersReady: KiHook unsupported, treating as ready");
            }
        }
        if (!g_ModuleInitialized)
        {
            __try
            {
                g_ModuleInitialized = g_ModuleHookController.Initialize();
                BkDbgLog("EnsureCoreHookControllersReady: ModuleHook=%u", g_ModuleInitialized ? 1u : 0u);
                if (!g_ModuleInitialized)
                {
                    LogModuleHookInitFault();
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                g_ModuleInitialized = false;
                BkDbgLog("EnsureCoreHookControllersReady: ModuleHook exception=0x%08lX",
                                  (unsigned long)GetExceptionCode());
            }
        }

        return g_NtInitialized && g_KiInitialized && g_ModuleInitialized;
    }

    DWORD WINAPI BkRuntimeEventLoopThreadProc(LPVOID) noexcept
    {
        BkDbgLog("BkRuntimeEventLoopThreadProc: start");

        for (;;)
        {
            __try
            {
                (void)EnsureCoreHookControllersReady();
                (void)MaybeInitializeWinsockHookController();
                PublishCurrentHookReadyMaskBestEffort();
                FlushHookEvents();
                PollHookIntegrityWatchdog();
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
            NativeDelayMs(60);
        }

        __assume(0);
    }

    bool EnsureRuntimeWorkerThreadStarted() noexcept
    {
        bool expected = false;
        if (!g_RuntimeWorkerStarted.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        {
            return true;
        }

        HANDLE worker = CreateThread(nullptr, 0, &BkRuntimeEventLoopThreadProc, nullptr, 0, nullptr);
        if (worker == nullptr)
        {
            g_RuntimeWorkerStarted.store(false, std::memory_order_release);
            BkDbgLog("EnsureRuntimeWorkerThreadStarted: CreateThread failed gle=%lu",
                              (unsigned long)GetLastError());
            return false;
        }

        BkDbgLog("EnsureRuntimeWorkerThreadStarted: started handle=%p", worker);
        NativeCloseHandle(worker);
        return true;
    }

    bool EnsureRuntimeInitializedForLaunch(bool signalLaunchGateReady, bool startWorkerAfterInit) noexcept
    {
        if (g_RuntimeInitialized.load(std::memory_order_acquire))
        {
            BkDbgLog("EnsureRuntimeInitializedForLaunch: already initialized");
            if (signalLaunchGateReady)
            {
                BkRuntimeSignalLaunchGateReady();
            }
            return true;
        }

        BkDbgLog("EnsureRuntimeInitializedForLaunch: begin");
        BkRuntimePrimeHooks();

        bool ipcReady = InitializeIpcWithRetry();
        BkDbgLog("EnsureRuntimeInitializedForLaunch: ipcReady=%u", ipcReady ? 1u : 0u);
        if (!ipcReady)
        {
            return false;
        }

        constexpr std::uint32_t kTransportReadyMask = BLACKBIRD_IPC_HOOK_READY_FLAG_IPC_CONNECTED;
        if (!NotifyHookReadyWithRetry(kTransportReadyMask))
        {
            BkDbgLog("EnsureRuntimeInitializedForLaunch: initial transport notify failed");
            BkRuntimeReportFault(BkRuntimeFaultCode::HookReadyTimedOut, kTransportReadyMask);
            return false;
        }
        g_LastPublishedHookReadyMask.store(kTransportReadyMask, std::memory_order_release);

        if (signalLaunchGateReady)
        {
            BkRuntimeSignalLaunchGateReady();
        }

        bool coreReady = EnsureCoreHookControllersReady();
        BkDbgLog("EnsureRuntimeInitializedForLaunch: coreReady=%u readyMask=0x%08lX", coreReady ? 1u : 0u,
                          (unsigned long)BuildHookReadyMask(true));
        if (!coreReady)
        {
            BkRuntimeReportFault(BkRuntimeFaultCode::CoreHookInitFailed, BuildHookReadyMask(true));
        }
        (void)MaybeInitializeWinsockHookController();
        PublishCurrentHookReadyMaskBestEffort();

        g_RuntimeInitialized.store(true, std::memory_order_release);

        if (startWorkerAfterInit && !EnsureRuntimeWorkerThreadStarted())
        {
            BkDbgLog("EnsureRuntimeInitializedForLaunch: worker start deferred");
        }

        return true;
    }

    bool MaybeInitializeWinsockHookController() noexcept
    {
        if (g_WinsockInitialized || !KeIsWinsockHookRequired())
        {
            return true;
        }

        if (FindLoadedModuleBaseByName(L"ws2_32.dll") == nullptr && FindLoadedModuleBaseByName(L"wsock32.dll") == nullptr)
        {
            return false;
        }

        __try
        {
            g_WinsockInitialized = g_WinsockController.Initialize();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            g_WinsockInitialized = false;
        }

        return g_WinsockInitialized;
    }

    std::uint32_t BuildHookReadyMask(bool ipcConnected) noexcept
    {
        std::uint32_t mask = 0;
        if (ipcConnected)
        {
            mask |= BLACKBIRD_IPC_HOOK_READY_FLAG_IPC_CONNECTED;
        }
        if (g_WinsockInitialized)
        {
            mask |= BLACKBIRD_IPC_HOOK_READY_FLAG_WINSOCK;
        }
        if (g_NtInitialized)
        {
            mask |= BLACKBIRD_IPC_HOOK_READY_FLAG_NT;
        }
        if (g_KiInitialized)
        {
            mask |= BLACKBIRD_IPC_HOOK_READY_FLAG_KI;
        }
        if (g_ModuleInitialized)
        {
            mask |= BLACKBIRD_IPC_HOOK_READY_FLAG_MODULE;
        }
        return mask;
    }

    bool InitializeIpcWithRetry() noexcept
    {
        ULONGLONG startTick = GetTickCount64();
        BkDbgLog("InitializeIpcWithRetry: begin");

        for (;;)
        {
            if (BKIPC::Initialize(kIpcInitAttemptTimeoutMs))
            {
                BkDbgLog("InitializeIpcWithRetry: success elapsedMs=%llu",
                                  (unsigned long long)(GetTickCount64() - startTick));
                return true;
            }

            if ((GetTickCount64() - startTick) >= kIpcInitMaxWaitMs)
            {
                BkDbgLog("InitializeIpcWithRetry: timeout elapsedMs=%llu",
                                  (unsigned long long)(GetTickCount64() - startTick));
                BkRuntimeReportFault(BkRuntimeFaultCode::IpcInitializeTimedOut,
                                     static_cast<std::uint64_t>(GetTickCount64() - startTick));
                return false;
            }

            NativeYield();
            NativeDelayMs(kIpcInitRetrySleepMs);
        }
    }

    bool NotifyHookReadyWithRetry(std::uint32_t localMask) noexcept
    {
        ULONGLONG startTick = GetTickCount64();
        if (localMask == 0)
        {
            BkDbgLog("NotifyHookReadyWithRetry: refused empty mask");
            return false;
        }

        BkDbgLog("NotifyHookReadyWithRetry: begin localMask=0x%08lX", (unsigned long)localMask);

        for (;;)
        {
            std::uint32_t observedMask = 0;
            if (BKIPC::NotifyHookReady(localMask, &observedMask))
            {
                BkDbgLog("NotifyHookReadyWithRetry: success localMask=0x%08lX observedMask=0x%08lX elapsedMs=%llu",
                                  (unsigned long)localMask, (unsigned long)observedMask,
                                  (unsigned long long)(GetTickCount64() - startTick));
                return true;
            }

            if ((GetTickCount64() - startTick) >= kHookReadyNotifyMaxWaitMs)
            {
                BkDbgLog("NotifyHookReadyWithRetry: timeout localMask=0x%08lX elapsedMs=%llu",
                                  (unsigned long)localMask, (unsigned long long)(GetTickCount64() - startTick));
                BkRuntimeReportFault(BkRuntimeFaultCode::HookReadyTimedOut, localMask,
                                     static_cast<std::uint64_t>(GetTickCount64() - startTick));
                return false;
            }

            NativeYield();
            NativeDelayMs(kHookReadyNotifyRetrySleepMs);
        }
    }

    void PublishCurrentHookReadyMaskBestEffort() noexcept
    {
        const std::uint32_t localMask = BuildHookReadyMask(true);
        if (localMask == 0)
        {
            return;
        }

        const std::uint32_t publishedMask = g_LastPublishedHookReadyMask.load(std::memory_order_acquire);
        if (publishedMask == localMask)
        {
            return;
        }

        std::uint32_t observedMask = 0;
        if (!BKIPC::NotifyHookReady(localMask, &observedMask))
        {
            return;
        }

        g_LastPublishedHookReadyMask.store(localMask, std::memory_order_release);
        BkDbgLog("PublishCurrentHookReadyMaskBestEffort: localMask=0x%08lX observedMask=0x%08lX",
                          (unsigned long)localMask, (unsigned long)observedMask);
    }
} // namespace BK_RUNTIME_INTERNAL
