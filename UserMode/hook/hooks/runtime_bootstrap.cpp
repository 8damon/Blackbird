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

        BkDbgLog("EnsureCoreHookControllersReady: NtHook fault=%s function=%s address=%p redirect=%p syscall=%lu "
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

        BkDbgLog("EnsureCoreHookControllersReady: ModuleHook fault=%s module=%ws export=%s address=%p redirect=%p "
                 "sample=%02X %02X %02X %02X %02X %02X %02X %02X",
                 DescribeModuleHookInitFaultCode(fault.Code), fault.ModuleName != nullptr ? fault.ModuleName : L"",
                 fault.ExportName != nullptr ? fault.ExportName : "", fault.Address, fault.RedirectTarget,
                 fault.Sample[0], fault.Sample[1], fault.Sample[2], fault.Sample[3], fault.Sample[4], fault.Sample[5],
                 fault.Sample[6], fault.Sample[7]);
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
                BkDbgLog("EnsureCoreHookControllersReady: NtHook exception=0x%08lX", (unsigned long)GetExceptionCode());
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
                BkDbgLog("EnsureCoreHookControllersReady: KiHook exception=0x%08lX", (unsigned long)GetExceptionCode());
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
            BkDbgLog("EnsureRuntimeWorkerThreadStarted: CreateThread failed gle=%lu", (unsigned long)GetLastError());
            return false;
        }

        DWORD tid = GetThreadId(worker);
        if (tid != 0)
        {
            KeRegisterConcealedThread(tid);
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

        constexpr std::uint32_t kTransportReadyMask = BKIPC_HOOK_READY_FLAG_IPC_CONNECTED;
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

        /* Register all SR71-owned pages with the controller so they are
           excluded from heuristics and surfaced as "BK Instrumentation"
           in the UI instead of being flagged as suspicious RWX/syscall stubs. */
        RegisterSr71OwnedRanges();

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

        if (FindLoadedModuleBaseByName(L"ws2_32.dll") == nullptr &&
            FindLoadedModuleBaseByName(L"wsock32.dll") == nullptr)
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
            mask |= BKIPC_HOOK_READY_FLAG_IPC_CONNECTED;
        }
        if (g_WinsockInitialized)
        {
            mask |= BKIPC_HOOK_READY_FLAG_WINSOCK;
        }
        if (g_NtInitialized)
        {
            mask |= BKIPC_HOOK_READY_FLAG_NT;
        }
        if (g_KiInitialized)
        {
            mask |= BKIPC_HOOK_READY_FLAG_KI;
        }
        if (g_ModuleInitialized)
        {
            mask |= BKIPC_HOOK_READY_FLAG_MODULE;
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
                BkDbgLog("NotifyHookReadyWithRetry: timeout localMask=0x%08lX elapsedMs=%llu", (unsigned long)localMask,
                         (unsigned long long)(GetTickCount64() - startTick));
                BkRuntimeReportFault(BkRuntimeFaultCode::HookReadyTimedOut, localMask,
                                     static_cast<std::uint64_t>(GetTickCount64() - startTick));
                return false;
            }

            NativeYield();
            NativeDelayMs(kHookReadyNotifyRetrySleepMs);
        }
    }

    void RegisterSr71HookPatchOverlays() noexcept;

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
        std::uint32_t pendingCmd = 0;
        if (!BKIPC::NotifyHookReady(localMask, &observedMask, &pendingCmd))
        {
            return;
        }

        g_LastPublishedHookReadyMask.store(localMask, std::memory_order_release);
        BkDbgLog("PublishCurrentHookReadyMaskBestEffort: localMask=0x%08lX observedMask=0x%08lX pendingCmd=%lu",
                 (unsigned long)localMask, (unsigned long)observedMask, (unsigned long)pendingCmd);

        if (pendingCmd == BlackbirdIpcCommandUpgradeWinsockHooks)
        {
            BkDbgLog("PublishCurrentHookReadyMaskBestEffort: controller requested inline Winsock hook upgrade");
            if (KeInstallWinsockInlineHooks())
            {
                RegisterSr71HookPatchOverlays();
            }
        }
    }
    /* ── SR71 ownership registration ──────────────────────────────────────
     * Sends every BK-allocated page to the controller exactly once so
     * the controller can suppress heuristics and mark them in the UI as
     * "BK Instrumentation" instead of flagging them as suspicious
     * RWX/direct-syscall regions.
     * ─────────────────────────────────────────────────────────────────── */
    static volatile LONG g_InstrumentationRangesRegistered = 0;

    static bool TryGetImageSize(void *moduleBase, std::uint64_t &imageSize) noexcept
    {
        imageSize = 0;
        if (moduleBase == nullptr)
        {
            return false;
        }

        auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(moduleBase);
        __try
        {
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            {
                return false;
            }

            auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(reinterpret_cast<const std::uint8_t *>(moduleBase) +
                                                                  dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.SizeOfImage == 0)
            {
                return false;
            }

            imageSize = nt->OptionalHeader.SizeOfImage;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            imageSize = 0;
            return false;
        }
    }

    static bool PublishSr71InstrumentationRange(void *base, std::uint64_t size, std::uint32_t instrumentationFlags,
                                                const char *tag) noexcept
    {
        std::uint32_t ihrFlags = kSr71IhrFlagSr71Owned;
        if ((instrumentationFlags & BK_INSTRUMENTATION_FLAG_SYSCALL_STUB) != 0 ||
            (instrumentationFlags & BK_INSTRUMENTATION_FLAG_LAUNCH_GATE) != 0)
        {
            ihrFlags |= kSr71IhrFlagExecutable;
        }
        if ((instrumentationFlags & BK_INSTRUMENTATION_FLAG_LAUNCH_GATE) != 0)
        {
            ihrFlags |= kSr71IhrFlagGuarded;
        }

        Sr71IhrToken token = RegisterIndirectHandle(base, size, Sr71IhrType::InstrumentationRange, ihrFlags, tag);
        Sr71IhrResolved resolved{};
        if (token == 0 || !ResolveIndirectHandle(token, Sr71IhrType::InstrumentationRange, resolved))
        {
            return false;
        }

        bool ok = BKIPC::RegisterInstrumentationRange(reinterpret_cast<UINT64>(resolved.Pointer), resolved.Size,
                                                      instrumentationFlags, tag);
        if (!ok)
        {
            BkRuntimeReportFault(BkRuntimeFaultCode::InstrumentationRangeRegisterFailed,
                                 reinterpret_cast<std::uint64_t>(resolved.Pointer), resolved.Size);
        }
        return ok;
    }

    static void BuildHookPatchTag(const char *prefix, const char *name, char tag[BK_HOOK_PATCH_TAG_CHARS]) noexcept
    {
        std::size_t p = 0;
        if (prefix != nullptr)
        {
            while (prefix[p] && p < BK_HOOK_PATCH_TAG_CHARS - 1)
            {
                tag[p] = prefix[p];
                ++p;
            }
        }
        if (name != nullptr)
        {
            std::size_t n = 0;
            while (name[n] && p < BK_HOOK_PATCH_TAG_CHARS - 1)
            {
                tag[p++] = name[n++];
            }
        }
        tag[p] = '\0';
    }

    static void PublishSr71HookPatch(void *patchAddress, std::size_t patchSize, const std::uint8_t originalBytes[16],
                                     std::uint32_t flags, const char *tagPrefix, const char *hookName) noexcept
    {
        if (patchAddress == nullptr || patchSize == 0 || patchSize > BK_MAX_HOOK_PATCH_BYTES ||
            originalBytes == nullptr)
        {
            return;
        }

        char tag[BK_HOOK_PATCH_TAG_CHARS]{};
        BuildHookPatchTag(tagPrefix, hookName, tag);
        if (!BKIPC::RegisterHookPatch(reinterpret_cast<UINT64>(patchAddress), static_cast<UINT32>(patchSize),
                                      originalBytes, BK_MAX_HOOK_PATCH_BYTES, flags, tag))
        {
            BkRuntimeReportFault(BkRuntimeFaultCode::HookPatchRegisterFailed,
                                 reinterpret_cast<std::uint64_t>(patchAddress), static_cast<std::uint64_t>(patchSize));
        }
    }

    void RegisterSr71HookPatchOverlays() noexcept
    {
        std::size_t totalCount = 0;

        constexpr std::size_t kMaxNtPatches = 64;
        NtHookPatchInfo ntPatches[kMaxNtPatches]{};
        std::size_t ntPatchCount = KeCollectNtHookPatchInfos(ntPatches, kMaxNtPatches);
        for (std::size_t i = 0; i < ntPatchCount; ++i)
        {
            PublishSr71HookPatch(ntPatches[i].PatchAddress, ntPatches[i].PatchSize, ntPatches[i].OriginalBytes,
                                 BK_HOOK_PATCH_FLAG_NT_INLINE, "BK Inst.NtPatch.", ntPatches[i].HookName);
        }
        totalCount += ntPatchCount;

        constexpr std::size_t kMaxWinsockPatches = 640;
        WinsockHookPatchInfo winsockPatches[kMaxWinsockPatches]{};
        std::size_t winsockPatchCount = KeCollectWinsockHookPatchInfos(winsockPatches, kMaxWinsockPatches);
        for (std::size_t i = 0; i < winsockPatchCount; ++i)
        {
            const char *prefix =
                (winsockPatches[i].Flags == BK_HOOK_PATCH_FLAG_WINSOCK_INLINE) ? "BK Inst.WsInline." : "BK Inst.WsIAT.";
            PublishSr71HookPatch(winsockPatches[i].PatchAddress, winsockPatches[i].PatchSize,
                                 winsockPatches[i].OriginalBytes, winsockPatches[i].Flags, prefix,
                                 winsockPatches[i].HookName);
        }
        totalCount += winsockPatchCount;

        constexpr std::size_t kMaxKiPatches = 4;
        KiHookPatchInfo kiPatches[kMaxKiPatches]{};
        std::size_t kiPatchCount = KeCollectKiHookPatchInfos(kiPatches, kMaxKiPatches);
        for (std::size_t i = 0; i < kiPatchCount; ++i)
        {
            PublishSr71HookPatch(kiPatches[i].PatchAddress, kiPatches[i].PatchSize, kiPatches[i].OriginalBytes,
                                 kiPatches[i].Flags, "BK Inst.KiSlot.", kiPatches[i].HookName);
        }
        totalCount += kiPatchCount;

        constexpr std::size_t kMaxModulePatches = 64;
        ModuleHookPatchInfo modulePatches[kMaxModulePatches]{};
        std::size_t modulePatchCount = KeCollectModuleHookPatchInfos(modulePatches, kMaxModulePatches);
        for (std::size_t i = 0; i < modulePatchCount; ++i)
        {
            PublishSr71HookPatch(modulePatches[i].PatchAddress, modulePatches[i].PatchSize,
                                 modulePatches[i].OriginalBytes, modulePatches[i].Flags, "BK Inst.Module.",
                                 modulePatches[i].HookName);
        }
        totalCount += modulePatchCount;

        BkDbgLog("RegisterSr71HookPatchOverlays: registered nt=%zu winsock=%zu ki=%zu module=%zu total=%zu",
                 ntPatchCount, winsockPatchCount, kiPatchCount, modulePatchCount, totalCount);
    }

    void RegisterSr71OwnedRanges() noexcept
    {
        if (InterlockedCompareExchange(&g_InstrumentationRangesRegistered, 1, 0) != 0)
            return; /* idempotent — only register once even if called multiple times */

        MEMORY_BASIC_INFORMATION selfMbi{};
        void *sr71Base = nullptr;
        if (VirtualQuery(reinterpret_cast<const void *>(&RegisterSr71OwnedRanges), &selfMbi, sizeof(selfMbi)) ==
            sizeof(selfMbi))
        {
            sr71Base = selfMbi.AllocationBase;
        }
        if (sr71Base == nullptr)
        {
            sr71Base = FindLoadedModuleBaseByName(L"SR71.dll");
        }
        std::uint64_t sr71ImageSize = 0;
        if (TryGetImageSize(sr71Base, sr71ImageSize))
        {
            (void)PublishSr71InstrumentationRange(sr71Base, sr71ImageSize, 0u, "SR71 Instrumentation");
        }

        /* 1. NT-hook syscall stubs — one 16-byte PAGE_EXECUTE_READWRITE allocation
              per hooked NT API, created by BuildSyscallStub() inside nt.cpp. */
        constexpr std::size_t kMaxStubs = 64;
        NtHookStubInfo stubs[kMaxStubs]{};
        std::size_t stubCount = KeCollectNtHookStubInfos(stubs, kMaxStubs);

        for (std::size_t i = 0; i < stubCount; ++i)
        {
            if (stubs[i].StubBase == nullptr || stubs[i].StubSize == 0)
                continue;

            /* Build a tag like "BK Instrument.NtHook.NtCreateThreadEx" */
            char tag[BK_MAX_INSTRUMENTATION_TAG]{};
            const char *prefix = "BK Instrument.NtHook.";
            std::size_t p = 0;
            while (prefix[p] && p < BK_MAX_INSTRUMENTATION_TAG - 1)
            {
                tag[p] = prefix[p];
                ++p;
            }
            if (stubs[i].HookName)
            {
                std::size_t n = 0;
                while (stubs[i].HookName[n] && p < BK_MAX_INSTRUMENTATION_TAG - 1)
                {
                    tag[p++] = stubs[i].HookName[n++];
                }
            }
            tag[p] = '\0';

            (void)PublishSr71InstrumentationRange(stubs[i].StubBase, static_cast<UINT64>(stubs[i].StubSize),
                                                  BK_INSTRUMENTATION_FLAG_SYSCALL_STUB, tag);
        }

        BkDbgLog("RegisterSr71OwnedRanges: registered %zu NT-hook stubs", stubCount);

        RegisterSr71HookPatchOverlays();

        /* 2. Launch-gate pages — RWX guard pages used to trap and redirect the
              target thread's initial IP before user code runs.
              g_LaunchGatePages is defined in runtime_launch_gate.cpp. */
        for (std::size_t i = 0; i < g_LaunchGatePageCount; ++i)
        {
            const LaunchGatePage &page = g_LaunchGatePages[i];
            Sr71IhrResolved resolved{};
            if (!ResolveIndirectHandle(page.BaseToken, Sr71IhrType::LaunchGatePage, resolved))
                continue;
            if (!BKIPC::RegisterInstrumentationRange(
                    reinterpret_cast<UINT64>(resolved.Pointer), resolved.Size ? resolved.Size : 4096u,
                    BK_INSTRUMENTATION_FLAG_LAUNCH_GATE,
                    page.TrapKind == 2u ? "BK Instrument.TLS Callback" : "BK Instrument.Entry"))
            {
                BkRuntimeReportFault(BkRuntimeFaultCode::InstrumentationRangeRegisterFailed,
                                     reinterpret_cast<std::uint64_t>(resolved.Pointer),
                                     resolved.Size ? resolved.Size : 4096u);
            }
        }
    }
} // namespace BK_RUNTIME_INTERNAL
