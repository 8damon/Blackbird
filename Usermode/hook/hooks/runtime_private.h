#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

#include "runtime.h"

#include "controller.h"
#include "encoded_literal.h"
#include "module.h"
#include "nt.h"
#include "ws.h"

#include "../ipc/pipe.h"
#include "../instrument/bk.h"
#include "../instrument/stacktrace.h"
#include "../../include/native_peb.h"

#include <Windows.h>
#include <winternl.h>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <vector>

/* Prevent SR71 housekeeping calls from recursively re-entering SR71 hooks. */
extern __declspec(thread) int g_Sr71CallDepth;

inline bool BkSr71IsInternalCall() noexcept
{
    return g_Sr71CallDepth > 0;
}

struct BkSr71InternalScope
{
    BkSr71InternalScope() noexcept
    {
        ++g_Sr71CallDepth;
    }
    ~BkSr71InternalScope() noexcept
    {
        --g_Sr71CallDepth;
    }
    BkSr71InternalScope(const BkSr71InternalScope &) = delete;
    BkSr71InternalScope &operator=(const BkSr71InternalScope &) = delete;
};

#define BK_SR71_INTERNAL_SCOPE() BkSr71InternalScope _bk_internal_scope_

namespace BK_RUNTIME_INTERNAL
{
    using Sr71IhrToken = std::uint64_t;

    enum class Sr71IhrType : std::uint32_t
    {
        Generic = 1,
        InstrumentationRange = 2,
        LaunchGatePage = 3,
        RuntimeCallback = 4,
        RuntimeState = 5,
        NtHookTarget = 6,
        NtSyscallStub = 7,
    };

    enum Sr71IhrFlags : std::uint32_t
    {
        kSr71IhrFlagExecutable = 0x00000001u,
        kSr71IhrFlagSr71Owned = 0x00000002u,
        kSr71IhrFlagGuarded = 0x00000004u,
    };

    enum class Sr71CfgCallTargetMode : std::uint32_t
    {
        CfgOnly = 0,
        CfgAndXfgWhenEnabled = 1,
    };

    struct Sr71ControlFlowPolicy
    {
        bool QuerySucceeded = false;
        bool CfgEnabled = false;
        bool CfgStrictMode = false;
        bool XfgEnabled = false;
        bool XfgAuditMode = false;
        std::uint32_t Flags = 0;
        std::uint32_t LastError = 0;
    };

    struct Sr71IhrResolved
    {
        void *Pointer = nullptr;
        std::uint64_t Size = 0;
        std::uint32_t Flags = 0;
        std::uint32_t TagHash = 0;
    };

    using KH_UNICODE_STRING = UNICODE_STRING;
    using KH_LDR_DATA_TABLE_ENTRY = BB_LDR_DATA_TABLE_ENTRY;
    using PKH_LDR_DATA_TABLE_ENTRY = PBB_LDR_DATA_TABLE_ENTRY;
    using KH_PEB_LDR_DATA = BB_PEB_LDR_DATA;
    using PKH_PEB_LDR_DATA = PBB_PEB_LDR_DATA;
    using KH_PEB = BB_PEB;
    using PKH_PEB = PBB_PEB;
    using KH_CLIENT_ID = BB_CLIENT_ID;
    using PKH_CLIENT_ID = PBB_CLIENT_ID;

    using NtCreateThreadExFn = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG,
                                                 SIZE_T, SIZE_T, SIZE_T, PVOID);
    using RtlCreateUserThreadFn = NTSTATUS(NTAPI *)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, PULONG, PULONG, PVOID,
                                                    PVOID, PHANDLE, PKH_CLIENT_ID);
    using NtTerminateProcessFn = NTSTATUS(NTAPI *)(HANDLE, NTSTATUS);
    using RtlExitUserThreadFn = VOID(NTAPI *)(NTSTATUS);
    using RtlRestoreContextFn = VOID(WINAPI *)(PCONTEXT, PEXCEPTION_RECORD);
    using NtContinueFn = NTSTATUS(NTAPI *)(PCONTEXT, BOOLEAN);
    using NtDelayExecutionFn = NTSTATUS(NTAPI *)(BOOLEAN, PLARGE_INTEGER);
    using NtYieldExecutionFn = NTSTATUS(NTAPI *)(VOID);

    struct LaunchGateCallbacks
    {
        bool (*InitializeRuntime)(bool signalGateReady, bool startWorkerAfterInit) noexcept = nullptr;
        void (*FailClosed)(DWORD exitStatus) noexcept = nullptr;
    };

    inline constexpr DWORD kLaunchGatePageSize = 0x1000u;
    inline constexpr std::size_t kLaunchGateMaxPages = 16;
    inline constexpr std::size_t kLaunchGateMaxParkContexts = 16;
    struct LaunchGatePage
    {
        Sr71IhrToken BaseToken = 0;
        DWORD OriginalProtect = 0;
        void *TrapAddress = nullptr;
        std::uint32_t TrapKind = 0;
        std::uint32_t TrapIndex = 0;
    };

    struct LaunchGateParkContext
    {
        CONTEXT Context{};
        DWORD ThreadId = 0;
        LONG State = 0;
        LONG InitializeRuntime = 0;
        void *TrapAddress = nullptr;
        void *TrapPage = nullptr;
        std::uint32_t TrapKind = 0;
        std::uint32_t TrapIndex = 0;
    };

    struct ExportProbeCache
    {
        std::uint8_t Expected[16]{};
        bool ExpectedCaptured = false;
        wchar_t ModulePath[MAX_PATH]{};
    };

    inline constexpr std::uint32_t kIntegrityMaskWinsock = 0x00000001u;
    inline constexpr std::uint32_t kIntegrityMaskNt = 0x00000002u;
    inline constexpr std::uint32_t kIntegrityMaskKi = 0x00000004u;
    inline constexpr std::uint32_t kIntegrityMaskModule = 0x00000008u;
    inline constexpr std::uint32_t kIntegrityOperationAmsiPatch = BK_HOOK_EVENT_OP_AMSI_PATCH;
    inline constexpr std::uint32_t kIntegrityOperationEtwPatch = BK_HOOK_EVENT_OP_ETW_PATCH;
    inline constexpr ULONGLONG kIntegrityCheckPeriodMs = 2000ull;
    inline constexpr ULONGLONG kIntegrityRepublishPeriodMs = 10000ull;
    inline constexpr DWORD kIpcInitAttemptTimeoutMs = 64u;
    inline constexpr DWORD kIpcInitRetrySleepMs = 2u;
    inline constexpr DWORD kHookReadyNotifyRetrySleepMs = 1u;
    inline constexpr ULONGLONG kIpcInitMaxWaitMs = 15000ull;
    inline constexpr ULONGLONG kHookReadyNotifyMaxWaitMs = 15000ull;

    extern WinsockHookController g_WinsockController;
    extern NtHookController g_NtHookController;
    extern KiHookController g_KiHookController;
    extern ModuleHookController g_ModuleHookController;
    extern bool g_WinsockInitialized;
    extern bool g_NtInitialized;
    extern bool g_KiInitialized;
    extern bool g_ModuleInitialized;
    extern ULONGLONG g_LastIntegrityCheckTick;
    extern ULONGLONG g_LastIntegrityPublishTick;
    extern std::uint32_t g_LastIntegrityMask;
    extern std::uint64_t g_IntegrityCheckCount;
    extern ExportProbeCache g_AmsiProbe;
    extern ExportProbeCache g_EtwProbe;
    extern bool g_LastAmsiTampered;
    extern bool g_LastEtwTampered;
    extern bool g_AmsiFirstPoll;
    extern bool g_EtwFirstPoll;
    extern ULONGLONG g_LastAmsiPublishTick;
    extern ULONGLONG g_LastEtwPublishTick;
    extern std::atomic<bool> g_RuntimePrimed;
    extern std::atomic<bool> g_RuntimeInitialized;
    extern std::atomic<bool> g_RuntimeWorkerStarted;
    extern std::atomic<std::uint32_t> g_LastPublishedHookReadyMask;
    extern BkBlackbirdTelemetryArguments g_RuntimeVehArgs;
    extern std::atomic<bool> g_LaunchGatePrepared;
    extern std::atomic<bool> g_LaunchGateReady;
    extern std::atomic<bool> g_LaunchGateDeferredOpen;
    extern HANDLE g_LaunchGateReadyEvent;
    extern LaunchGatePage g_LaunchGatePages[kLaunchGateMaxPages];
    extern LaunchGateParkContext g_LaunchGateParkContexts[kLaunchGateMaxParkContexts];
    extern std::uint32_t g_LaunchGatePageCount;
    extern LONG g_LaunchGateInitializerAssigned;
    extern LaunchGateCallbacks g_LaunchGateCallbacks;

    inline bool NtSucceeded(NTSTATUS status) noexcept
    {
        return status >= 0;
    }

    inline HANDLE CurrentProcessHandle() noexcept
    {
        return reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1));
    }

    PKH_PEB CurrentPeb() noexcept;
    bool UnicodeStringEqualsInsensitive(const KH_UNICODE_STRING &value, const wchar_t *literal) noexcept;
    const std::uint8_t *ImagePointerFromRva(const std::uint8_t *moduleBase, DWORD rva,
                                            std::size_t bytesNeeded) noexcept;
    void *FindProcessImageBase() noexcept;
    void *FindLoadedModuleBaseByName(const wchar_t *moduleName) noexcept;
    void *ResolveExportByName(void *moduleBase, const char *name) noexcept;

    template <typename T> inline T ResolveNtdllExport(const char *name) noexcept
    {
        auto ntdllName = DecodeNtdllDllName();
        HMODULE ntdll = GetModuleHandleW(ntdllName.c_str());
        if (ntdll != nullptr)
        {
            FARPROC proc = GetProcAddress(ntdll, name);
            if (proc != nullptr)
            {
                return reinterpret_cast<T>(proc);
            }
        }

        return reinterpret_cast<T>(ResolveExportByName(FindLoadedModuleBaseByName(ntdllName.c_str()), name));
    }

    bool NativeQueryMemory(void *address, MEMORY_BASIC_INFORMATION *memoryInfo) noexcept;
    bool NativeProtect(void *address, SIZE_T regionSize, ULONG newProtect, PULONG oldProtect) noexcept;
    HANDLE NativeCreateEvent(bool manualReset, bool initialState, const wchar_t *name = nullptr,
                             DWORD desiredAccess = EVENT_MODIFY_STATE | SYNCHRONIZE) noexcept;
    void NativeCloseHandle(HANDLE handle) noexcept;
    bool NativeSetEvent(HANDLE handle) noexcept;
    bool NativeWaitForSingleObject(HANDLE handle) noexcept;
    void NativeDelayMs(DWORD milliseconds) noexcept;
    void NativeYield() noexcept;
    HANDLE NativeCreateThread(void *startRoutine, void *parameter) noexcept;
    [[noreturn]] void NativeTerminateCurrentProcess(DWORD exitStatus) noexcept;
    [[noreturn]] void NativeExitCurrentThread() noexcept;

    Sr71ControlFlowPolicy QueryCurrentProcessControlFlowPolicy() noexcept;
    bool RegisterControlFlowGuardCallTarget(void *targetAddress, Sr71CfgCallTargetMode mode,
                                            const char *tag = nullptr) noexcept;
    void ResetControlFlowGuardPolicyCache() noexcept;

    template <typename TTrace> inline void CopyHookStack(const TTrace &trace, BKIPC_HOOK_EVENT &record) noexcept
    {
        const std::uint32_t safeCount = static_cast<std::uint32_t>(
            (trace.Count > BKIPC_MAX_HOOK_STACK_FRAMES) ? BKIPC_MAX_HOOK_STACK_FRAMES : trace.Count);
        record.StackCount = safeCount;
        for (std::uint32_t i = 0; i < safeCount; ++i)
        {
            record.Stack[i] = reinterpret_cast<std::uint64_t>(trace.Frames[i].Ip);
        }
    }

    void ResetIntegrityWatchdogState() noexcept;
    Sr71IhrToken RegisterIndirectHandle(void *pointer, std::uint64_t size, Sr71IhrType type, std::uint32_t flags,
                                        const char *tag) noexcept;
    bool ResolveIndirectHandle(Sr71IhrToken token, Sr71IhrType expectedType, Sr71IhrResolved &resolved) noexcept;
    void ReleaseIndirectHandle(Sr71IhrToken token) noexcept;
    void ResetIndirectHandles() noexcept;

    bool EnsureCoreHookControllersReady() noexcept;
    bool MaybeInitializeWinsockHookController() noexcept;
    std::uint32_t BuildHookReadyMask(bool ipcConnected) noexcept;
    bool InitializeIpcWithRetry() noexcept;
    bool NotifyHookReadyWithRetry(std::uint32_t localMask) noexcept;
    void PublishCurrentHookReadyMaskBestEffort() noexcept;
    void SignalHookEventsPending() noexcept;
    void FlushHookEvents() noexcept;
    void PollHookIntegrityWatchdog() noexcept;
    void RegisterSr71OwnedRanges() noexcept;
    DWORD WINAPI BkRuntimeEventLoopThreadProc(LPVOID) noexcept;
    bool EnsureRuntimeWorkerThreadStarted() noexcept;
    bool EnsureRuntimeInitializedForLaunch(bool signalLaunchGateReady, bool startWorkerAfterInit) noexcept;
    bool EnsureProcessInstrumentationCallbackInstalled(bool allowInstallNow) noexcept;
    void FlushProcessInstrumentationCallbackSamples() noexcept;
    void ResetProcessInstrumentationCallbackState() noexcept;

    bool LaunchGateHandleFault(EXCEPTION_POINTERS *ep) noexcept;
    bool LaunchGateIsPrepared() noexcept;
    bool LaunchGatePrepare() noexcept;
    void LaunchGateRelease() noexcept;
    void LaunchGateShutdown() noexcept;
} // namespace BK_RUNTIME_INTERNAL
