#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

#include "runtime_private.h"

#include <intrin.h>
#include <strsafe.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <cwchar>
#include <vector>

#pragma intrinsic(__readgsqword)
#pragma intrinsic(_ReturnAddress)

using namespace BK_RUNTIME_INTERNAL;

void BkDbgLog(_In_z_ _Printf_format_string_ PCSTR format, ...) noexcept
{
    if (format == nullptr)
    {
        return;
    }

    char message[512]{};
    va_list args;
    va_start(args, format);
    (void)StringCchVPrintfA(message, RTL_NUMBER_OF(message), format, args);
    va_end(args);

    char line[768]{};
    const unsigned long pid = GetCurrentProcessId();
    const unsigned long tid = GetCurrentThreadId();
    const unsigned long long tick = static_cast<unsigned long long>(GetTickCount64());
    (void)StringCchPrintfA(line, RTL_NUMBER_OF(line), "[PID=%lu TID=%lu TICK=%llu] %s\n", pid, tid, tick, message);
    OutputDebugStringA(line);
}

void BkRuntimeReportFault(BkRuntimeFaultCode code, std::uint64_t arg0, std::uint64_t arg1) noexcept
{
    BkDbgLog("Fault code=%lu arg0=0x%llX arg1=0x%llX", static_cast<unsigned long>(code),
                      static_cast<unsigned long long>(arg0), static_cast<unsigned long long>(arg1));
}

namespace BK_RUNTIME_INTERNAL
{
    WinsockHookController g_WinsockController;
    NtHookController g_NtHookController;
    KiHookController g_KiHookController;
    ModuleHookController g_ModuleHookController;
    bool g_WinsockInitialized = false;
    bool g_NtInitialized = false;
    bool g_KiInitialized = false;
    bool g_ModuleInitialized = false;
    ULONGLONG g_LastIntegrityCheckTick = 0;
    ULONGLONG g_LastIntegrityPublishTick = 0;
    std::uint32_t g_LastIntegrityMask = UINT32_MAX;
    std::uint64_t g_IntegrityCheckCount = 0;
    ExportProbeCache g_AmsiProbe;
    ExportProbeCache g_EtwProbe;
    bool g_LastAmsiTampered = false;
    bool g_LastEtwTampered = false;
    bool g_AmsiFirstPoll = true;
    bool g_EtwFirstPoll = true;
    ULONGLONG g_LastAmsiPublishTick = 0;
    ULONGLONG g_LastEtwPublishTick = 0;
    std::atomic<bool> g_RuntimePrimed{false};
    std::atomic<bool> g_RuntimeInitialized{false};
    std::atomic<bool> g_RuntimeWorkerStarted{false};
    std::atomic<std::uint32_t> g_LastPublishedHookReadyMask{0};
    BkBlackbirdTelemetryArguments g_RuntimeVehArgs{};
    std::atomic<bool> g_LaunchGatePrepared{false};
    std::atomic<bool> g_LaunchGateReady{false};
    std::atomic<bool> g_LaunchGateDeferredOpen{false};
    HANDLE g_LaunchGateReadyEvent = nullptr;
    LaunchGatePage g_LaunchGatePages[kLaunchGateMaxPages]{};
    LaunchGateParkContext g_LaunchGateParkContexts[kLaunchGateMaxParkContexts]{};
    std::uint32_t g_LaunchGatePageCount = 0;
    LONG g_LaunchGateInitializerAssigned = 0;
    LaunchGateCallbacks g_LaunchGateCallbacks{};

    PKH_PEB CurrentPeb() noexcept
    {
#if defined(_M_X64)
        return reinterpret_cast<PKH_PEB>(__readgsqword(0x60));
#elif defined(_M_IX86)
        return reinterpret_cast<PKH_PEB>(__readfsdword(0x30));
#else
        return nullptr;
#endif
    }

    bool UnicodeStringEqualsInsensitive(const KH_UNICODE_STRING &value, const wchar_t *literal) noexcept
    {
        if (literal == nullptr || value.Buffer == nullptr)
        {
            return false;
        }

        std::size_t literalChars = std::wcslen(literal);
        std::size_t valueChars = static_cast<std::size_t>(value.Length / sizeof(wchar_t));
        if (literalChars != valueChars)
        {
            return false;
        }

        for (std::size_t i = 0; i < literalChars; ++i)
        {
            wchar_t left = value.Buffer[i];
            wchar_t right = literal[i];
            if (left >= L'A' && left <= L'Z')
            {
                left = static_cast<wchar_t>(left + (L'a' - L'A'));
            }
            if (right >= L'A' && right <= L'Z')
            {
                right = static_cast<wchar_t>(right + (L'a' - L'A'));
            }
            if (left != right)
            {
                return false;
            }
        }

        return true;
    }

    const std::uint8_t *ImagePointerFromRva(const std::uint8_t *moduleBase, DWORD rva, std::size_t bytesNeeded) noexcept
    {
        if (moduleBase == nullptr || rva == 0)
        {
            return nullptr;
        }

        const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(moduleBase);
        if (dos == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return nullptr;
        }

        const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(moduleBase + static_cast<std::size_t>(dos->e_lfanew));
        if (nt == nullptr || nt->Signature != IMAGE_NT_SIGNATURE)
        {
            return nullptr;
        }

        const auto *section = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
        {
            DWORD sectionRva = section->VirtualAddress;
            DWORD sectionSize = std::max(section->Misc.VirtualSize, section->SizeOfRawData);
            if (rva >= sectionRva && rva < (sectionRva + sectionSize))
            {
                std::size_t offset = static_cast<std::size_t>(rva - sectionRva);
                if (offset + bytesNeeded > sectionSize)
                {
                    return nullptr;
                }
                return moduleBase + sectionRva + offset;
            }
        }

        return moduleBase + rva;
    }

    void *FindProcessImageBase() noexcept
    {
        HMODULE module = GetModuleHandleW(nullptr);
        if (module != nullptr)
        {
            return module;
        }

        PKH_PEB peb = CurrentPeb();
        if (peb == nullptr || peb->Ldr == nullptr)
        {
            return (peb != nullptr) ? peb->ImageBaseAddress : nullptr;
        }

        if (peb->ImageBaseAddress != nullptr)
        {
            return peb->ImageBaseAddress;
        }

        LIST_ENTRY *head = &peb->Ldr->InLoadOrderModuleList;
        if (head->Flink == nullptr || head->Flink == head)
        {
            return nullptr;
        }

        auto *entry = CONTAINING_RECORD(head->Flink, KH_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        return entry->DllBase;
    }

    void *FindLoadedModuleBaseByName(const wchar_t *moduleName) noexcept
    {
        PKH_PEB peb = CurrentPeb();
        if (moduleName == nullptr || peb == nullptr || peb->Ldr == nullptr)
        {
            return nullptr;
        }

        LIST_ENTRY *head = &peb->Ldr->InLoadOrderModuleList;
        for (LIST_ENTRY *cursor = head->Flink; cursor != nullptr && cursor != head; cursor = cursor->Flink)
        {
            auto *entry = CONTAINING_RECORD(cursor, KH_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (UnicodeStringEqualsInsensitive(entry->BaseDllName, moduleName))
            {
                return entry->DllBase;
            }
        }

        return nullptr;
    }

    void *ResolveExportByName(void *moduleBase, const char *name) noexcept
    {
        if (moduleBase == nullptr || name == nullptr || name[0] == '\0')
        {
            return nullptr;
        }

        const auto *base = static_cast<const std::uint8_t *>(moduleBase);
        const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
        if (dos == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return nullptr;
        }

        const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(base + static_cast<std::size_t>(dos->e_lfanew));
        if (nt == nullptr || nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        {
            return nullptr;
        }

        const IMAGE_DATA_DIRECTORY &exportDirEntry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDirEntry.VirtualAddress == 0 || exportDirEntry.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
        {
            return nullptr;
        }

        const auto *exportDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(
            ImagePointerFromRva(base, exportDirEntry.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY)));
        if (exportDir == nullptr)
        {
            return nullptr;
        }

        const auto *nameRvAs = reinterpret_cast<const DWORD *>(
            ImagePointerFromRva(base, exportDir->AddressOfNames, exportDir->NumberOfNames * sizeof(DWORD)));
        const auto *ordinals = reinterpret_cast<const WORD *>(
            ImagePointerFromRva(base, exportDir->AddressOfNameOrdinals, exportDir->NumberOfNames * sizeof(WORD)));
        const auto *functions = reinterpret_cast<const DWORD *>(
            ImagePointerFromRva(base, exportDir->AddressOfFunctions, exportDir->NumberOfFunctions * sizeof(DWORD)));
        if (nameRvAs == nullptr || ordinals == nullptr || functions == nullptr)
        {
            return nullptr;
        }

        for (DWORD i = 0; i < exportDir->NumberOfNames; ++i)
        {
            const char *exportName =
                reinterpret_cast<const char *>(ImagePointerFromRva(base, nameRvAs[i], std::strlen(name) + 1));
            if (exportName == nullptr || std::strcmp(exportName, name) != 0)
            {
                continue;
            }

            WORD ordinal = ordinals[i];
            if (ordinal >= exportDir->NumberOfFunctions)
            {
                return nullptr;
            }

            return const_cast<std::uint8_t *>(base) + functions[ordinal];
        }

        return nullptr;
    }

    bool NativeQueryMemory(void *address, MEMORY_BASIC_INFORMATION *memoryInfo) noexcept
    {
        if (memoryInfo == nullptr)
        {
            return false;
        }
        return VirtualQuery(address, memoryInfo, sizeof(*memoryInfo)) == sizeof(*memoryInfo);
    }

    bool NativeProtect(void *address, SIZE_T regionSize, ULONG newProtect, PULONG oldProtect) noexcept
    {
        if (address == nullptr || regionSize == 0 || oldProtect == nullptr)
        {
            return false;
        }

        DWORD previous = 0;
        if (!VirtualProtect(address, regionSize, newProtect, &previous))
        {
            return false;
        }

        *oldProtect = previous;
        return true;
    }

    HANDLE NativeCreateEvent(bool manualReset, bool initialState, const wchar_t *name) noexcept
    {
        return CreateEventW(nullptr, manualReset ? TRUE : FALSE, initialState ? TRUE : FALSE, name);
    }

    void NativeCloseHandle(HANDLE handle) noexcept
    {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE)
        {
            (void)CloseHandle(handle);
        }
    }

    bool NativeSetEvent(HANDLE handle) noexcept
    {
        return SetEvent(handle) != FALSE;
    }

    bool NativeWaitForSingleObject(HANDLE handle) noexcept
    {
        return WaitForSingleObject(handle, INFINITE) == WAIT_OBJECT_0;
    }

    void NativeDelayMs(DWORD milliseconds) noexcept
    {
        Sleep(milliseconds);
    }

    void NativeYield() noexcept
    {
        if (!SwitchToThread())
        {
            Sleep(0);
        }
    }

    HANDLE NativeCreateThread(void *startRoutine, void *parameter) noexcept
    {
        HANDLE threadHandle = nullptr;
        auto fn = ResolveNtdllExport<NtCreateThreadExFn>("NtCreateThreadEx");
        if (fn == nullptr)
        {
            auto rtlCreateUserThread = ResolveNtdllExport<RtlCreateUserThreadFn>("RtlCreateUserThread");
            if (rtlCreateUserThread == nullptr)
            {
                return nullptr;
            }

            KH_CLIENT_ID clientId{};
            if (!NtSucceeded(rtlCreateUserThread(CurrentProcessHandle(), nullptr, FALSE, 0, nullptr, nullptr, startRoutine,
                                                 parameter, &threadHandle, &clientId)))
            {
                return nullptr;
            }
            return threadHandle;
        }

        if (!NtSucceeded(fn(&threadHandle, THREAD_ALL_ACCESS, nullptr, CurrentProcessHandle(), startRoutine, parameter, 0,
                            0, 0, 0, nullptr)))
        {
            threadHandle =
                CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(startRoutine), parameter, 0, nullptr);
            return threadHandle;
        }

        return threadHandle;
    }

    [[noreturn]] void NativeTerminateCurrentProcess(DWORD exitStatus) noexcept
    {
        auto fn = ResolveNtdllExport<NtTerminateProcessFn>("NtTerminateProcess");
        if (fn != nullptr)
        {
            (void)fn(CurrentProcessHandle(), static_cast<NTSTATUS>(exitStatus));
        }

        for (;;)
        {
            NativeDelayMs(1000);
        }
    }

    [[noreturn]] void NativeExitCurrentThread() noexcept
    {
        auto fn = ResolveNtdllExport<RtlExitUserThreadFn>("RtlExitUserThread");
        if (fn != nullptr)
        {
            fn(0);
        }

        for (;;)
        {
            NativeDelayMs(1000);
        }
    }

    void ResetIntegrityWatchdogState() noexcept
    {
        g_LastIntegrityCheckTick = 0;
        g_LastIntegrityPublishTick = 0;
        g_LastIntegrityMask = UINT32_MAX;
        g_IntegrityCheckCount = 0;
        std::memset(&g_AmsiProbe, 0, sizeof(g_AmsiProbe));
        std::memset(&g_EtwProbe, 0, sizeof(g_EtwProbe));
        g_LastAmsiTampered = false;
        g_LastEtwTampered = false;
        g_LastAmsiPublishTick = 0;
        g_LastEtwPublishTick = 0;
        g_AmsiFirstPoll = true;
        g_EtwFirstPoll = true;
    }
} // namespace BK_RUNTIME_INTERNAL

namespace
{
    static void LowNoise(const bk::blackbird::Event &e, void *u) noexcept
    {
        UNREFERENCED_PARAMETER(e);
        UNREFERENCED_PARAMETER(u);
    }

    static void HighNoise(const bk::blackbird::Event &e, void *u) noexcept
    {
        UNREFERENCED_PARAMETER(e);
        UNREFERENCED_PARAMETER(u);
    }

    static bool MemFault(const bk::blackbird::Event &e, EXCEPTION_POINTERS *ep, void *) noexcept
    {
        if (LaunchGateHandleFault(ep))
        {
            return true;
        }

        return e.exception_code == STATUS_GUARD_PAGE_VIOLATION;
    }

    static bool BkRuntimePrimeVectoredExceptionHandler() noexcept
    {
        g_RuntimeVehArgs.target_module_basename = L"SR71.dll";
        g_RuntimeVehArgs.low_noise_telemetry = LowNoise;
        g_RuntimeVehArgs.high_noise_telemetry = HighNoise;
        g_RuntimeVehArgs.memory_fault_handler = MemFault;
        bool ok = BkRegisterVectoredExceptionHandler(&g_RuntimeVehArgs) != nullptr;
        BkDbgLog("BkRuntimePrimeVectoredExceptionHandler: result=%u", ok ? 1u : 0u);
        return ok;
    }
} // namespace

void BkRuntimePrimeHooks() noexcept
{
    bool expected = false;
    if (!g_RuntimePrimed.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        return;
    }

    IC_STACKTRACE::InitCallerClassifier(reinterpret_cast<void *>(&BkRuntimePrimeHooks));
    (void)BkRuntimePrimeVectoredExceptionHandler();

    ResetIntegrityWatchdogState();
    BkDbgLog("BkRuntimePrimeHooks: primed");
}

HANDLE BkRuntimeCreateBootstrapThread(LPTHREAD_START_ROUTINE startRoutine, LPVOID parameter) noexcept
{
    HANDLE threadHandle;

    if (startRoutine == nullptr)
    {
        BkDbgLog("BkRuntimeCreateBootstrapThread: invalid start routine");
        BkRuntimeReportFault(BkRuntimeFaultCode::BootstrapThreadCreateFailed, ERROR_INVALID_PARAMETER);
        return nullptr;
    }

    threadHandle = CreateThread(nullptr, 0, startRoutine, parameter, 0, nullptr);
    if (threadHandle != nullptr)
    {
        BkDbgLog("BkRuntimeCreateBootstrapThread: CreateThread succeeded handle=%p", threadHandle);
        return threadHandle;
    }

    BkDbgLog("BkRuntimeCreateBootstrapThread: CreateThread failed gle=%lu, trying native fallback",
                      (unsigned long)GetLastError());
    threadHandle = NativeCreateThread(reinterpret_cast<void *>(startRoutine), parameter);
    if (threadHandle != nullptr)
    {
        BkDbgLog("BkRuntimeCreateBootstrapThread: native fallback succeeded handle=%p", threadHandle);
    }
    else
    {
        BkDbgLog("BkRuntimeCreateBootstrapThread: native fallback failed");
        BkRuntimeReportFault(BkRuntimeFaultCode::BootstrapThreadCreateFailed, GetLastError());
    }

    return threadHandle;
}

void BkRuntimeCloseHandle(HANDLE handle) noexcept
{
    NativeCloseHandle(handle);
}

void BkRuntimeFailClosed(DWORD exitStatus) noexcept
{
    BkDbgLog("BkRuntimeFailClosed: exitStatus=%lu", (unsigned long)exitStatus);
    BkRuntimeReportFault(BkRuntimeFaultCode::FailClosedTriggered, exitStatus);
    NativeTerminateCurrentProcess(exitStatus);
}

bool BkInitializeSubsystems() noexcept
{
    BkRuntimePrimeHooks();

    if (!BkRuntimePrimeVectoredExceptionHandler())
    {
        BkDbgLog("BkInitializeSubsystems: VEH registration failed");
        BkRuntimeReportFault(BkRuntimeFaultCode::LaunchGatePrepareFailed);
        return false;
    }

    LaunchGateCallbacks callbacks{};
    callbacks.InitializeRuntime = &EnsureRuntimeInitializedForLaunch;
    callbacks.FailClosed = &BkRuntimeFailClosed;
    g_LaunchGateCallbacks = callbacks;
    bool ok = LaunchGatePrepare();
    BkDbgLog("BkInitializeSubsystems: result=%u", ok ? 1u : 0u);
    return ok;
}

void BkRuntimeSignalLaunchGateReady() noexcept
{
    LaunchGateRelease();
}

DWORD WINAPI BkRuntimeThreadProc(LPVOID)
{
    BkDbgLog("BkRuntimeThreadProc: start launchGatePrepared=%u", LaunchGateIsPrepared() ? 1u : 0u);

    if (!EnsureRuntimeInitializedForLaunch(!LaunchGateIsPrepared(), false))
    {
        BkDbgLog("BkRuntimeThreadProc: runtime initialization failed");
        return 0;
    }

    return BkRuntimeEventLoopThreadProc(nullptr);
}

void BkRuntimeShutdown()
{
    BkDbgLog("BkRuntimeShutdown: begin");
    BkRuntimeSignalLaunchGateReady();

    g_KiHookController.Shutdown();
    g_ModuleHookController.Shutdown();
    g_NtHookController.Shutdown();
    g_WinsockController.Shutdown();
    g_ModuleInitialized = false;
    g_KiInitialized = false;
    g_NtInitialized = false;
    g_WinsockInitialized = false;

    IC_STACKTRACE::CleanupSymbols();

    BKIPC::Shutdown();
    BkUnregisterVectoredExceptionHandler();
    LaunchGateShutdown();
    g_RuntimeInitialized.store(false, std::memory_order_release);
    g_RuntimeWorkerStarted.store(false, std::memory_order_release);
    g_LastPublishedHookReadyMask.store(0, std::memory_order_release);
}
