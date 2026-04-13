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
#include "module.h"
#include "ws.h"

#include "../ipc/pipe.h"
#include "../instrument/stacktrace.h"
#include "../instrument/bk.h"

#include <windows.h>

#include <cstdint>
#include <atomic>
#include <vector>
#include <cstring>
#include <algorithm>

namespace
{
    struct ExportProbeCache
    {
        std::uint8_t Expected[16]{};
        bool ExpectedCaptured = false;
        wchar_t ModulePath[MAX_PATH]{};
    };

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
    std::uint32_t g_LastIntegrityMask = UINT32_MAX; // sentinel: first poll always appears as state change
    std::uint64_t g_IntegrityCheckCount = 0;
    ExportProbeCache g_AmsiProbe;
    ExportProbeCache g_EtwProbe;
    bool g_LastAmsiTampered = false;
    bool g_LastEtwTampered = false;
    bool g_AmsiFirstPoll = true; // force publish on first AMSI observation
    bool g_EtwFirstPoll = true;  // force publish on first ETW observation
    ULONGLONG g_LastAmsiPublishTick = 0;
    ULONGLONG g_LastEtwPublishTick = 0;
    std::atomic<bool> g_RuntimePrimed{false};

    inline constexpr std::uint32_t kIntegrityMaskWinsock = 0x00000001u;
    inline constexpr std::uint32_t kIntegrityMaskNt = 0x00000002u;
    inline constexpr std::uint32_t kIntegrityMaskKi = 0x00000004u;
    inline constexpr std::uint32_t kIntegrityMaskModule = 0x00000008u;
    inline constexpr std::uint32_t kIntegrityOperationAmsiPatch = BLACKBIRD_HOOK_EVENT_OP_AMSI_PATCH;
    inline constexpr std::uint32_t kIntegrityOperationEtwPatch = BLACKBIRD_HOOK_EVENT_OP_ETW_PATCH;
    inline constexpr ULONGLONG kIntegrityCheckPeriodMs = 2000ull;
    inline constexpr ULONGLONG kIntegrityRepublishPeriodMs = 10000ull;
    inline constexpr DWORD kIpcInitAttemptTimeoutMs = 64u;
    inline constexpr DWORD kIpcInitRetrySleepMs = 2u;
    inline constexpr DWORD kHookReadyNotifyRetrySleepMs = 1u;
    inline constexpr ULONGLONG kIpcInitMaxWaitMs = 15000ull;
    inline constexpr ULONGLONG kHookReadyNotifyMaxWaitMs = 15000ull;

    template <typename TTrace> void CopyHookStack(const TTrace &trace, BLACKBIRD_IPC_HOOK_EVENT &record) noexcept
    {
        const std::uint32_t safeCount = static_cast<std::uint32_t>(
            (trace.Count > BLACKBIRD_IPC_MAX_HOOK_STACK_FRAMES) ? BLACKBIRD_IPC_MAX_HOOK_STACK_FRAMES : trace.Count);
        record.StackCount = safeCount;
        for (std::uint32_t i = 0; i < safeCount; ++i)
        {
            record.Stack[i] = reinterpret_cast<std::uint64_t>(trace.Frames[i].Ip);
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

    bool EnsureHookControllersReady() noexcept
    {
        if (!g_WinsockInitialized)
        {
            __try
            {
                g_WinsockInitialized = g_WinsockController.Initialize();
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                g_WinsockInitialized = false;
            }
            if (!g_WinsockInitialized && !KeIsWinsockHookRequired())
            {
                g_WinsockInitialized = true;
            }
        }
        if (!g_NtInitialized)
        {
            __try
            {
                g_NtInitialized = g_NtHookController.Initialize();
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                g_NtInitialized = false;
            }
        }
        if (!g_KiInitialized)
        {
            __try
            {
                g_KiInitialized = g_KiHookController.Initialize();
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                g_KiInitialized = false;
            }
            if (!g_KiInitialized && !KeIsKiHookSupported())
            {
                g_KiInitialized = true;
            }
        }
        if (!g_ModuleInitialized)
        {
            __try
            {
                g_ModuleInitialized = g_ModuleHookController.Initialize();
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                g_ModuleInitialized = false;
            }
        }

        return g_WinsockInitialized && g_NtInitialized && g_KiInitialized && g_ModuleInitialized;
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

        for (;;)
        {
            if (BKIPC::Initialize(kIpcInitAttemptTimeoutMs))
            {
                return true;
            }

            if ((GetTickCount64() - startTick) >= kIpcInitMaxWaitMs)
            {
                return false;
            }

            if (!SwitchToThread())
            {
                Sleep(kIpcInitRetrySleepMs);
            }
        }
    }

    bool NotifyHookReadyWithRetry() noexcept
    {
        ULONGLONG startTick = GetTickCount64();

        for (;;)
        {
            std::uint32_t observedMask = 0;
            std::uint32_t localMask = BuildHookReadyMask(true);
            if (BKIPC::NotifyHookReady(localMask, &observedMask))
            {
                return true;
            }

            if ((GetTickCount64() - startTick) >= kHookReadyNotifyMaxWaitMs)
            {
                return false;
            }

            if (!SwitchToThread())
            {
                Sleep(kHookReadyNotifyRetrySleepMs);
            }
        }
    }

    const char *WinsockOperationName(WinsockOperation op) noexcept
    {
        switch (op)
        {
        case WinsockOperation::WsaSend:
            return "WSASend";
        case WinsockOperation::WsaRecv:
            return "WSARecv";
        case WinsockOperation::Send:
            return "send";
        case WinsockOperation::Recv:
            return "recv";
        case WinsockOperation::Connect:
            return "connect";
        case WinsockOperation::WsaConnect:
            return "WSAConnect";
        case WinsockOperation::GetAddrInfoW:
            return "GetAddrInfoW";
        default:
            return "winsock";
        }
    }

    const char *ModuleOperationName(ModuleHookOperation op) noexcept
    {
        switch (op)
        {
        case ModuleHookOperation::LoadLibraryA:
            return "LoadLibraryA";
        case ModuleHookOperation::LoadLibraryW:
            return "LoadLibraryW";
        case ModuleHookOperation::LoadLibraryExA:
            return "LoadLibraryExA";
        case ModuleHookOperation::LoadLibraryExW:
            return "LoadLibraryExW";
        case ModuleHookOperation::LdrLoadDll:
            return "LdrLoadDll";
        default:
            return "LoadLibrary";
        }
    }

    // Encode a CallerClassification into the hook event's CallerFlags field.
    static inline std::uint32_t BuildCallerFlags(const IC_STACKTRACE::CallerClassification &cls) noexcept
    {
        std::uint32_t flags = cls.Flags;
        flags |= (static_cast<std::uint32_t>(cls.ImmediateCaller) << BLACKBIRD_HOOK_CALLER_IMMED_SHIFT);
        flags |= (static_cast<std::uint32_t>(cls.DeepestOrigin) << BLACKBIRD_HOOK_CALLER_DEEP_SHIFT);
        return flags;
    }

    bool SendWinsockEvent(const WinsockCapturedEvent &evt) noexcept
    {
        using namespace BKIPC;

        auto cls = IC_STACKTRACE::ClassifyTrace(evt.Stack);

        // Drop events whose entire call chain is system-DLL code.  These are
        // OS-internal Winsock operations, not target-initiated network activity.
        if (cls.Flags & IC_STACKTRACE::kCallerFlagAllSystem)
            return true;

        BLACKBIRD_IPC_HOOK_EVENT record{};
        const char *opName = WinsockOperationName(evt.Operation);
        std::size_t sampleSize = std::min<std::size_t>(evt.Data.size(), RTL_NUMBER_OF(record.DataSample));

        record.Kind = BlackbirdIpcHookEventWinsock;
        record.ProcessId = GetCurrentProcessId();
        record.ThreadId = evt.ThreadId;
        record.Operation = static_cast<std::uint32_t>(evt.Operation);
        record.Caller = reinterpret_cast<std::uint64_t>(evt.Caller);
        record.Context0 = static_cast<std::uint64_t>(static_cast<ULONG_PTR>(evt.Socket));
        record.Context1 = evt.Args[0];
        record.Context2 = evt.Args[1];
        record.Context3 = evt.Args[2];
        record.ArgCount = 4;
        for (std::size_t i = 0; i < RTL_NUMBER_OF(evt.Args); ++i)
        {
            record.Args[i] = evt.Args[i];
        }
        record.DataSize = static_cast<std::uint32_t>(sampleSize);
        record.CallerFlags = BuildCallerFlags(cls);
        (void)strncpy_s(record.ApiName, opName, _TRUNCATE);
        (void)strncpy_s(record.ModuleName, "WS2_32", _TRUNCATE);
        if (sampleSize != 0)
        {
            CopyMemory(record.DataSample, evt.Data.data(), sampleSize);
        }
        CopyHookStack(evt.Stack, record);
        return PublishHookEvent(record);
    }

    bool SendNtEvent(const NtCapturedEvent &evt) noexcept
    {
        using namespace BKIPC;

        auto cls = IC_STACKTRACE::ClassifyTrace(evt.Stack);

        // Drop events whose entire call chain is system-DLL code.  The monitored
        // process itself — or an injected DLL — must appear somewhere in the stack
        // for the event to be worth reporting.
        if (cls.Flags & IC_STACKTRACE::kCallerFlagAllSystem)
            return true;

        BLACKBIRD_IPC_HOOK_EVENT record{};
        const char *functionName =
            (evt.FunctionName != nullptr && evt.FunctionName[0] != '\0') ? evt.FunctionName : "NtCall";

        record.Kind = BlackbirdIpcHookEventNt;
        record.ProcessId = GetCurrentProcessId();
        record.ThreadId = evt.ThreadId;
        record.Operation = static_cast<std::uint32_t>(evt.Operation);
        record.Caller = reinterpret_cast<std::uint64_t>(evt.Caller);
        record.Context0 = evt.Args[0];
        record.Context1 = evt.Args[1];
        record.Context2 = evt.Args[2];
        record.Context3 = evt.Args[3];
        record.ArgCount = 8;
        for (std::size_t i = 0; i < RTL_NUMBER_OF(record.Args); ++i)
        {
            record.Args[i] = evt.Args[i];
        }
        record.DataSize = 0;
        record.CallerFlags = BuildCallerFlags(cls);
        CopyHookStack(evt.Stack, record);

        (void)strncpy_s(record.ApiName, functionName, _TRUNCATE);
        (void)strncpy_s(record.ModuleName, "ntdll", _TRUNCATE);
        return PublishHookEvent(record);
    }

    bool SendKiEvent(const KiCapturedEvent &evt) noexcept
    {
        using namespace BKIPC;

        auto cls = IC_STACKTRACE::ClassifyTrace(evt.Stack);

        // Ki (APC dispatcher / syscall stub) events from pure system-DLL chains
        // are OS-internal dispatch; drop them to avoid flooding with routine noise.
        if (cls.Flags & IC_STACKTRACE::kCallerFlagAllSystem)
            return true;

        const char *stubName = evt.StubName ? evt.StubName : "";

        BLACKBIRD_IPC_HOOK_EVENT record{};
        record.Kind = BlackbirdIpcHookEventKi;
        record.ProcessId = GetCurrentProcessId();
        record.ThreadId = evt.ThreadId;
        record.Operation = 0;
        record.Caller = reinterpret_cast<std::uint64_t>(evt.Caller);
        record.Context0 = reinterpret_cast<std::uint64_t>(evt.StackPointer);
        record.ArgCount = 0;
        record.DataSize = 0;
        record.CallerFlags = BuildCallerFlags(cls);
        CopyHookStack(evt.Stack, record);
        (void)strncpy_s(record.ApiName, (stubName[0] != '\0') ? stubName : "KiUserApcDispatcher", _TRUNCATE);
        (void)strncpy_s(record.ModuleName, "ntdll", _TRUNCATE);
        return PublishHookEvent(record);
    }

    bool SendModuleEvent(const ModuleCapturedEvent &evt) noexcept
    {
        using namespace BKIPC;

        auto cls = IC_STACKTRACE::ClassifyTrace(evt.Stack);
        if (cls.Flags & IC_STACKTRACE::kCallerFlagAllSystem)
            return true;

        BLACKBIRD_IPC_HOOK_EVENT record{};
        const char *functionName = ModuleOperationName(evt.Operation);
        std::size_t sampleSize = std::min<std::size_t>(evt.NameSample.size(), RTL_NUMBER_OF(record.DataSample));

        record.Kind = BlackbirdIpcHookEventModule;
        record.ProcessId = GetCurrentProcessId();
        record.ThreadId = evt.ThreadId;
        record.Operation = static_cast<std::uint32_t>(evt.Operation);
        record.Caller = reinterpret_cast<std::uint64_t>(evt.Caller);
        record.Context0 = reinterpret_cast<std::uint64_t>(evt.ModuleHandle);
        record.Context1 = evt.Args[0];
        record.Context2 = evt.Args[1];
        record.Context3 = evt.Args[2];
        record.ArgCount = 4;
        record.CallerFlags = BuildCallerFlags(cls);
        for (std::size_t i = 0; i < RTL_NUMBER_OF(evt.Args); ++i)
        {
            record.Args[i] = evt.Args[i];
        }
        if (sampleSize != 0)
        {
            record.DataSize = static_cast<std::uint32_t>(sampleSize);
            CopyMemory(record.DataSample, evt.NameSample.data(), sampleSize);
        }
        CopyHookStack(evt.Stack, record);
        (void)strncpy_s(record.ApiName, functionName, _TRUNCATE);
        (void)strncpy_s(record.ModuleName, (evt.SourceModule != nullptr) ? evt.SourceModule : "KERNEL32",
                        _TRUNCATE);
        return PublishHookEvent(record);
    }

    void FlushHookEvents() noexcept
    {
        {
            std::vector<WinsockCapturedEvent> events = g_WinsockController.ConsumeEvents();

            for (const auto &evt : events)
            {
                (void)SendWinsockEvent(evt);
            }
        }

        {
            std::vector<NtCapturedEvent> events = g_NtHookController.ConsumeEvents();

            for (const auto &evt : events)
                (void)SendNtEvent(evt);
        }

        {
            std::vector<KiCapturedEvent> events = g_KiHookController.ConsumeEvents();

            for (const auto &evt : events)
                (void)SendKiEvent(evt);
        }

        {
            std::vector<ModuleCapturedEvent> events = g_ModuleHookController.ConsumeEvents();

            for (const auto &evt : events)
                (void)SendModuleEvent(evt);
        }
    }

    bool SendHookIntegrityEvent(std::uint32_t integrityMask, std::uint32_t winsockMismatches,
                                std::uint32_t ntMismatches, std::uint32_t kiMismatches,
                                std::uint32_t moduleMismatches) noexcept
    {
        using namespace BKIPC;

        BLACKBIRD_IPC_HOOK_EVENT record{};
        record.Kind = BlackbirdIpcHookEventIntegrity;
        record.ProcessId = GetCurrentProcessId();
        record.ThreadId = GetCurrentThreadId();
        record.Operation = (integrityMask != 0u) ? 1u : 0u;
        record.Caller = 0;
        record.Context0 = integrityMask;
        record.Context1 = winsockMismatches;
        record.Context2 = ntMismatches;
        record.Context3 = kiMismatches;
        record.ArgCount = 3;
        record.Args[0] = g_IntegrityCheckCount;
        record.Args[1] = static_cast<std::uint64_t>(GetTickCount64());
        record.Args[2] = moduleMismatches;
        (void)strncpy_s(record.ApiName, "HookIntegrity", _TRUNCATE);
        (void)strncpy_s(record.ModuleName, "SR71", _TRUNCATE);
        return PublishHookEvent(record);
    }

    bool IsSuspiciousPatchedPrologue(const std::uint8_t bytes[16]) noexcept
    {
        if (bytes == nullptr)
        {
            return false;
        }

        if (bytes[0] == 0xC3 || bytes[0] == 0xC2 || bytes[0] == 0xE9 || bytes[0] == 0xE8 || bytes[0] == 0xEB ||
            bytes[0] == 0xCC)
        {
            return true;
        }

        if (bytes[0] == 0x33 && bytes[1] == 0xC0 && bytes[2] == 0xC3)
        {
            return true;
        }

        if (bytes[0] == 0x48 && bytes[1] == 0x31 && bytes[2] == 0xC0 && bytes[3] == 0xC3)
        {
            return true;
        }

        if (bytes[0] == 0xB8 && bytes[5] == 0xC3)
        {
            return true;
        }

        if (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0)
        {
            return true;
        }

        if (bytes[0] == 0xFF && bytes[1] == 0x25)
        {
            return true;
        }

        return false;
    }

    const std::uint8_t *RvaToFilePointer(const std::uint8_t *imageBase, std::size_t imageSize, DWORD rva,
                                        std::size_t bytesNeeded) noexcept
    {
        if (imageBase == nullptr || imageSize < sizeof(IMAGE_DOS_HEADER) || bytesNeeded == 0)
        {
            return nullptr;
        }

        const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(imageBase);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
            static_cast<std::size_t>(dos->e_lfanew) > (imageSize - sizeof(IMAGE_NT_HEADERS64)))
        {
            return nullptr;
        }

        const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(imageBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            return nullptr;
        }

        if (rva < nt->OptionalHeader.SizeOfHeaders)
        {
            if (static_cast<std::size_t>(rva) > imageSize || bytesNeeded > (imageSize - static_cast<std::size_t>(rva)))
            {
                return nullptr;
            }
            return imageBase + rva;
        }

        const auto *section = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
        {
            DWORD sectionRva = section->VirtualAddress;
            DWORD rawSize = section->SizeOfRawData;
            DWORD virtualSize = section->Misc.VirtualSize;
            DWORD span = (rawSize > virtualSize) ? rawSize : virtualSize;
            if (span == 0)
            {
                continue;
            }

            if (rva < sectionRva || rva >= (sectionRva + span))
            {
                continue;
            }

            DWORD offset = rva - sectionRva;
            if (offset > rawSize || bytesNeeded > static_cast<std::size_t>(rawSize - offset))
            {
                return nullptr;
            }

            std::size_t fileOffset = static_cast<std::size_t>(section->PointerToRawData) + offset;
            if (fileOffset > imageSize || bytesNeeded > (imageSize - fileOffset))
            {
                return nullptr;
            }

            return imageBase + fileOffset;
        }

        return nullptr;
    }

    bool RefreshExpectedExportBytes(HMODULE moduleHandle, const char *exportName, ExportProbeCache &cache) noexcept
    {
        wchar_t modulePath[MAX_PATH]{};
        HANDLE fileHandle = INVALID_HANDLE_VALUE;
        HANDLE mappingHandle = nullptr;
        const std::uint8_t *view = nullptr;
        bool success = false;

        if (moduleHandle == nullptr || exportName == nullptr)
        {
            return false;
        }

        DWORD pathChars = GetModuleFileNameW(moduleHandle, modulePath, RTL_NUMBER_OF(modulePath));
        if (pathChars == 0 || pathChars >= RTL_NUMBER_OF(modulePath))
        {
            return false;
        }

        if (cache.ExpectedCaptured && _wcsicmp(cache.ModulePath, modulePath) == 0)
        {
            return true;
        }

        fileHandle = CreateFileW(modulePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        mappingHandle = CreateFileMappingW(fileHandle, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (mappingHandle == nullptr)
        {
            CloseHandle(fileHandle);
            return false;
        }

        view = static_cast<const std::uint8_t *>(MapViewOfFile(mappingHandle, FILE_MAP_READ, 0, 0, 0));
        if (view != nullptr)
        {
            LARGE_INTEGER size{};
            if (GetFileSizeEx(fileHandle, &size) && size.QuadPart > 0 &&
                static_cast<ULONGLONG>(size.QuadPart) <= static_cast<ULONGLONG>(SIZE_MAX))
            {
                std::size_t imageSize = static_cast<std::size_t>(size.QuadPart);
                const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(view);
                if (imageSize >= sizeof(IMAGE_DOS_HEADER) && dos->e_magic == IMAGE_DOS_SIGNATURE &&
                    dos->e_lfanew > 0 && static_cast<std::size_t>(dos->e_lfanew) <= (imageSize - sizeof(IMAGE_NT_HEADERS64)))
                {
                    const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(view + dos->e_lfanew);
                    if (nt->Signature == IMAGE_NT_SIGNATURE &&
                        nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
                    {
                        const auto &exportDirEntry =
                            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                        const auto *exportDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(
                            RvaToFilePointer(view, imageSize, exportDirEntry.VirtualAddress,
                                             sizeof(IMAGE_EXPORT_DIRECTORY)));
                        if (exportDir != nullptr)
                        {
                            const auto *nameRvAs = reinterpret_cast<const DWORD *>(
                                RvaToFilePointer(view, imageSize, exportDir->AddressOfNames,
                                                 exportDir->NumberOfNames * sizeof(DWORD)));
                            const auto *nameOrdinals = reinterpret_cast<const WORD *>(
                                RvaToFilePointer(view, imageSize, exportDir->AddressOfNameOrdinals,
                                                 exportDir->NumberOfNames * sizeof(WORD)));
                            const auto *functionRvAs = reinterpret_cast<const DWORD *>(
                                RvaToFilePointer(view, imageSize, exportDir->AddressOfFunctions,
                                                 exportDir->NumberOfFunctions * sizeof(DWORD)));

                            if (nameRvAs != nullptr && nameOrdinals != nullptr && functionRvAs != nullptr)
                            {
                                for (DWORD i = 0; i < exportDir->NumberOfNames; ++i)
                                {
                                    const char *name = reinterpret_cast<const char *>(
                                        RvaToFilePointer(view, imageSize, nameRvAs[i], 1));
                                    if (name == nullptr || strcmp(name, exportName) != 0)
                                    {
                                        continue;
                                    }

                                    WORD ordinal = nameOrdinals[i];
                                    if (ordinal >= exportDir->NumberOfFunctions)
                                    {
                                        break;
                                    }

                                    DWORD functionRva = functionRvAs[ordinal];
                                    if (functionRva >= exportDirEntry.VirtualAddress &&
                                        functionRva < (exportDirEntry.VirtualAddress + exportDirEntry.Size))
                                    {
                                        break;
                                    }

                                    const std::uint8_t *expected = RvaToFilePointer(view, imageSize, functionRva, 16);
                                    if (expected != nullptr)
                                    {
                                        std::memcpy(cache.Expected, expected, 16);
                                        (void)wcscpy_s(cache.ModulePath, modulePath);
                                        cache.ExpectedCaptured = true;
                                        success = true;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            UnmapViewOfFile(view);
        }

        CloseHandle(mappingHandle);
        CloseHandle(fileHandle);
        return success;
    }

    bool ProbeExportPatchState(const wchar_t *moduleName, const char *exportName, ExportProbeCache &cache,
                               bool &present, bool &tampered, bool &suspicious, bool &expectedMismatch,
                               std::uint8_t sample[16]) noexcept
    {
        HMODULE moduleHandle = nullptr;
        FARPROC exportAddress = nullptr;

        present = false;
        tampered = false;
        suspicious = false;
        expectedMismatch = false;
        if (sample != nullptr)
        {
            std::memset(sample, 0, 16);
        }

        if (moduleName == nullptr || exportName == nullptr || sample == nullptr)
        {
            return false;
        }

        moduleHandle = GetModuleHandleW(moduleName);
        if (moduleHandle == nullptr)
        {
            return true;
        }

        exportAddress = GetProcAddress(moduleHandle, exportName);
        if (exportAddress == nullptr)
        {
            return true;
        }

        present = true;
        std::memcpy(sample, exportAddress, 16);
        suspicious = IsSuspiciousPatchedPrologue(sample);

        if (RefreshExpectedExportBytes(moduleHandle, exportName, cache))
        {
            expectedMismatch = std::memcmp(sample, cache.Expected, 16) != 0;
        }

        tampered = suspicious || expectedMismatch;
        return true;
    }

    bool SendPatchTamperEvent(std::uint32_t operation, const char *apiName, const char *moduleName, bool tampered,
                              bool suspicious, bool expectedMismatch, const std::uint8_t sample[16]) noexcept
    {
        using namespace BKIPC;

        BLACKBIRD_IPC_HOOK_EVENT record{};
        record.Kind = BlackbirdIpcHookEventIntegrity;
        record.ProcessId = GetCurrentProcessId();
        record.ThreadId = GetCurrentThreadId();
        record.Operation = operation;
        record.Caller = 0;
        record.Context0 = tampered ? 1u : 0u;
        record.Context1 = suspicious ? 1u : 0u;
        record.Context2 = expectedMismatch ? 1u : 0u;
        record.Context3 = g_IntegrityCheckCount;
        record.ArgCount = 1;
        record.Args[0] = static_cast<std::uint64_t>(GetTickCount64());
        record.DataSize = 16;
        std::memcpy(record.DataSample, sample, 16);
        (void)strncpy_s(record.ApiName, apiName != nullptr ? apiName : "UnknownPatchProbe", _TRUNCATE);
        (void)strncpy_s(record.ModuleName, moduleName != nullptr ? moduleName : "unknown", _TRUNCATE);
        return PublishHookEvent(record);
    }

    void PollAmsiEtwPatchWatchdog(ULONGLONG now) noexcept
    {
        bool present = false;
        bool tampered = false;
        bool suspicious = false;
        bool expectedMismatch = false;
        std::uint8_t sample[16]{};

        if (ProbeExportPatchState(L"amsi.dll", "AmsiScanBuffer", g_AmsiProbe, present, tampered, suspicious,
                                  expectedMismatch, sample))
        {
            if (present)
            {
                bool stateChanged = g_AmsiFirstPoll || (tampered != g_LastAmsiTampered);
                g_AmsiFirstPoll = false;
                bool publish =
                    stateChanged || (tampered && (now - g_LastAmsiPublishTick >= kIntegrityRepublishPeriodMs));
                if (publish && SendPatchTamperEvent(kIntegrityOperationAmsiPatch, "AmsiScanBuffer", "amsi",
                                                    tampered, suspicious, expectedMismatch, sample))
                {
                    g_LastAmsiPublishTick = now;
                }
                g_LastAmsiTampered = tampered;
            }
            else
            {
                std::memset(&g_AmsiProbe, 0, sizeof(g_AmsiProbe));
                g_AmsiFirstPoll = false;
                g_LastAmsiTampered = false;
            }
        }

        if (ProbeExportPatchState(L"ntdll.dll", "EtwEventWrite", g_EtwProbe, present, tampered, suspicious,
                                  expectedMismatch, sample))
        {
            if (present)
            {
                bool stateChanged = g_EtwFirstPoll || (tampered != g_LastEtwTampered);
                g_EtwFirstPoll = false;
                bool publish =
                    stateChanged || (tampered && (now - g_LastEtwPublishTick >= kIntegrityRepublishPeriodMs));
                if (publish && SendPatchTamperEvent(kIntegrityOperationEtwPatch, "EtwEventWrite", "ntdll",
                                                    tampered, suspicious, expectedMismatch, sample))
                {
                    g_LastEtwPublishTick = now;
                }
                g_LastEtwTampered = tampered;
            }
            else
            {
                std::memset(&g_EtwProbe, 0, sizeof(g_EtwProbe));
                g_EtwFirstPoll = false;
                g_LastEtwTampered = false;
            }
        }
    }

    void PollHookIntegrityWatchdog() noexcept
    {
        ULONGLONG now = GetTickCount64();
        if (now - g_LastIntegrityCheckTick < kIntegrityCheckPeriodMs)
        {
            return;
        }
        g_LastIntegrityCheckTick = now;
        ++g_IntegrityCheckCount;

        if (!g_WinsockInitialized && !g_NtInitialized && !g_KiInitialized && !g_ModuleInitialized)
        {
            PollAmsiEtwPatchWatchdog(now);
            return;
        }

        std::uint32_t winsockMismatches = 0;
        std::uint32_t ntMismatches = 0;
        std::uint32_t kiMismatches = 0;
        std::uint32_t moduleMismatches = 0;
        std::uint32_t integrityMask = 0;

        if (g_WinsockInitialized && !KeCheckWinsockHookIntegrity(&winsockMismatches))
        {
            integrityMask |= kIntegrityMaskWinsock;
        }
        if (g_NtInitialized && !KeCheckNtHookIntegrity(&ntMismatches))
        {
            integrityMask |= kIntegrityMaskNt;
        }
        if (g_KiInitialized && !KeCheckKiHookIntegrity(&kiMismatches))
        {
            integrityMask |= kIntegrityMaskKi;
        }
        if (g_ModuleInitialized && !KeCheckModuleHookIntegrity(&moduleMismatches))
        {
            integrityMask |= kIntegrityMaskModule;
        }

        bool stateChanged = integrityMask != g_LastIntegrityMask;
        bool publish = false;
        if (integrityMask != 0u)
        {
            publish = stateChanged || (now - g_LastIntegrityPublishTick >= kIntegrityRepublishPeriodMs);
        }
        else if (stateChanged && g_LastIntegrityMask != 0u)
        {
            publish = true;
        }

        g_LastIntegrityMask = integrityMask;
        if (publish && SendHookIntegrityEvent(integrityMask, winsockMismatches, ntMismatches, kiMismatches,
                                              moduleMismatches))
        {
            g_LastIntegrityPublishTick = now;
        }

        PollAmsiEtwPatchWatchdog(now);
    }
} // namespace

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

static bool MemFault(const bk::blackbird::Event &e, EXCEPTION_POINTERS *, void *) noexcept
{
    return e.exception_code == STATUS_GUARD_PAGE_VIOLATION;
}

void BkRuntimePrimeHooks() noexcept
{
    bool expected = false;
    if (!g_RuntimePrimed.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        return;
    }

    // Register our own module so ClassifyTrace can exclude SR71 frames from the
    // call-origin analysis.  Pass a pointer to a function that lives in this
    // compilation unit (i.e. inside SR71.dll) so GetModuleHandleExA can resolve
    // the HMODULE from its address.
    IC_STACKTRACE::InitCallerClassifier(reinterpret_cast<void *>(&BkRuntimePrimeHooks));

    static BkBlackbirdTelemetryArguments g_sw{};
    g_sw.target_module_basename = L"SR71.dll";
    g_sw.low_noise_telemetry = LowNoise;
    g_sw.high_noise_telemetry = HighNoise;
    g_sw.memory_fault_handler = MemFault;
    BkRegisterVectoredExceptionHandler(&g_sw);

    ResetIntegrityWatchdogState();
}

DWORD WINAPI BkRuntimeThreadProc(LPVOID)
{
    bool ipcReady;

    BkRuntimePrimeHooks();

    ipcReady = InitializeIpcWithRetry();

    // Signal controller launch-gating as soon as IPC is alive. The controller's
    // launch wait only requires IPC_CONNECTED, so this is the only readiness
    // notification the controller needs before it can continue launch/attach.
    if (ipcReady)
    {
        (void)NotifyHookReadyWithRetry();
    }

    (void)EnsureHookControllersReady();

    for (;;)
    {
        __try
        {
            FlushHookEvents();
            PollHookIntegrityWatchdog();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        ::Sleep(60);
    }

    __assume(0);
}

void BkRuntimeShutdown()
{
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
}
