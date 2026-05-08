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

__declspec(thread) int g_Sr71CallDepth = 0;

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

    char programData[MAX_PATH]{};
    DWORD programDataChars = GetEnvironmentVariableA("ProgramData", programData, RTL_NUMBER_OF(programData));
    if (programDataChars == 0 || programDataChars >= RTL_NUMBER_OF(programData))
    {
        (void)StringCchCopyA(programData, RTL_NUMBER_OF(programData), "C:\\ProgramData");
    }

    char logDir[MAX_PATH]{};
    char nodeDir[MAX_PATH]{};
    char rootDir[MAX_PATH]{};
    (void)StringCchPrintfA(rootDir, RTL_NUMBER_OF(rootDir), "%s\\Blackbird", programData);
    (void)CreateDirectoryA(rootDir, nullptr);
    (void)StringCchPrintfA(nodeDir, RTL_NUMBER_OF(nodeDir), "%s\\Node", rootDir);
    (void)CreateDirectoryA(nodeDir, nullptr);
    (void)StringCchPrintfA(logDir, RTL_NUMBER_OF(logDir), "%s\\logs", nodeDir);
    (void)CreateDirectoryA(logDir, nullptr);

    char logPath[MAX_PATH]{};
    (void)StringCchPrintfA(logPath, RTL_NUMBER_OF(logPath), "%s\\sr71-%lu.log", logDir, pid);
    HANDLE logFile = CreateFileA(logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (logFile != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        (void)WriteFile(logFile, line, static_cast<DWORD>(strnlen(line, RTL_NUMBER_OF(line))), &written, nullptr);
        CloseHandle(logFile);
    }
}

void BkRuntimeReportFault(BkRuntimeFaultCode code, std::uint64_t arg0, std::uint64_t arg1) noexcept
{
    BkDbgLog("Fault code=%lu arg0=0x%llX arg1=0x%llX", static_cast<unsigned long>(code),
             static_cast<unsigned long long>(arg0), static_cast<unsigned long long>(arg1));
}

namespace BK_RUNTIME_INTERNAL
{
    namespace
    {
        inline constexpr std::uint16_t kInvalidIhrSlot = 0;
        inline constexpr std::size_t kMaxIndirectHandles = 256;

        struct IndirectHandleEntry
        {
            std::uint64_t EncodedPointer = 0;
            std::uint64_t Size = 0;
            std::uint32_t Flags = 0;
            std::uint32_t TagHash = 0;
            std::uint32_t Type = 0;
            std::uint32_t Generation = 0;
            bool Active = false;
        };

        SRWLOCK g_IndirectHandleLock = SRWLOCK_INIT;
        IndirectHandleEntry g_IndirectHandles[kMaxIndirectHandles]{};
        std::uint64_t g_IndirectHandleCookie = 0;
        std::uint32_t g_IndirectHandleGeneration = 0x70000000u;

        std::uint64_t RotateLeft64(std::uint64_t value, unsigned int bits) noexcept
        {
            bits &= 63u;
            return bits == 0 ? value : ((value << bits) | (value >> (64u - bits)));
        }

        std::uint32_t HashTag(const char *tag) noexcept
        {
            std::uint32_t hash = 2166136261u;
            if (tag == nullptr)
            {
                return hash;
            }

            while (*tag != '\0')
            {
                hash ^= static_cast<std::uint8_t>(*tag++);
                hash *= 16777619u;
            }
            return hash;
        }

        std::uint64_t BuildIndirectHandleCookie() noexcept
        {
            LARGE_INTEGER counter{};
            (void)QueryPerformanceCounter(&counter);
            std::uintptr_t localAddress = reinterpret_cast<std::uintptr_t>(&counter);
            std::uint64_t cookie = static_cast<std::uint64_t>(counter.QuadPart);
            cookie ^= (static_cast<std::uint64_t>(GetCurrentProcessId()) << 32);
            cookie ^= static_cast<std::uint64_t>(GetCurrentThreadId());
            cookie ^= static_cast<std::uint64_t>(localAddress);
            cookie ^= __rdtsc();
            cookie = RotateLeft64(cookie, 17) ^ 0xA71C5D79B31F420Bull;
            return cookie != 0 ? cookie : 0x5D1B11D700000071ull;
        }

        std::uint64_t IndirectHandleCookie() noexcept
        {
            if (g_IndirectHandleCookie == 0)
            {
                g_IndirectHandleCookie = BuildIndirectHandleCookie();
            }
            return g_IndirectHandleCookie;
        }

        Sr71IhrToken EncodeToken(std::uint16_t slot, std::uint32_t type, std::uint32_t generation) noexcept
        {
            const std::uint64_t raw = (static_cast<std::uint64_t>(generation) << 32) |
                                      ((static_cast<std::uint64_t>(type) & 0xffffull) << 16) |
                                      static_cast<std::uint64_t>(slot);
            return raw ^ RotateLeft64(IndirectHandleCookie(), 29);
        }

        bool DecodeToken(Sr71IhrToken token, std::uint16_t &slot, std::uint32_t &type,
                         std::uint32_t &generation) noexcept
        {
            if (token == 0)
            {
                return false;
            }

            const std::uint64_t raw = token ^ RotateLeft64(IndirectHandleCookie(), 29);
            slot = static_cast<std::uint16_t>(raw & 0xffffu);
            type = static_cast<std::uint32_t>((raw >> 16) & 0xffffu);
            generation = static_cast<std::uint32_t>(raw >> 32);
            return slot != kInvalidIhrSlot && slot <= kMaxIndirectHandles;
        }

        std::uint64_t EncodePointer(void *pointer, std::uint64_t size, std::uint32_t generation) noexcept
        {
            std::uint64_t value = reinterpret_cast<std::uint64_t>(pointer);
            value ^= IndirectHandleCookie();
            value ^= RotateLeft64(size, 11);
            value ^= (static_cast<std::uint64_t>(generation) << 7);
            return value;
        }

        void *DecodePointer(std::uint64_t encoded, std::uint64_t size, std::uint32_t generation) noexcept
        {
            std::uint64_t value = encoded;
            value ^= (static_cast<std::uint64_t>(generation) << 7);
            value ^= RotateLeft64(size, 11);
            value ^= IndirectHandleCookie();
            return reinterpret_cast<void *>(value);
        }
    }

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

    Sr71IhrToken RegisterIndirectHandle(void *pointer, std::uint64_t size, Sr71IhrType type, std::uint32_t flags,
                                        const char *tag) noexcept
    {
        if (pointer == nullptr)
        {
            return 0;
        }

        const auto numericType = static_cast<std::uint32_t>(type);
        const std::uint32_t tagHash = HashTag(tag);
        (void)IndirectHandleCookie();

        AcquireSRWLockExclusive(&g_IndirectHandleLock);

        std::size_t freeIndex = kMaxIndirectHandles;
        for (std::size_t i = 0; i < kMaxIndirectHandles; ++i)
        {
            auto &entry = g_IndirectHandles[i];
            if (!entry.Active)
            {
                if (freeIndex == kMaxIndirectHandles)
                {
                    freeIndex = i;
                }
                continue;
            }

            if (entry.Type != numericType)
            {
                continue;
            }

            if (DecodePointer(entry.EncodedPointer, entry.Size, entry.Generation) == pointer)
            {
                entry.EncodedPointer = EncodePointer(pointer, size, entry.Generation);
                entry.Size = size;
                entry.Flags = flags;
                entry.TagHash = tagHash;
                Sr71IhrToken token = EncodeToken(static_cast<std::uint16_t>(i + 1), numericType, entry.Generation);
                ReleaseSRWLockExclusive(&g_IndirectHandleLock);
                return token;
            }
        }

        if (freeIndex == kMaxIndirectHandles)
        {
            ReleaseSRWLockExclusive(&g_IndirectHandleLock);
            return 0;
        }

        std::uint32_t generation = ++g_IndirectHandleGeneration;
        if (generation == 0)
        {
            generation = ++g_IndirectHandleGeneration;
        }

        auto &entry = g_IndirectHandles[freeIndex];
        entry.Size = size;
        entry.Flags = flags;
        entry.TagHash = tagHash;
        entry.Type = numericType;
        entry.Generation = generation;
        entry.EncodedPointer = EncodePointer(pointer, size, generation);
        entry.Active = true;

        Sr71IhrToken token = EncodeToken(static_cast<std::uint16_t>(freeIndex + 1), numericType, generation);
        ReleaseSRWLockExclusive(&g_IndirectHandleLock);
        return token;
    }

    bool ResolveIndirectHandle(Sr71IhrToken token, Sr71IhrType expectedType, Sr71IhrResolved &resolved) noexcept
    {
        resolved = {};
        std::uint16_t slot = 0;
        std::uint32_t type = 0;
        std::uint32_t generation = 0;
        if (!DecodeToken(token, slot, type, generation) || type != static_cast<std::uint32_t>(expectedType))
        {
            return false;
        }

        AcquireSRWLockShared(&g_IndirectHandleLock);
        const auto &entry = g_IndirectHandles[slot - 1];
        if (!entry.Active || entry.Type != type || entry.Generation != generation)
        {
            ReleaseSRWLockShared(&g_IndirectHandleLock);
            return false;
        }

        resolved.Pointer = DecodePointer(entry.EncodedPointer, entry.Size, entry.Generation);
        resolved.Size = entry.Size;
        resolved.Flags = entry.Flags;
        resolved.TagHash = entry.TagHash;
        ReleaseSRWLockShared(&g_IndirectHandleLock);
        return resolved.Pointer != nullptr;
    }

    void ReleaseIndirectHandle(Sr71IhrToken token) noexcept
    {
        std::uint16_t slot = 0;
        std::uint32_t type = 0;
        std::uint32_t generation = 0;
        if (!DecodeToken(token, slot, type, generation))
        {
            return;
        }

        AcquireSRWLockExclusive(&g_IndirectHandleLock);
        auto &entry = g_IndirectHandles[slot - 1];
        if (entry.Active && entry.Type == type && entry.Generation == generation)
        {
            entry = {};
        }
        ReleaseSRWLockExclusive(&g_IndirectHandleLock);
    }

    void ResetIndirectHandles() noexcept
    {
        AcquireSRWLockExclusive(&g_IndirectHandleLock);
        std::memset(g_IndirectHandles, 0, sizeof(g_IndirectHandles));
        ++g_IndirectHandleGeneration;
        ReleaseSRWLockExclusive(&g_IndirectHandleLock);
    }

    PKH_PEB CurrentPeb() noexcept
    {
        return BbCurrentPeb();
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

        const auto *nt =
            reinterpret_cast<const IMAGE_NT_HEADERS *>(moduleBase + static_cast<std::size_t>(dos->e_lfanew));
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

    HANDLE NativeCreateEvent(bool manualReset, bool initialState, const wchar_t *name, DWORD desiredAccess) noexcept
    {
        DWORD flags = 0;
        if (manualReset)
        {
            flags |= CREATE_EVENT_MANUAL_RESET;
        }
        if (initialState)
        {
            flags |= CREATE_EVENT_INITIAL_SET;
        }

        HANDLE eventHandle = CreateEventExW(nullptr, name, flags, desiredAccess);
        if (eventHandle == nullptr)
        {
            DWORD err = GetLastError();
            BkDbgLog("NativeCreateEvent: failed name=%ls manual=%u initial=%u access=0x%08lX gle=%lu",
                     name != nullptr ? name : L"<unnamed>", manualReset ? 1u : 0u, initialState ? 1u : 0u,
                     static_cast<unsigned long>(desiredAccess), static_cast<unsigned long>(err));
            SetLastError(err);
        }
        else
        {
            BkDbgLog("NativeCreateEvent: success name=%ls handle=%p access=0x%08lX gle=%lu",
                     name != nullptr ? name : L"<unnamed>", eventHandle, static_cast<unsigned long>(desiredAccess),
                     static_cast<unsigned long>(GetLastError()));
        }
        return eventHandle;
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
            if (!NtSucceeded(rtlCreateUserThread(CurrentProcessHandle(), nullptr, FALSE, 0, nullptr, nullptr,
                                                 startRoutine, parameter, &threadHandle, &clientId)))
            {
                return nullptr;
            }
            return threadHandle;
        }

        if (!NtSucceeded(fn(&threadHandle, THREAD_ALL_ACCESS, nullptr, CurrentProcessHandle(), startRoutine, parameter,
                            0, 0, 0, 0, nullptr)))
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
}

namespace
{
    static void InitializeAnalysisSubjectClassifier() noexcept
    {
        wchar_t kind[32]{};
        wchar_t subjectPath[1024]{};
        wchar_t hostPath[1024]{};
        std::uint32_t subjectKind = 0;

        DWORD kindChars = GetEnvironmentVariableW(L"BK_ANALYSIS_SUBJECT_KIND", kind, RTL_NUMBER_OF(kind));
        if (kindChars != 0 && kindChars < RTL_NUMBER_OF(kind) && _wcsicmp(kind, L"DLL") == 0)
        {
            subjectKind = 1;
            (void)GetEnvironmentVariableW(L"BK_ANALYSIS_SUBJECT_PATH", subjectPath, RTL_NUMBER_OF(subjectPath));
            (void)GetEnvironmentVariableW(L"BK_ANALYSIS_HOST_PATH", hostPath, RTL_NUMBER_OF(hostPath));
            subjectPath[RTL_NUMBER_OF(subjectPath) - 1] = L'\0';
            hostPath[RTL_NUMBER_OF(hostPath) - 1] = L'\0';
        }

        IC_STACKTRACE::SetAnalysisSubjectMetadata(subjectKind, subjectKind == 1 ? subjectPath : nullptr,
                                                  subjectKind == 1 ? hostPath : nullptr);
        if (subjectKind == 1)
        {
            BkDbgLog("InitializeAnalysisSubjectClassifier: kind=DLL subject=%ls host=%ls",
                     subjectPath[0] != L'\0' ? subjectPath : L"<unset>", hostPath[0] != L'\0' ? hostPath : L"<unset>");
        }
    }

    static void LogVehExceptionEvent(const char *channel, const bk::BK::Event &e) noexcept
    {
        if (e.exception_code == STATUS_GUARD_PAGE_VIOLATION)
        {
            return;
        }

        char moduleName[96]{};
        if (e.module_basename_lower[0] != L'\0')
        {
            (void)WideCharToMultiByte(CP_UTF8, 0, e.module_basename_lower, -1, moduleName, RTL_NUMBER_OF(moduleName),
                                      nullptr, nullptr);
        }
        else
        {
            (void)StringCchCopyA(moduleName, RTL_NUMBER_OF(moduleName), "unknown");
        }

        char stackSummary[256]{};
        std::size_t offset = 0;
        for (USHORT i = 0; i < e.stack_frame_count && i < 6; ++i)
        {
            int written = 0;
            if (offset != 0 && offset < RTL_NUMBER_OF(stackSummary))
            {
                stackSummary[offset++] = ',';
            }

            if (offset >= RTL_NUMBER_OF(stackSummary))
            {
                break;
            }

            HRESULT hr = StringCchPrintfExA(stackSummary + offset, RTL_NUMBER_OF(stackSummary) - offset, nullptr,
                                            nullptr, STRSAFE_IGNORE_NULLS, "%p", e.stack[i]);
            if (FAILED(hr))
            {
                break;
            }

            written = lstrlenA(stackSummary + offset);
            offset += static_cast<std::size_t>(written);
        }

        BkDbgLog(
            "[VEH] veh-exception channel=%s code=0x%08lX flags=0x%08lX addr=%p pid=%lu tid=%lu target=%u memory=%u noncontinuable=%u module=%s infoCount=%lu info0=0x%llX info1=0x%llX stack=%s",
            channel ? channel : "unknown", static_cast<unsigned long>(e.exception_code),
            static_cast<unsigned long>(e.exception_flags), e.exception_address, static_cast<unsigned long>(e.pid),
            static_cast<unsigned long>(e.tid), e.is_target_module ? 1u : 0u, e.is_memory_fault ? 1u : 0u,
            e.is_noncontinuable ? 1u : 0u, moduleName, static_cast<unsigned long>(e.exception_info_count),
            static_cast<unsigned long long>(e.exception_info_count > 0 ? e.exception_info[0] : 0),
            static_cast<unsigned long long>(e.exception_info_count > 1 ? e.exception_info[1] : 0),
            stackSummary[0] != '\0' ? stackSummary : "none");
    }

    static void LowNoise(const bk::BK::Event &e, void *u) noexcept
    {
        UNREFERENCED_PARAMETER(e);
        UNREFERENCED_PARAMETER(u);
        LogVehExceptionEvent("target", e);
    }

    static void HighNoise(const bk::BK::Event &e, void *u) noexcept
    {
        UNREFERENCED_PARAMETER(e);
        UNREFERENCED_PARAMETER(u);
        LogVehExceptionEvent("foreign", e);
    }

    static bool MemFault(const bk::BK::Event &e, EXCEPTION_POINTERS *ep, void *) noexcept
    {
        LogVehExceptionEvent("memory-fault", e);
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
}

void BkRuntimePrimeHooks() noexcept
{
    bool expected = false;
    if (!g_RuntimePrimed.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        return;
    }

    IC_STACKTRACE::InitCallerClassifier(reinterpret_cast<void *>(&BkRuntimePrimeHooks));
    InitializeAnalysisSubjectClassifier();
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
        DWORD tid = GetThreadId(threadHandle);
        if (tid != 0)
        {
            KeRegisterConcealedThread(tid);
        }
        BkDbgLog("BkRuntimeCreateBootstrapThread: CreateThread succeeded handle=%p", threadHandle);
        return threadHandle;
    }

    BkDbgLog("BkRuntimeCreateBootstrapThread: CreateThread failed gle=%lu, trying native fallback",
             (unsigned long)GetLastError());
    threadHandle = NativeCreateThread(reinterpret_cast<void *>(startRoutine), parameter);
    if (threadHandle != nullptr)
    {
        DWORD tid = GetThreadId(threadHandle);
        if (tid != 0)
        {
            KeRegisterConcealedThread(tid);
        }
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
    ResetControlFlowGuardPolicyCache();
    ResetProcessInstrumentationCallbackState();
    LaunchGateShutdown();
    g_RuntimeInitialized.store(false, std::memory_order_release);
    g_RuntimeWorkerStarted.store(false, std::memory_order_release);
    g_LastPublishedHookReadyMask.store(0, std::memory_order_release);
}
