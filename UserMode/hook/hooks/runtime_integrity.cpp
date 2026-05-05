#include "runtime_private.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace BK_RUNTIME_INTERNAL
{
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
        case ModuleHookOperation::RtlAddFunctionTable:
            return "RtlAddFunctionTable";
        case ModuleHookOperation::RtlInstallFunctionTableCallback:
            return "RtlInstallFunctionTableCallback";
        case ModuleHookOperation::RtlDeleteFunctionTable:
            return "RtlDeleteFunctionTable";
        case ModuleHookOperation::CoInitializeEx:
            return "CoInitializeEx";
        case ModuleHookOperation::CoInitializeSecurity:
            return "CoInitializeSecurity";
        case ModuleHookOperation::CoCreateInstance:
            return "CoCreateInstance";
        case ModuleHookOperation::EventRegister:
            return "EventRegister";
        case ModuleHookOperation::EventUnregister:
            return "EventUnregister";
        case ModuleHookOperation::StartTraceW:
            return "StartTraceW";
        case ModuleHookOperation::EnableTraceEx2:
            return "EnableTraceEx2";
        case ModuleHookOperation::CreateJobObjectW:
            return "CreateJobObjectW";
        case ModuleHookOperation::OpenJobObjectW:
            return "OpenJobObjectW";
        case ModuleHookOperation::AssignProcessToJobObject:
            return "AssignProcessToJobObject";
        case ModuleHookOperation::SetInformationJobObject:
            return "SetInformationJobObject";
        default:
            return "LoadLibrary";
        }
    }

    static inline std::uint32_t BuildCallerFlags(const IC_STACKTRACE::CallerClassification &cls,
                                                 std::uint32_t component) noexcept
    {
        std::uint32_t flags = cls.Flags;
        flags |= (static_cast<std::uint32_t>(cls.ImmediateCaller) << BK_HOOK_CALLER_IMMED_SHIFT);
        flags |= (static_cast<std::uint32_t>(cls.DeepestOrigin) << BK_HOOK_CALLER_DEEP_SHIFT);
        flags |= ((component << BK_HOOK_CALLER_COMPONENT_SHIFT) & BK_HOOK_CALLER_COMPONENT_MASK);
        return flags;
    }

    bool SendWinsockEvent(const WinsockCapturedEvent &evt) noexcept
    {
        using namespace BKIPC;

        auto cls = IC_STACKTRACE::ClassifyTrace(evt.Stack);
        if (cls.Flags & IC_STACKTRACE::kCallerFlagAllSystem)
            return true;

        BKIPC_HOOK_EVENT record{};
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
        record.CallerFlags = BuildCallerFlags(cls, BK_HOOK_COMPONENT_WINSOCK);
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
        const bool sr71WriteBlocked =
            (evt.Operation == NtOperation::NtWriteVirtualMemory && evt.Args[6] == kNtHookSr71WriteBlockedMarker) ||
            (evt.Operation == NtOperation::NtProtectVirtualMemory && evt.Args[6] == kNtHookSr71ProtectBlockedMarker);
        const bool processTerminate = (evt.Operation == NtOperation::NtTerminateProcess);
        if (!sr71WriteBlocked && !processTerminate && (cls.Flags & IC_STACKTRACE::kCallerFlagAllSystem))
            return true;

        BKIPC_HOOK_EVENT record{};
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

        switch (evt.Operation)
        {
        case NtOperation::NtAllocateVirtualMemory:
            record.Context0 = evt.Args[1];
            record.Context1 = evt.Args[3];
            record.Context2 = evt.Args[4];
            record.Context3 = evt.Args[5];
            break;
        case NtOperation::NtAllocateVirtualMemoryEx:
            record.Context0 = evt.Args[1];
            record.Context1 = evt.Args[2];
            record.Context2 = evt.Args[3];
            record.Context3 = evt.Args[4];
            break;
        case NtOperation::NtWriteVirtualMemory:
            record.Context0 = evt.Args[1];
            record.Context1 = evt.Args[3];
            record.Context2 = evt.Args[5];
            record.Context3 = 0;
            break;
        case NtOperation::NtProtectVirtualMemory:
            record.Context0 = evt.Args[1];
            record.Context1 = evt.Args[2];
            record.Context2 = evt.Args[3];
            record.Context3 = evt.Args[4];
            break;
        case NtOperation::NtCreateThreadEx:
            record.Context0 = evt.Args[2];
            record.Context1 = evt.Args[3];
            record.Context2 = evt.Args[5];
            record.Context3 = evt.Args[4];
            break;
        case NtOperation::NtCreateThread:
            record.Context0 = evt.Args[3];
            record.Context1 = 0;
            record.Context2 = evt.Args[7];
            record.Context3 = evt.Args[6];
            break;
        case NtOperation::NtSetContextThread:
        case NtOperation::NtGetContextThread:
            record.Context0 = evt.Args[0];
            record.Context1 = evt.Args[2];
            record.Context2 = evt.Args[3];
            record.Context3 = evt.Args[4];
            break;
        case NtOperation::NtSuspendThread:
        case NtOperation::NtResumeThread:
            record.Context0 = evt.Args[0];
            record.Context1 = evt.Args[2];
            record.Context2 = evt.Args[3];
            record.Context3 = evt.Args[4];
            break;
        case NtOperation::NtQueueApcThread:
            record.Context0 = evt.Args[0];
            record.Context1 = evt.Args[1];
            record.Context2 = evt.Args[2];
            record.Context3 = evt.Args[3];
            break;
        case NtOperation::NtQueueApcThreadEx:
            record.Context0 = evt.Args[0];
            record.Context1 = evt.Args[2];
            record.Context2 = evt.Args[3];
            record.Context3 = evt.Args[4];
            break;
        case NtOperation::NtQueueApcThreadEx2:
            record.Context0 = evt.Args[0];
            record.Context1 = evt.Args[3];
            record.Context2 = evt.Args[4];
            record.Context3 = evt.Args[5];
            break;
        case NtOperation::NtCreateSection:
            record.Context0 = evt.Args[0];
            record.Context1 = evt.Args[4];
            record.Context2 = evt.Args[5];
            record.Context3 = evt.Args[6];
            break;
        case NtOperation::NtTerminateProcess:
            record.Context0 = evt.Args[0];
            record.Context1 = evt.Args[1];
            record.Context2 = evt.Args[6];
            record.Context3 = evt.Args[7];
            break;
        case NtOperation::NtMapViewOfSection:
            record.Context0 = evt.Args[0];
            record.Context1 = evt.Args[1];
            record.Context2 = evt.Args[2];
            record.Context3 = evt.Args[3];
            break;
        case NtOperation::NtMapViewOfSectionEx:
            record.Context0 = evt.Args[0];
            record.Context1 = evt.Args[1];
            record.Context2 = evt.Args[2];
            record.Context3 = evt.Args[4];
            break;
        case NtOperation::NtUnmapViewOfSection:
        case NtOperation::NtUnmapViewOfSectionEx:
            record.Context0 = evt.Args[0];
            record.Context1 = evt.Args[1];
            record.Context2 = evt.Args[2];
            record.Context3 = evt.Args[3];
            break;
        default:
            break;
        }
        record.ArgCount = 8;
        for (std::size_t i = 0; i < RTL_NUMBER_OF(record.Args); ++i)
        {
            record.Args[i] = evt.Args[i];
        }
        record.DataSize =
            (evt.DataSize > RTL_NUMBER_OF(record.DataSample)) ? RTL_NUMBER_OF(record.DataSample) : evt.DataSize;
        record.CallerFlags = BuildCallerFlags(cls, BK_HOOK_COMPONENT_NT);
        CopyHookStack(evt.Stack, record);
        if (record.DataSize != 0)
        {
            CopyMemory(record.DataSample, evt.DataSample, record.DataSize);
        }

        (void)strncpy_s(record.ApiName, functionName, _TRUNCATE);
        (void)strncpy_s(record.ModuleName, "ntdll", _TRUNCATE);
        return PublishHookEvent(record);
    }

    bool SendKiEvent(const KiCapturedEvent &evt) noexcept
    {
        using namespace BKIPC;

        auto cls = IC_STACKTRACE::ClassifyTrace(evt.Stack);
        if (cls.Flags & IC_STACKTRACE::kCallerFlagAllSystem)
            return true;

        const char *stubName = evt.StubName ? evt.StubName : "";

        BKIPC_HOOK_EVENT record{};
        record.Kind = BlackbirdIpcHookEventKi;
        record.ProcessId = GetCurrentProcessId();
        record.ThreadId = evt.ThreadId;
        record.Operation = 0;
        record.Caller = reinterpret_cast<std::uint64_t>(evt.Caller);
        record.Context0 = reinterpret_cast<std::uint64_t>(evt.StackPointer);
        record.ArgCount = 0;
        record.DataSize = 0;
        record.CallerFlags = BuildCallerFlags(cls, BK_HOOK_COMPONENT_KI);
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

        BKIPC_HOOK_EVENT record{};
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
        record.CallerFlags = BuildCallerFlags(cls, BK_HOOK_COMPONENT_MODULE);
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
        (void)strncpy_s(record.ModuleName, (evt.SourceModule != nullptr) ? evt.SourceModule : "KERNEL32", _TRUNCATE);
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

        BKIPC_HOOK_EVENT record{};
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
        record.CallerFlags =
            ((BK_HOOK_COMPONENT_INTEGRITY << BK_HOOK_CALLER_COMPONENT_SHIFT) & BK_HOOK_CALLER_COMPONENT_MASK);
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

        fileHandle = CreateFileW(modulePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL, nullptr);
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
                if (imageSize >= sizeof(IMAGE_DOS_HEADER) && dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 &&
                    static_cast<std::size_t>(dos->e_lfanew) <= (imageSize - sizeof(IMAGE_NT_HEADERS64)))
                {
                    const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(view + dos->e_lfanew);
                    if (nt->Signature == IMAGE_NT_SIGNATURE &&
                        nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
                    {
                        const auto &exportDirEntry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                        const auto *exportDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(RvaToFilePointer(
                            view, imageSize, exportDirEntry.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY)));
                        if (exportDir != nullptr)
                        {
                            const auto *nameRvAs = reinterpret_cast<const DWORD *>(RvaToFilePointer(
                                view, imageSize, exportDir->AddressOfNames, exportDir->NumberOfNames * sizeof(DWORD)));
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

        BKIPC_HOOK_EVENT record{};
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
        record.CallerFlags =
            ((BK_HOOK_COMPONENT_INTEGRITY << BK_HOOK_CALLER_COMPONENT_SHIFT) & BK_HOOK_CALLER_COMPONENT_MASK);
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
                if (publish && SendPatchTamperEvent(kIntegrityOperationAmsiPatch, "AmsiScanBuffer", "amsi", tampered,
                                                    suspicious, expectedMismatch, sample))
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
                if (publish && SendPatchTamperEvent(kIntegrityOperationEtwPatch, "EtwEventWrite", "ntdll", tampered,
                                                    suspicious, expectedMismatch, sample))
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
        if (publish &&
            SendHookIntegrityEvent(integrityMask, winsockMismatches, ntMismatches, kiMismatches, moduleMismatches))
        {
            g_LastIntegrityPublishTick = now;
        }

        PollAmsiEtwPatchWatchdog(now);
    }
} // namespace BK_RUNTIME_INTERNAL
