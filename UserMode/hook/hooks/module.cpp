#include "module.h"

#include "ws.h"

#include <winternl.h>
#include <intrin.h>

#include <cstring>

#pragma intrinsic(_ReturnAddress)

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

namespace
{
    static ModuleHookInitFault g_LastModuleHookInitFault{};

    struct ModuleRange
    {
        std::uintptr_t Base = 0;
        std::uintptr_t End = 0;
    };

    static void ResetModuleHookInitFault() noexcept
    {
        std::memset(&g_LastModuleHookInitFault, 0, sizeof(g_LastModuleHookInitFault));
        g_LastModuleHookInitFault.Code = ModuleHookInitFaultCode::None;
    }

    static void CaptureFaultSample(const void *address, std::uint8_t sample[16]) noexcept
    {
        std::memset(sample, 0, 16);
        if (address == nullptr)
        {
            return;
        }

        __try
        {
            std::memcpy(sample, address, 16);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            std::memset(sample, 0, 16);
        }
    }

    static void SetModuleHookInitFault(ModuleHookInitFaultCode code, const wchar_t *moduleName, const char *exportName,
                                       void *address, void *redirectTarget = nullptr) noexcept
    {
        ResetModuleHookInitFault();
        g_LastModuleHookInitFault.Code = code;
        g_LastModuleHookInitFault.ModuleName = moduleName;
        g_LastModuleHookInitFault.ExportName = exportName;
        g_LastModuleHookInitFault.Address = address;
        g_LastModuleHookInitFault.RedirectTarget = redirectTarget;
        CaptureFaultSample(address, g_LastModuleHookInitFault.Sample);
    }

    static bool TryResolveModuleImageRange(HMODULE module, ModuleRange &range) noexcept
    {
        auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(module);
        if (module == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }

        auto *nt =
            reinterpret_cast<const IMAGE_NT_HEADERS *>(reinterpret_cast<const std::uint8_t *>(module) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.SizeOfImage == 0)
        {
            return false;
        }

        range.Base = reinterpret_cast<std::uintptr_t>(module);
        range.End = range.Base + nt->OptionalHeader.SizeOfImage;
        return true;
    }

    static bool AddressWithinRange(void *address, const ModuleRange &range) noexcept
    {
        std::uintptr_t value = reinterpret_cast<std::uintptr_t>(address);
        return value >= range.Base && value < range.End;
    }

    static bool TryDecodeAbsoluteTarget(void *entry, void *&target) noexcept
    {
        target = nullptr;
        if (entry == nullptr)
        {
            return false;
        }

        auto *bytes = static_cast<std::uint8_t *>(entry);
        __try
        {
            if (bytes[0] == 0xE9)
            {
                std::int32_t rel = *reinterpret_cast<std::int32_t *>(&bytes[1]);
                target = bytes + 5 + rel;
                return true;
            }

            if (bytes[0] == 0xFF && bytes[1] == 0x25)
            {
                std::int32_t disp = *reinterpret_cast<std::int32_t *>(&bytes[2]);
                auto **slot = reinterpret_cast<void **>(bytes + 6 + disp);
                target = *slot;
                return true;
            }

            if (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0)
            {
                target = *reinterpret_cast<void **>(&bytes[2]);
                return true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            target = nullptr;
            return false;
        }

        return false;
    }

    using LoadLibraryAFn = HMODULE(WINAPI *)(LPCSTR);
    using LoadLibraryWFn = HMODULE(WINAPI *)(LPCWSTR);
    using LoadLibraryExAFn = HMODULE(WINAPI *)(LPCSTR, HANDLE, DWORD);
    using LoadLibraryExWFn = HMODULE(WINAPI *)(LPCWSTR, HANDLE, DWORD);
    using LdrLoadDllFn = NTSTATUS(NTAPI *)(PWSTR, PULONG, PUNICODE_STRING, PHANDLE);
    using RtlAddFunctionTableFn = BOOLEAN(WINAPI *)(PRUNTIME_FUNCTION, DWORD, DWORD64);
    using RtlInstallFunctionTableCallbackFn = BOOLEAN(WINAPI *)(DWORD64, DWORD64, DWORD, PGET_RUNTIME_FUNCTION_CALLBACK,
                                                                PVOID, PCWSTR);
    using RtlDeleteFunctionTableFn = BOOLEAN(WINAPI *)(PRUNTIME_FUNCTION);

    struct InlineHook
    {
        const wchar_t *ModuleName;
        const char *ExportName;
        const char *SourceModule;
        void *HookEntry;
        void **OriginalFunction;
        void *TargetAddress;
        void *Trampoline;
        std::uint8_t OriginalBytes[16];
        bool Installed;
    };

    static ModuleHookCallback g_ActiveCallback = nullptr;
    static __declspec(thread) bool g_InHook = false;

    static LoadLibraryAFn g_OriginalLoadLibraryA = nullptr;
    static LoadLibraryWFn g_OriginalLoadLibraryW = nullptr;
    static LoadLibraryExAFn g_OriginalLoadLibraryExA = nullptr;
    static LoadLibraryExWFn g_OriginalLoadLibraryExW = nullptr;
    static LdrLoadDllFn g_OriginalLdrLoadDll = nullptr;
    static RtlAddFunctionTableFn g_OriginalRtlAddFunctionTable = nullptr;
    static RtlInstallFunctionTableCallbackFn g_OriginalRtlInstallFunctionTableCallback = nullptr;
    static RtlDeleteFunctionTableFn g_OriginalRtlDeleteFunctionTable = nullptr;

    HMODULE WINAPI LoadLibraryAHook(LPCSTR lpLibFileName);
    HMODULE WINAPI LoadLibraryWHook(LPCWSTR lpLibFileName);
    HMODULE WINAPI LoadLibraryExAHook(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
    HMODULE WINAPI LoadLibraryExWHook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
    NTSTATUS NTAPI LdrLoadDllHook(PWSTR searchPath, PULONG loadFlags, PUNICODE_STRING moduleFileName,
                                  PHANDLE moduleHandle);
    BOOLEAN WINAPI RtlAddFunctionTableHook(PRUNTIME_FUNCTION functionTable, DWORD entryCount, DWORD64 baseAddress);
    BOOLEAN WINAPI RtlInstallFunctionTableCallbackHook(DWORD64 tableIdentifier, DWORD64 baseAddress, DWORD length,
                                                       PGET_RUNTIME_FUNCTION_CALLBACK callback, PVOID context,
                                                       PCWSTR outOfProcessCallbackDll);
    BOOLEAN WINAPI RtlDeleteFunctionTableHook(PRUNTIME_FUNCTION functionTable);

    static InlineHook g_Hooks[] = {
        {L"KernelBase.dll",
         "LoadLibraryA",
         "KERNELBASE",
         reinterpret_cast<void *>(&LoadLibraryAHook),
         reinterpret_cast<void **>(&g_OriginalLoadLibraryA),
         nullptr,
         nullptr,
         {},
         false},
        {L"KernelBase.dll",
         "LoadLibraryW",
         "KERNELBASE",
         reinterpret_cast<void *>(&LoadLibraryWHook),
         reinterpret_cast<void **>(&g_OriginalLoadLibraryW),
         nullptr,
         nullptr,
         {},
         false},
        {L"KernelBase.dll",
         "LoadLibraryExA",
         "KERNELBASE",
         reinterpret_cast<void *>(&LoadLibraryExAHook),
         reinterpret_cast<void **>(&g_OriginalLoadLibraryExA),
         nullptr,
         nullptr,
         {},
         false},
        {L"KernelBase.dll",
         "LoadLibraryExW",
         "KERNELBASE",
         reinterpret_cast<void *>(&LoadLibraryExWHook),
         reinterpret_cast<void **>(&g_OriginalLoadLibraryExW),
         nullptr,
         nullptr,
         {},
         false},
        {L"ntdll.dll",
         "LdrLoadDll",
         "ntdll",
         reinterpret_cast<void *>(&LdrLoadDllHook),
         reinterpret_cast<void **>(&g_OriginalLdrLoadDll),
         nullptr,
         nullptr,
         {},
         false},
        {L"ntdll.dll",
         "RtlAddFunctionTable",
         "ntdll",
         reinterpret_cast<void *>(&RtlAddFunctionTableHook),
         reinterpret_cast<void **>(&g_OriginalRtlAddFunctionTable),
         nullptr,
         nullptr,
         {},
         false},
        {L"ntdll.dll",
         "RtlInstallFunctionTableCallback",
         "ntdll",
         reinterpret_cast<void *>(&RtlInstallFunctionTableCallbackHook),
         reinterpret_cast<void **>(&g_OriginalRtlInstallFunctionTableCallback),
         nullptr,
         nullptr,
         {},
         false},
        {L"ntdll.dll",
         "RtlDeleteFunctionTable",
         "ntdll",
         reinterpret_cast<void *>(&RtlDeleteFunctionTableHook),
         reinterpret_cast<void **>(&g_OriginalRtlDeleteFunctionTable),
         nullptr,
         nullptr,
         {},
         false},
    };

    static bool InstallInlineHook(void *target, void *hook, std::uint8_t original[16], void **trampolineOut) noexcept
    {
        constexpr std::size_t kPatchSize = 16;
        constexpr std::size_t kTrampolineSize = 32;

        if (target == nullptr || hook == nullptr || original == nullptr || trampolineOut == nullptr)
        {
            return false;
        }

        void *trampoline = VirtualAlloc(nullptr, kTrampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (trampoline == nullptr)
        {
            return false;
        }

        auto *dst = static_cast<std::uint8_t *>(target);
        auto *gate = static_cast<std::uint8_t *>(trampoline);

        DWORD oldProtect = 0;
        if (!VirtualProtect(dst, kPatchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }

        std::memcpy(original, dst, kPatchSize);
        std::memcpy(gate, dst, kPatchSize);
        gate[16] = 0x48;
        gate[17] = 0xB8;
        *reinterpret_cast<void **>(&gate[18]) = dst + kPatchSize;
        gate[26] = 0xFF;
        gate[27] = 0xE0;
        for (std::size_t i = 28; i < kTrampolineSize; ++i)
        {
            gate[i] = 0xCC;
        }

        dst[0] = 0x48;
        dst[1] = 0xB8;
        *reinterpret_cast<void **>(&dst[2]) = hook;
        dst[10] = 0xFF;
        dst[11] = 0xE0;
        dst[12] = 0xCC;
        dst[13] = 0xCC;
        dst[14] = 0xCC;
        dst[15] = 0xCC;

        DWORD temp = 0;
        VirtualProtect(dst, kPatchSize, oldProtect, &temp);
        FlushInstructionCache(GetCurrentProcess(), dst, kPatchSize);
        FlushInstructionCache(GetCurrentProcess(), trampoline, kTrampolineSize);

        *trampolineOut = trampoline;
        return true;
    }

    static void RemoveInlineHook(void *target, const std::uint8_t original[16], void *trampoline) noexcept
    {
        if (target == nullptr || original == nullptr)
        {
            return;
        }

        DWORD oldProtect = 0;
        if (VirtualProtect(target, 16, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            std::memcpy(target, original, 16);
            DWORD temp = 0;
            VirtualProtect(target, 16, oldProtect, &temp);
            FlushInstructionCache(GetCurrentProcess(), target, 16);
        }

        if (trampoline != nullptr)
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
        }
    }

    static void PublishModuleEvent(ModuleHookOperation operation, const char *functionName, const char *sourceModule,
                                   HMODULE moduleHandle, const void *nameBuffer, std::size_t nameLength,
                                   std::uint64_t arg0 = 0, std::uint64_t arg1 = 0, std::uint64_t arg2 = 0,
                                   std::uint64_t arg3 = 0) noexcept
    {
        if (g_InHook || g_ActiveCallback == nullptr)
        {
            return;
        }

        g_InHook = true;
        if (moduleHandle != nullptr)
        {
            (void)KeRefreshWinsockHooks(moduleHandle);
        }

        ModuleHookContext context{};
        context.Operation = operation;
        context.FunctionName = functionName;
        context.SourceModule = sourceModule;
        context.Caller = _ReturnAddress();
        context.ModuleHandle = moduleHandle;
        context.NameBuffer = nameBuffer;
        context.NameLength = nameLength;
        context.Args[0] = arg0;
        context.Args[1] = arg1;
        context.Args[2] = arg2;
        context.Args[3] = arg3;
        g_ActiveCallback(context);
        g_InHook = false;
    }

    static std::size_t CopyAnsiLength(LPCSTR value) noexcept
    {
        return (value != nullptr) ? strnlen_s(value, 31) : 0;
    }

    static std::size_t CopyWideLength(LPCWSTR value) noexcept
    {
        std::size_t chars = 0;
        if (value != nullptr)
        {
            while (value[chars] != L'\0' && chars < 31)
            {
                ++chars;
            }
        }
        return chars * sizeof(wchar_t);
    }

    HMODULE WINAPI LoadLibraryAHook(LPCSTR lpLibFileName)
    {
        if (g_OriginalLoadLibraryA == nullptr)
        {
            return nullptr;
        }

        HMODULE moduleHandle = g_OriginalLoadLibraryA(lpLibFileName);
        PublishModuleEvent(ModuleHookOperation::LoadLibraryA, "LoadLibraryA", "KERNELBASE", moduleHandle, lpLibFileName,
                           CopyAnsiLength(lpLibFileName));
        return moduleHandle;
    }

    HMODULE WINAPI LoadLibraryWHook(LPCWSTR lpLibFileName)
    {
        if (g_OriginalLoadLibraryW == nullptr)
        {
            return nullptr;
        }

        HMODULE moduleHandle = g_OriginalLoadLibraryW(lpLibFileName);
        PublishModuleEvent(ModuleHookOperation::LoadLibraryW, "LoadLibraryW", "KERNELBASE", moduleHandle, lpLibFileName,
                           CopyWideLength(lpLibFileName));
        return moduleHandle;
    }

    HMODULE WINAPI LoadLibraryExAHook(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
    {
        if (g_OriginalLoadLibraryExA == nullptr)
        {
            return nullptr;
        }

        HMODULE moduleHandle = g_OriginalLoadLibraryExA(lpLibFileName, hFile, dwFlags);
        PublishModuleEvent(ModuleHookOperation::LoadLibraryExA, "LoadLibraryExA", "KERNELBASE", moduleHandle,
                           lpLibFileName, CopyAnsiLength(lpLibFileName), static_cast<std::uint64_t>(dwFlags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(hFile)));
        return moduleHandle;
    }

    HMODULE WINAPI LoadLibraryExWHook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
    {
        if (g_OriginalLoadLibraryExW == nullptr)
        {
            return nullptr;
        }

        HMODULE moduleHandle = g_OriginalLoadLibraryExW(lpLibFileName, hFile, dwFlags);
        PublishModuleEvent(ModuleHookOperation::LoadLibraryExW, "LoadLibraryExW", "KERNELBASE", moduleHandle,
                           lpLibFileName, CopyWideLength(lpLibFileName), static_cast<std::uint64_t>(dwFlags),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(hFile)));
        return moduleHandle;
    }

    NTSTATUS NTAPI LdrLoadDllHook(PWSTR searchPath, PULONG loadFlags, PUNICODE_STRING moduleFileName,
                                  PHANDLE moduleHandle)
    {
        if (g_OriginalLdrLoadDll == nullptr)
        {
            return STATUS_UNSUCCESSFUL;
        }

        NTSTATUS status = g_OriginalLdrLoadDll(searchPath, loadFlags, moduleFileName, moduleHandle);
        HMODULE resolved = nullptr;
        if (NT_SUCCESS(status) && moduleHandle != nullptr)
        {
            resolved = reinterpret_cast<HMODULE>(*moduleHandle);
        }

        PublishModuleEvent(ModuleHookOperation::LdrLoadDll, "LdrLoadDll", "ntdll", resolved,
                           (moduleFileName != nullptr) ? moduleFileName->Buffer : nullptr,
                           (moduleFileName != nullptr && moduleFileName->Length > 0) ? moduleFileName->Length : 0,
                           static_cast<std::uint64_t>((loadFlags != nullptr) ? *loadFlags : 0),
                           static_cast<std::uint64_t>(static_cast<ULONG>(status)),
                           static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(searchPath)),
                           static_cast<std::uint64_t>((moduleFileName != nullptr) ? moduleFileName->Length : 0));
        return status;
    }

    BOOLEAN WINAPI RtlAddFunctionTableHook(PRUNTIME_FUNCTION functionTable, DWORD entryCount, DWORD64 baseAddress)
    {
        if (g_OriginalRtlAddFunctionTable == nullptr)
        {
            return FALSE;
        }

        BOOLEAN ok = g_OriginalRtlAddFunctionTable(functionTable, entryCount, baseAddress);
        if (ok)
        {
            PublishModuleEvent(ModuleHookOperation::RtlAddFunctionTable, "RtlAddFunctionTable", "ntdll", nullptr,
                               nullptr, 0, static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(functionTable)),
                               static_cast<std::uint64_t>(entryCount), static_cast<std::uint64_t>(baseAddress), 0);
        }
        return ok;
    }

    BOOLEAN WINAPI RtlInstallFunctionTableCallbackHook(DWORD64 tableIdentifier, DWORD64 baseAddress, DWORD length,
                                                       PGET_RUNTIME_FUNCTION_CALLBACK callback, PVOID context,
                                                       PCWSTR outOfProcessCallbackDll)
    {
        if (g_OriginalRtlInstallFunctionTableCallback == nullptr)
        {
            return FALSE;
        }

        BOOLEAN ok = g_OriginalRtlInstallFunctionTableCallback(tableIdentifier, baseAddress, length, callback, context,
                                                               outOfProcessCallbackDll);
        if (ok)
        {
            PublishModuleEvent(ModuleHookOperation::RtlInstallFunctionTableCallback,
                               "RtlInstallFunctionTableCallback", "ntdll", nullptr, outOfProcessCallbackDll,
                               CopyWideLength(outOfProcessCallbackDll), static_cast<std::uint64_t>(tableIdentifier),
                               static_cast<std::uint64_t>(baseAddress), static_cast<std::uint64_t>(length),
                               static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(callback)));
        }
        return ok;
    }

    BOOLEAN WINAPI RtlDeleteFunctionTableHook(PRUNTIME_FUNCTION functionTable)
    {
        if (g_OriginalRtlDeleteFunctionTable == nullptr)
        {
            return FALSE;
        }

        BOOLEAN ok = g_OriginalRtlDeleteFunctionTable(functionTable);
        if (ok)
        {
            PublishModuleEvent(ModuleHookOperation::RtlDeleteFunctionTable, "RtlDeleteFunctionTable", "ntdll", nullptr,
                               nullptr, 0, static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(functionTable)), 0, 0,
                               0);
        }
        return ok;
    }
} // namespace

bool KeSetModuleHook(ModuleHookCallback callback) noexcept
{
    if (callback == nullptr)
    {
        return false;
    }

    g_ActiveCallback = callback;
    ResetModuleHookInitFault();

    bool anyInstalled = false;
    for (auto &hook : g_Hooks)
    {
        if (hook.Installed)
        {
            anyInstalled = true;
            continue;
        }

        HMODULE moduleHandle = GetModuleHandleW(hook.ModuleName);
        if (moduleHandle == nullptr)
        {
            SetModuleHookInitFault(ModuleHookInitFaultCode::ModuleMissing, hook.ModuleName, hook.ExportName, nullptr);
            continue;
        }

        ModuleRange moduleRange{};
        if (!TryResolveModuleImageRange(moduleHandle, moduleRange))
        {
            SetModuleHookInitFault(ModuleHookInitFaultCode::ExportOutsideImage, hook.ModuleName, hook.ExportName,
                                   moduleHandle);
            continue;
        }

        FARPROC exportAddress = GetProcAddress(moduleHandle, hook.ExportName);
        if (exportAddress == nullptr)
        {
            SetModuleHookInitFault(ModuleHookInitFaultCode::ExportMissing, hook.ModuleName, hook.ExportName, nullptr);
            continue;
        }

        hook.TargetAddress = reinterpret_cast<void *>(exportAddress);
        if (!AddressWithinRange(hook.TargetAddress, moduleRange))
        {
            SetModuleHookInitFault(ModuleHookInitFaultCode::ExportOutsideImage, hook.ModuleName, hook.ExportName,
                                   hook.TargetAddress);
            continue;
        }

        void *redirectTarget = nullptr;
        if (TryDecodeAbsoluteTarget(hook.TargetAddress, redirectTarget) && redirectTarget != nullptr &&
            !AddressWithinRange(redirectTarget, moduleRange))
        {
            SetModuleHookInitFault(ModuleHookInitFaultCode::ExportRedirectedOutsideImage, hook.ModuleName,
                                   hook.ExportName, hook.TargetAddress, redirectTarget);
            continue;
        }

        if (!InstallInlineHook(hook.TargetAddress, hook.HookEntry, hook.OriginalBytes, &hook.Trampoline))
        {
            SetModuleHookInitFault(ModuleHookInitFaultCode::PatchInstallFailed, hook.ModuleName, hook.ExportName,
                                   hook.TargetAddress);
            continue;
        }

        *hook.OriginalFunction = hook.Trampoline;
        hook.Installed = true;
        anyInstalled = true;
    }

    if (!anyInstalled)
    {
        g_ActiveCallback = nullptr;
    }

    return anyInstalled;
}

void KeRemoveModuleHook() noexcept
{
    for (auto &hook : g_Hooks)
    {
        if (!hook.Installed || hook.TargetAddress == nullptr)
        {
            continue;
        }

        RemoveInlineHook(hook.TargetAddress, hook.OriginalBytes, hook.Trampoline);
        hook.TargetAddress = nullptr;
        hook.Trampoline = nullptr;
        *hook.OriginalFunction = nullptr;
        hook.Installed = false;
    }

    g_ActiveCallback = nullptr;
}

bool KeCheckModuleHookIntegrity(std::uint32_t *mismatchCount) noexcept
{
    std::uint32_t mismatches = 0;

    for (const auto &hook : g_Hooks)
    {
        if (!hook.Installed || hook.TargetAddress == nullptr)
        {
            continue;
        }

        const auto *bytes = static_cast<const std::uint8_t *>(hook.TargetAddress);
        void *patchedTarget = nullptr;
        std::memcpy(&patchedTarget, &bytes[2], sizeof(patchedTarget));
        bool intact = bytes[0] == 0x48 && bytes[1] == 0xB8 && patchedTarget == hook.HookEntry && bytes[10] == 0xFF &&
                      bytes[11] == 0xE0;
        if (!intact)
        {
            ++mismatches;
        }
    }

    if (mismatchCount != nullptr)
    {
        *mismatchCount = mismatches;
    }

    return mismatches == 0;
}

bool KeGetLastModuleHookInitFault(ModuleHookInitFault *faultOut) noexcept
{
    if (faultOut == nullptr)
    {
        return false;
    }

    *faultOut = g_LastModuleHookInitFault;
    return faultOut->Code != ModuleHookInitFaultCode::None;
}
