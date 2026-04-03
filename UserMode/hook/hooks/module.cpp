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
    using LoadLibraryAFn = HMODULE(WINAPI *)(LPCSTR);
    using LoadLibraryWFn = HMODULE(WINAPI *)(LPCWSTR);
    using LoadLibraryExAFn = HMODULE(WINAPI *)(LPCSTR, HANDLE, DWORD);
    using LoadLibraryExWFn = HMODULE(WINAPI *)(LPCWSTR, HANDLE, DWORD);
    using LdrLoadDllFn = NTSTATUS(NTAPI *)(PWSTR, PULONG, PUNICODE_STRING, PHANDLE);

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

    HMODULE WINAPI LoadLibraryAHook(LPCSTR lpLibFileName);
    HMODULE WINAPI LoadLibraryWHook(LPCWSTR lpLibFileName);
    HMODULE WINAPI LoadLibraryExAHook(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
    HMODULE WINAPI LoadLibraryExWHook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
    NTSTATUS NTAPI LdrLoadDllHook(PWSTR searchPath, PULONG loadFlags, PUNICODE_STRING moduleFileName,
                                  PHANDLE moduleHandle);

    static InlineHook g_Hooks[] = {
        {L"KernelBase.dll", "LoadLibraryA", "KERNELBASE", reinterpret_cast<void *>(&LoadLibraryAHook),
         reinterpret_cast<void **>(&g_OriginalLoadLibraryA), nullptr, nullptr, {}, false},
        {L"KernelBase.dll", "LoadLibraryW", "KERNELBASE", reinterpret_cast<void *>(&LoadLibraryWHook),
         reinterpret_cast<void **>(&g_OriginalLoadLibraryW), nullptr, nullptr, {}, false},
        {L"KernelBase.dll", "LoadLibraryExA", "KERNELBASE", reinterpret_cast<void *>(&LoadLibraryExAHook),
         reinterpret_cast<void **>(&g_OriginalLoadLibraryExA), nullptr, nullptr, {}, false},
        {L"KernelBase.dll", "LoadLibraryExW", "KERNELBASE", reinterpret_cast<void *>(&LoadLibraryExWHook),
         reinterpret_cast<void **>(&g_OriginalLoadLibraryExW), nullptr, nullptr, {}, false},
        {L"ntdll.dll", "LdrLoadDll", "ntdll", reinterpret_cast<void *>(&LdrLoadDllHook),
         reinterpret_cast<void **>(&g_OriginalLdrLoadDll), nullptr, nullptr, {}, false},
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
        PublishModuleEvent(ModuleHookOperation::LoadLibraryA, "LoadLibraryA", "KERNELBASE", moduleHandle,
                           lpLibFileName, CopyAnsiLength(lpLibFileName));
        return moduleHandle;
    }

    HMODULE WINAPI LoadLibraryWHook(LPCWSTR lpLibFileName)
    {
        if (g_OriginalLoadLibraryW == nullptr)
        {
            return nullptr;
        }

        HMODULE moduleHandle = g_OriginalLoadLibraryW(lpLibFileName);
        PublishModuleEvent(ModuleHookOperation::LoadLibraryW, "LoadLibraryW", "KERNELBASE", moduleHandle,
                           lpLibFileName, CopyWideLength(lpLibFileName));
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
                           lpLibFileName, CopyAnsiLength(lpLibFileName),
                           static_cast<std::uint64_t>(dwFlags),
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
                           lpLibFileName, CopyWideLength(lpLibFileName),
                           static_cast<std::uint64_t>(dwFlags),
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
} // namespace

bool KeSetModuleHook(ModuleHookCallback callback) noexcept
{
    if (callback == nullptr)
    {
        return false;
    }

    g_ActiveCallback = callback;

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
            continue;
        }

        FARPROC exportAddress = GetProcAddress(moduleHandle, hook.ExportName);
        if (exportAddress == nullptr)
        {
            continue;
        }

        hook.TargetAddress = reinterpret_cast<void *>(exportAddress);
        if (!InstallInlineHook(hook.TargetAddress, hook.HookEntry, hook.OriginalBytes, &hook.Trampoline))
        {
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
