#pragma once

#include <cstddef>
#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

enum class ModuleHookOperation : std::uint32_t
{
    LoadLibraryA = 0,
    LoadLibraryW = 1,
    LoadLibraryExA = 2,
    LoadLibraryExW = 3,
    LdrLoadDll = 4,
    RtlAddFunctionTable = 5,
    RtlInstallFunctionTableCallback = 6,
    RtlDeleteFunctionTable = 7
};

struct ModuleHookContext
{
    ModuleHookOperation Operation;
    const char *FunctionName;
    const char *SourceModule;
    void *Caller;
    HMODULE ModuleHandle;
    const void *NameBuffer;
    std::size_t NameLength;
    std::uint64_t Args[4];
};

using ModuleHookCallback = void (*)(const ModuleHookContext &context) noexcept;

enum class ModuleHookInitFaultCode : std::uint32_t
{
    None = 0,
    ModuleMissing,
    ExportMissing,
    ExportOutsideImage,
    ExportRedirectedOutsideImage,
    PatchInstallFailed,
};

struct ModuleHookInitFault
{
    ModuleHookInitFaultCode Code;
    const wchar_t *ModuleName;
    const char *ExportName;
    void *Address;
    void *RedirectTarget;
    std::uint8_t Sample[16];
};

bool KeSetModuleHook(ModuleHookCallback callback) noexcept;
void KeRemoveModuleHook() noexcept;

bool KeCheckModuleHookIntegrity(std::uint32_t *mismatchCount) noexcept;
bool KeGetLastModuleHookInitFault(ModuleHookInitFault *faultOut) noexcept;
