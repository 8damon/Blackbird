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
    LdrLoadDll = 4
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

bool KeSetModuleHook(ModuleHookCallback callback) noexcept;
void KeRemoveModuleHook() noexcept;

bool KeCheckModuleHookIntegrity(std::uint32_t *mismatchCount) noexcept;
