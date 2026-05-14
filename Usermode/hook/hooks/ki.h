#pragma once

#include <cstdint>
#include <cstddef>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

struct KiHookContext
{
    const char *StubName;
    void *Caller;
    void *StackPointer;
};

using KiHookCallback = void (*)(const KiHookContext &context) noexcept;

bool KeSetKiHook(KiHookCallback callback) noexcept;
bool KeIsKiHookSupported() noexcept;

void KeRemoveKiHook() noexcept;

bool KeCheckKiHookIntegrity(std::uint32_t *mismatchCount) noexcept;

struct KiHookPatchInfo
{
    void *PatchAddress;
    std::size_t PatchSize;
    std::uint8_t OriginalBytes[16];
    const char *HookName;
    std::uint32_t Flags;
};

std::size_t KeCollectKiHookPatchInfos(_Out_writes_(capacity) KiHookPatchInfo *out, _In_ std::size_t capacity) noexcept;
