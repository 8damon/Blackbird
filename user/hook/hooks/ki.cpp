#include "ki.h"

#include <intrin.h>

#pragma intrinsic(_ReturnAddress)

namespace
{
#ifdef _WIN64

    using KiApcCallbackFn = void (NTAPI*)(...);

    static KiHookCallback   g_ActiveKiCallback         = nullptr;
    static KiApcCallbackFn  g_OriginalApcCallback      = nullptr;
    static void**           g_KiUserApcCallbackSlot    = nullptr;

    void NTAPI KiUserApcHookStub(...)
    {
        if (g_ActiveKiCallback != nullptr)
        {
            KiHookContext ctx{};
            ctx.StubName     = "KiUserApcDispatcher";
            ctx.Caller       = _ReturnAddress();
            ctx.StackPointer = _AddressOfReturnAddress();

            g_ActiveKiCallback(ctx);
        }

        if (g_OriginalApcCallback != nullptr)
        {
            g_OriginalApcCallback(__VA_ARGS__);
        }
    }

    static void** FindKiUserApcCallbackSlot(void* kiUserApcDispatcher) noexcept
    {
        constexpr std::size_t ScanSize = 0x100;

        auto* base  = static_cast<std::uint8_t*>(kiUserApcDispatcher);
        auto* limit = base + ScanSize;

        for (auto* p = base; p + 7 < limit; ++p)
        {
            if (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0x05)
            {
                std::int32_t disp = *reinterpret_cast<std::int32_t*>(p + 3);

                std::uint8_t* nextInstr = p + 7;
                void** slot = reinterpret_cast<void**>(nextInstr + disp);

                bool hasCallRax = false;
                for (auto* q = nextInstr; q + 1 < limit; ++q)
                {
                    if (q[0] == 0xFF && q[1] == 0xD0)
                    {
                        hasCallRax = true;
                        break;
                    }
                }

                if (hasCallRax)
                {
                    return slot;
                }
            }
        }

        return nullptr;
    }

#endif
}

bool KeSetKiHook(KiHookCallback callback) noexcept
{
#ifndef _WIN64
    (void)callback;
    return false;
#else
    if (callback == nullptr)
    {
        return false;
    }

    g_ActiveKiCallback = callback;

    if (g_KiUserApcCallbackSlot != nullptr)
    {
        return true;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr)
    {
        return false;
    }

    FARPROC addr = GetProcAddress(ntdll, "KiUserApcDispatcher");
    if (addr == nullptr)
    {
        return false;
    }

    void** slot = FindKiUserApcCallbackSlot(reinterpret_cast<void*>(addr));
    if (slot == nullptr)
    {
        return false;
    }

    g_OriginalApcCallback   = reinterpret_cast<KiApcCallbackFn>(*slot);
    g_KiUserApcCallbackSlot = slot;

    DWORD oldProtect = 0;
    if (!VirtualProtect(slot, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        g_OriginalApcCallback   = nullptr;
        g_KiUserApcCallbackSlot = nullptr;
        return false;
    }

    *slot = reinterpret_cast<void*>(&KiUserApcHookStub);

    DWORD tmp = 0;
    VirtualProtect(slot, sizeof(void*), oldProtect, &tmp);
    FlushInstructionCache(GetCurrentProcess(), slot, sizeof(void*));

    return true;
#endif
}

bool KeIsKiHookSupported() noexcept
{
#ifndef _WIN64
    return false;
#else
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    FARPROC addr;

    if (ntdll == nullptr)
    {
        return false;
    }

    addr = GetProcAddress(ntdll, "KiUserApcDispatcher");
    if (addr == nullptr)
    {
        return false;
    }

    return (FindKiUserApcCallbackSlot(reinterpret_cast<void*>(addr)) != nullptr);
#endif
}

void KeRemoveKiHook() noexcept
{
#ifdef _WIN64
    if (g_KiUserApcCallbackSlot == nullptr)
    {
        g_ActiveKiCallback = nullptr;
        return;
    }

    DWORD oldProtect = 0;
    if (VirtualProtect(g_KiUserApcCallbackSlot,
                       sizeof(void*),
                       PAGE_EXECUTE_READWRITE,
                       &oldProtect))
    {
        *g_KiUserApcCallbackSlot =
            reinterpret_cast<void*>(g_OriginalApcCallback);

        DWORD tmp = 0;
        VirtualProtect(g_KiUserApcCallbackSlot,
                       sizeof(void*),
                       oldProtect,
                       &tmp);
        FlushInstructionCache(GetCurrentProcess(),
                              g_KiUserApcCallbackSlot,
                              sizeof(void*));
    }

    g_ActiveKiCallback = nullptr;
    g_OriginalApcCallback   = nullptr;
    g_KiUserApcCallbackSlot = nullptr;

#endif
}

bool KeCheckKiHookIntegrity(std::uint32_t* mismatchCount) noexcept
{
    std::uint32_t mismatches = 0;

#ifdef _WIN64
    if (g_KiUserApcCallbackSlot != nullptr)
    {
        if (*g_KiUserApcCallbackSlot != reinterpret_cast<void*>(&KiUserApcHookStub))
        {
            ++mismatches;
        }
    }
#endif

    if (mismatchCount != nullptr)
    {
        *mismatchCount = mismatches;
    }

    return mismatches == 0;
}

