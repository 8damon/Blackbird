#pragma once

#include <cstdint>
#include <cstddef>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace IC_STACKTRACE
{
    constexpr std::size_t kMaxFrames = 64;

    struct Frame
    {
        void* Ip;
        void* ModuleBase;
        std::uint32_t Rva;
    };

    struct Trace
    {
        std::uint16_t Count;
        Frame Frames[kMaxFrames];
    };

    bool Capture(Trace& out, std::uint32_t skip = 0, std::uint32_t maxFrames = (std::uint32_t)kMaxFrames) noexcept;
    struct ResolvedFrame
    {
        void* Ip;
        void* ModuleBase;
        std::uint32_t Rva;

        char ModuleName[MAX_PATH];
        char Symbol[256];
        std::uint32_t Displacement;

        char File[MAX_PATH];
        std::uint32_t Line;
        bool HasSymbol;
        bool HasLine;
    };
    bool InitSymbols() noexcept;
    void CleanupSymbols() noexcept;
    bool Resolve(const Trace& trace, ResolvedFrame* resolved, std::size_t resolvedCap) noexcept;
}