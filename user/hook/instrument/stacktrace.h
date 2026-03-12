#pragma once

#include <cstdint>
#include <cstddef>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace IC_STACKTRACE
{
    // Keep this small; you’ll be sending it over IPC.
    constexpr std::size_t kMaxFrames = 64;

    struct Frame
    {
        void* Ip;          // instruction pointer / return address
        void* ModuleBase;  // optional: filled during resolve (or capture if you want)
        std::uint32_t Rva; // optional: Ip - ModuleBase
    };

    struct Trace
    {
        std::uint16_t Count;
        Frame Frames[kMaxFrames];
    };

    bool Capture(Trace& out, std::uint32_t skip = 0, std::uint32_t maxFrames = (std::uint32_t)kMaxFrames) noexcept;

    // Symbolization output (do NOT call in-hook).
    struct ResolvedFrame
    {
        void* Ip;
        void* ModuleBase;
        std::uint32_t Rva;

        char ModuleName[MAX_PATH];  // e.g. "WS2_32.dll"
        char Symbol[256];           // function name if available
        std::uint32_t Displacement; // from symbol start

        char File[MAX_PATH];        // source file if available
        std::uint32_t Line;         // line number
        bool HasSymbol;
        bool HasLine;
    };

    // One-time setup for dbghelp (call on your receiver/worker thread).
    bool InitSymbols() noexcept;
    void CleanupSymbols() noexcept;

    // Resolve a captured trace to symbols/files (call out-of-hook only).
    // resolved must have capacity >= trace.Count.
    bool Resolve(const Trace& trace, ResolvedFrame* resolved, std::size_t resolvedCap) noexcept;
}