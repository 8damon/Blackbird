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
        void *Ip;
        void *ModuleBase;
        std::uint32_t Rva;
    };

    struct Trace
    {
        std::uint16_t Count;
        Frame Frames[kMaxFrames];
    };

    bool Capture(Trace &out, std::uint32_t skip = 0, std::uint32_t maxFrames = (std::uint32_t)kMaxFrames) noexcept;
    struct ResolvedFrame
    {
        void *Ip;
        void *ModuleBase;
        std::uint32_t Rva;

        char ModuleName[MAX_PATH];
        char Symbol[256];
        std::uint32_t Displacement;

        char File[MAX_PATH];
        std::uint32_t Line;
        bool HasSymbol;
        bool HasLine;
    };
    void MarkHookThread() noexcept;
    void UnmarkHookThread() noexcept;
    bool InitSymbols() noexcept;
    void CleanupSymbols() noexcept;

    // DbgHelp is process-global and unsafe on hook threads.
    bool Resolve(const Trace &trace, ResolvedFrame *resolved, std::size_t resolvedCap) noexcept;

    enum class CallerKind : std::uint8_t
    {
        Unknown = 0,
        Unmapped = 1,
        SystemDll = 2,
        ProcessImage = 3,
        OwnModule = 4,
        NonSystemDll = 5,
    };

    constexpr std::uint32_t kCallerFlagAllSystem = 0x00000001u;
    constexpr std::uint32_t kCallerFlagHasUnmapped = 0x00000002u;
    constexpr std::uint32_t kCallerFlagHasProcessImage = 0x00000004u;
    constexpr std::uint32_t kCallerFlagHasNonSystem = 0x00000008u;
    constexpr std::uint32_t kCallerFlagHasOwnModule = 0x00001000u;
    constexpr std::uint32_t kCallerFlagPrivateExecNoUnwind = 0x00002000u;
    constexpr std::uint32_t kCallerFlagPrivateExecDynamicUnwind = 0x00004000u;
    constexpr std::uint32_t kCallerFlagImageMissingUnwindMetadata = 0x00008000u;

    struct CallerClassification
    {
        CallerKind ImmediateCaller;
        CallerKind DeepestOrigin;
        std::uint32_t Flags;
    };

    void InitCallerClassifier(void *anyFnInOwnModule) noexcept;
    void RegisterOwnExecutableRange(void *base, std::size_t size) noexcept;

    void SetAnalysisSubjectMetadata(std::uint32_t subjectKind, const wchar_t *subjectPath,
                                    const wchar_t *hostPath) noexcept;

    CallerClassification ClassifyTrace(const Trace &trace) noexcept;

}
