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
    // Call MarkHookThread() at the start of any hook callback and UnmarkHookThread()
    // at the end.  This prevents DbgHelp from being called on hook threads.
    void MarkHookThread() noexcept;
    void UnmarkHookThread() noexcept;
    bool InitSymbols() noexcept;
    void CleanupSymbols() noexcept;
    // Resolve must only be called from a background/analysis thread (never a hook thread).
    bool Resolve(const Trace &trace, ResolvedFrame *resolved, std::size_t resolvedCap) noexcept;

    // ---------------------------------------------------------------------------
    // Caller-origin classification
    //
    // ClassifyTrace walks every frame in a captured Trace and determines where
    // the call originated:
    //   SystemDll    — all frames resolve to Windows system DLLs (System32 /
    //                  SysWOW64); these are OS-internal calls, not target code.
    //   ProcessImage — at least one frame is the monitored .exe itself.
    //   NonSystemDll — at least one frame is a non-system loaded DLL.
    //   Unmapped     — at least one frame has no backing module (shellcode /
    //                  RWX-allocated stubs — highly suspicious).
    //   OwnModule    — frames belonging to the hook DLL (SR71) are excluded from
    //                  all origin decisions; they are infrastructure, not callers.
    //
    // Call InitCallerClassifier once at DLL startup with any function pointer
    // that lives inside the hook DLL so ClassifyTrace can recognise and skip
    // its own frames.
    // ---------------------------------------------------------------------------

    enum class CallerKind : std::uint8_t
    {
        Unknown = 0,      // IP resolution failed
        Unmapped = 1,     // IP has no backing module (unbacked / shellcode region)
        SystemDll = 2,    // Windows system DLL (under %SystemRoot%)
        ProcessImage = 3, // The monitored process .exe image
        OwnModule = 4,    // Hook DLL (SR71) — infrastructure, excluded from origin
        NonSystemDll = 5, // Loaded DLL that is not a Windows system DLL
    };

    // Flags returned in CallerClassification::Flags
    constexpr std::uint32_t kCallerFlagAllSystem = 0x00000001u;       // every non-own frame is SystemDll
    constexpr std::uint32_t kCallerFlagHasUnmapped = 0x00000002u;     // at least one Unmapped frame
    constexpr std::uint32_t kCallerFlagHasProcessImage = 0x00000004u; // at least one ProcessImage frame
    constexpr std::uint32_t kCallerFlagHasNonSystem = 0x00000008u;    // at least one NonSystemDll frame
    constexpr std::uint32_t kCallerFlagHasOwnModule = 0x00001000u;    // trace contains SR71 / BK internal frames

    struct CallerClassification
    {
        CallerKind ImmediateCaller; // kind of the first non-OwnModule frame in the trace
        CallerKind DeepestOrigin;   // deepest (oldest) non-system, non-own frame; Unknown if none
        std::uint32_t Flags;        // combination of kCallerFlag* bits
    };

    // Register the hook DLL's identity so ClassifyTrace can skip its own frames.
    // Pass any function pointer that resides in the hook DLL (e.g. &BkRuntimePrimeHooks).
    void InitCallerClassifier(void *anyFnInOwnModule) noexcept;

    // Configure DLL-analysis attribution.  In DLL mode the staged host image is
    // infrastructure, while frames from subjectPath are treated as target code.
    void SetAnalysisSubjectMetadata(std::uint32_t subjectKind, const wchar_t *subjectPath,
                                    const wchar_t *hostPath) noexcept;

    // Classify the origin of a captured call stack.  Safe to call from any thread.
    // Does NOT require InitSymbols() — uses only GetModuleHandleExA / GetModuleFileNameW.
    CallerClassification ClassifyTrace(const Trace &trace) noexcept;

} // namespace IC_STACKTRACE
