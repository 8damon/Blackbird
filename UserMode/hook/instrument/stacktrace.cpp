#include "stacktrace.h"

#include <Psapi.h>
#include <DbgHelp.h>
#include <cstring>
#include <cwctype>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Psapi.lib")

namespace IC_STACKTRACE
{
    namespace
    {
        using RtlCaptureStackBackTraceFn = USHORT(WINAPI *)(ULONG FramesToSkip, ULONG FramesToCapture, PVOID *BackTrace,
                                                            PULONG BackTraceHash);
#if defined(_M_X64) || defined(_M_ARM64)
        using RtlLookupFunctionEntryFn = PRUNTIME_FUNCTION(WINAPI *)(DWORD64 ControlPc, PDWORD64 ImageBase,
                                                                     PUNWIND_HISTORY_TABLE HistoryTable);
#endif

        RtlCaptureStackBackTraceFn g_RtlCapture = nullptr;
#if defined(_M_X64) || defined(_M_ARM64)
        RtlLookupFunctionEntryFn g_RtlLookupFunctionEntry = nullptr;
        volatile LONG g_RtlLookupFunctionEntryState = 0;
#endif
        bool g_SymInit = false;
        DWORD g_symGuardTls = TLS_OUT_OF_INDEXES;

        struct OwnExecutableRange
        {
            std::uintptr_t Base;
            std::uintptr_t End;
        };

        constexpr LONG kMaxOwnExecutableRanges = 64;
        OwnExecutableRange g_OwnExecutableRanges[kMaxOwnExecutableRanges]{};
        volatile LONG g_OwnExecutableRangeCount = 0;

        bool EnsureRtlCapture() noexcept
        {
            if (g_RtlCapture)
                return true;

            HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
            if (!ntdll)
                return false;

            g_RtlCapture =
                reinterpret_cast<RtlCaptureStackBackTraceFn>(::GetProcAddress(ntdll, "RtlCaptureStackBackTrace"));
            return g_RtlCapture != nullptr;
        }

#if defined(_M_X64) || defined(_M_ARM64)
        bool EnsureRtlLookupFunctionEntry() noexcept
        {
            LONG state = InterlockedCompareExchange(&g_RtlLookupFunctionEntryState, 0, 0);
            if (state == 2)
                return g_RtlLookupFunctionEntry != nullptr;
            if (state == 1)
                return false;

            HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
            auto fn = ntdll != nullptr
                          ? reinterpret_cast<RtlLookupFunctionEntryFn>(
                                ::GetProcAddress(ntdll, "RtlLookupFunctionEntry"))
                          : nullptr;
            g_RtlLookupFunctionEntry = fn;
            InterlockedExchange(&g_RtlLookupFunctionEntryState, fn != nullptr ? 2 : 1);
            return fn != nullptr;
        }
#endif

        static bool IsOwnExecutableRange(void *ip) noexcept
        {
            if (!ip)
                return false;

            const auto value = reinterpret_cast<std::uintptr_t>(ip);
            LONG count = InterlockedCompareExchange(&g_OwnExecutableRangeCount, 0, 0);
            if (count > kMaxOwnExecutableRanges)
                count = kMaxOwnExecutableRanges;

            for (LONG i = 0; i < count; ++i)
            {
                OwnExecutableRange range = g_OwnExecutableRanges[i];
                if (range.Base != 0 && value >= range.Base && value < range.End)
                    return true;
            }

            return false;
        }

        static void ZeroResolved(ResolvedFrame &rf) noexcept
        {
            std::memset(&rf, 0, sizeof(rf));
            rf.ModuleName[0] = '\0';
            rf.Symbol[0] = '\0';
            rf.File[0] = '\0';
        }

        constexpr std::uint32_t kAnalysisSubjectProcess = 0;
        constexpr std::uint32_t kAnalysisSubjectDll = 1;
        constexpr std::size_t kAnalysisPathChars = 1024;

        static HMODULE g_OwnModule = nullptr;
        static std::uint32_t g_AnalysisSubjectKind = kAnalysisSubjectProcess;
        static wchar_t g_AnalysisSubjectPath[kAnalysisPathChars]{};
        static wchar_t g_AnalysisHostPath[kAnalysisPathChars]{};

        static bool g_SystemRootCached = false;
        static wchar_t g_SystemRoot[MAX_PATH]{};
        static std::size_t g_SystemRootLen = 0;

        static void EnsureSystemRoot() noexcept
        {
            if (g_SystemRootCached)
                return;

            UINT len = ::GetWindowsDirectoryW(g_SystemRoot, MAX_PATH);
            if (len == 0 || len >= MAX_PATH)
            {
                g_SystemRoot[0] = L'\0';
                g_SystemRootLen = 0;
            }
            else
            {
                for (UINT i = 0; i < len; ++i)
                    g_SystemRoot[i] = static_cast<wchar_t>(std::towlower(g_SystemRoot[i]));
                g_SystemRootLen = len;
            }
            g_SystemRootCached = true;
        }

        static bool EqualsInsensitive(const wchar_t *a, const wchar_t *b) noexcept
        {
            if (!a || !b)
                return false;
            return ::_wcsicmp(a, b) == 0;
        }

        static bool ContainsInsensitive(const wchar_t *haystack, const wchar_t *needle) noexcept
        {
            std::size_t hayLen;
            std::size_t needleLen;

            if (!haystack || !needle || !needle[0])
                return false;

            hayLen = ::wcslen(haystack);
            needleLen = ::wcslen(needle);
            if (needleLen == 0 || hayLen < needleLen)
                return false;

            for (std::size_t i = 0; i <= hayLen - needleLen; ++i)
            {
                if (_wcsnicmp(haystack + i, needle, needleLen) == 0)
                    return true;
            }

            return false;
        }

        static const wchar_t *SkipPathPrefix(const wchar_t *path) noexcept
        {
            if (!path)
                return nullptr;

            if ((path[0] == L'\\' && path[1] == L'\\' && path[2] == L'?' && path[3] == L'\\') ||
                (path[0] == L'\\' && path[1] == L'?' && path[2] == L'?' && path[3] == L'\\'))
            {
                return path + 4;
            }

            return path;
        }

        static void NormalizePath(const wchar_t *input, wchar_t output[kAnalysisPathChars]) noexcept
        {
            std::size_t j = 0;

            if (!output)
                return;
            output[0] = L'\0';

            input = SkipPathPrefix(input);
            if (!input)
                return;

            for (std::size_t i = 0; input[i] != L'\0' && (j + 1) < kAnalysisPathChars; ++i)
            {
                wchar_t ch = input[i] == L'/' ? L'\\' : input[i];
                output[j++] = static_cast<wchar_t>(std::towlower(ch));
            }
            output[j] = L'\0';
        }

        static bool PathHasTrailingSegment(const wchar_t *path, const wchar_t *tail) noexcept
        {
            if (!path || !tail || !path[0] || !tail[0])
                return false;

            const std::size_t pathLen = ::wcslen(path);
            const std::size_t tailLen = ::wcslen(tail);
            if (tailLen == 0 || pathLen < tailLen)
                return false;

            const wchar_t *start = path + (pathLen - tailLen);
            if (::_wcsicmp(start, tail) != 0)
                return false;

            if (tail[0] == L'\\' || tail[0] == L'/')
                return true;

            return start == path || start[-1] == L'\\' || start[-1] == L'/';
        }

        static bool PathMatchesConfiguredPath(const wchar_t *candidate, const wchar_t *configured) noexcept
        {
            wchar_t candidateNorm[kAnalysisPathChars]{};
            wchar_t configuredNorm[kAnalysisPathChars]{};

            if (!candidate || !configured || !configured[0])
                return false;

            NormalizePath(candidate, candidateNorm);
            NormalizePath(configured, configuredNorm);
            if (!candidateNorm[0] || !configuredNorm[0])
                return false;

            if (::_wcsicmp(candidateNorm, configuredNorm) == 0)
                return true;

            if (configuredNorm[0] != L'\0' && configuredNorm[1] == L':' && configuredNorm[2] != L'\0')
                return PathHasTrailingSegment(candidateNorm, configuredNorm + 2);

            return PathHasTrailingSegment(candidateNorm, configuredNorm);
        }

        static bool IsInternalInstrumentationModule(HMODULE mod) noexcept
        {
            wchar_t path[MAX_PATH]{};
            const wchar_t *leaf = path;

            if (!mod || ::GetModuleFileNameW(mod, path, MAX_PATH) == 0)
                return false;

            for (const wchar_t *p = path; *p; ++p)
            {
                if (*p == L'\\' || *p == L'/')
                    leaf = p + 1;
            }

            if (EqualsInsensitive(leaf, L"SR71.dll") || EqualsInsensitive(leaf, L"J58.dll") ||
                EqualsInsensitive(leaf, L"BlackbirdController.exe") ||
                EqualsInsensitive(leaf, L"BlackbirdInterface.exe"))
            {
                return true;
            }

            return ContainsInsensitive(path, L"\\BK\\");
        }

        static CallerKind ClassifyUnresolvedIp(void *ip) noexcept
        {
            MEMORY_BASIC_INFORMATION mbi{};

            if (!ip || ::VirtualQuery(ip, &mbi, sizeof(mbi)) != sizeof(mbi))
                return CallerKind::Unknown;

            if (mbi.State != MEM_COMMIT)
                return CallerKind::Unknown;

            if (IsOwnExecutableRange(ip))
                return CallerKind::OwnModule;

            if (mbi.Type == MEM_PRIVATE)
                return CallerKind::Unmapped;

            return CallerKind::Unknown;
        }

        static bool IsExecutableProtection(DWORD protect) noexcept
        {
            DWORD baseProtect = protect & 0xFFu;
            return baseProtect == PAGE_EXECUTE || baseProtect == PAGE_EXECUTE_READ ||
                   baseProtect == PAGE_EXECUTE_READWRITE || baseProtect == PAGE_EXECUTE_WRITECOPY;
        }

        static bool LookupFunctionEntryForIp(void *ip, DWORD64 *imageBaseOut) noexcept
        {
#if defined(_M_X64) || defined(_M_ARM64)
            if (imageBaseOut != nullptr)
                *imageBaseOut = 0;

            if (!ip || !EnsureRtlLookupFunctionEntry())
                return false;

            DWORD64 imageBase = 0;
            PRUNTIME_FUNCTION entry =
                g_RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(ip), &imageBase, nullptr);
            if (entry == nullptr)
                return false;

            if (imageBaseOut != nullptr)
                *imageBaseOut = imageBase;
            return true;
#else
            UNREFERENCED_PARAMETER(ip);
            if (imageBaseOut != nullptr)
                *imageBaseOut = 0;
            return false;
#endif
        }

        static bool ImageHasExceptionDirectory(void *moduleBase) noexcept
        {
            if (!moduleBase)
                return false;

            bool hasExceptionDirectory = false;
            __try
            {
                auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(moduleBase);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
                    return false;

                auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(
                    reinterpret_cast<const std::uint8_t *>(moduleBase) + dos->e_lfanew);
                if (nt->Signature != IMAGE_NT_SIGNATURE)
                    return false;

                if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION)
                    return false;

                const IMAGE_DATA_DIRECTORY &dir =
                    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                hasExceptionDirectory = dir.VirtualAddress != 0 && dir.Size >= sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                hasExceptionDirectory = false;
            }

            return hasExceptionDirectory;
        }

        static std::uint32_t CollectUnwindTraits(void *ip, CallerKind kind) noexcept
        {
            if (!ip || kind == CallerKind::OwnModule || IsOwnExecutableRange(ip))
                return 0;

            MEMORY_BASIC_INFORMATION mbi{};
            if (::VirtualQuery(ip, &mbi, sizeof(mbi)) != sizeof(mbi) || mbi.State != MEM_COMMIT ||
                !IsExecutableProtection(mbi.Protect))
            {
                return 0;
            }

            if (mbi.Type == MEM_PRIVATE)
            {
                return LookupFunctionEntryForIp(ip, nullptr) ? kCallerFlagPrivateExecDynamicUnwind
                                                             : kCallerFlagPrivateExecNoUnwind;
            }

            if (mbi.Type == MEM_IMAGE && !ImageHasExceptionDirectory(mbi.AllocationBase))
                return kCallerFlagImageMissingUnwindMetadata;

            return 0;
        }

        static CallerKind ClassifyIp(void *ip) noexcept
        {
            if (!ip)
                return CallerKind::Unknown;

            HMODULE mod = nullptr;
            if (!::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                      reinterpret_cast<LPCSTR>(ip), &mod) ||
                !mod)
            {
                return ClassifyUnresolvedIp(ip);
            }

            if (mod == g_OwnModule || IsInternalInstrumentationModule(mod))
                return CallerKind::OwnModule;

            wchar_t path[kAnalysisPathChars]{};
            bool hasPath = ::GetModuleFileNameW(mod, path, static_cast<DWORD>(kAnalysisPathChars)) > 0;
            path[kAnalysisPathChars - 1] = L'\0';

            if (g_AnalysisSubjectKind == kAnalysisSubjectDll)
            {
                if (hasPath && PathMatchesConfiguredPath(path, g_AnalysisSubjectPath))
                    return CallerKind::ProcessImage;

                if (mod == ::GetModuleHandleW(nullptr) ||
                    (hasPath && PathMatchesConfiguredPath(path, g_AnalysisHostPath)))
                {
                    return CallerKind::OwnModule;
                }
            }

            if (mod == ::GetModuleHandleW(nullptr))
                return CallerKind::ProcessImage;

            EnsureSystemRoot();
            if (g_SystemRootLen > 0)
            {
                if (hasPath)
                {
                    for (std::size_t i = 0; path[i]; ++i)
                        path[i] = static_cast<wchar_t>(std::towlower(path[i]));

                    if (::wcsncmp(path, g_SystemRoot, g_SystemRootLen) == 0 &&
                        (path[g_SystemRootLen] == L'\\' || path[g_SystemRootLen] == L'/'))
                    {
                        return CallerKind::SystemDll;
                    }
                }
            }

            return CallerKind::NonSystemDll;
        }

        static void FillModuleInfo(void *ip, void *&moduleBaseOut, std::uint32_t &rvaOut,
                                   char moduleNameOut[MAX_PATH]) noexcept
        {
            moduleBaseOut = nullptr;
            rvaOut = 0;
            moduleNameOut[0] = '\0';

            HMODULE mod = nullptr;
            if (!::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                      reinterpret_cast<LPCSTR>(ip), &mod) ||
                !mod)
            {
                return;
            }

            moduleBaseOut = mod;
            auto base = reinterpret_cast<std::uintptr_t>(mod);
            auto addr = reinterpret_cast<std::uintptr_t>(ip);
            if (addr >= base)
                rvaOut = static_cast<std::uint32_t>(addr - base);

            ::GetModuleFileNameA(mod, moduleNameOut, MAX_PATH);
            const char *slash = std::strrchr(moduleNameOut, '\\');
            if (slash && slash[1] != '\0')
            {
                std::memmove(moduleNameOut, slash + 1, std::strlen(slash + 1) + 1);
            }
        }
    }

    bool Capture(Trace &out, std::uint32_t skip, std::uint32_t maxFrames) noexcept
    {
        out.Count = 0;
        if (!EnsureRtlCapture())
            return false;

        if (maxFrames == 0)
            return true;

        if (maxFrames > (std::uint32_t)kMaxFrames)
            maxFrames = (std::uint32_t)kMaxFrames;
        void *frames[kMaxFrames]{};
        const ULONG captured = g_RtlCapture(ULONG(skip + 1), ULONG(maxFrames), frames, nullptr);

        out.Count = static_cast<std::uint16_t>(captured);
        for (std::uint16_t i = 0; i < out.Count; ++i)
        {
            out.Frames[i].Ip = frames[i];
            out.Frames[i].ModuleBase = nullptr;
            out.Frames[i].Rva = 0;
        }

        return true;
    }

    void MarkHookThread() noexcept
    {
        if (g_symGuardTls == TLS_OUT_OF_INDEXES)
            g_symGuardTls = TlsAlloc();
        if (g_symGuardTls != TLS_OUT_OF_INDEXES)
            TlsSetValue(g_symGuardTls, reinterpret_cast<void *>(1));
    }

    void UnmarkHookThread() noexcept
    {
        if (g_symGuardTls != TLS_OUT_OF_INDEXES)
            TlsSetValue(g_symGuardTls, nullptr);
    }

    static bool IsHookThread() noexcept
    {
        if (g_symGuardTls == TLS_OUT_OF_INDEXES)
            return false;
        return TlsGetValue(g_symGuardTls) != nullptr;
    }

    bool InitSymbols() noexcept
    {
        if (g_SymInit)
            return true;

        if (IsHookThread())
            return false;

        HANDLE proc = ::GetCurrentProcess();

        DWORD opts = ::SymGetOptions();
        opts |= SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS;
        ::SymSetOptions(opts);

        if (!::SymInitialize(proc, nullptr, TRUE))
            return false;

        g_SymInit = true;
        return true;
    }

    void CleanupSymbols() noexcept
    {
        if (!g_SymInit)
            return;
        ::SymCleanup(::GetCurrentProcess());
        g_SymInit = false;
    }

    bool Resolve(const Trace &trace, ResolvedFrame *resolved, std::size_t resolvedCap) noexcept
    {
        if (IsHookThread())
            return false;

        if (!g_SymInit || !resolved || resolvedCap < trace.Count)
            return false;

        HANDLE proc = ::GetCurrentProcess();

        for (std::uint16_t i = 0; i < trace.Count; ++i)
        {
            ResolvedFrame rf{};
            ZeroResolved(rf);

            rf.Ip = trace.Frames[i].Ip;

            FillModuleInfo(rf.Ip, rf.ModuleBase, rf.Rva, rf.ModuleName);
            alignas(SYMBOL_INFO) unsigned char symBuffer[sizeof(SYMBOL_INFO) + 256];
            auto *sym = reinterpret_cast<SYMBOL_INFO *>(symBuffer);
            std::memset(sym, 0, sizeof(symBuffer));
            sym->SizeOfStruct = sizeof(SYMBOL_INFO);
            sym->MaxNameLen = 255;

            DWORD64 displacement = 0;
            if (::SymFromAddr(proc, reinterpret_cast<DWORD64>(rf.Ip), &displacement, sym))
            {
                ::strncpy_s(rf.Symbol, sizeof(rf.Symbol), sym->Name, _TRUNCATE);
                rf.Displacement = static_cast<std::uint32_t>(displacement);
                rf.HasSymbol = true;
            }

            IMAGEHLP_LINE64 line{};
            line.SizeOfStruct = sizeof(line);
            DWORD lineDisp = 0;
            if (::SymGetLineFromAddr64(proc, reinterpret_cast<DWORD64>(rf.Ip), &lineDisp, &line))
            {
                ::strncpy_s(rf.File, sizeof(rf.File), line.FileName ? line.FileName : "", _TRUNCATE);
                rf.Line = line.LineNumber;
                rf.HasLine = true;
            }

            resolved[i] = rf;
        }

        return true;
    }

    void InitCallerClassifier(void *anyFnInOwnModule) noexcept
    {
        if (!anyFnInOwnModule)
            return;

        HMODULE mod = nullptr;
        ::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                             reinterpret_cast<LPCSTR>(anyFnInOwnModule), &mod);
        g_OwnModule = mod;
    }

    void RegisterOwnExecutableRange(void *base, std::size_t size) noexcept
    {
        if (!base || size == 0)
            return;

        const auto start = reinterpret_cast<std::uintptr_t>(base);
        const auto end = start + static_cast<std::uintptr_t>(size);
        if (end <= start)
            return;

        LONG count = InterlockedCompareExchange(&g_OwnExecutableRangeCount, 0, 0);
        if (count > kMaxOwnExecutableRanges)
            count = kMaxOwnExecutableRanges;

        for (LONG i = 0; i < count; ++i)
        {
            OwnExecutableRange range = g_OwnExecutableRanges[i];
            if (range.Base == start && range.End == end)
                return;
        }

        LONG slot = InterlockedIncrement(&g_OwnExecutableRangeCount) - 1;
        if (slot < 0)
            return;
        if (slot >= kMaxOwnExecutableRanges)
        {
            InterlockedExchange(&g_OwnExecutableRangeCount, kMaxOwnExecutableRanges);
            return;
        }

        g_OwnExecutableRanges[slot].Base = start;
        g_OwnExecutableRanges[slot].End = end;
    }

    void SetAnalysisSubjectMetadata(std::uint32_t subjectKind, const wchar_t *subjectPath,
                                    const wchar_t *hostPath) noexcept
    {
        g_AnalysisSubjectKind = (subjectKind == kAnalysisSubjectDll) ? kAnalysisSubjectDll : kAnalysisSubjectProcess;
        g_AnalysisSubjectPath[0] = L'\0';
        g_AnalysisHostPath[0] = L'\0';

        if (subjectPath != nullptr)
            ::wcsncpy_s(g_AnalysisSubjectPath, kAnalysisPathChars, subjectPath, _TRUNCATE);
        if (hostPath != nullptr)
            ::wcsncpy_s(g_AnalysisHostPath, kAnalysisPathChars, hostPath, _TRUNCATE);
    }

    CallerClassification ClassifyTrace(const Trace &trace) noexcept
    {
        CallerClassification result{};
        result.ImmediateCaller = CallerKind::Unknown;
        result.DeepestOrigin = CallerKind::Unknown;
        result.Flags = 0;

        bool foundImmediateCaller = false;
        bool anyNonOwn = false;

        for (std::uint16_t i = 0; i < trace.Count; ++i)
        {
            void *ip = trace.Frames[i].Ip;
            if (!ip)
                continue;

            CallerKind kind = ClassifyIp(ip);
            result.Flags |= CollectUnwindTraits(ip, kind);

            if (!foundImmediateCaller && kind != CallerKind::OwnModule)
            {
                result.ImmediateCaller = kind;
                foundImmediateCaller = true;
            }

            switch (kind)
            {
            case CallerKind::Unmapped:
                result.Flags |= kCallerFlagHasUnmapped;
                anyNonOwn = true;
                result.DeepestOrigin = kind;
                break;

            case CallerKind::ProcessImage:
                result.Flags |= kCallerFlagHasProcessImage;
                anyNonOwn = true;
                result.DeepestOrigin = kind;
                break;

            case CallerKind::NonSystemDll:
                result.Flags |= kCallerFlagHasNonSystem;
                anyNonOwn = true;
                result.DeepestOrigin = kind;
                break;

            case CallerKind::SystemDll:
                anyNonOwn = true;
                break;

            case CallerKind::OwnModule:
                result.Flags |= kCallerFlagHasOwnModule;
                break;

            case CallerKind::Unknown:
                break;
            }
        }

        bool hasNonSystemOrigin =
            (result.Flags & (kCallerFlagHasUnmapped | kCallerFlagHasProcessImage | kCallerFlagHasNonSystem)) != 0;
        if (anyNonOwn && !hasNonSystemOrigin)
            result.Flags |= kCallerFlagAllSystem;

        return result;
    }
}
