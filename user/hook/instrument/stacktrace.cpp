#include "stacktrace.h"

#include <Psapi.h>
#include <DbgHelp.h>
#include <cstring>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Psapi.lib")

namespace IC_STACKTRACE
{
    namespace
    {
        using RtlCaptureStackBackTraceFn =
            USHORT(WINAPI*)(ULONG FramesToSkip, ULONG FramesToCapture, PVOID* BackTrace, PULONG BackTraceHash);

        RtlCaptureStackBackTraceFn g_RtlCapture = nullptr;
        bool g_SymInit = false;

        bool EnsureRtlCapture() noexcept
        {
            if (g_RtlCapture) return true;

            HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
            if (!ntdll) return false;

            g_RtlCapture = reinterpret_cast<RtlCaptureStackBackTraceFn>(
                ::GetProcAddress(ntdll, "RtlCaptureStackBackTrace")
                );
            return g_RtlCapture != nullptr;
        }

        static void ZeroResolved(ResolvedFrame& rf) noexcept
        {
            std::memset(&rf, 0, sizeof(rf));
            rf.ModuleName[0] = '\0';
            rf.Symbol[0] = '\0';
            rf.File[0] = '\0';
        }

        static void FillModuleInfo(void* ip, void*& moduleBaseOut, std::uint32_t& rvaOut, char moduleNameOut[MAX_PATH]) noexcept
        {
            moduleBaseOut = nullptr;
            rvaOut = 0;
            moduleNameOut[0] = '\0';

            HMODULE mod = nullptr;
            if (!::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(ip), &mod) || !mod)
            {
                return;
            }

            moduleBaseOut = mod;
            auto base = reinterpret_cast<std::uintptr_t>(mod);
            auto addr = reinterpret_cast<std::uintptr_t>(ip);
            if (addr >= base)
                rvaOut = static_cast<std::uint32_t>(addr - base);

            ::GetModuleFileNameA(mod, moduleNameOut, MAX_PATH);
            const char* slash = std::strrchr(moduleNameOut, '\\');
            if (slash && slash[1] != '\0')
            {
                std::memmove(moduleNameOut, slash + 1, std::strlen(slash + 1) + 1);
            }
        }
    }

    bool Capture(Trace& out, std::uint32_t skip, std::uint32_t maxFrames) noexcept
    {
        out.Count = 0;
        if (!EnsureRtlCapture())
            return false;

        if (maxFrames == 0)
            return true;

        if (maxFrames > (std::uint32_t)kMaxFrames)
            maxFrames = (std::uint32_t)kMaxFrames;
        const ULONG frames = g_RtlCapture(ULONG(skip + 1), ULONG(maxFrames),
            reinterpret_cast<PVOID*>(out.Frames), nullptr);

        out.Count = static_cast<std::uint16_t>(frames);
        for (std::uint16_t i = 0; i < out.Count; ++i)
        {
            out.Frames[i].ModuleBase = nullptr;
            out.Frames[i].Rva = 0;
        }

        return true;
    }

    bool InitSymbols() noexcept
    {
        if (g_SymInit) return true;

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
        if (!g_SymInit) return;
        ::SymCleanup(::GetCurrentProcess());
        g_SymInit = false;
    }

    bool Resolve(const Trace& trace, ResolvedFrame* resolved, std::size_t resolvedCap) noexcept
    {
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
            auto* sym = reinterpret_cast<SYMBOL_INFO*>(symBuffer);
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
}