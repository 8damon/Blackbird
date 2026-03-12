#include "bk.h"

#include <atomic>

namespace
{
    using RtlCaptureStackBackTrace_t = USHORT(WINAPI*)(ULONG, ULONG, PVOID*, PULONG);

    // Global state (single binding for TelemetryArguments)
    static std::atomic<void*> g_veh_handle{ nullptr };
    static std::atomic<bk::blackbird::TelemetryArguments*> g_args{ nullptr };
    static std::atomic<bool> g_installed{ false };

    // Cached target module basename (lowercase)
    static wchar_t g_target_lower[bk::blackbird::kMaxModuleName]{};

    // Stack capture resolver
    static std::atomic<RtlCaptureStackBackTrace_t> g_capture{ nullptr };

    // TLS recursion guard
    static std::atomic<DWORD> g_tls{ TLS_OUT_OF_INDEXES };

    static inline wchar_t ToLowerW(wchar_t c) noexcept
    {
        if (c >= L'A' && c <= L'Z') return static_cast<wchar_t>(c + (L'a' - L'A'));
        return c;
    }

    static void CopyLowerBasename(const wchar_t* in, wchar_t* out, std::size_t outCount) noexcept
    {
        if (!out || outCount == 0)
            return;

        out[0] = L'\0';
        if (!in)
            return;

        const wchar_t* base = in;
        for (const wchar_t* p = in; *p; ++p)
        {
            if (*p == L'\\' || *p == L'/')
                base = p + 1;
        }

        std::size_t i = 0;
        for (; base[i] && (i + 1) < outCount; ++i)
            out[i] = ToLowerW(base[i]);
        out[i] = L'\0';
    }

    static bool EqualsLower(const wchar_t* a, const wchar_t* b) noexcept
    {
        if (!a || !b) return false;
        while (*a && *b)
        {
            if (*a != *b) return false;
            ++a; ++b;
        }
        return (*a == 0 && *b == 0);
    }

    static bool GetModuleBasenameLowerFromAddress(void* addr, wchar_t* outBase, std::size_t outCount) noexcept
    {
        if (!outBase || outCount == 0)
            return false;

        outBase[0] = L'\0';

        HMODULE hMod = nullptr;
        if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(addr),
            &hMod))
        {
            return false;
        }

        wchar_t path[MAX_PATH]{};
        DWORD n = GetModuleFileNameW(hMod, path, MAX_PATH);
        if (n == 0 || n >= MAX_PATH)
            return false;

        CopyLowerBasename(path, outBase, outCount);
        return true;
    }

    static bool EnsureRtlCaptureResolved() noexcept
    {
        if (g_capture.load(std::memory_order_acquire))
            return true;

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll)
            return false;

        auto fn = reinterpret_cast<RtlCaptureStackBackTrace_t>(
            GetProcAddress(ntdll, "RtlCaptureStackBackTrace")
            );

        g_capture.store(fn, std::memory_order_release);
        return (fn != nullptr);
    }

    static USHORT CaptureStack(std::uint16_t skip, std::uint16_t maxFrames, void** outFrames) noexcept
    {
        auto fn = g_capture.load(std::memory_order_acquire);
        if (!fn || !outFrames || maxFrames == 0)
            return 0;

        return fn(static_cast<ULONG>(skip), static_cast<ULONG>(maxFrames), outFrames, nullptr);
    }

    static bool DefaultMemoryFaultHandling(const bk::blackbird::Event& evt) noexcept
    {
        // Guard page violations are typically continuable (PAGE_GUARD clears on first hit)
        if (evt.exception_code == STATUS_GUARD_PAGE_VIOLATION)
            return true;

        // AV / in-page errors: do not continue unless caller remediates
        return false;
    }

    static void EnsureTls() noexcept
    {
        DWORD idx = g_tls.load(std::memory_order_acquire);
        if (idx != TLS_OUT_OF_INDEXES)
            return;

        idx = TlsAlloc();
        g_tls.store(idx, std::memory_order_release);
    }

    static bool TryEnterHandler() noexcept
    {
        EnsureTls();
        DWORD idx = g_tls.load(std::memory_order_acquire);
        if (idx == TLS_OUT_OF_INDEXES)
            return true; // proceed without guard

        void* v = TlsGetValue(idx);
        if (v)
            return false;

        TlsSetValue(idx, reinterpret_cast<void*>(1));
        return true;
    }

    static void LeaveHandler() noexcept
    {
        DWORD idx = g_tls.load(std::memory_order_acquire);
        if (idx == TLS_OUT_OF_INDEXES)
            return;

        TlsSetValue(idx, nullptr);
    }

    static inline bool IsMemoryFault(DWORD code) noexcept
    {
        return (code == EXCEPTION_ACCESS_VIOLATION) ||
            (code == EXCEPTION_IN_PAGE_ERROR) ||
            (code == STATUS_GUARD_PAGE_VIOLATION);
    }

    static LONG CALLBACK BlackbirdVeh(EXCEPTION_POINTERS* ep)
    {
        if (!ep || !ep->ExceptionRecord)
            return EXCEPTION_CONTINUE_SEARCH;

        if (!g_installed.load(std::memory_order_acquire))
            return EXCEPTION_CONTINUE_SEARCH;

        auto* a = g_args.load(std::memory_order_acquire);
        if (!a)
            return EXCEPTION_CONTINUE_SEARCH;

        if (!TryEnterHandler())
            return EXCEPTION_CONTINUE_SEARCH;

        bk::blackbird::Event evt{};
        evt.exception_code = ep->ExceptionRecord->ExceptionCode;
        evt.exception_flags = ep->ExceptionRecord->ExceptionFlags;
        evt.exception_address = ep->ExceptionRecord->ExceptionAddress;

        evt.pid = GetCurrentProcessId();
        evt.tid = GetCurrentThreadId();

        evt.is_noncontinuable = (evt.exception_flags & EXCEPTION_NONCONTINUABLE) != 0;
        evt.is_memory_fault = IsMemoryFault(evt.exception_code);

        evt.exception_info_count =
            (ep->ExceptionRecord->NumberParameters > bk::blackbird::kMaxExInfo)
            ? static_cast<ULONG>(bk::blackbird::kMaxExInfo)
            : static_cast<ULONG>(ep->ExceptionRecord->NumberParameters);

        for (ULONG i = 0; i < evt.exception_info_count; ++i)
            evt.exception_info[i] = ep->ExceptionRecord->ExceptionInformation[i];

        // Module attribution (best-effort)
        GetModuleBasenameLowerFromAddress(
            evt.exception_address,
            evt.module_basename_lower,
            bk::blackbird::kMaxModuleName
        );

        evt.is_target_module = EqualsLower(evt.module_basename_lower, g_target_lower);

        // Stack capture (best-effort)
        if (a->capture_stack)
        {
            (void)EnsureRtlCaptureResolved();

            std::uint16_t maxF = a->max_stack_frames;
            if (maxF == 0) maxF = 1;
            if (maxF > bk::blackbird::kMaxStackFrames)
                maxF = static_cast<std::uint16_t>(bk::blackbird::kMaxStackFrames);

            evt.stack_frame_count = CaptureStack(a->stack_frames_to_skip, maxF, evt.stack);
        }

        // Telemetry routing
        if (evt.is_target_module)
        {
            if (a->low_noise_telemetry) a->low_noise_telemetry(evt, a->user);
        }
        else
        {
            if (a->high_noise_telemetry) a->high_noise_telemetry(evt, a->user);
        }

        // Non-continuable exceptions must propagate
        if (evt.is_noncontinuable)
        {
            LeaveHandler();
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // Memory fault handling
        if (evt.is_memory_fault)
        {
            bool handled = false;

            if (a->memory_fault_handler)
                handled = a->memory_fault_handler(evt, ep, a->user);
            else
                handled = DefaultMemoryFaultHandling(evt);

            LeaveHandler();
            return handled ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
        }

        // Other exceptions
        if (!evt.is_target_module && a->swallow_non_target_exceptions)
        {
            LeaveHandler();
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        LeaveHandler();
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

PVOID BkRegisterVectoredExceptionHandler(BkBlackbirdTelemetryArguments* args) noexcept
{
    if (!args)
        return nullptr;

    // Cache target (lowercase basename)
    CopyLowerBasename(args->target_module_basename, g_target_lower, bk::blackbird::kMaxModuleName);

    if (args->capture_stack)
        (void)EnsureRtlCaptureResolved();

    // If already installed, update args + optionally promote
    void* existing = g_veh_handle.load(std::memory_order_acquire);
    if (existing)
    {
        g_args.store(args, std::memory_order_release);

        if (args->auto_promote && args->install_first)
            (void)BkPromoteVectoredExceptionHandlerToFront();

        g_installed.store(true, std::memory_order_release);
        return existing;
    }

    g_args.store(args, std::memory_order_release);

    const ULONG first = args->install_first ? 1u : 0u;
    void* h = AddVectoredExceptionHandler(first, BlackbirdVeh);
    if (!h)
    {
        g_args.store(nullptr, std::memory_order_release);
        g_target_lower[0] = L'\0';
        return nullptr;
    }

    g_veh_handle.store(h, std::memory_order_release);
    g_installed.store(true, std::memory_order_release);

    if (args->auto_promote && args->install_first)
        (void)BkPromoteVectoredExceptionHandlerToFront();

    return h;
}

BOOL BkPromoteVectoredExceptionHandlerToFront() noexcept
{
    void* h = g_veh_handle.load(std::memory_order_acquire);
    if (!h)
        return FALSE;

    RemoveVectoredExceptionHandler(h);

    void* nh = AddVectoredExceptionHandler(1, BlackbirdVeh);
    if (!nh)
    {
        // Fall back to non-first to avoid losing coverage entirely
        nh = AddVectoredExceptionHandler(0, BlackbirdVeh);
        if (!nh)
        {
            g_veh_handle.store(nullptr, std::memory_order_release);
            g_installed.store(false, std::memory_order_release);
            return FALSE;
        }
    }

    g_veh_handle.store(nh, std::memory_order_release);
    g_installed.store(true, std::memory_order_release);
    return TRUE;
}

void BkUnregisterVectoredExceptionHandler() noexcept
{
    g_installed.store(false, std::memory_order_release);

    void* h = g_veh_handle.exchange(nullptr, std::memory_order_acq_rel);
    if (h)
        RemoveVectoredExceptionHandler(h);

    g_args.store(nullptr, std::memory_order_release);
    g_target_lower[0] = L'\0';
}
