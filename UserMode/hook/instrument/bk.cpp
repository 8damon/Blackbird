#include "bk.h"
#include "../hooks/nt.h"

#include <atomic>
#include <cstring>

namespace
{
    using RtlCaptureStackBackTrace_t = USHORT(WINAPI *)(ULONG, ULONG, PVOID *, PULONG);
    static std::atomic<void *> g_veh_handle{nullptr};
    static std::atomic<bk::BK::TelemetryArguments *> g_args{nullptr};
    static std::atomic<bool> g_installed{false};
    static wchar_t g_target_lower[bk::BK::kMaxModuleName]{};
    static std::atomic<RtlCaptureStackBackTrace_t> g_capture{nullptr};
    static std::atomic<DWORD> g_tls{TLS_OUT_OF_INDEXES};

    static constexpr DWORD kVehRingCapacity = 256;

    struct alignas(MEMORY_ALLOCATION_ALIGNMENT) VehRingNode
    {
        SLIST_ENTRY ListEntry; // must be first field
        bk::BK::Event Evt;
        bool IsLowNoise;
    };

    static SLIST_HEADER g_vehFreeList;
    static SLIST_HEADER g_vehPendingList;
    static HANDLE g_vehSignal{nullptr};
    static HANDLE g_vehDispatchThread{nullptr};
    static std::atomic<bool> g_vehRunning{false};
    static VehRingNode *g_vehNodePool{nullptr};

    static DWORD WINAPI VehDispatchThreadProc(LPVOID) noexcept
    {
        while (g_vehRunning.load(std::memory_order_acquire))
        {
            if (g_vehSignal)
                WaitForSingleObject(g_vehSignal, 50);

            PSLIST_ENTRY head = InterlockedFlushSList(&g_vehPendingList);
            if (!head)
                continue;

            /* Reverse LIFO→FIFO. */
            PSLIST_ENTRY prev = nullptr;
            PSLIST_ENTRY cur = head;
            while (cur)
            {
                PSLIST_ENTRY next = cur->Next;
                cur->Next = prev;
                prev = cur;
                cur = next;
            }
            head = prev;

            auto *a = g_args.load(std::memory_order_acquire);
            cur = head;
            while (cur)
            {
                PSLIST_ENTRY next = cur->Next;
                auto *node = reinterpret_cast<VehRingNode *>(cur);
                if (a)
                {
                    if (node->IsLowNoise)
                    {
                        if (a->low_noise_telemetry)
                            a->low_noise_telemetry(node->Evt, a->user);
                    }
                    else
                    {
                        if (a->high_noise_telemetry)
                            a->high_noise_telemetry(node->Evt, a->user);
                    }
                }
                InterlockedPushEntrySList(&g_vehFreeList, &node->ListEntry);
                cur = next;
            }
        }

        /* Drain any residual events after stop. */
        PSLIST_ENTRY residual = InterlockedFlushSList(&g_vehPendingList);
        while (residual)
        {
            PSLIST_ENTRY next = residual->Next;
            InterlockedPushEntrySList(&g_vehFreeList, residual);
            residual = next;
        }
        return 0;
    }

    static bool VehRingInit() noexcept
    {
        InitializeSListHead(&g_vehFreeList);
        InitializeSListHead(&g_vehPendingList);

        g_vehSignal = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (!g_vehSignal)
            return false;

        const SIZE_T poolBytes = kVehRingCapacity * sizeof(VehRingNode);
        g_vehNodePool =
            static_cast<VehRingNode *>(VirtualAlloc(nullptr, poolBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!g_vehNodePool)
        {
            CloseHandle(g_vehSignal);
            g_vehSignal = nullptr;
            return false;
        }

        for (DWORD i = 0; i < kVehRingCapacity; ++i)
            InterlockedPushEntrySList(&g_vehFreeList, &g_vehNodePool[i].ListEntry);

        g_vehRunning.store(true, std::memory_order_release);
        g_vehDispatchThread = CreateThread(nullptr, 0, VehDispatchThreadProc, nullptr, 0, nullptr);
        if (!g_vehDispatchThread)
        {
            g_vehRunning.store(false, std::memory_order_release);
            VirtualFree(g_vehNodePool, 0, MEM_RELEASE);
            g_vehNodePool = nullptr;
            CloseHandle(g_vehSignal);
            g_vehSignal = nullptr;
            return false;
        }
        DWORD tid = GetThreadId(g_vehDispatchThread);
        if (tid != 0)
        {
            KeRegisterConcealedThread(tid);
        }
        return true;
    }

    static void VehRingShutdown() noexcept
    {
        g_vehRunning.store(false, std::memory_order_release);
        if (g_vehSignal)
            SetEvent(g_vehSignal);
        if (g_vehDispatchThread)
        {
            WaitForSingleObject(g_vehDispatchThread, 3000);
            CloseHandle(g_vehDispatchThread);
            g_vehDispatchThread = nullptr;
        }
        if (g_vehSignal)
        {
            CloseHandle(g_vehSignal);
            g_vehSignal = nullptr;
        }
        if (g_vehNodePool)
        {
            VirtualFree(g_vehNodePool, 0, MEM_RELEASE);
            g_vehNodePool = nullptr;
        }
    }

    /* Enqueue a non-memory-fault telemetry event to the ring.
     * Returns true if enqueued, false if the ring is full (caller may fall back). */
    static bool VehRingEnqueue(const bk::BK::Event &evt, bool isLowNoise) noexcept
    {
        PSLIST_ENTRY entry = InterlockedPopEntrySList(&g_vehFreeList);
        if (!entry)
            return false;

        auto *node = reinterpret_cast<VehRingNode *>(entry);
        std::memcpy(&node->Evt, &evt, sizeof(evt));
        node->IsLowNoise = isLowNoise;

        InterlockedPushEntrySList(&g_vehPendingList, &node->ListEntry);

        /* Signal on empty→non-empty transition (approximate; safe to over-signal). */
        if (g_vehSignal && QueryDepthSList(&g_vehPendingList) == 1)
            SetEvent(g_vehSignal);

        return true;
    }

    static inline wchar_t ToLowerW(wchar_t c) noexcept
    {
        if (c >= L'A' && c <= L'Z')
            return static_cast<wchar_t>(c + (L'a' - L'A'));
        return c;
    }

    static void CopyLowerBasename(const wchar_t *in, wchar_t *out, std::size_t outCount) noexcept
    {
        if (!out || outCount == 0)
            return;

        out[0] = L'\0';
        if (!in)
            return;

        const wchar_t *base = in;
        for (const wchar_t *p = in; *p; ++p)
        {
            if (*p == L'\\' || *p == L'/')
                base = p + 1;
        }

        std::size_t i = 0;
        for (; base[i] && (i + 1) < outCount; ++i)
            out[i] = ToLowerW(base[i]);
        out[i] = L'\0';
    }

    static bool EqualsLower(const wchar_t *a, const wchar_t *b) noexcept
    {
        if (!a || !b)
            return false;
        while (*a && *b)
        {
            if (*a != *b)
                return false;
            ++a;
            ++b;
        }
        return (*a == 0 && *b == 0);
    }

    static bool GetModuleBasenameLowerFromAddress(void *addr, wchar_t *outBase, std::size_t outCount) noexcept
    {
        if (!outBase || outCount == 0)
            return false;

        outBase[0] = L'\0';

        HMODULE hMod = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCWSTR>(addr), &hMod))
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

        auto fn = reinterpret_cast<RtlCaptureStackBackTrace_t>(GetProcAddress(ntdll, "RtlCaptureStackBackTrace"));

        g_capture.store(fn, std::memory_order_release);
        return (fn != nullptr);
    }

    static USHORT CaptureStack(std::uint16_t skip, std::uint16_t maxFrames, void **outFrames) noexcept
    {
        auto fn = g_capture.load(std::memory_order_acquire);
        if (!fn || !outFrames || maxFrames == 0)
            return 0;

        return fn(static_cast<ULONG>(skip), static_cast<ULONG>(maxFrames), outFrames, nullptr);
    }

    static bool DefaultMemoryFaultHandling(const bk::BK::Event &evt) noexcept
    {
        if (evt.exception_code == STATUS_GUARD_PAGE_VIOLATION)
            return true;
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
            return true;

        void *v = TlsGetValue(idx);
        if (v)
            return false;

        TlsSetValue(idx, reinterpret_cast<void *>(1));
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
        return (code == EXCEPTION_ACCESS_VIOLATION) || (code == EXCEPTION_IN_PAGE_ERROR) ||
               (code == STATUS_GUARD_PAGE_VIOLATION);
    }

    static LONG CALLBACK BlackbirdVeh(EXCEPTION_POINTERS *ep)
    {
        if (!ep || !ep->ExceptionRecord)
            return EXCEPTION_CONTINUE_SEARCH;

        if (!g_installed.load(std::memory_order_acquire))
            return EXCEPTION_CONTINUE_SEARCH;

        auto *a = g_args.load(std::memory_order_acquire);
        if (!a)
            return EXCEPTION_CONTINUE_SEARCH;

        if (!TryEnterHandler())
            return EXCEPTION_CONTINUE_SEARCH;

        bk::BK::Event evt{};
        evt.exception_code = ep->ExceptionRecord->ExceptionCode;
        evt.exception_flags = ep->ExceptionRecord->ExceptionFlags;
        evt.exception_address = ep->ExceptionRecord->ExceptionAddress;

        evt.pid = GetCurrentProcessId();
        evt.tid = GetCurrentThreadId();

        evt.is_noncontinuable = (evt.exception_flags & EXCEPTION_NONCONTINUABLE) != 0;
        evt.is_memory_fault = IsMemoryFault(evt.exception_code);

        evt.exception_info_count = (ep->ExceptionRecord->NumberParameters > bk::BK::kMaxExInfo)
                                       ? static_cast<ULONG>(bk::BK::kMaxExInfo)
                                       : static_cast<ULONG>(ep->ExceptionRecord->NumberParameters);

        for (ULONG i = 0; i < evt.exception_info_count; ++i)
            evt.exception_info[i] = ep->ExceptionRecord->ExceptionInformation[i];
        GetModuleBasenameLowerFromAddress(evt.exception_address, evt.module_basename_lower, bk::BK::kMaxModuleName);

        evt.is_target_module = EqualsLower(evt.module_basename_lower, g_target_lower);
        if (a->capture_stack)
        {
            (void)EnsureRtlCaptureResolved();

            std::uint16_t maxF = a->max_stack_frames;
            if (maxF == 0)
                maxF = 1;
            if (maxF > bk::BK::kMaxStackFrames)
                maxF = static_cast<std::uint16_t>(bk::BK::kMaxStackFrames);

            evt.stack_frame_count = CaptureStack(a->stack_frames_to_skip, maxF, evt.stack);
        }

        /* Memory-fault handling must be synchronous (return value determines
         * CONTINUE_EXECUTION vs CONTINUE_SEARCH).  Everything else is
         * fire-and-forget via the lock-free ring so the VEH handler returns fast. */
        if (evt.is_noncontinuable)
        {
            /* Non-continuable: dispatch telemetry synchronously, then let the
             * process terminate naturally. */
            if (evt.is_target_module)
            {
                if (a->low_noise_telemetry)
                    a->low_noise_telemetry(evt, a->user);
            }
            else
            {
                if (a->high_noise_telemetry)
                    a->high_noise_telemetry(evt, a->user);
            }
            LeaveHandler();
            return EXCEPTION_CONTINUE_SEARCH;
        }
        if (evt.is_memory_fault)
        {
            /* Memory-fault result is synchronous. */
            bool handled = false;
            if (a->memory_fault_handler)
                handled = a->memory_fault_handler(evt, ep, a->user);
            else
                handled = DefaultMemoryFaultHandling(evt);

            /* Also enqueue asynchronous telemetry notification. */
            (void)VehRingEnqueue(evt, evt.is_target_module);

            LeaveHandler();
            return handled ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
        }

        /* Normal (continuable, non-memory-fault) case: enqueue asynchronously.
         * If the ring is full, fall back to synchronous dispatch. */
        if (!VehRingEnqueue(evt, evt.is_target_module))
        {
            if (evt.is_target_module)
            {
                if (a->low_noise_telemetry)
                    a->low_noise_telemetry(evt, a->user);
            }
            else
            {
                if (a->high_noise_telemetry)
                    a->high_noise_telemetry(evt, a->user);
            }
        }

        if (!evt.is_target_module && a->swallow_non_target_exceptions)
        {
            LeaveHandler();
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        LeaveHandler();
        return EXCEPTION_CONTINUE_SEARCH;
    }
} // namespace

PVOID BkRegisterVectoredExceptionHandler(BkBlackbirdTelemetryArguments *args) noexcept
{
    if (!args)
        return nullptr;
    CopyLowerBasename(args->target_module_basename, g_target_lower, bk::BK::kMaxModuleName);

    if (args->capture_stack)
        (void)EnsureRtlCaptureResolved();
    void *existing = g_veh_handle.load(std::memory_order_acquire);
    if (existing)
    {
        g_args.store(args, std::memory_order_release);

        if (args->auto_promote && args->install_first)
            (void)BkPromoteVectoredExceptionHandlerToFront();

        g_installed.store(true, std::memory_order_release);
        return existing;
    }

    g_args.store(args, std::memory_order_release);

    (void)VehRingInit();

    const ULONG first = args->install_first ? 1u : 0u;
    void *h = AddVectoredExceptionHandler(first, BlackbirdVeh);
    if (!h)
    {
        VehRingShutdown();
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
    void *h = g_veh_handle.load(std::memory_order_acquire);
    if (!h)
        return FALSE;

    RemoveVectoredExceptionHandler(h);

    void *nh = AddVectoredExceptionHandler(1, BlackbirdVeh);
    if (!nh)
    {
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

    void *h = g_veh_handle.exchange(nullptr, std::memory_order_acq_rel);
    if (h)
        RemoveVectoredExceptionHandler(h);

    /* Shutdown the async ring before clearing g_args so the dispatcher can
     * finish draining any queued telemetry events. */
    VehRingShutdown();

    g_args.store(nullptr, std::memory_order_release);
    g_target_lower[0] = L'\0';
}
