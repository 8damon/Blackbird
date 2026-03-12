#include "controller.h"

bool WinsockHookController::s_Initialized = false;
std::mutex WinsockHookController::s_QueueMutex;
std::vector<WinsockCapturedEvent> WinsockHookController::s_Queue;

bool WinsockHookController::Initialize() noexcept
{
    if (s_Initialized)
    {
        return true;
    }

    if (!KeSetWinsockHook(&WinsockHookController::KeWinsockHookCallback))
    {
        return false;
    }

    s_Initialized = true;
    return true;
}

void WinsockHookController::Shutdown() noexcept
{
    if (!s_Initialized)
    {
        return;
    }

    KeRemoveWinsockHook();

    {
        std::lock_guard<std::mutex> lock(s_QueueMutex);
        s_Queue.clear();
    }

    s_Initialized = false;
}

std::vector<WinsockCapturedEvent> WinsockHookController::ConsumeEvents()
{
    std::vector<WinsockCapturedEvent> events;

    {
        std::lock_guard<std::mutex> lock(s_QueueMutex);
        events.swap(s_Queue);
    }

    return events;
}

void WinsockHookController::KeWinsockHookCallback(
    const WinsockHookContext& context) noexcept
{
    EnqueueEvent(context);
}

void WinsockHookController::EnqueueEvent(
    const WinsockHookContext& context)
{
    WinsockCapturedEvent evt{};
    evt.ThreadId = GetCurrentThreadId();
    evt.Socket = context.Socket;
    evt.Operation = context.Operation;
    evt.Caller = context.Caller;

    if (context.Buffers && context.BufferCount > 0)
    {
        std::size_t totalLen = 0;
        for (std::uint32_t i = 0; i < context.BufferCount; ++i)
            totalLen += context.Buffers[i].Length;

        evt.Data.reserve(totalLen);
        for (std::uint32_t i = 0; i < context.BufferCount; ++i)
        {
            const auto& buf = context.Buffers[i];
            if (buf.Data && buf.Length)
            {
                const auto* src = static_cast<const std::uint8_t*>(buf.Data);
                evt.Data.insert(evt.Data.end(), src, src + buf.Length);
            }
        }
    }

    IC_STACKTRACE::Capture(evt.Stack, /*skip=*/ 2);

    std::lock_guard<std::mutex> lock(s_QueueMutex);
    s_Queue.push_back(std::move(evt));
}

bool NtHookController::s_Initialized = false;
std::mutex NtHookController::s_QueueMutex;
std::vector<NtCapturedEvent> NtHookController::s_Queue;

bool NtHookController::Initialize() noexcept
{
    if (s_Initialized)
    {
        return true;
    }

    if (!KeSetNtHook(&NtHookController::KeNtHookCallback))
    {
        return false;
    }

    s_Initialized = true;
    return true;
}

void NtHookController::Shutdown() noexcept
{
    if (!s_Initialized)
    {
        return;
    }

    KeRemoveNtHook();

    {
        std::lock_guard<std::mutex> lock(s_QueueMutex);
        s_Queue.clear();
    }

    s_Initialized = false;
}

std::vector<NtCapturedEvent> NtHookController::ConsumeEvents()
{
    std::vector<NtCapturedEvent> events;

    {
        std::lock_guard<std::mutex> lock(s_QueueMutex);
        events.swap(s_Queue);
    }

    return events;
}

void NtHookController::KeNtHookCallback(
    const NtHookContext& context) noexcept
{
    EnqueueEvent(context);
}

void NtHookController::EnqueueEvent(
    const NtHookContext& context)
{
    NtCapturedEvent evt{};
    evt.ThreadId = GetCurrentThreadId();
    evt.Operation = context.Operation;
    evt.FunctionName = context.FunctionName;
    evt.Caller = context.Caller;

    for (std::size_t i = 0; i < 8; ++i)
    {
        evt.Args[i] = context.Args[i];
    }

    std::lock_guard<std::mutex> lock(s_QueueMutex);
    s_Queue.push_back(std::move(evt));
}


bool KiHookController::s_Initialized = false;
std::mutex KiHookController::s_QueueMutex;
std::vector<KiCapturedEvent> KiHookController::s_Queue;

bool KiHookController::Initialize() noexcept
{
    if (s_Initialized)
    {
        return true;
    }

    if (!KeSetKiHook(&KiHookController::KeKiHookCallback))
    {
        return false;
    }

    s_Initialized = true;
    return true;
}

void KiHookController::Shutdown() noexcept
{
    if (!s_Initialized)
    {
        return;
    }

    KeRemoveKiHook();

    {
        std::lock_guard<std::mutex> lock(s_QueueMutex);
        s_Queue.clear();
    }

    s_Initialized = false;
}

std::vector<KiCapturedEvent> KiHookController::ConsumeEvents()
{
    std::vector<KiCapturedEvent> events;

    {
        std::lock_guard<std::mutex> lock(s_QueueMutex);
        events.swap(s_Queue);
    }

    return events;
}

void KiHookController::KeKiHookCallback(
    const KiHookContext& context) noexcept
{
    EnqueueEvent(context);
}

void KiHookController::EnqueueEvent(
    const KiHookContext& context)
{
    KiCapturedEvent evt{};
    evt.ThreadId = GetCurrentThreadId();
    evt.StubName = context.StubName;
    evt.Caller = context.Caller;
    evt.StackPointer = context.StackPointer;

    std::lock_guard<std::mutex> lock(s_QueueMutex);
    s_Queue.push_back(std::move(evt));
}
