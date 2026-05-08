#include "controller.h"

#include <cstring>
#include <utility>

namespace BK_RUNTIME_INTERNAL
{
    void SignalHookEventsPending() noexcept;
}

namespace
{
    constexpr std::size_t kMaxQueuedHookEvents = 512;
    constexpr std::size_t kMaxQueueDedupeScan = 128;
    constexpr std::size_t kMaxCapturedPayloadBytes = 64;
    constexpr std::uint32_t kRepeatCountLimit = 0xFFFFFFFFu;

    std::size_t MinSize(std::size_t left, std::size_t right) noexcept
    {
        return left < right ? left : right;
    }

    void IncrementRepeat(std::uint32_t &value) noexcept
    {
        if (value != kRepeatCountLimit)
        {
            ++value;
        }
    }

    bool ArgsEqual(const std::uint64_t *left, const std::uint64_t *right, std::size_t count) noexcept
    {
        for (std::size_t i = 0; i < count; ++i)
        {
            if (left[i] != right[i])
            {
                return false;
            }
        }
        return true;
    }

    bool BytesEqual(const std::uint8_t *left, std::size_t leftSize, const std::uint8_t *right,
                    std::size_t rightSize) noexcept
    {
        if (leftSize != rightSize)
        {
            return false;
        }
        if (leftSize == 0)
        {
            return true;
        }
        return left != nullptr && right != nullptr && std::memcmp(left, right, leftSize) == 0;
    }

    bool ByteVectorsEqual(const std::vector<std::uint8_t> &left, const std::vector<std::uint8_t> &right) noexcept
    {
        return BytesEqual(left.data(), left.size(), right.data(), right.size());
    }

    bool CStringsEqual(const char *left, const char *right) noexcept
    {
        if (left == right)
        {
            return true;
        }
        if (left == nullptr || right == nullptr)
        {
            return false;
        }
        return std::strcmp(left, right) == 0;
    }

    bool IsExecutableProtect(std::uint64_t protect) noexcept
    {
        switch (static_cast<DWORD>(protect) & 0xFFu)
        {
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    bool IsRemoteTarget(std::uint64_t processHandle, std::uint64_t targetPid) noexcept
    {
        DWORD selfPid = GetCurrentProcessId();
        if (targetPid != 0 && targetPid <= MAXDWORD)
        {
            return static_cast<DWORD>(targetPid) != selfPid;
        }
        return processHandle != 0 && processHandle != 0xFFFFFFFFFFFFFFFFull;
    }

    bool NtEventIsInteresting(const NtCapturedEvent &event) noexcept
    {
        switch (event.Operation)
        {
        case NtOperation::NtCreateThread:
        case NtOperation::NtCreateThreadEx:
        case NtOperation::NtWriteVirtualMemory:
        case NtOperation::NtSetContextThread:
        case NtOperation::NtQueueApcThread:
        case NtOperation::NtQueueApcThreadEx:
        case NtOperation::NtQueueApcThreadEx2:
        case NtOperation::NtCreateSection:
        case NtOperation::NtTerminateProcess:
        case NtOperation::NtMapViewOfSection:
        case NtOperation::NtMapViewOfSectionEx:
        case NtOperation::NtUnmapViewOfSection:
        case NtOperation::NtUnmapViewOfSectionEx:
            return true;
        case NtOperation::NtAllocateVirtualMemory:
            return IsExecutableProtect(event.Args[5]) || IsRemoteTarget(event.Args[0], event.Args[6]);
        case NtOperation::NtAllocateVirtualMemoryEx:
            return IsExecutableProtect(event.Args[4]) || IsRemoteTarget(event.Args[0], event.Args[7]);
        case NtOperation::NtProtectVirtualMemory:
            return IsExecutableProtect(event.Args[3]) || IsRemoteTarget(event.Args[0], event.Args[7]) ||
                   event.Args[6] == kNtHookSr71ProtectBlockedMarker;
        default:
            return false;
        }
    }

    bool NtEventKeyEquals(const NtCapturedEvent &left, const NtCapturedEvent &right) noexcept
    {
        if (left.Operation != right.Operation || left.Status != right.Status)
        {
            return false;
        }

        switch (left.Operation)
        {
        case NtOperation::NtAllocateVirtualMemory:
            return left.Args[1] == right.Args[1] && left.Args[3] == right.Args[3] &&
                   left.Args[4] == right.Args[4] && left.Args[5] == right.Args[5] &&
                   left.Args[6] == right.Args[6];
        case NtOperation::NtAllocateVirtualMemoryEx:
            return left.Args[1] == right.Args[1] && left.Args[2] == right.Args[2] &&
                   left.Args[3] == right.Args[3] && left.Args[4] == right.Args[4] &&
                   left.Args[7] == right.Args[7];
        case NtOperation::NtProtectVirtualMemory:
            return left.Args[1] == right.Args[1] && left.Args[2] == right.Args[2] &&
                   left.Args[3] == right.Args[3] && left.Args[4] == right.Args[4] &&
                   left.Args[7] == right.Args[7];
        case NtOperation::NtWriteVirtualMemory:
            return left.Args[1] == right.Args[1] && left.Args[3] == right.Args[3] &&
                   left.Args[5] == right.Args[5] && left.Args[6] == right.Args[6] &&
                   BytesEqual(left.DataSample, left.DataSize, right.DataSample, right.DataSize);
        case NtOperation::NtReadVirtualMemory:
            return left.Caller == right.Caller && left.Args[1] == right.Args[1] && left.Args[3] == right.Args[3] &&
                   left.Args[7] == right.Args[7];
        case NtOperation::NtQueryVirtualMemory:
            return left.Caller == right.Caller && left.Args[1] == right.Args[1] && left.Args[2] == right.Args[2] &&
                   left.Args[4] == right.Args[4];
        case NtOperation::NtQuerySystemInformation:
            return left.Caller == right.Caller && left.Args[0] == right.Args[0] && left.Args[2] == right.Args[2];
        case NtOperation::NtQuerySystemInformationEx:
            return left.Caller == right.Caller && left.Args[0] == right.Args[0] && left.Args[2] == right.Args[2] &&
                   left.Args[4] == right.Args[4];
        default:
            return left.Caller == right.Caller && CStringsEqual(left.FunctionName, right.FunctionName) &&
                   ArgsEqual(left.Args, right.Args, RTL_NUMBER_OF(left.Args));
        }
    }

    bool WinsockEventIsInteresting(const WinsockCapturedEvent &event) noexcept
    {
        return event.Operation == WinsockOperation::Connect || event.Operation == WinsockOperation::WsaConnect ||
               event.Operation == WinsockOperation::GetAddrInfoW;
    }

    bool WinsockEventKeyEquals(const WinsockCapturedEvent &left, const WinsockCapturedEvent &right) noexcept
    {
        return left.Operation == right.Operation && left.Socket == right.Socket && left.Caller == right.Caller &&
               ArgsEqual(left.Args, right.Args, RTL_NUMBER_OF(left.Args)) && ByteVectorsEqual(left.Data, right.Data);
    }

    bool KiEventIsInteresting(const KiCapturedEvent &) noexcept
    {
        return true;
    }

    bool KiEventKeyEquals(const KiCapturedEvent &left, const KiCapturedEvent &right) noexcept
    {
        return left.Caller == right.Caller && left.StackPointer == right.StackPointer &&
               CStringsEqual(left.StubName, right.StubName);
    }

    bool ModuleEventIsInteresting(const ModuleCapturedEvent &) noexcept
    {
        return true;
    }

    bool ModuleEventKeyEquals(const ModuleCapturedEvent &left, const ModuleCapturedEvent &right) noexcept
    {
        return left.Operation == right.Operation && left.ModuleHandle == right.ModuleHandle &&
               left.Caller == right.Caller && CStringsEqual(left.FunctionName, right.FunctionName) &&
               CStringsEqual(left.SourceModule, right.SourceModule) && ArgsEqual(left.Args, right.Args, RTL_NUMBER_OF(left.Args)) &&
               ByteVectorsEqual(left.NameSample, right.NameSample);
    }

    template <typename T, typename EqualFn, typename InterestingFn>
    bool TryQueueCoalescedEvent(std::mutex &mutex, std::vector<T> &queue, T &&event, EqualFn equals,
                                InterestingFn isInteresting) noexcept
    {
        bool queued = false;
        std::lock_guard<std::mutex> lock(mutex);
        std::size_t checked = 0;
        for (auto it = queue.rbegin(); it != queue.rend() && checked < kMaxQueueDedupeScan; ++it, ++checked)
        {
            if (equals(*it, event))
            {
                IncrementRepeat(it->RepeatCount);
                BK_RUNTIME_INTERNAL::SignalHookEventsPending();
                return true;
            }
        }

        try
        {
            if (queue.size() < kMaxQueuedHookEvents)
            {
                queue.push_back(std::move(event));
                queued = true;
            }
            else
            {
                const bool incomingInteresting = isInteresting(event);
                if (incomingInteresting)
                {
                    for (auto it = queue.begin(); it != queue.end(); ++it)
                    {
                        if (!isInteresting(*it))
                        {
                            *it = std::move(event);
                            queued = true;
                            break;
                        }
                    }
                }

                if (!queued && !queue.empty())
                {
                    queue.erase(queue.begin());
                    queue.push_back(std::move(event));
                    queued = true;
                }
            }
        }
        catch (...)
        {
        }

        if (queued)
        {
            BK_RUNTIME_INTERNAL::SignalHookEventsPending();
        }
        return queued;
    }

    void TrimVectorCapacity(std::vector<std::uint8_t> &data) noexcept
    {
        if (data.empty())
        {
            std::vector<std::uint8_t>().swap(data);
        }
    }
}

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

void WinsockHookController::KeWinsockHookCallback(const WinsockHookContext &context) noexcept
{
    EnqueueEvent(context);
}

void WinsockHookController::EnqueueEvent(const WinsockHookContext &context)
{
    WinsockCapturedEvent evt{};
    evt.ThreadId = GetCurrentThreadId();
    evt.Socket = context.Socket;
    evt.Operation = context.Operation;
    evt.Caller = context.Caller;
    for (std::size_t i = 0; i < RTL_NUMBER_OF(evt.Args); ++i)
    {
        evt.Args[i] = context.Args[i];
    }

    if (context.Buffers && context.BufferCount > 0)
    {
        std::size_t totalLen = 0;
        for (std::uint32_t i = 0; i < context.BufferCount; ++i)
        {
            totalLen += MinSize(static_cast<std::size_t>(context.Buffers[i].Length),
                                kMaxCapturedPayloadBytes - MinSize(totalLen, kMaxCapturedPayloadBytes));
            if (totalLen >= kMaxCapturedPayloadBytes)
            {
                break;
            }
        }

        try
        {
            evt.Data.reserve(totalLen);
            for (std::uint32_t i = 0; i < context.BufferCount; ++i)
            {
                const auto &buf = context.Buffers[i];
                if (buf.Data && buf.Length && evt.Data.size() < kMaxCapturedPayloadBytes)
                {
                    std::size_t bytesToCopy =
                        MinSize(static_cast<std::size_t>(buf.Length), kMaxCapturedPayloadBytes - evt.Data.size());
                    const auto *src = static_cast<const std::uint8_t *>(buf.Data);
                    evt.Data.insert(evt.Data.end(), src, src + bytesToCopy);
                }
            }
        }
        catch (...)
        {
            evt.Data.clear();
            TrimVectorCapacity(evt.Data);
        }
    }

    IC_STACKTRACE::Capture(evt.Stack, 2);

    (void)TryQueueCoalescedEvent(s_QueueMutex, s_Queue, std::move(evt), WinsockEventKeyEquals,
                                 WinsockEventIsInteresting);
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

void NtHookController::KeNtHookCallback(const NtHookContext &context) noexcept
{
    EnqueueEvent(context);
}

void NtHookController::EnqueueEvent(const NtHookContext &context)
{
    NtCapturedEvent evt{};
    evt.ThreadId = GetCurrentThreadId();
    evt.Operation = context.Operation;
    evt.FunctionName = context.FunctionName;
    evt.Caller = context.Caller;
    evt.Status = context.Status;

    for (std::size_t i = 0; i < 8; ++i)
    {
        evt.Args[i] = context.Args[i];
    }
    evt.DataSize = context.DataSize;
    if (evt.DataSize > sizeof(evt.DataSample))
    {
        evt.DataSize = sizeof(evt.DataSample);
    }
    if (evt.DataSize != 0)
    {
        std::memcpy(evt.DataSample, context.DataSample, evt.DataSize);
    }

    evt.Stack = context.Stack;

    (void)TryQueueCoalescedEvent(s_QueueMutex, s_Queue, std::move(evt), NtEventKeyEquals, NtEventIsInteresting);
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

void KiHookController::KeKiHookCallback(const KiHookContext &context) noexcept
{
    EnqueueEvent(context);
}

void KiHookController::EnqueueEvent(const KiHookContext &context)
{
    KiCapturedEvent evt{};
    evt.ThreadId = GetCurrentThreadId();
    evt.StubName = context.StubName;
    evt.Caller = context.Caller;
    evt.StackPointer = context.StackPointer;
    IC_STACKTRACE::Capture(evt.Stack, 2);

    (void)TryQueueCoalescedEvent(s_QueueMutex, s_Queue, std::move(evt), KiEventKeyEquals, KiEventIsInteresting);
}

bool ModuleHookController::s_Initialized = false;
std::mutex ModuleHookController::s_QueueMutex;
std::vector<ModuleCapturedEvent> ModuleHookController::s_Queue;

bool ModuleHookController::Initialize() noexcept
{
    if (s_Initialized)
    {
        return true;
    }

    if (!KeSetModuleHook(&ModuleHookController::KeModuleHookCallback))
    {
        return false;
    }

    s_Initialized = true;
    return true;
}

void ModuleHookController::Shutdown() noexcept
{
    if (!s_Initialized)
    {
        return;
    }

    KeRemoveModuleHook();

    {
        std::lock_guard<std::mutex> lock(s_QueueMutex);
        s_Queue.clear();
    }

    s_Initialized = false;
}

std::vector<ModuleCapturedEvent> ModuleHookController::ConsumeEvents()
{
    std::vector<ModuleCapturedEvent> events;

    {
        std::lock_guard<std::mutex> lock(s_QueueMutex);
        events.swap(s_Queue);
    }

    return events;
}

void ModuleHookController::KeModuleHookCallback(const ModuleHookContext &context) noexcept
{
    EnqueueEvent(context);
}

void ModuleHookController::EnqueueEvent(const ModuleHookContext &context)
{
    ModuleCapturedEvent evt{};
    evt.ThreadId = GetCurrentThreadId();
    evt.Operation = context.Operation;
    evt.FunctionName = context.FunctionName;
    evt.SourceModule = context.SourceModule;
    evt.Caller = context.Caller;
    evt.ModuleHandle = context.ModuleHandle;
    for (std::size_t i = 0; i < RTL_NUMBER_OF(evt.Args); ++i)
    {
        evt.Args[i] = context.Args[i];
    }

    if (context.NameBuffer != nullptr && context.NameLength != 0)
    {
        const auto *bytes = static_cast<const std::uint8_t *>(context.NameBuffer);
        try
        {
            std::size_t bytesToCopy = MinSize(static_cast<std::size_t>(context.NameLength), kMaxCapturedPayloadBytes);
            evt.NameSample.insert(evt.NameSample.end(), bytes, bytes + bytesToCopy);
        }
        catch (...)
        {
            evt.NameSample.clear();
            TrimVectorCapacity(evt.NameSample);
        }
    }

    IC_STACKTRACE::Capture(evt.Stack, 2);

    (void)TryQueueCoalescedEvent(s_QueueMutex, s_Queue, std::move(evt), ModuleEventKeyEquals, ModuleEventIsInteresting);
}
