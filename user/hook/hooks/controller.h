#pragma once

#include <cstdint>
#include <vector>
#include <mutex>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "ws.h"
#include "nt.h"
#include "ki.h"

#include "../instrument/stacktrace.h"

struct WinsockCapturedEvent
{
    DWORD            ThreadId;
    SOCKET           Socket;
    WinsockOperation Operation;
    void*            Caller;
    std::vector<std::uint8_t> Data;

    IC_STACKTRACE::Trace Stack;
};

struct NtCapturedEvent
{
    DWORD        ThreadId;
    NtOperation  Operation;
    const char* FunctionName;
    void* Caller;
    std::uint64_t Args[8];
};


struct KiCapturedEvent
{
    DWORD       ThreadId;
    const char* StubName;
    void*       Caller;
    void*       StackPointer;
};


class WinsockHookController
{
public:
    WinsockHookController()  = default;
    ~WinsockHookController() = default;

    bool Initialize() noexcept;
    void Shutdown() noexcept;

    std::vector<WinsockCapturedEvent> ConsumeEvents();

private:
    static void KeWinsockHookCallback(const WinsockHookContext& context) noexcept;
    static void EnqueueEvent(const WinsockHookContext& context);

    static bool                         s_Initialized;
    static std::mutex                   s_QueueMutex;
    static std::vector<WinsockCapturedEvent> s_Queue;
};

class NtHookController
{
public:
    NtHookController()  = default;
    ~NtHookController() = default;

    bool Initialize() noexcept;
    void Shutdown() noexcept;

    std::vector<NtCapturedEvent> ConsumeEvents();

private:
    static void KeNtHookCallback(const NtHookContext& context) noexcept;
    static void EnqueueEvent(const NtHookContext& context);

    static bool                    s_Initialized;
    static std::mutex              s_QueueMutex;
    static std::vector<NtCapturedEvent> s_Queue;
};

class KiHookController
{
public:
    KiHookController()  = default;
    ~KiHookController() = default;

    bool Initialize() noexcept;
    void Shutdown() noexcept;

    std::vector<KiCapturedEvent> ConsumeEvents();

private:
    static void KeKiHookCallback(const KiHookContext& context) noexcept;
    static void EnqueueEvent(const KiHookContext& context);

    static bool                   s_Initialized;
    static std::mutex             s_QueueMutex;
    static std::vector<KiCapturedEvent> s_Queue;
};
