#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

#include <windows.h>
#include <cstdint>
#include "../../../abi/blackbird_ipc.h"

namespace BKIPC
{
    inline constexpr DWORD PIPE_DEFAULT_TIMEOUT_MS = 5000;

    struct WinsockEventHeader
    {
        std::uint32_t Operation;
        std::uint64_t Socket;
        std::uint64_t Caller;
        std::uint32_t DataLength;
    };

    struct NtEventMessage
    {
        std::uint32_t Operation;
        std::uint64_t Caller;
        std::uint64_t Args[8];
    };

    struct KiEventHeader
    {
        std::uint32_t StubNameLength;
        std::uint64_t Caller;
        std::uint64_t StackPointer;
    };

    static_assert(sizeof(wchar_t) == 2, "Windows x64 expected wchar_t == 2 bytes.");

    bool Initialize(DWORD timeoutMs = PIPE_DEFAULT_TIMEOUT_MS);
    void Shutdown();
    DWORD LastConnectStage() noexcept;
    DWORD LastConnectError() noexcept;

    bool WriteRaw(const void *data, DWORD size);
    bool ReadRaw(void *buffer, DWORD size, DWORD &bytesRead);
    bool PublishHookEvent(const BKIPC_HOOK_EVENT &eventRecord);
    bool PublishHookEventSynchronously(const BKIPC_HOOK_EVENT &eventRecord) noexcept;
    UINT32 DrainPendingHookEventsSynchronously(UINT32 maxEvents = 64) noexcept;
    bool NotifyHookReady(UINT32 readyMask, UINT32 *observedMaskOut = nullptr, UINT32 *pendingCommandOut = nullptr);
    /* Registers a memory range as runtime-owned instrumentation so the
       controller excludes it from heuristics
     * and annotates it in the UI. */
    bool RegisterInstrumentationRange(UINT64 baseAddress, UINT64 regionSize, UINT32 flags, const char *tag) noexcept;
    bool RegisterHookPatch(UINT64 patchAddress, UINT32 patchSize, const UINT8 *originalBytes, UINT32 originalSize,
                           UINT32 flags, const char *tag) noexcept;
    bool RegisterProcessInstrumentationCallback(UINT64 callbackAddress, UINT64 callbackSize, UINT32 flags) noexcept;
    bool IsProtectedIpcHandleValue(UINT64 handleValue) noexcept;

    template <typename T> bool SendMessage(const T &msg)
    {
        return WriteRaw(&msg, static_cast<DWORD>(sizeof(T)));
    }

    template <typename T> bool ReceiveMessage(T &msg)
    {
        DWORD bytesRead = 0;
        if (!ReadRaw(&msg, static_cast<DWORD>(sizeof(T)), bytesRead))
            return false;

        return bytesRead == sizeof(T);
    }
} // namespace BKIPC
