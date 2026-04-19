#pragma once

#include <windows.h>
#include <cstdint>
#include "../../../abi/blackbird_ipc.h"

namespace BKIPC
{
    inline constexpr const wchar_t *PIPE_NAME = BLACKBIRD_IPC_HOOK_PIPE_NAME;
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

    bool WriteRaw(const void *data, DWORD size);
    bool ReadRaw(void *buffer, DWORD size, DWORD &bytesRead);
    bool PublishHookEvent(const BLACKBIRD_IPC_HOOK_EVENT &eventRecord);
    bool NotifyHookReady(UINT32 readyMask, UINT32 *observedMaskOut = nullptr);

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
