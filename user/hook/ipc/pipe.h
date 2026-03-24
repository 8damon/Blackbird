#pragma once

#include <windows.h>
#include <string>
#include <cstdint>
#include "../../../abi/blackbird_ipc.h"

namespace XIPC
{
    inline constexpr const wchar_t *PIPE_NAME = BLACKBIRD_IPC_PIPE_NAME;
    inline constexpr DWORD KHOK_MAGIC = 0x4B4F484B;
    inline constexpr DWORD KHOK_VERSION = 1;
    inline constexpr DWORD MAX_NAME_CHARS = 256;
    inline constexpr DWORD PIPE_DEFAULT_TIMEOUT_MS = 5000;

    enum class RequestKind : std::uint32_t
    {
        NameToNumber = 1,
        NumberToName = 2,
        WinsockEvent = 3,
        NtEvent = 4,
        KiEvent = 5,
        BkExceptionLowNoise = 6,
        BkExceptionHighPriv = 7
    };

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

    struct HelloMessage
    {
        DWORD magic;
        DWORD version;
        DWORD pid;
        DWORD reserved;
    };

#pragma pack(push, 1)
    struct BkExceptionMessage
    {
        RequestKind Kind;

        std::uint32_t Pid;
        std::uint32_t Tid;

        std::uint32_t ExceptionCode;
        std::uint32_t ExceptionFlags;

        std::uint64_t ExceptionAddress;

        std::uint32_t ModuleNameChars;
        std::uint32_t ExceptionInfoCount;
        std::uint32_t StackFrameCount;
        std::uint32_t Reserved;

        std::uint64_t ExceptionInfo[4];
        std::uint64_t Stack[64];

        wchar_t ModuleName[MAX_NAME_CHARS];
    };
#pragma pack(pop)

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

    bool SendSwException(const BkExceptionMessage &msg);

    bool SendHello();
    bool RecvHello(HelloMessage &out);

    bool RequestNumberForName(const std::wstring &name, DWORD &outValue);
    bool RequestNameForNumber(DWORD ssn, std::wstring &outName);
} // namespace XIPC
