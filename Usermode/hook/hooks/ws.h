#pragma once

#include <cstddef>
#include <cstdint>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>

enum class WinsockOperation : std::uint32_t
{
    WsaSend = 0,
    WsaRecv = 1,
    Send = 2,
    Recv = 3,
    Connect = 4,
    WsaConnect = 5,
    GetAddrInfoW = 6
};

struct WinsockHookBuffer
{
    const void *Data;
    std::size_t Length;
};

struct WinsockHookContext
{
    WinsockOperation Operation;
    SOCKET Socket;
    const WinsockHookBuffer *Buffers;
    std::uint32_t BufferCount;
    void *Caller;
    std::uint64_t Args[4];
};

using WinsockHookCallback = void (*)(const WinsockHookContext &context) noexcept;

bool KeSetWinsockHook(WinsockHookCallback callback) noexcept;
bool KeIsWinsockHookRequired() noexcept;
bool KeRefreshWinsockHooks(HMODULE moduleHandle = nullptr) noexcept;
void KeRemoveWinsockHook() noexcept;
bool KeCheckWinsockHookIntegrity(std::uint32_t *mismatchCount) noexcept;
bool KeInstallWinsockInlineHooks() noexcept;

struct WinsockHookPatchInfo
{
    void *PatchAddress;
    std::size_t PatchSize;
    std::uint8_t OriginalBytes[16];
    const char *HookName;
    std::uint32_t Flags;
};

std::size_t KeCollectWinsockHookPatchInfos(_Out_writes_(capacity) WinsockHookPatchInfo *out,
                                           _In_ std::size_t capacity) noexcept;
