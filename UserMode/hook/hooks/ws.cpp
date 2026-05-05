#include "ws.h"
#include "../../../ABI/blackbird_ipc.h"

#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <TlHelp32.h>
#include <intrin.h>

#include <cstring>

#pragma intrinsic(_ReturnAddress)

namespace
{
    using WsasendFn = INT(WSAAPI *)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED,
                                    LPWSAOVERLAPPED_COMPLETION_ROUTINE);

    using WsarecvFn = INT(WSAAPI *)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED,
                                    LPWSAOVERLAPPED_COMPLETION_ROUTINE);

    using SendFn = int(WSAAPI *)(SOCKET, const char *, int, int);

    using RecvFn = int(WSAAPI *)(SOCKET, char *, int, int);

    using ConnectFn = int(WSAAPI *)(SOCKET, const sockaddr *, int);

    using WsaConnectFn = int(WSAAPI *)(SOCKET, const sockaddr *, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);

    using GetAddrInfoWFn = INT(WSAAPI *)(PCWSTR, PCWSTR, const ADDRINFOW *, PADDRINFOW *);

    struct HookEntry
    {
        const char *ModuleName;
        const char *FunctionName;
        void **OriginalFunction;
        void *HookFunction;
    };

    static WsasendFn g_OriginalWsasend = nullptr;
    static WsarecvFn g_OriginalWsarecv = nullptr;
    static SendFn g_OriginalSend = nullptr;
    static RecvFn g_OriginalRecv = nullptr;
    static ConnectFn g_OriginalConnect = nullptr;
    static WsaConnectFn g_OriginalWsaConnect = nullptr;
    static GetAddrInfoWFn g_OriginalGetAddrInfoW = nullptr;
    static WinsockHookCallback g_ActiveCallback = nullptr;
    static bool g_HooksInstalled = false;
    static __declspec(thread) bool g_InHook = false;

    /* Rotating ring that maps socket handles to their last connected remote endpoint.
       Populated at connect time; looked up by send/recv hooks to embed endpoint context
       without calling getpeername (extra syscall) on every I/O operation. */
    struct SocketEndpointEntry
    {
        SOCKET socket;
        UINT16 family;  /* AF_INET=2, AF_INET6=23 */
        UINT16 port;    /* host byte order */
        UINT32 addrNbo; /* IPv4 only: network byte order */
    };

    static constexpr std::size_t kEndpointCacheSlots = 64;
    static SocketEndpointEntry g_EndpointCache[kEndpointCacheSlots]{};
    static std::size_t g_EndpointCacheHead = 0;

    static void EndpointCacheStore(SOCKET s, const sockaddr *name, int nameLen) noexcept
    {
        if (s == INVALID_SOCKET || name == nullptr || nameLen < 4)
            return;

        SocketEndpointEntry entry{};
        entry.socket = s;
        entry.family = static_cast<UINT16>(name->sa_family);

        if (name->sa_family == AF_INET && nameLen >= static_cast<int>(sizeof(sockaddr_in)))
        {
            const auto *sin = reinterpret_cast<const sockaddr_in *>(name);
            /* Inline byte swap — avoids depending on ntohs from ws2_32.lib which is not linked
               directly in the hook DLL (Winsock is resolved through IAT patching, not the import lib). */
            const auto netPort = sin->sin_port;
            entry.port = static_cast<UINT16>(((netPort & 0x00FFu) << 8) | ((netPort & 0xFF00u) >> 8));
            entry.addrNbo = sin->sin_addr.s_addr;
        }

        g_EndpointCache[g_EndpointCacheHead % kEndpointCacheSlots] = entry;
        g_EndpointCacheHead = (g_EndpointCacheHead + 1) % kEndpointCacheSlots;
    }

    static bool EndpointCacheLookup(SOCKET s, SocketEndpointEntry *out) noexcept
    {
        if (s == INVALID_SOCKET || out == nullptr)
            return false;
        for (std::size_t i = 0; i < kEndpointCacheSlots; ++i)
        {
            if (g_EndpointCache[i].socket == s && g_EndpointCache[i].family != 0)
            {
                *out = g_EndpointCache[i];
                return true;
            }
        }
        return false;
    }

    struct PatchedIatSlot
    {
        ULONG_PTR *Slot;
        ULONG_PTR OriginalValue;
        void *HookFunction;
        const char *FunctionName;
    };

    static PatchedIatSlot g_PatchedSlots[512]{};
    static std::size_t g_PatchedSlotCount = 0;

    struct WinsockInlinePatchSlot
    {
        void *Target;
        std::size_t PatchSize;
        std::uint8_t OriginalBytes[16];
        const char *FunctionName;
        bool Active;
    };

    static WinsockInlinePatchSlot g_InlinePatchSlots[16]{};
    static std::size_t g_InlinePatchSlotCount = 0;

    static bool ModuleImportsWinsock(HMODULE moduleHandle)
    {
        if (moduleHandle == nullptr)
        {
            return false;
        }

        auto *base = reinterpret_cast<std::uint8_t *>(moduleHandle);
        auto *dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        if (dosHeader == nullptr || dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }

        auto *ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dosHeader->e_lfanew);
        if (ntHeaders == nullptr || ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            return false;
        }

        IMAGE_DATA_DIRECTORY &importDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0)
        {
            return false;
        }

        auto *importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + importDirectory.VirtualAddress);

        for (; importDescriptor->Name != 0; ++importDescriptor)
        {
            const char *importedModuleName = reinterpret_cast<const char *>(base + importDescriptor->Name);
            if (importedModuleName != nullptr && _stricmp(importedModuleName, "WS2_32.dll") == 0)
            {
                return true;
            }
        }

        return false;
    }

    static void TrackPatchedSlot(ULONG_PTR *slot, ULONG_PTR originalValue, void *hookFunction, const char *functionName)
    {
        if (slot == nullptr || hookFunction == nullptr)
        {
            return;
        }

        for (std::size_t i = 0; i < g_PatchedSlotCount; ++i)
        {
            if (g_PatchedSlots[i].Slot == slot)
            {
                if (g_PatchedSlots[i].OriginalValue == 0)
                {
                    g_PatchedSlots[i].OriginalValue = originalValue;
                }
                g_PatchedSlots[i].HookFunction = hookFunction;
                g_PatchedSlots[i].FunctionName = functionName;
                return;
            }
        }

        if (g_PatchedSlotCount < RTL_NUMBER_OF(g_PatchedSlots))
        {
            g_PatchedSlots[g_PatchedSlotCount].Slot = slot;
            g_PatchedSlots[g_PatchedSlotCount].OriginalValue = originalValue;
            g_PatchedSlots[g_PatchedSlotCount].HookFunction = hookFunction;
            g_PatchedSlots[g_PatchedSlotCount].FunctionName = functionName;
            ++g_PatchedSlotCount;
        }
    }

    static void TrackInlinePatch(void *target, std::size_t patchSize, const std::uint8_t *originalBytes,
                                 const char *functionName) noexcept
    {
        if (target == nullptr || patchSize == 0 || patchSize > 16 || originalBytes == nullptr)
        {
            return;
        }

        for (std::size_t i = 0; i < g_InlinePatchSlotCount; ++i)
        {
            if (g_InlinePatchSlots[i].Target == target)
            {
                g_InlinePatchSlots[i].PatchSize = patchSize;
                std::memcpy(g_InlinePatchSlots[i].OriginalBytes, originalBytes, patchSize);
                g_InlinePatchSlots[i].FunctionName = functionName;
                g_InlinePatchSlots[i].Active = true;
                return;
            }
        }

        if (g_InlinePatchSlotCount < RTL_NUMBER_OF(g_InlinePatchSlots))
        {
            g_InlinePatchSlots[g_InlinePatchSlotCount].Target = target;
            g_InlinePatchSlots[g_InlinePatchSlotCount].PatchSize = patchSize;
            std::memcpy(g_InlinePatchSlots[g_InlinePatchSlotCount].OriginalBytes, originalBytes, patchSize);
            g_InlinePatchSlots[g_InlinePatchSlotCount].FunctionName = functionName;
            g_InlinePatchSlots[g_InlinePatchSlotCount].Active = true;
            ++g_InlinePatchSlotCount;
        }
    }

    static void FillEndpointArgs(SOCKET s, WinsockHookContext &ctx) noexcept
    {
        SocketEndpointEntry ep{};
        if (EndpointCacheLookup(s, &ep))
        {
            ctx.Args[1] = (static_cast<std::uint64_t>(ep.family) << 16) | ep.port;
            ctx.Args[2] = static_cast<std::uint64_t>(ep.addrNbo);
        }
    }

    INT WSAAPI WsasendHook(SOCKET socketHandle, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesSent, DWORD flags,
                           LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine)
    {
        if (!g_InHook && g_ActiveCallback != nullptr && buffers != nullptr && bufferCount > 0)
        {
            g_InHook = true;
            void *caller = _ReturnAddress();

            for (DWORD i = 0; i < bufferCount; ++i)
            {
                if (buffers[i].buf == nullptr || buffers[i].len == 0)
                {
                    continue;
                }

                WinsockHookBuffer bufferView{};
                bufferView.Data = buffers[i].buf;
                bufferView.Length = buffers[i].len;

                WinsockHookContext context{};
                context.Operation = WinsockOperation::WsaSend;
                context.Socket = socketHandle;
                context.Buffers = &bufferView;
                context.BufferCount = 1U;
                context.Caller = caller;
                FillEndpointArgs(socketHandle, context);

                g_ActiveCallback(context);
            }

            g_InHook = false;
        }

        if (g_OriginalWsasend == nullptr)
        {
            return SOCKET_ERROR;
        }

        return g_OriginalWsasend(socketHandle, buffers, bufferCount, bytesSent, flags, overlapped, completionRoutine);
    }

    INT WSAAPI WsarecvHook(SOCKET socketHandle, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesReceived,
                           LPDWORD flags, LPWSAOVERLAPPED overlapped,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine)
    {
        if (g_OriginalWsarecv == nullptr)
        {
            return SOCKET_ERROR;
        }

        const INT result =
            g_OriginalWsarecv(socketHandle, buffers, bufferCount, bytesReceived, flags, overlapped, completionRoutine);

        if (result != 0)
        {
            return result;
        }

        if (!g_InHook && g_ActiveCallback != nullptr && buffers != nullptr && bufferCount > 0 &&
            bytesReceived != nullptr && *bytesReceived > 0)
        {
            g_InHook = true;
            void *caller = _ReturnAddress();

            std::size_t remaining = static_cast<std::size_t>(*bytesReceived);

            for (DWORD i = 0; i < bufferCount && remaining > 0; ++i)
            {
                if (buffers[i].buf == nullptr || buffers[i].len == 0)
                {
                    continue;
                }

                const std::size_t bufLen =
                    (remaining < buffers[i].len) ? remaining : static_cast<std::size_t>(buffers[i].len);

                WinsockHookBuffer bufferView{};
                bufferView.Data = buffers[i].buf;
                bufferView.Length = bufLen;

                WinsockHookContext context{};
                context.Operation = WinsockOperation::WsaRecv;
                context.Socket = socketHandle;
                context.Buffers = &bufferView;
                context.BufferCount = 1U;
                context.Caller = caller;
                FillEndpointArgs(socketHandle, context);

                g_ActiveCallback(context);

                remaining -= bufLen;
            }

            g_InHook = false;
        }

        return result;
    }

    int WSAAPI SendHook(SOCKET socketHandle, const char *buffer, int length, int flags)
    {
        if (!g_InHook && g_ActiveCallback != nullptr && buffer != nullptr && length > 0)
        {
            g_InHook = true;

            WinsockHookBuffer bufferView{};
            bufferView.Data = buffer;
            bufferView.Length = static_cast<std::size_t>(length);

            WinsockHookContext context{};
            context.Operation = WinsockOperation::Send;
            context.Socket = socketHandle;
            context.Buffers = &bufferView;
            context.BufferCount = 1U;
            context.Caller = _ReturnAddress();
            FillEndpointArgs(socketHandle, context);

            g_ActiveCallback(context);

            g_InHook = false;
        }

        if (g_OriginalSend == nullptr)
        {
            return SOCKET_ERROR;
        }

        return g_OriginalSend(socketHandle, buffer, length, flags);
    }

    int WSAAPI RecvHook(SOCKET socketHandle, char *buffer, int length, int flags)
    {
        if (g_OriginalRecv == nullptr)
        {
            return SOCKET_ERROR;
        }

        const int result = g_OriginalRecv(socketHandle, buffer, length, flags);

        if (result > 0 && !g_InHook && g_ActiveCallback != nullptr && buffer != nullptr)
        {
            g_InHook = true;

            WinsockHookBuffer bufferView{};
            bufferView.Data = buffer;
            bufferView.Length = static_cast<std::size_t>(result);

            WinsockHookContext context{};
            context.Operation = WinsockOperation::Recv;
            context.Socket = socketHandle;
            context.Buffers = &bufferView;
            context.BufferCount = 1U;
            context.Caller = _ReturnAddress();
            FillEndpointArgs(socketHandle, context);

            g_ActiveCallback(context);

            g_InHook = false;
        }

        return result;
    }

    int WSAAPI ConnectHook(SOCKET socketHandle, const sockaddr *name, int nameLength)
    {
        if (!g_InHook && g_ActiveCallback != nullptr && name != nullptr && nameLength > 0)
        {
            g_InHook = true;

            WinsockHookBuffer bufferView{};
            bufferView.Data = name;
            bufferView.Length = static_cast<std::size_t>(nameLength);

            WinsockHookContext context{};
            context.Operation = WinsockOperation::Connect;
            context.Socket = socketHandle;
            context.Buffers = &bufferView;
            context.BufferCount = 1U;
            context.Caller = _ReturnAddress();
            context.Args[0] = static_cast<std::uint64_t>(name->sa_family);
            context.Args[1] = static_cast<std::uint64_t>(nameLength);

            g_ActiveCallback(context);

            EndpointCacheStore(socketHandle, name, nameLength);

            g_InHook = false;
        }

        if (g_OriginalConnect == nullptr)
        {
            return SOCKET_ERROR;
        }

        return g_OriginalConnect(socketHandle, name, nameLength);
    }

    int WSAAPI WsaConnectHook(SOCKET socketHandle, const sockaddr *name, int nameLength, LPWSABUF callerData,
                              LPWSABUF calleeData, LPQOS sqos, LPQOS gqos)
    {
        if (!g_InHook && g_ActiveCallback != nullptr && name != nullptr && nameLength > 0)
        {
            g_InHook = true;

            WinsockHookBuffer bufferView{};
            bufferView.Data = name;
            bufferView.Length = static_cast<std::size_t>(nameLength);

            WinsockHookContext context{};
            context.Operation = WinsockOperation::WsaConnect;
            context.Socket = socketHandle;
            context.Buffers = &bufferView;
            context.BufferCount = 1U;
            context.Caller = _ReturnAddress();
            context.Args[0] = static_cast<std::uint64_t>(name->sa_family);
            context.Args[1] = static_cast<std::uint64_t>(nameLength);

            g_ActiveCallback(context);

            EndpointCacheStore(socketHandle, name, nameLength);

            g_InHook = false;
        }

        if (g_OriginalWsaConnect == nullptr)
        {
            return SOCKET_ERROR;
        }

        return g_OriginalWsaConnect(socketHandle, name, nameLength, callerData, calleeData, sqos, gqos);
    }

    INT WSAAPI GetAddrInfoWHook(PCWSTR nodeName, PCWSTR serviceName, const ADDRINFOW *hints, PADDRINFOW *result)
    {
        if (!g_InHook && g_ActiveCallback != nullptr && nodeName != nullptr && nodeName[0] != L'\0')
        {
            g_InHook = true;

            std::size_t chars = 0;
            while (nodeName[chars] != L'\0' && chars < 31)
            {
                ++chars;
            }

            WinsockHookBuffer bufferView{};
            bufferView.Data = nodeName;
            bufferView.Length = chars * sizeof(wchar_t);

            WinsockHookContext context{};
            context.Operation = WinsockOperation::GetAddrInfoW;
            context.Socket = INVALID_SOCKET;
            context.Buffers = &bufferView;
            context.BufferCount = 1U;
            context.Caller = _ReturnAddress();
            context.Args[0] = (hints != nullptr) ? static_cast<std::uint64_t>(hints->ai_family) : 0ull;
            context.Args[1] = (serviceName != nullptr && serviceName[0] != L'\0')
                                  ? reinterpret_cast<std::uint64_t>(serviceName)
                                  : 0ull;

            g_ActiveCallback(context);

            g_InHook = false;
        }

        if (g_OriginalGetAddrInfoW == nullptr)
        {
            return EAI_FAIL;
        }

        return g_OriginalGetAddrInfoW(nodeName, serviceName, hints, result);
    }

    static HookEntry g_HookEntries[] = {
        {"WS2_32.dll", "WSASend", reinterpret_cast<void **>(&g_OriginalWsasend),
         reinterpret_cast<void *>(&WsasendHook)},
        {"WS2_32.dll", "WSARecv", reinterpret_cast<void **>(&g_OriginalWsarecv),
         reinterpret_cast<void *>(&WsarecvHook)},
        {"WS2_32.dll", "send", reinterpret_cast<void **>(&g_OriginalSend), reinterpret_cast<void *>(&SendHook)},
        {"WS2_32.dll", "recv", reinterpret_cast<void **>(&g_OriginalRecv), reinterpret_cast<void *>(&RecvHook)},
        {"WS2_32.dll", "connect", reinterpret_cast<void **>(&g_OriginalConnect),
         reinterpret_cast<void *>(&ConnectHook)},
        {"WS2_32.dll", "WSAConnect", reinterpret_cast<void **>(&g_OriginalWsaConnect),
         reinterpret_cast<void *>(&WsaConnectHook)},
        {"WS2_32.dll", "GetAddrInfoW", reinterpret_cast<void **>(&g_OriginalGetAddrInfoW),
         reinterpret_cast<void *>(&GetAddrInfoWHook)},
    };

    bool PatchImportAddressTableForModule(HMODULE moduleHandle, bool install)
    {
        if (moduleHandle == nullptr)
        {
            return false;
        }

        auto *base = reinterpret_cast<std::uint8_t *>(moduleHandle);

        auto *dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        if (dosHeader == nullptr || dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }

        auto *ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dosHeader->e_lfanew);
        if (ntHeaders == nullptr || ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            return false;
        }

        IMAGE_DATA_DIRECTORY &importDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0)
        {
            return false;
        }

        auto *importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + importDirectory.VirtualAddress);

        bool anyPatched = false;

        for (; importDescriptor->Name != 0; ++importDescriptor)
        {
            const char *importedModuleName = reinterpret_cast<const char *>(base + importDescriptor->Name);

            bool moduleMatches = false;
            for (const auto &hookEntry : g_HookEntries)
            {
                if (_stricmp(importedModuleName, hookEntry.ModuleName) == 0)
                {
                    moduleMatches = true;
                    break;
                }
            }

            if (!moduleMatches)
            {
                continue;
            }

            auto *thunkIat = reinterpret_cast<PIMAGE_THUNK_DATA>(base + importDescriptor->FirstThunk);

            PIMAGE_THUNK_DATA thunkOriginal = nullptr;
            if (importDescriptor->OriginalFirstThunk != 0)
            {
                thunkOriginal = reinterpret_cast<PIMAGE_THUNK_DATA>(base + importDescriptor->OriginalFirstThunk);
            }

            for (; thunkIat->u1.Function != 0; ++thunkIat)
            {
                const char *functionName = nullptr;

                if (thunkOriginal != nullptr)
                {
                    if (IMAGE_SNAP_BY_ORDINAL(thunkOriginal->u1.Ordinal))
                    {
                        ++thunkOriginal;
                        continue;
                    }

                    auto *importByName =
                        reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(base + thunkOriginal->u1.AddressOfData);

                    functionName = reinterpret_cast<const char *>(importByName->Name);
                    ++thunkOriginal;
                }

                if (functionName == nullptr)
                {
                    continue;
                }

                for (auto &hookEntry : g_HookEntries)
                {
                    if (_stricmp(importedModuleName, hookEntry.ModuleName) != 0)
                    {
                        continue;
                    }

                    if (std::strcmp(functionName, hookEntry.FunctionName) != 0)
                    {
                        continue;
                    }

                    auto *functionSlot = reinterpret_cast<ULONG_PTR *>(&thunkIat->u1.Function);

                    DWORD oldProtection = 0;
                    if (!VirtualProtect(functionSlot, sizeof(ULONG_PTR), PAGE_READWRITE, &oldProtection))
                    {
                        continue;
                    }

                    if (install)
                    {
                        if (*hookEntry.OriginalFunction == nullptr)
                        {
                            *hookEntry.OriginalFunction = reinterpret_cast<void *>(*functionSlot);
                        }

                        ULONG_PTR originalValue = reinterpret_cast<ULONG_PTR>(*hookEntry.OriginalFunction);
                        *functionSlot = reinterpret_cast<ULONG_PTR>(hookEntry.HookFunction);
                        TrackPatchedSlot(functionSlot, originalValue, hookEntry.HookFunction, hookEntry.FunctionName);
                        anyPatched = true;
                    }
                    else
                    {
                        if (*hookEntry.OriginalFunction != nullptr)
                        {
                            *functionSlot = reinterpret_cast<ULONG_PTR>(*hookEntry.OriginalFunction);
                            anyPatched = true;
                        }
                    }

                    VirtualProtect(functionSlot, sizeof(ULONG_PTR), oldProtection, &oldProtection);
                }
            }
        }

        return anyPatched;
    }

    bool PatchLoadedModules(bool install, HMODULE specificModule = nullptr)
    {
        if (specificModule != nullptr)
        {
            return PatchImportAddressTableForModule(specificModule, install);
        }

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        MODULEENTRY32W moduleEntry{};
        moduleEntry.dwSize = sizeof(moduleEntry);
        bool anyPatched = false;

        if (Module32FirstW(snapshot, &moduleEntry))
        {
            do
            {
                anyPatched |= PatchImportAddressTableForModule(moduleEntry.hModule, install);
            } while (Module32NextW(snapshot, &moduleEntry));
        }

        CloseHandle(snapshot);
        return anyPatched;
    }
} // namespace

bool KeSetWinsockHook(WinsockHookCallback callback) noexcept
{
    if (callback == nullptr)
    {
        return false;
    }

    g_ActiveCallback = callback;

    if (g_HooksInstalled)
    {
        return true;
    }

    g_PatchedSlotCount = 0;
    g_InlinePatchSlotCount = 0;

    const bool patched = PatchLoadedModules(true);
    if (!patched)
    {
        g_ActiveCallback = nullptr;
        return false;
    }

    g_HooksInstalled = true;
    return true;
}

bool KeIsWinsockHookRequired() noexcept
{
    const HMODULE moduleHandle = GetModuleHandleW(nullptr);
    if (moduleHandle == nullptr)
    {
        return true;
    }

    return ModuleImportsWinsock(moduleHandle);
}

bool KeRefreshWinsockHooks(HMODULE moduleHandle) noexcept
{
    if (!g_HooksInstalled)
    {
        return false;
    }

    return PatchLoadedModules(true, moduleHandle);
}

void KeRemoveWinsockHook() noexcept
{
    if (!g_HooksInstalled)
    {
        g_ActiveCallback = nullptr;
        return;
    }

    (void)PatchLoadedModules(false);

    g_ActiveCallback = nullptr;
    g_HooksInstalled = false;
    g_PatchedSlotCount = 0;
    g_InlinePatchSlotCount = 0;
}

bool KeCheckWinsockHookIntegrity(std::uint32_t *mismatchCount) noexcept
{
    std::uint32_t mismatches = 0;

    if (g_HooksInstalled)
    {
        for (std::size_t i = 0; i < g_PatchedSlotCount; ++i)
        {
            ULONG_PTR *slot = g_PatchedSlots[i].Slot;
            void *expectedHook = g_PatchedSlots[i].HookFunction;
            if (slot == nullptr || expectedHook == nullptr)
            {
                ++mismatches;
                continue;
            }

            if (*slot != reinterpret_cast<ULONG_PTR>(expectedHook))
            {
                ++mismatches;
            }
        }
    }

    if (mismatchCount != nullptr)
    {
        *mismatchCount = mismatches;
    }

    return mismatches == 0;
}

bool KeInstallWinsockInlineHooks() noexcept
{
    /* Inline hook: write a 5-byte near JMP (0xE9 rel32) into the function prologue
       of each WS2_32 export so that code calling the function directly (not through
       the IAT) — e.g. shellcode in a hollowed process — is still intercepted.
       Requires VirtualProtect to make the .text section temporarily writable.
       Idempotent: already-patched slots are left untouched. */

    static volatile LONG s_inlineInstalled = 0;
    if (InterlockedCompareExchange(&s_inlineInstalled, 1, 0) != 0)
    {
        return true; /* already done */
    }

    if (!g_HooksInstalled || g_ActiveCallback == nullptr)
    {
        InterlockedExchange(&s_inlineInstalled, 0);
        return false;
    }

    struct InlineEntry
    {
        const char *FunctionName;
        void **OrigFn;
        void *HookFn;
    };

    static const InlineEntry kEntries[] = {
        {"connect", reinterpret_cast<void **>(&g_OriginalConnect), reinterpret_cast<void *>(&ConnectHook)},
        {"WSAConnect", reinterpret_cast<void **>(&g_OriginalWsaConnect), reinterpret_cast<void *>(&WsaConnectHook)},
        {"send", reinterpret_cast<void **>(&g_OriginalSend), reinterpret_cast<void *>(&SendHook)},
        {"recv", reinterpret_cast<void **>(&g_OriginalRecv), reinterpret_cast<void *>(&RecvHook)},
        {"WSASend", reinterpret_cast<void **>(&g_OriginalWsasend), reinterpret_cast<void *>(&WsasendHook)},
        {"WSARecv", reinterpret_cast<void **>(&g_OriginalWsarecv), reinterpret_cast<void *>(&WsarecvHook)},
        {"GetAddrInfoW", reinterpret_cast<void **>(&g_OriginalGetAddrInfoW),
         reinterpret_cast<void *>(&GetAddrInfoWHook)},
    };

    bool anyFailed = false;

    for (const auto &e : kEntries)
    {
        if (e.OrigFn == nullptr || *e.OrigFn == nullptr || e.HookFn == nullptr)
        {
            continue;
        }

        auto *target = static_cast<std::uint8_t *>(*e.OrigFn);

        /* Skip if JMP is already present at the target */
        if (target[0] == 0xE9u)
        {
            continue;
        }

        std::uint8_t originalBytes[16]{};
        std::memcpy(originalBytes, target, 5);

        DWORD old = 0;
        if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old))
        {
            anyFailed = true;
            continue;
        }

        const std::ptrdiff_t rel = static_cast<std::uint8_t *>(e.HookFn) - (target + 5);
        target[0] = 0xE9u;
        *reinterpret_cast<std::int32_t *>(target + 1) = static_cast<std::int32_t>(rel);

        VirtualProtect(target, 5, old, &old);
        FlushInstructionCache(GetCurrentProcess(), target, 5);
        TrackInlinePatch(target, 5, originalBytes, e.FunctionName);
    }

    return !anyFailed;
}

std::size_t KeCollectWinsockHookPatchInfos(WinsockHookPatchInfo *out, std::size_t capacity) noexcept
{
    if (out == nullptr || capacity == 0)
    {
        return 0;
    }

    std::size_t count = 0;
    for (std::size_t i = 0; i < g_PatchedSlotCount && count < capacity; ++i)
    {
        if (g_PatchedSlots[i].Slot == nullptr || g_PatchedSlots[i].OriginalValue == 0)
        {
            continue;
        }
        out[count].PatchAddress = g_PatchedSlots[i].Slot;
        out[count].PatchSize = sizeof(g_PatchedSlots[i].OriginalValue);
        std::memset(out[count].OriginalBytes, 0, sizeof(out[count].OriginalBytes));
        std::memcpy(out[count].OriginalBytes, &g_PatchedSlots[i].OriginalValue,
                    sizeof(g_PatchedSlots[i].OriginalValue));
        out[count].HookName = g_PatchedSlots[i].FunctionName;
        out[count].Flags = BK_HOOK_PATCH_FLAG_WINSOCK_IAT;
        ++count;
    }

    for (std::size_t i = 0; i < g_InlinePatchSlotCount && count < capacity; ++i)
    {
        if (!g_InlinePatchSlots[i].Active || g_InlinePatchSlots[i].Target == nullptr ||
            g_InlinePatchSlots[i].PatchSize == 0)
        {
            continue;
        }
        out[count].PatchAddress = g_InlinePatchSlots[i].Target;
        out[count].PatchSize = g_InlinePatchSlots[i].PatchSize;
        std::memset(out[count].OriginalBytes, 0, sizeof(out[count].OriginalBytes));
        std::memcpy(out[count].OriginalBytes, g_InlinePatchSlots[i].OriginalBytes, g_InlinePatchSlots[i].PatchSize);
        out[count].HookName = g_InlinePatchSlots[i].FunctionName;
        out[count].Flags = BK_HOOK_PATCH_FLAG_WINSOCK_INLINE;
        ++count;
    }

    return count;
}
