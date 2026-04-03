#include "ws.h"

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

    struct PatchedIatSlot
    {
        ULONG_PTR *Slot;
        void *HookFunction;
    };

    static PatchedIatSlot g_PatchedSlots[16]{};
    static std::size_t g_PatchedSlotCount = 0;

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

    static void TrackPatchedSlot(ULONG_PTR *slot, void *hookFunction)
    {
        if (slot == nullptr || hookFunction == nullptr)
        {
            return;
        }

        for (std::size_t i = 0; i < g_PatchedSlotCount; ++i)
        {
            if (g_PatchedSlots[i].Slot == slot)
            {
                g_PatchedSlots[i].HookFunction = hookFunction;
                return;
            }
        }

        if (g_PatchedSlotCount < RTL_NUMBER_OF(g_PatchedSlots))
        {
            g_PatchedSlots[g_PatchedSlotCount].Slot = slot;
            g_PatchedSlots[g_PatchedSlotCount].HookFunction = hookFunction;
            ++g_PatchedSlotCount;
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

                            *functionSlot = reinterpret_cast<ULONG_PTR>(hookEntry.HookFunction);
                            TrackPatchedSlot(functionSlot, hookEntry.HookFunction);
                            anyPatched = true;
                        }
                    }
                    else
                    {
                        if (*hookEntry.OriginalFunction != nullptr)
                        {
                            *functionSlot = reinterpret_cast<ULONG_PTR>(*hookEntry.OriginalFunction);
                            *hookEntry.OriginalFunction = nullptr;
                            anyPatched = true;
                        }
                    }

                    VirtualProtect(functionSlot, sizeof(ULONG_PTR), oldProtection, &oldProtection);
                }
            }
        }

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

    const HMODULE moduleHandle = GetModuleHandleW(nullptr);
    if (moduleHandle == nullptr)
    {
        g_ActiveCallback = nullptr;
        return false;
    }

    const bool patched = PatchImportAddressTableForModule(moduleHandle, true);
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

void KeRemoveWinsockHook() noexcept
{
    if (!g_HooksInstalled)
    {
        g_ActiveCallback = nullptr;
        return;
    }

    const HMODULE moduleHandle = GetModuleHandleW(nullptr);
    if (moduleHandle != nullptr)
    {
        PatchImportAddressTableForModule(moduleHandle, false);
    }

    g_ActiveCallback = nullptr;
    g_HooksInstalled = false;
    g_PatchedSlotCount = 0;
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
