#include "pipe.h"
#include <strsafe.h>

namespace XIPC
{
    static HANDLE  g_pipeHandle = INVALID_HANDLE_VALUE;
    static SRWLOCK g_pipeLock = SRWLOCK_INIT;
    static volatile LONG g_sequence = 1;
    static bool g_handshakeComplete = false;

    static void ClosePipeLocked()
    {
        if (g_pipeHandle != nullptr && g_pipeHandle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(g_pipeHandle);
            g_pipeHandle = INVALID_HANDLE_VALUE;
        }
        g_handshakeComplete = false;
    }

    static bool EnsurePipeOpenLocked(DWORD timeoutMs)
    {
        if (g_pipeHandle != nullptr && g_pipeHandle != INVALID_HANDLE_VALUE)
        {
            return true;
        }

        if (!WaitNamedPipeW(PIPE_NAME, timeoutMs))
        {
            return false;
        }

        HANDLE hPipe = CreateFileW(
            PIPE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (hPipe == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        DWORD mode = PIPE_READMODE_MESSAGE;
        (void)SetNamedPipeHandleState(hPipe, &mode, nullptr, nullptr);
        g_pipeHandle = hPipe;
        g_handshakeComplete = false;
        return true;
    }

    static bool SendPacketLocked(const BLACKBIRD_IPC_PACKET& request, BLACKBIRD_IPC_PACKET& response)
    {
        DWORD bytesWritten = 0;
        DWORD bytesRead = 0;
        BOOL ok = WriteFile(g_pipeHandle, &request, sizeof(request), &bytesWritten, nullptr);
        if (!ok || bytesWritten != sizeof(request))
        {
            ClosePipeLocked();
            return false;
        }

        ok = ReadFile(g_pipeHandle, &response, sizeof(response), &bytesRead, nullptr);
        if (!ok || bytesRead != sizeof(response))
        {
            ClosePipeLocked();
            return false;
        }

        if (response.Magic != BLACKBIRD_IPC_MAGIC || response.Version != BLACKBIRD_IPC_VERSION ||
            response.PacketType != BlackbirdIpcPacketResponse || response.Command != request.Command ||
            response.Sequence != request.Sequence)
        {
            ClosePipeLocked();
            return false;
        }

        return true;
    }

    static bool EnsureHandshakeLocked()
    {
        BLACKBIRD_IPC_PACKET request{};
        BLACKBIRD_IPC_PACKET response{};

        if (g_handshakeComplete)
        {
            return true;
        }

        request.Magic = BLACKBIRD_IPC_MAGIC;
        request.Version = BLACKBIRD_IPC_VERSION;
        request.PacketType = BlackbirdIpcPacketRequest;
        request.Command = BlackbirdIpcCommandHandshake;
        request.Sequence = (UINT32)InterlockedIncrement(&g_sequence);
        request.Status = ERROR_SUCCESS;
        request.Payload.HandshakeRequest.RequestedVersion = BLACKBIRD_IPC_VERSION;

        if (!SendPacketLocked(request, response))
        {
            return false;
        }

        if (response.Status != ERROR_SUCCESS ||
            response.Payload.HandshakeResponse.NegotiatedVersion != BLACKBIRD_IPC_VERSION)
        {
            ClosePipeLocked();
            return false;
        }

        g_handshakeComplete = true;
        return true;
    }

    static bool TransactCommandLocked(UINT32 command, const void* payload, size_t payloadSize, BLACKBIRD_IPC_PACKET* outResponse)
    {
        BLACKBIRD_IPC_PACKET request{};
        BLACKBIRD_IPC_PACKET response{};

        if (payloadSize > sizeof(request.Payload))
        {
            return false;
        }

        if (!EnsurePipeOpenLocked(PIPE_DEFAULT_TIMEOUT_MS))
        {
            return false;
        }

        if (!EnsureHandshakeLocked())
        {
            return false;
        }

        request.Magic = BLACKBIRD_IPC_MAGIC;
        request.Version = BLACKBIRD_IPC_VERSION;
        request.PacketType = BlackbirdIpcPacketRequest;
        request.Command = command;
        request.Sequence = (UINT32)InterlockedIncrement(&g_sequence);
        request.Status = ERROR_SUCCESS;
        if (payload != nullptr && payloadSize != 0)
        {
            CopyMemory(&request.Payload, payload, payloadSize);
        }

        if (!SendPacketLocked(request, response))
        {
            return false;
        }

        if (outResponse != nullptr)
        {
            *outResponse = response;
        }

        return (response.Status == ERROR_SUCCESS);
    }

    bool Initialize(DWORD timeoutMs)
    {
        bool ok;
        AcquireSRWLockExclusive(&g_pipeLock);
        ok = EnsurePipeOpenLocked(timeoutMs) && EnsureHandshakeLocked();
        ReleaseSRWLockExclusive(&g_pipeLock);
        return ok;
    }

    void Shutdown()
    {
        AcquireSRWLockExclusive(&g_pipeLock);
        ClosePipeLocked();
        ReleaseSRWLockExclusive(&g_pipeLock);
    }

    bool WriteRaw(const void* data, DWORD size)
    {
        if (!data || size == 0)
            return false;

        AcquireSRWLockExclusive(&g_pipeLock);
        if (!EnsurePipeOpenLocked(PIPE_DEFAULT_TIMEOUT_MS))
        {
            ReleaseSRWLockExclusive(&g_pipeLock);
            return false;
        }

        if (g_pipeHandle == nullptr || g_pipeHandle == INVALID_HANDLE_VALUE)
        {
            ReleaseSRWLockExclusive(&g_pipeLock);
            return false;
        }

        DWORD bytesWritten = 0;
        BOOL  ok = WriteFile(g_pipeHandle, data, size, &bytesWritten, nullptr);
        if (!ok || bytesWritten != size)
        {
            ClosePipeLocked();
            ReleaseSRWLockExclusive(&g_pipeLock);
            return false;
        }

        ReleaseSRWLockExclusive(&g_pipeLock);

        return true;
    }

    bool ReadRaw(void* buffer, DWORD size, DWORD& bytesRead)
    {
        bytesRead = 0;

        if (!buffer || size == 0)
            return false;

        AcquireSRWLockExclusive(&g_pipeLock);
        if (!EnsurePipeOpenLocked(PIPE_DEFAULT_TIMEOUT_MS))
        {
            ReleaseSRWLockExclusive(&g_pipeLock);
            return false;
        }

        if (g_pipeHandle == nullptr || g_pipeHandle == INVALID_HANDLE_VALUE)
        {
            ReleaseSRWLockExclusive(&g_pipeLock);
            return false;
        }

        BOOL ok = ReadFile(g_pipeHandle, buffer, size, &bytesRead, nullptr);
        if (!ok)
        {
            ClosePipeLocked();
            ReleaseSRWLockExclusive(&g_pipeLock);
            return false;
        }

        ReleaseSRWLockExclusive(&g_pipeLock);
        return true;
    }

    bool PublishHookEvent(const BLACKBIRD_IPC_HOOK_EVENT& eventRecord)
    {
        bool ok;
        AcquireSRWLockExclusive(&g_pipeLock);
        ok = TransactCommandLocked(BlackbirdIpcCommandPublishHookEvent, &eventRecord, sizeof(eventRecord), nullptr);
        ReleaseSRWLockExclusive(&g_pipeLock);
        return ok;
    }

    bool NotifyHookReady(UINT32 readyMask, UINT32* observedMaskOut)
    {
        bool ok;
        BLACKBIRD_IPC_NOTIFY_HOOK_READY_REQUEST request{};
        BLACKBIRD_IPC_PACKET response{};

        if (readyMask == 0)
        {
            return false;
        }

        request.ProcessId = GetCurrentProcessId();
        request.ReadyMask = readyMask;

        AcquireSRWLockExclusive(&g_pipeLock);
        ok = TransactCommandLocked(BlackbirdIpcCommandNotifyHookReady, &request, sizeof(request), &response);
        ReleaseSRWLockExclusive(&g_pipeLock);

        if (!ok)
        {
            return false;
        }

        if (observedMaskOut != nullptr)
        {
            *observedMaskOut = response.Payload.NotifyHookReadyResponse.ObservedMask;
        }
        return true;
    }

    bool SendSwException(const BkExceptionMessage& msg)
    {
        BLACKBIRD_IPC_HOOK_EVENT eventRecord{};
        eventRecord.Kind = (msg.Kind == RequestKind::BkExceptionHighPriv) ? BlackbirdIpcHookEventExceptionHighPriv
                                                                           : BlackbirdIpcHookEventExceptionLowNoise;
        eventRecord.ProcessId = msg.Pid;
        eventRecord.ThreadId = msg.Tid;
        eventRecord.Operation = msg.ExceptionCode;
        eventRecord.Caller = msg.ExceptionAddress;
        eventRecord.Context0 = msg.ExceptionFlags;
        eventRecord.Context1 = msg.ExceptionInfo[0];
        eventRecord.Context2 = msg.ExceptionInfo[1];
        eventRecord.Context3 = msg.ExceptionInfo[2];
        eventRecord.ArgCount = (msg.ExceptionInfoCount <= 4u) ? msg.ExceptionInfoCount : 4u;
        for (UINT32 i = 0; i < eventRecord.ArgCount; i += 1)
        {
            eventRecord.Args[i] = msg.ExceptionInfo[i];
        }
        (void)StringCchCopyA(eventRecord.ApiName, RTL_NUMBER_OF(eventRecord.ApiName), "VectoredException");
        if (msg.ModuleNameChars != 0)
        {
            (void)WideCharToMultiByte(CP_ACP, 0, msg.ModuleName, -1, eventRecord.ModuleName,
                                      RTL_NUMBER_OF(eventRecord.ModuleName), nullptr, nullptr);
        }
        return PublishHookEvent(eventRecord);
    }
}
