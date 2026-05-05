#include "pipe.h"
#include "../hooks/runtime_private.h"

#include <strsafe.h>
#include <cstring>

namespace BKIPC
{
    static void PipeDebugLog(_In_z_ _Printf_format_string_ PCSTR format, ...) noexcept
    {
        if (format == nullptr)
        {
            return;
        }

        char message[512]{};
        va_list args;
        va_start(args, format);
        (void)StringCchVPrintfA(message, RTL_NUMBER_OF(message), format, args);
        va_end(args);

        char line[768]{};
        (void)StringCchPrintfA(line, RTL_NUMBER_OF(line), "[BKIPC pid=%lu tid=%lu] %s\n", GetCurrentProcessId(),
                               GetCurrentThreadId(), message);
        OutputDebugStringA(line);
    }

    static HANDLE g_pipeHandle = INVALID_HANDLE_VALUE;
    static SRWLOCK g_pipeLock = SRWLOCK_INIT;
    static volatile LONG g_sequence = 1;
    static bool g_handshakeComplete = false;

    static constexpr LONG kAsyncPoolSize = 4096;

    struct alignas(MEMORY_ALLOCATION_ALIGNMENT) AsyncHookNode
    {
        SLIST_ENTRY FreeLink;
        BKIPC_HOOK_EVENT Event;
    };

    static SLIST_HEADER g_asyncFreeList;
    static SLIST_HEADER g_asyncPendingList;
    static AsyncHookNode *g_asyncNodePool = nullptr;
    static HANDLE g_asyncSignal = nullptr;
    static HANDLE g_asyncThread = nullptr;
    static volatile LONG g_asyncRunning = 0;
    static volatile LONG g_asyncDropped = 0;
    static constexpr DWORD kPipeCancelDrainTimeoutMs = 250;
    static constexpr DWORD kAsyncPublishTimeoutMs = 750;

    static bool TransactCommandLocked(UINT32 command, const void *payload, size_t payloadSize,
                                      BKIPC_PACKET *outResponse);

    static DWORD CommandTimeoutMs(UINT32 command) noexcept
    {
        switch (command)
        {
        case BlackbirdIpcCommandPublishHookEvent:
            return kAsyncPublishTimeoutMs;
        case BlackbirdIpcCommandNotifyHookReady:
        case BlackbirdIpcCommandRegisterInstrumentationRange:
        case BlackbirdIpcCommandRegisterHookPatch:
            return PIPE_DEFAULT_TIMEOUT_MS;
        default:
            return PIPE_DEFAULT_TIMEOUT_MS;
        }
    }

    static DWORD WINAPI AsyncDispatchThread(LPVOID) noexcept
    {
        while (InterlockedCompareExchange(&g_asyncRunning, 0, 0))
        {
            WaitForSingleObject(g_asyncSignal, 50);

            // Atomically claim all pending nodes (LIFO — reverse for FIFO dispatch).
            PSLIST_ENTRY head = InterlockedFlushSList(&g_asyncPendingList);
            if (!head)
                continue;

            // Reverse to restore arrival order.
            PSLIST_ENTRY prev = nullptr;
            PSLIST_ENTRY cur = head;
            while (cur)
            {
                PSLIST_ENTRY next = cur->Next;
                cur->Next = prev;
                prev = cur;
                cur = next;
            }
            head = prev;

            // Dispatch each event synchronously (we're off the hook thread now).
            while (head)
            {
                PSLIST_ENTRY next = head->Next;
                AsyncHookNode *node = CONTAINING_RECORD(head, AsyncHookNode, FreeLink);

                /* Guard: IPC sends must not re-enter SR71 hooks */
                BkSr71InternalScope _ipc_scope;
                AcquireSRWLockExclusive(&g_pipeLock);
                (void)TransactCommandLocked(BlackbirdIpcCommandPublishHookEvent, &node->Event, sizeof(node->Event),
                                            nullptr);
                ReleaseSRWLockExclusive(&g_pipeLock);

                InterlockedPushEntrySList(&g_asyncFreeList, &node->FreeLink);
                head = next;
            }
        }
        return 0;
    }

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
            PipeDebugLog("EnsurePipeOpenLocked: WaitNamedPipe failed timeoutMs=%lu gle=%lu", timeoutMs, GetLastError());
            return false;
        }

        HANDLE hPipe = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr);

        if (hPipe == INVALID_HANDLE_VALUE)
        {
            PipeDebugLog("EnsurePipeOpenLocked: CreateFile failed gle=%lu", GetLastError());
            return false;
        }

        DWORD mode = PIPE_READMODE_MESSAGE;
        (void)SetNamedPipeHandleState(hPipe, &mode, nullptr, nullptr);
        g_pipeHandle = hPipe;
        g_handshakeComplete = false;
        PipeDebugLog("EnsurePipeOpenLocked: connected");
        return true;
    }

    static bool PipeTransferExactLocked(void *buffer, DWORD size, bool write, DWORD timeoutMs, DWORD *bytesOut)
    {
        OVERLAPPED overlapped{};
        DWORD bytes = 0;
        DWORD err = ERROR_SUCCESS;
        BOOL ok;

        if (buffer == nullptr || size == 0 || g_pipeHandle == nullptr || g_pipeHandle == INVALID_HANDLE_VALUE)
            return false;

        overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (overlapped.hEvent == nullptr)
            return false;

        if (write)
            ok = WriteFile(g_pipeHandle, buffer, size, &bytes, &overlapped);
        else
            ok = ReadFile(g_pipeHandle, buffer, size, &bytes, &overlapped);

        if (!ok)
        {
            err = GetLastError();
            if (err == ERROR_IO_PENDING)
            {
                DWORD wait = WaitForSingleObject(overlapped.hEvent, timeoutMs);
                if (wait == WAIT_OBJECT_0)
                {
                    ok = GetOverlappedResult(g_pipeHandle, &overlapped, &bytes, FALSE);
                    err = ok ? ERROR_SUCCESS : GetLastError();
                }
                else
                {
                    (void)CancelIoEx(g_pipeHandle, &overlapped);
                    wait = WaitForSingleObject(overlapped.hEvent, kPipeCancelDrainTimeoutMs);
                    if (wait == WAIT_OBJECT_0)
                    {
                        (void)GetOverlappedResult(g_pipeHandle, &overlapped, &bytes, FALSE);
                    }
                    err = ERROR_TIMEOUT;
                    ok = FALSE;
                }
            }
        }

        if (ok && bytes != size)
        {
            err = write ? ERROR_WRITE_FAULT : ERROR_READ_FAULT;
            ok = FALSE;
        }

        CloseHandle(overlapped.hEvent);
        if (!ok)
        {
            SetLastError(err == ERROR_SUCCESS ? ERROR_OPERATION_ABORTED : err);
            return false;
        }

        if (bytesOut != nullptr)
            *bytesOut = bytes;
        return true;
    }

    static bool SendPacketLocked(const BKIPC_PACKET &request, BKIPC_PACKET &response, DWORD timeoutMs)
    {
        DWORD bytesWritten = 0;
        DWORD bytesRead = 0;
        if (!PipeTransferExactLocked((void *)&request, (DWORD)sizeof(request), true, timeoutMs, &bytesWritten))
        {
            PipeDebugLog("SendPacketLocked: write failed cmd=%lu gle=%lu", request.Command, GetLastError());
            ClosePipeLocked();
            return false;
        }

        if (!PipeTransferExactLocked(&response, (DWORD)sizeof(response), false, timeoutMs, &bytesRead))
        {
            PipeDebugLog("SendPacketLocked: read failed cmd=%lu gle=%lu bytesRead=%lu", request.Command, GetLastError(),
                         bytesRead);
            ClosePipeLocked();
            return false;
        }

        if (response.Magic != BKIPC_MAGIC || response.Version != BKIPC_VERSION ||
            response.PacketType != BlackbirdIpcPacketResponse || response.Command != request.Command ||
            response.Sequence != request.Sequence)
        {
            PipeDebugLog("SendPacketLocked: protocol mismatch cmd=%lu respCmd=%lu respType=%lu seq=%lu respSeq=%lu",
                         request.Command, response.Command, response.PacketType, request.Sequence, response.Sequence);
            ClosePipeLocked();
            return false;
        }

        return true;
    }

    static bool EnsureHandshakeLocked(DWORD timeoutMs)
    {
        BKIPC_PACKET request{};
        BKIPC_PACKET response{};

        if (g_handshakeComplete)
        {
            return true;
        }

        request.Magic = BKIPC_MAGIC;
        request.Version = BKIPC_VERSION;
        request.PacketType = BlackbirdIpcPacketRequest;
        request.Command = BlackbirdIpcCommandHandshake;
        request.Sequence = (UINT32)InterlockedIncrement(&g_sequence);
        request.Status = ERROR_SUCCESS;
        request.Payload.HandshakeRequest.RequestedVersion = BKIPC_VERSION;

        if (!SendPacketLocked(request, response, timeoutMs))
        {
            PipeDebugLog("EnsureHandshakeLocked: send failed");
            return false;
        }

        if (response.Status != ERROR_SUCCESS || response.Payload.HandshakeResponse.NegotiatedVersion != BKIPC_VERSION)
        {
            PipeDebugLog("EnsureHandshakeLocked: negotiation failed status=%lu version=%lu", response.Status,
                         response.Payload.HandshakeResponse.NegotiatedVersion);
            ClosePipeLocked();
            return false;
        }

        g_handshakeComplete = true;
        PipeDebugLog("EnsureHandshakeLocked: success caps=0x%08lX", response.Payload.HandshakeResponse.Capabilities);
        return true;
    }

    static bool TransactCommandLocked(UINT32 command, const void *payload, size_t payloadSize,
                                      BKIPC_PACKET *outResponse)
    {
        BkSr71InternalScope _ipc_scope;
        BKIPC_PACKET request{};
        BKIPC_PACKET response{};
        DWORD timeoutMs = CommandTimeoutMs(command);

        if (payloadSize > sizeof(request.Payload))
        {
            return false;
        }

        if (!EnsurePipeOpenLocked(timeoutMs))
        {
            return false;
        }

        if (!EnsureHandshakeLocked(timeoutMs))
        {
            return false;
        }

        request.Magic = BKIPC_MAGIC;
        request.Version = BKIPC_VERSION;
        request.PacketType = BlackbirdIpcPacketRequest;
        request.Command = command;
        request.Sequence = (UINT32)InterlockedIncrement(&g_sequence);
        request.Status = ERROR_SUCCESS;
        if (payload != nullptr && payloadSize != 0)
        {
            CopyMemory(&request.Payload, payload, payloadSize);
        }

        if (!SendPacketLocked(request, response, timeoutMs))
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
        // Start async dispatch infrastructure on first call.
        if (InterlockedCompareExchange(&g_asyncRunning, 0, 0) == 0)
        {
            InitializeSListHead(&g_asyncFreeList);
            InitializeSListHead(&g_asyncPendingList);
            g_asyncDropped = 0;

            g_asyncNodePool = static_cast<AsyncHookNode *>(VirtualAlloc(nullptr, sizeof(AsyncHookNode) * kAsyncPoolSize,
                                                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
            if (g_asyncNodePool)
            {
                for (LONG i = 0; i < kAsyncPoolSize; ++i)
                    InterlockedPushEntrySList(&g_asyncFreeList, &g_asyncNodePool[i].FreeLink);
            }

            g_asyncSignal = CreateEventW(nullptr, FALSE, FALSE, nullptr);
            if (g_asyncSignal && g_asyncNodePool)
            {
                InterlockedExchange(&g_asyncRunning, 1);
                g_asyncThread = CreateThread(nullptr, 0, AsyncDispatchThread, nullptr, 0, nullptr);
                if (g_asyncThread)
                {
                    DWORD tid = GetThreadId(g_asyncThread);
                    if (tid != 0)
                    {
                        KeRegisterConcealedThread(tid);
                    }
                }
                else
                {
                    InterlockedExchange(&g_asyncRunning, 0);
                }
            }
        }

        if (InterlockedCompareExchange(&g_asyncRunning, 0, 0) == 0)
        {
            PipeDebugLog("Initialize: async publisher unavailable");
            if (g_asyncSignal)
            {
                CloseHandle(g_asyncSignal);
                g_asyncSignal = nullptr;
            }
            if (g_asyncNodePool)
            {
                VirtualFree(g_asyncNodePool, 0, MEM_RELEASE);
                g_asyncNodePool = nullptr;
            }
            return false;
        }

        bool ok;
        BkSr71InternalScope _ipc_scope;
        AcquireSRWLockExclusive(&g_pipeLock);
        ok = EnsurePipeOpenLocked(timeoutMs) && EnsureHandshakeLocked(timeoutMs);
        ReleaseSRWLockExclusive(&g_pipeLock);
        if (!ok)
        {
            PipeDebugLog("Initialize: failed timeoutMs=%lu", timeoutMs);
        }
        return ok;
    }

    void Shutdown()
    {
        BkSr71InternalScope _ipc_scope;
        bool asyncStopped = true;

        // Stop the async dispatcher before closing the pipe.
        if (InterlockedExchange(&g_asyncRunning, 0) != 0)
        {
            if (g_asyncSignal)
                SetEvent(g_asyncSignal);
            if (g_asyncThread)
            {
                DWORD wait = WaitForSingleObject(g_asyncThread, 2500);
                if (wait == WAIT_OBJECT_0)
                {
                    CloseHandle(g_asyncThread);
                    g_asyncThread = nullptr;
                }
                else
                {
                    asyncStopped = false;
                    PipeDebugLog("Shutdown: async publisher did not stop wait=%lu; deferring resource release", wait);
                }
            }
            if (asyncStopped && g_asyncSignal)
            {
                CloseHandle(g_asyncSignal);
                g_asyncSignal = nullptr;
            }
            if (asyncStopped && g_asyncNodePool)
            {
                VirtualFree(g_asyncNodePool, 0, MEM_RELEASE);
                g_asyncNodePool = nullptr;
            }
        }

        if (TryAcquireSRWLockExclusive(&g_pipeLock))
        {
            ClosePipeLocked();
            ReleaseSRWLockExclusive(&g_pipeLock);
        }
        else
        {
            PipeDebugLog("Shutdown: pipe lock busy; leaving pipe handle for process teardown");
        }
    }

    bool WriteRaw(const void *data, DWORD size)
    {
        if (!data || size == 0)
            return false;

        BkSr71InternalScope _ipc_scope;
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
        bool ok = PipeTransferExactLocked((void *)data, size, true, PIPE_DEFAULT_TIMEOUT_MS, &bytesWritten);
        if (!ok || bytesWritten != size)
        {
            ClosePipeLocked();
            ReleaseSRWLockExclusive(&g_pipeLock);
            return false;
        }

        ReleaseSRWLockExclusive(&g_pipeLock);

        return true;
    }

    bool ReadRaw(void *buffer, DWORD size, DWORD &bytesRead)
    {
        bytesRead = 0;

        if (!buffer || size == 0)
            return false;

        BkSr71InternalScope _ipc_scope;
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

        bool ok = PipeTransferExactLocked(buffer, size, false, PIPE_DEFAULT_TIMEOUT_MS, &bytesRead);
        if (!ok)
        {
            ClosePipeLocked();
            ReleaseSRWLockExclusive(&g_pipeLock);
            return false;
        }

        ReleaseSRWLockExclusive(&g_pipeLock);
        return true;
    }

    bool PublishHookEvent(const BKIPC_HOOK_EVENT &eventRecord)
    {
        // Hook callbacks must never block on pipe I/O. If the modern async
        // publisher is unavailable or saturated, shed the event and report it.
        if (InterlockedCompareExchange(&g_asyncRunning, 0, 0) && g_asyncSignal)
        {
            PSLIST_ENTRY entry = InterlockedPopEntrySList(&g_asyncFreeList);
            if (entry)
            {
                AsyncHookNode *node = CONTAINING_RECORD(entry, AsyncHookNode, FreeLink);
                node->Event = eventRecord;
                InterlockedPushEntrySList(&g_asyncPendingList, &node->FreeLink);
                SetEvent(g_asyncSignal);
                return true;
            }

            InterlockedIncrement(&g_asyncDropped);
            return false;
        }

        InterlockedIncrement(&g_asyncDropped);
        return false;
    }

    UINT32 DrainPendingHookEventsSynchronously(UINT32 maxEvents) noexcept
    {
        UINT32 dispatched = 0;
        if (maxEvents == 0)
            return 0;

        PSLIST_ENTRY head = InterlockedFlushSList(&g_asyncPendingList);
        if (!head)
            return 0;

        PSLIST_ENTRY prev = nullptr;
        PSLIST_ENTRY cur = head;
        while (cur)
        {
            PSLIST_ENTRY next = cur->Next;
            cur->Next = prev;
            prev = cur;
            cur = next;
        }
        head = prev;

        while (head)
        {
            PSLIST_ENTRY next = head->Next;
            AsyncHookNode *node = CONTAINING_RECORD(head, AsyncHookNode, FreeLink);

            if (dispatched < maxEvents)
            {
                BkSr71InternalScope _ipc_scope;
                AcquireSRWLockExclusive(&g_pipeLock);
                (void)TransactCommandLocked(BlackbirdIpcCommandPublishHookEvent, &node->Event, sizeof(node->Event),
                                            nullptr);
                ReleaseSRWLockExclusive(&g_pipeLock);
                dispatched += 1;
            }
            else
            {
                InterlockedIncrement(&g_asyncDropped);
            }

            InterlockedPushEntrySList(&g_asyncFreeList, &node->FreeLink);
            head = next;
        }

        return dispatched;
    }

    bool RegisterInstrumentationRange(UINT64 baseAddress, UINT64 regionSize, UINT32 flags, const char *tag) noexcept
    {
        if (baseAddress == 0 || regionSize == 0)
            return false;

        BKIPC_REGISTER_INSTRUMENTATION_RANGE_REQUEST request{};
        request.BaseAddress = baseAddress;
        request.RegionSize = regionSize;
        request.Flags = flags;
        request.Reserved = 0;

        if (tag != nullptr && tag[0] != '\0')
        {
            std::size_t i = 0;
            while (i < BK_MAX_INSTRUMENTATION_TAG - 1u && tag[i] != '\0')
            {
                request.Tag[i] = tag[i];
                ++i;
            }
            request.Tag[i] = '\0';
        }

        bool ok;
        AcquireSRWLockExclusive(&g_pipeLock);
        ok = TransactCommandLocked(BlackbirdIpcCommandRegisterInstrumentationRange, &request, sizeof(request), nullptr);
        ReleaseSRWLockExclusive(&g_pipeLock);

        if (!ok)
        {
            PipeDebugLog("RegisterInstrumentationRange: failed base=0x%llX size=0x%llX flags=0x%08X tag=%s",
                         (unsigned long long)baseAddress, (unsigned long long)regionSize, (unsigned int)flags,
                         tag ? tag : "(null)");
        }
        return ok;
    }

    bool RegisterHookPatch(UINT64 patchAddress, UINT32 patchSize, const UINT8 *originalBytes, UINT32 originalSize,
                           UINT32 flags, const char *tag) noexcept
    {
        if (patchAddress == 0 || patchSize == 0 || originalBytes == nullptr || originalSize == 0 ||
            patchSize > BK_MAX_HOOK_PATCH_BYTES || originalSize > BK_MAX_HOOK_PATCH_BYTES)
        {
            return false;
        }

        BKIPC_REGISTER_HOOK_PATCH_REQUEST request{};
        request.PatchAddress = patchAddress;
        request.PatchSize = patchSize;
        request.OriginalSize = originalSize;
        request.Flags = flags;
        std::memcpy(request.OriginalBytes, originalBytes, originalSize);

        if (tag != nullptr && tag[0] != '\0')
        {
            std::size_t i = 0;
            while (i < BK_HOOK_PATCH_TAG_CHARS - 1u && tag[i] != '\0')
            {
                request.Tag[i] = tag[i];
                ++i;
            }
            request.Tag[i] = '\0';
        }

        bool ok;
        AcquireSRWLockExclusive(&g_pipeLock);
        ok = TransactCommandLocked(BlackbirdIpcCommandRegisterHookPatch, &request, sizeof(request), nullptr);
        ReleaseSRWLockExclusive(&g_pipeLock);

        if (!ok)
        {
            PipeDebugLog("RegisterHookPatch: failed address=0x%llX size=%lu tag=%s", (unsigned long long)patchAddress,
                         (unsigned long)patchSize, tag ? tag : "(null)");
        }
        return ok;
    }

    bool IsProtectedIpcHandleValue(UINT64 handleValue) noexcept
    {
        HANDLE snapshot = nullptr;
        AcquireSRWLockShared(&g_pipeLock);
        snapshot = g_pipeHandle;
        ReleaseSRWLockShared(&g_pipeLock);

        if (snapshot == nullptr || snapshot == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        return reinterpret_cast<UINT64>(snapshot) == handleValue;
    }

    bool NotifyHookReady(UINT32 readyMask, UINT32 *observedMaskOut, UINT32 *pendingCommandOut)
    {
        bool ok;
        BKIPC_NOTIFY_HOOK_READY_REQUEST request{};
        BKIPC_PACKET response{};

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
            PipeDebugLog("NotifyHookReady: failed mask=0x%08lX", readyMask);
            return false;
        }

        if (observedMaskOut != nullptr)
        {
            *observedMaskOut = response.Payload.NotifyHookReadyResponse.ObservedMask;
        }
        if (pendingCommandOut != nullptr)
        {
            *pendingCommandOut = response.Payload.NotifyHookReadyResponse.PendingCommand;
        }
        return true;
    }
} // namespace BKIPC
