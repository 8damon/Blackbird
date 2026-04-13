#include "pipe.h"

namespace BKIPC
{
    static HANDLE g_pipeHandle = INVALID_HANDLE_VALUE;
    static SRWLOCK g_pipeLock = SRWLOCK_INIT;
    static volatile LONG g_sequence = 1;
    static bool g_handshakeComplete = false;

    // ---------------------------------------------------------------------------
    // Async hook-event dispatch: SLIST-based MPSC queue + background thread.
    // PublishHookEvent is now fire-and-forget; hook threads never block on pipe I/O.
    // ---------------------------------------------------------------------------
    static constexpr LONG kAsyncPoolSize = 4096;

    struct alignas(MEMORY_ALLOCATION_ALIGNMENT) AsyncHookNode
    {
        SLIST_ENTRY FreeLink;
        BLACKBIRD_IPC_HOOK_EVENT Event;
    };

    static SLIST_HEADER g_asyncFreeList;
    static SLIST_HEADER g_asyncPendingList;
    static AsyncHookNode *g_asyncNodePool = nullptr;
    static HANDLE g_asyncSignal = nullptr;
    static HANDLE g_asyncThread = nullptr;
    static volatile LONG g_asyncRunning = 0;
    static volatile LONG g_asyncDropped = 0;

    static bool TransactCommandLocked(UINT32 command, const void *payload, size_t payloadSize,
                                      BLACKBIRD_IPC_PACKET *outResponse);

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
            return false;
        }

        HANDLE hPipe = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);

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

    static bool SendPacketLocked(const BLACKBIRD_IPC_PACKET &request, BLACKBIRD_IPC_PACKET &response)
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

    static bool TransactCommandLocked(UINT32 command, const void *payload, size_t payloadSize,
                                      BLACKBIRD_IPC_PACKET *outResponse)
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
                if (!g_asyncThread)
                    InterlockedExchange(&g_asyncRunning, 0);
            }
        }

        bool ok;
        AcquireSRWLockExclusive(&g_pipeLock);
        ok = EnsurePipeOpenLocked(timeoutMs) && EnsureHandshakeLocked();
        ReleaseSRWLockExclusive(&g_pipeLock);
        return ok;
    }

    void Shutdown()
    {
        // Stop the async dispatcher before closing the pipe.
        if (InterlockedExchange(&g_asyncRunning, 0) != 0)
        {
            if (g_asyncSignal)
                SetEvent(g_asyncSignal);
            if (g_asyncThread)
            {
                WaitForSingleObject(g_asyncThread, 2000);
                CloseHandle(g_asyncThread);
                g_asyncThread = nullptr;
            }
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
        }

        AcquireSRWLockExclusive(&g_pipeLock);
        ClosePipeLocked();
        ReleaseSRWLockExclusive(&g_pipeLock);
    }

    bool WriteRaw(const void *data, DWORD size)
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
        BOOL ok = WriteFile(g_pipeHandle, data, size, &bytesWritten, nullptr);
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

    bool PublishHookEvent(const BLACKBIRD_IPC_HOOK_EVENT &eventRecord)
    {
        // Fast path: enqueue to the async ring and return immediately.
        // Hook threads never block on pipe I/O.
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
            // Free list empty — pool exhausted; fall through to synchronous send.
            InterlockedIncrement(&g_asyncDropped);
        }

        // Synchronous fallback (async not yet started, or pool exhausted).
        bool ok;
        AcquireSRWLockExclusive(&g_pipeLock);
        ok = TransactCommandLocked(BlackbirdIpcCommandPublishHookEvent, &eventRecord, sizeof(eventRecord), nullptr);
        ReleaseSRWLockExclusive(&g_pipeLock);
        return ok;
    }

    bool NotifyHookReady(UINT32 readyMask, UINT32 *observedMaskOut)
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
} // namespace BKIPC
