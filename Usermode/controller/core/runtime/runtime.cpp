#include "../controller_private.h"

struct ClientConstruct
{
    BK_CONTROLLER_CLIENT *ptr = nullptr;

    ClientConstruct() noexcept = default;
    ~ClientConstruct() noexcept
    {
        Free();
    }

    ClientConstruct(const ClientConstruct &) = delete;
    ClientConstruct &operator=(const ClientConstruct &) = delete;

    void Free() noexcept
    {
        if (!ptr)
        {
            return;
        }
        if (ptr->IoctlQueueDataEvent)
        {
            CloseHandle(ptr->IoctlQueueDataEvent);
        }
        if (ptr->EtwQueueDataEvent)
        {
            CloseHandle(ptr->EtwQueueDataEvent);
        }
        if (ptr->DispatchIdleEvent)
        {
            CloseHandle(ptr->DispatchIdleEvent);
        }
        DeleteCriticalSection(&ptr->Lock);
        if (ptr->IoctlNodeSlab)
        {
            free(ptr->IoctlNodeSlab);
        }
        if (ptr->EtwNodeSlab)
        {
            free(ptr->EtwNodeSlab);
        }
        if (ptr->Pipe != NULL && ptr->Pipe != INVALID_HANDLE_VALUE)
        {
            CloseHandle(ptr->Pipe);
            ptr->Pipe = INVALID_HANDLE_VALUE;
        }
        free(ptr);
        ptr = nullptr;
    }

    BK_CONTROLLER_CLIENT *release() noexcept
    {
        auto *p = ptr;
        ptr = nullptr;
        return p;
    }
};

struct ClientWorkItem
{
    BK_CONTROLLER_CLIENT *Client;
    PTP_WORK Work;
};

static VOID CALLBACK ControllerClientWorkCallback(_Inout_ PTP_CALLBACK_INSTANCE Instance, _Inout_opt_ PVOID Context,
                                                  _Inout_ PTP_WORK Work)
{
    ClientWorkItem *item = static_cast<ClientWorkItem *>(Context);

    UNREFERENCED_PARAMETER(Work);
    CallbackMayRunLong(Instance);
    if (item != nullptr)
    {
        (void)ControllerClientThreadProc(item->Client);
        if (item->Work != nullptr)
        {
            CloseThreadpoolWork(item->Work);
        }
        free(item);
    }
}

static HANDLE g_ServerAcceptThreads[BK_CONTROLLER_SERVER_ACCEPT_THREADS] = {0};
static HANDLE g_HookAcceptThreads[BK_CONTROLLER_HOOK_ACCEPT_THREADS] = {0};

typedef struct _BK_SERVER_ENDPOINT_CONTEXT
{
    PCWSTR PipeName;
    DWORD ClientRole;
} BK_SERVER_ENDPOINT_CONTEXT, *PBK_SERVER_ENDPOINT_CONTEXT;

static const BK_SERVER_ENDPOINT_CONTEXT g_ControlEndpointContext = {BKIPC_PIPE_NAME, BkctlrClientRoleControl};
static const BK_SERVER_ENDPOINT_CONTEXT g_HookEndpointContext = {BKIPC_HOOK_PIPE_NAME, BkctlrClientRoleHook};

static volatile LONG g_ControllerProtectionReady = 0;
static volatile LONG g_ControllerProtectionArmed = 0;

VOID ControllerTryMarkProtectedReady(_In_ HANDLE DriverHandle, _In_ BOOL LogFailure)
{
    if (DriverHandle == NULL || DriverHandle == INVALID_HANDLE_VALUE)
    {
        return;
    }
    if (InterlockedCompareExchange(&g_ControllerProtectionReady, 0, 0) == 0 ||
        InterlockedCompareExchange(&g_ControllerProtectionArmed, 0, 0) != 0)
    {
        return;
    }

    if (BkscMarkControllerReady(DriverHandle, GetCurrentProcessId()))
    {
        if (InterlockedExchange(&g_ControllerProtectionArmed, 1) == 0)
        {
            ControllerLog("[DRIVER] controller protection readiness acknowledged\n");
        }
    }
    else if (LogFailure)
    {
        ControllerLog("[DRIVER][WARN] controller protection readiness failed (%lu)\n", GetLastError());
    }
}

static BOOL ControllerDriverPumpReadErrorIsRecoverable(_In_ DWORD ErrorCode)
{
    switch (ErrorCode)
    {
    case ERROR_OPERATION_ABORTED:
    case ERROR_NOT_READY:
    case ERROR_DEVICE_NOT_CONNECTED:
    case ERROR_BROKEN_PIPE:
    case ERROR_INVALID_HANDLE:
    case ERROR_GEN_FAILURE:
    case ERROR_SEM_TIMEOUT:
        return TRUE;
    default:
        return FALSE;
    }
}

static DWORD ControllerDriverPumpBackoffMs(_In_ DWORD Failures)
{
    DWORD cappedFailures = (Failures < 20u) ? Failures : 20u;
    DWORD scaled = 50 + cappedFailures * 25;
    return (scaled < 750u) ? scaled : 750u;
}

static BOOL ControllerDropDriverHandleIfCurrent(_In_ HANDLE LocalHandle, _In_z_ PCSTR Reason, _In_ DWORD ErrorCode)
{
    BOOL dropped = FALSE;

    EnterCriticalSection(g_DriverLock.get());
    if (g_DriverHandle == LocalHandle)
    {
        CloseHandle(g_DriverHandle);
        g_DriverHandle = INVALID_HANDLE_VALUE;
        InterlockedExchange(&g_ControllerProtectionArmed, 0);
        dropped = TRUE;
    }
    LeaveCriticalSection(g_DriverLock.get());

    if (dropped)
    {
        ControllerMarkDriverSubscriptionsDirty();
        ControllerLog("[DRIVER][WARN] dropped driver handle reason=%s err=%lu; controller remains online\n", Reason,
                      ErrorCode);
    }

    return dropped;
}

static DWORD WINAPI ControllerServerThreadProc(_In_ LPVOID Context)
{
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD pipeCreateFailures = 0;
    const BK_SERVER_ENDPOINT_CONTEXT *endpoint = (const BK_SERVER_ENDPOINT_CONTEXT *)Context;
    PCWSTR pipeName = BKIPC_PIPE_NAME;
    DWORD clientRole = BkctlrClientRoleControl;

    if (endpoint != NULL)
    {
        if (endpoint->PipeName != NULL && endpoint->PipeName[0] != L'\0')
        {
            pipeName = endpoint->PipeName;
        }
        if (endpoint->ClientRole != BkctlrClientRoleUnknown)
        {
            clientRole = endpoint->ClientRole;
        }
    }

    UniqueLocalPtr<SECURITY_DESCRIPTOR> sdOwner;
    if (!ControllerCreatePipeSecurity(clientRole, &sa, &sd))
    {
        ControllerLog("[-] BlackbirdController: failed to create pipe security role=%lu (%lu)\n", clientRole,
                      GetLastError());
        return 1;
    }
    sdOwner.reset(static_cast<SECURITY_DESCRIPTOR *>(sd));

    while (!ControllerShouldStop())
    {
        HANDLE pipe;
        BOOL connected;
        DWORD mode = PIPE_READMODE_MESSAGE;
        ClientWorkItem *workItem;
        DWORD slotIndex;
        ClientConstruct guard;

        pipe = CreateNamedPipeW(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                PIPE_UNLIMITED_INSTANCES, sizeof(BKIPC_PACKET), sizeof(BKIPC_PACKET), 3000, &sa);
        if (pipe == INVALID_HANDLE_VALUE)
        {
            pipeCreateFailures += 1;
            if (pipeCreateFailures == 1 || (pipeCreateFailures % 50) == 0)
            {
                ControllerLog("[WARN] BlackbirdController: CreateNamedPipe failed (%lu), retries=%lu\n", GetLastError(),
                              pipeCreateFailures);
            }
            Sleep(250);
            continue;
        }
        pipeCreateFailures = 0;

        connected = ConnectNamedPipe(pipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected)
        {
            ControllerLog("[WARN] BlackbirdController: ConnectNamedPipe failed (%lu)\n", GetLastError());
            CloseHandle(pipe);
            continue;
        }

        (void)SetNamedPipeHandleState(pipe, &mode, NULL, NULL);

        guard.ptr = (BK_CONTROLLER_CLIENT *)calloc(1, sizeof(*guard.ptr));
        if (guard.ptr == NULL)
        {
            CloseHandle(pipe);
            continue;
        }

        guard.ptr->Pipe = pipe;
        guard.ptr->Role = clientRole;
        guard.ptr->QueueHead = NULL;
        guard.ptr->QueueTail = NULL;
        guard.ptr->QueueDepth = 0;
        guard.ptr->DroppedEvents = 0;
        guard.ptr->SubscriptionCount = 0;
        guard.ptr->SlotIndex = BK_CONTROLLER_INVALID_SLOT;
        guard.ptr->DispatchRefCount = 0;
        guard.ptr->Detached = 0;
        InitializeCriticalSection(&guard.ptr->Lock);
        guard.ptr->IoctlQueueDataEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        guard.ptr->EtwQueueDataEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        guard.ptr->DispatchIdleEvent = CreateEventW(NULL, TRUE, TRUE, NULL);
        if (guard.ptr->IoctlQueueDataEvent == NULL || guard.ptr->EtwQueueDataEvent == NULL ||
            guard.ptr->DispatchIdleEvent == NULL)
        {
            continue;
        }

        guard.ptr->IoctlNodeSlab =
            (PBK_CONTROLLER_EVENT_NODE)calloc(BK_CONTROLLER_MAX_CLIENT_QUEUE_DEPTH, sizeof(BK_CONTROLLER_EVENT_NODE));
        if (guard.ptr->IoctlNodeSlab != NULL)
        {
            for (DWORD i = 0; i < BK_CONTROLLER_MAX_CLIENT_QUEUE_DEPTH - 1; i++)
            {
                guard.ptr->IoctlNodeSlab[i].Next = &guard.ptr->IoctlNodeSlab[i + 1];
            }
            guard.ptr->IoctlNodeSlab[BK_CONTROLLER_MAX_CLIENT_QUEUE_DEPTH - 1].Next = NULL;
            guard.ptr->IoctlNodeFreeHead = &guard.ptr->IoctlNodeSlab[0];
        }

        guard.ptr->EtwNodeSlab = (PBK_CONTROLLER_ETW_EVENT_NODE)calloc(BK_CONTROLLER_MAX_CLIENT_ETW_QUEUE_DEPTH,
                                                                       sizeof(BK_CONTROLLER_ETW_EVENT_NODE));
        if (guard.ptr->EtwNodeSlab != NULL)
        {
            for (DWORD i = 0; i < BK_CONTROLLER_MAX_CLIENT_ETW_QUEUE_DEPTH - 1; i++)
            {
                guard.ptr->EtwNodeSlab[i].Next = &guard.ptr->EtwNodeSlab[i + 1];
            }
            guard.ptr->EtwNodeSlab[BK_CONTROLLER_MAX_CLIENT_ETW_QUEUE_DEPTH - 1].Next = NULL;
            guard.ptr->EtwNodeFreeHead = &guard.ptr->EtwNodeSlab[0];
        }

        if (!GetNamedPipeClientProcessId(pipe, &guard.ptr->ProcessId))
        {
            guard.ptr->ProcessId = 0;
        }
        if (!ProcessIdToSessionId(guard.ptr->ProcessId, &guard.ptr->SessionId))
        {
            guard.ptr->SessionId = 0;
        }

        ControllerLog("[IPC] client connected role=%lu pid=%lu session=%lu pipe=%ls\n", guard.ptr->Role,
                      guard.ptr->ProcessId, guard.ptr->SessionId, pipeName);

        EnterCriticalSection(g_ClientListLock.get());
        if (g_ClientCount >= BK_CONTROLLER_MAX_CLIENTS)
        {
            LeaveCriticalSection(g_ClientListLock.get());
            continue;
        }
        slotIndex = ControllerAllocateClientSlotLocked();
        if (slotIndex == BK_CONTROLLER_INVALID_SLOT)
        {
            LeaveCriticalSection(g_ClientListLock.get());
            continue;
        }
        guard.ptr->SlotIndex = slotIndex;
        g_ClientSlots[slotIndex] = guard.ptr;
        guard.ptr->Next = g_ClientList;
        g_ClientList = guard.ptr;
        g_ClientCount += 1;
        ControllerLog("[IPC] active clients=%lu\n", g_ClientCount);
        LeaveCriticalSection(g_ClientListLock.get());

        workItem = (ClientWorkItem *)calloc(1, sizeof(*workItem));
        if (workItem == NULL)
        {
            ControllerLog("[WARN] BlackbirdController: failed to allocate client work item for pid=%lu\n",
                          guard.ptr->ProcessId);
            ControllerDetachClient(guard.ptr);
            continue;
        }

        workItem->Client = guard.ptr;
        workItem->Work = CreateThreadpoolWork(ControllerClientWorkCallback, workItem, NULL);
        if (workItem->Work == NULL)
        {
            ControllerLog("[WARN] BlackbirdController: failed to queue client work for pid=%lu (%lu)\n",
                          guard.ptr->ProcessId, GetLastError());
            free(workItem);
            ControllerDetachClient(guard.ptr);
            continue;
        }
        (void)guard.release();
        SubmitThreadpoolWork(workItem->Work);
    }

    return 0;
}

static DWORD WINAPI ControllerDriverPumpThreadProc(_In_ LPVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    DWORD driverOpenFailures = 0;
    DWORD recoverableReadFailures = 0;

    while (!ControllerShouldStop())
    {
        BK_EVENT_RECORD record;
        DWORD bytes = 0;
        BOOL ok;
        HANDLE localHandle;

        EnterCriticalSection(g_DriverLock.get());
        if (g_DriverHandle == INVALID_HANDLE_VALUE)
        {
            g_DriverHandle = BkscOpenControlDevice();
            localHandle = g_DriverHandle;
            LeaveCriticalSection(g_DriverLock.get());
            if (localHandle != INVALID_HANDLE_VALUE)
            {
                BK_STATS_RESPONSE stats;
                DWORD statsBytes = 0;
                ControllerTryMarkProtectedReady(localHandle, TRUE);
                ControllerMarkDriverSubscriptionsDirty();
                (void)ControllerApplyDriverSubscriptionsIfDirty();
                driverOpenFailures = 0;
                recoverableReadFailures = 0;
                ZeroMemory(&stats, sizeof(stats));
                if (BkscGetStats(localHandle, &stats, &statsBytes))
                {
                    ControllerLog("[DRIVER] connected and verified. subscriptions=%lu queueDepth=%lu dropped=%lu\n",
                                  stats.SubscriptionCount, stats.QueueDepth, stats.DroppedEvents);
                }
                else
                {
                    ControllerLog("[DRIVER][WARN] connected, but stats query failed (%lu)\n", GetLastError());
                }
            }
            else
            {
                driverOpenFailures += 1;
                if (driverOpenFailures == 1 || (driverOpenFailures % 40) == 0)
                {
                    ControllerLog("[DRIVER][WARN] open failed (%lu), retries=%lu\n", GetLastError(),
                                  driverOpenFailures);
                }
            }
            Sleep(250);
            continue;
        }
        localHandle = g_DriverHandle;
        LeaveCriticalSection(g_DriverLock.get());

        (void)ControllerApplyDriverSubscriptionsIfDirty();

        ok = BkscGetEvent(localHandle, &record, &bytes);
        if (!ok)
        {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS)
            {
                recoverableReadFailures = 0;
                Sleep(20);
                continue;
            }

            if (ControllerShouldStop())
            {
                break;
            }

            if (ControllerDriverPumpReadErrorIsRecoverable(err))
            {
                recoverableReadFailures += 1;
                if (recoverableReadFailures == 1 || (recoverableReadFailures % 20u) == 0)
                {
                    ControllerLog(
                        "[DRIVER][WARN] event read failed (%lu), recoverableFailures=%lu; reopening driver path\n", err,
                        recoverableReadFailures);
                }
                (void)ControllerDropDriverHandleIfCurrent(localHandle, "event-read-recoverable", err);
                Sleep(ControllerDriverPumpBackoffMs(recoverableReadFailures));
                continue;
            }

            ControllerLog(
                "[DRIVER][WARN] event read failed (%lu); unrecoverable driver path failure, stopping controller runtime\n",
                err);
            (void)ControllerDropDriverHandleIfCurrent(localHandle, "event-read-unrecoverable", err);
            if (g_StopEvent != NULL)
            {
                (void)SetEvent(g_StopEvent);
            }
            break;
        }

        if (bytes >= sizeof(record))
        {
            recoverableReadFailures = 0;
            ControllerDispatchDriverRecord(&record);
        }
    }

    return 0;
}

#ifndef BK_INTENT_PROCESS_MEMORY
#define BK_INTENT_PROCESS_MEMORY 0x00000001u
#endif

#ifndef BK_INTENT_THREAD_CONTEXT
#define BK_INTENT_THREAD_CONTEXT 0x00000002u
#endif

#ifndef BK_INTENT_DUP_HANDLE
#define BK_INTENT_DUP_HANDLE 0x00000004u
#endif

static BOOL ControllerIsInterestingHandleAccessMask(_In_ ULONG DesiredAccess)
{
    return ((DesiredAccess & PROCESS_VM_OPERATION) != 0) || ((DesiredAccess & PROCESS_VM_WRITE) != 0) ||
           ((DesiredAccess & PROCESS_CREATE_THREAD) != 0) ||
           ((DesiredAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS) ||
           ((DesiredAccess & THREAD_SET_CONTEXT) != 0) || ((DesiredAccess & THREAD_SUSPEND_RESUME) != 0) ||
           ((DesiredAccess & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS);
}

#ifndef BK_SOCKET_OPCODE_SEND
#define BK_SOCKET_OPCODE_SEND 10u
#define BK_SOCKET_OPCODE_RECV 11u
#define BK_SOCKET_OPCODE_CONNECT 12u
#define BK_SOCKET_OPCODE_DISCONNECT 13u
#define BK_SOCKET_OPCODE_ACCEPT 15u
#define BK_SOCKET_OPCODE_RECONNECT 16u
#define BK_SOCKET_OPCODE_SENDUDP 42u
#define BK_SOCKET_OPCODE_RECVUDP 43u
#define BK_SOCKET_OPCODE_FAILUDP 49u
#endif

static BOOL ControllerIsInterestingSocketOpcode(_In_ UCHAR Opcode)
{
    switch (Opcode)
    {
    case BK_SOCKET_OPCODE_SEND:
    case BK_SOCKET_OPCODE_RECV:
    case BK_SOCKET_OPCODE_CONNECT:
    case BK_SOCKET_OPCODE_DISCONNECT:
    case BK_SOCKET_OPCODE_ACCEPT:
    case BK_SOCKET_OPCODE_RECONNECT:
    case BK_SOCKET_OPCODE_SENDUDP:
    case BK_SOCKET_OPCODE_RECVUDP:
    case BK_SOCKET_OPCODE_FAILUDP:
        return TRUE;
    default:
        return FALSE;
    }
}

static PCSTR ControllerSocketOperationFromOpcode(_In_ UCHAR Opcode)
{
    switch (Opcode)
    {
    case BK_SOCKET_OPCODE_SEND:
        return "SEND";
    case BK_SOCKET_OPCODE_RECV:
        return "RECV";
    case BK_SOCKET_OPCODE_CONNECT:
        return "CONNECT";
    case BK_SOCKET_OPCODE_DISCONNECT:
        return "DISCONNECT";
    case BK_SOCKET_OPCODE_ACCEPT:
        return "ACCEPT";
    case BK_SOCKET_OPCODE_RECONNECT:
        return "RECONNECT";
    case BK_SOCKET_OPCODE_SENDUDP:
        return "SEND_UDP";
    case BK_SOCKET_OPCODE_RECVUDP:
        return "RECV_UDP";
    case BK_SOCKET_OPCODE_FAILUDP:
        return "FAIL_UDP";
    default:
        return "SOCKET";
    }
}

static BOOL ControllerShouldForwardEtwRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                             _In_ const BKIPC_ETW_EVENT *Event)
{
    ULONG desiredAccess = 0;
    ULONG correlationFlags = 0;
    ULONG severity = 0;
    ULONGLONG processId = 0;
    ULONGLONG creatorPid = 0;
    ULONGLONG targetPid = 0;
    CHAR className[64];
    CHAR detectionName[RTL_NUMBER_OF(Event->DetectionName)];
    BOOL selfTarget = FALSE;
    BOOL handleNoiseDetection = FALSE;
    BOOL lowSignalDetection = FALSE;
    BOOL strongDetection = FALSE;
    if (Record == NULL || Event == NULL)
    {
        return FALSE;
    }
    if (EventName == NULL || EventName[0] == L'\0')
    {
        if (Event->Source == BlackbirdIpcEtwSourceKernelNetwork)
        {
            return ControllerIsInterestingSocketOpcode((UCHAR)Event->Opcode);
        }
        return FALSE;
    }

    if (wcscmp(EventName, L"DetectionTelemetry") == 0)
    {
        ZeroMemory(detectionName, sizeof(detectionName));
        if (Event->DetectionName[0] != '\0')
        {
            (void)StringCchCopyA(detectionName, RTL_NUMBER_OF(detectionName), Event->DetectionName);
        }
        else
        {
            (void)ControllerEtwGetAnsiProperty(Record, L"detectionName", detectionName, RTL_NUMBER_OF(detectionName));
        }
        (void)_strupr_s(detectionName, sizeof(detectionName));
        severity = Event->Severity;
        targetPid = Event->TargetPid;
        processId = (Event->ProcessId != 0) ? Event->ProcessId : Event->EventProcessId;
        selfTarget = (processId != 0 && targetPid != 0 && processId == targetPid);
        correlationFlags = Event->CorrelationFlags;
        selfTarget = (processId != 0 && targetPid != 0 && processId == targetPid);

        if (correlationFlags == 0)
        {
            (void)ControllerEtwGetU32Property(Record, L"correlationFlags", &correlationFlags);
        }

        BOOL directSyscallHandleDetection =
            (strstr(detectionName, "DIRECT_SYSCALL") != NULL) || (strstr(detectionName, "DIRECT-SYSCALL") != NULL);

        handleNoiseDetection = directSyscallHandleDetection ||
                               (strstr(detectionName, "STACK_INTEGRITY_ANOMALY_ON_HANDLE_OP") != NULL) ||
                               (strstr(detectionName, "SUSPECT_HANDLE_OPERATION") != NULL) ||
                               (strstr(detectionName, "ANOMALY_ON_HANDLE_OP") != NULL);

        if (!handleNoiseDetection && ((strstr(detectionName, "USPECT_HANDLE_OPERATION") != NULL) ||
                                      (strstr(detectionName, "NOMALY_ON_HANDLE_OP") != NULL)))
        {
            handleNoiseDetection = TRUE;
        }

        lowSignalDetection = (strstr(detectionName, "REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT") != NULL) ||
                             (strstr(detectionName, "THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT") != NULL) ||
                             (strstr(detectionName, "REMOTE_THREAD_OUTSIDE_MAIN_IMAGE") != NULL);

        strongDetection =
            (strstr(detectionName, "PROCESS_HOLLOWING") != NULL) || (strstr(detectionName, "INJECTION") != NULL) ||
            (strstr(detectionName, "THREAD_HIJACK") != NULL) || (strstr(detectionName, "REMOTE_APC") != NULL) ||
            (strstr(detectionName, "NON_IMAGE_EXECUTABLE_REGION") != NULL) ||
            (strstr(detectionName, "CREDENTIAL_ACCESS_LSASS_HANDLE") != NULL) ||
            (strstr(detectionName, "REGISTRY_LSA_PACKAGE_WRITE") != NULL) ||
            (strstr(detectionName, "SHELLCODE_STAGE_PATTERN") != NULL) ||
            (strstr(detectionName, "PROCESS_IMAGE_TAMPER") != NULL) ||
            (strstr(detectionName, "PROCESS_IMAGE_GHOSTING") != NULL);

        if (handleNoiseDetection)
        {
            if (directSyscallHandleDetection)
            {
                return (severity >= 5);
            }
            if (selfTarget)
            {
                return FALSE;
            }
            if (severity < 7)
            {
                return FALSE;
            }
            if ((correlationFlags & (BK_INTENT_PROCESS_MEMORY | BK_INTENT_THREAD_CONTEXT | BK_INTENT_DUP_HANDLE)) == 0)
            {
                return FALSE;
            }

            return TRUE;
        }

        if (lowSignalDetection)
        {
            return FALSE;
        }

        if (strongDetection)
        {
            return (severity >= 5);
        }

        return (severity >= 6);
    }

    if (Event->Source == BlackbirdIpcEtwSourceThreatIntel)
    {
        return (Event->Task == 1 || Event->Task == 2 || Event->Task == 7);
    }
    if (Event->Source == BlackbirdIpcEtwSourceKernelNetwork)
    {
        return ControllerIsInterestingSocketOpcode((UCHAR)Event->Opcode);
    }

    if (wcscmp(EventName, L"HandleTelemetry") == 0)
    {
        ZeroMemory(className, sizeof(className));
        if (Event->ClassName[0] != '\0')
        {
            (void)StringCchCopyA(className, RTL_NUMBER_OF(className), Event->ClassName);
        }
        else
        {
            (void)ControllerEtwGetAnsiProperty(Record, L"class", className, RTL_NUMBER_OF(className));
        }
        desiredAccess = Event->DesiredAccess;
        if (desiredAccess == 0)
        {
            (void)ControllerEtwGetU32Property(Record, L"desiredAccess", &desiredAccess);
        }

        if (_stricmp(className, "DIRECT-SYSCALL-SUSPECT") == 0 || _stricmp(className, "UNKNOWN-ORIGIN") == 0)
        {
            return TRUE;
        }
        return ControllerIsInterestingHandleAccessMask(desiredAccess);
    }

    if (wcscmp(EventName, L"ApcTelemetry") == 0)
    {
        desiredAccess = Event->DesiredAccess;
        processId = Event->ProcessId;
        targetPid = Event->TargetPid;
        if (desiredAccess == 0)
        {
            (void)ControllerEtwGetU32Property(Record, L"desiredAccess", &desiredAccess);
        }
        if (processId == 0)
        {
            (void)ControllerEtwGetU64Property(Record, L"processId", &processId);
        }
        if (targetPid == 0)
        {
            (void)ControllerEtwGetU64Property(Record, L"targetPid", &targetPid);
        }
        if (targetPid == 0)
        {
            targetPid = Event->TargetPid;
        }
        if (processId == 0)
        {
            processId = Event->ProcessId;
        }

        if (processId != 0 && targetPid != 0 && processId == targetPid)
        {
            return FALSE;
        }

        return ((desiredAccess & (THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME)) != 0);
    }

    if (wcscmp(EventName, L"ThreadTelemetry") == 0)
    {
        correlationFlags = Event->CorrelationFlags;
        targetPid = Event->TargetPid;
        processId = Event->ProcessId;
        creatorPid = Event->CreatorProcessId;
        if (correlationFlags == 0)
        {
            (void)ControllerEtwGetU32Property(Record, L"correlationFlags", &correlationFlags);
        }
        if (targetPid == 0)
        {
            (void)ControllerEtwGetU64Property(Record, L"targetPid", &targetPid);
        }
        if (processId == 0)
        {
            (void)ControllerEtwGetU64Property(Record, L"processId", &processId);
        }
        if (creatorPid == 0)
        {
            (void)ControllerEtwGetU64Property(Record, L"creatorPid", &creatorPid);
        }
        if (creatorPid == 0)
        {
            creatorPid = Event->CreatorProcessId;
        }
        if (processId == 0)
        {
            processId = Event->ProcessId;
        }
        if (targetPid == 0)
        {
            targetPid = Event->TargetPid != 0 ? Event->TargetPid : processId;
        }

        if ((targetPid != 0 && creatorPid != 0 && targetPid == creatorPid) ||
            (processId != 0 && creatorPid != 0 && processId == creatorPid))
        {
            return ((correlationFlags & BK_INTENT_PROCESS_MEMORY) != 0);
        }

        if ((correlationFlags & (BK_INTENT_PROCESS_MEMORY | BK_INTENT_THREAD_CONTEXT | BK_INTENT_DUP_HANDLE)) != 0)
        {
            return TRUE;
        }

        if (processId != 0 && creatorPid != 0 && processId != creatorPid)
        {
            return TRUE;
        }
        return FALSE;
    }

    if (wcscmp(EventName, L"ProcessTelemetry") == 0)
    {
        if ((Event->Flags & BKIPC_ETW_FLAG_PROCESS_IS_CREATE) != 0u)
        {
            return TRUE;
        }
        return FALSE;
    }
    if (wcscmp(EventName, L"ImageTelemetry") == 0)
    {
        return ((Event->Flags & BKIPC_ETW_FLAG_IMAGE_SYSTEM_MODE) == 0u);
    }
    if (wcscmp(EventName, L"RegistryTelemetry") == 0)
    {
        return FALSE;
    }
    if (wcscmp(EventName, L"NtApiTelemetry") == 0)
    {
        return TRUE;
    }
    if (wcscmp(EventName, L"SystemInformationTelemetry") == 0)
    {
        return TRUE;
    }
    if (wcscmp(EventName, L"QpcTimingTelemetry") == 0)
    {
        return TRUE;
    }

    return FALSE;
}

static VOID WINAPI ControllerEtwCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName, _In_opt_ PVOID Context)
{
    static const PCWSTR stackPropertyNames[BKIPC_MAX_ETW_STACK_FRAMES] = {
        L"stack0",  L"stack1",  L"stack2",  L"stack3",  L"stack4",  L"stack5",  L"stack6",  L"stack7",
        L"stack8",  L"stack9",  L"stack10", L"stack11", L"stack12", L"stack13", L"stack14", L"stack15",
        L"stack16", L"stack17", L"stack18", L"stack19", L"stack20", L"stack21", L"stack22", L"stack23",
        L"stack24", L"stack25", L"stack26", L"stack27", L"stack28", L"stack29", L"stack30", L"stack31",
        L"stack32", L"stack33", L"stack34", L"stack35", L"stack36", L"stack37", L"stack38", L"stack39",
        L"stack40", L"stack41", L"stack42", L"stack43", L"stack44", L"stack45", L"stack46", L"stack47",
        L"stack48", L"stack49", L"stack50", L"stack51", L"stack52", L"stack53", L"stack54", L"stack55",
        L"stack56", L"stack57", L"stack58", L"stack59", L"stack60", L"stack61", L"stack62", L"stack63"};
    BKIPC_ETW_EVENT event;
    ULONGLONG processId = 0;
    ULONGLONG threadId = 0;
    ULONGLONG callerPid = 0;
    ULONGLONG targetPid = 0;
    ULONGLONG callerTid = 0;
    ULONGLONG parentProcessId = 0;
    ULONGLONG creatorProcessId = 0;
    ULONGLONG creatorThreadId = 0;
    ULONGLONG processStartKey = 0;
    ULONGLONG arg0 = 0;
    ULONGLONG arg1 = 0;
    ULONGLONG arg2 = 0;
    ULONGLONG arg3 = 0;
    ULONGLONG arg4 = 0;
    ULONGLONG arg5 = 0;
    ULONGLONG arg6 = 0;
    ULONGLONG arg7 = 0;
    ULONGLONG rawCounter = 0;
    ULONGLONG virtualCounter = 0;
    ULONGLONG rawDelta = 0;
    ULONGLONG virtualDelta = 0;
    ULONGLONG correctionTicks = 0;
    ULONGLONG autoBiasTicks = 0;
    ULONGLONG originAddress = 0;
    ULONGLONG deepAllocationBase = 0;
    ULONGLONG deepRegionSize = 0;
    ULONGLONG startAddress = 0;
    ULONGLONG imageBase = 0;
    ULONGLONG imageSize = 0;
    ULONG severity = 0;
    ULONG correlationFlags = 0;
    ULONG correlationAccessMask = 0;
    ULONG correlationAgeMs = 0;
    ULONG desiredAccess = 0;
    ULONG originProtect = 0;
    ULONG frameCount = 0;
    ULONG deepRegionProtect = 0;
    ULONG deepRegionState = 0;
    ULONG deepRegionType = 0;
    ULONG deepSampleSize = 0;
    ULONG startRegionProtect = 0;
    ULONG startRegionState = 0;
    ULONG startRegionType = 0;
    ULONG sessionId = 0;
    ULONG notifyClass = 0;
    ULONG dataType = 0;
    ULONG dataSize = 0;
    ULONG systemInformationClass = 0;
    ULONG systemInformationLength = 0;
    ULONG returnLength = 0;
    ULONG execFlags = 0;
    ULONG sourceFlags = 0;
    LONG statusOpenProcess = 0;
    LONG statusBasicInfo = 0;
    LONG statusSectionName = 0;
    LONG startRegionStatus = 0;
    LONG createStatus = 0;
    LONG callStatus = 0;
    LONG queryStatus = 0;
    BOOL boolValue = FALSE;
    BOOL traitsComputed = FALSE;
    UCHAR signatureLevel = 0;
    UCHAR signatureType = 0;
    CHAR apiName[96];
    DWORD i;

    UNREFERENCED_PARAMETER(Context);

    if (Record == NULL)
    {
        return;
    }

    if (IsEqualGUID(Record->EventHeader.ProviderId, BKSC_PROVIDER_GUID_TI))
    {
        return;
    }

    ZeroMemory(&event, sizeof(event));
    ZeroMemory(apiName, sizeof(apiName));
    event.EventId = Record->EventHeader.EventDescriptor.Id;
    event.Opcode = Record->EventHeader.EventDescriptor.Opcode;
    event.Task = Record->EventHeader.EventDescriptor.Task;
    event.EventProcessId = Record->EventHeader.ProcessId;
    event.EventThreadId = Record->EventHeader.ThreadId;
    if (EventName != NULL && EventName[0] != L'\0')
    {
        (void)StringCchCopyW(event.EventName, RTL_NUMBER_OF(event.EventName), EventName);
    }

    if (IsEqualGUID(Record->EventHeader.ProviderId, BKSC_PROVIDER_GUID_BLACKBIRD))
    {
        event.Source = BlackbirdIpcEtwSourceBlackbird;
    }
    else if (IsEqualGUID(Record->EventHeader.ProviderId, BKSC_PROVIDER_GUID_KERNEL_NETWORK))
    {
        event.Source = BlackbirdIpcEtwSourceKernelNetwork;
        event.Family = BlackbirdIpcEtwFamilySocket;
    }
    else
    {
        return;
    }

    (void)ControllerEtwGetU32Property(Record, L"severity", &severity);
    event.Severity = severity;
    (void)ControllerEtwGetU32Property(Record, L"correlationFlags", &correlationFlags);
    (void)ControllerEtwGetU32Property(Record, L"correlationAccessMask", &correlationAccessMask);
    (void)ControllerEtwGetU32Property(Record, L"correlationAgeMs", &correlationAgeMs);
    event.CorrelationFlags = (UINT32)correlationFlags;
    event.CorrelationAccessMask = (UINT32)correlationAccessMask;
    event.CorrelationAgeMs = (UINT32)correlationAgeMs;

    (void)ControllerEtwGetU64Property(Record, L"processId", &processId);
    if (processId == 0 && event.Source == BlackbirdIpcEtwSourceKernelNetwork)
    {
        (void)ControllerEtwGetU64Property(Record, L"PID", &processId);
        if (processId == 0)
        {
            (void)ControllerEtwGetU64Property(Record, L"ProcessId", &processId);
        }
    }
    (void)ControllerEtwGetU64Property(Record, L"threadId", &threadId);
    (void)ControllerEtwGetU64Property(Record, L"callerPid", &callerPid);
    (void)ControllerEtwGetU64Property(Record, L"callerTid", &callerTid);
    (void)ControllerEtwGetU64Property(Record, L"targetPid", &targetPid);
    (void)ControllerEtwGetU64Property(Record, L"parentProcessId", &parentProcessId);
    (void)ControllerEtwGetU64Property(Record, L"creatorProcessId", &creatorProcessId);
    if (creatorProcessId == 0)
    {
        (void)ControllerEtwGetU64Property(Record, L"creatorPid", &creatorProcessId);
    }
    (void)ControllerEtwGetU64Property(Record, L"creatorThreadId", &creatorThreadId);
    (void)ControllerEtwGetU64Property(Record, L"processStartKey", &processStartKey);

    if (processId == 0 && callerPid != 0)
    {
        processId = callerPid;
    }
    if (processId == 0)
    {
        processId = Record->EventHeader.ProcessId;
    }

    event.ProcessId = processId;
    event.ThreadId = threadId;
    event.CallerPid = callerPid;
    event.TargetPid = targetPid;
    event.ParentProcessId = parentProcessId;
    event.CreatorProcessId = creatorProcessId;
    event.CreatorThreadId = creatorThreadId;
    event.ProcessStartKey = processStartKey;

    if (event.Source == BlackbirdIpcEtwSourceKernelNetwork)
    {
        int converted = 0;
        ULONG daddrNbo = 0;
        ULONG saddrNbo = 0;
        ULONG dport = 0;
        ULONG sport = 0;
        ULONG pktSize = 0;
        CHAR ipDst[48] = {'\0'};
        CHAR ipSrc[48] = {'\0'};

        event.Family = BlackbirdIpcEtwFamilySocket;
        (void)StringCchCopyA(event.Operation, RTL_NUMBER_OF(event.Operation),
                             ControllerSocketOperationFromOpcode((UCHAR)event.Opcode));
        if (event.EventName[0] == L'\0' && event.Operation[0] != '\0')
        {
            converted = MultiByteToWideChar(CP_ACP, 0, event.Operation, -1, event.EventName,
                                            (int)RTL_NUMBER_OF(event.EventName));
            if (converted <= 0)
            {
                event.EventName[0] = L'\0';
            }
        }
        if (event.Severity == 0)
        {
            event.Severity = ControllerIsInterestingSocketOpcode((UCHAR)event.Opcode) ? 2u : 1u;
        }

        (void)ControllerEtwGetU32Property(Record, L"daddr", &daddrNbo);
        (void)ControllerEtwGetU32Property(Record, L"saddr", &saddrNbo);
        (void)ControllerEtwGetU32Property(Record, L"dport", &dport);
        (void)ControllerEtwGetU32Property(Record, L"sport", &sport);
        (void)ControllerEtwGetU32Property(Record, L"size", &pktSize);

        if (daddrNbo != 0)
        {
            UINT8 *a = (UINT8 *)&daddrNbo;
            (void)StringCchPrintfA(ipDst, sizeof(ipDst), "%u.%u.%u.%u", (unsigned)a[0], (unsigned)a[1], (unsigned)a[2],
                                   (unsigned)a[3]);
        }
        if (saddrNbo != 0)
        {
            UINT8 *a = (UINT8 *)&saddrNbo;
            (void)StringCchPrintfA(ipSrc, sizeof(ipSrc), "%u.%u.%u.%u", (unsigned)a[0], (unsigned)a[1], (unsigned)a[2],
                                   (unsigned)a[3]);
        }

        if (ipDst[0] != '\0' && ipSrc[0] != '\0')
        {
            (void)StringCchPrintfW(event.Reason, RTL_NUMBER_OF(event.Reason),
                                   L"kernel.net op=%S src=%S:%lu dst=%S:%lu bytes=%lu", event.Operation, ipSrc,
                                   (unsigned long)sport, ipDst, (unsigned long)dport, (unsigned long)pktSize);
        }
        else if (ipDst[0] != '\0')
        {
            (void)StringCchPrintfW(event.Reason, RTL_NUMBER_OF(event.Reason), L"kernel.net op=%S dst=%S:%lu bytes=%lu",
                                   event.Operation, ipDst, (unsigned long)dport, (unsigned long)pktSize);
        }
        else
        {
            (void)StringCchPrintfW(event.Reason, RTL_NUMBER_OF(event.Reason), L"kernel.net op=%S bytes=%lu",
                                   event.Operation, (unsigned long)pktSize);
        }

        if (ipDst[0] != '\0')
        {
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), "KERNEL_NETWORK_CONNECT");
        }
        else
        {
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), "KERNEL_NETWORK_IO");
        }
    }
    else if (EventName != NULL && wcscmp(EventName, L"HandleTelemetry") == 0)
    {
        event.Family = BlackbirdIpcEtwFamilyHandle;
        (void)ControllerEtwGetAnsiProperty(Record, L"class", event.ClassName, RTL_NUMBER_OF(event.ClassName));
        (void)ControllerEtwGetU32Property(Record, L"desiredAccess", &desiredAccess);
        (void)ControllerEtwGetU64Property(Record, L"originAddress", &originAddress);
        (void)ControllerEtwGetU32Property(Record, L"originProtect", &originProtect);
        (void)ControllerEtwGetWideProperty(Record, L"originPath", event.OriginPath, RTL_NUMBER_OF(event.OriginPath));
        (void)ControllerEtwGetI32Property(Record, L"statusOpenProcess", &statusOpenProcess);
        (void)ControllerEtwGetI32Property(Record, L"statusBasicInfo", &statusBasicInfo);
        (void)ControllerEtwGetI32Property(Record, L"statusSectionName", &statusSectionName);
        (void)ControllerEtwGetU64Property(Record, L"deepAllocationBase", &deepAllocationBase);
        (void)ControllerEtwGetU64Property(Record, L"deepRegionSize", &deepRegionSize);
        (void)ControllerEtwGetU32Property(Record, L"deepRegionProtect", &deepRegionProtect);
        (void)ControllerEtwGetU32Property(Record, L"deepRegionState", &deepRegionState);
        (void)ControllerEtwGetU32Property(Record, L"deepRegionType", &deepRegionType);
        (void)ControllerEtwGetU32Property(Record, L"deepSampleSize", &deepSampleSize);
        (void)ControllerEtwCopyBinaryProperty(Record, L"deepSample", event.DeepSample, RTL_NUMBER_OF(event.DeepSample),
                                              &event.DeepSampleSize);
        if (event.DeepSampleSize == 0 && deepSampleSize != 0)
        {
            event.DeepSampleSize =
                (deepSampleSize > RTL_NUMBER_OF(event.DeepSample)) ? RTL_NUMBER_OF(event.DeepSample) : deepSampleSize;
        }
        (void)ControllerEtwGetU32Property(Record, L"frameCount", &frameCount);
        event.StackCount = (frameCount > BKIPC_MAX_ETW_STACK_FRAMES) ? BKIPC_MAX_ETW_STACK_FRAMES : frameCount;
        for (i = 0; i < RTL_NUMBER_OF(stackPropertyNames); ++i)
        {
            (void)ControllerEtwGetU64Property(Record, stackPropertyNames[i], &event.Stack[i]);
        }
        if (ControllerEtwGetBoolProperty(Record, L"execProtect", &boolValue) && boolValue)
        {
            event.Flags |= BKIPC_ETW_FLAG_HANDLE_EXEC_PROTECT;
        }
        if (ControllerEtwGetBoolProperty(Record, L"fromNtdll", &boolValue) && boolValue)
        {
            event.Flags |= BKIPC_ETW_FLAG_HANDLE_FROM_NTDLL;
        }
        if (ControllerEtwGetBoolProperty(Record, L"fromExe", &boolValue) && boolValue)
        {
            event.Flags |= BKIPC_ETW_FLAG_HANDLE_FROM_EXE;
        }
        {
            ULONG handleFlags = 0;
            if (ControllerEtwGetU32Property(Record, L"handleFlags", &handleFlags))
            {
                event.Flags |=
                    handleFlags & (BKIPC_ETW_FLAG_SYSCALL_EXPORT_MATCH | BKIPC_ETW_FLAG_SYSCALL_EXPORT_MISMATCH |
                                   BKIPC_ETW_FLAG_MODULE_CHAIN_SANE | BKIPC_ETW_FLAG_UNWIND_METADATA_VALID |
                                   BKIPC_ETW_FLAG_TEB_STACK_BOUNDS_VALID | BKIPC_ETW_FLAG_FRAMES_OUTSIDE_TEB_STACK);
            }
        }

        event.DesiredAccess = desiredAccess;
        event.OriginAddress = originAddress;
        event.OriginProtect = originProtect;
        event.StatusOpenProcess = statusOpenProcess;
        event.StatusBasicInfo = statusBasicInfo;
        event.StatusSectionName = statusSectionName;
        event.DeepAllocationBase = deepAllocationBase;
        event.DeepRegionSize = deepRegionSize;
        event.DeepRegionProtect = deepRegionProtect;
        event.DeepRegionState = deepRegionState;
        event.DeepRegionType = deepRegionType;
    }
    else if (EventName != NULL && wcscmp(EventName, L"ThreadTelemetry") == 0)
    {
        event.Family = BlackbirdIpcEtwFamilyThread;
        (void)ControllerEtwGetU64Property(Record, L"startAddress", &startAddress);
        (void)ControllerEtwGetU64Property(Record, L"imageBase", &imageBase);
        (void)ControllerEtwGetU64Property(Record, L"imageSize", &imageSize);
        (void)ControllerEtwGetU32Property(Record, L"startRegionProtect", &startRegionProtect);
        (void)ControllerEtwGetU32Property(Record, L"startRegionState", &startRegionState);
        (void)ControllerEtwGetU32Property(Record, L"startRegionType", &startRegionType);
        (void)ControllerEtwGetI32Property(Record, L"startRegionStatus", &startRegionStatus);
        (void)ControllerEtwGetU32Property(Record, L"workerFrameCount", &frameCount);
        event.StackCount = (frameCount > BKIPC_MAX_ETW_STACK_FRAMES) ? BKIPC_MAX_ETW_STACK_FRAMES : frameCount;
        for (i = 0; i < RTL_NUMBER_OF(stackPropertyNames); ++i)
        {
            (void)ControllerEtwGetU64Property(Record, stackPropertyNames[i], &event.Stack[i]);
        }
        if (ControllerEtwGetBoolProperty(Record, L"gotStart", &boolValue) && boolValue)
        {
            event.Flags |= BKIPC_ETW_FLAG_THREAD_GOT_START;
        }
        if (ControllerEtwGetBoolProperty(Record, L"gotRange", &boolValue) && boolValue)
        {
            event.Flags |= BKIPC_ETW_FLAG_THREAD_GOT_RANGE;
        }
        if (ControllerEtwGetBoolProperty(Record, L"isRemoteCreator", &boolValue) && boolValue)
        {
            event.Flags |= BKIPC_ETW_FLAG_THREAD_REMOTE_CREATOR;
        }
        if (ControllerEtwGetBoolProperty(Record, L"outsideMainImage", &boolValue) && boolValue)
        {
            event.Flags |= BKIPC_ETW_FLAG_THREAD_OUTSIDE_MAIN_IMAGE;
        }

        event.StartAddress = startAddress;
        event.ImageBase = imageBase;
        event.ImageSize = imageSize;
        event.StartRegionProtect = startRegionProtect;
        event.StartRegionState = startRegionState;
        event.StartRegionType = startRegionType;
        event.StartRegionStatus = startRegionStatus;
    }
    else if (EventName != NULL && wcscmp(EventName, L"ProcessTelemetry") == 0)
    {
        event.Family = BlackbirdIpcEtwFamilyProcess;
        (void)ControllerEtwGetU32Property(Record, L"sessionId", &sessionId);
        (void)ControllerEtwGetI32Property(Record, L"createStatus", &createStatus);
        (void)ControllerEtwGetWideProperty(Record, L"imagePath", event.ImagePath, RTL_NUMBER_OF(event.ImagePath));
        (void)ControllerEtwGetWideProperty(Record, L"commandLine", event.CommandLine, RTL_NUMBER_OF(event.CommandLine));
        if (ControllerEtwGetBoolProperty(Record, L"isCreate", &boolValue) && boolValue)
        {
            event.Flags |= BKIPC_ETW_FLAG_PROCESS_IS_CREATE;
        }

        event.SessionId = sessionId;
        event.CreateStatus = createStatus;
    }
    else if (EventName != NULL && wcscmp(EventName, L"ImageTelemetry") == 0)
    {
        event.Family = BlackbirdIpcEtwFamilyImage;
        (void)ControllerEtwGetU64Property(Record, L"imageBase", &imageBase);
        (void)ControllerEtwGetU64Property(Record, L"imageSize", &imageSize);
        (void)ControllerEtwGetWideProperty(Record, L"imagePath", event.ImagePath, RTL_NUMBER_OF(event.ImagePath));
        if (ControllerEtwGetBoolProperty(Record, L"isSystemModeImage", &boolValue) && boolValue)
        {
            event.Flags |= BKIPC_ETW_FLAG_IMAGE_SYSTEM_MODE;
        }
        if (ControllerEtwGetBoolProperty(Record, L"isSignatureLevelKnown", &boolValue) && boolValue)
        {
            event.Flags |= BKIPC_ETW_FLAG_IMAGE_SIGNATURE_KNOWN;
        }
        (void)ControllerEtwGetU8Property(Record, L"signatureLevel", &signatureLevel);
        (void)ControllerEtwGetU8Property(Record, L"signatureType", &signatureType);

        event.ImageBase = imageBase;
        event.ImageSize = imageSize;
        event.SignatureLevel = signatureLevel;
        event.SignatureType = signatureType;
    }
    else if (EventName != NULL && wcscmp(EventName, L"RegistryTelemetry") == 0)
    {
        event.Family = BlackbirdIpcEtwFamilyRegistry;
        (void)ControllerEtwGetAnsiProperty(Record, L"operation", event.Operation, RTL_NUMBER_OF(event.Operation));
        (void)ControllerEtwGetU32Property(Record, L"sessionId", &sessionId);
        (void)ControllerEtwGetU32Property(Record, L"notifyClass", &notifyClass);
        (void)ControllerEtwGetU32Property(Record, L"dataType", &dataType);
        (void)ControllerEtwGetU32Property(Record, L"dataSize", &dataSize);
        (void)ControllerEtwGetWideProperty(Record, L"keyPath", event.KeyPath, RTL_NUMBER_OF(event.KeyPath));
        (void)ControllerEtwGetWideProperty(Record, L"valueName", event.ValueName, RTL_NUMBER_OF(event.ValueName));
        if (ControllerEtwGetBoolProperty(Record, L"isHighValuePath", &boolValue) && boolValue)
        {
            event.Flags |= BKIPC_ETW_FLAG_REGISTRY_HIGH_VALUE;
        }

        event.SessionId = sessionId;
        event.NotifyClass = notifyClass;
        event.DataType = dataType;
        event.DataSize = dataSize;
    }
    else if (EventName != NULL && wcscmp(EventName, L"ApcTelemetry") == 0)
    {
        event.Family = BlackbirdIpcEtwFamilyApc;
        (void)ControllerEtwGetAnsiProperty(Record, L"class", event.ClassName, RTL_NUMBER_OF(event.ClassName));
        (void)ControllerEtwGetU32Property(Record, L"desiredAccess", &desiredAccess);
        if (ControllerEtwGetBoolProperty(Record, L"isDuplicateOperation", &boolValue) && boolValue)
        {
            event.Flags |= BKIPC_ETW_FLAG_APC_DUPLICATE_OPERATION;
        }

        event.DesiredAccess = desiredAccess;
    }
    else if (EventName != NULL && wcscmp(EventName, L"DetectionTelemetry") == 0)
    {
        event.Family = BlackbirdIpcEtwFamilyDetection;
        (void)InterlockedIncrement(&g_EtwDetectionEvents);
        (void)ControllerEtwGetAnsiProperty(Record, L"detectionName", event.DetectionName,
                                           RTL_NUMBER_OF(event.DetectionName));
        if (event.DetectionName[0] == '\0')
        {
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), "UNKNOWN");
        }
        (void)ControllerEtwGetWideProperty(Record, L"reason", event.Reason, RTL_NUMBER_OF(event.Reason));
    }
    else if (EventName != NULL && wcscmp(EventName, L"QpcTimingTelemetry") == 0)
    {
        event.Family = BlackbirdIpcEtwFamilyUserHook;
        event.Severity = 2u;
        if (callerPid != 0)
        {
            event.ProcessId = callerPid;
            event.CallerPid = callerPid;
        }
        if (callerTid != 0)
        {
            event.ThreadId = callerTid;
        }
        (void)StringCchCopyA(event.Operation, RTL_NUMBER_OF(event.Operation), "NtQueryPerformanceCounter");
        (void)StringCchCopyW(event.EventName, RTL_NUMBER_OF(event.EventName), L"NtQueryPerformanceCounter");
        (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), "ANTIVM_TIMING_QPC_COMPENSATION");

        (void)ControllerEtwGetU64Property(Record, L"rawCounter", &rawCounter);
        (void)ControllerEtwGetU64Property(Record, L"virtualCounter", &virtualCounter);
        (void)ControllerEtwGetU64Property(Record, L"rawDelta", &rawDelta);
        (void)ControllerEtwGetU64Property(Record, L"virtualDelta", &virtualDelta);
        (void)ControllerEtwGetU64Property(Record, L"correctionTicks", &correctionTicks);
        (void)ControllerEtwGetU32Property(Record, L"sourceFlags", &sourceFlags);
        (void)ControllerEtwGetU64Property(Record, L"autoBiasTicks", &autoBiasTicks);
        (void)ControllerEtwGetI32Property(Record, L"queryStatus", &queryStatus);
        if (queryStatus != 0)
        {
            return;
        }

        event.HookArgCount = 7u;
        event.HookArgs[0] = rawCounter;
        event.HookArgs[1] = virtualCounter;
        event.HookArgs[2] = rawDelta;
        event.HookArgs[3] = virtualDelta;
        event.HookArgs[4] = correctionTicks;
        event.HookArgs[5] = sourceFlags;
        event.HookArgs[6] = autoBiasTicks;

        if ((sourceFlags & BK_QPC_TIMING_SOURCE_SUSPEND_PAUSE) != 0)
        {
            event.Severity = 3u;
        }
        (void)StringCchPrintfW(
            event.Reason, RTL_NUMBER_OF(event.Reason),
            L"anti-virtualization.qpc raw=0x%llX virtual=0x%llX rawDelta=0x%llX virtualDelta=0x%llX correction=%lld sourceFlags=0x%X autoBias=%lld status=0x%08X",
            (unsigned long long)rawCounter, (unsigned long long)virtualCounter, (unsigned long long)rawDelta,
            (unsigned long long)virtualDelta, (long long)correctionTicks, (unsigned int)sourceFlags,
            (long long)autoBiasTicks, (unsigned int)queryStatus);
    }
    else if (EventName != NULL && wcscmp(EventName, L"NtApiTelemetry") == 0)
    {
        event.Family = BlackbirdIpcEtwFamilyUserHook;

        (void)ControllerEtwGetAnsiProperty(Record, L"api", apiName, RTL_NUMBER_OF(apiName));
        if (apiName[0] == '\0')
        {
            (void)StringCchCopyA(apiName, RTL_NUMBER_OF(apiName), "UNKNOWN_NTAPI");
        }
        (void)StringCchCopyA(event.Operation, RTL_NUMBER_OF(event.Operation), apiName);
        (void)MultiByteToWideChar(CP_ACP, 0, apiName, -1, event.EventName, (int)RTL_NUMBER_OF(event.EventName));

        (void)ControllerEtwGetU64Property(Record, L"arg0", &arg0);
        (void)ControllerEtwGetU64Property(Record, L"arg1", &arg1);
        (void)ControllerEtwGetU64Property(Record, L"arg2", &arg2);
        (void)ControllerEtwGetU64Property(Record, L"arg3", &arg3);
        (void)ControllerEtwGetU64Property(Record, L"arg4", &arg4);
        (void)ControllerEtwGetU64Property(Record, L"arg5", &arg5);
        (void)ControllerEtwGetU64Property(Record, L"arg6", &arg6);
        (void)ControllerEtwGetU64Property(Record, L"arg7", &arg7);
        (void)ControllerEtwGetU32Property(Record, L"execFlags", &execFlags);
        (void)ControllerEtwGetI32Property(Record, L"status", &callStatus);
        if (callStatus != 0)
        {
            return;
        }
        event.HookArgCount = BKIPC_MAX_HOOK_ARGS;
        event.HookArgs[0] = arg0;
        event.HookArgs[1] = arg1;
        event.HookArgs[2] = arg2;
        event.HookArgs[3] = arg3;
        event.HookArgs[4] = arg4;
        event.HookArgs[5] = arg5;
        event.HookArgs[6] = arg6;
        event.HookArgs[7] = arg7;

        if (callerPid != 0)
        {
            event.ProcessId = callerPid;
            event.CallerPid = callerPid;
        }
        if (callerTid != 0)
        {
            event.ThreadId = callerTid;
        }
        if ((execFlags & BK_NTAPI_EXEC_FLAG_CALLER_KERNEL) != 0)
        {
            event.Flags |= BKIPC_ETW_FLAG_HOOK_KERNEL_CALLER;
        }
        if ((execFlags & BK_NTAPI_EXEC_FLAG_CALLER_USER) != 0)
        {
            event.Flags |= BKIPC_ETW_FLAG_HOOK_USER_CALLER;
        }
        if ((execFlags & BK_NTAPI_EXEC_FLAG_TARGET_CURRENT_PROCESS) != 0)
        {
            event.Flags |= BKIPC_ETW_FLAG_HOOK_TARGET_CURRENT_PROCESS;
        }
        if ((execFlags & BK_NTAPI_EXEC_FLAG_SECTION_IMAGE) != 0)
        {
            event.Flags |= BKIPC_ETW_FLAG_HOOK_SECTION_IMAGE;
        }
        if ((lstrcmpiA(apiName, "NtAllocateVirtualMemory") == 0 || lstrcmpiA(apiName, "NtWriteVirtualMemory") == 0 ||
             lstrcmpiA(apiName, "NtProtectVirtualMemory") == 0 || lstrcmpiA(apiName, "NtMapViewOfSection") == 0 ||
             lstrcmpiA(apiName, "NtMapViewOfSectionEx") == 0) &&
            arg6 != 0 && arg6 <= 0xFFFFFFFFull && (UINT32)arg6 != callerPid)
        {
            event.TargetPid = (UINT32)arg6;
        }
        else if ((lstrcmpiA(apiName, "NtUnmapViewOfSection") == 0 ||
                  lstrcmpiA(apiName, "NtUnmapViewOfSectionEx") == 0 || lstrcmpiA(apiName, "NtCreateThread") == 0 ||
                  lstrcmpiA(apiName, "NtCreateThreadEx") == 0) &&
                 arg2 != 0 && arg2 <= 0xFFFFFFFFull && (UINT32)arg2 != callerPid)
        {
            event.TargetPid = (UINT32)arg2;
        }
        else if (lstrcmpiA(apiName, "NtQueueApcThread") == 0 && arg6 != 0 && arg6 <= 0xFFFFFFFFull &&
                 (UINT32)arg6 != callerPid)
        {
            event.TargetPid = (UINT32)arg6;
        }
        else if ((lstrcmpiA(apiName, "NtQueueApcThreadEx") == 0 || lstrcmpiA(apiName, "NtQueueApcThreadEx2") == 0) &&
                 arg7 != 0 && arg7 <= 0xFFFFFFFFull && (UINT32)arg7 != callerPid)
        {
            event.TargetPid = (UINT32)arg7;
        }

        PCWSTR callerModeText = (event.Flags & BKIPC_ETW_FLAG_HOOK_KERNEL_CALLER) != 0 ? L"kernel" : L"user";
        PCWSTR targetText = (event.Flags & BKIPC_ETW_FLAG_HOOK_TARGET_CURRENT_PROCESS) != 0 ? L"current" : L"external";
        PCWSTR sectionText = (event.Flags & BKIPC_ETW_FLAG_HOOK_SECTION_IMAGE) != 0 ? L"image" : L"private";

        if (lstrcmpiA(apiName, "NtAllocateVirtualMemory") == 0)
        {
            event.Severity = 2u;
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), "USERMODE_MEMORY_ACTIVITY");
            (void)StringCchPrintfW(
                event.Reason, RTL_NUMBER_OF(event.Reason),
                L"kind=kernel_ntapi callerMode=%ws target=%ws memory.alloc base=0x%llX size=0x%llX allocType=0x%llX protect=0x%llX targetPid=%llu status=0x%08X",
                callerModeText, targetText, (unsigned long long)arg1, (unsigned long long)arg2,
                (unsigned long long)arg4, (unsigned long long)arg5, (unsigned long long)arg6, (unsigned int)callStatus);
        }
        else if (lstrcmpiA(apiName, "NtProtectVirtualMemory") == 0)
        {
            const BOOL sr71ProtectBlocked = (arg5 != 0 && callStatus == (NTSTATUS)0xC0000022L);
            event.Severity = sr71ProtectBlocked ? 8u : 3u;
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName),
                                 sr71ProtectBlocked ? "SR71_HOOK_PROTECT_BLOCKED" : "USERMODE_MEMORY_ACTIVITY");
            (void)StringCchPrintfW(
                event.Reason, RTL_NUMBER_OF(event.Reason),
                L"kind=kernel_ntapi callerMode=%ws target=%ws memory.protect base=0x%llX size=0x%llX newProtect=0x%llX oldProtect=0x%llX blockedSr71=%llu targetPid=%llu status=0x%08X",
                callerModeText, targetText, (unsigned long long)arg1, (unsigned long long)arg2,
                (unsigned long long)arg3, (unsigned long long)arg4, (unsigned long long)arg5, (unsigned long long)arg6,
                (unsigned int)callStatus);
        }
        else if (lstrcmpiA(apiName, "NtWriteVirtualMemory") == 0)
        {
            const BOOL sr71WriteBlocked = (arg5 != 0 && callStatus == (NTSTATUS)0xC0000022L);
            event.Severity = sr71WriteBlocked ? 8u : 3u;
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName),
                                 sr71WriteBlocked ? "SR71_HOOK_WRITE_BLOCKED" : "USERMODE_MEMORY_ACTIVITY");
            (void)StringCchPrintfW(
                event.Reason, RTL_NUMBER_OF(event.Reason),
                L"kind=kernel_ntapi callerMode=%ws target=%ws memory.write base=0x%llX size=0x%llX bytesWritten=0x%llX blockedSr71=%llu targetPid=%llu status=0x%08X",
                callerModeText, targetText, (unsigned long long)arg1, (unsigned long long)arg3,
                (unsigned long long)arg4, (unsigned long long)arg5, (unsigned long long)arg6, (unsigned int)callStatus);
        }
        else if (lstrcmpiA(apiName, "NtUnmapViewOfSection") == 0 || lstrcmpiA(apiName, "NtUnmapViewOfSectionEx") == 0)
        {
            const BOOL remoteUnmap = event.TargetPid != 0 && event.TargetPid != event.ProcessId;
            event.Severity = remoteUnmap ? 6u : 3u;
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName),
                                 "USERMODE_SECTION_UNMAP_ACTIVITY");
            (void)StringCchPrintfW(
                event.Reason, RTL_NUMBER_OF(event.Reason),
                L"kind=kernel_ntapi callerMode=%ws section.unmap api=%S processHandle=0x%llX base=0x%llX targetPid=%llu flags=0x%llX status=0x%08X",
                callerModeText, apiName, (unsigned long long)arg0, (unsigned long long)arg1, (unsigned long long)arg2,
                (unsigned long long)arg3, (unsigned int)callStatus);
        }
        else if (lstrcmpiA(apiName, "NtCreateThread") == 0 || lstrcmpiA(apiName, "NtCreateThreadEx") == 0)
        {
            const BOOL oldCreateThread = lstrcmpiA(apiName, "NtCreateThread") == 0;
            const BOOL remoteThread = event.TargetPid != 0 && event.TargetPid != event.ProcessId;
            const ULONGLONG startRoutine = oldCreateThread ? 0ull : arg3;
            const ULONGLONG argument = oldCreateThread ? 0ull : arg4;
            const ULONGLONG targetTid = oldCreateThread ? arg3 : arg6;
            const ULONGLONG createFlags = oldCreateThread ? 0ull : arg5;
            const BOOL createSuspended = oldCreateThread ? (arg4 != 0) : ((arg5 & 0x1ull) != 0);
            const BOOL hideFromDebugger = !oldCreateThread && ((arg5 & 0x4ull) != 0);
            event.Severity = remoteThread ? 6u : 2u;
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName),
                                 "USERMODE_THREAD_CREATE_ACTIVITY");
            (void)StringCchPrintfW(
                event.Reason, RTL_NUMBER_OF(event.Reason),
                L"kind=kernel_ntapi callerMode=%ws thread.create api=%S processHandle=0x%llX threadHandle=0x%llX targetPid=%llu targetTid=%llu startRoutine=0x%llX argument=0x%llX createFlags=0x%llX createSuspended=%u hideFromDebugger=%u status=0x%08X",
                callerModeText, apiName, (unsigned long long)arg0, (unsigned long long)arg1, (unsigned long long)arg2,
                (unsigned long long)targetTid, (unsigned long long)startRoutine, (unsigned long long)argument,
                (unsigned long long)createFlags, (unsigned int)createSuspended, (unsigned int)hideFromDebugger,
                (unsigned int)callStatus);
        }
        else if (lstrcmpiA(apiName, "NtQueueApcThread") == 0 || lstrcmpiA(apiName, "NtQueueApcThreadEx") == 0 ||
                 lstrcmpiA(apiName, "NtQueueApcThreadEx2") == 0)
        {
            const BOOL ex2 = lstrcmpiA(apiName, "NtQueueApcThreadEx2") == 0;
            const BOOL ex = lstrcmpiA(apiName, "NtQueueApcThreadEx") == 0;
            const ULONGLONG routine = ex2 ? arg3 : (ex ? arg2 : arg1);
            const ULONGLONG targetPidForReason = (ex || ex2) ? arg7 : arg6;
            event.Severity = (event.TargetPid != 0 && event.TargetPid != event.ProcessId) ? 6u : 2u;
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName),
                                 "USERMODE_APC_QUEUE_ACTIVITY");
            (void)StringCchPrintfW(
                event.Reason, RTL_NUMBER_OF(event.Reason),
                L"kind=kernel_ntapi callerMode=%ws thread.apc api=%S threadHandle=0x%llX routine=0x%llX targetPid=%llu status=0x%08X",
                callerModeText, apiName, (unsigned long long)arg0, (unsigned long long)routine,
                (unsigned long long)targetPidForReason, (unsigned int)callStatus);
        }
        else if (lstrcmpiA(apiName, "NtMapViewOfSection") == 0 || lstrcmpiA(apiName, "NtMapViewOfSectionEx") == 0)
        {
            const BOOL remoteMap = event.TargetPid != 0 && event.TargetPid != event.ProcessId;
            event.Severity = remoteMap ? 3u : 1u;
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName),
                                 "USERMODE_SECTION_MAP_ACTIVITY");
            (void)StringCchPrintfW(
                event.Reason, RTL_NUMBER_OF(event.Reason),
                L"kind=kernel_ntapi callerMode=%ws section.map api=%S sectionHandle=0x%llX processHandle=0x%llX base=0x%llX size=0x%llX protect=0x%llX targetPid=%llu status=0x%08X",
                callerModeText, apiName, (unsigned long long)arg0, (unsigned long long)arg1, (unsigned long long)arg2,
                (unsigned long long)arg3, (unsigned long long)arg4, (unsigned long long)arg6, (unsigned int)callStatus);
        }
        else if (lstrcmpiA(apiName, "NtQueryInformationProcess") == 0 ||
                 lstrcmpiA(apiName, "NtQuerySystemInformation") == 0)
        {
            event.Severity = 3u;
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), "USERMODE_PROCESS_RECON");
            (void)StringCchPrintfW(
                event.Reason, RTL_NUMBER_OF(event.Reason),
                L"kind=kernel_ntapi callerMode=%ws target=%ws process.recon api=%S c0=0x%llX c1=0x%llX c2=0x%llX c3=0x%llX status=0x%08X",
                callerModeText, targetText, apiName, (unsigned long long)arg0, (unsigned long long)arg1,
                (unsigned long long)arg2, (unsigned long long)arg3, (unsigned int)callStatus);
        }
        else
        {
            event.Severity = 2u;
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), "USERMODE_HOOK_API_CALL");
            (void)StringCchPrintfW(
                event.Reason, RTL_NUMBER_OF(event.Reason),
                L"kind=kernel_ntapi callerMode=%ws target=%ws section=%ws api=%S c0=0x%llX c1=0x%llX c2=0x%llX c3=0x%llX c4=0x%llX c5=0x%llX c6=0x%llX c7=0x%llX status=0x%08X",
                callerModeText, targetText, sectionText, apiName, (unsigned long long)arg0, (unsigned long long)arg1,
                (unsigned long long)arg2, (unsigned long long)arg3, (unsigned long long)arg4, (unsigned long long)arg5,
                (unsigned long long)arg6, (unsigned long long)arg7, (unsigned int)callStatus);
        }
    }
    else if (EventName != NULL && wcscmp(EventName, L"SystemInformationTelemetry") == 0)
    {
        event.Family = BlackbirdIpcEtwFamilyUserHook;
        event.Severity = 3u;
        if (callerPid != 0)
        {
            event.ProcessId = callerPid;
            event.CallerPid = callerPid;
        }
        if (callerTid != 0)
        {
            event.ThreadId = callerTid;
        }
        (void)StringCchCopyA(event.Operation, RTL_NUMBER_OF(event.Operation), "NtQuerySystemInformation");
        (void)StringCchCopyW(event.EventName, RTL_NUMBER_OF(event.EventName), L"NtQuerySystemInformation");
        (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), "USERMODE_PROCESS_RECON");

        (void)ControllerEtwGetU32Property(Record, L"systemInformationClass", &systemInformationClass);
        (void)ControllerEtwGetU32Property(Record, L"systemInformationLength", &systemInformationLength);
        (void)ControllerEtwGetU32Property(Record, L"returnLength", &returnLength);
        (void)ControllerEtwGetI32Property(Record, L"queryStatus", &queryStatus);
        if (queryStatus != 0)
        {
            return;
        }
        event.HookArgCount = 6u;
        event.HookArgs[0] = systemInformationClass;
        event.HookArgs[1] = 0ull;
        event.HookArgs[2] = systemInformationLength;
        event.HookArgs[3] = 0ull;
        event.HookArgs[4] = returnLength;
        event.HookArgs[5] = (UINT32)queryStatus;

        (void)StringCchPrintfW(
            event.Reason, RTL_NUMBER_OF(event.Reason),
            L"process.recon api=NtQuerySystemInformation systemInformationClass=0x%X systemInformationLength=0x%X returnLength=0x%X status=0x%08X",
            (unsigned int)systemInformationClass, (unsigned int)systemInformationLength, (unsigned int)returnLength,
            (unsigned int)queryStatus);
    }
    else
    {
        if (event.Source == BlackbirdIpcEtwSourceThreatIntel)
        {
            event.Family = BlackbirdIpcEtwFamilyThreatIntel;
        }
    }

    ControllerProcessHollowingEtwRecord(Record, EventName, &event);
    ControllerPicCorrelationApply(&event);

    if (EventName != NULL && wcscmp(EventName, L"ProcessTelemetry") == 0)
    {
        DWORD sourcePid32 = 0;
        DWORD childPid32 = 0;

        if (event.ProcessId != 0 && event.ProcessId <= 0xFFFFFFFFull)
        {
            childPid32 = (DWORD)event.ProcessId;
            if (event.CreatorProcessId != 0 && event.CreatorProcessId <= 0xFFFFFFFFull)
            {
                sourcePid32 = (DWORD)event.CreatorProcessId;
            }
            else if (event.ParentProcessId != 0 && event.ParentProcessId <= 0xFFFFFFFFull)
            {
                sourcePid32 = (DWORD)event.ParentProcessId;
            }
        }

        if (sourcePid32 != 0 && childPid32 != 0 && sourcePid32 != childPid32)
        {
            ControllerExpandMonitoringGraph(sourcePid32, childPid32, BK_CONTROLLER_DRIVER_STREAM_MASK);
        }
    }

    if (event.ProcessId != 0 && event.Severity >= 2u)
    {
        event.Reserved2 = ControllerComputeEtwDetectionTraits(event);
        traitsComputed = TRUE;
        UINT32 heurFlags = ControllerHeurFlagsFromDetectionTraits(event.Reserved2);
        ControllerHeuristicsObserveEvent((DWORD)event.ProcessId, event.Severity, heurFlags);
    }

    if (!ControllerShouldForwardEtwRecord(Record, EventName, &event))
    {
        return;
    }

    if (!traitsComputed)
    {
        event.Reserved2 = ControllerComputeEtwDetectionTraits(event);
    }
    ControllerDispatchEtwEvent(&event);
}

static DWORD WINAPI ControllerEtwThreadProc(_In_ LPVOID Context)
{
    DWORD status;

    UNREFERENCED_PARAMETER(Context);

    if (g_EtwSession == NULL)
    {
        return 1;
    }

    status = BkscRunEtwSession(g_EtwSession);
    ControllerLog("[ETW] run loop exited status=%lu tiEvents=%ld detectionEvents=%ld\n", status,
                  InterlockedCompareExchange(&g_EtwTiEvents, 0, 0),
                  InterlockedCompareExchange(&g_EtwDetectionEvents, 0, 0));
    return status;
}

static BOOL ControllerIsThreatIntelRetryableError(_In_ DWORD ErrorCode)
{
    if (ErrorCode == ERROR_SUCCESS)
    {
        return FALSE;
    }
    if (ErrorCode == ERROR_ACCESS_DENIED || ErrorCode == ERROR_PRIVILEGE_NOT_HELD || ErrorCode == ERROR_NOT_SUPPORTED)
    {
        return FALSE;
    }
    return TRUE;
}

static VOID WINAPI ControllerEtwWarmupCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                               _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Record);
    UNREFERENCED_PARAMETER(EventName);
    UNREFERENCED_PARAMETER(Context);
}

static BOOL ControllerWarmupThreatIntelProvider(_Out_opt_ DWORD *ErrorCode)
{
    WCHAR warmupSessionName[96];
    BKSC_ETW_PROVIDER_CONFIG provider;
    BKSC_ETW_SESSION_CONFIG config;
    BKSC_ETW_SESSION *warmupSession = NULL;
    BOOL ok;
    DWORD err = ERROR_SUCCESS;

    ZeroMemory(&provider, sizeof(provider));
    provider.ProviderId = BKSC_PROVIDER_GUID_TI;
    provider.Level = TRACE_LEVEL_INFORMATION;
    provider.MatchAnyKeyword = ~0ULL;
    provider.MatchAllKeyword = 0;

    ZeroMemory(&config, sizeof(config));
    (void)StringCchPrintfW(warmupSessionName, RTL_NUMBER_OF(warmupSessionName), L"%ws-TiWarmup",
                           BK_CONTROLLER_ETW_SESSION_NAMEW);
    config.SessionName = warmupSessionName;
    config.Providers = &provider;
    config.ProviderCount = 1;
    config.Callback = ControllerEtwWarmupCallback;
    config.CallbackContext = NULL;

    ok = BkscStartEtwSession(&config, &warmupSession);
    if (ok)
    {
        Sleep(120);
        BkscStopEtwSession(warmupSession);
        warmupSession = NULL;
        err = ERROR_SUCCESS;
    }
    else
    {
        err = GetLastError();
    }

    if (ErrorCode != NULL)
    {
        *ErrorCode = err;
    }
    return ok;
}

static VOID ControllerTryRecoverThreatIntelSession(_In_ DWORD InitialTiError)
{
    const DWORD maxAttempts = 3;
    DWORD attempt;
    DWORD tiErr = InitialTiError;

    if (g_EtwSession == NULL || g_ThreatIntelEnabled || !ControllerIsThreatIntelRetryableError(InitialTiError))
    {
        return;
    }

    for (attempt = 1; attempt <= maxAttempts && !ControllerShouldStop(); ++attempt)
    {
        DWORD warmErr = ERROR_SUCCESS;
        BOOL warmOk;

        ControllerLog("[ETW][WARN] TI inactive after subscribe (err=%lu). warmup+restart attempt %lu/%lu\n", tiErr,
                      attempt, maxAttempts);

        warmOk = ControllerWarmupThreatIntelProvider(&warmErr);
        if (!warmOk)
        {
            ControllerLog("[ETW][WARN] TI warmup failed attempt=%lu err=%lu\n", attempt, warmErr);
        }

        BkscStopEtwSession(g_EtwSession);
        g_EtwSession = NULL;
        g_ThreatIntelEnabled = FALSE;

        if (!BkscStartBlackbirdEtwSession(BK_CONTROLLER_ETW_SESSION_NAMEW, TRUE, ControllerEtwCallback, NULL,
                                          &g_EtwSession, &g_ThreatIntelEnabled))
        {
            DWORD restartErr = GetLastError();
            tiErr = BkscGetLastThreatIntelEnableError();
            ControllerLog("[ETW][WARN] restart after TI warmup failed attempt=%lu startErr=%lu tiErr=%lu\n", attempt,
                          restartErr, tiErr);
            if (attempt < maxAttempts)
            {
                Sleep(180 * attempt);
            }
            continue;
        }

        tiErr = BkscGetLastThreatIntelEnableError();
        g_ThreatIntelEnableError = tiErr;
        if (g_ThreatIntelEnabled)
        {
            ControllerLog("[ETW] TI provider enabled after warmup attempt %lu (tiEnableErr=%lu)\n", attempt, tiErr);
            return;
        }

        ControllerLog("[ETW][WARN] TI still inactive after restart attempt=%lu tiEnableErr=%lu\n", attempt, tiErr);
        if (!ControllerIsThreatIntelRetryableError(tiErr))
        {
            return;
        }

        if (attempt < maxAttempts)
        {
            Sleep(180 * attempt);
        }
    }

    UNREFERENCED_PARAMETER(tiErr);
}

static BOOL ControllerStartEtwSession(VOID)
{
    DWORD tiErr = ERROR_SUCCESS;

    ControllerCleanupStaleEtwSessions();
    (void)InterlockedExchange(&g_EtwTiEvents, 0);
    (void)InterlockedExchange(&g_EtwDetectionEvents, 0);
    g_ThreatIntelEnabled = FALSE;
    g_ThreatIntelEnableError = ERROR_SUCCESS;
    if (!BkscStartBlackbirdEtwSession(BK_CONTROLLER_ETW_SESSION_NAMEW, TRUE, ControllerEtwCallback, NULL, &g_EtwSession,
                                      &g_ThreatIntelEnabled))
    {
        DWORD err = GetLastError();
        g_ThreatIntelEnableError = err;
        ControllerLog("[WARN] BlackbirdController: failed to start ETW TI session name=%ws (%lu)\n",
                      BK_CONTROLLER_ETW_SESSION_NAMEW, err);
        g_EtwSession = NULL;
        g_ThreatIntelEnabled = FALSE;
        return FALSE;
    }

    tiErr = BkscGetLastThreatIntelEnableError();
    g_ThreatIntelEnableError = tiErr;
    if (!g_ThreatIntelEnabled)
    {
        ControllerTryRecoverThreatIntelSession(tiErr);
        tiErr = BkscGetLastThreatIntelEnableError();
        g_ThreatIntelEnableError = tiErr;
    }
    if (g_EtwSession == NULL)
    {
        ControllerLog("[WARN] BlackbirdController: ETW session unavailable after TI recovery attempts\n");
        return FALSE;
    }

    g_EtwThread = CreateThread(NULL, 0, ControllerEtwThreadProc, NULL, 0, NULL);
    if (g_EtwThread == NULL)
    {
        ControllerLog("[WARN] BlackbirdController: failed to start ETW thread (%lu)\n", GetLastError());
        BkscStopEtwSession(g_EtwSession);
        g_EtwSession = NULL;
        g_ThreatIntelEnabled = FALSE;
        return FALSE;
    }

    ControllerLog("[*] BlackbirdController: ETW session started. threat-intel=%s tiEnableErr=%lu\n",
                  g_ThreatIntelEnabled ? "enabled" : "disabled", tiErr);
    return TRUE;
}

static VOID ControllerStopEtwSession(VOID)
{
    if (g_EtwSession != NULL)
    {
        BkscStopEtwSession(g_EtwSession);
        g_EtwSession = NULL;
    }

    if (g_EtwThread != NULL)
    {
        (void)WaitForSingleObject(g_EtwThread, 3000);
        CloseHandle(g_EtwThread);
        g_EtwThread = NULL;
    }

    ControllerStopEtwSessionByNameBestEffort(BK_CONTROLLER_ETW_SESSION_NAMEW, "service-stop");
    ControllerLog("[ETW] session stopped tiEvents=%ld detectionEvents=%ld\n",
                  InterlockedCompareExchange(&g_EtwTiEvents, 0, 0),
                  InterlockedCompareExchange(&g_EtwDetectionEvents, 0, 0));
}

static BOOL ControllerStartCore(VOID)
{
    DWORD serverThreadsStarted = 0;
    DWORD serverThreadIndex;

    InterlockedExchange(&g_ControllerProtectionReady, 0);
    InterlockedExchange(&g_ControllerProtectionArmed, 0);
    g_ClientList = NULL;
    g_ClientCount = 0;
    g_PidIndexCount = 0;
    ZeroMemory(g_ClientSlots, sizeof(g_ClientSlots));
    ZeroMemory(g_PidIndex, sizeof(g_PidIndex));

    ControllerLog("[*] BlackbirdController: core start requested\n");
    ControllerResetHollowingState();
    ControllerPicCorrelationReset();
    ControllerHeuristicsInitialize();

    g_StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_StopEvent == NULL)
    {
        ControllerLog("[-] BlackbirdController: failed to create stop event (%lu)\n", GetLastError());
        return FALSE;
    }

    if (!ControllerStartHollowingWorkers())
    {
        ControllerLog("[WARN] controller hollowing worker start failed (%lu)\n", GetLastError());
    }

    if (!ControllerSymbolServiceStart())
    {
        ControllerLog("[WARN] controller symbol service start failed (%lu)\n", GetLastError());
    }

    BkscUseServiceProtocol();
    g_DriverHandle = BkscOpenControlDevice();
    if (g_DriverHandle == INVALID_HANDLE_VALUE)
    {
        ControllerLog("[WARN] BlackbirdController: initial driver open failed (%lu). retrying in background.\n",
                      GetLastError());
    }
    else
    {
        ControllerLog("[DRIVER] initial open succeeded\n");
    }

    InterlockedExchange(&g_ControllerProtectionReady, 1);
    ControllerTryMarkProtectedReady(g_DriverHandle, TRUE);

    if (!ControllerStartDriverSubscriptionWorker())
    {
        ControllerLog("[WARN] controller subscription apply worker start failed (%lu)\n", GetLastError());
        return FALSE;
    }

    (void)ControllerStartEtwSession();
    ControllerTryMarkProtectedReady(g_DriverHandle, TRUE);

    g_DriverPumpThread = CreateThread(NULL, 0, ControllerDriverPumpThreadProc, NULL, 0, NULL);
    if (g_DriverPumpThread == NULL)
    {
        ControllerLog("[-] BlackbirdController: failed to start driver pump thread (%lu)\n", GetLastError());
        return FALSE;
    }

    ZeroMemory(g_ServerAcceptThreads, sizeof(g_ServerAcceptThreads));
    ZeroMemory(g_HookAcceptThreads, sizeof(g_HookAcceptThreads));
    for (serverThreadIndex = 0; serverThreadIndex < BK_CONTROLLER_SERVER_ACCEPT_THREADS; serverThreadIndex += 1)
    {
        HANDLE thread = CreateThread(NULL, 0, ControllerServerThreadProc, (LPVOID)&g_ControlEndpointContext, 0, NULL);
        if (thread == NULL)
        {
            ControllerLog("[WARN] BlackbirdController: failed to start control accept thread %lu (%lu)\n",
                          serverThreadIndex, GetLastError());
            break;
        }
        g_ServerAcceptThreads[serverThreadIndex] = thread;
        serverThreadsStarted += 1;
    }
    if (serverThreadsStarted == 0)
    {
        ControllerLog("[-] BlackbirdController: failed to start any control accept thread\n");
        return FALSE;
    }
    g_ServerThread = g_ServerAcceptThreads[0];
    if (serverThreadsStarted < BK_CONTROLLER_SERVER_ACCEPT_THREADS)
    {
        ControllerLog("[WARN] BlackbirdController: control accept thread pool reduced to %lu/%lu\n",
                      serverThreadsStarted, (DWORD)BK_CONTROLLER_SERVER_ACCEPT_THREADS);
    }

    for (serverThreadIndex = 0; serverThreadIndex < BK_CONTROLLER_HOOK_ACCEPT_THREADS; serverThreadIndex += 1)
    {
        HANDLE thread = CreateThread(NULL, 0, ControllerServerThreadProc, (LPVOID)&g_HookEndpointContext, 0, NULL);
        if (thread == NULL)
        {
            ControllerLog("[WARN] BlackbirdController: failed to start hook accept thread %lu (%lu)\n",
                          serverThreadIndex, GetLastError());
            break;
        }
        g_HookAcceptThreads[serverThreadIndex] = thread;
    }

    ControllerLog("[*] BlackbirdController: IPC endpoints online control=%ls hook=%ls\n", BKIPC_PIPE_NAME,
                  BKIPC_HOOK_PIPE_NAME);
    ControllerTryMarkProtectedReady(g_DriverHandle, TRUE);
    return TRUE;
}

static VOID ControllerWakeServerPipe(_In_z_ PCWSTR PipeName, _In_ DWORD Attempts)
{
    DWORD index;

    if (PipeName == NULL || PipeName[0] == L'\0')
    {
        return;
    }

    for (index = 0; index < Attempts; index += 1)
    {
        HANDLE pipe = CreateFileW(PipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (pipe != INVALID_HANDLE_VALUE)
        {
            CloseHandle(pipe);
        }
    }
}

static VOID ControllerDisarmRuntimeForTeardown(_In_z_ PCSTR Reason)
{
    static const DWORD teardownMask = BK_RUNTIME_FLAG_ANTI_VIRTUALIZATION | BK_RUNTIME_FLAG_SELF_HIDE |
                                      BK_RUNTIME_FLAG_INTERFACE_PROTECTED_ACCESS |
                                      BK_RUNTIME_FLAG_CONTROLLER_PROTECTED_ACCESS |
                                      BK_RUNTIME_FLAG_NTAPI_HOOKS_DISARMED | BK_RUNTIME_FLAG_QPC_TIMING_DISABLED;
    static const DWORD teardownFlags = BK_RUNTIME_FLAG_NTAPI_HOOKS_DISARMED | BK_RUNTIME_FLAG_QPC_TIMING_DISABLED;

    EnterCriticalSection(g_DriverLock.get());
    if (g_DriverHandle != INVALID_HANDLE_VALUE)
    {
        if (!BkscSetRuntimeConfig(g_DriverHandle, teardownFlags, teardownMask))
        {
            ControllerLog("[DRIVER][WARN] teardown runtime disarm failed reason=%s err=%lu\n", Reason, GetLastError());
        }
        else
        {
            ControllerLog("[DRIVER] teardown runtime disarmed reason=%s flags=0x%08lX mask=0x%08lX\n", Reason,
                          teardownFlags, teardownMask);
        }
    }
    LeaveCriticalSection(g_DriverLock.get());

    InterlockedExchange(&g_ControllerProtectionReady, 0);
    InterlockedExchange(&g_ControllerProtectionArmed, 0);
}

static VOID ControllerStopCore(VOID)
{
    DWORD waitMs = 0;
    DWORD threadIndex = 0;

    ControllerLog("[*] BlackbirdController: stop requested\n");

    if (g_StopEvent != NULL)
    {
        (void)SetEvent(g_StopEvent);
    }

    ControllerDisarmRuntimeForTeardown("stop-core-begin");

    ControllerWakeServerPipe(BKIPC_PIPE_NAME, (DWORD)BK_CONTROLLER_SERVER_ACCEPT_THREADS);
    ControllerWakeServerPipe(BKIPC_HOOK_PIPE_NAME, (DWORD)BK_CONTROLLER_HOOK_ACCEPT_THREADS);
    ControllerStopDriverSubscriptionWorker();

    for (threadIndex = 0; threadIndex < BK_CONTROLLER_SERVER_ACCEPT_THREADS; threadIndex += 1)
    {
        HANDLE thread = g_ServerAcceptThreads[threadIndex];
        if (thread != NULL)
        {
            (void)WaitForSingleObject(thread, 3000);
            CloseHandle(thread);
            g_ServerAcceptThreads[threadIndex] = NULL;
        }
    }
    for (threadIndex = 0; threadIndex < BK_CONTROLLER_HOOK_ACCEPT_THREADS; threadIndex += 1)
    {
        HANDLE thread = g_HookAcceptThreads[threadIndex];
        if (thread != NULL)
        {
            (void)WaitForSingleObject(thread, 3000);
            CloseHandle(thread);
            g_HookAcceptThreads[threadIndex] = NULL;
        }
    }
    g_ServerThread = NULL;

    if (g_DriverPumpThread != NULL)
    {
        (void)WaitForSingleObject(g_DriverPumpThread, 3000);
        CloseHandle(g_DriverPumpThread);
        g_DriverPumpThread = NULL;
    }

    EnterCriticalSection(g_ClientListLock.get());
    {
        PBK_CONTROLLER_CLIENT client;
        for (client = g_ClientList; client != NULL; client = client->Next)
        {
            if (client->Pipe != INVALID_HANDLE_VALUE)
            {
                (void)CancelIoEx(client->Pipe, NULL);
                (void)DisconnectNamedPipe(client->Pipe);
            }
        }
    }
    LeaveCriticalSection(g_ClientListLock.get());

    while (waitMs < 2000)
    {
        DWORD remaining;
        EnterCriticalSection(g_ClientListLock.get());
        remaining = g_ClientCount;
        LeaveCriticalSection(g_ClientListLock.get());
        if (remaining == 0)
        {
            break;
        }
        Sleep(50);
        waitMs += 50;
    }

    ControllerStopEtwSession();

    EnterCriticalSection(g_DriverLock.get());
    if (g_DriverHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_DriverHandle);
        g_DriverHandle = INVALID_HANDLE_VALUE;
    }
    LeaveCriticalSection(g_DriverLock.get());

    ControllerStopHollowingWorkers();

    if (g_StopEvent != NULL)
    {
        CloseHandle(g_StopEvent);
        g_StopEvent = NULL;
    }

    ControllerSymbolServiceStop();
    ControllerResetHollowingState();
    ControllerPicCorrelationReset();
    ControllerHeuristicsUninitialize();

    ControllerLog("[*] BlackbirdController: core stopped\n");
}

static DWORD WINAPI ControllerServiceControlHandlerEx(_In_ DWORD ControlCode, _In_ DWORD EventType,
                                                      _In_ LPVOID EventData, _In_ LPVOID Context)
{
    UNREFERENCED_PARAMETER(EventType);
    UNREFERENCED_PARAMETER(EventData);
    UNREFERENCED_PARAMETER(Context);

    if (ControlCode == SERVICE_CONTROL_STOP || ControlCode == SERVICE_CONTROL_SHUTDOWN)
    {
        ControllerLog("[*] BlackbirdController: service control received code=%lu\n", ControlCode);
        ControllerUpdateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        if (g_StopEvent != NULL)
        {
            (void)SetEvent(g_StopEvent);
        }
        return NO_ERROR;
    }

    return ERROR_CALL_NOT_IMPLEMENTED;
}

static VOID WINAPI ControllerServiceMain(_In_ DWORD Argc, _In_reads_(Argc) LPWSTR *Argv)
{
    UNREFERENCED_PARAMETER(Argc);
    UNREFERENCED_PARAMETER(Argv);

    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatusHandle =
        RegisterServiceCtrlHandlerExW(BK_CONTROLLER_SERVICE_NAMEW, ControllerServiceControlHandlerEx, NULL);
    if (g_ServiceStatusHandle == NULL)
    {
        return;
    }
    ControllerLog("[*] BlackbirdController: service main entered\n");

    ControllerUpdateServiceStatus(SERVICE_START_PENDING, NO_ERROR, 6000);
    if (!ControllerStartCore())
    {
        ControllerUpdateServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        ControllerStopCore();
        return;
    }

    ControllerUpdateServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);
    ControllerLog("[*] BlackbirdController: service running\n");
    (void)WaitForSingleObject(g_StopEvent, INFINITE);

    ControllerUpdateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
    ControllerStopCore();
    ControllerUpdateServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

int __cdecl wmain(_In_ int argc, _In_reads_(argc) wchar_t **argv)
{
    SERVICE_TABLE_ENTRYW table[] = {{(LPWSTR)BK_CONTROLLER_SERVICE_NAMEW, ControllerServiceMain}, {NULL, NULL}};
    BOOL runAsConsole = FALSE;
    BOOL forceServiceMode = FALSE;
    int i;

    ControllerLogInit();
    ControllerApplyProcessMitigations();
    ControllerLog("[*] BlackbirdController: wmain entered pid=%lu\n", GetCurrentProcessId());

    for (i = 1; i < argc; ++i)
    {
        if (_wcsicmp(argv[i], L"--console") == 0)
        {
            runAsConsole = TRUE;
            continue;
        }
        if (_wcsicmp(argv[i], L"--service") == 0)
        {
            forceServiceMode = TRUE;
        }
    }

#ifdef TEMPUS_DEBUG
    if (!forceServiceMode && !runAsConsole)
    {
        if (GetConsoleWindow() != NULL || AttachConsole(ATTACH_PARENT_PROCESS))
        {
            runAsConsole = TRUE;
        }
    }
#endif

    if (runAsConsole)
    {
#ifdef TEMPUS_DEBUG
        if (GetConsoleWindow() == NULL && !AttachConsole(ATTACH_PARENT_PROCESS))
        {
            (void)AllocConsole();
        }
#endif
        ControllerLog("[*] BlackbirdController: running in console mode.\n");
        if (!ControllerStartCore())
        {
            ControllerStopCore();
            ControllerLogClose();
            return 1;
        }

        ControllerLog("[*] BlackbirdController: running. Press Enter to stop.\n");
        (void)getchar();
        ControllerStopCore();
        ControllerLogClose();
        return 0;
    }

    if (!StartServiceCtrlDispatcherW(table))
    {
        ControllerLog("[-] BlackbirdController: StartServiceCtrlDispatcherW failed (%lu)\n", GetLastError());
        ControllerLogClose();
        return 1;
    }

    ControllerLogClose();
    return 0;
}
