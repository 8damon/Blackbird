#include "../blackbird_controller_private.h"

static HANDLE g_ServerAcceptThreads[BLACKBIRD_CONTROLLER_SERVER_ACCEPT_THREADS] = { 0 };

static DWORD WINAPI ControllerServerThreadProc(_In_ LPVOID Context)
{
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD pipeCreateFailures = 0;

    UNREFERENCED_PARAMETER(Context);

    if (!ControllerCreatePipeSecurity(&sa, &sd))
    {
        ControllerLog("[-] BlackbirdController: failed to create pipe security (%lu)\n", GetLastError());
        return 1;
    }

    while (!ControllerShouldStop())
    {
        HANDLE pipe;
        BOOL connected;
        DWORD mode = PIPE_READMODE_MESSAGE;
        BLACKBIRD_CONTROLLER_CLIENT *client;
        HANDLE thread;
        DWORD slotIndex;

        pipe = CreateNamedPipeW(BLACKBIRD_IPC_PIPE_NAME,
                                PIPE_ACCESS_DUPLEX,
                                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                PIPE_UNLIMITED_INSTANCES,
                                sizeof(BLACKBIRD_IPC_PACKET),
                                sizeof(BLACKBIRD_IPC_PACKET),
                                3000,
                                &sa);
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

        client = (BLACKBIRD_CONTROLLER_CLIENT *)calloc(1, sizeof(*client));
        if (client == NULL)
        {
            CloseHandle(pipe);
            continue;
        }

        client->Pipe = pipe;
        client->QueueHead = NULL;
        client->QueueTail = NULL;
        client->QueueDepth = 0;
        client->DroppedEvents = 0;
        client->SubscriptionCount = 0;
        client->SlotIndex = BLACKBIRD_CONTROLLER_INVALID_SLOT;
        client->DispatchRefCount = 0;
        client->Detached = 0;
        InitializeCriticalSection(&client->Lock);
        client->IoctlQueueDataEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        client->EtwQueueDataEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        client->DispatchIdleEvent = CreateEventW(NULL, TRUE, TRUE, NULL);
        if (client->IoctlQueueDataEvent == NULL || client->EtwQueueDataEvent == NULL || client->DispatchIdleEvent == NULL)
        {
            if (client->IoctlQueueDataEvent != NULL)
            {
                (void)CloseHandle(client->IoctlQueueDataEvent);
                client->IoctlQueueDataEvent = NULL;
            }
            if (client->EtwQueueDataEvent != NULL)
            {
                (void)CloseHandle(client->EtwQueueDataEvent);
                client->EtwQueueDataEvent = NULL;
            }
            if (client->DispatchIdleEvent != NULL)
            {
                (void)CloseHandle(client->DispatchIdleEvent);
                client->DispatchIdleEvent = NULL;
            }
            DeleteCriticalSection(&client->Lock);
            CloseHandle(pipe);
            free(client);
            continue;
        }
        if (!GetNamedPipeClientProcessId(pipe, &client->ProcessId))
        {
            client->ProcessId = 0;
        }
        if (!ProcessIdToSessionId(client->ProcessId, &client->SessionId))
        {
            client->SessionId = 0;
        }

        ControllerLog("[IPC] client connected pid=%lu session=%lu\n", client->ProcessId, client->SessionId);

        EnterCriticalSection(&g_ClientListLock);
        if (g_ClientCount >= BLACKBIRD_CONTROLLER_MAX_CLIENTS)
        {
            LeaveCriticalSection(&g_ClientListLock);
            DeleteCriticalSection(&client->Lock);
            if (client->IoctlQueueDataEvent != NULL)
            {
                (void)CloseHandle(client->IoctlQueueDataEvent);
                client->IoctlQueueDataEvent = NULL;
            }
            if (client->EtwQueueDataEvent != NULL)
            {
                (void)CloseHandle(client->EtwQueueDataEvent);
                client->EtwQueueDataEvent = NULL;
            }
            if (client->DispatchIdleEvent != NULL)
            {
                (void)CloseHandle(client->DispatchIdleEvent);
                client->DispatchIdleEvent = NULL;
            }
            CloseHandle(pipe);
            free(client);
            continue;
        }
        slotIndex = ControllerAllocateClientSlotLocked();
        if (slotIndex == BLACKBIRD_CONTROLLER_INVALID_SLOT)
        {
            LeaveCriticalSection(&g_ClientListLock);
            DeleteCriticalSection(&client->Lock);
            if (client->IoctlQueueDataEvent != NULL)
            {
                (void)CloseHandle(client->IoctlQueueDataEvent);
                client->IoctlQueueDataEvent = NULL;
            }
            if (client->EtwQueueDataEvent != NULL)
            {
                (void)CloseHandle(client->EtwQueueDataEvent);
                client->EtwQueueDataEvent = NULL;
            }
            if (client->DispatchIdleEvent != NULL)
            {
                (void)CloseHandle(client->DispatchIdleEvent);
                client->DispatchIdleEvent = NULL;
            }
            CloseHandle(pipe);
            free(client);
            continue;
        }
        client->SlotIndex = slotIndex;
        g_ClientSlots[slotIndex] = client;
        client->Next = g_ClientList;
        g_ClientList = client;
        g_ClientCount += 1;
        ControllerLog("[IPC] active clients=%lu\n", g_ClientCount);
        LeaveCriticalSection(&g_ClientListLock);

        thread = CreateThread(NULL, 0, ControllerClientThreadProc, client, 0, NULL);
        if (thread == NULL)
        {
            ControllerLog("[WARN] BlackbirdController: failed to spawn client thread for pid=%lu (%lu)\n",
                          client->ProcessId, GetLastError());
            ControllerDetachClient(client);
            DeleteCriticalSection(&client->Lock);
            if (client->IoctlQueueDataEvent != NULL)
            {
                (void)CloseHandle(client->IoctlQueueDataEvent);
                client->IoctlQueueDataEvent = NULL;
            }
            if (client->EtwQueueDataEvent != NULL)
            {
                (void)CloseHandle(client->EtwQueueDataEvent);
                client->EtwQueueDataEvent = NULL;
            }
            if (client->DispatchIdleEvent != NULL)
            {
                (void)CloseHandle(client->DispatchIdleEvent);
                client->DispatchIdleEvent = NULL;
            }
            CloseHandle(pipe);
            free(client);
            continue;
        }
        CloseHandle(thread);
    }

    if (sd != NULL)
    {
        LocalFree(sd);
    }
    return 0;
}

static DWORD WINAPI ControllerDriverPumpThreadProc(_In_ LPVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    DWORD driverOpenFailures = 0;

    while (!ControllerShouldStop())
    {
        BLACKBIRD_EVENT_RECORD record;
        DWORD bytes = 0;
        BOOL ok;

        EnterCriticalSection(&g_DriverLock);
        if (g_DriverHandle == INVALID_HANDLE_VALUE)
        {
            g_DriverHandle = BLACKBIRDSCOpenControlDevice();
            LeaveCriticalSection(&g_DriverLock);
            if (g_DriverHandle != INVALID_HANDLE_VALUE)
            {
                BLACKBIRD_STATS_RESPONSE stats;
                DWORD statsBytes = 0;
                ControllerMarkDriverSubscriptionsDirty();
                (void)ControllerApplyDriverSubscriptions();
                driverOpenFailures = 0;
                ZeroMemory(&stats, sizeof(stats));
                if (BLACKBIRDSCGetStats(g_DriverHandle, &stats, &statsBytes))
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
        LeaveCriticalSection(&g_DriverLock);

        (void)ControllerApplyDriverSubscriptionsIfDirty();

        EnterCriticalSection(&g_DriverLock);
        ok = BLACKBIRDSCGetEvent(g_DriverHandle, &record, &bytes);
        if (!ok)
        {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS)
            {
                LeaveCriticalSection(&g_DriverLock);
                Sleep(20);
                continue;
            }

            ControllerLog("[DRIVER][WARN] event read failed (%lu), reconnecting\n", err);
            CloseHandle(g_DriverHandle);
            g_DriverHandle = INVALID_HANDLE_VALUE;
            LeaveCriticalSection(&g_DriverLock);
            Sleep(200);
            continue;
        }
        LeaveCriticalSection(&g_DriverLock);

        if (bytes >= sizeof(record))
        {
            ControllerDispatchDriverRecord(&record);
        }
    }

    return 0;
}

#ifndef BLACKBIRD_INTENT_PROCESS_MEMORY
#define BLACKBIRD_INTENT_PROCESS_MEMORY 0x00000001u
#endif

#ifndef BLACKBIRD_INTENT_THREAD_CONTEXT
#define BLACKBIRD_INTENT_THREAD_CONTEXT 0x00000002u
#endif

#ifndef BLACKBIRD_INTENT_DUP_HANDLE
#define BLACKBIRD_INTENT_DUP_HANDLE 0x00000004u
#endif

static BOOL ControllerIsInterestingHandleAccessMask(_In_ ULONG DesiredAccess)
{
    return ((DesiredAccess & PROCESS_VM_OPERATION) != 0) ||
           ((DesiredAccess & PROCESS_VM_WRITE) != 0) ||
           ((DesiredAccess & PROCESS_CREATE_THREAD) != 0) ||
           ((DesiredAccess & PROCESS_ALL_ACCESS) != 0) ||
           ((DesiredAccess & THREAD_SET_CONTEXT) != 0) ||
           ((DesiredAccess & THREAD_SUSPEND_RESUME) != 0) ||
           ((DesiredAccess & THREAD_ALL_ACCESS) != 0);
}

static BOOL ControllerAnsiContainsInsensitive(_In_opt_z_ const CHAR *Haystack, _In_z_ const CHAR *Needle)
{
    size_t hayLen;
    size_t needleLen;
    size_t i;

    if (Haystack == NULL || Needle == NULL || Needle[0] == '\0')
    {
        return FALSE;
    }

    hayLen = strlen(Haystack);
    needleLen = strlen(Needle);
    if (needleLen == 0 || hayLen < needleLen)
    {
        return FALSE;
    }

    for (i = 0; i <= (hayLen - needleLen); ++i)
    {
        if (_strnicmp(Haystack + i, Needle, needleLen) == 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}

#ifndef BLACKBIRD_SOCKET_OPCODE_SEND
#define BLACKBIRD_SOCKET_OPCODE_SEND 10u
#define BLACKBIRD_SOCKET_OPCODE_RECV 11u
#define BLACKBIRD_SOCKET_OPCODE_CONNECT 12u
#define BLACKBIRD_SOCKET_OPCODE_DISCONNECT 13u
#define BLACKBIRD_SOCKET_OPCODE_ACCEPT 15u
#define BLACKBIRD_SOCKET_OPCODE_RECONNECT 16u
#define BLACKBIRD_SOCKET_OPCODE_SENDUDP 42u
#define BLACKBIRD_SOCKET_OPCODE_RECVUDP 43u
#define BLACKBIRD_SOCKET_OPCODE_FAILUDP 49u
#endif

static BOOL ControllerIsInterestingSocketOpcode(_In_ UCHAR Opcode)
{
    switch (Opcode)
    {
    case BLACKBIRD_SOCKET_OPCODE_SEND:
    case BLACKBIRD_SOCKET_OPCODE_RECV:
    case BLACKBIRD_SOCKET_OPCODE_CONNECT:
    case BLACKBIRD_SOCKET_OPCODE_DISCONNECT:
    case BLACKBIRD_SOCKET_OPCODE_ACCEPT:
    case BLACKBIRD_SOCKET_OPCODE_RECONNECT:
    case BLACKBIRD_SOCKET_OPCODE_SENDUDP:
    case BLACKBIRD_SOCKET_OPCODE_RECVUDP:
    case BLACKBIRD_SOCKET_OPCODE_FAILUDP:
        return TRUE;
    default:
        return FALSE;
    }
}

static PCSTR ControllerSocketOperationFromOpcode(_In_ UCHAR Opcode)
{
    switch (Opcode)
    {
    case BLACKBIRD_SOCKET_OPCODE_SEND:
        return "SEND";
    case BLACKBIRD_SOCKET_OPCODE_RECV:
        return "RECV";
    case BLACKBIRD_SOCKET_OPCODE_CONNECT:
        return "CONNECT";
    case BLACKBIRD_SOCKET_OPCODE_DISCONNECT:
        return "DISCONNECT";
    case BLACKBIRD_SOCKET_OPCODE_ACCEPT:
        return "ACCEPT";
    case BLACKBIRD_SOCKET_OPCODE_RECONNECT:
        return "RECONNECT";
    case BLACKBIRD_SOCKET_OPCODE_SENDUDP:
        return "SEND_UDP";
    case BLACKBIRD_SOCKET_OPCODE_RECVUDP:
        return "RECV_UDP";
    case BLACKBIRD_SOCKET_OPCODE_FAILUDP:
        return "FAIL_UDP";
    default:
        return "SOCKET";
    }
}

static BOOL ControllerShouldForwardEtwRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                             _In_ const BLACKBIRD_IPC_ETW_EVENT *Event)
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
        (void)ControllerEtwGetAnsiProperty(Record, L"detectionName", detectionName, RTL_NUMBER_OF(detectionName));
        (void)ControllerEtwGetU32Property(Record, L"severity", &severity);
        (void)ControllerEtwGetU64Property(Record, L"processId", &processId);
        (void)ControllerEtwGetU64Property(Record, L"targetPid", &targetPid);
        if (targetPid == 0)
        {
            targetPid = Event->TargetPid;
        }
        if (processId == 0)
        {
            processId = (Event->ProcessId != 0) ? Event->ProcessId : Event->EventProcessId;
        }
        selfTarget = (processId != 0 && targetPid != 0 && processId == targetPid);

        (void)ControllerEtwGetU32Property(Record, L"correlationFlags", &correlationFlags);

        handleNoiseDetection =
            ControllerAnsiContainsInsensitive(detectionName, "DIRECT_SYSCALL_SUSPECT_HANDLE_OPERATION") ||
            ControllerAnsiContainsInsensitive(detectionName, "STACK_INTEGRITY_ANOMALY_ON_HANDLE_OP") ||
            ControllerAnsiContainsInsensitive(detectionName, "SUSPECT_HANDLE_OPERATION") ||
            ControllerAnsiContainsInsensitive(detectionName, "ANOMALY_ON_HANDLE_OP");

        if (!handleNoiseDetection &&
            (ControllerAnsiContainsInsensitive(detectionName, "USPECT_HANDLE_OPERATION") ||
             ControllerAnsiContainsInsensitive(detectionName, "NOMALY_ON_HANDLE_OP")))
        {
            handleNoiseDetection = TRUE;
        }

        lowSignalDetection =
            ControllerAnsiContainsInsensitive(detectionName, "REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT") ||
            ControllerAnsiContainsInsensitive(detectionName, "THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT") ||
            ControllerAnsiContainsInsensitive(detectionName, "REMOTE_THREAD_OUTSIDE_MAIN_IMAGE");

        strongDetection =
            ControllerAnsiContainsInsensitive(detectionName, "PROCESS_HOLLOWING") ||
            ControllerAnsiContainsInsensitive(detectionName, "INJECTION") ||
            ControllerAnsiContainsInsensitive(detectionName, "THREAD_HIJACK") ||
            ControllerAnsiContainsInsensitive(detectionName, "REMOTE_APC") ||
            ControllerAnsiContainsInsensitive(detectionName, "NON_IMAGE_EXECUTABLE_REGION");

        if (handleNoiseDetection)
        {
            if (selfTarget)
            {
                return FALSE;
            }
            if (severity < 7)
            {
                return FALSE;
            }
            if ((correlationFlags & (BLACKBIRD_INTENT_PROCESS_MEMORY | BLACKBIRD_INTENT_THREAD_CONTEXT |
                                     BLACKBIRD_INTENT_DUP_HANDLE)) == 0)
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
        (void)ControllerEtwGetAnsiProperty(Record, L"class", className, RTL_NUMBER_OF(className));
        (void)ControllerEtwGetU32Property(Record, L"desiredAccess", &desiredAccess);

        if (_stricmp(className, "DIRECT-SYSCALL-SUSPECT") == 0 || _stricmp(className, "UNKNOWN-ORIGIN") == 0)
        {
            return TRUE;
        }
        return ControllerIsInterestingHandleAccessMask(desiredAccess);
    }

    if (wcscmp(EventName, L"ApcTelemetry") == 0)
    {
        (void)ControllerEtwGetU32Property(Record, L"desiredAccess", &desiredAccess);
        return ((desiredAccess & (THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME)) != 0);
    }

    if (wcscmp(EventName, L"ThreadTelemetry") == 0)
    {
        (void)ControllerEtwGetU32Property(Record, L"correlationFlags", &correlationFlags);
        (void)ControllerEtwGetU64Property(Record, L"processId", &processId);
        (void)ControllerEtwGetU64Property(Record, L"creatorPid", &creatorPid);
        if (creatorPid == 0)
        {
            creatorPid = Event->CreatorProcessId;
        }
        if (processId == 0)
        {
            processId = Event->ProcessId;
        }

        if ((correlationFlags & (BLACKBIRD_INTENT_PROCESS_MEMORY | BLACKBIRD_INTENT_THREAD_CONTEXT |
                                 BLACKBIRD_INTENT_DUP_HANDLE)) != 0)
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
        if ((Event->Flags & BLACKBIRD_IPC_ETW_FLAG_PROCESS_IS_CREATE) != 0u)
        {
            return TRUE;
        }
        return FALSE;
    }
    if (wcscmp(EventName, L"ImageTelemetry") == 0)
    {
        return ((Event->Flags & BLACKBIRD_IPC_ETW_FLAG_IMAGE_SYSTEM_MODE) == 0u);
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

    return FALSE;
}

static VOID WINAPI ControllerEtwCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName, _In_opt_ PVOID Context)
{
    static const PCWSTR stackPropertyNames[BLACKBIRD_IPC_MAX_ETW_STACK_FRAMES] = {
        L"stack0", L"stack1", L"stack2", L"stack3", L"stack4", L"stack5", L"stack6", L"stack7"};
    BLACKBIRD_IPC_ETW_EVENT event;
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
    LONG statusOpenProcess = 0;
    LONG statusBasicInfo = 0;
    LONG statusSectionName = 0;
    LONG startRegionStatus = 0;
    LONG createStatus = 0;
    LONG callStatus = 0;
    LONG queryStatus = 0;
    BOOL boolValue = FALSE;
    UCHAR signatureLevel = 0;
    UCHAR signatureType = 0;
    CHAR apiName[96];
    DWORD i;

    UNREFERENCED_PARAMETER(Context);

    if (Record == NULL)
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

    if (IsEqualGUID(&Record->EventHeader.ProviderId, &BLACKBIRDSC_PROVIDER_GUID_TI))
    {
        event.Source = BlackbirdIpcEtwSourceThreatIntel;
        event.Family = BlackbirdIpcEtwFamilyThreatIntel;
        (void)InterlockedIncrement(&g_EtwTiEvents);
    }
    else if (IsEqualGUID(&Record->EventHeader.ProviderId, &BLACKBIRDSC_PROVIDER_GUID_BLACKBIRD))
    {
        event.Source = BlackbirdIpcEtwSourceBlackbird;
    }
    else if (IsEqualGUID(&Record->EventHeader.ProviderId, &BLACKBIRDSC_PROVIDER_GUID_KERNEL_NETWORK))
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
            event.DeepSampleSize = (deepSampleSize > RTL_NUMBER_OF(event.DeepSample))
                                       ? RTL_NUMBER_OF(event.DeepSample)
                                       : deepSampleSize;
        }
        (void)ControllerEtwGetU32Property(Record, L"frameCount", &frameCount);
        event.StackCount = (frameCount > BLACKBIRD_IPC_MAX_ETW_STACK_FRAMES) ? BLACKBIRD_IPC_MAX_ETW_STACK_FRAMES
                                                                                : frameCount;
        for (i = 0; i < RTL_NUMBER_OF(stackPropertyNames); ++i)
        {
            (void)ControllerEtwGetU64Property(Record, stackPropertyNames[i], &event.Stack[i]);
        }
        if (ControllerEtwGetBoolProperty(Record, L"execProtect", &boolValue) && boolValue)
        {
            event.Flags |= BLACKBIRD_IPC_ETW_FLAG_HANDLE_EXEC_PROTECT;
        }
        if (ControllerEtwGetBoolProperty(Record, L"fromNtdll", &boolValue) && boolValue)
        {
            event.Flags |= BLACKBIRD_IPC_ETW_FLAG_HANDLE_FROM_NTDLL;
        }
        if (ControllerEtwGetBoolProperty(Record, L"fromExe", &boolValue) && boolValue)
        {
            event.Flags |= BLACKBIRD_IPC_ETW_FLAG_HANDLE_FROM_EXE;
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
        event.StackCount = (frameCount > BLACKBIRD_IPC_MAX_ETW_STACK_FRAMES) ? BLACKBIRD_IPC_MAX_ETW_STACK_FRAMES
                                                                                : frameCount;
        for (i = 0; i < RTL_NUMBER_OF(stackPropertyNames); ++i)
        {
            (void)ControllerEtwGetU64Property(Record, stackPropertyNames[i], &event.Stack[i]);
        }
        if (ControllerEtwGetBoolProperty(Record, L"gotStart", &boolValue) && boolValue)
        {
            event.Flags |= BLACKBIRD_IPC_ETW_FLAG_THREAD_GOT_START;
        }
        if (ControllerEtwGetBoolProperty(Record, L"gotRange", &boolValue) && boolValue)
        {
            event.Flags |= BLACKBIRD_IPC_ETW_FLAG_THREAD_GOT_RANGE;
        }
        if (ControllerEtwGetBoolProperty(Record, L"isRemoteCreator", &boolValue) && boolValue)
        {
            event.Flags |= BLACKBIRD_IPC_ETW_FLAG_THREAD_REMOTE_CREATOR;
        }
        if (ControllerEtwGetBoolProperty(Record, L"outsideMainImage", &boolValue) && boolValue)
        {
            event.Flags |= BLACKBIRD_IPC_ETW_FLAG_THREAD_OUTSIDE_MAIN_IMAGE;
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
            event.Flags |= BLACKBIRD_IPC_ETW_FLAG_PROCESS_IS_CREATE;
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
            event.Flags |= BLACKBIRD_IPC_ETW_FLAG_IMAGE_SYSTEM_MODE;
        }
        if (ControllerEtwGetBoolProperty(Record, L"isSignatureLevelKnown", &boolValue) && boolValue)
        {
            event.Flags |= BLACKBIRD_IPC_ETW_FLAG_IMAGE_SIGNATURE_KNOWN;
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
            event.Flags |= BLACKBIRD_IPC_ETW_FLAG_REGISTRY_HIGH_VALUE;
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
            event.Flags |= BLACKBIRD_IPC_ETW_FLAG_APC_DUPLICATE_OPERATION;
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
        (void)ControllerEtwGetI32Property(Record, L"status", &callStatus);

        if (callerPid != 0)
        {
            event.ProcessId = callerPid;
            event.CallerPid = callerPid;
        }
        if (callerTid != 0)
        {
            event.ThreadId = callerTid;
        }

        if (lstrcmpiA(apiName, "NtAllocateVirtualMemory") == 0)
        {
            event.Severity = 2u;
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), "USERMODE_MEMORY_ACTIVITY");
            (void)StringCchPrintfW(event.Reason, RTL_NUMBER_OF(event.Reason),
                                   L"memory.alloc base=0x%llX size=0x%llX allocType=0x%llX protect=0x%llX status=0x%08X",
                                   (unsigned long long)arg1, (unsigned long long)arg2, (unsigned long long)arg4,
                                   (unsigned long long)arg5, (unsigned int)callStatus);
        }
        else if (lstrcmpiA(apiName, "NtProtectVirtualMemory") == 0)
        {
            event.Severity = 3u;
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), "USERMODE_MEMORY_ACTIVITY");
            (void)StringCchPrintfW(event.Reason, RTL_NUMBER_OF(event.Reason),
                                   L"memory.protect base=0x%llX size=0x%llX newProtect=0x%llX oldProtect=0x%llX status=0x%08X",
                                   (unsigned long long)arg1, (unsigned long long)arg2, (unsigned long long)arg3,
                                   (unsigned long long)arg4, (unsigned int)callStatus);
        }
        else if (lstrcmpiA(apiName, "NtWriteVirtualMemory") == 0)
        {
            event.Severity = 3u;
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), "USERMODE_MEMORY_ACTIVITY");
            (void)StringCchPrintfW(event.Reason, RTL_NUMBER_OF(event.Reason),
                                   L"memory.write base=0x%llX size=0x%llX bytesWritten=0x%llX status=0x%08X",
                                   (unsigned long long)arg1, (unsigned long long)arg3, (unsigned long long)arg4,
                                   (unsigned int)callStatus);
        }
        else if (lstrcmpiA(apiName, "NtQueryInformationProcess") == 0 ||
                 lstrcmpiA(apiName, "NtQuerySystemInformation") == 0)
        {
            event.Severity = 3u;
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), "USERMODE_PROCESS_RECON");
            (void)StringCchPrintfW(event.Reason, RTL_NUMBER_OF(event.Reason),
                                   L"process.recon api=%S c0=0x%llX c1=0x%llX c2=0x%llX c3=0x%llX status=0x%08X", apiName,
                                   (unsigned long long)arg0, (unsigned long long)arg1, (unsigned long long)arg2,
                                   (unsigned long long)arg3, (unsigned int)callStatus);
        }
        else
        {
            event.Severity = 2u;
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), "USERMODE_HOOK_API_CALL");
            (void)StringCchPrintfW(
                event.Reason, RTL_NUMBER_OF(event.Reason),
                L"kind=kernel_ntapi api=%S c0=0x%llX c1=0x%llX c2=0x%llX c3=0x%llX c4=0x%llX c5=0x%llX c6=0x%llX c7=0x%llX status=0x%08X",
                apiName, (unsigned long long)arg0, (unsigned long long)arg1, (unsigned long long)arg2,
                (unsigned long long)arg3, (unsigned long long)arg4, (unsigned long long)arg5, (unsigned long long)arg6,
                (unsigned long long)arg7, (unsigned int)callStatus);
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
            ControllerExpandMonitoringGraph(sourcePid32, childPid32, BLACKBIRD_CONTROLLER_DRIVER_STREAM_MASK);
        }
    }

    if (!ControllerShouldForwardEtwRecord(Record, EventName, &event))
    {
        return;
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

    status = BLACKBIRDSCRunEtwSession(g_EtwSession);
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
    if (ErrorCode == ERROR_ACCESS_DENIED || ErrorCode == ERROR_PRIVILEGE_NOT_HELD ||
        ErrorCode == ERROR_NOT_SUPPORTED)
    {
        return FALSE;
    }
    return TRUE;
}

static VOID WINAPI ControllerEtwWarmupCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName, _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Record);
    UNREFERENCED_PARAMETER(EventName);
    UNREFERENCED_PARAMETER(Context);
}

static BOOL ControllerWarmupThreatIntelProvider(_Out_opt_ DWORD *ErrorCode)
{
    WCHAR warmupSessionName[96];
    BLACKBIRDSC_ETW_PROVIDER_CONFIG provider;
    BLACKBIRDSC_ETW_SESSION_CONFIG config;
    BLACKBIRDSC_ETW_SESSION *warmupSession = NULL;
    BOOL ok;
    DWORD err = ERROR_SUCCESS;

    ZeroMemory(&provider, sizeof(provider));
    provider.ProviderId = BLACKBIRDSC_PROVIDER_GUID_TI;
    provider.Level = TRACE_LEVEL_INFORMATION;
    provider.MatchAnyKeyword = ~0ULL;
    provider.MatchAllKeyword = 0;

    ZeroMemory(&config, sizeof(config));
    (void)StringCchPrintfW(warmupSessionName, RTL_NUMBER_OF(warmupSessionName), L"%ws-TiWarmup",
                           BLACKBIRD_CONTROLLER_ETW_SESSION_NAMEW);
    config.SessionName = warmupSessionName;
    config.Providers = &provider;
    config.ProviderCount = 1;
    config.Callback = ControllerEtwWarmupCallback;
    config.CallbackContext = NULL;

    ok = BLACKBIRDSCStartEtwSession(&config, &warmupSession);
    if (ok)
    {
        // Brief hold gives the TI provider a chance to fully activate.
        Sleep(120);
        BLACKBIRDSCStopEtwSession(warmupSession);
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

        ControllerLog("[ETW][WARN] TI inactive after subscribe (err=%lu). warmup+restart attempt %lu/%lu\n",
                      tiErr, attempt, maxAttempts);

        warmOk = ControllerWarmupThreatIntelProvider(&warmErr);
        if (!warmOk)
        {
            ControllerLog("[ETW][WARN] TI warmup failed attempt=%lu err=%lu\n", attempt, warmErr);
        }

        BLACKBIRDSCStopEtwSession(g_EtwSession);
        g_EtwSession = NULL;
        g_ThreatIntelEnabled = FALSE;

        if (!BLACKBIRDSCStartBlackbirdEtwSession(BLACKBIRD_CONTROLLER_ETW_SESSION_NAMEW, TRUE, ControllerEtwCallback,
                                                     NULL, &g_EtwSession, &g_ThreatIntelEnabled))
        {
            DWORD restartErr = GetLastError();
            tiErr = BLACKBIRDSCGetLastThreatIntelEnableError();
            ControllerLog("[ETW][WARN] restart after TI warmup failed attempt=%lu startErr=%lu tiErr=%lu\n",
                          attempt, restartErr, tiErr);
            if (attempt < maxAttempts)
            {
                Sleep(180 * attempt);
            }
            continue;
        }

        tiErr = BLACKBIRDSCGetLastThreatIntelEnableError();
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
    if (!BLACKBIRDSCStartBlackbirdEtwSession(BLACKBIRD_CONTROLLER_ETW_SESSION_NAMEW, TRUE, ControllerEtwCallback,
                                                 NULL, &g_EtwSession, &g_ThreatIntelEnabled))
    {
        DWORD err = GetLastError();
        g_ThreatIntelEnableError = err;
        ControllerLog("[WARN] BlackbirdController: failed to start ETW TI session name=%ws (%lu)\n",
                      BLACKBIRD_CONTROLLER_ETW_SESSION_NAMEW, err);
        g_EtwSession = NULL;
        g_ThreatIntelEnabled = FALSE;
        return FALSE;
    }

    tiErr = BLACKBIRDSCGetLastThreatIntelEnableError();
    g_ThreatIntelEnableError = tiErr;
    if (!g_ThreatIntelEnabled)
    {
        ControllerTryRecoverThreatIntelSession(tiErr);
        tiErr = BLACKBIRDSCGetLastThreatIntelEnableError();
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
        BLACKBIRDSCStopEtwSession(g_EtwSession);
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
        BLACKBIRDSCStopEtwSession(g_EtwSession);
        g_EtwSession = NULL;
    }

    if (g_EtwThread != NULL)
    {
        (void)WaitForSingleObject(g_EtwThread, 3000);
        CloseHandle(g_EtwThread);
        g_EtwThread = NULL;
    }

    ControllerStopEtwSessionByNameBestEffort(BLACKBIRD_CONTROLLER_ETW_SESSION_NAMEW, "service-stop");
    ControllerLog("[ETW] session stopped tiEvents=%ld detectionEvents=%ld\n",
                  InterlockedCompareExchange(&g_EtwTiEvents, 0, 0),
                  InterlockedCompareExchange(&g_EtwDetectionEvents, 0, 0));
}

static BOOL ControllerStartCore(VOID)
{
    DWORD serverThreadsStarted = 0;
    DWORD serverThreadIndex;

    if (g_LocksInitialized)
    {
        return TRUE;
    }

    InitializeCriticalSection(&g_ClientListLock);
    InitializeCriticalSection(&g_DriverLock);
    InitializeCriticalSection(&g_DriverConfigLock);
    g_LocksInitialized = TRUE;
    g_ClientList = NULL;
    g_ClientCount = 0;
    g_PidIndexCount = 0;
    ZeroMemory(g_ClientSlots, sizeof(g_ClientSlots));
    ZeroMemory(g_PidIndex, sizeof(g_PidIndex));

    ControllerLog("[*] BlackbirdController: core start requested\n");
    ControllerResetHollowingState();

    g_StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_StopEvent == NULL)
    {
        ControllerLog("[-] BlackbirdController: failed to create stop event (%lu)\n", GetLastError());
        return FALSE;
    }

    if (!ControllerSymbolServiceStart())
    {
        ControllerLog("[WARN] controller symbol service start failed (%lu)\n", GetLastError());
    }

    BLACKBIRDSCUseServiceProtocol();
    g_DriverHandle = BLACKBIRDSCOpenControlDevice();
    if (g_DriverHandle == INVALID_HANDLE_VALUE)
    {
        ControllerLog("[WARN] BlackbirdController: initial driver open failed (%lu). retrying in background.\n",
                      GetLastError());
    }
    else
    {
        ControllerLog("[DRIVER] initial open succeeded\n");
    }

    (void)ControllerStartEtwSession();
    (void)ControllerNodeNetworkStart();

    g_DriverPumpThread = CreateThread(NULL, 0, ControllerDriverPumpThreadProc, NULL, 0, NULL);
    if (g_DriverPumpThread == NULL)
    {
        ControllerLog("[-] BlackbirdController: failed to start driver pump thread (%lu)\n", GetLastError());
        return FALSE;
    }

    ZeroMemory(g_ServerAcceptThreads, sizeof(g_ServerAcceptThreads));
    for (serverThreadIndex = 0; serverThreadIndex < BLACKBIRD_CONTROLLER_SERVER_ACCEPT_THREADS; serverThreadIndex += 1)
    {
        HANDLE thread = CreateThread(NULL, 0, ControllerServerThreadProc, NULL, 0, NULL);
        if (thread == NULL)
        {
            ControllerLog("[WARN] BlackbirdController: failed to start server accept thread %lu (%lu)\n",
                          serverThreadIndex, GetLastError());
            break;
        }
        g_ServerAcceptThreads[serverThreadIndex] = thread;
        serverThreadsStarted += 1;
    }
    if (serverThreadsStarted == 0)
    {
        ControllerLog("[-] BlackbirdController: failed to start any server accept thread\n");
        return FALSE;
    }
    g_ServerThread = g_ServerAcceptThreads[0];
    if (serverThreadsStarted < BLACKBIRD_CONTROLLER_SERVER_ACCEPT_THREADS)
    {
        ControllerLog("[WARN] BlackbirdController: server accept thread pool reduced to %lu/%lu\n",
                      serverThreadsStarted, (DWORD)BLACKBIRD_CONTROLLER_SERVER_ACCEPT_THREADS);
    }

    ControllerLog("[*] BlackbirdController: IPC endpoint online at %ls\n", BLACKBIRD_IPC_PIPE_NAME);
    return TRUE;
}

static VOID ControllerWakeServerPipe(_In_ DWORD Attempts)
{
    DWORD index;

    for (index = 0; index < Attempts; index += 1)
    {
        HANDLE pipe =
            CreateFileW(BLACKBIRD_IPC_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (pipe != INVALID_HANDLE_VALUE)
        {
            CloseHandle(pipe);
        }
    }
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

    ControllerWakeServerPipe((DWORD)BLACKBIRD_CONTROLLER_SERVER_ACCEPT_THREADS);

    for (threadIndex = 0; threadIndex < BLACKBIRD_CONTROLLER_SERVER_ACCEPT_THREADS; threadIndex += 1)
    {
        HANDLE thread = g_ServerAcceptThreads[threadIndex];
        if (thread != NULL)
        {
            (void)WaitForSingleObject(thread, 3000);
            CloseHandle(thread);
            g_ServerAcceptThreads[threadIndex] = NULL;
        }
    }
    g_ServerThread = NULL;

    if (g_DriverPumpThread != NULL)
    {
        (void)WaitForSingleObject(g_DriverPumpThread, 3000);
        CloseHandle(g_DriverPumpThread);
        g_DriverPumpThread = NULL;
    }

    EnterCriticalSection(&g_ClientListLock);
    {
        PBLACKBIRD_CONTROLLER_CLIENT client;
        for (client = g_ClientList; client != NULL; client = client->Next)
        {
            if (client->Pipe != INVALID_HANDLE_VALUE)
            {
                (void)CancelIoEx(client->Pipe, NULL);
                (void)DisconnectNamedPipe(client->Pipe);
            }
        }
    }
    LeaveCriticalSection(&g_ClientListLock);

    while (waitMs < 2000)
    {
        DWORD remaining;
        EnterCriticalSection(&g_ClientListLock);
        remaining = g_ClientCount;
        LeaveCriticalSection(&g_ClientListLock);
        if (remaining == 0)
        {
            break;
        }
        Sleep(50);
        waitMs += 50;
    }

    ControllerStopEtwSession();
    ControllerNodeNetworkStop();

    EnterCriticalSection(&g_DriverLock);
    if (g_DriverHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_DriverHandle);
        g_DriverHandle = INVALID_HANDLE_VALUE;
    }
    LeaveCriticalSection(&g_DriverLock);

    if (g_StopEvent != NULL)
    {
        CloseHandle(g_StopEvent);
        g_StopEvent = NULL;
    }

    ControllerSymbolServiceStop();
    ControllerResetHollowingState();

    ControllerLog("[*] BlackbirdController: core stopped\n");

}

static DWORD WINAPI ControllerServiceControlHandlerEx(_In_ DWORD ControlCode, _In_ DWORD EventType, _In_ LPVOID EventData,
                                                      _In_ LPVOID Context)
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
    g_ServiceStatusHandle = RegisterServiceCtrlHandlerExW(BLACKBIRD_CONTROLLER_SERVICE_NAMEW,
                                                          ControllerServiceControlHandlerEx, NULL);
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
    SERVICE_TABLE_ENTRYW table[] = {{(LPWSTR)BLACKBIRD_CONTROLLER_SERVICE_NAMEW, ControllerServiceMain},
                                    {NULL, NULL}};
    BOOL runAsConsole = FALSE;
    int i;

    // Open the log file before any other work so every log call, including early failures,
    // is captured.  ControllerLogInit is idempotent.
    ControllerLogInit();
    ControllerLog("[*] BlackbirdController: wmain entered pid=%lu\n", GetCurrentProcessId());

    for (i = 1; i < argc; ++i)
    {
        if (_wcsicmp(argv[i], L"--console") == 0)
        {
            runAsConsole = TRUE;
            break;
        }
    }

    if (runAsConsole)
    {
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


