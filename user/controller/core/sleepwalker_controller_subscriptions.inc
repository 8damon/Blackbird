static BOOL ControllerIsValidStreamMask(_In_ DWORD StreamMask)
{
    return ((StreamMask & SLEEPWALKER_CONTROLLER_DRIVER_STREAM_MASK) != 0);
}

static BOOL ControllerRecordMatchesSubscription(_In_ const SLEEPWALKER_EVENT_RECORD *Record, _In_ DWORD ProcessId,
                                                _In_ DWORD StreamMask)
{
    UINT32 recordMask;
    DWORD primary = 0;
    DWORD secondary = 0;

    if (Record == NULL || ProcessId == 0)
    {
        return FALSE;
    }

    recordMask = Record->Header.StreamMask;
    if ((recordMask & StreamMask) == 0)
    {
        return FALSE;
    }

    if (Record->Header.Type == SleepwalkerEventTypeHandle)
    {
        primary = (DWORD)Record->Data.Handle.CallerPid;
        secondary = (DWORD)Record->Data.Handle.TargetPid;
    }
    else if (Record->Header.Type == SleepwalkerEventTypeThread)
    {
        primary = (DWORD)Record->Data.Thread.ProcessId;
        secondary = (DWORD)Record->Data.Thread.CreatorPid;
    }
    else
    {
        return FALSE;
    }

    return (ProcessId == primary || ProcessId == secondary);
}

static BOOL ControllerClientHasMatchLocked(_In_ const SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                           _In_ const SLEEPWALKER_EVENT_RECORD *Record)
{
    DWORD i;

    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (ControllerRecordMatchesSubscription(Record, Client->Subscriptions[i].ProcessId,
                                                Client->Subscriptions[i].StreamMask))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static VOID ControllerClientFreeQueueLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client)
{
    PSLEEPWALKER_CONTROLLER_EVENT_NODE node = Client->QueueHead;

    while (node != NULL)
    {
        PSLEEPWALKER_CONTROLLER_EVENT_NODE next = node->Next;
        free(node);
        node = next;
    }

    Client->QueueHead = NULL;
    Client->QueueTail = NULL;
    Client->QueueDepth = 0;
}

static VOID ControllerClientFreeEtwQueueLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client)
{
    PSLEEPWALKER_CONTROLLER_ETW_EVENT_NODE node = Client->EtwQueueHead;

    while (node != NULL)
    {
        PSLEEPWALKER_CONTROLLER_ETW_EVENT_NODE next = node->Next;
        free(node);
        node = next;
    }

    Client->EtwQueueHead = NULL;
    Client->EtwQueueTail = NULL;
    Client->EtwQueueDepth = 0;
}

static BOOL ControllerClientEnqueueRecordLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                                _In_ const SLEEPWALKER_EVENT_RECORD *Record)
{
    PSLEEPWALKER_CONTROLLER_EVENT_NODE node;

    if (Client->QueueDepth >= SLEEPWALKER_CONTROLLER_MAX_CLIENT_QUEUE_DEPTH)
    {
        Client->DroppedEvents += 1;
        return FALSE;
    }

    node = (PSLEEPWALKER_CONTROLLER_EVENT_NODE)calloc(1, sizeof(*node));
    if (node == NULL)
    {
        Client->DroppedEvents += 1;
        return FALSE;
    }

    (void)CopyMemory(&node->Record, Record, sizeof(node->Record));
    node->Next = NULL;
    if (Client->QueueTail == NULL)
    {
        Client->QueueHead = node;
        Client->QueueTail = node;
    }
    else
    {
        Client->QueueTail->Next = node;
        Client->QueueTail = node;
    }
    Client->QueueDepth += 1;
    return TRUE;
}

static BOOL ControllerClientDequeueRecordLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                                _Out_ SLEEPWALKER_EVENT_RECORD *Record)
{
    PSLEEPWALKER_CONTROLLER_EVENT_NODE node;

    if (Client->QueueHead == NULL)
    {
        return FALSE;
    }

    node = Client->QueueHead;
    Client->QueueHead = node->Next;
    if (Client->QueueHead == NULL)
    {
        Client->QueueTail = NULL;
    }
    if (Client->QueueDepth > 0)
    {
        Client->QueueDepth -= 1;
    }

    (void)CopyMemory(Record, &node->Record, sizeof(*Record));
    free(node);
    return TRUE;
}

static BOOL ControllerClientEnqueueEtwEventLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                                  _In_ const SLEEPWALKER_IPC_ETW_EVENT *Event)
{
    PSLEEPWALKER_CONTROLLER_ETW_EVENT_NODE node;

    if (Client->EtwQueueDepth >= SLEEPWALKER_CONTROLLER_MAX_CLIENT_ETW_QUEUE_DEPTH)
    {
        Client->EtwDroppedEvents += 1;
        return FALSE;
    }

    node = (PSLEEPWALKER_CONTROLLER_ETW_EVENT_NODE)calloc(1, sizeof(*node));
    if (node == NULL)
    {
        Client->EtwDroppedEvents += 1;
        return FALSE;
    }

    (void)CopyMemory(&node->Event, Event, sizeof(node->Event));
    node->Next = NULL;
    if (Client->EtwQueueTail == NULL)
    {
        Client->EtwQueueHead = node;
        Client->EtwQueueTail = node;
    }
    else
    {
        Client->EtwQueueTail->Next = node;
        Client->EtwQueueTail = node;
    }
    Client->EtwQueueDepth += 1;
    return TRUE;
}

static BOOL ControllerClientDequeueEtwEventLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                                  _Out_ SLEEPWALKER_IPC_ETW_EVENT *Event)
{
    PSLEEPWALKER_CONTROLLER_ETW_EVENT_NODE node;

    if (Client->EtwQueueHead == NULL)
    {
        return FALSE;
    }

    node = Client->EtwQueueHead;
    Client->EtwQueueHead = node->Next;
    if (Client->EtwQueueHead == NULL)
    {
        Client->EtwQueueTail = NULL;
    }
    if (Client->EtwQueueDepth > 0)
    {
        Client->EtwQueueDepth -= 1;
    }

    (void)CopyMemory(Event, &node->Event, sizeof(*Event));
    free(node);
    return TRUE;
}

static BOOL ControllerCollectUnionPidSet(_Out_writes_(SLEEPWALKER_MAX_PID_LIST) DWORD *ProcessIds,
                                         _Out_ DWORD *ProcessCount)
{
    PSLEEPWALKER_CONTROLLER_CLIENT client;
    DWORD outCount = 0;

    if (ProcessIds == NULL || ProcessCount == NULL)
    {
        return FALSE;
    }

    EnterCriticalSection(&g_ClientListLock);
    for (client = g_ClientList; client != NULL; client = client->Next)
    {
        DWORD i;

        EnterCriticalSection(&client->Lock);
        for (i = 0; i < client->SubscriptionCount; ++i)
        {
            DWORD pid = client->Subscriptions[i].ProcessId;
            DWORD j;
            BOOL seen = FALSE;

            if (pid == 0)
            {
                continue;
            }

            for (j = 0; j < outCount; ++j)
            {
                if (ProcessIds[j] == pid)
                {
                    seen = TRUE;
                    break;
                }
            }

            if (!seen && outCount < SLEEPWALKER_MAX_PID_LIST)
            {
                ProcessIds[outCount++] = pid;
            }
        }
        LeaveCriticalSection(&client->Lock);
    }
    LeaveCriticalSection(&g_ClientListLock);

    *ProcessCount = outCount;
    return TRUE;
}

static BOOL ControllerApplyDriverSubscriptions(VOID)
{
    DWORD desiredPids[SLEEPWALKER_MAX_PID_LIST];
    DWORD desiredCount = 0;
    BOOL ok = TRUE;
    DWORD i;

    ZeroMemory(desiredPids, sizeof(desiredPids));
    if (!ControllerCollectUnionPidSet(desiredPids, &desiredCount))
    {
        return FALSE;
    }

    EnterCriticalSection(&g_DriverConfigLock);
    EnterCriticalSection(&g_DriverLock);

    if (g_DriverHandle == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_DEVICE_NOT_CONNECTED);
        ok = FALSE;
        goto Exit;
    }

    if (desiredCount == 0)
    {
        for (i = 0; i < g_ProgrammedPidCount; ++i)
        {
            (void)SLEEPWALKERSCUnsubscribe(g_DriverHandle, g_ProgrammedPids[i]);
        }
        g_ProgrammedPidCount = 0;
        ZeroMemory(g_ProgrammedPids, sizeof(g_ProgrammedPids));
        ControllerLog("[DRIVER] subscription set cleared\n");
        goto Exit;
    }

    ok = SLEEPWALKERSCSetPids(g_DriverHandle, desiredPids, desiredCount, SLEEPWALKER_CONTROLLER_DRIVER_STREAM_MASK);
    if (ok)
    {
        g_ProgrammedPidCount = desiredCount;
        ZeroMemory(g_ProgrammedPids, sizeof(g_ProgrammedPids));
        for (i = 0; i < desiredCount; ++i)
        {
            g_ProgrammedPids[i] = desiredPids[i];
        }
        ControllerLog("[DRIVER] programmed pid subscriptions count=%lu streamMask=0x%08lX\n", desiredCount,
                      SLEEPWALKER_CONTROLLER_DRIVER_STREAM_MASK);
    }
    else
    {
        ControllerLog("[DRIVER][WARN] failed to program pid subscriptions count=%lu (%lu)\n", desiredCount,
                      GetLastError());
    }

Exit:
    LeaveCriticalSection(&g_DriverLock);
    LeaveCriticalSection(&g_DriverConfigLock);
    return ok;
}
static VOID ControllerDispatchDriverRecord(_In_ const SLEEPWALKER_EVENT_RECORD *Record)
{
    PSLEEPWALKER_CONTROLLER_CLIENT client;

    EnterCriticalSection(&g_ClientListLock);
    for (client = g_ClientList; client != NULL; client = client->Next)
    {
        EnterCriticalSection(&client->Lock);
        if (ControllerClientHasMatchLocked(client, Record))
        {
            (void)ControllerClientEnqueueRecordLocked(client, Record);
        }
        LeaveCriticalSection(&client->Lock);
    }
    LeaveCriticalSection(&g_ClientListLock);
}

static BOOL ControllerEtwGetPropertyRaw(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name,
                                        _Outptr_result_bytebuffer_(*OutSize) PBYTE *OutBuffer, _Out_ ULONG *OutSize)
{
    TDHSTATUS status;
    PROPERTY_DATA_DESCRIPTOR descriptor;

    if (Record == NULL || Name == NULL || OutBuffer == NULL || OutSize == NULL)
    {
        return FALSE;
    }

    *OutBuffer = NULL;
    *OutSize = 0;

    ZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.PropertyName = (ULONGLONG)(ULONG_PTR)Name;
    descriptor.ArrayIndex = ULONG_MAX;

    status = TdhGetPropertySize(Record, 0, NULL, 1, &descriptor, OutSize);
    if (status != ERROR_SUCCESS || *OutSize == 0)
    {
        return FALSE;
    }

    *OutBuffer = (PBYTE)calloc(1, *OutSize + sizeof(WCHAR));
    if (*OutBuffer == NULL)
    {
        *OutSize = 0;
        return FALSE;
    }

    status = TdhGetProperty(Record, 0, NULL, 1, &descriptor, *OutSize, *OutBuffer);
    if (status != ERROR_SUCCESS)
    {
        free(*OutBuffer);
        *OutBuffer = NULL;
        *OutSize = 0;
        return FALSE;
    }

    return TRUE;
}

static BOOL ControllerEtwGetU64Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONGLONG *Value)
{
    PBYTE raw = NULL;
    ULONG size = 0;

    if (Value == NULL)
    {
        return FALSE;
    }
    *Value = 0;

    if (!ControllerEtwGetPropertyRaw(Record, Name, &raw, &size))
    {
        return FALSE;
    }

    if (size >= sizeof(ULONGLONG))
    {
        *Value = *(ULONGLONG *)raw;
        free(raw);
        return TRUE;
    }
    if (size >= sizeof(ULONG))
    {
        *Value = *(ULONG *)raw;
        free(raw);
        return TRUE;
    }

    free(raw);
    return FALSE;
}

static BOOL ControllerEtwGetU32Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONG *Value)
{
    PBYTE raw = NULL;
    ULONG size = 0;

    if (Value == NULL)
    {
        return FALSE;
    }
    *Value = 0;

    if (!ControllerEtwGetPropertyRaw(Record, Name, &raw, &size))
    {
        return FALSE;
    }
    if (size >= sizeof(ULONG))
    {
        *Value = *(ULONG *)raw;
        free(raw);
        return TRUE;
    }

    free(raw);
    return FALSE;
}

static BOOL ControllerEtwGetAnsiProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name,
                                         _Out_writes_z_(OutputChars) PSTR Output, _In_ size_t OutputChars)
{
    PBYTE raw = NULL;
    ULONG size = 0;

    if (Output == NULL || OutputChars == 0)
    {
        return FALSE;
    }
    Output[0] = '\0';

    if (!ControllerEtwGetPropertyRaw(Record, Name, &raw, &size))
    {
        return FALSE;
    }

    if (size > 0)
    {
        (void)StringCchCopyA(Output, OutputChars, (PCSTR)raw);
        free(raw);
        return TRUE;
    }

    free(raw);
    return FALSE;
}

static BOOL ControllerEtwEventMatchesPid(_In_ const SLEEPWALKER_IPC_ETW_EVENT *Event, _In_ DWORD ProcessId)
{
    if (Event == NULL || ProcessId == 0)
    {
        return FALSE;
    }

    if (Event->EventProcessId == ProcessId)
    {
        return TRUE;
    }
    if (Event->PrimaryPid != 0 && Event->PrimaryPid <= 0xFFFFFFFFull && (DWORD)Event->PrimaryPid == ProcessId)
    {
        return TRUE;
    }
    if (Event->SecondaryPid != 0 && Event->SecondaryPid <= 0xFFFFFFFFull && (DWORD)Event->SecondaryPid == ProcessId)
    {
        return TRUE;
    }

    return FALSE;
}

static BOOL ControllerClientHasEtwMatchLocked(_In_ const SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                              _In_ const SLEEPWALKER_IPC_ETW_EVENT *Event)
{
    DWORD i;

    if (Client == NULL || Event == NULL)
    {
        return FALSE;
    }

    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (ControllerEtwEventMatchesPid(Event, Client->Subscriptions[i].ProcessId))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static VOID ControllerDispatchEtwEvent(_In_ const SLEEPWALKER_IPC_ETW_EVENT *Event)
{
    PSLEEPWALKER_CONTROLLER_CLIENT client;

    if (Event == NULL)
    {
        return;
    }

    EnterCriticalSection(&g_ClientListLock);
    for (client = g_ClientList; client != NULL; client = client->Next)
    {
        EnterCriticalSection(&client->Lock);
        if (ControllerClientHasEtwMatchLocked(client, Event))
        {
            (void)ControllerClientEnqueueEtwEventLocked(client, Event);
        }
        LeaveCriticalSection(&client->Lock);
    }
    LeaveCriticalSection(&g_ClientListLock);
}

