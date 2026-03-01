static BOOL ControllerProxyQueryProcessImage(_In_ DWORD ProcessId,
                                             _Out_ SLEEPWALKER_QUERY_PROCESS_IMAGE_RESPONSE *Response)
{
    WCHAR imagePath[SLEEPWALKER_MAX_IMAGE_PATH_CHARS];
    BOOL ok;

    if (Response == NULL || ProcessId == 0)
    {
        return FALSE;
    }

    ZeroMemory(Response, sizeof(*Response));
    Response->ProcessId = ProcessId;
    imagePath[0] = L'\0';

    EnterCriticalSection(&g_DriverLock);
    ok = (g_DriverHandle != INVALID_HANDLE_VALUE) &&
         SLEEPWALKERSCQueryProcessImagePath(g_DriverHandle, ProcessId, imagePath, RTL_NUMBER_OF(imagePath));
    LeaveCriticalSection(&g_DriverLock);

    if (!ok)
    {
        Response->Status = (INT32)HRESULT_FROM_WIN32(GetLastError());
        return FALSE;
    }

    Response->Status = 0;
    (void)StringCchCopyW(Response->ImagePath, RTL_NUMBER_OF(Response->ImagePath), imagePath);
    return TRUE;
}

static BOOL ControllerProxySetShutdownMode(VOID)
{
    BOOL ok;

    EnterCriticalSection(&g_DriverLock);
    ok = (g_DriverHandle != INVALID_HANDLE_VALUE) && SLEEPWALKERSCSetShutdownMode(g_DriverHandle);
    LeaveCriticalSection(&g_DriverLock);
    return ok;
}

static BOOL ControllerValidatePacket(_In_ const SLEEPWALKER_IPC_PACKET *Packet, _In_ UINT16 ExpectedType)
{
    if (Packet == NULL)
    {
        return FALSE;
    }

    if (Packet->Magic != SLEEPWALKER_IPC_MAGIC)
    {
        return FALSE;
    }

    if (Packet->Version != SLEEPWALKER_IPC_VERSION)
    {
        return FALSE;
    }

    if (Packet->PacketType != ExpectedType)
    {
        return FALSE;
    }

    return TRUE;
}

static VOID ControllerPrepareResponse(_In_ const SLEEPWALKER_IPC_PACKET *Request, _Out_ SLEEPWALKER_IPC_PACKET *Response)
{
    ZeroMemory(Response, sizeof(*Response));
    Response->Magic = SLEEPWALKER_IPC_MAGIC;
    Response->Version = SLEEPWALKER_IPC_VERSION;
    Response->PacketType = SleepwalkerIpcPacketResponse;
    Response->Command = Request->Command;
    Response->Sequence = Request->Sequence;
    Response->Status = ERROR_SUCCESS;
}

static DWORD ControllerClientSubscribe(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                       _In_ const SLEEPWALKER_SUBSCRIBE_REQUEST *Request)
{
    DWORD i;

    if (Client == NULL || Request == NULL || Request->ProcessId == 0 || !ControllerIsValidStreamMask(Request->StreamMask))
    {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&Client->Lock);
    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (Client->Subscriptions[i].ProcessId == Request->ProcessId)
        {
            Client->Subscriptions[i].StreamMask |= Request->StreamMask;
            if (Client->Subscriptions[i].Dynamic)
            {
                Client->Subscriptions[i].Dynamic = FALSE;
                Client->Subscriptions[i].SourceProcessId = 0;
                Client->Subscriptions[i].Depth = 0;
                Client->Subscriptions[i].LastSeenTick = 0;
            }
            LeaveCriticalSection(&Client->Lock);
            ControllerLog("[IPC] subscribe update clientPid=%lu targetPid=%lu streamMask=0x%08lX\n", Client->ProcessId,
                          Request->ProcessId, Request->StreamMask);
            if (!ControllerApplyDriverSubscriptions())
            {
                return GetLastError();
            }
            return ERROR_SUCCESS;
        }
    }

    if (Client->SubscriptionCount >= SLEEPWALKER_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS)
    {
        LeaveCriticalSection(&Client->Lock);
        return ERROR_INSUFFICIENT_BUFFER;
    }

    Client->Subscriptions[Client->SubscriptionCount].ProcessId = Request->ProcessId;
    Client->Subscriptions[Client->SubscriptionCount].StreamMask = Request->StreamMask;
    Client->Subscriptions[Client->SubscriptionCount].Dynamic = FALSE;
    Client->Subscriptions[Client->SubscriptionCount].SourceProcessId = 0;
    Client->Subscriptions[Client->SubscriptionCount].Depth = 0;
    Client->Subscriptions[Client->SubscriptionCount].LastSeenTick = 0;
    Client->SubscriptionCount += 1;
    LeaveCriticalSection(&Client->Lock);
    ControllerLog("[IPC] subscribe add clientPid=%lu targetPid=%lu streamMask=0x%08lX\n", Client->ProcessId,
                  Request->ProcessId, Request->StreamMask);

    if (!ControllerApplyDriverSubscriptions())
    {
        return GetLastError();
    }

    return ERROR_SUCCESS;
}

static DWORD ControllerClientUnsubscribe(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                         _In_ const SLEEPWALKER_UNSUBSCRIBE_REQUEST *Request)
{
    DWORD i;
    DWORD removedPid = 0;
    BOOL changed = FALSE;

    if (Client == NULL || Request == NULL || Request->ProcessId == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&Client->Lock);
    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (Client->Subscriptions[i].ProcessId == Request->ProcessId)
        {
            removedPid = Client->Subscriptions[i].ProcessId;
            ControllerRemoveSubscriptionAtLocked(Client, i);
            changed = TRUE;
            if (removedPid != 0)
            {
                changed |= ControllerDropDynamicDescendantsLocked(Client, removedPid);
            }
            LeaveCriticalSection(&Client->Lock);
            ControllerLog("[IPC] unsubscribe clientPid=%lu targetPid=%lu\n", Client->ProcessId, Request->ProcessId);
            if (changed)
            {
                (void)ControllerApplyDriverSubscriptions();
            }
            return ERROR_SUCCESS;
        }
    }
    LeaveCriticalSection(&Client->Lock);

    return ERROR_NOT_FOUND;
}

static DWORD ControllerClientSetPids(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                     _In_ const SLEEPWALKER_SET_PIDS_REQUEST *Request)
{
    DWORD i;

    if (Client == NULL || Request == NULL || Request->ProcessCount > SLEEPWALKER_MAX_PID_LIST ||
        Request->ProcessCount == 0 || !ControllerIsValidStreamMask(Request->StreamMask))
    {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&Client->Lock);
    Client->SubscriptionCount = 0;
    ZeroMemory(Client->Subscriptions, sizeof(Client->Subscriptions));
    for (i = 0; i < Request->ProcessCount; ++i)
    {
        DWORD pid = Request->ProcessIds[i];
        DWORD j;
        BOOL seen = FALSE;

        if (pid == 0)
        {
            continue;
        }

        for (j = 0; j < Client->SubscriptionCount; ++j)
        {
            if (Client->Subscriptions[j].ProcessId == pid)
            {
                Client->Subscriptions[j].StreamMask |= Request->StreamMask;
                Client->Subscriptions[j].Dynamic = FALSE;
                Client->Subscriptions[j].SourceProcessId = 0;
                Client->Subscriptions[j].Depth = 0;
                Client->Subscriptions[j].LastSeenTick = 0;
                seen = TRUE;
                break;
            }
        }

        if (!seen && Client->SubscriptionCount < SLEEPWALKER_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS)
        {
            Client->Subscriptions[Client->SubscriptionCount].ProcessId = pid;
            Client->Subscriptions[Client->SubscriptionCount].StreamMask = Request->StreamMask;
            Client->Subscriptions[Client->SubscriptionCount].Dynamic = FALSE;
            Client->Subscriptions[Client->SubscriptionCount].SourceProcessId = 0;
            Client->Subscriptions[Client->SubscriptionCount].Depth = 0;
            Client->Subscriptions[Client->SubscriptionCount].LastSeenTick = 0;
            Client->SubscriptionCount += 1;
        }
    }
    LeaveCriticalSection(&Client->Lock);

    if (Client->SubscriptionCount == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }
    ControllerLog("[IPC] set-pids clientPid=%lu count=%lu streamMask=0x%08lX\n", Client->ProcessId,
                  Client->SubscriptionCount, Request->StreamMask);

    if (!ControllerApplyDriverSubscriptions())
    {
        return GetLastError();
    }

    return ERROR_SUCCESS;
}

static DWORD ControllerClientGetEvent(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client, _In_ DWORD TimeoutMs,
                                      _Out_ SLEEPWALKER_EVENT_RECORD *Record)
{
    DWORD waited = 0;

    if (Client == NULL || Record == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    for (;;)
    {
        BOOL dequeued = FALSE;

        EnterCriticalSection(&Client->Lock);
        dequeued = ControllerClientDequeueRecordLocked(Client, Record);
        LeaveCriticalSection(&Client->Lock);

        if (dequeued)
        {
            return ERROR_SUCCESS;
        }
        if (ControllerShouldStop())
        {
            return ERROR_OPERATION_ABORTED;
        }
        if (TimeoutMs != INFINITE && waited >= TimeoutMs)
        {
            return ERROR_NO_MORE_ITEMS;
        }

        Sleep(20);
        if (TimeoutMs != INFINITE)
        {
            waited += 20;
        }
    }
}

static DWORD ControllerClientGetEtwEvent(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client, _In_ DWORD TimeoutMs,
                                         _Out_ SLEEPWALKER_IPC_ETW_EVENT *Event)
{
    DWORD waited = 0;

    if (Client == NULL || Event == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    for (;;)
    {
        BOOL dequeued = FALSE;

        EnterCriticalSection(&Client->Lock);
        dequeued = ControllerClientDequeueEtwEventLocked(Client, Event);
        LeaveCriticalSection(&Client->Lock);

        if (dequeued)
        {
            return ERROR_SUCCESS;
        }
        if (ControllerShouldStop())
        {
            return ERROR_OPERATION_ABORTED;
        }
        if (TimeoutMs != INFINITE && waited >= TimeoutMs)
        {
            return ERROR_NO_MORE_ITEMS;
        }

        Sleep(20);
        if (TimeoutMs != INFINITE)
        {
            waited += 20;
        }
    }
}

static DWORD ControllerClientGetStats(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                      _Out_ SLEEPWALKER_STATS_RESPONSE *Stats)
{
    if (Client == NULL || Stats == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    ZeroMemory(Stats, sizeof(*Stats));
    EnterCriticalSection(&Client->Lock);
    Stats->SubscriptionCount = Client->SubscriptionCount;
    Stats->QueueDepth = Client->QueueDepth;
    Stats->DroppedEvents = Client->DroppedEvents;
    LeaveCriticalSection(&Client->Lock);

    return ERROR_SUCCESS;
}

static PCSTR ControllerCommandName(_In_ UINT32 Command)
{
    switch (Command)
    {
    case SleepwalkerIpcCommandHandshake:
        return "handshake";
    case SleepwalkerIpcCommandSubscribe:
        return "subscribe";
    case SleepwalkerIpcCommandUnsubscribe:
        return "unsubscribe";
    case SleepwalkerIpcCommandSetPids:
        return "set-pids";
    case SleepwalkerIpcCommandGetEvent:
        return "get-event";
    case SleepwalkerIpcCommandGetStats:
        return "get-stats";
    case SleepwalkerIpcCommandQueryProcessImage:
        return "query-process-image";
    case SleepwalkerIpcCommandSetShutdownMode:
        return "set-shutdown-mode";
    case SleepwalkerIpcCommandGetEtwEvent:
        return "get-etw-event";
    default:
        return "unknown";
    }
}

static DWORD ControllerHandleClientCommand(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                           _In_ const SLEEPWALKER_IPC_PACKET *Request,
                                           _Out_ SLEEPWALKER_IPC_PACKET *Response)
{
    DWORD err = ERROR_SUCCESS;

    ControllerPrepareResponse(Request, Response);

    switch (Request->Command)
    {
    case SleepwalkerIpcCommandHandshake:
        Response->Payload.HandshakeResponse.NegotiatedVersion = SLEEPWALKER_IPC_VERSION;
        Response->Payload.HandshakeResponse.Capabilities =
            SLEEPWALKER_IPC_CAP_DRIVER_PROXY | SLEEPWALKER_IPC_CAP_ETW_TI_SESSION | SLEEPWALKER_IPC_CAP_ETW_TI_UPLINK;
        Response->Payload.HandshakeResponse.ThreatIntelEnabled = g_ThreatIntelEnabled ? 1u : 0u;
        Response->Payload.HandshakeResponse.Reserved = g_ThreatIntelEnableError;
        break;
    case SleepwalkerIpcCommandSubscribe:
        err = ControllerClientSubscribe(Client, &Request->Payload.SubscribeRequest);
        break;
    case SleepwalkerIpcCommandUnsubscribe:
        err = ControllerClientUnsubscribe(Client, &Request->Payload.UnsubscribeRequest);
        break;
    case SleepwalkerIpcCommandSetPids:
        err = ControllerClientSetPids(Client, &Request->Payload.SetPidsRequest);
        break;
    case SleepwalkerIpcCommandGetEvent:
        err = ControllerClientGetEvent(Client, Request->Payload.GetEventRequest.TimeoutMs, &Response->Payload.EventRecord);
        break;
    case SleepwalkerIpcCommandGetStats:
        err = ControllerClientGetStats(Client, &Response->Payload.StatsResponse);
        break;
    case SleepwalkerIpcCommandQueryProcessImage:
        if (!ControllerProxyQueryProcessImage(Request->Payload.QueryProcessImageRequest.ProcessId,
                                              &Response->Payload.QueryProcessImageResponse))
        {
            err = GetLastError();
            if (err == ERROR_SUCCESS)
            {
                err = ERROR_NOT_FOUND;
            }
        }
        break;
    case SleepwalkerIpcCommandSetShutdownMode:
        if (!ControllerProxySetShutdownMode())
        {
            err = GetLastError();
        }
        break;
    case SleepwalkerIpcCommandGetEtwEvent:
        err = ControllerClientGetEtwEvent(Client, Request->Payload.GetEventRequest.TimeoutMs, &Response->Payload.EtwEvent);
        break;
    default:
        err = ERROR_INVALID_FUNCTION;
        break;
    }

    Response->Status = err;
    if (Request->Command != SleepwalkerIpcCommandGetEvent && Request->Command != SleepwalkerIpcCommandGetEtwEvent)
    {
        ControllerLog("[IPC] cmd=%s seq=%lu clientPid=%lu session=%lu status=%lu\n",
                      ControllerCommandName(Request->Command), Request->Sequence, Client->ProcessId, Client->SessionId,
                      err);
    }
    else if (err != ERROR_SUCCESS && err != ERROR_NO_MORE_ITEMS)
    {
        ControllerLog("[IPC][WARN] cmd=%s seq=%lu clientPid=%lu session=%lu status=%lu\n",
                      ControllerCommandName(Request->Command), Request->Sequence, Client->ProcessId, Client->SessionId,
                      err);
    }
    return err;
}

static VOID ControllerDetachClient(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client)
{
    PSLEEPWALKER_CONTROLLER_CLIENT *pp;

    if (Client == NULL)
    {
        return;
    }

    EnterCriticalSection(&g_ClientListLock);
    pp = &g_ClientList;
    while (*pp != NULL)
    {
        if (*pp == Client)
        {
            *pp = Client->Next;
            if (g_ClientCount > 0)
            {
                g_ClientCount -= 1;
            }
            ControllerLog("[IPC] active clients=%lu\n", g_ClientCount);
            break;
        }
        pp = &(*pp)->Next;
    }
    LeaveCriticalSection(&g_ClientListLock);

    ControllerMarkDriverSubscriptionsDirty();
}
static DWORD WINAPI ControllerClientThreadProc(_In_ LPVOID Context)
{
    SLEEPWALKER_CONTROLLER_CLIENT *client = (SLEEPWALKER_CONTROLLER_CLIENT *)Context;
    SLEEPWALKER_IPC_PACKET request;
    SLEEPWALKER_IPC_PACKET response;
    DWORD disconnectErr = ERROR_SUCCESS;

    if (client == NULL)
    {
        return 1;
    }

    for (;;)
    {
        DWORD bytesRead = 0;
        DWORD bytesWritten = 0;
        BOOL ok;

        if (ControllerShouldStop())
        {
            break;
        }

        ZeroMemory(&request, sizeof(request));
        ok = ReadFile(client->Pipe, &request, sizeof(request), &bytesRead, NULL);
        if (!ok || bytesRead != sizeof(request))
        {
            disconnectErr = GetLastError();
            break;
        }
        if (!ControllerValidatePacket(&request, SleepwalkerIpcPacketRequest))
        {
            disconnectErr = ERROR_BAD_FORMAT;
            break;
        }

        (void)ControllerHandleClientCommand(client, &request, &response);
        ok = WriteFile(client->Pipe, &response, sizeof(response), &bytesWritten, NULL);
        if (!ok || bytesWritten != sizeof(response))
        {
            disconnectErr = GetLastError();
            break;
        }
    }

    ControllerDetachClient(client);
    if (client->Pipe != INVALID_HANDLE_VALUE)
    {
        (void)DisconnectNamedPipe(client->Pipe);
        CloseHandle(client->Pipe);
        client->Pipe = INVALID_HANDLE_VALUE;
    }
    EnterCriticalSection(&client->Lock);
    ControllerLog("[IPC] client disconnected pid=%lu session=%lu subscriptions=%lu queueDepth=%lu dropped=%lu "
                  "etwQueueDepth=%lu etwDropped=%lu lastErr=%lu\n",
                  client->ProcessId, client->SessionId, client->SubscriptionCount, client->QueueDepth,
                  client->DroppedEvents, client->EtwQueueDepth, client->EtwDroppedEvents, disconnectErr);
    client->SubscriptionCount = 0;
    ControllerClientFreeQueueLocked(client);
    ControllerClientFreeEtwQueueLocked(client);
    LeaveCriticalSection(&client->Lock);
    DeleteCriticalSection(&client->Lock);
    free(client);
    return 0;
}

static BOOL ControllerCreatePipeSecurity(_Out_ PSECURITY_ATTRIBUTES SecurityAttributes,
                                         _Outptr_ PSECURITY_DESCRIPTOR *SecurityDescriptor)
{
    BOOL ok;

    if (SecurityAttributes == NULL || SecurityDescriptor == NULL)
    {
        return FALSE;
    }

    *SecurityDescriptor = NULL;
    ZeroMemory(SecurityAttributes, sizeof(*SecurityAttributes));

    ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)", SDDL_REVISION_1, SecurityDescriptor, NULL);
    if (!ok || *SecurityDescriptor == NULL)
    {
        return FALSE;
    }

    SecurityAttributes->nLength = sizeof(*SecurityAttributes);
    SecurityAttributes->lpSecurityDescriptor = *SecurityDescriptor;
    SecurityAttributes->bInheritHandle = FALSE;
    return TRUE;
}

