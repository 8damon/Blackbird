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

static DWORD ControllerClampSharedRingCapacity(_In_ DWORD Desired, _In_ DWORD DefaultValue, _In_ DWORD MaxValue)
{
    if (Desired == 0)
    {
        return DefaultValue;
    }
    if (Desired > MaxValue)
    {
        return MaxValue;
    }
    if (Desired < 64)
    {
        return 64;
    }
    return Desired;
}

static BOOL ControllerCreateSharedRing(_In_ DWORD Capacity, _In_ DWORD RecordSize, _Out_ HANDLE *MappingHandle,
                                       _Out_ HANDLE *DataReadyEvent, _Out_ PSLEEPWALKER_IPC_SHARED_RING_HEADER *Header,
                                       _Out_ PBYTE *Records)
{
    SIZE_T totalBytes;
    HANDLE mapping;
    PBYTE view;
    HANDLE ready;
    PSLEEPWALKER_IPC_SHARED_RING_HEADER hdr;

    if (MappingHandle == NULL || DataReadyEvent == NULL || Header == NULL || Records == NULL || Capacity == 0 ||
        RecordSize == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    totalBytes = sizeof(*hdr) + ((SIZE_T)Capacity * (SIZE_T)RecordSize);
    mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, (DWORD)((ULONGLONG)totalBytes >> 32),
                                 (DWORD)(totalBytes & 0xFFFFFFFFu), NULL);
    if (mapping == NULL)
    {
        return FALSE;
    }

    view = (PBYTE)MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, totalBytes);
    if (view == NULL)
    {
        DWORD err = GetLastError();
        (void)CloseHandle(mapping);
        SetLastError(err);
        return FALSE;
    }

    ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ready == NULL)
    {
        DWORD err = GetLastError();
        (void)UnmapViewOfFile(view);
        (void)CloseHandle(mapping);
        SetLastError(err);
        return FALSE;
    }

    hdr = (PSLEEPWALKER_IPC_SHARED_RING_HEADER)view;
    ZeroMemory(hdr, sizeof(*hdr));
    hdr->Capacity = Capacity;
    hdr->RecordSize = RecordSize;

    *MappingHandle = mapping;
    *DataReadyEvent = ready;
    *Header = hdr;
    *Records = view + sizeof(*hdr);
    return TRUE;
}

static DWORD ControllerClientEnsureSharedRingsLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                                     _In_ DWORD DesiredIoctlCapacity, _In_ DWORD DesiredEtwCapacity)
{
    DWORD ioctlCap;
    DWORD etwCap;

    if (Client == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (Client->IoctlSharedHeader != NULL && Client->EtwSharedHeader != NULL && Client->IoctlSharedDataEvent != NULL &&
        Client->EtwSharedDataEvent != NULL)
    {
        return ERROR_SUCCESS;
    }

    ioctlCap = ControllerClampSharedRingCapacity(DesiredIoctlCapacity, SLEEPWALKER_CONTROLLER_SHARED_IOCTL_RING_CAPACITY,
                                                 65536);
    etwCap = ControllerClampSharedRingCapacity(DesiredEtwCapacity, SLEEPWALKER_CONTROLLER_SHARED_ETW_RING_CAPACITY,
                                               32768);

    if (!ControllerCreateSharedRing(ioctlCap, sizeof(SLEEPWALKER_EVENT_RECORD), &Client->IoctlSharedMapping,
                                    &Client->IoctlSharedDataEvent, &Client->IoctlSharedHeader,
                                    &Client->IoctlSharedRecords))
    {
        return GetLastError();
    }

    if (!ControllerCreateSharedRing(etwCap, sizeof(SLEEPWALKER_IPC_ETW_EVENT), &Client->EtwSharedMapping,
                                    &Client->EtwSharedDataEvent, &Client->EtwSharedHeader, &Client->EtwSharedRecords))
    {
        DWORD err = GetLastError();
        ControllerClientDestroySharedRingsLocked(Client);
        return err;
    }

    return ERROR_SUCCESS;
}

static VOID ControllerCloseRemoteHandle(_In_ HANDLE ClientProcess, _Inout_ HANDLE *RemoteHandle)
{
    HANDLE localHandle = NULL;

    if (ClientProcess == NULL || ClientProcess == INVALID_HANDLE_VALUE || RemoteHandle == NULL || *RemoteHandle == NULL ||
        *RemoteHandle == INVALID_HANDLE_VALUE)
    {
        return;
    }

    if (DuplicateHandle(ClientProcess, *RemoteHandle, GetCurrentProcess(), &localHandle, 0, FALSE,
                        DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE))
    {
        if (localHandle != NULL && localHandle != INVALID_HANDLE_VALUE)
        {
            (void)CloseHandle(localHandle);
        }
    }

    *RemoteHandle = NULL;
}

static DWORD ControllerClientOpenSharedRing(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                            _In_ const SLEEPWALKER_IPC_OPEN_SHARED_RING_REQUEST *Request,
                                            _Out_ SLEEPWALKER_IPC_OPEN_SHARED_RING_RESPONSE *Response)
{
    DWORD err;
    HANDLE clientProcess = NULL;
    HANDLE ioctlMapDup = NULL;
    HANDLE ioctlEventDup = NULL;
    HANDLE etwMapDup = NULL;
    HANDLE etwEventDup = NULL;

    if (Client == NULL || Request == NULL || Response == NULL || Client->ProcessId == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&Client->Lock);
    err = ControllerClientEnsureSharedRingsLocked(Client, Request->DesiredIoctlCapacity, Request->DesiredEtwCapacity);
    if (err != ERROR_SUCCESS)
    {
        LeaveCriticalSection(&Client->Lock);
        return err;
    }

    clientProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, Client->ProcessId);
    if (clientProcess == NULL)
    {
        err = GetLastError();
        LeaveCriticalSection(&Client->Lock);
        return err;
    }

    if (!DuplicateHandle(GetCurrentProcess(), Client->IoctlSharedMapping, clientProcess, &ioctlMapDup, 0, FALSE,
                         DUPLICATE_SAME_ACCESS) ||
        !DuplicateHandle(GetCurrentProcess(), Client->IoctlSharedDataEvent, clientProcess, &ioctlEventDup, 0, FALSE,
                         DUPLICATE_SAME_ACCESS) ||
        !DuplicateHandle(GetCurrentProcess(), Client->EtwSharedMapping, clientProcess, &etwMapDup, 0, FALSE,
                         DUPLICATE_SAME_ACCESS) ||
        !DuplicateHandle(GetCurrentProcess(), Client->EtwSharedDataEvent, clientProcess, &etwEventDup, 0, FALSE,
                         DUPLICATE_SAME_ACCESS))
    {
        err = GetLastError();
        ControllerCloseRemoteHandle(clientProcess, &ioctlMapDup);
        ControllerCloseRemoteHandle(clientProcess, &ioctlEventDup);
        ControllerCloseRemoteHandle(clientProcess, &etwMapDup);
        ControllerCloseRemoteHandle(clientProcess, &etwEventDup);
        LeaveCriticalSection(&Client->Lock);
        (void)CloseHandle(clientProcess);
        return err;
    }

    ZeroMemory(Response, sizeof(*Response));
    Response->IoctlMappingHandle = (UINT64)(ULONG_PTR)ioctlMapDup;
    Response->IoctlDataReadyEventHandle = (UINT64)(ULONG_PTR)ioctlEventDup;
    Response->IoctlCapacity = Client->IoctlSharedHeader->Capacity;
    Response->IoctlRecordSize = Client->IoctlSharedHeader->RecordSize;
    Response->EtwMappingHandle = (UINT64)(ULONG_PTR)etwMapDup;
    Response->EtwDataReadyEventHandle = (UINT64)(ULONG_PTR)etwEventDup;
    Response->EtwCapacity = Client->EtwSharedHeader->Capacity;
    Response->EtwRecordSize = Client->EtwSharedHeader->RecordSize;
    Client->SharedRingEnabled = TRUE;
    LeaveCriticalSection(&Client->Lock);

    (void)CloseHandle(clientProcess);
    return ERROR_SUCCESS;
}

static BOOL ControllerCheckTokenMembershipRid(_In_ HANDLE Token, _In_ DWORD Rid, _Out_ BOOL *IsMember)
{
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID sid = NULL;
    BOOL isMember = FALSE;

    if (Token == NULL || Token == INVALID_HANDLE_VALUE || IsMember == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, Rid, 0, 0, 0, 0, 0, 0, &sid))
    {
        return FALSE;
    }

    if (!CheckTokenMembership(Token, sid, &isMember))
    {
        DWORD err = GetLastError();
        FreeSid(sid);
        SetLastError(err);
        return FALSE;
    }

    FreeSid(sid);
    *IsMember = isMember;
    return TRUE;
}

static BOOL ControllerCheckTokenIsLocalSystem(_In_ HANDLE Token, _Out_ BOOL *IsSystem)
{
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID systemSid = NULL;
    BOOL isSystem = FALSE;

    if (Token == NULL || Token == INVALID_HANDLE_VALUE || IsSystem == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &systemSid))
    {
        return FALSE;
    }

    if (!CheckTokenMembership(Token, systemSid, &isSystem))
    {
        DWORD err = GetLastError();
        FreeSid(systemSid);
        SetLastError(err);
        return FALSE;
    }

    FreeSid(systemSid);
    *IsSystem = isSystem;
    return TRUE;
}

static BOOL ControllerClientIsPrivileged(_In_ const SLEEPWALKER_CONTROLLER_CLIENT *Client, _Out_ BOOL *IsPrivileged)
{
    HANDLE process = NULL;
    HANDLE token = NULL;
    BOOL isAdmin = FALSE;
    BOOL isSystem = FALSE;

    if (Client == NULL || IsPrivileged == NULL || Client->ProcessId == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *IsPrivileged = FALSE;
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Client->ProcessId);
    if (process == NULL)
    {
        return FALSE;
    }

    if (!OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &token))
    {
        DWORD err = GetLastError();
        CloseHandle(process);
        SetLastError(err);
        return FALSE;
    }

    if (!ControllerCheckTokenMembershipRid(token, DOMAIN_ALIAS_RID_ADMINS, &isAdmin))
    {
        DWORD err = GetLastError();
        CloseHandle(token);
        CloseHandle(process);
        SetLastError(err);
        return FALSE;
    }

    if (!ControllerCheckTokenIsLocalSystem(token, &isSystem))
    {
        DWORD err = GetLastError();
        CloseHandle(token);
        CloseHandle(process);
        SetLastError(err);
        return FALSE;
    }

    CloseHandle(token);
    CloseHandle(process);
    *IsPrivileged = (isAdmin || isSystem);
    return TRUE;
}

static BOOL ControllerQueryProcessTokenUser(_In_ DWORD ProcessId, _Outptr_ PTOKEN_USER *TokenUserOut)
{
    HANDLE process = NULL;
    HANDLE token = NULL;
    DWORD tokenBytes = 0;
    PTOKEN_USER tokenUser = NULL;

    if (ProcessId == 0 || TokenUserOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *TokenUserOut = NULL;
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (process == NULL)
    {
        return FALSE;
    }

    if (!OpenProcessToken(process, TOKEN_QUERY, &token))
    {
        DWORD err = GetLastError();
        CloseHandle(process);
        SetLastError(err);
        return FALSE;
    }

    (void)GetTokenInformation(token, TokenUser, NULL, 0, &tokenBytes);
    if (tokenBytes == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        DWORD err = GetLastError();
        CloseHandle(token);
        CloseHandle(process);
        SetLastError(err == ERROR_SUCCESS ? ERROR_BAD_LENGTH : err);
        return FALSE;
    }

    tokenUser = (PTOKEN_USER)calloc(1, tokenBytes);
    if (tokenUser == NULL)
    {
        CloseHandle(token);
        CloseHandle(process);
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    if (!GetTokenInformation(token, TokenUser, tokenUser, tokenBytes, &tokenBytes))
    {
        DWORD err = GetLastError();
        free(tokenUser);
        CloseHandle(token);
        CloseHandle(process);
        SetLastError(err);
        return FALSE;
    }

    CloseHandle(token);
    CloseHandle(process);
    *TokenUserOut = tokenUser;
    return TRUE;
}

static BOOL ControllerProcessesShareOwnerSid(_In_ DWORD ProcessIdA, _In_ DWORD ProcessIdB, _Out_ BOOL *SameOwner)
{
    PTOKEN_USER tokenUserA = NULL;
    PTOKEN_USER tokenUserB = NULL;

    if (SameOwner == NULL || ProcessIdA == 0 || ProcessIdB == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *SameOwner = FALSE;
    if (!ControllerQueryProcessTokenUser(ProcessIdA, &tokenUserA))
    {
        return FALSE;
    }

    if (!ControllerQueryProcessTokenUser(ProcessIdB, &tokenUserB))
    {
        DWORD err = GetLastError();
        free(tokenUserA);
        SetLastError(err);
        return FALSE;
    }

    *SameOwner = EqualSid(tokenUserA->User.Sid, tokenUserB->User.Sid) ? TRUE : FALSE;
    free(tokenUserA);
    free(tokenUserB);
    return TRUE;
}

static BOOL ControllerClientCanMonitorPid(_In_ const SLEEPWALKER_CONTROLLER_CLIENT *Client, _In_ DWORD TargetPid,
                                          _Inout_opt_ BOOL *PrivilegeResolved, _Inout_opt_ BOOL *IsPrivileged)
{
    BOOL privileged = FALSE;
    DWORD targetSessionId = 0;
    BOOL sameOwner = FALSE;

    if (Client == NULL || TargetPid == 0 || Client->ProcessId == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (TargetPid == Client->ProcessId)
    {
        return TRUE;
    }

    if (PrivilegeResolved != NULL && IsPrivileged != NULL && *PrivilegeResolved)
    {
        privileged = *IsPrivileged;
    }
    else
    {
        if (!ControllerClientIsPrivileged(Client, &privileged))
        {
            DWORD err = GetLastError();
            if (err == ERROR_NO_IMPERSONATION_TOKEN)
            {
                privileged = TRUE;
            }
            else
            {
                return FALSE;
            }
        }
        if (PrivilegeResolved != NULL)
        {
            *PrivilegeResolved = TRUE;
        }
        if (IsPrivileged != NULL)
        {
            *IsPrivileged = privileged;
        }
    }

    if (privileged)
    {
        return TRUE;
    }

    if (!ProcessIdToSessionId(TargetPid, &targetSessionId))
    {
        return FALSE;
    }
    if (targetSessionId != Client->SessionId)
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    if (!ControllerProcessesShareOwnerSid(Client->ProcessId, TargetPid, &sameOwner))
    {
        return FALSE;
    }
    if (!sameOwner)
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    return TRUE;
}

static DWORD ControllerClientSubscribe(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client,
                                       _In_ const SLEEPWALKER_SUBSCRIBE_REQUEST *Request)
{
    DWORD i;

    if (Client == NULL || Request == NULL || Request->ProcessId == 0 || !ControllerIsValidStreamMask(Request->StreamMask))
    {
        return ERROR_INVALID_PARAMETER;
    }
    if (!ControllerClientCanMonitorPid(Client, Request->ProcessId, NULL, NULL))
    {
        DWORD err = GetLastError();
        return (err == ERROR_SUCCESS) ? ERROR_ACCESS_DENIED : err;
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
    BOOL privilegeResolved = FALSE;
    BOOL isPrivileged = FALSE;

    if (Client == NULL || Request == NULL || Request->ProcessCount > SLEEPWALKER_MAX_PID_LIST ||
        Request->ProcessCount == 0 || !ControllerIsValidStreamMask(Request->StreamMask))
    {
        return ERROR_INVALID_PARAMETER;
    }

    for (i = 0; i < Request->ProcessCount; ++i)
    {
        DWORD pid = Request->ProcessIds[i];
        if (pid == 0)
        {
            continue;
        }

        if (!ControllerClientCanMonitorPid(Client, pid, &privilegeResolved, &isPrivileged))
        {
            DWORD err = GetLastError();
            return (err == ERROR_SUCCESS) ? ERROR_ACCESS_DENIED : err;
        }
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
    case SleepwalkerIpcCommandOpenSharedRing:
        return "open-shared-ring";
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
            SLEEPWALKER_IPC_CAP_DRIVER_PROXY | SLEEPWALKER_IPC_CAP_ETW_TI_SESSION | SLEEPWALKER_IPC_CAP_ETW_TI_UPLINK |
            SLEEPWALKER_IPC_CAP_SHARED_RING;
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
    case SleepwalkerIpcCommandOpenSharedRing:
        err = ControllerClientOpenSharedRing(Client, &Request->Payload.OpenSharedRingRequest,
                                             &Response->Payload.OpenSharedRingResponse);
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
            if (Client->SlotIndex != SLEEPWALKER_CONTROLLER_INVALID_SLOT)
            {
                ControllerReleaseClientSlotLocked(Client->SlotIndex);
                Client->SlotIndex = SLEEPWALKER_CONTROLLER_INVALID_SLOT;
            }
            if (g_ClientCount > 0)
            {
                g_ClientCount -= 1;
            }
            ControllerLog("[IPC] active clients=%lu\n", g_ClientCount);
            break;
        }
        pp = &(*pp)->Next;
    }
    ControllerRebuildPidIndexLocked(NULL);
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
    ControllerClientDestroySharedRingsLocked(client);
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

