#include "../blackbird_controller_private.h"
#include "../injection/blackbird_controller_injection.h"
#include <math.h>

static BOOL ControllerProxyQueryProcessImage(_In_ DWORD ProcessId,
                                             _Out_ BLACKBIRD_QUERY_PROCESS_IMAGE_RESPONSE *Response)
{
    WCHAR imagePath[BLACKBIRD_MAX_IMAGE_PATH_CHARS];
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
         BLACKBIRDSCQueryProcessImagePath(g_DriverHandle, ProcessId, imagePath, RTL_NUMBER_OF(imagePath));
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
    ok = (g_DriverHandle != INVALID_HANDLE_VALUE) && BLACKBIRDSCSetShutdownMode(g_DriverHandle);
    LeaveCriticalSection(&g_DriverLock);
    return ok;
}

static VOID ControllerClientClearPendingLaunchLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client)
{
    if (Client == NULL)
    {
        return;
    }

    Client->PendingLaunchArmed = FALSE;
    Client->PendingLaunchPid = 0;
    Client->PendingLaunchArmedTick = 0;
    Client->PendingLaunchImagePath[0] = L'\0';
}

static VOID ControllerClientArmPendingLaunchLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                                   _In_opt_z_ PCWSTR ImagePath)
{
    if (Client == NULL)
    {
        return;
    }

    ControllerClientClearPendingLaunchLocked(Client);
    if (ImagePath == NULL || ImagePath[0] == L'\0')
    {
        return;
    }

    (void)StringCchCopyW(Client->PendingLaunchImagePath, RTL_NUMBER_OF(Client->PendingLaunchImagePath), ImagePath);
    Client->PendingLaunchArmed = TRUE;
    Client->PendingLaunchArmedTick = GetTickCount64();
}

static VOID ControllerClientPrimePendingLaunchPidLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                                        _In_ DWORD ProcessId)
{
    DWORD i;

    if (Client == NULL || ProcessId == 0)
    {
        return;
    }

    Client->PendingLaunchPid = ProcessId;
    Client->PendingLaunchArmed = FALSE;
    Client->PendingLaunchArmedTick = 0;

    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (Client->Subscriptions[i].ProcessId == ProcessId)
        {
            Client->Subscriptions[i].StreamMask |= BLACKBIRD_CONTROLLER_DRIVER_STREAM_MASK;
            if (Client->Subscriptions[i].Dynamic)
            {
                Client->Subscriptions[i].Dynamic = FALSE;
                Client->Subscriptions[i].Depth = 0;
                Client->Subscriptions[i].SourceProcessId = 0;
                Client->Subscriptions[i].LastSeenTick = 0;
            }
            ControllerMarkDriverSubscriptionsDirty();
            return;
        }
    }

    if (Client->SubscriptionCount >= BLACKBIRD_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS)
    {
        return;
    }

    Client->Subscriptions[Client->SubscriptionCount].ProcessId = ProcessId;
    Client->Subscriptions[Client->SubscriptionCount].StreamMask = BLACKBIRD_CONTROLLER_DRIVER_STREAM_MASK;
    Client->Subscriptions[Client->SubscriptionCount].Dynamic = FALSE;
    Client->Subscriptions[Client->SubscriptionCount].SourceProcessId = 0;
    Client->Subscriptions[Client->SubscriptionCount].Depth = 0;
    Client->Subscriptions[Client->SubscriptionCount].LastSeenTick = 0;
    Client->SubscriptionCount += 1;
    ControllerMarkDriverSubscriptionsDirty();
}

static DWORD ControllerQueryHookReadyMaskForProcess(_In_ DWORD ProcessId)
{
    PBLACKBIRD_CONTROLLER_CLIENT current;
    DWORD observedMask = 0;

    if (ProcessId == 0)
    {
        return 0;
    }

    EnterCriticalSection(&g_ClientListLock);
    current = g_ClientList;
    while (current != NULL)
    {
        if (current->ProcessId == ProcessId)
        {
            observedMask |= (DWORD)InterlockedCompareExchange(&current->HookReadyMask, 0, 0);
        }
        current = current->Next;
    }
    LeaveCriticalSection(&g_ClientListLock);

    return observedMask;
}

DWORD ControllerWaitForHookReady(_In_ DWORD ProcessId)
{
    static const DWORD kSpinSleepMs = 1u;
    static const ULONGLONG kLogPeriodMs = 1000ull;
    static const ULONGLONG kTimeoutMs = (ULONGLONG)BLACKBIRD_CONTROLLER_HOOK_READY_TIMEOUT_MS;
    static const DWORD kRequiredMask = BLACKBIRD_CONTROLLER_HOOK_READY_REQUIRED_MASK;
    HANDLE processHandle = NULL;
    DWORD access = SYNCHRONIZE;
    ULONGLONG startTick;
    ULONGLONG lastLogTick;
    ULONGLONG now;

    if (ProcessId == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    processHandle = OpenProcess(access, FALSE, ProcessId);
    startTick = GetTickCount64();
    lastLogTick = startTick;

    for (;;)
    {
        DWORD readyMask = ControllerQueryHookReadyMaskForProcess(ProcessId);
        if ((readyMask & kRequiredMask) == kRequiredMask)
        {
            ULONGLONG elapsed = GetTickCount64() - startTick;
            ControllerLog("[IPC] hook-ready confirmed pid=%lu mask=0x%08lX elapsedMs=%llu\n",
                          ProcessId, readyMask, elapsed);
            if (processHandle != NULL)
            {
                CloseHandle(processHandle);
            }
            return ERROR_SUCCESS;
        }

        if (processHandle != NULL)
        {
            DWORD waitResult = WaitForSingleObject(processHandle, 0);
            if (waitResult == WAIT_OBJECT_0)
            {
                CloseHandle(processHandle);
                return ERROR_DLL_INIT_FAILED;
            }
        }

        now = GetTickCount64();
        if (now - startTick >= kTimeoutMs)
        {
            ControllerLog("[IPC][WARN] hook-ready timed out pid=%lu mask=0x%08lX required=0x%08X elapsedMs=%llu\n",
                          ProcessId, readyMask, kRequiredMask, now - startTick);
            if (processHandle != NULL)
            {
                CloseHandle(processHandle);
            }
            return ERROR_TIMEOUT;
        }

        if (now - lastLogTick >= kLogPeriodMs)
        {
            ControllerLog("[IPC] waiting hook-ready pid=%lu mask=0x%08lX required=0x%08X elapsedMs=%llu\n",
                          ProcessId, readyMask, kRequiredMask, now - startTick);
            lastLogTick = now;
        }

        if (!SwitchToThread())
        {
            Sleep(kSpinSleepMs);
        }
    }
}

#define BLACKBIRD_CAPTURE_REQUIRED_HEALTH_MASK                                                   \
    (BLACKBIRD_HEALTH_CONTROL_READY | BLACKBIRD_HEALTH_ETW_READY |                             \
     BLACKBIRD_HEALTH_PROCESS_MONITOR_READY | BLACKBIRD_HEALTH_IMAGE_MONITOR_READY)

static DWORD ControllerEnsureCaptureReadyForLaunch(VOID)
{
    DWORD openErr = ERROR_SUCCESS;
    BLACKBIRD_HEALTH_RESPONSE health;
    DWORD healthErr = ERROR_SUCCESS;
    DWORD healthBytes = 0;
    BOOL healthOk = FALSE;

    if (ControllerShouldStop())
    {
        return ERROR_SHUTDOWN_IN_PROGRESS;
    }
    if (g_EtwSession == NULL || g_EtwThread == NULL)
    {
        return ERROR_SERVICE_NOT_ACTIVE;
    }

    EnterCriticalSection(&g_DriverLock);
    if (g_DriverHandle == INVALID_HANDLE_VALUE)
    {
        g_DriverHandle = BLACKBIRDSCOpenControlDevice();
        if (g_DriverHandle == INVALID_HANDLE_VALUE)
        {
            openErr = GetLastError();
        }
    }
    LeaveCriticalSection(&g_DriverLock);
    if (openErr != ERROR_SUCCESS)
    {
        return (openErr == ERROR_SUCCESS) ? ERROR_DEVICE_NOT_CONNECTED : openErr;
    }

    ZeroMemory(&health, sizeof(health));
    EnterCriticalSection(&g_DriverLock);
    if (g_DriverHandle != INVALID_HANDLE_VALUE)
    {
        healthOk = BLACKBIRDSCGetHealth(g_DriverHandle, &health, &healthBytes);
        if (!healthOk)
        {
            healthErr = GetLastError();
        }
    }
    LeaveCriticalSection(&g_DriverLock);
    if (!healthOk)
    {
        if (healthErr == ERROR_SUCCESS)
        {
            healthErr = ERROR_NOT_READY;
        }
        return healthErr;
    }
    if ((health.HealthMask & BLACKBIRD_CAPTURE_REQUIRED_HEALTH_MASK) != BLACKBIRD_CAPTURE_REQUIRED_HEALTH_MASK)
    {
        ControllerLog("[IPC][WARN] launch capture gate failed health=0x%08lX tamper=0x%08lX bytes=%lu\n",
                      health.HealthMask, health.TamperMask, healthBytes);
        return ERROR_NOT_READY;
    }
    if (health.TamperMask != 0)
    {
        ControllerLog("[IPC][WARN] launch capture continuing with kernel tamper mask=0x%08lX\n", health.TamperMask);
    }

    (void)ControllerApplyDriverSubscriptionsIfDirty();
    return ERROR_SUCCESS;
}

static BOOL ControllerValidatePacket(_In_ const BLACKBIRD_IPC_PACKET *Packet, _In_ UINT16 ExpectedType)
{
    if (Packet == NULL)
    {
        return FALSE;
    }

    if (Packet->Magic != BLACKBIRD_IPC_MAGIC)
    {
        return FALSE;
    }

    if (Packet->Version != BLACKBIRD_IPC_VERSION)
    {
        return FALSE;
    }

    if (Packet->PacketType != ExpectedType)
    {
        return FALSE;
    }

    return TRUE;
}

static VOID ControllerPrepareResponse(_In_ const BLACKBIRD_IPC_PACKET *Request, _Out_ BLACKBIRD_IPC_PACKET *Response)
{
    ZeroMemory(Response, sizeof(*Response));
    Response->Magic = BLACKBIRD_IPC_MAGIC;
    Response->Version = BLACKBIRD_IPC_VERSION;
    Response->PacketType = BlackbirdIpcPacketResponse;
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
                                       _Out_ HANDLE *DataReadyEvent, _Out_ PBLACKBIRD_IPC_SHARED_RING_HEADER *Header,
                                       _Out_ PBYTE *Records)
{
    SIZE_T totalBytes;
    HANDLE mapping;
    PBYTE view;
    HANDLE ready;
    PBLACKBIRD_IPC_SHARED_RING_HEADER hdr;

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

    hdr = (PBLACKBIRD_IPC_SHARED_RING_HEADER)view;
    ZeroMemory(hdr, sizeof(*hdr));
    hdr->Capacity = Capacity;
    hdr->RecordSize = RecordSize;

    *MappingHandle = mapping;
    *DataReadyEvent = ready;
    *Header = hdr;
    *Records = view + sizeof(*hdr);
    return TRUE;
}

static DWORD ControllerClientEnsureSharedRingsLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
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

    ioctlCap = ControllerClampSharedRingCapacity(DesiredIoctlCapacity, BLACKBIRD_CONTROLLER_SHARED_IOCTL_RING_CAPACITY,
                                                 65536);
    etwCap = ControllerClampSharedRingCapacity(DesiredEtwCapacity, BLACKBIRD_CONTROLLER_SHARED_ETW_RING_CAPACITY,
                                               32768);

    if (!ControllerCreateSharedRing(ioctlCap, sizeof(BLACKBIRD_EVENT_RECORD), &Client->IoctlSharedMapping,
                                    &Client->IoctlSharedDataEvent, &Client->IoctlSharedHeader,
                                    &Client->IoctlSharedRecords))
    {
        return GetLastError();
    }

    if (!ControllerCreateSharedRing(etwCap, sizeof(BLACKBIRD_IPC_ETW_EVENT), &Client->EtwSharedMapping,
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

static DWORD ControllerClientOpenSharedRing(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                            _In_ const BLACKBIRD_IPC_OPEN_SHARED_RING_REQUEST *Request,
                                            _Out_ BLACKBIRD_IPC_OPEN_SHARED_RING_RESPONSE *Response)
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

static BOOL ControllerClientIsPrivileged(_In_ const BLACKBIRD_CONTROLLER_CLIENT *Client, _Out_ BOOL *IsPrivileged)
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

static BOOL ControllerClientCanMonitorPid(_In_ const BLACKBIRD_CONTROLLER_CLIENT *Client, _In_ DWORD TargetPid,
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

static DWORD ControllerClientSubscribe(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                       _In_ const BLACKBIRD_SUBSCRIBE_REQUEST *Request)
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

    if (Client->SubscriptionCount >= BLACKBIRD_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS)
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

static DWORD ControllerClientUnsubscribe(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                         _In_ const BLACKBIRD_UNSUBSCRIBE_REQUEST *Request)
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

static DWORD ControllerClientSetPids(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                     _In_ const BLACKBIRD_SET_PIDS_REQUEST *Request)
{
    DWORD i;
    BOOL privilegeResolved = FALSE;
    BOOL isPrivileged = FALSE;

    if (Client == NULL || Request == NULL || Request->ProcessCount > BLACKBIRD_MAX_PID_LIST ||
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

        if (!seen && Client->SubscriptionCount < BLACKBIRD_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS)
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

static DWORD ControllerClientGetEvent(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client, _In_ DWORD TimeoutMs,
                                      _Out_ BLACKBIRD_EVENT_RECORD *Record)
{
    ULONGLONG startTick;

    if (Client == NULL || Record == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    startTick = GetTickCount64();
    for (;;)
    {
        BOOL dequeued = FALSE;
        HANDLE dataEvent = NULL;
        HANDLE waitHandles[2];
        DWORD waitCount = 0;
        DWORD waitMs = INFINITE;
        DWORD waitResult;
        ULONGLONG elapsed = 0;

        EnterCriticalSection(&Client->Lock);
        if (Client->SharedRingEnabled && Client->IoctlSharedDataEvent != NULL &&
            Client->IoctlSharedDataEvent != INVALID_HANDLE_VALUE)
        {
            dataEvent = Client->IoctlSharedDataEvent;
        }
        else
        {
            dataEvent = Client->IoctlQueueDataEvent;
        }
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
        if (TimeoutMs != INFINITE)
        {
            elapsed = GetTickCount64() - startTick;
            if (elapsed >= TimeoutMs)
            {
                return ERROR_NO_MORE_ITEMS;
            }
            waitMs = (DWORD)((ULONGLONG)TimeoutMs - elapsed);
        }

        if (g_StopEvent != NULL)
        {
            waitHandles[waitCount++] = g_StopEvent;
        }
        if (dataEvent != NULL && dataEvent != INVALID_HANDLE_VALUE)
        {
            waitHandles[waitCount++] = dataEvent;
        }
        if (waitCount == 0)
        {
            if (waitMs == 0)
            {
                return ERROR_NO_MORE_ITEMS;
            }
            Sleep((waitMs == INFINITE || waitMs > 2u) ? 2u : waitMs);
            continue;
        }

        waitResult = WaitForMultipleObjects(waitCount, waitHandles, FALSE, waitMs);
        if (waitResult == WAIT_OBJECT_0 && g_StopEvent != NULL)
        {
            return ERROR_OPERATION_ABORTED;
        }
        if (waitResult == WAIT_TIMEOUT)
        {
            if (TimeoutMs != INFINITE)
            {
                return ERROR_NO_MORE_ITEMS;
            }
            continue;
        }
        if (waitResult == WAIT_FAILED)
        {
            DWORD err = GetLastError();
            return (err == ERROR_SUCCESS) ? ERROR_GEN_FAILURE : err;
        }
    }
}

static DWORD ControllerClientGetEtwEvent(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client, _In_ DWORD TimeoutMs,
                                         _Out_ BLACKBIRD_IPC_ETW_EVENT *Event)
{
    ULONGLONG startTick;

    if (Client == NULL || Event == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    startTick = GetTickCount64();
    for (;;)
    {
        BOOL dequeued = FALSE;
        HANDLE dataEvent = NULL;
        HANDLE waitHandles[2];
        DWORD waitCount = 0;
        DWORD waitMs = INFINITE;
        DWORD waitResult;
        ULONGLONG elapsed = 0;

        EnterCriticalSection(&Client->Lock);
        if (Client->SharedRingEnabled && Client->EtwSharedDataEvent != NULL &&
            Client->EtwSharedDataEvent != INVALID_HANDLE_VALUE)
        {
            dataEvent = Client->EtwSharedDataEvent;
        }
        else
        {
            dataEvent = Client->EtwQueueDataEvent;
        }
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
        if (TimeoutMs != INFINITE)
        {
            elapsed = GetTickCount64() - startTick;
            if (elapsed >= TimeoutMs)
            {
                return ERROR_NO_MORE_ITEMS;
            }
            waitMs = (DWORD)((ULONGLONG)TimeoutMs - elapsed);
        }

        if (g_StopEvent != NULL)
        {
            waitHandles[waitCount++] = g_StopEvent;
        }
        if (dataEvent != NULL && dataEvent != INVALID_HANDLE_VALUE)
        {
            waitHandles[waitCount++] = dataEvent;
        }
        if (waitCount == 0)
        {
            if (waitMs == 0)
            {
                return ERROR_NO_MORE_ITEMS;
            }
            Sleep((waitMs == INFINITE || waitMs > 2u) ? 2u : waitMs);
            continue;
        }

        waitResult = WaitForMultipleObjects(waitCount, waitHandles, FALSE, waitMs);
        if (waitResult == WAIT_OBJECT_0 && g_StopEvent != NULL)
        {
            return ERROR_OPERATION_ABORTED;
        }
        if (waitResult == WAIT_TIMEOUT)
        {
            if (TimeoutMs != INFINITE)
            {
                return ERROR_NO_MORE_ITEMS;
            }
            continue;
        }
        if (waitResult == WAIT_FAILED)
        {
            DWORD err = GetLastError();
            return (err == ERROR_SUCCESS) ? ERROR_GEN_FAILURE : err;
        }
    }
}

static DWORD ControllerClientGetStats(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                      _Out_ BLACKBIRD_STATS_RESPONSE *Stats)
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

static VOID ControllerSanitizeAnsiLabel(_In_opt_z_ PCSTR Input, _Out_writes_z_(OutputChars) PSTR Output,
                                        _In_ size_t OutputChars)
{
    size_t i;
    size_t write = 0;

    if (Output == NULL || OutputChars == 0)
    {
        return;
    }

    Output[0] = '\0';
    if (Input == NULL)
    {
        return;
    }

    for (i = 0; Input[i] != '\0' && write + 1 < OutputChars; ++i)
    {
        CHAR ch = Input[i];
        if ((unsigned char)ch < 0x20u || ch == '\x7F')
        {
            continue;
        }
        Output[write++] = ch;
    }
    Output[write] = '\0';
}

static PCSTR ControllerHookEventKindName(_In_ UINT32 Kind)
{
    switch (Kind)
    {
    case BlackbirdIpcHookEventNt:
        return "Nt";
    case BlackbirdIpcHookEventWinsock:
        return "Winsock";
    case BlackbirdIpcHookEventKi:
        return "Ki";
    case BlackbirdIpcHookEventExceptionLowNoise:
        return "ExceptionLowNoise";
    case BlackbirdIpcHookEventExceptionHighPriv:
        return "ExceptionHighPriv";
    case BlackbirdIpcHookEventIntegrity:
        return "Integrity";
    default:
        return "Unknown";
    }
}

#define BLACKBIRD_HOOK_EVENT_OP_AMSI_PATCH 2u
#define BLACKBIRD_HOOK_EVENT_OP_ETW_PATCH 3u

static PCSTR ControllerMemoryProtectName(_In_ UINT32 Protect)
{
    switch (Protect)
    {
    case 0x01:
        return "PAGE_NOACCESS";
    case 0x02:
        return "PAGE_READONLY";
    case 0x04:
        return "PAGE_READWRITE";
    case 0x08:
        return "PAGE_WRITECOPY";
    case 0x10:
        return "PAGE_EXECUTE";
    case 0x20:
        return "PAGE_EXECUTE_READ";
    case 0x40:
        return "PAGE_EXECUTE_READWRITE";
    case 0x80:
        return "PAGE_EXECUTE_WRITECOPY";
    default:
        return "UNKNOWN";
    }
}

static PCSTR ControllerMemoryAllocTypeName(_In_ UINT32 AllocationType)
{
    if ((AllocationType & 0x3000u) == 0x3000u)
    {
        return "MEM_COMMIT_RESERVE";
    }
    if ((AllocationType & 0x1000u) != 0)
    {
        return "MEM_COMMIT";
    }
    if ((AllocationType & 0x2000u) != 0)
    {
        return "MEM_RESERVE";
    }
    if ((AllocationType & 0x1000000u) != 0)
    {
        return "MEM_LARGE_PAGES";
    }
    return "UNKNOWN";
}

static double ControllerComputeSampleEntropy(_In_reads_(SampleSize) const UINT8 *Sample, _In_ UINT32 SampleSize)
{
    UINT32 i;
    UINT32 counts[256];
    double entropy = 0.0;
    double invLength;

    if (Sample == NULL || SampleSize <= 1)
    {
        return -1.0;
    }

    ZeroMemory(counts, sizeof(counts));
    for (i = 0; i < SampleSize; ++i)
    {
        counts[Sample[i]] += 1u;
    }

    invLength = 1.0 / (double)SampleSize;
    for (i = 0; i < RTL_NUMBER_OF(counts); ++i)
    {
        if (counts[i] != 0u)
        {
            double p = (double)counts[i] * invLength;
            entropy -= p * (log(p) / log(2.0));
        }
    }

    return entropy;
}

static DWORD ControllerClientPublishHookEvent(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                               _In_ const BLACKBIRD_IPC_HOOK_EVENT *HookEvent)
{
    BLACKBIRD_IPC_ETW_EVENT mapped;
    DWORD eventPid = 0;
    DWORD threadId = 0;
    BOOL privileged = FALSE;
    CHAR apiName[BLACKBIRD_IPC_MAX_HOOK_API_NAME];
    CHAR moduleName[BLACKBIRD_IPC_MAX_HOOK_MODULE_NAME];
    PCSTR kindName;
    int wideChars;
    size_t reasonOffset = 0;
    UINT32 argCount;
    UINT32 i;
    UINT32 sampleSize;
    BOOL integrityTampered = FALSE;
    BOOL integrityAmsiPatch = FALSE;
    BOOL integrityEtwPatch = FALSE;
    BOOL memoryEvent = FALSE;

    if (Client == NULL || HookEvent == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (HookEvent->Kind == BlackbirdIpcHookEventUnknown || HookEvent->Kind > BlackbirdIpcHookEventIntegrity)
    {
        return ERROR_INVALID_PARAMETER;
    }

    eventPid = (HookEvent->ProcessId != 0) ? HookEvent->ProcessId : Client->ProcessId;
    if (eventPid == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (eventPid != Client->ProcessId)
    {
        if (!ControllerClientIsPrivileged(Client, &privileged) || !privileged)
        {
            return ERROR_ACCESS_DENIED;
        }
    }

    threadId = HookEvent->ThreadId;

    ControllerSanitizeAnsiLabel(HookEvent->ApiName, apiName, RTL_NUMBER_OF(apiName));
    ControllerSanitizeAnsiLabel(HookEvent->ModuleName, moduleName, RTL_NUMBER_OF(moduleName));
    kindName = ControllerHookEventKindName(HookEvent->Kind);
    argCount = (HookEvent->ArgCount > RTL_NUMBER_OF(HookEvent->Args)) ? RTL_NUMBER_OF(HookEvent->Args) : HookEvent->ArgCount;
    sampleSize =
        (HookEvent->DataSize > RTL_NUMBER_OF(HookEvent->DataSample)) ? RTL_NUMBER_OF(HookEvent->DataSample) : HookEvent->DataSize;

    ZeroMemory(&mapped, sizeof(mapped));
    mapped.Source = BlackbirdIpcEtwSourceBlackbird;
    mapped.Family = BlackbirdIpcEtwFamilyUserHook;
    mapped.EventId = (UINT16)(HookEvent->Operation & 0xFFFFu);
    mapped.Opcode = (UINT16)(HookEvent->Kind & 0xFFFFu);
    mapped.Task = 0;
    mapped.EventProcessId = eventPid;
    mapped.EventThreadId = threadId;
    mapped.Severity = 1;
    mapped.Flags = 0;
    mapped.ProcessId = eventPid;
    mapped.ThreadId = threadId;
    mapped.CallerPid = eventPid;
    mapped.TargetPid = (HookEvent->Context0 <= 0xFFFFFFFFull) ? HookEvent->Context0 : 0;

    if (HookEvent->Kind == BlackbirdIpcHookEventIntegrity)
    {
        integrityAmsiPatch = (HookEvent->Operation == BLACKBIRD_HOOK_EVENT_OP_AMSI_PATCH);
        integrityEtwPatch = (HookEvent->Operation == BLACKBIRD_HOOK_EVENT_OP_ETW_PATCH);
        if (integrityAmsiPatch || integrityEtwPatch)
        {
            integrityTampered = (HookEvent->Context0 != 0ull);
            mapped.Severity = integrityTampered ? 8u : 1u;
        }
        else
        {
            integrityTampered = (HookEvent->Context0 != 0ull || HookEvent->Operation != 0u);
            mapped.Severity = integrityTampered ? 7u : 1u;
        }
        mapped.TargetPid = eventPid;
    }

    if (moduleName[0] != '\0')
    {
        (void)StringCchCopyA(mapped.ClassName, RTL_NUMBER_OF(mapped.ClassName), moduleName);
    }
    else
    {
        (void)StringCchCopyA(mapped.ClassName, RTL_NUMBER_OF(mapped.ClassName), kindName);
    }

    if (apiName[0] != '\0')
    {
        (void)StringCchCopyA(mapped.Operation, RTL_NUMBER_OF(mapped.Operation), apiName);
    }
    else
    {
        (void)StringCchPrintfA(mapped.Operation, RTL_NUMBER_OF(mapped.Operation), "%sOp%lu", kindName,
                               (unsigned long)HookEvent->Operation);
    }

    wideChars = MultiByteToWideChar(CP_ACP, 0, (apiName[0] != '\0') ? apiName : mapped.Operation, -1, mapped.EventName,
                                    RTL_NUMBER_OF(mapped.EventName));
    if (wideChars <= 0)
    {
        (void)StringCchPrintfW(mapped.EventName, RTL_NUMBER_OF(mapped.EventName), L"%S", mapped.Operation);
    }

    if (HookEvent->Kind == BlackbirdIpcHookEventIntegrity)
    {
        if (integrityAmsiPatch || integrityEtwPatch)
        {
            PCSTR detectionName = integrityAmsiPatch ? "AMSI_PATCH_TAMPERED" : "ETW_PATCH_TAMPERED";
            PCSTR okDetectionName = integrityAmsiPatch ? "AMSI_PATCH_OK" : "ETW_PATCH_OK";
            PCSTR eventLabel = integrityAmsiPatch ? "AmsiPatchTamper" : "EtwPatchTamper";
            PCSTR okEventLabel = integrityAmsiPatch ? "AmsiPatchOk" : "EtwPatchOk";
            PCWSTR reasonLabel = integrityAmsiPatch ? L"amsi" : L"etw";

            if (integrityTampered)
            {
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName), detectionName);
                (void)StringCchCopyA(mapped.Operation, RTL_NUMBER_OF(mapped.Operation), eventLabel);
                (void)StringCchPrintfW(mapped.EventName, RTL_NUMBER_OF(mapped.EventName), L"%S", eventLabel);
            }
            else
            {
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName), okDetectionName);
                (void)StringCchCopyA(mapped.Operation, RTL_NUMBER_OF(mapped.Operation), okEventLabel);
                (void)StringCchPrintfW(mapped.EventName, RTL_NUMBER_OF(mapped.EventName), L"%S", okEventLabel);
            }

            if (moduleName[0] != '\0')
            {
                (void)StringCchCopyA(mapped.ClassName, RTL_NUMBER_OF(mapped.ClassName), moduleName);
            }
            else
            {
                (void)StringCchCopyA(mapped.ClassName, RTL_NUMBER_OF(mapped.ClassName),
                                     integrityAmsiPatch ? "amsi" : "ntdll");
            }

            (void)StringCchPrintfW(
                mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                L"%ws tamper=%u suspiciousPrologue=%llu baselineChanged=%llu checkCount=%llu", reasonLabel,
                integrityTampered ? 1u : 0u, (unsigned long long)HookEvent->Context1, (unsigned long long)HookEvent->Context2,
                (unsigned long long)HookEvent->Context3);
        }
        else
        {
            if (integrityTampered)
            {
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName), "USERMODE_HOOK_TAMPERED");
                (void)StringCchCopyA(mapped.Operation, RTL_NUMBER_OF(mapped.Operation), "HookIntegrityTamper");
                (void)StringCchCopyW(mapped.EventName, RTL_NUMBER_OF(mapped.EventName), L"HookIntegrityTamper");
            }
            else
            {
                (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName), "USERMODE_HOOK_INTEGRITY_OK");
                (void)StringCchCopyA(mapped.Operation, RTL_NUMBER_OF(mapped.Operation), "HookIntegrityOk");
                (void)StringCchCopyW(mapped.EventName, RTL_NUMBER_OF(mapped.EventName), L"HookIntegrityOk");
            }

            (void)StringCchCopyA(mapped.ClassName, RTL_NUMBER_OF(mapped.ClassName), "sr71");
            (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                   L"hookIntegrity tampered=%u mask=0x%llX winsock=%llu nt=%llu ki=%llu",
                                   integrityTampered ? 1u : 0u, (unsigned long long)HookEvent->Context0,
                                   (unsigned long long)HookEvent->Context1, (unsigned long long)HookEvent->Context2,
                                   (unsigned long long)HookEvent->Context3);
        }
    }
    else
    {
        if (HookEvent->Kind == BlackbirdIpcHookEventNt &&
            lstrcmpiA(apiName, "NtAllocateVirtualMemory") == 0)
        {
            UINT32 allocType = (UINT32)(HookEvent->Context2 & 0xFFFFFFFFull);
            UINT32 protect = (UINT32)(HookEvent->Context3 & 0xFFFFFFFFull);
            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName), "USERMODE_MEMORY_ACTIVITY");
            mapped.Severity = 2u;
            memoryEvent = TRUE;
            (void)StringCchPrintfW(
                mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                L"memory.alloc base=0x%llX size=0x%llX allocType=0x%X allocTypeName=%S protect=0x%X protectName=%S",
                (unsigned long long)HookEvent->Context0, (unsigned long long)HookEvent->Context1, allocType,
                ControllerMemoryAllocTypeName(allocType), protect, ControllerMemoryProtectName(protect));
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventNt &&
                 lstrcmpiA(apiName, "NtProtectVirtualMemory") == 0)
        {
            UINT32 newProtect = (UINT32)(HookEvent->Context2 & 0xFFFFFFFFull);
            UINT32 protectFlips = (UINT32)(HookEvent->Context3 & 0xFFFFFFFFull);
            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName), "USERMODE_MEMORY_ACTIVITY");
            mapped.Severity = (protectFlips >= 4u) ? 6u : 3u;
            memoryEvent = TRUE;
            (void)StringCchPrintfW(
                mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                L"memory.protect base=0x%llX size=0x%llX newProtect=0x%X newProtectName=%S protectFlips=%lu",
                (unsigned long long)HookEvent->Context0, (unsigned long long)HookEvent->Context1, newProtect,
                ControllerMemoryProtectName(newProtect), (unsigned long)protectFlips);
        }
        else if (HookEvent->Kind == BlackbirdIpcHookEventNt &&
                 lstrcmpiA(apiName, "NtWriteVirtualMemory") == 0)
        {
            UINT32 entropyBucket = (UINT32)(HookEvent->Context2 & 0xFFFFFFFFull);
            UINT32 protectFlips = (UINT32)((HookEvent->Context3 >> 32) & 0xFFFFFFFFull);
            UINT32 entropyFlips = (UINT32)(HookEvent->Context3 & 0xFFFFFFFFull);
            double entropy = (HookEvent->Args[7] != 0ull)
                ? ((double)HookEvent->Args[7] / 1000.0)
                : ControllerComputeSampleEntropy(HookEvent->DataSample, sampleSize);
            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName), "USERMODE_MEMORY_ACTIVITY");
            mapped.Severity = (entropyFlips >= 4u || protectFlips >= 4u) ? 7u : 3u;
            memoryEvent = TRUE;
            (void)StringCchPrintfW(
                mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                L"memory.write base=0x%llX size=0x%llX entropy=%.2f entropyBucket=%lu entropyFlips=%lu protectFlips=%lu sampleBytes=%lu",
                (unsigned long long)HookEvent->Context0, (unsigned long long)HookEvent->Context1, entropy,
                (unsigned long)entropyBucket, (unsigned long)entropyFlips, (unsigned long)protectFlips,
                (unsigned long)sampleSize);
        }

        if (!memoryEvent)
        {
            (void)StringCchCopyA(mapped.DetectionName, RTL_NUMBER_OF(mapped.DetectionName), "USERMODE_HOOK_API_CALL");

            (void)StringCchPrintfW(mapped.Reason, RTL_NUMBER_OF(mapped.Reason),
                                   L"kind=%S op=%lu caller=0x%llX c0=0x%llX c1=0x%llX c2=0x%llX c3=0x%llX", kindName,
                                   (unsigned long)HookEvent->Operation, (unsigned long long)HookEvent->Caller,
                                   (unsigned long long)HookEvent->Context0, (unsigned long long)HookEvent->Context1,
                                   (unsigned long long)HookEvent->Context2, (unsigned long long)HookEvent->Context3);
            reasonOffset = wcslen(mapped.Reason);

            for (i = 0; i < argCount && reasonOffset + 20 < RTL_NUMBER_OF(mapped.Reason); ++i)
            {
                (void)StringCchPrintfW(mapped.Reason + reasonOffset, RTL_NUMBER_OF(mapped.Reason) - reasonOffset,
                                       L" a%lu=0x%llX", (unsigned long)i, (unsigned long long)HookEvent->Args[i]);
                reasonOffset = wcslen(mapped.Reason);
            }
        }
    }

    mapped.OriginAddress = HookEvent->Caller;
    mapped.StackCount = 0;
    mapped.NotifyClass = HookEvent->Kind;
    mapped.DataType = HookEvent->Operation;
    mapped.DataSize = sampleSize;
    mapped.DeepSampleSize = sampleSize;
    if (sampleSize != 0)
    {
        CopyMemory(mapped.DeepSample, HookEvent->DataSample, sampleSize);
    }

    ControllerDispatchEtwEvent(&mapped);
    return ERROR_SUCCESS;
}

static DWORD ControllerClientNotifyHookReady(
    _Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
    _In_ const BLACKBIRD_IPC_NOTIFY_HOOK_READY_REQUEST *Request,
    _Out_ BLACKBIRD_IPC_NOTIFY_HOOK_READY_RESPONSE *Response)
{
    DWORD observedMask;
    DWORD processId;

    if (Client == NULL || Request == NULL || Response == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (Request->ReadyMask == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    processId = (Request->ProcessId != 0) ? Request->ProcessId : Client->ProcessId;
    if (processId == 0 || processId != Client->ProcessId)
    {
        return ERROR_ACCESS_DENIED;
    }

    observedMask = (DWORD)InterlockedOr(&Client->HookReadyMask, (LONG)Request->ReadyMask) | Request->ReadyMask;
    Client->HookReadyTick = GetTickCount64();

    ZeroMemory(Response, sizeof(*Response));
    Response->ProcessId = processId;
    Response->ObservedMask = observedMask;
    Response->RequiredMask = BLACKBIRD_IPC_HOOK_READY_REQUIRED_MASK;

    if ((observedMask & BLACKBIRD_IPC_HOOK_READY_REQUIRED_MASK) == BLACKBIRD_IPC_HOOK_READY_REQUIRED_MASK)
    {
        ControllerLog("[IPC] hook-ready notify pid=%lu mask=0x%08lX (ready)\n", processId, observedMask);
    }

    return ERROR_SUCCESS;
}

static DWORD ControllerClientSetUserHookTarget(
    _Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client, _In_ const BLACKBIRD_IPC_SET_USER_HOOK_TARGET_REQUEST *Request,
    _Out_ BLACKBIRD_IPC_SET_USER_HOOK_TARGET_RESPONSE *Response)
{
    WCHAR hookDllPath[BLACKBIRD_MAX_IMAGE_PATH_CHARS];
    BLACKBIRD_QUERY_PROCESS_IMAGE_RESPONSE kernelImage;
    WIN32_FILE_ATTRIBUTE_DATA hookAttrs;
    BOOL hookPathVisible = FALSE;
    ULONGLONG hookSize = 0;
    DWORD err = ERROR_SUCCESS;
    DWORD targetPid = 0;
    BOOL kernelAssured = FALSE;

    if (Client == NULL || Request == NULL || Response == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    ZeroMemory(Response, sizeof(*Response));
    ZeroMemory(hookDllPath, sizeof(hookDllPath));
    ZeroMemory(&kernelImage, sizeof(kernelImage));

    if (!ControllerInjectionResolveHookDllPath(Request, hookDllPath, RTL_NUMBER_OF(hookDllPath)))
    {
        return GetLastError();
    }

    ZeroMemory(&hookAttrs, sizeof(hookAttrs));
    hookPathVisible = GetFileAttributesExW(hookDllPath, GetFileExInfoStandard, &hookAttrs);
    if (hookPathVisible)
    {
        hookSize = (((ULONGLONG)hookAttrs.nFileSizeHigh) << 32) | (ULONGLONG)hookAttrs.nFileSizeLow;
    }
    ControllerLog("[IPC] userhook resolved hook path=%ws visible=%u size=%llu\n", hookDllPath,
                  hookPathVisible ? 1u : 0u, (unsigned long long)hookSize);
    if (!hookPathVisible)
    {
        return ERROR_FILE_NOT_FOUND;
    }

    switch (Request->Mode)
    {
    case BlackbirdIpcUserHookTargetAttach:
        EnterCriticalSection(&Client->Lock);
        ControllerClientClearPendingLaunchLocked(Client);
        LeaveCriticalSection(&Client->Lock);
        if (Request->ProcessId == 0)
        {
            return ERROR_INVALID_PARAMETER;
        }
        if (!ControllerClientCanMonitorPid(Client, Request->ProcessId, NULL, NULL))
        {
            err = GetLastError();
            return err == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : err;
        }

        err = ControllerInjectionAttachAndVerify(Request->ProcessId, hookDllPath,
                                                 BLACKBIRD_CONTROLLER_INJECTION_VERIFY_TIMEOUT_MS);
        if (err != ERROR_SUCCESS)
        {
            return err;
        }

        targetPid = Request->ProcessId;
        break;

    case BlackbirdIpcUserHookTargetLaunch:
        if (Request->ImagePath[0] == L'\0' || !ControllerInjectionPathPointsToFile(Request->ImagePath))
        {
            return ERROR_FILE_NOT_FOUND;
        }
        err = ControllerEnsureCaptureReadyForLaunch();
        if (err != ERROR_SUCCESS)
        {
            return err;
        }

        EnterCriticalSection(&Client->Lock);
        ControllerClientArmPendingLaunchLocked(Client, Request->ImagePath);
        LeaveCriticalSection(&Client->Lock);

        err = ControllerInjectionLaunchAndVerify(Client->Pipe, Request->ImagePath, hookDllPath, Request->Flags,
                                                 BLACKBIRD_CONTROLLER_INJECTION_VERIFY_TIMEOUT_MS, &targetPid);
        if (err != ERROR_SUCCESS)
        {
            EnterCriticalSection(&Client->Lock);
            ControllerClientClearPendingLaunchLocked(Client);
            LeaveCriticalSection(&Client->Lock);
            return err;
        }
        EnterCriticalSection(&Client->Lock);
        ControllerClientPrimePendingLaunchPidLocked(Client, targetPid);
        LeaveCriticalSection(&Client->Lock);
        (void)ControllerApplyDriverSubscriptionsIfDirty();

        err = ControllerWaitForHookReady(targetPid);
        if (err != ERROR_SUCCESS)
        {
            EnterCriticalSection(&Client->Lock);
            ControllerClientClearPendingLaunchLocked(Client);
            LeaveCriticalSection(&Client->Lock);
            return err;
        }
        break;

    default:
        return ERROR_INVALID_PARAMETER;
    }

    if (targetPid != 0 && ControllerProxyQueryProcessImage(targetPid, &kernelImage))
    {
        kernelAssured = TRUE;
        (void)StringCchCopyW(Response->ImagePath, RTL_NUMBER_OF(Response->ImagePath), kernelImage.ImagePath);
    }
    else if (targetPid != 0)
    {
        BOOL driverConnected = FALSE;
        DWORD kernelErr = GetLastError();
        DWORD normalizedKernelErr = kernelErr;

        EnterCriticalSection(&g_DriverLock);
        driverConnected = (g_DriverHandle != INVALID_HANDLE_VALUE);
        LeaveCriticalSection(&g_DriverLock);
        if (driverConnected)
        {
            if (normalizedKernelErr == ERROR_SUCCESS || normalizedKernelErr == ERROR_NO_MORE_FILES ||
                normalizedKernelErr == ERROR_BAD_LENGTH || normalizedKernelErr == ERROR_PARTIAL_COPY)
            {
                normalizedKernelErr = ERROR_NOT_FOUND;
            }

            ControllerLog("[IPC][WARN] userhook kernel image probe failed pid=%lu err=%lu; continuing unassured\n",
                          targetPid, normalizedKernelErr);
        }
    }

    Response->ProcessId = targetPid;
    Response->Status = kernelAssured ? 1 : 0;
    if (!kernelAssured && Request->Mode == BlackbirdIpcUserHookTargetLaunch && Request->ImagePath[0] != L'\0')
    {
        (void)StringCchCopyW(Response->ImagePath, RTL_NUMBER_OF(Response->ImagePath), Request->ImagePath);
    }
    else if (!kernelAssured && targetPid != 0)
    {
        HANDLE queryHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
        if (queryHandle != NULL)
        {
            DWORD imageChars = (DWORD)RTL_NUMBER_OF(Response->ImagePath);
            if (!QueryFullProcessImageNameW(queryHandle, 0, Response->ImagePath, &imageChars))
            {
                Response->ImagePath[0] = L'\0';
            }
            CloseHandle(queryHandle);
        }
    }

    ControllerLog("[IPC] userhook mode=%lu flags=0x%08lX clientPid=%lu targetPid=%lu kernelAssured=%u hook=%ws\n",
                  Request->Mode, Request->Flags, Client->ProcessId, targetPid, kernelAssured ? 1u : 0u, hookDllPath);
    return ERROR_SUCCESS;
}

static PCSTR ControllerCommandName(_In_ UINT32 Command)
{
    switch (Command)
    {
    case BlackbirdIpcCommandHandshake:
        return "handshake";
    case BlackbirdIpcCommandSubscribe:
        return "subscribe";
    case BlackbirdIpcCommandUnsubscribe:
        return "unsubscribe";
    case BlackbirdIpcCommandSetPids:
        return "set-pids";
    case BlackbirdIpcCommandGetEvent:
        return "get-event";
    case BlackbirdIpcCommandGetStats:
        return "get-stats";
    case BlackbirdIpcCommandQueryProcessImage:
        return "query-process-image";
    case BlackbirdIpcCommandSetShutdownMode:
        return "set-shutdown-mode";
    case BlackbirdIpcCommandGetEtwEvent:
        return "get-etw-event";
    case BlackbirdIpcCommandOpenSharedRing:
        return "open-shared-ring";
    case BlackbirdIpcCommandPublishHookEvent:
        return "publish-hook-event";
    case BlackbirdIpcCommandSetUserHookTarget:
        return "set-user-hook-target";
    case BlackbirdIpcCommandNotifyHookReady:
        return "notify-hook-ready";
    default:
        return "unknown";
    }
}

static DWORD ControllerHandleClientCommand(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                           _In_ const BLACKBIRD_IPC_PACKET *Request,
                                           _Out_ BLACKBIRD_IPC_PACKET *Response)
{
    DWORD err = ERROR_SUCCESS;

    ControllerPrepareResponse(Request, Response);

    switch (Request->Command)
    {
    case BlackbirdIpcCommandHandshake:
        Response->Payload.HandshakeResponse.NegotiatedVersion = BLACKBIRD_IPC_VERSION;
        Response->Payload.HandshakeResponse.Capabilities =
            BLACKBIRD_IPC_CAP_DRIVER_PROXY | BLACKBIRD_IPC_CAP_ETW_TI_SESSION | BLACKBIRD_IPC_CAP_ETW_TI_UPLINK |
            BLACKBIRD_IPC_CAP_SHARED_RING | BLACKBIRD_IPC_CAP_USER_HOOK_INGEST | BLACKBIRD_IPC_CAP_USER_HOOK_READY;
        Response->Payload.HandshakeResponse.ThreatIntelEnabled = g_ThreatIntelEnabled ? 1u : 0u;
        Response->Payload.HandshakeResponse.Reserved = g_ThreatIntelEnableError;
        break;
    case BlackbirdIpcCommandSubscribe:
        err = ControllerClientSubscribe(Client, &Request->Payload.SubscribeRequest);
        break;
    case BlackbirdIpcCommandUnsubscribe:
        err = ControllerClientUnsubscribe(Client, &Request->Payload.UnsubscribeRequest);
        break;
    case BlackbirdIpcCommandSetPids:
        err = ControllerClientSetPids(Client, &Request->Payload.SetPidsRequest);
        break;
    case BlackbirdIpcCommandGetEvent:
        err = ControllerClientGetEvent(Client, Request->Payload.GetEventRequest.TimeoutMs, &Response->Payload.EventRecord);
        break;
    case BlackbirdIpcCommandGetStats:
        err = ControllerClientGetStats(Client, &Response->Payload.StatsResponse);
        break;
    case BlackbirdIpcCommandQueryProcessImage:
        if (Request->Payload.QueryProcessImageRequest.ProcessId == 0)
        {
            err = ERROR_INVALID_PARAMETER;
            break;
        }
        if (!ControllerClientCanMonitorPid(Client, Request->Payload.QueryProcessImageRequest.ProcessId, NULL, NULL))
        {
            err = GetLastError();
            if (err == ERROR_SUCCESS)
            {
                err = ERROR_ACCESS_DENIED;
            }
            break;
        }
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
    case BlackbirdIpcCommandSetShutdownMode:
        if (!ControllerProxySetShutdownMode())
        {
            err = GetLastError();
        }
        break;
    case BlackbirdIpcCommandGetEtwEvent:
        err = ControllerClientGetEtwEvent(Client, Request->Payload.GetEventRequest.TimeoutMs, &Response->Payload.EtwEvent);
        break;
    case BlackbirdIpcCommandOpenSharedRing:
        err = ControllerClientOpenSharedRing(Client, &Request->Payload.OpenSharedRingRequest,
                                             &Response->Payload.OpenSharedRingResponse);
        break;
    case BlackbirdIpcCommandPublishHookEvent:
        err = ControllerClientPublishHookEvent(Client, &Request->Payload.HookEvent);
        break;
    case BlackbirdIpcCommandSetUserHookTarget:
        err = ControllerClientSetUserHookTarget(Client, &Request->Payload.SetUserHookTargetRequest,
                                                &Response->Payload.SetUserHookTargetResponse);
        break;
    case BlackbirdIpcCommandNotifyHookReady:
        err = ControllerClientNotifyHookReady(Client, &Request->Payload.NotifyHookReadyRequest,
                                              &Response->Payload.NotifyHookReadyResponse);
        break;
    default:
        err = ERROR_INVALID_FUNCTION;
        break;
    }

    Response->Status = err;
    if (Request->Command != BlackbirdIpcCommandGetEvent && Request->Command != BlackbirdIpcCommandGetEtwEvent &&
        Request->Command != BlackbirdIpcCommandPublishHookEvent)
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
VOID ControllerDetachClient(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client)
{
    PBLACKBIRD_CONTROLLER_CLIENT *pp;

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
            Client->Detached = 1;
            *pp = Client->Next;
            if (Client->SlotIndex != BLACKBIRD_CONTROLLER_INVALID_SLOT)
            {
                ControllerReleaseClientSlotLocked(Client->SlotIndex);
                Client->SlotIndex = BLACKBIRD_CONTROLLER_INVALID_SLOT;
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
DWORD WINAPI ControllerClientThreadProc(_In_ LPVOID Context)
{
    BLACKBIRD_CONTROLLER_CLIENT *client = (BLACKBIRD_CONTROLLER_CLIENT *)Context;
    BLACKBIRD_IPC_PACKET request;
    BLACKBIRD_IPC_PACKET response;
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
        if (!ControllerValidatePacket(&request, BlackbirdIpcPacketRequest))
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
    if (client->DispatchIdleEvent != NULL)
    {
        (void)WaitForSingleObject(client->DispatchIdleEvent, 3000);
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
    free(client);
    return 0;
}
BOOL ControllerCreatePipeSecurity(_Out_ PSECURITY_ATTRIBUTES SecurityAttributes,
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






