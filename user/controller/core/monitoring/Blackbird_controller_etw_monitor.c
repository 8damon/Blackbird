#include "../blackbird_controller_private.h"

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
BOOL ControllerEtwGetU64Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONGLONG *Value)
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
BOOL ControllerEtwGetU32Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONG *Value)
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
BOOL ControllerEtwGetI32Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ LONG *Value)
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
    if (size >= sizeof(LONG))
    {
        *Value = *(LONG *)raw;
        free(raw);
        return TRUE;
    }

    free(raw);
    return FALSE;
}
BOOL ControllerEtwGetU8Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ UCHAR *Value)
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
    if (size >= sizeof(UCHAR))
    {
        *Value = *raw;
        free(raw);
        return TRUE;
    }

    free(raw);
    return FALSE;
}
BOOL ControllerEtwGetBoolProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ BOOL *Value)
{
    PBYTE raw = NULL;
    ULONG size = 0;

    if (Value == NULL)
    {
        return FALSE;
    }
    *Value = FALSE;

    if (!ControllerEtwGetPropertyRaw(Record, Name, &raw, &size))
    {
        return FALSE;
    }
    if (size >= sizeof(ULONG))
    {
        *Value = (*(ULONG *)raw != 0) ? TRUE : FALSE;
        free(raw);
        return TRUE;
    }
    if (size >= sizeof(UCHAR))
    {
        *Value = (*raw != 0) ? TRUE : FALSE;
        free(raw);
        return TRUE;
    }

    free(raw);
    return FALSE;
}
BOOL ControllerEtwGetAnsiProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name,
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
BOOL ControllerEtwGetWideProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name,
                                         _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars)
{
    PBYTE raw = NULL;
    ULONG size = 0;

    if (Output == NULL || OutputChars == 0)
    {
        return FALSE;
    }
    Output[0] = L'\0';

    if (!ControllerEtwGetPropertyRaw(Record, Name, &raw, &size))
    {
        return FALSE;
    }

    if (size >= sizeof(WCHAR))
    {
        (void)StringCchCopyW(Output, OutputChars, (PCWSTR)raw);
        free(raw);
        return TRUE;
    }

    free(raw);
    return FALSE;
}
BOOL ControllerEtwCopyBinaryProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_writes_bytes_(Capacity) PBYTE Output,
                                            _In_ ULONG Capacity, _Out_opt_ UINT32 *BytesCopied)
{
    PBYTE raw = NULL;
    ULONG size = 0;
    ULONG copy = 0;

    if (Output == NULL || Capacity == 0)
    {
        return FALSE;
    }

    if (BytesCopied != NULL)
    {
        *BytesCopied = 0;
    }
    ZeroMemory(Output, Capacity);

    if (!ControllerEtwGetPropertyRaw(Record, Name, &raw, &size))
    {
        return FALSE;
    }

    copy = (size < Capacity) ? size : Capacity;
    if (copy != 0)
    {
        CopyMemory(Output, raw, copy);
    }
    free(raw);

    if (BytesCopied != NULL)
    {
        *BytesCopied = copy;
    }

    return (copy != 0);
}

static BOOL ControllerU64ToPid(_In_ ULONGLONG Value, _Out_ DWORD *ProcessId)
{
    if (ProcessId == NULL || Value == 0 || Value > 0xFFFFFFFFull)
    {
        return FALSE;
    }

    *ProcessId = (DWORD)Value;
    return TRUE;
}

static BOOL ControllerEtwEventMatchesPid(_In_ const BLACKBIRD_IPC_ETW_EVENT *Event, _In_ DWORD ProcessId)
{
    if (Event == NULL || ProcessId == 0)
    {
        return FALSE;
    }

    if (Event->EventProcessId == ProcessId)
    {
        return TRUE;
    }
    if (Event->ProcessId != 0 && Event->ProcessId <= 0xFFFFFFFFull && (DWORD)Event->ProcessId == ProcessId)
    {
        return TRUE;
    }
    if (Event->CallerPid != 0 && Event->CallerPid <= 0xFFFFFFFFull && (DWORD)Event->CallerPid == ProcessId)
    {
        return TRUE;
    }
    if (Event->TargetPid != 0 && Event->TargetPid <= 0xFFFFFFFFull && (DWORD)Event->TargetPid == ProcessId)
    {
        return TRUE;
    }
    if (Event->ParentProcessId != 0 && Event->ParentProcessId <= 0xFFFFFFFFull &&
        (DWORD)Event->ParentProcessId == ProcessId)
    {
        return TRUE;
    }
    if (Event->CreatorProcessId != 0 && Event->CreatorProcessId <= 0xFFFFFFFFull &&
        (DWORD)Event->CreatorProcessId == ProcessId)
    {
        return TRUE;
    }

    return FALSE;
}

static BOOL ControllerEtwResolveRelation(_In_ const BLACKBIRD_IPC_ETW_EVENT *Event, _Out_ DWORD *SourcePid,
                                         _Out_ DWORD *TargetPid)
{
    ULONGLONG sourceValue = 0;
    ULONGLONG targetValue = 0;

    if (Event == NULL || SourcePid == NULL || TargetPid == NULL)
    {
        return FALSE;
    }

    *SourcePid = 0;
    *TargetPid = 0;

    switch (Event->Family)
    {
    case BlackbirdIpcEtwFamilyHandle:
    case BlackbirdIpcEtwFamilyApc:
        sourceValue = (Event->CallerPid != 0) ? Event->CallerPid : Event->ProcessId;
        targetValue = Event->TargetPid;
        break;
    case BlackbirdIpcEtwFamilyThread:
        sourceValue = (Event->CreatorProcessId != 0) ? Event->CreatorProcessId : Event->ProcessId;
        targetValue = Event->ProcessId;
        break;
    case BlackbirdIpcEtwFamilyProcess:
        sourceValue = (Event->CreatorProcessId != 0) ? Event->CreatorProcessId : Event->ParentProcessId;
        targetValue = Event->ProcessId;
        break;
    case BlackbirdIpcEtwFamilyDetection:
    case BlackbirdIpcEtwFamilyThreatIntel:
    case BlackbirdIpcEtwFamilyUserHook:
    case BlackbirdIpcEtwFamilySocket:
        sourceValue = Event->ProcessId;
        targetValue = Event->TargetPid;
        break;
    default:
        return FALSE;
    }

    if (!ControllerU64ToPid(sourceValue, SourcePid) || !ControllerU64ToPid(targetValue, TargetPid))
    {
        *SourcePid = 0;
        *TargetPid = 0;
        return FALSE;
    }

    return TRUE;
}

static PCWSTR ControllerPathFileName(_In_opt_z_ PCWSTR Path)
{
    PCWSTR slash = NULL;
    PCWSTR fileName = Path;

    if (Path == NULL || Path[0] == L'\0')
    {
        return L"";
    }

    slash = wcsrchr(Path, L'\\');
    if (slash != NULL && slash[1] != L'\0')
    {
        fileName = slash + 1;
    }

    slash = wcsrchr(fileName, L'/');
    if (slash != NULL && slash[1] != L'\0')
    {
        fileName = slash + 1;
    }

    return fileName;
}

static BOOL ControllerPathEqualsInsensitive(_In_opt_z_ PCWSTR Left, _In_opt_z_ PCWSTR Right)
{
    PCWSTR leftFile;
    PCWSTR rightFile;

    if (Left == NULL || Right == NULL || Left[0] == L'\0' || Right[0] == L'\0')
    {
        return FALSE;
    }

    if (_wcsicmp(Left, Right) == 0)
    {
        return TRUE;
    }

    leftFile = ControllerPathFileName(Left);
    rightFile = ControllerPathFileName(Right);
    return (leftFile[0] != L'\0' && rightFile[0] != L'\0' && _wcsicmp(leftFile, rightFile) == 0);
}

static BOOL ControllerTryReadEventImagePath(_In_ const BLACKBIRD_IPC_ETW_EVENT *Event, _Outptr_result_z_ PCWSTR *Path)
{
    if (Path == NULL || Event == NULL)
    {
        return FALSE;
    }

    *Path = NULL;
    if ((Event->Family == BlackbirdIpcEtwFamilyProcess || Event->Family == BlackbirdIpcEtwFamilyImage) &&
        Event->ImagePath[0] != L'\0')
    {
        *Path = Event->ImagePath;
        return TRUE;
    }

    return FALSE;
}

static BOOL ControllerClientMatchPendingLaunchLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                                     _In_ const BLACKBIRD_IPC_ETW_EVENT *Event)
{
    PCWSTR eventImagePath = NULL;
    DWORD eventPid = 0;

    if (Client == NULL || Event == NULL)
    {
        return FALSE;
    }

    if (Client->PendingLaunchPid != 0 && ControllerEtwEventMatchesPid(Event, Client->PendingLaunchPid))
    {
        return TRUE;
    }

    if (!Client->PendingLaunchArmed || Client->PendingLaunchImagePath[0] == L'\0')
    {
        return FALSE;
    }

    if (!ControllerTryReadEventImagePath(Event, &eventImagePath))
    {
        return FALSE;
    }

    if (!ControllerPathEqualsInsensitive(Client->PendingLaunchImagePath, eventImagePath))
    {
        return FALSE;
    }

    if (Event->ProcessId != 0 && Event->ProcessId <= 0xFFFFFFFFull)
    {
        eventPid = (DWORD)Event->ProcessId;
    }
    else if (Event->EventProcessId != 0)
    {
        eventPid = Event->EventProcessId;
    }

    if (eventPid != 0)
    {
        DWORD i;

        Client->PendingLaunchPid = eventPid;
        Client->PendingLaunchArmed = FALSE;
        Client->PendingLaunchArmedTick = 0;

        for (i = 0; i < Client->SubscriptionCount; ++i)
        {
            if (Client->Subscriptions[i].ProcessId == eventPid)
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
                ControllerLog("[MON] pending launch matched clientPid=%lu targetPid=%lu image=%ws\n",
                              Client->ProcessId, eventPid, eventImagePath);
                return TRUE;
            }
        }

        if (Client->SubscriptionCount < BLACKBIRD_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS)
        {
            Client->Subscriptions[Client->SubscriptionCount].ProcessId = eventPid;
            Client->Subscriptions[Client->SubscriptionCount].StreamMask = BLACKBIRD_CONTROLLER_DRIVER_STREAM_MASK;
            Client->Subscriptions[Client->SubscriptionCount].Dynamic = FALSE;
            Client->Subscriptions[Client->SubscriptionCount].SourceProcessId = 0;
            Client->Subscriptions[Client->SubscriptionCount].Depth = 0;
            Client->Subscriptions[Client->SubscriptionCount].LastSeenTick = 0;
            Client->SubscriptionCount += 1;
            ControllerMarkDriverSubscriptionsDirty();
            ControllerLog("[MON] pending launch matched clientPid=%lu targetPid=%lu image=%ws\n",
                          Client->ProcessId, eventPid, eventImagePath);
        }
    }

    return TRUE;
}

static BOOL ControllerClientHasEtwMatchLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                              _In_ const BLACKBIRD_IPC_ETW_EVENT *Event)
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

    if (ControllerClientMatchPendingLaunchLocked(Client, Event))
    {
        return TRUE;
    }

    return FALSE;
}
VOID ControllerDispatchEtwEvent(_In_ const BLACKBIRD_IPC_ETW_EVENT *Event)
{
    BLACKBIRD_IPC_ETW_EVENT enriched;
    PBLACKBIRD_CONTROLLER_CLIENT client;
    PBLACKBIRD_CONTROLLER_CLIENT dispatchClients[BLACKBIRD_CONTROLLER_MAX_CLIENTS];
    DWORD dispatchCount = 0;
    DWORD sourcePid = 0;
    DWORD targetPid = 0;
    DWORD i;

    if (Event == NULL)
    {
        return;
    }

    enriched = *Event;
    ControllerSymbolServiceEnrichEvent(&enriched);

    if (ControllerEtwResolveRelation(&enriched, &sourcePid, &targetPid))
    {
        ControllerExpandMonitoringGraph(sourcePid, targetPid, BLACKBIRD_CONTROLLER_DRIVER_STREAM_MASK);
    }

    EnterCriticalSection(&g_ClientListLock);
    for (client = g_ClientList; client != NULL && dispatchCount < RTL_NUMBER_OF(dispatchClients); client = client->Next)
    {
        if (ControllerClientRetainForDispatchLocked(client))
        {
            dispatchClients[dispatchCount++] = client;
        }
    }
    LeaveCriticalSection(&g_ClientListLock);

    for (i = 0; i < dispatchCount; ++i)
    {
        client = dispatchClients[i];
        EnterCriticalSection(&client->Lock);
        if (ControllerClientHasEtwMatchLocked(client, &enriched))
        {
            (void)ControllerClientEnqueueEtwEventLocked(client, &enriched);
        }
        LeaveCriticalSection(&client->Lock);
        ControllerClientReleaseFromDispatch(client);
    }
}






