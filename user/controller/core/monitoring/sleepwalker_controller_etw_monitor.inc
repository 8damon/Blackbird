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

static BOOL ControllerEtwGetI32Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ LONG *Value)
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

static BOOL ControllerEtwGetU8Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ UCHAR *Value)
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

static BOOL ControllerEtwGetBoolProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ BOOL *Value)
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

static BOOL ControllerEtwGetWideProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name,
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

static BOOL ControllerEtwCopyBinaryProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_writes_bytes_(Capacity) PBYTE Output,
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

static BOOL ControllerEtwResolveRelation(_In_ const SLEEPWALKER_IPC_ETW_EVENT *Event, _Out_ DWORD *SourcePid,
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
    case SleepwalkerIpcEtwFamilyHandle:
    case SleepwalkerIpcEtwFamilyApc:
        sourceValue = (Event->CallerPid != 0) ? Event->CallerPid : Event->ProcessId;
        targetValue = Event->TargetPid;
        break;
    case SleepwalkerIpcEtwFamilyThread:
        sourceValue = (Event->CreatorProcessId != 0) ? Event->CreatorProcessId : Event->ProcessId;
        targetValue = Event->ProcessId;
        break;
    case SleepwalkerIpcEtwFamilyProcess:
        sourceValue = (Event->CreatorProcessId != 0) ? Event->CreatorProcessId : Event->ParentProcessId;
        targetValue = Event->ProcessId;
        break;
    case SleepwalkerIpcEtwFamilyDetection:
    case SleepwalkerIpcEtwFamilyThreatIntel:
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
    DWORD sourcePid = 0;
    DWORD targetPid = 0;

    if (Event == NULL)
    {
        return;
    }

    if (ControllerEtwResolveRelation(Event, &sourcePid, &targetPid))
    {
        ControllerExpandMonitoringGraph(sourcePid, targetPid, SLEEPWALKER_CONTROLLER_DRIVER_STREAM_MASK);
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
