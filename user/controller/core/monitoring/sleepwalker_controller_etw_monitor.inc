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
    DWORD sourcePid = 0;
    DWORD targetPid = 0;

    if (Event == NULL)
    {
        return;
    }

    if (ControllerU64ToPid(Event->PrimaryPid, &sourcePid) && ControllerU64ToPid(Event->SecondaryPid, &targetPid))
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
