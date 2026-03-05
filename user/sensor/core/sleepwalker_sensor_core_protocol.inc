SLEEPWALKERSC_API VOID SLEEPWALKERSCUseServiceProtocol(VOID)
{
    AcquireSRWLockExclusive(&g_SleepwalkerProtocolLock);
    g_SleepwalkerProtocolMode = SLEEPWALKERSC_PROTOCOL_SERVICE;
    InterlockedExchange(&g_SleepwalkerBrokerCapabilities, 0);
    InterlockedExchange(&g_SleepwalkerBrokerThreatIntelEnabled, 0);
    InterlockedExchange(&g_SleepwalkerBrokerThreatIntelEnableError, 0);
    InterlockedExchange(&g_SleepwalkerLastSharedRingError, ERROR_NOT_FOUND);
    ReleaseSRWLockExclusive(&g_SleepwalkerProtocolLock);
}

SLEEPWALKERSC_API BOOL SLEEPWALKERSCUseClientProtocol(_In_opt_z_ PCWSTR PipeName, _In_ DWORD ConnectTimeoutMs)
{
    size_t pipeLength;

    AcquireSRWLockExclusive(&g_SleepwalkerProtocolLock);

    if (PipeName != NULL)
    {
        pipeLength = wcslen(PipeName);
        if (pipeLength == 0 || pipeLength >= RTL_NUMBER_OF(g_SleepwalkerPipeName))
        {
            ReleaseSRWLockExclusive(&g_SleepwalkerProtocolLock);
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        (void)StringCchCopyW(g_SleepwalkerPipeName, RTL_NUMBER_OF(g_SleepwalkerPipeName), PipeName);
    }
    else
    {
        (void)StringCchCopyW(g_SleepwalkerPipeName, RTL_NUMBER_OF(g_SleepwalkerPipeName), SLEEPWALKER_IPC_PIPE_NAME);
    }

    if (ConnectTimeoutMs == 0)
    {
        ConnectTimeoutMs = 3000;
    }
    g_SleepwalkerPipeTimeoutMs = ConnectTimeoutMs;
    g_SleepwalkerProtocolMode = SLEEPWALKERSC_PROTOCOL_CLIENT;
    InterlockedExchange(&g_SleepwalkerBrokerCapabilities, 0);
    InterlockedExchange(&g_SleepwalkerBrokerThreatIntelEnabled, 0);
    InterlockedExchange(&g_SleepwalkerBrokerThreatIntelEnableError, 0);
    InterlockedExchange(&g_SleepwalkerLastSharedRingError, ERROR_NOT_FOUND);
    ReleaseSRWLockExclusive(&g_SleepwalkerProtocolLock);
    return TRUE;
}

SLEEPWALKERSC_API SLEEPWALKERSC_PROTOCOL_MODE SLEEPWALKERSCGetProtocolMode(VOID)
{
    SLEEPWALKERSC_PROTOCOL_MODE mode;

    AcquireSRWLockShared(&g_SleepwalkerProtocolLock);
    mode = (SLEEPWALKERSC_PROTOCOL_MODE)g_SleepwalkerProtocolMode;
    ReleaseSRWLockShared(&g_SleepwalkerProtocolLock);
    return mode;
}

static VOID SLEEPWALKERSCGetClientTransportConfig(_Out_writes_z_(PipeChars) PWSTR PipeName, _In_ size_t PipeChars,
                                                  _Out_ DWORD *ConnectTimeoutMs)
{
    AcquireSRWLockShared(&g_SleepwalkerProtocolLock);
    if (PipeName != NULL && PipeChars > 0)
    {
        (void)StringCchCopyW(PipeName, PipeChars, g_SleepwalkerPipeName);
    }
    if (ConnectTimeoutMs != NULL)
    {
        *ConnectTimeoutMs = g_SleepwalkerPipeTimeoutMs;
    }
    ReleaseSRWLockShared(&g_SleepwalkerProtocolLock);
}

static BOOL SLEEPWALKERSCIsClientProtocol(VOID)
{
    return (SLEEPWALKERSCGetProtocolMode() == SLEEPWALKERSC_PROTOCOL_CLIENT);
}

typedef struct _SLEEPWALKERSC_SHARED_CHANNEL
{
    struct _SLEEPWALKERSC_SHARED_CHANNEL *Next;
    volatile LONG RefCount;
    HANDLE Device;
    HANDLE IoctlMapping;
    HANDLE IoctlDataReadyEvent;
    volatile SLEEPWALKER_IPC_SHARED_RING_HEADER *IoctlHeader;
    PBYTE IoctlRecords;
    HANDLE EtwMapping;
    HANDLE EtwDataReadyEvent;
    volatile SLEEPWALKER_IPC_SHARED_RING_HEADER *EtwHeader;
    PBYTE EtwRecords;
} SLEEPWALKERSC_SHARED_CHANNEL, *PSLEEPWALKERSC_SHARED_CHANNEL;

static SRWLOCK g_SleepwalkerSharedChannelLock = SRWLOCK_INIT;
static PSLEEPWALKERSC_SHARED_CHANNEL g_SleepwalkerSharedChannels = NULL;

static BOOL SLEEPWALKERSCPopSharedRing(_Inout_ volatile SLEEPWALKER_IPC_SHARED_RING_HEADER *Header,
                                       _In_reads_bytes_(Header->Capacity * Header->RecordSize) const BYTE *Records,
                                       _In_ HANDLE DataReadyEvent, _Out_writes_bytes_(RecordSize) VOID *Record,
                                       _In_ UINT32 RecordSize)
{
    LONG writeIndex;
    LONG readIndex;
    LONG nextIndex;

    if (Header == NULL || Records == NULL || Record == NULL || DataReadyEvent == NULL || DataReadyEvent == INVALID_HANDLE_VALUE ||
        Header->Capacity == 0 || Header->RecordSize != RecordSize || RecordSize == 0)
    {
        return FALSE;
    }

    writeIndex = Header->WriteIndex;
    readIndex = Header->ReadIndex;
    if (writeIndex < 0 || readIndex < 0 || writeIndex >= (LONG)Header->Capacity || readIndex >= (LONG)Header->Capacity)
    {
        Header->WriteIndex = 0;
        Header->ReadIndex = 0;
        return FALSE;
    }

    if (readIndex == writeIndex)
    {
        return FALSE;
    }

    (void)CopyMemory(Record, Records + ((SIZE_T)readIndex * (SIZE_T)RecordSize), RecordSize);
    MemoryBarrier();
    nextIndex = readIndex + 1;
    if (nextIndex >= (LONG)Header->Capacity)
    {
        nextIndex = 0;
    }
    Header->ReadIndex = nextIndex;
    if (nextIndex == Header->WriteIndex)
    {
        (void)ResetEvent(DataReadyEvent);
        MemoryBarrier();
        if (nextIndex != Header->WriteIndex)
        {
            (void)SetEvent(DataReadyEvent);
        }
    }
    return TRUE;
}

static VOID SLEEPWALKERSCReleaseSharedChannel(_Inout_ PSLEEPWALKERSC_SHARED_CHANNEL Channel)
{
    if (Channel == NULL)
    {
        return;
    }

    if (Channel->IoctlHeader != NULL)
    {
        (void)UnmapViewOfFile((PVOID)Channel->IoctlHeader);
        Channel->IoctlHeader = NULL;
        Channel->IoctlRecords = NULL;
    }
    if (Channel->EtwHeader != NULL)
    {
        (void)UnmapViewOfFile((PVOID)Channel->EtwHeader);
        Channel->EtwHeader = NULL;
        Channel->EtwRecords = NULL;
    }

    if (Channel->IoctlDataReadyEvent != NULL && Channel->IoctlDataReadyEvent != INVALID_HANDLE_VALUE)
    {
        (void)CloseHandle(Channel->IoctlDataReadyEvent);
        Channel->IoctlDataReadyEvent = NULL;
    }
    if (Channel->EtwDataReadyEvent != NULL && Channel->EtwDataReadyEvent != INVALID_HANDLE_VALUE)
    {
        (void)CloseHandle(Channel->EtwDataReadyEvent);
        Channel->EtwDataReadyEvent = NULL;
    }

    if (Channel->IoctlMapping != NULL && Channel->IoctlMapping != INVALID_HANDLE_VALUE)
    {
        (void)CloseHandle(Channel->IoctlMapping);
        Channel->IoctlMapping = NULL;
    }
    if (Channel->EtwMapping != NULL && Channel->EtwMapping != INVALID_HANDLE_VALUE)
    {
        (void)CloseHandle(Channel->EtwMapping);
        Channel->EtwMapping = NULL;
    }
}

static PSLEEPWALKERSC_SHARED_CHANNEL SLEEPWALKERSCRetainSharedChannel(_In_ HANDLE Device)
{
    PSLEEPWALKERSC_SHARED_CHANNEL channel;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }

    AcquireSRWLockShared(&g_SleepwalkerSharedChannelLock);
    for (channel = g_SleepwalkerSharedChannels; channel != NULL; channel = channel->Next)
    {
        if (channel->Device == Device)
        {
            (void)InterlockedIncrement(&channel->RefCount);
            break;
        }
    }
    ReleaseSRWLockShared(&g_SleepwalkerSharedChannelLock);
    return channel;
}

static VOID SLEEPWALKERSCReleaseSharedChannelRef(_In_opt_ PSLEEPWALKERSC_SHARED_CHANNEL Channel)
{
    if (Channel == NULL)
    {
        return;
    }

    if (InterlockedDecrement(&Channel->RefCount) == 0)
    {
        SLEEPWALKERSCReleaseSharedChannel(Channel);
        free(Channel);
    }
}

static VOID SLEEPWALKERSCForgetSharedChannel(_In_ HANDLE Device)
{
    PSLEEPWALKERSC_SHARED_CHANNEL *pp;
    PSLEEPWALKERSC_SHARED_CHANNEL channel = NULL;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE)
    {
        return;
    }

    AcquireSRWLockExclusive(&g_SleepwalkerSharedChannelLock);
    pp = &g_SleepwalkerSharedChannels;
    while (*pp != NULL)
    {
        if ((*pp)->Device == Device)
        {
            channel = *pp;
            *pp = channel->Next;
            break;
        }
        pp = &(*pp)->Next;
    }
    ReleaseSRWLockExclusive(&g_SleepwalkerSharedChannelLock);

    if (channel != NULL)
    {
        channel->Next = NULL;
        SLEEPWALKERSCReleaseSharedChannelRef(channel);
    }
}

static BOOL SLEEPWALKERSCRegisterSharedChannel(_In_ HANDLE Device,
                                               _In_ const SLEEPWALKER_IPC_OPEN_SHARED_RING_RESPONSE *Response)
{
    PSLEEPWALKERSC_SHARED_CHANNEL channel;
    SIZE_T ioctlViewBytes;
    SIZE_T etwViewBytes;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE || Response == NULL || Response->IoctlMappingHandle == 0 ||
        Response->IoctlDataReadyEventHandle == 0 || Response->EtwMappingHandle == 0 ||
        Response->EtwDataReadyEventHandle == 0 || Response->IoctlCapacity == 0 || Response->EtwCapacity == 0 ||
        Response->IoctlRecordSize != sizeof(SLEEPWALKER_EVENT_RECORD) ||
        Response->EtwRecordSize != sizeof(SLEEPWALKER_IPC_ETW_EVENT))
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    SLEEPWALKERSCForgetSharedChannel(Device);

    channel = (PSLEEPWALKERSC_SHARED_CHANNEL)calloc(1, sizeof(*channel));
    if (channel == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    channel->Device = Device;
    channel->RefCount = 1;
    channel->IoctlMapping = (HANDLE)(ULONG_PTR)Response->IoctlMappingHandle;
    channel->IoctlDataReadyEvent = (HANDLE)(ULONG_PTR)Response->IoctlDataReadyEventHandle;
    channel->EtwMapping = (HANDLE)(ULONG_PTR)Response->EtwMappingHandle;
    channel->EtwDataReadyEvent = (HANDLE)(ULONG_PTR)Response->EtwDataReadyEventHandle;

    ioctlViewBytes = sizeof(SLEEPWALKER_IPC_SHARED_RING_HEADER) +
                     ((SIZE_T)Response->IoctlCapacity * (SIZE_T)Response->IoctlRecordSize);
    etwViewBytes = sizeof(SLEEPWALKER_IPC_SHARED_RING_HEADER) +
                   ((SIZE_T)Response->EtwCapacity * (SIZE_T)Response->EtwRecordSize);

    channel->IoctlHeader =
        (volatile SLEEPWALKER_IPC_SHARED_RING_HEADER *)MapViewOfFile(channel->IoctlMapping,
                                                                      FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                                                                      ioctlViewBytes);
    channel->EtwHeader =
        (volatile SLEEPWALKER_IPC_SHARED_RING_HEADER *)MapViewOfFile(channel->EtwMapping,
                                                                      FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                                                                      etwViewBytes);
    if (channel->IoctlHeader == NULL || channel->EtwHeader == NULL)
    {
        DWORD err = GetLastError();
        SLEEPWALKERSCReleaseSharedChannel(channel);
        free(channel);
        SetLastError(err);
        return FALSE;
    }

    channel->IoctlRecords = ((PBYTE)channel->IoctlHeader) + sizeof(SLEEPWALKER_IPC_SHARED_RING_HEADER);
    channel->EtwRecords = ((PBYTE)channel->EtwHeader) + sizeof(SLEEPWALKER_IPC_SHARED_RING_HEADER);

    AcquireSRWLockExclusive(&g_SleepwalkerSharedChannelLock);
    channel->Next = g_SleepwalkerSharedChannels;
    g_SleepwalkerSharedChannels = channel;
    ReleaseSRWLockExclusive(&g_SleepwalkerSharedChannelLock);
    return TRUE;
}

static BOOL SLEEPWALKERSCIpcTransact(_In_ HANDLE Device, _In_ const SLEEPWALKER_IPC_PACKET *Request,
                                     _Out_ SLEEPWALKER_IPC_PACKET *Response)
{
    DWORD bytes = 0;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE || Request == NULL || Response == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!WriteFile(Device, Request, sizeof(*Request), &bytes, NULL) || bytes != sizeof(*Request))
    {
        return FALSE;
    }

    bytes = 0;
    if (!ReadFile(Device, Response, sizeof(*Response), &bytes, NULL) || bytes != sizeof(*Response))
    {
        return FALSE;
    }

    if (Response->Magic != SLEEPWALKER_IPC_MAGIC || Response->Version != SLEEPWALKER_IPC_VERSION ||
        Response->PacketType != SleepwalkerIpcPacketResponse || Response->Command != Request->Command ||
        Response->Sequence != Request->Sequence)
    {
        SetLastError(ERROR_BAD_FORMAT);
        return FALSE;
    }

    if (Response->Status != ERROR_SUCCESS)
    {
        SetLastError(Response->Status);
        return FALSE;
    }

    return TRUE;
}

static VOID SLEEPWALKERSCInitIpcRequest(_Out_ SLEEPWALKER_IPC_PACKET *Request, _In_ UINT32 Command)
{
    ZeroMemory(Request, sizeof(*Request));
    Request->Magic = SLEEPWALKER_IPC_MAGIC;
    Request->Version = SLEEPWALKER_IPC_VERSION;
    Request->PacketType = SleepwalkerIpcPacketRequest;
    Request->Command = Command;
    Request->Sequence = (UINT32)InterlockedIncrement(&g_SleepwalkerIpcSequence);
}

static VOID WINAPI SLEEPWALKERSCInternalRecordCallback(_In_ PEVENT_RECORD Record)
{
    SLEEPWALKERSC_ETW_SESSION_INTERNAL *session;
    PTRACE_EVENT_INFO info = NULL;
    ULONG size = 0;
    TDHSTATUS status;
    PCWSTR eventName = NULL;

    if (Record == NULL)
    {
        return;
    }

    session = (SLEEPWALKERSC_ETW_SESSION_INTERNAL *)Record->UserContext;
    if (session == NULL || session->Callback == NULL)
    {
        return;
    }

    status = TdhGetEventInformation(Record, 0, NULL, NULL, &size);
    if (status == ERROR_INSUFFICIENT_BUFFER && size != 0)
    {
        info = (PTRACE_EVENT_INFO)malloc(size);
        if (info != NULL)
        {
            status = TdhGetEventInformation(Record, 0, NULL, info, &size);
            if (status == ERROR_SUCCESS && info->EventNameOffset != 0)
            {
                eventName = (PCWSTR)(((PBYTE)info) + info->EventNameOffset);
            }
        }
    }

    session->Callback(Record, eventName, session->CallbackContext);

    if (info != NULL)
    {
        free(info);
    }
}

static VOID SLEEPWALKERSCCopyAnsiToWide(_In_z_ const char *Source, _Out_writes_z_(OutputChars) PWSTR Output,
                                        _In_ size_t OutputChars)
{
    int converted;

    if (Output == NULL || OutputChars == 0)
    {
        return;
    }
    Output[0] = L'\0';

    if (Source == NULL || Source[0] == '\0')
    {
        return;
    }

    converted = MultiByteToWideChar(CP_UTF8, 0, Source, -1, Output, (int)OutputChars);
    if (converted <= 0)
    {
        converted = MultiByteToWideChar(CP_ACP, 0, Source, -1, Output, (int)OutputChars);
    }
    if (converted <= 0)
    {
        Output[0] = L'\0';
    }
}

static VOID WINAPI SLEEPWALKERSCStgDetectionBridgeCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                                           _In_opt_ PVOID Context)
{
    SLEEPWALKERSC_STG_DETECTION_BRIDGE *bridge = (SLEEPWALKERSC_STG_DETECTION_BRIDGE *)Context;
    SwkDetectionEvent event;
    char detectionNameAnsi[128];

    if (Record == NULL || bridge == NULL || bridge->Callback == NULL)
    {
        return;
    }

    if (!IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_SLEEPWALKER))
    {
        return;
    }

    if (EventName == NULL || wcscmp(EventName, L"DetectionTelemetry") != 0)
    {
        return;
    }

    ZeroMemory(&event, sizeof(event));
    ZeroMemory(detectionNameAnsi, sizeof(detectionNameAnsi));

    event.EtwProcessId = Record->EventHeader.ProcessId;
    event.EtwThreadId = Record->EventHeader.ThreadId;
    event.TimestampQpc = (ULONGLONG)Record->EventHeader.TimeStamp.QuadPart;

    (void)SLEEPWALKERGetU32Property(Record, L"severity", &event.Severity);
    (void)SLEEPWALKERGetU64Property(Record, L"processId", &event.ProcessId);
    (void)SLEEPWALKERGetU64Property(Record, L"targetPid", &event.TargetPid);
    (void)SLEEPWALKERGetU32Property(Record, L"correlationFlags", &event.CorrelationFlags);
    (void)SLEEPWALKERGetU32Property(Record, L"correlationAccessMask", &event.CorrelationAccessMask);
    (void)SLEEPWALKERGetU32Property(Record, L"correlationAgeMs", &event.CorrelationAgeMs);
    (void)SLEEPWALKERGetWideProperty(Record, L"reason", event.Reason, RTL_NUMBER_OF(event.Reason));

    if (SLEEPWALKERGetAnsiProperty(Record, L"detectionName", detectionNameAnsi, RTL_NUMBER_OF(detectionNameAnsi)))
    {
        SLEEPWALKERSCCopyAnsiToWide(detectionNameAnsi, event.DetectionName, RTL_NUMBER_OF(event.DetectionName));
    }
    if (event.DetectionName[0] == L'\0')
    {
        (void)StringCchCopyW(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), L"UNKNOWN");
    }

    bridge->Callback(&event, bridge->CallbackContext);
}

HANDLE
SLEEPWALKERSCOpenControlDevice(VOID)
{
    HANDLE h;

    if (!SLEEPWALKERSCIsClientProtocol())
    {
        InterlockedExchange(&g_SleepwalkerBrokerCapabilities, 0);
        InterlockedExchange(&g_SleepwalkerBrokerThreatIntelEnabled, 0);
        InterlockedExchange(&g_SleepwalkerBrokerThreatIntelEnableError, 0);
        h = CreateFileW(L"\\\\.\\Global\\SleepwalkerCtl", GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        return h;
    }
    else
    {
        WCHAR pipeName[MAX_PATH];
        DWORD timeoutMs = 0;
        DWORD mode = PIPE_READMODE_MESSAGE;
        SLEEPWALKER_IPC_PACKET request;
        SLEEPWALKER_IPC_PACKET response;

        SLEEPWALKERSCGetClientTransportConfig(pipeName, RTL_NUMBER_OF(pipeName), &timeoutMs);
        if (!WaitNamedPipeW(pipeName, timeoutMs))
        {
            return INVALID_HANDLE_VALUE;
        }

        h = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE)
        {
            return h;
        }

        (void)SetNamedPipeHandleState(h, &mode, NULL, NULL);

        SLEEPWALKERSCInitIpcRequest(&request, SleepwalkerIpcCommandHandshake);
        request.Payload.HandshakeRequest.RequestedVersion = SLEEPWALKER_IPC_VERSION;
        if (!SLEEPWALKERSCIpcTransact(h, &request, &response))
        {
            (void)SLEEPWALKERSCCloseControlDevice(h);
            return INVALID_HANDLE_VALUE;
        }

        if (response.Payload.HandshakeResponse.NegotiatedVersion == 0 ||
            response.Payload.HandshakeResponse.NegotiatedVersion > SLEEPWALKER_IPC_VERSION)
        {
            (void)SLEEPWALKERSCCloseControlDevice(h);
            SetLastError(ERROR_REVISION_MISMATCH);
            return INVALID_HANDLE_VALUE;
        }

        InterlockedExchange(&g_SleepwalkerBrokerCapabilities, (LONG)response.Payload.HandshakeResponse.Capabilities);
        InterlockedExchange(&g_SleepwalkerBrokerThreatIntelEnabled,
                            response.Payload.HandshakeResponse.ThreatIntelEnabled ? 1 : 0);
        InterlockedExchange(&g_SleepwalkerBrokerThreatIntelEnableError,
                            (LONG)response.Payload.HandshakeResponse.Reserved);
        InterlockedExchange(&g_SleepwalkerLastSharedRingError, ERROR_NOT_FOUND);

        {
            BOOL ringReady = FALSE;
            DWORD ringErr = ERROR_SUCCESS;
            SLEEPWALKER_IPC_PACKET ringRequest;
            SLEEPWALKER_IPC_PACKET ringResponse;

            SLEEPWALKERSCInitIpcRequest(&ringRequest, SleepwalkerIpcCommandOpenSharedRing);
            ringRequest.Payload.OpenSharedRingRequest.DesiredIoctlCapacity = 0;
            ringRequest.Payload.OpenSharedRingRequest.DesiredEtwCapacity = 0;
            if (SLEEPWALKERSCIpcTransact(h, &ringRequest, &ringResponse))
            {
                if (SLEEPWALKERSCRegisterSharedChannel(h, &ringResponse.Payload.OpenSharedRingResponse))
                {
                    ringReady = TRUE;
                    ringErr = ERROR_SUCCESS;
                }
                else
                {
                    ringErr = GetLastError();
                }
            }
            else
            {
                ringErr = GetLastError();
            }

            if (ringReady)
            {
                InterlockedOr(&g_SleepwalkerBrokerCapabilities, (LONG)SLEEPWALKER_IPC_CAP_SHARED_RING);
                InterlockedExchange(&g_SleepwalkerLastSharedRingError, ERROR_SUCCESS);
            }
            else
            {
                InterlockedAnd(&g_SleepwalkerBrokerCapabilities, ~(LONG)SLEEPWALKER_IPC_CAP_SHARED_RING);
                if (ringErr == ERROR_SUCCESS)
                {
                    ringErr = ERROR_NOT_FOUND;
                }
                InterlockedExchange(&g_SleepwalkerLastSharedRingError, (LONG)ringErr);
                (void)SLEEPWALKERSCCloseControlDevice(h);
                SetLastError(ringErr);
                return INVALID_HANDLE_VALUE;
            }
        }

        return h;
    }
}

SLEEPWALKERSC_API BOOL SLEEPWALKERSCCloseControlDevice(_In_opt_ HANDLE Device)
{
    BOOL ok;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    SLEEPWALKERSCForgetSharedChannel(Device);
    ok = CloseHandle(Device);
    return ok;
}

BOOL SLEEPWALKERSCGetBrokerInfo(_Out_opt_ UINT32 *Capabilities, _Out_opt_ BOOL *ThreatIntelEnabled)
{
    if (!SLEEPWALKERSCIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    if (Capabilities != NULL)
    {
        *Capabilities = (UINT32)InterlockedCompareExchange(&g_SleepwalkerBrokerCapabilities, 0, 0);
    }
    if (ThreatIntelEnabled != NULL)
    {
        *ThreatIntelEnabled = (InterlockedCompareExchange(&g_SleepwalkerBrokerThreatIntelEnabled, 0, 0) != 0);
    }
    return TRUE;
}

SLEEPWALKERSC_API BOOL SLEEPWALKERSCHasSharedChannel(_In_ HANDLE Device, _Out_opt_ BOOL *HasIoctlChannel,
                                                     _Out_opt_ BOOL *HasEtwChannel)
{
    PSLEEPWALKERSC_SHARED_CHANNEL channel;
    BOOL hasIoctl = FALSE;
    BOOL hasEtw = FALSE;

    if (!SLEEPWALKERSCIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    if (Device == NULL || Device == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    channel = SLEEPWALKERSCRetainSharedChannel(Device);
    if (channel != NULL)
    {
        hasIoctl = (channel->IoctlHeader != NULL && channel->IoctlRecords != NULL);
        hasEtw = (channel->EtwHeader != NULL && channel->EtwRecords != NULL);
        SLEEPWALKERSCReleaseSharedChannelRef(channel);
    }

    if (HasIoctlChannel != NULL)
    {
        *HasIoctlChannel = hasIoctl;
    }
    if (HasEtwChannel != NULL)
    {
        *HasEtwChannel = hasEtw;
    }
    return TRUE;
}

SLEEPWALKERSC_API DWORD SLEEPWALKERSCGetLastSharedRingError(VOID)
{
    return (DWORD)InterlockedCompareExchange(&g_SleepwalkerLastSharedRingError, 0, 0);
}

DWORD SLEEPWALKERSCGetBrokerThreatIntelEnableError(VOID)
{
    if (!SLEEPWALKERSCIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return ERROR_NOT_SUPPORTED;
    }

    return (DWORD)InterlockedCompareExchange(&g_SleepwalkerBrokerThreatIntelEnableError, 0, 0);
}

DWORD SLEEPWALKERSCGetLastThreatIntelEnableError(VOID)
{
    return (DWORD)InterlockedCompareExchange(&g_SleepwalkerLastTiEnableError, 0, 0);
}

BOOL SLEEPWALKERSCSubscribe(_In_ HANDLE Device, _In_ DWORD ProcessId, _In_ DWORD StreamMask)
{
    SLEEPWALKER_SUBSCRIBE_REQUEST req;
    DWORD bytes = 0;
    SLEEPWALKER_IPC_PACKET request;
    SLEEPWALKER_IPC_PACKET response;

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = ProcessId;
    req.StreamMask = StreamMask;

    if (SLEEPWALKERSCIsClientProtocol())
    {
        SLEEPWALKERSCInitIpcRequest(&request, SleepwalkerIpcCommandSubscribe);
        request.Payload.SubscribeRequest = req;
        return SLEEPWALKERSCIpcTransact(Device, &request, &response);
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_SLEEPWALKER_SUBSCRIBE, &req, sizeof(req), NULL, 0, &bytes, NULL);
}

BOOL SLEEPWALKERSCUnsubscribe(_In_ HANDLE Device, _In_ DWORD ProcessId)
{
    SLEEPWALKER_UNSUBSCRIBE_REQUEST req;
    DWORD bytes = 0;
    SLEEPWALKER_IPC_PACKET request;
    SLEEPWALKER_IPC_PACKET response;

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = ProcessId;

    if (SLEEPWALKERSCIsClientProtocol())
    {
        SLEEPWALKERSCInitIpcRequest(&request, SleepwalkerIpcCommandUnsubscribe);
        request.Payload.UnsubscribeRequest = req;
        return SLEEPWALKERSCIpcTransact(Device, &request, &response);
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_SLEEPWALKER_UNSUBSCRIBE, &req, sizeof(req), NULL, 0, &bytes, NULL);
}

BOOL SLEEPWALKERSCSetPids(_In_ HANDLE Device, _In_reads_(ProcessCount) const DWORD *ProcessIds, _In_ DWORD ProcessCount,
                          _In_ DWORD StreamMask)
{
    SLEEPWALKER_SET_PIDS_REQUEST req;
    DWORD bytes = 0;
    DWORD i;
    SLEEPWALKER_IPC_PACKET request;
    SLEEPWALKER_IPC_PACKET response;

    if (ProcessIds == NULL || ProcessCount == 0 || ProcessCount > SLEEPWALKER_MAX_PID_LIST)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(&req, sizeof(req));
    req.StreamMask = StreamMask;
    req.ProcessCount = ProcessCount;

    for (i = 0; i < ProcessCount; ++i)
    {
        req.ProcessIds[i] = ProcessIds[i];
    }

    if (SLEEPWALKERSCIsClientProtocol())
    {
        SLEEPWALKERSCInitIpcRequest(&request, SleepwalkerIpcCommandSetPids);
        request.Payload.SetPidsRequest = req;
        return SLEEPWALKERSCIpcTransact(Device, &request, &response);
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_SLEEPWALKER_SET_PIDS, &req, sizeof(req), NULL, 0, &bytes, NULL);
}

BOOL SLEEPWALKERSCGetEvent(_In_ HANDLE Device, _Out_ SLEEPWALKER_EVENT_RECORD *Record, _Out_opt_ DWORD *BytesReturned)
{
    DWORD bytes = 0;
    BOOL ok;
    PSLEEPWALKERSC_SHARED_CHANNEL channel;

    if (Record == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Record, sizeof(*Record));
    if (SLEEPWALKERSCIsClientProtocol())
    {
        channel = SLEEPWALKERSCRetainSharedChannel(Device);
        if (channel != NULL && channel->IoctlHeader != NULL)
        {
            ok = SLEEPWALKERSCPopSharedRing(channel->IoctlHeader, channel->IoctlRecords, channel->IoctlDataReadyEvent,
                                            Record, sizeof(*Record));
            if (!ok)
            {
                (void)WaitForSingleObject(channel->IoctlDataReadyEvent, 20);
                ok = SLEEPWALKERSCPopSharedRing(channel->IoctlHeader, channel->IoctlRecords,
                                                channel->IoctlDataReadyEvent, Record, sizeof(*Record));
            }
            if (ok)
            {
                bytes = sizeof(*Record);
            }
            else
            {
                SetLastError(ERROR_NO_MORE_ITEMS);
            }
            SLEEPWALKERSCReleaseSharedChannelRef(channel);
        }
        else
        {
            if (channel != NULL)
            {
                SLEEPWALKERSCReleaseSharedChannelRef(channel);
            }
            ok = FALSE;
            SetLastError(ERROR_NOT_SUPPORTED);
        }
    }
    else
    {
        ok = DeviceIoControl(Device, (DWORD)IOCTL_SLEEPWALKER_GET_EVENT, NULL, 0, Record, sizeof(*Record), &bytes, NULL);
    }

    if (BytesReturned != NULL)
    {
        *BytesReturned = bytes;
    }
    return ok;
}

BOOL SLEEPWALKERSCGetStats(_In_ HANDLE Device, _Out_ SLEEPWALKER_STATS_RESPONSE *Stats, _Out_opt_ DWORD *BytesReturned)
{
    DWORD bytes = 0;
    BOOL ok;
    SLEEPWALKER_IPC_PACKET request;
    SLEEPWALKER_IPC_PACKET response;

    if (Stats == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Stats, sizeof(*Stats));
    if (SLEEPWALKERSCIsClientProtocol())
    {
        SLEEPWALKERSCInitIpcRequest(&request, SleepwalkerIpcCommandGetStats);
        ok = SLEEPWALKERSCIpcTransact(Device, &request, &response);
        if (ok)
        {
            *Stats = response.Payload.StatsResponse;
            bytes = sizeof(*Stats);
        }
    }
    else
    {
        ok = DeviceIoControl(Device, (DWORD)IOCTL_SLEEPWALKER_GET_STATS, NULL, 0, Stats, sizeof(*Stats), &bytes, NULL);
    }

    if (BytesReturned != NULL)
    {
        *BytesReturned = bytes;
    }
    return ok;
}

BOOL SLEEPWALKERSCQueryProcessImagePath(_In_ HANDLE Device, _In_ DWORD ProcessId,
                                        _Out_writes_z_(OutputChars) PWSTR Output, _In_ DWORD OutputChars)
{
    SLEEPWALKER_QUERY_PROCESS_IMAGE_REQUEST req;
    SLEEPWALKER_QUERY_PROCESS_IMAGE_RESPONSE resp;
    DWORD bytes = 0;
    BOOL ok;
    SLEEPWALKER_IPC_PACKET request;
    SLEEPWALKER_IPC_PACKET response;

    if (Output == NULL || OutputChars == 0 || ProcessId == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    Output[0] = L'\0';

    ZeroMemory(&req, sizeof(req));
    ZeroMemory(&resp, sizeof(resp));
    req.ProcessId = ProcessId;

    if (SLEEPWALKERSCIsClientProtocol())
    {
        SLEEPWALKERSCInitIpcRequest(&request, SleepwalkerIpcCommandQueryProcessImage);
        request.Payload.QueryProcessImageRequest = req;
        ok = SLEEPWALKERSCIpcTransact(Device, &request, &response);
        if (ok)
        {
            resp = response.Payload.QueryProcessImageResponse;
            bytes = sizeof(resp);
        }
    }
    else
    {
        ok = DeviceIoControl(Device, (DWORD)IOCTL_SLEEPWALKER_QUERY_PROCESS_IMAGE, &req, sizeof(req), &resp, sizeof(resp),
                             &bytes, NULL);
    }
    if (!ok)
    {
        return FALSE;
    }
    if (bytes < sizeof(resp.ProcessId) + sizeof(resp.Status))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (!NT_SUCCESS(resp.Status) || resp.ImagePath[0] == L'\0')
    {
        SetLastError(ERROR_NOT_FOUND);
        return FALSE;
    }
    if (FAILED(StringCchCopyW(Output, OutputChars, resp.ImagePath)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return TRUE;
}

BOOL SLEEPWALKERSCSetShutdownMode(_In_ HANDLE Device)
{
    DWORD bytes = 0;
    SLEEPWALKER_IPC_PACKET request;
    SLEEPWALKER_IPC_PACKET response;

    if (SLEEPWALKERSCIsClientProtocol())
    {
        SLEEPWALKERSCInitIpcRequest(&request, SleepwalkerIpcCommandSetShutdownMode);
        return SLEEPWALKERSCIpcTransact(Device, &request, &response);
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_SLEEPWALKER_SET_SHUTDOWN_MODE, NULL, 0, NULL, 0, &bytes, NULL);
}

BOOL SLEEPWALKERSCGetEtwEvent(_In_ HANDLE Device, _Out_ SLEEPWALKER_IPC_ETW_EVENT *Event, _In_ DWORD TimeoutMs)
{
    PSLEEPWALKERSC_SHARED_CHANNEL channel;

    if (Event == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Event, sizeof(*Event));
    if (!SLEEPWALKERSCIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    channel = SLEEPWALKERSCRetainSharedChannel(Device);
    if (channel != NULL && channel->EtwHeader != NULL)
    {
        BOOL ok = SLEEPWALKERSCPopSharedRing(channel->EtwHeader, channel->EtwRecords, channel->EtwDataReadyEvent,
                                             Event, sizeof(*Event));
        if (!ok)
        {
            DWORD waitResult = WaitForSingleObject(channel->EtwDataReadyEvent, TimeoutMs);
            if (waitResult == WAIT_OBJECT_0)
            {
                ok = SLEEPWALKERSCPopSharedRing(channel->EtwHeader, channel->EtwRecords, channel->EtwDataReadyEvent,
                                                Event, sizeof(*Event));
            }
            else if (waitResult == WAIT_TIMEOUT)
            {
                SetLastError(ERROR_NO_MORE_ITEMS);
            }
            else
            {
                SetLastError(GetLastError());
            }
        }

        if (!ok && GetLastError() == ERROR_SUCCESS)
        {
            SetLastError(ERROR_NO_MORE_ITEMS);
        }
        SLEEPWALKERSCReleaseSharedChannelRef(channel);
        return ok;
    }
    if (channel != NULL)
    {
        SLEEPWALKERSCReleaseSharedChannelRef(channel);
    }

    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

DWORD
SLEEPWALKERSCParseStreamMaskA(_In_z_ const char *Text)
{
    DWORD mask = 0;
    char *copy;
    char *tok;
    char *ctx = NULL;

    if (Text == NULL)
    {
        return 0;
    }

    copy = _strdup(Text);
    if (copy == NULL)
    {
        return 0;
    }

    for (tok = strtok_s(copy, ",", &ctx); tok != NULL; tok = strtok_s(NULL, ",", &ctx))
    {
        if (_stricmp(tok, "handle") == 0)
        {
            mask |= SLEEPWALKER_STREAM_HANDLE;
        }
        else if (_stricmp(tok, "memory") == 0)
        {
            mask |= SLEEPWALKER_STREAM_MEMORY;
        }
        else if (_stricmp(tok, "thread") == 0)
        {
            mask |= SLEEPWALKER_STREAM_THREAD;
        }
    }

    free(copy);
    return mask;
}

