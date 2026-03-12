#include "blackbird_sensor_core_internal.h"

BLACKBIRDSC_API VOID BLACKBIRDSCUseServiceProtocol(VOID)
{
    AcquireSRWLockExclusive(&g_BlackbirdProtocolLock);
    g_BlackbirdProtocolMode = BLACKBIRDSC_PROTOCOL_SERVICE;
    InterlockedExchange(&g_BlackbirdBrokerCapabilities, 0);
    InterlockedExchange(&g_BlackbirdBrokerThreatIntelEnabled, 0);
    InterlockedExchange(&g_BlackbirdBrokerThreatIntelEnableError, 0);
    InterlockedExchange(&g_BlackbirdLastSharedRingError, ERROR_NOT_FOUND);
    ReleaseSRWLockExclusive(&g_BlackbirdProtocolLock);
}

BLACKBIRDSC_API BOOL BLACKBIRDSCUseClientProtocol(_In_opt_z_ PCWSTR PipeName, _In_ DWORD ConnectTimeoutMs)
{
    size_t pipeLength;

    AcquireSRWLockExclusive(&g_BlackbirdProtocolLock);

    if (PipeName != NULL)
    {
        pipeLength = wcslen(PipeName);
        if (pipeLength == 0 || pipeLength >= RTL_NUMBER_OF(g_BlackbirdPipeName))
        {
            ReleaseSRWLockExclusive(&g_BlackbirdProtocolLock);
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        (void)StringCchCopyW(g_BlackbirdPipeName, RTL_NUMBER_OF(g_BlackbirdPipeName), PipeName);
    }
    else
    {
        (void)StringCchCopyW(g_BlackbirdPipeName, RTL_NUMBER_OF(g_BlackbirdPipeName), BLACKBIRD_IPC_PIPE_NAME);
    }

    if (ConnectTimeoutMs == 0)
    {
        ConnectTimeoutMs = 3000;
    }
    g_BlackbirdPipeTimeoutMs = ConnectTimeoutMs;
    g_BlackbirdProtocolMode = BLACKBIRDSC_PROTOCOL_CLIENT;
    InterlockedExchange(&g_BlackbirdBrokerCapabilities, 0);
    InterlockedExchange(&g_BlackbirdBrokerThreatIntelEnabled, 0);
    InterlockedExchange(&g_BlackbirdBrokerThreatIntelEnableError, 0);
    InterlockedExchange(&g_BlackbirdLastSharedRingError, ERROR_NOT_FOUND);
    ReleaseSRWLockExclusive(&g_BlackbirdProtocolLock);
    return TRUE;
}

BLACKBIRDSC_API BLACKBIRDSC_PROTOCOL_MODE BLACKBIRDSCGetProtocolMode(VOID)
{
    BLACKBIRDSC_PROTOCOL_MODE mode;

    AcquireSRWLockShared(&g_BlackbirdProtocolLock);
    mode = (BLACKBIRDSC_PROTOCOL_MODE)g_BlackbirdProtocolMode;
    ReleaseSRWLockShared(&g_BlackbirdProtocolLock);
    return mode;
}

static VOID BLACKBIRDSCGetClientTransportConfig(_Out_writes_z_(PipeChars) PWSTR PipeName, _In_ size_t PipeChars,
                                                  _Out_ DWORD *ConnectTimeoutMs)
{
    AcquireSRWLockShared(&g_BlackbirdProtocolLock);
    if (PipeName != NULL && PipeChars > 0)
    {
        (void)StringCchCopyW(PipeName, PipeChars, g_BlackbirdPipeName);
    }
    if (ConnectTimeoutMs != NULL)
    {
        *ConnectTimeoutMs = g_BlackbirdPipeTimeoutMs;
    }
    ReleaseSRWLockShared(&g_BlackbirdProtocolLock);
}

static BOOL BLACKBIRDSCIsClientProtocol(VOID)
{
    return (BLACKBIRDSCGetProtocolMode() == BLACKBIRDSC_PROTOCOL_CLIENT);
}

typedef struct _BLACKBIRDSC_SHARED_CHANNEL
{
    struct _BLACKBIRDSC_SHARED_CHANNEL *Next;
    volatile LONG RefCount;
    HANDLE Device;
    HANDLE IoctlMapping;
    HANDLE IoctlDataReadyEvent;
    volatile BLACKBIRD_IPC_SHARED_RING_HEADER *IoctlHeader;
    PBYTE IoctlRecords;
    HANDLE EtwMapping;
    HANDLE EtwDataReadyEvent;
    volatile BLACKBIRD_IPC_SHARED_RING_HEADER *EtwHeader;
    PBYTE EtwRecords;
} BLACKBIRDSC_SHARED_CHANNEL, *PBLACKBIRDSC_SHARED_CHANNEL;

static SRWLOCK g_BlackbirdSharedChannelLock = SRWLOCK_INIT;
static PBLACKBIRDSC_SHARED_CHANNEL g_BlackbirdSharedChannels = NULL;

static BOOL BLACKBIRDSCPopSharedRing(_Inout_ volatile BLACKBIRD_IPC_SHARED_RING_HEADER *Header,
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

static VOID BLACKBIRDSCReleaseSharedChannel(_Inout_ PBLACKBIRDSC_SHARED_CHANNEL Channel)
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

static PBLACKBIRDSC_SHARED_CHANNEL BLACKBIRDSCRetainSharedChannel(_In_ HANDLE Device)
{
    PBLACKBIRDSC_SHARED_CHANNEL channel;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }

    AcquireSRWLockShared(&g_BlackbirdSharedChannelLock);
    for (channel = g_BlackbirdSharedChannels; channel != NULL; channel = channel->Next)
    {
        if (channel->Device == Device)
        {
            (void)InterlockedIncrement(&channel->RefCount);
            break;
        }
    }
    ReleaseSRWLockShared(&g_BlackbirdSharedChannelLock);
    return channel;
}

static VOID BLACKBIRDSCReleaseSharedChannelRef(_In_opt_ PBLACKBIRDSC_SHARED_CHANNEL Channel)
{
    if (Channel == NULL)
    {
        return;
    }

    if (InterlockedDecrement(&Channel->RefCount) == 0)
    {
        BLACKBIRDSCReleaseSharedChannel(Channel);
        free(Channel);
    }
}

static VOID BLACKBIRDSCForgetSharedChannel(_In_ HANDLE Device)
{
    PBLACKBIRDSC_SHARED_CHANNEL *pp;
    PBLACKBIRDSC_SHARED_CHANNEL channel = NULL;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE)
    {
        return;
    }

    AcquireSRWLockExclusive(&g_BlackbirdSharedChannelLock);
    pp = &g_BlackbirdSharedChannels;
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
    ReleaseSRWLockExclusive(&g_BlackbirdSharedChannelLock);

    if (channel != NULL)
    {
        channel->Next = NULL;
        BLACKBIRDSCReleaseSharedChannelRef(channel);
    }
}

static BOOL BLACKBIRDSCRegisterSharedChannel(_In_ HANDLE Device,
                                               _In_ const BLACKBIRD_IPC_OPEN_SHARED_RING_RESPONSE *Response)
{
    PBLACKBIRDSC_SHARED_CHANNEL channel;
    SIZE_T ioctlViewBytes;
    SIZE_T etwViewBytes;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE || Response == NULL || Response->IoctlMappingHandle == 0 ||
        Response->IoctlDataReadyEventHandle == 0 || Response->EtwMappingHandle == 0 ||
        Response->EtwDataReadyEventHandle == 0 || Response->IoctlCapacity == 0 || Response->EtwCapacity == 0 ||
        Response->IoctlRecordSize != sizeof(BLACKBIRD_EVENT_RECORD) ||
        Response->EtwRecordSize != sizeof(BLACKBIRD_IPC_ETW_EVENT))
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    BLACKBIRDSCForgetSharedChannel(Device);

    channel = (PBLACKBIRDSC_SHARED_CHANNEL)calloc(1, sizeof(*channel));
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

    ioctlViewBytes = sizeof(BLACKBIRD_IPC_SHARED_RING_HEADER) +
                     ((SIZE_T)Response->IoctlCapacity * (SIZE_T)Response->IoctlRecordSize);
    etwViewBytes = sizeof(BLACKBIRD_IPC_SHARED_RING_HEADER) +
                   ((SIZE_T)Response->EtwCapacity * (SIZE_T)Response->EtwRecordSize);

    channel->IoctlHeader =
        (volatile BLACKBIRD_IPC_SHARED_RING_HEADER *)MapViewOfFile(channel->IoctlMapping,
                                                                      FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                                                                      ioctlViewBytes);
    channel->EtwHeader =
        (volatile BLACKBIRD_IPC_SHARED_RING_HEADER *)MapViewOfFile(channel->EtwMapping,
                                                                      FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                                                                      etwViewBytes);
    if (channel->IoctlHeader == NULL || channel->EtwHeader == NULL)
    {
        DWORD err = GetLastError();
        BLACKBIRDSCReleaseSharedChannel(channel);
        free(channel);
        SetLastError(err);
        return FALSE;
    }

    channel->IoctlRecords = ((PBYTE)channel->IoctlHeader) + sizeof(BLACKBIRD_IPC_SHARED_RING_HEADER);
    channel->EtwRecords = ((PBYTE)channel->EtwHeader) + sizeof(BLACKBIRD_IPC_SHARED_RING_HEADER);

    AcquireSRWLockExclusive(&g_BlackbirdSharedChannelLock);
    channel->Next = g_BlackbirdSharedChannels;
    g_BlackbirdSharedChannels = channel;
    ReleaseSRWLockExclusive(&g_BlackbirdSharedChannelLock);
    return TRUE;
}

static BOOL BLACKBIRDSCIpcTransact(_In_ HANDLE Device, _In_ const BLACKBIRD_IPC_PACKET *Request,
                                     _Out_ BLACKBIRD_IPC_PACKET *Response)
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

    if (Response->Magic != BLACKBIRD_IPC_MAGIC || Response->Version != BLACKBIRD_IPC_VERSION ||
        Response->PacketType != BlackbirdIpcPacketResponse || Response->Command != Request->Command ||
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

static VOID BLACKBIRDSCInitIpcRequest(_Out_ BLACKBIRD_IPC_PACKET *Request, _In_ UINT32 Command)
{
    ZeroMemory(Request, sizeof(*Request));
    Request->Magic = BLACKBIRD_IPC_MAGIC;
    Request->Version = BLACKBIRD_IPC_VERSION;
    Request->PacketType = BlackbirdIpcPacketRequest;
    Request->Command = Command;
    Request->Sequence = (UINT32)InterlockedIncrement(&g_BlackbirdIpcSequence);
}

VOID WINAPI BLACKBIRDSCInternalRecordCallback(_In_ PEVENT_RECORD Record)
{
    BLACKBIRDSC_ETW_SESSION_INTERNAL *session;
    PTRACE_EVENT_INFO info = NULL;
    ULONG size = 0;
    TDHSTATUS status;
    PCWSTR eventName = NULL;

    if (Record == NULL)
    {
        return;
    }

    session = (BLACKBIRDSC_ETW_SESSION_INTERNAL *)Record->UserContext;
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

static VOID BLACKBIRDSCCopyAnsiToWide(_In_z_ const char *Source, _Out_writes_z_(OutputChars) PWSTR Output,
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

VOID WINAPI BLACKBIRDSCStgDetectionBridgeCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                                    _In_opt_ PVOID Context)
{
    BLACKBIRDSC_STG_DETECTION_BRIDGE *bridge = (BLACKBIRDSC_STG_DETECTION_BRIDGE *)Context;
    SwkDetectionEvent event;
    char detectionNameAnsi[128];

    if (Record == NULL || bridge == NULL || bridge->Callback == NULL)
    {
        return;
    }

    if (!IsEqualGUID(&Record->EventHeader.ProviderId, &BLACKBIRDSC_PROVIDER_GUID_BLACKBIRD))
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

    (void)BLACKBIRDGetU32Property(Record, L"severity", &event.Severity);
    (void)BLACKBIRDGetU64Property(Record, L"processId", &event.ProcessId);
    (void)BLACKBIRDGetU64Property(Record, L"targetPid", &event.TargetPid);
    (void)BLACKBIRDGetU32Property(Record, L"correlationFlags", &event.CorrelationFlags);
    (void)BLACKBIRDGetU32Property(Record, L"correlationAccessMask", &event.CorrelationAccessMask);
    (void)BLACKBIRDGetU32Property(Record, L"correlationAgeMs", &event.CorrelationAgeMs);
    (void)BLACKBIRDGetWideProperty(Record, L"reason", event.Reason, RTL_NUMBER_OF(event.Reason));

    if (BLACKBIRDGetAnsiProperty(Record, L"detectionName", detectionNameAnsi, RTL_NUMBER_OF(detectionNameAnsi)))
    {
        BLACKBIRDSCCopyAnsiToWide(detectionNameAnsi, event.DetectionName, RTL_NUMBER_OF(event.DetectionName));
    }
    if (event.DetectionName[0] == L'\0')
    {
        (void)StringCchCopyW(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), L"UNKNOWN");
    }

    bridge->Callback(&event, bridge->CallbackContext);
}

HANDLE
BLACKBIRDSCOpenControlDevice(VOID)
{
    HANDLE h;

    if (!BLACKBIRDSCIsClientProtocol())
    {
        InterlockedExchange(&g_BlackbirdBrokerCapabilities, 0);
        InterlockedExchange(&g_BlackbirdBrokerThreatIntelEnabled, 0);
        InterlockedExchange(&g_BlackbirdBrokerThreatIntelEnableError, 0);
        h = CreateFileW(L"\\\\.\\Global\\BlackbirdCtl", GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        return h;
    }
    else
    {
        WCHAR pipeName[MAX_PATH];
        DWORD timeoutMs = 0;
        DWORD mode = PIPE_READMODE_MESSAGE;
        BLACKBIRD_IPC_PACKET request;
        BLACKBIRD_IPC_PACKET response;

        BLACKBIRDSCGetClientTransportConfig(pipeName, RTL_NUMBER_OF(pipeName), &timeoutMs);
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

        BLACKBIRDSCInitIpcRequest(&request, BlackbirdIpcCommandHandshake);
        request.Payload.HandshakeRequest.RequestedVersion = BLACKBIRD_IPC_VERSION;
        if (!BLACKBIRDSCIpcTransact(h, &request, &response))
        {
            (void)BLACKBIRDSCCloseControlDevice(h);
            return INVALID_HANDLE_VALUE;
        }

        if (response.Payload.HandshakeResponse.NegotiatedVersion == 0 ||
            response.Payload.HandshakeResponse.NegotiatedVersion > BLACKBIRD_IPC_VERSION)
        {
            (void)BLACKBIRDSCCloseControlDevice(h);
            SetLastError(ERROR_REVISION_MISMATCH);
            return INVALID_HANDLE_VALUE;
        }

        InterlockedExchange(&g_BlackbirdBrokerCapabilities, (LONG)response.Payload.HandshakeResponse.Capabilities);
        InterlockedExchange(&g_BlackbirdBrokerThreatIntelEnabled,
                            response.Payload.HandshakeResponse.ThreatIntelEnabled ? 1 : 0);
        InterlockedExchange(&g_BlackbirdBrokerThreatIntelEnableError,
                            (LONG)response.Payload.HandshakeResponse.Reserved);
        InterlockedExchange(&g_BlackbirdLastSharedRingError, ERROR_NOT_FOUND);

        {
            BOOL ringReady = FALSE;
            DWORD ringErr = ERROR_SUCCESS;
            BLACKBIRD_IPC_PACKET ringRequest;
            BLACKBIRD_IPC_PACKET ringResponse;

            BLACKBIRDSCInitIpcRequest(&ringRequest, BlackbirdIpcCommandOpenSharedRing);
            ringRequest.Payload.OpenSharedRingRequest.DesiredIoctlCapacity = 16384u;
            ringRequest.Payload.OpenSharedRingRequest.DesiredEtwCapacity = 4096u;
            if (BLACKBIRDSCIpcTransact(h, &ringRequest, &ringResponse))
            {
                if (BLACKBIRDSCRegisterSharedChannel(h, &ringResponse.Payload.OpenSharedRingResponse))
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
                InterlockedOr(&g_BlackbirdBrokerCapabilities, (LONG)BLACKBIRD_IPC_CAP_SHARED_RING);
                InterlockedExchange(&g_BlackbirdLastSharedRingError, ERROR_SUCCESS);
            }
            else
            {
                InterlockedAnd(&g_BlackbirdBrokerCapabilities, ~(LONG)BLACKBIRD_IPC_CAP_SHARED_RING);
                if (ringErr == ERROR_SUCCESS)
                {
                    ringErr = ERROR_NOT_FOUND;
                }
                InterlockedExchange(&g_BlackbirdLastSharedRingError, (LONG)ringErr);
                (void)BLACKBIRDSCCloseControlDevice(h);
                SetLastError(ringErr);
                return INVALID_HANDLE_VALUE;
            }
        }

        return h;
    }
}

BLACKBIRDSC_API BOOL BLACKBIRDSCCloseControlDevice(_In_opt_ HANDLE Device)
{
    BOOL ok;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    BLACKBIRDSCForgetSharedChannel(Device);
    ok = CloseHandle(Device);
    return ok;
}

BOOL BLACKBIRDSCGetBrokerInfo(_Out_opt_ UINT32 *Capabilities, _Out_opt_ BOOL *ThreatIntelEnabled)
{
    if (!BLACKBIRDSCIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    if (Capabilities != NULL)
    {
        *Capabilities = (UINT32)InterlockedCompareExchange(&g_BlackbirdBrokerCapabilities, 0, 0);
    }
    if (ThreatIntelEnabled != NULL)
    {
        *ThreatIntelEnabled = (InterlockedCompareExchange(&g_BlackbirdBrokerThreatIntelEnabled, 0, 0) != 0);
    }
    return TRUE;
}

BLACKBIRDSC_API BOOL BLACKBIRDSCHasSharedChannel(_In_ HANDLE Device, _Out_opt_ BOOL *HasIoctlChannel,
                                                     _Out_opt_ BOOL *HasEtwChannel)
{
    PBLACKBIRDSC_SHARED_CHANNEL channel;
    BOOL hasIoctl = FALSE;
    BOOL hasEtw = FALSE;

    if (!BLACKBIRDSCIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    if (Device == NULL || Device == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    channel = BLACKBIRDSCRetainSharedChannel(Device);
    if (channel != NULL)
    {
        hasIoctl = (channel->IoctlHeader != NULL && channel->IoctlRecords != NULL);
        hasEtw = (channel->EtwHeader != NULL && channel->EtwRecords != NULL);
        BLACKBIRDSCReleaseSharedChannelRef(channel);
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

BLACKBIRDSC_API DWORD BLACKBIRDSCGetLastSharedRingError(VOID)
{
    return (DWORD)InterlockedCompareExchange(&g_BlackbirdLastSharedRingError, 0, 0);
}

DWORD BLACKBIRDSCGetBrokerThreatIntelEnableError(VOID)
{
    if (!BLACKBIRDSCIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return ERROR_NOT_SUPPORTED;
    }

    return (DWORD)InterlockedCompareExchange(&g_BlackbirdBrokerThreatIntelEnableError, 0, 0);
}

DWORD BLACKBIRDSCGetLastThreatIntelEnableError(VOID)
{
    return (DWORD)InterlockedCompareExchange(&g_BlackbirdLastTiEnableError, 0, 0);
}

BOOL BLACKBIRDSCSubscribe(_In_ HANDLE Device, _In_ DWORD ProcessId, _In_ DWORD StreamMask)
{
    BLACKBIRD_SUBSCRIBE_REQUEST req;
    DWORD bytes = 0;
    BLACKBIRD_IPC_PACKET request;
    BLACKBIRD_IPC_PACKET response;

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = ProcessId;
    req.StreamMask = StreamMask;

    if (BLACKBIRDSCIsClientProtocol())
    {
        BLACKBIRDSCInitIpcRequest(&request, BlackbirdIpcCommandSubscribe);
        request.Payload.SubscribeRequest = req;
        return BLACKBIRDSCIpcTransact(Device, &request, &response);
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BLACKBIRD_SUBSCRIBE, &req, sizeof(req), NULL, 0, &bytes, NULL);
}

BOOL BLACKBIRDSCUnsubscribe(_In_ HANDLE Device, _In_ DWORD ProcessId)
{
    BLACKBIRD_UNSUBSCRIBE_REQUEST req;
    DWORD bytes = 0;
    BLACKBIRD_IPC_PACKET request;
    BLACKBIRD_IPC_PACKET response;

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = ProcessId;

    if (BLACKBIRDSCIsClientProtocol())
    {
        BLACKBIRDSCInitIpcRequest(&request, BlackbirdIpcCommandUnsubscribe);
        request.Payload.UnsubscribeRequest = req;
        return BLACKBIRDSCIpcTransact(Device, &request, &response);
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BLACKBIRD_UNSUBSCRIBE, &req, sizeof(req), NULL, 0, &bytes, NULL);
}

BOOL BLACKBIRDSCSetPids(_In_ HANDLE Device, _In_reads_(ProcessCount) const DWORD *ProcessIds, _In_ DWORD ProcessCount,
                          _In_ DWORD StreamMask)
{
    BLACKBIRD_SET_PIDS_REQUEST req;
    DWORD bytes = 0;
    DWORD i;
    BLACKBIRD_IPC_PACKET request;
    BLACKBIRD_IPC_PACKET response;

    if (ProcessIds == NULL || ProcessCount == 0 || ProcessCount > BLACKBIRD_MAX_PID_LIST)
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

    if (BLACKBIRDSCIsClientProtocol())
    {
        BLACKBIRDSCInitIpcRequest(&request, BlackbirdIpcCommandSetPids);
        request.Payload.SetPidsRequest = req;
        return BLACKBIRDSCIpcTransact(Device, &request, &response);
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BLACKBIRD_SET_PIDS, &req, sizeof(req), NULL, 0, &bytes, NULL);
}

BOOL BLACKBIRDSCGetEvent(_In_ HANDLE Device, _Out_ BLACKBIRD_EVENT_RECORD *Record, _Out_opt_ DWORD *BytesReturned)
{
    DWORD bytes = 0;
    BOOL ok;
    PBLACKBIRDSC_SHARED_CHANNEL channel;

    if (Record == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Record, sizeof(*Record));
    if (BLACKBIRDSCIsClientProtocol())
    {
        channel = BLACKBIRDSCRetainSharedChannel(Device);
        if (channel != NULL && channel->IoctlHeader != NULL)
        {
            ok = BLACKBIRDSCPopSharedRing(channel->IoctlHeader, channel->IoctlRecords, channel->IoctlDataReadyEvent,
                                            Record, sizeof(*Record));
            if (!ok)
            {
                if (WaitForSingleObject(channel->IoctlDataReadyEvent, 0) == WAIT_OBJECT_0)
                {
                    ok = BLACKBIRDSCPopSharedRing(channel->IoctlHeader, channel->IoctlRecords,
                                                    channel->IoctlDataReadyEvent, Record, sizeof(*Record));
                }
            }
            if (ok)
            {
                bytes = sizeof(*Record);
            }
            else
            {
                SetLastError(ERROR_NO_MORE_ITEMS);
            }
            BLACKBIRDSCReleaseSharedChannelRef(channel);
        }
        else
        {
            if (channel != NULL)
            {
                BLACKBIRDSCReleaseSharedChannelRef(channel);
            }
            ok = FALSE;
            SetLastError(ERROR_NOT_SUPPORTED);
        }
    }
    else
    {
        ok = DeviceIoControl(Device, (DWORD)IOCTL_BLACKBIRD_GET_EVENT, NULL, 0, Record, sizeof(*Record), &bytes, NULL);
    }

    if (BytesReturned != NULL)
    {
        *BytesReturned = bytes;
    }
    return ok;
}

BOOL BLACKBIRDSCGetStats(_In_ HANDLE Device, _Out_ BLACKBIRD_STATS_RESPONSE *Stats, _Out_opt_ DWORD *BytesReturned)
{
    DWORD bytes = 0;
    BOOL ok;
    BLACKBIRD_IPC_PACKET request;
    BLACKBIRD_IPC_PACKET response;

    if (Stats == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Stats, sizeof(*Stats));
    if (BLACKBIRDSCIsClientProtocol())
    {
        BLACKBIRDSCInitIpcRequest(&request, BlackbirdIpcCommandGetStats);
        ok = BLACKBIRDSCIpcTransact(Device, &request, &response);
        if (ok)
        {
            *Stats = response.Payload.StatsResponse;
            bytes = sizeof(*Stats);
        }
    }
    else
    {
        ok = DeviceIoControl(Device, (DWORD)IOCTL_BLACKBIRD_GET_STATS, NULL, 0, Stats, sizeof(*Stats), &bytes, NULL);
    }

    if (BytesReturned != NULL)
    {
        *BytesReturned = bytes;
    }
    return ok;
}

BOOL BLACKBIRDSCGetHealth(_In_ HANDLE Device, _Out_ BLACKBIRD_HEALTH_RESPONSE *Health,
                            _Out_opt_ DWORD *BytesReturned)
{
    DWORD bytes = 0;
    BOOL ok;

    if (Health == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Health, sizeof(*Health));
    if (BLACKBIRDSCIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    ok = DeviceIoControl(Device, (DWORD)IOCTL_BLACKBIRD_GET_HEALTH, NULL, 0, Health, sizeof(*Health), &bytes, NULL);
    if (BytesReturned != NULL)
    {
        *BytesReturned = bytes;
    }
    return ok;
}

BOOL BLACKBIRDSCQueryProcessImagePath(_In_ HANDLE Device, _In_ DWORD ProcessId,
                                        _Out_writes_z_(OutputChars) PWSTR Output, _In_ DWORD OutputChars)
{
    BLACKBIRD_QUERY_PROCESS_IMAGE_REQUEST req;
    BLACKBIRD_QUERY_PROCESS_IMAGE_RESPONSE resp;
    DWORD bytes = 0;
    BOOL ok;
    BLACKBIRD_IPC_PACKET request;
    BLACKBIRD_IPC_PACKET response;

    if (Output == NULL || OutputChars == 0 || ProcessId == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    Output[0] = L'\0';

    ZeroMemory(&req, sizeof(req));
    ZeroMemory(&resp, sizeof(resp));
    req.ProcessId = ProcessId;

    if (BLACKBIRDSCIsClientProtocol())
    {
        BLACKBIRDSCInitIpcRequest(&request, BlackbirdIpcCommandQueryProcessImage);
        request.Payload.QueryProcessImageRequest = req;
        ok = BLACKBIRDSCIpcTransact(Device, &request, &response);
        if (ok)
        {
            resp = response.Payload.QueryProcessImageResponse;
            bytes = sizeof(resp);
        }
    }
    else
    {
        ok = DeviceIoControl(Device, (DWORD)IOCTL_BLACKBIRD_QUERY_PROCESS_IMAGE, &req, sizeof(req), &resp, sizeof(resp),
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

BOOL BLACKBIRDSCSetUserHookTarget(
    _In_ HANDLE Device, _In_ DWORD Mode, _In_ DWORD ProcessId, _In_ DWORD Flags, _In_opt_z_ PCWSTR ImagePath,
    _In_opt_z_ PCWSTR HookDllPath, _Out_opt_ BLACKBIRD_IPC_SET_USER_HOOK_TARGET_RESPONSE *Response)
{
    BLACKBIRD_IPC_PACKET request;
    BLACKBIRD_IPC_PACKET response;
    BLACKBIRD_IPC_SET_USER_HOOK_TARGET_REQUEST payload;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    if (!BLACKBIRDSCIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    ZeroMemory(&payload, sizeof(payload));
    payload.Mode = Mode;
    payload.ProcessId = ProcessId;
    payload.Flags = Flags;
    if (ImagePath != NULL)
    {
        (void)StringCchCopyW(payload.ImagePath, RTL_NUMBER_OF(payload.ImagePath), ImagePath);
    }
    if (HookDllPath != NULL)
    {
        (void)StringCchCopyW(payload.HookDllPath, RTL_NUMBER_OF(payload.HookDllPath), HookDllPath);
    }

    BLACKBIRDSCInitIpcRequest(&request, BlackbirdIpcCommandSetUserHookTarget);
    request.Payload.SetUserHookTargetRequest = payload;
    if (!BLACKBIRDSCIpcTransact(Device, &request, &response))
    {
        return FALSE;
    }

    if (Response != NULL)
    {
        *Response = response.Payload.SetUserHookTargetResponse;
    }
    return TRUE;
}

BOOL BLACKBIRDSCSetShutdownMode(_In_ HANDLE Device)
{
    DWORD bytes = 0;
    BLACKBIRD_IPC_PACKET request;
    BLACKBIRD_IPC_PACKET response;

    if (BLACKBIRDSCIsClientProtocol())
    {
        BLACKBIRDSCInitIpcRequest(&request, BlackbirdIpcCommandSetShutdownMode);
        return BLACKBIRDSCIpcTransact(Device, &request, &response);
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BLACKBIRD_SET_SHUTDOWN_MODE, NULL, 0, NULL, 0, &bytes, NULL);
}

BOOL BLACKBIRDSCGetEtwEvent(_In_ HANDLE Device, _Out_ BLACKBIRD_IPC_ETW_EVENT *Event, _In_ DWORD TimeoutMs)
{
    PBLACKBIRDSC_SHARED_CHANNEL channel;

    if (Event == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Event, sizeof(*Event));
    if (!BLACKBIRDSCIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    channel = BLACKBIRDSCRetainSharedChannel(Device);
    if (channel != NULL && channel->EtwHeader != NULL)
    {
        BOOL ok = BLACKBIRDSCPopSharedRing(channel->EtwHeader, channel->EtwRecords, channel->EtwDataReadyEvent,
                                             Event, sizeof(*Event));
        if (!ok)
        {
            DWORD waitResult = WaitForSingleObject(channel->EtwDataReadyEvent, TimeoutMs);
            if (waitResult == WAIT_OBJECT_0)
            {
                ok = BLACKBIRDSCPopSharedRing(channel->EtwHeader, channel->EtwRecords, channel->EtwDataReadyEvent,
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
        BLACKBIRDSCReleaseSharedChannelRef(channel);
        return ok;
    }
    if (channel != NULL)
    {
        BLACKBIRDSCReleaseSharedChannelRef(channel);
    }

    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

DWORD
BLACKBIRDSCParseStreamMaskA(_In_z_ const char *Text)
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
            mask |= BLACKBIRD_STREAM_HANDLE;
        }
        else if (_stricmp(tok, "memory") == 0)
        {
            mask |= BLACKBIRD_STREAM_MEMORY;
        }
        else if (_stricmp(tok, "thread") == 0)
        {
            mask |= BLACKBIRD_STREAM_THREAD;
        }
        else if (_stricmp(tok, "filesystem") == 0 || _stricmp(tok, "file") == 0 || _stricmp(tok, "fs") == 0)
        {
            mask |= BLACKBIRD_STREAM_FILESYSTEM;
        }
    }

    free(copy);
    return mask;
}

