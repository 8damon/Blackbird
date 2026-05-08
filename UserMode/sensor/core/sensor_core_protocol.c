#include "sensor_core_internal.h"

BKSC_API VOID BkscUseServiceProtocol(VOID)
{
    AcquireSRWLockExclusive(&g_BlackbirdProtocolLock);
    g_BlackbirdProtocolMode = BKSC_PROTOCOL_SERVICE;
    InterlockedExchange(&g_BlackbirdBrokerCapabilities, 0);
    InterlockedExchange(&g_BlackbirdBrokerThreatIntelEnabled, 0);
    InterlockedExchange(&g_BlackbirdLastTiEnableError, 0);
    InterlockedExchange(&g_BlackbirdLastSharedRingError, ERROR_NOT_FOUND);
    ReleaseSRWLockExclusive(&g_BlackbirdProtocolLock);
}

BKSC_API BOOL BkscUseClientProtocol(_In_opt_z_ PCWSTR PipeName, _In_ DWORD ConnectTimeoutMs)
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
        (void)StringCchCopyW(g_BlackbirdPipeName, RTL_NUMBER_OF(g_BlackbirdPipeName), BKIPC_PIPE_NAME);
    }

    if (ConnectTimeoutMs == 0)
    {
        ConnectTimeoutMs = 3000;
    }
    g_BlackbirdPipeTimeoutMs = ConnectTimeoutMs;
    g_BlackbirdProtocolMode = BKSC_PROTOCOL_CLIENT;
    InterlockedExchange(&g_BlackbirdBrokerCapabilities, 0);
    InterlockedExchange(&g_BlackbirdBrokerThreatIntelEnabled, 0);
    InterlockedExchange(&g_BlackbirdLastTiEnableError, 0);
    InterlockedExchange(&g_BlackbirdLastSharedRingError, ERROR_NOT_FOUND);
    ReleaseSRWLockExclusive(&g_BlackbirdProtocolLock);
    return TRUE;
}

BKSC_API BKSC_PROTOCOL_MODE BkscGetProtocolMode(VOID)
{
    BKSC_PROTOCOL_MODE mode;

    AcquireSRWLockShared(&g_BlackbirdProtocolLock);
    mode = (BKSC_PROTOCOL_MODE)g_BlackbirdProtocolMode;
    ReleaseSRWLockShared(&g_BlackbirdProtocolLock);
    return mode;
}

static VOID BkscGetClientTransportConfig(_Out_writes_z_(PipeChars) PWSTR PipeName, _In_ size_t PipeChars,
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

static BOOL BkscIsClientProtocol(VOID)
{
    return (BkscGetProtocolMode() == BKSC_PROTOCOL_CLIENT);
}

typedef struct _BKSC_SHARED_CHANNEL
{
    struct _BKSC_SHARED_CHANNEL *Next;
    volatile LONG RefCount;
    HANDLE Device;
    HANDLE IoctlMapping;
    HANDLE IoctlDataReadyEvent;
    volatile BKIPC_SHARED_RING_HEADER *IoctlHeader;
    PBYTE IoctlRecords;
    HANDLE EtwMapping;
    HANDLE EtwDataReadyEvent;
    volatile BKIPC_SHARED_RING_HEADER *EtwHeader;
    PBYTE EtwRecords;
} BKSC_SHARED_CHANNEL, *PBKSC_SHARED_CHANNEL;

static SRWLOCK g_BlackbirdSharedChannelLock = SRWLOCK_INIT;
static PBKSC_SHARED_CHANNEL g_BlackbirdSharedChannels = NULL;

static BOOL BkscPopSharedRing(_Inout_ volatile BKIPC_SHARED_RING_HEADER *Header,
                              _In_reads_bytes_(Header->Capacity * Header->RecordSize) const BYTE *Records,
                              _In_ HANDLE DataReadyEvent, _Out_writes_bytes_(RecordSize) VOID *Record,
                              _In_ UINT32 RecordSize)
{
    LONG writeIndex;
    LONG readIndex;
    LONG nextIndex;

    if (Header == NULL || Records == NULL || Record == NULL || DataReadyEvent == NULL ||
        DataReadyEvent == INVALID_HANDLE_VALUE || Header->Capacity == 0 || Header->RecordSize != RecordSize ||
        RecordSize == 0)
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

static VOID BkscReleaseSharedChannel(_Inout_ PBKSC_SHARED_CHANNEL Channel)
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

static PBKSC_SHARED_CHANNEL BkscRetainSharedChannel(_In_ HANDLE Device)
{
    PBKSC_SHARED_CHANNEL channel;

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

static VOID BkscReleaseSharedChannelRef(_In_opt_ PBKSC_SHARED_CHANNEL Channel)
{
    if (Channel == NULL)
    {
        return;
    }

    if (InterlockedDecrement(&Channel->RefCount) == 0)
    {
        BkscReleaseSharedChannel(Channel);
        free(Channel);
    }
}

static VOID BkscForgetSharedChannel(_In_ HANDLE Device)
{
    PBKSC_SHARED_CHANNEL *pp;
    PBKSC_SHARED_CHANNEL channel = NULL;

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
        BkscReleaseSharedChannelRef(channel);
    }
}

static BOOL BkscRegisterSharedChannel(_In_ HANDLE Device, _In_ const BKIPC_OPEN_SHARED_RING_RESPONSE *Response)
{
    PBKSC_SHARED_CHANNEL channel;
    SIZE_T ioctlViewBytes;
    SIZE_T etwViewBytes;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE || Response == NULL || Response->IoctlMappingHandle == 0 ||
        Response->IoctlDataReadyEventHandle == 0 || Response->EtwMappingHandle == 0 ||
        Response->EtwDataReadyEventHandle == 0 || Response->IoctlCapacity == 0 || Response->EtwCapacity == 0 ||
        Response->IoctlRecordSize != sizeof(BK_EVENT_RECORD) || Response->EtwRecordSize != sizeof(BKIPC_ETW_EVENT))
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    BkscForgetSharedChannel(Device);

    channel = (PBKSC_SHARED_CHANNEL)calloc(1, sizeof(*channel));
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

    ioctlViewBytes =
        sizeof(BKIPC_SHARED_RING_HEADER) + ((SIZE_T)Response->IoctlCapacity * (SIZE_T)Response->IoctlRecordSize);
    etwViewBytes = sizeof(BKIPC_SHARED_RING_HEADER) + ((SIZE_T)Response->EtwCapacity * (SIZE_T)Response->EtwRecordSize);

    channel->IoctlHeader = (volatile BKIPC_SHARED_RING_HEADER *)MapViewOfFile(
        channel->IoctlMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, ioctlViewBytes);
    channel->EtwHeader = (volatile BKIPC_SHARED_RING_HEADER *)MapViewOfFile(
        channel->EtwMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, etwViewBytes);
    if (channel->IoctlHeader == NULL || channel->EtwHeader == NULL)
    {
        DWORD err = GetLastError();
        BkscReleaseSharedChannel(channel);
        free(channel);
        SetLastError(err);
        return FALSE;
    }

    channel->IoctlRecords = ((PBYTE)channel->IoctlHeader) + sizeof(BKIPC_SHARED_RING_HEADER);
    channel->EtwRecords = ((PBYTE)channel->EtwHeader) + sizeof(BKIPC_SHARED_RING_HEADER);

    AcquireSRWLockExclusive(&g_BlackbirdSharedChannelLock);
    channel->Next = g_BlackbirdSharedChannels;
    g_BlackbirdSharedChannels = channel;
    ReleaseSRWLockExclusive(&g_BlackbirdSharedChannelLock);
    return TRUE;
}

#define BKSC_IPC_DEFAULT_TIMEOUT_MS 5000u
#define BKSC_IPC_LAUNCH_TIMEOUT_MS 30000u
#define BKSC_IPC_MEMORY_TIMEOUT_MS 10000u
#define BKSC_IPC_FAST_TIMEOUT_MS 2500u
#define BKSC_IPC_CANCEL_DRAIN_TIMEOUT_MS 1000u

static DWORD BkscIpcCommandTimeoutMs(_In_ UINT32 Command)
{
    switch (Command)
    {
    case BlackbirdIpcCommandSetUserHookTarget:
        return BKSC_IPC_LAUNCH_TIMEOUT_MS;
    case BlackbirdIpcCommandQueryProcessMemory:
    case BlackbirdIpcCommandControlProcessExecution:
        return BKSC_IPC_MEMORY_TIMEOUT_MS;
    case BlackbirdIpcCommandGetStats:
    case BlackbirdIpcCommandGetHealth:
    case BlackbirdIpcCommandGetDiagnostics:
    case BlackbirdIpcCommandGetRuntimeConfig:
    case BlackbirdIpcCommandGetQpcTimingState:
    case BlackbirdIpcCommandOpenSharedRing:
    case BlackbirdIpcCommandHandshake:
        return BKSC_IPC_FAST_TIMEOUT_MS;
    default:
        return BKSC_IPC_DEFAULT_TIMEOUT_MS;
    }
}

static BOOL BkscCompleteOverlappedPipeIo(_In_ HANDLE Device, _Inout_ OVERLAPPED *Overlapped, _Out_ DWORD *BytesReturned,
                                         _In_ DWORD TimeoutMs)
{
    DWORD waitResult;
    DWORD bytes = 0;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE || Overlapped == NULL || BytesReturned == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (TimeoutMs == 0)
    {
        TimeoutMs = BKSC_IPC_DEFAULT_TIMEOUT_MS;
    }

    waitResult = WaitForSingleObject(Overlapped->hEvent, TimeoutMs);
    if (waitResult == WAIT_OBJECT_0)
    {
        if (!GetOverlappedResult(Device, Overlapped, &bytes, FALSE))
        {
            return FALSE;
        }
        *BytesReturned = bytes;
        return TRUE;
    }

    if (waitResult == WAIT_TIMEOUT)
    {
        (void)CancelIoEx(Device, Overlapped);
        waitResult = WaitForSingleObject(Overlapped->hEvent, BKSC_IPC_CANCEL_DRAIN_TIMEOUT_MS);
        if (waitResult == WAIT_OBJECT_0)
        {
            (void)GetOverlappedResult(Device, Overlapped, &bytes, FALSE);
        }
        SetLastError(ERROR_TIMEOUT);
        return FALSE;
    }

    SetLastError(ERROR_OPERATION_ABORTED);
    return FALSE;
}

static BOOL BkscPipeTransferExact(_In_ HANDLE Device, _Inout_updates_bytes_(BufferSize) VOID *Buffer,
                                  _In_ DWORD BufferSize, _In_ BOOL Write, _In_ DWORD TimeoutMs)
{
    DWORD bytes = 0;
    OVERLAPPED overlapped;
    HANDLE eventHandle;
    BOOL ok;
    DWORD err;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE || Buffer == NULL || BufferSize == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    eventHandle = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (eventHandle == NULL)
    {
        return FALSE;
    }

    ZeroMemory(&overlapped, sizeof(overlapped));
    overlapped.hEvent = eventHandle;

    if (Write)
    {
        ok = WriteFile(Device, Buffer, BufferSize, &bytes, &overlapped);
    }
    else
    {
        ok = ReadFile(Device, Buffer, BufferSize, &bytes, &overlapped);
    }

    if (!ok)
    {
        err = GetLastError();
        if (err != ERROR_IO_PENDING)
        {
            CloseHandle(eventHandle);
            SetLastError(err);
            return FALSE;
        }
        ok = BkscCompleteOverlappedPipeIo(Device, &overlapped, &bytes, TimeoutMs);
    }

    if (ok && !GetOverlappedResult(Device, &overlapped, &bytes, FALSE))
    {
        ok = FALSE;
    }

    err = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(eventHandle);

    if (!ok)
    {
        SetLastError(err);
        return FALSE;
    }
    if (bytes != BufferSize)
    {
        SetLastError(Write ? ERROR_WRITE_FAULT : ERROR_READ_FAULT);
        return FALSE;
    }

    return TRUE;
}

static BOOL BkscIpcTransact(_In_ HANDLE Device, _In_ const BKIPC_PACKET *Request, _Out_ BKIPC_PACKET *Response)
{
    DWORD timeoutMs;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE || Request == NULL || Response == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    timeoutMs = BkscIpcCommandTimeoutMs(Request->Command);
    if (!BkscPipeTransferExact(Device, (VOID *)Request, (DWORD)sizeof(*Request), TRUE, timeoutMs))
    {
        return FALSE;
    }

    if (!BkscPipeTransferExact(Device, Response, (DWORD)sizeof(*Response), FALSE, timeoutMs))
    {
        return FALSE;
    }

    if (Response->Magic != BKIPC_MAGIC || Response->Version != BKIPC_VERSION ||
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

static VOID BkscInitIpcRequest(_Out_ BKIPC_PACKET *Request, _In_ UINT32 Command)
{
    ZeroMemory(Request, sizeof(*Request));
    Request->Magic = BKIPC_MAGIC;
    Request->Version = BKIPC_VERSION;
    Request->PacketType = BlackbirdIpcPacketRequest;
    Request->Command = Command;
    Request->Sequence = (UINT32)InterlockedIncrement(&g_BlackbirdIpcSequence);
}

VOID WINAPI BkscInternalRecordCallback(_In_ PEVENT_RECORD Record)
{
    BKSC_ETW_SESSION_INTERNAL *session;
    PTRACE_EVENT_INFO info = NULL;
    ULONG size = 0;
    TDHSTATUS status;
    PCWSTR eventName = NULL;

    if (Record == NULL)
    {
        return;
    }

    session = (BKSC_ETW_SESSION_INTERNAL *)Record->UserContext;
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

static VOID BkscCopyAnsiToWide(_In_z_ const char *Source, _Out_writes_z_(OutputChars) PWSTR Output,
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

VOID WINAPI BkscDetectionBridgeCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName, _In_opt_ PVOID Context)
{
    BKSC_DETECTION_BRIDGE *bridge = (BKSC_DETECTION_BRIDGE *)Context;
    BKSC_DETECTION_EVENT event;
    char detectionNameAnsi[128];

    if (Record == NULL || bridge == NULL || bridge->Callback == NULL)
    {
        return;
    }

    if (!IsEqualGUID(&Record->EventHeader.ProviderId, &BKSC_PROVIDER_GUID_BLACKBIRD))
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

    (void)BketwpGetU32Property(Record, L"severity", &event.Severity);
    (void)BketwpGetU64Property(Record, L"processId", &event.ProcessId);
    (void)BketwpGetU64Property(Record, L"targetPid", &event.TargetPid);
    (void)BketwpGetU32Property(Record, L"correlationFlags", &event.CorrelationFlags);
    (void)BketwpGetU32Property(Record, L"correlationAccessMask", &event.CorrelationAccessMask);
    (void)BketwpGetU32Property(Record, L"correlationAgeMs", &event.CorrelationAgeMs);
    (void)BketwpGetWideProperty(Record, L"reason", event.Reason, RTL_NUMBER_OF(event.Reason));

    if (BketwpGetAnsiProperty(Record, L"detectionName", detectionNameAnsi, RTL_NUMBER_OF(detectionNameAnsi)))
    {
        BkscCopyAnsiToWide(detectionNameAnsi, event.DetectionName, RTL_NUMBER_OF(event.DetectionName));
    }
    if (event.DetectionName[0] == L'\0')
    {
        (void)StringCchCopyW(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), L"UNKNOWN");
    }

    bridge->Callback(&event, bridge->CallbackContext);
}

HANDLE
BkscOpenControlDevice(VOID)
{
    HANDLE h;

    if (!BkscIsClientProtocol())
    {
        InterlockedExchange(&g_BlackbirdBrokerCapabilities, 0);
        InterlockedExchange(&g_BlackbirdBrokerThreatIntelEnabled, 0);
        InterlockedExchange(&g_BlackbirdLastTiEnableError, 0);
        h = CreateFileW(L"\\\\.\\Global\\BlackbirdCtl", GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        return h;
    }
    else
    {
        WCHAR pipeName[MAX_PATH];
        DWORD timeoutMs = 0;
        DWORD mode = PIPE_READMODE_MESSAGE;
        BKIPC_PACKET request;
        BKIPC_PACKET response;

        BkscGetClientTransportConfig(pipeName, RTL_NUMBER_OF(pipeName), &timeoutMs);
        if (!WaitNamedPipeW(pipeName, timeoutMs))
        {
            return INVALID_HANDLE_VALUE;
        }

        h = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
                        NULL);
        if (h == INVALID_HANDLE_VALUE)
        {
            return h;
        }

        (void)SetNamedPipeHandleState(h, &mode, NULL, NULL);

        BkscInitIpcRequest(&request, BlackbirdIpcCommandHandshake);
        request.Payload.HandshakeRequest.RequestedVersion = BKIPC_VERSION;
        if (!BkscIpcTransact(h, &request, &response))
        {
            (void)BkscCloseControlDevice(h);
            return INVALID_HANDLE_VALUE;
        }

        if (response.Payload.HandshakeResponse.NegotiatedVersion == 0 ||
            response.Payload.HandshakeResponse.NegotiatedVersion > BKIPC_VERSION)
        {
            (void)BkscCloseControlDevice(h);
            SetLastError(ERROR_REVISION_MISMATCH);
            return INVALID_HANDLE_VALUE;
        }

        InterlockedExchange(&g_BlackbirdBrokerCapabilities, (LONG)response.Payload.HandshakeResponse.Capabilities);
        InterlockedExchange(&g_BlackbirdBrokerThreatIntelEnabled,
                            response.Payload.HandshakeResponse.ThreatIntelEnabled ? 1 : 0);
        InterlockedExchange(&g_BlackbirdLastTiEnableError, (LONG)response.Payload.HandshakeResponse.Reserved);
        InterlockedExchange(&g_BlackbirdLastSharedRingError, ERROR_NOT_FOUND);

        {
            BOOL ringReady = FALSE;
            DWORD ringErr = ERROR_SUCCESS;
            BKIPC_PACKET ringRequest;
            BKIPC_PACKET ringResponse;

            BkscInitIpcRequest(&ringRequest, BlackbirdIpcCommandOpenSharedRing);
            ringRequest.Payload.OpenSharedRingRequest.DesiredIoctlCapacity = 262144u;
            ringRequest.Payload.OpenSharedRingRequest.DesiredEtwCapacity = 65536u;
            if (BkscIpcTransact(h, &ringRequest, &ringResponse))
            {
                if (BkscRegisterSharedChannel(h, &ringResponse.Payload.OpenSharedRingResponse))
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
                InterlockedOr(&g_BlackbirdBrokerCapabilities, (LONG)BKIPC_CAP_SHARED_RING);
                InterlockedExchange(&g_BlackbirdLastSharedRingError, ERROR_SUCCESS);
            }
            else
            {
                InterlockedAnd(&g_BlackbirdBrokerCapabilities, ~(LONG)BKIPC_CAP_SHARED_RING);
                if (ringErr == ERROR_SUCCESS)
                {
                    ringErr = ERROR_NOT_FOUND;
                }
                InterlockedExchange(&g_BlackbirdLastSharedRingError, (LONG)ringErr);
            }
        }

        return h;
    }
}

BKSC_API BOOL BkscCloseControlDevice(_In_opt_ HANDLE Device)
{
    BOOL ok;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    BkscForgetSharedChannel(Device);
    ok = CloseHandle(Device);
    return ok;
}

BOOL BkscGetBrokerInfo(_Out_opt_ UINT32 *Capabilities, _Out_opt_ BOOL *ThreatIntelEnabled)
{
    if (!BkscIsClientProtocol())
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

BKSC_API BOOL BkscHasSharedChannel(_In_ HANDLE Device, _Out_opt_ BOOL *HasIoctlChannel, _Out_opt_ BOOL *HasEtwChannel)
{
    PBKSC_SHARED_CHANNEL channel;
    BOOL hasIoctl = FALSE;
    BOOL hasEtw = FALSE;

    if (!BkscIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    if (Device == NULL || Device == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    channel = BkscRetainSharedChannel(Device);
    if (channel != NULL)
    {
        hasIoctl = (channel->IoctlHeader != NULL && channel->IoctlRecords != NULL);
        hasEtw = (channel->EtwHeader != NULL && channel->EtwRecords != NULL);
        BkscReleaseSharedChannelRef(channel);
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

BKSC_API DWORD BkscGetLastSharedRingError(VOID)
{
    return (DWORD)InterlockedCompareExchange(&g_BlackbirdLastSharedRingError, 0, 0);
}

DWORD BkscGetLastThreatIntelEnableError(VOID)
{
    return (DWORD)InterlockedCompareExchange(&g_BlackbirdLastTiEnableError, 0, 0);
}

BOOL BkscSubscribe(_In_ HANDLE Device, _In_ DWORD ProcessId, _In_ DWORD StreamMask)
{
    BK_SUBSCRIBE_REQUEST req;
    DWORD bytes = 0;
    BKIPC_PACKET request;
    BKIPC_PACKET response;

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = ProcessId;
    req.StreamMask = StreamMask;

    if (BkscIsClientProtocol())
    {
        BkscInitIpcRequest(&request, BlackbirdIpcCommandSubscribe);
        request.Payload.SubscribeRequest = req;
        return BkscIpcTransact(Device, &request, &response);
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BK_SUBSCRIBE, &req, sizeof(req), NULL, 0, &bytes, NULL);
}

BOOL BkscUnsubscribe(_In_ HANDLE Device, _In_ DWORD ProcessId)
{
    BK_UNSUBSCRIBE_REQUEST req;
    DWORD bytes = 0;
    BKIPC_PACKET request;
    BKIPC_PACKET response;

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = ProcessId;

    if (BkscIsClientProtocol())
    {
        BkscInitIpcRequest(&request, BlackbirdIpcCommandUnsubscribe);
        request.Payload.UnsubscribeRequest = req;
        return BkscIpcTransact(Device, &request, &response);
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BK_UNSUBSCRIBE, &req, sizeof(req), NULL, 0, &bytes, NULL);
}

BOOL BkscSetPids(_In_ HANDLE Device, _In_reads_(ProcessCount) const DWORD *ProcessIds, _In_ DWORD ProcessCount,
                 _In_ DWORD StreamMask)
{
    BK_SET_PIDS_REQUEST req;
    DWORD bytes = 0;
    DWORD i;
    BKIPC_PACKET request;
    BKIPC_PACKET response;

    if ((ProcessIds == NULL && ProcessCount != 0) || ProcessCount > BK_MAX_PID_LIST)
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

    if (BkscIsClientProtocol())
    {
        BkscInitIpcRequest(&request, BlackbirdIpcCommandSetPids);
        request.Payload.SetPidsRequest = req;
        return BkscIpcTransact(Device, &request, &response);
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BK_SET_PIDS, &req, sizeof(req), NULL, 0, &bytes, NULL);
}

BOOL BkscArmPendingLaunch(_In_ HANDLE Device, _In_ const BK_ARM_PENDING_LAUNCH_REQUEST *Request)
{
    DWORD bytes = 0;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE || Request == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (BkscIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BK_ARM_PENDING_LAUNCH, (LPVOID)Request, sizeof(*Request), NULL, 0,
                           &bytes, NULL);
}

BOOL BkscGetEvent(_In_ HANDLE Device, _Out_ BK_EVENT_RECORD *Record, _Out_opt_ DWORD *BytesReturned)
{
    DWORD bytes = 0;
    BOOL ok;
    PBKSC_SHARED_CHANNEL channel;

    if (Record == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Record, sizeof(*Record));
    if (BkscIsClientProtocol())
    {
        channel = BkscRetainSharedChannel(Device);
        if (channel != NULL && channel->IoctlHeader != NULL)
        {
            ok = BkscPopSharedRing(channel->IoctlHeader, channel->IoctlRecords, channel->IoctlDataReadyEvent, Record,
                                   sizeof(*Record));
            if (!ok)
            {
                if (WaitForSingleObject(channel->IoctlDataReadyEvent, 0) == WAIT_OBJECT_0)
                {
                    ok = BkscPopSharedRing(channel->IoctlHeader, channel->IoctlRecords, channel->IoctlDataReadyEvent,
                                           Record, sizeof(*Record));
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
            BkscReleaseSharedChannelRef(channel);
        }
        else
        {
            if (channel != NULL)
            {
                BkscReleaseSharedChannelRef(channel);
            }
            ok = FALSE;
            SetLastError(ERROR_NOT_SUPPORTED);
        }
    }
    else
    {
        ok = DeviceIoControl(Device, (DWORD)IOCTL_BK_GET_EVENT, NULL, 0, Record, sizeof(*Record), &bytes, NULL);
    }

    if (BytesReturned != NULL)
    {
        *BytesReturned = bytes;
    }
    return ok;
}

BOOL BkscGetEventWait(_In_ HANDLE Device, _Out_ BK_EVENT_RECORD *Record, _Out_opt_ DWORD *BytesReturned,
                      _In_ DWORD TimeoutMs)
{
    PBKSC_SHARED_CHANNEL channel;

    if (Record == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Record, sizeof(*Record));
    if (!BkscIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    channel = BkscRetainSharedChannel(Device);
    if (channel != NULL && channel->IoctlHeader != NULL)
    {
        BOOL ok = BkscPopSharedRing(channel->IoctlHeader, channel->IoctlRecords, channel->IoctlDataReadyEvent, Record,
                                    sizeof(*Record));
        if (!ok)
        {
            DWORD waitResult = WaitForSingleObject(channel->IoctlDataReadyEvent, TimeoutMs);
            if (waitResult == WAIT_OBJECT_0)
            {
                ok = BkscPopSharedRing(channel->IoctlHeader, channel->IoctlRecords, channel->IoctlDataReadyEvent,
                                       Record, sizeof(*Record));
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
        if (ok && BytesReturned != NULL)
        {
            *BytesReturned = sizeof(*Record);
        }
        BkscReleaseSharedChannelRef(channel);
        return ok;
    }
    if (channel != NULL)
    {
        BkscReleaseSharedChannelRef(channel);
    }

    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

BOOL BkscGetStats(_In_ HANDLE Device, _Out_ BK_STATS_RESPONSE *Stats, _Out_opt_ DWORD *BytesReturned)
{
    DWORD bytes = 0;
    BOOL ok;
    BKIPC_PACKET request;
    BKIPC_PACKET response;

    if (Stats == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Stats, sizeof(*Stats));
    if (BkscIsClientProtocol())
    {
        BkscInitIpcRequest(&request, BlackbirdIpcCommandGetStats);
        ok = BkscIpcTransact(Device, &request, &response);
        if (ok)
        {
            *Stats = response.Payload.StatsResponse;
            bytes = sizeof(*Stats);
        }
    }
    else
    {
        ok = DeviceIoControl(Device, (DWORD)IOCTL_BK_GET_STATS, NULL, 0, Stats, sizeof(*Stats), &bytes, NULL);
    }

    if (BytesReturned != NULL)
    {
        *BytesReturned = bytes;
    }
    return ok;
}

BOOL BkscGetHealth(_In_ HANDLE Device, _Out_ BK_HEALTH_RESPONSE *Health, _Out_opt_ DWORD *BytesReturned)
{
    DWORD bytes = 0;
    BOOL ok;
    BKIPC_PACKET request;
    BKIPC_PACKET response;

    if (Health == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Health, sizeof(*Health));
    if (BkscIsClientProtocol())
    {
        BkscInitIpcRequest(&request, BlackbirdIpcCommandGetHealth);
        ok = BkscIpcTransact(Device, &request, &response);
        if (ok)
        {
            *Health = response.Payload.HealthResponse;
            bytes = sizeof(*Health);
        }
    }
    else
    {
        ok = DeviceIoControl(Device, (DWORD)IOCTL_BK_GET_HEALTH, NULL, 0, Health, sizeof(*Health), &bytes, NULL);
    }

    if (BytesReturned != NULL)
    {
        *BytesReturned = bytes;
    }
    return ok;
}

BOOL BkscGetDiagnostics(_In_ HANDLE Device, _Out_ BK_DIAGNOSTICS_RESPONSE *Diagnostics, _Out_opt_ DWORD *BytesReturned)
{
    DWORD bytes = 0;
    BOOL ok;
    BKIPC_PACKET request;
    BKIPC_PACKET response;

    if (Diagnostics == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Diagnostics, sizeof(*Diagnostics));
    if (BkscIsClientProtocol())
    {
        BkscInitIpcRequest(&request, BlackbirdIpcCommandGetDiagnostics);
        ok = BkscIpcTransact(Device, &request, &response);
        if (ok)
        {
            *Diagnostics = response.Payload.DiagnosticsResponse;
            bytes = sizeof(*Diagnostics);
        }
    }
    else
    {
        ok = DeviceIoControl(Device, (DWORD)IOCTL_BK_GET_DIAGNOSTICS, NULL, 0, Diagnostics, sizeof(*Diagnostics),
                             &bytes, NULL);
    }

    if (BytesReturned != NULL)
    {
        *BytesReturned = bytes;
    }
    return ok;
}

BOOL BkscQueryProcessImagePath(_In_ HANDLE Device, _In_ DWORD ProcessId, _Out_writes_z_(OutputChars) PWSTR Output,
                               _In_ DWORD OutputChars)
{
    BK_QUERY_PROCESS_IMAGE_REQUEST req;
    BK_QUERY_PROCESS_IMAGE_RESPONSE resp;
    DWORD bytes = 0;
    BOOL ok;
    BKIPC_PACKET request;
    BKIPC_PACKET response;

    if (Output == NULL || OutputChars == 0 || ProcessId == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    Output[0] = L'\0';

    ZeroMemory(&req, sizeof(req));
    ZeroMemory(&resp, sizeof(resp));
    req.ProcessId = ProcessId;

    if (BkscIsClientProtocol())
    {
        BkscInitIpcRequest(&request, BlackbirdIpcCommandQueryProcessImage);
        request.Payload.QueryProcessImageRequest = req;
        ok = BkscIpcTransact(Device, &request, &response);
        if (ok)
        {
            resp = response.Payload.QueryProcessImageResponse;
            bytes = sizeof(resp);
        }
    }
    else
    {
        ok = DeviceIoControl(Device, (DWORD)IOCTL_BK_QUERY_PROCESS_IMAGE, &req, sizeof(req), &resp, sizeof(resp),
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

BOOL BkscSetRuntimeConfig(_In_ HANDLE Device, _In_ DWORD Flags, _In_ DWORD Mask)
{
    BKIPC_PACKET request;
    BKIPC_PACKET response;
    BK_SET_RUNTIME_CONFIG_REQUEST req;
    DWORD bytes = 0;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    ZeroMemory(&req, sizeof(req));
    req.Flags = Flags;
    req.Mask = Mask;

    if (BkscIsClientProtocol())
    {
        BkscInitIpcRequest(&request, BlackbirdIpcCommandSetRuntimeConfig);
        request.Payload.SetRuntimeConfigRequest = req;
        return BkscIpcTransact(Device, &request, &response);
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BK_SET_RUNTIME_CONFIG, &req, sizeof(req), NULL, 0, &bytes, NULL);
}

BOOL BkscGetRuntimeConfig(_In_ HANDLE Device, _Out_ BK_RUNTIME_CONFIG_RESPONSE *Response)
{
    BKIPC_PACKET request;
    BKIPC_PACKET response;
    DWORD bytes = 0;
    BOOL ok;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE || Response == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Response, sizeof(*Response));

    if (BkscIsClientProtocol())
    {
        BkscInitIpcRequest(&request, BlackbirdIpcCommandGetRuntimeConfig);
        ok = BkscIpcTransact(Device, &request, &response);
        if (ok)
        {
            *Response = response.Payload.RuntimeConfigResponse;
        }
        return ok;
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BK_GET_RUNTIME_CONFIG, NULL, 0, Response, sizeof(*Response), &bytes,
                           NULL);
}

BOOL BkscSetQpcTimingConfig(_In_ HANDLE Device, _In_ const BK_QPC_TIMING_CONFIG *Config)
{
    BKIPC_PACKET request;
    BKIPC_PACKET response;
    DWORD bytes = 0;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE || Config == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (BkscIsClientProtocol())
    {
        BkscInitIpcRequest(&request, BlackbirdIpcCommandSetQpcTimingConfig);
        request.Payload.QpcTimingConfig = *Config;
        return BkscIpcTransact(Device, &request, &response);
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BK_SET_QPC_TIMING_CONFIG, (LPVOID)Config, sizeof(*Config), NULL, 0,
                           &bytes, NULL);
}

BOOL BkscGetQpcTimingState(_In_ HANDLE Device, _Out_ BK_QPC_TIMING_STATE *State)
{
    BKIPC_PACKET request;
    BKIPC_PACKET response;
    DWORD bytes = 0;
    BOOL ok;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE || State == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(State, sizeof(*State));

    if (BkscIsClientProtocol())
    {
        BkscInitIpcRequest(&request, BlackbirdIpcCommandGetQpcTimingState);
        ok = BkscIpcTransact(Device, &request, &response);
        if (ok)
        {
            *State = response.Payload.QpcTimingState;
        }
        return ok;
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BK_GET_QPC_TIMING_STATE, NULL, 0, State, sizeof(*State), &bytes, NULL);
}

BOOL BkscMarkControllerReady(_In_ HANDLE Device, _In_ DWORD ProcessId)
{
    BK_MARK_CONTROLLER_READY_REQUEST req;
    DWORD bytes = 0;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE || ProcessId == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(&req, sizeof(req));
    req.ProcessId = ProcessId;

    if (BkscIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BK_MARK_CONTROLLER_READY, &req, sizeof(req), NULL, 0, &bytes, NULL);
}

BOOL BkscRegisterInstrumentationRange(_In_ HANDLE Device, _In_ const BK_REGISTER_INSTRUMENTATION_RANGE_REQUEST *Request)
{
    DWORD bytes = 0;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE || Request == NULL || Request->ProcessId == 0 ||
        Request->BaseAddress == 0 || Request->RegionSize == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (BkscIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BK_REGISTER_INSTRUMENTATION_RANGE, (LPVOID)Request, sizeof(*Request),
                           NULL, 0, &bytes, NULL);
}

BOOL BkscRegisterHookPatch(_In_ HANDLE Device, _In_ const BK_REGISTER_HOOK_PATCH_REQUEST *Request)
{
    DWORD bytes = 0;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE || Request == NULL || Request->ProcessId == 0 ||
        Request->PatchAddress == 0 || Request->PatchSize == 0 || Request->OriginalSize == 0 ||
        Request->PatchSize > BK_MAX_HOOK_PATCH_BYTES || Request->OriginalSize > BK_MAX_HOOK_PATCH_BYTES)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (BkscIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BK_REGISTER_HOOK_PATCH, (LPVOID)Request, sizeof(*Request), NULL, 0,
                           &bytes, NULL);
}

BOOL BkscRegisterProcessInstrumentationCallback(
    _In_ HANDLE Device, _In_ const BK_REGISTER_PROCESS_INSTRUMENTATION_CALLBACK_REQUEST *Request)
{
    DWORD bytes = 0;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE || Request == NULL || Request->ProcessId == 0 ||
        Request->CallbackAddress == 0 || Request->CallbackSize == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (BkscIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BK_REGISTER_PROCESS_INSTRUMENTATION_CALLBACK, (LPVOID)Request,
                           sizeof(*Request), NULL, 0, &bytes, NULL);
}

BOOL BkscSetEndpointGuard(_In_ HANDLE Device, _In_ const BK_ENDPOINT_GUARD_REQUEST *Request)
{
    DWORD bytes = 0;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE || Request == NULL || Request->ProcessId == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (BkscIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BK_SET_ENDPOINT_GUARD, (LPVOID)Request, sizeof(*Request), NULL, 0,
                           &bytes, NULL);
}

BOOL BkscSetUserHookTarget(_In_ HANDLE Device, _In_ DWORD Mode, _In_ DWORD ProcessId, _In_ DWORD Flags,
                           _In_opt_z_ PCWSTR ImagePath, _In_ DWORD AnalysisSubjectKind,
                           _In_opt_z_ PCWSTR AnalysisSubjectPath, _In_opt_z_ PCWSTR HookDllPath,
                           _In_opt_z_ PCWSTR WorkingDirectory, _In_opt_z_ PCWSTR EnvironmentOverrides,
                           _In_opt_z_ PCWSTR CommandLineArguments, _In_ DWORD ParentProcessId, _In_ DWORD PriorityClass,
                           _In_ UINT64 AffinityMask, _In_ BOOL InheritHandles, _In_ DWORD IntegrityLevel,
                           _Out_opt_ BKIPC_SET_USER_HOOK_TARGET_RESPONSE *Response)
{
    BKIPC_PACKET request;
    BKIPC_PACKET response;
    BKIPC_SET_USER_HOOK_TARGET_REQUEST payload;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    if (!BkscIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    ZeroMemory(&payload, sizeof(payload));
    payload.Mode = Mode;
    payload.ProcessId = ProcessId;
    payload.Flags = Flags;
    payload.ParentProcessId = ParentProcessId;
    payload.PriorityClass = PriorityClass;
    payload.InheritHandles = InheritHandles ? 1u : 0u;
    payload.IntegrityLevel = IntegrityLevel;
    payload.AnalysisSubjectKind = AnalysisSubjectKind;
    payload.AffinityMask = AffinityMask;
    if (ImagePath != NULL)
    {
        (void)StringCchCopyW(payload.ImagePath, RTL_NUMBER_OF(payload.ImagePath), ImagePath);
    }
    if (AnalysisSubjectPath != NULL)
    {
        (void)StringCchCopyW(payload.AnalysisSubjectPath, RTL_NUMBER_OF(payload.AnalysisSubjectPath),
                             AnalysisSubjectPath);
    }
    if (HookDllPath != NULL)
    {
        (void)StringCchCopyW(payload.HookDllPath, RTL_NUMBER_OF(payload.HookDllPath), HookDllPath);
    }
    if (WorkingDirectory != NULL)
    {
        (void)StringCchCopyW(payload.WorkingDirectory, RTL_NUMBER_OF(payload.WorkingDirectory), WorkingDirectory);
    }
    if (CommandLineArguments != NULL)
    {
        (void)StringCchCopyW(payload.CommandLineArguments, RTL_NUMBER_OF(payload.CommandLineArguments),
                             CommandLineArguments);
    }
    if (EnvironmentOverrides != NULL)
    {
        (void)StringCchCopyW(payload.EnvironmentOverrides, RTL_NUMBER_OF(payload.EnvironmentOverrides),
                             EnvironmentOverrides);
    }

    BkscInitIpcRequest(&request, BlackbirdIpcCommandSetUserHookTarget);
    request.Payload.SetUserHookTargetRequest = payload;
    if (!BkscIpcTransact(Device, &request, &response))
    {
        return FALSE;
    }

    if (Response != NULL)
    {
        *Response = response.Payload.SetUserHookTargetResponse;
    }
    return TRUE;
}

BOOL BkscSetShutdownMode(_In_ HANDLE Device)
{
    DWORD bytes = 0;
    BKIPC_PACKET request;
    BKIPC_PACKET response;

    if (BkscIsClientProtocol())
    {
        BkscInitIpcRequest(&request, BlackbirdIpcCommandSetShutdownMode);
        return BkscIpcTransact(Device, &request, &response);
    }

    return DeviceIoControl(Device, (DWORD)IOCTL_BK_SET_SHUTDOWN_MODE, NULL, 0, NULL, 0, &bytes, NULL);
}

BOOL BkscControlProcessExecution(_In_ HANDLE Device, _In_ DWORD ProcessId, _In_ BOOL Suspend)
{
    BKIPC_PACKET request;
    BKIPC_PACKET response;
    BK_CONTROL_EXECUTION_REQUEST req;
    DWORD bytes = 0;

    if (BkscIsClientProtocol())
    {
        BkscInitIpcRequest(&request, BlackbirdIpcCommandControlProcessExecution);
        request.Payload.ControlProcessExecutionRequest.ProcessId = ProcessId;
        request.Payload.ControlProcessExecutionRequest.Suspend = Suspend ? 1u : 0u;
        return BkscIpcTransact(Device, &request, &response);
    }

    req.ProcessId = ProcessId;
    req.Suspend = Suspend ? 1u : 0u;
    return DeviceIoControl(Device, (DWORD)IOCTL_BK_CONTROL_EXECUTION, &req, sizeof(req), NULL, 0, &bytes, NULL);
}

BOOL BkscGetEtwEvent(_In_ HANDLE Device, _Out_ BKIPC_ETW_EVENT *Event, _In_ DWORD TimeoutMs)
{
    PBKSC_SHARED_CHANNEL channel;

    if (Event == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Event, sizeof(*Event));
    if (!BkscIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    channel = BkscRetainSharedChannel(Device);
    if (channel != NULL && channel->EtwHeader != NULL)
    {
        BOOL ok = BkscPopSharedRing(channel->EtwHeader, channel->EtwRecords, channel->EtwDataReadyEvent, Event,
                                    sizeof(*Event));
        if (!ok)
        {
            DWORD waitResult = WaitForSingleObject(channel->EtwDataReadyEvent, TimeoutMs);
            if (waitResult == WAIT_OBJECT_0)
            {
                ok = BkscPopSharedRing(channel->EtwHeader, channel->EtwRecords, channel->EtwDataReadyEvent, Event,
                                       sizeof(*Event));
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
        BkscReleaseSharedChannelRef(channel);
        return ok;
    }
    if (channel != NULL)
    {
        BkscReleaseSharedChannelRef(channel);
    }

    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

BKSC_API BOOL BkscQueryProcessMemory(_In_ HANDLE Device, _In_ DWORD ProcessId, _In_ UINT64 BaseAddress,
                                     _In_ DWORD RequestedSize, _Out_writes_bytes_(*BytesRead) PVOID Buffer,
                                     _In_ DWORD BufferSize, _Out_ DWORD *BytesRead)
{
    BKIPC_PACKET request;
    BKIPC_PACKET response;
    HANDLE hSection;
    PVOID pView;
    DWORD toCopy;

    if (Device == NULL || Device == INVALID_HANDLE_VALUE || ProcessId == 0 || RequestedSize == 0 || Buffer == NULL ||
        BufferSize == 0 || BytesRead == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *BytesRead = 0;

    if (!BkscIsClientProtocol())
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    BkscInitIpcRequest(&request, BlackbirdIpcCommandQueryProcessMemory);
    request.Payload.QueryMemoryRequest.ProcessId = ProcessId;
    request.Payload.QueryMemoryRequest.BaseAddress = BaseAddress;
    request.Payload.QueryMemoryRequest.RequestedSize =
        (RequestedSize < BK_MAX_MEMORY_READ_BYTES) ? RequestedSize : BK_MAX_MEMORY_READ_BYTES;

    if (!BkscIpcTransact(Device, &request, &response))
    {
        return FALSE;
    }

    if (response.Payload.QueryMemoryResponse.BytesRead == 0 || response.Payload.QueryMemoryResponse.SectionHandle == 0)
    {
        SetLastError(ERROR_NO_DATA);
        return FALSE;
    }

    hSection = (HANDLE)(ULONG_PTR)response.Payload.QueryMemoryResponse.SectionHandle;
    toCopy = (response.Payload.QueryMemoryResponse.BytesRead < BufferSize)
                 ? response.Payload.QueryMemoryResponse.BytesRead
                 : BufferSize;

    pView = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, toCopy);
    if (pView == NULL)
    {
        CloseHandle(hSection);
        return FALSE;
    }

    CopyMemory(Buffer, pView, toCopy);
    UnmapViewOfFile(pView);
    CloseHandle(hSection);

    *BytesRead = toCopy;
    return TRUE;
}

DWORD
BkscParseStreamMaskA(_In_z_ const char *Text)
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
            mask |= BK_STREAM_HANDLE;
        }
        else if (_stricmp(tok, "memory") == 0)
        {
            mask |= BK_STREAM_MEMORY;
        }
        else if (_stricmp(tok, "thread") == 0)
        {
            mask |= BK_STREAM_THREAD;
        }
        else if (_stricmp(tok, "filesystem") == 0 || _stricmp(tok, "file") == 0 || _stricmp(tok, "fs") == 0)
        {
            mask |= BK_STREAM_FILESYSTEM;
        }
        else if (_stricmp(tok, "registry") == 0 || _stricmp(tok, "reg") == 0)
        {
            mask |= BK_STREAM_REGISTRY;
        }
        else if (_stricmp(tok, "timing") == 0 || _stricmp(tok, "qpc") == 0)
        {
            mask |= BK_STREAM_TIMING;
        }
        else if (_stricmp(tok, "enterprise") == 0 || _stricmp(tok, "ad") == 0 || _stricmp(tok, "credential") == 0)
        {
            mask |= BK_STREAM_ENTERPRISE;
        }
    }

    free(copy);
    return mask;
}
