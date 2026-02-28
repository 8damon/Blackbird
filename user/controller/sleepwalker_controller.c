#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winsvc.h>
#include <sddl.h>
#include <strsafe.h>
#include <tdh.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "..\sensor\sleepwalker_sensor_core.h"
#include "..\..\abi\sleepwalker_ipc.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

#define SLEEPWALKER_CONTROLLER_SERVICE_NAMEW L"SleepwlkrController"
#define SLEEPWALKER_CONTROLLER_ETW_SESSION_NAMEW L"SleepwlkrControllerSession"
#define SLEEPWALKER_CONTROLLER_ETW_LEGACY_PREFIXW L"SleepwlkrController-"
#define SLEEPWALKER_CONTROLLER_ETW_MAX_QUERY_SESSIONS 64u
#define SLEEPWALKER_CONTROLLER_MAX_CLIENTS 256u
#define SLEEPWALKER_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS 64u
#define SLEEPWALKER_CONTROLLER_MAX_CLIENT_QUEUE_DEPTH 1024u
#define SLEEPWALKER_CONTROLLER_MAX_CLIENT_ETW_QUEUE_DEPTH 2048u
#define SLEEPWALKER_CONTROLLER_DRIVER_STREAM_MASK \
    (SLEEPWALKER_STREAM_HANDLE | SLEEPWALKER_STREAM_MEMORY | SLEEPWALKER_STREAM_THREAD)

typedef struct _SLEEPWALKER_CONTROLLER_SUBSCRIPTION
{
    DWORD ProcessId;
    DWORD StreamMask;
} SLEEPWALKER_CONTROLLER_SUBSCRIPTION, *PSLEEPWALKER_CONTROLLER_SUBSCRIPTION;

typedef struct _SLEEPWALKER_CONTROLLER_EVENT_NODE
{
    struct _SLEEPWALKER_CONTROLLER_EVENT_NODE *Next;
    SLEEPWALKER_EVENT_RECORD Record;
} SLEEPWALKER_CONTROLLER_EVENT_NODE, *PSLEEPWALKER_CONTROLLER_EVENT_NODE;

typedef struct _SLEEPWALKER_CONTROLLER_ETW_EVENT_NODE
{
    struct _SLEEPWALKER_CONTROLLER_ETW_EVENT_NODE *Next;
    SLEEPWALKER_IPC_ETW_EVENT Event;
} SLEEPWALKER_CONTROLLER_ETW_EVENT_NODE, *PSLEEPWALKER_CONTROLLER_ETW_EVENT_NODE;

typedef struct _SLEEPWALKER_CONTROLLER_CLIENT
{
    struct _SLEEPWALKER_CONTROLLER_CLIENT *Next;
    HANDLE Pipe;
    DWORD ProcessId;
    DWORD SessionId;
    CRITICAL_SECTION Lock;
    DWORD SubscriptionCount;
    SLEEPWALKER_CONTROLLER_SUBSCRIPTION Subscriptions[SLEEPWALKER_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS];
    PSLEEPWALKER_CONTROLLER_EVENT_NODE QueueHead;
    PSLEEPWALKER_CONTROLLER_EVENT_NODE QueueTail;
    DWORD QueueDepth;
    DWORD DroppedEvents;
    PSLEEPWALKER_CONTROLLER_ETW_EVENT_NODE EtwQueueHead;
    PSLEEPWALKER_CONTROLLER_ETW_EVENT_NODE EtwQueueTail;
    DWORD EtwQueueDepth;
    DWORD EtwDroppedEvents;
} SLEEPWALKER_CONTROLLER_CLIENT, *PSLEEPWALKER_CONTROLLER_CLIENT;

static SERVICE_STATUS_HANDLE g_ServiceStatusHandle = NULL;
static SERVICE_STATUS g_ServiceStatus;
static HANDLE g_StopEvent = NULL;
static HANDLE g_ServerThread = NULL;
static HANDLE g_DriverPumpThread = NULL;
static HANDLE g_EtwThread = NULL;
static HANDLE g_DriverHandle = INVALID_HANDLE_VALUE;
static SLEEPWALKERSC_ETW_SESSION *g_EtwSession = NULL;
static BOOL g_ThreatIntelEnabled = FALSE;
static volatile LONG g_EtwDetectionEvents = 0;
static volatile LONG g_EtwTiEvents = 0;
static CRITICAL_SECTION g_ClientListLock;
static CRITICAL_SECTION g_DriverLock;
static CRITICAL_SECTION g_DriverConfigLock;
static BOOL g_LocksInitialized = FALSE;
static PSLEEPWALKER_CONTROLLER_CLIENT g_ClientList = NULL;
static DWORD g_ClientCount = 0;
static DWORD g_ProgrammedPids[SLEEPWALKER_MAX_PID_LIST];
static DWORD g_ProgrammedPidCount = 0;

static VOID ControllerLog(_In_z_ _Printf_format_string_ PCSTR Format, ...)
{
    char message[1024];
    va_list args;

    va_start(args, Format);
    (void)StringCchVPrintfA(message, RTL_NUMBER_OF(message), Format, args);
    va_end(args);

    (void)OutputDebugStringA(message);
    (void)printf("%s", message);
}

static VOID ControllerUpdateServiceStatus(_In_ DWORD CurrentState, _In_ DWORD Win32ExitCode, _In_ DWORD WaitHint)
{
    static DWORD checkpoint = 1;

    if (g_ServiceStatusHandle == NULL)
    {
        return;
    }

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = CurrentState;
    g_ServiceStatus.dwWin32ExitCode = Win32ExitCode;
    g_ServiceStatus.dwWaitHint = WaitHint;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (CurrentState == SERVICE_START_PENDING || CurrentState == SERVICE_STOP_PENDING)
    {
        g_ServiceStatus.dwCheckPoint = checkpoint++;
    }

    if (CurrentState == SERVICE_RUNNING)
    {
        g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }

    (void)SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
}

static BOOL ControllerShouldStop(VOID)
{
    return (g_StopEvent != NULL && WaitForSingleObject(g_StopEvent, 0) == WAIT_OBJECT_0);
}

static VOID ControllerStopEtwSessionByNameBestEffort(_In_z_ PCWSTR SessionName, _In_z_ PCSTR Reason)
{
    ULONG status;

    if (SessionName == NULL || SessionName[0] == L'\0')
    {
        return;
    }

    status = SLEEPWALKERSCStopSessionByName(SessionName);
    if (status == ERROR_SUCCESS)
    {
        ControllerLog("[ETW] stopped session reason=%s name=%ws\n", Reason, SessionName);
    }
    else
    {
        ControllerLog("[ETW][WARN] stop-by-name failed reason=%s name=%ws status=%lu\n", Reason, SessionName, status);
    }
}

static VOID ControllerCleanupStaleEtwSessions(VOID)
{
    const ULONG propsBytes = sizeof(EVENT_TRACE_PROPERTIES) + (1024 * sizeof(WCHAR));
    PEVENT_TRACE_PROPERTIES propsArray[SLEEPWALKER_CONTROLLER_ETW_MAX_QUERY_SESSIONS];
    ULONG loggerCount = SLEEPWALKER_CONTROLLER_ETW_MAX_QUERY_SESSIONS;
    ULONG status;
    ULONG i;
    size_t legacyPrefixChars = wcslen(SLEEPWALKER_CONTROLLER_ETW_LEGACY_PREFIXW);

    ZeroMemory(propsArray, sizeof(propsArray));
    ControllerStopEtwSessionByNameBestEffort(SLEEPWALKER_CONTROLLER_ETW_SESSION_NAMEW, "pre-start");

    for (i = 0; i < SLEEPWALKER_CONTROLLER_ETW_MAX_QUERY_SESSIONS; ++i)
    {
        propsArray[i] = (PEVENT_TRACE_PROPERTIES)calloc(1, propsBytes);
        if (propsArray[i] == NULL)
        {
            loggerCount = i;
            break;
        }

        propsArray[i]->Wnode.BufferSize = propsBytes;
        propsArray[i]->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        propsArray[i]->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + (512 * sizeof(WCHAR));
    }

    if (loggerCount == 0)
    {
        return;
    }

    status = QueryAllTracesW(propsArray, loggerCount, &loggerCount);
    if (status == ERROR_SUCCESS || status == ERROR_MORE_DATA)
    {
        for (i = 0; i < loggerCount && i < SLEEPWALKER_CONTROLLER_ETW_MAX_QUERY_SESSIONS; ++i)
        {
            PWSTR loggerName;

            if (propsArray[i] == NULL || propsArray[i]->LoggerNameOffset == 0)
            {
                continue;
            }

            loggerName = (PWSTR)((PBYTE)propsArray[i] + propsArray[i]->LoggerNameOffset);
            if (loggerName == NULL || loggerName[0] == L'\0')
            {
                continue;
            }

            if (_wcsnicmp(loggerName, SLEEPWALKER_CONTROLLER_ETW_LEGACY_PREFIXW, legacyPrefixChars) == 0)
            {
                ControllerStopEtwSessionByNameBestEffort(loggerName, "cleanup-legacy");
            }
        }
    }
    else
    {
        ControllerLog("[ETW][WARN] QueryAllTracesW failed status=%lu\n", status);
    }

    for (i = 0; i < SLEEPWALKER_CONTROLLER_ETW_MAX_QUERY_SESSIONS; ++i)
    {
        if (propsArray[i] != NULL)
        {
            free(propsArray[i]);
            propsArray[i] = NULL;
        }
    }
}

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

    if (Client == NULL || Request == NULL || Request->ProcessId == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&Client->Lock);
    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (Client->Subscriptions[i].ProcessId == Request->ProcessId)
        {
            DWORD tail = Client->SubscriptionCount - 1;
            if (i != tail)
            {
                Client->Subscriptions[i] = Client->Subscriptions[tail];
            }
            Client->SubscriptionCount -= 1;
            LeaveCriticalSection(&Client->Lock);
            ControllerLog("[IPC] unsubscribe clientPid=%lu targetPid=%lu\n", Client->ProcessId, Request->ProcessId);
            (void)ControllerApplyDriverSubscriptions();
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
                seen = TRUE;
                break;
            }
        }

        if (!seen && Client->SubscriptionCount < SLEEPWALKER_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS)
        {
            Client->Subscriptions[Client->SubscriptionCount].ProcessId = pid;
            Client->Subscriptions[Client->SubscriptionCount].StreamMask = Request->StreamMask;
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

    (void)ControllerApplyDriverSubscriptions();
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
        (void)FlushFileBuffers(client->Pipe);
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

static DWORD WINAPI ControllerServerThreadProc(_In_ LPVOID Context)
{
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD pipeCreateFailures = 0;

    UNREFERENCED_PARAMETER(Context);

    if (!ControllerCreatePipeSecurity(&sa, &sd))
    {
        ControllerLog("[-] SleepwlkrController: failed to create pipe security (%lu)\n", GetLastError());
        return 1;
    }

    while (!ControllerShouldStop())
    {
        HANDLE pipe;
        BOOL connected;
        DWORD mode = PIPE_READMODE_MESSAGE;
        SLEEPWALKER_CONTROLLER_CLIENT *client;
        HANDLE thread;

        pipe = CreateNamedPipeW(SLEEPWALKER_IPC_PIPE_NAME,
                                PIPE_ACCESS_DUPLEX,
                                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                PIPE_UNLIMITED_INSTANCES,
                                sizeof(SLEEPWALKER_IPC_PACKET),
                                sizeof(SLEEPWALKER_IPC_PACKET),
                                3000,
                                &sa);
        if (pipe == INVALID_HANDLE_VALUE)
        {
            pipeCreateFailures += 1;
            if (pipeCreateFailures == 1 || (pipeCreateFailures % 50) == 0)
            {
                ControllerLog("[WARN] SleepwlkrController: CreateNamedPipe failed (%lu), retries=%lu\n", GetLastError(),
                              pipeCreateFailures);
            }
            Sleep(250);
            continue;
        }
        pipeCreateFailures = 0;

        connected = ConnectNamedPipe(pipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected)
        {
            ControllerLog("[WARN] SleepwlkrController: ConnectNamedPipe failed (%lu)\n", GetLastError());
            CloseHandle(pipe);
            continue;
        }

        (void)SetNamedPipeHandleState(pipe, &mode, NULL, NULL);

        client = (SLEEPWALKER_CONTROLLER_CLIENT *)calloc(1, sizeof(*client));
        if (client == NULL)
        {
            CloseHandle(pipe);
            continue;
        }

        client->Pipe = pipe;
        client->QueueHead = NULL;
        client->QueueTail = NULL;
        client->QueueDepth = 0;
        client->DroppedEvents = 0;
        client->SubscriptionCount = 0;
        InitializeCriticalSection(&client->Lock);
        if (!GetNamedPipeClientProcessId(pipe, &client->ProcessId))
        {
            client->ProcessId = 0;
        }
        if (!ProcessIdToSessionId(client->ProcessId, &client->SessionId))
        {
            client->SessionId = 0;
        }

        ControllerLog("[IPC] client connected pid=%lu session=%lu\n", client->ProcessId, client->SessionId);

        EnterCriticalSection(&g_ClientListLock);
        if (g_ClientCount >= SLEEPWALKER_CONTROLLER_MAX_CLIENTS)
        {
            LeaveCriticalSection(&g_ClientListLock);
            DeleteCriticalSection(&client->Lock);
            CloseHandle(pipe);
            free(client);
            continue;
        }
        client->Next = g_ClientList;
        g_ClientList = client;
        g_ClientCount += 1;
        ControllerLog("[IPC] active clients=%lu\n", g_ClientCount);
        LeaveCriticalSection(&g_ClientListLock);

        thread = CreateThread(NULL, 0, ControllerClientThreadProc, client, 0, NULL);
        if (thread == NULL)
        {
            ControllerLog("[WARN] SleepwlkrController: failed to spawn client thread for pid=%lu (%lu)\n",
                          client->ProcessId, GetLastError());
            ControllerDetachClient(client);
            DeleteCriticalSection(&client->Lock);
            CloseHandle(pipe);
            free(client);
            continue;
        }
        CloseHandle(thread);
    }

    if (sd != NULL)
    {
        LocalFree(sd);
    }
    return 0;
}

static DWORD WINAPI ControllerDriverPumpThreadProc(_In_ LPVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    DWORD driverOpenFailures = 0;

    while (!ControllerShouldStop())
    {
        SLEEPWALKER_EVENT_RECORD record;
        DWORD bytes = 0;
        BOOL ok;

        EnterCriticalSection(&g_DriverLock);
        if (g_DriverHandle == INVALID_HANDLE_VALUE)
        {
            g_DriverHandle = SLEEPWALKERSCOpenControlDevice();
            LeaveCriticalSection(&g_DriverLock);
            if (g_DriverHandle != INVALID_HANDLE_VALUE)
            {
                SLEEPWALKER_STATS_RESPONSE stats;
                DWORD statsBytes = 0;
                (void)ControllerApplyDriverSubscriptions();
                driverOpenFailures = 0;
                ZeroMemory(&stats, sizeof(stats));
                if (SLEEPWALKERSCGetStats(g_DriverHandle, &stats, &statsBytes))
                {
                    ControllerLog("[DRIVER] connected and verified. subscriptions=%lu queueDepth=%lu dropped=%lu\n",
                                  stats.SubscriptionCount, stats.QueueDepth, stats.DroppedEvents);
                }
                else
                {
                    ControllerLog("[DRIVER][WARN] connected, but stats query failed (%lu)\n", GetLastError());
                }
            }
            else
            {
                driverOpenFailures += 1;
                if (driverOpenFailures == 1 || (driverOpenFailures % 40) == 0)
                {
                    ControllerLog("[DRIVER][WARN] open failed (%lu), retries=%lu\n", GetLastError(),
                                  driverOpenFailures);
                }
            }
            Sleep(250);
            continue;
        }

        ok = SLEEPWALKERSCGetEvent(g_DriverHandle, &record, &bytes);
        if (!ok)
        {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS)
            {
                LeaveCriticalSection(&g_DriverLock);
                Sleep(20);
                continue;
            }

            ControllerLog("[DRIVER][WARN] event read failed (%lu), reconnecting\n", err);
            CloseHandle(g_DriverHandle);
            g_DriverHandle = INVALID_HANDLE_VALUE;
            LeaveCriticalSection(&g_DriverLock);
            Sleep(200);
            continue;
        }
        LeaveCriticalSection(&g_DriverLock);

        if (bytes >= sizeof(record))
        {
            ControllerDispatchDriverRecord(&record);
        }
    }

    return 0;
}
static VOID WINAPI ControllerEtwCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName, _In_opt_ PVOID Context)
{
    SLEEPWALKER_IPC_ETW_EVENT event;
    ULONGLONG processId = 0;
    ULONGLONG callerPid = 0;
    ULONGLONG targetPid = 0;
    ULONG severity = 0;

    UNREFERENCED_PARAMETER(Context);

    if (Record == NULL)
    {
        return;
    }

    ZeroMemory(&event, sizeof(event));
    event.EventId = Record->EventHeader.EventDescriptor.Id;
    event.Opcode = Record->EventHeader.EventDescriptor.Opcode;
    event.Task = Record->EventHeader.EventDescriptor.Task;
    event.EventProcessId = Record->EventHeader.ProcessId;
    event.EventThreadId = Record->EventHeader.ThreadId;
    if (EventName != NULL && EventName[0] != L'\0')
    {
        (void)StringCchCopyW(event.EventName, RTL_NUMBER_OF(event.EventName), EventName);
    }

    if (IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_TI))
    {
        event.Source = SleepwalkerIpcEtwSourceThreatIntel;
        (void)InterlockedIncrement(&g_EtwTiEvents);
    }
    else if (IsEqualGUID(&Record->EventHeader.ProviderId, &SLEEPWALKERSC_PROVIDER_GUID_SLEEPWALKER))
    {
        event.Source = SleepwalkerIpcEtwSourceSleepwalker;
    }
    else
    {
        return;
    }

    if (EventName != NULL && wcscmp(EventName, L"DetectionTelemetry") == 0)
    {
        (void)InterlockedIncrement(&g_EtwDetectionEvents);
        (void)ControllerEtwGetAnsiProperty(Record, L"detectionName", event.DetectionName,
                                           RTL_NUMBER_OF(event.DetectionName));
        if (event.DetectionName[0] == '\0')
        {
            (void)StringCchCopyA(event.DetectionName, RTL_NUMBER_OF(event.DetectionName), "UNKNOWN");
        }
        (void)ControllerEtwGetU32Property(Record, L"severity", &severity);
        event.Severity = severity;
    }

    (void)ControllerEtwGetU64Property(Record, L"processId", &processId);
    (void)ControllerEtwGetU64Property(Record, L"callerPid", &callerPid);
    (void)ControllerEtwGetU64Property(Record, L"targetPid", &targetPid);
    if (processId == 0)
    {
        processId = callerPid;
    }
    if (processId == 0)
    {
        processId = Record->EventHeader.ProcessId;
    }

    event.PrimaryPid = processId;
    event.SecondaryPid = targetPid;
    ControllerDispatchEtwEvent(&event);
}

static DWORD WINAPI ControllerEtwThreadProc(_In_ LPVOID Context)
{
    DWORD status;

    UNREFERENCED_PARAMETER(Context);

    if (g_EtwSession == NULL)
    {
        return 1;
    }

    status = SLEEPWALKERSCRunEtwSession(g_EtwSession);
    ControllerLog("[ETW] run loop exited status=%lu tiEvents=%ld detectionEvents=%ld\n", status,
                  InterlockedCompareExchange(&g_EtwTiEvents, 0, 0),
                  InterlockedCompareExchange(&g_EtwDetectionEvents, 0, 0));
    return status;
}

static BOOL ControllerStartEtwSession(VOID)
{
    ControllerCleanupStaleEtwSessions();
    (void)InterlockedExchange(&g_EtwTiEvents, 0);
    (void)InterlockedExchange(&g_EtwDetectionEvents, 0);
    g_ThreatIntelEnabled = FALSE;
    if (!SLEEPWALKERSCStartSleepwalkerEtwSession(SLEEPWALKER_CONTROLLER_ETW_SESSION_NAMEW, TRUE, ControllerEtwCallback,
                                                 NULL, &g_EtwSession, &g_ThreatIntelEnabled))
    {
        DWORD err = GetLastError();
        ControllerLog("[WARN] SleepwlkrController: failed to start ETW TI session name=%ws (%lu)\n",
                      SLEEPWALKER_CONTROLLER_ETW_SESSION_NAMEW, err);
        g_EtwSession = NULL;
        g_ThreatIntelEnabled = FALSE;
        return FALSE;
    }

    g_EtwThread = CreateThread(NULL, 0, ControllerEtwThreadProc, NULL, 0, NULL);
    if (g_EtwThread == NULL)
    {
        ControllerLog("[WARN] SleepwlkrController: failed to start ETW thread (%lu)\n", GetLastError());
        SLEEPWALKERSCStopEtwSession(g_EtwSession);
        g_EtwSession = NULL;
        g_ThreatIntelEnabled = FALSE;
        return FALSE;
    }

    ControllerLog("[*] SleepwlkrController: ETW session started. threat-intel=%s\n",
                  g_ThreatIntelEnabled ? "enabled" : "fallback-disabled");
    return TRUE;
}

static VOID ControllerStopEtwSession(VOID)
{
    if (g_EtwSession != NULL)
    {
        SLEEPWALKERSCStopEtwSession(g_EtwSession);
        g_EtwSession = NULL;
    }

    if (g_EtwThread != NULL)
    {
        (void)WaitForSingleObject(g_EtwThread, 3000);
        CloseHandle(g_EtwThread);
        g_EtwThread = NULL;
    }

    ControllerStopEtwSessionByNameBestEffort(SLEEPWALKER_CONTROLLER_ETW_SESSION_NAMEW, "service-stop");
    ControllerLog("[ETW] session stopped tiEvents=%ld detectionEvents=%ld\n",
                  InterlockedCompareExchange(&g_EtwTiEvents, 0, 0),
                  InterlockedCompareExchange(&g_EtwDetectionEvents, 0, 0));
}

static BOOL ControllerStartCore(VOID)
{
    if (g_LocksInitialized)
    {
        return TRUE;
    }

    InitializeCriticalSection(&g_ClientListLock);
    InitializeCriticalSection(&g_DriverLock);
    InitializeCriticalSection(&g_DriverConfigLock);
    g_LocksInitialized = TRUE;

    ControllerLog("[*] SleepwlkrController: core start requested\n");

    g_StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_StopEvent == NULL)
    {
        ControllerLog("[-] SleepwlkrController: failed to create stop event (%lu)\n", GetLastError());
        return FALSE;
    }

    SLEEPWALKERSCUseServiceProtocol();
    g_DriverHandle = SLEEPWALKERSCOpenControlDevice();
    if (g_DriverHandle == INVALID_HANDLE_VALUE)
    {
        ControllerLog("[WARN] SleepwlkrController: initial driver open failed (%lu). retrying in background.\n",
                      GetLastError());
    }
    else
    {
        ControllerLog("[DRIVER] initial open succeeded\n");
    }

    (void)ControllerStartEtwSession();

    g_DriverPumpThread = CreateThread(NULL, 0, ControllerDriverPumpThreadProc, NULL, 0, NULL);
    if (g_DriverPumpThread == NULL)
    {
        ControllerLog("[-] SleepwlkrController: failed to start driver pump thread (%lu)\n", GetLastError());
        return FALSE;
    }

    g_ServerThread = CreateThread(NULL, 0, ControllerServerThreadProc, NULL, 0, NULL);
    if (g_ServerThread == NULL)
    {
        ControllerLog("[-] SleepwlkrController: failed to start server thread (%lu)\n", GetLastError());
        return FALSE;
    }

    ControllerLog("[*] SleepwlkrController: IPC endpoint online at %ls\n", SLEEPWALKER_IPC_PIPE_NAME);
    return TRUE;
}

static VOID ControllerWakeServerPipe(VOID)
{
    HANDLE pipe =
        CreateFileW(SLEEPWALKER_IPC_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (pipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(pipe);
    }
}

static VOID ControllerStopCore(VOID)
{
    DWORD waitMs = 0;

    ControllerLog("[*] SleepwlkrController: stop requested\n");

    if (g_StopEvent != NULL)
    {
        (void)SetEvent(g_StopEvent);
    }

    ControllerWakeServerPipe();

    if (g_ServerThread != NULL)
    {
        (void)WaitForSingleObject(g_ServerThread, 3000);
        CloseHandle(g_ServerThread);
        g_ServerThread = NULL;
    }

    if (g_DriverPumpThread != NULL)
    {
        (void)WaitForSingleObject(g_DriverPumpThread, 3000);
        CloseHandle(g_DriverPumpThread);
        g_DriverPumpThread = NULL;
    }

    EnterCriticalSection(&g_ClientListLock);
    {
        PSLEEPWALKER_CONTROLLER_CLIENT client;
        for (client = g_ClientList; client != NULL; client = client->Next)
        {
            if (client->Pipe != INVALID_HANDLE_VALUE)
            {
                (void)CancelIoEx(client->Pipe, NULL);
                (void)DisconnectNamedPipe(client->Pipe);
            }
        }
    }
    LeaveCriticalSection(&g_ClientListLock);

    while (waitMs < 2000)
    {
        DWORD remaining;
        EnterCriticalSection(&g_ClientListLock);
        remaining = g_ClientCount;
        LeaveCriticalSection(&g_ClientListLock);
        if (remaining == 0)
        {
            break;
        }
        Sleep(50);
        waitMs += 50;
    }

    ControllerStopEtwSession();

    EnterCriticalSection(&g_DriverLock);
    if (g_DriverHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_DriverHandle);
        g_DriverHandle = INVALID_HANDLE_VALUE;
    }
    LeaveCriticalSection(&g_DriverLock);

    if (g_StopEvent != NULL)
    {
        CloseHandle(g_StopEvent);
        g_StopEvent = NULL;
    }

    ControllerLog("[*] SleepwlkrController: core stopped\n");

}

static DWORD WINAPI ControllerServiceControlHandlerEx(_In_ DWORD ControlCode, _In_ DWORD EventType, _In_ LPVOID EventData,
                                                      _In_ LPVOID Context)
{
    UNREFERENCED_PARAMETER(EventType);
    UNREFERENCED_PARAMETER(EventData);
    UNREFERENCED_PARAMETER(Context);

    if (ControlCode == SERVICE_CONTROL_STOP || ControlCode == SERVICE_CONTROL_SHUTDOWN)
    {
        ControllerLog("[*] SleepwlkrController: service control received code=%lu\n", ControlCode);
        ControllerUpdateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        if (g_StopEvent != NULL)
        {
            (void)SetEvent(g_StopEvent);
        }
        return NO_ERROR;
    }

    return ERROR_CALL_NOT_IMPLEMENTED;
}

static VOID WINAPI ControllerServiceMain(_In_ DWORD Argc, _In_reads_(Argc) LPWSTR *Argv)
{
    UNREFERENCED_PARAMETER(Argc);
    UNREFERENCED_PARAMETER(Argv);

    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatusHandle = RegisterServiceCtrlHandlerExW(SLEEPWALKER_CONTROLLER_SERVICE_NAMEW,
                                                          ControllerServiceControlHandlerEx, NULL);
    if (g_ServiceStatusHandle == NULL)
    {
        return;
    }
    ControllerLog("[*] SleepwlkrController: service main entered\n");

    ControllerUpdateServiceStatus(SERVICE_START_PENDING, NO_ERROR, 6000);
    if (!ControllerStartCore())
    {
        ControllerUpdateServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        ControllerStopCore();
        return;
    }

    ControllerUpdateServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);
    ControllerLog("[*] SleepwlkrController: service running\n");
    (void)WaitForSingleObject(g_StopEvent, INFINITE);

    ControllerUpdateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
    ControllerStopCore();
    ControllerUpdateServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

int __cdecl wmain(_In_ int argc, _In_reads_(argc) wchar_t **argv)
{
    SERVICE_TABLE_ENTRYW table[] = {{(LPWSTR)SLEEPWALKER_CONTROLLER_SERVICE_NAMEW, ControllerServiceMain},
                                    {NULL, NULL}};
    BOOL runAsConsole = FALSE;
    int i;

    for (i = 1; i < argc; ++i)
    {
        if (_wcsicmp(argv[i], L"--console") == 0)
        {
            runAsConsole = TRUE;
            break;
        }
    }

    if (runAsConsole)
    {
        ControllerLog("[*] SleepwlkrController: running in console mode.\n");
        if (!ControllerStartCore())
        {
            ControllerStopCore();
            return 1;
        }

        ControllerLog("[*] SleepwlkrController: running. Press Enter to stop.\n");
        (void)getchar();
        ControllerStopCore();
        return 0;
    }

    if (!StartServiceCtrlDispatcherW(table))
    {
        ControllerLog("[-] SleepwlkrController: StartServiceCtrlDispatcherW failed (%lu)\n", GetLastError());
        return 1;
    }

    return 0;
}
