#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "control.h"

#define SLEEPWALKER_POOL_TAG 'lrtS'
#define SLEEPWALKER_MAX_CLIENT_SUBSCRIPTIONS 64
#define SLEEPWALKER_MAX_CLIENT_QUEUE_DEPTH 1024
#define SLEEPWALKER_MAX_TOTAL_CLIENTS 256
#define SLEEPWALKER_MAX_TOTAL_QUEUED_EVENTS 16384
#define SLEEPWALKER_QUERY_IMAGE_WINDOW_100NS 10000000ULL
#define SLEEPWALKER_QUERY_IMAGE_MAX_PER_WINDOW 64
#define SLEEPWALKER_QUERY_IMAGE_MAX_INFLIGHT 8

typedef struct _SLEEPWALKER_SUBSCRIPTION
{
    UINT32 ProcessId;
    UINT32 StreamMask;
} SLEEPWALKER_SUBSCRIPTION;

typedef struct _SLEEPWALKER_EVENT_NODE
{
    LIST_ENTRY Link;
    SLEEPWALKER_EVENT_RECORD Record;
} SLEEPWALKER_EVENT_NODE, *PSLEEPWALKER_EVENT_NODE;

typedef struct _SLEEPWALKER_CLIENT
{
    LIST_ENTRY Link;
    LIST_ENTRY EventQueue;
    FAST_MUTEX Lock;
    UINT32 Sequence;
    UINT32 QueueDepth;
    UINT32 DroppedEvents;
    UINT32 SubscriptionCount;
    ULONGLONG QueryWindowStart100ns;
    UINT32 QueryWindowCount;
    volatile LONG RefCount;
    SLEEPWALKER_SUBSCRIPTION Subscriptions[SLEEPWALKER_MAX_CLIENT_SUBSCRIPTIONS];
} SLEEPWALKER_CLIENT, *PSLEEPWALKER_CLIENT;

typedef struct _SLEEPWALKER_FILE_CONTEXT
{
    PSLEEPWALKER_CLIENT Client;
} SLEEPWALKER_FILE_CONTEXT, *PSLEEPWALKER_FILE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(SLEEPWALKER_FILE_CONTEXT, SLEEPWALKERGetFileContext);

static WDFDEVICE g_ControlDevice = NULL;
static FAST_MUTEX g_ClientListLock;
static LIST_ENTRY g_ClientList;
static LONG g_ClientCount = 0;
static volatile LONG g_ControlInitialized = 0;
static volatile LONG g_ControlShutdown = 0;
static volatile LONG g_ControlQueueDropLogCounter = 0;
static volatile LONG g_ControlTotalQueuedEvents = 0;
static volatile LONG g_QueryImageInflight = 0;
static volatile LONG g_QueryImageThrottleCounter = 0;

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS *Process);

NTSYSAPI
NTSTATUS
NTAPI
SeLocateProcessImageName(_In_ PEPROCESS Process, _Out_ PUNICODE_STRING *pImageFileName);

static BOOLEAN SLEEPWALKERModeAllowed(_In_ WDFREQUEST Request)
{
    return (WdfRequestGetRequestorMode(Request) == UserMode);
}

static BOOLEAN SLEEPWALKERControlIsShutdown(VOID)
{
    return (InterlockedCompareExchange(&g_ControlShutdown, 0, 0) != 0);
}

static BOOLEAN SLEEPWALKERTryAcquireGlobalQueueSlot(VOID)
{
    LONG current;

    for (;;)
    {
        current = InterlockedCompareExchange(&g_ControlTotalQueuedEvents, 0, 0);
        if (current >= SLEEPWALKER_MAX_TOTAL_QUEUED_EVENTS)
        {
            return FALSE;
        }
        if (InterlockedCompareExchange(&g_ControlTotalQueuedEvents, current + 1, current) == current)
        {
            return TRUE;
        }
    }
}

static VOID SLEEPWALKERReleaseGlobalQueueSlot(VOID)
{
    LONG remaining;

    remaining = InterlockedDecrement(&g_ControlTotalQueuedEvents);
    if (remaining < 0)
    {
        InterlockedExchange(&g_ControlTotalQueuedEvents, 0);
    }
}

static BOOLEAN SLEEPWALKERClientConsumeQueryBudgetLocked(_Inout_ PSLEEPWALKER_CLIENT Client)
{
    ULONGLONG now;

    now = KeQueryInterruptTime();
    if (Client->QueryWindowStart100ns == 0 || now < Client->QueryWindowStart100ns ||
        (now - Client->QueryWindowStart100ns) >= SLEEPWALKER_QUERY_IMAGE_WINDOW_100NS)
    {
        Client->QueryWindowStart100ns = now;
        Client->QueryWindowCount = 1;
        return TRUE;
    }

    if (Client->QueryWindowCount >= SLEEPWALKER_QUERY_IMAGE_MAX_PER_WINDOW)
    {
        return FALSE;
    }

    Client->QueryWindowCount += 1;
    return TRUE;
}

static BOOLEAN SLEEPWALKERTryAcquireQueryInflightSlot(VOID)
{
    LONG current;

    for (;;)
    {
        current = InterlockedCompareExchange(&g_QueryImageInflight, 0, 0);
        if (current >= SLEEPWALKER_QUERY_IMAGE_MAX_INFLIGHT)
        {
            return FALSE;
        }
        if (InterlockedCompareExchange(&g_QueryImageInflight, current + 1, current) == current)
        {
            return TRUE;
        }
    }
}

static VOID SLEEPWALKERReleaseQueryInflightSlot(VOID)
{
    LONG remaining;

    remaining = InterlockedDecrement(&g_QueryImageInflight);
    if (remaining < 0)
    {
        InterlockedExchange(&g_QueryImageInflight, 0);
    }
}

static VOID SLEEPWALKERClientFreeQueuedEvents(_Inout_ PSLEEPWALKER_CLIENT Client)
{
    while (!IsListEmpty(&Client->EventQueue))
    {
        PLIST_ENTRY entry = RemoveHeadList(&Client->EventQueue);
        PSLEEPWALKER_EVENT_NODE node = CONTAINING_RECORD(entry, SLEEPWALKER_EVENT_NODE, Link);
        ExFreePoolWithTag(node, SLEEPWALKER_POOL_TAG);
        SLEEPWALKERReleaseGlobalQueueSlot();
    }
    Client->QueueDepth = 0;
}

static VOID SLEEPWALKERClientRelease(_Inout_ PSLEEPWALKER_CLIENT Client)
{
    if (InterlockedDecrement(&Client->RefCount) != 0)
    {
        return;
    }

    ExAcquireFastMutex(&Client->Lock);
    SLEEPWALKERClientFreeQueuedEvents(Client);
    ExReleaseFastMutex(&Client->Lock);
    ExFreePoolWithTag(Client, SLEEPWALKER_POOL_TAG);
}

static VOID SLEEPWALKERClientReference(_Inout_ PSLEEPWALKER_CLIENT Client)
{
    (void)InterlockedIncrement(&Client->RefCount);
}

static VOID SLEEPWALKERControlFlushAllClientState(VOID)
{
    PSLEEPWALKER_CLIENT snapshot[SLEEPWALKER_MAX_TOTAL_CLIENTS];
    UINT32 snapshotCount = 0;
    UINT32 i;
    PLIST_ENTRY e;

    ExAcquireFastMutex(&g_ClientListLock);
    for (e = g_ClientList.Flink; e != &g_ClientList; e = e->Flink)
    {
        PSLEEPWALKER_CLIENT c = CONTAINING_RECORD(e, SLEEPWALKER_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot))
        {
            break;
        }
        SLEEPWALKERClientReference(c);
        snapshot[snapshotCount++] = c;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i)
    {
        PSLEEPWALKER_CLIENT c = snapshot[i];
        ExAcquireFastMutex(&c->Lock);
        c->SubscriptionCount = 0;
        SLEEPWALKERClientFreeQueuedEvents(c);
        ExReleaseFastMutex(&c->Lock);
        SLEEPWALKERClientRelease(c);
    }
}

VOID SLEEPWALKERControlBeginShutdown(VOID)
{
    if (InterlockedExchange(&g_ControlShutdown, 1) == 0)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "SLEEPWALKER: control plane entering shutdown mode.\n");
    }
    SLEEPWALKERControlFlushAllClientState();
}

static PSLEEPWALKER_CLIENT SLEEPWALKERClientCreate(VOID)
{
    PSLEEPWALKER_CLIENT client;

    client = (PSLEEPWALKER_CLIENT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*client), SLEEPWALKER_POOL_TAG);
    if (client == NULL)
    {
        return NULL;
    }

    RtlZeroMemory(client, sizeof(*client));
    InitializeListHead(&client->EventQueue);
    ExInitializeFastMutex(&client->Lock);
    client->RefCount = 1;
    return client;
}

static BOOLEAN SLEEPWALKERClientMatchSubscriptionEither(_In_ PSLEEPWALKER_CLIENT Client, _In_ UINT32 PrimaryProcessId,
                                                        _In_ UINT32 SecondaryProcessId, _In_ UINT32 StreamMask)
{
    UINT32 i;

    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        UINT32 subscribedPid;
        UINT32 subscribedMask;

        subscribedPid = Client->Subscriptions[i].ProcessId;
        subscribedMask = Client->Subscriptions[i].StreamMask;
        if ((subscribedMask & StreamMask) == 0)
        {
            continue;
        }

        if (subscribedPid == PrimaryProcessId || (SecondaryProcessId != 0 && subscribedPid == SecondaryProcessId))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static VOID SLEEPWALKERClientEnqueueEvent(_Inout_ PSLEEPWALKER_CLIENT Client,
                                          _In_ const SLEEPWALKER_EVENT_RECORD *Source)
{
    PSLEEPWALKER_EVENT_NODE node;
    LONG dropLogCounter;

    if (Client->QueueDepth >= SLEEPWALKER_MAX_CLIENT_QUEUE_DEPTH)
    {
        Client->DroppedEvents += 1;
        dropLogCounter = InterlockedIncrement(&g_ControlQueueDropLogCounter);
        if (dropLogCounter == 1 || ((dropLogCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "SLEEPWALKER: queue drop (client depth cap=%lu) totalDrops=%lu clientDrops=%u queueDepth=%u.\n",
                       SLEEPWALKER_MAX_CLIENT_QUEUE_DEPTH, (ULONG)dropLogCounter, Client->DroppedEvents,
                       Client->QueueDepth);
        }
        return;
    }

    if (!SLEEPWALKERTryAcquireGlobalQueueSlot())
    {
        Client->DroppedEvents += 1;
        dropLogCounter = InterlockedIncrement(&g_ControlQueueDropLogCounter);
        if (dropLogCounter == 1 || ((dropLogCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "SLEEPWALKER: queue drop (global cap=%lu) totalDrops=%lu clientDrops=%u globalQueued=%ld.\n",
                       SLEEPWALKER_MAX_TOTAL_QUEUED_EVENTS, (ULONG)dropLogCounter, Client->DroppedEvents,
                       InterlockedCompareExchange(&g_ControlTotalQueuedEvents, 0, 0));
        }
        return;
    }

    node = (PSLEEPWALKER_EVENT_NODE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*node), SLEEPWALKER_POOL_TAG);
    if (node == NULL)
    {
        SLEEPWALKERReleaseGlobalQueueSlot();
        Client->DroppedEvents += 1;
        dropLogCounter = InterlockedIncrement(&g_ControlQueueDropLogCounter);
        if (dropLogCounter == 1 || ((dropLogCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "SLEEPWALKER: queue drop (alloc failure) totalDrops=%lu clientDrops=%u queueDepth=%u.\n",
                       (ULONG)dropLogCounter, Client->DroppedEvents, Client->QueueDepth);
        }
        return;
    }

    RtlZeroMemory(node, sizeof(*node));
    RtlCopyMemory(&node->Record, Source, sizeof(node->Record));
    InsertTailList(&Client->EventQueue, &node->Link);
    Client->QueueDepth += 1;
}

static VOID SLEEPWALKERPublishRecordToSubscribers(_In_ UINT32 PrimaryPid, _In_ UINT32 SecondaryPid,
                                                  _In_ UINT32 StreamMask, _In_ SLEEPWALKER_EVENT_RECORD *Record)
{
    PSLEEPWALKER_CLIENT snapshot[SLEEPWALKER_MAX_TOTAL_CLIENTS];
    UINT32 snapshotCount = 0;
    UINT32 i;
    PLIST_ENTRY e;

    if (InterlockedCompareExchange(&g_ControlInitialized, 0, 0) == 0)
    {
        return;
    }
    if (SLEEPWALKERControlIsShutdown())
    {
        return;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    for (e = g_ClientList.Flink; e != &g_ClientList; e = e->Flink)
    {
        PSLEEPWALKER_CLIENT c = CONTAINING_RECORD(e, SLEEPWALKER_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot))
        {
            break;
        }
        SLEEPWALKERClientReference(c);
        snapshot[snapshotCount++] = c;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i)
    {
        PSLEEPWALKER_CLIENT c = snapshot[i];
        ExAcquireFastMutex(&c->Lock);
        if (SLEEPWALKERClientMatchSubscriptionEither(c, PrimaryPid, SecondaryPid, StreamMask))
        {
            Record->Header.Sequence = ++c->Sequence;
            SLEEPWALKERClientEnqueueEvent(c, Record);
        }
        ExReleaseFastMutex(&c->Lock);
        SLEEPWALKERClientRelease(c);
    }
}

EVT_WDF_DEVICE_FILE_CREATE SLEEPWALKEREvtFileCreate;
EVT_WDF_FILE_CLEANUP SLEEPWALKEREvtFileCleanup;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL SLEEPWALKEREvtIoDeviceControl;

_Use_decl_annotations_ VOID SLEEPWALKEREvtFileCreate(WDFDEVICE Device, WDFREQUEST Request, WDFFILEOBJECT FileObject)
{
    PSLEEPWALKER_FILE_CONTEXT ctx;
    PSLEEPWALKER_CLIENT client;

    UNREFERENCED_PARAMETER(Device);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_STATE);
        return;
    }
    if (SLEEPWALKERControlIsShutdown())
    {
        WdfRequestComplete(Request, STATUS_DELETE_PENDING);
        return;
    }

    client = SLEEPWALKERClientCreate();
    if (client == NULL)
    {
        WdfRequestComplete(Request, STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    if (g_ClientCount >= SLEEPWALKER_MAX_TOTAL_CLIENTS)
    {
        ExReleaseFastMutex(&g_ClientListLock);
        SLEEPWALKERClientRelease(client);
        WdfRequestComplete(Request, STATUS_QUOTA_EXCEEDED);
        return;
    }
    InsertTailList(&g_ClientList, &client->Link);
    g_ClientCount += 1;
    ExReleaseFastMutex(&g_ClientListLock);

    ctx = SLEEPWALKERGetFileContext(FileObject);
    ctx->Client = client;
    WdfRequestComplete(Request, STATUS_SUCCESS);
}

_Use_decl_annotations_ VOID SLEEPWALKEREvtFileCleanup(WDFFILEOBJECT FileObject)
{
    PSLEEPWALKER_FILE_CONTEXT ctx = SLEEPWALKERGetFileContext(FileObject);
    PSLEEPWALKER_CLIENT client = ctx->Client;
    PLIST_ENTRY e;

    if (client == NULL)
    {
        return;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    for (e = g_ClientList.Flink; e != &g_ClientList; e = e->Flink)
    {
        if (CONTAINING_RECORD(e, SLEEPWALKER_CLIENT, Link) == client)
        {
            RemoveEntryList(e);
            if (g_ClientCount > 0)
            {
                g_ClientCount -= 1;
            }
            break;
        }
    }
    ExReleaseFastMutex(&g_ClientListLock);

    SLEEPWALKERClientRelease(client);
    ctx->Client = NULL;
}

static NTSTATUS SLEEPWALKERHandleSubscribeIoctl(_In_ PSLEEPWALKER_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PSLEEPWALKER_SUBSCRIBE_REQUEST in;
    size_t inSize;
    UINT32 i;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    if ((in->StreamMask & (SLEEPWALKER_STREAM_HANDLE | SLEEPWALKER_STREAM_MEMORY | SLEEPWALKER_STREAM_THREAD)) == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (SLEEPWALKERControlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireFastMutex(&Client->Lock);
    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (Client->Subscriptions[i].ProcessId == in->ProcessId)
        {
            Client->Subscriptions[i].StreamMask |= in->StreamMask;
            ExReleaseFastMutex(&Client->Lock);
            return STATUS_SUCCESS;
        }
    }

    if (Client->SubscriptionCount >= SLEEPWALKER_MAX_CLIENT_SUBSCRIPTIONS)
    {
        ExReleaseFastMutex(&Client->Lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Client->Subscriptions[Client->SubscriptionCount].ProcessId = in->ProcessId;
    Client->Subscriptions[Client->SubscriptionCount].StreamMask = in->StreamMask;
    Client->SubscriptionCount += 1;
    ExReleaseFastMutex(&Client->Lock);
    return STATUS_SUCCESS;
}

static NTSTATUS SLEEPWALKERHandleUnsubscribeIoctl(_In_ PSLEEPWALKER_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PSLEEPWALKER_UNSUBSCRIBE_REQUEST in;
    size_t inSize;
    UINT32 i;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);
    if (SLEEPWALKERControlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireFastMutex(&Client->Lock);
    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (Client->Subscriptions[i].ProcessId == in->ProcessId)
        {
            UINT32 tail = Client->SubscriptionCount - 1;
            if (i != tail)
            {
                Client->Subscriptions[i] = Client->Subscriptions[tail];
            }
            Client->SubscriptionCount -= 1;
            ExReleaseFastMutex(&Client->Lock);
            return STATUS_SUCCESS;
        }
    }
    ExReleaseFastMutex(&Client->Lock);
    return STATUS_NOT_FOUND;
}

static NTSTATUS SLEEPWALKERHandleGetStatsIoctl(_In_ PSLEEPWALKER_CLIENT Client, _In_ WDFREQUEST Request,
                                               _Out_ size_t *BytesOut)
{
    NTSTATUS status;
    PSLEEPWALKER_STATS_RESPONSE out;
    size_t outSize;

    *BytesOut = 0;

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID *)&out, &outSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (outSize < sizeof(*out))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(out, sizeof(*out));
    ExAcquireFastMutex(&Client->Lock);
    out->SubscriptionCount = Client->SubscriptionCount;
    out->QueueDepth = Client->QueueDepth;
    out->DroppedEvents = Client->DroppedEvents;
    ExReleaseFastMutex(&Client->Lock);

    *BytesOut = sizeof(*out);
    return STATUS_SUCCESS;
}

static NTSTATUS SLEEPWALKERHandleSetPidsIoctl(_In_ PSLEEPWALKER_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PSLEEPWALKER_SET_PIDS_REQUEST in;
    size_t inSize;
    UINT32 i;
    UINT32 streamMask;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    streamMask = in->StreamMask;
    if ((streamMask & (SLEEPWALKER_STREAM_HANDLE | SLEEPWALKER_STREAM_MEMORY | SLEEPWALKER_STREAM_THREAD)) == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (in->ProcessCount == 0 || in->ProcessCount > SLEEPWALKER_MAX_PID_LIST)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (SLEEPWALKERControlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireFastMutex(&Client->Lock);
    Client->SubscriptionCount = 0;

    for (i = 0; i < in->ProcessCount; ++i)
    {
        UINT32 pid = in->ProcessIds[i];
        UINT32 j;
        BOOLEAN seen = FALSE;

        if (pid == 0)
        {
            continue;
        }

        for (j = 0; j < Client->SubscriptionCount; ++j)
        {
            if (Client->Subscriptions[j].ProcessId == pid)
            {
                Client->Subscriptions[j].StreamMask |= streamMask;
                seen = TRUE;
                break;
            }
        }

        if (!seen && Client->SubscriptionCount < SLEEPWALKER_MAX_CLIENT_SUBSCRIPTIONS)
        {
            Client->Subscriptions[Client->SubscriptionCount].ProcessId = pid;
            Client->Subscriptions[Client->SubscriptionCount].StreamMask = streamMask;
            Client->SubscriptionCount += 1;
        }
    }

    ExReleaseFastMutex(&Client->Lock);

    return (Client->SubscriptionCount != 0) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

static NTSTATUS SLEEPWALKERResolveProcessImagePath(_In_ UINT32 ProcessId, _Out_writes_z_(OutputChars) PWSTR Output,
                                                   _In_ size_t OutputChars)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING imageName = NULL;

    if (Output == NULL || OutputChars == 0 || ProcessId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    Output[0] = L'\0';

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = SeLocateProcessImageName(process, &imageName);
    ObDereferenceObject(process);
    process = NULL;
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (imageName == NULL || imageName->Buffer == NULL || imageName->Length == 0)
    {
        if (imageName != NULL)
        {
            ExFreePool(imageName);
        }
        return STATUS_NOT_FOUND;
    }

    status = RtlStringCchCopyNW(Output, OutputChars, imageName->Buffer, imageName->Length / sizeof(WCHAR));
    ExFreePool(imageName);
    if (status == STATUS_BUFFER_OVERFLOW)
    {
        return STATUS_SUCCESS;
    }
    return status;
}

static NTSTATUS SLEEPWALKERHandleQueryProcessImageIoctl(_In_ PSLEEPWALKER_CLIENT Client, _In_ WDFREQUEST Request,
                                                        _Out_ size_t *BytesOut)
{
    NTSTATUS status;
    PSLEEPWALKER_QUERY_PROCESS_IMAGE_REQUEST in;
    PSLEEPWALKER_QUERY_PROCESS_IMAGE_RESPONSE out;
    size_t inSize;
    size_t outSize;

    *BytesOut = 0;
    if (SLEEPWALKERControlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireFastMutex(&Client->Lock);
    if (!SLEEPWALKERClientConsumeQueryBudgetLocked(Client))
    {
        LONG throttleCounter = InterlockedIncrement(&g_QueryImageThrottleCounter);
        ExReleaseFastMutex(&Client->Lock);
        if (throttleCounter == 1 || ((throttleCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "SLEEPWALKER: throttling IOCTL_SLEEPWALKER_QUERY_PROCESS_IMAGE total=%lu.\n",
                       (ULONG)throttleCounter);
        }
        return STATUS_QUOTA_EXCEEDED;
    }
    ExReleaseFastMutex(&Client->Lock);

    if (!SLEEPWALKERTryAcquireQueryInflightSlot())
    {
        InterlockedIncrement(&g_QueryImageThrottleCounter);
        return STATUS_DEVICE_BUSY;
    }

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        SLEEPWALKERReleaseQueryInflightSlot();
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID *)&out, &outSize);
    if (!NT_SUCCESS(status))
    {
        SLEEPWALKERReleaseQueryInflightSlot();
        return status;
    }
    if (outSize < sizeof(*out))
    {
        SLEEPWALKERReleaseQueryInflightSlot();
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(out, sizeof(*out));
    out->ProcessId = in->ProcessId;
    out->Status = SLEEPWALKERResolveProcessImagePath(in->ProcessId, out->ImagePath, RTL_NUMBER_OF(out->ImagePath));

    SLEEPWALKERReleaseQueryInflightSlot();
    *BytesOut = sizeof(*out);
    return STATUS_SUCCESS;
}

static NTSTATUS SLEEPWALKERHandleGetEventIoctl(_In_ PSLEEPWALKER_CLIENT Client, _In_ WDFREQUEST Request,
                                               _Out_ size_t *BytesOut)
{
    NTSTATUS status;
    PSLEEPWALKER_EVENT_RECORD out;
    size_t outSize;

    *BytesOut = 0;
    if (SLEEPWALKERControlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }
    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID *)&out, &outSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (outSize < sizeof(*out))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    ExAcquireFastMutex(&Client->Lock);
    if (IsListEmpty(&Client->EventQueue))
    {
        ExReleaseFastMutex(&Client->Lock);
        return STATUS_NO_MORE_ENTRIES;
    }

    {
        PLIST_ENTRY entry = RemoveHeadList(&Client->EventQueue);
        PSLEEPWALKER_EVENT_NODE node = CONTAINING_RECORD(entry, SLEEPWALKER_EVENT_NODE, Link);
        RtlCopyMemory(out, &node->Record, sizeof(*out));
        if (Client->QueueDepth > 0)
        {
            Client->QueueDepth -= 1;
        }
        ExFreePoolWithTag(node, SLEEPWALKER_POOL_TAG);
        SLEEPWALKERReleaseGlobalQueueSlot();
    }
    ExReleaseFastMutex(&Client->Lock);

    *BytesOut = sizeof(*out);
    return STATUS_SUCCESS;
}

static NTSTATUS SLEEPWALKERHandleSetShutdownModeIoctl(_In_ PSLEEPWALKER_CLIENT Client)
{
    UNREFERENCED_PARAMETER(Client);
    SLEEPWALKERControlBeginShutdown();
    return STATUS_SUCCESS;
}

_Use_decl_annotations_ VOID SLEEPWALKEREvtIoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength,
                                                          size_t InputBufferLength, ULONG IoControlCode)
{
    WDFOBJECT fileObj;
    PSLEEPWALKER_FILE_CONTEXT ctx;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t bytesOut = 0;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_STATE);
        return;
    }

    if (!SLEEPWALKERModeAllowed(Request))
    {
        WdfRequestComplete(Request, STATUS_ACCESS_DENIED);
        return;
    }

    fileObj = WdfRequestGetFileObject(Request);
    if (fileObj == NULL)
    {
        WdfRequestComplete(Request, STATUS_INVALID_HANDLE);
        return;
    }

    ctx = SLEEPWALKERGetFileContext(fileObj);
    if (ctx->Client == NULL)
    {
        WdfRequestComplete(Request, STATUS_INVALID_HANDLE);
        return;
    }

    if (SLEEPWALKERControlIsShutdown() && IoControlCode != IOCTL_SLEEPWALKER_GET_STATS &&
        IoControlCode != IOCTL_SLEEPWALKER_SET_SHUTDOWN_MODE)
    {
        WdfRequestComplete(Request, STATUS_DEVICE_NOT_READY);
        return;
    }

    switch (IoControlCode)
    {
    case IOCTL_SLEEPWALKER_SUBSCRIBE:
        status = SLEEPWALKERHandleSubscribeIoctl(ctx->Client, Request);
        break;
    case IOCTL_SLEEPWALKER_UNSUBSCRIBE:
        status = SLEEPWALKERHandleUnsubscribeIoctl(ctx->Client, Request);
        break;
    case IOCTL_SLEEPWALKER_GET_EVENT:
        status = SLEEPWALKERHandleGetEventIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_SLEEPWALKER_GET_STATS:
        status = SLEEPWALKERHandleGetStatsIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_SLEEPWALKER_SET_PIDS:
        status = SLEEPWALKERHandleSetPidsIoctl(ctx->Client, Request);
        break;
    case IOCTL_SLEEPWALKER_QUERY_PROCESS_IMAGE:
        status = SLEEPWALKERHandleQueryProcessImageIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_SLEEPWALKER_SET_SHUTDOWN_MODE:
        status = SLEEPWALKERHandleSetShutdownModeIoctl(ctx->Client);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, bytesOut);
}

NTSTATUS
SLEEPWALKERControlInitialize(_In_ WDFDRIVER Driver)
{
    NTSTATUS status;
    WDFDEVICE device;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_OBJECT_ATTRIBUTES attrs;
    WDF_FILEOBJECT_CONFIG fileConfig;
    PWDFDEVICE_INIT devInit;
    UNICODE_STRING deviceName;
    UNICODE_STRING symlink;
    UNICODE_STRING globalSymlink;
    UNICODE_STRING sddl;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (InterlockedCompareExchange(&g_ControlInitialized, 1, 0) != 0)
    {
        return STATUS_SUCCESS;
    }

    ExInitializeFastMutex(&g_ClientListLock);
    InitializeListHead(&g_ClientList);
    g_ClientCount = 0;
    InterlockedExchange(&g_ControlShutdown, 0);
    InterlockedExchange(&g_ControlQueueDropLogCounter, 0);
    InterlockedExchange(&g_ControlTotalQueuedEvents, 0);
    InterlockedExchange(&g_QueryImageInflight, 0);
    InterlockedExchange(&g_QueryImageThrottleCounter, 0);

    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    devInit = WdfControlDeviceInitAllocate(Driver, &sddl);
    if (devInit == NULL)
    {
        InterlockedExchange(&g_ControlInitialized, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetDeviceType(devInit, FILE_DEVICE_SLEEPWALKER);
    WdfDeviceInitSetExclusive(devInit, FALSE);

    RtlInitUnicodeString(&deviceName, L"\\Device\\SleepwalkerCtl");
    status = WdfDeviceInitAssignName(devInit, &deviceName);
    if (!NT_SUCCESS(status))
    {
        WdfDeviceInitFree(devInit);
        InterlockedExchange(&g_ControlInitialized, 0);
        return status;
    }

    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, SLEEPWALKEREvtFileCreate, SLEEPWALKEREvtFileCleanup, WDF_NO_EVENT_CALLBACK);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs, SLEEPWALKER_FILE_CONTEXT);
    attrs.ExecutionLevel = WdfExecutionLevelPassive;
    WdfDeviceInitSetFileObjectConfig(devInit, &fileConfig, &attrs);

    WDF_OBJECT_ATTRIBUTES_INIT(&attrs);
    attrs.ExecutionLevel = WdfExecutionLevelPassive;
    status = WdfDeviceCreate(&devInit, &attrs, &device);
    if (!NT_SUCCESS(status))
    {
        InterlockedExchange(&g_ControlInitialized, 0);
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = SLEEPWALKEREvtIoDeviceControl;
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status))
    {
        WdfObjectDelete(device);
        InterlockedExchange(&g_ControlInitialized, 0);
        return status;
    }

    RtlInitUnicodeString(&globalSymlink, L"\\DosDevices\\Global\\SleepwalkerCtl");
    status = WdfDeviceCreateSymbolicLink(device, &globalSymlink);
    if (!NT_SUCCESS(status))
    {
        WdfObjectDelete(device);
        InterlockedExchange(&g_ControlInitialized, 0);
        return status;
    }

    // Best-effort legacy link for callers using \\.\SleepwalkerCtl.
    RtlInitUnicodeString(&symlink, L"\\DosDevices\\SleepwalkerCtl");
    (void)WdfDeviceCreateSymbolicLink(device, &symlink);

    g_ControlDevice = device;
    WdfControlFinishInitializing(device);
    return STATUS_SUCCESS;
}

VOID SLEEPWALKERControlUninitialize(VOID)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }

    if (InterlockedExchange(&g_ControlInitialized, 0) == 0)
    {
        return;
    }

    SLEEPWALKERControlBeginShutdown();
    if (g_ControlDevice != NULL)
    {
        WdfObjectDelete(g_ControlDevice);
        g_ControlDevice = NULL;
    }
    InterlockedExchange(&g_ControlTotalQueuedEvents, 0);
    InterlockedExchange(&g_QueryImageInflight, 0);
    g_ClientCount = 0;
}

VOID SLEEPWALKERControlPublishHandleEvent(_In_ UINT64 CallerPid, _In_ UINT64 TargetPid, _In_ UINT32 DesiredAccess,
                                          _In_ UINT32 ClassId, _In_ UINT64 OriginAddress, _In_ UINT32 OriginProtect,
                                          _In_ UINT32 Flags, _In_opt_z_ PCWSTR OriginPath, _In_ UINT32 FrameCount,
                                          _In_reads_opt_(FrameCount) PVOID const *Frames, _In_ INT32 StatusOpenProcess,
                                          _In_ INT32 StatusBasicInfo, _In_ INT32 StatusSectionName,
                                          _In_ UINT64 DeepAllocationBase, _In_ UINT64 DeepRegionSize,
                                          _In_ UINT32 DeepRegionProtect, _In_ UINT32 DeepRegionState,
                                          _In_ UINT32 DeepRegionType, _In_ UINT32 DeepSampleSize,
                                          _In_reads_bytes_opt_(DeepSampleSize) const UCHAR *DeepSample)
{
    SLEEPWALKER_EVENT_RECORD record;
    UINT32 stream = SLEEPWALKER_STREAM_HANDLE;
    UINT32 i;
    UINT32 safeCount;

    if (KeGetCurrentIrql() > APC_LEVEL)
    {
        return;
    }

    RtlZeroMemory(&record, sizeof(record));
    record.Header.Size = sizeof(record);
    record.Header.Type = SleepwalkerEventTypeHandle;
    record.Header.TimestampQpc = KeQueryPerformanceCounter(NULL).QuadPart;

    if ((Flags & SLEEPWALKER_HANDLE_FLAG_MEMORY_RELATED) != 0)
    {
        stream |= SLEEPWALKER_STREAM_MEMORY;
    }
    record.Header.StreamMask = stream;

    record.Data.Handle.CallerPid = CallerPid;
    record.Data.Handle.TargetPid = TargetPid;
    record.Data.Handle.DesiredAccess = DesiredAccess;
    record.Data.Handle.ClassId = ClassId;
    record.Data.Handle.OriginAddress = OriginAddress;
    record.Data.Handle.OriginProtect = OriginProtect;
    record.Data.Handle.Flags = Flags;
    record.Data.Handle.StatusOpenProcess = StatusOpenProcess;
    record.Data.Handle.StatusBasicInfo = StatusBasicInfo;
    record.Data.Handle.StatusSectionName = StatusSectionName;
    record.Data.Handle.DeepAllocationBase = DeepAllocationBase;
    record.Data.Handle.DeepRegionSize = DeepRegionSize;
    record.Data.Handle.DeepRegionProtect = DeepRegionProtect;
    record.Data.Handle.DeepRegionState = DeepRegionState;
    record.Data.Handle.DeepRegionType = DeepRegionType;

    if (DeepSample != NULL && DeepSampleSize != 0)
    {
        UINT32 safeDeepBytes =
            (DeepSampleSize > SLEEPWALKER_MAX_DEEP_SAMPLE_BYTES) ? SLEEPWALKER_MAX_DEEP_SAMPLE_BYTES : DeepSampleSize;
        record.Data.Handle.DeepSampleSize = safeDeepBytes;
        RtlCopyMemory(record.Data.Handle.DeepSample, DeepSample, safeDeepBytes);
    }

    safeCount = (FrameCount > SLEEPWALKER_MAX_EVENT_FRAMES) ? SLEEPWALKER_MAX_EVENT_FRAMES : FrameCount;
    record.Data.Handle.FrameCount = safeCount;
    if (Frames != NULL)
    {
        for (i = 0; i < safeCount; ++i)
        {
            record.Data.Handle.Frames[i] = (UINT64)(ULONG_PTR)Frames[i];
        }
    }

    if (OriginPath != NULL)
    {
        (void)RtlStringCchCopyW(record.Data.Handle.OriginPath, RTL_NUMBER_OF(record.Data.Handle.OriginPath),
                                OriginPath);
    }

    SLEEPWALKERPublishRecordToSubscribers(
        (UINT32)CallerPid, ((UINT32)TargetPid != (UINT32)CallerPid) ? (UINT32)TargetPid : 0, stream, &record);
}

VOID SLEEPWALKERControlPublishThreadEvent(_In_ UINT64 ProcessId, _In_ UINT64 ThreadId, _In_ UINT64 CreatorPid,
                                          _In_ UINT64 StartAddress, _In_ UINT64 ImageBase, _In_ UINT64 ImageSize,
                                          _In_ UINT32 Flags, _In_ UINT32 FrameCount,
                                          _In_reads_opt_(FrameCount) PVOID const *Frames)
{
    SLEEPWALKER_EVENT_RECORD record;
    UINT32 i;
    UINT32 safeCount;

    if (KeGetCurrentIrql() > APC_LEVEL)
    {
        return;
    }

    RtlZeroMemory(&record, sizeof(record));
    record.Header.Size = sizeof(record);
    record.Header.Type = SleepwalkerEventTypeThread;
    record.Header.StreamMask = SLEEPWALKER_STREAM_THREAD;
    record.Header.TimestampQpc = KeQueryPerformanceCounter(NULL).QuadPart;

    record.Data.Thread.ProcessId = ProcessId;
    record.Data.Thread.ThreadId = ThreadId;
    record.Data.Thread.CreatorPid = CreatorPid;
    record.Data.Thread.StartAddress = StartAddress;
    record.Data.Thread.ImageBase = ImageBase;
    record.Data.Thread.ImageSize = ImageSize;
    record.Data.Thread.Flags = Flags;

    safeCount = (FrameCount > SLEEPWALKER_MAX_EVENT_FRAMES) ? SLEEPWALKER_MAX_EVENT_FRAMES : FrameCount;
    record.Data.Thread.FrameCount = safeCount;
    if (Frames != NULL)
    {
        for (i = 0; i < safeCount; ++i)
        {
            record.Data.Thread.Frames[i] = (UINT64)(ULONG_PTR)Frames[i];
        }
    }

    SLEEPWALKERPublishRecordToSubscribers((UINT32)ProcessId,
                                          ((UINT32)CreatorPid != (UINT32)ProcessId) ? (UINT32)CreatorPid : 0,
                                          SLEEPWALKER_STREAM_THREAD, &record);
}

BOOLEAN
SLEEPWALKERControlSelfCheck(VOID)
{
    PDEVICE_OBJECT deviceObject;

    if (InterlockedCompareExchange(&g_ControlInitialized, 0, 0) == 0)
    {
        return FALSE;
    }
    if (g_ControlDevice == NULL)
    {
        return FALSE;
    }

    deviceObject = WdfDeviceWdmGetDeviceObject(g_ControlDevice);
    if (deviceObject == NULL)
    {
        return FALSE;
    }

    if ((deviceObject->Flags & DO_DEVICE_INITIALIZING) != 0)
    {
        return FALSE;
    }

    return TRUE;
}
