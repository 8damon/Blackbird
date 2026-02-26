#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "control.h"

#define STINGER_POOL_TAG 'lrtS'
#define STINGER_MAX_CLIENT_SUBSCRIPTIONS 64
#define STINGER_MAX_CLIENT_QUEUE_DEPTH 1024
#define STINGER_MAX_TOTAL_CLIENTS 256

typedef struct _STINGER_SUBSCRIPTION {
    UINT32 ProcessId;
    UINT32 StreamMask;
} STINGER_SUBSCRIPTION;

typedef struct _STINGER_EVENT_NODE {
    LIST_ENTRY Link;
    STINGER_EVENT_RECORD Record;
} STINGER_EVENT_NODE, *PSTINGER_EVENT_NODE;

typedef struct _STINGER_CLIENT {
    LIST_ENTRY Link;
    LIST_ENTRY EventQueue;
    FAST_MUTEX Lock;
    UINT32 Sequence;
    UINT32 QueueDepth;
    UINT32 DroppedEvents;
    UINT32 SubscriptionCount;
    volatile LONG RefCount;
    STINGER_SUBSCRIPTION Subscriptions[STINGER_MAX_CLIENT_SUBSCRIPTIONS];
} STINGER_CLIENT, *PSTINGER_CLIENT;

typedef struct _STINGER_FILE_CONTEXT {
    PSTINGER_CLIENT Client;
} STINGER_FILE_CONTEXT, *PSTINGER_FILE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(STINGER_FILE_CONTEXT, STINGERGetFileContext);

static WDFDEVICE g_ControlDevice = NULL;
static FAST_MUTEX g_ClientListLock;
static LIST_ENTRY g_ClientList;
static LONG g_ClientCount = 0;
static volatile LONG g_ControlInitialized = 0;
static volatile LONG g_ControlQueueDropLogCounter = 0;

static
BOOLEAN
STINGERModeAllowed(
    _In_ WDFREQUEST Request
)
{
    return (WdfRequestGetRequestorMode(Request) == UserMode);
}

static
VOID
STINGERClientFreeQueuedEvents(
    _Inout_ PSTINGER_CLIENT Client
)
{
    while (!IsListEmpty(&Client->EventQueue)) {
        PLIST_ENTRY entry = RemoveHeadList(&Client->EventQueue);
        PSTINGER_EVENT_NODE node = CONTAINING_RECORD(entry, STINGER_EVENT_NODE, Link);
        ExFreePoolWithTag(node, STINGER_POOL_TAG);
    }
    Client->QueueDepth = 0;
}

static
VOID
STINGERClientRelease(
    _Inout_ PSTINGER_CLIENT Client
)
{
    if (InterlockedDecrement(&Client->RefCount) != 0) {
        return;
    }

    ExAcquireFastMutex(&Client->Lock);
    STINGERClientFreeQueuedEvents(Client);
    ExReleaseFastMutex(&Client->Lock);
    ExFreePoolWithTag(Client, STINGER_POOL_TAG);
}

static
VOID
STINGERClientReference(
    _Inout_ PSTINGER_CLIENT Client
)
{
    (void)InterlockedIncrement(&Client->RefCount);
}

static
PSTINGER_CLIENT
STINGERClientCreate(
    VOID
)
{
    PSTINGER_CLIENT client;

    client = (PSTINGER_CLIENT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*client), STINGER_POOL_TAG);
    if (client == NULL) {
        return NULL;
    }

    RtlZeroMemory(client, sizeof(*client));
    InitializeListHead(&client->EventQueue);
    ExInitializeFastMutex(&client->Lock);
    client->RefCount = 1;
    return client;
}

static
BOOLEAN
STINGERClientMatchSubscription(
    _In_ PSTINGER_CLIENT Client,
    _In_ UINT32 ProcessId,
    _In_ UINT32 StreamMask
)
{
    UINT32 i;

    for (i = 0; i < Client->SubscriptionCount; ++i) {
        if (Client->Subscriptions[i].ProcessId == ProcessId &&
            (Client->Subscriptions[i].StreamMask & StreamMask) != 0) {
            return TRUE;
        }
    }

    return FALSE;
}

static
VOID
STINGERClientEnqueueEvent(
    _Inout_ PSTINGER_CLIENT Client,
    _In_ const STINGER_EVENT_RECORD* Source
)
{
    PSTINGER_EVENT_NODE node;
    LONG dropLogCounter;

    node = (PSTINGER_EVENT_NODE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*node), STINGER_POOL_TAG);
    if (node == NULL) {
        Client->DroppedEvents += 1;
        dropLogCounter = InterlockedIncrement(&g_ControlQueueDropLogCounter);
        if (dropLogCounter == 1 || ((dropLogCounter & 0xFF) == 0)) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "STINGER: queue drop (alloc failure) totalDrops=%lu clientDrops=%u queueDepth=%u.\n",
                (ULONG)dropLogCounter,
                Client->DroppedEvents,
                Client->QueueDepth
            );
        }
        return;
    }

    RtlZeroMemory(node, sizeof(*node));
    RtlCopyMemory(&node->Record, Source, sizeof(node->Record));

    if (Client->QueueDepth >= STINGER_MAX_CLIENT_QUEUE_DEPTH) {
        PLIST_ENTRY oldEntry = RemoveHeadList(&Client->EventQueue);
        PSTINGER_EVENT_NODE oldNode = CONTAINING_RECORD(oldEntry, STINGER_EVENT_NODE, Link);
        ExFreePoolWithTag(oldNode, STINGER_POOL_TAG);
        Client->QueueDepth -= 1;
        Client->DroppedEvents += 1;
        dropLogCounter = InterlockedIncrement(&g_ControlQueueDropLogCounter);
        if (dropLogCounter == 1 || ((dropLogCounter & 0xFF) == 0)) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "STINGER: queue drop (depth cap=%lu) totalDrops=%lu clientDrops=%u queueDepth=%u.\n",
                STINGER_MAX_CLIENT_QUEUE_DEPTH,
                (ULONG)dropLogCounter,
                Client->DroppedEvents,
                Client->QueueDepth
            );
        }
    }

    InsertTailList(&Client->EventQueue, &node->Link);
    Client->QueueDepth += 1;
}

static
VOID
STINGERPublishRecordToSubscribers(
    _In_ UINT32 MatchPid,
    _In_ UINT32 StreamMask,
    _In_ STINGER_EVENT_RECORD* Record
)
{
    PSTINGER_CLIENT snapshot[STINGER_MAX_TOTAL_CLIENTS];
    UINT32 snapshotCount = 0;
    UINT32 i;
    PLIST_ENTRY e;

    if (InterlockedCompareExchange(&g_ControlInitialized, 0, 0) == 0) {
        return;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    for (e = g_ClientList.Flink; e != &g_ClientList; e = e->Flink) {
        PSTINGER_CLIENT c = CONTAINING_RECORD(e, STINGER_CLIENT, Link);
        if (snapshotCount >= RTL_NUMBER_OF(snapshot)) {
            break;
        }
        STINGERClientReference(c);
        snapshot[snapshotCount++] = c;
    }
    ExReleaseFastMutex(&g_ClientListLock);

    for (i = 0; i < snapshotCount; ++i) {
        PSTINGER_CLIENT c = snapshot[i];
        ExAcquireFastMutex(&c->Lock);
        if (STINGERClientMatchSubscription(c, MatchPid, StreamMask)) {
            Record->Header.Sequence = ++c->Sequence;
            STINGERClientEnqueueEvent(c, Record);
        }
        ExReleaseFastMutex(&c->Lock);
        STINGERClientRelease(c);
    }
}

EVT_WDF_DEVICE_FILE_CREATE STINGEREvtFileCreate;
EVT_WDF_FILE_CLEANUP STINGEREvtFileCleanup;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL STINGEREvtIoDeviceControl;

_Use_decl_annotations_
VOID
STINGEREvtFileCreate(
    WDFDEVICE Device,
    WDFREQUEST Request,
    WDFFILEOBJECT FileObject
)
{
    PSTINGER_FILE_CONTEXT ctx;
    PSTINGER_CLIENT client;

    UNREFERENCED_PARAMETER(Device);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_STATE);
        return;
    }

    client = STINGERClientCreate();
    if (client == NULL) {
        WdfRequestComplete(Request, STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    if (g_ClientCount >= STINGER_MAX_TOTAL_CLIENTS) {
        ExReleaseFastMutex(&g_ClientListLock);
        STINGERClientRelease(client);
        WdfRequestComplete(Request, STATUS_QUOTA_EXCEEDED);
        return;
    }
    InsertTailList(&g_ClientList, &client->Link);
    g_ClientCount += 1;
    ExReleaseFastMutex(&g_ClientListLock);

    ctx = STINGERGetFileContext(FileObject);
    ctx->Client = client;
    WdfRequestComplete(Request, STATUS_SUCCESS);
}

_Use_decl_annotations_
VOID
STINGEREvtFileCleanup(
    WDFFILEOBJECT FileObject
)
{
    PSTINGER_FILE_CONTEXT ctx = STINGERGetFileContext(FileObject);
    PSTINGER_CLIENT client = ctx->Client;
    PLIST_ENTRY e;

    if (client == NULL) {
        return;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    ExAcquireFastMutex(&g_ClientListLock);
    for (e = g_ClientList.Flink; e != &g_ClientList; e = e->Flink) {
        if (CONTAINING_RECORD(e, STINGER_CLIENT, Link) == client) {
            RemoveEntryList(e);
            if (g_ClientCount > 0) {
                g_ClientCount -= 1;
            }
            break;
        }
    }
    ExReleaseFastMutex(&g_ClientListLock);

    STINGERClientRelease(client);
    ctx->Client = NULL;
}

static
NTSTATUS
STINGERHandleSubscribeIoctl(
    _In_ PSTINGER_CLIENT Client,
    _In_ WDFREQUEST Request
)
{
    NTSTATUS status;
    PSTINGER_SUBSCRIBE_REQUEST in;
    size_t inSize;
    UINT32 i;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID*)&in, &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    if ((in->StreamMask & (STINGER_STREAM_HANDLE | STINGER_STREAM_MEMORY | STINGER_STREAM_THREAD)) == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&Client->Lock);
    for (i = 0; i < Client->SubscriptionCount; ++i) {
        if (Client->Subscriptions[i].ProcessId == in->ProcessId) {
            Client->Subscriptions[i].StreamMask |= in->StreamMask;
            ExReleaseFastMutex(&Client->Lock);
            return STATUS_SUCCESS;
        }
    }

    if (Client->SubscriptionCount >= STINGER_MAX_CLIENT_SUBSCRIPTIONS) {
        ExReleaseFastMutex(&Client->Lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Client->Subscriptions[Client->SubscriptionCount].ProcessId = in->ProcessId;
    Client->Subscriptions[Client->SubscriptionCount].StreamMask = in->StreamMask;
    Client->SubscriptionCount += 1;
    ExReleaseFastMutex(&Client->Lock);
    return STATUS_SUCCESS;
}

static
NTSTATUS
STINGERHandleUnsubscribeIoctl(
    _In_ PSTINGER_CLIENT Client,
    _In_ WDFREQUEST Request
)
{
    NTSTATUS status;
    PSTINGER_UNSUBSCRIBE_REQUEST in;
    size_t inSize;
    UINT32 i;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID*)&in, &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    ExAcquireFastMutex(&Client->Lock);
    for (i = 0; i < Client->SubscriptionCount; ++i) {
        if (Client->Subscriptions[i].ProcessId == in->ProcessId) {
            UINT32 tail = Client->SubscriptionCount - 1;
            if (i != tail) {
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

static
NTSTATUS
STINGERHandleGetStatsIoctl(
    _In_ PSTINGER_CLIENT Client,
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesOut
)
{
    NTSTATUS status;
    PSTINGER_STATS_RESPONSE out;
    size_t outSize;

    *BytesOut = 0;

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID*)&out, &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (outSize < sizeof(*out)) {
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

static
NTSTATUS
STINGERHandleSetPidsIoctl(
    _In_ PSTINGER_CLIENT Client,
    _In_ WDFREQUEST Request
)
{
    NTSTATUS status;
    PSTINGER_SET_PIDS_REQUEST in;
    size_t inSize;
    UINT32 i;
    UINT32 streamMask;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID*)&in, &inSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    streamMask = in->StreamMask;
    if ((streamMask & (STINGER_STREAM_HANDLE | STINGER_STREAM_MEMORY | STINGER_STREAM_THREAD)) == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (in->ProcessCount == 0 || in->ProcessCount > STINGER_MAX_PID_LIST) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&Client->Lock);
    Client->SubscriptionCount = 0;

    for (i = 0; i < in->ProcessCount; ++i) {
        UINT32 pid = in->ProcessIds[i];
        UINT32 j;
        BOOLEAN seen = FALSE;

        if (pid == 0) {
            continue;
        }

        for (j = 0; j < Client->SubscriptionCount; ++j) {
            if (Client->Subscriptions[j].ProcessId == pid) {
                Client->Subscriptions[j].StreamMask |= streamMask;
                seen = TRUE;
                break;
            }
        }

        if (!seen && Client->SubscriptionCount < STINGER_MAX_CLIENT_SUBSCRIPTIONS) {
            Client->Subscriptions[Client->SubscriptionCount].ProcessId = pid;
            Client->Subscriptions[Client->SubscriptionCount].StreamMask = streamMask;
            Client->SubscriptionCount += 1;
        }
    }

    ExReleaseFastMutex(&Client->Lock);

    return (Client->SubscriptionCount != 0) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

static
NTSTATUS
STINGERHandleGetEventIoctl(
    _In_ PSTINGER_CLIENT Client,
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesOut
)
{
    NTSTATUS status;
    PSTINGER_EVENT_RECORD out;
    size_t outSize;

    *BytesOut = 0;
    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID*)&out, &outSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (outSize < sizeof(*out)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    ExAcquireFastMutex(&Client->Lock);
    if (IsListEmpty(&Client->EventQueue)) {
        ExReleaseFastMutex(&Client->Lock);
        return STATUS_NO_MORE_ENTRIES;
    }

    {
        PLIST_ENTRY entry = RemoveHeadList(&Client->EventQueue);
        PSTINGER_EVENT_NODE node = CONTAINING_RECORD(entry, STINGER_EVENT_NODE, Link);
        RtlCopyMemory(out, &node->Record, sizeof(*out));
        if (Client->QueueDepth > 0) {
            Client->QueueDepth -= 1;
        }
        ExFreePoolWithTag(node, STINGER_POOL_TAG);
    }
    ExReleaseFastMutex(&Client->Lock);

    *BytesOut = sizeof(*out);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
STINGEREvtIoDeviceControl(
    WDFQUEUE Queue,
    WDFREQUEST Request,
    size_t OutputBufferLength,
    size_t InputBufferLength,
    ULONG IoControlCode
)
{
    WDFOBJECT fileObj;
    PSTINGER_FILE_CONTEXT ctx;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t bytesOut = 0;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_STATE);
        return;
    }

    if (!STINGERModeAllowed(Request)) {
        WdfRequestComplete(Request, STATUS_ACCESS_DENIED);
        return;
    }

    fileObj = WdfRequestGetFileObject(Request);
    if (fileObj == NULL) {
        WdfRequestComplete(Request, STATUS_INVALID_HANDLE);
        return;
    }

    ctx = STINGERGetFileContext(fileObj);
    if (ctx->Client == NULL) {
        WdfRequestComplete(Request, STATUS_INVALID_HANDLE);
        return;
    }

    switch (IoControlCode) {
    case IOCTL_STINGER_SUBSCRIBE:
        status = STINGERHandleSubscribeIoctl(ctx->Client, Request);
        break;
    case IOCTL_STINGER_UNSUBSCRIBE:
        status = STINGERHandleUnsubscribeIoctl(ctx->Client, Request);
        break;
    case IOCTL_STINGER_GET_EVENT:
        status = STINGERHandleGetEventIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_STINGER_GET_STATS:
        status = STINGERHandleGetStatsIoctl(ctx->Client, Request, &bytesOut);
        break;
    case IOCTL_STINGER_SET_PIDS:
        status = STINGERHandleSetPidsIoctl(ctx->Client, Request);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, bytesOut);
}

NTSTATUS
STINGERControlInitialize(
    _In_ WDFDRIVER Driver
)
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

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (InterlockedCompareExchange(&g_ControlInitialized, 1, 0) != 0) {
        return STATUS_SUCCESS;
    }

    ExInitializeFastMutex(&g_ClientListLock);
    InitializeListHead(&g_ClientList);
    g_ClientCount = 0;

    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    devInit = WdfControlDeviceInitAllocate(Driver, &sddl);
    if (devInit == NULL) {
        InterlockedExchange(&g_ControlInitialized, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetDeviceType(devInit, FILE_DEVICE_STINGER);
    WdfDeviceInitSetExclusive(devInit, FALSE);

    RtlInitUnicodeString(&deviceName, L"\\Device\\StingerCtl");
    status = WdfDeviceInitAssignName(devInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(devInit);
        InterlockedExchange(&g_ControlInitialized, 0);
        return status;
    }

    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, STINGEREvtFileCreate, STINGEREvtFileCleanup, WDF_NO_EVENT_CALLBACK);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs, STINGER_FILE_CONTEXT);
    attrs.ExecutionLevel = WdfExecutionLevelPassive;
    WdfDeviceInitSetFileObjectConfig(devInit, &fileConfig, &attrs);

    WDF_OBJECT_ATTRIBUTES_INIT(&attrs);
    attrs.ExecutionLevel = WdfExecutionLevelPassive;
    status = WdfDeviceCreate(&devInit, &attrs, &device);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&g_ControlInitialized, 0);
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = STINGEREvtIoDeviceControl;
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        WdfObjectDelete(device);
        InterlockedExchange(&g_ControlInitialized, 0);
        return status;
    }

    RtlInitUnicodeString(&globalSymlink, L"\\DosDevices\\Global\\StingerCtl");
    status = WdfDeviceCreateSymbolicLink(device, &globalSymlink);
    if (!NT_SUCCESS(status)) {
        WdfObjectDelete(device);
        InterlockedExchange(&g_ControlInitialized, 0);
        return status;
    }

    // Best-effort legacy link for callers using \\.\StingerCtl.
    RtlInitUnicodeString(&symlink, L"\\DosDevices\\StingerCtl");
    (void)WdfDeviceCreateSymbolicLink(device, &symlink);

    g_ControlDevice = device;
    WdfControlFinishInitializing(device);
    return STATUS_SUCCESS;
}

VOID
STINGERControlUninitialize(
    VOID
)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    if (InterlockedExchange(&g_ControlInitialized, 0) == 0) {
        return;
    }

    if (g_ControlDevice != NULL) {
        WdfObjectDelete(g_ControlDevice);
        g_ControlDevice = NULL;
    }
    g_ClientCount = 0;
}

VOID
STINGERControlPublishHandleEvent(
    _In_ UINT64 CallerPid,
    _In_ UINT64 TargetPid,
    _In_ UINT32 DesiredAccess,
    _In_ UINT32 ClassId,
    _In_ UINT64 OriginAddress,
    _In_ UINT32 OriginProtect,
    _In_ UINT32 Flags,
    _In_opt_z_ PCWSTR OriginPath,
    _In_ UINT32 FrameCount,
    _In_reads_opt_(FrameCount) PVOID const* Frames,
    _In_ INT32 StatusOpenProcess,
    _In_ INT32 StatusBasicInfo,
    _In_ INT32 StatusSectionName
)
{
    STINGER_EVENT_RECORD record;
    UINT32 stream = STINGER_STREAM_HANDLE;
    UINT32 i;
    UINT32 safeCount;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return;
    }

    RtlZeroMemory(&record, sizeof(record));
    record.Header.Size = sizeof(record);
    record.Header.Type = StingerEventTypeHandle;
    record.Header.TimestampQpc = KeQueryPerformanceCounter(NULL).QuadPart;

    if ((Flags & STINGER_HANDLE_FLAG_MEMORY_RELATED) != 0) {
        stream |= STINGER_STREAM_MEMORY;
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

    safeCount = (FrameCount > STINGER_MAX_EVENT_FRAMES) ? STINGER_MAX_EVENT_FRAMES : FrameCount;
    record.Data.Handle.FrameCount = safeCount;
    if (Frames != NULL) {
        for (i = 0; i < safeCount; ++i) {
            record.Data.Handle.Frames[i] = (UINT64)(ULONG_PTR)Frames[i];
        }
    }

    if (OriginPath != NULL) {
        (void)RtlStringCchCopyW(record.Data.Handle.OriginPath, RTL_NUMBER_OF(record.Data.Handle.OriginPath), OriginPath);
    }

    STINGERPublishRecordToSubscribers((UINT32)CallerPid, stream, &record);
}

VOID
STINGERControlPublishThreadEvent(
    _In_ UINT64 ProcessId,
    _In_ UINT64 ThreadId,
    _In_ UINT64 CreatorPid,
    _In_ UINT64 StartAddress,
    _In_ UINT64 ImageBase,
    _In_ UINT64 ImageSize,
    _In_ UINT32 Flags,
    _In_ UINT32 FrameCount,
    _In_reads_opt_(FrameCount) PVOID const* Frames
)
{
    STINGER_EVENT_RECORD record;
    UINT32 i;
    UINT32 safeCount;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return;
    }

    RtlZeroMemory(&record, sizeof(record));
    record.Header.Size = sizeof(record);
    record.Header.Type = StingerEventTypeThread;
    record.Header.StreamMask = STINGER_STREAM_THREAD;
    record.Header.TimestampQpc = KeQueryPerformanceCounter(NULL).QuadPart;

    record.Data.Thread.ProcessId = ProcessId;
    record.Data.Thread.ThreadId = ThreadId;
    record.Data.Thread.CreatorPid = CreatorPid;
    record.Data.Thread.StartAddress = StartAddress;
    record.Data.Thread.ImageBase = ImageBase;
    record.Data.Thread.ImageSize = ImageSize;
    record.Data.Thread.Flags = Flags;

    safeCount = (FrameCount > STINGER_MAX_EVENT_FRAMES) ? STINGER_MAX_EVENT_FRAMES : FrameCount;
    record.Data.Thread.FrameCount = safeCount;
    if (Frames != NULL) {
        for (i = 0; i < safeCount; ++i) {
            record.Data.Thread.Frames[i] = (UINT64)(ULONG_PTR)Frames[i];
        }
    }

    STINGERPublishRecordToSubscribers((UINT32)ProcessId, STINGER_STREAM_THREAD, &record);
}

BOOLEAN
STINGERControlSelfCheck(
    VOID
)
{
    PDEVICE_OBJECT deviceObject;

    if (InterlockedCompareExchange(&g_ControlInitialized, 0, 0) == 0) {
        return FALSE;
    }
    if (g_ControlDevice == NULL) {
        return FALSE;
    }

    deviceObject = WdfDeviceWdmGetDeviceObject(g_ControlDevice);
    if (deviceObject == NULL) {
        return FALSE;
    }

    if ((deviceObject->Flags & DO_DEVICE_INITIALIZING) != 0) {
        return FALSE;
    }

    return TRUE;
}
