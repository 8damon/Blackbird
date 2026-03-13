#include "control_private.h"
#include "..\..\monitors\anti_tamper.h"
#include "..\..\monitors\handle_monitor.h"
#include "..\..\monitors\thread_monitor.h"
#include "..\..\monitors\process_monitor.h"
#include "..\..\monitors\image_monitor.h"
#include "..\..\monitors\registry_monitor.h"
#include "..\..\monitors\apc_monitor.h"
#include "..\..\monitors\filesystem_monitor.h"
#include "..\..\correlation\intent_store.h"
#include "..\..\correlation\hollowing_engine.h"
#include "..\..\telemetry\etw.h"

NTSTATUS BLACKBIRDHandleSubscribeIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PBLACKBIRD_SUBSCRIBE_REQUEST in;
    size_t inSize;
    UINT32 i;
    ULONG requesterPid;
    UINT32 subscriptionCountSnapshot;
    UINT32 mergedMask;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    if ((in->StreamMask &
         (BLACKBIRD_STREAM_HANDLE | BLACKBIRD_STREAM_MEMORY | BLACKBIRD_STREAM_THREAD |
          BLACKBIRD_STREAM_FILESYSTEM)) == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (BLACKBIRDControlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireFastMutex(&Client->Lock);
    for (i = 0; i < Client->SubscriptionCount; ++i)
    {
        if (Client->Subscriptions[i].ProcessId == in->ProcessId)
        {
            Client->Subscriptions[i].StreamMask |= in->StreamMask;
            mergedMask = Client->Subscriptions[i].StreamMask;
            subscriptionCountSnapshot = Client->SubscriptionCount;
            ExReleaseFastMutex(&Client->Lock);
            requesterPid = BLACKBIRDGetRequestorPid(Request);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_INFO_LEVEL,
                       "BLACKBIRD: subscribe update requesterPid=%lu targetPid=%lu streamMask=0x%08X mergedMask=0x%08X subscriptions=%lu.\n",
                       requesterPid,
                       in->ProcessId,
                       in->StreamMask,
                       mergedMask,
                       subscriptionCountSnapshot);
            InterlockedExchange(&g_ControlTelemetryArmed, 1);
            return STATUS_SUCCESS;
        }
    }

    if (Client->SubscriptionCount >= BLACKBIRD_MAX_CLIENT_SUBSCRIPTIONS)
    {
        ExReleaseFastMutex(&Client->Lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Client->Subscriptions[Client->SubscriptionCount].ProcessId = in->ProcessId;
    Client->Subscriptions[Client->SubscriptionCount].StreamMask = in->StreamMask;
    Client->SubscriptionCount += 1;
    subscriptionCountSnapshot = Client->SubscriptionCount;
    ExReleaseFastMutex(&Client->Lock);

    requesterPid = BLACKBIRDGetRequestorPid(Request);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               "BLACKBIRD: subscribe add requesterPid=%lu targetPid=%lu streamMask=0x%08X subscriptions=%lu.\n",
               requesterPid,
               in->ProcessId,
               in->StreamMask,
               subscriptionCountSnapshot);
    InterlockedExchange(&g_ControlTelemetryArmed, 1);

    return STATUS_SUCCESS;
}

NTSTATUS BLACKBIRDHandleUnsubscribeIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PBLACKBIRD_UNSUBSCRIBE_REQUEST in;
    size_t inSize;
    UINT32 i;
    ULONG requesterPid;
    UINT32 subscriptionCountSnapshot;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);
    if (BLACKBIRDControlIsShutdown())
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
            subscriptionCountSnapshot = Client->SubscriptionCount;
            ExReleaseFastMutex(&Client->Lock);
            requesterPid = BLACKBIRDGetRequestorPid(Request);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_INFO_LEVEL,
                       "BLACKBIRD: unsubscribe requesterPid=%lu targetPid=%lu subscriptions=%lu.\n",
                       requesterPid,
                       in->ProcessId,
                       subscriptionCountSnapshot);
            BLACKBIRDControlRefreshArmedState();
            return STATUS_SUCCESS;
        }
    }
    ExReleaseFastMutex(&Client->Lock);
    requesterPid = BLACKBIRDGetRequestorPid(Request);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_WARNING_LEVEL,
               "BLACKBIRD: unsubscribe miss requesterPid=%lu targetPid=%lu status=STATUS_NOT_FOUND.\n",
               requesterPid,
               in->ProcessId);
    return STATUS_NOT_FOUND;
}

NTSTATUS BLACKBIRDHandleGetStatsIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut)
{
    NTSTATUS status;
    PBLACKBIRD_STATS_RESPONSE out;
    size_t outSize;
    LONG statsCounter;
    ULONG requesterPid;

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
    statsCounter = InterlockedIncrement(&g_IoctlGetStatsCounter);
    if (statsCounter == 1 || ((statsCounter & 0x7F) == 0))
    {
        requesterPid = BLACKBIRDGetRequestorPid(Request);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   "BLACKBIRD: get-stats requesterPid=%lu count=%ld subscriptions=%lu queueDepth=%lu dropped=%lu.\n",
                   requesterPid,
                   statsCounter,
                   out->SubscriptionCount,
                   out->QueueDepth,
                   out->DroppedEvents);
    }
    return STATUS_SUCCESS;
}

NTSTATUS BLACKBIRDHandleGetHealthIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request,
                                         _Out_ size_t *BytesOut)
{
    NTSTATUS status;
    PBLACKBIRD_HEALTH_RESPONSE out;
    size_t outSize;

    UNREFERENCED_PARAMETER(Client);

    if (BytesOut == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
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
    if (BLACKBIRDControlSelfCheck())
    {
        out->HealthMask |= BLACKBIRD_HEALTH_CONTROL_READY;
    }
    if (BLACKBIRDEtwSelfCheck())
    {
        out->HealthMask |= BLACKBIRD_HEALTH_ETW_READY;
    }
    if (BLACKBIRDHandleMonitorSelfCheck())
    {
        out->HealthMask |= BLACKBIRD_HEALTH_HANDLE_MONITOR_READY;
    }
    if (BLACKBIRDThreadMonitorSelfCheck())
    {
        out->HealthMask |= BLACKBIRD_HEALTH_THREAD_MONITOR_READY;
    }
    if (BLACKBIRDProcessMonitorSelfCheck())
    {
        out->HealthMask |= BLACKBIRD_HEALTH_PROCESS_MONITOR_READY;
    }
    if (BLACKBIRDImageMonitorSelfCheck())
    {
        out->HealthMask |= BLACKBIRD_HEALTH_IMAGE_MONITOR_READY;
    }
    if (BLACKBIRDRegistryMonitorSelfCheck())
    {
        out->HealthMask |= BLACKBIRD_HEALTH_REGISTRY_MONITOR_READY;
    }
    if (BLACKBIRDApcMonitorSelfCheck())
    {
        out->HealthMask |= BLACKBIRD_HEALTH_APC_MONITOR_READY;
    }
    if (BLACKBIRDFileSystemMonitorSelfCheck())
    {
        out->HealthMask |= BLACKBIRD_HEALTH_FILESYSTEM_MONITOR_READY;
    }
    if (BLACKBIRDCorrelationSelfCheck())
    {
        out->HealthMask |= BLACKBIRD_HEALTH_CORRELATION_READY;
    }
    if (BLACKBIRDHollowingEngineSelfCheck())
    {
        out->HealthMask |= BLACKBIRD_HEALTH_HOLLOWING_ENGINE_READY;
    }
    out->TamperMask = BLACKBIRDAntiTamperGetLastMask();
    *BytesOut = sizeof(*out);
    return STATUS_SUCCESS;
}

NTSTATUS BLACKBIRDHandleSetPidsIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PBLACKBIRD_SET_PIDS_REQUEST in;
    size_t inSize;
    UINT32 i;
    UINT32 streamMask;
    UINT32 appliedCount;
    ULONG requesterPid;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    streamMask = in->StreamMask;
    if ((streamMask &
         (BLACKBIRD_STREAM_HANDLE | BLACKBIRD_STREAM_MEMORY | BLACKBIRD_STREAM_THREAD |
          BLACKBIRD_STREAM_FILESYSTEM)) == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (in->ProcessCount == 0 || in->ProcessCount > BLACKBIRD_MAX_PID_LIST)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (BLACKBIRDControlIsShutdown())
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

        if (!seen && Client->SubscriptionCount < BLACKBIRD_MAX_CLIENT_SUBSCRIPTIONS)
        {
            Client->Subscriptions[Client->SubscriptionCount].ProcessId = pid;
            Client->Subscriptions[Client->SubscriptionCount].StreamMask = streamMask;
            Client->SubscriptionCount += 1;
        }
    }

    appliedCount = Client->SubscriptionCount;
    ExReleaseFastMutex(&Client->Lock);
    requesterPid = BLACKBIRDGetRequestorPid(Request);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               "BLACKBIRD: set-pids requesterPid=%lu requestedCount=%lu appliedCount=%lu streamMask=0x%08X.\n",
               requesterPid,
               in->ProcessCount,
               appliedCount,
               streamMask);
    if (appliedCount != 0)
    {
        InterlockedExchange(&g_ControlTelemetryArmed, 1);
    }
    else
    {
        BLACKBIRDControlRefreshArmedState();
    }

    return (appliedCount != 0) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

NTSTATUS BLACKBIRDHandleArmPendingLaunchIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PBLACKBIRD_ARM_PENDING_LAUNCH_REQUEST in;
    size_t inSize;
    ULONG requesterPid;
    BOOLEAN clearOnly;
    BOOLEAN hasPathSpec;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    if (BLACKBIRDControlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    clearOnly = ((in->Flags & BLACKBIRD_PENDING_LAUNCH_FLAG_CLEAR) != 0);
    hasPathSpec = (in->ImagePathNormDos[0] != L'\0' || in->ImagePathNormNt[0] != L'\0' || in->ImagePathTail[0] != L'\0');
    if (!clearOnly)
    {
        if ((in->StreamMask & (BLACKBIRD_STREAM_HANDLE | BLACKBIRD_STREAM_MEMORY | BLACKBIRD_STREAM_THREAD |
                               BLACKBIRD_STREAM_FILESYSTEM)) == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (!hasPathSpec)
        {
            return STATUS_INVALID_PARAMETER;
        }
    }

    ExAcquireFastMutex(&Client->Lock);
    Client->PendingLaunchArmed = FALSE;
    Client->PendingLaunchStreamMask = 0;
    Client->PendingLaunchPathNormDos[0] = L'\0';
    Client->PendingLaunchPathNormNt[0] = L'\0';
    Client->PendingLaunchPathTail[0] = L'\0';

    if (!clearOnly)
    {
        Client->PendingLaunchStreamMask = in->StreamMask;
        Client->PendingLaunchArmed = TRUE;
        (void)RtlStringCchCopyW(Client->PendingLaunchPathNormDos, RTL_NUMBER_OF(Client->PendingLaunchPathNormDos),
                                in->ImagePathNormDos);
        (void)RtlStringCchCopyW(Client->PendingLaunchPathNormNt, RTL_NUMBER_OF(Client->PendingLaunchPathNormNt),
                                in->ImagePathNormNt);
        (void)RtlStringCchCopyW(Client->PendingLaunchPathTail, RTL_NUMBER_OF(Client->PendingLaunchPathTail),
                                in->ImagePathTail);
    }
    ExReleaseFastMutex(&Client->Lock);

    requesterPid = BLACKBIRDGetRequestorPid(Request);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               "BLACKBIRD: pending-launch %s requesterPid=%lu streamMask=0x%08X normDos=%ws normNt=%ws tail=%ws.\n",
               clearOnly ? "clear" : "arm",
               requesterPid,
               in->StreamMask,
               in->ImagePathNormDos,
               in->ImagePathNormNt,
               in->ImagePathTail);

    return STATUS_SUCCESS;
}

static NTSTATUS BLACKBIRDResolveProcessImagePath(_In_ UINT32 ProcessId, _Out_writes_z_(OutputChars) PWSTR Output,
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

NTSTATUS BLACKBIRDHandleQueryProcessImageIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request,
                                                 _Out_ size_t *BytesOut)
{
    NTSTATUS status;
    PBLACKBIRD_QUERY_PROCESS_IMAGE_REQUEST in;
    PBLACKBIRD_QUERY_PROCESS_IMAGE_RESPONSE out;
    size_t inSize;
    size_t outSize;
    ULONG requesterPid;

    *BytesOut = 0;
    if (BLACKBIRDControlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireFastMutex(&Client->Lock);
    if (!BLACKBIRDClientConsumeQueryBudgetLocked(Client))
    {
        LONG throttleCounter = InterlockedIncrement(&g_QueryImageThrottleCounter);
        ExReleaseFastMutex(&Client->Lock);
        if (throttleCounter == 1 || ((throttleCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "BLACKBIRD: throttling IOCTL_BLACKBIRD_QUERY_PROCESS_IMAGE total=%lu.\n",
                       (ULONG)throttleCounter);
        }
        return STATUS_QUOTA_EXCEEDED;
    }
    ExReleaseFastMutex(&Client->Lock);

    if (!BLACKBIRDTryAcquireQueryInflightSlot())
    {
        InterlockedIncrement(&g_QueryImageThrottleCounter);
        return STATUS_DEVICE_BUSY;
    }

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        BLACKBIRDReleaseQueryInflightSlot();
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID *)&out, &outSize);
    if (!NT_SUCCESS(status))
    {
        BLACKBIRDReleaseQueryInflightSlot();
        return status;
    }
    if (outSize < sizeof(*out))
    {
        BLACKBIRDReleaseQueryInflightSlot();
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(out, sizeof(*out));
    out->ProcessId = in->ProcessId;
    out->Status = BLACKBIRDResolveProcessImagePath(in->ProcessId, out->ImagePath, RTL_NUMBER_OF(out->ImagePath));

    BLACKBIRDReleaseQueryInflightSlot();
    *BytesOut = sizeof(*out);
    requesterPid = BLACKBIRDGetRequestorPid(Request);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               NT_SUCCESS(out->Status) ? DPFLTR_INFO_LEVEL : DPFLTR_WARNING_LEVEL,
               "BLACKBIRD: query-process-image requesterPid=%lu targetPid=%lu status=0x%08X.\n",
               requesterPid,
               in->ProcessId,
               out->Status);
    return STATUS_SUCCESS;
}

NTSTATUS BLACKBIRDHandleGetEventIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut)
{
    NTSTATUS status;
    PBLACKBIRD_EVENT_RECORD out;
    size_t outSize;
    UINT32 queueDepthSnapshot = 0;
    LONG emptyCounter;
    LONG deliverCounter;
    ULONG requesterPid;

    *BytesOut = 0;
    if (BLACKBIRDControlIsShutdown())
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
        emptyCounter = InterlockedIncrement(&g_IoctlGetEventEmptyCounter);
        if (emptyCounter == 1 || ((emptyCounter & 0x1FF) == 0))
        {
            requesterPid = BLACKBIRDGetRequestorPid(Request);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_INFO_LEVEL,
                       "BLACKBIRD: get-event empty requesterPid=%lu emptyCount=%ld.\n",
                       requesterPid,
                       emptyCounter);
        }
        return STATUS_NO_MORE_ENTRIES;
    }

    {
        PLIST_ENTRY entry = RemoveHeadList(&Client->EventQueue);
        PBLACKBIRD_EVENT_NODE node = CONTAINING_RECORD(entry, BLACKBIRD_EVENT_NODE, Link);
        RtlCopyMemory(out, &node->Record, sizeof(*out));
        if (Client->QueueDepth > 0)
        {
            Client->QueueDepth -= 1;
        }
        queueDepthSnapshot = Client->QueueDepth;
        ExFreePoolWithTag(node, BLACKBIRD_POOL_TAG);
        BLACKBIRDReleaseGlobalQueueSlot();
    }
    ExReleaseFastMutex(&Client->Lock);

    *BytesOut = sizeof(*out);
    deliverCounter = InterlockedIncrement(&g_IoctlGetEventDeliverCounter);
    if (deliverCounter == 1 || ((deliverCounter & 0x1FF) == 0))
    {
        requesterPid = BLACKBIRDGetRequestorPid(Request);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   "BLACKBIRD: get-event delivered requesterPid=%lu deliveredCount=%ld queueDepthNow=%lu eventType=%lu seq=%lu.\n",
                   requesterPid,
                   deliverCounter,
                   queueDepthSnapshot,
                   out->Header.Type,
                   out->Header.Sequence);
    }
    return STATUS_SUCCESS;
}

NTSTATUS BLACKBIRDHandleSetShutdownModeIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request)
{
    ULONG requesterPid;

    UNREFERENCED_PARAMETER(Client);
    requesterPid = BLACKBIRDGetRequestorPid(Request);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_WARNING_LEVEL,
               "BLACKBIRD: shutdown mode requested by requesterPid=%lu.\n",
               requesterPid);
    BLACKBIRDControlBeginShutdown();
    return STATUS_SUCCESS;
}
