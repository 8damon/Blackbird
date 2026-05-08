#include "control_private.h"
#include "..\..\monitors\anti_tamper.h"
#include "..\..\callbacks\handle_monitor.h"
#include "..\..\callbacks\thread_monitor.h"
#include "..\..\callbacks\process_monitor.h"
#include "..\..\callbacks\image_monitor.h"
#include "..\..\callbacks\registry_monitor.h"
#include "..\..\monitors\apc_monitor.h"
#include "..\..\callbacks\filesystem_monitor.h"
#include "..\..\correlation\intent_store.h"
#include "..\..\correlation\hollowing_engine.h"
#include "..\..\telemetry\etw.h"
#include "..\runtime_config.h"
#include "..\optional_features.h"
#include "..\..\hooks\monitor\ntapi_monitor.h"
#include "..\..\antivirt\qpc_timing.h"

static volatile LONG g_BkctlSetPidsBusyCounter = 0;

static BOOLEAN BkctlRequestorIsTrustedControlPlane(_In_ ULONG RequesterPid)
{
    return (BkcprocIsControllerReadyPid(RequesterPid) || BkcprocIsInterfacePid(RequesterPid));
}

static BOOLEAN BkctlRequestorIsControllerOnly(_In_ ULONG RequesterPid)
{
    return BkcprocIsControllerReadyPid(RequesterPid);
}

static BOOLEAN BkctlRequestorCanMarkControllerReady(_In_ ULONG RequesterPid, _In_ UINT32 TargetPid)
{
    return (TargetPid != 0 && (RequesterPid == TargetPid || BkcprocIsControllerReadyPid(RequesterPid)));
}

static UINT32 BkctlEndpointGuardDiagnosticDetail(_In_opt_ const BK_ENDPOINT_GUARD_REQUEST *Request)
{
    if (Request == NULL)
    {
        return 0;
    }

    return ((Request->Action & 0x0Fu) << 28) | ((Request->Direction & 0x0Fu) << 24) |
           ((Request->Protocol & 0xFFu) << 16) | Request->LocalPort;
}

static UINT32 BkctlBuildHealthMask(VOID)
{
    UINT32 mask = 0;

    if (BkctlSelfCheck())
    {
        mask |= BK_HEALTH_CONTROL_READY;
    }
    if (BketwSelfCheck())
    {
        mask |= BK_HEALTH_ETW_READY;
    }
    if (BkchdlSelfCheck())
    {
        mask |= BK_HEALTH_HANDLE_MONITOR_READY;
    }
    if (BkcthrSelfCheck())
    {
        mask |= BK_HEALTH_THREAD_MONITOR_READY;
    }
    if (BkcprocSelfCheck())
    {
        mask |= BK_HEALTH_PROCESS_MONITOR_READY;
    }
    if (BkcimgSelfCheck())
    {
        mask |= BK_HEALTH_IMAGE_MONITOR_READY;
    }
    if (BkcregSelfCheck())
    {
        mask |= BK_HEALTH_REGISTRY_MONITOR_READY;
    }
    if (BkapcSelfCheck())
    {
        mask |= BK_HEALTH_APC_MONITOR_READY;
    }
    if (BkcfsSelfCheck())
    {
        mask |= BK_HEALTH_FILESYSTEM_MONITOR_READY;
    }
    if (BkcorSelfCheck())
    {
        mask |= BK_HEALTH_CORRELATION_READY;
    }
    if (BkhloEngineSelfCheck())
    {
        mask |= BK_HEALTH_HOLLOWING_ENGINE_READY;
    }
    if (BkntkiMonitorSelfCheck())
    {
        mask |= BK_HEALTH_NTAPI_MONITOR_READY;
    }
    if (BkatSelfCheck())
    {
        mask |= BK_HEALTH_ANTI_TAMPER_READY;
    }
    if (BkdiagSelfCheck())
    {
        mask |= BK_HEALTH_DIAGNOSTICS_READY;
    }
    if (BkwfpEndpointGuardSelfCheck())
    {
        mask |= BK_HEALTH_ENDPOINT_GUARD_READY;
    }
    if (BkbugSelfCheck())
    {
        mask |= BK_HEALTH_BUGCHECK_MONITOR_READY;
    }
    if (BkchdlSelfCheck() && BkcregSelfCheck() && BkcfsSelfCheck())
    {
        mask |= BK_HEALTH_ENTERPRISE_MONITOR_READY;
    }
    return mask;
}

static VOID BkctlPutComponentState(_Inout_ PBK_DIAGNOSTICS_RESPONSE Response, _In_ UINT16 ComponentId,
                                   _In_ UINT16 SubsystemId, _In_ BOOLEAN Online, _In_ UINT32 ExtraFlags,
                                   _In_ UINT64 Detail0, _In_ UINT64 Detail1)
{
    PBK_DIAGNOSTIC_COMPONENT_STATE state;

    if (Response == NULL || Response->ComponentStateCount >= BK_DIAGNOSTIC_MAX_COMPONENT_STATES)
    {
        return;
    }

    state = &Response->Components[Response->ComponentStateCount++];
    RtlZeroMemory(state, sizeof(*state));
    state->ComponentId = ComponentId;
    state->SubsystemId = SubsystemId;
    state->Flags = ExtraFlags | (Online ? BK_DIAG_STATE_ONLINE : BK_DIAG_STATE_DEGRADED);
    state->Status = Online ? STATUS_SUCCESS : STATUS_DEVICE_NOT_READY;
    state->Detail0 = Detail0;
    state->Detail1 = Detail1;
}

static VOID BkctlFillComponentDiagnostics(_Inout_ PBK_DIAGNOSTICS_RESPONSE Response, _In_opt_ PBK_CLIENT Client)
{
    UINT64 subscriptions = 0;
    UINT64 bugCheckExRoutine = 0;
    UINT64 bugCheck2Routine = 0;
    UINT32 enterpriseProducers = 0;

    if (Client != NULL)
    {
        ExAcquireFastMutex(&Client->Lock);
        subscriptions = Client->SubscriptionCount;
        ExReleaseFastMutex(&Client->Lock);
    }

    BkctlPutComponentState(Response, BK_DIAG_COMPONENT_DRIVER_ENTRY, BktmpSubsystemDriver, TRUE, 0, 0, 0);
    BkctlPutComponentState(Response, BK_DIAG_COMPONENT_RUNTIME_CONFIG, BktmpSubsystemDriver, TRUE, 0,
                           BkrtGetPersistentFlags(), BkrtGetEffectiveFlags());
    BkctlPutComponentState(Response, BK_DIAG_COMPONENT_CONTROL, BktmpSubsystemControl, BkctlSelfCheck(),
                           BK_DIAG_STATE_REGISTERED, subscriptions, 0);
    BkctlPutComponentState(Response, BK_DIAG_COMPONENT_ETW, BktmpSubsystemEtw, BketwSelfCheck(),
                           BK_DIAG_STATE_TELEMETRY, 0, 0);
    BkctlPutComponentState(Response, BK_DIAG_COMPONENT_HANDLE_MONITOR, BktmpSubsystemHandleMonitor, BkchdlSelfCheck(),
                           BK_DIAG_STATE_CALLBACK | BK_DIAG_STATE_REGISTERED, 2, 0);
    BkctlPutComponentState(Response, BK_DIAG_COMPONENT_THREAD_MONITOR, BktmpSubsystemThreadMonitor, BkcthrSelfCheck(),
                           BK_DIAG_STATE_CALLBACK | BK_DIAG_STATE_REGISTERED, 1, 0);
    BkctlPutComponentState(Response, BK_DIAG_COMPONENT_PROCESS_MONITOR, BktmpSubsystemProcessMonitor,
                           BkcprocSelfCheck(), BK_DIAG_STATE_CALLBACK | BK_DIAG_STATE_REGISTERED, 1, 0);
    BkctlPutComponentState(Response, BK_DIAG_COMPONENT_IMAGE_MONITOR, BktmpSubsystemImageMonitor, BkcimgSelfCheck(),
                           BK_DIAG_STATE_CALLBACK | BK_DIAG_STATE_REGISTERED, 1, 0);
    BkctlPutComponentState(Response, BK_DIAG_COMPONENT_REGISTRY_MONITOR, BktmpSubsystemRegistryMonitor,
                           BkcregSelfCheck(), BK_DIAG_STATE_CALLBACK | BK_DIAG_STATE_REGISTERED, 1, 0);
    BkctlPutComponentState(Response, BK_DIAG_COMPONENT_FILESYSTEM_MONITOR, BktmpSubsystemFileSystemMonitor,
                           BkcfsSelfCheck(), BK_DIAG_STATE_CALLBACK | BK_DIAG_STATE_REGISTERED, 9, 0);
    BkctlPutComponentState(Response, BK_DIAG_COMPONENT_APC_MONITOR, BktmpSubsystemApcMonitor, BkapcSelfCheck(), 0, 0,
                           0);
    BkctlPutComponentState(Response, BK_DIAG_COMPONENT_CORRELATION, BktmpSubsystemCorrelation, BkcorSelfCheck(), 0, 0,
                           0);
    BkctlPutComponentState(Response, BK_DIAG_COMPONENT_HOLLOWING_ENGINE, BktmpSubsystemHollowingEngine,
                           BkhloEngineSelfCheck(), 0, 0, 0);
    BkctlPutComponentState(
        Response, BK_DIAG_COMPONENT_NTAPI_MONITOR, BktmpSubsystemNtApiMonitor, BkntkiMonitorSelfCheck(),
        BK_DIAG_STATE_HOOK | (BkrtIsNtApiHooksDisarmed() ? BK_DIAG_STATE_POLICY_DISABLED : BK_DIAG_STATE_ARMED),
        Response->NtApiHookStateCount, Response->HookPatchCount);
    BkctlPutComponentState(Response, BK_DIAG_COMPONENT_ANTI_TAMPER, BktmpSubsystemAntiTamper, BkatSelfCheck(),
                           BK_DIAG_STATE_TAMPER_ACTIVE, BkatGetLastMask(), 5000);
    BkctlPutComponentState(Response, BK_DIAG_COMPONENT_DIAGNOSTICS, BktmpSubsystemDriver, BkdiagSelfCheck(), 0,
                           Response->EventCount, Response->DroppedCount);
    BkctlPutComponentState(Response, BK_DIAG_COMPONENT_WFP_ENDPOINT_GUARD, BktmpSubsystemDriver,
                           BkwfpEndpointGuardSelfCheck(), BK_DIAG_STATE_CALLBACK | BK_DIAG_STATE_REGISTERED, 4, 0);
    BkbugQueryState(&bugCheckExRoutine, &bugCheck2Routine);
    BkctlPutComponentState(
        Response, BK_DIAG_COMPONENT_BUGCHECK_MONITOR, BktmpSubsystemDriver, BkbugSelfCheck(),
        BK_DIAG_STATE_TELEMETRY | BK_DIAG_STATE_FAST_PATH |
            ((bugCheckExRoutine != 0 || bugCheck2Routine != 0) ? BK_DIAG_STATE_HOOK : BK_DIAG_STATE_POLICY_DISABLED),
        bugCheckExRoutine, bugCheck2Routine);
    if (BkchdlSelfCheck())
    {
        enterpriseProducers |= BK_ENTERPRISE_PRODUCER_HANDLE;
    }
    if (BkcregSelfCheck())
    {
        enterpriseProducers |= BK_ENTERPRISE_PRODUCER_REGISTRY;
    }
    if (BkcfsSelfCheck())
    {
        enterpriseProducers |= BK_ENTERPRISE_PRODUCER_FILESYSTEM;
    }
    if (BkwfpEndpointGuardRuntimeActive())
    {
        enterpriseProducers |= BK_ENTERPRISE_PRODUCER_WFP_AD;
    }
    BkctlPutComponentState(
        Response, BK_DIAG_COMPONENT_ENTERPRISE_MONITOR, BktmpSubsystemDriver,
        (enterpriseProducers &
         (BK_ENTERPRISE_PRODUCER_HANDLE | BK_ENTERPRISE_PRODUCER_REGISTRY | BK_ENTERPRISE_PRODUCER_FILESYSTEM)) ==
            (BK_ENTERPRISE_PRODUCER_HANDLE | BK_ENTERPRISE_PRODUCER_REGISTRY | BK_ENTERPRISE_PRODUCER_FILESYSTEM),
        BK_DIAG_STATE_CALLBACK | BK_DIAG_STATE_REGISTERED | BK_DIAG_STATE_TELEMETRY | BK_DIAG_STATE_FAST_PATH,
        enterpriseProducers, ((UINT64)BK_STREAM_ENTERPRISE << 32) | enterpriseProducers);
}

static VOID BkctlFillDiagnosticsSnapshot(_Inout_ PBK_DIAGNOSTICS_RESPONSE Response, _In_opt_ PBK_CLIENT Client)
{
    if (Response == NULL)
    {
        return;
    }

    Response->SchemaVersion = BK_DIAGNOSTIC_SCHEMA_VERSION;
    Response->RuntimeFlags = BkrtGetRuntimeFlags();
    Response->EffectiveRuntimeFlags = BkrtGetEffectiveFlags();
    Response->HealthMask = BkctlBuildHealthMask();
    Response->TamperMask = BkatGetLastMask();
    BkntkiQueryDiagnostics(&Response->InstrumentationRangeCount, &Response->HookPatchCount,
                           &Response->HookPatchOverlayCount, &Response->InstrumentationReadDenyCount,
                           &Response->DuplicateNtdllMirrorCount, &Response->DuplicateNtdllMirrorFailureCount);
    BkqpcQueryState(&Response->QpcTiming);
    BkntkiQueryHookDiagnostics(Response->NtApiHooks, RTL_NUMBER_OF(Response->NtApiHooks),
                               &Response->NtApiHookStateCount);
    BkntkiQuerySanitizerDiagnostics(Response->Sanitizers, RTL_NUMBER_OF(Response->Sanitizers),
                                    &Response->SanitizerStateCount);
    BkctlFillComponentDiagnostics(Response, Client);
}

NTSTATUS BkctlHandleSubscribeIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PBK_SUBSCRIBE_REQUEST in;
    size_t inSize;
    ULONG requesterPid;
    UINT32 subscriptionCountSnapshot;
    UINT32 mergedMask;
    BOOLEAN updated;
    BOOLEAN applied;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    if (!BkctlIsValidStreamMask(in->StreamMask))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (BkctlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireFastMutex(&Client->Lock);
    subscriptionCountSnapshot = Client->SubscriptionCount;
    updated = FALSE;
    applied = FALSE;
    mergedMask = in->StreamMask;
    if (BkctlClientAddOrUpdateSubscriptionLocked(Client, in->ProcessId, in->StreamMask))
    {
        UINT32 i;

        applied = TRUE;
        updated = (subscriptionCountSnapshot == Client->SubscriptionCount);
        subscriptionCountSnapshot = Client->SubscriptionCount;
        for (i = 0; i < Client->SubscriptionCount; ++i)
        {
            if (Client->Subscriptions[i].ProcessId == in->ProcessId)
            {
                mergedMask = Client->Subscriptions[i].StreamMask;
                break;
            }
        }
    }
    ExReleaseFastMutex(&Client->Lock);
    if (!applied || subscriptionCountSnapshot == 0 || mergedMask == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    requesterPid = BkctlGetRequestorPid();
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "BK: subscribe %s requesterPid=%lu targetPid=%lu streamMask=0x%08X mergedMask=0x%08X subscriptions=%lu.\n",
        updated ? "update" : "add", requesterPid, in->ProcessId, in->StreamMask, mergedMask, subscriptionCountSnapshot);
    BkctlRebuildPidInterestIndex();
    BkctlSetTelemetryArmed(TRUE);

    return STATUS_SUCCESS;
}

NTSTATUS BkctlHandleUnsubscribeIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PBK_UNSUBSCRIBE_REQUEST in;
    size_t inSize;
    ULONG requesterPid;
    UINT32 subscriptionCountSnapshot;
    BOOLEAN removed;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);
    if (BkctlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireFastMutex(&Client->Lock);
    removed = BkctlClientRemoveSubscriptionLocked(Client, in->ProcessId);
    subscriptionCountSnapshot = Client->SubscriptionCount;
    ExReleaseFastMutex(&Client->Lock);
    if (removed)
    {
        requesterPid = BkctlGetRequestorPid();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "BK: unsubscribe requesterPid=%lu targetPid=%lu subscriptions=%lu.\n", requesterPid, in->ProcessId,
                   subscriptionCountSnapshot);
        BkctlRebuildPidInterestIndex();
        BkctlRefreshArmedState();
        return STATUS_SUCCESS;
    }
    requesterPid = BkctlGetRequestorPid();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
               "BK: unsubscribe miss requesterPid=%lu targetPid=%lu status=STATUS_NOT_FOUND.\n", requesterPid,
               in->ProcessId);
    return STATUS_NOT_FOUND;
}

NTSTATUS BkctlHandleGetStatsIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut)
{
    ULONGLONG tempusStartQpc = BktmpEnter(BktmpSubsystemControl);
    NTSTATUS status;
    PBK_STATS_RESPONSE out;
    size_t outSize;
    LONG statsCounter;
    ULONG requesterPid;

    *BytesOut = 0;

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID *)&out, &outSize);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    if (outSize < sizeof(*out))
    {
        status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    RtlZeroMemory(out, sizeof(*out));
    ExAcquireFastMutex(&Client->Lock);
    out->SubscriptionCount = Client->SubscriptionCount;
    out->QueueDepth = Client->QueueDepth;
    out->DroppedEvents = Client->DroppedEvents;
    ExReleaseFastMutex(&Client->Lock);
    out->TempusEnabled = BktmpIsEnabled() ? 1u : 0u;
    out->TempusSubsystemCount = BK_TEMPUS_SUBSYSTEM_COUNT;
    BkntkiQueryDiagnostics(&out->InstrumentationRangeCount, &out->HookPatchCount, &out->HookPatchOverlayCount,
                           &out->InstrumentationReadDenyCount, &out->DuplicateNtdllMirrorCount,
                           &out->DuplicateNtdllMirrorFailureCount);
    BktmpQueryStats(out->Tempus, RTL_NUMBER_OF(out->Tempus), &out->TempusQpcFrequency);

    *BytesOut = sizeof(*out);
    statsCounter = InterlockedIncrement(&g_IoctlGetStatsCounter);
    if (statsCounter == 1 || ((statsCounter & 0x7F) == 0))
    {
        requesterPid = BkctlGetRequestorPid();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "BK: get-stats requesterPid=%lu count=%ld subscriptions=%lu queueDepth=%lu dropped=%lu.\n",
                   requesterPid, statsCounter, out->SubscriptionCount, out->QueueDepth, out->DroppedEvents);
    }
    status = STATUS_SUCCESS;

Exit:
    BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
    return status;
}

NTSTATUS BkctlHandleGetHealthIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut)
{
    NTSTATUS status;
    PBK_HEALTH_RESPONSE out;
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
    if (BkctlSelfCheck())
    {
        out->HealthMask |= BK_HEALTH_CONTROL_READY;
    }
    if (BketwSelfCheck())
    {
        out->HealthMask |= BK_HEALTH_ETW_READY;
    }
    if (BkchdlSelfCheck())
    {
        out->HealthMask |= BK_HEALTH_HANDLE_MONITOR_READY;
    }
    if (BkcthrSelfCheck())
    {
        out->HealthMask |= BK_HEALTH_THREAD_MONITOR_READY;
    }
    if (BkcprocSelfCheck())
    {
        out->HealthMask |= BK_HEALTH_PROCESS_MONITOR_READY;
    }
    if (BkcimgSelfCheck())
    {
        out->HealthMask |= BK_HEALTH_IMAGE_MONITOR_READY;
    }
    if (BkcregSelfCheck())
    {
        out->HealthMask |= BK_HEALTH_REGISTRY_MONITOR_READY;
    }
    if (BkapcSelfCheck())
    {
        out->HealthMask |= BK_HEALTH_APC_MONITOR_READY;
    }
    if (BkcfsSelfCheck())
    {
        out->HealthMask |= BK_HEALTH_FILESYSTEM_MONITOR_READY;
    }
    if (BkcorSelfCheck())
    {
        out->HealthMask |= BK_HEALTH_CORRELATION_READY;
    }
    if (BkhloEngineSelfCheck())
    {
        out->HealthMask |= BK_HEALTH_HOLLOWING_ENGINE_READY;
    }
    if (BkntkiMonitorSelfCheck())
    {
        out->HealthMask |= BK_HEALTH_NTAPI_MONITOR_READY;
    }
    if (BkatSelfCheck())
    {
        out->HealthMask |= BK_HEALTH_ANTI_TAMPER_READY;
    }
    if (BkdiagSelfCheck())
    {
        out->HealthMask |= BK_HEALTH_DIAGNOSTICS_READY;
    }
    if (BkwfpEndpointGuardSelfCheck())
    {
        out->HealthMask |= BK_HEALTH_ENDPOINT_GUARD_READY;
    }
    if (BkchdlSelfCheck() && BkcregSelfCheck() && BkcfsSelfCheck())
    {
        out->HealthMask |= BK_HEALTH_ENTERPRISE_MONITOR_READY;
    }
    out->TamperMask = BkatGetLastMask();
    out->Reserved0 = BK_HEALTH_BUILD_MAGIC;
    out->Reserved1 = BkoptEndpointGuardIsCompiled()
                         ? (BK_HEALTH_FEATURE_ENDPOINT_GUARD_DYNAMIC_ALE | BK_HEALTH_FEATURE_ENDPOINT_GUARD_FILTER_DIAG)
                         : 0;
    *BytesOut = sizeof(*out);
    return STATUS_SUCCESS;
}

NTSTATUS BkctlHandleGetDiagnosticsIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut)
{
    NTSTATUS status;
    PBK_DIAGNOSTICS_RESPONSE out;
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

    BkdiagQuery(out);
    BkctlFillDiagnosticsSnapshot(out, Client);
    *BytesOut = sizeof(*out);
    return STATUS_SUCCESS;
}

NTSTATUS BkctlHandleSetEndpointGuardIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PBK_ENDPOINT_GUARD_REQUEST in;
    size_t inSize;
    ULONG requesterPid;

    UNREFERENCED_PARAMETER(Client);

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        BkdiagRecord(BktmpSubsystemDriver, BkDiagEventSelfCheckFailed, status, 0, BK_DIAG_FLAG_FAILURE, 0,
                     BK_DIAG_COMPONENT_WFP_ENDPOINT);
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    requesterPid = BkctlGetRequestorPid();
    status = BkwfpEndpointGuardConfigure(in, requesterPid);
    if (!NT_SUCCESS(status))
    {
        BkdiagRecord(BktmpSubsystemDriver, BkDiagEventSelfCheckFailed, status, 0, BK_DIAG_FLAG_FAILURE,
                     BkctlEndpointGuardDiagnosticDetail(in), BK_DIAG_COMPONENT_WFP_ENDPOINT);
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "BK: endpoint-guard ioctl failed requesterPid=%lu targetPid=%lu action=%lu protocol=%lu localPort=%hu remotePort=%hu status=0x%08X.\n",
            requesterPid, in->ProcessId, in->Action, in->Protocol, in->LocalPort, in->RemotePort, status);
    }
    else
    {
        BkdiagRecord(BktmpSubsystemDriver,
                     in->Action == BK_ENDPOINT_GUARD_ACTION_DISARM ? BkDiagEventDisarmed : BkDiagEventConfirmedOnline,
                     STATUS_SUCCESS, 0, 0, BkctlEndpointGuardDiagnosticDetail(in), BK_DIAG_COMPONENT_WFP_ENDPOINT);
    }
    return status;
}

NTSTATUS BkctlHandleSetPidsIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PBK_SET_PIDS_REQUEST in;
    size_t inSize;
    UINT32 streamMask;
    UINT32 appliedCount;
    ULONG requesterPid;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    requesterPid = BkctlGetRequestorPid();
    if (!BkctlRequestorIsTrustedControlPlane(requesterPid))
    {
        return STATUS_ACCESS_DENIED;
    }

    streamMask = in->StreamMask;
    if (!BkctlIsValidStreamMask(streamMask))
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (in->ProcessCount > BK_MAX_PID_LIST)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (BkctlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    if (!ExTryToAcquireFastMutex(&Client->Lock))
    {
        LONG busyCount = InterlockedIncrement(&g_BkctlSetPidsBusyCounter);
        if (busyCount == 1 || ((busyCount & 0x3F) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "BK: set-pids busy requesterPid=%lu requestedCount=%lu busyCount=%ld client=0x%p.\n",
                       requesterPid, in->ProcessCount, busyCount, Client);
        }
        return STATUS_DEVICE_BUSY;
    }
    appliedCount = BkctlClientReplaceSubscriptionsLocked(Client, in->ProcessIds, in->ProcessCount, streamMask);
    ExReleaseFastMutex(&Client->Lock);
    requesterPid = BkctlGetRequestorPid();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "BK: set-pids requesterPid=%lu requestedCount=%lu appliedCount=%lu streamMask=0x%08X.\n", requesterPid,
               in->ProcessCount, appliedCount, streamMask);
    BkctlRebuildPidInterestIndex();
    if (appliedCount != 0)
    {
        BkctlSetTelemetryArmed(TRUE);
    }
    else
    {
        BkctlRefreshArmedState();
    }

    return STATUS_SUCCESS;
}

NTSTATUS BkctlHandleArmPendingLaunchIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PBK_ARM_PENDING_LAUNCH_REQUEST in;
    size_t inSize;
    ULONG requesterPid;
    BOOLEAN clearOnly;
    BOOLEAN hasPathSpec;
    BOOLEAN hasSubjectSpec;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    requesterPid = BkctlGetRequestorPid();
    if (!BkctlRequestorIsControllerOnly(requesterPid))
    {
        return STATUS_ACCESS_DENIED;
    }

    if (BkctlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    clearOnly = ((in->Flags & BK_PENDING_LAUNCH_FLAG_CLEAR) != 0);
    hasPathSpec =
        (in->ImagePathNormDos[0] != L'\0' || in->ImagePathNormNt[0] != L'\0' || in->ImagePathTail[0] != L'\0');
    hasSubjectSpec = (in->AnalysisSubjectNormDos[0] != L'\0' || in->AnalysisSubjectNormNt[0] != L'\0' ||
                      in->AnalysisSubjectTail[0] != L'\0');
    if (!clearOnly)
    {
        if (in->AnalysisSubjectKind != BlackbirdAnalysisSubjectProcess &&
            in->AnalysisSubjectKind != BlackbirdAnalysisSubjectDll)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if ((in->StreamMask & (BK_STREAM_HANDLE | BK_STREAM_MEMORY | BK_STREAM_THREAD | BK_STREAM_FILESYSTEM |
                               BK_STREAM_REGISTRY | BK_STREAM_TIMING | BK_STREAM_ENTERPRISE)) == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (in->AnalysisSubjectKind == BlackbirdAnalysisSubjectDll && !hasSubjectSpec)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (in->AnalysisSubjectKind == BlackbirdAnalysisSubjectProcess && hasSubjectSpec)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (!hasPathSpec)
        {
            return STATUS_INVALID_PARAMETER;
        }
    }

    ExAcquireFastMutex(&Client->Lock);
    if (!clearOnly)
    {
        BkctlClientConfigurePendingLaunchLocked(Client, in);
    }
    else
    {
        BkctlClientClearPendingLaunchLocked(Client);
    }
    ExReleaseFastMutex(&Client->Lock);

    if (!clearOnly)
    {
        BkctlSetTelemetryArmed(TRUE);
    }
    else
    {
        BkctlRefreshArmedState();
    }

    requesterPid = BkctlGetRequestorPid();
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "BK: pending-launch %s requesterPid=%lu streamMask=0x%08X subjectKind=%lu normDos=%ws normNt=%ws tail=%ws subjectDos=%ws subjectNt=%ws subjectTail=%ws.\n",
        clearOnly ? "clear" : "arm", requesterPid, in->StreamMask, in->AnalysisSubjectKind, in->ImagePathNormDos,
        in->ImagePathNormNt, in->ImagePathTail, in->AnalysisSubjectNormDos, in->AnalysisSubjectNormNt,
        in->AnalysisSubjectTail);

    return STATUS_SUCCESS;
}

static NTSTATUS BkctlResolveProcessImagePath(_In_ UINT32 ProcessId, _Out_writes_z_(OutputChars) PWSTR Output,
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
    return status;
}

NTSTATUS BkctlHandleQueryProcessImageIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut)
{
    NTSTATUS status;
    PBK_QUERY_PROCESS_IMAGE_REQUEST in;
    PBK_QUERY_PROCESS_IMAGE_RESPONSE out;
    size_t inSize;
    size_t outSize;
    ULONG requesterPid;

    *BytesOut = 0;
    if (BkctlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireFastMutex(&Client->Lock);
    if (!BkctlClientConsumeQueryBudgetLocked(Client))
    {
        LONG throttleCounter = InterlockedIncrement(&g_QueryImageThrottleCounter);
        ExReleaseFastMutex(&Client->Lock);
        if (throttleCounter == 1 || ((throttleCounter & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "BK: throttling IOCTL_BK_QUERY_PROCESS_IMAGE total=%lu.\n", (ULONG)throttleCounter);
        }
        return STATUS_QUOTA_EXCEEDED;
    }
    ExReleaseFastMutex(&Client->Lock);

    if (!BkctlTryAcquireQueryInflightSlot())
    {
        InterlockedIncrement(&g_QueryImageThrottleCounter);
        return STATUS_DEVICE_BUSY;
    }

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        BkctlReleaseQueryInflightSlot();
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID *)&out, &outSize);
    if (!NT_SUCCESS(status))
    {
        BkctlReleaseQueryInflightSlot();
        return status;
    }
    if (outSize < sizeof(*out))
    {
        BkctlReleaseQueryInflightSlot();
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(out, sizeof(*out));
    out->ProcessId = in->ProcessId;
    out->Status = BkctlResolveProcessImagePath(in->ProcessId, out->ImagePath, RTL_NUMBER_OF(out->ImagePath));

    BkctlReleaseQueryInflightSlot();
    *BytesOut = sizeof(*out);
    requesterPid = BkctlGetRequestorPid();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, NT_SUCCESS(out->Status) ? DPFLTR_INFO_LEVEL : DPFLTR_WARNING_LEVEL,
               "BK: query-process-image requesterPid=%lu targetPid=%lu status=0x%08X.\n", requesterPid, in->ProcessId,
               out->Status);
    return STATUS_SUCCESS;
}

NTSTATUS BkctlHandleGetEventIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut)
{
    ULONGLONG tempusStartQpc = BktmpEnter(BktmpSubsystemControl);
    NTSTATUS status;
    PBK_EVENT_RECORD out;
    size_t outSize;
    UINT32 queueDepthSnapshot = 0;
    LONG emptyCounter;
    LONG deliverCounter;
    ULONG requesterPid;

    *BytesOut = 0;
    if (BkctlIsShutdown())
    {
        status = STATUS_DEVICE_NOT_READY;
        goto Exit;
    }
    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID *)&out, &outSize);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    if (outSize < sizeof(*out))
    {
        status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    ExAcquireFastMutex(&Client->Lock);
    if (IsListEmpty(&Client->EventQueue))
    {
        ExReleaseFastMutex(&Client->Lock);
        emptyCounter = InterlockedIncrement(&g_IoctlGetEventEmptyCounter);
        if (emptyCounter == 1 || ((emptyCounter & 0x1FF) == 0))
        {
            requesterPid = BkctlGetRequestorPid();
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BK: get-event empty requesterPid=%lu emptyCount=%ld.\n",
                       requesterPid, emptyCounter);
        }
        status = STATUS_NO_MORE_ENTRIES;
        goto Exit;
    }

    {
        PLIST_ENTRY entry = RemoveHeadList(&Client->EventQueue);
        PBK_EVENT_NODE node = CONTAINING_RECORD(entry, BK_EVENT_NODE, Link);
        RtlCopyMemory(out, &node->Record, sizeof(*out));
        if (Client->QueueDepth > 0)
        {
            Client->QueueDepth -= 1;
        }
        queueDepthSnapshot = Client->QueueDepth;
        BkctlFreeEventNode(node);
        BkctlReleaseGlobalQueueSlot();
    }
    ExReleaseFastMutex(&Client->Lock);

    *BytesOut = sizeof(*out);
    deliverCounter = InterlockedIncrement(&g_IoctlGetEventDeliverCounter);
    if (deliverCounter == 1 || ((deliverCounter & 0x1FF) == 0))
    {
        requesterPid = BkctlGetRequestorPid();
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "BK: get-event delivered requesterPid=%lu deliveredCount=%ld queueDepthNow=%lu eventType=%lu seq=%lu.\n",
            requesterPid, deliverCounter, queueDepthSnapshot, out->Header.Type, out->Header.Sequence);
    }
    status = STATUS_SUCCESS;

Exit:
    BktmpLeave(BktmpSubsystemControl, tempusStartQpc);
    return status;
}

NTSTATUS BkctlHandleSetShutdownModeIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request)
{
    ULONG requesterPid;

    UNREFERENCED_PARAMETER(Client);
    UNREFERENCED_PARAMETER(Request);
    requesterPid = BkctlGetRequestorPid();
    if (!BkctlRequestorIsTrustedControlPlane(requesterPid))
    {
        return STATUS_ACCESS_DENIED;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "BK: shutdown mode requested by requesterPid=%lu.\n",
               requesterPid);
    BkctlBeginShutdown();
    return STATUS_SUCCESS;
}

NTSTATUS BkctlHandleControlExecutionIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PBK_CONTROL_EXECUTION_REQUEST in;
    size_t inSize;
    PEPROCESS process = NULL;
    ULONG requesterPid;

    UNREFERENCED_PARAMETER(Client);

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    if (in->ProcessId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    requesterPid = BkctlGetRequestorPid();
    if (!BkctlRequestorIsControllerOnly(requesterPid))
    {
        return STATUS_ACCESS_DENIED;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)in->ProcessId, &process);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = in->Suspend ? PsSuspendProcess(process) : PsResumeProcess(process);
    ObDereferenceObject(process);
    if (NT_SUCCESS(status))
    {
        BkqpcNotifyProcessExecutionControl(in->ProcessId, in->Suspend != 0);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, NT_SUCCESS(status) ? DPFLTR_INFO_LEVEL : DPFLTR_WARNING_LEVEL,
               "BK: control-execution requesterPid=%lu targetPid=%lu suspend=%lu status=0x%08X.\n", requesterPid,
               in->ProcessId, in->Suspend, status);
    return status;
}

NTSTATUS BkctlHandleSetRuntimeConfigIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PBK_SET_RUNTIME_CONFIG_REQUEST in;
    size_t inSize;
    ULONG requesterPid;

    UNREFERENCED_PARAMETER(Client);

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    requesterPid = BkctlGetRequestorPid();
    if (!BkctlRequestorIsTrustedControlPlane(requesterPid))
    {
        return STATUS_ACCESS_DENIED;
    }

    status = BkrtSetRuntimeFlags(in->Flags, in->Mask);
    if (NT_SUCCESS(status) && ((in->Mask & BK_RUNTIME_FLAG_NTAPI_HOOKS_DISARMED) != 0))
    {
        BkntkiMonitorSetArmedState(BkctlIsArmedFast());
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, NT_SUCCESS(status) ? DPFLTR_INFO_LEVEL : DPFLTR_WARNING_LEVEL,
               "BK: set-runtime-config requesterPid=%lu flags=0x%08X mask=0x%08X status=0x%08X.\n", requesterPid,
               in->Flags, in->Mask, status);
    return status;
}

NTSTATUS BkctlHandleGetRuntimeConfigIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut)
{
    NTSTATUS status;
    PBK_RUNTIME_CONFIG_RESPONSE out;
    size_t outSize;

    UNREFERENCED_PARAMETER(Client);

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID *)&out, &outSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(outSize);

    BkrtFillResponse(out);
    *BytesOut = sizeof(*out);
    return STATUS_SUCCESS;
}

NTSTATUS BkctlHandleSetQpcTimingConfigIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PBK_QPC_TIMING_CONFIG in;
    size_t inSize;
    ULONG requesterPid;

    UNREFERENCED_PARAMETER(Client);

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    requesterPid = BkctlGetRequestorPid();
    if (!BkctlRequestorIsTrustedControlPlane(requesterPid))
    {
        return STATUS_ACCESS_DENIED;
    }

    status = BkqpcSetConfig(in);
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID, NT_SUCCESS(status) ? DPFLTR_INFO_LEVEL : DPFLTR_WARNING_LEVEL,
        "BK: set-qpc-timing requesterPid=%lu flags=0x%08X mask=0x%08X pairWindowMs=%lu maxCorrectionUs=%lu status=0x%08X.\n",
        requesterPid, in->Flags, in->Mask, in->PairWindowMs, in->MaxCorrectionUs, status);
    return status;
}

NTSTATUS BkctlHandleGetQpcTimingStateIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut)
{
    NTSTATUS status;
    PBK_QPC_TIMING_STATE out;
    size_t outSize;
    ULONG requesterPid;

    UNREFERENCED_PARAMETER(Client);

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID *)&out, &outSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(outSize);

    requesterPid = BkctlGetRequestorPid();
    if (!BkctlRequestorIsTrustedControlPlane(requesterPid))
    {
        return STATUS_ACCESS_DENIED;
    }

    BkqpcQueryState(out);
    *BytesOut = sizeof(*out);
    return STATUS_SUCCESS;
}

NTSTATUS BkctlHandleMarkControllerReadyIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PBK_MARK_CONTROLLER_READY_REQUEST in;
    size_t inSize;
    ULONG requesterPid;

    UNREFERENCED_PARAMETER(Client);

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    if (in->ProcessId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    requesterPid = BkctlGetRequestorPid();
    if (!BkctlRequestorCanMarkControllerReady(requesterPid, in->ProcessId))
    {
        return STATUS_ACCESS_DENIED;
    }
    if (requesterPid == in->ProcessId)
    {
        if (!BkcprocRegisterControllerPid(in->ProcessId) || !BkcprocMarkControllerReady(in->ProcessId))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "BK: mark-controller-ready rejected requesterPid=%lu targetPid=%lu status=STATUS_NOT_FOUND.\n",
                       requesterPid, in->ProcessId);
            return STATUS_NOT_FOUND;
        }
    }
    else if (BkcprocIsControllerReadyPid(requesterPid))
    {
        if (!BkcprocRegisterNetSvcPid(in->ProcessId) || !BkcprocMarkNetSvcReady(in->ProcessId))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "BK: mark-netsvc-ready rejected requesterPid=%lu targetPid=%lu status=STATUS_NOT_FOUND.\n",
                       requesterPid, in->ProcessId);
            return STATUS_NOT_FOUND;
        }
    }
    else
    {
        return STATUS_ACCESS_DENIED;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "BK: mark-controller-ready requesterPid=%lu targetPid=%lu status=STATUS_SUCCESS.\n", requesterPid,
               in->ProcessId);
    return STATUS_SUCCESS;
}

NTSTATUS BkctlHandleReadMemoryIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut)
{
    NTSTATUS status;
    PBK_READ_MEMORY_REQUEST in;
    PBK_READ_MEMORY_RESPONSE out;
    size_t inSize;
    size_t outSize;
    PEPROCESS targetProcess = NULL;
    SIZE_T bytesCopied = 0;
    UINT32 readSize;
    UINT32 targetPid;
    UINT64 targetBase;
    ULONG requesterPid;

    UNREFERENCED_PARAMETER(Client);

    *BytesOut = 0;

    if (BkctlIsShutdown())
    {
        return STATUS_DEVICE_NOT_READY;
    }

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID *)&out, &outSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (outSize < sizeof(*out))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (in->ProcessId == 0 || in->BaseAddress == 0 || in->Size == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* METHOD_BUFFERED: in and out point to the same kernel buffer.
       Save request fields before RtlZeroMemory corrupts them. */
    targetPid = in->ProcessId;
    targetBase = in->BaseAddress;
    readSize = (in->Size < BK_MAX_MEMORY_READ_BYTES) ? in->Size : BK_MAX_MEMORY_READ_BYTES;

    RtlZeroMemory(out, sizeof(*out));
    out->ProcessId = targetPid;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)targetPid, &targetProcess);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = MmCopyVirtualMemory(targetProcess, (PVOID)(ULONG_PTR)targetBase, PsGetCurrentProcess(), out->Data,
                                 readSize, KernelMode, &bytesCopied);
    ObDereferenceObject(targetProcess);
    if (NT_SUCCESS(status) && bytesCopied != 0)
    {
        (void)BkntkiOverlayHookPatchBytesForPid(targetPid, targetBase, bytesCopied, out->Data);
    }

    requesterPid = BkctlGetRequestorPid();
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID, (bytesCopied > 0) ? DPFLTR_INFO_LEVEL : DPFLTR_WARNING_LEVEL,
        "BK: read-memory requesterPid=%lu targetPid=%lu base=0x%016I64X size=%lu bytesRead=%Iu ntStatus=0x%08X.\n",
        requesterPid, targetPid, targetBase, readSize, bytesCopied, status);

    if (bytesCopied == 0)
    {
        /* Nothing was copied. Return the NTSTATUS directly so DeviceIoControl fails
           with a Win32 code the caller can map back to a human-readable reason. */
        return NT_SUCCESS(status) ? STATUS_NO_DATA_DETECTED : status;
    }

    out->Status = status;
    out->BytesRead = (UINT32)bytesCopied;
    *BytesOut = sizeof(*out);
    return STATUS_SUCCESS;
}

NTSTATUS BkctlHandleRegisterInstrumentationRangeIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PBK_REGISTER_INSTRUMENTATION_RANGE_REQUEST in;
    size_t inSize;
    ULONG requesterPid;

    UNREFERENCED_PARAMETER(Client);

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    requesterPid = BkctlGetRequestorPid();
    if (!BkctlRequestorIsControllerOnly(requesterPid))
    {
        return STATUS_ACCESS_DENIED;
    }
    if (in->ProcessId == 0 || in->BaseAddress == 0 || in->RegionSize == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = BkntkiRegisterInstrumentationRange(in->ProcessId, in->BaseAddress, in->RegionSize, in->Flags, in->Tag);
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID, NT_SUCCESS(status) ? DPFLTR_INFO_LEVEL : DPFLTR_WARNING_LEVEL,
        "BK: register-instrumentation-range requesterPid=%lu targetPid=%lu base=0x%016I64X size=0x%016I64X status=0x%08X.\n",
        requesterPid, in->ProcessId, in->BaseAddress, in->RegionSize, status);
    return status;
}

NTSTATUS BkctlHandleRegisterHookPatchIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PBK_REGISTER_HOOK_PATCH_REQUEST in;
    size_t inSize;
    ULONG requesterPid;

    UNREFERENCED_PARAMETER(Client);

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    if (in->ProcessId == 0 || in->PatchAddress == 0 || in->PatchSize == 0 || in->OriginalSize == 0 ||
        in->PatchSize > BK_MAX_HOOK_PATCH_BYTES || in->OriginalSize > BK_MAX_HOOK_PATCH_BYTES)
    {
        return STATUS_INVALID_PARAMETER;
    }

    requesterPid = BkctlGetRequestorPid();
    if (!BkctlRequestorIsControllerOnly(requesterPid))
    {
        return STATUS_ACCESS_DENIED;
    }

    status = BkntkiRegisterHookPatch(in->ProcessId, in->PatchAddress, in->PatchSize, in->OriginalBytes,
                                     in->OriginalSize, in->Flags, in->Tag);
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID, NT_SUCCESS(status) ? DPFLTR_INFO_LEVEL : DPFLTR_WARNING_LEVEL,
        "BK: hook-patch register requesterPid=%lu targetPid=%lu address=0x%016I64X size=%lu tag=%s status=0x%08X.\n",
        requesterPid, in->ProcessId, in->PatchAddress, in->PatchSize, in->Tag, status);
    return status;
}

NTSTATUS BkctlHandleRegisterProcessInstrumentationCallbackIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PBK_REGISTER_PROCESS_INSTRUMENTATION_CALLBACK_REQUEST in;
    size_t inSize;
    ULONG requesterPid;

    UNREFERENCED_PARAMETER(Client);

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID *)&in, &inSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNREFERENCED_PARAMETER(inSize);

    if (in->ProcessId == 0 || in->CallbackAddress == 0 || in->CallbackSize == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    requesterPid = BkctlGetRequestorPid();
    if (!BkctlRequestorIsControllerOnly(requesterPid))
    {
        return STATUS_ACCESS_DENIED;
    }

    status = BkntkiRegisterProcessInstrumentationCallback(in->ProcessId, in->CallbackAddress, in->CallbackSize,
                                                          in->Flags);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, NT_SUCCESS(status) ? DPFLTR_INFO_LEVEL : DPFLTR_WARNING_LEVEL,
               "BK: process-instrumentation-callback register requesterPid=%lu targetPid=%lu callback=0x%016I64X size=0x%016I64X status=0x%08X.\n",
               requesterPid, in->ProcessId, in->CallbackAddress, in->CallbackSize, status);
    return status;
}
