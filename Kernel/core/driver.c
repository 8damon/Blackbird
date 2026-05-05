#include <ntddk.h>
#include <wdf.h>
#include "control.h"
#include "tempus_debug.h"
#include "runtime_config.h"
#include "diagnostics.h"
#include "crashdump.h"
#include "optional_features.h"
#include "..\telemetry\etw.h"
#include "..\callbacks\handle_monitor.h"
#include "..\monitors\apc_monitor.h"
#include "..\monitors\anti_tamper.h"
#include "..\callbacks\image_monitor.h"
#include "..\callbacks\process_monitor.h"
#include "..\callbacks\registry_monitor.h"
#include "..\callbacks\thread_monitor.h"
#include "..\callbacks\filesystem_monitor.h"
#include "..\hooks\monitor\ntapi_monitor.h"
#include "..\correlation\intent_store.h"
#include "..\correlation\hollowing_engine.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD BkdrvEvtUnload;

#define BKDRV_LOG_COMPONENT(_level, _component, ...)            \
    do                                                          \
    {                                                           \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, (_level), __VA_ARGS__); \
    } while (0)

#define BKDRV_LOG(_level, ...) BKDRV_LOG_COMPONENT((_level), BK_DIAG_COMPONENT_DRIVER_ENTRY, __VA_ARGS__)

typedef enum _BK_DRIVER_STATE
{
    BkdrvStateCold = 0,
    BkdrvStateInitializing,
    BkdrvStateInitialized,
    BkdrvStateUnloading,
    BkdrvStateUnloaded
} BK_DRIVER_STATE;

#define BK_INIT_THREAD_MONITOR 0x1
#define BK_INIT_HANDLE_MONITOR 0x2
#define BK_INIT_ETW 0x4
#define BK_INIT_CONTROL 0x8
#define BK_INIT_PROCESS_MONITOR 0x20
#define BK_INIT_IMAGE_MONITOR 0x40
#define BK_INIT_REGISTRY_MONITOR 0x80
#define BK_INIT_APC_MONITOR 0x100
#define BK_INIT_ANTI_TAMPER 0x200
#define BK_INIT_CORRELATION 0x400
#define BK_INIT_HOLLOWING_ENGINE 0x800
#define BK_INIT_FILESYSTEM_MONITOR 0x1000
#define BK_INIT_NTAPI_MONITOR 0x2000
#define BK_INIT_ENDPOINT_GUARD 0x4000
#define BK_INIT_BUGCHECK_MONITOR 0x8000
#define BK_INIT_REQUIRED_FLAGS                                                                                   \
    (BK_INIT_THREAD_MONITOR | BK_INIT_HANDLE_MONITOR | BK_INIT_ETW | BK_INIT_CONTROL | BK_INIT_PROCESS_MONITOR | \
     BK_INIT_IMAGE_MONITOR | BK_INIT_REGISTRY_MONITOR | BK_INIT_APC_MONITOR | BK_INIT_ANTI_TAMPER |              \
     BK_INIT_CORRELATION | BK_INIT_HOLLOWING_ENGINE | BK_INIT_FILESYSTEM_MONITOR | BK_INIT_NTAPI_MONITOR)

static volatile LONG g_DriverState = BkdrvStateCold;
static volatile LONG g_InitFlags = 0;

typedef VOID (*BKDRV_UNINIT_ROUTINE)(VOID);

static UINT64 BkdrvQpcDeltaToMicroseconds(_In_ UINT64 DeltaQpc, _In_ UINT64 Frequency)
{
    if (Frequency == 0)
    {
        return 0;
    }
    if (DeltaQpc > ((~(UINT64)0) / 1000000ULL))
    {
        return ((DeltaQpc / Frequency) * 1000000ULL) + (((DeltaQpc % Frequency) * 1000000ULL) / Frequency);
    }

    return (DeltaQpc * 1000000ULL) / Frequency;
}

static UINT64 BkdrvElapsedMicroseconds(_In_ ULONGLONG StartQpc)
{
    LARGE_INTEGER frequency;
    LARGE_INTEGER now;

    if (StartQpc == 0)
    {
        return 0;
    }

    now = KeQueryPerformanceCounter(&frequency);
    if (frequency.QuadPart <= 0 || now.QuadPart < (LONGLONG)StartQpc)
    {
        return 0;
    }

    return BkdrvQpcDeltaToMicroseconds((UINT64)(now.QuadPart - (LONGLONG)StartQpc), (UINT64)frequency.QuadPart);
}

static VOID BkdrvMarkInitializedFlag(_In_ LONG InitFlag)
{
    LONG flags = InterlockedOr(&g_InitFlags, InitFlag) | InitFlag;
    BkcrashSetInitFlags(flags);
}

static VOID BkdrvUninitializeSubsystem(_In_ UINT32 SubsystemId, _In_ BKDRV_UNINIT_ROUTINE Routine,
                                       _In_ UINT32 ComponentId)
{
    ULONGLONG diagStartQpc;

    if (Routine == NULL)
    {
        return;
    }

    diagStartQpc = BkdiagBegin(SubsystemId, BkDiagEventShutdownBegin, ComponentId);
    BkcrashRecordCheckpoint(SubsystemId, BkDiagEventShutdownBegin, STATUS_SUCCESS, ComponentId);
    Routine();
    BkdiagComplete(SubsystemId, BkDiagEventShutdownOk, STATUS_SUCCESS, diagStartQpc, BK_DIAG_FLAG_SHUTDOWN, 0,
                   ComponentId);
    BkcrashRecordCheckpoint(SubsystemId, BkDiagEventShutdownOk, STATUS_SUCCESS, ComponentId);
}

static VOID BkdrvUninitializeByFlags(_In_ LONG InitFlags)
{
    if ((InitFlags & BK_INIT_ANTI_TAMPER) != 0)
    {
        BkdrvUninitializeSubsystem(BktmpSubsystemAntiTamper, BkatUninitialize, BK_DIAG_COMPONENT_ANTI_TAMPER);
    }
    if ((InitFlags & BK_INIT_ENDPOINT_GUARD) != 0)
    {
        BkdrvUninitializeSubsystem(BktmpSubsystemDriver, BkwfpEndpointGuardUninitialize,
                                   BK_DIAG_COMPONENT_WFP_ENDPOINT_GUARD);
    }
    if ((InitFlags & BK_INIT_HANDLE_MONITOR) != 0)
    {
        BkdrvUninitializeSubsystem(BktmpSubsystemHandleMonitor, BkchdlUninitialize, BK_DIAG_COMPONENT_HANDLE_MONITOR);
    }
    if ((InitFlags & BK_INIT_APC_MONITOR) != 0)
    {
        BkdrvUninitializeSubsystem(BktmpSubsystemApcMonitor, BkapcUninitialize, BK_DIAG_COMPONENT_APC_MONITOR);
    }
    if ((InitFlags & BK_INIT_THREAD_MONITOR) != 0)
    {
        BkdrvUninitializeSubsystem(BktmpSubsystemThreadMonitor, BkcthrUninitialize, BK_DIAG_COMPONENT_THREAD_MONITOR);
    }
    if ((InitFlags & BK_INIT_FILESYSTEM_MONITOR) != 0)
    {
        BkdrvUninitializeSubsystem(BktmpSubsystemFileSystemMonitor, BkcfsUninitialize,
                                   BK_DIAG_COMPONENT_FILESYSTEM_MONITOR);
    }
    if ((InitFlags & BK_INIT_NTAPI_MONITOR) != 0)
    {
        BkdrvUninitializeSubsystem(BktmpSubsystemNtApiMonitor, BkntkiMonitorUninitialize,
                                   BK_DIAG_COMPONENT_NTAPI_MONITOR);
    }
    if ((InitFlags & BK_INIT_REGISTRY_MONITOR) != 0)
    {
        BkdrvUninitializeSubsystem(BktmpSubsystemRegistryMonitor, BkcregUninitialize,
                                   BK_DIAG_COMPONENT_REGISTRY_MONITOR);
    }
    if ((InitFlags & BK_INIT_IMAGE_MONITOR) != 0)
    {
        BkdrvUninitializeSubsystem(BktmpSubsystemImageMonitor, BkcimgUninitialize, BK_DIAG_COMPONENT_IMAGE_MONITOR);
    }
    if ((InitFlags & BK_INIT_PROCESS_MONITOR) != 0)
    {
        BkdrvUninitializeSubsystem(BktmpSubsystemProcessMonitor, BkcprocUninitialize,
                                   BK_DIAG_COMPONENT_PROCESS_MONITOR);
    }
    if ((InitFlags & BK_INIT_CORRELATION) != 0)
    {
        BkdrvUninitializeSubsystem(BktmpSubsystemCorrelation, BkcorUninitialize, BK_DIAG_COMPONENT_CORRELATION);
    }
    if ((InitFlags & BK_INIT_HOLLOWING_ENGINE) != 0)
    {
        BkdrvUninitializeSubsystem(BktmpSubsystemHollowingEngine, BkhloEngineUninitialize,
                                   BK_DIAG_COMPONENT_HOLLOWING_ENGINE);
    }
    if ((InitFlags & BK_INIT_BUGCHECK_MONITOR) != 0)
    {
        BkdrvUninitializeSubsystem(BktmpSubsystemDriver, BkbugUninitialize, BK_DIAG_COMPONENT_BUGCHECK_MONITOR);
    }
    if ((InitFlags & BK_INIT_CONTROL) != 0)
    {
        BkdrvUninitializeSubsystem(BktmpSubsystemControl, BkctlUninitialize, BK_DIAG_COMPONENT_CONTROL);
    }
    if ((InitFlags & BK_INIT_ETW) != 0)
    {
        BkdrvUninitializeSubsystem(BktmpSubsystemEtw, BketwUninitialize, BK_DIAG_COMPONENT_ETW);
    }
}

static VOID BkdrvRecordSelfCheck(_In_ UINT32 SubsystemId, _In_ BOOLEAN Ok, _In_ UINT32 ComponentId)
{
    BkdiagRecord(SubsystemId, Ok ? BkDiagEventConfirmedOnline : BkDiagEventSelfCheckFailed,
                 Ok ? STATUS_SUCCESS : STATUS_DEVICE_CONFIGURATION_ERROR, 0,
                 BK_DIAG_FLAG_SELF_CHECK | (Ok ? 0 : BK_DIAG_FLAG_FAILURE), 0, ComponentId);
    if (Ok)
    {
        BKDRV_LOG_COMPONENT(DPFLTR_INFO_LEVEL, ComponentId, "BK: online ss=%lu comp=%lu.\n", SubsystemId, ComponentId);
    }
    else
    {
        BKDRV_LOG_COMPONENT(DPFLTR_ERROR_LEVEL, ComponentId, "BK: offline ss=%lu comp=%lu status=0x%08X.\n",
                            SubsystemId, ComponentId, STATUS_DEVICE_CONFIGURATION_ERROR);
    }
}

static VOID BkdrvRecordSubsystemSelfChecks(VOID)
{
    BkdrvRecordSelfCheck(BktmpSubsystemControl, BkctlSelfCheck(), BK_DIAG_COMPONENT_CONTROL);
    BkdrvRecordSelfCheck(BktmpSubsystemEtw, BketwSelfCheck(), BK_DIAG_COMPONENT_ETW);
    BkdrvRecordSelfCheck(BktmpSubsystemHandleMonitor, BkchdlSelfCheck(), BK_DIAG_COMPONENT_HANDLE_MONITOR);
    BkdrvRecordSelfCheck(BktmpSubsystemThreadMonitor, BkcthrSelfCheck(), BK_DIAG_COMPONENT_THREAD_MONITOR);
    BkdrvRecordSelfCheck(BktmpSubsystemProcessMonitor, BkcprocSelfCheck(), BK_DIAG_COMPONENT_PROCESS_MONITOR);
    BkdrvRecordSelfCheck(BktmpSubsystemImageMonitor, BkcimgSelfCheck(), BK_DIAG_COMPONENT_IMAGE_MONITOR);
    BkdrvRecordSelfCheck(BktmpSubsystemRegistryMonitor, BkcregSelfCheck(), BK_DIAG_COMPONENT_REGISTRY_MONITOR);
    BkdrvRecordSelfCheck(BktmpSubsystemFileSystemMonitor, BkcfsSelfCheck(), BK_DIAG_COMPONENT_FILESYSTEM_MONITOR);
    BkdrvRecordSelfCheck(BktmpSubsystemApcMonitor, BkapcSelfCheck(), BK_DIAG_COMPONENT_APC_MONITOR);
    BkdrvRecordSelfCheck(BktmpSubsystemCorrelation, BkcorSelfCheck(), BK_DIAG_COMPONENT_CORRELATION);
    BkdrvRecordSelfCheck(BktmpSubsystemHollowingEngine, BkhloEngineSelfCheck(), BK_DIAG_COMPONENT_HOLLOWING_ENGINE);
    BkdrvRecordSelfCheck(BktmpSubsystemNtApiMonitor, BkntkiMonitorSelfCheck(), BK_DIAG_COMPONENT_NTAPI_MONITOR);
#if BK_ENABLE_BUGCHECK_MONITOR
    BkdrvRecordSelfCheck(BktmpSubsystemDriver, BkbugSelfCheck(), BK_DIAG_COMPONENT_BUGCHECK_MONITOR);
#endif
    BkdrvRecordSelfCheck(BktmpSubsystemAntiTamper, BkatSelfCheck(), BK_DIAG_COMPONENT_ANTI_TAMPER);
    BkdrvRecordSelfCheck(BktmpSubsystemDriver, BkdiagSelfCheck(), BK_DIAG_COMPONENT_DIAGNOSTICS);
#if BK_ENABLE_WFP_ENDPOINT_GUARD
    BkdrvRecordSelfCheck(BktmpSubsystemDriver, BkwfpEndpointGuardSelfCheck(), BK_DIAG_COMPONENT_WFP_ENDPOINT_GUARD);
#endif
}

static ULONGLONG BkdrvBeginSubsystemInit(_In_ UINT32 SubsystemId, _In_ UINT32 ComponentId)
{
    BkcrashRecordCheckpoint(SubsystemId, BkDiagEventInitBegin, STATUS_PENDING, ComponentId);
    BKDRV_LOG_COMPONENT(DPFLTR_INFO_LEVEL, ComponentId, "BK: init-begin ss=%lu comp=%lu.\n", SubsystemId, ComponentId);
    return BkdiagBegin(SubsystemId, BkDiagEventInitBegin, ComponentId);
}

static VOID BkdrvCompleteSubsystemInit(_In_ UINT32 SubsystemId, _In_ NTSTATUS Status, _In_ ULONGLONG StartQpc,
                                       _In_ UINT32 ComponentId)
{
    BOOLEAN ok = NT_SUCCESS(Status);
    UINT64 elapsedUs = BkdrvElapsedMicroseconds(StartQpc);

    BkdiagComplete(SubsystemId, ok ? BkDiagEventInitOk : BkDiagEventInitFailed, Status, StartQpc,
                   ok ? 0 : BK_DIAG_FLAG_FAILURE, 0, ComponentId);
    BkcrashRecordCheckpoint(SubsystemId, ok ? BkDiagEventInitOk : BkDiagEventInitFailed, Status, ComponentId);
    if (ok)
    {
        BKDRV_LOG_COMPONENT(DPFLTR_INFO_LEVEL, ComponentId, "BK: init-ok ss=%lu comp=%lu us=%I64u.\n", SubsystemId,
                            ComponentId, elapsedUs);
    }
    else
    {
        BKDRV_LOG_COMPONENT(DPFLTR_ERROR_LEVEL, ComponentId, "BK: init-fail ss=%lu comp=%lu status=0x%08X us=%I64u.\n",
                            SubsystemId, ComponentId, Status, elapsedUs);
    }
    if (ok)
    {
        BkdiagRecord(SubsystemId, BkDiagEventOnline, STATUS_SUCCESS, 0, 0, 0, ComponentId);
    }
}

static NTSTATUS BkdrvSelfTest(VOID)
{
    LONG flags;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    flags = InterlockedCompareExchange(&g_InitFlags, 0, 0);
    if ((flags & BK_INIT_REQUIRED_FLAGS) != BK_INIT_REQUIRED_FLAGS)
    {
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    if (InterlockedCompareExchange(&g_DriverState, 0, 0) != BkdrvStateInitializing)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    return STATUS_SUCCESS;
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

_Use_decl_annotations_ VOID BkdrvEvtUnload(WDFDRIVER Driver)
{
    ULONGLONG tempusStartQpc = 0;
    ULONGLONG diagStartQpc;
    ULONGLONG diagRuntimeStartQpc;
    LONG prevState;
    LONG initFlags;

    UNREFERENCED_PARAMETER(Driver);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        BKDRV_LOG(DPFLTR_ERROR_LEVEL, "BK: unload called at invalid IRQL=%lu.\n", KeGetCurrentIrql());
        return;
    }

    prevState = InterlockedExchange(&g_DriverState, BkdrvStateUnloading);
    BkcrashSetDriverState(BkdrvStateUnloading);
    if (prevState == BkdrvStateUnloading || prevState == BkdrvStateUnloaded)
    {
        return;
    }

    tempusStartQpc = BktmpEnter(BktmpSubsystemDriver);
    diagStartQpc = BkdiagBegin(BktmpSubsystemDriver, BkDiagEventShutdownBegin, BK_DIAG_COMPONENT_DRIVER_ENTRY);
    BkcrashRecordCheckpoint(BktmpSubsystemDriver, BkDiagEventShutdownBegin, STATUS_SUCCESS,
                            BK_DIAG_COMPONENT_DRIVER_ENTRY);
    BkctlBeginShutdown();
    initFlags = InterlockedExchange(&g_InitFlags, 0);
    BkcrashSetInitFlags(initFlags);
    BkdrvUninitializeByFlags(initFlags);
    BkcrashSetInitFlags(0);
    diagRuntimeStartQpc = BkdiagBegin(BktmpSubsystemDriver, BkDiagEventShutdownBegin, BK_DIAG_COMPONENT_RUNTIME_CONFIG);
    BkcrashRecordCheckpoint(BktmpSubsystemDriver, BkDiagEventShutdownBegin, STATUS_SUCCESS,
                            BK_DIAG_COMPONENT_RUNTIME_CONFIG);
    BkrtUninitialize();
    BkdiagComplete(BktmpSubsystemDriver, BkDiagEventShutdownOk, STATUS_SUCCESS, diagRuntimeStartQpc,
                   BK_DIAG_FLAG_SHUTDOWN, 0, BK_DIAG_COMPONENT_RUNTIME_CONFIG);
    BkcrashRecordCheckpoint(BktmpSubsystemDriver, BkDiagEventShutdownOk, STATUS_SUCCESS,
                            BK_DIAG_COMPONENT_RUNTIME_CONFIG);

    InterlockedExchange(&g_DriverState, BkdrvStateUnloaded);
    BkcrashSetDriverState(BkdrvStateUnloaded);
    BkdiagComplete(BktmpSubsystemDriver, BkDiagEventShutdownOk, STATUS_SUCCESS, diagStartQpc, BK_DIAG_FLAG_SHUTDOWN, 0,
                   BK_DIAG_COMPONENT_DRIVER_ENTRY);
    BkcrashRecordCheckpoint(BktmpSubsystemDriver, BkDiagEventShutdownOk, STATUS_SUCCESS,
                            BK_DIAG_COMPONENT_DRIVER_ENTRY);
    BktmpLeave(BktmpSubsystemDriver, tempusStartQpc);
    BktmpUninitialize();
    BkdiagUninitialize();
    BkcrashUninitialize();

    BKDRV_LOG(DPFLTR_INFO_LEVEL, "BK: EvtDriverUnload invoked.\n");
}

_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    ULONGLONG tempusStartQpc = 0;
    ULONGLONG diagDriverStartQpc = 0;
    ULONGLONG diagSubsystemStartQpc = 0;
    LONG expectedState;
    LONG initFlags;
    NTSTATUS status;
    NTSTATUS crashStatus;
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    expectedState = InterlockedCompareExchange(&g_DriverState, BkdrvStateInitializing, BkdrvStateCold);
    if (expectedState != BkdrvStateCold)
    {
        return STATUS_ALREADY_REGISTERED;
    }

    BKDRV_LOG(DPFLTR_INFO_LEVEL, "BK: DriverEntry invoked.\n");

    InterlockedExchange(&g_InitFlags, 0);
    (void)BkdiagInitialize();
    crashStatus = BkcrashInitialize(DriverObject, RegistryPath);
    BkcrashSetDriverState(BkdrvStateInitializing);
    BkcrashSetInitFlags(0);
    diagDriverStartQpc = BkdiagBegin(BktmpSubsystemDriver, BkDiagEventInitBegin, BK_DIAG_COMPONENT_DRIVER_ENTRY);
    BkcrashRecordCheckpoint(BktmpSubsystemDriver, BkDiagEventInitBegin, STATUS_PENDING, BK_DIAG_COMPONENT_DRIVER_ENTRY);
    if (!NT_SUCCESS(crashStatus))
    {
        BkdiagRecord(BktmpSubsystemDriver, BkDiagEventDegradedContinuing, crashStatus, 0, BK_DIAG_FLAG_CONTINUING, 0,
                     BK_DIAG_COMPONENT_DIAGNOSTICS);
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = BkdrvEvtUnload;

    status = WdfDriverCreate(DriverObject, RegistryPath, &attributes, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status))
    {
        BkdiagComplete(BktmpSubsystemDriver, BkDiagEventInitFailed, status, diagDriverStartQpc, BK_DIAG_FLAG_FAILURE, 0,
                       BK_DIAG_COMPONENT_DRIVER_ENTRY);
        BKDRV_LOG(DPFLTR_ERROR_LEVEL, "BK: WdfDriverCreate failed (0x%08X).\n", status);
        goto ExitFailure;
    }

    (void)BktmpInitialize();
    tempusStartQpc = BktmpEnter(BktmpSubsystemDriver);

    diagSubsystemStartQpc = BkdrvBeginSubsystemInit(BktmpSubsystemDriver, BK_DIAG_COMPONENT_RUNTIME_CONFIG);
    status = BkrtInitialize(RegistryPath);
    BkdrvCompleteSubsystemInit(BktmpSubsystemDriver, status, diagSubsystemStartQpc, BK_DIAG_COMPONENT_RUNTIME_CONFIG);
    if (!NT_SUCCESS(status))
    {
        BKDRV_LOG(DPFLTR_ERROR_LEVEL, "BK: runtime config init failed (0x%08X).\n", status);
        goto ExitFailure;
    }

    diagSubsystemStartQpc = BkdrvBeginSubsystemInit(BktmpSubsystemEtw, BK_DIAG_COMPONENT_ETW);
    status = BketwInitialize();
    BkdrvCompleteSubsystemInit(BktmpSubsystemEtw, status, diagSubsystemStartQpc, BK_DIAG_COMPONENT_ETW);
    if (!NT_SUCCESS(status))
    {
        BKDRV_LOG(DPFLTR_ERROR_LEVEL, "BK: ETW init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    BkdrvMarkInitializedFlag(BK_INIT_ETW);

    diagSubsystemStartQpc = BkdrvBeginSubsystemInit(BktmpSubsystemControl, BK_DIAG_COMPONENT_CONTROL);
    status = BkctlInitialize(WdfGetDriver());
    BkdrvCompleteSubsystemInit(BktmpSubsystemControl, status, diagSubsystemStartQpc, BK_DIAG_COMPONENT_CONTROL);
    if (!NT_SUCCESS(status))
    {
        BKDRV_LOG(DPFLTR_ERROR_LEVEL, "BK: control plane init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    BkdrvMarkInitializedFlag(BK_INIT_CONTROL);

    diagSubsystemStartQpc = BkdrvBeginSubsystemInit(BktmpSubsystemCorrelation, BK_DIAG_COMPONENT_CORRELATION);
    status = BkcorInitialize();
    BkdrvCompleteSubsystemInit(BktmpSubsystemCorrelation, status, diagSubsystemStartQpc, BK_DIAG_COMPONENT_CORRELATION);
    if (!NT_SUCCESS(status))
    {
        BKDRV_LOG(DPFLTR_ERROR_LEVEL, "BK: correlation init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    BkdrvMarkInitializedFlag(BK_INIT_CORRELATION);

    diagSubsystemStartQpc = BkdrvBeginSubsystemInit(BktmpSubsystemHollowingEngine, BK_DIAG_COMPONENT_HOLLOWING_ENGINE);
    status = BkhloEngineInitialize();
    BkdrvCompleteSubsystemInit(BktmpSubsystemHollowingEngine, status, diagSubsystemStartQpc,
                               BK_DIAG_COMPONENT_HOLLOWING_ENGINE);
    if (!NT_SUCCESS(status))
    {
        BKDRV_LOG(DPFLTR_ERROR_LEVEL, "BK: hollowing engine init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    BkdrvMarkInitializedFlag(BK_INIT_HOLLOWING_ENGINE);

    diagSubsystemStartQpc = BkdrvBeginSubsystemInit(BktmpSubsystemApcMonitor, BK_DIAG_COMPONENT_APC_MONITOR);
    status = BkapcInitialize();
    BkdrvCompleteSubsystemInit(BktmpSubsystemApcMonitor, status, diagSubsystemStartQpc, BK_DIAG_COMPONENT_APC_MONITOR);
    if (!NT_SUCCESS(status))
    {
        BKDRV_LOG(DPFLTR_ERROR_LEVEL, "BK: apc monitor init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    BkdrvMarkInitializedFlag(BK_INIT_APC_MONITOR);

    diagSubsystemStartQpc = BkdrvBeginSubsystemInit(BktmpSubsystemProcessMonitor, BK_DIAG_COMPONENT_PROCESS_MONITOR);
    status = BkcprocInitialize();
    BkdrvCompleteSubsystemInit(BktmpSubsystemProcessMonitor, status, diagSubsystemStartQpc,
                               BK_DIAG_COMPONENT_PROCESS_MONITOR);
    if (!NT_SUCCESS(status))
    {
        BKDRV_LOG(DPFLTR_ERROR_LEVEL, "BK: process monitor init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    BkdrvMarkInitializedFlag(BK_INIT_PROCESS_MONITOR);

    diagSubsystemStartQpc = BkdrvBeginSubsystemInit(BktmpSubsystemImageMonitor, BK_DIAG_COMPONENT_IMAGE_MONITOR);
    status = BkcimgInitialize();
    BkdrvCompleteSubsystemInit(BktmpSubsystemImageMonitor, status, diagSubsystemStartQpc,
                               BK_DIAG_COMPONENT_IMAGE_MONITOR);
    if (!NT_SUCCESS(status))
    {
        BKDRV_LOG(DPFLTR_ERROR_LEVEL, "BK: image monitor init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    BkdrvMarkInitializedFlag(BK_INIT_IMAGE_MONITOR);

    diagSubsystemStartQpc = BkdrvBeginSubsystemInit(BktmpSubsystemRegistryMonitor, BK_DIAG_COMPONENT_REGISTRY_MONITOR);
    status = BkcregInitialize(DriverObject);
    BkdrvCompleteSubsystemInit(BktmpSubsystemRegistryMonitor, status, diagSubsystemStartQpc,
                               BK_DIAG_COMPONENT_REGISTRY_MONITOR);
    if (!NT_SUCCESS(status))
    {
        BKDRV_LOG(DPFLTR_ERROR_LEVEL, "BK: registry monitor init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    BkdrvMarkInitializedFlag(BK_INIT_REGISTRY_MONITOR);

    diagSubsystemStartQpc = BkdrvBeginSubsystemInit(BktmpSubsystemThreadMonitor, BK_DIAG_COMPONENT_THREAD_MONITOR);
    status = BkcthrInitialize();
    BkdrvCompleteSubsystemInit(BktmpSubsystemThreadMonitor, status, diagSubsystemStartQpc,
                               BK_DIAG_COMPONENT_THREAD_MONITOR);
    if (!NT_SUCCESS(status))
    {
        BKDRV_LOG(DPFLTR_ERROR_LEVEL, "BK: thread monitor init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    BkdrvMarkInitializedFlag(BK_INIT_THREAD_MONITOR);

    diagSubsystemStartQpc =
        BkdrvBeginSubsystemInit(BktmpSubsystemFileSystemMonitor, BK_DIAG_COMPONENT_FILESYSTEM_MONITOR);
    status = BkcfsInitialize(DriverObject);
    BkdrvCompleteSubsystemInit(BktmpSubsystemFileSystemMonitor, status, diagSubsystemStartQpc,
                               BK_DIAG_COMPONENT_FILESYSTEM_MONITOR);
    if (!NT_SUCCESS(status))
    {
        BKDRV_LOG(DPFLTR_ERROR_LEVEL, "BK: filesystem monitor init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    BkdrvMarkInitializedFlag(BK_INIT_FILESYSTEM_MONITOR);

    diagSubsystemStartQpc = BkdrvBeginSubsystemInit(BktmpSubsystemHandleMonitor, BK_DIAG_COMPONENT_HANDLE_MONITOR);
    status = BkchdlInitialize();
    BkdrvCompleteSubsystemInit(BktmpSubsystemHandleMonitor, status, diagSubsystemStartQpc,
                               BK_DIAG_COMPONENT_HANDLE_MONITOR);
    if (!NT_SUCCESS(status))
    {
        BKDRV_LOG(DPFLTR_ERROR_LEVEL, "BK: handle monitor init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    BkdrvMarkInitializedFlag(BK_INIT_HANDLE_MONITOR);

    diagSubsystemStartQpc = BkdrvBeginSubsystemInit(BktmpSubsystemNtApiMonitor, BK_DIAG_COMPONENT_NTAPI_MONITOR);
    status = BkntkiMonitorInitialize();
    BkdrvCompleteSubsystemInit(BktmpSubsystemNtApiMonitor, status, diagSubsystemStartQpc,
                               BK_DIAG_COMPONENT_NTAPI_MONITOR);
    if (!NT_SUCCESS(status))
    {
        BKDRV_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi monitor init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    BkdrvMarkInitializedFlag(BK_INIT_NTAPI_MONITOR);

    diagSubsystemStartQpc = BkdrvBeginSubsystemInit(BktmpSubsystemDriver, BK_DIAG_COMPONENT_BUGCHECK_MONITOR);
    status = BkbugInitialize();
    BkdrvCompleteSubsystemInit(BktmpSubsystemDriver, status, diagSubsystemStartQpc, BK_DIAG_COMPONENT_BUGCHECK_MONITOR);
    if (!NT_SUCCESS(status))
    {
        BKDRV_LOG(DPFLTR_WARNING_LEVEL, "BK: optional bugcheck monitor unavailable (0x%08X); continuing.\n", status);
        BkdiagRecord(BktmpSubsystemDriver, BkDiagEventDegradedContinuing, status, 0,
                     BK_DIAG_FLAG_OPTIONAL | BK_DIAG_FLAG_CONTINUING, 0, BK_DIAG_COMPONENT_BUGCHECK_MONITOR);
    }
    else
    {
        BkdrvMarkInitializedFlag(BK_INIT_BUGCHECK_MONITOR);
    }

    diagSubsystemStartQpc = BkdrvBeginSubsystemInit(BktmpSubsystemDriver, BK_DIAG_COMPONENT_WFP_ENDPOINT_GUARD);
    status = BkwfpEndpointGuardInitialize();
    BkdrvCompleteSubsystemInit(BktmpSubsystemDriver, status, diagSubsystemStartQpc,
                               BK_DIAG_COMPONENT_WFP_ENDPOINT_GUARD);
    if (!NT_SUCCESS(status))
    {
        BKDRV_LOG(DPFLTR_WARNING_LEVEL, "BK: optional WFP endpoint guard unavailable (0x%08X); continuing.\n", status);
        BkdiagRecord(BktmpSubsystemDriver, BkDiagEventDegradedContinuing, status, 0,
                     BK_DIAG_FLAG_OPTIONAL | BK_DIAG_FLAG_CONTINUING, 0, BK_DIAG_COMPONENT_WFP_ENDPOINT_GUARD);
    }
    else
    {
        BkdrvMarkInitializedFlag(BK_INIT_ENDPOINT_GUARD);
    }

    diagSubsystemStartQpc = BkdrvBeginSubsystemInit(BktmpSubsystemAntiTamper, BK_DIAG_COMPONENT_ANTI_TAMPER);
    status = BkatInitialize(DriverObject);
    BkdrvCompleteSubsystemInit(BktmpSubsystemAntiTamper, status, diagSubsystemStartQpc, BK_DIAG_COMPONENT_ANTI_TAMPER);
    if (!NT_SUCCESS(status))
    {
        BKDRV_LOG(DPFLTR_ERROR_LEVEL, "BK: anti tamper init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    BkdrvMarkInitializedFlag(BK_INIT_ANTI_TAMPER);

    status = BkdrvSelfTest();
    if (!NT_SUCCESS(status))
    {
        goto ExitFailure;
    }

    BkdrvRecordSubsystemSelfChecks();
    InterlockedExchange(&g_DriverState, BkdrvStateInitialized);
    BkcrashSetDriverState(BkdrvStateInitialized);
    initFlags = InterlockedCompareExchange(&g_InitFlags, 0, 0);
    BKDRV_LOG(DPFLTR_INFO_LEVEL, "BK: init-summary state=%ld flags=0x%08lX required=0x%08lX.\n", BkdrvStateInitialized,
              initFlags, BK_INIT_REQUIRED_FLAGS);
    BkdiagComplete(BktmpSubsystemDriver, BkDiagEventInitOk, STATUS_SUCCESS, diagDriverStartQpc, 0, 0,
                   BK_DIAG_COMPONENT_DRIVER_ENTRY);
    BkcrashRecordCheckpoint(BktmpSubsystemDriver, BkDiagEventInitOk, STATUS_SUCCESS, BK_DIAG_COMPONENT_DRIVER_ENTRY);
    BkdiagRecord(BktmpSubsystemDriver, BkDiagEventOnline, STATUS_SUCCESS, 0, 0, 0, BK_DIAG_COMPONENT_DRIVER_ENTRY);
    BkdiagRecord(BktmpSubsystemDriver, BkDiagEventConfirmedOnline, STATUS_SUCCESS, 0, BK_DIAG_FLAG_SELF_CHECK, 0,
                 BK_DIAG_COMPONENT_DRIVER_ENTRY);
    BktmpLeave(BktmpSubsystemDriver, tempusStartQpc);
    BKDRV_LOG(DPFLTR_INFO_LEVEL, "BK: Driver initialized.\n");
    return STATUS_SUCCESS;

ExitFailure:
    if (diagDriverStartQpc != 0)
    {
        BkdiagComplete(BktmpSubsystemDriver, BkDiagEventInitFailed, status, diagDriverStartQpc, BK_DIAG_FLAG_FAILURE, 0,
                       BK_DIAG_COMPONENT_DRIVER_ENTRY);
    }
    initFlags = InterlockedExchange(&g_InitFlags, 0);
    BkcrashSetInitFlags(initFlags);
    BkdrvUninitializeByFlags(initFlags);
    BkcrashSetInitFlags(0);
    diagSubsystemStartQpc =
        BkdiagBegin(BktmpSubsystemDriver, BkDiagEventShutdownBegin, BK_DIAG_COMPONENT_RUNTIME_CONFIG);
    BkcrashRecordCheckpoint(BktmpSubsystemDriver, BkDiagEventShutdownBegin, STATUS_SUCCESS,
                            BK_DIAG_COMPONENT_RUNTIME_CONFIG);
    BkrtUninitialize();
    BkdiagComplete(BktmpSubsystemDriver, BkDiagEventShutdownOk, STATUS_SUCCESS, diagSubsystemStartQpc,
                   BK_DIAG_FLAG_SHUTDOWN, 0, BK_DIAG_COMPONENT_RUNTIME_CONFIG);
    BkcrashRecordCheckpoint(BktmpSubsystemDriver, BkDiagEventShutdownOk, STATUS_SUCCESS,
                            BK_DIAG_COMPONENT_RUNTIME_CONFIG);
    InterlockedExchange(&g_DriverState, BkdrvStateCold);
    BkcrashSetDriverState(BkdrvStateCold);
    if (tempusStartQpc != 0)
    {
        BktmpLeave(BktmpSubsystemDriver, tempusStartQpc);
        BktmpUninitialize();
    }
    BkdiagUninitialize();
    BkcrashUninitialize();
    return status;
}
