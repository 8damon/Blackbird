#include <ntddk.h>
#include <wdf.h>
#include "control.h"
#include "tempus_debug.h"
#include "runtime_config.h"
#include "..\telemetry\etw.h"
#include "..\monitors\handle_monitor.h"
#include "..\monitors\apc_monitor.h"
#include "..\monitors\anti_tamper.h"
#include "..\monitors\image_monitor.h"
#include "..\monitors\process_monitor.h"
#include "..\monitors\registry_monitor.h"
#include "..\monitors\thread_monitor.h"
#include "..\monitors\filesystem_monitor.h"
#include "..\hooks\monitor\ntapi_monitor.h"
#include "..\correlation\intent_store.h"
#include "..\correlation\hollowing_engine.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD BLACKBIRDEvtDriverUnload;

typedef enum _BLACKBIRD_DRIVER_STATE
{
    BLACKBIRDStateCold = 0,
    BLACKBIRDStateInitializing,
    BLACKBIRDStateInitialized,
    BLACKBIRDStateUnloading,
    BLACKBIRDStateUnloaded
} BLACKBIRD_DRIVER_STATE;

#define BLACKBIRD_INIT_THREAD_MONITOR 0x1
#define BLACKBIRD_INIT_HANDLE_MONITOR 0x2
#define BLACKBIRD_INIT_ETW 0x4
#define BLACKBIRD_INIT_CONTROL 0x8
#define BLACKBIRD_INIT_PROCESS_MONITOR 0x20
#define BLACKBIRD_INIT_IMAGE_MONITOR 0x40
#define BLACKBIRD_INIT_REGISTRY_MONITOR 0x80
#define BLACKBIRD_INIT_APC_MONITOR 0x100
#define BLACKBIRD_INIT_ANTI_TAMPER 0x200
#define BLACKBIRD_INIT_CORRELATION 0x400
#define BLACKBIRD_INIT_HOLLOWING_ENGINE 0x800
#define BLACKBIRD_INIT_FILESYSTEM_MONITOR 0x1000
#define BLACKBIRD_INIT_NTAPI_MONITOR 0x2000

static volatile LONG g_DriverState = BLACKBIRDStateCold;
static volatile LONG g_InitFlags = 0;

static VOID BLACKBIRDDriverUninitializeByFlags(_In_ LONG InitFlags)
{
    if ((InitFlags & BLACKBIRD_INIT_ANTI_TAMPER) != 0)
    {
        BLACKBIRDAntiTamperUninitialize();
    }
    if ((InitFlags & BLACKBIRD_INIT_HANDLE_MONITOR) != 0)
    {
        BLACKBIRDHandleMonitorUninitialize();
    }
    if ((InitFlags & BLACKBIRD_INIT_APC_MONITOR) != 0)
    {
        BLACKBIRDApcMonitorUninitialize();
    }
    if ((InitFlags & BLACKBIRD_INIT_THREAD_MONITOR) != 0)
    {
        BLACKBIRDThreadMonitorUninitialize();
    }
    if ((InitFlags & BLACKBIRD_INIT_FILESYSTEM_MONITOR) != 0)
    {
        BLACKBIRDFileSystemMonitorUninitialize();
    }
    if ((InitFlags & BLACKBIRD_INIT_NTAPI_MONITOR) != 0)
    {
        BLACKBIRDNtApiMonitorUninitialize();
    }
    if ((InitFlags & BLACKBIRD_INIT_REGISTRY_MONITOR) != 0)
    {
        BLACKBIRDRegistryMonitorUninitialize();
    }
    if ((InitFlags & BLACKBIRD_INIT_IMAGE_MONITOR) != 0)
    {
        BLACKBIRDImageMonitorUninitialize();
    }
    if ((InitFlags & BLACKBIRD_INIT_PROCESS_MONITOR) != 0)
    {
        BLACKBIRDProcessMonitorUninitialize();
    }
    if ((InitFlags & BLACKBIRD_INIT_CORRELATION) != 0)
    {
        BLACKBIRDCorrelationUninitialize();
    }
    if ((InitFlags & BLACKBIRD_INIT_HOLLOWING_ENGINE) != 0)
    {
        BLACKBIRDHollowingEngineUninitialize();
    }
    if ((InitFlags & BLACKBIRD_INIT_CONTROL) != 0)
    {
        BLACKBIRDControlUninitialize();
    }
    if ((InitFlags & BLACKBIRD_INIT_ETW) != 0)
    {
        BLACKBIRDEtwUninitialize();
    }
}

static NTSTATUS BLACKBIRDDriverSelfTest(VOID)
{
    LONG flags;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    flags = InterlockedCompareExchange(&g_InitFlags, 0, 0);
    if ((flags & BLACKBIRD_INIT_ETW) == 0 || (flags & BLACKBIRD_INIT_CONTROL) == 0 ||
        (flags & BLACKBIRD_INIT_APC_MONITOR) == 0 || (flags & BLACKBIRD_INIT_PROCESS_MONITOR) == 0 ||
        (flags & BLACKBIRD_INIT_IMAGE_MONITOR) == 0 || (flags & BLACKBIRD_INIT_REGISTRY_MONITOR) == 0 ||
        (flags & BLACKBIRD_INIT_THREAD_MONITOR) == 0 || (flags & BLACKBIRD_INIT_FILESYSTEM_MONITOR) == 0 ||
        (flags & BLACKBIRD_INIT_HANDLE_MONITOR) == 0 || (flags & BLACKBIRD_INIT_NTAPI_MONITOR) == 0 ||
        (flags & BLACKBIRD_INIT_ANTI_TAMPER) == 0 || (flags & BLACKBIRD_INIT_CORRELATION) == 0 ||
        (flags & BLACKBIRD_INIT_HOLLOWING_ENGINE) == 0)
    {
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    if (InterlockedCompareExchange(&g_DriverState, 0, 0) != BLACKBIRDStateInitializing)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    return STATUS_SUCCESS;
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

_Use_decl_annotations_ VOID BLACKBIRDEvtDriverUnload(WDFDRIVER Driver)
{
    ULONGLONG tempusStartQpc = BLACKBIRDTempusEnter(BlackbirdTempusSubsystemDriver);
    LONG prevState;
    LONG initFlags;

    UNREFERENCED_PARAMETER(Driver);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BLACKBIRD: unload called at invalid IRQL=%lu.\n",
                   KeGetCurrentIrql());
        return;
    }

    prevState = InterlockedExchange(&g_DriverState, BLACKBIRDStateUnloading);
    if (prevState == BLACKBIRDStateUnloading || prevState == BLACKBIRDStateUnloaded)
    {
        return;
    }

    BLACKBIRDControlBeginShutdown();
    initFlags = InterlockedExchange(&g_InitFlags, 0);
    BLACKBIRDDriverUninitializeByFlags(initFlags);
    BLACKBIRDRuntimeConfigUninitialize();

    InterlockedExchange(&g_DriverState, BLACKBIRDStateUnloaded);
    BLACKBIRDTempusUninitialize();
    BLACKBIRDTempusLeave(BlackbirdTempusSubsystemDriver, tempusStartQpc);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BLACKBIRD: EvtDriverUnload invoked.\n");
}

_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    ULONGLONG tempusStartQpc = 0;
    LONG expectedState;
    LONG initFlags;
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BLACKBIRD: DriverEntry invoked.\n");

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    expectedState = InterlockedCompareExchange(&g_DriverState, BLACKBIRDStateInitializing, BLACKBIRDStateCold);
    if (expectedState != BLACKBIRDStateCold)
    {
        return STATUS_ALREADY_REGISTERED;
    }

    InterlockedExchange(&g_InitFlags, 0);

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = BLACKBIRDEvtDriverUnload;

    status = WdfDriverCreate(DriverObject, RegistryPath, &attributes, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BLACKBIRD: WdfDriverCreate failed (0x%08X).\n", status);
        goto ExitFailure;
    }

    (void)BLACKBIRDTempusInitialize();
    tempusStartQpc = BLACKBIRDTempusEnter(BlackbirdTempusSubsystemDriver);

    status = BLACKBIRDRuntimeConfigInitialize(RegistryPath);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BLACKBIRD: runtime config init failed (0x%08X).\n",
                   status);
        goto ExitFailure;
    }

    status = BLACKBIRDEtwInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BLACKBIRD: ETW init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, BLACKBIRD_INIT_ETW);

    status = BLACKBIRDControlInitialize(WdfGetDriver());
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BLACKBIRD: control plane init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, BLACKBIRD_INIT_CONTROL);

    status = BLACKBIRDCorrelationInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BLACKBIRD: correlation init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, BLACKBIRD_INIT_CORRELATION);

    status = BLACKBIRDHollowingEngineInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BLACKBIRD: hollowing engine init failed (0x%08X).\n",
                   status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, BLACKBIRD_INIT_HOLLOWING_ENGINE);

    status = BLACKBIRDApcMonitorInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BLACKBIRD: apc monitor init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, BLACKBIRD_INIT_APC_MONITOR);

    status = BLACKBIRDProcessMonitorInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BLACKBIRD: process monitor init failed (0x%08X).\n",
                   status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, BLACKBIRD_INIT_PROCESS_MONITOR);

    status = BLACKBIRDImageMonitorInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BLACKBIRD: image monitor init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, BLACKBIRD_INIT_IMAGE_MONITOR);

    status = BLACKBIRDRegistryMonitorInitialize(DriverObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BLACKBIRD: registry monitor init failed (0x%08X).\n",
                   status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, BLACKBIRD_INIT_REGISTRY_MONITOR);

    status = BLACKBIRDThreadMonitorInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BLACKBIRD: thread monitor init failed (0x%08X).\n",
                   status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, BLACKBIRD_INIT_THREAD_MONITOR);

    status = BLACKBIRDFileSystemMonitorInitialize(DriverObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BLACKBIRD: filesystem monitor init failed (0x%08X).\n",
                   status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, BLACKBIRD_INIT_FILESYSTEM_MONITOR);

    status = BLACKBIRDHandleMonitorInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BLACKBIRD: handle monitor init failed (0x%08X).\n",
                   status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, BLACKBIRD_INIT_HANDLE_MONITOR);

    status = BLACKBIRDNtApiMonitorInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BLACKBIRD: ntapi monitor init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, BLACKBIRD_INIT_NTAPI_MONITOR);

    status = BLACKBIRDAntiTamperInitialize(DriverObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BLACKBIRD: anti tamper init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, BLACKBIRD_INIT_ANTI_TAMPER);

    status = BLACKBIRDDriverSelfTest();
    if (!NT_SUCCESS(status))
    {
        goto ExitFailure;
    }

    InterlockedExchange(&g_DriverState, BLACKBIRDStateInitialized);
    BLACKBIRDTempusLeave(BlackbirdTempusSubsystemDriver, tempusStartQpc);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BLACKBIRD: Driver initialized.\n");
    return STATUS_SUCCESS;

ExitFailure:
    initFlags = InterlockedExchange(&g_InitFlags, 0);
    BLACKBIRDDriverUninitializeByFlags(initFlags);
    BLACKBIRDRuntimeConfigUninitialize();
    InterlockedExchange(&g_DriverState, BLACKBIRDStateCold);
    BLACKBIRDTempusLeave(BlackbirdTempusSubsystemDriver, tempusStartQpc);
    BLACKBIRDTempusUninitialize();
    return status;
}
