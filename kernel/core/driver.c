#include <ntddk.h>
#include <wdf.h>
#include "control.h"
#include "..\telemetry\etw.h"
#include "..\monitors\correlation.h"
#include "..\monitors\handle_monitor.h"
#include "..\monitors\apc_monitor.h"
#include "..\monitors\anti_tamper.h"
#include "..\monitors\image_monitor.h"
#include "..\monitors\process_monitor.h"
#include "..\monitors\registry_monitor.h"
#include "..\monitors\thread_monitor.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD STINGEREvtDriverUnload;

typedef enum _STINGER_DRIVER_STATE {
    STINGERStateCold = 0,
    STINGERStateInitializing,
    STINGERStateInitialized,
    STINGERStateUnloading,
    STINGERStateUnloaded
} STINGER_DRIVER_STATE;

#define STINGER_INIT_THREAD_MONITOR 0x1
#define STINGER_INIT_HANDLE_MONITOR 0x2
#define STINGER_INIT_ETW 0x4
#define STINGER_INIT_CONTROL 0x8
#define STINGER_INIT_CORRELATION 0x10
#define STINGER_INIT_PROCESS_MONITOR 0x20
#define STINGER_INIT_IMAGE_MONITOR 0x40
#define STINGER_INIT_REGISTRY_MONITOR 0x80
#define STINGER_INIT_APC_MONITOR 0x100
#define STINGER_INIT_ANTI_TAMPER 0x200

static volatile LONG g_DriverState = STINGERStateCold;
static volatile LONG g_InitFlags = 0;

static
NTSTATUS
STINGERDriverSelfTest(
    VOID
)
{
    LONG flags;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    flags = InterlockedCompareExchange(&g_InitFlags, 0, 0);
    if ((flags & STINGER_INIT_ETW) == 0 ||
        (flags & STINGER_INIT_CONTROL) == 0 ||
        (flags & STINGER_INIT_CORRELATION) == 0 ||
        (flags & STINGER_INIT_APC_MONITOR) == 0 ||
        (flags & STINGER_INIT_PROCESS_MONITOR) == 0 ||
        (flags & STINGER_INIT_IMAGE_MONITOR) == 0 ||
        (flags & STINGER_INIT_REGISTRY_MONITOR) == 0 ||
        (flags & STINGER_INIT_THREAD_MONITOR) == 0 ||
        (flags & STINGER_INIT_HANDLE_MONITOR) == 0 ||
        (flags & STINGER_INIT_ANTI_TAMPER) == 0) {
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    if (InterlockedCompareExchange(&g_DriverState, 0, 0) != STINGERStateInitializing) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    return STATUS_SUCCESS;
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

_Use_decl_annotations_
VOID
STINGEREvtDriverUnload(
    WDFDRIVER Driver
)
{
    LONG prevState;
    LONG initFlags;

    UNREFERENCED_PARAMETER(Driver);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "STINGER: unload called at invalid IRQL=%lu.\n",
            KeGetCurrentIrql()
        );
        return;
    }

    prevState = InterlockedExchange(&g_DriverState, STINGERStateUnloading);
    if (prevState == STINGERStateUnloading || prevState == STINGERStateUnloaded) {
        return;
    }

    initFlags = InterlockedExchange(&g_InitFlags, 0);
    if ((initFlags & STINGER_INIT_ANTI_TAMPER) != 0) {
        STINGERAntiTamperUninitialize();
    }
    if ((initFlags & STINGER_INIT_HANDLE_MONITOR) != 0) {
        STINGERHandleMonitorUninitialize();
    }
    if ((initFlags & STINGER_INIT_APC_MONITOR) != 0) {
        STINGERApcMonitorUninitialize();
    }
    if ((initFlags & STINGER_INIT_THREAD_MONITOR) != 0) {
        STINGERThreadMonitorUninitialize();
    }
    if ((initFlags & STINGER_INIT_REGISTRY_MONITOR) != 0) {
        STINGERRegistryMonitorUninitialize();
    }
    if ((initFlags & STINGER_INIT_IMAGE_MONITOR) != 0) {
        STINGERImageMonitorUninitialize();
    }
    if ((initFlags & STINGER_INIT_PROCESS_MONITOR) != 0) {
        STINGERProcessMonitorUninitialize();
    }
    if ((initFlags & STINGER_INIT_CORRELATION) != 0) {
        STINGERCorrelationUninitialize();
    }
    if ((initFlags & STINGER_INIT_ETW) != 0) {
        STINGEREtwUninitialize();
    }
    if ((initFlags & STINGER_INIT_CONTROL) != 0) {
        STINGERControlUninitialize();
    }

    InterlockedExchange(&g_DriverState, STINGERStateUnloaded);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "STINGER: EvtDriverUnload invoked.\n");
}

_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    LONG expectedState;
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "STINGER: DriverEntry invoked.\n");

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    expectedState = InterlockedCompareExchange(
        &g_DriverState,
        STINGERStateInitializing,
        STINGERStateCold
    );
    if (expectedState != STINGERStateCold) {
        return STATUS_ALREADY_REGISTERED;
    }

    InterlockedExchange(&g_InitFlags, 0);

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = STINGEREvtDriverUnload;

    status = WdfDriverCreate(DriverObject, RegistryPath, &attributes, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "STINGER: WdfDriverCreate failed (0x%08X).\n",
            status
        );
        InterlockedExchange(&g_DriverState, STINGERStateCold);
        return status;
    }

    status = STINGEREtwInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "STINGER: ETW init failed (0x%08X).\n",
            status
        );
        InterlockedExchange(&g_DriverState, STINGERStateCold);
        return status;
    }
    InterlockedOr(&g_InitFlags, STINGER_INIT_ETW);

    status = STINGERControlInitialize(WdfGetDriver());
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "STINGER: control plane init failed (0x%08X).\n",
            status
        );
        STINGEREtwUninitialize();
        InterlockedExchange(&g_InitFlags, 0);
        InterlockedExchange(&g_DriverState, STINGERStateCold);
        return status;
    }
    InterlockedOr(&g_InitFlags, STINGER_INIT_CONTROL);

    status = STINGERCorrelationInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "STINGER: correlation init failed (0x%08X).\n",
            status
        );
        STINGERControlUninitialize();
        STINGEREtwUninitialize();
        InterlockedExchange(&g_InitFlags, 0);
        InterlockedExchange(&g_DriverState, STINGERStateCold);
        return status;
    }
    InterlockedOr(&g_InitFlags, STINGER_INIT_CORRELATION);

    status = STINGERApcMonitorInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "STINGER: apc monitor init failed (0x%08X).\n",
            status
        );
        STINGERCorrelationUninitialize();
        STINGERControlUninitialize();
        STINGEREtwUninitialize();
        InterlockedExchange(&g_InitFlags, 0);
        InterlockedExchange(&g_DriverState, STINGERStateCold);
        return status;
    }
    InterlockedOr(&g_InitFlags, STINGER_INIT_APC_MONITOR);

    status = STINGERProcessMonitorInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "STINGER: process monitor init failed (0x%08X).\n",
            status
        );
        STINGERApcMonitorUninitialize();
        STINGERCorrelationUninitialize();
        STINGERControlUninitialize();
        STINGEREtwUninitialize();
        InterlockedExchange(&g_InitFlags, 0);
        InterlockedExchange(&g_DriverState, STINGERStateCold);
        return status;
    }
    InterlockedOr(&g_InitFlags, STINGER_INIT_PROCESS_MONITOR);

    status = STINGERImageMonitorInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "STINGER: image monitor init failed (0x%08X).\n",
            status
        );
        STINGERProcessMonitorUninitialize();
        STINGERApcMonitorUninitialize();
        STINGERCorrelationUninitialize();
        STINGERControlUninitialize();
        STINGEREtwUninitialize();
        InterlockedExchange(&g_InitFlags, 0);
        InterlockedExchange(&g_DriverState, STINGERStateCold);
        return status;
    }
    InterlockedOr(&g_InitFlags, STINGER_INIT_IMAGE_MONITOR);

    status = STINGERRegistryMonitorInitialize(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "STINGER: registry monitor init failed (0x%08X).\n",
            status
        );
        STINGERImageMonitorUninitialize();
        STINGERProcessMonitorUninitialize();
        STINGERApcMonitorUninitialize();
        STINGERCorrelationUninitialize();
        STINGERControlUninitialize();
        STINGEREtwUninitialize();
        InterlockedExchange(&g_InitFlags, 0);
        InterlockedExchange(&g_DriverState, STINGERStateCold);
        return status;
    }
    InterlockedOr(&g_InitFlags, STINGER_INIT_REGISTRY_MONITOR);

    status = STINGERThreadMonitorInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "STINGER: thread monitor init failed (0x%08X).\n",
            status
        );
        STINGERRegistryMonitorUninitialize();
        STINGERImageMonitorUninitialize();
        STINGERProcessMonitorUninitialize();
        STINGERApcMonitorUninitialize();
        STINGERCorrelationUninitialize();
        STINGERControlUninitialize();
        STINGEREtwUninitialize();
        InterlockedExchange(&g_InitFlags, 0);
        InterlockedExchange(&g_DriverState, STINGERStateCold);
        return status;
    }
    InterlockedOr(&g_InitFlags, STINGER_INIT_THREAD_MONITOR);

    status = STINGERHandleMonitorInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "STINGER: handle monitor init failed (0x%08X).\n",
            status
        );
        STINGERThreadMonitorUninitialize();
        STINGERRegistryMonitorUninitialize();
        STINGERImageMonitorUninitialize();
        STINGERProcessMonitorUninitialize();
        STINGERApcMonitorUninitialize();
        STINGERCorrelationUninitialize();
        STINGERControlUninitialize();
        STINGEREtwUninitialize();
        InterlockedExchange(&g_InitFlags, 0);
        InterlockedExchange(&g_DriverState, STINGERStateCold);
        return status;
    }
    InterlockedOr(&g_InitFlags, STINGER_INIT_HANDLE_MONITOR);

    status = STINGERAntiTamperInitialize(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "STINGER: anti tamper init failed (0x%08X).\n",
            status
        );
        STINGERHandleMonitorUninitialize();
        STINGERThreadMonitorUninitialize();
        STINGERRegistryMonitorUninitialize();
        STINGERImageMonitorUninitialize();
        STINGERProcessMonitorUninitialize();
        STINGERApcMonitorUninitialize();
        STINGERCorrelationUninitialize();
        STINGERControlUninitialize();
        STINGEREtwUninitialize();
        InterlockedExchange(&g_InitFlags, 0);
        InterlockedExchange(&g_DriverState, STINGERStateCold);
        return status;
    }
    InterlockedOr(&g_InitFlags, STINGER_INIT_ANTI_TAMPER);

    status = STINGERDriverSelfTest();
    if (!NT_SUCCESS(status)) {
        STINGERAntiTamperUninitialize();
        STINGERHandleMonitorUninitialize();
        STINGERThreadMonitorUninitialize();
        STINGERRegistryMonitorUninitialize();
        STINGERImageMonitorUninitialize();
        STINGERProcessMonitorUninitialize();
        STINGERApcMonitorUninitialize();
        STINGERCorrelationUninitialize();
        STINGERControlUninitialize();
        STINGEREtwUninitialize();
        InterlockedExchange(&g_InitFlags, 0);
        InterlockedExchange(&g_DriverState, STINGERStateCold);
        return status;
    }

    InterlockedExchange(&g_DriverState, STINGERStateInitialized);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "STINGER: Driver initialized.\n");
    return STATUS_SUCCESS;
}
