#include <ntddk.h>
#include <wdf.h>
#include "control.h"
#include "..\telemetry\etw.h"
#include "..\monitors\handle_monitor.h"
#include "..\monitors\apc_monitor.h"
#include "..\monitors\anti_tamper.h"
#include "..\monitors\image_monitor.h"
#include "..\monitors\process_monitor.h"
#include "..\monitors\registry_monitor.h"
#include "..\monitors\thread_monitor.h"
#include "..\correlation\intent_store.h"
#include "..\correlation\hollowing_engine.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD SLEEPWALKEREvtDriverUnload;

typedef enum _SLEEPWALKER_DRIVER_STATE
{
    SLEEPWALKERStateCold = 0,
    SLEEPWALKERStateInitializing,
    SLEEPWALKERStateInitialized,
    SLEEPWALKERStateUnloading,
    SLEEPWALKERStateUnloaded
} SLEEPWALKER_DRIVER_STATE;

#define SLEEPWALKER_INIT_THREAD_MONITOR 0x1
#define SLEEPWALKER_INIT_HANDLE_MONITOR 0x2
#define SLEEPWALKER_INIT_ETW 0x4
#define SLEEPWALKER_INIT_CONTROL 0x8
#define SLEEPWALKER_INIT_PROCESS_MONITOR 0x20
#define SLEEPWALKER_INIT_IMAGE_MONITOR 0x40
#define SLEEPWALKER_INIT_REGISTRY_MONITOR 0x80
#define SLEEPWALKER_INIT_APC_MONITOR 0x100
#define SLEEPWALKER_INIT_ANTI_TAMPER 0x200
#define SLEEPWALKER_INIT_CORRELATION 0x400
#define SLEEPWALKER_INIT_HOLLOWING_ENGINE 0x800

static volatile LONG g_DriverState = SLEEPWALKERStateCold;
static volatile LONG g_InitFlags = 0;

static VOID SLEEPWALKERDriverUninitializeByFlags(_In_ LONG InitFlags)
{
    if ((InitFlags & SLEEPWALKER_INIT_ANTI_TAMPER) != 0)
    {
        SLEEPWALKERAntiTamperUninitialize();
    }
    if ((InitFlags & SLEEPWALKER_INIT_HANDLE_MONITOR) != 0)
    {
        SLEEPWALKERHandleMonitorUninitialize();
    }
    if ((InitFlags & SLEEPWALKER_INIT_APC_MONITOR) != 0)
    {
        SLEEPWALKERApcMonitorUninitialize();
    }
    if ((InitFlags & SLEEPWALKER_INIT_THREAD_MONITOR) != 0)
    {
        SLEEPWALKERThreadMonitorUninitialize();
    }
    if ((InitFlags & SLEEPWALKER_INIT_REGISTRY_MONITOR) != 0)
    {
        SLEEPWALKERRegistryMonitorUninitialize();
    }
    if ((InitFlags & SLEEPWALKER_INIT_IMAGE_MONITOR) != 0)
    {
        SLEEPWALKERImageMonitorUninitialize();
    }
    if ((InitFlags & SLEEPWALKER_INIT_PROCESS_MONITOR) != 0)
    {
        SLEEPWALKERProcessMonitorUninitialize();
    }
    if ((InitFlags & SLEEPWALKER_INIT_CORRELATION) != 0)
    {
        SLEEPWALKERCorrelationUninitialize();
    }
    if ((InitFlags & SLEEPWALKER_INIT_HOLLOWING_ENGINE) != 0)
    {
        SLEEPWALKERHollowingEngineUninitialize();
    }
    if ((InitFlags & SLEEPWALKER_INIT_CONTROL) != 0)
    {
        SLEEPWALKERControlUninitialize();
    }
    if ((InitFlags & SLEEPWALKER_INIT_ETW) != 0)
    {
        SLEEPWALKEREtwUninitialize();
    }
}

static NTSTATUS SLEEPWALKERDriverSelfTest(VOID)
{
    LONG flags;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    flags = InterlockedCompareExchange(&g_InitFlags, 0, 0);
    if ((flags & SLEEPWALKER_INIT_ETW) == 0 || (flags & SLEEPWALKER_INIT_CONTROL) == 0 ||
        (flags & SLEEPWALKER_INIT_APC_MONITOR) == 0 || (flags & SLEEPWALKER_INIT_PROCESS_MONITOR) == 0 ||
        (flags & SLEEPWALKER_INIT_IMAGE_MONITOR) == 0 || (flags & SLEEPWALKER_INIT_REGISTRY_MONITOR) == 0 ||
        (flags & SLEEPWALKER_INIT_THREAD_MONITOR) == 0 || (flags & SLEEPWALKER_INIT_HANDLE_MONITOR) == 0 ||
        (flags & SLEEPWALKER_INIT_ANTI_TAMPER) == 0 || (flags & SLEEPWALKER_INIT_CORRELATION) == 0 ||
        (flags & SLEEPWALKER_INIT_HOLLOWING_ENGINE) == 0)
    {
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    if (InterlockedCompareExchange(&g_DriverState, 0, 0) != SLEEPWALKERStateInitializing)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    return STATUS_SUCCESS;
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

_Use_decl_annotations_ VOID SLEEPWALKEREvtDriverUnload(WDFDRIVER Driver)
{
    LONG prevState;
    LONG initFlags;

    UNREFERENCED_PARAMETER(Driver);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SLEEPWALKER: unload called at invalid IRQL=%lu.\n",
                   KeGetCurrentIrql());
        return;
    }

    prevState = InterlockedExchange(&g_DriverState, SLEEPWALKERStateUnloading);
    if (prevState == SLEEPWALKERStateUnloading || prevState == SLEEPWALKERStateUnloaded)
    {
        return;
    }

    SLEEPWALKERControlBeginShutdown();
    initFlags = InterlockedExchange(&g_InitFlags, 0);
    SLEEPWALKERDriverUninitializeByFlags(initFlags);

    InterlockedExchange(&g_DriverState, SLEEPWALKERStateUnloaded);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "SLEEPWALKER: EvtDriverUnload invoked.\n");
}

_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    LONG expectedState;
    LONG initFlags;
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "SLEEPWALKER: DriverEntry invoked.\n");

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    expectedState = InterlockedCompareExchange(&g_DriverState, SLEEPWALKERStateInitializing, SLEEPWALKERStateCold);
    if (expectedState != SLEEPWALKERStateCold)
    {
        return STATUS_ALREADY_REGISTERED;
    }

    InterlockedExchange(&g_InitFlags, 0);

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = SLEEPWALKEREvtDriverUnload;

    status = WdfDriverCreate(DriverObject, RegistryPath, &attributes, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SLEEPWALKER: WdfDriverCreate failed (0x%08X).\n", status);
        goto ExitFailure;
    }

    status = SLEEPWALKEREtwInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SLEEPWALKER: ETW init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, SLEEPWALKER_INIT_ETW);

    status = SLEEPWALKERControlInitialize(WdfGetDriver());
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SLEEPWALKER: control plane init failed (0x%08X).\n",
                   status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, SLEEPWALKER_INIT_CONTROL);

    status = SLEEPWALKERCorrelationInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SLEEPWALKER: correlation init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, SLEEPWALKER_INIT_CORRELATION);

    status = SLEEPWALKERHollowingEngineInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SLEEPWALKER: hollowing engine init failed (0x%08X).\n",
                   status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, SLEEPWALKER_INIT_HOLLOWING_ENGINE);

    status = SLEEPWALKERApcMonitorInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SLEEPWALKER: apc monitor init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, SLEEPWALKER_INIT_APC_MONITOR);

    status = SLEEPWALKERProcessMonitorInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SLEEPWALKER: process monitor init failed (0x%08X).\n",
                   status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, SLEEPWALKER_INIT_PROCESS_MONITOR);

    status = SLEEPWALKERImageMonitorInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SLEEPWALKER: image monitor init failed (0x%08X).\n",
                   status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, SLEEPWALKER_INIT_IMAGE_MONITOR);

    status = SLEEPWALKERRegistryMonitorInitialize(DriverObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SLEEPWALKER: registry monitor init failed (0x%08X).\n",
                   status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, SLEEPWALKER_INIT_REGISTRY_MONITOR);

    status = SLEEPWALKERThreadMonitorInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SLEEPWALKER: thread monitor init failed (0x%08X).\n",
                   status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, SLEEPWALKER_INIT_THREAD_MONITOR);

    status = SLEEPWALKERHandleMonitorInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SLEEPWALKER: handle monitor init failed (0x%08X).\n",
                   status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, SLEEPWALKER_INIT_HANDLE_MONITOR);

    status = SLEEPWALKERAntiTamperInitialize(DriverObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SLEEPWALKER: anti tamper init failed (0x%08X).\n", status);
        goto ExitFailure;
    }
    InterlockedOr(&g_InitFlags, SLEEPWALKER_INIT_ANTI_TAMPER);

    status = SLEEPWALKERDriverSelfTest();
    if (!NT_SUCCESS(status))
    {
        goto ExitFailure;
    }

    InterlockedExchange(&g_DriverState, SLEEPWALKERStateInitialized);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "SLEEPWALKER: Driver initialized.\n");
    return STATUS_SUCCESS;

ExitFailure:
    initFlags = InterlockedExchange(&g_InitFlags, 0);
    SLEEPWALKERDriverUninitializeByFlags(initFlags);
    InterlockedExchange(&g_DriverState, SLEEPWALKERStateCold);
    return status;
}
