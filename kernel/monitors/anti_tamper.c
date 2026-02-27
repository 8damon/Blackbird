#include <ntddk.h>
#include "anti_tamper.h"
#include "handle_monitor.h"
#include "thread_monitor.h"
#include "process_monitor.h"
#include "image_monitor.h"
#include "registry_monitor.h"
#include "apc_monitor.h"
#include "correlation.h"
#include "..\core\control.h"
#include "..\telemetry\etw.h"

#define SLEEPWALKER_TAMPER_CHECK_PERIOD_MS 5000

#define SLEEPWALKER_TAMPER_MAJOR_FN_CHANGED 0x00000001
#define SLEEPWALKER_TAMPER_UNLOAD_CHANGED 0x00000002
#define SLEEPWALKER_TAMPER_FASTIO_CHANGED 0x00000004
#define SLEEPWALKER_TAMPER_OBJECT_TYPE_INVALID 0x00000008
#define SLEEPWALKER_TAMPER_OBJECT_SIZE_INVALID 0x00000010
#define SLEEPWALKER_TAMPER_EXTENSION_MISSING 0x00000020
#define SLEEPWALKER_TAMPER_CONTROL_INTEGRITY 0x00000040
#define SLEEPWALKER_TAMPER_ETW_INTEGRITY 0x00000080
#define SLEEPWALKER_TAMPER_IOCTL_DISPATCH_INVALID 0x00000100
#define SLEEPWALKER_TAMPER_MAJOR_PTR_INVALID 0x00000200
#define SLEEPWALKER_TAMPER_DRIVER_IMAGE_INVALID 0x00000400
#define SLEEPWALKER_TAMPER_CHECK_IRQL_INVALID 0x00000800
#define SLEEPWALKER_TAMPER_MONITOR_INTEGRITY 0x00001000

typedef struct _SLEEPWALKER_DISPATCH_SNAPSHOT
{
    PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
    PDRIVER_UNLOAD DriverUnload;
    PFAST_IO_DISPATCH FastIoDispatch;
    CSHORT Type;
    CSHORT Size;
} SLEEPWALKER_DISPATCH_SNAPSHOT;

static SLEEPWALKER_DISPATCH_SNAPSHOT g_Snapshot;
static PDRIVER_OBJECT g_DriverObject = NULL;
static KTIMER g_Timer;
static KDPC g_TimerDpc;
static WORK_QUEUE_ITEM g_WorkItem;
static volatile LONG g_WorkQueued = 0;
static volatile LONG g_Stopping = 0;
static volatile LONG g_Initialized = 0;
static volatile LONG g_LastTamperMask = 0;
static KEVENT g_WorkDrainEvent;

static BOOLEAN SLEEPWALKERIsKernelPointer(_In_opt_ PVOID Address)
{
    if (Address == NULL)
    {
        return FALSE;
    }

    return ((ULONG_PTR)Address >= (ULONG_PTR)MmSystemRangeStart);
}

static VOID SLEEPWALKERAntiTamperWorkRoutine(_In_ PVOID Context)
{
    PDRIVER_OBJECT driverObject;
    ULONG tamperMask = 0;
    UINT32 i;
    LONG prevMask;
    KIRQL irql = KeGetCurrentIrql();

    UNREFERENCED_PARAMETER(Context);

    driverObject = g_DriverObject;
    if (driverObject == NULL)
    {
        InterlockedExchange(&g_WorkQueued, 0);
        KeSetEvent(&g_WorkDrainEvent, IO_NO_INCREMENT, FALSE);
        return;
    }

    if (irql != PASSIVE_LEVEL)
    {
        tamperMask |= SLEEPWALKER_TAMPER_CHECK_IRQL_INVALID;
    }

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
    {
        if (driverObject->MajorFunction[i] != g_Snapshot.MajorFunction[i])
        {
            tamperMask |= SLEEPWALKER_TAMPER_MAJOR_FN_CHANGED;
        }
        if (!SLEEPWALKERIsKernelPointer((PVOID)driverObject->MajorFunction[i]))
        {
            tamperMask |= SLEEPWALKER_TAMPER_MAJOR_PTR_INVALID;
        }
    }

    if (!SLEEPWALKERIsKernelPointer((PVOID)driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]))
    {
        tamperMask |= SLEEPWALKER_TAMPER_IOCTL_DISPATCH_INVALID;
    }

    if (driverObject->DriverUnload != g_Snapshot.DriverUnload)
    {
        tamperMask |= SLEEPWALKER_TAMPER_UNLOAD_CHANGED;
    }
    if (driverObject->FastIoDispatch != g_Snapshot.FastIoDispatch)
    {
        tamperMask |= SLEEPWALKER_TAMPER_FASTIO_CHANGED;
    }
    if (driverObject->Type != g_Snapshot.Type)
    {
        tamperMask |= SLEEPWALKER_TAMPER_OBJECT_TYPE_INVALID;
    }
    if (driverObject->Size != g_Snapshot.Size)
    {
        tamperMask |= SLEEPWALKER_TAMPER_OBJECT_SIZE_INVALID;
    }
    if (driverObject->DriverExtension == NULL)
    {
        tamperMask |= SLEEPWALKER_TAMPER_EXTENSION_MISSING;
    }
    if (!SLEEPWALKERIsKernelPointer(driverObject->DriverStart) || driverObject->DriverSize == 0 ||
        driverObject->DriverSection == NULL || !SLEEPWALKERIsKernelPointer((PVOID)driverObject->DriverInit))
    {
        tamperMask |= SLEEPWALKER_TAMPER_DRIVER_IMAGE_INVALID;
    }
    if (!SLEEPWALKERControlSelfCheck())
    {
        tamperMask |= SLEEPWALKER_TAMPER_CONTROL_INTEGRITY;
    }
    if (!SLEEPWALKEREtwSelfCheck())
    {
        tamperMask |= SLEEPWALKER_TAMPER_ETW_INTEGRITY;
    }
    if (!SLEEPWALKERHandleMonitorSelfCheck() || !SLEEPWALKERThreadMonitorSelfCheck() ||
        !SLEEPWALKERProcessMonitorSelfCheck() || !SLEEPWALKERImageMonitorSelfCheck() ||
        !SLEEPWALKERRegistryMonitorSelfCheck() || !SLEEPWALKERApcMonitorSelfCheck() ||
        !SLEEPWALKERCorrelationSelfCheck())
    {
        tamperMask |= SLEEPWALKER_TAMPER_MONITOR_INTEGRITY;
    }

    prevMask = InterlockedExchange(&g_LastTamperMask, (LONG)tamperMask);
    if (prevMask != (LONG)tamperMask)
    {
        if (tamperMask != 0)
        {
            SLEEPWALKEREtwLogDetectionEvent("DRIVER_DISPATCH_OR_OBJECT_TAMPER", 5, PsGetCurrentProcessId(), NULL,
                                            tamperMask, 0, 0, L"driver dispatch/object integrity drift detected");
        }
        else if (prevMask != 0)
        {
            SLEEPWALKEREtwLogDetectionEvent("DRIVER_DISPATCH_OR_OBJECT_TAMPER_CLEARED", 2, PsGetCurrentProcessId(),
                                            NULL, 0, 0, 0,
                                            L"driver dispatch/object integrity returned to expected state");
        }
    }

    InterlockedExchange(&g_WorkQueued, 0);
    KeSetEvent(&g_WorkDrainEvent, IO_NO_INCREMENT, FALSE);
}

static VOID SLEEPWALKERAntiTamperTimerDpc(_In_ PKDPC Dpc, _In_opt_ PVOID DeferredContext,
                                          _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (InterlockedCompareExchange(&g_Stopping, 0, 0) != 0)
    {
        return;
    }

    if (InterlockedCompareExchange(&g_WorkQueued, 1, 0) == 0)
    {
        KeClearEvent(&g_WorkDrainEvent);
        ExQueueWorkItem(&g_WorkItem, DelayedWorkQueue);
    }
}

NTSTATUS
SLEEPWALKERAntiTamperInitialize(_In_ PDRIVER_OBJECT DriverObject)
{
    LARGE_INTEGER dueTime;
    UINT32 i;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (DriverObject == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0)
    {
        return STATUS_SUCCESS;
    }

    g_DriverObject = DriverObject;
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
    {
        g_Snapshot.MajorFunction[i] = DriverObject->MajorFunction[i];
    }
    g_Snapshot.DriverUnload = DriverObject->DriverUnload;
    g_Snapshot.FastIoDispatch = DriverObject->FastIoDispatch;
    g_Snapshot.Type = DriverObject->Type;
    g_Snapshot.Size = DriverObject->Size;

    InterlockedExchange(&g_Stopping, 0);
    InterlockedExchange(&g_WorkQueued, 0);
    InterlockedExchange(&g_LastTamperMask, 0);

    KeInitializeEvent(&g_WorkDrainEvent, NotificationEvent, TRUE);
    ExInitializeWorkItem(&g_WorkItem, SLEEPWALKERAntiTamperWorkRoutine, NULL);
    KeInitializeTimer(&g_Timer);
    KeInitializeDpc(&g_TimerDpc, SLEEPWALKERAntiTamperTimerDpc, NULL);

    dueTime.QuadPart = -(LONGLONG)SLEEPWALKER_TAMPER_CHECK_PERIOD_MS * 10000LL;
    KeSetTimerEx(&g_Timer, dueTime, SLEEPWALKER_TAMPER_CHECK_PERIOD_MS, &g_TimerDpc);
    return STATUS_SUCCESS;
}

VOID SLEEPWALKERAntiTamperUninitialize(VOID)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }
    if (InterlockedExchange(&g_Initialized, 0) == 0)
    {
        return;
    }

    InterlockedExchange(&g_Stopping, 1);
    KeCancelTimer(&g_Timer);

    if (InterlockedCompareExchange(&g_WorkQueued, 0, 0) != 0)
    {
        KeWaitForSingleObject(&g_WorkDrainEvent, Executive, KernelMode, FALSE, NULL);
    }

    RtlZeroMemory(&g_Snapshot, sizeof(g_Snapshot));
    g_DriverObject = NULL;
    InterlockedExchange(&g_LastTamperMask, 0);
    InterlockedExchange(&g_WorkQueued, 0);
}
