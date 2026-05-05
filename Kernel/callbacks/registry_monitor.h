#ifndef BK_REGISTRY_MONITOR_H
#define BK_REGISTRY_MONITOR_H

#include <ntddk.h>

NTSTATUS
BkcregInitialize(_In_ PDRIVER_OBJECT DriverObject);

VOID BkcregUninitialize(VOID);

BOOLEAN
BkcregSelfCheck(VOID);

#endif
