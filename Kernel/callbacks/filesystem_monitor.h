#ifndef BK_FILESYSTEM_MONITOR_H
#define BK_FILESYSTEM_MONITOR_H

#include <ntddk.h>

NTSTATUS
BkcfsInitialize(_In_ PDRIVER_OBJECT DriverObject);

VOID BkcfsUninitialize(VOID);

BOOLEAN
BkcfsSelfCheck(VOID);

#endif
