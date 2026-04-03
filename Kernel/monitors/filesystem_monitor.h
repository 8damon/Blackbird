#ifndef BLACKBIRD_FILESYSTEM_MONITOR_H
#define BLACKBIRD_FILESYSTEM_MONITOR_H

#include <ntddk.h>

NTSTATUS
BLACKBIRDFileSystemMonitorInitialize(_In_ PDRIVER_OBJECT DriverObject);

VOID BLACKBIRDFileSystemMonitorUninitialize(VOID);

BOOLEAN
BLACKBIRDFileSystemMonitorSelfCheck(VOID);

#endif
