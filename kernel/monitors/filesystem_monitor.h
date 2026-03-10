#ifndef SLEEPWALKER_FILESYSTEM_MONITOR_H
#define SLEEPWALKER_FILESYSTEM_MONITOR_H

#include <ntddk.h>

NTSTATUS
SLEEPWALKERFileSystemMonitorInitialize(_In_ PDRIVER_OBJECT DriverObject);

VOID SLEEPWALKERFileSystemMonitorUninitialize(VOID);

BOOLEAN
SLEEPWALKERFileSystemMonitorSelfCheck(VOID);

#endif
