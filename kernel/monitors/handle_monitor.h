#ifndef BLACKBIRD_HANDLE_MONITOR_H
#define BLACKBIRD_HANDLE_MONITOR_H

#include <ntdef.h>

NTSTATUS
BLACKBIRDHandleMonitorInitialize(VOID);

VOID BLACKBIRDHandleMonitorUninitialize(VOID);

BOOLEAN
BLACKBIRDHandleMonitorSelfCheck(VOID);

#endif

