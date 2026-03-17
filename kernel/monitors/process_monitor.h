#ifndef BLACKBIRD_PROCESS_MONITOR_H
#define BLACKBIRD_PROCESS_MONITOR_H

#include <ntdef.h>

NTSTATUS
BLACKBIRDProcessMonitorInitialize(VOID);

VOID BLACKBIRDProcessMonitorUninitialize(VOID);

BOOLEAN
BLACKBIRDProcessMonitorSelfCheck(VOID);

#endif

