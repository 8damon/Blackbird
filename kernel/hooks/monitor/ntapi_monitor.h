#ifndef BLACKBIRD_NTAPI_MONITOR_H
#define BLACKBIRD_NTAPI_MONITOR_H

#include <ntdef.h>

NTSTATUS
BLACKBIRDNtApiMonitorInitialize(VOID);

VOID BLACKBIRDNtApiMonitorUninitialize(VOID);

BOOLEAN
BLACKBIRDNtApiMonitorSelfCheck(VOID);

#endif

