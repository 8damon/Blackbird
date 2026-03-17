#ifndef BLACKBIRD_IMAGE_MONITOR_H
#define BLACKBIRD_IMAGE_MONITOR_H

#include <ntdef.h>

NTSTATUS
BLACKBIRDImageMonitorInitialize(VOID);

VOID BLACKBIRDImageMonitorUninitialize(VOID);

BOOLEAN
BLACKBIRDImageMonitorSelfCheck(VOID);

#endif

