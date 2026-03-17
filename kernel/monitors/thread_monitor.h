#ifndef BLACKBIRD_THREAD_H
#define BLACKBIRD_THREAD_H

#include <ntdef.h>

NTSTATUS
BLACKBIRDThreadMonitorInitialize(VOID);

VOID BLACKBIRDThreadMonitorUninitialize(VOID);

BOOLEAN
BLACKBIRDThreadMonitorSelfCheck(VOID);

#endif

