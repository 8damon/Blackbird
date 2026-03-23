#ifndef BLACKBIRD_APC_MONITOR_H
#define BLACKBIRD_APC_MONITOR_H

#include <ntdef.h>

NTSTATUS
BLACKBIRDApcMonitorInitialize(VOID);

VOID BLACKBIRDApcMonitorUninitialize(VOID);

VOID BLACKBIRDApcMonitorRecordThreadHandleIntent(_In_ HANDLE CallerPid, _In_ HANDLE TargetPid,
                                                 _In_ ACCESS_MASK DesiredAccess, _In_ BOOLEAN IsDuplicateOperation);

BOOLEAN
BLACKBIRDApcMonitorSelfCheck(VOID);

#endif
