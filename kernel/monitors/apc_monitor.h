#ifndef STINGER_APC_MONITOR_H
#define STINGER_APC_MONITOR_H

#include <ntdef.h>

NTSTATUS
STINGERApcMonitorInitialize(
    VOID
);

VOID
STINGERApcMonitorUninitialize(
    VOID
);

VOID
STINGERApcMonitorRecordThreadHandleIntent(
    _In_ HANDLE CallerPid,
    _In_ HANDLE TargetPid,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ BOOLEAN IsDuplicateOperation
);

BOOLEAN
STINGERApcMonitorSelfCheck(
    VOID
);

#endif
