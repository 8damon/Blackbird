#ifndef BK_APC_MONITOR_H
#define BK_APC_MONITOR_H

#include <ntdef.h>

NTSTATUS
BkapcInitialize(VOID);

VOID BkapcUninitialize(VOID);

VOID BkapcRecordThreadHandleIntent(_In_ HANDLE CallerPid, _In_ HANDLE TargetPid, _In_ ACCESS_MASK DesiredAccess,
                                   _In_ BOOLEAN IsDuplicateOperation);

BOOLEAN
BkapcSelfCheck(VOID);

#endif
