#ifndef SLEEPWALKER_APC_MONITOR_H
#define SLEEPWALKER_APC_MONITOR_H

#include <ntdef.h>

NTSTATUS
SLEEPWALKERApcMonitorInitialize(VOID);

VOID SLEEPWALKERApcMonitorUninitialize(VOID);

VOID SLEEPWALKERApcMonitorRecordThreadHandleIntent(_In_ HANDLE CallerPid, _In_ HANDLE TargetPid,
                                                   _In_ ACCESS_MASK DesiredAccess, _In_ BOOLEAN IsDuplicateOperation);

BOOLEAN
SLEEPWALKERApcMonitorSelfCheck(VOID);

#endif
