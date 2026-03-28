#ifndef BLACKBIRD_PROCESS_MONITOR_H
#define BLACKBIRD_PROCESS_MONITOR_H

#include <ntdef.h>

NTSTATUS
BLACKBIRDProcessMonitorInitialize(VOID);

VOID BLACKBIRDProcessMonitorUninitialize(VOID);

BOOLEAN BLACKBIRDProcessMonitorSelfCheck(VOID);

BOOLEAN BLACKBIRDProcessMonitorIsProtectedPid(_In_ UINT32 ProcessId);

BOOLEAN BLACKBIRDProcessMonitorIsInterfacePid(_In_ UINT32 ProcessId);

BOOLEAN BLACKBIRDProcessMonitorIsControllerPid(_In_ UINT32 ProcessId);

BOOLEAN BLACKBIRDProcessMonitorMarkInterfaceReady(_In_ UINT32 ProcessId);
BOOLEAN BLACKBIRDProcessMonitorMarkControllerReady(_In_ UINT32 ProcessId);

BOOLEAN BLACKBIRDProcessMonitorIsTrustedProtectedCaller(_In_ UINT32 CallerPid, _In_ UINT32 TargetPid);

#endif

