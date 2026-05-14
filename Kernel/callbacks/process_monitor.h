#ifndef BK_PROCESS_MONITOR_H
#define BK_PROCESS_MONITOR_H

#include <ntdef.h>

NTSTATUS
BkcprocInitialize(VOID);

VOID BkcprocUninitialize(VOID);

BOOLEAN BkcprocSelfCheck(VOID);

BOOLEAN BkcprocIsProtectedPid(_In_ UINT32 ProcessId);

BOOLEAN BkcprocIsInterfacePid(_In_ UINT32 ProcessId);

BOOLEAN BkcprocIsControllerPid(_In_ UINT32 ProcessId);
BOOLEAN BkcprocIsControllerReadyPid(_In_ UINT32 ProcessId);

BOOLEAN BkcprocRegisterInterfacePid(_In_ UINT32 ProcessId);
BOOLEAN BkcprocRegisterControllerPid(_In_ UINT32 ProcessId);

BOOLEAN BkcprocMarkControllerReady(_In_ UINT32 ProcessId);

BOOLEAN BkcprocIsTrustedProtectedCaller(_In_ UINT32 CallerPid, _In_ UINT32 TargetPid);

BOOLEAN BkcprocIsKnownSystemBrokerPid(_In_ UINT32 ProcessId);

BOOLEAN BkcprocShouldSuppressLaunchBootstrapNtApi(_In_ UINT32 AttachedPid, _In_ UINT32 ThreadOwnerPid);

#endif
