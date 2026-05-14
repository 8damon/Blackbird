#ifndef BK_RUNTIME_CONFIG_H
#define BK_RUNTIME_CONFIG_H

#include <ntddk.h>
#include "..\..\abi\blackbird_ioctl.h"

NTSTATUS BkrtInitialize(_In_ PUNICODE_STRING RegistryPath);
VOID BkrtUninitialize(VOID);

BOOLEAN BkrtIsAntiVirtualizationEnabled(VOID);
BOOLEAN BkrtIsSelfHideEnabled(VOID);
BOOLEAN BkrtIsInterfaceProtectedAccessEnabled(VOID);
BOOLEAN BkrtIsControllerProtectedAccessEnabled(VOID);
BOOLEAN BkrtIsNtApiHooksDisarmed(VOID);
BOOLEAN BkrtIsQpcTimingCompensationEnabled(VOID);
UINT32 BkrtGetPersistentFlags(VOID);
UINT32 BkrtGetRuntimeFlags(VOID);
UINT32 BkrtGetEffectiveFlags(VOID);
UINT32 BkrtGetCurrentMode(VOID);

NTSTATUS BkrtSetRuntimeFlags(_In_ UINT32 Flags, _In_ UINT32 Mask);
VOID BkrtFillResponse(_Out_ PBK_RUNTIME_CONFIG_RESPONSE Response);

#endif
