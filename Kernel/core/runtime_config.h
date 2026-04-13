#ifndef BLACKBIRD_RUNTIME_CONFIG_H
#define BLACKBIRD_RUNTIME_CONFIG_H

#include <ntddk.h>
#include "..\..\abi\blackbird_ioctl.h"

NTSTATUS BLACKBIRDRuntimeConfigInitialize(_In_ PUNICODE_STRING RegistryPath);
VOID BLACKBIRDRuntimeConfigUninitialize(VOID);

BOOLEAN BLACKBIRDRuntimeConfigIsAntiVirtualizationEnabled(VOID);
BOOLEAN BLACKBIRDRuntimeConfigIsSelfHideEnabled(VOID);
BOOLEAN BLACKBIRDRuntimeConfigIsInterfaceProtectedAccessEnabled(VOID);
BOOLEAN BLACKBIRDRuntimeConfigIsControllerProtectedAccessEnabled(VOID);
UINT32 BLACKBIRDRuntimeConfigGetPersistentFlags(VOID);
UINT32 BLACKBIRDRuntimeConfigGetRuntimeFlags(VOID);
UINT32 BLACKBIRDRuntimeConfigGetEffectiveFlags(VOID);
UINT32 BLACKBIRDRuntimeConfigGetCurrentMode(VOID);

NTSTATUS BLACKBIRDRuntimeConfigSetRuntimeFlags(_In_ UINT32 Flags, _In_ UINT32 Mask);
VOID BLACKBIRDRuntimeConfigFillResponse(_Out_ PBLACKBIRD_RUNTIME_CONFIG_RESPONSE Response);

#endif
