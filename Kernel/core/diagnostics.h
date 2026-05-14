#ifndef BK_DIAGNOSTICS_H
#define BK_DIAGNOSTICS_H

#include <ntddk.h>
#include "..\..\abi\blackbird_ioctl.h"

NTSTATUS
BkdiagInitialize(VOID);

VOID BkdiagUninitialize(VOID);

BOOLEAN
BkdiagSelfCheck(VOID);

ULONGLONG
BkdiagBegin(_In_ UINT32 SubsystemId, _In_ UINT32 EventType, _In_ UINT32 ComponentId);

VOID BkdiagComplete(_In_ UINT32 SubsystemId, _In_ UINT32 EventType, _In_ NTSTATUS Status, _In_ ULONGLONG StartQpc,
                    _In_ UINT32 Flags, _In_ UINT32 DetailCode, _In_ UINT32 ComponentId);

VOID BkdiagRecord(_In_ UINT32 SubsystemId, _In_ UINT32 EventType, _In_ NTSTATUS Status, _In_ UINT64 ElapsedQpc,
                  _In_ UINT32 Flags, _In_ UINT32 DetailCode, _In_ UINT32 ComponentId);

VOID BkdiagQuery(_Out_ PBK_DIAGNOSTICS_RESPONSE Response);

#endif
