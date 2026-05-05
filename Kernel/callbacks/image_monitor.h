#ifndef BK_IMAGE_MONITOR_H
#define BK_IMAGE_MONITOR_H

#include <ntdef.h>

NTSTATUS
BkcimgInitialize(VOID);

VOID BkcimgUninitialize(VOID);

BOOLEAN
BkcimgSelfCheck(VOID);

BOOLEAN
BkcimgQueryPrimaryNtdll(_In_ HANDLE ProcessId, _Out_ UINT64 *PrimaryBase, _Out_opt_ UINT64 *PrimarySize);

#endif
