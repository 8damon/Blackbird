#ifndef BK_CRASHDUMP_H
#define BK_CRASHDUMP_H

#include <ntddk.h>

#ifndef BK_ENABLE_CRASHDUMP_CALLBACK
#define BK_ENABLE_CRASHDUMP_CALLBACK 0
#endif

NTSTATUS
BkcrashInitialize(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

VOID BkcrashUninitialize(VOID);

VOID BkcrashSetDriverState(_In_ LONG DriverState);

VOID BkcrashSetInitFlags(_In_ LONG InitFlags);

VOID BkcrashRecordCheckpoint(_In_ UINT32 SubsystemId, _In_ UINT32 EventType, _In_ NTSTATUS Status,
                             _In_ UINT32 ComponentId);

#endif
