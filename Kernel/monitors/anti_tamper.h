#ifndef BK_ANTI_TAMPER_H
#define BK_ANTI_TAMPER_H

#include <ntdef.h>

NTSTATUS
BkatInitialize(_In_ PDRIVER_OBJECT DriverObject);

VOID BkatUninitialize(VOID);

ULONG BkatGetLastMask(VOID);

BOOLEAN BkatSelfCheck(VOID);

#endif
