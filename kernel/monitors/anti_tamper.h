#ifndef BLACKBIRD_ANTI_TAMPER_H
#define BLACKBIRD_ANTI_TAMPER_H

#include <ntdef.h>

NTSTATUS
BLACKBIRDAntiTamperInitialize(_In_ PDRIVER_OBJECT DriverObject);

VOID BLACKBIRDAntiTamperUninitialize(VOID);

ULONG BLACKBIRDAntiTamperGetLastMask(VOID);

#endif

