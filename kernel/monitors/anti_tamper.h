#ifndef STINGER_ANTI_TAMPER_H
#define STINGER_ANTI_TAMPER_H

#include <ntdef.h>

NTSTATUS
STINGERAntiTamperInitialize(
    _In_ PDRIVER_OBJECT DriverObject
);

VOID
STINGERAntiTamperUninitialize(
    VOID
);

#endif
