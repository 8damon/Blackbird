#ifndef SLEEPWALKER_ANTI_TAMPER_H
#define SLEEPWALKER_ANTI_TAMPER_H

#include <ntdef.h>

NTSTATUS
SLEEPWALKERAntiTamperInitialize(_In_ PDRIVER_OBJECT DriverObject);

VOID SLEEPWALKERAntiTamperUninitialize(VOID);

#endif
