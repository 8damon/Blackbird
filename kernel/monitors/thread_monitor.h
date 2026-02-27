#ifndef SLEEPWALKER_THREAD_H
#define SLEEPWALKER_THREAD_H

#include <ntdef.h>

NTSTATUS
SLEEPWALKERThreadMonitorInitialize(VOID);

VOID SLEEPWALKERThreadMonitorUninitialize(VOID);

BOOLEAN
SLEEPWALKERThreadMonitorSelfCheck(VOID);

#endif
