#ifndef SLEEPWALKER_IMAGE_MONITOR_H
#define SLEEPWALKER_IMAGE_MONITOR_H

#include <ntdef.h>

NTSTATUS
SLEEPWALKERImageMonitorInitialize(VOID);

VOID SLEEPWALKERImageMonitorUninitialize(VOID);

BOOLEAN
SLEEPWALKERImageMonitorSelfCheck(VOID);

#endif
