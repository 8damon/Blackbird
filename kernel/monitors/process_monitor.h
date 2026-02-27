#ifndef SLEEPWALKER_PROCESS_MONITOR_H
#define SLEEPWALKER_PROCESS_MONITOR_H

#include <ntdef.h>

NTSTATUS
SLEEPWALKERProcessMonitorInitialize(VOID);

VOID SLEEPWALKERProcessMonitorUninitialize(VOID);

BOOLEAN
SLEEPWALKERProcessMonitorSelfCheck(VOID);

#endif
