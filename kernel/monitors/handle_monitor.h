#ifndef SLEEPWALKER_HANDLE_MONITOR_H
#define SLEEPWALKER_HANDLE_MONITOR_H

#include <ntdef.h>

NTSTATUS
SLEEPWALKERHandleMonitorInitialize(VOID);

VOID SLEEPWALKERHandleMonitorUninitialize(VOID);

BOOLEAN
SLEEPWALKERHandleMonitorSelfCheck(VOID);

#endif
