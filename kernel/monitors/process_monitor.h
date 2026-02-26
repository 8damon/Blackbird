#ifndef STINGER_PROCESS_MONITOR_H
#define STINGER_PROCESS_MONITOR_H

#include <ntdef.h>

NTSTATUS
STINGERProcessMonitorInitialize(
    VOID
);

VOID
STINGERProcessMonitorUninitialize(
    VOID
);

BOOLEAN
STINGERProcessMonitorSelfCheck(
    VOID
);

#endif
