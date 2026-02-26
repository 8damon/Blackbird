#ifndef STINGER_IMAGE_MONITOR_H
#define STINGER_IMAGE_MONITOR_H

#include <ntdef.h>

NTSTATUS
STINGERImageMonitorInitialize(
    VOID
);

VOID
STINGERImageMonitorUninitialize(
    VOID
);

BOOLEAN
STINGERImageMonitorSelfCheck(
    VOID
);

#endif
