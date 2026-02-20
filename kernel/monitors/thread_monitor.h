#ifndef STINGER_THREAD_H
#define STINGER_THREAD_H

#include <ntdef.h>

NTSTATUS
STINGERThreadMonitorInitialize(
    VOID
);

VOID
STINGERThreadMonitorUninitialize(
    VOID
);

#endif
