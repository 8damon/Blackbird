#ifndef BK_HANDLE_MONITOR_H
#define BK_HANDLE_MONITOR_H

#include <ntdef.h>

NTSTATUS
BkchdlInitialize(VOID);

VOID BkchdlUninitialize(VOID);

BOOLEAN
BkchdlSelfCheck(VOID);

#endif
