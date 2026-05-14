#ifndef BK_THREAD_H
#define BK_THREAD_H

#include <ntdef.h>

NTSTATUS
BkcthrInitialize(VOID);

VOID BkcthrUninitialize(VOID);

BOOLEAN
BkcthrSelfCheck(VOID);

#endif
