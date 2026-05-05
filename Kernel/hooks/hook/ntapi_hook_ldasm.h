#ifndef BK_NTAPI_HOOK_LDASM_H
#define BK_NTAPI_HOOK_LDASM_H

#include <ntddk.h>

_Success_(return != 0) ULONG
    Bkx64MinCoverLength(_In_reads_bytes_(MaxBytes) const UCHAR *Code, _In_ ULONG MinBytes, _In_ ULONG MaxBytes);

#endif
