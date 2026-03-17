#ifndef BLACKBIRD_NTAPI_HOOK_LDASM_H
#define BLACKBIRD_NTAPI_HOOK_LDASM_H

#include <ntddk.h>

//
// BLACKBIRDx64MinCoverLength
//
// Given a pointer to executable code (kernel mode), returns the minimum number of bytes
// >= MinBytes that covers only complete x86-64 instructions.  The caller should pass
// BLACKBIRD_NTAPI_PATCH_SIZE as MinBytes.
//
// Returns 0 when:
//   - an instruction cannot be decoded (unknown/privileged encoding in this table)
//   - the required length would exceed MaxBytes
//   - the input pointer is NULL
//
// The decoder is intentionally conservative: it covers the encodings produced by MSVC
// for Windows kernel function prologues (SUB RSP/imm, MOV [RSP+N]/reg, PUSH reg,
// MOV reg/imm64, LEA reg/[RIP+disp], TEST, CMP, and common short/near jumps).
// If it encounters an opcode it does not recognise it returns 0 so the caller can
// fall back to its hardcoded OverwriteLength value safely.
//
_Success_(return != 0)
ULONG BLACKBIRDx64MinCoverLength(
    _In_reads_bytes_(MaxBytes) const UCHAR *Code,
    _In_ ULONG MinBytes,
    _In_ ULONG MaxBytes);

#endif
