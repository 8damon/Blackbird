#ifndef BLACKBIRD_ETW_PROPS_H
#define BLACKBIRD_ETW_PROPS_H

#include <windows.h>
#include <evntcons.h>

BOOL BLACKBIRDGetU32Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONG *Value);
BOOL BLACKBIRDGetU8Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ UCHAR *Value);
BOOL BLACKBIRDGetI32Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ LONG *Value);
BOOL BLACKBIRDGetU64Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONGLONG *Value);
BOOL BLACKBIRDGetBoolProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ BOOL *Value);
BOOL BLACKBIRDGetWideProperty(_In_ PEVENT_RECORD Record,
                              _In_z_ PCWSTR Name,
                              _Out_writes_z_(OutputChars) PWSTR Output,
                              _In_ size_t OutputChars);
BOOL BLACKBIRDGetAnsiProperty(_In_ PEVENT_RECORD Record,
                              _In_z_ PCWSTR Name,
                              _Out_writes_z_(OutputChars) PSTR Output,
                              _In_ size_t OutputChars);
BOOL BLACKBIRDGetBinaryProperty(_In_ PEVENT_RECORD Record,
                                _In_z_ PCWSTR Name,
                                _Out_writes_bytes_(OutputBytes) PBYTE Output,
                                _In_ ULONG OutputBytes,
                                _Out_opt_ ULONG *ActualSize);

#endif
