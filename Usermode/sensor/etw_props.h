#ifndef BK_ETW_PROPS_H
#define BK_ETW_PROPS_H

#include <windows.h>
#include <evntcons.h>

BOOL BketwpGetU32Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONG *Value);
BOOL BketwpGetU8Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ UCHAR *Value);
BOOL BketwpGetI32Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ LONG *Value);
BOOL BketwpGetU64Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONGLONG *Value);
BOOL BketwpGetBoolProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ BOOL *Value);
BOOL BketwpGetWideProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_writes_z_(OutputChars) PWSTR Output,
                           _In_ size_t OutputChars);
BOOL BketwpGetAnsiProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_writes_z_(OutputChars) PSTR Output,
                           _In_ size_t OutputChars);
BOOL BketwpGetBinaryProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name,
                             _Out_writes_bytes_(OutputBytes) PBYTE Output, _In_ ULONG OutputBytes,
                             _Out_opt_ ULONG *ActualSize);

#endif
