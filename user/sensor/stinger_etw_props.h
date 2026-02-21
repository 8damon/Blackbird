#ifndef STINGER_ETW_PROPS_H
#define STINGER_ETW_PROPS_H

#include <windows.h>
#include <evntcons.h>

BOOL STINGERGetU32Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONG* Value);
BOOL STINGERGetI32Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ LONG* Value);
BOOL STINGERGetU64Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONGLONG* Value);
BOOL STINGERGetBoolProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ BOOL* Value);
BOOL STINGERGetWideProperty(
    _In_ PEVENT_RECORD Record,
    _In_z_ PCWSTR Name,
    _Out_writes_z_(OutputChars) PWSTR Output,
    _In_ size_t OutputChars
);
BOOL STINGERGetAnsiProperty(
    _In_ PEVENT_RECORD Record,
    _In_z_ PCWSTR Name,
    _Out_writes_z_(OutputChars) PSTR Output,
    _In_ size_t OutputChars
);

#endif
