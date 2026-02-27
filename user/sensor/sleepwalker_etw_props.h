#ifndef SLEEPWALKER_ETW_PROPS_H
#define SLEEPWALKER_ETW_PROPS_H

#include <windows.h>
#include <evntcons.h>

BOOL SLEEPWALKERGetU32Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONG *Value);
BOOL SLEEPWALKERGetU8Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ UCHAR *Value);
BOOL SLEEPWALKERGetI32Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ LONG *Value);
BOOL SLEEPWALKERGetU64Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONGLONG *Value);
BOOL SLEEPWALKERGetBoolProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ BOOL *Value);
BOOL SLEEPWALKERGetWideProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_writes_z_(OutputChars) PWSTR Output,
                                _In_ size_t OutputChars);
BOOL SLEEPWALKERGetAnsiProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_writes_z_(OutputChars) PSTR Output,
                                _In_ size_t OutputChars);
BOOL SLEEPWALKERGetBinaryProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name,
                                  _Out_writes_bytes_(OutputBytes) PBYTE Output, _In_ ULONG OutputBytes,
                                  _Out_opt_ ULONG *ActualSize);

#endif
