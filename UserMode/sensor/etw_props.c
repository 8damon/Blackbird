#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <strsafe.h>
#include <stdlib.h>
#include "etw_props.h"

static BOOL BketwpGetPropertyRaw(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name,
                                 _Outptr_result_bytebuffer_(*OutSize) PBYTE *OutBuffer, _Out_ ULONG *OutSize)
{
    TDHSTATUS status;
    PROPERTY_DATA_DESCRIPTOR descriptor;

    *OutBuffer = NULL;
    *OutSize = 0;

    RtlZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.PropertyName = (ULONGLONG)(ULONG_PTR)Name;
    descriptor.ArrayIndex = ULONG_MAX;

    status = TdhGetPropertySize(Record, 0, NULL, 1, &descriptor, OutSize);
    if (status != ERROR_SUCCESS || *OutSize == 0)
    {
        return FALSE;
    }

    *OutBuffer = (PBYTE)malloc(*OutSize + sizeof(WCHAR));
    if (*OutBuffer == NULL)
    {
        *OutSize = 0;
        return FALSE;
    }
    RtlZeroMemory(*OutBuffer, *OutSize + sizeof(WCHAR));

    status = TdhGetProperty(Record, 0, NULL, 1, &descriptor, *OutSize, *OutBuffer);
    if (status != ERROR_SUCCESS)
    {
        free(*OutBuffer);
        *OutBuffer = NULL;
        *OutSize = 0;
        return FALSE;
    }

    return TRUE;
}

BOOL BketwpGetU32Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONG *Value)
{
    PBYTE raw = NULL;
    ULONG size = 0;

    *Value = 0;
    if (!BketwpGetPropertyRaw(Record, Name, &raw, &size))
    {
        return FALSE;
    }
    if (size >= sizeof(ULONG))
    {
        *Value = *(ULONG *)raw;
        free(raw);
        return TRUE;
    }
    free(raw);
    return FALSE;
}

BOOL BketwpGetU8Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ UCHAR *Value)
{
    PBYTE raw = NULL;
    ULONG size = 0;

    *Value = 0;
    if (!BketwpGetPropertyRaw(Record, Name, &raw, &size))
    {
        return FALSE;
    }
    if (size >= sizeof(UCHAR))
    {
        *Value = *(UCHAR *)raw;
        free(raw);
        return TRUE;
    }
    free(raw);
    return FALSE;
}

BOOL BketwpGetI32Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ LONG *Value)
{
    PBYTE raw = NULL;
    ULONG size = 0;

    *Value = 0;
    if (!BketwpGetPropertyRaw(Record, Name, &raw, &size))
    {
        return FALSE;
    }
    if (size >= sizeof(LONG))
    {
        *Value = *(LONG *)raw;
        free(raw);
        return TRUE;
    }
    free(raw);
    return FALSE;
}

BOOL BketwpGetU64Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONGLONG *Value)
{
    PBYTE raw = NULL;
    ULONG size = 0;

    *Value = 0;
    if (!BketwpGetPropertyRaw(Record, Name, &raw, &size))
    {
        return FALSE;
    }
    if (size >= sizeof(ULONGLONG))
    {
        *Value = *(ULONGLONG *)raw;
        free(raw);
        return TRUE;
    }
    free(raw);
    return FALSE;
}

BOOL BketwpGetBoolProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ BOOL *Value)
{
    PBYTE raw = NULL;
    ULONG size = 0;
    ULONG u = 0;

    *Value = FALSE;
    if (!BketwpGetPropertyRaw(Record, Name, &raw, &size))
    {
        return FALSE;
    }

    if (size >= sizeof(BOOLEAN))
    {
        u = (size >= sizeof(ULONG)) ? *(ULONG *)raw : (ULONG)(*(BOOLEAN *)raw);
        *Value = (u != 0) ? TRUE : FALSE;
        free(raw);
        return TRUE;
    }

    free(raw);
    return FALSE;
}

BOOL BketwpGetWideProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_writes_z_(OutputChars) PWSTR Output,
                           _In_ size_t OutputChars)
{
    PBYTE raw = NULL;
    ULONG size = 0;

    if (OutputChars == 0)
    {
        return FALSE;
    }
    Output[0] = L'\0';

    if (!BketwpGetPropertyRaw(Record, Name, &raw, &size))
    {
        return FALSE;
    }

    if (size >= sizeof(WCHAR))
    {
        WCHAR *ws = (WCHAR *)raw;
        (void)StringCchCopyW(Output, OutputChars, ws);
        free(raw);
        return TRUE;
    }

    free(raw);
    return FALSE;
}

BOOL BketwpGetAnsiProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_writes_z_(OutputChars) PSTR Output,
                           _In_ size_t OutputChars)
{
    PBYTE raw = NULL;
    ULONG size = 0;

    if (OutputChars == 0)
    {
        return FALSE;
    }
    Output[0] = '\0';

    if (!BketwpGetPropertyRaw(Record, Name, &raw, &size))
    {
        return FALSE;
    }

    if (size > 0)
    {
        (void)StringCchCopyA(Output, OutputChars, (PCSTR)raw);
        free(raw);
        return TRUE;
    }

    free(raw);
    return FALSE;
}

BOOL BketwpGetBinaryProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name,
                             _Out_writes_bytes_(OutputBytes) PBYTE Output, _In_ ULONG OutputBytes,
                             _Out_opt_ ULONG *ActualSize)
{
    PBYTE raw = NULL;
    ULONG size = 0;
    ULONG copySize;

    if (ActualSize != NULL)
    {
        *ActualSize = 0;
    }
    if (Output == NULL || OutputBytes == 0)
    {
        return FALSE;
    }
    ZeroMemory(Output, OutputBytes);

    if (!BketwpGetPropertyRaw(Record, Name, &raw, &size))
    {
        return FALSE;
    }
    if (size == 0)
    {
        free(raw);
        return FALSE;
    }

    copySize = (size > OutputBytes) ? OutputBytes : size;
    RtlCopyMemory(Output, raw, copySize);
    if (ActualSize != NULL)
    {
        *ActualSize = copySize;
    }

    free(raw);
    return TRUE;
}
