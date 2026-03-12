#ifndef BLACKBIRD_UNICODE_UTILS_H
#define BLACKBIRD_UNICODE_UTILS_H

#include <ntddk.h>

static __forceinline BOOLEAN BLACKBIRDUnicodeContainsInsensitive(_In_ PCUNICODE_STRING Haystack,
                                                                   _In_reads_(NeedleChars) PCWSTR Needle,
                                                                   _In_ USHORT NeedleChars)
{
    USHORT hayChars;
    USHORT i;
    USHORT j;

    if (Haystack == NULL || Haystack->Buffer == NULL || Needle == NULL || NeedleChars == 0)
    {
        return FALSE;
    }

    hayChars = Haystack->Length / sizeof(WCHAR);
    if (hayChars < NeedleChars)
    {
        return FALSE;
    }

    for (i = 0; i <= (USHORT)(hayChars - NeedleChars); ++i)
    {
        BOOLEAN match = TRUE;
        for (j = 0; j < NeedleChars; ++j)
        {
            if (RtlDowncaseUnicodeChar(Haystack->Buffer[i + j]) != RtlDowncaseUnicodeChar(Needle[j]))
            {
                match = FALSE;
                break;
            }
        }
        if (match)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static __forceinline VOID BLACKBIRDSafeCopyUnicode(_In_opt_ PCUNICODE_STRING Source,
                                                     _Out_writes_z_(DestChars) PWSTR Dest, _In_ SIZE_T DestChars)
{
    SIZE_T copyChars;

    if (Dest == NULL || DestChars == 0)
    {
        return;
    }
    Dest[0] = L'\0';

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0)
    {
        return;
    }

    copyChars = Source->Length / sizeof(WCHAR);
    if (copyChars >= DestChars)
    {
        copyChars = DestChars - 1;
    }
    if (copyChars == 0)
    {
        return;
    }

    RtlCopyMemory(Dest, Source->Buffer, copyChars * sizeof(WCHAR));
    Dest[copyChars] = L'\0';
}

#endif
