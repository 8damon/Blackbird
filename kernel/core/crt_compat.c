#include <ntddk.h>

/*
 * Provide local implementations to avoid hard-importing CRT-like symbols
 * from ntoskrnl on target builds where those exports may not be available.
 */
#pragma function(strlen)
#pragma function(wcslen)

size_t __cdecl
strlen(
    _In_opt_z_ const char* s
)
{
    const char* p = s;

    if (p == NULL) {
        return 0;
    }

    while (*p != '\0') {
        ++p;
    }

    return (size_t)(p - s);
}

size_t __cdecl
wcslen(
    _In_opt_z_ const wchar_t* s
)
{
    const wchar_t* p = s;

    if (p == NULL) {
        return 0;
    }

    while (*p != L'\0') {
        ++p;
    }

    return (size_t)(p - s);
}
