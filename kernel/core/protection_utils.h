#ifndef SLEEPWALKER_PROTECTION_UTILS_H
#define SLEEPWALKER_PROTECTION_UTILS_H

#include <ntddk.h>

static __forceinline BOOLEAN SLEEPWALKERIsExecutableProtection(_In_ ULONG Protect)
{
    return (((Protect & PAGE_EXECUTE) != 0) || ((Protect & PAGE_EXECUTE_READ) != 0) ||
            ((Protect & PAGE_EXECUTE_READWRITE) != 0) || ((Protect & PAGE_EXECUTE_WRITECOPY) != 0));
}

#endif
