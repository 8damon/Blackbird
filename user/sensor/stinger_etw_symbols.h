#ifndef STINGER_ETW_SYMBOLS_H
#define STINGER_ETW_SYMBOLS_H

#include <windows.h>

void STINGEREtwSymbolsInitialize(void);
void STINGEREtwSymbolsCleanup(void);
void STINGEREtwSymbolsFormatAddress(
    _In_ ULONGLONG Address,
    _Out_writes_z_(OutputChars) PWSTR Output,
    _In_ size_t OutputChars
);

#endif
