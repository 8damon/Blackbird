#ifndef STINGER_SYMBOL_RESOLVER_H
#define STINGER_SYMBOL_RESOLVER_H

#include <windows.h>
#include <basetsd.h>

void STINGERSymbolResolverInitialize(void);
void STINGERSymbolResolverCleanup(void);
void STINGERSymbolResolverPrintAddress(UINT64 address);

#endif
