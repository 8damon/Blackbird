#ifndef BLACKBIRD_SYMBOL_RESOLVER_H
#define BLACKBIRD_SYMBOL_RESOLVER_H

#include <windows.h>
#include <basetsd.h>

void BLACKBIRDSymbolResolverInitialize(void);
void BLACKBIRDSymbolResolverCleanup(void);
void BLACKBIRDSymbolResolverPrintAddress(UINT64 address);

#endif
