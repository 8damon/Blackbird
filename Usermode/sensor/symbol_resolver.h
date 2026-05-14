#ifndef BK_SYMBOL_RESOLVER_H
#define BK_SYMBOL_RESOLVER_H

#include <windows.h>
#include <basetsd.h>

void BksymResolverInitialize(void);
void BksymResolverCleanup(void);
void BksymResolverPrintAddress(UINT64 address);

#endif
