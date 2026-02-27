#ifndef SLEEPWALKER_SYMBOL_RESOLVER_H
#define SLEEPWALKER_SYMBOL_RESOLVER_H

#include <windows.h>
#include <basetsd.h>

void SLEEPWALKERSymbolResolverInitialize(void);
void SLEEPWALKERSymbolResolverCleanup(void);
void SLEEPWALKERSymbolResolverPrintAddress(UINT64 address);

#endif
