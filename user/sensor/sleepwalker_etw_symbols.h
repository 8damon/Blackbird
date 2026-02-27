#ifndef SLEEPWALKER_ETW_SYMBOLS_H
#define SLEEPWALKER_ETW_SYMBOLS_H

#include <windows.h>

void SLEEPWALKEREtwSymbolsInitialize(void);
void SLEEPWALKEREtwSymbolsCleanup(void);
void SLEEPWALKEREtwSymbolsFormatAddress(_In_ ULONGLONG Address, _Out_writes_z_(OutputChars) PWSTR Output,
                                        _In_ size_t OutputChars);
void SLEEPWALKEREtwSymbolsFormatAddressForProcess(_In_ DWORD ProcessId, _In_ ULONGLONG Address,
                                                  _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars);
void SLEEPWALKEREtwSymbolsCacheModuleForProcess(_In_ DWORD ProcessId, _In_ ULONGLONG ImageBase,
                                                _In_ ULONGLONG ImageSize, _In_opt_z_ PCWSTR ImagePath);
BOOL SLEEPWALKEREtwSymbolsTryResolveViaModuleCache(_In_ DWORD ProcessId, _In_ ULONGLONG Address,
                                                   _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars);

#endif
