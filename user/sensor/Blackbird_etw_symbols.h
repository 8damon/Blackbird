#ifndef BLACKBIRD_ETW_SYMBOLS_H
#define BLACKBIRD_ETW_SYMBOLS_H

#include <windows.h>

void BLACKBIRDEtwSymbolsInitialize(void);
void BLACKBIRDEtwSymbolsCleanup(void);
void BLACKBIRDEtwSymbolsFormatAddress(_In_ ULONGLONG Address,
                                      _Out_writes_z_(OutputChars) PWSTR Output,
                                      _In_ size_t OutputChars);
void BLACKBIRDEtwSymbolsFormatAddressForProcess(_In_ DWORD ProcessId,
                                                _In_ ULONGLONG Address,
                                                _Out_writes_z_(OutputChars) PWSTR Output,
                                                _In_ size_t OutputChars);
void BLACKBIRDEtwSymbolsCacheModuleForProcess(_In_ DWORD ProcessId,
                                              _In_ ULONGLONG ImageBase,
                                              _In_ ULONGLONG ImageSize,
                                              _In_opt_z_ PCWSTR ImagePath);
BOOL BLACKBIRDEtwSymbolsTryResolveViaModuleCache(_In_ DWORD ProcessId,
                                                 _In_ ULONGLONG Address,
                                                 _Out_writes_z_(OutputChars) PWSTR Output,
                                                 _In_ size_t OutputChars);

#endif
