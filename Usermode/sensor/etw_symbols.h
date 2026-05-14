#ifndef BK_ETW_SYMBOLS_H
#define BK_ETW_SYMBOLS_H

#include <windows.h>

void BksymEtwInitialize(void);
void BksymEtwCleanup(void);
void BksymEtwFormatAddress(_In_ ULONGLONG Address, _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars);
void BksymEtwFormatAddressForProcess(_In_ DWORD ProcessId, _In_ ULONGLONG Address,
                                     _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars);
void BksymEtwCacheModuleForProcess(_In_ DWORD ProcessId, _In_ ULONGLONG ImageBase, _In_ ULONGLONG ImageSize,
                                   _In_opt_z_ PCWSTR ImagePath);
BOOL BksymEtwTryResolveViaModuleCache(_In_ DWORD ProcessId, _In_ ULONGLONG Address,
                                      _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars);

#endif
