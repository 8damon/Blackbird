#ifndef BLACKBIRD_SYMBOL_COMMON_H
#define BLACKBIRD_SYMBOL_COMMON_H

#include <windows.h>
#include <basetsd.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define BLACKBIRD_DEFAULT_SYMBOL_PATH "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"

    BOOL BLACKBIRDSymStartsWithInsensitive(_In_opt_z_ const char *Text, _In_opt_z_ const char *Prefix);

    BOOL BLACKBIRDSymNormalizeKernelImagePath(_In_z_ const char *RawPath,
                                              _Out_writes_z_(OutputChars) char *Output,
                                              _In_ size_t OutputChars);

    BOOL BLACKBIRDSymBuildKernelGuessPath(_In_z_ const char *ModuleName,
                                          _Out_writes_z_(OutputChars) char *Output,
                                          _In_ size_t OutputChars);

    DWORD
    BLACKBIRDSymLoadKernelModulesForProcess(_In_ HANDLE SymbolProcess,
                                            _Out_opt_ DWORD *LoadedCount,
                                            _Out_opt_ DWORD *TotalCount);

#ifdef __cplusplus
}
#endif

#endif
