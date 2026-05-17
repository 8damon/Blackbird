#ifndef BK_SYMBOL_COMMON_H
#define BK_SYMBOL_COMMON_H

#include <windows.h>
#include <basetsd.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define BK_DEFAULT_SYMBOL_PATH "C:\\symbols"

    BOOL BksymStartsWithInsensitive(_In_opt_z_ const char *Text, _In_opt_z_ const char *Prefix);

    BOOL BksymNormalizeKernelImagePath(_In_z_ const char *RawPath, _Out_writes_z_(OutputChars) char *Output,
                                       _In_ size_t OutputChars);

    BOOL BksymBuildKernelGuessPath(_In_z_ const char *ModuleName, _Out_writes_z_(OutputChars) char *Output,
                                   _In_ size_t OutputChars);

    DWORD
    BksymLoadKernelModulesForProcess(_In_ HANDLE SymbolProcess, _Out_opt_ DWORD *LoadedCount,
                                     _Out_opt_ DWORD *TotalCount);

#ifdef __cplusplus
}
#endif

#endif
