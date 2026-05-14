#ifndef BK_REGISTRY_CONCEALMENT_H
#define BK_REGISTRY_CONCEALMENT_H

#include <ntddk.h>

BOOLEAN BkavRegPathIsHighValue(_In_opt_ PCUNICODE_STRING Path);

BOOLEAN BkavRegNullPath(_In_opt_ PCUNICODE_STRING Path);

VOID BkavRegBuildPathForCompare(_In_ PLARGE_INTEGER Cookie, _In_opt_ PVOID RootObject,
                                _In_opt_ PCUNICODE_STRING CompleteName, _Out_writes_z_(PathChars) PWSTR PathBuffer,
                                _In_ SIZE_T PathChars, _Out_ PUNICODE_STRING PathUs);

BOOLEAN BkavRegBlindBiosValue(_In_ PLARGE_INTEGER Cookie, _In_opt_ PVOID Object,
                              _In_ PREG_QUERY_VALUE_KEY_INFORMATION PreInfo);

BOOLEAN BkavRegBlindNicValue(_In_ PLARGE_INTEGER Cookie, _In_opt_ PVOID Object,
                             _In_ PREG_QUERY_VALUE_KEY_INFORMATION PreInfo);

BOOLEAN BkavRegBlindDisplayValue(_In_ PLARGE_INTEGER Cookie, _In_opt_ PVOID Object,
                                 _In_ PREG_QUERY_VALUE_KEY_INFORMATION PreInfo);

BOOLEAN BkavRegBlindScsiValue(_In_ PLARGE_INTEGER Cookie, _In_opt_ PVOID Object,
                              _In_ PREG_QUERY_VALUE_KEY_INFORMATION PreInfo);

#endif
