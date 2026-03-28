#ifndef BLACKBIRD_REGISTRY_CONCEALMENT_H
#define BLACKBIRD_REGISTRY_CONCEALMENT_H

#include <ntddk.h>

BOOLEAN BLACKBIRDRegistryPathIsHighValue(_In_opt_ PCUNICODE_STRING Path);

BOOLEAN BLACKBIRDRegistryNullPath(_In_opt_ PCUNICODE_STRING Path);

VOID BLACKBIRDRegistryBuildPathForCompare(_In_ PLARGE_INTEGER Cookie, _In_opt_ PVOID RootObject,
                                          _In_opt_ PCUNICODE_STRING CompleteName,
                                          _Out_writes_z_(PathChars) PWSTR PathBuffer, _In_ SIZE_T PathChars,
                                          _Out_ PUNICODE_STRING PathUs);

BOOLEAN BLACKBIRDRegistryBlindBiosValue(_In_ PLARGE_INTEGER Cookie, _In_opt_ PVOID Object,
                                        _In_ PREG_QUERY_VALUE_KEY_INFORMATION PreInfo);

BOOLEAN BLACKBIRDRegistryBlindNicValue(_In_ PLARGE_INTEGER Cookie, _In_opt_ PVOID Object,
                                       _In_ PREG_QUERY_VALUE_KEY_INFORMATION PreInfo);

BOOLEAN BLACKBIRDRegistryBlindDisplayValue(_In_ PLARGE_INTEGER Cookie, _In_opt_ PVOID Object,
                                           _In_ PREG_QUERY_VALUE_KEY_INFORMATION PreInfo);

BOOLEAN BLACKBIRDRegistryBlindScsiValue(_In_ PLARGE_INTEGER Cookie, _In_opt_ PVOID Object,
                                        _In_ PREG_QUERY_VALUE_KEY_INFORMATION PreInfo);

#endif
