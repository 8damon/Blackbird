#ifndef BLACKBIRD_NTAPI_HOOK_H
#define BLACKBIRD_NTAPI_HOOK_H

#include <ntddk.h>

#define BLACKBIRD_NTAPI_PATCH_SIZE 14
#define BLACKBIRD_NTAPI_MAX_OVERWRITE 32

typedef struct _BLACKBIRD_NTAPI_HOOK_DESCRIPTOR
{
    PCSTR ApiName;
    PCWSTR Name0;
    PCWSTR Name1;
    PCWSTR Name2;
    PVOID HookFunction;
    ULONG OverwriteLength;
    BOOLEAN Required;
    ULONGLONG FallbackNtosOffset;
    UCHAR FallbackSignature[8];
    ULONG FallbackSignatureSize;
} BLACKBIRD_NTAPI_HOOK_DESCRIPTOR, *PBLACKBIRD_NTAPI_HOOK_DESCRIPTOR;

typedef struct _BLACKBIRD_NTAPI_HOOK
{
    BLACKBIRD_NTAPI_HOOK_DESCRIPTOR Descriptor;
    PVOID RoutineAddress;
    PVOID Trampoline;
    UCHAR OriginalPatch[BLACKBIRD_NTAPI_MAX_OVERWRITE];
    BOOLEAN Installed;
} BLACKBIRD_NTAPI_HOOK, *PBLACKBIRD_NTAPI_HOOK;

VOID BLACKBIRDNtApiHookInitialize(_Out_ PBLACKBIRD_NTAPI_HOOK Hook,
                                  _In_ const BLACKBIRD_NTAPI_HOOK_DESCRIPTOR *Descriptor);

NTSTATUS BLACKBIRDNtApiHookInstall(_Inout_ PBLACKBIRD_NTAPI_HOOK Hook, _Outptr_opt_result_maybenull_ PVOID *Original);

VOID BLACKBIRDNtApiHookDeactivate(_Inout_ PBLACKBIRD_NTAPI_HOOK Hook);

VOID BLACKBIRDNtApiHookFreeTrampoline(_Inout_ PBLACKBIRD_NTAPI_HOOK Hook);

VOID BLACKBIRDNtApiHookRemove(_Inout_ PBLACKBIRD_NTAPI_HOOK Hook);

#endif

