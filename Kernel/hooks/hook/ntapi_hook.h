#ifndef BK_NTAPI_HOOK_H
#define BK_NTAPI_HOOK_H

#include <ntddk.h>

#define BK_NTAPI_PATCH_SIZE 14
#define BK_NTAPI_MAX_OVERWRITE 32

typedef struct _BK_NTAPI_HOOK_DESCRIPTOR
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
} BK_NTAPI_HOOK_DESCRIPTOR, *PBK_NTAPI_HOOK_DESCRIPTOR;

typedef struct _BK_NTAPI_HOOK
{
    BK_NTAPI_HOOK_DESCRIPTOR Descriptor;
    PVOID RoutineAddress;
    PVOID Trampoline;
    UCHAR OriginalPatch[BK_NTAPI_MAX_OVERWRITE];
    ULONG ActiveOverwriteLength;
    BOOLEAN Installed;
} BK_NTAPI_HOOK, *PBK_NTAPI_HOOK;

VOID BkntkhHookInitialize(_Out_ PBK_NTAPI_HOOK Hook, _In_ const BK_NTAPI_HOOK_DESCRIPTOR *Descriptor);

NTSTATUS BkntkhHookInstall(_Inout_ PBK_NTAPI_HOOK Hook, _Outptr_opt_result_maybenull_ PVOID *Original);

VOID BkntkhHookDeactivate(_Inout_ PBK_NTAPI_HOOK Hook);

VOID BkntkhHookFreeTrampoline(_Inout_ PBK_NTAPI_HOOK Hook);

VOID BkntkhHookRemove(_Inout_ PBK_NTAPI_HOOK Hook);

#endif
