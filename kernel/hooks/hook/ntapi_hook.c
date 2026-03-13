#include <ntddk.h>
#include <intrin.h>
#include <ntstrsafe.h>
#include "ntapi_hook.h"

#if defined(_AMD64_)

#define BLACKBIRD_NTAPI_HOOK_TAG 'pAnB'
#define BLACKBIRD_HOOK_LOG(_level, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, (_level), __VA_ARGS__)
#define BLACKBIRD_SSDT_MAX_SERVICES 8192

typedef struct _BLACKBIRD_KSERVICE_TABLE_DESCRIPTOR
{
    LONG *ServiceTableBase;
    PVOID ServiceCounterTableBase;
    ULONGLONG NumberOfServices;
    PVOID ParamTableBase;
} BLACKBIRD_KSERVICE_TABLE_DESCRIPTOR, *PBLACKBIRD_KSERVICE_TABLE_DESCRIPTOR;

static BOOLEAN BLACKBIRDNtApiIsKernelPointer(_In_opt_ PVOID Address)
{
    if (Address == NULL || MmSystemRangeStart == NULL)
    {
        return FALSE;
    }

    return ((ULONG_PTR)Address >= (ULONG_PTR)MmSystemRangeStart);
}

typedef struct _BLACKBIRD_NTAPI_PATCH_CONTEXT
{
    volatile LONG Applied;
    volatile UCHAR *Destination;
    const UCHAR *Source;
    SIZE_T Size;
} BLACKBIRD_NTAPI_PATCH_CONTEXT, *PBLACKBIRD_NTAPI_PATCH_CONTEXT;

VOID BLACKBIRDNtApiFormatBytes(_In_reads_bytes_(Length) const UCHAR *Bytes, _In_ ULONG Length,
                               _Out_writes_bytes_(OutputSize) PCHAR Output, _In_ SIZE_T OutputSize);
VOID BLACKBIRDNtApiBuildJump(_Out_writes_(BLACKBIRD_NTAPI_PATCH_SIZE) UCHAR *Patch, _In_ PVOID Destination);
VOID BLACKBIRDNtApiRollbackPatchOnInstallFailure(_Inout_ PBLACKBIRD_NTAPI_HOOK Hook, _In_ ULONG OverwriteLength);
NTSTATUS BLACKBIRDNtApiWriteReadonlyMemory(_In_ PVOID Destination, _In_reads_bytes_(Size) const VOID *Source,
                                           _In_ SIZE_T Size);
PVOID BLACKBIRDNtApiResolveAddress(_In_ PCWSTR Name0, _In_opt_ PCWSTR Name1, _In_opt_ PCWSTR Name2);
PVOID BLACKBIRDNtApiResolveViaSsdtSignature(_In_ const BLACKBIRD_NTAPI_HOOK_DESCRIPTOR *Descriptor);

VOID BLACKBIRDNtApiHookInitialize(_Out_ PBLACKBIRD_NTAPI_HOOK Hook,
                                  _In_ const BLACKBIRD_NTAPI_HOOK_DESCRIPTOR *Descriptor)
{
    RtlZeroMemory(Hook, sizeof(*Hook));
    Hook->Descriptor = *Descriptor;
}

NTSTATUS BLACKBIRDNtApiHookInstall(_Inout_ PBLACKBIRD_NTAPI_HOOK Hook, _Outptr_opt_result_maybenull_ PVOID *Original)
{
    NTSTATUS status;
    UCHAR patch[32];
    UCHAR verifyPatch[BLACKBIRD_NTAPI_MAX_OVERWRITE];
    UCHAR trampolineJump[BLACKBIRD_NTAPI_PATCH_SIZE];
    CHAR prologueBytesText[3 * BLACKBIRD_NTAPI_MAX_OVERWRITE + 1];
    CHAR patchBytesText[3 * BLACKBIRD_NTAPI_MAX_OVERWRITE + 1];
    CHAR verifyBytesText[3 * BLACKBIRD_NTAPI_MAX_OVERWRITE + 1];
    CHAR trampolineJumpBytesText[3 * BLACKBIRD_NTAPI_PATCH_SIZE + 1];
    PVOID trampoline;
    ULONG overwriteLength;
    ULONG i;

    if (Hook == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!BLACKBIRDNtApiIsKernelPointer(Hook->Descriptor.HookFunction))
    {
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook invalid hook target api=%s hook=%p.\n",
                           (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                           Hook->Descriptor.HookFunction);
        return STATUS_INVALID_PARAMETER;
    }

    overwriteLength = Hook->Descriptor.OverwriteLength;
    if (overwriteLength < BLACKBIRD_NTAPI_PATCH_SIZE || overwriteLength > sizeof(patch))
    {
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook invalid overwrite length api=%s len=%lu.\n",
                           (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                           overwriteLength);
        return STATUS_INVALID_PARAMETER;
    }

    Hook->RoutineAddress =
        BLACKBIRDNtApiResolveAddress(Hook->Descriptor.Name0, Hook->Descriptor.Name1, Hook->Descriptor.Name2);
    if (Hook->RoutineAddress == NULL)
    {
        BLACKBIRD_HOOK_LOG(DPFLTR_WARNING_LEVEL,
                           "BLACKBIRD: ntapi hook export resolve miss api=%s n0=%ws n1=%ws n2=%ws, trying ssdt.\n",
                           (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                           (Hook->Descriptor.Name0 != NULL) ? Hook->Descriptor.Name0 : L"<null>",
                           (Hook->Descriptor.Name1 != NULL) ? Hook->Descriptor.Name1 : L"<null>",
                           (Hook->Descriptor.Name2 != NULL) ? Hook->Descriptor.Name2 : L"<null>");
        Hook->RoutineAddress = BLACKBIRDNtApiResolveViaSsdtSignature(&Hook->Descriptor);
        if (Hook->RoutineAddress == NULL)
        {
            BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                               "BLACKBIRD: ntapi hook resolve failed api=%s.\n",
                               (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>");
            return STATUS_PROCEDURE_NOT_FOUND;
        }
    }
    if (!BLACKBIRDNtApiIsKernelPointer(Hook->RoutineAddress))
    {
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook invalid routine address api=%s routine=%p.\n",
                           (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                           Hook->RoutineAddress);
        Hook->RoutineAddress = NULL;
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    __try
    {
        RtlCopyMemory(Hook->OriginalPatch, Hook->RoutineAddress, overwriteLength);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook prologue read failed api=%s routine=%p status=0x%08X.\n",
                           (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                           Hook->RoutineAddress,
                           status);
        Hook->RoutineAddress = NULL;
        return status;
    }

    BLACKBIRDNtApiFormatBytes(Hook->OriginalPatch, overwriteLength, prologueBytesText, sizeof(prologueBytesText));
    BLACKBIRD_HOOK_LOG(DPFLTR_INFO_LEVEL,
                       "BLACKBIRD: ntapi hook prologue api=%s routine=%p len=%lu bytes=%s.\n",
                       (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                       Hook->RoutineAddress,
                       overwriteLength,
                       prologueBytesText);

    trampoline =
        ExAllocatePoolWithTag(NonPagedPoolExecute, overwriteLength + BLACKBIRD_NTAPI_PATCH_SIZE, BLACKBIRD_NTAPI_HOOK_TAG);
    if (trampoline == NULL)
    {
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook trampoline alloc failed api=%s.\n",
                           (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(trampoline, overwriteLength + BLACKBIRD_NTAPI_PATCH_SIZE);
    RtlCopyMemory(trampoline, Hook->OriginalPatch, overwriteLength);
    BLACKBIRDNtApiBuildJump(trampolineJump, (PVOID)((PUCHAR)Hook->RoutineAddress + overwriteLength));
    RtlCopyMemory((PUCHAR)trampoline + overwriteLength, trampolineJump, BLACKBIRD_NTAPI_PATCH_SIZE);
    BLACKBIRDNtApiFormatBytes(trampolineJump, BLACKBIRD_NTAPI_PATCH_SIZE, trampolineJumpBytesText,
                              sizeof(trampolineJumpBytesText));
    BLACKBIRD_HOOK_LOG(DPFLTR_INFO_LEVEL,
                       "BLACKBIRD: ntapi hook trampoline jump api=%s bytes=%s target=%p.\n",
                       (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                       trampolineJumpBytesText,
                       (PVOID)((PUCHAR)Hook->RoutineAddress + overwriteLength));

    Hook->Trampoline = trampoline;
    if (Original != NULL)
    {
        *Original = trampoline;
    }

    RtlFillMemory(patch, overwriteLength, 0x90);
    BLACKBIRDNtApiBuildJump(patch, Hook->Descriptor.HookFunction);
    for (i = BLACKBIRD_NTAPI_PATCH_SIZE; i < overwriteLength; ++i)
    {
        patch[i] = 0x90;
    }
    BLACKBIRDNtApiFormatBytes(patch, overwriteLength, patchBytesText, sizeof(patchBytesText));
    BLACKBIRD_HOOK_LOG(DPFLTR_INFO_LEVEL,
                       "BLACKBIRD: ntapi hook patch bytes api=%s bytes=%s.\n",
                       (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                       patchBytesText);

    status = BLACKBIRDNtApiWriteReadonlyMemory(Hook->RoutineAddress, patch, overwriteLength);
    if (!NT_SUCCESS(status))
    {
        if (Original != NULL)
        {
            *Original = NULL;
        }
        Hook->Trampoline = NULL;
        ExFreePoolWithTag(trampoline, BLACKBIRD_NTAPI_HOOK_TAG);
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook patch write failed api=%s routine=%p len=%lu status=0x%08X.\n",
                           (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                           Hook->RoutineAddress,
                           overwriteLength,
                           status);
        Hook->RoutineAddress = NULL;
        return status;
    }

    RtlZeroMemory(verifyPatch, sizeof(verifyPatch));
    __try
    {
        RtlCopyMemory(verifyPatch, Hook->RoutineAddress, overwriteLength);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook verify read failed api=%s routine=%p status=0x%08X.\n",
                           (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                           Hook->RoutineAddress,
                           status);
        BLACKBIRDNtApiRollbackPatchOnInstallFailure(Hook, overwriteLength);
        if (Original != NULL)
        {
            *Original = NULL;
        }
        Hook->Trampoline = NULL;
        ExFreePoolWithTag(trampoline, BLACKBIRD_NTAPI_HOOK_TAG);
        Hook->RoutineAddress = NULL;
        return status;
    }
    BLACKBIRDNtApiFormatBytes(verifyPatch, overwriteLength, verifyBytesText, sizeof(verifyBytesText));
    if (RtlCompareMemory(verifyPatch, patch, overwriteLength) != overwriteLength)
    {
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook verify mismatch api=%s expected=%s actual=%s.\n",
                           (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                           patchBytesText,
                           verifyBytesText);
        BLACKBIRDNtApiRollbackPatchOnInstallFailure(Hook, overwriteLength);
        if (Original != NULL)
        {
            *Original = NULL;
        }
        Hook->Trampoline = NULL;
        ExFreePoolWithTag(trampoline, BLACKBIRD_NTAPI_HOOK_TAG);
        Hook->RoutineAddress = NULL;
        return STATUS_DATA_ERROR;
    }
    BLACKBIRD_HOOK_LOG(DPFLTR_INFO_LEVEL,
                       "BLACKBIRD: ntapi hook verify ok api=%s bytes=%s.\n",
                       (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                       verifyBytesText);

    Hook->Installed = TRUE;
    BLACKBIRD_HOOK_LOG(DPFLTR_INFO_LEVEL,
                       "BLACKBIRD: ntapi hook installed api=%s routine=%p hook=%p trampoline=%p len=%lu.\n",
                       (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                       Hook->RoutineAddress,
                       Hook->Descriptor.HookFunction,
                       Hook->Trampoline,
                       overwriteLength);
    return STATUS_SUCCESS;
}

VOID BLACKBIRDNtApiHookDeactivate(_Inout_ PBLACKBIRD_NTAPI_HOOK Hook)
{
    UCHAR verifyPatch[BLACKBIRD_NTAPI_MAX_OVERWRITE];
    CHAR verifyBytesText[3 * BLACKBIRD_NTAPI_MAX_OVERWRITE + 1];

    if (Hook == NULL)
    {
        return;
    }

    if (Hook->Installed && Hook->RoutineAddress != NULL)
    {
        ULONG overwriteLength = Hook->Descriptor.OverwriteLength;
        NTSTATUS status =
            BLACKBIRDNtApiWriteReadonlyMemory(Hook->RoutineAddress, Hook->OriginalPatch, overwriteLength);
        if (!NT_SUCCESS(status))
        {
            BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                               "BLACKBIRD: ntapi hook restore failed api=%s routine=%p status=0x%08X.\n",
                               (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                               Hook->RoutineAddress,
                               status);
        }
        else
        {
            RtlZeroMemory(verifyPatch, sizeof(verifyPatch));
            __try
            {
                RtlCopyMemory(verifyPatch, Hook->RoutineAddress, overwriteLength);
                BLACKBIRDNtApiFormatBytes(verifyPatch, overwriteLength, verifyBytesText, sizeof(verifyBytesText));
                BLACKBIRD_HOOK_LOG(DPFLTR_INFO_LEVEL,
                                   "BLACKBIRD: ntapi hook restore verify api=%s bytes=%s.\n",
                                   (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                                   verifyBytesText);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                                   "BLACKBIRD: ntapi hook restore verify read failed api=%s routine=%p status=0x%08X.\n",
                                   (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                                   Hook->RoutineAddress,
                                   GetExceptionCode());
            }
        }
    }
    Hook->Installed = FALSE;
}

VOID BLACKBIRDNtApiHookFreeTrampoline(_Inout_ PBLACKBIRD_NTAPI_HOOK Hook)
{
    if (Hook == NULL)
    {
        return;
    }

    if (Hook->Trampoline != NULL)
    {
        ExFreePoolWithTag(Hook->Trampoline, BLACKBIRD_NTAPI_HOOK_TAG);
    }

    Hook->RoutineAddress = NULL;
    Hook->Trampoline = NULL;
    RtlZeroMemory(Hook->OriginalPatch, sizeof(Hook->OriginalPatch));
    Hook->Installed = FALSE;
}

VOID BLACKBIRDNtApiHookRemove(_Inout_ PBLACKBIRD_NTAPI_HOOK Hook)
{
    BLACKBIRDNtApiHookDeactivate(Hook);
    BLACKBIRDNtApiHookFreeTrampoline(Hook);
}

#else

VOID BLACKBIRDNtApiHookInitialize(_Out_ PBLACKBIRD_NTAPI_HOOK Hook,
                                  _In_ const BLACKBIRD_NTAPI_HOOK_DESCRIPTOR *Descriptor)
{
    RtlZeroMemory(Hook, sizeof(*Hook));
    Hook->Descriptor = *Descriptor;
}

NTSTATUS BLACKBIRDNtApiHookInstall(_Inout_ PBLACKBIRD_NTAPI_HOOK Hook, _Outptr_opt_result_maybenull_ PVOID *Original)
{
    UNREFERENCED_PARAMETER(Hook);
    if (Original != NULL)
    {
        *Original = NULL;
    }
    return STATUS_NOT_SUPPORTED;
}

VOID BLACKBIRDNtApiHookRemove(_Inout_ PBLACKBIRD_NTAPI_HOOK Hook)
{
    UNREFERENCED_PARAMETER(Hook);
}

VOID BLACKBIRDNtApiHookDeactivate(_Inout_ PBLACKBIRD_NTAPI_HOOK Hook)
{
    UNREFERENCED_PARAMETER(Hook);
}

VOID BLACKBIRDNtApiHookFreeTrampoline(_Inout_ PBLACKBIRD_NTAPI_HOOK Hook)
{
    UNREFERENCED_PARAMETER(Hook);
}

#endif
