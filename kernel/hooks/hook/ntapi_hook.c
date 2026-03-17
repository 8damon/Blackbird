#include <ntddk.h>
#include <intrin.h>
#include <ntstrsafe.h>
#include "ntapi_hook.h"
#include "ntapi_hook_ldasm.h"

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

    // Determine the overwrite length.  The descriptor carries a hardcoded hint value chosen
    // at development time; we always try to refine it at runtime using the instruction-length
    // disassembler so that the trampoline never splits a multi-byte instruction when Microsoft
    // ships a CU that changes the function prologue.
    //
    // Strategy:
    //   1. Read up to BLACKBIRD_NTAPI_MAX_OVERWRITE bytes from the routine at this point
    //      (before we have resolved RoutineAddress, so do it after resolution below — see the
    //      second call site).  The block here just validates the descriptor hint as a fallback.
    //   2. BLACKBIRDx64MinCoverLength returns the minimum byte count >= BLACKBIRD_NTAPI_PATCH_SIZE
    //      that lands on an instruction boundary.  If it returns 0 (unknown encoding) we fall
    //      back to the hardcoded descriptor value.
    //   3. The computed length must still fit in the patch buffer (BLACKBIRD_NTAPI_MAX_OVERWRITE).
    overwriteLength = Hook->Descriptor.OverwriteLength;
    if (overwriteLength < BLACKBIRD_NTAPI_PATCH_SIZE || overwriteLength > sizeof(patch))
    {
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook invalid descriptor overwrite length api=%s len=%lu.\n",
                           (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                           overwriteLength);
        return STATUS_INVALID_PARAMETER;
    }

    Hook->RoutineAddress =
        BLACKBIRDNtApiResolveAddress(Hook->Descriptor.Name0, Hook->Descriptor.Name1, Hook->Descriptor.Name2);
    if (Hook->RoutineAddress == NULL)
    {
        BLACKBIRD_HOOK_LOG(DPFLTR_WARNING_LEVEL,
                           "BLACKBIRD: ntapi hook export resolve miss api=%s n0=%ws n1=%ws n2=%ws (trying ssdt fallback).\n",
                           (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                           (Hook->Descriptor.Name0 != NULL) ? Hook->Descriptor.Name0 : L"<null>",
                           (Hook->Descriptor.Name1 != NULL) ? Hook->Descriptor.Name1 : L"<null>",
                           (Hook->Descriptor.Name2 != NULL) ? Hook->Descriptor.Name2 : L"<null>");
        if (Hook->Descriptor.FallbackSignatureSize == 0)
        {
            BLACKBIRD_HOOK_LOG(DPFLTR_WARNING_LEVEL,
                               "BLACKBIRD: ntapi hook ssdt fallback unavailable api=%s reason=no-signature.\n",
                               (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>");
        }
        Hook->RoutineAddress = BLACKBIRDNtApiResolveViaSsdtSignature(&Hook->Descriptor);
        if (Hook->RoutineAddress == NULL)
        {
            BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                               "BLACKBIRD: ntapi hook resolve failed api=%s n0=%ws n1=%ws n2=%ws.\n",
                               (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                               (Hook->Descriptor.Name0 != NULL) ? Hook->Descriptor.Name0 : L"<null>",
                               (Hook->Descriptor.Name1 != NULL) ? Hook->Descriptor.Name1 : L"<null>",
                               (Hook->Descriptor.Name2 != NULL) ? Hook->Descriptor.Name2 : L"<null>");
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

    // Always read the maximum overwrite window so the disassembler has enough bytes to work
    // with regardless of what the descriptor's hint value is.  OriginalPatch is sized at
    // BLACKBIRD_NTAPI_MAX_OVERWRITE so this is always safe.
    __try
    {
        RtlCopyMemory(Hook->OriginalPatch, Hook->RoutineAddress, BLACKBIRD_NTAPI_MAX_OVERWRITE);
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

    // Refine overwriteLength at runtime: find the minimum instruction-boundary-aligned byte
    // count >= BLACKBIRD_NTAPI_PATCH_SIZE.  If the disassembler cannot decode the prologue
    // (uncommon or new encoding) it returns 0 and we keep the descriptor hint unchanged.
    {
        ULONG computed = BLACKBIRDx64MinCoverLength(
                             Hook->OriginalPatch,
                             BLACKBIRD_NTAPI_PATCH_SIZE,
                             BLACKBIRD_NTAPI_MAX_OVERWRITE);
        if (computed != 0 && computed <= BLACKBIRD_NTAPI_MAX_OVERWRITE)
        {
            if (computed != overwriteLength)
            {
                BLACKBIRD_HOOK_LOG(DPFLTR_INFO_LEVEL,
                                   "BLACKBIRD: ntapi hook overwrite length refined api=%s"
                                   " descriptor=%lu computed=%lu.\n",
                                   (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                                   overwriteLength,
                                   computed);
                overwriteLength = computed;
            }
        }
        else
        {
            BLACKBIRD_HOOK_LOG(DPFLTR_WARNING_LEVEL,
                               "BLACKBIRD: ntapi hook overwrite length using descriptor fallback api=%s"
                               " computed=%lu descriptor=%lu.\n",
                               (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                               computed,
                               overwriteLength);
        }
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

    // Initialize patch with the original prologue bytes so that any bytes beyond the 14-byte
    // jump (bytes 14..overwriteLength-1) are identical to the live code.  A NOP sled at those
    // offsets is an unambiguous inline-hook signature that PatchGuard and AV pattern scanners
    // flag; keeping the original bytes there makes the overwritten region indistinguishable
    // from a compiler-emitted prologue to static analysis.
    RtlCopyMemory(patch, Hook->OriginalPatch, overwriteLength);
    BLACKBIRDNtApiBuildJump(patch, Hook->Descriptor.HookFunction);
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

