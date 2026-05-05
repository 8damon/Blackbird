#include <ntddk.h>
#include <intrin.h>
#include <ntstrsafe.h>
#include "ntapi_hook.h"
#include "ntapi_hook_ldasm.h"

#if defined(_AMD64_)

#define BK_NTAPI_HOOK_TAG 'pAnB'
#define BK_HOOK_LOG(_level, ...)                                \
    do                                                          \
    {                                                           \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, (_level), __VA_ARGS__); \
    } while (0)
#define BK_SSDT_MAX_SERVICES 8192

typedef struct _BK_KSERVICE_TABLE_DESCRIPTOR
{
    LONG *ServiceTableBase;
    PVOID ServiceCounterTableBase;
    ULONGLONG NumberOfServices;
    PVOID ParamTableBase;
} BK_KSERVICE_TABLE_DESCRIPTOR, *PBK_KSERVICE_TABLE_DESCRIPTOR;

static BOOLEAN BkntkhIsKernelPointer(_In_opt_ PVOID Address)
{
    if (Address == NULL || MmSystemRangeStart == NULL)
    {
        return FALSE;
    }

    return ((ULONG_PTR)Address >= (ULONG_PTR)MmSystemRangeStart);
}

typedef struct _BK_NTAPI_PATCH_CONTEXT
{
    volatile LONG Applied;
    volatile UCHAR *Destination;
    const UCHAR *Source;
    SIZE_T Size;
} BK_NTAPI_PATCH_CONTEXT, *PBK_NTAPI_PATCH_CONTEXT;

VOID BkntkhFormatBytes(_In_reads_bytes_(Length) const UCHAR *Bytes, _In_ ULONG Length,
                       _Out_writes_bytes_(OutputSize) PCHAR Output, _In_ SIZE_T OutputSize);
VOID BkntkhBuildJump(_Out_writes_(BK_NTAPI_PATCH_SIZE) UCHAR *Patch, _In_ PVOID Destination);
VOID BkntkhRollbackPatchOnInstallFailure(_Inout_ PBK_NTAPI_HOOK Hook, _In_ ULONG OverwriteLength);
NTSTATUS BkntkhWriteReadonlyMemory(_In_ PVOID Destination, _In_reads_bytes_(Size) const VOID *Source, _In_ SIZE_T Size);
PVOID BkntkhResolveAddress(_In_ PCWSTR Name0, _In_opt_ PCWSTR Name1, _In_opt_ PCWSTR Name2);
PVOID BkntkhResolveViaSsdtSignature(_In_ const BK_NTAPI_HOOK_DESCRIPTOR *Descriptor);

static NTSTATUS BkntkhHookApplyPatch(_Inout_ PBK_NTAPI_HOOK Hook, _In_ ULONG OverwriteLength)
{
    NTSTATUS status;
    UCHAR patch[BK_NTAPI_MAX_OVERWRITE];
    UCHAR verifyPatch[BK_NTAPI_MAX_OVERWRITE];
    CHAR patchBytesText[3 * BK_NTAPI_MAX_OVERWRITE + 1];
    CHAR verifyBytesText[3 * BK_NTAPI_MAX_OVERWRITE + 1];

    if (Hook == NULL || Hook->RoutineAddress == NULL || Hook->Descriptor.HookFunction == NULL ||
        OverwriteLength < BK_NTAPI_PATCH_SIZE || OverwriteLength > BK_NTAPI_MAX_OVERWRITE)
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(patch, Hook->OriginalPatch, OverwriteLength);
    BkntkhBuildJump(patch, Hook->Descriptor.HookFunction);
    BkntkhFormatBytes(patch, OverwriteLength, patchBytesText, sizeof(patchBytesText));
    BK_HOOK_LOG(DPFLTR_INFO_LEVEL, "BK: ntapi hook patch bytes api=%s bytes=%s.\n",
                (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>", patchBytesText);

    status = BkntkhWriteReadonlyMemory(Hook->RoutineAddress, patch, OverwriteLength);
    if (!NT_SUCCESS(status))
    {
        BK_HOOK_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook patch write failed api=%s routine=%p len=%lu status=0x%08X.\n",
                    (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>", Hook->RoutineAddress,
                    OverwriteLength, status);
        return status;
    }

    RtlZeroMemory(verifyPatch, sizeof(verifyPatch));
    __try
    {
        RtlCopyMemory(verifyPatch, Hook->RoutineAddress, OverwriteLength);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        BK_HOOK_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook verify read failed api=%s routine=%p status=0x%08X.\n",
                    (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>", Hook->RoutineAddress,
                    status);
        BkntkhRollbackPatchOnInstallFailure(Hook, OverwriteLength);
        return status;
    }

    BkntkhFormatBytes(verifyPatch, OverwriteLength, verifyBytesText, sizeof(verifyBytesText));
    if (RtlCompareMemory(verifyPatch, patch, OverwriteLength) != OverwriteLength)
    {
        BK_HOOK_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook verify mismatch api=%s expected=%s actual=%s.\n",
                    (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>", patchBytesText,
                    verifyBytesText);
        BkntkhRollbackPatchOnInstallFailure(Hook, OverwriteLength);
        return STATUS_DATA_ERROR;
    }

    Hook->Installed = TRUE;
    BK_HOOK_LOG(DPFLTR_INFO_LEVEL, "BK: ntapi hook verify ok api=%s bytes=%s.\n",
                (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>", verifyBytesText);
    return STATUS_SUCCESS;
}

VOID BkntkhHookInitialize(_Out_ PBK_NTAPI_HOOK Hook, _In_ const BK_NTAPI_HOOK_DESCRIPTOR *Descriptor)
{
    RtlZeroMemory(Hook, sizeof(*Hook));
    Hook->Descriptor = *Descriptor;
}

NTSTATUS BkntkhHookInstall(_Inout_ PBK_NTAPI_HOOK Hook, _Outptr_opt_result_maybenull_ PVOID *Original)
{
    NTSTATUS status;
    UCHAR trampolineJump[BK_NTAPI_PATCH_SIZE];
    CHAR prologueBytesText[3 * BK_NTAPI_MAX_OVERWRITE + 1];
    CHAR trampolineJumpBytesText[3 * BK_NTAPI_PATCH_SIZE + 1];
    PVOID trampoline;
    ULONG overwriteLength;

    if (Hook == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (Hook->Installed)
    {
        if (Original != NULL)
        {
            *Original = Hook->Trampoline;
        }
        return STATUS_SUCCESS;
    }
    if (Hook->Trampoline != NULL && Hook->RoutineAddress != NULL &&
        Hook->ActiveOverwriteLength >= BK_NTAPI_PATCH_SIZE &&
        Hook->ActiveOverwriteLength <= BK_NTAPI_MAX_OVERWRITE)
    {
        status = BkntkhHookApplyPatch(Hook, Hook->ActiveOverwriteLength);
        if (NT_SUCCESS(status))
        {
            if (Original != NULL)
            {
                *Original = Hook->Trampoline;
            }
            BK_HOOK_LOG(DPFLTR_INFO_LEVEL, "BK: ntapi hook reactivated api=%s routine=%p trampoline=%p len=%lu.\n",
                        (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                        Hook->RoutineAddress, Hook->Trampoline, Hook->ActiveOverwriteLength);
        }
        return status;
    }
    if (!BkntkhIsKernelPointer(Hook->Descriptor.HookFunction))
    {
        BK_HOOK_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook invalid hook target api=%s hook=%p.\n",
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
    //   1. Read up to BK_NTAPI_MAX_OVERWRITE bytes from the routine at this point
    //      (before we have resolved RoutineAddress, so do it after resolution below — see the
    //      second call site).  The block here just validates the descriptor hint as a fallback.
    //   2. Bkx64MinCoverLength returns the minimum byte count >= BK_NTAPI_PATCH_SIZE
    //      that lands on an instruction boundary.  If it returns 0 (unknown encoding) we fall
    //      back to the hardcoded descriptor value.
    //   3. The computed length must still fit in the patch buffer (BK_NTAPI_MAX_OVERWRITE).
    overwriteLength = Hook->Descriptor.OverwriteLength;
    if (overwriteLength < BK_NTAPI_PATCH_SIZE || overwriteLength > BK_NTAPI_MAX_OVERWRITE)
    {
        BK_HOOK_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook invalid descriptor overwrite length api=%s len=%lu.\n",
                    (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>", overwriteLength);
        return STATUS_INVALID_PARAMETER;
    }

    Hook->RoutineAddress = BkntkhResolveAddress(Hook->Descriptor.Name0, Hook->Descriptor.Name1, Hook->Descriptor.Name2);
    if (Hook->RoutineAddress == NULL && Hook->Descriptor.FallbackNtosOffset != 0)
    {
        PVOID fallbackAddress = (PVOID)(ULONG_PTR)Hook->Descriptor.FallbackNtosOffset;
        if (BkntkhIsKernelPointer(fallbackAddress))
        {
            Hook->RoutineAddress = fallbackAddress;
            BK_HOOK_LOG(DPFLTR_INFO_LEVEL, "BK: ntapi hook direct routine resolved api=%s routine=%p.\n",
                        (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>", Hook->RoutineAddress);
        }
    }
    if (Hook->RoutineAddress == NULL)
    {
        BK_HOOK_LOG(DPFLTR_WARNING_LEVEL,
                    "BK: ntapi hook export resolve miss api=%s n0=%ws n1=%ws n2=%ws (trying ssdt fallback).\n",
                    (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                    (Hook->Descriptor.Name0 != NULL) ? Hook->Descriptor.Name0 : L"<null>",
                    (Hook->Descriptor.Name1 != NULL) ? Hook->Descriptor.Name1 : L"<null>",
                    (Hook->Descriptor.Name2 != NULL) ? Hook->Descriptor.Name2 : L"<null>");
        if (Hook->Descriptor.FallbackSignatureSize == 0)
        {
            BK_HOOK_LOG(DPFLTR_WARNING_LEVEL, "BK: ntapi hook ssdt fallback unavailable api=%s reason=no-signature.\n",
                        (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>");
        }
        Hook->RoutineAddress = BkntkhResolveViaSsdtSignature(&Hook->Descriptor);
        if (Hook->RoutineAddress == NULL)
        {
            BK_HOOK_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook resolve failed api=%s n0=%ws n1=%ws n2=%ws.\n",
                        (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                        (Hook->Descriptor.Name0 != NULL) ? Hook->Descriptor.Name0 : L"<null>",
                        (Hook->Descriptor.Name1 != NULL) ? Hook->Descriptor.Name1 : L"<null>",
                        (Hook->Descriptor.Name2 != NULL) ? Hook->Descriptor.Name2 : L"<null>");
            return STATUS_PROCEDURE_NOT_FOUND;
        }
    }
    if (!BkntkhIsKernelPointer(Hook->RoutineAddress))
    {
        BK_HOOK_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook invalid routine address api=%s routine=%p.\n",
                    (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>", Hook->RoutineAddress);
        Hook->RoutineAddress = NULL;
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // Always read the maximum overwrite window so the disassembler has enough bytes to work
    // with regardless of what the descriptor's hint value is.  OriginalPatch is sized at
    // BK_NTAPI_MAX_OVERWRITE so this is always safe.
    __try
    {
        RtlCopyMemory(Hook->OriginalPatch, Hook->RoutineAddress, BK_NTAPI_MAX_OVERWRITE);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        BK_HOOK_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook prologue read failed api=%s routine=%p status=0x%08X.\n",
                    (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>", Hook->RoutineAddress,
                    status);
        Hook->RoutineAddress = NULL;
        return status;
    }

    // Refine overwriteLength at runtime: find the minimum instruction-boundary-aligned byte
    // count >= BK_NTAPI_PATCH_SIZE.  If the disassembler cannot decode the prologue
    // (uncommon or new encoding) it returns 0 and we keep the descriptor hint unchanged.
    {
        ULONG computed = Bkx64MinCoverLength(Hook->OriginalPatch, BK_NTAPI_PATCH_SIZE, BK_NTAPI_MAX_OVERWRITE);
        if (computed != 0 && computed <= BK_NTAPI_MAX_OVERWRITE)
        {
            if (computed != overwriteLength)
            {
                BK_HOOK_LOG(DPFLTR_INFO_LEVEL,
                            "BK: ntapi hook overwrite length refined api=%s"
                            " descriptor=%lu computed=%lu.\n",
                            (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>", overwriteLength,
                            computed);
                overwriteLength = computed;
            }
        }
        else
        {
            BK_HOOK_LOG(DPFLTR_WARNING_LEVEL,
                        "BK: ntapi hook overwrite length using descriptor fallback api=%s"
                        " computed=%lu descriptor=%lu.\n",
                        (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>", computed,
                        overwriteLength);
        }
    }

    BkntkhFormatBytes(Hook->OriginalPatch, overwriteLength, prologueBytesText, sizeof(prologueBytesText));
    BK_HOOK_LOG(DPFLTR_INFO_LEVEL, "BK: ntapi hook prologue api=%s routine=%p len=%lu bytes=%s.\n",
                (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>", Hook->RoutineAddress,
                overwriteLength, prologueBytesText);

    trampoline = ExAllocatePoolWithTag(NonPagedPoolExecute, overwriteLength + BK_NTAPI_PATCH_SIZE, BK_NTAPI_HOOK_TAG);
    if (trampoline == NULL)
    {
        BK_HOOK_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook trampoline alloc failed api=%s.\n",
                    (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(trampoline, overwriteLength + BK_NTAPI_PATCH_SIZE);
    RtlCopyMemory(trampoline, Hook->OriginalPatch, overwriteLength);
    BkntkhBuildJump(trampolineJump, (PVOID)((PUCHAR)Hook->RoutineAddress + overwriteLength));
    RtlCopyMemory((PUCHAR)trampoline + overwriteLength, trampolineJump, BK_NTAPI_PATCH_SIZE);
    BkntkhFormatBytes(trampolineJump, BK_NTAPI_PATCH_SIZE, trampolineJumpBytesText, sizeof(trampolineJumpBytesText));
    BK_HOOK_LOG(DPFLTR_INFO_LEVEL, "BK: ntapi hook trampoline jump api=%s bytes=%s target=%p.\n",
                (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>", trampolineJumpBytesText,
                (PVOID)((PUCHAR)Hook->RoutineAddress + overwriteLength));

    Hook->Trampoline = trampoline;
    Hook->ActiveOverwriteLength = overwriteLength;
    if (Original != NULL)
    {
        *Original = trampoline;
    }

    status = BkntkhHookApplyPatch(Hook, overwriteLength);
    if (!NT_SUCCESS(status))
    {
        if (Original != NULL)
        {
            *Original = NULL;
        }
        Hook->Trampoline = NULL;
        ExFreePoolWithTag(trampoline, BK_NTAPI_HOOK_TAG);
        Hook->ActiveOverwriteLength = 0;
        Hook->RoutineAddress = NULL;
        return status;
    }
    BK_HOOK_LOG(DPFLTR_INFO_LEVEL, "BK: ntapi hook installed api=%s routine=%p hook=%p trampoline=%p len=%lu.\n",
                (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>", Hook->RoutineAddress,
                Hook->Descriptor.HookFunction, Hook->Trampoline, overwriteLength);
    return STATUS_SUCCESS;
}

VOID BkntkhHookDeactivate(_Inout_ PBK_NTAPI_HOOK Hook)
{
    UCHAR verifyPatch[BK_NTAPI_MAX_OVERWRITE];
    CHAR verifyBytesText[3 * BK_NTAPI_MAX_OVERWRITE + 1];

    if (Hook == NULL)
    {
        return;
    }

    if (Hook->Installed && Hook->RoutineAddress != NULL)
    {
        ULONG overwriteLength = Hook->ActiveOverwriteLength;
        if (overwriteLength < BK_NTAPI_PATCH_SIZE || overwriteLength > BK_NTAPI_MAX_OVERWRITE)
        {
            overwriteLength = Hook->Descriptor.OverwriteLength;
        }
        NTSTATUS status = BkntkhWriteReadonlyMemory(Hook->RoutineAddress, Hook->OriginalPatch, overwriteLength);
        if (!NT_SUCCESS(status))
        {
            BK_HOOK_LOG(DPFLTR_ERROR_LEVEL, "BK: ntapi hook restore failed api=%s routine=%p status=0x%08X.\n",
                        (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>", Hook->RoutineAddress,
                        status);
        }
        else
        {
            RtlZeroMemory(verifyPatch, sizeof(verifyPatch));
            __try
            {
                RtlCopyMemory(verifyPatch, Hook->RoutineAddress, overwriteLength);
                BkntkhFormatBytes(verifyPatch, overwriteLength, verifyBytesText, sizeof(verifyBytesText));
                BK_HOOK_LOG(DPFLTR_INFO_LEVEL, "BK: ntapi hook restore verify api=%s bytes=%s.\n",
                            (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>", verifyBytesText);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                BK_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                            "BK: ntapi hook restore verify read failed api=%s routine=%p status=0x%08X.\n",
                            (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                            Hook->RoutineAddress, GetExceptionCode());
            }
        }
    }
    Hook->Installed = FALSE;
}

VOID BkntkhHookFreeTrampoline(_Inout_ PBK_NTAPI_HOOK Hook)
{
    if (Hook == NULL)
    {
        return;
    }

    if (Hook->Trampoline != NULL)
    {
        ExFreePoolWithTag(Hook->Trampoline, BK_NTAPI_HOOK_TAG);
    }

    Hook->RoutineAddress = NULL;
    Hook->Trampoline = NULL;
    Hook->ActiveOverwriteLength = 0;
    RtlZeroMemory(Hook->OriginalPatch, sizeof(Hook->OriginalPatch));
    Hook->Installed = FALSE;
}

VOID BkntkhHookRemove(_Inout_ PBK_NTAPI_HOOK Hook)
{
    BkntkhHookDeactivate(Hook);
    BkntkhHookFreeTrampoline(Hook);
}

#else

VOID BkntkhHookInitialize(_Out_ PBK_NTAPI_HOOK Hook, _In_ const BK_NTAPI_HOOK_DESCRIPTOR *Descriptor)
{
    RtlZeroMemory(Hook, sizeof(*Hook));
    Hook->Descriptor = *Descriptor;
}

NTSTATUS BkntkhHookInstall(_Inout_ PBK_NTAPI_HOOK Hook, _Outptr_opt_result_maybenull_ PVOID *Original)
{
    UNREFERENCED_PARAMETER(Hook);
    if (Original != NULL)
    {
        *Original = NULL;
    }
    return STATUS_NOT_SUPPORTED;
}

VOID BkntkhHookRemove(_Inout_ PBK_NTAPI_HOOK Hook)
{
    UNREFERENCED_PARAMETER(Hook);
}

VOID BkntkhHookDeactivate(_Inout_ PBK_NTAPI_HOOK Hook)
{
    UNREFERENCED_PARAMETER(Hook);
}

VOID BkntkhHookFreeTrampoline(_Inout_ PBK_NTAPI_HOOK Hook)
{
    UNREFERENCED_PARAMETER(Hook);
}

#endif
