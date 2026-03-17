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

typedef struct _BLACKBIRD_NTAPI_PATCH_CONTEXT
{
    volatile LONG Applied;
    volatile UCHAR *Destination;
    const UCHAR *Source;
    SIZE_T Size;
} BLACKBIRD_NTAPI_PATCH_CONTEXT, *PBLACKBIRD_NTAPI_PATCH_CONTEXT;

NTSTATUS BLACKBIRDNtApiWriteReadonlyMemory(_In_ PVOID Destination, _In_reads_bytes_(Size) const VOID *Source,
                                           _In_ SIZE_T Size);

VOID BLACKBIRDNtApiFormatBytes(_In_reads_bytes_(Length) const UCHAR *Bytes, _In_ ULONG Length,
                                      _Out_writes_bytes_(OutputSize) PCHAR Output, _In_ SIZE_T OutputSize)
{
    ULONG i;
    SIZE_T offset = 0;
    NTSTATUS status;

    if (Output == NULL || OutputSize == 0)
    {
        return;
    }

    Output[0] = '\0';
    if (Bytes == NULL || Length == 0)
    {
        return;
    }

    for (i = 0; i < Length; ++i)
    {
        if ((offset + 4) > OutputSize)
        {
            break;
        }
        status = RtlStringCbPrintfA(Output + offset, OutputSize - offset, "%02X ", Bytes[i]);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        offset += 3;
    }
}

static ULONG_PTR BLACKBIRDNtApiBroadcastWrite(_In_ ULONG_PTR Context)
{
    PBLACKBIRD_NTAPI_PATCH_CONTEXT patchContext;
    SIZE_T i;

    patchContext = (PBLACKBIRD_NTAPI_PATCH_CONTEXT)Context;
    if (patchContext == NULL || patchContext->Destination == NULL || patchContext->Source == NULL ||
        patchContext->Size == 0)
    {
        return 0;
    }
    if (InterlockedCompareExchange(&patchContext->Applied, 1, 0) == 0)
    {
        // Commit bytes 1..Size-1 first, then byte 0 last ("commit-last" pattern).
        // Byte 0 of our patch is 0xFF (the JMP opcode prefix).  Writing the tail bytes first
        // means any concurrent observer that reads the hook site before we finish still sees
        // the original byte 0, which is a valid instruction start; the site is therefore in a
        // consistent (pre-hook) state until the final atomic store makes the jump live.
        for (i = 1; i < patchContext->Size; ++i)
        {
            patchContext->Destination[i] = patchContext->Source[i];
        }
        patchContext->Destination[0] = patchContext->Source[0];

        // KeMemoryBarrier() issues an MFENCE (data store barrier) but is not a serialising
        // instruction and does not flush the instruction cache on remote processors.  Self-
        // modifying code on x86-64 requires a serialising instruction on the modifying CPU
        // after the stores complete so that subsequent instruction fetches on ALL CPUs pick up
        // the new bytes.  CPUID is the lightest serialising instruction available in ring 0 on
        // both Intel and AMD.  The IPI delivery already forced a serialising interrupt on every
        // remote CPU before they resumed, so the CPUID here covers only the writing CPU itself.
        KeMemoryBarrier();
        {
            int cpuInfo[4];
            __cpuid(cpuInfo, 0);
        }
    }

    return 0;
}

VOID BLACKBIRDNtApiBuildJump(_Out_writes_(BLACKBIRD_NTAPI_PATCH_SIZE) UCHAR *Patch, _In_ PVOID Destination)
{
    ULONGLONG destination64;
    ULONG displacement = 0;

    destination64 = (ULONGLONG)(ULONG_PTR)Destination;
    Patch[0] = 0xFF; // jmp qword ptr [rip+0]
    Patch[1] = 0x25;
    RtlCopyMemory(&Patch[2], &displacement, sizeof(displacement));
    RtlCopyMemory(&Patch[6], &destination64, sizeof(destination64));
}

VOID BLACKBIRDNtApiRollbackPatchOnInstallFailure(_Inout_ PBLACKBIRD_NTAPI_HOOK Hook, _In_ ULONG OverwriteLength)
{
    NTSTATUS rollbackStatus;

    if (Hook == NULL || Hook->RoutineAddress == NULL || OverwriteLength == 0)
    {
        return;
    }

    rollbackStatus = BLACKBIRDNtApiWriteReadonlyMemory(Hook->RoutineAddress, Hook->OriginalPatch, OverwriteLength);
    if (!NT_SUCCESS(rollbackStatus))
    {
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook rollback failed api=%s routine=%p status=0x%08X.\n",
                           (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                           Hook->RoutineAddress,
                           rollbackStatus);
    }
    else
    {
        BLACKBIRD_HOOK_LOG(DPFLTR_INFO_LEVEL,
                           "BLACKBIRD: ntapi hook rollback restored api=%s routine=%p.\n",
                           (Hook->Descriptor.ApiName != NULL) ? Hook->Descriptor.ApiName : "<null>",
                           Hook->RoutineAddress);
    }
}

NTSTATUS BLACKBIRDNtApiWriteReadonlyMemory(_In_ PVOID Destination, _In_reads_bytes_(Size) const VOID *Source,
                                                  _In_ SIZE_T Size)
{
    PMDL mdl;
    PVOID mappedAddress = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    BLACKBIRD_NTAPI_PATCH_CONTEXT patchContext;

    if (Destination == NULL || Source == NULL || Size == 0 || Size > MAXULONG)
    {
        return STATUS_INVALID_PARAMETER;
    }

    mdl = IoAllocateMdl(Destination, (ULONG)Size, FALSE, FALSE, NULL);
    if (mdl == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try
    {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook probe/lock failed dst=%p size=%Iu status=0x%08X.\n",
                           Destination,
                           Size,
                           status);
    }

    if (!NT_SUCCESS(status))
    {
        IoFreeMdl(mdl);
        return status;
    }

    // Use MmCached so the write alias shares the same cache type as the original WB mapping.
    // Using MmNonCached would create overlapping UC/WB aliases to the same physical page, which
    // Intel vol. 3A §11.12.4 describes as producing model-specific (undefined) behaviour and can
    // cause the write to bypass the L1/L2 cache entirely, leaving remote CPU icaches stale in a
    // way that MFENCE alone cannot resolve.  With MmCached the store goes through the normal WB
    // cache hierarchy and the IPI-forced serialisation on each remote CPU is sufficient.
    mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (mappedAddress == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook map-locked-pages failed dst=%p size=%Iu.\n",
                           Destination,
                           Size);
        goto Exit;
    }

    status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook protect-mdl failed dst=%p size=%Iu status=0x%08X.\n",
                           Destination,
                           Size,
                           status);
        goto Exit;
    }

    patchContext.Applied = 0;
    patchContext.Destination = (volatile UCHAR *)mappedAddress;
    patchContext.Source = (const UCHAR *)Source;
    patchContext.Size = Size;

    __try
    {
        KeIpiGenericCall(BLACKBIRDNtApiBroadcastWrite, (ULONG_PTR)&patchContext);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook broadcast copy failed dst=%p mapped=%p size=%Iu status=0x%08X.\n",
                           Destination,
                           mappedAddress,
                           Size,
                           status);
    }
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    if (InterlockedCompareExchange(&patchContext.Applied, 0, 0) == 0)
    {
        status = STATUS_UNSUCCESSFUL;
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook broadcast copy not applied dst=%p mapped=%p size=%Iu.\n",
                           Destination,
                           mappedAddress,
                           Size);
        goto Exit;
    }
    KeMemoryBarrier();

Exit:
    if (mappedAddress != NULL)
    {
        MmUnmapLockedPages(mappedAddress, mdl);
    }
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return status;
}

PVOID BLACKBIRDNtApiResolveAddress(_In_ PCWSTR Name0, _In_opt_ PCWSTR Name1, _In_opt_ PCWSTR Name2)
{
    UNICODE_STRING us;
    PVOID address = NULL;

    if (Name0 != NULL)
    {
        RtlInitUnicodeString(&us, Name0);
        address = MmGetSystemRoutineAddress(&us);
        if (address != NULL)
        {
            return address;
        }
    }
    if (Name1 != NULL)
    {
        RtlInitUnicodeString(&us, Name1);
        address = MmGetSystemRoutineAddress(&us);
        if (address != NULL)
        {
            return address;
        }
    }
    if (Name2 != NULL)
    {
        RtlInitUnicodeString(&us, Name2);
        address = MmGetSystemRoutineAddress(&us);
    }

    return address;
}

static BOOLEAN BLACKBIRDNtApiAddressMatchesSignature(_In_ PVOID Address, _In_reads_bytes_(Size) const UCHAR *Signature,
                                                     _In_ ULONG Size)
{
    ULONG i;
    volatile const UCHAR *bytes;

    if (Address == NULL || Signature == NULL || Size == 0)
    {
        return FALSE;
    }

    bytes = (volatile const UCHAR *)Address;
    __try
    {
        for (i = 0; i < Size; ++i)
        {
            if (bytes[i] != Signature[i])
            {
                return FALSE;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }

    return TRUE;
}

static PBLACKBIRD_KSERVICE_TABLE_DESCRIPTOR BLACKBIRDNtApiResolveServiceDescriptor(VOID)
{
    UNICODE_STRING name;
    PVOID address;

    RtlInitUnicodeString(&name, L"KeServiceDescriptorTable");
    address = MmGetSystemRoutineAddress(&name);
    if (address != NULL)
    {
        return (PBLACKBIRD_KSERVICE_TABLE_DESCRIPTOR)address;
    }

    RtlInitUnicodeString(&name, L"KeServiceDescriptorTableShadow");
    address = MmGetSystemRoutineAddress(&name);
    if (address != NULL)
    {
        return (PBLACKBIRD_KSERVICE_TABLE_DESCRIPTOR)address;
    }

    return NULL;
}

static BOOLEAN BLACKBIRDNtApiIsLikelyDescriptor(_In_ PBLACKBIRD_KSERVICE_TABLE_DESCRIPTOR Candidate)
{
    PBLACKBIRD_KSERVICE_TABLE_DESCRIPTOR d = Candidate;
    LONG *table;
    ULONGLONG count;
    LONG firstEntry;

    if (d == NULL)
    {
        return FALSE;
    }

    __try
    {
        table = d->ServiceTableBase;
        count = d->NumberOfServices;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }

    if (table == NULL || count == 0 || count > BLACKBIRD_SSDT_MAX_SERVICES)
    {
        return FALSE;
    }
    if ((ULONG_PTR)table < (ULONG_PTR)MmSystemRangeStart)
    {
        return FALSE;
    }

    __try
    {
        firstEntry = table[0];
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }

    UNREFERENCED_PARAMETER(firstEntry);
    return TRUE;
}

static PBLACKBIRD_KSERVICE_TABLE_DESCRIPTOR BLACKBIRDNtApiResolveServiceDescriptorFromLstar(VOID)
{
    ULONGLONG lstar;
    PUCHAR entry;
    ULONG i;

    lstar = __readmsr(0xC0000082); // IA32_LSTAR
    entry = (PUCHAR)(ULONG_PTR)lstar;
    if (entry == NULL || (ULONG_PTR)entry < (ULONG_PTR)MmSystemRangeStart)
    {
        return NULL;
    }

    // Look for RIP-relative LEA that points to a valid KSERVICE_TABLE_DESCRIPTOR.
    for (i = 0; i < 0x600; ++i)
    {
        LONG disp;
        PUCHAR instr;
        PBLACKBIRD_KSERVICE_TABLE_DESCRIPTOR candidate;
        BOOLEAN isLeaRip;

        instr = entry + i;
        __try
        {
            isLeaRip = (instr[0] == 0x4C && instr[1] == 0x8D &&
                        (instr[2] == 0x15 || instr[2] == 0x1D || instr[2] == 0x25 || instr[2] == 0x2D));
            if (!isLeaRip)
            {
                continue;
            }

            disp = *(LONG *)&instr[3];
            candidate = (PBLACKBIRD_KSERVICE_TABLE_DESCRIPTOR)(instr + 7 + disp);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            continue;
        }

        if (!BLACKBIRDNtApiIsLikelyDescriptor(candidate))
        {
            continue;
        }

        BLACKBIRD_HOOK_LOG(DPFLTR_INFO_LEVEL,
                           "BLACKBIRD: ntapi hook ssdt descriptor via lstar entry=%p candidate=%p scanOffset=0x%lX.\n",
                           entry,
                           candidate,
                           i);
        return candidate;
    }

    return NULL;
}

PVOID BLACKBIRDNtApiResolveViaSsdtSignature(_In_ const BLACKBIRD_NTAPI_HOOK_DESCRIPTOR *Descriptor)
{
    PBLACKBIRD_KSERVICE_TABLE_DESCRIPTOR descriptor;
    LONG *table;
    ULONG serviceCount;
    ULONG i;
    ULONG matchCount = 0;
    PVOID firstMatch = NULL;

    if (Descriptor == NULL || Descriptor->FallbackSignatureSize == 0 ||
        Descriptor->FallbackSignatureSize > sizeof(Descriptor->FallbackSignature))
    {
        return NULL;
    }

    descriptor = BLACKBIRDNtApiResolveServiceDescriptor();
    if (descriptor == NULL)
    {
        descriptor = BLACKBIRDNtApiResolveServiceDescriptorFromLstar();
    }
    if (descriptor == NULL)
    {
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook ssdt descriptor not resolved api=%s.\n",
                           (Descriptor->ApiName != NULL) ? Descriptor->ApiName : "<null>");
        return NULL;
    }
    table = descriptor->ServiceTableBase;
    if (table == NULL || descriptor->NumberOfServices == 0)
    {
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook ssdt invalid table api=%s table=%p count=%llu.\n",
                           (Descriptor->ApiName != NULL) ? Descriptor->ApiName : "<null>",
                           table,
                           descriptor->NumberOfServices);
        return NULL;
    }

    serviceCount =
        (descriptor->NumberOfServices > BLACKBIRD_SSDT_MAX_SERVICES) ? BLACKBIRD_SSDT_MAX_SERVICES : (ULONG)descriptor->NumberOfServices;
    for (i = 0; i < serviceCount; ++i)
    {
        LONG entry;
        PUCHAR candidate;
        BOOLEAN matched;

        __try
        {
            entry = table[i];
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            continue;
        }

        candidate = (PUCHAR)table + (((LONG_PTR)entry) >> 4);
        matched = BLACKBIRDNtApiAddressMatchesSignature(candidate, Descriptor->FallbackSignature,
                                                        Descriptor->FallbackSignatureSize);
        if (!matched)
        {
            continue;
        }

        if (firstMatch == NULL)
        {
            firstMatch = candidate;
        }
        matchCount += 1;
    }

    if (firstMatch == NULL)
    {
        BLACKBIRD_HOOK_LOG(DPFLTR_ERROR_LEVEL,
                           "BLACKBIRD: ntapi hook ssdt signature match failed api=%s siglen=%lu.\n",
                           (Descriptor->ApiName != NULL) ? Descriptor->ApiName : "<null>",
                           Descriptor->FallbackSignatureSize);
        return NULL;
    }

    BLACKBIRD_HOOK_LOG((matchCount == 1) ? DPFLTR_INFO_LEVEL : DPFLTR_WARNING_LEVEL,
                       "BLACKBIRD: ntapi hook ssdt signature resolved api=%s address=%p matches=%lu.\n",
                       (Descriptor->ApiName != NULL) ? Descriptor->ApiName : "<null>",
                       firstMatch,
                       matchCount);
    return firstMatch;
}


#endif



