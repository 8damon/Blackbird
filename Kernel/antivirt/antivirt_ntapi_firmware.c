#include "..\hooks\monitor\ntapi_monitor_private.h"

#if defined(_AMD64_)

#pragma pack(push, 1)
typedef struct _BK_RAW_SMBIOS_DATA
{
    UCHAR Used20CallingMethod;
    UCHAR SMBIOSMajorVersion;
    UCHAR SMBIOSMinorVersion;
    UCHAR DmiRevision;
    ULONG Length;
    UCHAR SMBIOSTableData[1];
} BK_RAW_SMBIOS_DATA, *PBK_RAW_SMBIOS_DATA;

typedef struct _BK_SMBIOS_HEADER
{
    UCHAR Type;
    UCHAR Length;
    USHORT Handle;
} BK_SMBIOS_HEADER, *PBK_SMBIOS_HEADER;
#pragma pack(pop)

static VOID BkavNtPatchBoundedString(_Inout_updates_bytes_(CurrentLength) PUCHAR CurrentValue,
                                     _In_ SIZE_T CurrentLength, _In_z_ PCSTR Replacement)
{
    SIZE_T replacementLength;
    SIZE_T copyLength;

    if (CurrentValue == NULL || CurrentLength == 0 || Replacement == NULL)
    {
        return;
    }

    replacementLength = strlen(Replacement);
    copyLength = (replacementLength < CurrentLength) ? replacementLength : CurrentLength;
    if (copyLength != 0)
    {
        RtlCopyMemory(CurrentValue, Replacement, copyLength);
    }
    if (copyLength < CurrentLength)
    {
        RtlFillMemory(CurrentValue + copyLength, CurrentLength - copyLength, ' ');
    }
}

_Success_(return != FALSE) static BOOLEAN
    BkavNtFindSmbiosStringByIndex(_Inout_ PUCHAR StringsStart, _In_ PUCHAR NextStructure, _In_ UCHAR StringIndex,
                                  _Out_ PUCHAR *StringStart, _Out_ PUCHAR *StringEnd)
{
    PUCHAR cursor;
    UCHAR currentIndex;

    if (StringsStart == NULL || NextStructure == NULL || StringStart == NULL || StringEnd == NULL || StringIndex == 0 ||
        StringsStart >= NextStructure)
    {
        return FALSE;
    }

    cursor = StringsStart;
    currentIndex = 1;
    while ((cursor + 1) < NextStructure)
    {
        PUCHAR start = cursor;

        if (*cursor == 0 && *(cursor + 1) == 0)
        {
            break;
        }

        while (cursor < NextStructure && *cursor != 0)
        {
            cursor++;
        }
        if (cursor >= NextStructure)
        {
            break;
        }

        if (currentIndex == StringIndex)
        {
            *StringStart = start;
            *StringEnd = cursor;
            return TRUE;
        }

        cursor++;
        currentIndex++;
    }

    return FALSE;
}

static VOID BkavNtPatchSmbiosString(_Inout_ PUCHAR Structure, _In_ UCHAR StructureLength, _In_ UCHAR StringOffset,
                                    _Inout_ PUCHAR StringsStart, _In_ PUCHAR NextStructure, _In_z_ PCSTR Replacement)
{
    UCHAR stringIndex;
    PUCHAR stringStart;
    PUCHAR stringEnd;

    if (Structure == NULL || StringsStart == NULL || NextStructure == NULL || Replacement == NULL ||
        StringOffset >= StructureLength)
    {
        return;
    }

    stringIndex = Structure[StringOffset];
    if (stringIndex == 0)
    {
        return;
    }

    if (!BkavNtFindSmbiosStringByIndex(StringsStart, NextStructure, stringIndex, &stringStart, &stringEnd))
    {
        return;
    }
    if (stringEnd <= stringStart)
    {
        return;
    }

    BkavNtPatchBoundedString(stringStart, (SIZE_T)(stringEnd - stringStart), Replacement);
}

static VOID BkavNtRandomizeUuid(_Out_writes_(16) PUCHAR UuidBytes)
{
    LARGE_INTEGER qpc;
    ULONG seed;
    UINT32 i;

    if (UuidBytes == NULL)
    {
        return;
    }

    qpc = KeQueryPerformanceCounter(NULL);
    seed = (ULONG)(qpc.LowPart ^ (ULONG)(ULONG_PTR)PsGetCurrentProcessId() ^ (ULONG)(ULONG_PTR)PsGetCurrentThreadId());
    for (i = 0; i < 16; ++i)
    {
        seed = (seed * 1664525u) + 1013904223u;
        UuidBytes[i] = (UCHAR)((seed >> 24) & 0xFFu);
    }

    UuidBytes[6] = (UCHAR)((UuidBytes[6] & 0x0Fu) | 0x40u);
    UuidBytes[8] = (UCHAR)((UuidBytes[8] & 0x3Fu) | 0x80u);
}

static VOID BkavNtSanitizeSmbiosBlob(_Inout_updates_bytes_(RawLength) PUCHAR RawTable, _In_ ULONG RawLength)
{
    PUCHAR cursor;
    PUCHAR end;
    ULONG sanitizedCount = 0;

    if (RawTable == NULL || RawLength < sizeof(BK_SMBIOS_HEADER))
    {
        return;
    }

    cursor = RawTable;
    end = RawTable + RawLength;
    while ((cursor + sizeof(BK_SMBIOS_HEADER)) <= end)
    {
        UCHAR structureType;
        UCHAR structureLength;
        PUCHAR stringsStart;
        PUCHAR nextStructure;

        structureType = cursor[0];
        structureLength = cursor[1];
        if (structureLength < sizeof(BK_SMBIOS_HEADER))
        {
            break;
        }
        if ((cursor + structureLength) > end)
        {
            break;
        }

        stringsStart = cursor + structureLength;
        nextStructure = stringsStart;
        while ((nextStructure + 1) < end)
        {
            if (*nextStructure == 0 && *(nextStructure + 1) == 0)
            {
                nextStructure += 2;
                break;
            }
            nextStructure++;
        }
        if (nextStructure > end || (nextStructure <= stringsStart))
        {
            break;
        }

        if (structureType == 0)
        {
            BkavNtPatchSmbiosString(cursor, structureLength, 4, stringsStart, nextStructure,
                                    "American Megatrends Inc.");
            BkavNtPatchSmbiosString(cursor, structureLength, 5, stringsStart, nextStructure, "F.27");
            BkavNtPatchSmbiosString(cursor, structureLength, 8, stringsStart, nextStructure, "07/15/2021");
            sanitizedCount++;
        }
        else if (structureType == 1)
        {
            BkavNtPatchSmbiosString(cursor, structureLength, 4, stringsStart, nextStructure, "Dell Inc.");
            BkavNtPatchSmbiosString(cursor, structureLength, 5, stringsStart, nextStructure, "XPS 8940");
            BkavNtPatchSmbiosString(cursor, structureLength, 6, stringsStart, nextStructure, "1.0");
            BkavNtPatchSmbiosString(cursor, structureLength, 7, stringsStart, nextStructure, "8CG1234");
            if (structureLength >= 0x18)
            {
                BkavNtRandomizeUuid(cursor + 8);
            }
            sanitizedCount++;
        }
        else if (structureType == 2)
        {
            BkavNtPatchSmbiosString(cursor, structureLength, 4, stringsStart, nextStructure, "Dell Inc.");
            BkavNtPatchSmbiosString(cursor, structureLength, 5, stringsStart, nextStructure, "0K3CM7");
            BkavNtPatchSmbiosString(cursor, structureLength, 6, stringsStart, nextStructure, "A00");
            BkavNtPatchSmbiosString(cursor, structureLength, 7, stringsStart, nextStructure, "CN12345678ABCD");
            sanitizedCount++;
        }
        else if (structureType == 17)
        {
            BkavNtPatchSmbiosString(cursor, structureLength, 0x10, stringsStart, nextStructure, "DIMM A1");
            BkavNtPatchSmbiosString(cursor, structureLength, 0x11, stringsStart, nextStructure, "BANK 0");
        }

        if (structureType == 127)
        {
            break;
        }
        cursor = nextStructure;
    }

    if (sanitizedCount != 0 && InterlockedDecrement(&g_NtApiSmbiosSanitizeApplyBudget) >= 0)
    {
        BK_NTAPI_LOG(DPFLTR_INFO_LEVEL, "BK: ntapi sanitized smbios structures count=%lu.\n", sanitizedCount);
    }
    if (sanitizedCount != 0)
    {
        BkntkiRecordSanitizerHit(BkDiagSanitizerFirmwareTable);
    }
}

VOID BkavNtSanitizeFirmwareTableInformation(_In_ ULONG SystemInformationClass,
                                            _Inout_updates_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                            _In_ ULONG SystemInformationLength, _In_ NTSTATUS Status)
{
    PSYSTEM_FIRMWARE_TABLE_INFORMATION firmwareInfo;
    PBK_RAW_SMBIOS_DATA rawSmbios;
    ULONG availableTableBytes;
    ULONG smbiosPayloadLength;

    if (SystemInformationClass != BK_SYSTEM_INFORMATION_CLASS_FIRMWARE_TABLE || !NT_SUCCESS(Status) ||
        SystemInformation == NULL || SystemInformationLength < sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION))
    {
        return;
    }

    __try
    {
        firmwareInfo = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)SystemInformation;
        if (firmwareInfo->ProviderSignature != BK_FIRMWARE_PROVIDER_RSMB ||
            firmwareInfo->Action != SystemFirmwareTable_Get)
        {
            return;
        }

        availableTableBytes = SystemInformationLength - FIELD_OFFSET(SYSTEM_FIRMWARE_TABLE_INFORMATION, TableBuffer);
        if (firmwareInfo->TableBufferLength > availableTableBytes ||
            firmwareInfo->TableBufferLength < sizeof(BK_RAW_SMBIOS_DATA))
        {
            return;
        }

        rawSmbios = (PBK_RAW_SMBIOS_DATA)firmwareInfo->TableBuffer;
        if (rawSmbios->Length > (firmwareInfo->TableBufferLength - FIELD_OFFSET(BK_RAW_SMBIOS_DATA, SMBIOSTableData)))
        {
            return;
        }
        smbiosPayloadLength = rawSmbios->Length;
        if (smbiosPayloadLength == 0)
        {
            return;
        }

        BkavNtSanitizeSmbiosBlob(rawSmbios->SMBIOSTableData, smbiosPayloadLength);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (InterlockedDecrement(&g_NtApiSmbiosSanitizeBudget) >= 0)
        {
            BK_NTAPI_LOG(DPFLTR_WARNING_LEVEL, "BK: ntapi smbios sanitize failed status=0x%08X ex=0x%08X.\n", Status,
                         GetExceptionCode());
        }
    }
}

#endif
