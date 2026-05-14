#include <ntddk.h>
#include "..\core\unicode_utils.h"
#include "..\core\runtime_config.h"
#include "registry_concealment.h"

BOOLEAN BkavRegPathIsHighValue(_In_opt_ PCUNICODE_STRING Path)
{
    if (Path == NULL || Path->Buffer == NULL)
    {
        return FALSE;
    }

    if (BkstrUnicodeContainsInsensitive(Path, L"\\currentversion\\run", 19) ||
        BkstrUnicodeContainsInsensitive(Path, L"\\currentversion\\runonce", 23) ||
        BkstrUnicodeContainsInsensitive(Path, L"\\image file execution options", 29) ||
        BkstrUnicodeContainsInsensitive(Path, L"\\system\\currentcontrolset\\services\\", 35))
    {
        return TRUE;
    }

    return FALSE;
}

BOOLEAN BkavRegNullPath(_In_opt_ PCUNICODE_STRING Path)
{
    if (Path == NULL || Path->Buffer == NULL)
    {
        return FALSE;
    }

    if (BkrtIsAntiVirtualizationEnabled() && (BkstrUnicodeContainsInsensitive(Path, L"\\services\\vmicheartbeat", 23) ||
                                              BkstrUnicodeContainsInsensitive(Path, L"\\services\\vmicvmsession", 23) ||
                                              BkstrUnicodeContainsInsensitive(Path, L"\\services\\vmictimesync", 22) ||
                                              BkstrUnicodeContainsInsensitive(Path, L"\\services\\vmicvss", 17)))
    {
        return TRUE;
    }

    if (BkrtIsAntiVirtualizationEnabled() && (BkstrUnicodeContainsInsensitive(Path, L"\\services\\vmhgfs", 16) ||
                                              BkstrUnicodeContainsInsensitive(Path, L"\\services\\vmmouse", 17) ||
                                              BkstrUnicodeContainsInsensitive(Path, L"\\services\\vmrawdsk", 18) ||
                                              BkstrUnicodeContainsInsensitive(Path, L"\\services\\vmusbmouse", 20) ||
                                              BkstrUnicodeContainsInsensitive(Path, L"\\services\\vmxnet", 16) ||
                                              BkstrUnicodeContainsInsensitive(Path, L"\\services\\vmci", 14) ||
                                              BkstrUnicodeContainsInsensitive(Path, L"\\services\\vsock", 15) ||
                                              BkstrUnicodeContainsInsensitive(Path, L"\\services\\vmbus", 15) ||
                                              BkstrUnicodeContainsInsensitive(Path, L"\\services\\hyperkbd", 18) ||
                                              BkstrUnicodeContainsInsensitive(Path, L"\\services\\storflt", 17) ||
                                              BkstrUnicodeContainsInsensitive(Path, L"\\services\\vmstorfl", 18)))
    {
        return TRUE;
    }

    if (BkrtIsAntiVirtualizationEnabled() && (BkstrUnicodeContainsInsensitive(Path, L"\\services\\vboxguest", 19) ||
                                              BkstrUnicodeContainsInsensitive(Path, L"\\services\\vboxmouse", 19) ||
                                              BkstrUnicodeContainsInsensitive(Path, L"\\services\\vboxservice", 21) ||
                                              BkstrUnicodeContainsInsensitive(Path, L"\\services\\vboxsf", 16)))
    {
        return TRUE;
    }

    if (BkrtIsAntiVirtualizationEnabled() &&
        (BkstrUnicodeContainsInsensitive(Path, L"\\software\\vmware, inc.\\vmware tools", 34) ||
         BkstrUnicodeContainsInsensitive(Path, L"\\enum\\pci\\ven_15ad", 19)))
    {
        return TRUE;
    }

    return FALSE;
}
VOID BkavRegBuildPathForCompare(_In_ PLARGE_INTEGER Cookie, _In_opt_ PVOID RootObject,
                                _In_opt_ PCUNICODE_STRING CompleteName, _Out_writes_z_(PathChars) PWSTR PathBuffer,
                                _In_ SIZE_T PathChars, _Out_ PUNICODE_STRING PathUs)
{
    SIZE_T offsetChars = 0;

    if (PathBuffer == NULL || PathChars == 0 || PathUs == NULL)
    {
        return;
    }

    PathBuffer[0] = L'\0';
    RtlInitUnicodeString(PathUs, NULL);

    if (CompleteName == NULL || CompleteName->Buffer == NULL || CompleteName->Length == 0)
    {
        return;
    }

    if (CompleteName->Buffer[0] == L'\\' || RootObject == NULL)
    {
        BkstrSafeCopyUnicode(CompleteName, PathBuffer, PathChars);
    }
    else
    {
        PUNICODE_STRING rootName = NULL;
        NTSTATUS status = CmCallbackGetKeyObjectIDEx(Cookie, RootObject, NULL, &rootName, 0);

        if (NT_SUCCESS(status) && rootName != NULL)
        {
            BkstrSafeCopyUnicode(rootName, PathBuffer, PathChars);
            offsetChars = wcslen(PathBuffer);
            if (offsetChars > 0 && offsetChars < (PathChars - 1) && PathBuffer[offsetChars - 1] != L'\\')
            {
                PathBuffer[offsetChars++] = L'\\';
                PathBuffer[offsetChars] = L'\0';
            }
            if (offsetChars < (PathChars - 1))
            {
                SIZE_T remainingChars = PathChars - offsetChars;
                SIZE_T nameChars = CompleteName->Length / sizeof(WCHAR);

                if (nameChars >= remainingChars)
                {
                    nameChars = remainingChars - 1;
                }
                if (nameChars != 0)
                {
                    RtlCopyMemory(PathBuffer + offsetChars, CompleteName->Buffer, nameChars * sizeof(WCHAR));
                    PathBuffer[offsetChars + nameChars] = L'\0';
                }
            }
            CmCallbackReleaseKeyObjectIDEx(rootName);
        }
        else
        {
            BkstrSafeCopyUnicode(CompleteName, PathBuffer, PathChars);
        }
    }

    RtlInitUnicodeString(PathUs, PathBuffer);
}

static VOID BkavBlindWideString(_Inout_updates_bytes_(DataLength) PUCHAR DataBytes, _In_ ULONG DataLength,
                                _In_z_ PCWSTR Replacement)
{
    ULONG i = 0;
    ULONG maxChars;
    PWCHAR dest;

    if (DataBytes == NULL || DataLength < sizeof(WCHAR) || Replacement == NULL)
    {
        return;
    }

    dest = (PWCHAR)(PVOID)DataBytes;
    maxChars = DataLength / sizeof(WCHAR);

    while (i < maxChars && Replacement[i] != L'\0')
    {
        dest[i] = Replacement[i];
        i++;
    }
    while (i < maxChars)
    {
        dest[i] = L'\0';
        i++;
    }
}

/* Replace the first 3 bytes (OUI) of a binary MAC address with the Intel Corporate
 * OUI 8C:8D:28, leaving the device-specific last 3 bytes intact. */
static VOID BkavBlindOuiBinary(_Inout_updates_bytes_(DataLength) PUCHAR DataBytes, _In_ ULONG DataLength)
{
    if (DataBytes == NULL || DataLength < 6)
    {
        return;
    }
    DataBytes[0] = 0x8Cu;
    DataBytes[1] = 0x8Du;
    DataBytes[2] = 0x28u;
}

/* Replace the OUI portion of a REG_SZ MAC string ("XXXXXXXXXXXX", 12 wide chars minimum)
 * with the hex digits for Intel OUI 8C8D28. */
static VOID BkavBlindOuiString(_Inout_updates_bytes_(DataLength) PUCHAR DataBytes, _In_ ULONG DataLength)
{
    static const WCHAR kOuiHex[] = L"8C8D28";
    PWCHAR dest;
    ULONG maxChars;
    ULONG i;

    if (DataBytes == NULL || DataLength < 6 * sizeof(WCHAR))
    {
        return;
    }

    dest = (PWCHAR)(PVOID)DataBytes;
    maxChars = DataLength / sizeof(WCHAR);

    for (i = 0; i < 6 && i < maxChars; ++i)
    {
        dest[i] = kOuiHex[i];
    }
}

BOOLEAN BkavRegBlindNicValue(_In_ PLARGE_INTEGER Cookie, _In_opt_ PVOID Object,
                             _In_ PREG_QUERY_VALUE_KEY_INFORMATION PreInfo)
{
    /* Network Adapters device setup class GUID â€” all NIC miniport driver instances
     * are registered under this key in CurrentControlSet\Control\Class. */
    static const WCHAR kNicClassGuid[] = L"{4d36e972-e325-11ce-bfc1-08002be10318}";
    static const USHORT kNicClassGuidLen = 38u;

    PKEY_VALUE_PARTIAL_INFORMATION partialInfo;
    PUNICODE_STRING keyNamePtr = NULL;
    UNICODE_STRING nicKeyPath;
    NTSTATUS nameStatus;
    BOOLEAN isNicPath;

    /* Value names we spoof */
    UNICODE_STRING usDriverDesc = RTL_CONSTANT_STRING(L"DriverDesc");
    UNICODE_STRING usProviderName = RTL_CONSTANT_STRING(L"ProviderName");
    UNICODE_STRING usHwAddr = RTL_CONSTANT_STRING(L"AdapterHardwareAddress");
    UNICODE_STRING usNetAddr = RTL_CONSTANT_STRING(L"NetworkAddress");

    BOOLEAN isDriverDesc = FALSE;
    BOOLEAN isProviderName = FALSE;
    BOOLEAN isHwAddr = FALSE;
    BOOLEAN isNetAddr = FALSE;

    if (Cookie == NULL || PreInfo == NULL || PreInfo->ValueName == NULL || PreInfo->KeyValueInformation == NULL)
    {
        return FALSE;
    }
    if (PreInfo->KeyValueInformationClass != KeyValuePartialInformation)
    {
        return FALSE;
    }
    if (!BkrtIsAntiVirtualizationEnabled())
    {
        return FALSE;
    }

    isDriverDesc = BkstrUnicodeEquals(PreInfo->ValueName, &usDriverDesc, TRUE);
    isProviderName = BkstrUnicodeEquals(PreInfo->ValueName, &usProviderName, TRUE);
    isHwAddr = BkstrUnicodeEquals(PreInfo->ValueName, &usHwAddr, TRUE);
    isNetAddr = BkstrUnicodeEquals(PreInfo->ValueName, &usNetAddr, TRUE);

    if (!isDriverDesc && !isProviderName && !isHwAddr && !isNetAddr)
    {
        return FALSE;
    }

    nameStatus = CmCallbackGetKeyObjectIDEx(Cookie, Object, NULL, &keyNamePtr, 0);
    if (!NT_SUCCESS(nameStatus) || keyNamePtr == NULL)
    {
        return FALSE;
    }

    nicKeyPath = *keyNamePtr;
    isNicPath = BkstrUnicodeContainsInsensitive(&nicKeyPath, kNicClassGuid, kNicClassGuidLen);
    CmCallbackReleaseKeyObjectIDEx(keyNamePtr);

    if (!isNicPath)
    {
        return FALSE;
    }

    __try
    {
        partialInfo = (PKEY_VALUE_PARTIAL_INFORMATION)PreInfo->KeyValueInformation;

        if ((isDriverDesc || isProviderName) && partialInfo->Type == REG_SZ && partialInfo->DataLength >= sizeof(WCHAR))
        {
            PCWSTR replacement = isDriverDesc ? L"Intel(R) Ethernet Connection (7) I219-V" : L"Intel";
            BkavBlindWideString(partialInfo->Data, partialInfo->DataLength, replacement);
            return TRUE;
        }

        if (isHwAddr && partialInfo->Type == REG_BINARY && partialInfo->DataLength >= 6)
        {
            BkavBlindOuiBinary(partialInfo->Data, partialInfo->DataLength);
            return TRUE;
        }

        if (isNetAddr && partialInfo->Type == REG_SZ && partialInfo->DataLength >= 6 * sizeof(WCHAR))
        {
            BkavBlindOuiString(partialInfo->Data, partialInfo->DataLength);
            return TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return FALSE;
}

BOOLEAN BkavRegBlindDisplayValue(_In_ PLARGE_INTEGER Cookie, _In_opt_ PVOID Object,
                                 _In_ PREG_QUERY_VALUE_KEY_INFORMATION PreInfo)
{
    static const WCHAR kDisplayClassGuid[] = L"{4d36e968-e325-11ce-bfc1-08002be10318}";
    PKEY_VALUE_PARTIAL_INFORMATION partialInfo;
    PUNICODE_STRING keyNamePtr = NULL;
    UNICODE_STRING displayKeyPath;
    UNICODE_STRING usDriverDesc = RTL_CONSTANT_STRING(L"DriverDesc");
    UNICODE_STRING usProviderName = RTL_CONSTANT_STRING(L"ProviderName");
    NTSTATUS nameStatus;
    BOOLEAN isDisplayPath;
    PCWSTR spoofValue = NULL;

    if (Cookie == NULL || PreInfo == NULL || PreInfo->ValueName == NULL || PreInfo->KeyValueInformation == NULL)
    {
        return FALSE;
    }
    if (PreInfo->KeyValueInformationClass != KeyValuePartialInformation)
    {
        return FALSE;
    }
    if (!BkrtIsAntiVirtualizationEnabled())
    {
        return FALSE;
    }

    if (BkstrUnicodeEquals(PreInfo->ValueName, &usDriverDesc, TRUE))
    {
        spoofValue = L"NVIDIA GeForce RTX 3070";
    }
    else if (BkstrUnicodeEquals(PreInfo->ValueName, &usProviderName, TRUE))
    {
        spoofValue = L"NVIDIA";
    }
    else
    {
        return FALSE;
    }

    nameStatus = CmCallbackGetKeyObjectIDEx(Cookie, Object, NULL, &keyNamePtr, 0);
    if (!NT_SUCCESS(nameStatus) || keyNamePtr == NULL)
    {
        return FALSE;
    }

    displayKeyPath = *keyNamePtr;
    isDisplayPath = BkstrUnicodeContainsInsensitive(&displayKeyPath, kDisplayClassGuid, 38);
    CmCallbackReleaseKeyObjectIDEx(keyNamePtr);

    if (!isDisplayPath)
    {
        return FALSE;
    }

    __try
    {
        partialInfo = (PKEY_VALUE_PARTIAL_INFORMATION)PreInfo->KeyValueInformation;
        if (partialInfo->Type == REG_SZ && partialInfo->DataLength >= sizeof(WCHAR))
        {
            BkavBlindWideString(partialInfo->Data, partialInfo->DataLength, spoofValue);
            return TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return FALSE;
}

BOOLEAN BkavRegBlindScsiValue(_In_ PLARGE_INTEGER Cookie, _In_opt_ PVOID Object,
                              _In_ PREG_QUERY_VALUE_KEY_INFORMATION PreInfo)
{
    PKEY_VALUE_PARTIAL_INFORMATION partialInfo;
    PUNICODE_STRING keyNamePtr = NULL;
    UNICODE_STRING scsiKeyPath;
    UNICODE_STRING usIdentifier = RTL_CONSTANT_STRING(L"Identifier");
    UNICODE_STRING usProductId = RTL_CONSTANT_STRING(L"ProductId");
    NTSTATUS nameStatus;
    BOOLEAN isScsiPath;
    PCWSTR spoofValue = NULL;

    if (Cookie == NULL || PreInfo == NULL || PreInfo->ValueName == NULL || PreInfo->KeyValueInformation == NULL)
    {
        return FALSE;
    }
    if (PreInfo->KeyValueInformationClass != KeyValuePartialInformation)
    {
        return FALSE;
    }
    if (!BkrtIsAntiVirtualizationEnabled())
    {
        return FALSE;
    }

    if (BkstrUnicodeEquals(PreInfo->ValueName, &usIdentifier, TRUE))
    {
        spoofValue = L"Samsung SSD 970 EVO Plus";
    }
    else if (BkstrUnicodeEquals(PreInfo->ValueName, &usProductId, TRUE))
    {
        spoofValue = L"Samsung SSD 970 EVO Plus";
    }
    else
    {
        return FALSE;
    }

    nameStatus = CmCallbackGetKeyObjectIDEx(Cookie, Object, NULL, &keyNamePtr, 0);
    if (!NT_SUCCESS(nameStatus) || keyNamePtr == NULL)
    {
        return FALSE;
    }

    scsiKeyPath = *keyNamePtr;
    isScsiPath = BkstrUnicodeContainsInsensitive(&scsiKeyPath, L"\\hardware\\devicemap\\scsi", 24);
    CmCallbackReleaseKeyObjectIDEx(keyNamePtr);

    if (!isScsiPath)
    {
        return FALSE;
    }

    __try
    {
        partialInfo = (PKEY_VALUE_PARTIAL_INFORMATION)PreInfo->KeyValueInformation;
        if (partialInfo->Type == REG_SZ && partialInfo->DataLength >= sizeof(WCHAR))
        {
            BkavBlindWideString(partialInfo->Data, partialInfo->DataLength, spoofValue);
            return TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return FALSE;
}

BOOLEAN BkavRegBlindBiosValue(_In_ PLARGE_INTEGER Cookie, _In_opt_ PVOID Object,
                              _In_ PREG_QUERY_VALUE_KEY_INFORMATION PreInfo)
{
    PKEY_VALUE_PARTIAL_INFORMATION partialInfo;
    PUNICODE_STRING keyNamePtr = NULL;
    UNICODE_STRING biosKeyPath;
    NTSTATUS nameStatus;
    BOOLEAN isBiosPath;
    PCWSTR spoofValue = NULL;

    if (Cookie == NULL || PreInfo == NULL || PreInfo->ValueName == NULL || PreInfo->KeyValueInformation == NULL)
    {
        return FALSE;
    }
    if (PreInfo->KeyValueInformationClass != KeyValuePartialInformation)
    {
        return FALSE;
    }
    if (!BkrtIsAntiVirtualizationEnabled())
    {
        return FALSE;
    }

    {
        UNICODE_STRING usBiosVendor = RTL_CONSTANT_STRING(L"BIOSVendor");
        UNICODE_STRING usSysMfg = RTL_CONSTANT_STRING(L"SystemManufacturer");
        UNICODE_STRING usSysProd = RTL_CONSTANT_STRING(L"SystemProductName");
        UNICODE_STRING usBoardProduct = RTL_CONSTANT_STRING(L"BaseBoardProduct");
        UNICODE_STRING usBoardMfg = RTL_CONSTANT_STRING(L"BaseBoardManufacturer");

        if (BkstrUnicodeEquals(PreInfo->ValueName, &usBiosVendor, TRUE))
        {
            spoofValue = L"American Megatrends Inc.";
        }
        else if (BkstrUnicodeEquals(PreInfo->ValueName, &usSysMfg, TRUE))
        {
            spoofValue = L"Dell Inc.";
        }
        else if (BkstrUnicodeEquals(PreInfo->ValueName, &usSysProd, TRUE))
        {
            spoofValue = L"XPS 8940";
        }
        else if (BkstrUnicodeEquals(PreInfo->ValueName, &usBoardProduct, TRUE))
        {
            spoofValue = L"0K3CM7";
        }
        else if (BkstrUnicodeEquals(PreInfo->ValueName, &usBoardMfg, TRUE))
        {
            spoofValue = L"Dell Inc.";
        }
    }

    if (spoofValue == NULL)
    {
        return FALSE;
    }

    nameStatus = CmCallbackGetKeyObjectIDEx(Cookie, Object, NULL, &keyNamePtr, 0);
    if (!NT_SUCCESS(nameStatus) || keyNamePtr == NULL)
    {
        return FALSE;
    }

    biosKeyPath = *keyNamePtr;
    isBiosPath = BkstrUnicodeContainsInsensitive(&biosKeyPath, L"\\hardware\\description\\system\\bios", 33);
    CmCallbackReleaseKeyObjectIDEx(keyNamePtr);

    if (!isBiosPath)
    {
        return FALSE;
    }

    __try
    {
        partialInfo = (PKEY_VALUE_PARTIAL_INFORMATION)PreInfo->KeyValueInformation;
        if (partialInfo->Type == REG_SZ && partialInfo->DataLength >= sizeof(WCHAR))
        {
            BkavBlindWideString(partialInfo->Data, partialInfo->DataLength, spoofValue);
            return TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return FALSE;
}
