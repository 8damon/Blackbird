#include <ntddk.h>
#include "..\core\unicode_utils.h"
#include "registry_concealment.h"

BOOLEAN BLACKBIRDRegistryPathIsHighValue(_In_opt_ PCUNICODE_STRING Path)
{
    if (Path == NULL || Path->Buffer == NULL)
    {
        return FALSE;
    }

    if (BLACKBIRDUnicodeContainsInsensitive(Path, L"\\currentversion\\run", 19) ||
        BLACKBIRDUnicodeContainsInsensitive(Path, L"\\currentversion\\runonce", 23) ||
        BLACKBIRDUnicodeContainsInsensitive(Path, L"\\image file execution options", 29) ||
        BLACKBIRDUnicodeContainsInsensitive(Path, L"\\system\\currentcontrolset\\services\\", 35))
    {
        return TRUE;
    }

    return FALSE;
}

BOOLEAN BLACKBIRDRegistryShouldBlockPath(_In_opt_ PCUNICODE_STRING Path)
{
    if (Path == NULL || Path->Buffer == NULL)
    {
        return FALSE;
    }

    if (BLACKBIRDUnicodeContainsInsensitive(Path, L"\\services\\vmicheartbeat", 23) ||
        BLACKBIRDUnicodeContainsInsensitive(Path, L"\\services\\vmicvmsession", 23) ||
        BLACKBIRDUnicodeContainsInsensitive(Path, L"\\services\\vmictimesync", 22) ||
        BLACKBIRDUnicodeContainsInsensitive(Path, L"\\services\\vmicvss", 17))
    {
        return TRUE;
    }

    if (BLACKBIRDUnicodeContainsInsensitive(Path, L"\\services\\vmhgfs", 16) ||
        BLACKBIRDUnicodeContainsInsensitive(Path, L"\\services\\vmmouse", 17) ||
        BLACKBIRDUnicodeContainsInsensitive(Path, L"\\services\\vmrawdsk", 18) ||
        BLACKBIRDUnicodeContainsInsensitive(Path, L"\\services\\vmusbmouse", 20) ||
        BLACKBIRDUnicodeContainsInsensitive(Path, L"\\services\\vmxnet", 16) ||
        BLACKBIRDUnicodeContainsInsensitive(Path, L"\\services\\vmci", 14))
    {
        return TRUE;
    }

    if (BLACKBIRDUnicodeContainsInsensitive(Path, L"\\services\\vboxguest", 19) ||
        BLACKBIRDUnicodeContainsInsensitive(Path, L"\\services\\vboxmouse", 19) ||
        BLACKBIRDUnicodeContainsInsensitive(Path, L"\\services\\vboxservice", 21) ||
        BLACKBIRDUnicodeContainsInsensitive(Path, L"\\services\\vboxsf", 16))
    {
        return TRUE;
    }

    return FALSE;
}

VOID BLACKBIRDRegistryBuildPathForCompare(_In_ PLARGE_INTEGER Cookie, _In_opt_ PVOID RootObject,
                                          _In_opt_ PCUNICODE_STRING CompleteName,
                                          _Out_writes_z_(PathChars) PWSTR PathBuffer, _In_ SIZE_T PathChars,
                                          _Out_ PUNICODE_STRING PathUs)
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
        BLACKBIRDSafeCopyUnicode(CompleteName, PathBuffer, PathChars);
    }
    else
    {
        PUNICODE_STRING rootName = NULL;
        NTSTATUS status = CmCallbackGetKeyObjectIDEx(Cookie, RootObject, NULL, &rootName, 0);

        if (NT_SUCCESS(status) && rootName != NULL)
        {
            BLACKBIRDSafeCopyUnicode(rootName, PathBuffer, PathChars);
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
            BLACKBIRDSafeCopyUnicode(CompleteName, PathBuffer, PathChars);
        }
    }

    RtlInitUnicodeString(PathUs, PathBuffer);
}

static VOID BLACKBIRDPatchRegistryWideString(_Inout_updates_bytes_(DataLength) PUCHAR DataBytes, _In_ ULONG DataLength,
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

BOOLEAN BLACKBIRDRegistryTrySpoofBiosValue(_In_ PLARGE_INTEGER Cookie, _In_opt_ PVOID Object,
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

    {
        UNICODE_STRING usBiosVendor = RTL_CONSTANT_STRING(L"BIOSVendor");
        UNICODE_STRING usSysMfg = RTL_CONSTANT_STRING(L"SystemManufacturer");
        UNICODE_STRING usSysProd = RTL_CONSTANT_STRING(L"SystemProductName");

        if (BLACKBIRDUnicodeEquals(PreInfo->ValueName, &usBiosVendor, TRUE))
        {
            spoofValue = L"American Megatrends Inc.";
        }
        else if (BLACKBIRDUnicodeEquals(PreInfo->ValueName, &usSysMfg, TRUE))
        {
            spoofValue = L"Dell Inc.";
        }
        else if (BLACKBIRDUnicodeEquals(PreInfo->ValueName, &usSysProd, TRUE))
        {
            spoofValue = L"XPS 8940";
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
    isBiosPath = BLACKBIRDUnicodeContainsInsensitive(&biosKeyPath, L"\\hardware\\description\\system\\bios", 33);
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
            BLACKBIRDPatchRegistryWideString(partialInfo->Data, partialInfo->DataLength, spoofValue);
            return TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return FALSE;
}
