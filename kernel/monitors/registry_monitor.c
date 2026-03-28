#include <ntddk.h>
#include "..\core\unicode_utils.h"
#include "..\core\runtime_config.h"
#include "..\telemetry\etw.h"
#include "..\antivirt\registry_concealment.h"
#include "registry_monitor.h"

#define BLACKBIRD_REG_MON_ALTITUDE L"385000.424244"

/* Classification result for a registry write operation.  Name == NULL means no
 * actionable detection — caller should not emit a detection event. */
typedef struct _BLACKBIRD_REG_WRITE_CLASS
{
    PCSTR  DetectionName;
    ULONG  Severity;
    PCWSTR Reason;
} BLACKBIRD_REG_WRITE_CLASS;

/* Classify a registry key path + optional value name for persistence / security-bypass
 * relevance.  Only called on write-class operations (SET_VALUE, CREATE_KEY). */
static VOID BLACKBIRDRegistryClassifyWrite(_In_opt_z_ PCWSTR KeyPath,
                                           _In_opt_z_ PCWSTR ValueName,
                                           _Out_ BLACKBIRD_REG_WRITE_CLASS *Out)
{
    UNICODE_STRING keyUs;
    UNICODE_STRING valUs;

    Out->DetectionName = NULL;
    Out->Severity      = 0;
    Out->Reason        = NULL;

    if (KeyPath == NULL || KeyPath[0] == L'\0')
    {
        return;
    }

    RtlInitUnicodeString(&keyUs, KeyPath);
    if (ValueName != NULL && ValueName[0] != L'\0')
    {
        RtlInitUnicodeString(&valUs, ValueName);
    }
    else
    {
        RtlInitUnicodeString(&valUs, L"");
    }

    /* LSA security / authentication packages — loader injects these DLLs into lsass at boot */
    if (BLACKBIRDUnicodeContainsInsensitive(&keyUs, L"\\Lsa", 4))
    {
        if (BLACKBIRDUnicodeContainsInsensitive(&valUs, L"Security Packages", 17) ||
            BLACKBIRDUnicodeContainsInsensitive(&valUs, L"Authentication Packages", 22) ||
            BLACKBIRDUnicodeContainsInsensitive(&valUs, L"Notification Packages", 21))
        {
            Out->DetectionName = "REGISTRY_LSA_PACKAGE_WRITE";
            Out->Severity      = 8;
            Out->Reason        = L"write to LSA security-package value — DLL injected into lsass at next boot";
            return;
        }
    }

    /* Defender / security product exclusion paths */
    if (BLACKBIRDUnicodeContainsInsensitive(&keyUs, L"Windows Defender\\Exclusions", 27) ||
        BLACKBIRDUnicodeContainsInsensitive(&keyUs, L"Windows Defender\\Features", 25))
    {
        Out->DetectionName = "REGISTRY_SECURITY_BYPASS_WRITE";
        Out->Severity      = 7;
        Out->Reason        = L"write to Windows Defender exclusion or feature key";
        return;
    }

    /* AppInit_DLLs — classic DLL injection via kernel32 loader */
    if (BLACKBIRDUnicodeContainsInsensitive(&valUs, L"AppInit_DLLs", 12))
    {
        Out->DetectionName = "REGISTRY_APPINIT_DLL_WRITE";
        Out->Severity      = 7;
        Out->Reason        = L"write to AppInit_DLLs — DLL loaded into every user-mode process using user32";
        return;
    }

    /* BootExecute — runs native executables before Win32 subsystem starts */
    if (BLACKBIRDUnicodeContainsInsensitive(&valUs, L"BootExecute", 11) ||
        BLACKBIRDUnicodeContainsInsensitive(&keyUs, L"Session Manager\\BootExecute", 27))
    {
        Out->DetectionName = "REGISTRY_BOOT_EXECUTE_WRITE";
        Out->Severity      = 7;
        Out->Reason        = L"write to BootExecute — executed by smss before Win32 subsystem starts";
        return;
    }

    /* Winlogon helper DLLs / notification packages */
    if (BLACKBIRDUnicodeContainsInsensitive(&keyUs, L"Windows NT\\CurrentVersion\\Winlogon", 33))
    {
        if (BLACKBIRDUnicodeContainsInsensitive(&valUs, L"Userinit", 8) ||
            BLACKBIRDUnicodeContainsInsensitive(&valUs, L"Shell", 5)    ||
            BLACKBIRDUnicodeContainsInsensitive(&valUs, L"Notify", 6)   ||
            BLACKBIRDUnicodeContainsInsensitive(&valUs, L"GpExtensions", 12))
        {
            Out->DetectionName = "REGISTRY_WINLOGON_MODIFY";
            Out->Severity      = 6;
            Out->Reason        = L"write to Winlogon control value — can redirect logon shell or hook logon events";
            return;
        }
    }

    /* Image File Execution Options — debugger/silentprocessexit hijack */
    if (BLACKBIRDUnicodeContainsInsensitive(&keyUs, L"Image File Execution Options", 28))
    {
        if (BLACKBIRDUnicodeContainsInsensitive(&valUs, L"Debugger", 8)            ||
            BLACKBIRDUnicodeContainsInsensitive(&valUs, L"MonitorProcess", 14)     ||
            BLACKBIRDUnicodeContainsInsensitive(&valUs, L"ReportingMode", 13))
        {
            Out->DetectionName = "REGISTRY_IFEO_WRITE";
            Out->Severity      = 6;
            Out->Reason        = L"write to Image File Execution Options — Debugger or MonitorProcess can redirect execution";
            return;
        }
    }

    /* SAM / SECURITY hive access — credential store */
    if (BLACKBIRDUnicodeContainsInsensitive(&keyUs, L"\\REGISTRY\\MACHINE\\SAM", 21) ||
        BLACKBIRDUnicodeContainsInsensitive(&keyUs, L"\\REGISTRY\\MACHINE\\SECURITY", 26))
    {
        Out->DetectionName = "REGISTRY_CREDENTIAL_HIVE_WRITE";
        Out->Severity      = 7;
        Out->Reason        = L"write into SAM or SECURITY hive — credential store modification";
        return;
    }

    /* Run / RunOnce / RunServices autorun keys */
    if (BLACKBIRDUnicodeContainsInsensitive(&keyUs, L"CurrentVersion\\Run", 18))
    {
        Out->DetectionName = "REGISTRY_AUTORUN_WRITE";
        Out->Severity      = 5;
        Out->Reason        = L"write to autorun persistence key (Run/RunOnce/RunServices)";
        return;
    }

    /* COM hijacking targets — HKCU\CLSID overrides system HKCR registrations */
    if (BLACKBIRDUnicodeContainsInsensitive(&keyUs, L"\\REGISTRY\\USER\\", 15) &&
        BLACKBIRDUnicodeContainsInsensitive(&keyUs, L"\\CLSID\\", 7) &&
        BLACKBIRDUnicodeContainsInsensitive(&valUs, L"InprocServer32", 14))
    {
        Out->DetectionName = "REGISTRY_COM_HIJACK_WRITE";
        Out->Severity      = 5;
        Out->Reason        = L"write to per-user CLSID InprocServer32 — COM server hijacking via HKCU override";
        return;
    }
}

static LARGE_INTEGER g_RegistryCookie = {0};
static volatile LONG g_RegistryMonitorRegistered = 0;
static volatile LONG g_RegistryFailureCounter = 0;

NTKERNELAPI ULONG PsGetProcessSessionIdEx(_In_ PEPROCESS Process);

static VOID BLACKBIRDRegistryOverwriteKeyName(_Out_writes_bytes_(NameBytes) PWCHAR NameBuffer,
                                              _In_ ULONG NameBytes, _In_z_ PCWSTR Replacement)
{
    SIZE_T maxChars;
    SIZE_T copyChars;

    if (NameBuffer == NULL || NameBytes < sizeof(WCHAR) || Replacement == NULL)
    {
        return;
    }

    maxChars = NameBytes / sizeof(WCHAR);
    copyChars = wcslen(Replacement);
    if (copyChars >= maxChars)
    {
        copyChars = maxChars - 1;
    }

    if (copyChars != 0)
    {
        RtlCopyMemory(NameBuffer, Replacement, copyChars * sizeof(WCHAR));
    }
    NameBuffer[copyChars] = L'\0';
    if ((copyChars + 1) < maxChars)
    {
        RtlZeroMemory(NameBuffer + copyChars + 1, (maxChars - copyChars - 1) * sizeof(WCHAR));
    }
}

static BOOLEAN BLACKBIRDRegistryBlindPciEnumeration(_In_ PREG_POST_OPERATION_INFORMATION PostInfo)
{
    PUNICODE_STRING keyNamePtr = NULL;
    UNICODE_STRING keyPath;
    NTSTATUS nameStatus;
    PREG_ENUMERATE_KEY_INFORMATION preInfo;

    if (PostInfo == NULL || !NT_SUCCESS(PostInfo->Status) || PostInfo->Object == NULL || PostInfo->PreInformation == NULL ||
        !BLACKBIRDRuntimeConfigIsAntiVirtualizationEnabled())
    {
        return FALSE;
    }

    preInfo = (PREG_ENUMERATE_KEY_INFORMATION)PostInfo->PreInformation;
    nameStatus = CmCallbackGetKeyObjectIDEx(&g_RegistryCookie, PostInfo->Object, NULL, &keyNamePtr, 0);
    if (!NT_SUCCESS(nameStatus) || keyNamePtr == NULL)
    {
        return FALSE;
    }

    keyPath = *keyNamePtr;
    if (!BLACKBIRDUnicodeContainsInsensitive(&keyPath, L"\\enum\\pci", 10))
    {
        CmCallbackReleaseKeyObjectIDEx(keyNamePtr);
        return FALSE;
    }

    switch (preInfo->KeyInformationClass)
    {
    case KeyBasicInformation:
    {
        PKEY_BASIC_INFORMATION info = (PKEY_BASIC_INFORMATION)preInfo->KeyInformation;
        if (info != NULL && info->NameLength >= (8 * sizeof(WCHAR)) &&
            _wcsnicmp(info->Name, L"VEN_15AD", 8) == 0)
        {
            BLACKBIRDRegistryOverwriteKeyName(info->Name, info->NameLength, L"VEN_8086");
            info->NameLength = 8 * sizeof(WCHAR);
            CmCallbackReleaseKeyObjectIDEx(keyNamePtr);
            return TRUE;
        }
        break;
    }
    case KeyNodeInformation:
    {
        PKEY_NODE_INFORMATION info = (PKEY_NODE_INFORMATION)preInfo->KeyInformation;
        if (info != NULL && info->NameLength >= (8 * sizeof(WCHAR)) &&
            _wcsnicmp(info->Name, L"VEN_15AD", 8) == 0)
        {
            BLACKBIRDRegistryOverwriteKeyName(info->Name, info->NameLength, L"VEN_8086");
            info->NameLength = 8 * sizeof(WCHAR);
            CmCallbackReleaseKeyObjectIDEx(keyNamePtr);
            return TRUE;
        }
        break;
    }
    case KeyNameInformation:
    {
        PKEY_NAME_INFORMATION info = (PKEY_NAME_INFORMATION)preInfo->KeyInformation;
        if (info != NULL && info->NameLength >= (8 * sizeof(WCHAR)) &&
            _wcsnicmp(info->Name, L"VEN_15AD", 8) == 0)
        {
            BLACKBIRDRegistryOverwriteKeyName(info->Name, info->NameLength, L"VEN_8086");
            info->NameLength = 8 * sizeof(WCHAR);
            CmCallbackReleaseKeyObjectIDEx(keyNamePtr);
            return TRUE;
        }
        break;
    }
    default:
        break;
    }

    CmCallbackReleaseKeyObjectIDEx(keyNamePtr);
    return FALSE;
}

static NTSTATUS BLACKBIRDRegistryCallback(_In_opt_ PVOID CallbackContext, _In_opt_ PVOID Argument1,
                                          _In_opt_ PVOID Argument2)
{
    REG_NOTIFY_CLASS notifyClass;
    UNICODE_STRING keyPathUs;
    WCHAR keyPath[512];
    WCHAR valueName[128];
    ULONG dataType = 0;
    ULONG dataSize = 0;
    BOOLEAN highValuePath = FALSE;
    BOOLEAN nullPath = FALSE;
    ULONG sessionId = 0;
    HANDLE pid;
    PCSTR operation = "OTHER";

    UNREFERENCED_PARAMETER(CallbackContext);

    keyPath[0] = L'\0';
    valueName[0] = L'\0';
    RtlInitUnicodeString(&keyPathUs, NULL);

    if (Argument1 == NULL)
    {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    pid = PsGetCurrentProcessId();
    sessionId = PsGetProcessSessionIdEx(PsGetCurrentProcess());

    if (notifyClass == RegNtPreSetValueKey)
    {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        PUNICODE_STRING keyNameUs = NULL;
        NTSTATUS nameStatus;

        operation = "SET_VALUE";
        if (info != NULL)
        {
            dataType = info->Type;
            dataSize = info->DataSize;
            BLACKBIRDSafeCopyUnicode(info->ValueName, valueName, RTL_NUMBER_OF(valueName));

            nameStatus = CmCallbackGetKeyObjectIDEx(&g_RegistryCookie, info->Object, NULL, &keyNameUs, 0);
            if (NT_SUCCESS(nameStatus) && keyNameUs != NULL)
            {
                keyPathUs = *keyNameUs;
                BLACKBIRDSafeCopyUnicode(&keyPathUs, keyPath, RTL_NUMBER_OF(keyPath));
                highValuePath = BLACKBIRDRegistryPathIsHighValue(&keyPathUs);
                CmCallbackReleaseKeyObjectIDEx(keyNameUs);
            }
        }
    }
    else if (notifyClass == RegNtPreCreateKeyEx)
    {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)Argument2;
        operation = "CREATE_KEY";
        if (info != NULL && info->CompleteName != NULL)
        {
            BLACKBIRDRegistryBuildPathForCompare(&g_RegistryCookie, info->RootObject, info->CompleteName, keyPath,
                                                 RTL_NUMBER_OF(keyPath), &keyPathUs);
            highValuePath = BLACKBIRDRegistryPathIsHighValue(&keyPathUs);
            nullPath = BLACKBIRDRegistryNullPath(&keyPathUs);
        }
    }
    else if (notifyClass == RegNtPreOpenKey || notifyClass == RegNtPreOpenKeyEx)
    {
        PREG_OPEN_KEY_INFORMATION info = (PREG_OPEN_KEY_INFORMATION)Argument2;
        operation = "OPEN_KEY";
        if (info != NULL && info->CompleteName != NULL)
        {
            BLACKBIRDRegistryBuildPathForCompare(&g_RegistryCookie, info->RootObject, info->CompleteName, keyPath,
                                                 RTL_NUMBER_OF(keyPath), &keyPathUs);
            highValuePath = BLACKBIRDRegistryPathIsHighValue(&keyPathUs);
            nullPath = BLACKBIRDRegistryNullPath(&keyPathUs);
        }
    }
    else if (notifyClass == RegNtPostQueryValueKey)
    {
        PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
        PREG_QUERY_VALUE_KEY_INFORMATION preInfo;

        if (postInfo == NULL || !NT_SUCCESS(postInfo->Status) || postInfo->PreInformation == NULL)
        {
            return STATUS_SUCCESS;
        }

        preInfo = (PREG_QUERY_VALUE_KEY_INFORMATION)postInfo->PreInformation;
        if (BLACKBIRDRegistryBlindBiosValue(&g_RegistryCookie, postInfo->Object, preInfo))
        {
            return STATUS_SUCCESS;
        }
        if (BLACKBIRDRegistryBlindNicValue(&g_RegistryCookie, postInfo->Object, preInfo))
        {
            return STATUS_SUCCESS;
        }
        if (BLACKBIRDRegistryBlindDisplayValue(&g_RegistryCookie, postInfo->Object, preInfo))
        {
            return STATUS_SUCCESS;
        }
        if (BLACKBIRDRegistryBlindScsiValue(&g_RegistryCookie, postInfo->Object, preInfo))
        {
            return STATUS_SUCCESS;
        }
    }
    else if (notifyClass == RegNtPostEnumerateKey)
    {
        PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
        if (BLACKBIRDRegistryBlindPciEnumeration(postInfo))
        {
            return STATUS_SUCCESS;
        }
        return STATUS_SUCCESS;
    }
    else if (notifyClass == RegNtPreDeleteValueKey)
    {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        operation = "DELETE_VALUE";
        if (info != NULL)
        {
            PUNICODE_STRING keyNameUs = NULL;
            NTSTATUS nameStatus = CmCallbackGetKeyObjectIDEx(&g_RegistryCookie, info->Object, NULL, &keyNameUs, 0);
            BLACKBIRDSafeCopyUnicode(info->ValueName, valueName, RTL_NUMBER_OF(valueName));
            if (NT_SUCCESS(nameStatus) && keyNameUs != NULL)
            {
                keyPathUs = *keyNameUs;
                BLACKBIRDSafeCopyUnicode(&keyPathUs, keyPath, RTL_NUMBER_OF(keyPath));
                highValuePath = BLACKBIRDRegistryPathIsHighValue(&keyPathUs);
                CmCallbackReleaseKeyObjectIDEx(keyNameUs);
            }
        }
    }
    else
    {
        return STATUS_SUCCESS;
    }

    BLACKBIRDEtwLogRegistryEvent(operation, pid, sessionId, (ULONG)notifyClass, dataType, dataSize, highValuePath,
                                 (keyPath[0] != L'\0') ? keyPath : NULL, (valueName[0] != L'\0') ? valueName : NULL);

    if (highValuePath)
    {
        BLACKBIRDEtwLogDetectionEvent("HIGH_VALUE_REGISTRY_ACTIVITY", 2, pid, NULL, 0, 0, 0, keyPath);
    }

    /* Specific persistence / credential / security-bypass classification for write operations. */
    if (notifyClass == RegNtPreSetValueKey || notifyClass == RegNtPreCreateKeyEx)
    {
        BLACKBIRD_REG_WRITE_CLASS cls;
        BLACKBIRDRegistryClassifyWrite(keyPath, valueName, &cls);
        if (cls.DetectionName != NULL)
        {
            BLACKBIRDEtwLogDetectionEvent(cls.DetectionName, cls.Severity, pid, NULL, 0, 0, 0, cls.Reason);
        }
    }

    if (nullPath)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
BLACKBIRDRegistryMonitorInitialize(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING altitude;
    LONG failures;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (InterlockedCompareExchange(&g_RegistryMonitorRegistered, 0, 0) != 0)
    {
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&altitude, BLACKBIRD_REG_MON_ALTITUDE);
    status = CmRegisterCallbackEx(BLACKBIRDRegistryCallback, &altitude, DriverObject, NULL, &g_RegistryCookie, NULL);
    if (!NT_SUCCESS(status))
    {
        failures = InterlockedIncrement(&g_RegistryFailureCounter);
        if (failures == 1 || ((failures & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "BLACKBIRD: registry monitor callback registration failed status=0x%08X total=%lu.\n", status,
                       (ULONG)failures);
        }
        return status;
    }

    InterlockedExchange(&g_RegistryMonitorRegistered, 1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BLACKBIRD: registry monitor initialized.\n");
    return STATUS_SUCCESS;
}

VOID BLACKBIRDRegistryMonitorUninitialize(VOID)
{
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }
    if (InterlockedCompareExchange(&g_RegistryMonitorRegistered, 0, 0) == 0)
    {
        return;
    }

    status = CmUnRegisterCallback(g_RegistryCookie);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "BLACKBIRD: registry monitor callback removal failed; monitor remains registered (status=0x%08X).\n",
                   status);
        return;
    }

    InterlockedExchange(&g_RegistryMonitorRegistered, 0);
    RtlZeroMemory(&g_RegistryCookie, sizeof(g_RegistryCookie));
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BLACKBIRD: registry monitor uninitialized.\n");
}

BOOLEAN
BLACKBIRDRegistryMonitorSelfCheck(VOID)
{
    if (InterlockedCompareExchange(&g_RegistryMonitorRegistered, 0, 0) == 0)
    {
        return FALSE;
    }

    return (g_RegistryCookie.QuadPart != 0);
}
