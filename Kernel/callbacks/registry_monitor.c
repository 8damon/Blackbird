#include <ntddk.h>
#include "..\core\unicode_utils.h"
#include "..\core\runtime_config.h"
#include "..\core\tempus_debug.h"
#include "..\core\control.h"
#include "..\telemetry\etw.h"
#include "..\antivirt\registry_concealment.h"
#include "..\hooks\monitor\ntapi_monitor.h"
#include "registry_monitor.h"

#define BK_REG_MON_ALTITUDE L"385000.424244"

/* Classification result for a registry write operation.  Name == NULL means no
 * actionable detection — caller should not emit a detection event. */
typedef struct _BK_REG_WRITE_CLASS
{
    PCSTR DetectionName;
    ULONG Severity;
    PCWSTR Reason;
} BK_REG_WRITE_CLASS;

/* Classify a registry key path + optional value name for persistence / security-bypass
 * relevance.  Only called on write-class operations (SET_VALUE, CREATE_KEY). */
static VOID BkavRegClassifyWrite(_In_opt_z_ PCWSTR KeyPath, _In_opt_z_ PCWSTR ValueName, _Out_ BK_REG_WRITE_CLASS *Out)
{
    UNICODE_STRING keyUs;
    UNICODE_STRING valUs;

    Out->DetectionName = NULL;
    Out->Severity = 0;
    Out->Reason = NULL;

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
    if (BkstrUnicodeContainsInsensitive(&keyUs, L"\\Lsa", 4))
    {
        if (BkstrUnicodeContainsInsensitive(&valUs, L"Security Packages", 17) ||
            BkstrUnicodeContainsInsensitive(&valUs, L"Authentication Packages", 22) ||
            BkstrUnicodeContainsInsensitive(&valUs, L"Notification Packages", 21))
        {
            Out->DetectionName = "REGISTRY_LSA_PACKAGE_WRITE";
            Out->Severity = 8;
            Out->Reason = L"write to LSA security-package value — DLL injected into lsass at next boot";
            return;
        }
    }

    /* Defender / security product exclusion paths */
    if (BkstrUnicodeContainsInsensitive(&keyUs, L"Windows Defender\\Exclusions", 27) ||
        BkstrUnicodeContainsInsensitive(&keyUs, L"Windows Defender\\Features", 25))
    {
        Out->DetectionName = "REGISTRY_SECURITY_BYPASS_WRITE";
        Out->Severity = 7;
        Out->Reason = L"write to Windows Defender exclusion or feature key";
        return;
    }

    /* AppInit_DLLs — classic DLL injection via kernel32 loader */
    if (BkstrUnicodeContainsInsensitive(&valUs, L"AppInit_DLLs", 12))
    {
        Out->DetectionName = "REGISTRY_APPINIT_DLL_WRITE";
        Out->Severity = 7;
        Out->Reason = L"write to AppInit_DLLs — DLL loaded into every user-mode process using user32";
        return;
    }

    /* BootExecute — runs native executables before Win32 subsystem starts */
    if (BkstrUnicodeContainsInsensitive(&valUs, L"BootExecute", 11) ||
        BkstrUnicodeContainsInsensitive(&keyUs, L"Session Manager\\BootExecute", 27))
    {
        Out->DetectionName = "REGISTRY_BOOT_EXECUTE_WRITE";
        Out->Severity = 7;
        Out->Reason = L"write to BootExecute — executed by smss before Win32 subsystem starts";
        return;
    }

    /* Winlogon helper DLLs / notification packages */
    if (BkstrUnicodeContainsInsensitive(&keyUs, L"Windows NT\\CurrentVersion\\Winlogon", 33))
    {
        if (BkstrUnicodeContainsInsensitive(&valUs, L"Userinit", 8) ||
            BkstrUnicodeContainsInsensitive(&valUs, L"Shell", 5) ||
            BkstrUnicodeContainsInsensitive(&valUs, L"Notify", 6) ||
            BkstrUnicodeContainsInsensitive(&valUs, L"GpExtensions", 12))
        {
            Out->DetectionName = "REGISTRY_WINLOGON_MODIFY";
            Out->Severity = 6;
            Out->Reason = L"write to Winlogon control value — can redirect logon shell or hook logon events";
            return;
        }
    }

    /* Image File Execution Options — debugger/silentprocessexit hijack */
    if (BkstrUnicodeContainsInsensitive(&keyUs, L"Image File Execution Options", 28))
    {
        if (BkstrUnicodeContainsInsensitive(&valUs, L"Debugger", 8) ||
            BkstrUnicodeContainsInsensitive(&valUs, L"MonitorProcess", 14) ||
            BkstrUnicodeContainsInsensitive(&valUs, L"ReportingMode", 13))
        {
            Out->DetectionName = "REGISTRY_IFEO_WRITE";
            Out->Severity = 6;
            Out->Reason = L"write to Image File Execution Options — Debugger or MonitorProcess can redirect execution";
            return;
        }
    }

    /* SAM / SECURITY hive access — credential store */
    if (BkstrUnicodeContainsInsensitive(&keyUs, L"\\REGISTRY\\MACHINE\\SAM", 21) ||
        BkstrUnicodeContainsInsensitive(&keyUs, L"\\REGISTRY\\MACHINE\\SECURITY", 26))
    {
        Out->DetectionName = "REGISTRY_CREDENTIAL_HIVE_WRITE";
        Out->Severity = 7;
        Out->Reason = L"write into SAM or SECURITY hive — credential store modification";
        return;
    }

    if (BkstrUnicodeContainsInsensitive(&keyUs, L"CurrentControlSet\\Services", 26))
    {
        Out->DetectionName = "REGISTRY_SERVICE_WRITE";
        Out->Severity = 6;
        Out->Reason = L"write to Services configuration — service or driver persistence / LPE surface";
        return;
    }

    /* Run / RunOnce / RunServices autorun keys */
    if (BkstrUnicodeContainsInsensitive(&keyUs, L"CurrentVersion\\Run", 18))
    {
        Out->DetectionName = "REGISTRY_AUTORUN_WRITE";
        Out->Severity = 5;
        Out->Reason = L"write to autorun persistence key (Run/RunOnce/RunServices)";
        return;
    }

    /* COM hijacking targets — HKCU\CLSID overrides system HKCR registrations */
    if (BkstrUnicodeContainsInsensitive(&keyUs, L"\\REGISTRY\\USER\\", 15) &&
        BkstrUnicodeContainsInsensitive(&keyUs, L"\\CLSID\\", 7) &&
        BkstrUnicodeContainsInsensitive(&valUs, L"InprocServer32", 14))
    {
        Out->DetectionName = "REGISTRY_COM_HIJACK_WRITE";
        Out->Severity = 5;
        Out->Reason = L"write to per-user CLSID InprocServer32 — COM server hijacking via HKCU override";
        return;
    }

    /* WMI persistence — subscription store and service configuration */
    if (BkstrUnicodeContainsInsensitive(&keyUs, L"\\WBEM\\WDM", 9) ||
        BkstrUnicodeContainsInsensitive(&keyUs, L"\\Services\\WinMgmt", 17) ||
        BkstrUnicodeContainsInsensitive(&keyUs, L"\\WMI\\Security", 13))
    {
        Out->DetectionName = "REGISTRY_WMI_PERSISTENCE_WRITE";
        Out->Severity = 6;
        Out->Reason = L"write to WMI service or security key — WMI subscription or service persistence";
        return;
    }

    /* Scheduled tasks registry backing store */
    if (BkstrUnicodeContainsInsensitive(&keyUs, L"\\Schedule\\TaskCache", 19))
    {
        Out->DetectionName = "REGISTRY_SCHEDULED_TASK_WRITE";
        Out->Severity = 5;
        Out->Reason = L"write to scheduled task cache — task persistence via registry";
        return;
    }
}

static VOID BkavRegClassifyQuery(_In_opt_z_ PCWSTR KeyPath, _In_opt_z_ PCWSTR ValueName, _Out_ BK_REG_WRITE_CLASS *Out)
{
    UNICODE_STRING keyUs;
    UNICODE_STRING valUs;

    Out->DetectionName = NULL;
    Out->Severity = 0;
    Out->Reason = NULL;

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

#define BK_REGISTRY_VALUE_IS_LSA_PACKAGE_QUERY()                                \
    (BkstrUnicodeContainsInsensitive(&valUs, L"Security Packages", 17) ||       \
     BkstrUnicodeContainsInsensitive(&valUs, L"Authentication Packages", 22) || \
     BkstrUnicodeContainsInsensitive(&valUs, L"Notification Packages", 21))

    if (BkstrUnicodeContainsInsensitive(&keyUs, L"\\REGISTRY\\MACHINE\\SAM", 21))
    {
        Out->DetectionName = "REGISTRY_CREDENTIAL_HIVE_QUERY";
        Out->Severity = 8;
        Out->Reason = L"read from SAM hive — NTLM hash extraction vector";
        return;
    }

    if (BkstrUnicodeContainsInsensitive(&keyUs, L"\\REGISTRY\\MACHINE\\SECURITY", 26))
    {
        if (BkstrUnicodeContainsInsensitive(&keyUs, L"\\Lsa\\Secrets", 12))
        {
            Out->DetectionName = "REGISTRY_LSA_SECRETS_QUERY";
            Out->Severity = 8;
            Out->Reason = L"read from LSA Secrets — stored credentials and service account passwords";
            return;
        }
        if (BkstrUnicodeContainsInsensitive(&keyUs, L"\\Lsa\\Credentials", 16))
        {
            Out->DetectionName = "REGISTRY_LSA_CREDENTIALS_QUERY";
            Out->Severity = 7;
            Out->Reason = L"read from LSA Credentials cache — cached domain credential hashes";
            return;
        }
        Out->DetectionName = "REGISTRY_CREDENTIAL_HIVE_QUERY";
        Out->Severity = 8;
        Out->Reason = L"read from SECURITY hive — LSA secrets and cached credentials";
        return;
    }

    /* Kerberos credential store — read before the generic Lsa catch */
    if (BkstrUnicodeContainsInsensitive(&keyUs, L"\\Lsa\\Kerberos", 13) ||
        BkstrUnicodeContainsInsensitive(&keyUs, L"\\Lsa\\MSV1_0", 11) ||
        BkstrUnicodeContainsInsensitive(&keyUs, L"\\Services\\Kdc", 13))
    {
        Out->DetectionName = "REGISTRY_KERBEROS_QUERY";
        Out->Severity = 7;
        Out->Reason =
            L"read from Kerberos/MSV1_0/KDC configuration — Kerberos credential or ticket cache reconnaissance";
        return;
    }

    if ((BkstrUnicodeContainsInsensitive(&keyUs, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa", 54) ||
         BkstrUnicodeContainsInsensitive(&keyUs, L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Lsa", 52)) &&
        BK_REGISTRY_VALUE_IS_LSA_PACKAGE_QUERY())
    {
        Out->DetectionName = "REGISTRY_LSA_QUERY";
        Out->Severity = 7;
        Out->Reason = L"read from LSA authentication-package configuration";
        return;
    }

#undef BK_REGISTRY_VALUE_IS_LSA_PACKAGE_QUERY

    if (BkstrUnicodeContainsInsensitive(&keyUs, L"Windows Defender\\Exclusions", 27) ||
        BkstrUnicodeContainsInsensitive(&keyUs, L"Windows Defender\\Features", 25))
    {
        Out->DetectionName = "REGISTRY_SECURITY_PRODUCT_QUERY";
        Out->Severity = 6;
        Out->Reason = L"read from Windows Defender exclusion or feature key — security product reconnaissance";
        return;
    }

    if (BkstrUnicodeContainsInsensitive(&keyUs, L"Windows\\PowerShell", 18) ||
        BkstrUnicodeContainsInsensitive(&keyUs, L"Policies\\Microsoft\\Windows\\PowerShell", 36))
    {
        Out->DetectionName = "REGISTRY_POWERSHELL_POLICY_QUERY";
        Out->Severity = 6;
        Out->Reason = L"read from PowerShell policy key — script execution and AMSI bypass reconnaissance";
        return;
    }

    if (BkstrUnicodeContainsInsensitive(&keyUs, L"WinSock2\\Parameters", 19))
    {
        Out->DetectionName = "REGISTRY_LSP_QUERY";
        Out->Severity = 6;
        Out->Reason = L"read from Winsock2 parameters — LSP chain reconnaissance for network interception";
        return;
    }

    if (BkstrUnicodeContainsInsensitive(&keyUs, L"Session Manager\\BootExecute", 27))
    {
        Out->DetectionName = "REGISTRY_BOOT_EXECUTE_QUERY";
        Out->Severity = 6;
        Out->Reason = L"read from BootExecute — native executable persistence reconnaissance";
        return;
    }

    if (BkstrUnicodeContainsInsensitive(&keyUs, L"CurrentVersion\\Run", 18))
    {
        Out->DetectionName = "REGISTRY_AUTORUN_QUERY";
        Out->Severity = 5;
        Out->Reason = L"read from autorun key — persistence reconnaissance";
        return;
    }

    if (BkstrUnicodeContainsInsensitive(&keyUs, L"Image File Execution Options", 28))
    {
        Out->DetectionName = "REGISTRY_IFEO_QUERY";
        Out->Severity = 5;
        Out->Reason = L"read from Image File Execution Options — debugger hijack or process redirect reconnaissance";
        return;
    }

    if (BkstrUnicodeContainsInsensitive(&keyUs, L"Windows NT\\CurrentVersion\\Winlogon", 33))
    {
        Out->DetectionName = "REGISTRY_WINLOGON_QUERY";
        Out->Severity = 5;
        Out->Reason = L"read from Winlogon configuration — logon shell and hook reconnaissance";
        return;
    }

    if (BkstrUnicodeContainsInsensitive(&keyUs, L"CurrentControlSet\\Services", 26))
    {
        Out->DetectionName = "REGISTRY_SERVICE_QUERY";
        Out->Severity = 4;
        Out->Reason = L"read from Services key — service enumeration for lateral movement or LPE reconnaissance";
        return;
    }

    if (BkstrUnicodeContainsInsensitive(&valUs, L"AppInit_DLLs", 12))
    {
        Out->DetectionName = "REGISTRY_APPINIT_QUERY";
        Out->Severity = 4;
        Out->Reason = L"read of AppInit_DLLs value — DLL injection persistence reconnaissance";
        return;
    }

    if (BkstrUnicodeContainsInsensitive(&keyUs, L"\\REGISTRY\\USER\\", 15) &&
        BkstrUnicodeContainsInsensitive(&keyUs, L"\\CLSID\\", 7))
    {
        Out->DetectionName = "REGISTRY_COM_HIJACK_RECON";
        Out->Severity = 4;
        Out->Reason = L"read from per-user CLSID key — COM hijacking reconnaissance";
        return;
    }

    if (BkstrUnicodeContainsInsensitive(&keyUs, L"Windows Script Host", 19))
    {
        Out->DetectionName = "REGISTRY_SCRIPT_HOST_QUERY";
        Out->Severity = 4;
        Out->Reason = L"read from Windows Script Host configuration — WSH execution policy reconnaissance";
        return;
    }
}

static LARGE_INTEGER g_RegistryCookie = {0};
static volatile LONG g_RegistryMonitorRegistered = 0;
static volatile LONG g_RegistryFailureCounter = 0;

NTKERNELAPI ULONG PsGetProcessSessionIdEx(_In_ PEPROCESS Process);

#define BK_REG_TARGET_STREAM_MASK                                                                         \
    (BK_STREAM_HANDLE | BK_STREAM_MEMORY | BK_STREAM_THREAD | BK_STREAM_FILESYSTEM | BK_STREAM_REGISTRY | \
     BK_STREAM_TIMING)
#define BK_REG_LIT_CHARS(_Literal) ((USHORT)(RTL_NUMBER_OF(_Literal) - 1))

static BOOLEAN BkavRegIsTargetProcess(_In_ UINT32 ProcessId)
{
    return (BkctlIsArmedFast() && BkctlHasPidInterest(ProcessId, 0, BK_REG_TARGET_STREAM_MASK));
}

static BOOLEAN BkavRegUnicodeContainsAnyBlackbirdArtifact(_In_opt_ PCUNICODE_STRING Text)
{
    if (Text == NULL || Text->Buffer == NULL || Text->Length == 0)
    {
        return FALSE;
    }

    return (BkstrUnicodeContainsInsensitive(Text, L"blackbird", BK_REG_LIT_CHARS(L"blackbird")) ||
            BkstrUnicodeContainsInsensitive(Text, L"BlackbirdCtl", BK_REG_LIT_CHARS(L"BlackbirdCtl")) ||
            BkstrUnicodeContainsInsensitive(Text, L"BlackbirdHookIngest", BK_REG_LIT_CHARS(L"BlackbirdHookIngest")) ||
            BkstrUnicodeContainsInsensitive(Text, L"BlackbirdController", BK_REG_LIT_CHARS(L"BlackbirdController")) ||
            BkstrUnicodeContainsInsensitive(Text, L"BlackbirdInterface", BK_REG_LIT_CHARS(L"BlackbirdInterface")) ||
            BkstrUnicodeContainsInsensitive(Text, L"BK.Kernel", BK_REG_LIT_CHARS(L"BK.Kernel")) ||
            BkstrUnicodeContainsInsensitive(Text, L"sr71.dll", BK_REG_LIT_CHARS(L"sr71.dll")) ||
            BkstrUnicodeContainsInsensitive(Text, L"j58.dll", BK_REG_LIT_CHARS(L"j58.dll")));
}

static BOOLEAN BkavRegUnicodeContainsAnyAnalysisArtifact(_In_opt_ PCUNICODE_STRING Text)
{
    if (Text == NULL || Text->Buffer == NULL || Text->Length == 0)
    {
        return FALSE;
    }

    if (BkavRegUnicodeContainsAnyBlackbirdArtifact(Text))
    {
        return TRUE;
    }

    return (BkstrUnicodeContainsInsensitive(Text, L"vmtoolsd.exe", BK_REG_LIT_CHARS(L"vmtoolsd.exe")) ||
            BkstrUnicodeContainsInsensitive(Text, L"vboxservice.exe", BK_REG_LIT_CHARS(L"vboxservice.exe")) ||
            BkstrUnicodeContainsInsensitive(Text, L"vboxtray.exe", BK_REG_LIT_CHARS(L"vboxtray.exe")) ||
            BkstrUnicodeContainsInsensitive(Text, L"qemu-ga.exe", BK_REG_LIT_CHARS(L"qemu-ga.exe")) ||
            BkstrUnicodeContainsInsensitive(Text, L"xenservice.exe", BK_REG_LIT_CHARS(L"xenservice.exe")) ||
            BkstrUnicodeContainsInsensitive(Text, L"xensvc.exe", BK_REG_LIT_CHARS(L"xensvc.exe")) ||
            BkstrUnicodeContainsInsensitive(Text, L"prl_tools.exe", BK_REG_LIT_CHARS(L"prl_tools.exe")) ||
            BkstrUnicodeContainsInsensitive(Text, L"windbg.exe", BK_REG_LIT_CHARS(L"windbg.exe")) ||
            BkstrUnicodeContainsInsensitive(Text, L"x64dbg.exe", BK_REG_LIT_CHARS(L"x64dbg.exe")) ||
            BkstrUnicodeContainsInsensitive(Text, L"x32dbg.exe", BK_REG_LIT_CHARS(L"x32dbg.exe")) ||
            BkstrUnicodeContainsInsensitive(Text, L"ollydbg.exe", BK_REG_LIT_CHARS(L"ollydbg.exe")) ||
            BkstrUnicodeContainsInsensitive(Text, L"ida64.exe", BK_REG_LIT_CHARS(L"ida64.exe")) ||
            BkstrUnicodeContainsInsensitive(Text, L"ida.exe", BK_REG_LIT_CHARS(L"ida.exe")) ||
            BkstrUnicodeContainsInsensitive(Text, L"ghidra", BK_REG_LIT_CHARS(L"ghidra")) ||
            BkstrUnicodeContainsInsensitive(Text, L"\\vmware\\", BK_REG_LIT_CHARS(L"\\vmware\\")) ||
            BkstrUnicodeContainsInsensitive(Text, L"\\virtualbox\\", BK_REG_LIT_CHARS(L"\\virtualbox\\")) ||
            BkstrUnicodeContainsInsensitive(Text, L"\\qemu\\", BK_REG_LIT_CHARS(L"\\qemu\\")));
}

static BOOLEAN BkavRegIsBamUserSettingsPath(_In_opt_ PCUNICODE_STRING KeyPath)
{
    if (KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0)
    {
        return FALSE;
    }

    return (BkstrUnicodeContainsInsensitive(KeyPath, L"\\services\\bam\\", BK_REG_LIT_CHARS(L"\\services\\bam\\")) &&
            BkstrUnicodeContainsInsensitive(KeyPath, L"\\usersettings\\", BK_REG_LIT_CHARS(L"\\usersettings\\")));
}

static BOOLEAN BkavRegShouldConcealTargetQuery(_In_ UINT32 ProcessId, _In_ ULONG NotifyClass,
                                               _In_opt_ PCUNICODE_STRING KeyPath, _In_opt_ PCUNICODE_STRING ValueName)
{
    if (!BkavRegIsTargetProcess(ProcessId))
    {
        return FALSE;
    }

    if (NotifyClass != RegNtPreOpenKey && NotifyClass != RegNtPreOpenKeyEx && NotifyClass != RegNtPreQueryKey &&
        NotifyClass != RegNtPreQueryValueKey && NotifyClass != RegNtPreEnumerateKey &&
        NotifyClass != RegNtPreEnumerateValueKey)
    {
        return FALSE;
    }

    if (BkavRegUnicodeContainsAnyBlackbirdArtifact(KeyPath) || BkavRegUnicodeContainsAnyBlackbirdArtifact(ValueName))
    {
        return TRUE;
    }

    if (BkavRegIsBamUserSettingsPath(KeyPath) && BkavRegUnicodeContainsAnyAnalysisArtifact(ValueName))
    {
        return TRUE;
    }

    return FALSE;
}

static ULONG BkavRegOverwriteUnicodeName(_Out_writes_bytes_(NameBytes) PWCHAR NameBuffer, _In_ ULONG NameBytes,
                                         _In_z_ PCWSTR Replacement)
{
    SIZE_T maxChars;
    SIZE_T copyChars;

    if (NameBuffer == NULL || NameBytes < sizeof(WCHAR) || Replacement == NULL)
    {
        return 0;
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

    return (ULONG)(copyChars * sizeof(WCHAR));
}

static USHORT BkavRegClampNameLength(_In_ ULONG NameLength)
{
    return (NameLength > MAXUSHORT) ? MAXUSHORT : (USHORT)NameLength;
}

static VOID BkavRegOverwriteKeyName(_Out_writes_bytes_(NameBytes) PWCHAR NameBuffer, _In_ ULONG NameBytes,
                                    _In_z_ PCWSTR Replacement)
{
    (void)BkavRegOverwriteUnicodeName(NameBuffer, NameBytes, Replacement);
}

static BOOLEAN BkavRegBlindPciEnumeration(_In_ PREG_POST_OPERATION_INFORMATION PostInfo)
{
    PUNICODE_STRING keyNamePtr = NULL;
    UNICODE_STRING keyPath;
    NTSTATUS nameStatus;
    PREG_ENUMERATE_KEY_INFORMATION preInfo;

    if (PostInfo == NULL || !NT_SUCCESS(PostInfo->Status) || PostInfo->Object == NULL ||
        PostInfo->PreInformation == NULL || !BkrtIsAntiVirtualizationEnabled())
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
    if (!BkstrUnicodeContainsInsensitive(&keyPath, L"\\enum\\pci", 10))
    {
        CmCallbackReleaseKeyObjectIDEx(keyNamePtr);
        return FALSE;
    }

    switch (preInfo->KeyInformationClass)
    {
    case KeyBasicInformation:
    {
        PKEY_BASIC_INFORMATION info = (PKEY_BASIC_INFORMATION)preInfo->KeyInformation;
        if (info != NULL && info->NameLength >= (8 * sizeof(WCHAR)) && _wcsnicmp(info->Name, L"VEN_15AD", 8) == 0)
        {
            BkavRegOverwriteKeyName(info->Name, info->NameLength, L"VEN_8086");
            info->NameLength = 8 * sizeof(WCHAR);
            CmCallbackReleaseKeyObjectIDEx(keyNamePtr);
            return TRUE;
        }
        break;
    }
    case KeyNodeInformation:
    {
        PKEY_NODE_INFORMATION info = (PKEY_NODE_INFORMATION)preInfo->KeyInformation;
        if (info != NULL && info->NameLength >= (8 * sizeof(WCHAR)) && _wcsnicmp(info->Name, L"VEN_15AD", 8) == 0)
        {
            BkavRegOverwriteKeyName(info->Name, info->NameLength, L"VEN_8086");
            info->NameLength = 8 * sizeof(WCHAR);
            CmCallbackReleaseKeyObjectIDEx(keyNamePtr);
            return TRUE;
        }
        break;
    }
    case KeyNameInformation:
    {
        PKEY_NAME_INFORMATION info = (PKEY_NAME_INFORMATION)preInfo->KeyInformation;
        if (info != NULL && info->NameLength >= (8 * sizeof(WCHAR)) && _wcsnicmp(info->Name, L"VEN_15AD", 8) == 0)
        {
            BkavRegOverwriteKeyName(info->Name, info->NameLength, L"VEN_8086");
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

static BOOLEAN BkavRegConcealBlackbirdKeyEnumeration(_In_ PREG_POST_OPERATION_INFORMATION PostInfo)
{
    PREG_ENUMERATE_KEY_INFORMATION preInfo;
    UNICODE_STRING nameUs;
    ULONG copiedBytes;
    const WCHAR replacement[] = L"Microsoft";

    if (PostInfo == NULL || !NT_SUCCESS(PostInfo->Status) || PostInfo->PreInformation == NULL ||
        !BkavRegIsTargetProcess((UINT32)(ULONG_PTR)PsGetCurrentProcessId()))
    {
        return FALSE;
    }

    preInfo = (PREG_ENUMERATE_KEY_INFORMATION)PostInfo->PreInformation;
    RtlInitUnicodeString(&nameUs, NULL);

    switch (preInfo->KeyInformationClass)
    {
    case KeyBasicInformation:
    {
        PKEY_BASIC_INFORMATION info = (PKEY_BASIC_INFORMATION)preInfo->KeyInformation;
        if (info != NULL && info->NameLength != 0)
        {
            nameUs.Buffer = info->Name;
            nameUs.Length = BkavRegClampNameLength(info->NameLength);
            nameUs.MaximumLength = nameUs.Length;
            if (BkavRegUnicodeContainsAnyBlackbirdArtifact(&nameUs))
            {
                copiedBytes = BkavRegOverwriteUnicodeName(info->Name, info->NameLength, replacement);
                info->NameLength = copiedBytes;
                BkntkiRecordSanitizerHit(BkDiagSanitizerRegistryBlackbird);
                return TRUE;
            }
        }
        break;
    }
    case KeyNodeInformation:
    {
        PKEY_NODE_INFORMATION info = (PKEY_NODE_INFORMATION)preInfo->KeyInformation;
        if (info != NULL && info->NameLength != 0)
        {
            nameUs.Buffer = info->Name;
            nameUs.Length = BkavRegClampNameLength(info->NameLength);
            nameUs.MaximumLength = nameUs.Length;
            if (BkavRegUnicodeContainsAnyBlackbirdArtifact(&nameUs))
            {
                copiedBytes = BkavRegOverwriteUnicodeName(info->Name, info->NameLength, replacement);
                info->NameLength = copiedBytes;
                BkntkiRecordSanitizerHit(BkDiagSanitizerRegistryBlackbird);
                return TRUE;
            }
        }
        break;
    }
    case KeyNameInformation:
    {
        PKEY_NAME_INFORMATION info = (PKEY_NAME_INFORMATION)preInfo->KeyInformation;
        if (info != NULL && info->NameLength != 0)
        {
            nameUs.Buffer = info->Name;
            nameUs.Length = BkavRegClampNameLength(info->NameLength);
            nameUs.MaximumLength = nameUs.Length;
            if (BkavRegUnicodeContainsAnyBlackbirdArtifact(&nameUs))
            {
                copiedBytes = BkavRegOverwriteUnicodeName(info->Name, info->NameLength, replacement);
                info->NameLength = copiedBytes;
                BkntkiRecordSanitizerHit(BkDiagSanitizerRegistryBlackbird);
                return TRUE;
            }
        }
        break;
    }
    default:
        break;
    }

    return FALSE;
}

static BOOLEAN BkavRegConcealBamValueEnumeration(_In_ PREG_POST_OPERATION_INFORMATION PostInfo)
{
    PUNICODE_STRING keyNamePtr = NULL;
    UNICODE_STRING keyPath;
    UNICODE_STRING valueNameUs;
    NTSTATUS nameStatus;
    PREG_ENUMERATE_VALUE_KEY_INFORMATION preInfo;
    ULONG availableBytes;
    ULONG copiedBytes;
    const WCHAR replacement[] = L"\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe";

    if (PostInfo == NULL || !NT_SUCCESS(PostInfo->Status) || PostInfo->Object == NULL ||
        PostInfo->PreInformation == NULL || !BkavRegIsTargetProcess((UINT32)(ULONG_PTR)PsGetCurrentProcessId()))
    {
        return FALSE;
    }

    preInfo = (PREG_ENUMERATE_VALUE_KEY_INFORMATION)PostInfo->PreInformation;
    nameStatus = CmCallbackGetKeyObjectIDEx(&g_RegistryCookie, PostInfo->Object, NULL, &keyNamePtr, 0);
    if (!NT_SUCCESS(nameStatus) || keyNamePtr == NULL)
    {
        return FALSE;
    }

    keyPath = *keyNamePtr;
    if (!BkavRegIsBamUserSettingsPath(&keyPath))
    {
        CmCallbackReleaseKeyObjectIDEx(keyNamePtr);
        return FALSE;
    }

    RtlInitUnicodeString(&valueNameUs, NULL);

    switch (preInfo->KeyValueInformationClass)
    {
    case KeyValueBasicInformation:
    {
        PKEY_VALUE_BASIC_INFORMATION info = (PKEY_VALUE_BASIC_INFORMATION)preInfo->KeyValueInformation;
        if (info != NULL && info->NameLength != 0)
        {
            valueNameUs.Buffer = info->Name;
            valueNameUs.Length = BkavRegClampNameLength(info->NameLength);
            valueNameUs.MaximumLength = valueNameUs.Length;
            if (BkavRegUnicodeContainsAnyAnalysisArtifact(&valueNameUs))
            {
                availableBytes = (preInfo->Length > (ULONG)FIELD_OFFSET(KEY_VALUE_BASIC_INFORMATION, Name))
                                     ? (preInfo->Length - (ULONG)FIELD_OFFSET(KEY_VALUE_BASIC_INFORMATION, Name))
                                     : info->NameLength;
                copiedBytes = BkavRegOverwriteUnicodeName(info->Name, availableBytes, replacement);
                info->NameLength = copiedBytes;
                CmCallbackReleaseKeyObjectIDEx(keyNamePtr);
                BkntkiRecordSanitizerHit(BkDiagSanitizerRegistryBam);
                return TRUE;
            }
        }
        break;
    }
    case KeyValueFullInformation:
    {
        PKEY_VALUE_FULL_INFORMATION info = (PKEY_VALUE_FULL_INFORMATION)preInfo->KeyValueInformation;
        if (info != NULL && info->NameLength != 0)
        {
            valueNameUs.Buffer = info->Name;
            valueNameUs.Length = BkavRegClampNameLength(info->NameLength);
            valueNameUs.MaximumLength = valueNameUs.Length;
            if (BkavRegUnicodeContainsAnyAnalysisArtifact(&valueNameUs))
            {
                availableBytes = (preInfo->Length > (ULONG)FIELD_OFFSET(KEY_VALUE_FULL_INFORMATION, Name))
                                     ? (preInfo->Length - (ULONG)FIELD_OFFSET(KEY_VALUE_FULL_INFORMATION, Name))
                                     : info->NameLength;
                copiedBytes = BkavRegOverwriteUnicodeName(info->Name, availableBytes, replacement);
                info->NameLength = copiedBytes;
                CmCallbackReleaseKeyObjectIDEx(keyNamePtr);
                BkntkiRecordSanitizerHit(BkDiagSanitizerRegistryBam);
                return TRUE;
            }
        }
        break;
    }
    default:
        break;
    }

    CmCallbackReleaseKeyObjectIDEx(keyNamePtr);
    return FALSE;
}

static VOID BkavRegPublishIoctl(_In_ HANDLE Pid, _In_ ULONG SessionId, _In_ UINT32 Operation, _In_ ULONG NotifyClass,
                                _In_ ULONG DataType, _In_ ULONG DataSize, _In_ BOOLEAN HighValuePath,
                                _In_ BOOLEAN SensitiveQuery, _In_opt_z_ PCWSTR KeyPath, _In_opt_z_ PCWSTR ValueName)
{
    BK_REGISTRY_EVENT regEvent;

    if (!BkctlHasPidInterest((UINT32)(ULONG_PTR)Pid, 0, BK_STREAM_REGISTRY))
    {
        return;
    }

    RtlZeroMemory(&regEvent, sizeof(regEvent));
    regEvent.ProcessId = (UINT64)(ULONG_PTR)Pid;
    regEvent.ThreadId = (UINT64)(ULONG_PTR)PsGetCurrentThreadId();
    regEvent.Operation = Operation;
    regEvent.NotifyClass = NotifyClass;
    regEvent.DataType = DataType;
    regEvent.DataSize = DataSize;
    regEvent.Flags = (HighValuePath ? BK_REGISTRY_FLAG_HIGH_VALUE_PATH : 0) |
                     (SensitiveQuery ? BK_REGISTRY_FLAG_SENSITIVE_QUERY : 0);
    regEvent.SessionId = SessionId;
    if (KeyPath != NULL && KeyPath[0] != L'\0')
        RtlCopyMemory(regEvent.KeyPath, KeyPath, sizeof(regEvent.KeyPath) - sizeof(WCHAR));
    if (ValueName != NULL && ValueName[0] != L'\0')
        RtlCopyMemory(regEvent.ValueName, ValueName, sizeof(regEvent.ValueName) - sizeof(WCHAR));

    BkctlPublishRegistryEvent(&regEvent);
}

static NTSTATUS BkavRegCallback(_In_opt_ PVOID CallbackContext, _In_opt_ PVOID Argument1, _In_opt_ PVOID Argument2)
{
    ULONGLONG tempusStartQpc = BktmpEnter(BktmpSubsystemRegistryMonitor);
    REG_NOTIFY_CLASS notifyClass;
    UNICODE_STRING keyPathUs;
    WCHAR keyPath[512];
    WCHAR valueName[128];
    ULONG dataType = 0;
    ULONG dataSize = 0;
    BOOLEAN highValuePath = FALSE;
    BOOLEAN nullPath = FALSE;
    BOOLEAN isQueryClass = FALSE;
    UINT32 ioctlOperation = BkavRegOperationUnknown;
    ULONG sessionId = 0;
    HANDLE pid;
    PCSTR operation = "OTHER";

    UNREFERENCED_PARAMETER(CallbackContext);

    keyPath[0] = L'\0';
    valueName[0] = L'\0';
    RtlInitUnicodeString(&keyPathUs, NULL);

    if (Argument1 == NULL)
    {
        BktmpLeave(BktmpSubsystemRegistryMonitor, tempusStartQpc);
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
        ioctlOperation = BkavRegOperationSetValue;
        if (info != NULL)
        {
            dataType = info->Type;
            dataSize = info->DataSize;
            BkstrSafeCopyUnicode(info->ValueName, valueName, RTL_NUMBER_OF(valueName));

            nameStatus = CmCallbackGetKeyObjectIDEx(&g_RegistryCookie, info->Object, NULL, &keyNameUs, 0);
            if (NT_SUCCESS(nameStatus) && keyNameUs != NULL)
            {
                keyPathUs = *keyNameUs;
                BkstrSafeCopyUnicode(&keyPathUs, keyPath, RTL_NUMBER_OF(keyPath));
                highValuePath = BkavRegPathIsHighValue(&keyPathUs);
                CmCallbackReleaseKeyObjectIDEx(keyNameUs);
            }
        }
    }
    else if (notifyClass == RegNtPreCreateKeyEx)
    {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)Argument2;
        operation = "CREATE_KEY";
        ioctlOperation = BkavRegOperationCreateKey;
        if (info != NULL && info->CompleteName != NULL)
        {
            BkavRegBuildPathForCompare(&g_RegistryCookie, info->RootObject, info->CompleteName, keyPath,
                                       RTL_NUMBER_OF(keyPath), &keyPathUs);
            highValuePath = BkavRegPathIsHighValue(&keyPathUs);
            nullPath = BkavRegNullPath(&keyPathUs);
        }
    }
    else if (notifyClass == RegNtPreOpenKey || notifyClass == RegNtPreOpenKeyEx)
    {
        PREG_OPEN_KEY_INFORMATION info = (PREG_OPEN_KEY_INFORMATION)Argument2;
        operation = "OPEN_KEY";
        ioctlOperation = BkavRegOperationOpenKey;
        if (info != NULL && info->CompleteName != NULL)
        {
            BkavRegBuildPathForCompare(&g_RegistryCookie, info->RootObject, info->CompleteName, keyPath,
                                       RTL_NUMBER_OF(keyPath), &keyPathUs);
            highValuePath = BkavRegPathIsHighValue(&keyPathUs);
            nullPath = BkavRegNullPath(&keyPathUs);
        }
    }
    else if (notifyClass == RegNtPreQueryValueKey)
    {
        PREG_QUERY_VALUE_KEY_INFORMATION info = (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2;
        PUNICODE_STRING keyNameUs = NULL;
        NTSTATUS nameStatus;

        operation = "QUERY_VALUE";
        ioctlOperation = BkavRegOperationQueryValue;
        isQueryClass = TRUE;
        if (info != NULL)
        {
            BkstrSafeCopyUnicode(info->ValueName, valueName, RTL_NUMBER_OF(valueName));
            nameStatus = CmCallbackGetKeyObjectIDEx(&g_RegistryCookie, info->Object, NULL, &keyNameUs, 0);
            if (NT_SUCCESS(nameStatus) && keyNameUs != NULL)
            {
                keyPathUs = *keyNameUs;
                BkstrSafeCopyUnicode(&keyPathUs, keyPath, RTL_NUMBER_OF(keyPath));
                highValuePath = BkavRegPathIsHighValue(&keyPathUs);
                CmCallbackReleaseKeyObjectIDEx(keyNameUs);
            }
        }
    }
    else if (notifyClass == RegNtPreQueryKey)
    {
        PREG_QUERY_KEY_INFORMATION info = (PREG_QUERY_KEY_INFORMATION)Argument2;
        PUNICODE_STRING keyNameUs = NULL;
        NTSTATUS nameStatus;

        operation = "QUERY_KEY";
        ioctlOperation = BkavRegOperationQueryKey;
        isQueryClass = TRUE;
        if (info != NULL)
        {
            nameStatus = CmCallbackGetKeyObjectIDEx(&g_RegistryCookie, info->Object, NULL, &keyNameUs, 0);
            if (NT_SUCCESS(nameStatus) && keyNameUs != NULL)
            {
                keyPathUs = *keyNameUs;
                BkstrSafeCopyUnicode(&keyPathUs, keyPath, RTL_NUMBER_OF(keyPath));
                highValuePath = BkavRegPathIsHighValue(&keyPathUs);
                CmCallbackReleaseKeyObjectIDEx(keyNameUs);
            }
        }
    }
    else if (notifyClass == RegNtPreEnumerateKey)
    {
        PREG_ENUMERATE_KEY_INFORMATION info = (PREG_ENUMERATE_KEY_INFORMATION)Argument2;
        PUNICODE_STRING keyNameUs = NULL;
        NTSTATUS nameStatus;

        operation = "ENUMERATE_KEY";
        ioctlOperation = BkavRegOperationEnumerateKey;
        isQueryClass = TRUE;
        if (info != NULL)
        {
            nameStatus = CmCallbackGetKeyObjectIDEx(&g_RegistryCookie, info->Object, NULL, &keyNameUs, 0);
            if (NT_SUCCESS(nameStatus) && keyNameUs != NULL)
            {
                keyPathUs = *keyNameUs;
                BkstrSafeCopyUnicode(&keyPathUs, keyPath, RTL_NUMBER_OF(keyPath));
                highValuePath = BkavRegPathIsHighValue(&keyPathUs);
                CmCallbackReleaseKeyObjectIDEx(keyNameUs);
            }
        }
    }
    else if (notifyClass == RegNtPreEnumerateValueKey)
    {
        PREG_ENUMERATE_VALUE_KEY_INFORMATION info = (PREG_ENUMERATE_VALUE_KEY_INFORMATION)Argument2;
        PUNICODE_STRING keyNameUs = NULL;
        NTSTATUS nameStatus;

        operation = "ENUMERATE_VALUE";
        ioctlOperation = BkavRegOperationEnumerateValue;
        isQueryClass = TRUE;
        if (info != NULL)
        {
            nameStatus = CmCallbackGetKeyObjectIDEx(&g_RegistryCookie, info->Object, NULL, &keyNameUs, 0);
            if (NT_SUCCESS(nameStatus) && keyNameUs != NULL)
            {
                keyPathUs = *keyNameUs;
                BkstrSafeCopyUnicode(&keyPathUs, keyPath, RTL_NUMBER_OF(keyPath));
                highValuePath = BkavRegPathIsHighValue(&keyPathUs);
                CmCallbackReleaseKeyObjectIDEx(keyNameUs);
            }
        }
    }
    else if (notifyClass == RegNtPostQueryValueKey)
    {
        PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
        PREG_QUERY_VALUE_KEY_INFORMATION preInfo;

        if (postInfo == NULL || !NT_SUCCESS(postInfo->Status) || postInfo->PreInformation == NULL)
        {
            BktmpLeave(BktmpSubsystemRegistryMonitor, tempusStartQpc);
            return STATUS_SUCCESS;
        }

        preInfo = (PREG_QUERY_VALUE_KEY_INFORMATION)postInfo->PreInformation;
        if (BkavRegBlindBiosValue(&g_RegistryCookie, postInfo->Object, preInfo))
        {
            BktmpLeave(BktmpSubsystemRegistryMonitor, tempusStartQpc);
            return STATUS_SUCCESS;
        }
        if (BkavRegBlindNicValue(&g_RegistryCookie, postInfo->Object, preInfo))
        {
            BktmpLeave(BktmpSubsystemRegistryMonitor, tempusStartQpc);
            return STATUS_SUCCESS;
        }
        if (BkavRegBlindDisplayValue(&g_RegistryCookie, postInfo->Object, preInfo))
        {
            BktmpLeave(BktmpSubsystemRegistryMonitor, tempusStartQpc);
            return STATUS_SUCCESS;
        }
        if (BkavRegBlindScsiValue(&g_RegistryCookie, postInfo->Object, preInfo))
        {
            BktmpLeave(BktmpSubsystemRegistryMonitor, tempusStartQpc);
            return STATUS_SUCCESS;
        }

        {
            PUNICODE_STRING keyNameUs = NULL;
            NTSTATUS nameStatus = CmCallbackGetKeyObjectIDEx(&g_RegistryCookie, postInfo->Object, NULL, &keyNameUs, 0);
            BkstrSafeCopyUnicode(preInfo->ValueName, valueName, RTL_NUMBER_OF(valueName));
            if (NT_SUCCESS(nameStatus) && keyNameUs != NULL)
            {
                keyPathUs = *keyNameUs;
                BkstrSafeCopyUnicode(&keyPathUs, keyPath, RTL_NUMBER_OF(keyPath));
                highValuePath = BkavRegPathIsHighValue(&keyPathUs);
                CmCallbackReleaseKeyObjectIDEx(keyNameUs);
            }
        }

        operation = "QUERY_VALUE";
        ioctlOperation = BkavRegOperationQueryValue;
        isQueryClass = TRUE;
    }
    else if (notifyClass == RegNtPostEnumerateKey)
    {
        PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
        if (BkavRegBlindPciEnumeration(postInfo) || BkavRegConcealBlackbirdKeyEnumeration(postInfo))
        {
            BktmpLeave(BktmpSubsystemRegistryMonitor, tempusStartQpc);
            return STATUS_SUCCESS;
        }
        BktmpLeave(BktmpSubsystemRegistryMonitor, tempusStartQpc);
        return STATUS_SUCCESS;
    }
    else if (notifyClass == RegNtPostEnumerateValueKey)
    {
        PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
        if (BkavRegConcealBamValueEnumeration(postInfo))
        {
            BktmpLeave(BktmpSubsystemRegistryMonitor, tempusStartQpc);
            return STATUS_SUCCESS;
        }
        BktmpLeave(BktmpSubsystemRegistryMonitor, tempusStartQpc);
        return STATUS_SUCCESS;
    }
    else if (notifyClass == RegNtPreDeleteValueKey)
    {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        operation = "DELETE_VALUE";
        ioctlOperation = BkavRegOperationDeleteValue;
        if (info != NULL)
        {
            PUNICODE_STRING keyNameUs = NULL;
            NTSTATUS nameStatus = CmCallbackGetKeyObjectIDEx(&g_RegistryCookie, info->Object, NULL, &keyNameUs, 0);
            BkstrSafeCopyUnicode(info->ValueName, valueName, RTL_NUMBER_OF(valueName));
            if (NT_SUCCESS(nameStatus) && keyNameUs != NULL)
            {
                keyPathUs = *keyNameUs;
                BkstrSafeCopyUnicode(&keyPathUs, keyPath, RTL_NUMBER_OF(keyPath));
                highValuePath = BkavRegPathIsHighValue(&keyPathUs);
                CmCallbackReleaseKeyObjectIDEx(keyNameUs);
            }
        }
    }
    else
    {
        BktmpLeave(BktmpSubsystemRegistryMonitor, tempusStartQpc);
        return STATUS_SUCCESS;
    }

    {
        UNICODE_STRING concealKeyPathUs;
        UNICODE_STRING concealValueNameUs;

        RtlInitUnicodeString(&concealKeyPathUs, (keyPath[0] != L'\0') ? keyPath : L"");
        RtlInitUnicodeString(&concealValueNameUs, (valueName[0] != L'\0') ? valueName : L"");
        if (BkavRegShouldConcealTargetQuery((UINT32)(ULONG_PTR)pid, (ULONG)notifyClass, &concealKeyPathUs,
                                            &concealValueNameUs))
        {
            nullPath = TRUE;
            BkntkiRecordSanitizerHit(BkavRegIsBamUserSettingsPath(&concealKeyPathUs)
                                         ? BkDiagSanitizerRegistryBam
                                         : BkDiagSanitizerRegistryBlackbird);
        }
    }

    {
        BK_REG_WRITE_CLASS cls;
        BOOLEAN sensitiveQuery = FALSE;

        RtlZeroMemory(&cls, sizeof(cls));
        BketwLogRegistryEvent(operation, pid, sessionId, (ULONG)notifyClass, dataType, dataSize, highValuePath,
                              (keyPath[0] != L'\0') ? keyPath : NULL, (valueName[0] != L'\0') ? valueName : NULL);

        if (highValuePath)
        {
            BketwLogDetectionEvent("HIGH_VALUE_REGISTRY_ACTIVITY", 2, pid, NULL, 0, 0, 0, keyPath);
        }

        if (notifyClass == RegNtPreSetValueKey || notifyClass == RegNtPreCreateKeyEx ||
            notifyClass == RegNtPreDeleteValueKey)
        {
            BkavRegClassifyWrite(keyPath, valueName, &cls);
            if (cls.DetectionName != NULL)
            {
                BketwLogDetectionEvent(cls.DetectionName, cls.Severity, pid, NULL, 0, 0, 0, cls.Reason);
            }
        }

        if (isQueryClass)
        {
            BkavRegClassifyQuery(keyPath, valueName, &cls);
            if (cls.DetectionName != NULL)
            {
                sensitiveQuery = TRUE;
                BketwLogDetectionEvent(cls.DetectionName, cls.Severity, pid, NULL, 0, 0, 0, cls.Reason);
            }
        }

        if (ioctlOperation != BkavRegOperationUnknown)
        {
            BkavRegPublishIoctl(pid, sessionId, ioctlOperation, (ULONG)notifyClass, dataType, dataSize, highValuePath,
                                sensitiveQuery, (keyPath[0] != L'\0') ? keyPath : NULL,
                                (valueName[0] != L'\0') ? valueName : NULL);
        }
    }

    if (nullPath)
    {
        BktmpLeave(BktmpSubsystemRegistryMonitor, tempusStartQpc);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    BktmpLeave(BktmpSubsystemRegistryMonitor, tempusStartQpc);
    return STATUS_SUCCESS;
}

NTSTATUS
BkcregInitialize(_In_ PDRIVER_OBJECT DriverObject)
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

    RtlInitUnicodeString(&altitude, BK_REG_MON_ALTITUDE);
    status = CmRegisterCallbackEx(BkavRegCallback, &altitude, DriverObject, NULL, &g_RegistryCookie, NULL);
    if (!NT_SUCCESS(status))
    {
        failures = InterlockedIncrement(&g_RegistryFailureCounter);
        if (failures == 1 || ((failures & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "BK: registry monitor callback registration failed status=0x%08X total=%lu.\n", status,
                       (ULONG)failures);
        }
        return status;
    }

    InterlockedExchange(&g_RegistryMonitorRegistered, 1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BK: registry monitor initialized.\n");
    return STATUS_SUCCESS;
}

VOID BkcregUninitialize(VOID)
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
                   "BK: registry monitor callback removal failed; monitor remains registered (status=0x%08X).\n",
                   status);
        return;
    }

    InterlockedExchange(&g_RegistryMonitorRegistered, 0);
    RtlZeroMemory(&g_RegistryCookie, sizeof(g_RegistryCookie));
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BK: registry monitor uninitialized.\n");
}

BOOLEAN
BkcregSelfCheck(VOID)
{
    if (InterlockedCompareExchange(&g_RegistryMonitorRegistered, 0, 0) == 0)
    {
        return FALSE;
    }

    return (g_RegistryCookie.QuadPart != 0);
}
