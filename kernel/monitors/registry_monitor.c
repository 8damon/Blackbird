#include <ntddk.h>
#include "..\telemetry\etw.h"
#include "registry_monitor.h"

#define STINGER_REG_MON_ALTITUDE L"385000.424244"

static LARGE_INTEGER g_RegistryCookie = { 0 };
static volatile LONG g_RegistryMonitorRegistered = 0;
static volatile LONG g_RegistryFailureCounter = 0;

NTKERNELAPI ULONG PsGetProcessSessionIdEx(_In_ PEPROCESS Process);

static
BOOLEAN
STINGERUnicodeContainsInsensitive(
    _In_ PCUNICODE_STRING Haystack,
    _In_reads_(NeedleChars) PCWSTR Needle,
    _In_ USHORT NeedleChars
)
{
    USHORT hayChars;
    USHORT i;
    USHORT j;

    if (Haystack == NULL || Haystack->Buffer == NULL || Needle == NULL || NeedleChars == 0) {
        return FALSE;
    }

    hayChars = Haystack->Length / sizeof(WCHAR);
    if (hayChars < NeedleChars) {
        return FALSE;
    }

    for (i = 0; i <= (USHORT)(hayChars - NeedleChars); ++i) {
        BOOLEAN match = TRUE;
        for (j = 0; j < NeedleChars; ++j) {
            if (RtlDowncaseUnicodeChar(Haystack->Buffer[i + j]) != RtlDowncaseUnicodeChar(Needle[j])) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN
STINGERIsHighValueRegistryPath(
    _In_ PCUNICODE_STRING Path
)
{
    if (Path == NULL || Path->Buffer == NULL) {
        return FALSE;
    }

    if (STINGERUnicodeContainsInsensitive(Path, L"\\currentversion\\run", 19) ||
        STINGERUnicodeContainsInsensitive(Path, L"\\currentversion\\runonce", 23) ||
        STINGERUnicodeContainsInsensitive(Path, L"\\image file execution options", 29) ||
        STINGERUnicodeContainsInsensitive(Path, L"\\system\\currentcontrolset\\services\\", 35)) {
        return TRUE;
    }
    return FALSE;
}

static
VOID
STINGERSafeCopyUnicode(
    _In_opt_ PCUNICODE_STRING Source,
    _Out_writes_z_(DestChars) PWSTR Dest,
    _In_ SIZE_T DestChars
)
{
    SIZE_T copyChars;

    if (Dest == NULL || DestChars == 0) {
        return;
    }
    Dest[0] = L'\0';

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return;
    }

    copyChars = Source->Length / sizeof(WCHAR);
    if (copyChars >= DestChars) {
        copyChars = DestChars - 1;
    }
    if (copyChars == 0) {
        return;
    }

    RtlCopyMemory(Dest, Source->Buffer, copyChars * sizeof(WCHAR));
    Dest[copyChars] = L'\0';
}

static
NTSTATUS
STINGERRegistryCallback(
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
)
{
    REG_NOTIFY_CLASS notifyClass;
    UNICODE_STRING keyPathUs;
    WCHAR keyPath[512];
    WCHAR valueName[128];
    ULONG dataType = 0;
    ULONG dataSize = 0;
    BOOLEAN highValuePath = FALSE;
    ULONG sessionId = 0;
    HANDLE pid;
    PCSTR operation = "OTHER";

    UNREFERENCED_PARAMETER(CallbackContext);

    keyPath[0] = L'\0';
    valueName[0] = L'\0';
    RtlInitUnicodeString(&keyPathUs, NULL);

    if (Argument1 == NULL) {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    pid = PsGetCurrentProcessId();
    sessionId = PsGetProcessSessionIdEx(PsGetCurrentProcess());

    if (notifyClass == RegNtPreSetValueKey) {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        PUNICODE_STRING keyNameUs = NULL;
        NTSTATUS nameStatus;

        operation = "SET_VALUE";
        if (info != NULL) {
            dataType = info->Type;
            dataSize = info->DataSize;
            STINGERSafeCopyUnicode(info->ValueName, valueName, RTL_NUMBER_OF(valueName));

            nameStatus = CmCallbackGetKeyObjectIDEx(&g_RegistryCookie, info->Object, NULL, &keyNameUs, 0);
            if (NT_SUCCESS(nameStatus) && keyNameUs != NULL) {
                keyPathUs = *keyNameUs;
                STINGERSafeCopyUnicode(&keyPathUs, keyPath, RTL_NUMBER_OF(keyPath));
                highValuePath = STINGERIsHighValueRegistryPath(&keyPathUs);
                CmCallbackReleaseKeyObjectIDEx(keyNameUs);
            }
        }
    } else if (notifyClass == RegNtPreCreateKeyEx) {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)Argument2;
        operation = "CREATE_KEY";
        if (info != NULL && info->CompleteName != NULL) {
            keyPathUs = *info->CompleteName;
            STINGERSafeCopyUnicode(&keyPathUs, keyPath, RTL_NUMBER_OF(keyPath));
            highValuePath = STINGERIsHighValueRegistryPath(&keyPathUs);
        }
    } else if (notifyClass == RegNtPreOpenKeyEx) {
        PREG_OPEN_KEY_INFORMATION info = (PREG_OPEN_KEY_INFORMATION)Argument2;
        operation = "OPEN_KEY";
        if (info != NULL && info->CompleteName != NULL) {
            keyPathUs = *info->CompleteName;
            STINGERSafeCopyUnicode(&keyPathUs, keyPath, RTL_NUMBER_OF(keyPath));
            highValuePath = STINGERIsHighValueRegistryPath(&keyPathUs);
        }
    } else if (notifyClass == RegNtPreDeleteValueKey) {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        operation = "DELETE_VALUE";
        if (info != NULL) {
            PUNICODE_STRING keyNameUs = NULL;
            NTSTATUS nameStatus = CmCallbackGetKeyObjectIDEx(&g_RegistryCookie, info->Object, NULL, &keyNameUs, 0);
            STINGERSafeCopyUnicode(info->ValueName, valueName, RTL_NUMBER_OF(valueName));
            if (NT_SUCCESS(nameStatus) && keyNameUs != NULL) {
                keyPathUs = *keyNameUs;
                STINGERSafeCopyUnicode(&keyPathUs, keyPath, RTL_NUMBER_OF(keyPath));
                highValuePath = STINGERIsHighValueRegistryPath(&keyPathUs);
                CmCallbackReleaseKeyObjectIDEx(keyNameUs);
            }
        }
    } else {
        return STATUS_SUCCESS;
    }

    STINGEREtwLogRegistryEvent(
        operation,
        pid,
        sessionId,
        (ULONG)notifyClass,
        dataType,
        dataSize,
        highValuePath,
        (keyPath[0] != L'\0') ? keyPath : NULL,
        (valueName[0] != L'\0') ? valueName : NULL
    );

    if (highValuePath) {
        STINGEREtwLogDetectionEvent(
            "HIGH_VALUE_REGISTRY_ACTIVITY",
            2,
            pid,
            NULL,
            0,
            0,
            0,
            keyPath
        );
    }

    return STATUS_SUCCESS;
}

NTSTATUS
STINGERRegistryMonitorInitialize(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    NTSTATUS status;
    UNICODE_STRING altitude;
    LONG failures;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (InterlockedCompareExchange(&g_RegistryMonitorRegistered, 0, 0) != 0) {
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&altitude, STINGER_REG_MON_ALTITUDE);
    status = CmRegisterCallbackEx(
        STINGERRegistryCallback,
        &altitude,
        DriverObject,
        NULL,
        &g_RegistryCookie,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        failures = InterlockedIncrement(&g_RegistryFailureCounter);
        if (failures == 1 || ((failures & 0xFF) == 0)) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_ERROR_LEVEL,
                "STINGER: registry monitor callback registration failed status=0x%08X total=%lu.\n",
                status,
                (ULONG)failures
            );
        }
        return status;
    }

    InterlockedExchange(&g_RegistryMonitorRegistered, 1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "STINGER: registry monitor initialized.\n");
    return STATUS_SUCCESS;
}

VOID
STINGERRegistryMonitorUninitialize(
    VOID
)
{
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }
    if (InterlockedExchange(&g_RegistryMonitorRegistered, 0) == 0) {
        return;
    }

    status = CmUnRegisterCallback(g_RegistryCookie);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "STINGER: registry monitor callback removal failed status=0x%08X.\n",
            status
        );
    }

    RtlZeroMemory(&g_RegistryCookie, sizeof(g_RegistryCookie));
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "STINGER: registry monitor uninitialized.\n");
}
