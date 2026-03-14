#include <ntddk.h>
#include "..\telemetry\etw.h"
#include "..\core\unicode_utils.h"
#include "registry_monitor.h"

#define BLACKBIRD_REG_MON_ALTITUDE L"385000.424244"

static LARGE_INTEGER g_RegistryCookie = { 0 };
static volatile LONG g_RegistryMonitorRegistered = 0;
static volatile LONG g_RegistryFailureCounter = 0;

NTKERNELAPI ULONG PsGetProcessSessionIdEx(_In_ PEPROCESS Process);

static BOOLEAN BLACKBIRDIsHighValueRegistryPath(_In_ PCUNICODE_STRING Path)
{
    if (Path == NULL || Path->Buffer == NULL)
    {
        return FALSE;
    }

    if (BLACKBIRDUnicodeContainsInsensitive(Path, L"\\currentversion\\run", 19)
        || BLACKBIRDUnicodeContainsInsensitive(Path, L"\\currentversion\\runonce", 23)
        || BLACKBIRDUnicodeContainsInsensitive(Path, L"\\image file execution options", 29)
        || BLACKBIRDUnicodeContainsInsensitive(Path, L"\\system\\currentcontrolset\\services\\", 35))
    {
        return TRUE;
    }
    return FALSE;
}

static NTSTATUS
BLACKBIRDRegistryCallback(_In_opt_ PVOID CallbackContext, _In_opt_ PVOID Argument1, _In_opt_ PVOID Argument2)
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

    if (Argument1 == NULL)
    {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS) (ULONG_PTR) Argument1;
    pid = PsGetCurrentProcessId();
    sessionId = PsGetProcessSessionIdEx(PsGetCurrentProcess());

    if (notifyClass == RegNtPreSetValueKey)
    {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION) Argument2;
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
                highValuePath = BLACKBIRDIsHighValueRegistryPath(&keyPathUs);
                CmCallbackReleaseKeyObjectIDEx(keyNameUs);
            }
        }
    }
    else if (notifyClass == RegNtPreCreateKeyEx)
    {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION) Argument2;
        operation = "CREATE_KEY";
        if (info != NULL && info->CompleteName != NULL)
        {
            keyPathUs = *info->CompleteName;
            BLACKBIRDSafeCopyUnicode(&keyPathUs, keyPath, RTL_NUMBER_OF(keyPath));
            highValuePath = BLACKBIRDIsHighValueRegistryPath(&keyPathUs);
        }
    }
    else if (notifyClass == RegNtPreOpenKeyEx)
    {
        PREG_OPEN_KEY_INFORMATION info = (PREG_OPEN_KEY_INFORMATION) Argument2;
        operation = "OPEN_KEY";
        if (info != NULL && info->CompleteName != NULL)
        {
            keyPathUs = *info->CompleteName;
            BLACKBIRDSafeCopyUnicode(&keyPathUs, keyPath, RTL_NUMBER_OF(keyPath));
            highValuePath = BLACKBIRDIsHighValueRegistryPath(&keyPathUs);
        }
    }
    else if (notifyClass == RegNtPreDeleteValueKey)
    {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION) Argument2;
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
                highValuePath = BLACKBIRDIsHighValueRegistryPath(&keyPathUs);
                CmCallbackReleaseKeyObjectIDEx(keyNameUs);
            }
        }
    }
    else
    {
        return STATUS_SUCCESS;
    }

    BLACKBIRDEtwLogRegistryEvent(operation,
                                 pid,
                                 sessionId,
                                 (ULONG) notifyClass,
                                 dataType,
                                 dataSize,
                                 highValuePath,
                                 (keyPath[0] != L'\0') ? keyPath : NULL,
                                 (valueName[0] != L'\0') ? valueName : NULL);

    if (highValuePath)
    {
        BLACKBIRDEtwLogDetectionEvent("HIGH_VALUE_REGISTRY_ACTIVITY", 2, pid, NULL, 0, 0, 0, keyPath);
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
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_ERROR_LEVEL,
                       "BLACKBIRD: registry monitor callback registration failed status=0x%08X total=%lu.\n",
                       status,
                       (ULONG) failures);
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
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
