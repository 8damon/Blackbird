#include <ntddk.h>
#include <ntstrsafe.h>
#include "runtime_config.h"
#include "control.h"

static volatile LONG g_RuntimeConfigInitialized = 0;
static volatile ULONG g_RuntimePersistentFlags = 0;
static volatile ULONG g_RuntimeRequestedFlags = 0;

static ULONG BLACKBIRDRuntimeConfigReadDwordValue(_In_ HANDLE KeyHandle, _In_z_ PCWSTR ValueName)
{
    UNICODE_STRING valueName;
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)] = {0};
    ULONG bytes = 0;
    NTSTATUS status;
    PKEY_VALUE_PARTIAL_INFORMATION info;

    if (KeyHandle == NULL || ValueName == NULL || ValueName[0] == L'\0')
    {
        return 0;
    }

    RtlInitUnicodeString(&valueName, ValueName);
    status = ZwQueryValueKey(KeyHandle, &valueName, KeyValuePartialInformation, buffer, sizeof(buffer), &bytes);
    if (!NT_SUCCESS(status))
    {
        return 0;
    }

    info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    if (info->Type != REG_DWORD || info->DataLength < sizeof(ULONG))
    {
        return 0;
    }

    return *(ULONG UNALIGNED *)info->Data;
}

static ULONG BLACKBIRDRuntimeConfigLoadPersistentFlags(_In_ PUNICODE_STRING RegistryPath)
{
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING parametersPath;
    WCHAR buffer[512];
    HANDLE keyHandle = NULL;
    ULONG flags = 0;

    if (RegistryPath == NULL || RegistryPath->Buffer == NULL || RegistryPath->Length == 0)
    {
        return 0;
    }

    if (!NT_SUCCESS(RtlStringCchPrintfW(buffer, RTL_NUMBER_OF(buffer), L"%wZ\\Parameters", RegistryPath)))
    {
        return 0;
    }

    RtlInitUnicodeString(&parametersPath, buffer);
    InitializeObjectAttributes(&oa, &parametersPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&keyHandle, KEY_QUERY_VALUE, &oa)))
    {
        return 0;
    }

    if (BLACKBIRDRuntimeConfigReadDwordValue(keyHandle, L"EnableAntiVirtualization") != 0)
    {
        flags |= BLACKBIRD_RUNTIME_FLAG_ANTI_VIRTUALIZATION;
    }
    if (BLACKBIRDRuntimeConfigReadDwordValue(keyHandle, L"EnableSelfHide") != 0)
    {
        flags |= BLACKBIRD_RUNTIME_FLAG_SELF_HIDE;
    }
    if (BLACKBIRDRuntimeConfigReadDwordValue(keyHandle, L"EnableInterfaceProtectedAccess") != 0)
    {
        flags |= BLACKBIRD_RUNTIME_FLAG_INTERFACE_PROTECTED_ACCESS;
    }
    if (BLACKBIRDRuntimeConfigReadDwordValue(keyHandle, L"EnableControllerProtectedAccess") != 0)
    {
        flags |= BLACKBIRD_RUNTIME_FLAG_CONTROLLER_PROTECTED_ACCESS;
    }
    if (BLACKBIRDRuntimeConfigReadDwordValue(keyHandle, L"DisableNtApiHooks") != 0)
    {
        flags |= BLACKBIRD_RUNTIME_FLAG_NTAPI_HOOKS_DISARMED;
    }

    ZwClose(keyHandle);
    return flags;
}

NTSTATUS BLACKBIRDRuntimeConfigInitialize(_In_ PUNICODE_STRING RegistryPath)
{
    ULONG persistentFlags;

    persistentFlags = BLACKBIRDRuntimeConfigLoadPersistentFlags(RegistryPath);
    InterlockedExchange((volatile LONG *)&g_RuntimePersistentFlags, (LONG)persistentFlags);
    InterlockedExchange((volatile LONG *)&g_RuntimeRequestedFlags, 0);
    InterlockedExchange(&g_RuntimeConfigInitialized, 1);
    return STATUS_SUCCESS;
}

VOID BLACKBIRDRuntimeConfigUninitialize(VOID)
{
    InterlockedExchange(&g_RuntimeConfigInitialized, 0);
    InterlockedExchange((volatile LONG *)&g_RuntimePersistentFlags, 0);
    InterlockedExchange((volatile LONG *)&g_RuntimeRequestedFlags, 0);
}

UINT32 BLACKBIRDRuntimeConfigGetPersistentFlags(VOID)
{
    return (UINT32)InterlockedCompareExchange((volatile LONG *)&g_RuntimePersistentFlags, 0, 0);
}

UINT32 BLACKBIRDRuntimeConfigGetRuntimeFlags(VOID)
{
    return (UINT32)InterlockedCompareExchange((volatile LONG *)&g_RuntimeRequestedFlags, 0, 0);
}

UINT32 BLACKBIRDRuntimeConfigGetEffectiveFlags(VOID)
{
    return BLACKBIRDRuntimeConfigGetPersistentFlags() | BLACKBIRDRuntimeConfigGetRuntimeFlags();
}

BOOLEAN BLACKBIRDRuntimeConfigIsAntiVirtualizationEnabled(VOID)
{
    return ((BLACKBIRDRuntimeConfigGetEffectiveFlags() & BLACKBIRD_RUNTIME_FLAG_ANTI_VIRTUALIZATION) != 0);
}

BOOLEAN BLACKBIRDRuntimeConfigIsSelfHideEnabled(VOID)
{
    return ((BLACKBIRDRuntimeConfigGetEffectiveFlags() & BLACKBIRD_RUNTIME_FLAG_SELF_HIDE) != 0);
}

BOOLEAN BLACKBIRDRuntimeConfigIsInterfaceProtectedAccessEnabled(VOID)
{
    return ((BLACKBIRDRuntimeConfigGetEffectiveFlags() & BLACKBIRD_RUNTIME_FLAG_INTERFACE_PROTECTED_ACCESS) != 0);
}

BOOLEAN BLACKBIRDRuntimeConfigIsControllerProtectedAccessEnabled(VOID)
{
    return ((BLACKBIRDRuntimeConfigGetEffectiveFlags() & BLACKBIRD_RUNTIME_FLAG_CONTROLLER_PROTECTED_ACCESS) != 0);
}

BOOLEAN BLACKBIRDRuntimeConfigIsNtApiHooksDisarmed(VOID)
{
    return ((BLACKBIRDRuntimeConfigGetEffectiveFlags() & BLACKBIRD_RUNTIME_FLAG_NTAPI_HOOKS_DISARMED) != 0);
}

UINT32 BLACKBIRDRuntimeConfigGetCurrentMode(VOID)
{
    return BLACKBIRDControlIsArmedFast() ? BLACKBIRD_RUNTIME_MODE_GUIDED : BLACKBIRD_RUNTIME_MODE_LOITER;
}

NTSTATUS BLACKBIRDRuntimeConfigSetRuntimeFlags(_In_ UINT32 Flags, _In_ UINT32 Mask)
{
    LONG currentFlags;
    LONG nextFlags;

    if (InterlockedCompareExchange(&g_RuntimeConfigInitialized, 0, 0) == 0)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    Mask &= (BLACKBIRD_RUNTIME_FLAG_ANTI_VIRTUALIZATION | BLACKBIRD_RUNTIME_FLAG_SELF_HIDE |
             BLACKBIRD_RUNTIME_FLAG_INTERFACE_PROTECTED_ACCESS | BLACKBIRD_RUNTIME_FLAG_CONTROLLER_PROTECTED_ACCESS |
             BLACKBIRD_RUNTIME_FLAG_NTAPI_HOOKS_DISARMED);
    Flags &= (BLACKBIRD_RUNTIME_FLAG_ANTI_VIRTUALIZATION | BLACKBIRD_RUNTIME_FLAG_SELF_HIDE |
              BLACKBIRD_RUNTIME_FLAG_INTERFACE_PROTECTED_ACCESS | BLACKBIRD_RUNTIME_FLAG_CONTROLLER_PROTECTED_ACCESS |
              BLACKBIRD_RUNTIME_FLAG_NTAPI_HOOKS_DISARMED);

    for (;;)
    {
        currentFlags = InterlockedCompareExchange((volatile LONG *)&g_RuntimeRequestedFlags, 0, 0);
        nextFlags = (currentFlags & ~(LONG)Mask) | (LONG)(Flags & Mask);
        if (InterlockedCompareExchange((volatile LONG *)&g_RuntimeRequestedFlags, nextFlags, currentFlags) ==
            currentFlags)
        {
            return STATUS_SUCCESS;
        }
    }
}

VOID BLACKBIRDRuntimeConfigFillResponse(_Out_ PBLACKBIRD_RUNTIME_CONFIG_RESPONSE Response)
{
    if (Response == NULL)
    {
        return;
    }

    RtlZeroMemory(Response, sizeof(*Response));
    Response->PersistentFlags = BLACKBIRDRuntimeConfigGetPersistentFlags();
    Response->RuntimeFlags = BLACKBIRDRuntimeConfigGetRuntimeFlags();
    Response->EffectiveFlags = BLACKBIRDRuntimeConfigGetEffectiveFlags();
    Response->Mode = BLACKBIRDRuntimeConfigGetCurrentMode();
}
