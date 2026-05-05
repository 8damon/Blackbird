#include <ntddk.h>
#include <ntstrsafe.h>
#include "runtime_config.h"
#include "control.h"

static volatile LONG g_RuntimeConfigInitialized = 0;
static volatile ULONG g_RuntimePersistentFlags = 0;
static volatile LONG64 g_RuntimeOverride = 0;

#define BK_RUNTIME_MUTABLE_MASK                                                                                     \
    (BK_RUNTIME_FLAG_ANTI_VIRTUALIZATION | BK_RUNTIME_FLAG_SELF_HIDE | BK_RUNTIME_FLAG_INTERFACE_PROTECTED_ACCESS | \
     BK_RUNTIME_FLAG_CONTROLLER_PROTECTED_ACCESS | BK_RUNTIME_FLAG_NTAPI_HOOKS_DISARMED |                           \
     BK_RUNTIME_FLAG_QPC_TIMING_DISABLED)

static ULONGLONG BkrtPackRuntimeOverride(_In_ UINT32 Flags, _In_ UINT32 Mask)
{
    return (((ULONGLONG)Mask) << 32) | (ULONGLONG)Flags;
}

static UINT32 BkrtRuntimeOverrideFlags(_In_ ULONGLONG Override)
{
    return (UINT32)(Override & 0xFFFFFFFFull);
}

static UINT32 BkrtRuntimeOverrideMask(_In_ ULONGLONG Override)
{
    return (UINT32)((Override >> 32) & 0xFFFFFFFFull);
}

static ULONGLONG BkrtReadRuntimeOverride(VOID)
{
    return (ULONGLONG)InterlockedCompareExchange64(&g_RuntimeOverride, 0, 0);
}

static ULONG BkrtReadDwordValue(_In_ HANDLE KeyHandle, _In_z_ PCWSTR ValueName)
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

static ULONG BkrtLoadPersistentFlags(_In_ PUNICODE_STRING RegistryPath)
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

    if (BkrtReadDwordValue(keyHandle, L"EnableAntiVirtualization") != 0)
    {
        flags |= BK_RUNTIME_FLAG_ANTI_VIRTUALIZATION;
    }
    if (BkrtReadDwordValue(keyHandle, L"EnableSelfHide") != 0)
    {
        flags |= BK_RUNTIME_FLAG_SELF_HIDE;
    }
    if (BkrtReadDwordValue(keyHandle, L"EnableInterfaceProtectedAccess") != 0)
    {
        flags |= BK_RUNTIME_FLAG_INTERFACE_PROTECTED_ACCESS;
    }
    if (BkrtReadDwordValue(keyHandle, L"EnableControllerProtectedAccess") != 0)
    {
        flags |= BK_RUNTIME_FLAG_CONTROLLER_PROTECTED_ACCESS;
    }
    if (BkrtReadDwordValue(keyHandle, L"DisableNtApiHooks") != 0)
    {
        flags |= BK_RUNTIME_FLAG_NTAPI_HOOKS_DISARMED;
    }
    if (BkrtReadDwordValue(keyHandle, L"DisableQpcTimingCompensation") != 0)
    {
        flags |= BK_RUNTIME_FLAG_QPC_TIMING_DISABLED;
    }

    ZwClose(keyHandle);
    return flags;
}

NTSTATUS BkrtInitialize(_In_ PUNICODE_STRING RegistryPath)
{
    ULONG persistentFlags;

    persistentFlags = BkrtLoadPersistentFlags(RegistryPath);
    InterlockedExchange((volatile LONG *)&g_RuntimePersistentFlags, (LONG)persistentFlags);
    InterlockedExchange64(&g_RuntimeOverride, 0);
    InterlockedExchange(&g_RuntimeConfigInitialized, 1);
    return STATUS_SUCCESS;
}

VOID BkrtUninitialize(VOID)
{
    InterlockedExchange(&g_RuntimeConfigInitialized, 0);
    InterlockedExchange((volatile LONG *)&g_RuntimePersistentFlags, 0);
    InterlockedExchange64(&g_RuntimeOverride, 0);
}

UINT32 BkrtGetPersistentFlags(VOID)
{
    return (UINT32)InterlockedCompareExchange((volatile LONG *)&g_RuntimePersistentFlags, 0, 0);
}

UINT32 BkrtGetRuntimeFlags(VOID)
{
    return BkrtRuntimeOverrideFlags(BkrtReadRuntimeOverride());
}

UINT32 BkrtGetEffectiveFlags(VOID)
{
    ULONGLONG runtimeOverride = BkrtReadRuntimeOverride();
    UINT32 runtimeMask = BkrtRuntimeOverrideMask(runtimeOverride);
    UINT32 runtimeFlags = BkrtRuntimeOverrideFlags(runtimeOverride);
    UINT32 persistentFlags = BkrtGetPersistentFlags();

    return (persistentFlags & ~runtimeMask) | (runtimeFlags & runtimeMask);
}

BOOLEAN BkrtIsAntiVirtualizationEnabled(VOID)
{
    return ((BkrtGetEffectiveFlags() & BK_RUNTIME_FLAG_ANTI_VIRTUALIZATION) != 0);
}

BOOLEAN BkrtIsSelfHideEnabled(VOID)
{
    return ((BkrtGetEffectiveFlags() & BK_RUNTIME_FLAG_SELF_HIDE) != 0);
}

BOOLEAN BkrtIsInterfaceProtectedAccessEnabled(VOID)
{
    return ((BkrtGetEffectiveFlags() & BK_RUNTIME_FLAG_INTERFACE_PROTECTED_ACCESS) != 0);
}

BOOLEAN BkrtIsControllerProtectedAccessEnabled(VOID)
{
    return ((BkrtGetEffectiveFlags() & BK_RUNTIME_FLAG_CONTROLLER_PROTECTED_ACCESS) != 0);
}

BOOLEAN BkrtIsNtApiHooksDisarmed(VOID)
{
    return ((BkrtGetEffectiveFlags() & BK_RUNTIME_FLAG_NTAPI_HOOKS_DISARMED) != 0);
}

BOOLEAN BkrtIsQpcTimingCompensationEnabled(VOID)
{
    UINT32 flags = BkrtGetEffectiveFlags();

    return (((flags & BK_RUNTIME_FLAG_ANTI_VIRTUALIZATION) != 0) &&
            ((flags & BK_RUNTIME_FLAG_NTAPI_HOOKS_DISARMED) == 0) &&
            ((flags & BK_RUNTIME_FLAG_QPC_TIMING_DISABLED) == 0));
}

UINT32 BkrtGetCurrentMode(VOID)
{
    return BkctlIsArmedFast() ? BK_RUNTIME_MODE_GUIDED : BK_RUNTIME_MODE_LOITER;
}

NTSTATUS BkrtSetRuntimeFlags(_In_ UINT32 Flags, _In_ UINT32 Mask)
{
    ULONGLONG currentOverride;
    ULONGLONG nextOverride;
    UINT32 currentFlags;
    UINT32 currentMask;
    UINT32 nextFlags;
    UINT32 nextMask;

    if (InterlockedCompareExchange(&g_RuntimeConfigInitialized, 0, 0) == 0)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    Mask &= BK_RUNTIME_MUTABLE_MASK;
    Flags &= BK_RUNTIME_MUTABLE_MASK;

    for (;;)
    {
        currentOverride = BkrtReadRuntimeOverride();
        currentFlags = BkrtRuntimeOverrideFlags(currentOverride);
        currentMask = BkrtRuntimeOverrideMask(currentOverride);
        nextMask = currentMask | Mask;
        nextFlags = ((currentFlags & ~Mask) | (Flags & Mask)) & nextMask;
        nextOverride = BkrtPackRuntimeOverride(nextFlags, nextMask);

        if ((ULONGLONG)InterlockedCompareExchange64(&g_RuntimeOverride, (LONG64)nextOverride,
                                                    (LONG64)currentOverride) == currentOverride)
        {
            return STATUS_SUCCESS;
        }
    }
}

VOID BkrtFillResponse(_Out_ PBK_RUNTIME_CONFIG_RESPONSE Response)
{
    if (Response == NULL)
    {
        return;
    }

    RtlZeroMemory(Response, sizeof(*Response));
    Response->PersistentFlags = BkrtGetPersistentFlags();
    Response->RuntimeFlags = BkrtGetRuntimeFlags();
    Response->EffectiveFlags = BkrtGetEffectiveFlags();
    Response->Mode = BkrtGetCurrentMode();
}
