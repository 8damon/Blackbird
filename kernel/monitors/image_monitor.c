#include <ntddk.h>
#include "..\telemetry\etw.h"
#include "image_monitor.h"

static volatile LONG g_ImageMonitorRegistered = 0;
static volatile LONG g_ImageMonitorFailureCounter = 0;

static
VOID
STINGERImageLoadNotifyRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
)
{
    WCHAR path[512];
    SIZE_T copyChars;
    BOOLEAN isSignatureKnown = FALSE;
    UCHAR signatureLevel = 0;
    UCHAR signatureType = 0;

    if (ImageInfo == NULL) {
        return;
    }

    path[0] = L'\0';
    if (FullImageName != NULL && FullImageName->Buffer != NULL && FullImageName->Length > 0) {
        copyChars = FullImageName->Length / sizeof(WCHAR);
        if (copyChars >= RTL_NUMBER_OF(path)) {
            copyChars = RTL_NUMBER_OF(path) - 1;
        }
        if (copyChars > 0) {
            RtlCopyMemory(path, FullImageName->Buffer, copyChars * sizeof(WCHAR));
            path[copyChars] = L'\0';
        }
    }

#if (NTDDI_VERSION >= NTDDI_WIN8)
    isSignatureKnown = TRUE;
    signatureLevel = (UCHAR)ImageInfo->ImageSignatureLevel;
    signatureType = (UCHAR)ImageInfo->ImageSignatureType;
#endif

    STINGEREtwLogImageLoadEvent(
        ProcessId,
        ImageInfo->ImageBase,
        ImageInfo->ImageSize,
        ImageInfo->SystemModeImage ? TRUE : FALSE,
        isSignatureKnown,
        signatureLevel,
        signatureType,
        (path[0] != L'\0') ? path : NULL
    );
}

NTSTATUS
STINGERImageMonitorInitialize(
    VOID
)
{
    NTSTATUS status;
    LONG failures;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (InterlockedCompareExchange(&g_ImageMonitorRegistered, 0, 0) != 0) {
        return STATUS_SUCCESS;
    }

    status = PsSetLoadImageNotifyRoutine(STINGERImageLoadNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        failures = InterlockedIncrement(&g_ImageMonitorFailureCounter);
        if (failures == 1 || ((failures & 0xFF) == 0)) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_ERROR_LEVEL,
                "STINGER: image monitor callback registration failed status=0x%08X total=%lu.\n",
                status,
                (ULONG)failures
            );
        }
        return status;
    }

    InterlockedExchange(&g_ImageMonitorRegistered, 1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "STINGER: image monitor initialized.\n");
    return STATUS_SUCCESS;
}

VOID
STINGERImageMonitorUninitialize(
    VOID
)
{
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }
    if (InterlockedExchange(&g_ImageMonitorRegistered, 0) == 0) {
        return;
    }

    status = PsRemoveLoadImageNotifyRoutine(STINGERImageLoadNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "STINGER: image monitor callback removal failed status=0x%08X.\n",
            status
        );
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "STINGER: image monitor uninitialized.\n");
}
