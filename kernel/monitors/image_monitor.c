#include <ntddk.h>
#include "..\telemetry\etw.h"
#include "image_monitor.h"

#define STINGER_NTDLL_TRACK_SLOTS 512

static volatile LONG g_ImageMonitorRegistered = 0;
static volatile LONG g_ImageMonitorFailureCounter = 0;
static KSPIN_LOCK g_NtdllTrackLock;

typedef struct _STINGER_NTDLL_TRACK_ENTRY {
    UINT64 ProcessId;
    ULONG LoadCount;
} STINGER_NTDLL_TRACK_ENTRY, *PSTINGER_NTDLL_TRACK_ENTRY;

static STINGER_NTDLL_TRACK_ENTRY g_NtdllTrack[STINGER_NTDLL_TRACK_SLOTS];

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
ULONG
STINGERTrackNtdllLoad(
    _In_ HANDLE ProcessId
)
{
    ULONG index;
    ULONG count;
    KIRQL oldIrql;

    index = ((ULONG)((ULONG_PTR)ProcessId >> 2)) % STINGER_NTDLL_TRACK_SLOTS;

    KeAcquireSpinLock(&g_NtdllTrackLock, &oldIrql);
    if (g_NtdllTrack[index].ProcessId != (UINT64)(ULONG_PTR)ProcessId) {
        g_NtdllTrack[index].ProcessId = (UINT64)(ULONG_PTR)ProcessId;
        g_NtdllTrack[index].LoadCount = 0;
    }
    g_NtdllTrack[index].LoadCount += 1;
    count = g_NtdllTrack[index].LoadCount;
    KeReleaseSpinLock(&g_NtdllTrackLock, oldIrql);

    return count;
}

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
    UNICODE_STRING imagePathUs;
    BOOLEAN isNtdllPath = FALSE;
    BOOLEAN isKnownGoodNtdllPath = FALSE;
    ULONG ntdllLoadCount = 0;

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

    if (path[0] == L'\0' || ImageInfo->SystemModeImage) {
        return;
    }

    RtlInitUnicodeString(&imagePathUs, path);
    isNtdllPath = STINGERUnicodeContainsInsensitive(&imagePathUs, L"ntdll.dll", 9);
    if (!isNtdllPath) {
        return;
    }

    isKnownGoodNtdllPath =
        STINGERUnicodeContainsInsensitive(&imagePathUs, L"\\system32\\ntdll.dll", 20) ||
        STINGERUnicodeContainsInsensitive(&imagePathUs, L"\\knowndlls\\ntdll.dll", 20);

    ntdllLoadCount = STINGERTrackNtdllLoad(ProcessId);

    if (!isKnownGoodNtdllPath) {
        STINGEREtwLogDetectionEvent(
            "SUSPICIOUS_NTDLL_IMAGE_PATH",
            4,
            ProcessId,
            ProcessId,
            0,
            0,
            0,
            path
        );
    }

    if (ntdllLoadCount > 1) {
        STINGEREtwLogDetectionEvent(
            "MULTIPLE_NTDLL_IMAGE_MAPPINGS",
            3,
            ProcessId,
            ProcessId,
            0,
            0,
            0,
            L"multiple ntdll image-load events observed for process"
        );
    }
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

    KeInitializeSpinLock(&g_NtdllTrackLock);
    RtlZeroMemory(g_NtdllTrack, sizeof(g_NtdllTrack));

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

    RtlZeroMemory(g_NtdllTrack, sizeof(g_NtdllTrack));
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "STINGER: image monitor uninitialized.\n");
}
