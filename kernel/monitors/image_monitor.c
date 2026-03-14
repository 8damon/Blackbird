#include <ntddk.h>
#include "..\telemetry\etw.h"
#include "..\core\unicode_utils.h"
#include "image_monitor.h"

#define BLACKBIRD_NTDLL_TRACK_SLOTS 512

static volatile LONG g_ImageMonitorRegistered = 0;
static volatile LONG g_ImageMonitorFailureCounter = 0;
static KSPIN_LOCK g_NtdllTrackLock;
typedef NTSTATUS(NTAPI *PBLACKBIRD_PS_SET_LOAD_IMAGE_NOTIFY_ROUTINE_EX)(_In_ PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine,
                                                                        _In_ ULONG Flags);
static PBLACKBIRD_PS_SET_LOAD_IMAGE_NOTIFY_ROUTINE_EX g_SetLoadImageNotifyRoutineEx = NULL;

typedef struct _BLACKBIRD_NTDLL_TRACK_ENTRY
{
    UINT64 ProcessId;
    ULONG LoadCount;
} BLACKBIRD_NTDLL_TRACK_ENTRY, *PBLACKBIRD_NTDLL_TRACK_ENTRY;

static BLACKBIRD_NTDLL_TRACK_ENTRY g_NtdllTrack[BLACKBIRD_NTDLL_TRACK_SLOTS];

static PBLACKBIRD_PS_SET_LOAD_IMAGE_NOTIFY_ROUTINE_EX BLACKBIRDResolvePsSetLoadImageNotifyRoutineEx(VOID)
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsSetLoadImageNotifyRoutineEx");
    return (PBLACKBIRD_PS_SET_LOAD_IMAGE_NOTIFY_ROUTINE_EX) MmGetSystemRoutineAddress(&routineName);
}

static ULONG BLACKBIRDTrackNtdllLoad(_In_ HANDLE ProcessId)
{
    ULONG index;
    ULONG count;
    KIRQL oldIrql;

    index = ((ULONG) ((ULONG_PTR) ProcessId >> 2)) % BLACKBIRD_NTDLL_TRACK_SLOTS;

    KeAcquireSpinLock(&g_NtdllTrackLock, &oldIrql);
    if (g_NtdllTrack[index].ProcessId != (UINT64) (ULONG_PTR) ProcessId)
    {
        g_NtdllTrack[index].ProcessId = (UINT64) (ULONG_PTR) ProcessId;
        g_NtdllTrack[index].LoadCount = 0;
    }
    g_NtdllTrack[index].LoadCount += 1;
    count = g_NtdllTrack[index].LoadCount;
    KeReleaseSpinLock(&g_NtdllTrackLock, oldIrql);

    return count;
}

static VOID BLACKBIRDImageLoadNotifyRoutine(_In_opt_ PUNICODE_STRING FullImageName,
                                            _In_ HANDLE ProcessId,
                                            _In_ PIMAGE_INFO ImageInfo)
{
    WCHAR path[512];
    BOOLEAN isSignatureKnown = FALSE;
    UCHAR signatureLevel = 0;
    UCHAR signatureType = 0;
    UNICODE_STRING imagePathUs;
    BOOLEAN isNtdllPath = FALSE;
    BOOLEAN isKnownGoodNtdllPath = FALSE;
    ULONG ntdllLoadCount = 0;

    if (ImageInfo == NULL)
    {
        return;
    }

    path[0] = L'\0';
    BLACKBIRDSafeCopyUnicode(FullImageName, path, RTL_NUMBER_OF(path));

#if (NTDDI_VERSION >= NTDDI_WIN8)
    isSignatureKnown = TRUE;
    signatureLevel = (UCHAR) ImageInfo->ImageSignatureLevel;
    signatureType = (UCHAR) ImageInfo->ImageSignatureType;
#endif

    BLACKBIRDEtwLogImageLoadEvent(ProcessId,
                                  ImageInfo->ImageBase,
                                  ImageInfo->ImageSize,
                                  ImageInfo->SystemModeImage ? TRUE : FALSE,
                                  isSignatureKnown,
                                  signatureLevel,
                                  signatureType,
                                  (path[0] != L'\0') ? path : NULL);

    if (path[0] == L'\0' || ImageInfo->SystemModeImage)
    {
        return;
    }

    RtlInitUnicodeString(&imagePathUs, path);
    isNtdllPath = BLACKBIRDUnicodeContainsInsensitive(&imagePathUs, L"ntdll.dll", 9);
    if (!isNtdllPath)
    {
        return;
    }

    isKnownGoodNtdllPath = BLACKBIRDUnicodeContainsInsensitive(&imagePathUs, L"\\system32\\ntdll.dll", 20)
            || BLACKBIRDUnicodeContainsInsensitive(&imagePathUs, L"\\knowndlls\\ntdll.dll", 20);

    ntdllLoadCount = BLACKBIRDTrackNtdllLoad(ProcessId);

    if (!isKnownGoodNtdllPath)
    {
        BLACKBIRDEtwLogDetectionEvent("SUSPICIOUS_NTDLL_IMAGE_PATH", 4, ProcessId, ProcessId, 0, 0, 0, path);
    }

    if (ntdllLoadCount > 1)
    {
        BLACKBIRDEtwLogDetectionEvent("MULTIPLE_NTDLL_IMAGE_MAPPINGS",
                                      3,
                                      ProcessId,
                                      ProcessId,
                                      0,
                                      0,
                                      0,
                                      L"multiple ntdll image-load events observed for process");
    }
}

NTSTATUS
BLACKBIRDImageMonitorInitialize(VOID)
{
    NTSTATUS status;
    LONG failures;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (InterlockedCompareExchange(&g_ImageMonitorRegistered, 0, 0) != 0)
    {
        return STATUS_SUCCESS;
    }

    KeInitializeSpinLock(&g_NtdllTrackLock);
    RtlZeroMemory(g_NtdllTrack, sizeof(g_NtdllTrack));

    g_SetLoadImageNotifyRoutineEx = BLACKBIRDResolvePsSetLoadImageNotifyRoutineEx();
    if (g_SetLoadImageNotifyRoutineEx == NULL)
    {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = g_SetLoadImageNotifyRoutineEx(BLACKBIRDImageLoadNotifyRoutine, 0);
    if (!NT_SUCCESS(status))
    {
        failures = InterlockedIncrement(&g_ImageMonitorFailureCounter);
        if (failures == 1 || ((failures & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_ERROR_LEVEL,
                       "BLACKBIRD: image monitor callback registration failed status=0x%08X total=%lu.\n",
                       status,
                       (ULONG) failures);
        }
        g_SetLoadImageNotifyRoutineEx = NULL;
        return status;
    }

    InterlockedExchange(&g_ImageMonitorRegistered, 1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BLACKBIRD: image monitor initialized.\n");
    return STATUS_SUCCESS;
}

VOID BLACKBIRDImageMonitorUninitialize(VOID)
{
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }
    if (InterlockedCompareExchange(&g_ImageMonitorRegistered, 0, 0) == 0)
    {
        return;
    }

    status = PsRemoveLoadImageNotifyRoutine(BLACKBIRDImageLoadNotifyRoutine);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "BLACKBIRD: image monitor callback removal failed; monitor remains registered (status=0x%08X).\n",
                   status);
        return;
    }

    InterlockedExchange(&g_ImageMonitorRegistered, 0);
    g_SetLoadImageNotifyRoutineEx = NULL;
    RtlZeroMemory(g_NtdllTrack, sizeof(g_NtdllTrack));
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BLACKBIRD: image monitor uninitialized.\n");
}

BOOLEAN
BLACKBIRDImageMonitorSelfCheck(VOID)
{
    return (InterlockedCompareExchange(&g_ImageMonitorRegistered, 0, 0) != 0);
}
