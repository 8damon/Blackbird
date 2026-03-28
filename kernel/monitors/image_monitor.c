#include <ntddk.h>
#include "..\telemetry\etw.h"
#include "..\core\unicode_utils.h"
#include "image_monitor.h"

#define BLACKBIRD_NTDLL_TRACK_SLOTS 512

static VOID BLACKBIRDImageLoadNotifyRoutineHeuristics(_In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo,
                                                      _In_z_ PCWSTR Path, _In_ BOOLEAN IsSignatureLevelKnown,
                                                      _In_ UCHAR SignatureLevel, _In_ UCHAR SignatureType);

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
    return (PBLACKBIRD_PS_SET_LOAD_IMAGE_NOTIFY_ROUTINE_EX)MmGetSystemRoutineAddress(&routineName);
}

static ULONG BLACKBIRDTrackNtdllLoad(_In_ HANDLE ProcessId)
{
    ULONG index;
    ULONG count;
    KIRQL oldIrql;

    index = ((ULONG)((ULONG_PTR)ProcessId >> 2)) % BLACKBIRD_NTDLL_TRACK_SLOTS;

    KeAcquireSpinLock(&g_NtdllTrackLock, &oldIrql);
    if (g_NtdllTrack[index].ProcessId != (UINT64)(ULONG_PTR)ProcessId)
    {
        g_NtdllTrack[index].ProcessId = (UINT64)(ULONG_PTR)ProcessId;
        g_NtdllTrack[index].LoadCount = 0;
    }
    g_NtdllTrack[index].LoadCount += 1;
    count = g_NtdllTrack[index].LoadCount;
    KeReleaseSpinLock(&g_NtdllTrackLock, oldIrql);

    return count;
}

static VOID BLACKBIRDImageLoadNotifyRoutine(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId,
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
    signatureLevel = (UCHAR)ImageInfo->ImageSignatureLevel;
    signatureType = (UCHAR)ImageInfo->ImageSignatureType;
#endif

    BLACKBIRDEtwLogImageLoadEvent(ProcessId, ImageInfo->ImageBase, ImageInfo->ImageSize,
                                  ImageInfo->SystemModeImage ? TRUE : FALSE, isSignatureKnown, signatureLevel,
                                  signatureType, (path[0] != L'\0') ? path : NULL);

    if (path[0] == L'\0' || ImageInfo->SystemModeImage)
    {
        return;
    }

    /* Broad heuristic checks for all non-system image loads */
    BLACKBIRDImageLoadNotifyRoutineHeuristics(ProcessId, ImageInfo, path, isSignatureKnown, signatureLevel,
                                              signatureType);

    RtlInitUnicodeString(&imagePathUs, path);
    isNtdllPath = BLACKBIRDUnicodeContainsInsensitive(&imagePathUs, L"ntdll.dll", 9);
    if (!isNtdllPath)
    {
        return;
    }

    isKnownGoodNtdllPath = BLACKBIRDUnicodeContainsInsensitive(&imagePathUs, L"\\system32\\ntdll.dll", 20) ||
                           BLACKBIRDUnicodeContainsInsensitive(&imagePathUs, L"\\knowndlls\\ntdll.dll", 20);

    ntdllLoadCount = BLACKBIRDTrackNtdllLoad(ProcessId);

    if (!isKnownGoodNtdllPath)
    {
        BLACKBIRDEtwLogDetectionEvent("SUSPICIOUS_NTDLL_IMAGE_PATH", 4, ProcessId, ProcessId, 0, 0, 0, path);
    }

    if (ntdllLoadCount > 1)
    {
        BLACKBIRDEtwLogDetectionEvent("MULTIPLE_NTDLL_IMAGE_MAPPINGS", 3, ProcessId, ProcessId, 0, 0, 0,
                                      L"multiple ntdll image-load events observed for process");
    }
}

/* Returns TRUE if the character sequence at [Ptr..Ptr+Len-1] (case-insensitive) is
 * present anywhere in the wide string Path.  Simple O(n*m) scan — image paths are
 * short and this runs on a notify callback, not a hot syscall path. */
static BOOLEAN BLACKBIRDImagePathContains(_In_z_ PCWSTR Path, _In_z_ PCWSTR Needle, _In_ USHORT NeedleLen)
{
    UNICODE_STRING pathUs;
    UNICODE_STRING needleUs;
    RtlInitUnicodeString(&pathUs, Path);
    needleUs.Buffer        = (PWSTR)Needle;
    needleUs.Length        = (USHORT)(NeedleLen * sizeof(WCHAR));
    needleUs.MaximumLength = needleUs.Length;
    return BLACKBIRDUnicodeContainsInsensitive(&pathUs, Needle, NeedleLen);
}

/* Check the image filename (basename, derived from the last backslash in Path) for
 * a double-extension pattern — e.g. "invoice.pdf.exe", "readme.doc.exe". */
static BOOLEAN BLACKBIRDImageHasDoubleExtension(_In_z_ PCWSTR Path)
{
    static const PCWSTR kInnerExts[] = {
        L".pdf", L".doc", L".docx", L".xls", L".xlsx", L".txt",
        L".jpg", L".jpeg", L".png", L".zip", L".rar", L".mp3", L".mp4"
    };
    static const ULONG kInnerCount = 13;
    ULONG  i;
    PCWSTR base = Path;
    PCWSTR p    = Path;
    PCWSTR dotPos;

    /* Find the last backslash to isolate the filename */
    while (*p != L'\0')
    {
        if (*p == L'\\' || *p == L'/')
        {
            base = p + 1;
        }
        ++p;
    }

    /* Look for ".exe", ".dll", ".scr", ".com" as the final extension */
    p = base;
    dotPos = NULL;
    while (*p != L'\0')
    {
        if (*p == L'.')
        {
            dotPos = p;
        }
        ++p;
    }
    if (dotPos == NULL)
    {
        return FALSE;
    }
    if (_wcsicmp(dotPos, L".exe") != 0 && _wcsicmp(dotPos, L".dll") != 0 &&
        _wcsicmp(dotPos, L".scr") != 0 && _wcsicmp(dotPos, L".com") != 0)
    {
        return FALSE;
    }

    /* Now scan the filename before the final extension for a known document extension */
    for (i = 0; i < kInnerCount; ++i)
    {
        SIZE_T needleLen = wcslen(kInnerExts[i]);
        PCWSTR scan     = base;
        while (scan < dotPos)
        {
            SIZE_T remaining = (SIZE_T)(dotPos - scan);
            if (remaining >= needleLen &&
                _wcsnicmp(scan, kInnerExts[i], needleLen) == 0 &&
                scan + needleLen == dotPos)
            {
                return TRUE;
            }
            ++scan;
        }
    }

    return FALSE;
}

static VOID BLACKBIRDImageLoadNotifyRoutineHeuristics(_In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo,
                                                      _In_z_ PCWSTR Path, _In_ BOOLEAN IsSignatureLevelKnown,
                                                      _In_ UCHAR SignatureLevel, _In_ UCHAR SignatureType)
{
    BOOLEAN isSystemPath;
    BOOLEAN isUserWritable;
    BOOLEAN doubleExt;
    BOOLEAN unsigned_;

    UNREFERENCED_PARAMETER(SignatureType);

    if (Path[0] == L'\0' || ImageInfo->SystemModeImage)
    {
        return;
    }

    /* Classify path as system or user-writable */
    isSystemPath = BLACKBIRDImagePathContains(Path, L"\\Windows\\System32\\", 18) ||
                   BLACKBIRDImagePathContains(Path, L"\\Windows\\SysWOW64\\", 18) ||
                   BLACKBIRDImagePathContains(Path, L"\\Windows\\WinSxS\\", 16)    ||
                   BLACKBIRDImagePathContains(Path, L"\\KnownDlls\\", 11);

    isUserWritable = BLACKBIRDImagePathContains(Path, L"\\Temp\\",          6)  ||
                     BLACKBIRDImagePathContains(Path, L"\\AppData\\",        9)  ||
                     BLACKBIRDImagePathContains(Path, L"\\Downloads\\",     11)  ||
                     BLACKBIRDImagePathContains(Path, L"\\Desktop\\",        9)  ||
                     BLACKBIRDImagePathContains(Path, L"\\Public\\",         8)  ||
                     BLACKBIRDImagePathContains(Path, L"\\$Recycle.Bin\\",  14)  ||
                     BLACKBIRDImagePathContains(Path, L"\\ProgramData\\Temp\\", 19);

    doubleExt = BLACKBIRDImageHasDoubleExtension(Path);
    unsigned_ = IsSignatureLevelKnown && (SignatureLevel == 0);

    /* Double-extension executable — highest priority, always emit */
    if (doubleExt)
    {
        BLACKBIRDEtwLogDetectionEvent("IMAGE_LOAD_DOUBLE_EXTENSION", 5, ProcessId, ProcessId, 0, 0, 0, Path);
    }

    /* Image from a user-writable path */
    if (isUserWritable)
    {
        ULONG sev = (unsigned_) ? 5u : 4u;
        BLACKBIRDEtwLogDetectionEvent("IMAGE_LOAD_FROM_USER_WRITABLE_PATH", sev, ProcessId, ProcessId, 0, 0, 0, Path);
    }

    /* Unsigned non-system image */
    if (unsigned_ && !isSystemPath && !isUserWritable)
    {
        BLACKBIRDEtwLogDetectionEvent("IMAGE_LOAD_UNSIGNED_NON_SYSTEM", 3, ProcessId, ProcessId, 0, 0, 0, Path);
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
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "BLACKBIRD: image monitor callback registration failed status=0x%08X total=%lu.\n", status,
                       (ULONG)failures);
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
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
