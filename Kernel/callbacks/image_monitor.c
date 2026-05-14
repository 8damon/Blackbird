#include <ntddk.h>
#include "..\telemetry\etw.h"
#include "..\core\tempus_debug.h"
#include "..\core\unicode_utils.h"
#include "..\core\control.h"
#include "..\hooks\monitor\ntapi_monitor.h"
#include "image_monitor.h"

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS *Process);
NTSYSAPI NTSTATUS NTAPI SeLocateProcessImageName(_In_ PEPROCESS Process, _Out_ PUNICODE_STRING *pImageFileName);

#define BK_NTDLL_TRACK_SLOTS 512

static VOID BkcimgImageLoadNotifyRoutineHeuristics(_In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo,
                                                   _In_z_ PCWSTR Path, _In_ BOOLEAN IsSignatureLevelKnown,
                                                   _In_ UCHAR SignatureLevel, _In_ UCHAR SignatureType);

static volatile LONG g_ImageMonitorRegistered = 0;
static volatile LONG g_ImageMonitorFailureCounter = 0;
static KSPIN_LOCK g_NtdllTrackLock;
typedef NTSTATUS(NTAPI *PBK_PS_SET_LOAD_IMAGE_NOTIFY_ROUTINE_EX)(_In_ PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine,
                                                                 _In_ ULONG Flags);
static PBK_PS_SET_LOAD_IMAGE_NOTIFY_ROUTINE_EX g_SetLoadImageNotifyRoutineEx = NULL;

typedef struct _BK_NTDLL_TRACK_ENTRY
{
    UINT64 ProcessId;
    UINT64 PrimaryBase;
    UINT64 PrimarySize;
    ULONG LoadCount;
} BK_NTDLL_TRACK_ENTRY, *PBK_NTDLL_TRACK_ENTRY;

static BK_NTDLL_TRACK_ENTRY g_NtdllTrack[BK_NTDLL_TRACK_SLOTS];

static PBK_PS_SET_LOAD_IMAGE_NOTIFY_ROUTINE_EX BkcimgResolvePsSetLoadImageNotifyRoutineEx(VOID)
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsSetLoadImageNotifyRoutineEx");
    return (PBK_PS_SET_LOAD_IMAGE_NOTIFY_ROUTINE_EX)MmGetSystemRoutineAddress(&routineName);
}

static ULONG BkcimgTrackNtdllLoad(_In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo, _Out_ UINT64 *PrimaryBase,
                                  _Out_ UINT64 *PrimarySize)
{
    ULONG index;
    ULONG count;
    KIRQL oldIrql;

    if (PrimaryBase != NULL)
    {
        *PrimaryBase = 0;
    }
    if (PrimarySize != NULL)
    {
        *PrimarySize = 0;
    }

    index = ((ULONG)((ULONG_PTR)ProcessId >> 2)) % BK_NTDLL_TRACK_SLOTS;

    KeAcquireSpinLock(&g_NtdllTrackLock, &oldIrql);
    if (g_NtdllTrack[index].ProcessId != (UINT64)(ULONG_PTR)ProcessId)
    {
        g_NtdllTrack[index].ProcessId = (UINT64)(ULONG_PTR)ProcessId;
        g_NtdllTrack[index].PrimaryBase = (UINT64)(ULONG_PTR)ImageInfo->ImageBase;
        g_NtdllTrack[index].PrimarySize = (UINT64)ImageInfo->ImageSize;
        g_NtdllTrack[index].LoadCount = 0;
    }
    g_NtdllTrack[index].LoadCount += 1;
    count = g_NtdllTrack[index].LoadCount;
    if (PrimaryBase != NULL)
    {
        *PrimaryBase = g_NtdllTrack[index].PrimaryBase;
    }
    if (PrimarySize != NULL)
    {
        *PrimarySize = g_NtdllTrack[index].PrimarySize;
    }
    KeReleaseSpinLock(&g_NtdllTrackLock, oldIrql);

    return count;
}

BOOLEAN
BkcimgQueryPrimaryNtdll(_In_ HANDLE ProcessId, _Out_ UINT64 *PrimaryBase, _Out_opt_ UINT64 *PrimarySize)
{
    ULONG index;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    if (PrimaryBase == NULL)
    {
        return FALSE;
    }

    *PrimaryBase = 0;
    if (PrimarySize != NULL)
    {
        *PrimarySize = 0;
    }

    index = ((ULONG)((ULONG_PTR)ProcessId >> 2)) % BK_NTDLL_TRACK_SLOTS;
    KeAcquireSpinLock(&g_NtdllTrackLock, &oldIrql);
    if (g_NtdllTrack[index].ProcessId == (UINT64)(ULONG_PTR)ProcessId && g_NtdllTrack[index].PrimaryBase != 0 &&
        g_NtdllTrack[index].PrimarySize != 0)
    {
        *PrimaryBase = g_NtdllTrack[index].PrimaryBase;
        if (PrimarySize != NULL)
        {
            *PrimarySize = g_NtdllTrack[index].PrimarySize;
        }
        found = TRUE;
    }
    KeReleaseSpinLock(&g_NtdllTrackLock, oldIrql);

    return found;
}

static BOOLEAN BkcimgImagePathContains(_In_z_ PCWSTR Path, _In_z_ PCWSTR Needle, _In_ USHORT NeedleLen);

static VOID BkcimgImageLoadNotifyRoutine(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId,
                                         _In_ PIMAGE_INFO ImageInfo)
{
    ULONGLONG tempusStartQpc = BktmpEnter(BktmpSubsystemImageMonitor);
    WCHAR path[512];
    BOOLEAN isSignatureKnown = FALSE;
    UCHAR signatureLevel = 0;
    UCHAR signatureType = 0;
    UNICODE_STRING imagePathUs;
    BOOLEAN isNtdllPath = FALSE;
    BOOLEAN isKnownGoodNtdllPath = FALSE;
    ULONG ntdllLoadCount = 0;
    UINT64 primaryNtdllBase = 0;
    UINT64 primaryNtdllSize = 0;

    if (ImageInfo == NULL)
    {
        BktmpLeave(BktmpSubsystemImageMonitor, tempusStartQpc);
        return;
    }

    path[0] = L'\0';
    BkstrSafeCopyUnicode(FullImageName, path, RTL_NUMBER_OF(path));

#if (NTDDI_VERSION >= NTDDI_WIN8)
    isSignatureKnown = TRUE;
    signatureLevel = (UCHAR)ImageInfo->ImageSignatureLevel;
    signatureType = (UCHAR)ImageInfo->ImageSignatureType;
#endif

    BketwLogImageLoadEvent(ProcessId, ImageInfo->ImageBase, ImageInfo->ImageSize,
                           ImageInfo->SystemModeImage ? TRUE : FALSE, isSignatureKnown, signatureLevel, signatureType,
                           (path[0] != L'\0') ? path : NULL);

    if (path[0] == L'\0' || ImageInfo->SystemModeImage)
    {
        BktmpLeave(BktmpSubsystemImageMonitor, tempusStartQpc);
        return;
    }

    /* Broad heuristic checks for all non-system image loads */
    BkcimgImageLoadNotifyRoutineHeuristics(ProcessId, ImageInfo, path, isSignatureKnown, signatureLevel, signatureType);

    RtlInitUnicodeString(&imagePathUs, path);
    if (ProcessId != NULL &&
        BkctlMarkAnalysisSubjectImageLoad((UINT32)(ULONG_PTR)ProcessId, &imagePathUs,
                                          (UINT64)(ULONG_PTR)ImageInfo->ImageBase, (UINT64)ImageInfo->ImageSize))
    {
        BketwLogDetectionEvent("ANALYSIS_SUBJECT_DLL_LOADED", 2, ProcessId, ProcessId, 0, 0, 0, path);
    }

    /* Unsigned or non-system DLL loaded into a credential-handling process (lsass, winlogon) */
    if (ProcessId != NULL)
    {
        NTSTATUS sensStatus;
        PEPROCESS sensProc = NULL;
        sensStatus = PsLookupProcessByProcessId(ProcessId, &sensProc);
        if (NT_SUCCESS(sensStatus) && sensProc != NULL)
        {
            PUNICODE_STRING sensName = NULL;
            sensStatus = SeLocateProcessImageName(sensProc, &sensName);
            if (NT_SUCCESS(sensStatus) && sensName != NULL && sensName->Buffer != NULL && sensName->Length != 0)
            {
                if (BkstrUnicodeContainsInsensitive(sensName, L"lsass.exe", 9) ||
                    BkstrUnicodeContainsInsensitive(sensName, L"winlogon.exe", 12))
                {
                    BOOLEAN isSensSystemPath = BkcimgImagePathContains(path, L"\\Windows\\System32\\", 18) ||
                                               BkcimgImagePathContains(path, L"\\Windows\\SysWOW64\\", 18) ||
                                               BkcimgImagePathContains(path, L"\\Windows\\WinSxS\\", 16);
                    if (!isSensSystemPath || (isSignatureKnown && signatureLevel == 0))
                    {
                        BketwLogDetectionEvent("SUSPICIOUS_DLL_LOAD_SENSITIVE_PROCESS", 7, ProcessId, ProcessId, 0, 0,
                                               0, path);
                    }
                }
            }
            if (sensName != NULL)
                ExFreePool(sensName);
            ObDereferenceObject(sensProc);
        }
    }

    isNtdllPath = BkstrUnicodeContainsInsensitive(&imagePathUs, L"ntdll.dll", 9);
    if (!isNtdllPath)
    {
        BktmpLeave(BktmpSubsystemImageMonitor, tempusStartQpc);
        return;
    }

    isKnownGoodNtdllPath = BkstrUnicodeContainsInsensitive(&imagePathUs, L"\\system32\\ntdll.dll", 20) ||
                           BkstrUnicodeContainsInsensitive(&imagePathUs, L"\\knowndlls\\ntdll.dll", 20);

    ntdllLoadCount = BkcimgTrackNtdllLoad(ProcessId, ImageInfo, &primaryNtdllBase, &primaryNtdllSize);

    if (!isKnownGoodNtdllPath)
    {
        BketwLogDetectionEvent("SUSPICIOUS_NTDLL_IMAGE_PATH", 4, ProcessId, ProcessId, 0, 0, 0, path);
    }

    if (ntdllLoadCount > 1)
    {
        NTSTATUS mirrorStatus =
            BkntkiMirrorHookPatchesIntoImage((UINT32)(ULONG_PTR)ProcessId, primaryNtdllBase,
                                             (UINT64)(ULONG_PTR)ImageInfo->ImageBase, (UINT64)ImageInfo->ImageSize);
        BketwLogDetectionEvent("MULTIPLE_NTDLL_IMAGE_MAPPINGS", 3, ProcessId, ProcessId, 0, 0, 0,
                               L"multiple ntdll image-load events observed for process");
        if (!NT_SUCCESS(mirrorStatus))
        {
            BketwLogDetectionEvent("NTDLL_MIRROR_PATCH_FAILED", 5, ProcessId, ProcessId, 0, (UINT32)mirrorStatus, 0,
                                   L"failed to mirror BK hook patch bytes into duplicate ntdll mapping");
        }
    }
    BktmpLeave(BktmpSubsystemImageMonitor, tempusStartQpc);
}

/* Returns TRUE if the character sequence at [Ptr..Ptr+Len-1] (case-insensitive) is
 * present anywhere in the wide string Path.  Simple O(n*m) scan — image paths are
 * short and this runs on a notify callback, not a hot syscall path. */
static BOOLEAN BkcimgImagePathContains(_In_z_ PCWSTR Path, _In_z_ PCWSTR Needle, _In_ USHORT NeedleLen)
{
    UNICODE_STRING pathUs;
    UNICODE_STRING needleUs;
    RtlInitUnicodeString(&pathUs, Path);
    needleUs.Buffer = (PWSTR)Needle;
    needleUs.Length = (USHORT)(NeedleLen * sizeof(WCHAR));
    needleUs.MaximumLength = needleUs.Length;
    return BkstrUnicodeContainsInsensitive(&pathUs, Needle, NeedleLen);
}

/* Check the image filename (basename, derived from the last backslash in Path) for
 * a double-extension pattern — e.g. "invoice.pdf.exe", "readme.doc.exe". */
static BOOLEAN BkcimgImageHasDoubleExtension(_In_z_ PCWSTR Path)
{
    static const PCWSTR kInnerExts[] = {L".pdf",  L".doc", L".docx", L".xls", L".xlsx", L".txt", L".jpg",
                                        L".jpeg", L".png", L".zip",  L".rar", L".mp3",  L".mp4"};
    static const ULONG kInnerCount = 13;
    ULONG i;
    PCWSTR base = Path;
    PCWSTR p = Path;
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
    if (_wcsicmp(dotPos, L".exe") != 0 && _wcsicmp(dotPos, L".dll") != 0 && _wcsicmp(dotPos, L".scr") != 0 &&
        _wcsicmp(dotPos, L".com") != 0)
    {
        return FALSE;
    }

    /* Now scan the filename before the final extension for a known document extension */
    for (i = 0; i < kInnerCount; ++i)
    {
        SIZE_T needleLen = wcslen(kInnerExts[i]);
        PCWSTR scan = base;
        while (scan < dotPos)
        {
            SIZE_T remaining = (SIZE_T)(dotPos - scan);
            if (remaining >= needleLen && _wcsnicmp(scan, kInnerExts[i], needleLen) == 0 && scan + needleLen == dotPos)
            {
                return TRUE;
            }
            ++scan;
        }
    }

    return FALSE;
}

static VOID BkcimgImageLoadNotifyRoutineHeuristics(_In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo,
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
    isSystemPath = BkcimgImagePathContains(Path, L"\\Windows\\System32\\", 18) ||
                   BkcimgImagePathContains(Path, L"\\Windows\\SysWOW64\\", 18) ||
                   BkcimgImagePathContains(Path, L"\\Windows\\WinSxS\\", 16) ||
                   BkcimgImagePathContains(Path, L"\\KnownDlls\\", 11);

    isUserWritable =
        BkcimgImagePathContains(Path, L"\\Temp\\", 6) || BkcimgImagePathContains(Path, L"\\AppData\\", 9) ||
        BkcimgImagePathContains(Path, L"\\Downloads\\", 11) || BkcimgImagePathContains(Path, L"\\Desktop\\", 9) ||
        BkcimgImagePathContains(Path, L"\\Public\\", 8) || BkcimgImagePathContains(Path, L"\\$Recycle.Bin\\", 14) ||
        BkcimgImagePathContains(Path, L"\\ProgramData\\Temp\\", 19);

    doubleExt = BkcimgImageHasDoubleExtension(Path);
    unsigned_ = IsSignatureLevelKnown && (SignatureLevel == 0);

    /* Double-extension executable — highest priority, always emit */
    if (doubleExt)
    {
        BketwLogDetectionEvent("IMAGE_LOAD_DOUBLE_EXTENSION", 5, ProcessId, ProcessId, 0, 0, 0, Path);
    }

    /* Image from a user-writable path */
    if (isUserWritable)
    {
        ULONG sev = (unsigned_) ? 5u : 4u;
        BketwLogDetectionEvent("IMAGE_LOAD_FROM_USER_WRITABLE_PATH", sev, ProcessId, ProcessId, 0, 0, 0, Path);
    }

    /* Unsigned non-system image */
    if (unsigned_ && !isSystemPath && !isUserWritable)
    {
        BketwLogDetectionEvent("IMAGE_LOAD_UNSIGNED_NON_SYSTEM", 3, ProcessId, ProcessId, 0, 0, 0, Path);
    }

    /* DLL search-order hijacking — known system DLL name resolved outside of system directories */
    if (!isSystemPath)
    {
        static const PCWSTR kHijackableDlls[] = {L"version.dll",   L"winmm.dll",   L"wtsapi32.dll", L"cryptsp.dll",
                                                 L"dwrite.dll",    L"dwmapi.dll",  L"propsys.dll",  L"msasn1.dll",
                                                 L"cryptbase.dll", L"uxtheme.dll", L"wintrust.dll", L"dbghelp.dll",
                                                 L"winhttp.dll",   L"userenv.dll", L"profapi.dll"};
        PCWSTR base = Path;
        PCWSTR p = Path;
        ULONG j;

        while (*p != L'\0')
        {
            if (*p == L'\\' || *p == L'/')
                base = p + 1;
            ++p;
        }

        for (j = 0; j < RTL_NUMBER_OF(kHijackableDlls); ++j)
        {
            if (_wcsicmp(base, kHijackableDlls[j]) == 0)
            {
                BketwLogDetectionEvent("DLL_SEARCH_ORDER_HIJACK_SUSPECT", 6, ProcessId, ProcessId, 0, 0, 0, Path);
                break;
            }
        }
    }
}

NTSTATUS
BkcimgInitialize(VOID)
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

    g_SetLoadImageNotifyRoutineEx = BkcimgResolvePsSetLoadImageNotifyRoutineEx();
    if (g_SetLoadImageNotifyRoutineEx == NULL)
    {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = g_SetLoadImageNotifyRoutineEx(BkcimgImageLoadNotifyRoutine, 0);
    if (!NT_SUCCESS(status))
    {
        failures = InterlockedIncrement(&g_ImageMonitorFailureCounter);
        if (failures == 1 || ((failures & 0xFF) == 0))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "BK: image monitor callback registration failed status=0x%08X total=%lu.\n", status,
                       (ULONG)failures);
        }
        g_SetLoadImageNotifyRoutineEx = NULL;
        return status;
    }

    InterlockedExchange(&g_ImageMonitorRegistered, 1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BK: image monitor initialized.\n");
    return STATUS_SUCCESS;
}

VOID BkcimgUninitialize(VOID)
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

    status = PsRemoveLoadImageNotifyRoutine(BkcimgImageLoadNotifyRoutine);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "BK: image monitor callback removal failed; monitor remains registered (status=0x%08X).\n", status);
        return;
    }

    InterlockedExchange(&g_ImageMonitorRegistered, 0);
    g_SetLoadImageNotifyRoutineEx = NULL;
    RtlZeroMemory(g_NtdllTrack, sizeof(g_NtdllTrack));
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BK: image monitor uninitialized.\n");
}

BOOLEAN
BkcimgSelfCheck(VOID)
{
    return (InterlockedCompareExchange(&g_ImageMonitorRegistered, 0, 0) != 0);
}
