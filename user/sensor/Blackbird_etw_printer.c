#include <windows.h>
#include <strsafe.h>
#include <stdio.h>
#include <wctype.h>
#include <math.h>
#include <winnt.h>
#include "blackbird_sensor_core.h"
#include "blackbird_etw_printer.h"
#include "blackbird_etw_props.h"
#include "blackbird_etw_symbols.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define BLACKBIRD_INTENT_PROCESS_MEMORY 0x00000001
#define BLACKBIRD_INTENT_THREAD_CONTEXT 0x00000002
#define BLACKBIRD_INTENT_DUP_HANDLE 0x00000004

typedef struct _ACCESS_NAME_ENTRY
{
    DWORD Mask;
    PCWSTR Name;
} ACCESS_NAME_ENTRY;

typedef struct _BLACKBIRD_PID_IMAGE_CACHE_ENTRY
{
    ULONGLONG Pid;
    WCHAR Path[BLACKBIRD_MAX_IMAGE_PATH_CHARS];
} BLACKBIRD_PID_IMAGE_CACHE_ENTRY;

static const ACCESS_NAME_ENTRY g_ProcessAccessNames[] = {{PROCESS_TERMINATE, L"TERMINATE"},
                                                         {PROCESS_CREATE_THREAD, L"CREATE_THREAD"},
                                                         {PROCESS_SET_SESSIONID, L"SET_SESSIONID"},
                                                         {PROCESS_VM_OPERATION, L"VM_OPERATION"},
                                                         {PROCESS_VM_READ, L"VM_READ"},
                                                         {PROCESS_VM_WRITE, L"VM_WRITE"},
                                                         {PROCESS_DUP_HANDLE, L"DUP_HANDLE"},
                                                         {PROCESS_CREATE_PROCESS, L"CREATE_PROCESS"},
                                                         {PROCESS_SET_QUOTA, L"SET_QUOTA"},
                                                         {PROCESS_SET_INFORMATION, L"SET_INFORMATION"},
                                                         {PROCESS_QUERY_INFORMATION, L"QUERY_INFORMATION"},
                                                         {PROCESS_SUSPEND_RESUME, L"SUSPEND_RESUME"},
                                                         {PROCESS_QUERY_LIMITED_INFORMATION, L"QUERY_LIMITED_INFO"},
                                                         {SYNCHRONIZE, L"SYNCHRONIZE"}};

#define BLACKBIRD_PID_IMAGE_CACHE_CAPACITY 512

static PCWSTR RegistryNotifyClassToString(_In_ ULONG NotifyClass);
static BOOL BLACKBIRDEventNameContainsInsensitive(_In_opt_z_ PCWSTR EventName, _In_z_ PCWSTR Needle);

static BLACKBIRD_PID_IMAGE_CACHE_ENTRY g_PidImageCache[BLACKBIRD_PID_IMAGE_CACHE_CAPACITY];
static ULONG g_PidImageCacheCursor = 0;
static SRWLOCK g_PidImageCacheLock = SRWLOCK_INIT;

typedef struct _BLACKBIRD_REGISTRY_SUPPRESSOR
{
    BOOL Active;
    ULONGLONG ProcessId;
    ULONG SessionId;
    ULONG NotifyClass;
    ULONG DataType;
    ULONG DataSize;
    BOOL HighValue;
    CHAR Operation[64];
    WCHAR KeyPath[1024];
    WCHAR ValueName[256];
    WCHAR ProcessImage[MAX_PATH];
    ULONG SuppressedCount;
} BLACKBIRD_REGISTRY_SUPPRESSOR;

static BLACKBIRD_REGISTRY_SUPPRESSOR g_RegistrySuppressor;

static BOOL BLACKBIRDRegistryIsSuppressible(_In_z_ const CHAR *Operation, _In_ BOOL HighValue)
{
    if (Operation == NULL)
    {
        return FALSE;
    }
    if (HighValue)
    {
        return FALSE;
    }
    return (_stricmp(Operation, "OPEN_KEY") == 0);
}

static BOOL BLACKBIRDRegistrySuppressorMatches(_In_ const BLACKBIRD_REGISTRY_SUPPRESSOR *State,
                                                 _In_z_ const CHAR *Operation, _In_ ULONGLONG ProcessId,
                                                 _In_ ULONG SessionId, _In_ ULONG NotifyClass, _In_ ULONG DataType,
                                                 _In_ ULONG DataSize, _In_ BOOL HighValue,
                                                 _In_z_ const WCHAR *ProcessImage, _In_z_ const WCHAR *KeyPath,
                                                 _In_z_ const WCHAR *ValueName)
{
    if (State == NULL || !State->Active)
    {
        return FALSE;
    }

    return State->ProcessId == ProcessId && State->SessionId == SessionId && State->NotifyClass == NotifyClass &&
           State->DataType == DataType && State->DataSize == DataSize && State->HighValue == HighValue &&
           _stricmp(State->Operation, Operation) == 0 && _wcsicmp(State->ProcessImage, ProcessImage) == 0 &&
           _wcsicmp(State->KeyPath, KeyPath) == 0 && _wcsicmp(State->ValueName, ValueName) == 0;
}

static VOID BLACKBIRDFlushRegistrySuppressor(VOID)
{
    if (!g_RegistrySuppressor.Active || g_RegistrySuppressor.SuppressedCount == 0)
    {
        return;
    }

    wprintf(L"[REGISTRY] op=%S pid=%016llX class=%ls(%lu) path=%ls value=%ls (+%lu similar suppressed)\n",
            g_RegistrySuppressor.Operation[0] ? g_RegistrySuppressor.Operation : "OTHER",
            g_RegistrySuppressor.ProcessId, RegistryNotifyClassToString(g_RegistrySuppressor.NotifyClass),
            g_RegistrySuppressor.NotifyClass,
            g_RegistrySuppressor.KeyPath[0] ? g_RegistrySuppressor.KeyPath : L"<unknown>",
            g_RegistrySuppressor.ValueName[0] ? g_RegistrySuppressor.ValueName : L"<none>",
            g_RegistrySuppressor.SuppressedCount);
    g_RegistrySuppressor.SuppressedCount = 0;
}

static VOID BLACKBIRDUpdateRegistrySuppressor(_In_z_ const CHAR *Operation, _In_ ULONGLONG ProcessId,
                                                _In_ ULONG SessionId, _In_ ULONG NotifyClass, _In_ ULONG DataType,
                                                _In_ ULONG DataSize, _In_ BOOL HighValue,
                                                _In_z_ const WCHAR *ProcessImage, _In_z_ const WCHAR *KeyPath,
                                                _In_z_ const WCHAR *ValueName)
{
    g_RegistrySuppressor.Active = TRUE;
    g_RegistrySuppressor.ProcessId = ProcessId;
    g_RegistrySuppressor.SessionId = SessionId;
    g_RegistrySuppressor.NotifyClass = NotifyClass;
    g_RegistrySuppressor.DataType = DataType;
    g_RegistrySuppressor.DataSize = DataSize;
    g_RegistrySuppressor.HighValue = HighValue;
    g_RegistrySuppressor.SuppressedCount = 0;
    (void)StringCchCopyA(g_RegistrySuppressor.Operation, RTL_NUMBER_OF(g_RegistrySuppressor.Operation), Operation);
    (void)StringCchCopyW(g_RegistrySuppressor.ProcessImage, RTL_NUMBER_OF(g_RegistrySuppressor.ProcessImage),
                         ProcessImage);
    (void)StringCchCopyW(g_RegistrySuppressor.KeyPath, RTL_NUMBER_OF(g_RegistrySuppressor.KeyPath), KeyPath);
    (void)StringCchCopyW(g_RegistrySuppressor.ValueName, RTL_NUMBER_OF(g_RegistrySuppressor.ValueName), ValueName);
}

static BOOL BLACKBIRDPathEndsWithInsensitive(_In_z_ PCWSTR Path, _In_z_ PCWSTR Suffix)
{
    size_t pathLen;
    size_t suffixLen;

    if (Path == NULL || Suffix == NULL)
    {
        return FALSE;
    }

    pathLen = wcslen(Path);
    suffixLen = wcslen(Suffix);
    if (suffixLen == 0 || suffixLen > pathLen)
    {
        return FALSE;
    }

    return (_wcsicmp(Path + (pathLen - suffixLen), Suffix) == 0);
}

static BOOL BLACKBIRDIsExecutableImagePath(_In_z_ PCWSTR Path)
{
    if (Path == NULL || Path[0] == L'\0')
    {
        return FALSE;
    }

    return BLACKBIRDPathEndsWithInsensitive(Path, L".exe") || BLACKBIRDPathEndsWithInsensitive(Path, L".com");
}

static BOOL BLACKBIRDLookupCachedProcessImage(_In_ ULONGLONG Pid, _Out_writes_z_(OutputChars) PWSTR Output,
                                                _In_ size_t OutputChars)
{
    ULONG i;

    if (Output == NULL || OutputChars == 0 || Pid == 0)
    {
        return FALSE;
    }

    AcquireSRWLockShared(&g_PidImageCacheLock);
    for (i = 0; i < RTL_NUMBER_OF(g_PidImageCache); ++i)
    {
        if (g_PidImageCache[i].Pid != Pid || g_PidImageCache[i].Path[0] == L'\0')
        {
            continue;
        }
        (void)StringCchCopyW(Output, OutputChars, g_PidImageCache[i].Path);
        ReleaseSRWLockShared(&g_PidImageCacheLock);
        return TRUE;
    }
    ReleaseSRWLockShared(&g_PidImageCacheLock);
    return FALSE;
}

static VOID BLACKBIRDCacheProcessImage(_In_ ULONGLONG Pid, _In_opt_z_ PCWSTR Path)
{
    ULONG i;

    if (Pid == 0 || Path == NULL || Path[0] == L'\0' || Path[0] == L'<' || !BLACKBIRDIsExecutableImagePath(Path))
    {
        return;
    }

    AcquireSRWLockExclusive(&g_PidImageCacheLock);
    for (i = 0; i < RTL_NUMBER_OF(g_PidImageCache); ++i)
    {
        if (g_PidImageCache[i].Pid != Pid)
        {
            continue;
        }
        (void)StringCchCopyW(g_PidImageCache[i].Path, RTL_NUMBER_OF(g_PidImageCache[i].Path), Path);
        ReleaseSRWLockExclusive(&g_PidImageCacheLock);
        return;
    }

    g_PidImageCache[g_PidImageCacheCursor].Pid = Pid;
    (void)StringCchCopyW(g_PidImageCache[g_PidImageCacheCursor].Path,
                         RTL_NUMBER_OF(g_PidImageCache[g_PidImageCacheCursor].Path), Path);
    g_PidImageCacheCursor = (g_PidImageCacheCursor + 1) % RTL_NUMBER_OF(g_PidImageCache);
    ReleaseSRWLockExclusive(&g_PidImageCacheLock);
}

static BOOL BLACKBIRDQueryProcessImageFromKernel(_In_ ULONGLONG Pid, _Out_writes_z_(OutputChars) PWSTR Output,
                                                   _In_ size_t OutputChars)
{
    HANDLE device;
    DWORD outputCharsDword;
    BOOL ok;

    if (Output == NULL || OutputChars == 0 || Pid == 0 || Pid > MAXDWORD || OutputChars > MAXDWORD)
    {
        return FALSE;
    }

    outputCharsDword = (DWORD)OutputChars;
    device = BLACKBIRDSCOpenControlDevice();
    if (device == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    ok = BLACKBIRDSCQueryProcessImagePath(device, (DWORD)Pid, Output, outputCharsDword);
    (void)BLACKBIRDSCCloseControlDevice(device);
    return ok;
}

void BLACKBIRDPrimeProcessImagePath(_In_ ULONGLONG Pid, _In_opt_z_ PCWSTR ImagePath)
{
    BLACKBIRDCacheProcessImage(Pid, ImagePath);
}

void BLACKBIRDPrimeProcessImageFromEtw(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName)
{
    ULONGLONG processId = 0;
    WCHAR imagePath[1024];

    if (Record == NULL || EventName == NULL)
    {
        return;
    }
    if (!IsEqualGUID(&Record->EventHeader.ProviderId, &BLACKBIRDSC_PROVIDER_GUID_BLACKBIRD))
    {
        return;
    }
    if (wcscmp(EventName, L"ProcessTelemetry") != 0 && wcscmp(EventName, L"ImageTelemetry") != 0)
    {
        return;
    }

    imagePath[0] = L'\0';
    if (!BLACKBIRDGetU64Property(Record, L"processId", &processId) || processId == 0)
    {
        return;
    }
    if (!BLACKBIRDGetWideProperty(Record, L"imagePath", imagePath, RTL_NUMBER_OF(imagePath)))
    {
        return;
    }

    BLACKBIRDCacheProcessImage(processId, imagePath);
    if (wcscmp(EventName, L"ImageTelemetry") == 0)
    {
        ULONGLONG imageBase = 0;
        ULONGLONG imageSize = 0;
        if (BLACKBIRDGetU64Property(Record, L"imageBase", &imageBase) &&
            BLACKBIRDGetU64Property(Record, L"imageSize", &imageSize) && imageBase != 0 && imageSize != 0)
        {
            BLACKBIRDEtwSymbolsCacheModuleForProcess((DWORD)processId, imageBase, imageSize, imagePath);
        }
    }
}

static void AppendFlag(_Inout_updates_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars, _In_z_ PCWSTR FlagName,
                       _Inout_ BOOL *First)
{
    if (!*First)
    {
        (void)StringCchCatW(Output, OutputChars, L"|");
    }
    (void)StringCchCatW(Output, OutputChars, FlagName);
    *First = FALSE;
}

static void FormatProcessAccessMask(_In_ DWORD DesiredAccess, _Out_writes_z_(OutputChars) PWSTR Output,
                                    _In_ size_t OutputChars)
{
    DWORD i;
    BOOL first = TRUE;

    if (OutputChars == 0)
    {
        return;
    }
    Output[0] = L'\0';

    if (DesiredAccess == PROCESS_ALL_ACCESS)
    {
        (void)StringCchCopyW(Output, OutputChars, L"PROCESS_ALL_ACCESS");
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(g_ProcessAccessNames); ++i)
    {
        if ((DesiredAccess & g_ProcessAccessNames[i].Mask) == g_ProcessAccessNames[i].Mask)
        {
            AppendFlag(Output, OutputChars, g_ProcessAccessNames[i].Name, &first);
        }
    }

    if (first)
    {
        (void)StringCchCopyW(Output, OutputChars, L"<none>");
    }
}

static void FormatProtect(_In_ DWORD Protect, _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars)
{
    BOOL first = TRUE;

    if (OutputChars == 0)
    {
        return;
    }
    Output[0] = L'\0';

    if (Protect & PAGE_GUARD)
    {
        AppendFlag(Output, OutputChars, L"GUARD", &first);
    }
    if (Protect & PAGE_NOCACHE)
    {
        AppendFlag(Output, OutputChars, L"NOCACHE", &first);
    }
    if (Protect & PAGE_WRITECOMBINE)
    {
        AppendFlag(Output, OutputChars, L"WRITECOMBINE", &first);
    }

    switch (Protect & 0xFF)
    {
    case PAGE_NOACCESS:
        AppendFlag(Output, OutputChars, L"NOACCESS", &first);
        break;
    case PAGE_READONLY:
        AppendFlag(Output, OutputChars, L"R", &first);
        break;
    case PAGE_READWRITE:
        AppendFlag(Output, OutputChars, L"RW", &first);
        break;
    case PAGE_WRITECOPY:
        AppendFlag(Output, OutputChars, L"WCOPY", &first);
        break;
    case PAGE_EXECUTE:
        AppendFlag(Output, OutputChars, L"X", &first);
        break;
    case PAGE_EXECUTE_READ:
        AppendFlag(Output, OutputChars, L"XR", &first);
        break;
    case PAGE_EXECUTE_READWRITE:
        AppendFlag(Output, OutputChars, L"XRW", &first);
        break;
    case PAGE_EXECUTE_WRITECOPY:
        AppendFlag(Output, OutputChars, L"XWCOPY", &first);
        break;
    default:
        break;
    }

    if (first)
    {
        (void)StringCchCopyW(Output, OutputChars, L"<unknown>");
    }
}

static void FormatMemState(_In_ ULONG State, _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars)
{
    if (OutputChars == 0)
    {
        return;
    }

    if (State == MEM_COMMIT)
    {
        (void)StringCchCopyW(Output, OutputChars, L"COMMIT");
    }
    else if (State == MEM_RESERVE)
    {
        (void)StringCchCopyW(Output, OutputChars, L"RESERVE");
    }
    else if (State == MEM_FREE)
    {
        (void)StringCchCopyW(Output, OutputChars, L"FREE");
    }
    else
    {
        (void)StringCchPrintfW(Output, OutputChars, L"0x%08lX", State);
    }
}

static void FormatMemType(_In_ ULONG Type, _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars)
{
    if (OutputChars == 0)
    {
        return;
    }

    if (Type == MEM_IMAGE)
    {
        (void)StringCchCopyW(Output, OutputChars, L"IMAGE");
    }
    else if (Type == MEM_MAPPED)
    {
        (void)StringCchCopyW(Output, OutputChars, L"MAPPED");
    }
    else if (Type == MEM_PRIVATE)
    {
        (void)StringCchCopyW(Output, OutputChars, L"PRIVATE");
    }
    else
    {
        (void)StringCchPrintfW(Output, OutputChars, L"0x%08lX", Type);
    }
}

static void FormatCorrelationFlags(_In_ ULONG Flags, _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars)
{
    BOOL first = TRUE;

    if (OutputChars == 0)
    {
        return;
    }
    Output[0] = L'\0';

    if ((Flags & BLACKBIRD_INTENT_PROCESS_MEMORY) != 0)
    {
        AppendFlag(Output, OutputChars, L"ProcessMemory", &first);
    }
    if ((Flags & BLACKBIRD_INTENT_THREAD_CONTEXT) != 0)
    {
        AppendFlag(Output, OutputChars, L"ThreadContext", &first);
    }
    if ((Flags & BLACKBIRD_INTENT_DUP_HANDLE) != 0)
    {
        AppendFlag(Output, OutputChars, L"DuplicateHandle", &first);
    }

    if (first)
    {
        (void)StringCchCopyW(Output, OutputChars, L"<none>");
    }
}

static void FormatHandleClass(_In_z_ PCSTR EventClass, _Out_writes_z_(OutputChars) PWSTR Output,
                              _In_ size_t OutputChars)
{
    if (OutputChars == 0)
    {
        return;
    }
    Output[0] = L'\0';

    if (EventClass == NULL || EventClass[0] == '\0')
    {
        (void)StringCchCopyW(Output, OutputChars, L"UNKNOWN");
        return;
    }

    if (_stricmp(EventClass, "DIRECT-SYSCALL-SUSPECT") == 0)
    {
        (void)StringCchCopyW(Output, OutputChars, L"DIRECT-SYSCALL-SUSPECT");
    }
    else if (_stricmp(EventClass, "LEGITIMATE-SYSCALL") == 0)
    {
        (void)StringCchCopyW(Output, OutputChars, L"LEGITIMATE-SYSCALL");
    }
    else
    {
        (void)StringCchPrintfW(Output, OutputChars, L"%S", EventClass);
    }
}

static BOOL BLACKBIRDWideContainsInsensitive(_In_opt_z_ PCWSTR Haystack, _In_z_ PCWSTR Needle)
{
    WCHAR hay[1024];
    WCHAR need[64];
    size_t i;

    if (Haystack == NULL || Needle == NULL)
    {
        return FALSE;
    }

    (void)StringCchCopyW(hay, RTL_NUMBER_OF(hay), Haystack);
    (void)StringCchCopyW(need, RTL_NUMBER_OF(need), Needle);

    for (i = 0; i < RTL_NUMBER_OF(hay); ++i)
    {
        hay[i] = (WCHAR)towlower(hay[i]);
        if (hay[i] == L'\0')
        {
            break;
        }
    }
    for (i = 0; i < RTL_NUMBER_OF(need); ++i)
    {
        need[i] = (WCHAR)towlower(need[i]);
        if (need[i] == L'\0')
        {
            break;
        }
    }

    return (wcsstr(hay, need) != NULL);
}

static void ComputeUserModeHandleClass(_In_z_ PCSTR KernelClass, _In_ BOOL ExecProtect, _In_ BOOL FromNtdll,
                                       _In_ BOOL FromExe, _In_z_ PCWSTR OriginPath,
                                       _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars)
{
    BOOL fromKnownSyscallStub;

    if (OutputChars == 0)
    {
        return;
    }
    Output[0] = L'\0';

    if (KernelClass != NULL &&
        (_stricmp(KernelClass, "LEGITIMATE-SYSCALL") == 0 || _stricmp(KernelClass, "DIRECT-SYSCALL-SUSPECT") == 0))
    {
        FormatHandleClass(KernelClass, Output, OutputChars);
        return;
    }

    fromKnownSyscallStub = (FromNtdll || BLACKBIRDWideContainsInsensitive(OriginPath, L"ntdll.dll") ||
                            BLACKBIRDWideContainsInsensitive(OriginPath, L"win32u.dll"));

    if (ExecProtect && fromKnownSyscallStub)
    {
        (void)StringCchCopyW(Output, OutputChars, L"LEGITIMATE-SYSCALL");
        return;
    }

    if (ExecProtect && (!fromKnownSyscallStub) && (FromExe || OriginPath == NULL || OriginPath[0] == L'\0'))
    {
        (void)StringCchCopyW(Output, OutputChars, L"DIRECT-SYSCALL-SUSPECT");
        return;
    }

    (void)StringCchCopyW(Output, OutputChars, L"UNKNOWN-ORIGIN");
}

static double ComputeShannonEntropy(_In_reads_bytes_(Size) const BYTE *Data, _In_ ULONG Size)
{
    UINT32 counts[256];
    ULONG i;
    double entropy = 0.0;

    if (Data == NULL || Size == 0)
    {
        return 0.0;
    }

    ZeroMemory(counts, sizeof(counts));
    for (i = 0; i < Size; ++i)
    {
        counts[Data[i]] += 1;
    }

    for (i = 0; i < RTL_NUMBER_OF(counts); ++i)
    {
        if (counts[i] == 0)
        {
            continue;
        }
        {
            double p = ((double)counts[i]) / ((double)Size);
            entropy -= p * (log(p) / log(2.0));
        }
    }

    return entropy;
}

static void FormatOpcodePreview(_In_reads_bytes_(Size) const BYTE *Data, _In_ ULONG Size,
                                _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars)
{
    ULONG i;
    ULONG limit;

    if (OutputChars == 0)
    {
        return;
    }
    Output[0] = L'\0';

    if (Data == NULL || Size == 0)
    {
        (void)StringCchCopyW(Output, OutputChars, L"<none>");
        return;
    }

    limit = (Size > 16) ? 16 : Size;
    for (i = 0; i < limit; ++i)
    {
        WCHAR chunk[8];
        (void)StringCchPrintfW(chunk, RTL_NUMBER_OF(chunk), (i == 0) ? L"%02X" : L" %02X", Data[i]);
        (void)StringCchCatW(Output, OutputChars, chunk);
    }
    if (Size > limit)
    {
        (void)StringCchCatW(Output, OutputChars, L" ...");
    }
}

static void FormatProcessImage(_In_ ULONGLONG Pid, _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars)
{
    HANDLE process;
    DWORD size;
    BOOL openedUserProcess = FALSE;

    if (OutputChars == 0)
    {
        return;
    }
    Output[0] = L'\0';

    if (Pid == 0)
    {
        (void)StringCchCopyW(Output, OutputChars, L"<pid:0>");
        return;
    }
    if (Pid > MAXDWORD)
    {
        (void)StringCchPrintfW(Output, OutputChars, L"<pid:%llu invalid>", Pid);
        return;
    }

    if (BLACKBIRDLookupCachedProcessImage(Pid, Output, OutputChars))
    {
        return;
    }

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)Pid);
    if (process != NULL)
    {
        openedUserProcess = TRUE;
        size = (DWORD)OutputChars;
        if (QueryFullProcessImageNameW(process, 0, Output, &size) && Output[0] != L'\0')
        {
            BLACKBIRDCacheProcessImage(Pid, Output);
            CloseHandle(process);
            return;
        }
        CloseHandle(process);
    }

    if (BLACKBIRDQueryProcessImageFromKernel(Pid, Output, OutputChars) && Output[0] != L'\0')
    {
        BLACKBIRDCacheProcessImage(Pid, Output);
        return;
    }

    if (openedUserProcess)
    {
        (void)StringCchPrintfW(Output, OutputChars, L"<pid:%llu image-unknown>", Pid);
    }
    else
    {
        (void)StringCchPrintfW(Output, OutputChars, L"<pid:%llu inaccessible>", Pid);
    }
}

static PCWSTR RegistryNotifyClassToString(_In_ ULONG NotifyClass)
{
    switch (NotifyClass)
    {
    case 4:
        return L"RegNtPreCreateKey";
    case 6:
        return L"RegNtPreCreateKeyEx";
    case 10:
        return L"RegNtPreOpenKey";
    case 12:
        return L"RegNtPreOpenKeyEx";
    case 22:
        return L"RegNtPreSetValueKey";
    case 24:
        return L"RegNtPreDeleteValueKey";
    default:
        return L"Other";
    }
}

static BOOL BLACKBIRDIsLikelyMainImageAddress(_In_ ULONGLONG Address)
{
    if (Address >= 0x00007FF600000000ULL && Address <= 0x00007FF7FFFFFFFFULL)
    {
        return TRUE;
    }
    if (Address >= 0x0000000140000000ULL && Address <= 0x00000001FFFFFFFFULL)
    {
        return TRUE;
    }
    return FALSE;
}

static void FormatAddressWithImageHint(_In_ DWORD ProcessId, _In_ ULONGLONG Address, _In_opt_z_ PCWSTR ImageHint,
                                       _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars)
{
    PCWSTR baseName;
    PCWSTR slash;

    BLACKBIRDEtwSymbolsFormatAddressForProcess(ProcessId, Address, Output, OutputChars);
    if (Output == NULL || OutputChars == 0)
    {
        return;
    }
    if (wcsstr(Output, L"[unresolved]") == NULL)
    {
        return;
    }
    if (ProcessId != 0 && BLACKBIRDEtwSymbolsTryResolveViaModuleCache(ProcessId, Address, Output, OutputChars))
    {
        return;
    }
    if (!BLACKBIRDIsLikelyMainImageAddress(Address))
    {
        return;
    }
    if (ImageHint == NULL || ImageHint[0] == L'\0')
    {
        return;
    }

    baseName = ImageHint;
    slash = wcsrchr(ImageHint, L'\\');
    if (slash != NULL && slash[1] != L'\0')
    {
        baseName = slash + 1;
    }

    (void)StringCchPrintfW(Output, OutputChars, L"%ls", baseName);
}

static void PrintStack(_In_ PEVENT_RECORD Record, _In_ ULONG Count, _In_ DWORD PrimaryProcessId,
                       _In_ DWORD SecondaryProcessId, _In_opt_z_ PCWSTR ImageHint)
{
    ULONG i;
    WCHAR name[16];
    UNREFERENCED_PARAMETER(SecondaryProcessId);

    for (i = 0; i < Count && i < 8; ++i)
    {
        ULONGLONG addr = 0;
        WCHAR resolved[768];
        (void)StringCchPrintfW(name, RTL_NUMBER_OF(name), L"stack%lu", i);
        if (!BLACKBIRDGetU64Property(Record, name, &addr))
        {
            continue;
        }
        FormatAddressWithImageHint(PrimaryProcessId, addr, ImageHint, resolved, RTL_NUMBER_OF(resolved));
        wprintf(L"       #%lu 0x%016llX (%ls)\n", i, addr, resolved);
    }
}

static void PrintHeaderMetadata(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR EventName)
{
    static ULONGLONG s_LastTimestamp = 0;
    ULONGLONG currentTs = (ULONGLONG)Record->EventHeader.TimeStamp.QuadPart;
    ULONGLONG delta = 0;
    if (s_LastTimestamp != 0 && currentTs >= s_LastTimestamp)
    {
        delta = currentTs - s_LastTimestamp;
    }
    s_LastTimestamp = currentTs;

    wprintf(L"Meta   event=%ls pid=%lu tid=%lu cpu=%u lvl=%u op=%u ver=%u ts=0x%016llX dt=0x%llX\n", EventName,
            Record->EventHeader.ProcessId, Record->EventHeader.ThreadId, Record->BufferContext.ProcessorNumber,
            Record->EventHeader.EventDescriptor.Level, Record->EventHeader.EventDescriptor.Opcode,
            Record->EventHeader.EventDescriptor.Version, currentTs, delta);
}

static void PrintHandleTelemetry(_In_ PEVENT_RECORD Record)
{
    CHAR eventClass[64];
    ULONGLONG callerPid = 0;
    ULONGLONG targetPid = 0;
    ULONG desiredAccess = 0;
    ULONGLONG originAddress = 0;
    ULONG originProtect = 0;
    BOOL execProtect = FALSE;
    BOOL fromNtdll = FALSE;
    BOOL fromExe = FALSE;
    WCHAR path[1024];
    ULONG frameCount = 0;
    LONG statusOpen = 0;
    LONG statusBasic = 0;
    LONG statusSection = 0;
    WCHAR classW[64];
    WCHAR accessText[512];
    WCHAR protectText[128];
    WCHAR originSym[768];
    WCHAR callerImage[MAX_PATH];
    WCHAR targetImage[MAX_PATH];
    ULONGLONG deepAllocationBase = 0;
    ULONGLONG deepRegionSize = 0;
    ULONG deepRegionProtect = 0;
    ULONG deepRegionState = 0;
    ULONG deepRegionType = 0;
    ULONG deepSampleSize = 0;
    BYTE deepSample[BLACKBIRD_MAX_DEEP_SAMPLE_BYTES];
    WCHAR deepOpcodePreview[128];
    double deepEntropy = 0.0;
    DWORD stackPidPrimary;
    DWORD stackPidSecondary = 0;

    eventClass[0] = '\0';
    path[0] = L'\0';
    classW[0] = L'\0';
    ZeroMemory(deepSample, sizeof(deepSample));
    deepOpcodePreview[0] = L'\0';

    (void)BLACKBIRDGetAnsiProperty(Record, L"class", eventClass, RTL_NUMBER_OF(eventClass));
    (void)BLACKBIRDGetU64Property(Record, L"callerPid", &callerPid);
    (void)BLACKBIRDGetU64Property(Record, L"targetPid", &targetPid);
    (void)BLACKBIRDGetU32Property(Record, L"desiredAccess", &desiredAccess);
    (void)BLACKBIRDGetU64Property(Record, L"originAddress", &originAddress);
    (void)BLACKBIRDGetU32Property(Record, L"originProtect", &originProtect);
    (void)BLACKBIRDGetBoolProperty(Record, L"execProtect", &execProtect);
    (void)BLACKBIRDGetBoolProperty(Record, L"fromNtdll", &fromNtdll);
    (void)BLACKBIRDGetBoolProperty(Record, L"fromExe", &fromExe);
    (void)BLACKBIRDGetWideProperty(Record, L"originPath", path, RTL_NUMBER_OF(path));
    (void)BLACKBIRDGetU32Property(Record, L"frameCount", &frameCount);
    (void)BLACKBIRDGetI32Property(Record, L"statusOpenProcess", &statusOpen);
    (void)BLACKBIRDGetI32Property(Record, L"statusBasicInfo", &statusBasic);
    (void)BLACKBIRDGetI32Property(Record, L"statusSectionName", &statusSection);
    (void)BLACKBIRDGetU64Property(Record, L"deepAllocationBase", &deepAllocationBase);
    (void)BLACKBIRDGetU64Property(Record, L"deepRegionSize", &deepRegionSize);
    (void)BLACKBIRDGetU32Property(Record, L"deepRegionProtect", &deepRegionProtect);
    (void)BLACKBIRDGetU32Property(Record, L"deepRegionState", &deepRegionState);
    (void)BLACKBIRDGetU32Property(Record, L"deepRegionType", &deepRegionType);
    if (!BLACKBIRDGetBinaryProperty(Record, L"deepSample", deepSample, sizeof(deepSample), &deepSampleSize))
    {
        deepSampleSize = 0;
    }

    ComputeUserModeHandleClass(eventClass, execProtect, fromNtdll, fromExe, path, classW, RTL_NUMBER_OF(classW));
    FormatProcessAccessMask(desiredAccess, accessText, RTL_NUMBER_OF(accessText));
    FormatProtect(originProtect, protectText, RTL_NUMBER_OF(protectText));
    FormatProcessImage(callerPid, callerImage, RTL_NUMBER_OF(callerImage));
    FormatProcessImage(targetPid, targetImage, RTL_NUMBER_OF(targetImage));
    FormatAddressWithImageHint((DWORD)callerPid, originAddress, callerImage, originSym, RTL_NUMBER_OF(originSym));
    stackPidPrimary = (DWORD)callerPid;
    if (stackPidPrimary == 0 || stackPidPrimary == 4)
    {
        stackPidPrimary = (DWORD)targetPid;
    }
    if (deepSampleSize > sizeof(deepSample))
    {
        deepSampleSize = sizeof(deepSample);
    }
    if (deepSampleSize != 0)
    {
        deepEntropy = ComputeShannonEntropy(deepSample, deepSampleSize);
        FormatOpcodePreview(deepSample, deepSampleSize, deepOpcodePreview, RTL_NUMBER_OF(deepOpcodePreview));
    }

    wprintf(L"\n[HANDLE] %ls  %016llX -> %016llX  access=0x%08lX (%ls)\n", classW, callerPid, targetPid, desiredAccess,
            accessText);
    PrintHeaderMetadata(Record, L"HandleTelemetry");
    wprintf(L"Actor  callerImage=%ls\n", callerImage);
    wprintf(L"       targetImage=%ls\n", targetImage);
    wprintf(L"Origin addr=0x%016llX (%ls)\n", originAddress, originSym);
    wprintf(L"       path=%ls\n", path[0] ? path : L"<unknown>");
    wprintf(L"       protect=0x%08lX (%ls) exec=%u fromNtdll=%u fromExe=%u\n", originProtect, protectText,
            execProtect ? 1 : 0, fromNtdll ? 1 : 0, fromExe ? 1 : 0);
    wprintf(L"Status open=%hs(0x%08X) basic=%hs(0x%08X) section=%hs(0x%08X)\n",
            NT_SUCCESS(statusOpen) ? "SUCCESS" : "FAIL", (ULONG)statusOpen,
            NT_SUCCESS(statusBasic) ? "SUCCESS" : "FAIL", (ULONG)statusBasic,
            NT_SUCCESS(statusSection) ? "SUCCESS" : "FAIL", (ULONG)statusSection);
    if (deepAllocationBase != 0 || deepRegionSize != 0 || deepSampleSize != 0)
    {
        WCHAR deepProtectText[64];
        WCHAR deepStateText[64];
        WCHAR deepTypeText[64];
        PCWSTR deepBacking = L"unknown";
        BOOL deepCommitted;
        BOOL deepPrivateCommit;
        BOOL deepImageCommit;
        BOOL deepMappedCommit;
        FormatProtect(deepRegionProtect, deepProtectText, RTL_NUMBER_OF(deepProtectText));
        FormatMemState(deepRegionState, deepStateText, RTL_NUMBER_OF(deepStateText));
        FormatMemType(deepRegionType, deepTypeText, RTL_NUMBER_OF(deepTypeText));
        if (deepRegionType == MEM_PRIVATE)
        {
            deepBacking = L"private";
        }
        else if (deepRegionType == MEM_MAPPED)
        {
            deepBacking = L"mapped";
        }
        else if (deepRegionType == MEM_IMAGE)
        {
            deepBacking = L"image";
        }
        deepCommitted = (deepRegionState == MEM_COMMIT);
        deepPrivateCommit = (deepCommitted && deepRegionType == MEM_PRIVATE);
        deepImageCommit = (deepCommitted && deepRegionType == MEM_IMAGE);
        deepMappedCommit = (deepCommitted && deepRegionType == MEM_MAPPED);
        wprintf(L"Deep   allocBase=0x%016llX regionSize=0x%llX protect=0x%08lX (%ls) state=%ls type=%ls\n",
                deepAllocationBase, deepRegionSize, deepRegionProtect, deepProtectText, deepStateText, deepTypeText);
        wprintf(L"       backing=%ls committed=%u privateCommit=%u imageCommit=%u mappedCommit=%u\n", deepBacking,
                deepCommitted ? 1u : 0u, deepPrivateCommit ? 1u : 0u, deepImageCommit ? 1u : 0u,
                deepMappedCommit ? 1u : 0u);
        wprintf(L"       sampleSize=%lu entropy=%.3f opcodes=%ls\n", deepSampleSize, deepEntropy,
                deepSampleSize ? deepOpcodePreview : L"<none>");
    }
    wprintf(L"Stack  frames=%lu\n", frameCount);
    PrintStack(Record, frameCount, stackPidPrimary, stackPidSecondary, callerImage);

    if (wcscmp(classW, L"DIRECT-SYSCALL-SUSPECT") == 0)
    {
        wprintf(L"Alert  direct-syscall-suspect classification observed\n");
    }
}

static void PrintThreadTelemetry(_In_ PEVENT_RECORD Record)
{
    ULONGLONG processId = 0;
    ULONGLONG threadId = 0;
    ULONGLONG creatorPid = 0;
    ULONGLONG startAddress = 0;
    ULONGLONG imageBase = 0;
    ULONGLONG imageSize = 0;
    BOOL gotStart = FALSE;
    BOOL gotRange = FALSE;
    BOOL isRemote = FALSE;
    BOOL outsideImage = FALSE;
    ULONG correlationFlags = 0;
    ULONG correlationAccessMask = 0;
    ULONG correlationAgeMs = 0;
    ULONG startRegionProtect = 0;
    ULONG startRegionState = 0;
    ULONG startRegionType = 0;
    LONG startRegionStatus = 0;
    ULONG frameCount = 0;
    WCHAR startSym[768];
    WCHAR imageSym[768];
    WCHAR processImage[MAX_PATH];
    WCHAR creatorImage[MAX_PATH];
    WCHAR corrFlagsText[128];
    WCHAR startProtectText[64];
    WCHAR startStateText[64];
    WCHAR startTypeText[64];

    (void)BLACKBIRDGetU64Property(Record, L"processId", &processId);
    (void)BLACKBIRDGetU64Property(Record, L"threadId", &threadId);
    (void)BLACKBIRDGetU64Property(Record, L"creatorPid", &creatorPid);
    (void)BLACKBIRDGetU64Property(Record, L"startAddress", &startAddress);
    (void)BLACKBIRDGetU64Property(Record, L"imageBase", &imageBase);
    (void)BLACKBIRDGetU64Property(Record, L"imageSize", &imageSize);
    (void)BLACKBIRDGetBoolProperty(Record, L"gotStart", &gotStart);
    (void)BLACKBIRDGetBoolProperty(Record, L"gotRange", &gotRange);
    (void)BLACKBIRDGetBoolProperty(Record, L"isRemoteCreator", &isRemote);
    (void)BLACKBIRDGetBoolProperty(Record, L"outsideMainImage", &outsideImage);
    (void)BLACKBIRDGetU32Property(Record, L"correlationFlags", &correlationFlags);
    (void)BLACKBIRDGetU32Property(Record, L"correlationAccessMask", &correlationAccessMask);
    (void)BLACKBIRDGetU32Property(Record, L"correlationAgeMs", &correlationAgeMs);
    (void)BLACKBIRDGetU32Property(Record, L"startRegionProtect", &startRegionProtect);
    (void)BLACKBIRDGetU32Property(Record, L"startRegionState", &startRegionState);
    (void)BLACKBIRDGetU32Property(Record, L"startRegionType", &startRegionType);
    (void)BLACKBIRDGetI32Property(Record, L"startRegionStatus", &startRegionStatus);
    (void)BLACKBIRDGetU32Property(Record, L"workerFrameCount", &frameCount);

    FormatProcessImage(processId, processImage, RTL_NUMBER_OF(processImage));
    FormatProcessImage(creatorPid, creatorImage, RTL_NUMBER_OF(creatorImage));
    FormatAddressWithImageHint((DWORD)processId, startAddress, processImage, startSym, RTL_NUMBER_OF(startSym));
    FormatAddressWithImageHint((DWORD)processId, imageBase, processImage, imageSym, RTL_NUMBER_OF(imageSym));
    FormatCorrelationFlags(correlationFlags, corrFlagsText, RTL_NUMBER_OF(corrFlagsText));
    FormatProtect(startRegionProtect, startProtectText, RTL_NUMBER_OF(startProtectText));
    FormatMemState(startRegionState, startStateText, RTL_NUMBER_OF(startStateText));
    FormatMemType(startRegionType, startTypeText, RTL_NUMBER_OF(startTypeText));

    wprintf(L"\n[THREAD] pid=%016llX tid=%016llX creator=%016llX\n", processId, threadId, creatorPid);
    PrintHeaderMetadata(Record, L"ThreadTelemetry");
    wprintf(L"Flags  remote=%u outsideMainImage=%u gotStart=%u gotRange=%u\n", isRemote ? 1 : 0, outsideImage ? 1 : 0,
            gotStart ? 1 : 0, gotRange ? 1 : 0);
    wprintf(L"Actor  processImage=%ls\n", processImage);
    wprintf(L"       creatorImage=%ls\n", creatorImage);
    wprintf(L"Start  0x%016llX (%ls)\n", startAddress, startSym);
    wprintf(L"Image  base=0x%016llX (%ls) size=0x%llX\n", imageBase, imageSym, imageSize);
    wprintf(L"Corr   flags=0x%08lX (%ls) access=0x%08lX ageMs=%lu\n", correlationFlags, corrFlagsText,
            correlationAccessMask, correlationAgeMs);
    wprintf(L"StartR status=%hs(0x%08X) protect=0x%08lX (%ls) state=%ls type=%ls\n",
            NT_SUCCESS(startRegionStatus) ? "SUCCESS" : "FAIL", (ULONG)startRegionStatus, startRegionProtect,
            startProtectText, startStateText, startTypeText);
    {
        PCWSTR startBacking = L"unknown";
        BOOL startCommitted = (startRegionState == MEM_COMMIT);
        BOOL startPrivateCommit = (startCommitted && startRegionType == MEM_PRIVATE);
        if (startRegionType == MEM_PRIVATE)
        {
            startBacking = L"private";
        }
        else if (startRegionType == MEM_MAPPED)
        {
            startBacking = L"mapped";
        }
        else if (startRegionType == MEM_IMAGE)
        {
            startBacking = L"image";
        }
        wprintf(L"StartB backing=%ls committed=%u privateCommit=%u\n", startBacking, startCommitted ? 1u : 0u,
                startPrivateCommit ? 1u : 0u);
    }
    wprintf(L"Stack  frames=%lu\n", frameCount);
    PrintStack(Record, frameCount, (DWORD)processId, 0, processImage);
    if (outsideImage)
    {
        wprintf(L"Alert  thread start is outside main image range\n");
    }
    if (correlationFlags != 0)
    {
        wprintf(L"Alert  thread event has recent handle-intent correlation\n");
    }
}

static void PrintProcessTelemetry(_In_ PEVENT_RECORD Record)
{
    BOOL isCreate = FALSE;
    LONG createStatus = 0;
    ULONGLONG processId = 0;
    ULONGLONG parentPid = 0;
    ULONGLONG creatorPid = 0;
    ULONGLONG creatorTid = 0;
    ULONGLONG startKey = 0;
    ULONG sessionId = 0;
    WCHAR imagePath[1024];
    WCHAR commandLine[1024];

    imagePath[0] = L'\0';
    commandLine[0] = L'\0';

    (void)BLACKBIRDGetBoolProperty(Record, L"isCreate", &isCreate);
    (void)BLACKBIRDGetI32Property(Record, L"createStatus", &createStatus);
    (void)BLACKBIRDGetU64Property(Record, L"processId", &processId);
    (void)BLACKBIRDGetU64Property(Record, L"parentProcessId", &parentPid);
    (void)BLACKBIRDGetU64Property(Record, L"creatorProcessId", &creatorPid);
    (void)BLACKBIRDGetU64Property(Record, L"creatorThreadId", &creatorTid);
    (void)BLACKBIRDGetU64Property(Record, L"processStartKey", &startKey);
    (void)BLACKBIRDGetU32Property(Record, L"sessionId", &sessionId);
    (void)BLACKBIRDGetWideProperty(Record, L"imagePath", imagePath, RTL_NUMBER_OF(imagePath));
    (void)BLACKBIRDGetWideProperty(Record, L"commandLine", commandLine, RTL_NUMBER_OF(commandLine));
    BLACKBIRDCacheProcessImage(processId, imagePath);

    wprintf(L"\n[PROCESS] %ls pid=%016llX parent=%016llX creator=%016llX/%016llX session=%lu\n",
            isCreate ? L"CREATE" : L"EXIT", processId, parentPid, creatorPid, creatorTid, sessionId);
    PrintHeaderMetadata(Record, L"ProcessTelemetry");
    wprintf(L"Status create=%hs(0x%08X) startKey=0x%016llX\n", NT_SUCCESS(createStatus) ? "SUCCESS" : "FAIL",
            (ULONG)createStatus, startKey);
    wprintf(L"Image  %ls\n", imagePath[0] ? imagePath : L"<unknown>");
    wprintf(L"Cmd    %ls\n", commandLine[0] ? commandLine : L"<none>");
}

static void PrintImageTelemetry(_In_ PEVENT_RECORD Record)
{
    ULONGLONG processId = 0;
    ULONGLONG imageBase = 0;
    ULONGLONG imageSize = 0;
    BOOL systemMode = FALSE;
    BOOL sigKnown = FALSE;
    UCHAR sigLevel = 0;
    UCHAR sigType = 0;
    WCHAR imagePath[1024];
    WCHAR imageSym[768];
    WCHAR processImage[MAX_PATH];

    imagePath[0] = L'\0';

    (void)BLACKBIRDGetU64Property(Record, L"processId", &processId);
    (void)BLACKBIRDGetU64Property(Record, L"imageBase", &imageBase);
    (void)BLACKBIRDGetU64Property(Record, L"imageSize", &imageSize);
    (void)BLACKBIRDGetBoolProperty(Record, L"isSystemModeImage", &systemMode);
    (void)BLACKBIRDGetBoolProperty(Record, L"isSignatureLevelKnown", &sigKnown);
    (void)BLACKBIRDGetU8Property(Record, L"signatureLevel", &sigLevel);
    (void)BLACKBIRDGetU8Property(Record, L"signatureType", &sigType);
    (void)BLACKBIRDGetWideProperty(Record, L"imagePath", imagePath, RTL_NUMBER_OF(imagePath));
    BLACKBIRDCacheProcessImage(processId, imagePath);
    BLACKBIRDEtwSymbolsCacheModuleForProcess((DWORD)processId, imageBase, imageSize, imagePath);

    BLACKBIRDEtwSymbolsFormatAddressForProcess((DWORD)processId, imageBase, imageSym, RTL_NUMBER_OF(imageSym));
    FormatProcessImage(processId, processImage, RTL_NUMBER_OF(processImage));

    wprintf(L"\n[IMAGE] pid=%016llX base=0x%016llX size=0x%llX\n", processId, imageBase, imageSize);
    PrintHeaderMetadata(Record, L"ImageTelemetry");
    wprintf(L"Actor  processImage=%ls\n", processImage);
    wprintf(L"Image  path=%ls\n", imagePath[0] ? imagePath : L"<unknown>");
    wprintf(L"       symbol=%ls\n", imageSym);
    wprintf(L"Trust  systemMode=%u sigKnown=%u sigLevel=%u sigType=%u\n", systemMode ? 1 : 0, sigKnown ? 1 : 0,
            (unsigned)sigLevel, (unsigned)sigType);
}

static void PrintRegistryTelemetry(_In_ PEVENT_RECORD Record)
{
    CHAR operation[64];
    ULONGLONG processId = 0;
    ULONG sessionId = 0;
    ULONG notifyClass = 0;
    ULONG dataType = 0;
    ULONG dataSize = 0;
    BOOL highValue = FALSE;
    WCHAR keyPath[1024];
    WCHAR valueName[256];
    WCHAR processImage[MAX_PATH];
    BOOL suppressible;

    operation[0] = '\0';
    keyPath[0] = L'\0';
    valueName[0] = L'\0';

    (void)BLACKBIRDGetAnsiProperty(Record, L"operation", operation, RTL_NUMBER_OF(operation));
    (void)BLACKBIRDGetU64Property(Record, L"processId", &processId);
    (void)BLACKBIRDGetU32Property(Record, L"sessionId", &sessionId);
    (void)BLACKBIRDGetU32Property(Record, L"notifyClass", &notifyClass);
    (void)BLACKBIRDGetU32Property(Record, L"dataType", &dataType);
    (void)BLACKBIRDGetU32Property(Record, L"dataSize", &dataSize);
    (void)BLACKBIRDGetBoolProperty(Record, L"isHighValuePath", &highValue);
    (void)BLACKBIRDGetWideProperty(Record, L"keyPath", keyPath, RTL_NUMBER_OF(keyPath));
    (void)BLACKBIRDGetWideProperty(Record, L"valueName", valueName, RTL_NUMBER_OF(valueName));

    FormatProcessImage(processId, processImage, RTL_NUMBER_OF(processImage));
    suppressible = BLACKBIRDRegistryIsSuppressible(operation, highValue);

    if (suppressible &&
        BLACKBIRDRegistrySuppressorMatches(&g_RegistrySuppressor, operation, processId, sessionId, notifyClass,
                                             dataType, dataSize, highValue, processImage, keyPath, valueName))
    {
        g_RegistrySuppressor.SuppressedCount += 1;
        return;
    }

    BLACKBIRDFlushRegistrySuppressor();

    wprintf(L"\n[REGISTRY] op=%S pid=%016llX session=%lu class=%ls(%lu)\n", operation[0] ? operation : "OTHER",
            processId, sessionId, RegistryNotifyClassToString(notifyClass), notifyClass);
    PrintHeaderMetadata(Record, L"RegistryTelemetry");
    wprintf(L"Actor  processImage=%ls\n", processImage);
    wprintf(L"Path   %ls\n", keyPath[0] ? keyPath : L"<unknown>");
    wprintf(L"Value  %ls\n", valueName[0] ? valueName : L"<none>");
    wprintf(L"Data   type=%lu size=%lu highValue=%u\n", dataType, dataSize, highValue ? 1 : 0);

    if (suppressible)
    {
        BLACKBIRDUpdateRegistrySuppressor(operation, processId, sessionId, notifyClass, dataType, dataSize, highValue,
                                            processImage, keyPath, valueName);
    }
    else
    {
        ZeroMemory(&g_RegistrySuppressor, sizeof(g_RegistrySuppressor));
    }
}

static void PrintDetectionTelemetry(_In_ PEVENT_RECORD Record)
{
    CHAR detectionName[128];
    ULONG severity = 0;
    ULONGLONG processId = 0;
    ULONGLONG targetPid = 0;
    ULONG correlationFlags = 0;
    ULONG correlationAccessMask = 0;
    ULONG correlationAgeMs = 0;
    WCHAR reason[1024];
    WCHAR corrFlagsText[128];
    WCHAR processImage[MAX_PATH];
    WCHAR targetImage[MAX_PATH];

    detectionName[0] = '\0';
    reason[0] = L'\0';

    (void)BLACKBIRDGetAnsiProperty(Record, L"detectionName", detectionName, RTL_NUMBER_OF(detectionName));
    (void)BLACKBIRDGetU32Property(Record, L"severity", &severity);
    (void)BLACKBIRDGetU64Property(Record, L"processId", &processId);
    (void)BLACKBIRDGetU64Property(Record, L"targetPid", &targetPid);
    (void)BLACKBIRDGetU32Property(Record, L"correlationFlags", &correlationFlags);
    (void)BLACKBIRDGetU32Property(Record, L"correlationAccessMask", &correlationAccessMask);
    (void)BLACKBIRDGetU32Property(Record, L"correlationAgeMs", &correlationAgeMs);
    (void)BLACKBIRDGetWideProperty(Record, L"reason", reason, RTL_NUMBER_OF(reason));

    FormatCorrelationFlags(correlationFlags, corrFlagsText, RTL_NUMBER_OF(corrFlagsText));
    FormatProcessImage(processId, processImage, RTL_NUMBER_OF(processImage));
    FormatProcessImage(targetPid, targetImage, RTL_NUMBER_OF(targetImage));

    wprintf(L"\n[DETECTION] name=%S severity=%lu pid=%016llX target=%016llX\n",
            detectionName[0] ? detectionName : "UNKNOWN", severity, processId, targetPid);
    PrintHeaderMetadata(Record, L"DetectionTelemetry");
    wprintf(L"Actor  processImage=%ls\n", processImage);
    wprintf(L"       targetImage=%ls\n", targetImage);
    wprintf(L"Corr   flags=0x%08lX (%ls) access=0x%08lX ageMs=%lu\n", correlationFlags, corrFlagsText,
            correlationAccessMask, correlationAgeMs);
    wprintf(L"Reason %ls\n", reason[0] ? reason : L"<none>");
}

void BLACKBIRDPrintEtwRecord(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR EventName)
{
    if (Record == NULL || EventName == NULL)
    {
        return;
    }

    if (wcscmp(EventName, L"RegistryTelemetry") != 0)
    {
        BLACKBIRDFlushRegistrySuppressor();
    }

    if (wcscmp(EventName, L"HandleTelemetry") == 0)
    {
        PrintHandleTelemetry(Record);
        return;
    }
    if (wcscmp(EventName, L"ThreadTelemetry") == 0)
    {
        PrintThreadTelemetry(Record);
        return;
    }
    if (wcscmp(EventName, L"ProcessTelemetry") == 0)
    {
        PrintProcessTelemetry(Record);
        return;
    }
    if (wcscmp(EventName, L"ImageTelemetry") == 0)
    {
        PrintImageTelemetry(Record);
        return;
    }
    if (wcscmp(EventName, L"RegistryTelemetry") == 0)
    {
        PrintRegistryTelemetry(Record);
        return;
    }
    if (wcscmp(EventName, L"DetectionTelemetry") == 0)
    {
        PrintDetectionTelemetry(Record);
        return;
    }

    wprintf(L"\n[ETW] event=%ls (no formatter)\n", EventName);
    PrintHeaderMetadata(Record, EventName);
}

void BLACKBIRDFlushEtwPrinterState(VOID)
{
    BLACKBIRDFlushRegistrySuppressor();
}

static BOOL BLACKBIRDTryGetU64Any(_In_ PEVENT_RECORD Record, _In_reads_(NameCount) const PCWSTR *Names,
                                    _In_ size_t NameCount, _Out_ ULONGLONG *Value)
{
    size_t i;

    if (Value == NULL)
    {
        return FALSE;
    }
    *Value = 0;

    for (i = 0; i < NameCount; ++i)
    {
        if (BLACKBIRDGetU64Property(Record, Names[i], Value))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL BLACKBIRDTryGetU32Any(_In_ PEVENT_RECORD Record, _In_reads_(NameCount) const PCWSTR *Names,
                                    _In_ size_t NameCount, _Out_ ULONG *Value)
{
    size_t i;

    if (Value == NULL)
    {
        return FALSE;
    }
    *Value = 0;

    for (i = 0; i < NameCount; ++i)
    {
        if (BLACKBIRDGetU32Property(Record, Names[i], Value))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL BLACKBIRDEventNameContainsInsensitive(_In_opt_z_ PCWSTR EventName, _In_z_ PCWSTR Needle)
{
    WCHAR eventLower[256];
    WCHAR needleLower[64];
    size_t i;

    if (EventName == NULL || Needle == NULL)
    {
        return FALSE;
    }

    (void)StringCchCopyW(eventLower, RTL_NUMBER_OF(eventLower), EventName);
    (void)StringCchCopyW(needleLower, RTL_NUMBER_OF(needleLower), Needle);

    for (i = 0; i < RTL_NUMBER_OF(eventLower); ++i)
    {
        eventLower[i] = (WCHAR)towlower(eventLower[i]);
        if (eventLower[i] == L'\0')
        {
            break;
        }
    }
    for (i = 0; i < RTL_NUMBER_OF(needleLower); ++i)
    {
        needleLower[i] = (WCHAR)towlower(needleLower[i]);
        if (needleLower[i] == L'\0')
        {
            break;
        }
    }

    return (wcsstr(eventLower, needleLower) != NULL);
}

void BLACKBIRDPrintThreatIntelRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName)
{
    static const PCWSTR callerPidNames[] = {L"CallingProcessId", L"CallerProcessId", L"SourceProcessId", L"ProcessId"};
    static const PCWSTR targetPidNames[] = {L"TargetProcessId", L"NewProcessId", L"DestProcessId", L"ProcessId"};
    static const PCWSTR targetTidNames[] = {L"TargetThreadId", L"NewThreadId", L"ThreadId"};
    static const PCWSTR startAddrNames[] = {L"StartAddress", L"ThreadStartAddress", L"Win32StartAddress"};
    static const PCWSTR routineNames[] = {L"ApcRoutine", L"NormalRoutine", L"Routine"};
    static const PCWSTR accessNames[] = {L"DesiredAccess", L"GrantedAccess", L"ThreadAccessMask"};

    ULONGLONG callerPid = 0;
    ULONGLONG targetPid = 0;
    ULONGLONG targetTid = 0;
    ULONGLONG startAddress = 0;
    ULONGLONG routineAddress = 0;
    ULONG desiredAccess = 0;
    WCHAR callerImage[MAX_PATH];
    WCHAR targetImage[MAX_PATH];
    WCHAR startSym[768];
    WCHAR routineSym[768];
    PCWSTR safeName;
    BOOL nameSuggestsCreateThread;
    BOOL nameSuggestsSetContext;
    BOOL nameSuggestsQueueApc;

    if (Record == NULL)
    {
        return;
    }

    safeName = (EventName != NULL && EventName[0] != L'\0') ? EventName : L"<unnamed-ti-event>";

    (void)BLACKBIRDTryGetU64Any(Record, callerPidNames, RTL_NUMBER_OF(callerPidNames), &callerPid);
    (void)BLACKBIRDTryGetU64Any(Record, targetPidNames, RTL_NUMBER_OF(targetPidNames), &targetPid);
    (void)BLACKBIRDTryGetU64Any(Record, targetTidNames, RTL_NUMBER_OF(targetTidNames), &targetTid);
    (void)BLACKBIRDTryGetU64Any(Record, startAddrNames, RTL_NUMBER_OF(startAddrNames), &startAddress);
    (void)BLACKBIRDTryGetU64Any(Record, routineNames, RTL_NUMBER_OF(routineNames), &routineAddress);
    (void)BLACKBIRDTryGetU32Any(Record, accessNames, RTL_NUMBER_OF(accessNames), &desiredAccess);

    FormatProcessImage(callerPid, callerImage, RTL_NUMBER_OF(callerImage));
    FormatProcessImage(targetPid, targetImage, RTL_NUMBER_OF(targetImage));
    FormatAddressWithImageHint((DWORD)targetPid, startAddress, targetImage, startSym, RTL_NUMBER_OF(startSym));
    FormatAddressWithImageHint((DWORD)targetPid, routineAddress, targetImage, routineSym, RTL_NUMBER_OF(routineSym));

    nameSuggestsCreateThread = BLACKBIRDEventNameContainsInsensitive(safeName, L"createthread") ||
                               BLACKBIRDEventNameContainsInsensitive(safeName, L"ntcreatethreadex");
    nameSuggestsSetContext = BLACKBIRDEventNameContainsInsensitive(safeName, L"setcontext") ||
                             BLACKBIRDEventNameContainsInsensitive(safeName, L"setthreadcontext");
    nameSuggestsQueueApc = BLACKBIRDEventNameContainsInsensitive(safeName, L"queueapc") ||
                           BLACKBIRDEventNameContainsInsensitive(safeName, L"insertqueueapc");

    wprintf(L"\n[ETW-TI] event=%ls\n", safeName);
    PrintHeaderMetadata(Record, safeName);
    wprintf(L"Actor  callerPid=%016llX image=%ls\n", callerPid, callerImage);
    wprintf(L"Target pid=%016llX image=%ls tid=%016llX access=0x%08lX\n", targetPid, targetImage, targetTid,
            desiredAccess);
    if (startAddress != 0)
    {
        wprintf(L"Start  0x%016llX (%ls)\n", startAddress, startSym);
    }
    if (routineAddress != 0)
    {
        wprintf(L"APC    routine=0x%016llX (%ls)\n", routineAddress, routineSym);
    }

    if (nameSuggestsCreateThread)
    {
        wprintf(L"Signal NtCreateThreadEx / remote-thread style TI event\n");
    }
    if (nameSuggestsSetContext)
    {
        wprintf(L"Signal thread-context modification TI event (hijack compatible)\n");
    }
    if (nameSuggestsQueueApc)
    {
        wprintf(L"Signal APC queue/insertion TI event\n");
    }
}
