#include <windows.h>
#include <strsafe.h>
#include <stdio.h>
#include <winnt.h>
#include "stinger_etw_printer.h"
#include "stinger_etw_props.h"
#include "stinger_etw_symbols.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _ACCESS_NAME_ENTRY {
    DWORD Mask;
    PCWSTR Name;
} ACCESS_NAME_ENTRY;

static const ACCESS_NAME_ENTRY g_ProcessAccessNames[] = {
    { PROCESS_TERMINATE, L"TERMINATE" },
    { PROCESS_CREATE_THREAD, L"CREATE_THREAD" },
    { PROCESS_SET_SESSIONID, L"SET_SESSIONID" },
    { PROCESS_VM_OPERATION, L"VM_OPERATION" },
    { PROCESS_VM_READ, L"VM_READ" },
    { PROCESS_VM_WRITE, L"VM_WRITE" },
    { PROCESS_DUP_HANDLE, L"DUP_HANDLE" },
    { PROCESS_CREATE_PROCESS, L"CREATE_PROCESS" },
    { PROCESS_SET_QUOTA, L"SET_QUOTA" },
    { PROCESS_SET_INFORMATION, L"SET_INFORMATION" },
    { PROCESS_QUERY_INFORMATION, L"QUERY_INFORMATION" },
    { PROCESS_SUSPEND_RESUME, L"SUSPEND_RESUME" },
    { PROCESS_QUERY_LIMITED_INFORMATION, L"QUERY_LIMITED_INFO" },
    { SYNCHRONIZE, L"SYNCHRONIZE" }
};

static void
AppendFlag(
    _Inout_updates_z_(OutputChars) PWSTR Output,
    _In_ size_t OutputChars,
    _In_z_ PCWSTR FlagName,
    _Inout_ BOOL* First
)
{
    if (!*First) {
        (void)StringCchCatW(Output, OutputChars, L"|");
    }
    (void)StringCchCatW(Output, OutputChars, FlagName);
    *First = FALSE;
}

static void
FormatProcessAccessMask(
    _In_ DWORD DesiredAccess,
    _Out_writes_z_(OutputChars) PWSTR Output,
    _In_ size_t OutputChars
)
{
    DWORD i;
    BOOL first = TRUE;

    if (OutputChars == 0) {
        return;
    }
    Output[0] = L'\0';

    if (DesiredAccess == PROCESS_ALL_ACCESS) {
        (void)StringCchCopyW(Output, OutputChars, L"PROCESS_ALL_ACCESS");
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(g_ProcessAccessNames); ++i) {
        if ((DesiredAccess & g_ProcessAccessNames[i].Mask) == g_ProcessAccessNames[i].Mask) {
            AppendFlag(Output, OutputChars, g_ProcessAccessNames[i].Name, &first);
        }
    }

    if (first) {
        (void)StringCchCopyW(Output, OutputChars, L"<none>");
    }
}

static void
FormatProtect(
    _In_ DWORD Protect,
    _Out_writes_z_(OutputChars) PWSTR Output,
    _In_ size_t OutputChars
)
{
    BOOL first = TRUE;

    if (OutputChars == 0) {
        return;
    }
    Output[0] = L'\0';

    if (Protect & PAGE_GUARD) {
        AppendFlag(Output, OutputChars, L"GUARD", &first);
    }
    if (Protect & PAGE_NOCACHE) {
        AppendFlag(Output, OutputChars, L"NOCACHE", &first);
    }
    if (Protect & PAGE_WRITECOMBINE) {
        AppendFlag(Output, OutputChars, L"WRITECOMBINE", &first);
    }

    switch (Protect & 0xFF) {
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

    if (first) {
        (void)StringCchCopyW(Output, OutputChars, L"<unknown>");
    }
}

static void
FormatHandleClass(
    _In_z_ PCSTR EventClass,
    _Out_writes_z_(OutputChars) PWSTR Output,
    _In_ size_t OutputChars
)
{
    if (OutputChars == 0) {
        return;
    }
    Output[0] = L'\0';

    if (EventClass == NULL || EventClass[0] == '\0') {
        (void)StringCchCopyW(Output, OutputChars, L"UNKNOWN");
        return;
    }

    if (_stricmp(EventClass, "DIRECT-SYSCALL-SUSPECT") == 0) {
        (void)StringCchCopyW(Output, OutputChars, L"DIRECT-SYSCALL-SUSPECT");
    } else if (_stricmp(EventClass, "LEGITIMATE-SYSCALL") == 0) {
        (void)StringCchCopyW(Output, OutputChars, L"LEGITIMATE-SYSCALL");
    } else {
        (void)StringCchPrintfW(Output, OutputChars, L"%S", EventClass);
    }
}

static void
FormatProcessImage(
    _In_ ULONGLONG Pid,
    _Out_writes_z_(OutputChars) PWSTR Output,
    _In_ size_t OutputChars
)
{
    HANDLE process;
    DWORD size;

    if (OutputChars == 0) {
        return;
    }
    Output[0] = L'\0';

    if (Pid == 0) {
        (void)StringCchCopyW(Output, OutputChars, L"<pid:0>");
        return;
    }

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)Pid);
    if (process == NULL) {
        (void)StringCchPrintfW(Output, OutputChars, L"<pid:%llu inaccessible>", Pid);
        return;
    }

    size = (DWORD)OutputChars;
    if (!QueryFullProcessImageNameW(process, 0, Output, &size)) {
        (void)StringCchPrintfW(Output, OutputChars, L"<pid:%llu image-unknown>", Pid);
    }
    CloseHandle(process);
}

static void
PrintStack(
    _In_ PEVENT_RECORD Record,
    _In_ ULONG Count
)
{
    ULONG i;
    WCHAR name[16];

    for (i = 0; i < Count && i < 8; ++i) {
        ULONGLONG addr = 0;
        WCHAR resolved[768];
        (void)StringCchPrintfW(name, RTL_NUMBER_OF(name), L"stack%lu", i);
        if (!STINGERGetU64Property(Record, name, &addr)) {
            continue;
        }
        STINGEREtwSymbolsFormatAddress(addr, resolved, RTL_NUMBER_OF(resolved));
        wprintf(L"       #%lu 0x%016llX (%ls)\n", i, addr, resolved);
    }
}

static void
PrintHeaderMetadata(
    _In_ PEVENT_RECORD Record,
    _In_z_ PCWSTR EventName
)
{
    static ULONGLONG s_LastTimestamp = 0;
    ULONGLONG currentTs = (ULONGLONG)Record->EventHeader.TimeStamp.QuadPart;
    ULONGLONG delta = 0;
    if (s_LastTimestamp != 0 && currentTs >= s_LastTimestamp) {
        delta = currentTs - s_LastTimestamp;
    }
    s_LastTimestamp = currentTs;

    wprintf(
        L"Meta   event=%ls pid=%lu tid=%lu cpu=%u lvl=%u op=%u ver=%u ts=0x%016llX dt=0x%llX\n",
        EventName,
        Record->EventHeader.ProcessId,
        Record->EventHeader.ThreadId,
        Record->BufferContext.ProcessorNumber,
        Record->EventHeader.EventDescriptor.Level,
        Record->EventHeader.EventDescriptor.Opcode,
        Record->EventHeader.EventDescriptor.Version,
        currentTs,
        delta
    );
}

static void
PrintHandleTelemetry(_In_ PEVENT_RECORD Record)
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

    eventClass[0] = '\0';
    path[0] = L'\0';
    classW[0] = L'\0';

    (void)STINGERGetAnsiProperty(Record, L"class", eventClass, RTL_NUMBER_OF(eventClass));
    (void)STINGERGetU64Property(Record, L"callerPid", &callerPid);
    (void)STINGERGetU64Property(Record, L"targetPid", &targetPid);
    (void)STINGERGetU32Property(Record, L"desiredAccess", &desiredAccess);
    (void)STINGERGetU64Property(Record, L"originAddress", &originAddress);
    (void)STINGERGetU32Property(Record, L"originProtect", &originProtect);
    (void)STINGERGetBoolProperty(Record, L"execProtect", &execProtect);
    (void)STINGERGetBoolProperty(Record, L"fromNtdll", &fromNtdll);
    (void)STINGERGetBoolProperty(Record, L"fromExe", &fromExe);
    (void)STINGERGetWideProperty(Record, L"originPath", path, RTL_NUMBER_OF(path));
    (void)STINGERGetU32Property(Record, L"frameCount", &frameCount);
    (void)STINGERGetI32Property(Record, L"statusOpenProcess", &statusOpen);
    (void)STINGERGetI32Property(Record, L"statusBasicInfo", &statusBasic);
    (void)STINGERGetI32Property(Record, L"statusSectionName", &statusSection);

    FormatHandleClass(eventClass, classW, RTL_NUMBER_OF(classW));
    FormatProcessAccessMask(desiredAccess, accessText, RTL_NUMBER_OF(accessText));
    FormatProtect(originProtect, protectText, RTL_NUMBER_OF(protectText));
    STINGEREtwSymbolsFormatAddress(originAddress, originSym, RTL_NUMBER_OF(originSym));
    FormatProcessImage(callerPid, callerImage, RTL_NUMBER_OF(callerImage));
    FormatProcessImage(targetPid, targetImage, RTL_NUMBER_OF(targetImage));

    wprintf(L"\n[HANDLE] %ls  %016llX -> %016llX  access=0x%08lX (%ls)\n",
        classW,
        callerPid,
        targetPid,
        desiredAccess,
        accessText);
    PrintHeaderMetadata(Record, L"HandleTelemetry");
    wprintf(L"Actor  callerImage=%ls\n", callerImage);
    wprintf(L"       targetImage=%ls\n", targetImage);
    wprintf(
        L"Origin addr=0x%016llX (%ls)\n",
        originAddress,
        originSym
    );
    wprintf(
        L"       path=%ls\n",
        path[0] ? path : L"<unknown>"
    );
    wprintf(
        L"       protect=0x%08lX (%ls) exec=%u fromNtdll=%u fromExe=%u\n",
        originProtect,
        protectText,
        execProtect ? 1 : 0,
        fromNtdll ? 1 : 0,
        fromExe ? 1 : 0
    );
    wprintf(
        L"Status open=%hs(0x%08X) basic=%hs(0x%08X) section=%hs(0x%08X)\n",
        NT_SUCCESS(statusOpen) ? "SUCCESS" : "FAIL", (ULONG)statusOpen,
        NT_SUCCESS(statusBasic) ? "SUCCESS" : "FAIL", (ULONG)statusBasic,
        NT_SUCCESS(statusSection) ? "SUCCESS" : "FAIL", (ULONG)statusSection
    );
    wprintf(L"Stack  frames=%lu\n", frameCount);
    PrintStack(Record, frameCount);

    if (_stricmp(eventClass, "DIRECT-SYSCALL-SUSPECT") == 0) {
        wprintf(L"Alert  direct-syscall-suspect classification observed\n");
    }
}

static void
PrintThreadTelemetry(_In_ PEVENT_RECORD Record)
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
    ULONG frameCount = 0;
    WCHAR startSym[768];
    WCHAR imageSym[768];
    WCHAR processImage[MAX_PATH];
    WCHAR creatorImage[MAX_PATH];

    (void)STINGERGetU64Property(Record, L"processId", &processId);
    (void)STINGERGetU64Property(Record, L"threadId", &threadId);
    (void)STINGERGetU64Property(Record, L"creatorPid", &creatorPid);
    (void)STINGERGetU64Property(Record, L"startAddress", &startAddress);
    (void)STINGERGetU64Property(Record, L"imageBase", &imageBase);
    (void)STINGERGetU64Property(Record, L"imageSize", &imageSize);
    (void)STINGERGetBoolProperty(Record, L"gotStart", &gotStart);
    (void)STINGERGetBoolProperty(Record, L"gotRange", &gotRange);
    (void)STINGERGetBoolProperty(Record, L"isRemoteCreator", &isRemote);
    (void)STINGERGetBoolProperty(Record, L"outsideMainImage", &outsideImage);
    (void)STINGERGetU32Property(Record, L"workerFrameCount", &frameCount);

    STINGEREtwSymbolsFormatAddress(startAddress, startSym, RTL_NUMBER_OF(startSym));
    STINGEREtwSymbolsFormatAddress(imageBase, imageSym, RTL_NUMBER_OF(imageSym));
    FormatProcessImage(processId, processImage, RTL_NUMBER_OF(processImage));
    FormatProcessImage(creatorPid, creatorImage, RTL_NUMBER_OF(creatorImage));

    wprintf(L"\n[THREAD] pid=%016llX tid=%016llX creator=%016llX\n", processId, threadId, creatorPid);
    PrintHeaderMetadata(Record, L"ThreadTelemetry");
    wprintf(
        L"Flags  remote=%u outsideMainImage=%u gotStart=%u gotRange=%u\n",
        isRemote ? 1 : 0,
        outsideImage ? 1 : 0,
        gotStart ? 1 : 0,
        gotRange ? 1 : 0
    );
    wprintf(L"Actor  processImage=%ls\n", processImage);
    wprintf(L"       creatorImage=%ls\n", creatorImage);
    wprintf(
        L"Start  0x%016llX (%ls)\n",
        startAddress,
        startSym
    );
    wprintf(
        L"Image  base=0x%016llX (%ls) size=0x%llX\n",
        imageBase,
        imageSym,
        imageSize
    );
    wprintf(L"Stack  frames=%lu\n", frameCount);
    PrintStack(Record, frameCount);
    if (outsideImage) {
        wprintf(L"Alert  thread start is outside main image range\n");
    }
}

void
STINGERPrintEtwRecord(
    _In_ PEVENT_RECORD Record,
    _In_z_ PCWSTR EventName
)
{
    if (Record == NULL || EventName == NULL) {
        return;
    }

    if (wcscmp(EventName, L"HandleTelemetry") == 0) {
        PrintHandleTelemetry(Record);
        return;
    }
    if (wcscmp(EventName, L"ThreadTelemetry") == 0) {
        PrintThreadTelemetry(Record);
        return;
    }
}
