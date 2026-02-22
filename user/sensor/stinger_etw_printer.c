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

#define STINGER_INTENT_PROCESS_MEMORY 0x00000001
#define STINGER_INTENT_THREAD_CONTEXT 0x00000002
#define STINGER_INTENT_DUP_HANDLE     0x00000004

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
FormatMemState(
    _In_ ULONG State,
    _Out_writes_z_(OutputChars) PWSTR Output,
    _In_ size_t OutputChars
)
{
    if (OutputChars == 0) {
        return;
    }

    if (State == MEM_COMMIT) {
        (void)StringCchCopyW(Output, OutputChars, L"COMMIT");
    } else if (State == MEM_RESERVE) {
        (void)StringCchCopyW(Output, OutputChars, L"RESERVE");
    } else if (State == MEM_FREE) {
        (void)StringCchCopyW(Output, OutputChars, L"FREE");
    } else {
        (void)StringCchPrintfW(Output, OutputChars, L"0x%08lX", State);
    }
}

static void
FormatMemType(
    _In_ ULONG Type,
    _Out_writes_z_(OutputChars) PWSTR Output,
    _In_ size_t OutputChars
)
{
    if (OutputChars == 0) {
        return;
    }

    if (Type == MEM_IMAGE) {
        (void)StringCchCopyW(Output, OutputChars, L"IMAGE");
    } else if (Type == MEM_MAPPED) {
        (void)StringCchCopyW(Output, OutputChars, L"MAPPED");
    } else if (Type == MEM_PRIVATE) {
        (void)StringCchCopyW(Output, OutputChars, L"PRIVATE");
    } else {
        (void)StringCchPrintfW(Output, OutputChars, L"0x%08lX", Type);
    }
}

static void
FormatCorrelationFlags(
    _In_ ULONG Flags,
    _Out_writes_z_(OutputChars) PWSTR Output,
    _In_ size_t OutputChars
)
{
    BOOL first = TRUE;

    if (OutputChars == 0) {
        return;
    }
    Output[0] = L'\0';

    if ((Flags & STINGER_INTENT_PROCESS_MEMORY) != 0) {
        AppendFlag(Output, OutputChars, L"ProcessMemory", &first);
    }
    if ((Flags & STINGER_INTENT_THREAD_CONTEXT) != 0) {
        AppendFlag(Output, OutputChars, L"ThreadContext", &first);
    }
    if ((Flags & STINGER_INTENT_DUP_HANDLE) != 0) {
        AppendFlag(Output, OutputChars, L"DuplicateHandle", &first);
    }

    if (first) {
        (void)StringCchCopyW(Output, OutputChars, L"<none>");
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

static PCWSTR
RegistryNotifyClassToString(
    _In_ ULONG NotifyClass
)
{
    switch (NotifyClass) {
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
    (void)STINGERGetU32Property(Record, L"correlationFlags", &correlationFlags);
    (void)STINGERGetU32Property(Record, L"correlationAccessMask", &correlationAccessMask);
    (void)STINGERGetU32Property(Record, L"correlationAgeMs", &correlationAgeMs);
    (void)STINGERGetU32Property(Record, L"startRegionProtect", &startRegionProtect);
    (void)STINGERGetU32Property(Record, L"startRegionState", &startRegionState);
    (void)STINGERGetU32Property(Record, L"startRegionType", &startRegionType);
    (void)STINGERGetI32Property(Record, L"startRegionStatus", &startRegionStatus);
    (void)STINGERGetU32Property(Record, L"workerFrameCount", &frameCount);

    STINGEREtwSymbolsFormatAddress(startAddress, startSym, RTL_NUMBER_OF(startSym));
    STINGEREtwSymbolsFormatAddress(imageBase, imageSym, RTL_NUMBER_OF(imageSym));
    FormatProcessImage(processId, processImage, RTL_NUMBER_OF(processImage));
    FormatProcessImage(creatorPid, creatorImage, RTL_NUMBER_OF(creatorImage));
    FormatCorrelationFlags(correlationFlags, corrFlagsText, RTL_NUMBER_OF(corrFlagsText));
    FormatProtect(startRegionProtect, startProtectText, RTL_NUMBER_OF(startProtectText));
    FormatMemState(startRegionState, startStateText, RTL_NUMBER_OF(startStateText));
    FormatMemType(startRegionType, startTypeText, RTL_NUMBER_OF(startTypeText));

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
    wprintf(
        L"Corr   flags=0x%08lX (%ls) access=0x%08lX ageMs=%lu\n",
        correlationFlags,
        corrFlagsText,
        correlationAccessMask,
        correlationAgeMs
    );
    wprintf(
        L"StartR status=%hs(0x%08X) protect=0x%08lX (%ls) state=%ls type=%ls\n",
        NT_SUCCESS(startRegionStatus) ? "SUCCESS" : "FAIL",
        (ULONG)startRegionStatus,
        startRegionProtect,
        startProtectText,
        startStateText,
        startTypeText
    );
    wprintf(L"Stack  frames=%lu\n", frameCount);
    PrintStack(Record, frameCount);
    if (outsideImage) {
        wprintf(L"Alert  thread start is outside main image range\n");
    }
    if (correlationFlags != 0) {
        wprintf(L"Alert  thread event has recent handle-intent correlation\n");
    }
}

static void
PrintProcessTelemetry(_In_ PEVENT_RECORD Record)
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

    (void)STINGERGetBoolProperty(Record, L"isCreate", &isCreate);
    (void)STINGERGetI32Property(Record, L"createStatus", &createStatus);
    (void)STINGERGetU64Property(Record, L"processId", &processId);
    (void)STINGERGetU64Property(Record, L"parentProcessId", &parentPid);
    (void)STINGERGetU64Property(Record, L"creatorProcessId", &creatorPid);
    (void)STINGERGetU64Property(Record, L"creatorThreadId", &creatorTid);
    (void)STINGERGetU64Property(Record, L"processStartKey", &startKey);
    (void)STINGERGetU32Property(Record, L"sessionId", &sessionId);
    (void)STINGERGetWideProperty(Record, L"imagePath", imagePath, RTL_NUMBER_OF(imagePath));
    (void)STINGERGetWideProperty(Record, L"commandLine", commandLine, RTL_NUMBER_OF(commandLine));

    wprintf(
        L"\n[PROCESS] %ls pid=%016llX parent=%016llX creator=%016llX/%016llX session=%lu\n",
        isCreate ? L"CREATE" : L"EXIT",
        processId,
        parentPid,
        creatorPid,
        creatorTid,
        sessionId
    );
    PrintHeaderMetadata(Record, L"ProcessTelemetry");
    wprintf(
        L"Status create=%hs(0x%08X) startKey=0x%016llX\n",
        NT_SUCCESS(createStatus) ? "SUCCESS" : "FAIL",
        (ULONG)createStatus,
        startKey
    );
    wprintf(L"Image  %ls\n", imagePath[0] ? imagePath : L"<unknown>");
    wprintf(L"Cmd    %ls\n", commandLine[0] ? commandLine : L"<none>");
}

static void
PrintImageTelemetry(_In_ PEVENT_RECORD Record)
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

    (void)STINGERGetU64Property(Record, L"processId", &processId);
    (void)STINGERGetU64Property(Record, L"imageBase", &imageBase);
    (void)STINGERGetU64Property(Record, L"imageSize", &imageSize);
    (void)STINGERGetBoolProperty(Record, L"isSystemModeImage", &systemMode);
    (void)STINGERGetBoolProperty(Record, L"isSignatureLevelKnown", &sigKnown);
    (void)STINGERGetU8Property(Record, L"signatureLevel", &sigLevel);
    (void)STINGERGetU8Property(Record, L"signatureType", &sigType);
    (void)STINGERGetWideProperty(Record, L"imagePath", imagePath, RTL_NUMBER_OF(imagePath));

    STINGEREtwSymbolsFormatAddress(imageBase, imageSym, RTL_NUMBER_OF(imageSym));
    FormatProcessImage(processId, processImage, RTL_NUMBER_OF(processImage));

    wprintf(L"\n[IMAGE] pid=%016llX base=0x%016llX size=0x%llX\n", processId, imageBase, imageSize);
    PrintHeaderMetadata(Record, L"ImageTelemetry");
    wprintf(L"Actor  processImage=%ls\n", processImage);
    wprintf(L"Image  path=%ls\n", imagePath[0] ? imagePath : L"<unknown>");
    wprintf(L"       symbol=%ls\n", imageSym);
    wprintf(
        L"Trust  systemMode=%u sigKnown=%u sigLevel=%u sigType=%u\n",
        systemMode ? 1 : 0,
        sigKnown ? 1 : 0,
        (unsigned)sigLevel,
        (unsigned)sigType
    );
}

static void
PrintRegistryTelemetry(_In_ PEVENT_RECORD Record)
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

    operation[0] = '\0';
    keyPath[0] = L'\0';
    valueName[0] = L'\0';

    (void)STINGERGetAnsiProperty(Record, L"operation", operation, RTL_NUMBER_OF(operation));
    (void)STINGERGetU64Property(Record, L"processId", &processId);
    (void)STINGERGetU32Property(Record, L"sessionId", &sessionId);
    (void)STINGERGetU32Property(Record, L"notifyClass", &notifyClass);
    (void)STINGERGetU32Property(Record, L"dataType", &dataType);
    (void)STINGERGetU32Property(Record, L"dataSize", &dataSize);
    (void)STINGERGetBoolProperty(Record, L"isHighValuePath", &highValue);
    (void)STINGERGetWideProperty(Record, L"keyPath", keyPath, RTL_NUMBER_OF(keyPath));
    (void)STINGERGetWideProperty(Record, L"valueName", valueName, RTL_NUMBER_OF(valueName));

    FormatProcessImage(processId, processImage, RTL_NUMBER_OF(processImage));

    wprintf(
        L"\n[REGISTRY] op=%S pid=%016llX session=%lu class=%ls(%lu)\n",
        operation[0] ? operation : "OTHER",
        processId,
        sessionId,
        RegistryNotifyClassToString(notifyClass),
        notifyClass
    );
    PrintHeaderMetadata(Record, L"RegistryTelemetry");
    wprintf(L"Actor  processImage=%ls\n", processImage);
    wprintf(L"Path   %ls\n", keyPath[0] ? keyPath : L"<unknown>");
    wprintf(L"Value  %ls\n", valueName[0] ? valueName : L"<none>");
    wprintf(
        L"Data   type=%lu size=%lu highValue=%u\n",
        dataType,
        dataSize,
        highValue ? 1 : 0
    );
}

static void
PrintDetectionTelemetry(_In_ PEVENT_RECORD Record)
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

    (void)STINGERGetAnsiProperty(Record, L"detectionName", detectionName, RTL_NUMBER_OF(detectionName));
    (void)STINGERGetU32Property(Record, L"severity", &severity);
    (void)STINGERGetU64Property(Record, L"processId", &processId);
    (void)STINGERGetU64Property(Record, L"targetPid", &targetPid);
    (void)STINGERGetU32Property(Record, L"correlationFlags", &correlationFlags);
    (void)STINGERGetU32Property(Record, L"correlationAccessMask", &correlationAccessMask);
    (void)STINGERGetU32Property(Record, L"correlationAgeMs", &correlationAgeMs);
    (void)STINGERGetWideProperty(Record, L"reason", reason, RTL_NUMBER_OF(reason));

    FormatCorrelationFlags(correlationFlags, corrFlagsText, RTL_NUMBER_OF(corrFlagsText));
    FormatProcessImage(processId, processImage, RTL_NUMBER_OF(processImage));
    FormatProcessImage(targetPid, targetImage, RTL_NUMBER_OF(targetImage));

    wprintf(
        L"\n[DETECTION] name=%S severity=%lu pid=%016llX target=%016llX\n",
        detectionName[0] ? detectionName : "UNKNOWN",
        severity,
        processId,
        targetPid
    );
    PrintHeaderMetadata(Record, L"DetectionTelemetry");
    wprintf(L"Actor  processImage=%ls\n", processImage);
    wprintf(L"       targetImage=%ls\n", targetImage);
    wprintf(
        L"Corr   flags=0x%08lX (%ls) access=0x%08lX ageMs=%lu\n",
        correlationFlags,
        corrFlagsText,
        correlationAccessMask,
        correlationAgeMs
    );
    wprintf(L"Reason %ls\n", reason[0] ? reason : L"<none>");
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
    if (wcscmp(EventName, L"ProcessTelemetry") == 0) {
        PrintProcessTelemetry(Record);
        return;
    }
    if (wcscmp(EventName, L"ImageTelemetry") == 0) {
        PrintImageTelemetry(Record);
        return;
    }
    if (wcscmp(EventName, L"RegistryTelemetry") == 0) {
        PrintRegistryTelemetry(Record);
        return;
    }
    if (wcscmp(EventName, L"DetectionTelemetry") == 0) {
        PrintDetectionTelemetry(Record);
        return;
    }

    wprintf(L"\n[ETW] event=%ls (no formatter)\n", EventName);
    PrintHeaderMetadata(Record, EventName);
}
