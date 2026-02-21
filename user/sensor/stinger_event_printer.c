#include <stdio.h>
#include "stinger_event_printer.h"
#include "stinger_symbol_resolver.h"

typedef struct _MASK_NAME_ENTRY {
    UINT32 Bit;
    const char* Name;
} MASK_NAME_ENTRY;

static const MASK_NAME_ENTRY g_StreamMaskNames[] = {
    { STINGER_STREAM_HANDLE, "HANDLE" },
    { STINGER_STREAM_MEMORY, "MEMORY" },
    { STINGER_STREAM_THREAD, "THREAD" }
};

static const char*
STINGERHandleClassToString(UINT32 classId)
{
    if (classId == StingerHandleClassLegitimateSyscall) {
        return "LEGITIMATE-SYSCALL";
    }
    if (classId == StingerHandleClassDirectSyscallSuspect) {
        return "DIRECT-SYSCALL-SUSPECT";
    }
    return "UNKNOWN";
}

static void
STINGEREventTypeToString(UINT32 type, char* output, size_t outputChars)
{
    if (output == NULL || outputChars == 0) {
        return;
    }

    if (type == StingerEventTypeHandle) {
        (void)snprintf(output, outputChars, "HANDLE");
    } else if (type == StingerEventTypeThread) {
        (void)snprintf(output, outputChars, "THREAD");
    } else {
        (void)snprintf(output, outputChars, "UNKNOWN(%u)", type);
    }
}

static void
STINGERFormatStreamMask(UINT32 mask, char* output, size_t outputChars)
{
    UINT32 i;
    int wrote = 0;

    if (output == NULL || outputChars == 0) {
        return;
    }
    output[0] = '\0';

    for (i = 0; i < (UINT32)(sizeof(g_StreamMaskNames) / sizeof(g_StreamMaskNames[0])); ++i) {
        if ((mask & g_StreamMaskNames[i].Bit) == 0) {
            continue;
        }

        if (wrote > 0) {
            wrote += snprintf(output + wrote, outputChars - (size_t)wrote, "|");
        }
        wrote += snprintf(output + wrote, outputChars - (size_t)wrote, "%s", g_StreamMaskNames[i].Name);
        if (wrote < 0 || (size_t)wrote >= outputChars) {
            break;
        }
    }

    if (output[0] == '\0') {
        (void)snprintf(output, outputChars, "<none>");
    }
}

static void
STINGERPrintHandleFlags(UINT32 flags)
{
    printf("Flags  ");
    if (flags == 0) {
        printf("<none>\n");
        return;
    }
    if ((flags & STINGER_HANDLE_FLAG_EXEC_PROTECT) != 0) {
        printf("ExecProtect ");
    }
    if ((flags & STINGER_HANDLE_FLAG_FROM_NTDLL) != 0) {
        printf("FromNtdll ");
    }
    if ((flags & STINGER_HANDLE_FLAG_FROM_EXE) != 0) {
        printf("FromExe ");
    }
    if ((flags & STINGER_HANDLE_FLAG_MEMORY_RELATED) != 0) {
        printf("MemoryRelated ");
    }
    printf("\n");
}

static void
STINGERPrintThreadFlags(UINT32 flags)
{
    printf("Flags  ");
    if (flags == 0) {
        printf("<none>\n");
        return;
    }
    if ((flags & STINGER_THREAD_FLAG_GOT_START) != 0) {
        printf("GotStart ");
    }
    if ((flags & STINGER_THREAD_FLAG_GOT_RANGE) != 0) {
        printf("GotRange ");
    }
    if ((flags & STINGER_THREAD_FLAG_REMOTE_CREATOR) != 0) {
        printf("RemoteCreator ");
    }
    if ((flags & STINGER_THREAD_FLAG_OUTSIDE_MAIN_IMG) != 0) {
        printf("OutsideMainImage ");
    }
    printf("\n");
}

static void
STINGERPrintAddressLine(const char* label, UINT64 address)
{
    printf("%-6s ", label);
    STINGERSymbolResolverPrintAddress(address);
    printf("\n");
}

static void
STINGERPrintFrames(const UINT64* frames, UINT32 count)
{
    UINT32 i;
    UINT32 limit = (count > STINGER_MAX_EVENT_FRAMES) ? STINGER_MAX_EVENT_FRAMES : count;

    printf("Stack  frames=%u\n", limit);
    if (limit == 0) {
        printf("       <none>\n");
        return;
    }

    for (i = 0; i < limit; ++i) {
        printf("       #%u ", i);
        STINGERSymbolResolverPrintAddress(frames[i]);
        printf("\n");
    }
}

static void
STINGERPrintHandleEvent(const STINGER_EVENT_RECORD* rec)
{
    const STINGER_HANDLE_EVENT* h = &rec->Data.Handle;

    printf("[IOCTL][HANDLE] class=%s(%u) caller=%llu target=%llu access=0x%08X\n",
        STINGERHandleClassToString(h->ClassId),
        h->ClassId,
        (unsigned long long)h->CallerPid,
        (unsigned long long)h->TargetPid,
        h->DesiredAccess);
    STINGERPrintHandleFlags(h->Flags);
    printf("Path   %ls\n", (h->OriginPath[0] != L'\0') ? h->OriginPath : L"<none>");
    printf("Mem    protect=0x%08X\n", h->OriginProtect);
    STINGERPrintAddressLine("Origin", h->OriginAddress);
    printf("Status open=0x%08X basic=0x%08X section=0x%08X\n",
        (UINT32)h->StatusOpenProcess,
        (UINT32)h->StatusBasicInfo,
        (UINT32)h->StatusSectionName);
    STINGERPrintFrames(h->Frames, h->FrameCount);
}

static void
STINGERPrintThreadEvent(const STINGER_EVENT_RECORD* rec)
{
    const STINGER_THREAD_EVENT* t = &rec->Data.Thread;

    printf("[IOCTL][THREAD] process=%llu thread=%llu creator=%llu\n",
        (unsigned long long)t->ProcessId,
        (unsigned long long)t->ThreadId,
        (unsigned long long)t->CreatorPid);
    STINGERPrintThreadFlags(t->Flags);
    STINGERPrintAddressLine("Start", t->StartAddress);
    STINGERPrintAddressLine("Image", t->ImageBase);
    printf("Size   imageSize=0x%llX\n", (unsigned long long)t->ImageSize);
    STINGERPrintFrames(t->Frames, t->FrameCount);
}

static void
STINGERPrintHeader(const STINGER_EVENT_RECORD* rec)
{
    char typeName[32];
    char maskName[64];

    STINGEREventTypeToString(rec->Header.Type, typeName, sizeof(typeName));
    STINGERFormatStreamMask(rec->Header.StreamMask, maskName, sizeof(maskName));

    printf("\n[IOCTL][EVENT] seq=%u type=%s stream=0x%08X(%s) size=%u qpc=%lld\n",
        rec->Header.Sequence,
        typeName,
        rec->Header.StreamMask,
        maskName,
        rec->Header.Size,
        (long long)rec->Header.TimestampQpc);
}

void
STINGEREventPrinterPrintRecord(const STINGER_EVENT_RECORD* rec)
{
    if (rec == NULL) {
        return;
    }

    STINGERPrintHeader(rec);

    if (rec->Header.Type == StingerEventTypeHandle) {
        STINGERPrintHandleEvent(rec);
    } else if (rec->Header.Type == StingerEventTypeThread) {
        STINGERPrintThreadEvent(rec);
    } else {
        printf("[IOCTL][UNKNOWN] event type=%u\n", rec->Header.Type);
    }
}
