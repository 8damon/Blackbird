#include <stdio.h>
#include "sleepwalker_event_printer.h"
#include "sleepwalker_symbol_resolver.h"

typedef struct _MASK_NAME_ENTRY
{
    UINT32 Bit;
    const char *Name;
} MASK_NAME_ENTRY;

static const MASK_NAME_ENTRY g_StreamMaskNames[] = {{SLEEPWALKER_STREAM_HANDLE, "HANDLE"},
                                                    {SLEEPWALKER_STREAM_MEMORY, "MEMORY"},
                                                    {SLEEPWALKER_STREAM_THREAD, "THREAD"}};

static const char *SLEEPWALKERHandleClassToString(UINT32 classId)
{
    if (classId == SleepwalkerHandleClassLegitimateSyscall)
    {
        return "LEGITIMATE-SYSCALL";
    }
    if (classId == SleepwalkerHandleClassDirectSyscallSuspect)
    {
        return "DIRECT-SYSCALL-SUSPECT";
    }
    return "UNKNOWN";
}

static void SLEEPWALKEREventTypeToString(UINT32 type, char *output, size_t outputChars)
{
    if (output == NULL || outputChars == 0)
    {
        return;
    }

    if (type == SleepwalkerEventTypeHandle)
    {
        (void)snprintf(output, outputChars, "HANDLE");
    }
    else if (type == SleepwalkerEventTypeThread)
    {
        (void)snprintf(output, outputChars, "THREAD");
    }
    else
    {
        (void)snprintf(output, outputChars, "UNKNOWN(%u)", type);
    }
}

static void SLEEPWALKERFormatStreamMask(UINT32 mask, char *output, size_t outputChars)
{
    UINT32 i;
    int wrote = 0;

    if (output == NULL || outputChars == 0)
    {
        return;
    }
    output[0] = '\0';

    for (i = 0; i < (UINT32)(sizeof(g_StreamMaskNames) / sizeof(g_StreamMaskNames[0])); ++i)
    {
        if ((mask & g_StreamMaskNames[i].Bit) == 0)
        {
            continue;
        }

        if (wrote > 0)
        {
            wrote += snprintf(output + wrote, outputChars - (size_t)wrote, "|");
        }
        wrote += snprintf(output + wrote, outputChars - (size_t)wrote, "%s", g_StreamMaskNames[i].Name);
        if (wrote < 0 || (size_t)wrote >= outputChars)
        {
            break;
        }
    }

    if (output[0] == '\0')
    {
        (void)snprintf(output, outputChars, "<none>");
    }
}

static void SLEEPWALKERPrintHandleFlags(UINT32 flags)
{
    printf("Flags  ");
    if (flags == 0)
    {
        printf("<none>\n");
        return;
    }
    if ((flags & SLEEPWALKER_HANDLE_FLAG_EXEC_PROTECT) != 0)
    {
        printf("ExecProtect ");
    }
    if ((flags & SLEEPWALKER_HANDLE_FLAG_FROM_NTDLL) != 0)
    {
        printf("FromNtdll ");
    }
    if ((flags & SLEEPWALKER_HANDLE_FLAG_FROM_EXE) != 0)
    {
        printf("FromExe ");
    }
    if ((flags & SLEEPWALKER_HANDLE_FLAG_MEMORY_RELATED) != 0)
    {
        printf("MemoryRelated ");
    }
    if ((flags & SLEEPWALKER_HANDLE_FLAG_THREAD_OBJECT) != 0)
    {
        printf("ThreadObject ");
    }
    if ((flags & SLEEPWALKER_HANDLE_FLAG_DUPLICATE_OPERATION) != 0)
    {
        printf("DuplicateOp ");
    }
    if ((flags & SLEEPWALKER_HANDLE_FLAG_RETURN_ADDRESS_VALID) != 0)
    {
        printf("ReturnAddressValid ");
    }
    if ((flags & SLEEPWALKER_HANDLE_FLAG_STACK_VALIDATED) != 0)
    {
        printf("StackValidated ");
    }
    if ((flags & SLEEPWALKER_HANDLE_FLAG_STACK_SPOOF_SUSPECT) != 0)
    {
        printf("StackSpoofSuspect ");
    }
    if ((flags & SLEEPWALKER_HANDLE_FLAG_SYSCALL_EXPORT_MATCH) != 0)
    {
        printf("SyscallExportMatch ");
    }
    if ((flags & SLEEPWALKER_HANDLE_FLAG_SYSCALL_EXPORT_MISMATCH) != 0)
    {
        printf("SyscallExportMismatch ");
    }
    if ((flags & SLEEPWALKER_HANDLE_FLAG_MODULE_CHAIN_SANE) != 0)
    {
        printf("ModuleChainSane ");
    }
    if ((flags & SLEEPWALKER_HANDLE_FLAG_UNWIND_METADATA_VALID) != 0)
    {
        printf("UnwindMetadataValid ");
    }
    if ((flags & SLEEPWALKER_HANDLE_FLAG_TEB_STACK_BOUNDS_VALID) != 0)
    {
        printf("TebStackBoundsValid ");
    }
    if ((flags & SLEEPWALKER_HANDLE_FLAG_FRAMES_OUTSIDE_TEB_STACK) != 0)
    {
        printf("FramesOutsideTebStack ");
    }
    printf("\n");
}

static void SLEEPWALKERPrintThreadFlags(UINT32 flags)
{
    printf("Flags  ");
    if (flags == 0)
    {
        printf("<none>\n");
        return;
    }
    if ((flags & SLEEPWALKER_THREAD_FLAG_GOT_START) != 0)
    {
        printf("GotStart ");
    }
    if ((flags & SLEEPWALKER_THREAD_FLAG_GOT_RANGE) != 0)
    {
        printf("GotRange ");
    }
    if ((flags & SLEEPWALKER_THREAD_FLAG_REMOTE_CREATOR) != 0)
    {
        printf("RemoteCreator ");
    }
    if ((flags & SLEEPWALKER_THREAD_FLAG_OUTSIDE_MAIN_IMG) != 0)
    {
        printf("OutsideMainImage ");
    }
    if ((flags & SLEEPWALKER_THREAD_FLAG_CORRELATED_INTENT) != 0)
    {
        printf("CorrelatedIntent ");
    }
    if ((flags & SLEEPWALKER_THREAD_FLAG_CORR_MEMORY) != 0)
    {
        printf("IntentProcessMemory ");
    }
    if ((flags & SLEEPWALKER_THREAD_FLAG_CORR_THREAD_CTX) != 0)
    {
        printf("IntentThreadContext ");
    }
    if ((flags & SLEEPWALKER_THREAD_FLAG_CORR_DUP_HANDLE) != 0)
    {
        printf("IntentDupHandle ");
    }
    if ((flags & SLEEPWALKER_THREAD_FLAG_START_REGION_EXEC) != 0)
    {
        printf("StartRegionExec ");
    }
    printf("\n");
}

static void SLEEPWALKERPrintAddressLine(const char *label, UINT64 address)
{
    printf("%-6s ", label);
    SLEEPWALKERSymbolResolverPrintAddress(address);
    printf("\n");
}

static void SLEEPWALKERPrintFrames(const UINT64 *frames, UINT32 count)
{
    UINT32 i;
    UINT32 limit = (count > SLEEPWALKER_MAX_EVENT_FRAMES) ? SLEEPWALKER_MAX_EVENT_FRAMES : count;

    printf("Stack  frames=%u\n", limit);
    if (limit == 0)
    {
        printf("       <none>\n");
        return;
    }

    for (i = 0; i < limit; ++i)
    {
        printf("       #%u ", i);
        SLEEPWALKERSymbolResolverPrintAddress(frames[i]);
        printf("\n");
    }
}

static void SLEEPWALKERPrintHandleEvent(const SLEEPWALKER_EVENT_RECORD *rec)
{
    const SLEEPWALKER_HANDLE_EVENT *h = &rec->Data.Handle;

    printf("[IOCTL][HANDLE] class=%s(%u) caller=%llu target=%llu access=0x%08X\n",
           SLEEPWALKERHandleClassToString(h->ClassId), h->ClassId, (unsigned long long)h->CallerPid,
           (unsigned long long)h->TargetPid, h->DesiredAccess);
    SLEEPWALKERPrintHandleFlags(h->Flags);
    printf("Path   %ls\n", (h->OriginPath[0] != L'\0') ? h->OriginPath : L"<none>");
    printf("Mem    protect=0x%08X\n", h->OriginProtect);
    SLEEPWALKERPrintAddressLine("Origin", h->OriginAddress);
    printf("Status open=0x%08X basic=0x%08X section=0x%08X\n", (UINT32)h->StatusOpenProcess, (UINT32)h->StatusBasicInfo,
           (UINT32)h->StatusSectionName);
    SLEEPWALKERPrintFrames(h->Frames, h->FrameCount);
}

static void SLEEPWALKERPrintThreadEvent(const SLEEPWALKER_EVENT_RECORD *rec)
{
    const SLEEPWALKER_THREAD_EVENT *t = &rec->Data.Thread;

    printf("[IOCTL][THREAD] process=%llu thread=%llu creator=%llu\n", (unsigned long long)t->ProcessId,
           (unsigned long long)t->ThreadId, (unsigned long long)t->CreatorPid);
    SLEEPWALKERPrintThreadFlags(t->Flags);
    SLEEPWALKERPrintAddressLine("Start", t->StartAddress);
    SLEEPWALKERPrintAddressLine("Image", t->ImageBase);
    printf("Size   imageSize=0x%llX\n", (unsigned long long)t->ImageSize);
    SLEEPWALKERPrintFrames(t->Frames, t->FrameCount);
}

static void SLEEPWALKERPrintHeader(const SLEEPWALKER_EVENT_RECORD *rec)
{
    char typeName[32];
    char maskName[64];

    SLEEPWALKEREventTypeToString(rec->Header.Type, typeName, sizeof(typeName));
    SLEEPWALKERFormatStreamMask(rec->Header.StreamMask, maskName, sizeof(maskName));

    printf("\n[IOCTL][EVENT] seq=%u type=%s stream=0x%08X(%s) size=%u qpc=%lld\n", rec->Header.Sequence, typeName,
           rec->Header.StreamMask, maskName, rec->Header.Size, (long long)rec->Header.TimestampQpc);
}

void SLEEPWALKEREventPrinterPrintRecord(const SLEEPWALKER_EVENT_RECORD *rec)
{
    if (rec == NULL)
    {
        return;
    }

    SLEEPWALKERPrintHeader(rec);

    if (rec->Header.Type == SleepwalkerEventTypeHandle)
    {
        SLEEPWALKERPrintHandleEvent(rec);
    }
    else if (rec->Header.Type == SleepwalkerEventTypeThread)
    {
        SLEEPWALKERPrintThreadEvent(rec);
    }
    else
    {
        printf("[IOCTL][UNKNOWN] event type=%u\n", rec->Header.Type);
    }
}
