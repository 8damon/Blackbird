#include <stdio.h>
#include "blackbird_event_printer.h"
#include "blackbird_symbol_resolver.h"

typedef struct _MASK_NAME_ENTRY
{
    UINT32 Bit;
    const char *Name;
} MASK_NAME_ENTRY;

static const MASK_NAME_ENTRY g_StreamMaskNames[] = { { BLACKBIRD_STREAM_HANDLE, "HANDLE" },
                                                     { BLACKBIRD_STREAM_MEMORY, "MEMORY" },
                                                     { BLACKBIRD_STREAM_THREAD, "THREAD" },
                                                     { BLACKBIRD_STREAM_FILESYSTEM, "FILESYSTEM" } };

static const char *BLACKBIRDHandleClassToString(UINT32 classId)
{
    if (classId == BlackbirdHandleClassLegitimateSyscall)
    {
        return "LEGITIMATE-SYSCALL";
    }
    if (classId == BlackbirdHandleClassDirectSyscallSuspect)
    {
        return "DIRECT-SYSCALL-SUSPECT";
    }
    return "UNKNOWN";
}

static void BLACKBIRDEventTypeToString(UINT32 type, char *output, size_t outputChars)
{
    if (output == NULL || outputChars == 0)
    {
        return;
    }

    if (type == BlackbirdEventTypeHandle)
    {
        (void) snprintf(output, outputChars, "HANDLE");
    }
    else if (type == BlackbirdEventTypeThread)
    {
        (void) snprintf(output, outputChars, "THREAD");
    }
    else if (type == BlackbirdEventTypeFileSystem)
    {
        (void) snprintf(output, outputChars, "FILESYSTEM");
    }
    else
    {
        (void) snprintf(output, outputChars, "UNKNOWN(%u)", type);
    }
}

static void BLACKBIRDFormatStreamMask(UINT32 mask, char *output, size_t outputChars)
{
    UINT32 i;
    int wrote = 0;

    if (output == NULL || outputChars == 0)
    {
        return;
    }
    output[0] = '\0';

    for (i = 0; i < (UINT32) (sizeof(g_StreamMaskNames) / sizeof(g_StreamMaskNames[0])); ++i)
    {
        if ((mask & g_StreamMaskNames[i].Bit) == 0)
        {
            continue;
        }

        if (wrote > 0)
        {
            wrote += snprintf(output + wrote, outputChars - (size_t) wrote, "|");
        }
        wrote += snprintf(output + wrote, outputChars - (size_t) wrote, "%s", g_StreamMaskNames[i].Name);
        if (wrote < 0 || (size_t) wrote >= outputChars)
        {
            break;
        }
    }

    if (output[0] == '\0')
    {
        (void) snprintf(output, outputChars, "<none>");
    }
}

static void BLACKBIRDPrintHandleFlags(UINT32 flags)
{
    printf("Flags  ");
    if (flags == 0)
    {
        printf("<none>\n");
        return;
    }
    if ((flags & BLACKBIRD_HANDLE_FLAG_EXEC_PROTECT) != 0)
    {
        printf("ExecProtect ");
    }
    if ((flags & BLACKBIRD_HANDLE_FLAG_FROM_NTDLL) != 0)
    {
        printf("FromNtdll ");
    }
    if ((flags & BLACKBIRD_HANDLE_FLAG_FROM_EXE) != 0)
    {
        printf("FromExe ");
    }
    if ((flags & BLACKBIRD_HANDLE_FLAG_MEMORY_RELATED) != 0)
    {
        printf("MemoryRelated ");
    }
    if ((flags & BLACKBIRD_HANDLE_FLAG_THREAD_OBJECT) != 0)
    {
        printf("ThreadObject ");
    }
    if ((flags & BLACKBIRD_HANDLE_FLAG_DUPLICATE_OPERATION) != 0)
    {
        printf("DuplicateOp ");
    }
    if ((flags & BLACKBIRD_HANDLE_FLAG_RETURN_ADDRESS_VALID) != 0)
    {
        printf("ReturnAddressValid ");
    }
    if ((flags & BLACKBIRD_HANDLE_FLAG_STACK_VALIDATED) != 0)
    {
        printf("StackValidated ");
    }
    if ((flags & BLACKBIRD_HANDLE_FLAG_STACK_SPOOF_SUSPECT) != 0)
    {
        printf("StackSpoofSuspect ");
    }
    if ((flags & BLACKBIRD_HANDLE_FLAG_SYSCALL_EXPORT_MATCH) != 0)
    {
        printf("SyscallExportMatch ");
    }
    if ((flags & BLACKBIRD_HANDLE_FLAG_SYSCALL_EXPORT_MISMATCH) != 0)
    {
        printf("SyscallExportMismatch ");
    }
    if ((flags & BLACKBIRD_HANDLE_FLAG_MODULE_CHAIN_SANE) != 0)
    {
        printf("ModuleChainSane ");
    }
    if ((flags & BLACKBIRD_HANDLE_FLAG_UNWIND_METADATA_VALID) != 0)
    {
        printf("UnwindMetadataValid ");
    }
    if ((flags & BLACKBIRD_HANDLE_FLAG_TEB_STACK_BOUNDS_VALID) != 0)
    {
        printf("TebStackBoundsValid ");
    }
    if ((flags & BLACKBIRD_HANDLE_FLAG_FRAMES_OUTSIDE_TEB_STACK) != 0)
    {
        printf("FramesOutsideTebStack ");
    }
    printf("\n");
}

static void BLACKBIRDPrintThreadFlags(UINT32 flags)
{
    printf("Flags  ");
    if (flags == 0)
    {
        printf("<none>\n");
        return;
    }
    if ((flags & BLACKBIRD_THREAD_FLAG_GOT_START) != 0)
    {
        printf("GotStart ");
    }
    if ((flags & BLACKBIRD_THREAD_FLAG_GOT_RANGE) != 0)
    {
        printf("GotRange ");
    }
    if ((flags & BLACKBIRD_THREAD_FLAG_REMOTE_CREATOR) != 0)
    {
        printf("RemoteCreator ");
    }
    if ((flags & BLACKBIRD_THREAD_FLAG_OUTSIDE_MAIN_IMG) != 0)
    {
        printf("OutsideMainImage ");
    }
    if ((flags & BLACKBIRD_THREAD_FLAG_CORRELATED_INTENT) != 0)
    {
        printf("CorrelatedIntent ");
    }
    if ((flags & BLACKBIRD_THREAD_FLAG_CORR_MEMORY) != 0)
    {
        printf("IntentProcessMemory ");
    }
    if ((flags & BLACKBIRD_THREAD_FLAG_CORR_THREAD_CTX) != 0)
    {
        printf("IntentThreadContext ");
    }
    if ((flags & BLACKBIRD_THREAD_FLAG_CORR_DUP_HANDLE) != 0)
    {
        printf("IntentDupHandle ");
    }
    if ((flags & BLACKBIRD_THREAD_FLAG_START_REGION_EXEC) != 0)
    {
        printf("StartRegionExec ");
    }
    printf("\n");
}

static void BLACKBIRDPrintAddressLine(const char *label, UINT64 address)
{
    printf("%-6s ", label);
    BLACKBIRDSymbolResolverPrintAddress(address);
    printf("\n");
}

static void BLACKBIRDPrintFrames(const UINT64 *frames, UINT32 count)
{
    UINT32 i;
    UINT32 limit = (count > BLACKBIRD_MAX_EVENT_FRAMES) ? BLACKBIRD_MAX_EVENT_FRAMES : count;

    printf("Stack  frames=%u\n", limit);
    if (limit == 0)
    {
        printf("       <none>\n");
        return;
    }

    for (i = 0; i < limit; ++i)
    {
        printf("       #%u ", i);
        BLACKBIRDSymbolResolverPrintAddress(frames[i]);
        printf("\n");
    }
}

static void BLACKBIRDPrintHandleEvent(const BLACKBIRD_EVENT_RECORD *rec)
{
    const BLACKBIRD_HANDLE_EVENT *h = &rec->Data.Handle;

    printf("[IOCTL][HANDLE] class=%s(%u) caller=%llu target=%llu access=0x%08X\n",
           BLACKBIRDHandleClassToString(h->ClassId),
           h->ClassId,
           (unsigned long long) h->CallerPid,
           (unsigned long long) h->TargetPid,
           h->DesiredAccess);
    BLACKBIRDPrintHandleFlags(h->Flags);
    printf("Path   %ls\n", (h->OriginPath[0] != L'\0') ? h->OriginPath : L"<none>");
    printf("Mem    protect=0x%08X\n", h->OriginProtect);
    BLACKBIRDPrintAddressLine("Origin", h->OriginAddress);
    printf("Status open=0x%08X basic=0x%08X section=0x%08X\n",
           (UINT32) h->StatusOpenProcess,
           (UINT32) h->StatusBasicInfo,
           (UINT32) h->StatusSectionName);
    BLACKBIRDPrintFrames(h->Frames, h->FrameCount);
}

static void BLACKBIRDPrintThreadEvent(const BLACKBIRD_EVENT_RECORD *rec)
{
    const BLACKBIRD_THREAD_EVENT *t = &rec->Data.Thread;

    printf("[IOCTL][THREAD] process=%llu thread=%llu creator=%llu\n",
           (unsigned long long) t->ProcessId,
           (unsigned long long) t->ThreadId,
           (unsigned long long) t->CreatorPid);
    BLACKBIRDPrintThreadFlags(t->Flags);
    BLACKBIRDPrintAddressLine("Start", t->StartAddress);
    BLACKBIRDPrintAddressLine("Image", t->ImageBase);
    printf("Size   imageSize=0x%llX\n", (unsigned long long) t->ImageSize);
    BLACKBIRDPrintFrames(t->Frames, t->FrameCount);
}

static const char *BLACKBIRDFileOperationToString(UINT32 op)
{
    switch (op)
    {
        case BlackbirdFileOperationCreate:
            return "CREATE";
        case BlackbirdFileOperationRead:
            return "READ";
        case BlackbirdFileOperationWrite:
            return "WRITE";
        case BlackbirdFileOperationClose:
            return "CLOSE";
        case BlackbirdFileOperationCleanup:
            return "CLEANUP";
        case BlackbirdFileOperationSetInformation:
            return "SET_INFORMATION";
        case BlackbirdFileOperationQueryInformation:
            return "QUERY_INFO";
        case BlackbirdFileOperationDirectoryControl:
            return "DIRECTORY_CONTROL";
        case BlackbirdFileOperationFsControl:
            return "FS_CONTROL";
        default:
            return "UNKNOWN";
    }
}

static void BLACKBIRDPrintFileEvent(const BLACKBIRD_EVENT_RECORD *rec)
{
    const BLACKBIRD_FILE_EVENT *f = &rec->Data.FileSystem;

    printf("[IOCTL][FILESYSTEM] op=%s(%u) process=%llu thread=%llu status=0x%08llX info=0x%llX\n",
           BLACKBIRDFileOperationToString(f->Operation),
           f->Operation,
           (unsigned long long) f->ProcessId,
           (unsigned long long) f->ThreadId,
           (unsigned long long) f->Status,
           (unsigned long long) f->Information);
    printf("Path   %ls\n", (f->Path[0] != L'\0') ? f->Path : L"<none>");
    printf("IO     major=%u minor=%u irpFlags=0x%08X flags=0x%08X\n",
           f->MajorCode,
           f->MinorCode,
           f->IrpFlags,
           f->Flags);
    printf("Range  offset=0x%llX length=0x%llX\n", (unsigned long long) f->ByteOffset, (unsigned long long) f->Length);
    printf("Create desired=0x%08X share=0x%08X disp=%u options=0x%08X\n",
           f->DesiredAccess,
           f->ShareAccess,
           f->CreateDisposition,
           f->CreateOptions);
}

static void BLACKBIRDPrintHeader(const BLACKBIRD_EVENT_RECORD *rec)
{
    char typeName[32];
    char maskName[64];

    BLACKBIRDEventTypeToString(rec->Header.Type, typeName, sizeof(typeName));
    BLACKBIRDFormatStreamMask(rec->Header.StreamMask, maskName, sizeof(maskName));

    printf("\n[IOCTL][EVENT] seq=%u type=%s stream=0x%08X(%s) size=%u qpc=%lld\n",
           rec->Header.Sequence,
           typeName,
           rec->Header.StreamMask,
           maskName,
           rec->Header.Size,
           (long long) rec->Header.TimestampQpc);
}

void BLACKBIRDEventPrinterPrintRecord(const BLACKBIRD_EVENT_RECORD *rec)
{
    if (rec == NULL)
    {
        return;
    }

    BLACKBIRDPrintHeader(rec);

    if (rec->Header.Type == BlackbirdEventTypeHandle)
    {
        BLACKBIRDPrintHandleEvent(rec);
    }
    else if (rec->Header.Type == BlackbirdEventTypeThread)
    {
        BLACKBIRDPrintThreadEvent(rec);
    }
    else if (rec->Header.Type == BlackbirdEventTypeFileSystem)
    {
        BLACKBIRDPrintFileEvent(rec);
    }
    else
    {
        printf("[IOCTL][UNKNOWN] event type=%u\n", rec->Header.Type);
    }
}
