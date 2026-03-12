#include "blackbird_client_internal.h"

void PrintUsage(void)
{
    printf("Usage: blackbird_client.exe shutdown\n");
    printf("Usage: blackbird_client.exe [--config <file>] [--broker-pipe <name>] [--log-format text|jsonl] [--log-file <path>]\n");
    printf("                             [--high-priority-file <path>] [--high-priority-min-severity <0-10>]\n");
    printf("                             [--ioctl-verbose 0|1] <target> <streams> [scope]\n");
    printf("target: PID | pid:<PID> | pid=<PID> | name:process.exe | name=process.exe | process.exe | path:<full-path> "
           "| path=<full-path> | launch:<full-path>\n");
    printf("streams: handle,memory,thread,filesystem[,etw]\n");
    printf("scope: local (default) | remote | both\n");
    printf("transport is service-broker IPC (BlackbirdController) only.\n");
    printf("config file supports key:value or key=value (YAML-like flat keys)\n");
    printf("keys: target, streams, scope, log.format, log.file, log.high_priority_file,\n");
    printf("      log.high_priority_min_severity, output.ioctl_verbose,\n");
    printf("      filter.ioctl.handle, filter.ioctl.thread, filter.ioctl.filesystem,\n");
    printf("      filter.etw.blackbird, filter.etw.ti\n");
    printf("example: blackbird_client.exe shutdown\n");
    printf("example: blackbird_client.exe notepad.exe handle,thread,filesystem\n");
    printf("example: blackbird_client.exe --log-format jsonl --log-file events.swk.jsonl notepad.exe handle,memory,thread,filesystem\n");
    printf("example: blackbird_client.exe notepad.exe handle,memory,thread,filesystem,etw\n");
    printf("example: blackbird_client.exe path:C:\\Windows\\System32\\notepad.exe handle,memory,thread,filesystem\n");
    printf("example: blackbird_client.exe launch:C:\\Windows\\System32\\notepad.exe handle,memory,thread,filesystem\n");
    printf("example: blackbird_client.exe 4242 handle,memory,thread,filesystem both\n");
}

static const char *HandleClassToString(DWORD classId)
{
    switch (classId)
    {
    case BlackbirdHandleClassLegitimateSyscall:
        return "LEGITIMATE-SYSCALL";
    case BlackbirdHandleClassDirectSyscallSuspect:
        return "DIRECT-SYSCALL-SUSPECT";
    default:
        return "UNKNOWN-ORIGIN";
    }
}

static BOOL WideContainsInsensitive(_In_opt_z_ const WCHAR *Haystack, _In_z_ const WCHAR *Needle)
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

static const char *ComputeUserModeHandleClass(_In_ const BLACKBIRD_HANDLE_EVENT *h,
                                              _In_z_ const WCHAR *OriginResolved)
{
    BOOL fromKnownSyscallStub;
    BOOL execProtect;
    BOOL fromExe;

    if (h == NULL)
    {
        return "UNKNOWN-ORIGIN";
    }

    fromKnownSyscallStub = ((h->Flags & BLACKBIRD_HANDLE_FLAG_FROM_NTDLL) != 0) ||
                           WideContainsInsensitive(OriginResolved, L"ntdll!") ||
                           WideContainsInsensitive(OriginResolved, L"ntdll+") ||
                           WideContainsInsensitive(OriginResolved, L"win32u!") ||
                           WideContainsInsensitive(OriginResolved, L"win32u+") ||
                           WideContainsInsensitive(h->OriginPath, L"ntdll.dll") ||
                           WideContainsInsensitive(h->OriginPath, L"win32u.dll");
    execProtect = ((h->Flags & BLACKBIRD_HANDLE_FLAG_EXEC_PROTECT) != 0);
    fromExe = ((h->Flags & BLACKBIRD_HANDLE_FLAG_FROM_EXE) != 0);

    if (execProtect && fromKnownSyscallStub)
    {
        return "LEGITIMATE-SYSCALL";
    }
    if (execProtect && !fromKnownSyscallStub && (fromExe || h->OriginPath[0] == L'\0'))
    {
        return "DIRECT-SYSCALL-SUSPECT";
    }
    return "UNKNOWN-ORIGIN";
}

static double ComputeShannonEntropy(_In_reads_bytes_(Size) const BYTE *Data, _In_ DWORD Size)
{
    DWORD i;
    UINT32 counts[256];
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
        if (counts[i] != 0)
        {
            double p = ((double)counts[i]) / ((double)Size);
            entropy -= p * (log(p) / log(2.0));
        }
    }
    return entropy;
}

static void FormatOpcodePreviewA(_In_reads_bytes_(Size) const BYTE *Data, _In_ DWORD Size,
                                 _Out_writes_z_(OutputChars) char *Output, _In_ size_t OutputChars)
{
    DWORD i;
    DWORD limit;

    if (Output == NULL || OutputChars == 0)
    {
        return;
    }
    Output[0] = '\0';

    if (Data == NULL || Size == 0)
    {
        (void)StringCchCopyA(Output, OutputChars, "<none>");
        return;
    }

    limit = (Size > 16) ? 16 : Size;
    for (i = 0; i < limit; ++i)
    {
        char chunk[8];
        (void)StringCchPrintfA(chunk, RTL_NUMBER_OF(chunk), (i == 0) ? "%02X" : " %02X", Data[i]);
        (void)StringCchCatA(Output, OutputChars, chunk);
    }
    if (Size > limit)
    {
        (void)StringCchCatA(Output, OutputChars, " ...");
    }
}

static void PrintHandleFlags(_In_ DWORD flags)
{
    printf("flags=");
    if (flags == 0)
    {
        printf("<none>");
    }
    else
    {
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
        if ((flags & BLACKBIRD_HANDLE_FLAG_DEEP_PATH_CANDIDATE) != 0)
        {
            printf("DeepCandidate ");
        }
        if ((flags & BLACKBIRD_HANDLE_FLAG_DEEP_PATH_CAPTURED) != 0)
        {
            printf("DeepCaptured ");
        }
        if ((flags & BLACKBIRD_HANDLE_FLAG_DEEP_PATH_CACHE_HIT) != 0)
        {
            printf("DeepCacheHit ");
        }
    }
    printf("\n");
}

static void PrintThreadFlags(_In_ DWORD flags)
{
    printf("flags=");
    if (flags == 0)
    {
        printf("<none>");
    }
    else
    {
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
    }
    printf("\n");
}

static const char *FileOperationToString(_In_ UINT32 operation)
{
    switch (operation)
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
        return "QUERY_INFORMATION";
    case BlackbirdFileOperationDirectoryControl:
        return "DIRECTORY_CONTROL";
    case BlackbirdFileOperationFsControl:
        return "FS_CONTROL";
    default:
        return "UNKNOWN";
    }
}

static void PrintFileFlags(_In_ DWORD flags)
{
    printf("fileFlags=");
    if (flags == 0)
    {
        printf("<none>");
    }
    else
    {
        if ((flags & BLACKBIRD_FILE_FLAG_PRE_OPERATION) != 0)
        {
            printf("PreOp ");
        }
        if ((flags & BLACKBIRD_FILE_FLAG_POST_OPERATION) != 0)
        {
            printf("PostOp ");
        }
        if ((flags & BLACKBIRD_FILE_FLAG_PAGING_IO) != 0)
        {
            printf("PagingIo ");
        }
        if ((flags & BLACKBIRD_FILE_FLAG_SYNCHRONOUS_IO) != 0)
        {
            printf("SyncIo ");
        }
        if ((flags & BLACKBIRD_FILE_FLAG_NON_CACHED_IO) != 0)
        {
            printf("NonCached ");
        }
        if ((flags & BLACKBIRD_FILE_FLAG_DIRECTORY_FILE) != 0)
        {
            printf("Directory ");
        }
        if ((flags & BLACKBIRD_FILE_FLAG_DELETE_ON_CLOSE) != 0)
        {
            printf("DeleteOnClose ");
        }
        if ((flags & BLACKBIRD_FILE_FLAG_REPARSE_POINT) != 0)
        {
            printf("ReparsePoint ");
        }
        if ((flags & BLACKBIRD_FILE_FLAG_FAST_IO) != 0)
        {
            printf("FastIo ");
        }
    }
    printf("\n");
}

static void PrintResolvedFrames(_In_ DWORD ProcessId, _In_reads_(FrameCount) const UINT64 *Frames,
                                _In_ DWORD FrameCount)
{
    DWORD i;
    DWORD limit = (FrameCount > BLACKBIRD_MAX_EVENT_FRAMES) ? BLACKBIRD_MAX_EVENT_FRAMES : FrameCount;

    printf("stackFrames=%lu\n", limit);
    for (i = 0; i < limit; ++i)
    {
        WCHAR resolved[768];
        BLACKBIRDEtwSymbolsFormatAddressForProcess(ProcessId, Frames[i], resolved, RTL_NUMBER_OF(resolved));
        wprintf(L"  #%lu 0x%016llX (%ls)\n", i, (unsigned long long)Frames[i], resolved);
    }
}

BOOL IoctlRecordMatchesTargetPid(_In_ const BLACKBIRD_EVENT_RECORD *Record, _In_ DWORD TargetPid,
                                 _In_ BLACKBIRD_TARGET_SCOPE Scope)
{
    BOOL localMatch = FALSE;
    BOOL remoteMatch = FALSE;

    if (Record == NULL || TargetPid == 0)
    {
        return FALSE;
    }

    if (Record->Header.Type == BlackbirdEventTypeHandle)
    {
        DWORD caller = (DWORD)Record->Data.Handle.CallerPid;
        DWORD target = (DWORD)Record->Data.Handle.TargetPid;
        localMatch = (caller == TargetPid);
        remoteMatch = (target == TargetPid);
        return ScopeMatches(Scope, localMatch, remoteMatch);
    }

    if (Record->Header.Type == BlackbirdEventTypeThread)
    {
        DWORD process = (DWORD)Record->Data.Thread.ProcessId;
        DWORD creator = (DWORD)Record->Data.Thread.CreatorPid;
        localMatch = (creator == TargetPid);
        remoteMatch = (process == TargetPid);
        return ScopeMatches(Scope, localMatch, remoteMatch);
    }

    if (Record->Header.Type == BlackbirdEventTypeFileSystem)
    {
        DWORD process = (DWORD)Record->Data.FileSystem.ProcessId;
        localMatch = (process == TargetPid);
        remoteMatch = FALSE;
        return ScopeMatches(Scope, localMatch, remoteMatch);
    }

    return FALSE;
}

void PrintHandleEvent(_In_ const BLACKBIRD_HANDLE_EVENT *h, _In_ DWORD sequence)
{
    WCHAR originResolved[768];
    const char *userClass;
    BOOL flagFromNtdll;
    BOOL originResolvedAsNtdll;
    char deepOpcodes[128];
    double deepEntropy = 0.0;

    BLACKBIRDEtwSymbolsFormatAddressForProcess((DWORD)h->CallerPid, h->OriginAddress, originResolved,
                                                 RTL_NUMBER_OF(originResolved));
    flagFromNtdll = ((h->Flags & BLACKBIRD_HANDLE_FLAG_FROM_NTDLL) != 0);
    originResolvedAsNtdll =
        WideContainsInsensitive(originResolved, L"ntdll!") || WideContainsInsensitive(originResolved, L"ntdll+");
    userClass = ComputeUserModeHandleClass(h, originResolved);
    deepOpcodes[0] = '\0';
    if (h->DeepSampleSize != 0)
    {
        deepEntropy = ComputeShannonEntropy(h->DeepSample, h->DeepSampleSize);
        FormatOpcodePreviewA(h->DeepSample, h->DeepSampleSize, deepOpcodes, RTL_NUMBER_OF(deepOpcodes));
    }

    printf("[BLACKBIRD][HANDLE] seq=%lu\n", sequence);
    printf("class=%s callerPid=%016llX targetPid=%016llX access=0x%08X\n", userClass, (unsigned long long)h->CallerPid,
           (unsigned long long)h->TargetPid, h->DesiredAccess);
    wprintf(L"origin=0x%016llX (%ls)\n", (unsigned long long)h->OriginAddress, originResolved);
    wprintf(L"path=%ls\n", h->OriginPath[0] ? h->OriginPath : L"<unknown>");
    printf("protect=0x%08X\n", h->OriginProtect);
    PrintHandleFlags(h->Flags);
    printf("statusOpen=0x%08X statusBasic=0x%08X statusSection=0x%08X\n", (unsigned int)h->StatusOpenProcess,
           (unsigned int)h->StatusBasicInfo, (unsigned int)h->StatusSectionName);
    if (h->DeepAllocationBase != 0 || h->DeepRegionSize != 0 || h->DeepSampleSize != 0)
    {
        printf("deep allocBase=0x%016llX regionSize=0x%016llX protect=0x%08X state=0x%08X type=0x%08X\n",
               (unsigned long long)h->DeepAllocationBase, (unsigned long long)h->DeepRegionSize, h->DeepRegionProtect,
               h->DeepRegionState, h->DeepRegionType);
        printf("deep sampleSize=%u entropy=%.3f opcodes=%s\n", h->DeepSampleSize, deepEntropy,
               (h->DeepSampleSize != 0) ? deepOpcodes : "<none>");
    }
    PrintResolvedFrames((DWORD)h->CallerPid, h->Frames, h->FrameCount);

    if (flagFromNtdll != originResolvedAsNtdll)
    {
        printf("[WARN] fromNtdll flag mismatch: flag=%u resolvedNtdll=%u\n", flagFromNtdll ? 1u : 0u,
               originResolvedAsNtdll ? 1u : 0u);
    }
    if (_stricmp(userClass, "DIRECT-SYSCALL-SUSPECT") == 0)
    {
        printf("[ALERT] direct-syscall-suspect classification observed\n");
    }
    printf("\n");
}

void PrintThreadEvent(_In_ const BLACKBIRD_THREAD_EVENT *t, _In_ DWORD sequence)
{
    WCHAR startResolved[768];
    WCHAR imageResolved[768];

    BLACKBIRDEtwSymbolsFormatAddressForProcess((DWORD)t->ProcessId, t->StartAddress, startResolved,
                                                 RTL_NUMBER_OF(startResolved));
    BLACKBIRDEtwSymbolsFormatAddressForProcess((DWORD)t->ProcessId, t->ImageBase, imageResolved,
                                                 RTL_NUMBER_OF(imageResolved));

    printf("[BLACKBIRD][THREAD] seq=%lu\n", sequence);
    printf("pid=%016llX tid=%016llX creatorPid=%016llX flags=0x%08X\n", (unsigned long long)t->ProcessId,
           (unsigned long long)t->ThreadId, (unsigned long long)t->CreatorPid, t->Flags);
    wprintf(L"start=0x%016llX (%ls)\n", (unsigned long long)t->StartAddress, startResolved);
    wprintf(L"imageBase=0x%016llX (%ls) imageSize=0x%llX\n", (unsigned long long)t->ImageBase, imageResolved,
            (unsigned long long)t->ImageSize);
    PrintThreadFlags(t->Flags);
    PrintResolvedFrames((DWORD)t->ProcessId, t->Frames, t->FrameCount);
    printf("\n");
}

void PrintFileEvent(_In_ const BLACKBIRD_FILE_EVENT *f, _In_ DWORD sequence)
{
    const char *operation;

    if (f == NULL)
    {
        return;
    }

    operation = FileOperationToString(f->Operation);
    printf("[BLACKBIRD][FILESYSTEM] seq=%lu\n", sequence);
    printf("op=%s pid=%016llX tid=%016llX major=%u minor=%u\n", operation, (unsigned long long)f->ProcessId,
           (unsigned long long)f->ThreadId, f->MajorCode, f->MinorCode);
    printf("status=0x%08X info=0x%llX len=0x%llX offset=0x%llX\n", (unsigned int)f->Status,
           (unsigned long long)f->Information, (unsigned long long)f->Length, (unsigned long long)f->ByteOffset);
    printf("irpFlags=0x%08X createOptions=0x%08X createDisposition=0x%08X access=0x%08X share=0x%08X\n", f->IrpFlags,
           f->CreateOptions, f->CreateDisposition, f->DesiredAccess, f->ShareAccess);
    printf("fileObject=0x%016llX fileId=0x%016llX\n", (unsigned long long)f->FileObject, (unsigned long long)f->FileId);
    wprintf(L"path=%ls\n", f->Path[0] ? f->Path : L"<unknown>");
    PrintFileFlags(f->Flags);
    printf("\n");
}

