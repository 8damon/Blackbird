#include <stdio.h>
#include "event_printer.h"
#include "symbol_resolver.h"

typedef struct _MASK_NAME_ENTRY
{
    UINT32 Bit;
    const char *Name;
} MASK_NAME_ENTRY;

static const MASK_NAME_ENTRY g_StreamMaskNames[] = {
    {BK_STREAM_HANDLE, "HANDLE"},         {BK_STREAM_MEMORY, "MEMORY"},     {BK_STREAM_THREAD, "THREAD"},
    {BK_STREAM_FILESYSTEM, "FILESYSTEM"}, {BK_STREAM_REGISTRY, "REGISTRY"}, {BK_STREAM_TIMING, "TIMING"},
    {BK_STREAM_ENTERPRISE, "ENTERPRISE"}};

static const char *BkchdlClassToString(UINT32 classId)
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

static void BkevtTypeToString(UINT32 type, char *output, size_t outputChars)
{
    if (output == NULL || outputChars == 0)
    {
        return;
    }

    if (type == BlackbirdEventTypeHandle)
    {
        (void)snprintf(output, outputChars, "HANDLE");
    }
    else if (type == BlackbirdEventTypeThread)
    {
        (void)snprintf(output, outputChars, "THREAD");
    }
    else if (type == BlackbirdEventTypeFileSystem)
    {
        (void)snprintf(output, outputChars, "FILESYSTEM");
    }
    else if (type == BlackbirdEventTypeRegistry)
    {
        (void)snprintf(output, outputChars, "REGISTRY");
    }
    else if (type == BlackbirdEventTypeEnterprise)
    {
        (void)snprintf(output, outputChars, "ENTERPRISE");
    }
    else
    {
        (void)snprintf(output, outputChars, "UNKNOWN(%u)", type);
    }
}

static void BkfmtStreamMask(UINT32 mask, char *output, size_t outputChars)
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

static void BkevtPrintHandleFlags(UINT32 flags)
{
    printf("Flags  ");
    if (flags == 0)
    {
        printf("<none>\n");
        return;
    }
    if ((flags & BK_HANDLE_FLAG_EXEC_PROTECT) != 0)
    {
        printf("ExecProtect ");
    }
    if ((flags & BK_HANDLE_FLAG_FROM_NTDLL) != 0)
    {
        printf("FromNtdll ");
    }
    if ((flags & BK_HANDLE_FLAG_FROM_EXE) != 0)
    {
        printf("FromExe ");
    }
    if ((flags & BK_HANDLE_FLAG_MEMORY_RELATED) != 0)
    {
        printf("MemoryRelated ");
    }
    if ((flags & BK_HANDLE_FLAG_THREAD_OBJECT) != 0)
    {
        printf("ThreadObject ");
    }
    if ((flags & BK_HANDLE_FLAG_DUPLICATE_OPERATION) != 0)
    {
        printf("DuplicateOp ");
    }
    if ((flags & BK_HANDLE_FLAG_RETURN_ADDRESS_VALID) != 0)
    {
        printf("ReturnAddressValid ");
    }
    if ((flags & BK_HANDLE_FLAG_STACK_VALIDATED) != 0)
    {
        printf("StackValidated ");
    }
    if ((flags & BK_HANDLE_FLAG_STACK_SPOOF_SUSPECT) != 0)
    {
        printf("StackSpoofSuspect ");
    }
    if ((flags & BK_HANDLE_FLAG_SYSCALL_EXPORT_MATCH) != 0)
    {
        printf("SyscallExportMatch ");
    }
    if ((flags & BK_HANDLE_FLAG_SYSCALL_EXPORT_MISMATCH) != 0)
    {
        printf("SyscallExportMismatch ");
    }
    if ((flags & BK_HANDLE_FLAG_MODULE_CHAIN_SANE) != 0)
    {
        printf("ModuleChainSane ");
    }
    if ((flags & BK_HANDLE_FLAG_UNWIND_METADATA_VALID) != 0)
    {
        printf("UnwindMetadataValid ");
    }
    if ((flags & BK_HANDLE_FLAG_TEB_STACK_BOUNDS_VALID) != 0)
    {
        printf("TebStackBoundsValid ");
    }
    if ((flags & BK_HANDLE_FLAG_FRAMES_OUTSIDE_TEB_STACK) != 0)
    {
        printf("FramesOutsideTebStack ");
    }
    printf("\n");
}

static void BkevtPrintThreadFlags(UINT32 flags)
{
    printf("Flags  ");
    if (flags == 0)
    {
        printf("<none>\n");
        return;
    }
    if ((flags & BK_THREAD_FLAG_GOT_START) != 0)
    {
        printf("GotStart ");
    }
    if ((flags & BK_THREAD_FLAG_GOT_RANGE) != 0)
    {
        printf("GotRange ");
    }
    if ((flags & BK_THREAD_FLAG_REMOTE_CREATOR) != 0)
    {
        printf("RemoteCreator ");
    }
    if ((flags & BK_THREAD_FLAG_OUTSIDE_MAIN_IMG) != 0)
    {
        printf("OutsideMainImage ");
    }
    if ((flags & BK_THREAD_FLAG_CORRELATED_INTENT) != 0)
    {
        printf("CorrelatedIntent ");
    }
    if ((flags & BK_THREAD_FLAG_CORR_MEMORY) != 0)
    {
        printf("IntentProcessMemory ");
    }
    if ((flags & BK_THREAD_FLAG_CORR_THREAD_CTX) != 0)
    {
        printf("IntentThreadContext ");
    }
    if ((flags & BK_THREAD_FLAG_CORR_DUP_HANDLE) != 0)
    {
        printf("IntentDupHandle ");
    }
    if ((flags & BK_THREAD_FLAG_START_REGION_EXEC) != 0)
    {
        printf("StartRegionExec ");
    }
    printf("\n");
}

static void BkevtPrintAddressLine(const char *label, UINT64 address)
{
    printf("%-6s ", label);
    BksymResolverPrintAddress(address);
    printf("\n");
}

static void BkevtPrintFrames(const UINT64 *frames, UINT32 count)
{
    UINT32 i;
    UINT32 limit = (count > BK_MAX_EVENT_FRAMES) ? BK_MAX_EVENT_FRAMES : count;

    printf("Stack  frames=%u\n", limit);
    if (limit == 0)
    {
        printf("       <none>\n");
        return;
    }

    for (i = 0; i < limit; ++i)
    {
        printf("       #%u ", i);
        BksymResolverPrintAddress(frames[i]);
        printf("\n");
    }
}

static void BkevtPrintHandleEvent(const BK_EVENT_RECORD *rec)
{
    const BK_HANDLE_EVENT *h = &rec->Data.Handle;

    printf("[IOCTL][HANDLE] class=%s(%u) caller=%llu target=%llu access=0x%08X\n", BkchdlClassToString(h->ClassId),
           h->ClassId, (unsigned long long)h->CallerPid, (unsigned long long)h->TargetPid, h->DesiredAccess);
    BkevtPrintHandleFlags(h->Flags);
    printf("Path   %ls\n", (h->OriginPath[0] != L'\0') ? h->OriginPath : L"<none>");
    printf("Mem    protect=0x%08X\n", h->OriginProtect);
    BkevtPrintAddressLine("Origin", h->OriginAddress);
    printf("Status open=0x%08X basic=0x%08X section=0x%08X\n", (UINT32)h->StatusOpenProcess, (UINT32)h->StatusBasicInfo,
           (UINT32)h->StatusSectionName);
    BkevtPrintFrames(h->Frames, h->FrameCount);
}

static void BkevtPrintThreadEvent(const BK_EVENT_RECORD *rec)
{
    const BK_THREAD_EVENT *t = &rec->Data.Thread;

    printf("[IOCTL][THREAD] process=%llu thread=%llu creator=%llu\n", (unsigned long long)t->ProcessId,
           (unsigned long long)t->ThreadId, (unsigned long long)t->CreatorPid);
    BkevtPrintThreadFlags(t->Flags);
    BkevtPrintAddressLine("Start", t->StartAddress);
    BkevtPrintAddressLine("Image", t->ImageBase);
    printf("Size   imageSize=0x%llX\n", (unsigned long long)t->ImageSize);
    BkevtPrintFrames(t->Frames, t->FrameCount);
}

static const char *BkfileOperationToString(UINT32 op)
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

static void BkevtPrintFileEvent(const BK_EVENT_RECORD *rec)
{
    const BK_FILE_EVENT *f = &rec->Data.FileSystem;

    printf("[IOCTL][FILESYSTEM] op=%s(%u) process=%llu thread=%llu status=0x%08llX info=0x%llX\n",
           BkfileOperationToString(f->Operation), f->Operation, (unsigned long long)f->ProcessId,
           (unsigned long long)f->ThreadId, (unsigned long long)f->Status, (unsigned long long)f->Information);
    printf("Path   %ls\n", (f->Path[0] != L'\0') ? f->Path : L"<none>");
    printf("IO     major=%u minor=%u irpFlags=0x%08X flags=0x%08X\n", f->MajorCode, f->MinorCode, f->IrpFlags,
           f->Flags);
    printf("Range  offset=0x%llX length=0x%llX\n", (unsigned long long)f->ByteOffset, (unsigned long long)f->Length);
    printf("Create desired=0x%08X share=0x%08X disp=%u options=0x%08X\n", f->DesiredAccess, f->ShareAccess,
           f->CreateDisposition, f->CreateOptions);
}

static const char *BkregOperationToString(UINT32 op)
{
    switch (op)
    {
    case BkavRegOperationQueryValue:
        return "QUERY_VALUE";
    case BkavRegOperationQueryKey:
        return "QUERY_KEY";
    case BkavRegOperationEnumerateKey:
        return "ENUMERATE_KEY";
    case BkavRegOperationEnumerateValue:
        return "ENUMERATE_VALUE";
    case BkavRegOperationSetValue:
        return "SET_VALUE";
    case BkavRegOperationCreateKey:
        return "CREATE_KEY";
    case BkavRegOperationOpenKey:
        return "OPEN_KEY";
    case BkavRegOperationDeleteValue:
        return "DELETE_VALUE";
    case BkavRegOperationDeleteKey:
        return "DELETE_KEY";
    default:
        return "UNKNOWN";
    }
}

static void BkevtPrintRegistryEvent(const BK_EVENT_RECORD *rec)
{
    const BK_REGISTRY_EVENT *r = &rec->Data.Registry;

    printf("[IOCTL][REGISTRY] op=%s(%u) process=%llu thread=%llu flags=0x%08X session=%u\n",
           BkregOperationToString(r->Operation), r->Operation, (unsigned long long)r->ProcessId,
           (unsigned long long)r->ThreadId, r->Flags, r->SessionId);
    printf("Key    %ls\n", (r->KeyPath[0] != L'\0') ? r->KeyPath : L"<none>");
    printf("Value  %ls\n", (r->ValueName[0] != L'\0') ? r->ValueName : L"<none>");
    printf("Data   notifyClass=%u type=0x%08X size=%u\n", r->NotifyClass, r->DataType, r->DataSize);
}

static const char *BkenterpriseOperationToString(UINT32 op)
{
    switch (op)
    {
    case BkEnterpriseOperationProcessCredentialAccess:
        return "PROCESS_CREDENTIAL_ACCESS";
    case BkEnterpriseOperationProcessPrivilegedAccess:
        return "PROCESS_PRIVILEGED_ACCESS";
    case BkEnterpriseOperationTokenAccess:
        return "TOKEN_ACCESS";
    case BkEnterpriseOperationRegistryCredentialHiveAccess:
        return "REGISTRY_CREDENTIAL_HIVE";
    case BkEnterpriseOperationRegistryLsaPolicyAccess:
        return "REGISTRY_LSA_POLICY";
    case BkEnterpriseOperationRegistryKerberosNtlmAccess:
        return "REGISTRY_KERBEROS_NTLM";
    case BkEnterpriseOperationRegistryServiceConfigAccess:
        return "REGISTRY_SERVICE_CONFIG";
    case BkEnterpriseOperationRegistryLpePersistenceAccess:
        return "REGISTRY_LPE_PERSISTENCE";
    case BkEnterpriseOperationFileCredentialStoreAccess:
        return "FILE_CREDENTIAL_STORE";
    case BkEnterpriseOperationFileDirectoryCredentialAccess:
        return "FILE_CREDENTIAL_DIRECTORY";
    case BkEnterpriseOperationFileDriverArtifactAccess:
        return "FILE_DRIVER_ARTIFACT";
    case BkEnterpriseOperationNetworkAdProtocolConnect:
        return "NETWORK_AD_PROTOCOL";
    default:
        return "UNKNOWN";
    }
}

static void BkevtPrintEnterpriseEvent(const BK_EVENT_RECORD *rec)
{
    const BK_ENTERPRISE_EVENT *e = &rec->Data.Enterprise;

    printf("[IOCTL][ENTERPRISE] op=%s(%u) actor=%llu tid=%llu target=%llu targetTid=%llu flags=0x%08X\n",
           BkenterpriseOperationToString(e->Operation), e->Operation, (unsigned long long)e->ProcessId,
           (unsigned long long)e->ThreadId, (unsigned long long)e->TargetProcessId,
           (unsigned long long)e->TargetThreadId, e->Flags);
    printf("Access desired=0x%08X granted=0x%08X status=0x%08X subOp=%u\n", e->DesiredAccess, e->GrantedAccess,
           e->Status, e->SubOperation);
    printf("Obj    object=0x%llX aux0=0x%llX aux1=0x%llX proto=%u lport=%u rport=%u\n",
           (unsigned long long)e->ObjectAddress, (unsigned long long)e->Aux0, (unsigned long long)e->Aux1, e->Protocol,
           e->LocalPort, e->RemotePort);
}

static void BkevtPrintHeader(const BK_EVENT_RECORD *rec)
{
    char typeName[32];
    char maskName[64];

    BkevtTypeToString(rec->Header.Type, typeName, sizeof(typeName));
    BkfmtStreamMask(rec->Header.StreamMask, maskName, sizeof(maskName));

    printf("\n[IOCTL][EVENT] seq=%u type=%s stream=0x%08X(%s) size=%u qpc=%lld\n", rec->Header.Sequence, typeName,
           rec->Header.StreamMask, maskName, rec->Header.Size, (long long)rec->Header.TimestampQpc);
}

void BkevtPrinterPrintRecord(const BK_EVENT_RECORD *rec)
{
    if (rec == NULL)
    {
        return;
    }

    BkevtPrintHeader(rec);

    if (rec->Header.Type == BlackbirdEventTypeHandle)
    {
        BkevtPrintHandleEvent(rec);
    }
    else if (rec->Header.Type == BlackbirdEventTypeThread)
    {
        BkevtPrintThreadEvent(rec);
    }
    else if (rec->Header.Type == BlackbirdEventTypeFileSystem)
    {
        BkevtPrintFileEvent(rec);
    }
    else if (rec->Header.Type == BlackbirdEventTypeRegistry)
    {
        BkevtPrintRegistryEvent(rec);
    }
    else if (rec->Header.Type == BlackbirdEventTypeEnterprise)
    {
        BkevtPrintEnterpriseEvent(rec);
    }
    else
    {
        printf("[IOCTL][UNKNOWN] event type=%u\n", rec->Header.Type);
    }
}
