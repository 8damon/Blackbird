#include "../controller_private.h"
#include "ipc_internal.h"
#include <math.h>

static int __cdecl ControllerCompareDwordForStats(_In_ const void *Left, _In_ const void *Right)
{
    DWORD left = *(const DWORD *)Left;
    DWORD right = *(const DWORD *)Right;

    if (left < right)
    {
        return -1;
    }
    if (left > right)
    {
        return 1;
    }
    return 0;
}

static BOOL ControllerStatsPidSetContains(_In_reads_(PidCount) const DWORD *Pids, _In_ DWORD PidCount,
                                          _In_ DWORD ProcessId)
{
    LONG lo = 0;
    LONG hi = (LONG)PidCount - 1;

    if (Pids == NULL || ProcessId == 0)
    {
        return FALSE;
    }

    while (lo <= hi)
    {
        LONG mid = lo + ((hi - lo) / 2);
        DWORD midPid = Pids[(DWORD)mid];

        if (midPid == ProcessId)
        {
            return TRUE;
        }
        if (midPid < ProcessId)
        {
            lo = mid + 1;
        }
        else
        {
            hi = mid - 1;
        }
    }

    return FALSE;
}

static DWORD ControllerQueryHookReadyMaskForStats(_In_reads_(PidCount) const DWORD *Pids, _In_ DWORD PidCount)
{
    PBK_CONTROLLER_CLIENT current;
    DWORD observedMask = 0;

    if (Pids == NULL || PidCount == 0)
    {
        return 0;
    }

    EnterCriticalSection(g_ClientListLock.get());
    current = g_ClientList;
    while (current != NULL)
    {
        if (ControllerStatsPidSetContains(Pids, PidCount, current->ProcessId))
        {
            observedMask |= (DWORD)InterlockedCompareExchange(&current->HookReadyMask, 0, 0);
        }
        current = current->Next;
    }
    LeaveCriticalSection(g_ClientListLock.get());

    return observedMask;
}

static DWORD ControllerSharedRingDepthForStats(_In_opt_ volatile BKIPC_SHARED_RING_HEADER *Header)
{
    LONG writeIndex;
    LONG readIndex;

    if (Header == NULL || Header->Capacity == 0)
    {
        return 0;
    }

    writeIndex = Header->WriteIndex;
    readIndex = Header->ReadIndex;
    if (writeIndex < 0 || readIndex < 0 || writeIndex >= (LONG)Header->Capacity || readIndex >= (LONG)Header->Capacity)
    {
        return 0;
    }

    if (writeIndex >= readIndex)
    {
        return (DWORD)(writeIndex - readIndex);
    }

    return (DWORD)(((LONG)Header->Capacity - readIndex) + writeIndex);
}

static DWORD ControllerSharedRingDroppedForStats(_In_opt_ volatile BKIPC_SHARED_RING_HEADER *Header)
{
    LONG dropped;

    if (Header == NULL)
    {
        return 0;
    }

    dropped = Header->DroppedCount;
    return dropped <= 0 ? 0 : (DWORD)dropped;
}

DWORD ControllerClientGetStats(_Inout_ BK_CONTROLLER_CLIENT *Client, _Out_ BK_STATS_RESPONSE *Stats)
{
    BOOL driverOk = FALSE;
    DWORD driverBytes = 0;
    DWORD hookReadyMask;
    DWORD controllerQueueDepth;
    DWORD controllerDroppedEvents;
    DWORD subscriptionCount;
    DWORD subscribedCount;
    DWORD subscribedPids[BK_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS];
    DWORD i;

    if (Client == NULL || Stats == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    ZeroMemory(Stats, sizeof(*Stats));
    ZeroMemory(subscribedPids, sizeof(subscribedPids));

    EnterCriticalSection(&Client->Lock);
    subscriptionCount = Client->SubscriptionCount;
    controllerQueueDepth = Client->QueueDepth + Client->EtwQueueDepth +
                           ControllerSharedRingDepthForStats(Client->IoctlSharedHeader) +
                           ControllerSharedRingDepthForStats(Client->EtwSharedHeader);
    controllerDroppedEvents = Client->DroppedEvents + Client->EtwDroppedEvents +
                              ControllerSharedRingDroppedForStats(Client->IoctlSharedHeader) +
                              ControllerSharedRingDroppedForStats(Client->EtwSharedHeader);
    hookReadyMask = (DWORD)InterlockedCompareExchange(&Client->HookReadyMask, 0, 0);
    subscribedCount = Client->SubscriptionCount;
    if (subscribedCount > BK_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS)
    {
        subscribedCount = BK_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS;
    }
    for (i = 0; i < subscribedCount; ++i)
    {
        subscribedPids[i] = Client->Subscriptions[i].ProcessId;
    }
    LeaveCriticalSection(&Client->Lock);

    if (subscribedCount > 1)
    {
        qsort(subscribedPids, subscribedCount, sizeof(subscribedPids[0]), ControllerCompareDwordForStats);
    }
    hookReadyMask |= ControllerQueryHookReadyMaskForStats(subscribedPids, subscribedCount);

    EnterCriticalSection(g_DriverLock.get());
    if (g_DriverHandle != INVALID_HANDLE_VALUE)
    {
        driverOk = BkscGetStats(g_DriverHandle, Stats, &driverBytes);
    }
    LeaveCriticalSection(g_DriverLock.get());

    if (!driverOk)
    {
        ZeroMemory(Stats, sizeof(*Stats));
        Stats->SubscriptionCount = subscriptionCount;
    }
    Stats->QueueDepth += controllerQueueDepth;
    Stats->DroppedEvents += controllerDroppedEvents;

    Stats->HookReadyMask = hookReadyMask;
    Stats->HookReadyRequiredMask = BK_CONTROLLER_HOOK_READY_REQUIRED_MASK;
    return ERROR_SUCCESS;
}

VOID ControllerSanitizeAnsiLabel(_In_opt_z_ PCSTR Input, _Out_writes_z_(OutputChars) PSTR Output,
                                 _In_ size_t OutputChars)
{
    size_t i;
    size_t write = 0;

    if (Output == NULL || OutputChars == 0)
    {
        return;
    }

    Output[0] = '\0';
    if (Input == NULL)
    {
        return;
    }

    for (i = 0; Input[i] != '\0' && write + 1 < OutputChars; ++i)
    {
        CHAR ch = Input[i];
        if ((unsigned char)ch < 0x20u || ch == '\x7F')
        {
            continue;
        }
        Output[write++] = ch;
    }
    Output[write] = '\0';
}

PCSTR ControllerHookEventKindName(_In_ UINT32 Kind)
{
    switch (Kind)
    {
    case BlackbirdIpcHookEventNt:
        return "Nt";
    case BlackbirdIpcHookEventWinsock:
        return "Winsock";
    case BlackbirdIpcHookEventKi:
        return "Ki";
    case BlackbirdIpcHookEventExceptionLowNoise:
        return "ExceptionLowNoise";
    case BlackbirdIpcHookEventExceptionHighPriv:
        return "ExceptionHighPriv";
    case BlackbirdIpcHookEventIntegrity:
        return "Integrity";
    case BlackbirdIpcHookEventModule:
        return "Module";
    default:
        return "Unknown";
    }
}

PCSTR ControllerMemoryProtectName(_In_ UINT32 Protect)
{
    switch (Protect)
    {
    case 0x01:
        return "PAGE_NOACCESS";
    case 0x02:
        return "PAGE_READONLY";
    case 0x04:
        return "PAGE_READWRITE";
    case 0x08:
        return "PAGE_WRITECOPY";
    case 0x10:
        return "PAGE_EXECUTE";
    case 0x20:
        return "PAGE_EXECUTE_READ";
    case 0x40:
        return "PAGE_EXECUTE_READWRITE";
    case 0x80:
        return "PAGE_EXECUTE_WRITECOPY";
    default:
        return "UNKNOWN";
    }
}

PCSTR ControllerMemoryAllocTypeName(_In_ UINT32 AllocationType)
{
    if ((AllocationType & 0x3000u) == 0x3000u)
    {
        return "MEM_COMMIT_RESERVE";
    }
    if ((AllocationType & 0x1000u) != 0)
    {
        return "MEM_COMMIT";
    }
    if ((AllocationType & 0x2000u) != 0)
    {
        return "MEM_RESERVE";
    }
    if ((AllocationType & 0x1000000u) != 0)
    {
        return "MEM_LARGE_PAGES";
    }
    return "UNKNOWN";
}

UINT16 ControllerHookByteSwap16(_In_ UINT16 Value)
{
    return (UINT16)(((Value & 0x00FFu) << 8) | ((Value & 0xFF00u) >> 8));
}

BOOL ControllerHookIsInterestingProcessAccess(_In_ ULONG DesiredAccess)
{
    return ((DesiredAccess & PROCESS_VM_OPERATION) != 0) || ((DesiredAccess & PROCESS_VM_WRITE) != 0) ||
           ((DesiredAccess & PROCESS_VM_READ) != 0) || ((DesiredAccess & PROCESS_CREATE_THREAD) != 0) ||
           ((DesiredAccess & PROCESS_DUP_HANDLE) != 0) || ((DesiredAccess & PROCESS_QUERY_INFORMATION) != 0) ||
           ((DesiredAccess & PROCESS_QUERY_LIMITED_INFORMATION) != 0) ||
           ((DesiredAccess & PROCESS_SUSPEND_RESUME) != 0);
}

BOOL ControllerHookIsInterestingThreadAccess(_In_ ULONG DesiredAccess)
{
    return ((DesiredAccess & THREAD_SET_CONTEXT) != 0) || ((DesiredAccess & THREAD_GET_CONTEXT) != 0) ||
           ((DesiredAccess & THREAD_SUSPEND_RESUME) != 0) || ((DesiredAccess & THREAD_QUERY_INFORMATION) != 0) ||
           ((DesiredAccess & THREAD_SET_INFORMATION) != 0);
}

UINT32 ControllerHookSeverityForProcessAccess(_In_ ULONG DesiredAccess)
{
    if ((DesiredAccess & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)) != 0)
    {
        return 6u;
    }
    if ((DesiredAccess & (PROCESS_VM_READ | PROCESS_DUP_HANDLE)) != 0)
    {
        return 4u;
    }
    return 2u;
}

UINT32 ControllerHookSeverityForThreadAccess(_In_ ULONG DesiredAccess)
{
    if ((DesiredAccess & (THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME)) != 0)
    {
        return 6u;
    }
    if ((DesiredAccess & (THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION)) != 0)
    {
        return 4u;
    }
    return 2u;
}

UINT32 ControllerCallerOriginSeverityBoost(_In_ UINT32 CallerFlags)
{
    UNREFERENCED_PARAMETER(CallerFlags);
    return 0u;
}

BOOL ControllerHookDecodeSockaddr(_In_reads_bytes_(SampleSize) const UINT8 *Sample, _In_ UINT32 SampleSize,
                                  _Out_ UINT16 *FamilyOut, _Out_ UINT16 *PortOut,
                                  _Out_writes_opt_z_(IpBufChars) PSTR IpBuf, _In_ size_t IpBufChars)
{
    UINT16 family;

    if (FamilyOut != NULL)
    {
        *FamilyOut = 0;
    }
    if (PortOut != NULL)
    {
        *PortOut = 0;
    }
    if (IpBuf != NULL && IpBufChars > 0)
    {
        IpBuf[0] = '\0';
    }

    if (FamilyOut == NULL || PortOut == NULL || Sample == NULL || SampleSize < sizeof(UINT16))
    {
        return FALSE;
    }

    CopyMemory(&family, Sample, sizeof(family));
    *FamilyOut = family;
    *PortOut = 0;

    if (family == 2u && SampleSize >= 8u)
    {
        UINT16 netPort;
        UINT8 addr[4];
        CopyMemory(&netPort, Sample + 2, sizeof(netPort));
        *PortOut = ControllerHookByteSwap16(netPort);
        CopyMemory(addr, Sample + 4, 4);
        if (IpBuf != NULL && IpBufChars >= 16u)
        {
            (void)StringCchPrintfA(IpBuf, IpBufChars, "%u.%u.%u.%u", (unsigned)addr[0], (unsigned)addr[1],
                                   (unsigned)addr[2], (unsigned)addr[3]);
        }
        return TRUE;
    }
    if (family == 2u && SampleSize >= 4u)
    {
        UINT16 netPort;
        CopyMemory(&netPort, Sample + 2, sizeof(netPort));
        *PortOut = ControllerHookByteSwap16(netPort);
        return TRUE;
    }

    if (family == 23u && SampleSize >= 28u)
    {
        UINT16 netPort;
        UINT8 addr[16];
        CopyMemory(&netPort, Sample + 2, sizeof(netPort));
        *PortOut = ControllerHookByteSwap16(netPort);
        CopyMemory(addr, Sample + 8, 16);
        if (IpBuf != NULL && IpBufChars >= 40u)
        {
            (void)StringCchPrintfA(IpBuf, IpBufChars,
                                   "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                                   "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                                   addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8],
                                   addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
        }
        return TRUE;
    }
    if (family == 23u && SampleSize >= 4u)
    {
        UINT16 netPort;
        CopyMemory(&netPort, Sample + 2, sizeof(netPort));
        *PortOut = ControllerHookByteSwap16(netPort);
        return TRUE;
    }

    return TRUE;
}

VOID ControllerHookCopyWideSampleToReason(_Out_writes_z_(ReasonChars) PWSTR Reason, _In_ size_t ReasonChars,
                                          _In_reads_bytes_(SampleSize) const UINT8 *Sample, _In_ UINT32 SampleSize)
{
    size_t charCount;

    if (Reason == NULL || ReasonChars == 0)
    {
        return;
    }

    Reason[0] = L'\0';
    if (Sample == NULL || SampleSize < sizeof(WCHAR))
    {
        return;
    }

    charCount = (size_t)(SampleSize / sizeof(WCHAR));
    if (charCount >= ReasonChars)
    {
        charCount = ReasonChars - 1;
    }

    CopyMemory(Reason, Sample, charCount * sizeof(WCHAR));
    Reason[charCount] = L'\0';
}

VOID ControllerHookCopyAnsiSampleToReason(_Out_writes_z_(ReasonChars) PWSTR Reason, _In_ size_t ReasonChars,
                                          _In_reads_bytes_(SampleSize) const UINT8 *Sample, _In_ UINT32 SampleSize)
{
    CHAR buffer[BKIPC_MAX_HOOK_DATA_SAMPLE + 1];
    int written;

    if (Reason == NULL || ReasonChars == 0)
    {
        return;
    }

    Reason[0] = L'\0';
    if (Sample == NULL || SampleSize == 0)
    {
        return;
    }

    RtlZeroMemory(buffer, sizeof(buffer));
    CopyMemory(buffer, Sample, (SampleSize < BKIPC_MAX_HOOK_DATA_SAMPLE) ? SampleSize : BKIPC_MAX_HOOK_DATA_SAMPLE);
    written = MultiByteToWideChar(CP_ACP, 0, buffer, -1, Reason, (int)ReasonChars);
    if (written <= 0)
    {
        Reason[0] = L'\0';
    }
}

BOOL ControllerHookWidePathContainsI(_In_opt_z_ PCWSTR Haystack, _In_z_ PCWSTR Needle)
{
    if (Haystack == NULL || Needle == NULL || Needle[0] == L'\0')
    {
        return FALSE;
    }

    return ControllerWideContainsInsensitive(Haystack, Needle) ? TRUE : FALSE;
}

double ControllerComputeSampleEntropy(_In_reads_(SampleSize) const UINT8 *Sample, _In_ UINT32 SampleSize)
{
    UINT32 i;
    UINT32 counts[256];
    double entropy = 0.0;
    double invLength;

    if (Sample == NULL || SampleSize <= 1)
    {
        return -1.0;
    }

    ZeroMemory(counts, sizeof(counts));
    for (i = 0; i < SampleSize; ++i)
    {
        counts[Sample[i]] += 1u;
    }

    invLength = 1.0 / (double)SampleSize;
    for (i = 0; i < RTL_NUMBER_OF(counts); ++i)
    {
        if (counts[i] != 0u)
        {
            double p = (double)counts[i] * invLength;
            entropy -= p * (log(p) / log(2.0));
        }
    }

    return entropy;
}

VOID ControllerHookAppendArgsToReason(_Inout_updates_(ReasonChars) PWSTR Reason, _In_ size_t ReasonChars,
                                      _In_reads_(ArgCount) const UINT64 *Args, _In_ UINT32 ArgCount)
{
    size_t reasonOffset;
    UINT32 i;

    if (Reason == NULL || ReasonChars == 0 || Args == NULL || ArgCount == 0)
    {
        return;
    }

    reasonOffset = wcslen(Reason);
    for (i = 0; i < ArgCount && reasonOffset + 20 < ReasonChars; ++i)
    {
        WCHAR token[32];

        (void)StringCchPrintfW(token, RTL_NUMBER_OF(token), L"a%lu=", (unsigned long)i);
        if (wcsstr(Reason, token) != NULL)
        {
            continue;
        }

        (void)StringCchPrintfW(Reason + reasonOffset, ReasonChars - reasonOffset, L" a%lu=0x%llX", (unsigned long)i,
                               (unsigned long long)Args[i]);
        reasonOffset = wcslen(Reason);
    }
}

VOID ControllerHookCopyArgs(_Out_writes_(BKIPC_MAX_HOOK_ARGS) UINT64 *Destination, _Out_opt_ UINT32 *DestinationCount,
                            _In_reads_(SourceCount) const UINT64 *Source, _In_ UINT32 SourceCount)
{
    UINT32 i;
    UINT32 count;

    if (Destination == NULL)
    {
        return;
    }

    RtlZeroMemory(Destination, sizeof(UINT64) * BKIPC_MAX_HOOK_ARGS);
    count = SourceCount;
    if (count > BKIPC_MAX_HOOK_ARGS)
    {
        count = BKIPC_MAX_HOOK_ARGS;
    }

    if (Source != NULL)
    {
        for (i = 0; i < count; ++i)
        {
            Destination[i] = Source[i];
        }
    }

    if (DestinationCount != NULL)
    {
        *DestinationCount = count;
    }
}

VOID ControllerPrimeHookArgumentSymbols(_In_ DWORD ProcessId, _In_z_ PCSTR ApiName,
                                        _In_reads_(ArgCount) const UINT64 *Args, _In_ UINT32 ArgCount)
{
    if (ProcessId == 0 || ApiName == NULL || ApiName[0] == '\0' || Args == NULL || ArgCount == 0)
    {
        return;
    }

    if (lstrcmpiA(ApiName, "NtCreateThreadEx") == 0 && ArgCount >= 4)
    {
        ControllerSymbolServicePrimeHookAddress(ProcessId, Args[3]);
    }
    else if (lstrcmpiA(ApiName, "NtQueueApcThread") == 0 && ArgCount >= 2)
    {
        ControllerSymbolServicePrimeHookAddress(ProcessId, Args[1]);
    }
    else if (lstrcmpiA(ApiName, "NtQueueApcThreadEx") == 0 && ArgCount >= 3)
    {
        ControllerSymbolServicePrimeHookAddress(ProcessId, Args[2]);
    }
    else if (lstrcmpiA(ApiName, "NtQueueApcThreadEx2") == 0 && ArgCount >= 4)
    {
        ControllerSymbolServicePrimeHookAddress(ProcessId, Args[3]);
    }
    else if (lstrcmpiA(ApiName, "NtMapViewOfSectionEx") == 0 && ArgCount >= 3)
    {
        ControllerSymbolServicePrimeHookAddress(ProcessId, Args[2]);
    }
}
