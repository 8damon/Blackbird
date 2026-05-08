#ifndef BK_CONTROLLER_PRIVATE_H
#define BK_CONTROLLER_PRIVATE_H

#include <windows.h>
#include <winsvc.h>
#include <sddl.h>
#include <strsafe.h>
#include <tdh.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <memory>
#include <array>
#include <vector>
#include <atomic>
#include "util/handles.h"
#include "..\\..\\sensor\\sensor_core.h"
#include "..\\..\\..\\abi\\blackbird_ipc.h"
#include "heuristics\\heuristics.h"

inline constexpr DWORD BK_CONTROLLER_MAX_CLIENTS = 256u;
inline constexpr DWORD BK_CONTROLLER_INVALID_SLOT = 0xFFFFFFFFu;
inline constexpr DWORD BK_CONTROLLER_CLIENT_MASK_DWORDS = (BK_CONTROLLER_MAX_CLIENTS + 31u) / 32u;
inline constexpr DWORD BK_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS = 4096u;
inline constexpr DWORD BK_CONTROLLER_MAX_CLIENT_QUEUE_DEPTH = 4096u;
inline constexpr DWORD BK_CONTROLLER_MAX_CLIENT_ETW_QUEUE_DEPTH = 8192u;
inline constexpr DWORD BK_CONTROLLER_SHARED_IOCTL_RING_CAPACITY = 262144u;
inline constexpr DWORD BK_CONTROLLER_SHARED_ETW_RING_CAPACITY = 65536u;
inline constexpr DWORD BK_CONTROLLER_DYNAMIC_SUBSCRIPTION_TTL_MS = 0u;
inline constexpr DWORD BK_CONTROLLER_DYNAMIC_SUBSCRIPTION_MAX_DEPTH = 0xFFFFFFFFu;
inline constexpr DWORD BK_CONTROLLER_HOOK_READY_TIMEOUT_MS = 15000u;
inline constexpr DWORD BK_CONTROLLER_SERVER_ACCEPT_THREADS = 3u;
inline constexpr DWORD BK_CONTROLLER_HOOK_ACCEPT_THREADS = 1u;
inline constexpr DWORD BK_CONTROLLER_HOLLOW_MAX_ENTRIES = 256u;
inline constexpr DWORD BK_CONTROLLER_HOLLOW_WINDOW_MS = 30000u;
inline constexpr DWORD BK_CONTROLLER_MANUAL_MAP_EMIT_COOLDOWN_MS = 4000u;
inline constexpr DWORD BK_CONTROLLER_MANUAL_MAP_PROBE_MIN_INTERVAL_MS = 1500u;
inline constexpr DWORD BK_CONTROLLER_SUBSCRIPTION_APPLY_SYNC_TIMEOUT_MS = 2500u;
inline constexpr UINT64 BK_CONTROLLER_HOLLOW_LARGE_ALLOC_BYTES = 0x8000ull;
inline constexpr UINT32 BK_NTAPI_EXEC_FLAG_CALLER_KERNEL = 0x00000001u;
inline constexpr UINT32 BK_NTAPI_EXEC_FLAG_CALLER_USER = 0x00000002u;
inline constexpr UINT32 BK_NTAPI_EXEC_FLAG_TARGET_CURRENT_PROCESS = 0x00000004u;
inline constexpr UINT32 BK_NTAPI_EXEC_FLAG_SECTION_IMAGE = 0x00000008u;

inline bool ControllerAsciiContainsInsensitive(_In_opt_z_ PCSTR haystack, _In_z_ PCSTR needle)
{
    if (haystack == nullptr || needle == nullptr || needle[0] == '\0')
    {
        return false;
    }

    const size_t hayLen = strlen(haystack);
    const size_t needleLen = strlen(needle);
    if (hayLen < needleLen)
    {
        return false;
    }

    for (size_t i = 0; i <= (hayLen - needleLen); ++i)
    {
        if (_strnicmp(haystack + i, needle, needleLen) == 0)
        {
            return true;
        }
    }

    return false;
}

inline bool ControllerAsciiEqualsInsensitive(_In_opt_z_ PCSTR left, _In_z_ PCSTR right)
{
    return (left != nullptr && right != nullptr && _stricmp(left, right) == 0);
}

inline bool ControllerWideContainsInsensitive(_In_opt_z_ PCWSTR haystack, _In_z_ PCWSTR needle)
{
    if (haystack == nullptr || needle == nullptr || needle[0] == L'\0')
    {
        return false;
    }

    size_t hayLen = wcslen(haystack);
    size_t needleLen = wcslen(needle);
    if (hayLen < needleLen)
    {
        return false;
    }

    for (size_t i = 0; i <= (hayLen - needleLen); ++i)
    {
        if (_wcsnicmp(haystack + i, needle, needleLen) == 0)
        {
            return true;
        }
    }

    return false;
}

inline UINT32 ControllerComputeEtwDetectionTraits(_In_ const BKIPC_ETW_EVENT &Event)
{
    UINT32 traits = 0;
    const bool isDetection = (Event.DetectionName[0] != '\0') || Event.Family == BlackbirdIpcEtwFamilyDetection ||
                             Event.Family == BlackbirdIpcEtwFamilyThreatIntel || Event.Severity >= 4u;
    const bool isProcessFamily = Event.Family == BlackbirdIpcEtwFamilyProcess;
    const bool isImageFamily = Event.Family == BlackbirdIpcEtwFamilyImage;
    const bool isThreadFamily = Event.Family == BlackbirdIpcEtwFamilyThread;
    const bool isApcFamily = Event.Family == BlackbirdIpcEtwFamilyApc;
    const bool isSocketFamily = Event.Family == BlackbirdIpcEtwFamilySocket;

    if (isDetection)
    {
        traits |= BKIPC_ETW_TRAIT_DETECTION_CLASS;
    }

    if (isProcessFamily && (Event.Flags & BKIPC_ETW_FLAG_PROCESS_IS_CREATE) != 0)
    {
        traits |= BKIPC_ETW_TRAIT_PROCESS_LAUNCH | BKIPC_ETW_TRAIT_SCAN_IMAGE_PATH;
    }
    if (isImageFamily)
    {
        traits |= BKIPC_ETW_TRAIT_IMAGE_LOAD | BKIPC_ETW_TRAIT_SCAN_IMAGE_PATH;
    }
    if (isSocketFamily || ControllerAsciiContainsInsensitive(Event.DetectionName, "NETWORK_CONNECT") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "DOMAIN_RESOLUTION"))
    {
        traits |= BKIPC_ETW_TRAIT_NETWORK;
    }
    if ((isThreadFamily && (Event.Flags & BKIPC_ETW_FLAG_THREAD_REMOTE_CREATOR) != 0) || isApcFamily ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "REMOTE_THREAD") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "THREAD_HIJACK") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "APC"))
    {
        traits |= BKIPC_ETW_TRAIT_REMOTE_EXECUTION | BKIPC_ETW_TRAIT_SCAN_TARGET_PROCESS;
    }
    if (ControllerAsciiEqualsInsensitive(Event.Operation, "NtAllocateVirtualMemory") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "RWX_ALLOCATION") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "MEMORY_ACTIVITY"))
    {
        traits |= BKIPC_ETW_TRAIT_MEMORY_ALLOC_RW;
    }
    if (ControllerAsciiEqualsInsensitive(Event.Operation, "NtWriteVirtualMemory") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "WRITE_VM") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "PE_INJECTION_WRITE"))
    {
        traits |= BKIPC_ETW_TRAIT_MEMORY_WRITE_VM | BKIPC_ETW_TRAIT_SCAN_TARGET_PROCESS;
    }
    if (ControllerAsciiEqualsInsensitive(Event.Operation, "NtProtectVirtualMemory") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "PROTECT") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "RWX_ALLOCATION"))
    {
        traits |= BKIPC_ETW_TRAIT_MEMORY_PROTECT_RX;
    }
    if (ControllerAsciiContainsInsensitive(Event.DetectionName, "DIRECT_SYSCALL") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "PIC_DIRECT_SYSCALL") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "ANOMALY_ON_HANDLE_OP") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "SUSPECT_HANDLE_OPERATION") ||
        ControllerAsciiEqualsInsensitive(Event.ClassName, "DIRECT-SYSCALL-SUSPECT") ||
        (Event.Flags & BKIPC_ETW_FLAG_SYSCALL_EXPORT_MISMATCH) != 0)
    {
        traits |= BKIPC_ETW_TRAIT_DIRECT_SYSCALL;
    }
    if ((Event.Flags & BKIPC_ETW_FLAG_HOOK_CALLER_UNWIND_SUSPECT) != 0)
    {
        traits |= BKIPC_ETW_TRAIT_UNWIND_SUSPECT;
    }
    if (ControllerAsciiContainsInsensitive(Event.DetectionName, "HOOK_TAMPER") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "AMSI_PATCH_TAMPERED") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "ETW_PATCH_TAMPERED") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "IAT_TAMPER") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "EAT_TAMPER") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "NTDLL_IMAGE_TAMPER") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "SR71_PIC_") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "SR71_HOOK_WRITE_BLOCKED") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "SR71_HOOK_PROTECT_BLOCKED"))
    {
        traits |= BKIPC_ETW_TRAIT_HOOK_TAMPER;
    }
    if (ControllerAsciiContainsInsensitive(Event.DetectionName, "CREDENTIAL_ACCESS"))
    {
        traits |= BKIPC_ETW_TRAIT_CREDENTIAL_ACCESS;
    }
    if (ControllerAsciiContainsInsensitive(Event.DetectionName, "PROCESS_IMAGE_TAMPER") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "GHOST") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "HERP") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "DOPPELGANG"))
    {
        traits |= BKIPC_ETW_TRAIT_IMAGE_TAMPER;
    }
    if (ControllerAsciiContainsInsensitive(Event.DetectionName, "LOLBIN") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "SCRIPT_HOST_ABUSE") ||
        ControllerAsciiContainsInsensitive(Event.DetectionName, "POWERSHELL_"))
    {
        traits |= BKIPC_ETW_TRAIT_LOLBIN;
    }

    if (Event.TargetPid != 0 && Event.TargetPid != Event.ProcessId &&
        (traits &
         (BKIPC_ETW_TRAIT_REMOTE_EXECUTION | BKIPC_ETW_TRAIT_MEMORY_WRITE_VM | BKIPC_ETW_TRAIT_MEMORY_PROTECT_RX)) != 0)
    {
        traits |= BKIPC_ETW_TRAIT_SCAN_TARGET_PROCESS;
    }

    if ((isProcessFamily || isImageFamily || ControllerWideContainsInsensitive(Event.EventName, L"load") ||
         ControllerWideContainsInsensitive(Event.EventName, L"create")) &&
        Event.ImagePath[0] != L'\0')
    {
        traits |= BKIPC_ETW_TRAIT_SCAN_IMAGE_PATH;
    }

    return traits;
}

inline UINT32 ControllerHeurFlagsFromDetectionTraits(_In_ UINT32 traits)
{
    UINT32 heurFlags = 0;

    if ((traits & BKIPC_ETW_TRAIT_MEMORY_ALLOC_RW) != 0)
        heurFlags |= BK_HEUR_FLAG_ALLOC_RW;
    if ((traits & BKIPC_ETW_TRAIT_MEMORY_WRITE_VM) != 0)
        heurFlags |= BK_HEUR_FLAG_WRITE_VM;
    if ((traits & BKIPC_ETW_TRAIT_MEMORY_PROTECT_RX) != 0)
        heurFlags |= BK_HEUR_FLAG_PROTECT_RX;
    if ((traits & BKIPC_ETW_TRAIT_NETWORK) != 0)
        heurFlags |= BK_HEUR_FLAG_NETWORK;
    if ((traits & BKIPC_ETW_TRAIT_REMOTE_EXECUTION) != 0)
        heurFlags |= BK_HEUR_FLAG_REMOTE_TH;
    if ((traits & BKIPC_ETW_TRAIT_CREDENTIAL_ACCESS) != 0)
        heurFlags |= BK_HEUR_FLAG_CRED_ACCS;
    if ((traits & BKIPC_ETW_TRAIT_IMAGE_TAMPER) != 0)
        heurFlags |= BK_HEUR_FLAG_IMG_TAMPER;
    if ((traits & BKIPC_ETW_TRAIT_LOLBIN) != 0)
        heurFlags |= BK_HEUR_FLAG_LOLBIN;
    if ((traits & BKIPC_ETW_TRAIT_DETECTION_CLASS) != 0)
        heurFlags |= BK_HEUR_FLAG_DETECTION;

    return heurFlags;
}

#define BK_CONTROLLER_SERVICE_NAMEW L"BlackbirdController"
#define BK_SENSOR_CORE_IMAGE_NAMEW L"J58.dll"
#define BK_HOOK_IMAGE_NAMEW L"SR71.dll"
#define BK_DRIVER_IMAGE_NAMEW L"Blackbird.sys"
#define BK_CONTROLLER_ETW_SESSION_NAMEW L"BlackbirdControllerSession"
#define BK_CONTROLLER_VERSIONA "2.0.0"
#define BK_CONTROLLER_HOOK_CORE_REQUIRED_MASK                                                    \
    (BKIPC_HOOK_READY_FLAG_IPC_CONNECTED | BKIPC_HOOK_READY_FLAG_NT | BKIPC_HOOK_READY_FLAG_KI | \
     BKIPC_HOOK_READY_FLAG_MODULE)
#define BK_CONTROLLER_HOOK_LAUNCH_REQUIRED_MASK BK_CONTROLLER_HOOK_CORE_REQUIRED_MASK
#define BK_CONTROLLER_HOOK_READY_REQUIRED_MASK BK_CONTROLLER_HOOK_CORE_REQUIRED_MASK
#define BK_CONTROLLER_DRIVER_STREAM_MASK                                                                  \
    (BK_STREAM_HANDLE | BK_STREAM_MEMORY | BK_STREAM_THREAD | BK_STREAM_FILESYSTEM | BK_STREAM_REGISTRY | \
     BK_STREAM_TIMING | BK_STREAM_ENTERPRISE)

enum class BkctlrClientRole : DWORD
{
    Unknown = 0,
    Control = 1,
    Hook = 2
};
inline constexpr DWORD BkctlrClientRoleUnknown = static_cast<DWORD>(BkctlrClientRole::Unknown);
inline constexpr DWORD BkctlrClientRoleControl = static_cast<DWORD>(BkctlrClientRole::Control);
inline constexpr DWORD BkctlrClientRoleHook = static_cast<DWORD>(BkctlrClientRole::Hook);

typedef struct _BK_CONTROLLER_SUBSCRIPTION
{
    DWORD ProcessId;
    DWORD StreamMask;
    BOOL Dynamic;
    DWORD SourceProcessId;
    UINT32 Depth;
    ULONGLONG LastSeenTick;
} BK_CONTROLLER_SUBSCRIPTION, *PBK_CONTROLLER_SUBSCRIPTION;

#define BK_CONTROLLER_MAX_OWNED_RANGES 128u

typedef struct _BK_CONTROLLER_OWNED_RANGE
{
    UINT64 BaseAddress;
    UINT64 RegionSize;
    UINT32 Flags;
    CHAR Tag[BK_MAX_INSTRUMENTATION_TAG];
} BK_CONTROLLER_OWNED_RANGE, *PBK_CONTROLLER_OWNED_RANGE;

typedef struct _BK_CONTROLLER_EVENT_NODE
{
    struct _BK_CONTROLLER_EVENT_NODE *Next;
    BK_EVENT_RECORD Record;
} BK_CONTROLLER_EVENT_NODE, *PBK_CONTROLLER_EVENT_NODE;

typedef struct _BK_CONTROLLER_ETW_EVENT_NODE
{
    struct _BK_CONTROLLER_ETW_EVENT_NODE *Next;
    BKIPC_ETW_EVENT Event;
} BK_CONTROLLER_ETW_EVENT_NODE, *PBK_CONTROLLER_ETW_EVENT_NODE;

typedef struct _BK_CONTROLLER_CLIENT
{
    struct _BK_CONTROLLER_CLIENT *Next;
    HANDLE Pipe;
    DWORD ProcessId;
    DWORD SessionId;
    DWORD Role;
    DWORD SlotIndex;
    CRITICAL_SECTION Lock;
    DWORD SubscriptionCount;
    BK_CONTROLLER_SUBSCRIPTION Subscriptions[BK_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS];
    PBK_CONTROLLER_EVENT_NODE QueueHead;
    PBK_CONTROLLER_EVENT_NODE QueueTail;
    DWORD QueueDepth;
    DWORD DroppedEvents;
    HANDLE IoctlQueueDataEvent;
    PBK_CONTROLLER_EVENT_NODE IoctlNodeSlab;
    PBK_CONTROLLER_EVENT_NODE IoctlNodeFreeHead;
    PBK_CONTROLLER_ETW_EVENT_NODE EtwNodeSlab;
    PBK_CONTROLLER_ETW_EVENT_NODE EtwNodeFreeHead;
    PBK_CONTROLLER_ETW_EVENT_NODE EtwQueueHead;
    PBK_CONTROLLER_ETW_EVENT_NODE EtwQueueTail;
    DWORD EtwQueueDepth;
    DWORD EtwDroppedEvents;
    HANDLE EtwQueueDataEvent;
    BOOL SharedRingEnabled;
    HANDLE IoctlSharedMapping;
    HANDLE IoctlSharedDataEvent;
    PBKIPC_SHARED_RING_HEADER IoctlSharedHeader;
    PBYTE IoctlSharedRecords;
    HANDLE EtwSharedMapping;
    HANDLE EtwSharedDataEvent;
    PBKIPC_SHARED_RING_HEADER EtwSharedHeader;
    PBYTE EtwSharedRecords;
    BOOL PendingLaunchArmed;
    DWORD PendingLaunchPid;
    DWORD PendingAnalysisSubjectKind;
    ULONGLONG PendingLaunchArmedTick;
    WCHAR PendingLaunchImagePath[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR PendingAnalysisSubjectPath[BK_MAX_IMAGE_PATH_CHARS];
    ULONGLONG AnalysisSessionId;
    DWORD AnalysisRootProcessId;
    BOOL AnalysisLaunchOwned;
    BOOL AnalysisActive;
    ULONGLONG AnalysisStartedTick;
    volatile LONG HookReadyMask;
    ULONGLONG HookReadyTick;
    volatile LONG DispatchRefCount;
    volatile LONG Detached;
    HANDLE DispatchIdleEvent;
    volatile LONG WinsockInlineUpgradePending;
    DWORD OwnedRangeCount;
    BK_CONTROLLER_OWNED_RANGE
    OwnedRanges[BK_CONTROLLER_MAX_OWNED_RANGES];
} BK_CONTROLLER_CLIENT, *PBK_CONTROLLER_CLIENT;

inline BOOL ControllerIsBlackbirdOwnedAddress(_In_ const BK_CONTROLLER_CLIENT *Client, _In_ UINT64 Address)
{
    if (Client == NULL || Address == 0 || Client->OwnedRangeCount == 0)
        return FALSE;
    for (DWORD i = 0; i < Client->OwnedRangeCount; ++i)
    {
        const BK_CONTROLLER_OWNED_RANGE *r = &Client->OwnedRanges[i];
        if (r->BaseAddress == 0 || r->RegionSize == 0)
            continue;
        if (Address >= r->BaseAddress && Address < r->BaseAddress + r->RegionSize)
            return TRUE;
    }
    return FALSE;
}

typedef struct _BK_CONTROLLER_PID_INDEX_ENTRY
{
    DWORD ProcessId;
    DWORD StreamMask;
    DWORD ClientMask[BK_CONTROLLER_CLIENT_MASK_DWORDS];
    DWORD ClientStreamMask[BK_CONTROLLER_MAX_CLIENTS];
} BK_CONTROLLER_PID_INDEX_ENTRY, *PBK_CONTROLLER_PID_INDEX_ENTRY;

typedef struct _BK_CONTROLLER_HOLLOW_ENTRY
{
    BOOL Active;
    DWORD ActorPid;
    DWORD TargetPid;
    ULONGLONG FirstSeenTick;
    ULONGLONG LastSeenTick;
    ULONGLONG LastAllocBase;
    ULONGLONG LastAllocSize;
    ULONG LastAllocProtect;
    ULONGLONG LastWriteBase;
    ULONGLONG LastWriteSize;
    ULONGLONG LastWriteTick;
    ULONGLONG LastProtectRxBase;
    ULONGLONG LastProtectRxSize;
    ULONG LastProtectRxProtect;
    ULONGLONG LastProtectRxTick;
    ULONGLONG LastThreadStartAddress;
    ULONGLONG LastThreadStartTick;
    ULONGLONG LastDllPathWriteTick;
    ULONGLONG LastThreadCreateTarget;
    ULONGLONG LastThreadCreateTick;
    UINT32 LastThreadCreateKind;
    UINT32 LastThreadCreateHasPe;
    ULONGLONG LastThreadCreateRegionBase;
    ULONGLONG LastThreadCreateRegionSize;
    ULONGLONG LastApcRoutine;
    ULONGLONG LastApcTick;
    UINT32 LastApcKind;
    UINT32 LastApcHasPe;
    ULONGLONG LastApcRegionBase;
    ULONGLONG LastApcRegionSize;
    ULONGLONG LastSetContextRip;
    ULONGLONG LastSetContextRsp;
    ULONGLONG LastSetContextTick;
    UINT32 LastSetContextKind;
    UINT32 LastSetContextHasPe;
    ULONGLONG LastSetContextRegionBase;
    ULONGLONG LastSetContextRegionSize;
    ULONGLONG LastSuspendTick;
    ULONGLONG LastResumeTick;
    ULONGLONG LastImageLoadTick;
    ULONGLONG LastImageLoadBase;
    ULONGLONG LastImageLoadSize;
    WCHAR LastImageLoadPath[BKIPC_MAX_ETW_IMAGE_PATH];
    UINT64 Marks;
    ULONGLONG LastMediumEmitTick;
    ULONGLONG LastStrongEmitTick;
    ULONGLONG LastManualMapLikelyEmitTick;
    ULONGLONG LastManualMapConfirmedEmitTick;
    ULONGLONG LastManualMapHeaderlessEmitTick;
    ULONGLONG LastRemoteThreadDllEmitTick;
    ULONGLONG LastApcDllEmitTick;
    ULONGLONG LastHijackDllEmitTick;
    ULONGLONG LastRemoteThreadPrivateEmitTick;
    ULONGLONG LastApcPrivateEmitTick;
    ULONGLONG LastHijackPrivateEmitTick;
    ULONGLONG LastManualMapProbeBase;
    ULONGLONG LastManualMapProbeSize;
    ULONGLONG LastManualMapProbeTick;
} BK_CONTROLLER_HOLLOW_ENTRY, *PBK_CONTROLLER_HOLLOW_ENTRY;

extern SERVICE_STATUS_HANDLE g_ServiceStatusHandle;
extern SERVICE_STATUS g_ServiceStatus;
extern HANDLE g_StopEvent;
extern HANDLE g_ServerThread;
extern HANDLE g_DriverPumpThread;
extern HANDLE g_EtwThread;
extern HANDLE g_DriverHandle;
extern BKSC_ETW_SESSION *g_EtwSession;
extern BOOL g_ThreatIntelEnabled;
extern DWORD g_ThreatIntelEnableError;
extern volatile LONG g_EtwDetectionEvents;
extern volatile LONG g_EtwTiEvents;
extern OwnedCriticalSection g_ClientListLock;
extern OwnedCriticalSection g_DriverLock;
extern OwnedCriticalSection g_DriverConfigLock;
extern volatile LONG g_DriverSubscriptionsDirty;
extern PBK_CONTROLLER_CLIENT g_ClientList;
extern PBK_CONTROLLER_CLIENT g_ClientSlots[BK_CONTROLLER_MAX_CLIENTS];
extern DWORD g_ClientCount;
extern DWORD g_ProgrammedPids[BK_MAX_PID_LIST];
extern DWORD g_ProgrammedPidCount;
extern BK_CONTROLLER_PID_INDEX_ENTRY g_PidIndex[BK_MAX_PID_LIST];
extern DWORD g_PidIndexCount;
extern SRWLOCK g_HollowLock;
extern BK_CONTROLLER_HOLLOW_ENTRY g_HollowEntries[BK_CONTROLLER_HOLLOW_MAX_ENTRIES];

VOID ControllerLogInit(VOID);
VOID ControllerLogClose(VOID);
VOID ControllerLog(_In_z_ _Printf_format_string_ PCSTR Format, ...);
VOID ControllerApplyProcessMitigations(VOID);
VOID ControllerUpdateServiceStatus(_In_ DWORD CurrentState, _In_ DWORD Win32ExitCode, _In_ DWORD WaitHint);
BOOL ControllerShouldStop(VOID);
VOID ControllerStopEtwSessionByNameBestEffort(_In_z_ PCWSTR SessionName, _In_z_ PCSTR Reason);
VOID ControllerCleanupStaleEtwSessions(VOID);

BOOL ControllerIsValidStreamMask(_In_ DWORD StreamMask);
VOID ControllerMarkDriverSubscriptionsDirty(VOID);
BOOL ControllerStartDriverSubscriptionWorker(VOID);
VOID ControllerStopDriverSubscriptionWorker(VOID);
BOOL ControllerRequestDriverSubscriptionApply(_In_ BOOL WaitForCompletion, _In_ DWORD TimeoutMs);
BOOL ControllerApplyDriverSubscriptionsIfDirty(VOID);
DWORD ControllerAllocateClientSlotLocked(VOID);
VOID ControllerReleaseClientSlotLocked(_In_ DWORD SlotIndex);
VOID ControllerRebuildPidIndexLocked(_Out_opt_ BOOL *DynamicPruned);
VOID ControllerRemoveSubscriptionAtLocked(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_ DWORD Index);
BOOL ControllerDropDynamicDescendantsLocked(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_ DWORD RootProcessId);
BOOL ControllerDropProcessSubscriptions(_In_ DWORD ProcessId, _In_z_ PCSTR Reason);
VOID ControllerExpandMonitoringGraph(_In_ DWORD SourceProcessId, _In_ DWORD TargetProcessId,
                                     _In_ DWORD RelationStreamMask);
VOID ControllerClientDestroySharedRingsLocked(_Inout_ BK_CONTROLLER_CLIENT *Client);
VOID ControllerClientFreeQueueLocked(_Inout_ BK_CONTROLLER_CLIENT *Client);
VOID ControllerClientFreeEtwQueueLocked(_Inout_ BK_CONTROLLER_CLIENT *Client);
BOOL ControllerClientRetainForDispatchLocked(_Inout_ BK_CONTROLLER_CLIENT *Client);
VOID ControllerClientReleaseFromDispatch(_Inout_ BK_CONTROLLER_CLIENT *Client);
BOOL ControllerClientDequeueRecordLocked(_Inout_ BK_CONTROLLER_CLIENT *Client, _Out_ BK_EVENT_RECORD *Record);
BOOL ControllerClientEnqueueEtwEventLocked(_Inout_ BK_CONTROLLER_CLIENT *Client, _In_ const BKIPC_ETW_EVENT *Event);
BOOL ControllerClientDequeueEtwEventLocked(_Inout_ BK_CONTROLLER_CLIENT *Client, _Out_ BKIPC_ETW_EVENT *Event);
BOOL ControllerApplyDriverSubscriptions(VOID);
VOID ControllerDispatchDriverRecord(_In_ const BK_EVENT_RECORD *Record);

BOOL ControllerEtwGetU64Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONGLONG *Value);
BOOL ControllerEtwGetU32Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ ULONG *Value);
BOOL ControllerEtwGetI32Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ LONG *Value);
BOOL ControllerEtwGetU8Property(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ UCHAR *Value);
BOOL ControllerEtwGetBoolProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name, _Out_ BOOL *Value);
BOOL ControllerEtwGetAnsiProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name,
                                  _Out_writes_z_(OutputChars) PSTR Output, _In_ size_t OutputChars);
BOOL ControllerEtwGetWideProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name,
                                  _Out_writes_z_(OutputChars) PWSTR Output, _In_ size_t OutputChars);
BOOL ControllerEtwCopyBinaryProperty(_In_ PEVENT_RECORD Record, _In_z_ PCWSTR Name,
                                     _Out_writes_bytes_(Capacity) PBYTE Output, _In_ ULONG Capacity,
                                     _Out_opt_ UINT32 *BytesCopied);
VOID ControllerDispatchEtwEvent(_In_ const BKIPC_ETW_EVENT *Event);

VOID ControllerProcessHollowingEtwRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                         _In_ const BKIPC_ETW_EVENT *BrokerEvent);
VOID ControllerObserveUserHookHollowEvent(_In_ const BKIPC_ETW_EVENT *Event);
VOID ControllerResetHollowingState(VOID);
BOOL ControllerStartHollowingWorkers(VOID);
VOID ControllerStopHollowingWorkers(VOID);
VOID ControllerPicCorrelationObserve(_In_ const BKIPC_ETW_EVENT *Event);
VOID ControllerPicCorrelationApply(_Inout_ BKIPC_ETW_EVENT *Event);
VOID ControllerPicCorrelationReset(VOID);

BOOL ControllerSymbolServiceStart(VOID);
VOID ControllerSymbolServiceStop(VOID);
VOID ControllerSymbolServiceEnrichEvent(_Inout_ BKIPC_ETW_EVENT *Event);
BOOL ControllerSymbolServiceResolveHookAddress(_In_ DWORD ProcessId, _In_ UINT64 Address,
                                               _Out_writes_z_(TextChars) PWSTR Text, _In_ size_t TextChars,
                                               _Out_opt_ PWSTR Path, _In_ size_t PathChars);
VOID ControllerSymbolServicePrimeHookAddress(_In_ DWORD ProcessId, _In_ UINT64 Address);
BOOL ControllerCreatePipeSecurity(_In_ DWORD ClientRole, _Out_ PSECURITY_ATTRIBUTES SecurityAttributes,
                                  _Outptr_ PSECURITY_DESCRIPTOR *SecurityDescriptor);
DWORD ControllerWaitForHookReady(_In_ DWORD ProcessId);
VOID ControllerDetachClient(_Inout_ BK_CONTROLLER_CLIENT *Client);
VOID ControllerTryMarkProtectedReady(_In_ HANDLE DriverHandle, _In_ BOOL LogFailure);
DWORD WINAPI ControllerClientThreadProc(_In_ LPVOID Context);

// ABI safety assertions
// Structs that cross the C/C++ or kernel/usermode boundary must remain
// trivially copyable POD so that the compiler cannot silently insert padding
// or vtable pointers.
static_assert(std::is_trivially_copyable_v<BK_CONTROLLER_SUBSCRIPTION>,
              "BK_CONTROLLER_SUBSCRIPTION must remain trivially copyable");
static_assert(std::is_trivially_copyable_v<BK_CONTROLLER_CLIENT>,
              "BK_CONTROLLER_CLIENT must remain trivially copyable");
static_assert(std::is_trivially_copyable_v<BK_CONTROLLER_HOLLOW_ENTRY>,
              "BK_CONTROLLER_HOLLOW_ENTRY must remain trivially copyable");
static_assert(std::is_trivially_copyable_v<BK_CONTROLLER_PID_INDEX_ENTRY>,
              "BK_CONTROLLER_PID_INDEX_ENTRY must remain trivially copyable");

// Service entry points — must keep C linkage to match SCM expectations.
extern "C"
{
    VOID WINAPI ServiceMain(_In_ DWORD argc, _In_ LPWSTR *argv);
    DWORD WINAPI ServiceCtrlHandlerEx(_In_ DWORD control, _In_ DWORD eventType, _In_opt_ LPVOID eventData,
                                      _In_opt_ LPVOID context);
}

#endif
