#ifndef BLACKBIRD_CONTROLLER_PRIVATE_H
#define BLACKBIRD_CONTROLLER_PRIVATE_H

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winsvc.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <sddl.h>
#include <strsafe.h>
#include <tdh.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "..\\..\\sensor\\blackbird_sensor_core.h"
#include "..\\..\\..\\abi\\blackbird_ipc.h"
#include "heuristics\\Blackbird_controller_heuristics.h"

#define BLACKBIRD_CONTROLLER_SERVICE_NAMEW L"BlackbirdController"
#define BLACKBIRD_CONTROLLER_ETW_SESSION_NAMEW L"BlackbirdControllerSession"
#define BLACKBIRD_CONTROLLER_MAX_CLIENTS 256u
#define BLACKBIRD_CONTROLLER_INVALID_SLOT 0xFFFFFFFFu
#define BLACKBIRD_CONTROLLER_CLIENT_MASK_DWORDS ((BLACKBIRD_CONTROLLER_MAX_CLIENTS + 31u) / 32u)
#define BLACKBIRD_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS 256u
#define BLACKBIRD_CONTROLLER_MAX_CLIENT_QUEUE_DEPTH 1024u
#define BLACKBIRD_CONTROLLER_MAX_CLIENT_ETW_QUEUE_DEPTH 2048u
#define BLACKBIRD_CONTROLLER_SHARED_IOCTL_RING_CAPACITY 262144u
#define BLACKBIRD_CONTROLLER_SHARED_ETW_RING_CAPACITY 65536u
#define BLACKBIRD_CONTROLLER_DYNAMIC_SUBSCRIPTION_TTL_MS 120000u
#define BLACKBIRD_CONTROLLER_DYNAMIC_SUBSCRIPTION_MAX_DEPTH 3u
#define BLACKBIRD_CONTROLLER_HOOK_READY_TIMEOUT_MS 15000u
#define BLACKBIRD_CONTROLLER_HOOK_LAUNCH_REQUIRED_MASK BLACKBIRD_IPC_HOOK_READY_FLAG_IPC_CONNECTED
#define BLACKBIRD_CONTROLLER_HOOK_READY_REQUIRED_MASK BLACKBIRD_IPC_HOOK_READY_REQUIRED_MASK
#define BLACKBIRD_CONTROLLER_SERVER_ACCEPT_THREADS 3u
#define BLACKBIRD_CONTROLLER_HOOK_ACCEPT_THREADS 1u

typedef enum _BLACKBIRD_CONTROLLER_CLIENT_ROLE
{
    BlackbirdControllerClientRoleUnknown = 0,
    BlackbirdControllerClientRoleControl = 1,
    BlackbirdControllerClientRoleHook = 2
} BLACKBIRD_CONTROLLER_CLIENT_ROLE,
    *PBLACKBIRD_CONTROLLER_CLIENT_ROLE;
#define BLACKBIRD_CONTROLLER_HOLLOW_MAX_ENTRIES 256u
#define BLACKBIRD_CONTROLLER_HOLLOW_WINDOW_MS 30000u
#define BLACKBIRD_CONTROLLER_HOLLOW_LARGE_ALLOC_BYTES 0x8000ull
#define BLACKBIRD_CONTROLLER_MANUAL_MAP_EMIT_COOLDOWN_MS 4000u
#define BLACKBIRD_CONTROLLER_MANUAL_MAP_PROBE_MIN_INTERVAL_MS 1500u
#define BLACKBIRD_OPERATOR_DISCOVERY_PORT 49371u
#define BLACKBIRD_OPERATOR_STATUS_PORT 49372u
#define BLACKBIRD_OPERATOR_COMMAND_PORT 49373u
#define BLACKBIRD_OPERATOR_DISCOVERY_QUERY "BLACKBIRD_DISCOVER_V1"
#define BLACKBIRD_OPERATOR_BEACON_KIND "blackbird.node.beacon"
#define BLACKBIRD_OPERATOR_STATUS_KIND "blackbird.node.status"
#define BLACKBIRD_CONTROLLER_VERSIONA "1.7.0"
#define BLACKBIRD_CONTROLLER_DRIVER_STREAM_MASK \
    (BLACKBIRD_STREAM_HANDLE | BLACKBIRD_STREAM_MEMORY | BLACKBIRD_STREAM_THREAD | BLACKBIRD_STREAM_FILESYSTEM)

typedef struct _BLACKBIRD_CONTROLLER_SUBSCRIPTION
{
    DWORD ProcessId;
    DWORD StreamMask;
    BOOL Dynamic;
    DWORD SourceProcessId;
    UINT32 Depth;
    ULONGLONG LastSeenTick;
} BLACKBIRD_CONTROLLER_SUBSCRIPTION, *PBLACKBIRD_CONTROLLER_SUBSCRIPTION;

typedef struct _BLACKBIRD_CONTROLLER_EVENT_NODE
{
    struct _BLACKBIRD_CONTROLLER_EVENT_NODE *Next;
    BLACKBIRD_EVENT_RECORD Record;
} BLACKBIRD_CONTROLLER_EVENT_NODE, *PBLACKBIRD_CONTROLLER_EVENT_NODE;

typedef struct _BLACKBIRD_CONTROLLER_ETW_EVENT_NODE
{
    struct _BLACKBIRD_CONTROLLER_ETW_EVENT_NODE *Next;
    BLACKBIRD_IPC_ETW_EVENT Event;
} BLACKBIRD_CONTROLLER_ETW_EVENT_NODE, *PBLACKBIRD_CONTROLLER_ETW_EVENT_NODE;

typedef struct _BLACKBIRD_CONTROLLER_CLIENT
{
    struct _BLACKBIRD_CONTROLLER_CLIENT *Next;
    HANDLE Pipe;
    DWORD ProcessId;
    DWORD SessionId;
    DWORD Role;
    BOOL ControlAuthenticated;
    DWORD SlotIndex;
    CRITICAL_SECTION Lock;
    DWORD SubscriptionCount;
    BLACKBIRD_CONTROLLER_SUBSCRIPTION Subscriptions[BLACKBIRD_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS];
    PBLACKBIRD_CONTROLLER_EVENT_NODE QueueHead;
    PBLACKBIRD_CONTROLLER_EVENT_NODE QueueTail;
    DWORD QueueDepth;
    DWORD DroppedEvents;
    HANDLE IoctlQueueDataEvent;
    /* Pre-allocated IOCTL node slab: eliminates calloc/free in the hot enqueue path.
     * IoctlNodeSlab owns the allocation; IoctlNodeFreeHead is the free-list head. */
    PBLACKBIRD_CONTROLLER_EVENT_NODE IoctlNodeSlab;
    PBLACKBIRD_CONTROLLER_EVENT_NODE IoctlNodeFreeHead;
    /* Pre-allocated ETW node slab: same pattern as the IOCTL slab. */
    PBLACKBIRD_CONTROLLER_ETW_EVENT_NODE EtwNodeSlab;
    PBLACKBIRD_CONTROLLER_ETW_EVENT_NODE EtwNodeFreeHead;
    PBLACKBIRD_CONTROLLER_ETW_EVENT_NODE EtwQueueHead;
    PBLACKBIRD_CONTROLLER_ETW_EVENT_NODE EtwQueueTail;
    DWORD EtwQueueDepth;
    DWORD EtwDroppedEvents;
    HANDLE EtwQueueDataEvent;
    BOOL SharedRingEnabled;
    HANDLE IoctlSharedMapping;
    HANDLE IoctlSharedDataEvent;
    PBLACKBIRD_IPC_SHARED_RING_HEADER IoctlSharedHeader;
    PBYTE IoctlSharedRecords;
    HANDLE EtwSharedMapping;
    HANDLE EtwSharedDataEvent;
    PBLACKBIRD_IPC_SHARED_RING_HEADER EtwSharedHeader;
    PBYTE EtwSharedRecords;
    BOOL PendingLaunchArmed;
    DWORD PendingLaunchPid;
    ULONGLONG PendingLaunchArmedTick;
    WCHAR PendingLaunchImagePath[BLACKBIRD_MAX_IMAGE_PATH_CHARS];
    volatile LONG HookReadyMask;
    ULONGLONG HookReadyTick;
    volatile LONG DispatchRefCount;
    volatile LONG Detached;
    HANDLE DispatchIdleEvent;
} BLACKBIRD_CONTROLLER_CLIENT, *PBLACKBIRD_CONTROLLER_CLIENT;

typedef struct _BLACKBIRD_CONTROLLER_PID_INDEX_ENTRY
{
    DWORD ProcessId;
    DWORD StreamMask;
    DWORD ClientMask[BLACKBIRD_CONTROLLER_CLIENT_MASK_DWORDS];
} BLACKBIRD_CONTROLLER_PID_INDEX_ENTRY, *PBLACKBIRD_CONTROLLER_PID_INDEX_ENTRY;

typedef struct _BLACKBIRD_CONTROLLER_HOLLOW_ENTRY
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
    UINT64 Marks;
    ULONGLONG LastMediumEmitTick;
    ULONGLONG LastStrongEmitTick;
    ULONGLONG LastManualMapLikelyEmitTick;
    ULONGLONG LastManualMapConfirmedEmitTick;
    ULONGLONG LastManualMapHeaderlessEmitTick;
    ULONGLONG LastManualMapProbeBase;
    ULONGLONG LastManualMapProbeSize;
    ULONGLONG LastManualMapProbeTick;
} BLACKBIRD_CONTROLLER_HOLLOW_ENTRY, *PBLACKBIRD_CONTROLLER_HOLLOW_ENTRY;

extern SERVICE_STATUS_HANDLE g_ServiceStatusHandle;
extern SERVICE_STATUS g_ServiceStatus;
extern HANDLE g_StopEvent;
extern HANDLE g_ServerThread;
extern HANDLE g_DriverPumpThread;
extern HANDLE g_EtwThread;
extern HANDLE g_DriverHandle;
extern BLACKBIRDSC_ETW_SESSION *g_EtwSession;
extern BOOL g_ThreatIntelEnabled;
extern DWORD g_ThreatIntelEnableError;
extern volatile LONG g_EtwDetectionEvents;
extern volatile LONG g_EtwTiEvents;
extern CRITICAL_SECTION g_ClientListLock;
extern CRITICAL_SECTION g_DriverLock;
extern CRITICAL_SECTION g_DriverConfigLock;
extern BOOL g_LocksInitialized;
extern volatile LONG g_DriverSubscriptionsDirty;
extern PBLACKBIRD_CONTROLLER_CLIENT g_ClientList;
extern PBLACKBIRD_CONTROLLER_CLIENT g_ClientSlots[BLACKBIRD_CONTROLLER_MAX_CLIENTS];
extern DWORD g_ClientCount;
extern DWORD g_ProgrammedPids[BLACKBIRD_MAX_PID_LIST];
extern DWORD g_ProgrammedPidCount;
extern BLACKBIRD_CONTROLLER_PID_INDEX_ENTRY g_PidIndex[BLACKBIRD_MAX_PID_LIST];
extern DWORD g_PidIndexCount;
extern SRWLOCK g_HollowLock;
extern BLACKBIRD_CONTROLLER_HOLLOW_ENTRY g_HollowEntries[BLACKBIRD_CONTROLLER_HOLLOW_MAX_ENTRIES];

// Log path written to: %ProgramData%\Blackbird\Node\logs\controller.log
// Rotated to controller.log.1 when file exceeds 4 MB.
VOID ControllerLogInit(VOID);
VOID ControllerLogClose(VOID);
VOID ControllerLog(_In_z_ _Printf_format_string_ PCSTR Format, ...);
VOID ControllerUpdateServiceStatus(_In_ DWORD CurrentState, _In_ DWORD Win32ExitCode, _In_ DWORD WaitHint);
BOOL ControllerShouldStop(VOID);
VOID ControllerStopEtwSessionByNameBestEffort(_In_z_ PCWSTR SessionName, _In_z_ PCSTR Reason);
VOID ControllerCleanupStaleEtwSessions(VOID);

BOOL ControllerIsValidStreamMask(_In_ DWORD StreamMask);
VOID ControllerMarkDriverSubscriptionsDirty(VOID);
BOOL ControllerApplyDriverSubscriptionsIfDirty(VOID);
DWORD ControllerAllocateClientSlotLocked(VOID);
VOID ControllerReleaseClientSlotLocked(_In_ DWORD SlotIndex);
VOID ControllerRebuildPidIndexLocked(_Out_opt_ BOOL *DynamicPruned);
VOID ControllerRemoveSubscriptionAtLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client, _In_ DWORD Index);
BOOL ControllerDropDynamicDescendantsLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client, _In_ DWORD RootProcessId);
VOID ControllerExpandMonitoringGraph(_In_ DWORD SourceProcessId, _In_ DWORD TargetProcessId,
                                     _In_ DWORD RelationStreamMask);
VOID ControllerClientDestroySharedRingsLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client);
VOID ControllerClientFreeQueueLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client);
VOID ControllerClientFreeEtwQueueLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client);
BOOL ControllerClientRetainForDispatchLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client);
VOID ControllerClientReleaseFromDispatch(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client);
BOOL ControllerClientDequeueRecordLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                         _Out_ BLACKBIRD_EVENT_RECORD *Record);
BOOL ControllerClientEnqueueEtwEventLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                           _In_ const BLACKBIRD_IPC_ETW_EVENT *Event);
BOOL ControllerClientDequeueEtwEventLocked(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client,
                                           _Out_ BLACKBIRD_IPC_ETW_EVENT *Event);
BOOL ControllerApplyDriverSubscriptions(VOID);
VOID ControllerDispatchDriverRecord(_In_ const BLACKBIRD_EVENT_RECORD *Record);

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
VOID ControllerDispatchEtwEvent(_In_ const BLACKBIRD_IPC_ETW_EVENT *Event);

VOID ControllerProcessHollowingEtwRecord(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                         _In_ const BLACKBIRD_IPC_ETW_EVENT *BrokerEvent);
VOID ControllerResetHollowingState(VOID);
BOOL ControllerStartHollowingWorkers(VOID);
VOID ControllerStopHollowingWorkers(VOID);

BOOL ControllerSymbolServiceStart(VOID);
VOID ControllerSymbolServiceStop(VOID);
VOID ControllerSymbolServiceEnrichEvent(_Inout_ BLACKBIRD_IPC_ETW_EVENT *Event);
BOOL ControllerSymbolServiceResolveHookAddress(_In_ DWORD ProcessId, _In_ UINT64 Address,
                                               _Out_writes_z_(TextChars) PWSTR Text, _In_ size_t TextChars,
                                               _Out_opt_ PWSTR Path, _In_ size_t PathChars);
VOID ControllerSymbolServicePrimeHookAddress(_In_ DWORD ProcessId, _In_ UINT64 Address);
BOOL ControllerNodeNetworkStart(VOID);
VOID ControllerNodeNetworkStop(VOID);

BOOL ControllerCreatePipeSecurity(_In_ DWORD ClientRole, _Out_ PSECURITY_ATTRIBUTES SecurityAttributes,
                                  _Outptr_ PSECURITY_DESCRIPTOR *SecurityDescriptor);
DWORD ControllerWaitForHookReady(_In_ DWORD ProcessId);
VOID ControllerDetachClient(_Inout_ BLACKBIRD_CONTROLLER_CLIENT *Client);
DWORD WINAPI ControllerClientThreadProc(_In_ LPVOID Context);

#endif
