#ifndef BK_CONTROL_PRIVATE_H
#define BK_CONTROL_PRIVATE_H

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "../control.h"
#include "../pool_compat.h"
#include "../tempus_debug.h"
#include "../diagnostics.h"

#define BK_POOL_TAG 'lrtS'
#define BK_MAX_CLIENT_SUBSCRIPTIONS 4096
#define BK_INITIAL_CLIENT_SUBSCRIPTIONS 64
#define BK_MAX_CLIENT_QUEUE_DEPTH 8192
#define BK_MAX_TOTAL_CLIENTS 256
#define BK_MAX_TOTAL_QUEUED_EVENTS 131072
#define BK_PID_INTEREST_INDEX_BUCKETS 16384
#define BK_QUERY_IMAGE_WINDOW_100NS 10000000ULL
#define BK_QUERY_IMAGE_MAX_PER_WINDOW 64
#define BK_QUERY_IMAGE_MAX_INFLIGHT 8

typedef struct _BK_SUBSCRIPTION
{
    UINT32 ProcessId;
    UINT32 StreamMask;
} BK_SUBSCRIPTION, *PBK_SUBSCRIPTION;

typedef struct _BK_EVENT_NODE
{
    LIST_ENTRY Link;
    BK_EVENT_RECORD Record;
} BK_EVENT_NODE, *PBK_EVENT_NODE;

typedef struct _BK_PID_INTEREST_ENTRY
{
    UINT32 ProcessId;
    UINT32 StreamMask;
} BK_PID_INTEREST_ENTRY, *PBK_PID_INTEREST_ENTRY;

typedef struct _BK_CLIENT
{
    LIST_ENTRY Link;
    LIST_ENTRY EventQueue;
    WDFQUEUE PendingGetEventQueue;
    FAST_MUTEX Lock;
    UINT32 Sequence;
    UINT32 QueueDepth;
    UINT32 DroppedEvents;
    UINT32 SubscriptionCount;
    UINT32 PendingLaunchStreamMask;
    UINT32 PendingAnalysisSubjectKind;
    UINT32 AnalysisSubjectKind;
    UINT32 AnalysisSubjectProcessId;
    UINT64 AnalysisSubjectImageBase;
    UINT64 AnalysisSubjectImageSize;
    ULONGLONG QueryWindowStart100ns;
    UINT32 QueryWindowCount;
    BOOLEAN PendingLaunchArmed;
    UCHAR PendingLaunchReserved[3];
    volatile LONG RefCount;
    UINT32 SubscriptionCapacity;
    UCHAR SubscriptionReserved[4];
    PBK_SUBSCRIPTION Subscriptions;
    WCHAR PendingLaunchPathNormDos[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR PendingLaunchPathNormNt[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR PendingLaunchPathTail[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR PendingSubjectPathNormDos[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR PendingSubjectPathNormNt[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR PendingSubjectPathTail[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR AnalysisSubjectPathNormDos[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR AnalysisSubjectPathNormNt[BK_MAX_IMAGE_PATH_CHARS];
    WCHAR AnalysisSubjectPathTail[BK_MAX_IMAGE_PATH_CHARS];
} BK_CLIENT, *PBK_CLIENT;

typedef struct _BK_FILE_CONTEXT
{
    PBK_CLIENT Client;
} BK_FILE_CONTEXT, *PBK_FILE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(BK_FILE_CONTEXT, BkctlGetFileContext);

extern WDFDEVICE g_ControlDevice;
extern FAST_MUTEX g_ClientListLock;
extern LIST_ENTRY g_ClientList;
extern LONG g_ClientCount;
extern volatile LONG g_ControlInitialized;
extern volatile LONG g_ControlShutdown;
extern volatile LONG g_ControlTelemetryArmed;
extern volatile LONG g_ControlQueueDropLogCounter;
extern volatile LONG g_ControlTotalQueuedEvents;
extern volatile LONG g_QueryImageInflight;
extern volatile LONG g_QueryImageThrottleCounter;
extern volatile LONG g_IoctlGetEventDeliverCounter;
extern volatile LONG g_IoctlGetEventEmptyCounter;
extern volatile LONG g_IoctlGetStatsCounter;
extern NPAGED_LOOKASIDE_LIST g_BkctlEventNodeLookaside;

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS *Process);

NTSYSAPI
NTSTATUS
NTAPI
PsSuspendProcess(_In_ PEPROCESS Process);

NTSYSAPI
NTSTATUS
NTAPI
PsResumeProcess(_In_ PEPROCESS Process);

NTSYSAPI
NTSTATUS
NTAPI
SeLocateProcessImageName(_In_ PEPROCESS Process, _Out_ PUNICODE_STRING *pImageFileName);

NTSYSAPI
NTSTATUS
NTAPI
PsLookupThreadByThreadId(_In_ HANDLE ThreadId, _Outptr_ PETHREAD *Thread);

NTSYSAPI
HANDLE
NTAPI
PsGetThreadProcessId(_In_ PETHREAD Thread);

NTSYSAPI
NTSTATUS
NTAPI
MmCopyVirtualMemory(_In_ PEPROCESS FromProcess, _In_ const VOID *FromAddress, _In_ PEPROCESS ToProcess,
                    _Out_writes_bytes_(BufferSize) PVOID ToAddress, _In_ SIZE_T BufferSize,
                    _In_ KPROCESSOR_MODE PreviousMode, _Out_ PSIZE_T NumberOfBytesCopied);

BOOLEAN BkctlModeAllowed(_In_ WDFREQUEST Request);
ULONG BkctlGetRequestorPid(VOID);
PCSTR BkctlIoctlName(_In_ ULONG Ioctl);
BOOLEAN BkctlIsShutdown(VOID);
VOID BkctlSetTelemetryArmed(_In_ BOOLEAN Armed);
VOID BkctlReleaseGlobalQueueSlot(VOID);
BOOLEAN BkctlClientConsumeQueryBudgetLocked(_Inout_ PBK_CLIENT Client);
BOOLEAN BkctlTryAcquireQueryInflightSlot(VOID);
VOID BkctlReleaseQueryInflightSlot(VOID);
VOID BkctlClientFreeQueuedEvents(_Inout_ PBK_CLIENT Client);
VOID BkctlClientRelease(_Inout_ PBK_CLIENT Client);
VOID BkctlClientReference(_Inout_ PBK_CLIENT Client);
BOOLEAN BkctlIsValidStreamMask(_In_ UINT32 StreamMask);
VOID BkctlClientClearPendingLaunchLocked(_Inout_ PBK_CLIENT Client);
VOID BkctlClientConfigurePendingLaunchLocked(_Inout_ PBK_CLIENT Client,
                                             _In_opt_ const BK_ARM_PENDING_LAUNCH_REQUEST *Request);
BOOLEAN BkctlClientAddOrUpdateSubscriptionLocked(_Inout_ PBK_CLIENT Client, _In_ UINT32 ProcessId,
                                                 _In_ UINT32 StreamMask);
BOOLEAN BkctlClientRemoveSubscriptionLocked(_Inout_ PBK_CLIENT Client, _In_ UINT32 ProcessId);
UINT32 BkctlClientReplaceSubscriptionsLocked(_Inout_ PBK_CLIENT Client,
                                             _In_reads_(ProcessCount) const UINT32 *ProcessIds,
                                             _In_ UINT32 ProcessCount, _In_ UINT32 StreamMask);
VOID BkctlInitializeEventNodeLookaside(VOID);
VOID BkctlUninitializeEventNodeLookaside(VOID);
PBK_EVENT_NODE BkctlAllocateEventNode(VOID);
VOID BkctlFreeEventNode(_Inout_ PBK_EVENT_NODE Node);
VOID BkctlInitializePidInterestIndex(VOID);
VOID BkctlClearPidInterestIndex(VOID);
VOID BkctlRebuildPidInterestIndex(VOID);
VOID BkctlRefreshArmedState(VOID);
UINT32 BkctlClientQuerySubscriptionMaskEither(_In_ PBK_CLIENT Client, _In_ UINT32 PrimaryProcessId,
                                              _In_ UINT32 SecondaryProcessId, _In_ UINT32 StreamMask);
BOOLEAN BkctlClientMatchSubscriptionEither(_In_ PBK_CLIENT Client, _In_ UINT32 PrimaryProcessId,
                                           _In_ UINT32 SecondaryProcessId, _In_ UINT32 StreamMask);
VOID BkctlPublishRecordToSubscribers(_In_ UINT32 PrimaryPid, _In_ UINT32 SecondaryPid, _In_ UINT32 StreamMask,
                                     _In_ BK_EVENT_RECORD *Record);

EVT_WDF_DEVICE_FILE_CREATE BkctlEvtFileCreate;
EVT_WDF_FILE_CLEANUP BkctlEvtFileCleanup;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL BkctlEvtIoDeviceControl;

NTSTATUS BkctlHandleSubscribeIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BkctlHandleUnsubscribeIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BkctlHandleGetEventIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut);
NTSTATUS BkctlHandleGetStatsIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut);
NTSTATUS BkctlHandleGetHealthIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut);
NTSTATUS BkctlHandleGetDiagnosticsIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut);
NTSTATUS BkctlHandleSetEndpointGuardIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BkctlHandleSetPidsIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BkctlHandleArmPendingLaunchIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BkctlHandleQueryProcessImageIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut);
NTSTATUS BkctlHandleSetShutdownModeIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BkctlHandleControlExecutionIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BkctlHandleSetRuntimeConfigIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BkctlHandleReadMemoryIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut);
NTSTATUS BkctlHandleGetRuntimeConfigIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut);
NTSTATUS BkctlHandleSetQpcTimingConfigIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BkctlHandleGetQpcTimingStateIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut);
NTSTATUS BkctlHandleMarkControllerReadyIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BkctlHandleRegisterInstrumentationRangeIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BkctlHandleRegisterHookPatchIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BkctlHandleRegisterProcessInstrumentationCallbackIoctl(_In_ PBK_CLIENT Client, _In_ WDFREQUEST Request);

#endif
