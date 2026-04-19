#ifndef BLACKBIRD_CONTROL_PRIVATE_H
#define BLACKBIRD_CONTROL_PRIVATE_H

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "../control.h"
#include "../pool_compat.h"
#include "../tempus_debug.h"

#define BLACKBIRD_POOL_TAG 'lrtS'
#define BLACKBIRD_MAX_CLIENT_SUBSCRIPTIONS 64
#define BLACKBIRD_MAX_CLIENT_QUEUE_DEPTH 1024
#define BLACKBIRD_MAX_TOTAL_CLIENTS 256
#define BLACKBIRD_MAX_TOTAL_QUEUED_EVENTS 16384
#define BLACKBIRD_QUERY_IMAGE_WINDOW_100NS 10000000ULL
#define BLACKBIRD_QUERY_IMAGE_MAX_PER_WINDOW 64
#define BLACKBIRD_QUERY_IMAGE_MAX_INFLIGHT 8

typedef struct _BLACKBIRD_SUBSCRIPTION
{
    UINT32 ProcessId;
    UINT32 StreamMask;
} BLACKBIRD_SUBSCRIPTION;

typedef struct _BLACKBIRD_EVENT_NODE
{
    LIST_ENTRY Link;
    BLACKBIRD_EVENT_RECORD Record;
} BLACKBIRD_EVENT_NODE, *PBLACKBIRD_EVENT_NODE;

typedef struct _BLACKBIRD_CLIENT
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
    ULONGLONG QueryWindowStart100ns;
    UINT32 QueryWindowCount;
    BOOLEAN PendingLaunchArmed;
    UCHAR PendingLaunchReserved[3];
    volatile LONG RefCount;
    BLACKBIRD_SUBSCRIPTION Subscriptions[BLACKBIRD_MAX_CLIENT_SUBSCRIPTIONS];
    WCHAR PendingLaunchPathNormDos[BLACKBIRD_MAX_IMAGE_PATH_CHARS];
    WCHAR PendingLaunchPathNormNt[BLACKBIRD_MAX_IMAGE_PATH_CHARS];
    WCHAR PendingLaunchPathTail[BLACKBIRD_MAX_IMAGE_PATH_CHARS];
} BLACKBIRD_CLIENT, *PBLACKBIRD_CLIENT;

typedef struct _BLACKBIRD_FILE_CONTEXT
{
    PBLACKBIRD_CLIENT Client;
} BLACKBIRD_FILE_CONTEXT, *PBLACKBIRD_FILE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(BLACKBIRD_FILE_CONTEXT, BLACKBIRDGetFileContext);

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

BOOLEAN BLACKBIRDModeAllowed(_In_ WDFREQUEST Request);
ULONG BLACKBIRDGetRequestorPid(VOID);
PCSTR BLACKBIRDIoctlName(_In_ ULONG Ioctl);
BOOLEAN BLACKBIRDControlIsShutdown(VOID);
VOID BLACKBIRDReleaseGlobalQueueSlot(VOID);
BOOLEAN BLACKBIRDClientConsumeQueryBudgetLocked(_Inout_ PBLACKBIRD_CLIENT Client);
BOOLEAN BLACKBIRDTryAcquireQueryInflightSlot(VOID);
VOID BLACKBIRDReleaseQueryInflightSlot(VOID);
VOID BLACKBIRDClientFreeQueuedEvents(_Inout_ PBLACKBIRD_CLIENT Client);
VOID BLACKBIRDClientRelease(_Inout_ PBLACKBIRD_CLIENT Client);
VOID BLACKBIRDClientReference(_Inout_ PBLACKBIRD_CLIENT Client);
BOOLEAN BLACKBIRDControlIsValidStreamMask(_In_ UINT32 StreamMask);
VOID BLACKBIRDClientClearPendingLaunchLocked(_Inout_ PBLACKBIRD_CLIENT Client);
VOID BLACKBIRDClientConfigurePendingLaunchLocked(_Inout_ PBLACKBIRD_CLIENT Client,
                                                 _In_opt_ const BLACKBIRD_ARM_PENDING_LAUNCH_REQUEST *Request);
BOOLEAN BLACKBIRDClientAddOrUpdateSubscriptionLocked(_Inout_ PBLACKBIRD_CLIENT Client, _In_ UINT32 ProcessId,
                                                     _In_ UINT32 StreamMask);
BOOLEAN BLACKBIRDClientRemoveSubscriptionLocked(_Inout_ PBLACKBIRD_CLIENT Client, _In_ UINT32 ProcessId);
UINT32 BLACKBIRDClientReplaceSubscriptionsLocked(_Inout_ PBLACKBIRD_CLIENT Client,
                                                 _In_reads_(ProcessCount) const UINT32 *ProcessIds,
                                                 _In_ UINT32 ProcessCount, _In_ UINT32 StreamMask);
VOID BLACKBIRDControlRefreshArmedState(VOID);
BOOLEAN BLACKBIRDClientMatchSubscriptionEither(_In_ PBLACKBIRD_CLIENT Client, _In_ UINT32 PrimaryProcessId,
                                               _In_ UINT32 SecondaryProcessId, _In_ UINT32 StreamMask);
VOID BLACKBIRDPublishRecordToSubscribers(_In_ UINT32 PrimaryPid, _In_ UINT32 SecondaryPid, _In_ UINT32 StreamMask,
                                         _In_ BLACKBIRD_EVENT_RECORD *Record);

EVT_WDF_DEVICE_FILE_CREATE BLACKBIRDEvtFileCreate;
EVT_WDF_FILE_CLEANUP BLACKBIRDEvtFileCleanup;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL BLACKBIRDEvtIoDeviceControl;

NTSTATUS BLACKBIRDHandleSubscribeIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BLACKBIRDHandleUnsubscribeIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BLACKBIRDHandleGetEventIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut);
NTSTATUS BLACKBIRDHandleGetStatsIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut);
NTSTATUS BLACKBIRDHandleGetHealthIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request, _Out_ size_t *BytesOut);
NTSTATUS BLACKBIRDHandleSetPidsIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BLACKBIRDHandleArmPendingLaunchIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BLACKBIRDHandleQueryProcessImageIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request,
                                               _Out_ size_t *BytesOut);
NTSTATUS BLACKBIRDHandleSetShutdownModeIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BLACKBIRDHandleControlExecutionIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BLACKBIRDHandleSetRuntimeConfigIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request);
NTSTATUS BLACKBIRDHandleGetRuntimeConfigIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request,
                                              _Out_ size_t *BytesOut);
NTSTATUS BLACKBIRDHandleMarkControllerReadyIoctl(_In_ PBLACKBIRD_CLIENT Client, _In_ WDFREQUEST Request);

#endif
