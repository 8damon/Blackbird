#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "control.h"
#include "pool_compat.h"

#define SLEEPWALKER_POOL_TAG 'lrtS'
#define SLEEPWALKER_MAX_CLIENT_SUBSCRIPTIONS 64
#define SLEEPWALKER_MAX_CLIENT_QUEUE_DEPTH 1024
#define SLEEPWALKER_MAX_TOTAL_CLIENTS 256
#define SLEEPWALKER_MAX_TOTAL_QUEUED_EVENTS 16384
#define SLEEPWALKER_QUERY_IMAGE_WINDOW_100NS 10000000ULL
#define SLEEPWALKER_QUERY_IMAGE_MAX_PER_WINDOW 64
#define SLEEPWALKER_QUERY_IMAGE_MAX_INFLIGHT 8

typedef struct _SLEEPWALKER_SUBSCRIPTION
{
    UINT32 ProcessId;
    UINT32 StreamMask;
} SLEEPWALKER_SUBSCRIPTION;

typedef struct _SLEEPWALKER_EVENT_NODE
{
    LIST_ENTRY Link;
    SLEEPWALKER_EVENT_RECORD Record;
} SLEEPWALKER_EVENT_NODE, *PSLEEPWALKER_EVENT_NODE;

typedef struct _SLEEPWALKER_CLIENT
{
    LIST_ENTRY Link;
    LIST_ENTRY EventQueue;
    FAST_MUTEX Lock;
    UINT32 Sequence;
    UINT32 QueueDepth;
    UINT32 DroppedEvents;
    UINT32 SubscriptionCount;
    ULONGLONG QueryWindowStart100ns;
    UINT32 QueryWindowCount;
    volatile LONG RefCount;
    SLEEPWALKER_SUBSCRIPTION Subscriptions[SLEEPWALKER_MAX_CLIENT_SUBSCRIPTIONS];
} SLEEPWALKER_CLIENT, *PSLEEPWALKER_CLIENT;

typedef struct _SLEEPWALKER_FILE_CONTEXT
{
    PSLEEPWALKER_CLIENT Client;
} SLEEPWALKER_FILE_CONTEXT, *PSLEEPWALKER_FILE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(SLEEPWALKER_FILE_CONTEXT, SLEEPWALKERGetFileContext);

static WDFDEVICE g_ControlDevice = NULL;
static FAST_MUTEX g_ClientListLock;
static LIST_ENTRY g_ClientList;
static LONG g_ClientCount = 0;
static volatile LONG g_ControlInitialized = 0;
static volatile LONG g_ControlShutdown = 0;
static volatile LONG g_ControlQueueDropLogCounter = 0;
static volatile LONG g_ControlTotalQueuedEvents = 0;
static volatile LONG g_QueryImageInflight = 0;
static volatile LONG g_QueryImageThrottleCounter = 0;
static volatile LONG g_IoctlGetEventDeliverCounter = 0;
static volatile LONG g_IoctlGetEventEmptyCounter = 0;
static volatile LONG g_IoctlGetStatsCounter = 0;

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS *Process);

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

#include "control/control_common.inc"
#include "control/control_ioctl_handlers.inc"
#include "control/control_dispatch_init.inc"
#include "control/control_uninit_exports.inc"

