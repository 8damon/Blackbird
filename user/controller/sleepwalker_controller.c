#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winsvc.h>
#include <sddl.h>
#include <strsafe.h>
#include <tdh.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "..\sensor\sleepwalker_sensor_core.h"
#include "..\..\abi\sleepwalker_ipc.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

#define SLEEPWALKER_CONTROLLER_SERVICE_NAMEW L"SleepwlkrController"
#define SLEEPWALKER_CONTROLLER_ETW_SESSION_NAMEW L"SleepwlkrControllerSession"
#define SLEEPWALKER_CONTROLLER_MAX_CLIENTS 256u
#define SLEEPWALKER_CONTROLLER_INVALID_SLOT 0xFFFFFFFFu
#define SLEEPWALKER_CONTROLLER_CLIENT_MASK_DWORDS ((SLEEPWALKER_CONTROLLER_MAX_CLIENTS + 31u) / 32u)
#define SLEEPWALKER_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS 256u
#define SLEEPWALKER_CONTROLLER_MAX_CLIENT_QUEUE_DEPTH 1024u
#define SLEEPWALKER_CONTROLLER_MAX_CLIENT_ETW_QUEUE_DEPTH 2048u
#define SLEEPWALKER_CONTROLLER_SHARED_IOCTL_RING_CAPACITY 16384u
#define SLEEPWALKER_CONTROLLER_SHARED_ETW_RING_CAPACITY 4096u
#define SLEEPWALKER_CONTROLLER_DYNAMIC_SUBSCRIPTION_TTL_MS 120000u
#define SLEEPWALKER_CONTROLLER_DYNAMIC_SUBSCRIPTION_MAX_DEPTH 3u
#define SLEEPWALKER_CONTROLLER_HOLLOW_MAX_ENTRIES 256u
#define SLEEPWALKER_CONTROLLER_HOLLOW_WINDOW_MS 30000u
#define SLEEPWALKER_CONTROLLER_HOLLOW_LARGE_ALLOC_BYTES 0x8000ull
#define SLEEPWALKER_CONTROLLER_DRIVER_STREAM_MASK \
    (SLEEPWALKER_STREAM_HANDLE | SLEEPWALKER_STREAM_MEMORY | SLEEPWALKER_STREAM_THREAD | SLEEPWALKER_STREAM_FILESYSTEM)

typedef struct _SLEEPWALKER_CONTROLLER_SUBSCRIPTION
{
    DWORD ProcessId;
    DWORD StreamMask;
    BOOL Dynamic;
    DWORD SourceProcessId;
    UINT32 Depth;
    ULONGLONG LastSeenTick;
} SLEEPWALKER_CONTROLLER_SUBSCRIPTION, *PSLEEPWALKER_CONTROLLER_SUBSCRIPTION;

typedef struct _SLEEPWALKER_CONTROLLER_EVENT_NODE
{
    struct _SLEEPWALKER_CONTROLLER_EVENT_NODE *Next;
    SLEEPWALKER_EVENT_RECORD Record;
} SLEEPWALKER_CONTROLLER_EVENT_NODE, *PSLEEPWALKER_CONTROLLER_EVENT_NODE;

typedef struct _SLEEPWALKER_CONTROLLER_ETW_EVENT_NODE
{
    struct _SLEEPWALKER_CONTROLLER_ETW_EVENT_NODE *Next;
    SLEEPWALKER_IPC_ETW_EVENT Event;
} SLEEPWALKER_CONTROLLER_ETW_EVENT_NODE, *PSLEEPWALKER_CONTROLLER_ETW_EVENT_NODE;

typedef struct _SLEEPWALKER_CONTROLLER_CLIENT
{
    struct _SLEEPWALKER_CONTROLLER_CLIENT *Next;
    HANDLE Pipe;
    DWORD ProcessId;
    DWORD SessionId;
    DWORD SlotIndex;
    CRITICAL_SECTION Lock;
    DWORD SubscriptionCount;
    SLEEPWALKER_CONTROLLER_SUBSCRIPTION Subscriptions[SLEEPWALKER_CONTROLLER_MAX_CLIENT_SUBSCRIPTIONS];
    PSLEEPWALKER_CONTROLLER_EVENT_NODE QueueHead;
    PSLEEPWALKER_CONTROLLER_EVENT_NODE QueueTail;
    DWORD QueueDepth;
    DWORD DroppedEvents;
    PSLEEPWALKER_CONTROLLER_ETW_EVENT_NODE EtwQueueHead;
    PSLEEPWALKER_CONTROLLER_ETW_EVENT_NODE EtwQueueTail;
    DWORD EtwQueueDepth;
    DWORD EtwDroppedEvents;
    BOOL SharedRingEnabled;
    HANDLE IoctlSharedMapping;
    HANDLE IoctlSharedDataEvent;
    PSLEEPWALKER_IPC_SHARED_RING_HEADER IoctlSharedHeader;
    PBYTE IoctlSharedRecords;
    HANDLE EtwSharedMapping;
    HANDLE EtwSharedDataEvent;
    PSLEEPWALKER_IPC_SHARED_RING_HEADER EtwSharedHeader;
    PBYTE EtwSharedRecords;
} SLEEPWALKER_CONTROLLER_CLIENT, *PSLEEPWALKER_CONTROLLER_CLIENT;

typedef struct _SLEEPWALKER_CONTROLLER_PID_INDEX_ENTRY
{
    DWORD ProcessId;
    DWORD StreamMask;
    DWORD ClientMask[SLEEPWALKER_CONTROLLER_CLIENT_MASK_DWORDS];
} SLEEPWALKER_CONTROLLER_PID_INDEX_ENTRY, *PSLEEPWALKER_CONTROLLER_PID_INDEX_ENTRY;

static VOID ControllerClientDestroySharedRingsLocked(_Inout_ SLEEPWALKER_CONTROLLER_CLIENT *Client);

typedef struct _SLEEPWALKER_CONTROLLER_HOLLOW_ENTRY
{
    BOOL Active;
    DWORD ActorPid;
    DWORD TargetPid;
    ULONGLONG FirstSeenTick;
    ULONGLONG LastSeenTick;
    ULONGLONG LastAllocBase;
    ULONGLONG LastAllocSize;
    ULONG LastAllocProtect;
    UINT64 Marks;
    ULONGLONG LastMediumEmitTick;
    ULONGLONG LastStrongEmitTick;
} SLEEPWALKER_CONTROLLER_HOLLOW_ENTRY, *PSLEEPWALKER_CONTROLLER_HOLLOW_ENTRY;

static SERVICE_STATUS_HANDLE g_ServiceStatusHandle = NULL;
static SERVICE_STATUS g_ServiceStatus;
static HANDLE g_StopEvent = NULL;
static HANDLE g_ServerThread = NULL;
static HANDLE g_DriverPumpThread = NULL;
static HANDLE g_EtwThread = NULL;
static HANDLE g_DriverHandle = INVALID_HANDLE_VALUE;
static SLEEPWALKERSC_ETW_SESSION *g_EtwSession = NULL;
static BOOL g_ThreatIntelEnabled = FALSE;
static DWORD g_ThreatIntelEnableError = ERROR_SUCCESS;
static volatile LONG g_EtwDetectionEvents = 0;
static volatile LONG g_EtwTiEvents = 0;
static CRITICAL_SECTION g_ClientListLock;
static CRITICAL_SECTION g_DriverLock;
static CRITICAL_SECTION g_DriverConfigLock;
static BOOL g_LocksInitialized = FALSE;
static volatile LONG g_DriverSubscriptionsDirty = 0;
static PSLEEPWALKER_CONTROLLER_CLIENT g_ClientList = NULL;
static PSLEEPWALKER_CONTROLLER_CLIENT g_ClientSlots[SLEEPWALKER_CONTROLLER_MAX_CLIENTS];
static DWORD g_ClientCount = 0;
static DWORD g_ProgrammedPids[SLEEPWALKER_MAX_PID_LIST];
static DWORD g_ProgrammedPidCount = 0;
static SLEEPWALKER_CONTROLLER_PID_INDEX_ENTRY g_PidIndex[SLEEPWALKER_MAX_PID_LIST];
static DWORD g_PidIndexCount = 0;
static SRWLOCK g_HollowLock = SRWLOCK_INIT;
static SLEEPWALKER_CONTROLLER_HOLLOW_ENTRY g_HollowEntries[SLEEPWALKER_CONTROLLER_HOLLOW_MAX_ENTRIES];

static VOID ControllerLog(_In_z_ _Printf_format_string_ PCSTR Format, ...)
{
    char message[1024];
    va_list args;

    va_start(args, Format);
    (void)StringCchVPrintfA(message, RTL_NUMBER_OF(message), Format, args);
    va_end(args);

    (void)OutputDebugStringA(message);
    (void)printf("%s", message);
}

static VOID ControllerUpdateServiceStatus(_In_ DWORD CurrentState, _In_ DWORD Win32ExitCode, _In_ DWORD WaitHint)
{
    static DWORD checkpoint = 1;

    if (g_ServiceStatusHandle == NULL)
    {
        return;
    }

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = CurrentState;
    g_ServiceStatus.dwWin32ExitCode = Win32ExitCode;
    g_ServiceStatus.dwWaitHint = WaitHint;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (CurrentState == SERVICE_START_PENDING || CurrentState == SERVICE_STOP_PENDING)
    {
        g_ServiceStatus.dwCheckPoint = checkpoint++;
    }

    if (CurrentState == SERVICE_RUNNING)
    {
        g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }

    (void)SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
}

static BOOL ControllerShouldStop(VOID)
{
    return (g_StopEvent != NULL && WaitForSingleObject(g_StopEvent, 0) == WAIT_OBJECT_0);
}

static VOID ControllerStopEtwSessionByNameBestEffort(_In_z_ PCWSTR SessionName, _In_z_ PCSTR Reason)
{
    ULONG status;

    if (SessionName == NULL || SessionName[0] == L'\0')
    {
        return;
    }

    status = SLEEPWALKERSCStopSessionByName(SessionName);
    if (status == ERROR_SUCCESS)
    {
        ControllerLog("[ETW] stopped session reason=%s name=%ws\n", Reason, SessionName);
    }
    else
    {
        ControllerLog("[ETW][WARN] stop-by-name failed reason=%s name=%ws status=%lu\n", Reason, SessionName, status);
    }
}

static VOID ControllerCleanupStaleEtwSessions(VOID)
{
    ControllerStopEtwSessionByNameBestEffort(SLEEPWALKER_CONTROLLER_ETW_SESSION_NAMEW, "pre-start");
}

#include "core/monitoring/sleepwalker_controller_subscriptions.inc"
#include "core/monitoring/sleepwalker_controller_etw_monitor.inc"
#include "core/correlation/sleepwalker_controller_hollowing.inc"
#include "core/ipc/sleepwalker_controller_ipc.inc"
#include "core/runtime/sleepwalker_controller_runtime.inc"

