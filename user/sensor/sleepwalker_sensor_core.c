#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <strsafe.h>
#include <ntsecapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sleepwalker_sensor_core.h"
#include "sleepwalker_etw_props.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

SLEEPWALKERSC_API const GUID SLEEPWALKERSC_PROVIDER_GUID_SLEEPWALKER = {
    0xd6c73f8a, 0x6ad8, 0x4f4b, {0xa3, 0x63, 0x3d, 0x2f, 0xa3, 0x1c, 0xd0, 0xe2}};
SLEEPWALKERSC_API const GUID SLEEPWALKERSC_PROVIDER_GUID_TI = {
    0xf4e1897c, 0xbb5d, 0x5668, {0xf1, 0xd8, 0x04, 0x0f, 0x4d, 0x8d, 0xd3, 0x44}};
SLEEPWALKERSC_API const GUID SLEEPWALKERSC_PROVIDER_GUID_KERNEL_NETWORK = {
    0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};

typedef struct _SLEEPWALKERSC_ETW_SESSION
{
    WCHAR SessionName[128];
    TRACEHANDLE SessionHandle;
    TRACEHANDLE TraceHandle;
    SLEEPWALKERSC_ETW_EVENT_CALLBACK Callback;
    PVOID CallbackContext;
    PVOID OwnedCallbackContext;
    volatile LONG ActiveRuns;
    HANDLE RunStoppedEvent;
} SLEEPWALKERSC_ETW_SESSION_INTERNAL;

typedef struct _SLEEPWALKERSC_STG_DETECTION_BRIDGE
{
    SwkDetectionCallback Callback;
    PVOID CallbackContext;
} SLEEPWALKERSC_STG_DETECTION_BRIDGE;

static volatile LONG g_SleepwalkerProtocolMode = SLEEPWALKERSC_PROTOCOL_SERVICE;
static WCHAR g_SleepwalkerPipeName[MAX_PATH] = SLEEPWALKER_IPC_PIPE_NAME;
static DWORD g_SleepwalkerPipeTimeoutMs = 3000;
static volatile LONG g_SleepwalkerIpcSequence = 1;
static volatile LONG g_SleepwalkerBrokerCapabilities = 0;
static volatile LONG g_SleepwalkerBrokerThreatIntelEnabled = 0;
static volatile LONG g_SleepwalkerBrokerThreatIntelEnableError = 0;
static volatile LONG g_SleepwalkerLastTiEnableError = 0;
static volatile LONG g_SleepwalkerLastSharedRingError = ERROR_NOT_FOUND;
static SRWLOCK g_SleepwalkerProtocolLock = SRWLOCK_INIT;

#include "core/sleepwalker_sensor_core_protocol.inc"
#include "core/sleepwalker_sensor_core_etw.inc"

