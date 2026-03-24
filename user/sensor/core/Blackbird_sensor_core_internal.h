#ifndef BLACKBIRD_SENSOR_CORE_INTERNAL_H
#define BLACKBIRD_SENSOR_CORE_INTERNAL_H

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
#include "..\blackbird_sensor_core.h"
#include "..\blackbird_etw_props.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _BLACKBIRDSC_ETW_SESSION
{
    WCHAR SessionName[128];
    TRACEHANDLE SessionHandle;
    TRACEHANDLE TraceHandle;
    BLACKBIRDSC_ETW_EVENT_CALLBACK Callback;
    PVOID CallbackContext;
    PVOID OwnedCallbackContext;
    volatile LONG ActiveRuns;
    HANDLE RunStoppedEvent;
} BLACKBIRDSC_ETW_SESSION_INTERNAL;

typedef struct _BLACKBIRDSC_STG_DETECTION_BRIDGE
{
    SwkDetectionCallback Callback;
    PVOID CallbackContext;
} BLACKBIRDSC_STG_DETECTION_BRIDGE;

extern volatile LONG g_BlackbirdProtocolMode;
extern WCHAR g_BlackbirdPipeName[MAX_PATH];
extern DWORD g_BlackbirdPipeTimeoutMs;
extern volatile LONG g_BlackbirdIpcSequence;
extern volatile LONG g_BlackbirdBrokerCapabilities;
extern volatile LONG g_BlackbirdBrokerThreatIntelEnabled;
extern volatile LONG g_BlackbirdBrokerThreatIntelEnableError;
extern volatile LONG g_BlackbirdLastTiEnableError;
extern volatile LONG g_BlackbirdLastSharedRingError;
extern SRWLOCK g_BlackbirdProtocolLock;

VOID WINAPI BLACKBIRDSCInternalRecordCallback(_In_ PEVENT_RECORD Record);
VOID WINAPI BLACKBIRDSCStgDetectionBridgeCallback(_In_ PEVENT_RECORD Record, _In_opt_z_ PCWSTR EventName,
                                                  _In_opt_ PVOID Context);

#endif
