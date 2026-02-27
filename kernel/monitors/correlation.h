#ifndef SLEEPWALKER_CORRELATION_H
#define SLEEPWALKER_CORRELATION_H

#include <ntdef.h>

#define SLEEPWALKER_INTENT_PROCESS_MEMORY 0x00000001
#define SLEEPWALKER_INTENT_THREAD_CONTEXT 0x00000002
#define SLEEPWALKER_INTENT_DUP_HANDLE 0x00000004

NTSTATUS
SLEEPWALKERCorrelationInitialize(VOID);

VOID SLEEPWALKERCorrelationUninitialize(VOID);

VOID SLEEPWALKERCorrelationRecordHandleIntent(_In_ HANDLE CallerPid, _In_ HANDLE TargetPid, _In_ ACCESS_MASK AccessMask,
                                              _In_ UINT32 IntentFlags);

BOOLEAN
SLEEPWALKERCorrelationQueryRecentIntent(_In_ HANDLE CallerPid, _In_ HANDLE TargetPid, _In_ UINT32 WindowMs,
                                        _Out_opt_ UINT32 *IntentFlags, _Out_opt_ UINT32 *AccessMask,
                                        _Out_opt_ UINT32 *AgeMs);

BOOLEAN
SLEEPWALKERCorrelationQueryRecentIntentForTarget(_In_ HANDLE TargetPid, _In_ UINT32 WindowMs,
                                                 _In_ BOOLEAN PreferExternalCaller, _Out_opt_ HANDLE *CallerPid,
                                                 _Out_opt_ UINT32 *IntentFlags, _Out_opt_ UINT32 *AccessMask,
                                                 _Out_opt_ UINT32 *AgeMs);

BOOLEAN
SLEEPWALKERCorrelationSelfCheck(VOID);

#endif
