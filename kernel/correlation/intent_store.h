#ifndef BLACKBIRD_CORRELATION_H
#define BLACKBIRD_CORRELATION_H

#include <ntdef.h>

#define BLACKBIRD_INTENT_PROCESS_MEMORY 0x00000001
#define BLACKBIRD_INTENT_THREAD_CONTEXT 0x00000002
#define BLACKBIRD_INTENT_DUP_HANDLE 0x00000004

NTSTATUS
BLACKBIRDCorrelationInitialize(VOID);

VOID BLACKBIRDCorrelationUninitialize(VOID);

VOID BLACKBIRDCorrelationRecordHandleIntent(_In_ HANDLE CallerPid,
                                            _In_ HANDLE TargetPid,
                                            _In_ ACCESS_MASK AccessMask,
                                            _In_ UINT32 IntentFlags);

BOOLEAN
BLACKBIRDCorrelationQueryRecentIntent(_In_ HANDLE CallerPid,
                                      _In_ HANDLE TargetPid,
                                      _In_ UINT32 WindowMs,
                                      _Out_opt_ UINT32 *IntentFlags,
                                      _Out_opt_ UINT32 *AccessMask,
                                      _Out_opt_ UINT32 *AgeMs);

BOOLEAN
BLACKBIRDCorrelationQueryRecentIntentForTarget(_In_ HANDLE TargetPid,
                                               _In_ UINT32 WindowMs,
                                               _In_ BOOLEAN PreferExternalCaller,
                                               _Out_opt_ HANDLE *CallerPid,
                                               _Out_opt_ UINT32 *IntentFlags,
                                               _Out_opt_ UINT32 *AccessMask,
                                               _Out_opt_ UINT32 *AgeMs);

BOOLEAN
BLACKBIRDCorrelationSelfCheck(VOID);

#endif
