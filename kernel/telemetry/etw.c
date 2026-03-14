#include <ntddk.h>
#include <TraceLoggingProvider.h>
#include "etw.h"

#ifndef TRACE_LEVEL_INFORMATION
#define TRACE_LEVEL_INFORMATION 4
#endif

#ifndef BLACKBIRD_MAX_DEEP_SAMPLE_BYTES
#define BLACKBIRD_MAX_DEEP_SAMPLE_BYTES 64
#endif

TRACELOGGING_DEFINE_PROVIDER(g_BlackbirdEtwProvider,
                             "Blackbird.Kernel",
                             (0xd6c73f8a, 0x6ad8, 0x4f4b, 0xa3, 0x63, 0x3d, 0x2f, 0xa3, 0x1c, 0xd0, 0xe2));

static volatile LONG g_EtwState = 0; // 0=stopped, 1=starting, 2=started

static BOOLEAN BLACKBIRDEtwIsStarted(VOID)
{
    return (InterlockedCompareExchange(&g_EtwState, 0, 0) == 2);
}

NTSTATUS
BLACKBIRDEtwInitialize(VOID)
{
    NTSTATUS status;
    LONG prior;

    prior = InterlockedCompareExchange(&g_EtwState, 1, 0);
    if (prior == 2)
    {
        return STATUS_SUCCESS;
    }
    if (prior != 0)
    {
        return STATUS_DEVICE_BUSY;
    }

    status = TraceLoggingRegister(g_BlackbirdEtwProvider);
    if (!NT_SUCCESS(status))
    {
        InterlockedExchange(&g_EtwState, 0);
        return status;
    }

    InterlockedExchange(&g_EtwState, 2);
    return STATUS_SUCCESS;
}

VOID BLACKBIRDEtwUninitialize(VOID)
{
    LONG prior = InterlockedExchange(&g_EtwState, 0);
    if (prior == 2)
    {
        TraceLoggingUnregister(g_BlackbirdEtwProvider);
    }
}

BOOLEAN
BLACKBIRDEtwSelfCheck(VOID)
{
    return BLACKBIRDEtwIsStarted();
}

VOID BLACKBIRDEtwLogHandleEvent(_In_z_ PCSTR EventClass,
                                _In_ HANDLE CallerPid,
                                _In_ HANDLE TargetPid,
                                _In_ ACCESS_MASK DesiredAccess,
                                _In_ PVOID OriginAddress,
                                _In_ ULONG OriginProtect,
                                _In_ BOOLEAN ExecProtect,
                                _In_ BOOLEAN FromNtdll,
                                _In_ BOOLEAN FromExe,
                                _In_opt_z_ PCWSTR OriginPath,
                                _In_ ULONG FrameCount,
                                _In_reads_opt_(FrameCount) PVOID const *Frames,
                                _In_ NTSTATUS OpenProcessStatus,
                                _In_ NTSTATUS BasicInfoStatus,
                                _In_ NTSTATUS SectionNameStatus,
                                _In_ UINT64 DeepAllocationBase,
                                _In_ UINT64 DeepRegionSize,
                                _In_ ULONG DeepRegionProtect,
                                _In_ ULONG DeepRegionState,
                                _In_ ULONG DeepRegionType,
                                _In_ ULONG DeepSampleSize,
                                _In_reads_bytes_opt_(DeepSampleSize) const UCHAR *DeepSample)
{
    PVOID safeFrames[8] = { 0 };
    UCHAR safeDeepSample[BLACKBIRD_MAX_DEEP_SAMPLE_BYTES] = { 0 };
    ULONG safeFrameCount = 0;
    ULONG safeDeepSampleSize = 0;
    ULONG i;
    PCWSTR path;

    if (!BLACKBIRDEtwIsStarted())
    {
        return;
    }

    if (Frames != NULL)
    {
        safeFrameCount = (FrameCount > RTL_NUMBER_OF(safeFrames)) ? RTL_NUMBER_OF(safeFrames) : FrameCount;
        for (i = 0; i < safeFrameCount; ++i)
        {
            safeFrames[i] = Frames[i];
        }
    }
    if (DeepSample != NULL && DeepSampleSize != 0)
    {
        safeDeepSampleSize =
                (DeepSampleSize > RTL_NUMBER_OF(safeDeepSample)) ? RTL_NUMBER_OF(safeDeepSample) : DeepSampleSize;
        RtlCopyMemory(safeDeepSample, DeepSample, safeDeepSampleSize);
    }
    path = (OriginPath != NULL) ? OriginPath : L"";

    TraceLoggingWrite(g_BlackbirdEtwProvider,
                      "HandleTelemetry",
                      TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
                      TraceLoggingString((EventClass != NULL) ? EventClass : "UNKNOWN", "class"),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) CallerPid, "callerPid"),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) TargetPid, "targetPid"),
                      TraceLoggingHexUInt32((ULONG) DesiredAccess, "desiredAccess"),
                      TraceLoggingPointer(OriginAddress, "originAddress"),
                      TraceLoggingHexUInt32(OriginProtect, "originProtect"),
                      TraceLoggingBool(ExecProtect, "execProtect"),
                      TraceLoggingBool(FromNtdll, "fromNtdll"),
                      TraceLoggingBool(FromExe, "fromExe"),
                      TraceLoggingWideString(path, "originPath"),
                      TraceLoggingUInt32(safeFrameCount, "frameCount"),
                      TraceLoggingPointer(safeFrames[0], "stack0"),
                      TraceLoggingPointer(safeFrames[1], "stack1"),
                      TraceLoggingPointer(safeFrames[2], "stack2"),
                      TraceLoggingPointer(safeFrames[3], "stack3"),
                      TraceLoggingPointer(safeFrames[4], "stack4"),
                      TraceLoggingPointer(safeFrames[5], "stack5"),
                      TraceLoggingPointer(safeFrames[6], "stack6"),
                      TraceLoggingPointer(safeFrames[7], "stack7"),
                      TraceLoggingHexInt32((LONG) OpenProcessStatus, "statusOpenProcess"),
                      TraceLoggingHexInt32((LONG) BasicInfoStatus, "statusBasicInfo"),
                      TraceLoggingHexInt32((LONG) SectionNameStatus, "statusSectionName"),
                      TraceLoggingPointer((PVOID) (ULONG_PTR) DeepAllocationBase, "deepAllocationBase"),
                      TraceLoggingUInt64((ULONGLONG) DeepRegionSize, "deepRegionSize"),
                      TraceLoggingHexUInt32(DeepRegionProtect, "deepRegionProtect"),
                      TraceLoggingHexUInt32(DeepRegionState, "deepRegionState"),
                      TraceLoggingHexUInt32(DeepRegionType, "deepRegionType"),
                      TraceLoggingUInt32(safeDeepSampleSize, "deepSampleSize"),
                      TraceLoggingBinary(safeDeepSample, safeDeepSampleSize, "deepSample"));
}

VOID BLACKBIRDEtwLogThreadEvent(_In_ HANDLE ProcessId,
                                _In_ HANDLE ThreadId,
                                _In_ HANDLE CreatorPid,
                                _In_ PVOID StartAddress,
                                _In_ PVOID ImageBase,
                                _In_ SIZE_T ImageSize,
                                _In_ BOOLEAN GotStart,
                                _In_ BOOLEAN GotRange,
                                _In_ BOOLEAN IsRemoteCreator,
                                _In_ BOOLEAN OutsideMainImage,
                                _In_ UINT32 CorrelationFlags,
                                _In_ UINT32 CorrelationAccessMask,
                                _In_ UINT32 CorrelationAgeMs,
                                _In_ ULONG StartRegionProtect,
                                _In_ ULONG StartRegionState,
                                _In_ ULONG StartRegionType,
                                _In_ NTSTATUS StartRegionStatus,
                                _In_ ULONG WorkerFrameCount,
                                _In_reads_opt_(WorkerFrameCount) PVOID const *WorkerFrames)
{
    PVOID safeFrames[8] = { 0 };
    ULONG safeFrameCount = 0;
    ULONG i;

    if (!BLACKBIRDEtwIsStarted())
    {
        return;
    }

    if (WorkerFrames != NULL)
    {
        safeFrameCount = (WorkerFrameCount > RTL_NUMBER_OF(safeFrames)) ? RTL_NUMBER_OF(safeFrames) : WorkerFrameCount;
        for (i = 0; i < safeFrameCount; ++i)
        {
            safeFrames[i] = WorkerFrames[i];
        }
    }

    TraceLoggingWrite(g_BlackbirdEtwProvider,
                      "ThreadTelemetry",
                      TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) ProcessId, "processId"),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) ThreadId, "threadId"),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) CreatorPid, "creatorPid"),
                      TraceLoggingPointer(StartAddress, "startAddress"),
                      TraceLoggingPointer(ImageBase, "imageBase"),
                      TraceLoggingUInt64((ULONGLONG) ImageSize, "imageSize"),
                      TraceLoggingBool(GotStart, "gotStart"),
                      TraceLoggingBool(GotRange, "gotRange"),
                      TraceLoggingBool(IsRemoteCreator, "isRemoteCreator"),
                      TraceLoggingBool(OutsideMainImage, "outsideMainImage"),
                      TraceLoggingHexUInt32(CorrelationFlags, "correlationFlags"),
                      TraceLoggingHexUInt32(CorrelationAccessMask, "correlationAccessMask"),
                      TraceLoggingUInt32(CorrelationAgeMs, "correlationAgeMs"),
                      TraceLoggingHexUInt32(StartRegionProtect, "startRegionProtect"),
                      TraceLoggingHexUInt32(StartRegionState, "startRegionState"),
                      TraceLoggingHexUInt32(StartRegionType, "startRegionType"),
                      TraceLoggingHexInt32((LONG) StartRegionStatus, "startRegionStatus"),
                      TraceLoggingUInt32(safeFrameCount, "workerFrameCount"),
                      TraceLoggingPointer(safeFrames[0], "stack0"),
                      TraceLoggingPointer(safeFrames[1], "stack1"),
                      TraceLoggingPointer(safeFrames[2], "stack2"),
                      TraceLoggingPointer(safeFrames[3], "stack3"),
                      TraceLoggingPointer(safeFrames[4], "stack4"),
                      TraceLoggingPointer(safeFrames[5], "stack5"),
                      TraceLoggingPointer(safeFrames[6], "stack6"),
                      TraceLoggingPointer(safeFrames[7], "stack7"));
}

VOID BLACKBIRDEtwLogApcEvent(_In_z_ PCSTR EventClass,
                             _In_ HANDLE CallerPid,
                             _In_ HANDLE TargetPid,
                             _In_ ACCESS_MASK DesiredAccess,
                             _In_ BOOLEAN IsDuplicateOperation,
                             _In_ UINT32 CorrelationFlags,
                             _In_ UINT32 CorrelationAccessMask,
                             _In_ UINT32 CorrelationAgeMs)
{
    if (!BLACKBIRDEtwIsStarted())
    {
        return;
    }

    TraceLoggingWrite(g_BlackbirdEtwProvider,
                      "ApcTelemetry",
                      TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
                      TraceLoggingString((EventClass != NULL) ? EventClass : "UNKNOWN", "class"),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) CallerPid, "callerPid"),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) TargetPid, "targetPid"),
                      TraceLoggingHexUInt32((ULONG) DesiredAccess, "desiredAccess"),
                      TraceLoggingBool(IsDuplicateOperation, "isDuplicateOperation"),
                      TraceLoggingHexUInt32(CorrelationFlags, "correlationFlags"),
                      TraceLoggingHexUInt32(CorrelationAccessMask, "correlationAccessMask"),
                      TraceLoggingUInt32(CorrelationAgeMs, "correlationAgeMs"));
}

VOID BLACKBIRDEtwLogProcessEvent(_In_ HANDLE ProcessId,
                                 _In_ HANDLE ParentProcessId,
                                 _In_ HANDLE CreatorProcessId,
                                 _In_ HANDLE CreatorThreadId,
                                 _In_ ULONGLONG ProcessStartKey,
                                 _In_ ULONG SessionId,
                                 _In_ BOOLEAN IsCreate,
                                 _In_ NTSTATUS CreateStatus,
                                 _In_opt_z_ PCWSTR ImagePath,
                                 _In_opt_z_ PCWSTR CommandLine)
{
    PCWSTR safeImagePath;
    PCWSTR safeCommandLine;

    if (!BLACKBIRDEtwIsStarted())
    {
        return;
    }

    safeImagePath = (ImagePath != NULL) ? ImagePath : L"";
    safeCommandLine = (CommandLine != NULL) ? CommandLine : L"";

    TraceLoggingWrite(g_BlackbirdEtwProvider,
                      "ProcessTelemetry",
                      TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
                      TraceLoggingBool(IsCreate, "isCreate"),
                      TraceLoggingHexInt32((LONG) CreateStatus, "createStatus"),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) ProcessId, "processId"),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) ParentProcessId, "parentProcessId"),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) CreatorProcessId, "creatorProcessId"),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) CreatorThreadId, "creatorThreadId"),
                      TraceLoggingHexUInt64(ProcessStartKey, "processStartKey"),
                      TraceLoggingUInt32(SessionId, "sessionId"),
                      TraceLoggingWideString(safeImagePath, "imagePath"),
                      TraceLoggingWideString(safeCommandLine, "commandLine"));
}

VOID BLACKBIRDEtwLogImageLoadEvent(_In_ HANDLE ProcessId,
                                   _In_ PVOID ImageBase,
                                   _In_ SIZE_T ImageSize,
                                   _In_ BOOLEAN IsSystemModeImage,
                                   _In_ BOOLEAN IsSignatureLevelKnown,
                                   _In_ UCHAR SignatureLevel,
                                   _In_ UCHAR SignatureType,
                                   _In_opt_z_ PCWSTR ImagePath)
{
    PCWSTR safePath;

    if (!BLACKBIRDEtwIsStarted())
    {
        return;
    }

    safePath = (ImagePath != NULL) ? ImagePath : L"";

    TraceLoggingWrite(g_BlackbirdEtwProvider,
                      "ImageTelemetry",
                      TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) ProcessId, "processId"),
                      TraceLoggingPointer(ImageBase, "imageBase"),
                      TraceLoggingUInt64((ULONGLONG) ImageSize, "imageSize"),
                      TraceLoggingBool(IsSystemModeImage, "isSystemModeImage"),
                      TraceLoggingBool(IsSignatureLevelKnown, "isSignatureLevelKnown"),
                      TraceLoggingUInt8(SignatureLevel, "signatureLevel"),
                      TraceLoggingUInt8(SignatureType, "signatureType"),
                      TraceLoggingWideString(safePath, "imagePath"));
}

VOID BLACKBIRDEtwLogRegistryEvent(_In_z_ PCSTR Operation,
                                  _In_ HANDLE ProcessId,
                                  _In_ ULONG SessionId,
                                  _In_ ULONG NotifyClass,
                                  _In_ ULONG DataType,
                                  _In_ ULONG DataSize,
                                  _In_ BOOLEAN IsHighValuePath,
                                  _In_opt_z_ PCWSTR KeyPath,
                                  _In_opt_z_ PCWSTR ValueName)
{
    PCSTR safeOperation;
    PCWSTR safeKeyPath;
    PCWSTR safeValueName;

    if (!BLACKBIRDEtwIsStarted())
    {
        return;
    }

    safeOperation = (Operation != NULL) ? Operation : "UNKNOWN";
    safeKeyPath = (KeyPath != NULL) ? KeyPath : L"";
    safeValueName = (ValueName != NULL) ? ValueName : L"";

    TraceLoggingWrite(g_BlackbirdEtwProvider,
                      "RegistryTelemetry",
                      TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
                      TraceLoggingString(safeOperation, "operation"),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) ProcessId, "processId"),
                      TraceLoggingUInt32(SessionId, "sessionId"),
                      TraceLoggingUInt32(NotifyClass, "notifyClass"),
                      TraceLoggingUInt32(DataType, "dataType"),
                      TraceLoggingUInt32(DataSize, "dataSize"),
                      TraceLoggingBool(IsHighValuePath, "isHighValuePath"),
                      TraceLoggingWideString(safeKeyPath, "keyPath"),
                      TraceLoggingWideString(safeValueName, "valueName"));
}

VOID BLACKBIRDEtwLogDetectionEvent(_In_z_ PCSTR DetectionName,
                                   _In_ ULONG Severity,
                                   _In_ HANDLE ProcessId,
                                   _In_ HANDLE TargetPid,
                                   _In_ UINT32 CorrelationFlags,
                                   _In_ UINT32 CorrelationAccessMask,
                                   _In_ UINT32 CorrelationAgeMs,
                                   _In_opt_z_ PCWSTR Reason)
{
    PCSTR safeName;
    PCWSTR safeReason;

    if (!BLACKBIRDEtwIsStarted())
    {
        return;
    }

    safeName = (DetectionName != NULL) ? DetectionName : "UNKNOWN";
    safeReason = (Reason != NULL) ? Reason : L"";

    TraceLoggingWrite(g_BlackbirdEtwProvider,
                      "DetectionTelemetry",
                      TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
                      TraceLoggingString(safeName, "detectionName"),
                      TraceLoggingUInt32(Severity, "severity"),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) ProcessId, "processId"),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) TargetPid, "targetPid"),
                      TraceLoggingHexUInt32(CorrelationFlags, "correlationFlags"),
                      TraceLoggingHexUInt32(CorrelationAccessMask, "correlationAccessMask"),
                      TraceLoggingUInt32(CorrelationAgeMs, "correlationAgeMs"),
                      TraceLoggingWideString(safeReason, "reason"));
}

VOID BLACKBIRDEtwLogSystemInfoEvent(_In_ HANDLE CallerPid,
                                    _In_ HANDLE CallerTid,
                                    _In_ ULONG SystemInformationClass,
                                    _In_ ULONG SystemInformationLength,
                                    _In_ ULONG ReturnLength,
                                    _In_ NTSTATUS QueryStatus)
{
    if (!BLACKBIRDEtwIsStarted())
    {
        return;
    }

    TraceLoggingWrite(g_BlackbirdEtwProvider,
                      "SystemInformationTelemetry",
                      TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) CallerPid, "callerPid"),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) CallerTid, "callerTid"),
                      TraceLoggingUInt32(SystemInformationClass, "systemInformationClass"),
                      TraceLoggingUInt32(SystemInformationLength, "systemInformationLength"),
                      TraceLoggingUInt32(ReturnLength, "returnLength"),
                      TraceLoggingHexInt32((LONG) QueryStatus, "queryStatus"));
}

VOID BLACKBIRDEtwLogNtApiEvent(_In_z_ PCSTR ApiName,
                               _In_ HANDLE CallerPid,
                               _In_ HANDLE CallerTid,
                               _In_ UINT64 Arg0,
                               _In_ UINT64 Arg1,
                               _In_ UINT64 Arg2,
                               _In_ UINT64 Arg3,
                               _In_ UINT64 Arg4,
                               _In_ UINT64 Arg5,
                               _In_ UINT64 Arg6,
                               _In_ UINT64 Arg7,
                               _In_ NTSTATUS CallStatus)
{
    if (!BLACKBIRDEtwIsStarted())
    {
        return;
    }

    TraceLoggingWrite(g_BlackbirdEtwProvider,
                      "NtApiTelemetry",
                      TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
                      TraceLoggingString((ApiName != NULL) ? ApiName : "UNKNOWN", "api"),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) CallerPid, "callerPid"),
                      TraceLoggingHexUInt64((ULONGLONG) (ULONG_PTR) CallerTid, "callerTid"),
                      TraceLoggingHexUInt64(Arg0, "arg0"),
                      TraceLoggingHexUInt64(Arg1, "arg1"),
                      TraceLoggingHexUInt64(Arg2, "arg2"),
                      TraceLoggingHexUInt64(Arg3, "arg3"),
                      TraceLoggingHexUInt64(Arg4, "arg4"),
                      TraceLoggingHexUInt64(Arg5, "arg5"),
                      TraceLoggingHexUInt64(Arg6, "arg6"),
                      TraceLoggingHexUInt64(Arg7, "arg7"),
                      TraceLoggingHexInt32((LONG) CallStatus, "status"));
}
