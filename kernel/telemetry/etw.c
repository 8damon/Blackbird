#include <ntddk.h>
#include <TraceLoggingProvider.h>
#include "etw.h"

#ifndef TRACE_LEVEL_INFORMATION
#define TRACE_LEVEL_INFORMATION 4
#endif

TRACELOGGING_DEFINE_PROVIDER(
    g_StingerEtwProvider,
    "Stinger.Kernel",
    (0xd6c73f8a, 0x6ad8, 0x4f4b, 0xa3, 0x63, 0x3d, 0x2f, 0xa3, 0x1c, 0xd0, 0xe2)
);

static volatile LONG g_EtwState = 0; // 0=stopped, 1=starting, 2=started

static
BOOLEAN
STINGEREtwIsStarted(
    VOID
)
{
    return (InterlockedCompareExchange(&g_EtwState, 0, 0) == 2);
}

NTSTATUS
STINGEREtwInitialize(
    VOID
)
{
    NTSTATUS status;
    LONG prior;

    prior = InterlockedCompareExchange(&g_EtwState, 1, 0);
    if (prior == 2) {
        return STATUS_SUCCESS;
    }
    if (prior != 0) {
        return STATUS_DEVICE_BUSY;
    }

    status = TraceLoggingRegister(g_StingerEtwProvider);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&g_EtwState, 0);
        return status;
    }

    InterlockedExchange(&g_EtwState, 2);
    return STATUS_SUCCESS;
}

VOID
STINGEREtwUninitialize(
    VOID
)
{
    LONG prior = InterlockedExchange(&g_EtwState, 0);
    if (prior == 2) {
        TraceLoggingUnregister(g_StingerEtwProvider);
    }
}

VOID
STINGEREtwLogHandleEvent(
    _In_z_ PCSTR EventClass,
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
    _In_reads_opt_(FrameCount) PVOID const* Frames,
    _In_ NTSTATUS OpenProcessStatus,
    _In_ NTSTATUS BasicInfoStatus,
    _In_ NTSTATUS SectionNameStatus
)
{
    PVOID safeFrames[8] = { 0 };
    ULONG safeFrameCount = 0;
    ULONG i;
    PCWSTR path;

    if (!STINGEREtwIsStarted()) {
        return;
    }

    if (Frames != NULL) {
        safeFrameCount = (FrameCount > RTL_NUMBER_OF(safeFrames)) ? RTL_NUMBER_OF(safeFrames) : FrameCount;
        for (i = 0; i < safeFrameCount; ++i) {
            safeFrames[i] = Frames[i];
        }
    }
    path = (OriginPath != NULL) ? OriginPath : L"";

    TraceLoggingWrite(
        g_StingerEtwProvider,
        "HandleTelemetry",
        TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
        TraceLoggingString((EventClass != NULL) ? EventClass : "UNKNOWN", "class"),
        TraceLoggingHexUInt64((ULONGLONG)(ULONG_PTR)CallerPid, "callerPid"),
        TraceLoggingHexUInt64((ULONGLONG)(ULONG_PTR)TargetPid, "targetPid"),
        TraceLoggingHexUInt32((ULONG)DesiredAccess, "desiredAccess"),
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
        TraceLoggingHexInt32((LONG)OpenProcessStatus, "statusOpenProcess"),
        TraceLoggingHexInt32((LONG)BasicInfoStatus, "statusBasicInfo"),
        TraceLoggingHexInt32((LONG)SectionNameStatus, "statusSectionName")
    );
}

VOID
STINGEREtwLogThreadEvent(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ HANDLE CreatorPid,
    _In_ PVOID StartAddress,
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ BOOLEAN GotStart,
    _In_ BOOLEAN GotRange,
    _In_ BOOLEAN IsRemoteCreator,
    _In_ BOOLEAN OutsideMainImage,
    _In_ ULONG WorkerFrameCount,
    _In_reads_opt_(WorkerFrameCount) PVOID const* WorkerFrames
)
{
    PVOID safeFrames[8] = { 0 };
    ULONG safeFrameCount = 0;
    ULONG i;

    if (!STINGEREtwIsStarted()) {
        return;
    }

    if (WorkerFrames != NULL) {
        safeFrameCount = (WorkerFrameCount > RTL_NUMBER_OF(safeFrames)) ? RTL_NUMBER_OF(safeFrames) : WorkerFrameCount;
        for (i = 0; i < safeFrameCount; ++i) {
            safeFrames[i] = WorkerFrames[i];
        }
    }

    TraceLoggingWrite(
        g_StingerEtwProvider,
        "ThreadTelemetry",
        TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
        TraceLoggingHexUInt64((ULONGLONG)(ULONG_PTR)ProcessId, "processId"),
        TraceLoggingHexUInt64((ULONGLONG)(ULONG_PTR)ThreadId, "threadId"),
        TraceLoggingHexUInt64((ULONGLONG)(ULONG_PTR)CreatorPid, "creatorPid"),
        TraceLoggingPointer(StartAddress, "startAddress"),
        TraceLoggingPointer(ImageBase, "imageBase"),
        TraceLoggingUInt64((ULONGLONG)ImageSize, "imageSize"),
        TraceLoggingBool(GotStart, "gotStart"),
        TraceLoggingBool(GotRange, "gotRange"),
        TraceLoggingBool(IsRemoteCreator, "isRemoteCreator"),
        TraceLoggingBool(OutsideMainImage, "outsideMainImage"),
        TraceLoggingUInt32(safeFrameCount, "workerFrameCount"),
        TraceLoggingPointer(safeFrames[0], "stack0"),
        TraceLoggingPointer(safeFrames[1], "stack1"),
        TraceLoggingPointer(safeFrames[2], "stack2"),
        TraceLoggingPointer(safeFrames[3], "stack3"),
        TraceLoggingPointer(safeFrames[4], "stack4"),
        TraceLoggingPointer(safeFrames[5], "stack5"),
        TraceLoggingPointer(safeFrames[6], "stack6"),
        TraceLoggingPointer(safeFrames[7], "stack7")
    );
}
