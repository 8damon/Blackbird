using System;
using System.Collections.Generic;

namespace BlackbirdInterface
{
    public sealed class PerformanceSample
    {
        public DateTime TimestampUtc { get; set; }

        public int CoreCount { get; set; }

        public double CpuPercent { get; set; }
        public double CoresUsedPercent { get; set; }

        public double DiskReadBytesPerSec { get; set; }
        public double DiskWriteBytesPerSec { get; set; }

        public double PrivateBytes { get; set; }
        public double ReservedBytes { get; set; }
        public double CommitBytes { get; set; }
        public double ImageBytes { get; set; }
        public double MappedBytes { get; set; }
        public double PrivateVadBytes { get; set; }

        public double NetInBytesPerSec { get; set; }
        public double NetOutBytesPerSec { get; set; }
        public double NetPacketsPerSec { get; set; }

        public List<ThreadUsageSample> TopThreads { get; set; } = new();
        public List<CoreUsageSample> CoreUsage { get; set; } = new();
        public List<MemoryMetricSample> MemoryMetrics { get; set; } = new();
        public List<MemoryPageSample> MemoryPages { get; set; } = new();
    }

    public sealed class CoreUsageSample
    {
        public int CoreIndex { get; set; }
        public double BusyPercent { get; set; }
        public int DominantTid { get; set; }
        public string DominantThreadKind { get; set; } = "";
        public double DominantThreadCpuMs { get; set; }
        public int ThreadCount { get; set; }
    }

    public sealed class ThreadUsageSample
    {
        public int Tid { get; set; }
        public double CpuMsDelta { get; set; }
        public string State { get; set; } = "";
        public string WaitReason { get; set; } = "";
        public string Kind { get; set; } = "";
        public DateTime? StartTimeUtc { get; set; }
        public bool TargetSuspended { get; set; }
    }

    public sealed class MemoryMetricSample
    {
        public string Metric { get; set; } = "";
        public string Value { get; set; } = "";
        public long? BytesValue { get; set; }
    }

    public sealed class MemoryPageSample
    {
        public ulong BaseAddress { get; set; }
        public ulong AllocationBase { get; set; }
        public ulong RegionSize { get; set; }
        public uint State { get; set; }
        public uint Protect { get; set; }
        public uint AllocationProtect { get; set; }
        public uint Type { get; set; }
        public string StateLabel { get; set; } = "";
        public string ProtectLabel { get; set; } = "";
        public string TypeLabel { get; set; } = "";
        public string Category { get; set; } = "";
        public string SpecialUse { get; set; } = "";
        public string BackingPath { get; set; } = "";
        public string ModulePath { get; set; } = "";
        public bool Sr71Owned { get; set; }
        public string Sr71OwnerTag { get; set; } = "";
        public bool WorkingSetValid { get; set; }
        public bool WorkingSetShared { get; set; }
        public uint WorkingSetShareCount { get; set; }
        public bool WorkingSetLocked { get; set; }
        public bool WorkingSetLargePage { get; set; }
        public uint SnapshotOffset { get; set; }
        public byte[]? SnapshotBytes { get; set; }
    }

    public sealed class MemoryRegionAttributionSample
    {
        public DateTime TimestampUtc { get; set; }
        public ulong ProcessStartKey { get; set; }
        public uint TargetPid { get; set; }
        public uint ActorPid { get; set; }
        public uint ActorTid { get; set; }
        public ulong AllocationBase { get; set; }
        public ulong BaseAddress { get; set; }
        public ulong RegionSize { get; set; }
        public string ApiName { get; set; } = "";
        public string EventKind { get; set; } = "";
        public string RegionKind { get; set; } = "";
        public string RegionIdentity { get; set; } = "";
        public string OriginPath { get; set; } = "";
        public string SourceFamily { get; set; } = "";
        public string ExecutionContext { get; set; } = "";
        public string CallerOrigin { get; set; } = "";
        public ulong FirstUserFrame { get; set; }
        public string FirstUserFrameModule { get; set; } = "";
        public string FrameSummary { get; set; } = "";
        public bool UnwindClean { get; set; }
        public bool FrameChainHadGaps { get; set; }
        public bool ObservedByKernel { get; set; }
        public bool ObservedByUserHook { get; set; }
        public bool BlackbirdOwned { get; set; }
        public bool CrossProcess { get; set; }
        public bool ImageBacked { get; set; }
        public uint InitialProtection { get; set; }
        public uint CurrentProtection { get; set; }
        public uint PreviousProtection { get; set; }
        public bool FirstExecutableTransition { get; set; }
        public uint MapCount { get; set; }
        public uint WriteCount { get; set; }
        public uint ProtectCount { get; set; }
        public uint ThreadStartCount { get; set; }
        public uint ProtectFlipCount { get; set; }
        public uint RapidProtectFlipCount { get; set; }
        public uint ExecutableFlipCount { get; set; }
        public uint GuardNoAccessFlipCount { get; set; }
        public uint WritableExecutableFlipCount { get; set; }
        public string ProtectionTransition { get; set; } = "";
        public double EntropyBits { get; set; } = -1;
        public double MaxEntropyBits { get; set; } = -1;
        public uint EntropyFlipCount { get; set; }
        public uint RapidEntropyFlipCount { get; set; }
        public uint HighEntropyWriteCount { get; set; }
        public uint SampleBytes { get; set; }
        public string LifecycleSummary { get; set; } = "";
        public bool ThreadStartObserved { get; set; }
        public uint ThreadId { get; set; }
        public ulong ThreadStartAddress { get; set; }
        public bool FunctionTableRegistered { get; set; }
        public ulong FunctionTablePointer { get; set; }
        public byte SignatureLevel { get; set; }
        public byte SignatureType { get; set; }
    }

    public sealed class ThreadLifecycleEventSample
    {
        public DateTime TimestampUtc { get; set; }
        public uint ProcessPid { get; set; }
        public uint ThreadId { get; set; }
        public uint CreatorPid { get; set; }
        public uint Flags { get; set; }
        public ulong StartAddress { get; set; }
        public ulong ImageBase { get; set; }
        public ulong ImageSize { get; set; }
        public string EventKind { get; set; } = "";
        public string Notes { get; set; } = "";
    }
}
