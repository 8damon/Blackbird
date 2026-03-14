using System;
using System.Collections.Generic;

namespace BlackbirdInterface
{
    public sealed class PerformanceSample
    {
        public DateTime TimestampUtc { get; set; }

        public int CoreCount { get; set; }

        // CPU
        public double CpuPercent { get; set; }              // 0..100
        public double CoresUsedPercent { get; set; }        // 0..100 (kept for chart consistency)

        // Disk (bytes/sec)
        public double DiskReadBytesPerSec { get; set; }
        public double DiskWriteBytesPerSec { get; set; }

        // RAM (bytes)
        public double PrivateBytes { get; set; }
        public double ReservedBytes { get; set; }
        public double CommitBytes { get; set; }
        public double ImageBytes { get; set; }
        public double MappedBytes { get; set; }
        public double PrivateVadBytes { get; set; }

        // Network
        public double NetInBytesPerSec { get; set; }
        public double NetOutBytesPerSec { get; set; }
        public double NetPacketsPerSec { get; set; }

        public List<ThreadUsageSample> TopThreads { get; set; } = new();
        public List<MemoryMetricSample> MemoryMetrics { get; set; } = new();
        public List<MemoryPageSample> MemoryPages { get; set; } = new();
    }

    public sealed class ThreadUsageSample
    {
        public int Tid { get; set; }
        public double CpuMsDelta { get; set; }
        public string State { get; set; } = "";
        public string WaitReason { get; set; } = "";
        public string Kind { get; set; } = "";
        public DateTime? StartTimeUtc { get; set; }
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
        public ulong RegionSize { get; set; }
        public uint State { get; set; }
        public uint Protect { get; set; }
        public uint Type { get; set; }
        public string StateLabel { get; set; } = "";
        public string ProtectLabel { get; set; } = "";
        public string TypeLabel { get; set; } = "";
        public string Category { get; set; } = "";
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
