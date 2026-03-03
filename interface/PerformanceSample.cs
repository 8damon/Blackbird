using System;
using System.Collections.Generic;

namespace SleepwalkerInterface
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

        // Network
        public double NetInBytesPerSec { get; set; }
        public double NetOutBytesPerSec { get; set; }
        public double NetPacketsPerSec { get; set; }

        public List<ThreadUsageSample> TopThreads { get; set; } = new();
    }

    public sealed class ThreadUsageSample
    {
        public int Tid { get; set; }
        public double CpuMsDelta { get; set; }
        public string State { get; set; } = "";
        public DateTime? StartTimeUtc { get; set; }
    }
}