using System;
using System.Collections.Generic;

namespace BlackbirdInterface.Capture
{
    internal enum CaptureEventKind : byte
    {
        Timeline = 1,
        EtwGrouped = 2,
        HeuristicGrouped = 3,
        FilesystemGrouped = 4,
        RelationGrouped = 5,
        ThreadLifecycle = 6,
        IoctlRaw = 7,
        EtwRaw = 8,
        FilesystemRaw = 9
    }

    internal sealed class CaptureLoadedWorkspace
    {
        public SessionFileArchive Archive { get; set; } = new();
        public Dictionary<int, string> TabPaths { get; set; } = new();
    }

    internal sealed class CaptureWorkspaceManifest
    {
        public int Version { get; set; }
        public DateTime SavedUtc { get; set; }
        public int ActivePid { get; set; }
        public List<CaptureWorkspaceTabDescriptor> Tabs { get; set; } = new();
    }

    internal sealed class CaptureWorkspaceTabDescriptor
    {
        public int Pid { get; set; }
        public string Title { get; set; } = string.Empty;
        public string RelativePath { get; set; } = string.Empty;
    }

    internal sealed class CaptureTabManifest
    {
        public int Version { get; set; }
        public int Pid { get; set; }
        public string Title { get; set; } = string.Empty;
        public DateTime CaptureStartUtc { get; set; }
        public int SegmentCount { get; set; }
        public int BlobCount { get; set; }
        public int TimelineEventCount { get; set; }
        public int GroupedRowCount { get; set; }
        public int PerformanceSampleCount { get; set; }
        public int ThreadLifecycleCount { get; set; }
        public int ThreadStackHistoryCount { get; set; }
    }

    internal sealed class CaptureTimelineBucket
    {
        public int ResolutionMs { get; set; }
        public long BucketKey { get; set; }
        public int TotalEvents { get; set; }
        public int TimelineEvents { get; set; }
        public int HeuristicEvents { get; set; }
        public int FilesystemEvents { get; set; }
        public int RelationEvents { get; set; }
        public DateTime BucketStartUtc { get; set; }
        public DateTime BucketEndUtc { get; set; }
        public long HotGroupRef { get; set; }
    }

    internal sealed class CaptureCanonicalRecord
    {
        public DateTime TimestampUtc { get; set; }
        public int Pid { get; set; }
        public int Tid { get; set; }
        public CaptureEventKind Kind { get; set; }
        public byte Flags { get; set; }
        public string Group { get; set; } = string.Empty;
        public string SubType { get; set; } = string.Empty;
        public string Summary { get; set; } = string.Empty;
        public string ObjectIdentity { get; set; } = string.Empty;
        public byte[]? PayloadBytes { get; set; }
        public byte[]? StackBytes { get; set; }
    }

    internal sealed class CaptureBucketCounter
    {
        public int ResolutionMs { get; set; }
        public long BucketKey { get; set; }
        public long StartTicks { get; set; }
        public long EndTicks { get; set; }
        public int TotalEvents { get; set; }
        public int TimelineEvents { get; set; }
        public int HeuristicEvents { get; set; }
        public int FilesystemEvents { get; set; }
        public int RelationEvents { get; set; }
        public long HotGroupRef { get; set; }
        public Dictionary<long, int> GroupCounts { get; } = new();
    }
}
