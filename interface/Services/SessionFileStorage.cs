using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text.Json;

namespace SleepwalkerInterface
{
    internal sealed class SessionFileArchive
    {
        public int Version { get; set; } = 1;
        public DateTime SavedUtc { get; set; } = DateTime.UtcNow;
        public int ActivePid { get; set; }
        public List<SessionFileTab> Tabs { get; set; } = new();
    }

    internal sealed class SessionFileTab
    {
        public int Pid { get; set; }
        public string Title { get; set; } = "";
        public DateTime CaptureStartUtc { get; set; } = DateTime.UtcNow;
        public double ViewDurationSeconds { get; set; } = 120;
        public double ViewStartSeconds { get; set; }
        public string? LaneFocusKey { get; set; }
        public bool TargetExited { get; set; }
        public bool OfflineSnapshot { get; set; } = true;

        public List<TelemetryEvent> Events { get; set; } = new();
        public List<PerformanceSample> PerformanceHistory { get; set; } = new();
        public List<GroupedEventRow> EtwGroups { get; set; } = new();
        public List<GroupedEventRow> HeuristicsGroups { get; set; } = new();
        public List<GroupedEventRow> ProcessRelationsGroups { get; set; } = new();
    }

    internal static class SessionFileStorage
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            WriteIndented = false
        };

        internal static void SaveArchive(string path, SessionFileArchive archive)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("Session path is required.", nameof(path));
            }

            string? directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            using var stream = File.Create(path);
            using var gzip = new GZipStream(stream, CompressionLevel.SmallestSize);
            JsonSerializer.Serialize(gzip, archive, JsonOptions);
        }

        internal static SessionFileArchive LoadArchive(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("Session path is required.", nameof(path));
            }

            using var stream = File.OpenRead(path);
            using var gzip = new GZipStream(stream, CompressionMode.Decompress);
            SessionFileArchive? archive = JsonSerializer.Deserialize<SessionFileArchive>(gzip, JsonOptions);
            if (archive == null)
            {
                throw new InvalidDataException("Session archive is empty or invalid.");
            }

            archive.Tabs ??= new List<SessionFileTab>();
            return archive;
        }
    }
}
