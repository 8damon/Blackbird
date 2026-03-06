using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Threading;
using System.Text.Json;

namespace SleepwalkerInterface
{
    internal sealed class SessionFileArchive
    {
        public int Version { get; set; } = SessionFileStorage.CurrentVersion;
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
        public List<ThreadLifecycleEventSample> ThreadLifecycleHistory { get; set; } = new();
        public List<GroupedEventRow> EtwGroups { get; set; } = new();
        public List<GroupedEventRow> HeuristicsGroups { get; set; } = new();
        public List<GroupedEventRow> ProcessRelationsGroups { get; set; } = new();
    }

    internal static class SessionFileStorage
    {
        internal const int CurrentVersion = 1;
        private const long MaxCompressedArchiveBytes = 64L * 1024L * 1024L;
        private const long MaxUncompressedArchiveBytes = 256L * 1024L * 1024L;
        private const int MaxTabCount = 128;
        private const int MaxEventsPerTab = 500_000;
        private const int MaxPerformanceSamplesPerTab = 500_000;
        private const int MaxThreadLifecycleEventsPerTab = 500_000;
        private const int MaxGroupedRowsPerCategory = 250_000;

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
            if (archive == null)
            {
                throw new ArgumentNullException(nameof(archive));
            }

            NormalizeArchive(archive);
            ValidateArchiveShape(archive);

            string? directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            string tempPath = path + ".tmp";
            try
            {
                using (var stream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var gzip = new GZipStream(stream, CompressionLevel.SmallestSize))
                {
                    JsonSerializer.Serialize(gzip, archive, JsonOptions);
                }

                if (File.Exists(path))
                {
                    File.Replace(tempPath, path, destinationBackupFileName: null, ignoreMetadataErrors: true);
                }
                else
                {
                    File.Move(tempPath, path);
                }
            }
            finally
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
        }

        internal static SessionFileArchive LoadArchive(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("Session path is required.", nameof(path));
            }
            if (!File.Exists(path))
            {
                throw new FileNotFoundException("Session archive not found.", path);
            }

            var info = new FileInfo(path);
            if (info.Length <= 0)
            {
                throw new InvalidDataException("Session archive is empty.");
            }
            if (info.Length > MaxCompressedArchiveBytes)
            {
                throw new InvalidDataException(
                    $"Session archive exceeds compressed size limit ({MaxCompressedArchiveBytes / (1024 * 1024)} MB).");
            }

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
            using var gzip = new GZipStream(stream, CompressionMode.Decompress);
            using var bounded = new BoundedReadStream(gzip, MaxUncompressedArchiveBytes);

            SessionFileArchive? archive = JsonSerializer.Deserialize<SessionFileArchive>(bounded, JsonOptions);
            if (archive == null)
            {
                throw new InvalidDataException("Session archive is empty or invalid.");
            }

            if (archive.Version <= 0 || archive.Version > CurrentVersion)
            {
                throw new InvalidDataException(
                    $"Unsupported session archive version ({archive.Version}).");
            }

            NormalizeArchive(archive);
            ValidateArchiveShape(archive);

            return archive;
        }

        private static void NormalizeArchive(SessionFileArchive archive)
        {
            archive.Tabs ??= new List<SessionFileTab>();

            foreach (SessionFileTab tab in archive.Tabs)
            {
                tab.Title ??= string.Empty;
                tab.LaneFocusKey ??= null;
                tab.Events ??= new List<TelemetryEvent>();
                tab.PerformanceHistory ??= new List<PerformanceSample>();
                tab.ThreadLifecycleHistory ??= new List<ThreadLifecycleEventSample>();
                tab.EtwGroups ??= new List<GroupedEventRow>();
                tab.HeuristicsGroups ??= new List<GroupedEventRow>();
                tab.ProcessRelationsGroups ??= new List<GroupedEventRow>();
            }
        }

        private static void ValidateArchiveShape(SessionFileArchive archive)
        {
            if (archive.Tabs.Count > MaxTabCount)
            {
                throw new InvalidDataException($"Session archive contains too many tabs ({archive.Tabs.Count}).");
            }

            foreach (SessionFileTab tab in archive.Tabs)
            {
                if (tab.Events.Count > MaxEventsPerTab)
                {
                    throw new InvalidDataException($"PID {tab.Pid} has too many events ({tab.Events.Count}).");
                }
                if (tab.PerformanceHistory.Count > MaxPerformanceSamplesPerTab)
                {
                    throw new InvalidDataException(
                        $"PID {tab.Pid} has too many performance samples ({tab.PerformanceHistory.Count}).");
                }
                if (tab.ThreadLifecycleHistory.Count > MaxThreadLifecycleEventsPerTab)
                {
                    throw new InvalidDataException(
                        $"PID {tab.Pid} has too many thread lifecycle events ({tab.ThreadLifecycleHistory.Count}).");
                }
                if (tab.EtwGroups.Count > MaxGroupedRowsPerCategory ||
                    tab.HeuristicsGroups.Count > MaxGroupedRowsPerCategory ||
                    tab.ProcessRelationsGroups.Count > MaxGroupedRowsPerCategory)
                {
                    throw new InvalidDataException($"PID {tab.Pid} has too many grouped intel rows.");
                }
            }
        }

        private sealed class BoundedReadStream : Stream
        {
            private readonly Stream _inner;
            private readonly long _limit;
            private long _bytesRead;

            public BoundedReadStream(Stream inner, long limit)
            {
                _inner = inner ?? throw new ArgumentNullException(nameof(inner));
                _limit = limit > 0 ? limit : throw new ArgumentOutOfRangeException(nameof(limit));
            }

            public override bool CanRead => _inner.CanRead;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                int read = _inner.Read(buffer, offset, count);
                Track(read);
                return read;
            }

            public override int Read(Span<byte> buffer)
            {
                int read = _inner.Read(buffer);
                Track(read);
                return read;
            }

            public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                ValueTask<int> pending = _inner.ReadAsync(buffer, cancellationToken);
                if (pending.IsCompletedSuccessfully)
                {
                    int read = pending.Result;
                    Track(read);
                    return new ValueTask<int>(read);
                }

                return AwaitReadAsync(pending);
            }

            private async ValueTask<int> AwaitReadAsync(ValueTask<int> pending)
            {
                int read = await pending.ConfigureAwait(false);
                Track(read);
                return read;
            }

            public override void Flush() => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _inner.Dispose();
                }

                base.Dispose(disposing);
            }

            private void Track(int read)
            {
                if (read <= 0)
                {
                    return;
                }

                _bytesRead += read;
                if (_bytesRead > _limit)
                {
                    throw new InvalidDataException(
                        $"Session archive exceeds uncompressed size limit ({_limit / (1024 * 1024)} MB).");
                }
            }
        }
    }
}
