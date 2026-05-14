using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace BlackbirdInterface.Capture
{
    internal sealed class BlackbirdCaptureLiveStore : IDisposable
    {
        private const byte FlagPayloadTrimmed = 0x01;
        private const byte FlagStackTrimmed = 0x02;
        private const int MaxSegmentEvents = 768;
        private const int MaxMaterializedTimelineEvents = 5000;
        private const int MaxPayloadTextChars = 4096;
        private const long MaxSegmentBytes = 1024L * 1024L;
        private const long PayloadBudgetBytes = 256L * 1024L * 1024L;
        private const long StackBudgetBytes = 64L * 1024L * 1024L;
        private static readonly TimeSpan MaxSegmentWindow = TimeSpan.FromSeconds(2);
        private const int MaterializedWriteEventDelta = 384;
        private static readonly TimeSpan MaterializedWriteInterval = TimeSpan.FromSeconds(15);
        private static readonly TimeSpan MaterializedLowVolumeWriteInterval = TimeSpan.FromSeconds(45);
        private static readonly JsonSerializerOptions JsonOptions =
            new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true,
                    WriteIndented = true };
        private static readonly JsonSerializerOptions PayloadJsonOptions =
            new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull };

        private readonly object _sync = new();
        private readonly string _rootPath;
        private readonly string _tabDirectory;
        private readonly string _segmentsPath;
        private readonly string _blobsPath;
        private readonly SqliteDatabase _database;
        private readonly Dictionary<string, long> _stringRefs = new(StringComparer.Ordinal);
        private readonly Dictionary<string, long> _blobRefs = new(StringComparer.Ordinal);
        private readonly Dictionary<(int ResolutionMs, long BucketKey), CaptureBucketCounter> _buckets = new();
        private readonly List<CaptureCanonicalRecord> _buffer = new(MaxSegmentEvents);
        private readonly TelemetryEventStore _timeline = new();
        private readonly int _pid;
        private readonly string _title;
        private readonly DateTime _captureStartUtc;
        private int _nextSegmentNumber;
        private long _bufferBytes;
        private long _payloadBytesAccepted;
        private long _stackBytesAccepted;
        private long _materializedSequence;
        private long _lastMaterializedSequence;
        private DateTime _lastMaterializedWriteUtc;
        private bool _disposed;

        private BlackbirdCaptureLiveStore(string rootPath, string tabDirectory, string segmentsPath, string blobsPath,
                                          SqliteDatabase database, int pid, string title)
        {
            _rootPath = rootPath;
            _tabDirectory = tabDirectory;
            _segmentsPath = segmentsPath;
            _blobsPath = blobsPath;
            _database = database;
            _pid = pid;
            _title = title;
            _captureStartUtc = DateTime.UtcNow;
            _nextSegmentNumber = Directory.GetFiles(_segmentsPath, "*.bbseg").Length;
        }

        internal static BlackbirdCaptureLiveStore Open(string rootPath, int pid, string title)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
            if (!string.IsNullOrWhiteSpace(Path.GetExtension(rootPath)))
            {
                throw new InvalidOperationException("Live capture storage requires a directory path.");
            }

            string fullRoot = Path.GetFullPath(rootPath);
            string tabDirectory = Path.Combine(fullRoot, "tabs", $"pid-{pid}");
            string segmentsPath = Path.Combine(tabDirectory, "segments");
            string blobsPath = Path.Combine(tabDirectory, "blobs");
            Directory.CreateDirectory(segmentsPath);
            Directory.CreateDirectory(blobsPath);
            SqliteDatabase database = SqliteDatabase.Open(Path.Combine(tabDirectory, "index.sqlite"));
            CaptureArchiveStorage.CreateSchema(database);
            var store = new BlackbirdCaptureLiveStore(fullRoot, tabDirectory, segmentsPath, blobsPath, database, pid,
                                                      title ?? string.Empty);
            store.WriteMaterializedFiles(force: true);
            return store;
        }

        internal void AppendIoctl(DateTime timestampUtc, IoctlParsedEvent record)
        {
            ArgumentNullException.ThrowIfNull(record);
            CaptureCanonicalRecord canonical = BuildIoctlRecord(timestampUtc, record, out TelemetryEvent materialized);
            AppendRecord(canonical, materialized);
        }

        internal void AppendEtw(BrokerEtwEventView view)
        {
            ArgumentNullException.ThrowIfNull(view);
            CaptureCanonicalRecord canonical = BuildEtwRecord(view, out TelemetryEvent materialized);
            AppendRecord(canonical, materialized);
        }

        internal void AppendSyntheticHeuristic(DateTime timestampUtc, int pid, int tid, string group, string subtype,
                                               string summary, string details, string objectIdentity,
                                               byte[]? payloadBytes = null, byte[]? stackBytes = null)
        {
            string safeGroup = string.IsNullOrWhiteSpace(group) ? "heuristic" : group.Trim();
            string safeSubtype = string.IsNullOrWhiteSpace(subtype) ? "Synthetic" : subtype.Trim();
            string safeSummary = string.IsNullOrWhiteSpace(summary) ? safeSubtype : summary.Trim();
            string safeDetails = string.IsNullOrWhiteSpace(details) ? safeSummary : details.Trim();
            CaptureCanonicalRecord canonical =
                new() { TimestampUtc = timestampUtc == default ? DateTime.UtcNow : timestampUtc,
                        Pid = pid,
                        Tid = tid,
                        HitCount = 1,
                        Kind = CaptureEventKind.HeuristicGrouped,
                        Group = safeGroup,
                        SubType = safeSubtype,
                        Summary = safeSummary,
                        ObjectIdentity = string.IsNullOrWhiteSpace(objectIdentity)
                                             ? $"synthetic:{safeGroup}:{safeSubtype}:{pid}:{tid}:{safeSummary}"
                                             : objectIdentity.Trim(),
                        PayloadBytes = payloadBytes,
                        StackBytes = stackBytes };

            TelemetryEvent materialized = new() { TimestampUtc = canonical.TimestampUtc,
                                                  PID = pid,
                                                  TID = tid,
                                                  Group = safeGroup,
                                                  SubType = safeSubtype,
                                                  Summary = safeSummary,
                                                  Details = safeDetails };

            AppendRecord(canonical, materialized);
        }

        internal void Flush()
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                FlushCore();
                WriteMaterializedFiles(force: true);
            }
        }

        public void Dispose()
        {
            lock (_sync)
            {
                if (_disposed)
                {
                    return;
                }

                FlushCore();
                WriteMaterializedFiles(force: true);
                _database.Dispose();
                _disposed = true;
                GC.SuppressFinalize(this);
            }
        }

        private void AppendRecord(CaptureCanonicalRecord record, TelemetryEvent materialized)
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                ApplyBudgets(record);
                _buffer.Add(record);
                _bufferBytes += 96 + record.Group.Length + record.SubType.Length + record.Summary.Length +
                                (record.PayloadBytes?.Length ?? 0) + (record.StackBytes?.Length ?? 0);
                _timeline.Add(CloneTelemetryEvent(materialized));
                _materializedSequence += 1;
                if (_timeline.Count > MaxMaterializedTimelineEvents)
                {
                    _timeline.RemoveFirst(_timeline.Count - MaxMaterializedTimelineEvents);
                }

                bool flush = _buffer.Count >= MaxSegmentEvents || _bufferBytes >= MaxSegmentBytes ||
                             (_buffer.Count > 1 && (record.TimestampUtc - _buffer[0].TimestampUtc) >= MaxSegmentWindow);
                if (flush)
                {
                    FlushCore();
                    WriteMaterializedFiles(force: false);
                }
            }
        }

        private void ApplyBudgets(CaptureCanonicalRecord record)
        {
            if (record.PayloadBytes != null && record.PayloadBytes.Length > 0)
            {
                long projected = _payloadBytesAccepted + record.PayloadBytes.LongLength;
                if (projected > PayloadBudgetBytes)
                {
                    record.PayloadBytes = null;
                    record.Flags |= FlagPayloadTrimmed;
                }
                else
                {
                    _payloadBytesAccepted = projected;
                }
            }

            if (record.StackBytes != null && record.StackBytes.Length > 0)
            {
                long projected = _stackBytesAccepted + record.StackBytes.LongLength;
                if (projected > StackBudgetBytes)
                {
                    record.StackBytes = null;
                    record.Flags |= FlagStackTrimmed;
                }
                else
                {
                    _stackBytesAccepted = projected;
                }
            }
        }
        private void FlushCore()
        {
            if (_buffer.Count == 0)
            {
                return;
            }

            using MemoryStream payloadStream = new();
            using SqliteStatement insert = _database.Prepare(
                "INSERT INTO events(segment_no, record_index, ts_utc_ticks, dt_us, pid, tid, kind, flags, group_ref, subtype_ref, summary_ref, object_ref, payload_blob_ref, stack_blob_ref) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14);");
            _database.ExecuteNonQuery("BEGIN IMMEDIATE;");
            try
            {
                DateTime previous = _buffer[0].TimestampUtc;
                for (int i = 0; i < _buffer.Count; i += 1)
                {
                    CaptureCanonicalRecord record = _buffer[i];
                    long deltaUs =
                        i == 0 ? 0 : Math.Max(0, (long)(record.TimestampUtc - previous).TotalMilliseconds * 1000L);
                    previous = record.TimestampUtc;
                    long groupRef =
                        CaptureArchiveStorage.EnsureStringRef(_database, _stringRefs, "group", record.Group);
                    long subtypeRef =
                        CaptureArchiveStorage.EnsureStringRef(_database, _stringRefs, "subtype", record.SubType);
                    long summaryRef =
                        CaptureArchiveStorage.EnsureStringRef(_database, _stringRefs, "summary", record.Summary);
                    long objectRef =
                        CaptureArchiveStorage.EnsureStringRef(_database, _stringRefs, "object", record.ObjectIdentity);
                    long payloadRef = CaptureArchiveStorage.EnsureBlobRef(_database, _stringRefs, _blobRefs, _blobsPath,
                                                                          "payload", record.PayloadBytes);
                    long stackRef = CaptureArchiveStorage.EnsureBlobRef(_database, _stringRefs, _blobRefs, _blobsPath,
                                                                        "stack", record.StackBytes);

                    CaptureArchiveStorage.WriteVarUInt64(payloadStream, (ulong)deltaUs);
                    CaptureArchiveStorage.WriteVarUInt64(payloadStream, (ulong)Math.Max(0, record.Pid));
                    CaptureArchiveStorage.WriteVarUInt64(payloadStream, (ulong)Math.Max(0, record.Tid));
                    payloadStream.WriteByte((byte)record.Kind);
                    payloadStream.WriteByte(record.Flags);
                    CaptureArchiveStorage.WriteVarUInt64(payloadStream, (ulong)groupRef);
                    CaptureArchiveStorage.WriteVarUInt64(payloadStream, (ulong)subtypeRef);
                    CaptureArchiveStorage.WriteVarUInt64(payloadStream, (ulong)summaryRef);
                    CaptureArchiveStorage.WriteVarUInt64(payloadStream, (ulong)objectRef);
                    CaptureArchiveStorage.WriteVarUInt64(payloadStream, (ulong)payloadRef);
                    CaptureArchiveStorage.WriteVarUInt64(payloadStream, (ulong)stackRef);

                    insert.Reset();
                    insert.ClearBindings();
                    insert.BindInt64(1, _nextSegmentNumber);
                    insert.BindInt64(2, i);
                    insert.BindInt64(3, record.TimestampUtc.Ticks);
                    insert.BindInt64(4, deltaUs);
                    insert.BindInt64(5, record.Pid);
                    insert.BindInt64(6, record.Tid);
                    insert.BindInt64(7, (int)record.Kind);
                    insert.BindInt64(8, record.Flags);
                    insert.BindInt64(9, groupRef);
                    insert.BindInt64(10, subtypeRef);
                    insert.BindInt64(11, summaryRef);
                    insert.BindInt64(12, objectRef);
                    insert.BindInt64(13, payloadRef);
                    insert.BindInt64(14, stackRef);
                    _ = insert.Step();
                    UpdateBuckets(record, groupRef);
                }

                WriteBucketsToDatabase();
                _database.ExecuteNonQuery("COMMIT;");
            }
            catch
            {
                _database.ExecuteNonQuery("ROLLBACK;");
                throw;
            }

            byte[] payload = payloadStream.ToArray();
            byte[] compressed = global::BlackbirdInterface.Lz4BlockCodec.Compress(payload);
            string segmentPath = Path.Combine(_segmentsPath, $"{_nextSegmentNumber:D6}.bbseg");
            using FileStream file = new(segmentPath, FileMode.Create, FileAccess.Write, FileShare.None);
            using BinaryWriter writer = new(file, Encoding.UTF8, false);
            writer.Write(new byte[] { (byte)'B', (byte)'B', (byte)'S', (byte)'1' });
            writer.Write(CaptureArchiveStorage.FormatVersion);
            writer.Write(_buffer.Count);
            writer.Write(_buffer[0].TimestampUtc.Ticks);
            writer.Write(_buffer[^1].TimestampUtc.Ticks);
            writer.Write(payload.Length);
            writer.Write(compressed.Length);
            writer.Write((byte)1);
            writer.Write((byte)0);
            writer.Write((ushort)0);
            writer.Write(compressed);

            _buffer.Clear();
            _bufferBytes = 0;
            _nextSegmentNumber += 1;
        }

        private void UpdateBuckets(CaptureCanonicalRecord record, long groupRef)
        {
            int weight = Math.Max(1, record.HitCount);
            foreach (int resolutionMs in new[] { 100, 1_000, 10_000, 60_000 })
            {
                long bucketTicks = TimeSpan.FromMilliseconds(resolutionMs).Ticks;
                long bucketKey = record.TimestampUtc.Ticks / bucketTicks;
                var key = (resolutionMs, bucketKey);
                if (!_buckets.TryGetValue(key, out CaptureBucketCounter? bucket))
                {
                    bucket = new CaptureBucketCounter { ResolutionMs = resolutionMs, BucketKey = bucketKey,
                                                        StartTicks = bucketKey * bucketTicks,
                                                        EndTicks = bucketKey * bucketTicks + bucketTicks };
                    _buckets[key] = bucket;
                }
                bucket.TotalEvents += weight;
                switch (record.Kind)
                {
                case CaptureEventKind.Timeline:
                    bucket.TimelineEvents += weight;
                    break;
                case CaptureEventKind.HeuristicGrouped:
                    bucket.HeuristicEvents += weight;
                    break;
                case CaptureEventKind.FilesystemGrouped:
                case CaptureEventKind.FilesystemRaw:
                    bucket.FilesystemEvents += weight;
                    break;
                case CaptureEventKind.RelationGrouped:
                    bucket.RelationEvents += weight;
                    break;
                }
                if (groupRef != 0)
                {
                    bucket.GroupCounts.TryGetValue(groupRef, out int count);
                    count += weight;
                    bucket.GroupCounts[groupRef] = count;
                    if (bucket.HotGroupRef == 0 ||
                        !bucket.GroupCounts.TryGetValue(bucket.HotGroupRef, out int hotCount) || count >= hotCount)
                    {
                        bucket.HotGroupRef = groupRef;
                    }
                }
            }
        }

        private void WriteBucketsToDatabase()
        {
            using SqliteStatement insert = _database.Prepare(
                "INSERT OR REPLACE INTO buckets(resolution_ms, bucket_key, total_events, timeline_events, heuristic_events, filesystem_events, relation_events, bucket_start_ticks, bucket_end_ticks, hot_group_ref) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10);");
            foreach (CaptureBucketCounter bucket in _buckets.Values.OrderBy(x => x.ResolutionMs)
                         .ThenBy(x => x.BucketKey))
            {
                insert.Reset();
                insert.ClearBindings();
                insert.BindInt64(1, bucket.ResolutionMs);
                insert.BindInt64(2, bucket.BucketKey);
                insert.BindInt64(3, bucket.TotalEvents);
                insert.BindInt64(4, bucket.TimelineEvents);
                insert.BindInt64(5, bucket.HeuristicEvents);
                insert.BindInt64(6, bucket.FilesystemEvents);
                insert.BindInt64(7, bucket.RelationEvents);
                insert.BindInt64(8, bucket.StartTicks);
                insert.BindInt64(9, bucket.EndTicks);
                insert.BindInt64(10, bucket.HotGroupRef);
                _ = insert.Step();
            }
        }

        private void WriteMaterializedFiles(bool force)
        {
            DateTime nowUtc = DateTime.UtcNow;
            if (!force && _lastMaterializedWriteUtc != default)
            {
                TimeSpan elapsed = nowUtc - _lastMaterializedWriteUtc;
                long pendingMaterializedEvents = _materializedSequence - _lastMaterializedSequence;
                if (pendingMaterializedEvents <= 0 || elapsed < MaterializedWriteInterval ||
                    (pendingMaterializedEvents < MaterializedWriteEventDelta &&
                     elapsed < MaterializedLowVolumeWriteInterval))
                {
                    return;
                }
            }

            Directory.CreateDirectory(_rootPath);
            Directory.CreateDirectory(Path.Combine(_rootPath, "tabs"));
            Directory.CreateDirectory(_tabDirectory);
            Directory.CreateDirectory(_segmentsPath);
            Directory.CreateDirectory(_blobsPath);

            var workspace = new CaptureWorkspaceManifest {
                Version = CaptureArchiveStorage.FormatVersion, SavedUtc = nowUtc, ActivePid = _pid,
                Tabs = new List<CaptureWorkspaceTabDescriptor> { new() { Pid = _pid, Title = _title,
                                                                         RelativePath =
                                                                             Path.Combine("tabs", $"pid-{_pid}") } }
            };
            File.WriteAllText(Path.Combine(_rootPath, "manifest.json"),
                              JsonSerializer.Serialize(workspace, JsonOptions), Encoding.UTF8);

            SessionFileTab materialized =
                new() { Pid = _pid, Title = _title, CaptureStartUtc = _captureStartUtc, OfflineSnapshot = true,
                        Events = _timeline.Select(CloneTelemetryEvent).ToList() };
            File.WriteAllText(Path.Combine(_tabDirectory, "materialized.json"),
                              JsonSerializer.Serialize(materialized, JsonOptions), Encoding.UTF8);

            List<CaptureTimelineBucket> buckets =
                _buckets.Values.OrderBy(x => x.ResolutionMs)
                    .ThenBy(x => x.BucketKey)
                    .Select(x => new CaptureTimelineBucket {
                        ResolutionMs = x.ResolutionMs, BucketKey = x.BucketKey, TotalEvents = x.TotalEvents,
                        TimelineEvents = x.TimelineEvents, HeuristicEvents = x.HeuristicEvents,
                        FilesystemEvents = x.FilesystemEvents, RelationEvents = x.RelationEvents,
                        BucketStartUtc = new DateTime(x.StartTicks, DateTimeKind.Utc),
                        BucketEndUtc = new DateTime(x.EndTicks, DateTimeKind.Utc), HotGroupRef = x.HotGroupRef
                    })
                    .ToList();
            File.WriteAllText(Path.Combine(_tabDirectory, "buckets.json"),
                              JsonSerializer.Serialize(buckets, JsonOptions), Encoding.UTF8);

            var tabManifest = new CaptureTabManifest {
                Version = CaptureArchiveStorage.FormatVersion,
                Pid = _pid,
                Title = _title,
                CaptureStartUtc = _captureStartUtc,
                SegmentCount = Directory.GetFiles(_segmentsPath, "*.bbseg").Length,
                BlobCount = Directory.Exists(_blobsPath)
                                ? Directory.GetFiles(_blobsPath, "*.bbblob", SearchOption.AllDirectories).Length
                                : 0,
                TimelineEventCount = _timeline.Count,
                GroupedRowCount = 0,
                PerformanceSampleCount = 0,
                ThreadLifecycleCount =
                    _timeline.Count(x => string.Equals(x.Group, "ioctl-thread", StringComparison.OrdinalIgnoreCase)),
                ThreadStackHistoryCount = 0
            };
            File.WriteAllText(Path.Combine(_tabDirectory, "tab.manifest.json"),
                              JsonSerializer.Serialize(tabManifest, JsonOptions), Encoding.UTF8);

            _lastMaterializedWriteUtc = nowUtc;
            _lastMaterializedSequence = _materializedSequence;
        }
        private static CaptureCanonicalRecord BuildIoctlRecord(DateTime timestampUtc, IoctlParsedEvent record,
                                                               out TelemetryEvent materialized)
        {
            CaptureEventKind kind =
                record.Type switch { BlackbirdNative.EventTypeFileSystem => CaptureEventKind.FilesystemRaw,
                                     BlackbirdNative.EventTypeRegistry => CaptureEventKind.RegistryRaw,
                                     BlackbirdNative.EventTypeThread => CaptureEventKind.ThreadLifecycle,
                                     _ => CaptureEventKind.IoctlRaw };
            string group = record.Type switch { BlackbirdNative.EventTypeHandle => "ioctl-handle",
                                                BlackbirdNative.EventTypeThread => "ioctl-thread",
                                                BlackbirdNative.EventTypeFileSystem => "ioctl-filesystem",
                                                BlackbirdNative.EventTypeRegistry => "ioctl-registry",
                                                _ => "ioctl" };
            string subtype = record.Type switch { BlackbirdNative.EventTypeHandle => "Handle",
                                                  BlackbirdNative.EventTypeThread => "Thread",
                                                  BlackbirdNative.EventTypeFileSystem => "Filesystem",
                                                  BlackbirdNative.EventTypeRegistry => "Registry",
                                                  _ => "Unknown" };
            string summary = record.Type switch {
                BlackbirdNative.EventTypeThread => $"thread {record.ThreadId} start=0x{record.StartAddress:X}",
                BlackbirdNative.EventTypeFileSystem =>
                    string.IsNullOrWhiteSpace(record.FilePath) ? "filesystem event" : record.FilePath,
                BlackbirdNative.EventTypeRegistry => string.IsNullOrWhiteSpace(record.RegistryKeyPath)
                                                         ? "registry event"
                                                     : string.IsNullOrWhiteSpace(record.RegistryValueName)
                                                         ? record.RegistryKeyPath
                                                         : $"{record.RegistryKeyPath}\\{record.RegistryValueName}",
                _ => $"caller={record.CallerPid} target={record.TargetPid} access=0x{record.DesiredAccess:X8}"
            };
            byte[]? stackBytes = record.StackSnapshotSize > 0 && record.StackSnapshot.Length > 0
                                     ? TrimByteBuffer(record.StackSnapshot, (int)record.StackSnapshotSize)
                                     : SerializeUlongs(record.FullFrames.Length > 0 ? record.FullFrames
                                                       : record.Frames.Length > 0   ? record.Frames
                                                                                    : record.ThreadFrames,
                                                       int.MaxValue);

            materialized = new TelemetryEvent {
                TimestampUtc = timestampUtc,
                PID = record.Type == BlackbirdNative.EventTypeThread ? unchecked((int)record.ProcessPid)
                      : record.Type == BlackbirdNative.EventTypeRegistry
                          ? unchecked((int)record.RegistryProcessPid)
                          : unchecked((int)(record.CallerPid != 0 ? record.CallerPid : record.FileProcessPid)),
                TID = record.Type == BlackbirdNative.EventTypeRegistry
                          ? unchecked((int)record.RegistryThreadId)
                          : unchecked((int)(record.ThreadId != 0 ? record.ThreadId : record.FileThreadId)),
                Group = group,
                SubType = subtype,
                Summary = summary,
                Details = summary
            };

            return new CaptureCanonicalRecord {
                TimestampUtc = timestampUtc,
                Pid = materialized.PID,
                Tid = materialized.TID,
                HitCount = 1,
                Kind = kind,
                Flags = (byte)(record.Type == BlackbirdNative.EventTypeThread     ? (record.ThreadFlags & 0xFF)
                               : record.Type == BlackbirdNative.EventTypeRegistry ? (record.RegistryFlags & 0xFF)
                                                                                  : (record.HandleFlags & 0xFF)),
                Group = group,
                SubType = subtype,
                Summary = summary,
                ObjectIdentity = BuildIoctlIdentity(record),
                PayloadBytes = BuildIoctlPayloadBytes(record),
                StackBytes = stackBytes
            };
        }

        private static CaptureCanonicalRecord BuildEtwRecord(BrokerEtwEventView view, out TelemetryEvent materialized)
        {
            string group = EventDetailFormatting.IsUsermodeSensorTelemetry(view)
                               ? EventDetailFormatting.HookTimelineGroup(view)
                               : (string.IsNullOrWhiteSpace(view.Source) ? "etw" : view.Source);
            string subtype = string.IsNullOrWhiteSpace(view.EventName)
                                 ? (string.IsNullOrWhiteSpace(view.DetectionName) ? "Etw" : view.DetectionName)
                                 : view.EventName;
            string summary = view.Summary;
            materialized =
                new TelemetryEvent { TimestampUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc,
                                     PID = unchecked((int)(view.ActorPid != 0 ? view.ActorPid : view.EventProcessId)),
                                     TID = unchecked((int)(view.ThreadId != 0 ? view.ThreadId : view.EventThreadId)),
                                     Group = group,
                                     SubType = subtype,
                                     Summary = summary,
                                     Details = view.Details };

            return new CaptureCanonicalRecord {
                TimestampUtc = materialized.TimestampUtc,
                Pid = materialized.PID,
                Tid = materialized.TID,
                HitCount = Math.Max(1, view.RepeatCount),
                Kind = string.IsNullOrWhiteSpace(view.DetectionName) ? CaptureEventKind.EtwRaw
                                                                     : CaptureEventKind.HeuristicGrouped,
                Flags = (byte)(view.Flags & 0xFF),
                Group = group,
                SubType = subtype,
                Summary = summary,
                ObjectIdentity = BuildEtwIdentity(view),
                PayloadBytes = BuildEtwPayloadBytes(view),
                StackBytes = view.StackCount > 0 ? SerializeUlongs(view.Stack, (int)view.StackCount) : null
            };
        }

        private static byte[]? BuildIoctlPayloadBytes(IoctlParsedEvent record)
        {
            var payload = new CaptureIoctlPayload { Type = record.Type, Sequence = record.Sequence,
                                                    StreamMask = record.StreamMask };

            if (record.Type == BlackbirdNative.EventTypeHandle)
            {
                payload.Handle = new CaptureIoctlHandlePayload {
                    CallerPid = record.CallerPid,
                    TargetPid = record.TargetPid,
                    DesiredAccess = record.DesiredAccess,
                    HandleClass = record.HandleClass,
                    HandleFlags = record.HandleFlags,
                    OriginAddress = record.OriginAddress,
                    OriginProtect = record.OriginProtect,
                    StatusOpenProcess = record.StatusOpenProcess,
                    StatusBasicInfo = record.StatusBasicInfo,
                    StatusSectionName = record.StatusSectionName,
                    DeepAllocationBase = record.DeepAllocationBase,
                    DeepRegionSize = record.DeepRegionSize,
                    DeepRegionProtect = record.DeepRegionProtect,
                    DeepRegionState = record.DeepRegionState,
                    DeepRegionType = record.DeepRegionType,
                    OriginPath = NormalizeText(record.OriginPath),
                    CaptureFlags = record.CaptureFlags,
                    DeepSample = TrimByteBuffer(record.DeepSample, (int)record.DeepSampleSize),
                    Registers = HasHandleContext(record)
                                    ? new CaptureIoctlRegisterPayload { Rax = record.RegRax, Rbx = record.RegRbx,
                                                                        Rcx = record.RegRcx, Rdx = record.RegRdx,
                                                                        Rsi = record.RegRsi, Rdi = record.RegRdi,
                                                                        Rbp = record.RegRbp, Rsp = record.RegRsp,
                                                                        R8 = record.RegR8,   R9 = record.RegR9,
                                                                        R10 = record.RegR10, R11 = record.RegR11,
                                                                        R12 = record.RegR12, R13 = record.RegR13,
                                                                        R14 = record.RegR14, R15 = record.RegR15,
                                                                        Rip = record.RegRip, EFlags = record.RegEFlags,
                                                                        Dr0 = record.RegDr0, Dr1 = record.RegDr1,
                                                                        Dr2 = record.RegDr2, Dr3 = record.RegDr3,
                                                                        Dr6 = record.RegDr6, Dr7 = record.RegDr7 }
                                    : null
                };
            }
            else if (record.Type == BlackbirdNative.EventTypeThread)
            {
                payload.Thread = new CaptureIoctlThreadPayload {
                    ProcessPid = record.ProcessPid,     ThreadId = record.ThreadId,
                    CreatorPid = record.CreatorPid,     ThreadFlags = record.ThreadFlags,
                    StartAddress = record.StartAddress, ImageBase = record.ImageBase,
                    ImageSize = record.ImageSize
                };
            }
            else if (record.Type == BlackbirdNative.EventTypeFileSystem)
            {
                payload.File = new CaptureIoctlFilePayload { ProcessPid = record.FileProcessPid,
                                                             ThreadId = record.FileThreadId,
                                                             FileObject = record.FileObject,
                                                             FileId = record.FileId,
                                                             ByteOffset = record.FileByteOffset,
                                                             Length = record.FileLength,
                                                             Status = record.FileStatus,
                                                             Information = record.FileInformation,
                                                             Operation = record.FileOperation,
                                                             MajorCode = record.FileMajorCode,
                                                             MinorCode = record.FileMinorCode,
                                                             IrpFlags = record.FileIrpFlags,
                                                             CreateOptions = record.FileCreateOptions,
                                                             CreateDisposition = record.FileCreateDisposition,
                                                             DesiredAccess = record.FileDesiredAccess,
                                                             ShareAccess = record.FileShareAccess,
                                                             Flags = record.FileFlags,
                                                             Path = NormalizeText(record.FilePath) };
            }
            else if (record.Type == BlackbirdNative.EventTypeRegistry)
            {
                payload.Registry =
                    new CaptureIoctlRegistryPayload { ProcessPid = record.RegistryProcessPid,
                                                      ThreadId = record.RegistryThreadId,
                                                      Operation = record.RegistryOperation,
                                                      NotifyClass = record.RegistryNotifyClass,
                                                      DataType = record.RegistryDataType,
                                                      DataSize = record.RegistryDataSize,
                                                      Flags = record.RegistryFlags,
                                                      SessionId = record.RegistrySessionId,
                                                      KeyPath = NormalizeText(record.RegistryKeyPath),
                                                      ValueName = NormalizeText(record.RegistryValueName) };
            }
            return SerializePayload(payload);
        }

        private static byte[]? BuildEtwPayloadBytes(BrokerEtwEventView view)
        {
            var payload =
                new CaptureEtwPayload { Source = NormalizeText(view.Source),
                                        SourceId = view.SourceId,
                                        Family = view.Family,
                                        EventName = NormalizeText(view.EventName),
                                        Task = view.Task,
                                        Opcode = view.Opcode,
                                        EventId = view.EventId,
                                        EventProcessId = view.EventProcessId,
                                        EventThreadId = view.EventThreadId,
                                        Severity = view.Severity,
                                        Flags = view.Flags,
                                        ActorPid = view.ActorPid,
                                        TargetPid = view.TargetPid,
                                        ProcessPid = view.ProcessPid,
                                        ThreadId = view.ThreadId,
                                        CallerPid = view.CallerPid,
                                        ExplicitTargetPid = view.ExplicitTargetPid,
                                        ParentPid = view.ParentPid,
                                        CreatorPid = view.CreatorPid,
                                        CreatorThreadId = view.CreatorThreadId,
                                        CorrelationFlags = view.CorrelationFlags,
                                        CorrelationAccessMask = view.CorrelationAccessMask,
                                        CorrelationAgeMs = view.CorrelationAgeMs,
                                        DetectionName = NormalizeText(view.DetectionName),
                                        Reason = NormalizeText(view.Reason),
                                        ClassName = NormalizeText(view.ClassName),
                                        Operation = NormalizeText(view.Operation),
                                        DesiredAccess = view.DesiredAccess,
                                        OriginAddress = view.OriginAddress,
                                        OriginProtect = view.OriginProtect,
                                        StatusOpenProcess = view.StatusOpenProcess,
                                        StatusBasicInfo = view.StatusBasicInfo,
                                        StatusSectionName = view.StatusSectionName,
                                        DeepAllocationBase = view.DeepAllocationBase,
                                        DeepRegionSize = view.DeepRegionSize,
                                        DeepRegionProtect = view.DeepRegionProtect,
                                        DeepRegionState = view.DeepRegionState,
                                        DeepRegionType = view.DeepRegionType,
                                        DeepSample = TrimByteBuffer(view.DeepSample, (int)view.DeepSampleSize),
                                        OriginPath = NormalizeText(view.OriginPath),
                                        StartAddress = view.StartAddress,
                                        ImageBase = view.ImageBase,
                                        ImageSize = view.ImageSize,
                                        StartRegionProtect = view.StartRegionProtect,
                                        StartRegionState = view.StartRegionState,
                                        StartRegionType = view.StartRegionType,
                                        StartRegionStatus = view.StartRegionStatus,
                                        SessionId = view.SessionId,
                                        CreateStatus = view.CreateStatus,
                                        ProcessStartKey = view.ProcessStartKey,
                                        SignatureLevel = view.SignatureLevel,
                                        SignatureType = view.SignatureType,
                                        NotifyClass = view.NotifyClass,
                                        DataType = view.DataType,
                                        DataSize = view.DataSize,
                                        ImagePath = NormalizeText(view.ImagePath),
                                        CommandLine = NormalizeText(view.CommandLine),
                                        KeyPath = NormalizeText(view.KeyPath),
                                        ValueName = NormalizeText(view.ValueName),
                                        Details = NormalizeText(view.Details),
                                        ArgumentSummary = NormalizeText(view.ArgumentSummary),
                                        RepeatCount = view.RepeatCount };

            return SerializePayload(payload);
        }

        private static string BuildIoctlIdentity(IoctlParsedEvent record) =>
            record.Type == BlackbirdNative.EventTypeHandle
                ? $"handle:{record.CallerPid}:{record.TargetPid}:{record.OriginAddress:X}"
            : record.Type == BlackbirdNative.EventTypeThread
                ? $"thread:{record.ProcessPid}:{record.ThreadId}:{record.StartAddress:X}"
            : record.Type == BlackbirdNative.EventTypeRegistry
                ? $"registry:{record.RegistryProcessPid}:{record.RegistryKeyPath}:{record.RegistryValueName}"
            : !string.IsNullOrWhiteSpace(record.FilePath) ? $"file:{record.FileProcessPid}:{record.FilePath}"
                                                          : $"ioctl:{record.Sequence}:{record.Type}";

        private static string BuildEtwIdentity(BrokerEtwEventView view) =>
            !string.IsNullOrWhiteSpace(view.ImagePath) ? $"image:{view.ProcessPid}:{view.ImagePath}"
            : !string.IsNullOrWhiteSpace(view.KeyPath) ? $"registry:{view.ProcessPid}:{view.KeyPath}"
            : !string.IsNullOrWhiteSpace(view.DetectionName)
                ? $"detection:{view.ActorPid}:{view.DetectionName}"
                : $"etw:{view.Source}:{view.EventName}:{view.ActorPid}:{view.TargetPid}";

        private static byte[]? SerializeUlongs(ulong[]? values, int count)
        {
            int safeCount = Math.Max(0, Math.Min(values?.Length ?? 0, count));
            if (safeCount == 0)
            {
                return null;
            }

            byte[] buffer = new byte[safeCount * sizeof(ulong)];
            for (int i = 0; i < safeCount; i += 1)
            {
                BitConverter.TryWriteBytes(buffer.AsSpan(i * sizeof(ulong), sizeof(ulong)), values![i]);
            }

            return buffer;
        }

        private static byte[]? SerializePayload<T>(T payload)
            where T : class => JsonSerializer.SerializeToUtf8Bytes(payload, PayloadJsonOptions);

                      private static string NormalizeText(string ? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            string trimmed = value.Trim();
            if (trimmed.Length <= MaxPayloadTextChars)
            {
                return trimmed;
            }

            return trimmed[..MaxPayloadTextChars];
        }

        private static byte[]? TrimByteBuffer(byte[]? bytes, int declaredSize)
        {
            int safeLength = Math.Max(0, Math.Min(bytes?.Length ?? 0, declaredSize));
            if (safeLength == 0)
            {
                return null;
            }

            if (bytes!.Length == safeLength)
            {
                return bytes;
            }

            byte[] trimmed = new byte[safeLength];
            Buffer.BlockCopy(bytes, 0, trimmed, 0, safeLength);
            return trimmed;
        }

        private static bool HasHandleContext(IoctlParsedEvent record)
        {
            if (record.CaptureFlags != 0)
            {
                return true;
            }

            return record.RegRip != 0 || record.RegRsp != 0 || record.RegRax != 0 || record.RegRcx != 0;
        }

        private static TelemetryEvent
        CloneTelemetryEvent(TelemetryEvent src) => new() { TimestampUtc = src.TimestampUtc,
                                                           PID = src.PID,
                                                           TID = src.TID,
                                                           Group = src.Group,
                                                           SubType = src.SubType,
                                                           ProcessName = src.ProcessName,
                                                           Summary = src.Summary,
                                                           Details = src.Details };

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(BlackbirdCaptureLiveStore));
            }
        }

        private sealed class CaptureIoctlPayload
        {
            public uint Type { get; set; }
            public uint Sequence { get; set; }
            public uint StreamMask { get; set; }
            public CaptureIoctlHandlePayload? Handle { get; set; }
            public CaptureIoctlThreadPayload? Thread { get; set; }
            public CaptureIoctlFilePayload? File { get; set; }
            public CaptureIoctlRegistryPayload? Registry { get; set; }
        }

        private sealed class CaptureIoctlHandlePayload
        {
            public uint CallerPid { get; set; }
            public uint TargetPid { get; set; }
            public uint DesiredAccess { get; set; }
            public uint HandleClass { get; set; }
            public uint HandleFlags { get; set; }
            public ulong OriginAddress { get; set; }
            public uint OriginProtect { get; set; }
            public int StatusOpenProcess { get; set; }
            public int StatusBasicInfo { get; set; }
            public int StatusSectionName { get; set; }
            public ulong DeepAllocationBase { get; set; }
            public ulong DeepRegionSize { get; set; }
            public uint DeepRegionProtect { get; set; }
            public uint DeepRegionState { get; set; }
            public uint DeepRegionType { get; set; }
            public string OriginPath { get; set; } = string.Empty;
            public uint CaptureFlags { get; set; }
            public byte[]? DeepSample { get; set; }
            public CaptureIoctlRegisterPayload? Registers { get; set; }
        }

        private sealed class CaptureIoctlRegisterPayload
        {
            public ulong Rax { get; set; }
            public ulong Rbx { get; set; }
            public ulong Rcx { get; set; }
            public ulong Rdx { get; set; }
            public ulong Rsi { get; set; }
            public ulong Rdi { get; set; }
            public ulong Rbp { get; set; }
            public ulong Rsp { get; set; }
            public ulong R8 { get; set; }
            public ulong R9 { get; set; }
            public ulong R10 { get; set; }
            public ulong R11 { get; set; }
            public ulong R12 { get; set; }
            public ulong R13 { get; set; }
            public ulong R14 { get; set; }
            public ulong R15 { get; set; }
            public ulong Rip { get; set; }
            public ulong EFlags { get; set; }
            public ulong Dr0 { get; set; }
            public ulong Dr1 { get; set; }
            public ulong Dr2 { get; set; }
            public ulong Dr3 { get; set; }
            public ulong Dr6 { get; set; }
            public ulong Dr7 { get; set; }
        }

        private sealed class CaptureIoctlThreadPayload
        {
            public uint ProcessPid { get; set; }
            public uint ThreadId { get; set; }
            public uint CreatorPid { get; set; }
            public uint ThreadFlags { get; set; }
            public ulong StartAddress { get; set; }
            public ulong ImageBase { get; set; }
            public ulong ImageSize { get; set; }
        }

        private sealed class CaptureIoctlFilePayload
        {
            public uint ProcessPid { get; set; }
            public uint ThreadId { get; set; }
            public ulong FileObject { get; set; }
            public ulong FileId { get; set; }
            public ulong ByteOffset { get; set; }
            public ulong Length { get; set; }
            public ulong Status { get; set; }
            public ulong Information { get; set; }
            public uint Operation { get; set; }
            public uint MajorCode { get; set; }
            public uint MinorCode { get; set; }
            public uint IrpFlags { get; set; }
            public uint CreateOptions { get; set; }
            public uint CreateDisposition { get; set; }
            public uint DesiredAccess { get; set; }
            public uint ShareAccess { get; set; }
            public uint Flags { get; set; }
            public string Path { get; set; } = string.Empty;
        }

        private sealed class CaptureIoctlRegistryPayload
        {
            public uint ProcessPid { get; set; }
            public uint ThreadId { get; set; }
            public uint Operation { get; set; }
            public uint NotifyClass { get; set; }
            public uint DataType { get; set; }
            public uint DataSize { get; set; }
            public uint Flags { get; set; }
            public uint SessionId { get; set; }
            public string KeyPath { get; set; } = string.Empty;
            public string ValueName { get; set; } = string.Empty;
        }

        private sealed class CaptureEtwPayload
        {
            public string Source { get; set; } = string.Empty;
            public uint SourceId { get; set; }
            public uint Family { get; set; }
            public string EventName { get; set; } = string.Empty;
            public ushort Task { get; set; }
            public ushort Opcode { get; set; }
            public ushort EventId { get; set; }
            public uint EventProcessId { get; set; }
            public uint EventThreadId { get; set; }
            public uint Severity { get; set; }
            public uint Flags { get; set; }
            public uint ActorPid { get; set; }
            public uint TargetPid { get; set; }
            public uint ProcessPid { get; set; }
            public uint ThreadId { get; set; }
            public uint CallerPid { get; set; }
            public uint ExplicitTargetPid { get; set; }
            public uint ParentPid { get; set; }
            public uint CreatorPid { get; set; }
            public uint CreatorThreadId { get; set; }
            public uint CorrelationFlags { get; set; }
            public uint CorrelationAccessMask { get; set; }
            public uint CorrelationAgeMs { get; set; }
            public string DetectionName { get; set; } = string.Empty;
            public string Reason { get; set; } = string.Empty;
            public string ClassName { get; set; } = string.Empty;
            public string Operation { get; set; } = string.Empty;
            public uint DesiredAccess { get; set; }
            public ulong OriginAddress { get; set; }
            public uint OriginProtect { get; set; }
            public int StatusOpenProcess { get; set; }
            public int StatusBasicInfo { get; set; }
            public int StatusSectionName { get; set; }
            public ulong DeepAllocationBase { get; set; }
            public ulong DeepRegionSize { get; set; }
            public uint DeepRegionProtect { get; set; }
            public uint DeepRegionState { get; set; }
            public uint DeepRegionType { get; set; }
            public byte[]? DeepSample { get; set; }
            public string OriginPath { get; set; } = string.Empty;
            public ulong StartAddress { get; set; }
            public ulong ImageBase { get; set; }
            public ulong ImageSize { get; set; }
            public uint StartRegionProtect { get; set; }
            public uint StartRegionState { get; set; }
            public uint StartRegionType { get; set; }
            public int StartRegionStatus { get; set; }
            public uint SessionId { get; set; }
            public int CreateStatus { get; set; }
            public ulong ProcessStartKey { get; set; }
            public byte SignatureLevel { get; set; }
            public byte SignatureType { get; set; }
            public uint NotifyClass { get; set; }
            public uint DataType { get; set; }
            public uint DataSize { get; set; }
            public string ImagePath { get; set; } = string.Empty;
            public string CommandLine { get; set; } = string.Empty;
            public string KeyPath { get; set; } = string.Empty;
            public string ValueName { get; set; } = string.Empty;
            public string Details { get; set; } = string.Empty;
            public string ArgumentSummary { get; set; } = string.Empty;
            public int RepeatCount { get; set; }
        }
    }
}
