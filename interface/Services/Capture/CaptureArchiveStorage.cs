using BlackbirdInterface;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace BlackbirdInterface.Capture
{
    internal static class CaptureArchiveStorage
    {
        internal const int FormatVersion = 1;
        private const string WorkspaceManifestFileName = "manifest.json";
        private const string TabsDirectoryName = "tabs";
        private const string MaterializedFileName = "materialized.json";
        private const string BucketsFileName = "buckets.json";
        private const string TabManifestFileName = "tab.manifest.json";
        private const string SegmentsDirectoryName = "segments";
        private const string BlobsDirectoryName = "blobs";
        private const string IndexFileName = "index.sqlite";
        private const string SegmentExtension = ".bbseg";
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true,
            WriteIndented = true
        };

        internal static bool Exists(string path)
            => !string.IsNullOrWhiteSpace(path) && (File.Exists(path) || Directory.Exists(path));

        internal static void Delete(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
            else if (File.Exists(path))
            {
                File.Delete(path);
            }
        }

        internal static void SaveWorkspace(string path, SessionFileArchive archive)
        {
            string? directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            if (ShouldWriteDirectoryStore(path))
            {
                SaveWorkspaceDirectory(path, archive);
                return;
            }

            string tempRoot = Path.Combine(Path.GetTempPath(), "Blackbird", "archive-build", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempRoot);
            try
            {
                SaveWorkspaceDirectory(tempRoot, archive);
                string tempFile = path + ".tmp";
                if (File.Exists(tempFile))
                {
                    File.Delete(tempFile);
                }

                ZipFile.CreateFromDirectory(tempRoot, tempFile, CompressionLevel.Fastest, includeBaseDirectory: false);
                if (File.Exists(path))
                {
                    File.Replace(tempFile, path, destinationBackupFileName: null, ignoreMetadataErrors: true);
                }
                else
                {
                    File.Move(tempFile, path);
                }
            }
            finally
            {
                if (Directory.Exists(tempRoot))
                {
                    Directory.Delete(tempRoot, recursive: true);
                }
            }
        }

        internal static CaptureLoadedWorkspace LoadWorkspace(string path)
        {
            if (Directory.Exists(path))
            {
                string resolvedPath = ResolveWorkspaceRoot(path);
                if (File.Exists(Path.Combine(resolvedPath, WorkspaceManifestFileName)))
                {
                    return LoadWorkspaceDirectory(resolvedPath);
                }

                if (File.Exists(Path.Combine(path, MaterializedFileName)))
                {
                    return LoadSingleTabWorkspace(path);
                }

                throw new InvalidDataException("Capture workspace is invalid.");
            }

            if (!File.Exists(path))
            {
                throw new FileNotFoundException("Capture workspace not found.", path);
            }

            if (LooksLikeLegacyGzip(path))
            {
                return new CaptureLoadedWorkspace { Archive = SessionFileStorage.LoadLegacyArchive(path) };
            }

            string extractRoot = Path.Combine(Path.GetTempPath(), "Blackbird", "capture-open", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(extractRoot);
            ZipFile.ExtractToDirectory(path, extractRoot, overwriteFiles: true);
            return LoadWorkspaceDirectory(ResolveWorkspaceRoot(extractRoot));
        }

        internal static BlackbirdCaptureLiveStore OpenLiveStore(string rootPath, int pid, string title)
            => BlackbirdCaptureLiveStore.Open(rootPath, pid, title);

        internal static void WriteVarUInt64(Stream stream, ulong value)
        {
            while (value >= 0x80)
            {
                stream.WriteByte((byte)(value | 0x80));
                value >>= 7;
            }

            stream.WriteByte((byte)value);
        }

        internal static long EnsureStringRef(SqliteDatabase database, Dictionary<string, long> cache, string kind, string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return 0;
            }

            string key = kind + "\n" + value;
            if (cache.TryGetValue(key, out long existing))
            {
                return existing;
            }

            using (SqliteStatement insert = database.Prepare("INSERT OR IGNORE INTO strings(kind, value) VALUES(?1, ?2);"))
            {
                insert.BindText(1, kind);
                insert.BindText(2, value);
                _ = insert.Step();
            }

            using (SqliteStatement query = database.Prepare("SELECT id FROM strings WHERE kind=?1 AND value=?2;"))
            {
                query.BindText(1, kind);
                query.BindText(2, value);
                if (query.Step() != SqliteStepState.Row)
                {
                    throw new InvalidOperationException("Failed to resolve string reference.");
                }

                long id = query.ReadInt64(0);
                cache[key] = id;
                return id;
            }
        }

        internal static long EnsureBlobRef(SqliteDatabase database, Dictionary<string, long> stringRefs, Dictionary<string, long> blobRefs, string blobsRoot, string mediaKind, byte[]? bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return 0;
            }

            string hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            if (blobRefs.TryGetValue(hash, out long existing))
            {
                return existing;
            }

            string relativePath = Path.Combine(hash[..2], hash + ".bbblob");
            string fullPath = Path.Combine(blobsRoot, relativePath);
            string? directory = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }
            if (!File.Exists(fullPath))
            {
                File.WriteAllBytes(fullPath, bytes);
            }

            using (SqliteStatement insert = database.Prepare("INSERT OR IGNORE INTO blobs(hash, relative_path, size_bytes, media_kind) VALUES(?1, ?2, ?3, ?4);"))
            {
                insert.BindText(1, hash);
                insert.BindText(2, relativePath.Replace('\\', '/'));
                insert.BindInt64(3, bytes.Length);
                insert.BindText(4, mediaKind);
                _ = insert.Step();
            }

            long id = EnsureStringRef(database, stringRefs, "blob", hash);
            blobRefs[hash] = id;
            return id;
        }

        internal static void CreateSchema(SqliteDatabase database)
        {
            database.ExecuteNonQuery(
                "CREATE TABLE IF NOT EXISTS strings(id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, value TEXT NOT NULL, UNIQUE(kind, value));" +
                "CREATE TABLE IF NOT EXISTS blobs(hash TEXT PRIMARY KEY, relative_path TEXT NOT NULL, size_bytes INTEGER NOT NULL, media_kind TEXT NOT NULL);" +
                "CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, segment_no INTEGER NOT NULL, record_index INTEGER NOT NULL, ts_utc_ticks INTEGER NOT NULL, dt_us INTEGER NOT NULL, pid INTEGER NOT NULL, tid INTEGER NOT NULL, kind INTEGER NOT NULL, flags INTEGER NOT NULL, group_ref INTEGER NOT NULL, subtype_ref INTEGER NOT NULL, summary_ref INTEGER NOT NULL, object_ref INTEGER NOT NULL, payload_blob_ref INTEGER NOT NULL, stack_blob_ref INTEGER NOT NULL);" +
                "CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts_utc_ticks);" +
                "CREATE INDEX IF NOT EXISTS ix_events_pid_ts ON events(pid, ts_utc_ticks);" +
                "CREATE TABLE IF NOT EXISTS buckets(resolution_ms INTEGER NOT NULL, bucket_key INTEGER NOT NULL, total_events INTEGER NOT NULL, timeline_events INTEGER NOT NULL, heuristic_events INTEGER NOT NULL, filesystem_events INTEGER NOT NULL, relation_events INTEGER NOT NULL, bucket_start_ticks INTEGER NOT NULL, bucket_end_ticks INTEGER NOT NULL, hot_group_ref INTEGER NOT NULL, PRIMARY KEY(resolution_ms, bucket_key));");
        }

        private static bool ShouldWriteDirectoryStore(string path)
            => Directory.Exists(path) || string.IsNullOrWhiteSpace(Path.GetExtension(path));

        private static bool LooksLikeLegacyGzip(string path)
        {
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            Span<byte> header = stackalloc byte[2];
            return stream.Read(header) == 2 && header[0] == 0x1F && header[1] == 0x8B;
        }

        private static string ResolveWorkspaceRoot(string rootPath)
        {
            if (File.Exists(Path.Combine(rootPath, WorkspaceManifestFileName)))
            {
                return rootPath;
            }

            string[] childDirectories = Directory.GetDirectories(rootPath);
            if (childDirectories.Length == 1 &&
                File.Exists(Path.Combine(childDirectories[0], WorkspaceManifestFileName)))
            {
                return childDirectories[0];
            }

            return rootPath;
        }

        private static void SaveWorkspaceDirectory(string rootPath, SessionFileArchive archive)
        {
            Directory.CreateDirectory(rootPath);
            string tabsRoot = Path.Combine(rootPath, TabsDirectoryName);
            Directory.CreateDirectory(tabsRoot);

            var manifest = new CaptureWorkspaceManifest
            {
                Version = FormatVersion,
                SavedUtc = archive.SavedUtc == default ? DateTime.UtcNow : archive.SavedUtc,
                ActivePid = archive.ActivePid
            };

            foreach (SessionFileTab tab in archive.Tabs)
            {
                string tabDirectory = Path.Combine(tabsRoot, $"pid-{tab.Pid}");
                WriteTabStore(tabDirectory, tab);
                manifest.Tabs.Add(new CaptureWorkspaceTabDescriptor { Pid = tab.Pid, Title = tab.Title, RelativePath = Path.Combine(TabsDirectoryName, $"pid-{tab.Pid}") });
            }

            File.WriteAllText(Path.Combine(rootPath, WorkspaceManifestFileName), JsonSerializer.Serialize(manifest, JsonOptions), Encoding.UTF8);
        }

        private static CaptureLoadedWorkspace LoadWorkspaceDirectory(string rootPath)
        {
            string manifestPath = Path.Combine(rootPath, WorkspaceManifestFileName);
            if (!File.Exists(manifestPath))
            {
                throw new InvalidDataException("Capture manifest not found.");
            }

            CaptureWorkspaceManifest? manifest = JsonSerializer.Deserialize<CaptureWorkspaceManifest>(File.ReadAllText(manifestPath, Encoding.UTF8), JsonOptions);
            if (manifest == null)
            {
                throw new InvalidDataException("Capture manifest is invalid.");
            }

            var archive = new SessionFileArchive { Version = SessionFileStorage.CurrentVersion, SavedUtc = manifest.SavedUtc, ActivePid = manifest.ActivePid };
            var tabPaths = new Dictionary<int, string>();
            foreach (CaptureWorkspaceTabDescriptor descriptor in manifest.Tabs)
            {
                string tabDirectory = Path.Combine(rootPath, descriptor.RelativePath);
                SessionFileTab? tab = JsonSerializer.Deserialize<SessionFileTab>(File.ReadAllText(Path.Combine(tabDirectory, MaterializedFileName), Encoding.UTF8), JsonOptions);
                if (tab == null)
                {
                    continue;
                }

                tab.CaptureStorePath = tabDirectory;
                archive.Tabs.Add(tab);
                tabPaths[tab.Pid] = tabDirectory;
            }

            return new CaptureLoadedWorkspace { Archive = archive, TabPaths = tabPaths };
        }

        private static CaptureLoadedWorkspace LoadSingleTabWorkspace(string tabDirectory)
        {
            SessionFileTab? tab = JsonSerializer.Deserialize<SessionFileTab>(
                File.ReadAllText(Path.Combine(tabDirectory, MaterializedFileName), Encoding.UTF8),
                JsonOptions);
            if (tab == null)
            {
                throw new InvalidDataException("Capture tab materialized snapshot is invalid.");
            }

            tab.CaptureStorePath = tabDirectory;
            var archive = new SessionFileArchive
            {
                Version = SessionFileStorage.CurrentVersion,
                SavedUtc = File.GetLastWriteTimeUtc(Path.Combine(tabDirectory, MaterializedFileName)),
                ActivePid = tab.Pid
            };
            archive.Tabs.Add(tab);

            return new CaptureLoadedWorkspace
            {
                Archive = archive,
                TabPaths = new Dictionary<int, string> { [tab.Pid] = tabDirectory }
            };
        }

        private static void WriteTabStore(string tabDirectory, SessionFileTab tab)
        {
            Directory.CreateDirectory(tabDirectory);
            string segmentsPath = Path.Combine(tabDirectory, SegmentsDirectoryName);
            string blobsPath = Path.Combine(tabDirectory, BlobsDirectoryName);
            string indexPath = Path.Combine(tabDirectory, IndexFileName);
            Directory.CreateDirectory(segmentsPath);
            Directory.CreateDirectory(blobsPath);

            bool copiedExisting = false;
            if (!string.IsNullOrWhiteSpace(tab.CaptureStorePath) && Directory.Exists(tab.CaptureStorePath))
            {
                string sourceFull = Path.GetFullPath(tab.CaptureStorePath);
                string destFull = Path.GetFullPath(tabDirectory);
                if (!string.Equals(sourceFull, destFull, StringComparison.OrdinalIgnoreCase) && File.Exists(Path.Combine(sourceFull, IndexFileName)))
                {
                    CopyDirectory(sourceFull, destFull);
                    copiedExisting = true;
                }
            }

            if (!copiedExisting && (!File.Exists(indexPath) || !Directory.GetFiles(segmentsPath, "*" + SegmentExtension).Any()))
            {
                GenerateRawStoreFromSnapshot(tabDirectory, tab);
            }

            List<CaptureTimelineBucket> buckets = BuildTimelineBuckets(tab);
            File.WriteAllText(Path.Combine(tabDirectory, BucketsFileName), JsonSerializer.Serialize(buckets, JsonOptions), Encoding.UTF8);
            File.WriteAllText(Path.Combine(tabDirectory, MaterializedFileName), JsonSerializer.Serialize(CloneTab(tab), JsonOptions), Encoding.UTF8);
            File.WriteAllText(Path.Combine(tabDirectory, TabManifestFileName), JsonSerializer.Serialize(new CaptureTabManifest
            {
                Version = FormatVersion,
                Pid = tab.Pid,
                Title = tab.Title,
                CaptureStartUtc = tab.CaptureStartUtc,
                SegmentCount = Directory.GetFiles(segmentsPath, "*" + SegmentExtension).Length,
                BlobCount = Directory.Exists(blobsPath) ? Directory.GetFiles(blobsPath, "*.bbblob", SearchOption.AllDirectories).Length : 0,
                TimelineEventCount = tab.Events.Count,
                GroupedRowCount = tab.EtwGroups.Count + tab.HeuristicsGroups.Count + tab.FilesystemGroups.Count + tab.ProcessRelationsGroups.Count,
                PerformanceSampleCount = tab.PerformanceHistory.Count,
                ThreadLifecycleCount = tab.ThreadLifecycleHistory.Count,
                ThreadStackHistoryCount = tab.ThreadStackHistories.Count
            }, JsonOptions), Encoding.UTF8);
        }

        private static void GenerateRawStoreFromSnapshot(string tabDirectory, SessionFileTab tab)
        {
            string segmentsPath = Path.Combine(tabDirectory, SegmentsDirectoryName);
            string blobsPath = Path.Combine(tabDirectory, BlobsDirectoryName);
            string indexPath = Path.Combine(tabDirectory, IndexFileName);
            if (Directory.Exists(segmentsPath)) Directory.Delete(segmentsPath, recursive: true);
            if (Directory.Exists(blobsPath)) Directory.Delete(blobsPath, recursive: true);
            if (File.Exists(indexPath)) File.Delete(indexPath);
            Directory.CreateDirectory(segmentsPath);
            Directory.CreateDirectory(blobsPath);

            List<CaptureCanonicalRecord> records = BuildCanonicalRecords(tab);
            using SqliteDatabase database = SqliteDatabase.Open(indexPath);
            CreateSchema(database);
            Dictionary<string, long> stringRefs = new(StringComparer.Ordinal);
            Dictionary<string, long> blobRefs = new(StringComparer.Ordinal);
            Dictionary<(int ResolutionMs, long BucketKey), CaptureBucketCounter> buckets = new();

            int cursor = 0;
            int segmentNumber = 0;
            while (cursor < records.Count)
            {
                List<CaptureCanonicalRecord> chunk = TakeChunk(records, ref cursor);
                WriteSegmentChunk(database, chunk, stringRefs, blobRefs, blobsPath, buckets, Path.Combine(segmentsPath, $"{segmentNumber:D6}{SegmentExtension}"), segmentNumber);
                segmentNumber += 1;
            }

            PersistBuckets(database, buckets);
        }
        private static List<CaptureCanonicalRecord> BuildCanonicalRecords(SessionFileTab tab)
        {
            List<CaptureCanonicalRecord> records = new();
            foreach (TelemetryEvent ev in tab.Events)
            {
                records.Add(new CaptureCanonicalRecord { TimestampUtc = ev.TimestampUtc, Pid = ev.PID, Tid = ev.TID, Kind = CaptureEventKind.Timeline, Group = ev.Group, SubType = ev.SubType, Summary = ev.Summary, ObjectIdentity = $"timeline:{ev.Group}:{ev.SubType}:{ev.PID}:{ev.TID}", PayloadBytes = string.IsNullOrWhiteSpace(ev.Details) ? null : Encoding.UTF8.GetBytes(ev.Details) });
            }

            AddGroupedRecords(records, tab.EtwGroups, CaptureEventKind.EtwGrouped, "ETW");
            AddGroupedRecords(records, tab.HeuristicsGroups, CaptureEventKind.HeuristicGrouped, "Heuristics");
            AddGroupedRecords(records, tab.FilesystemGroups, CaptureEventKind.FilesystemGrouped, "Filesystem");
            AddGroupedRecords(records, tab.ProcessRelationsGroups, CaptureEventKind.RelationGrouped, "ProcessRelations");

            foreach (ThreadLifecycleEventSample sample in tab.ThreadLifecycleHistory)
            {
                records.Add(new CaptureCanonicalRecord { TimestampUtc = sample.TimestampUtc, Pid = unchecked((int)sample.ProcessPid), Tid = unchecked((int)sample.ThreadId), Kind = CaptureEventKind.ThreadLifecycle, Group = "ThreadLifecycle", SubType = sample.EventKind, Summary = sample.Notes, ObjectIdentity = $"thread:{sample.ProcessPid}:{sample.ThreadId}:{sample.StartAddress:X}", PayloadBytes = JsonSerializer.SerializeToUtf8Bytes(sample, JsonOptions) });
            }

            records.Sort((a, b) => a.TimestampUtc.CompareTo(b.TimestampUtc));
            return records;
        }

        private static void AddGroupedRecords(List<CaptureCanonicalRecord> records, IEnumerable<GroupedEventRow> groups, CaptureEventKind kind, string groupName)
        {
            foreach (GroupedEventRow row in groups)
            {
                if (row.Details.Count == 0)
                {
                    records.Add(new CaptureCanonicalRecord { TimestampUtc = row.LastSeenUtc, Kind = kind, Group = groupName, SubType = row.Event, Summary = row.Detection, ObjectIdentity = $"{groupName}:{row.GroupKey}", PayloadBytes = JsonSerializer.SerializeToUtf8Bytes(row, JsonOptions) });
                    continue;
                }

                foreach (GroupedEventDetailRow detail in row.Details)
                {
                    records.Add(new CaptureCanonicalRecord { TimestampUtc = detail.TimestampUtc, Pid = unchecked((int)detail.ActorPid), Kind = kind, Group = groupName, SubType = row.Event, Summary = string.IsNullOrWhiteSpace(detail.Event) ? row.Detection : detail.Event, ObjectIdentity = $"{groupName}:{row.GroupKey}:{detail.ActorPid}:{detail.TargetPid}", PayloadBytes = JsonSerializer.SerializeToUtf8Bytes(detail, JsonOptions) });
                }
            }
        }

        private static List<CaptureCanonicalRecord> TakeChunk(List<CaptureCanonicalRecord> records, ref int cursor)
        {
            int start = cursor;
            if (start >= records.Count) return new List<CaptureCanonicalRecord>();
            DateTime firstTimestamp = records[start].TimestampUtc;
            int approxBytes = 0;
            while (cursor < records.Count)
            {
                CaptureCanonicalRecord record = records[cursor];
                approxBytes += 96 + record.Group.Length + record.SubType.Length + record.Summary.Length + (record.PayloadBytes?.Length ?? 0) + (record.StackBytes?.Length ?? 0);
                bool hitLimit = (cursor - start) >= 768 || approxBytes >= 1024 * 1024;
                bool hitWindow = cursor > start && (record.TimestampUtc - firstTimestamp) >= TimeSpan.FromSeconds(2);
                if (hitLimit || hitWindow) break;
                cursor += 1;
            }
            if (cursor == start) cursor += 1;
            return records.GetRange(start, cursor - start);
        }

        private static void WriteSegmentChunk(SqliteDatabase database, List<CaptureCanonicalRecord> chunk, Dictionary<string, long> stringRefs, Dictionary<string, long> blobRefs, string blobsRoot, Dictionary<(int ResolutionMs, long BucketKey), CaptureBucketCounter> buckets, string segmentPath, int segmentNumber)
        {
            using MemoryStream payloadStream = new();
            using SqliteStatement insert = database.Prepare("INSERT INTO events(segment_no, record_index, ts_utc_ticks, dt_us, pid, tid, kind, flags, group_ref, subtype_ref, summary_ref, object_ref, payload_blob_ref, stack_blob_ref) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14);");
            database.ExecuteNonQuery("BEGIN IMMEDIATE;");
            try
            {
                DateTime previous = chunk[0].TimestampUtc;
                for (int i = 0; i < chunk.Count; i += 1)
                {
                    CaptureCanonicalRecord record = chunk[i];
                    long deltaUs = i == 0 ? 0 : Math.Max(0, (long)(record.TimestampUtc - previous).TotalMilliseconds * 1000L);
                    previous = record.TimestampUtc;
                    long groupRef = EnsureStringRef(database, stringRefs, "group", record.Group);
                    long subtypeRef = EnsureStringRef(database, stringRefs, "subtype", record.SubType);
                    long summaryRef = EnsureStringRef(database, stringRefs, "summary", record.Summary);
                    long objectRef = EnsureStringRef(database, stringRefs, "object", record.ObjectIdentity);
                    long payloadRef = EnsureBlobRef(database, stringRefs, blobRefs, blobsRoot, "payload", record.PayloadBytes);
                    long stackRef = EnsureBlobRef(database, stringRefs, blobRefs, blobsRoot, "stack", record.StackBytes);

                    WriteVarUInt64(payloadStream, (ulong)deltaUs);
                    WriteVarUInt64(payloadStream, (ulong)Math.Max(0, record.Pid));
                    WriteVarUInt64(payloadStream, (ulong)Math.Max(0, record.Tid));
                    payloadStream.WriteByte((byte)record.Kind);
                    payloadStream.WriteByte(record.Flags);
                    WriteVarUInt64(payloadStream, (ulong)groupRef);
                    WriteVarUInt64(payloadStream, (ulong)subtypeRef);
                    WriteVarUInt64(payloadStream, (ulong)summaryRef);
                    WriteVarUInt64(payloadStream, (ulong)objectRef);
                    WriteVarUInt64(payloadStream, (ulong)payloadRef);
                    WriteVarUInt64(payloadStream, (ulong)stackRef);

                    insert.Reset(); insert.ClearBindings();
                    insert.BindInt64(1, segmentNumber); insert.BindInt64(2, i); insert.BindInt64(3, record.TimestampUtc.Ticks); insert.BindInt64(4, deltaUs); insert.BindInt64(5, record.Pid); insert.BindInt64(6, record.Tid); insert.BindInt64(7, (int)record.Kind); insert.BindInt64(8, record.Flags); insert.BindInt64(9, groupRef); insert.BindInt64(10, subtypeRef); insert.BindInt64(11, summaryRef); insert.BindInt64(12, objectRef); insert.BindInt64(13, payloadRef); insert.BindInt64(14, stackRef);
                    _ = insert.Step();
                    AddToBuckets(buckets, record, groupRef);
                }
                database.ExecuteNonQuery("COMMIT;");
            }
            catch
            {
                database.ExecuteNonQuery("ROLLBACK;");
                throw;
            }

            byte[] payload = payloadStream.ToArray();
            byte[] compressed = global::BlackbirdInterface.Lz4BlockCodec.Compress(payload);
            using FileStream file = new(segmentPath, FileMode.Create, FileAccess.Write, FileShare.None);
            using BinaryWriter writer = new(file, Encoding.UTF8, leaveOpen: false);
            writer.Write(new byte[] { (byte)'B', (byte)'B', (byte)'S', (byte)'1' }); writer.Write(FormatVersion); writer.Write(chunk.Count); writer.Write(chunk[0].TimestampUtc.Ticks); writer.Write(chunk[^1].TimestampUtc.Ticks); writer.Write(payload.Length); writer.Write(compressed.Length); writer.Write((byte)1); writer.Write((byte)0); writer.Write((ushort)0); writer.Write(compressed);
        }
        private static void PersistBuckets(SqliteDatabase database, Dictionary<(int ResolutionMs, long BucketKey), CaptureBucketCounter> buckets)
        {
            using SqliteStatement insert = database.Prepare("INSERT OR REPLACE INTO buckets(resolution_ms, bucket_key, total_events, timeline_events, heuristic_events, filesystem_events, relation_events, bucket_start_ticks, bucket_end_ticks, hot_group_ref) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10);");
            database.ExecuteNonQuery("BEGIN IMMEDIATE;");
            try
            {
                foreach (CaptureBucketCounter bucket in buckets.Values.OrderBy(x => x.ResolutionMs).ThenBy(x => x.BucketKey))
                {
                    insert.Reset(); insert.ClearBindings();
                    insert.BindInt64(1, bucket.ResolutionMs); insert.BindInt64(2, bucket.BucketKey); insert.BindInt64(3, bucket.TotalEvents); insert.BindInt64(4, bucket.TimelineEvents); insert.BindInt64(5, bucket.HeuristicEvents); insert.BindInt64(6, bucket.FilesystemEvents); insert.BindInt64(7, bucket.RelationEvents); insert.BindInt64(8, bucket.StartTicks); insert.BindInt64(9, bucket.EndTicks); insert.BindInt64(10, bucket.HotGroupRef);
                    _ = insert.Step();
                }
                database.ExecuteNonQuery("COMMIT;");
            }
            catch
            {
                database.ExecuteNonQuery("ROLLBACK;");
                throw;
            }
        }

        private static List<CaptureTimelineBucket> BuildTimelineBuckets(SessionFileTab tab)
            => BuildCanonicalRecords(tab).Aggregate(new Dictionary<(int ResolutionMs, long BucketKey), CaptureBucketCounter>(), (acc, record) => { AddToBuckets(acc, record, 0); return acc; }).Values.OrderBy(x => x.ResolutionMs).ThenBy(x => x.BucketKey).Select(x => new CaptureTimelineBucket { ResolutionMs = x.ResolutionMs, BucketKey = x.BucketKey, TotalEvents = x.TotalEvents, TimelineEvents = x.TimelineEvents, HeuristicEvents = x.HeuristicEvents, FilesystemEvents = x.FilesystemEvents, RelationEvents = x.RelationEvents, BucketStartUtc = new DateTime(x.StartTicks, DateTimeKind.Utc), BucketEndUtc = new DateTime(x.EndTicks, DateTimeKind.Utc), HotGroupRef = x.HotGroupRef }).ToList();

        internal static void AddToBuckets(Dictionary<(int ResolutionMs, long BucketKey), CaptureBucketCounter> buckets, CaptureCanonicalRecord record, long groupRef)
        {
            foreach (int resolutionMs in new[] { 100, 1000, 10000, 60000 })
            {
                long bucketTicks = TimeSpan.FromMilliseconds(resolutionMs).Ticks;
                long bucketKey = record.TimestampUtc.Ticks / bucketTicks;
                var key = (resolutionMs, bucketKey);
                if (!buckets.TryGetValue(key, out CaptureBucketCounter? bucket) || bucket == null)
                {
                    bucket = new CaptureBucketCounter { ResolutionMs = resolutionMs, BucketKey = bucketKey, StartTicks = bucketKey * bucketTicks, EndTicks = bucketKey * bucketTicks + bucketTicks };
                    buckets[key] = bucket;
                }
                bucket.TotalEvents += 1;
                switch (record.Kind)
                {
                    case CaptureEventKind.Timeline: bucket.TimelineEvents += 1; break;
                    case CaptureEventKind.HeuristicGrouped: bucket.HeuristicEvents += 1; break;
                    case CaptureEventKind.FilesystemGrouped:
                    case CaptureEventKind.FilesystemRaw: bucket.FilesystemEvents += 1; break;
                    case CaptureEventKind.RelationGrouped: bucket.RelationEvents += 1; break;
                }
                if (groupRef != 0)
                {
                    bucket.GroupCounts.TryGetValue(groupRef, out int count);
                    count += 1;
                    bucket.GroupCounts[groupRef] = count;
                    if (bucket.HotGroupRef == 0 || !bucket.GroupCounts.TryGetValue(bucket.HotGroupRef, out int hotCount) || count >= hotCount)
                    {
                        bucket.HotGroupRef = groupRef;
                    }
                }
            }
        }

        private static SessionFileTab CloneTab(SessionFileTab tab)
        {
            byte[] json = JsonSerializer.SerializeToUtf8Bytes(tab, JsonOptions);
            SessionFileTab? clone = JsonSerializer.Deserialize<SessionFileTab>(json, JsonOptions);
            if (clone == null) throw new InvalidOperationException("Failed to clone session tab.");
            clone.CaptureStorePath = null;
            return clone;
        }

        private static void CopyDirectory(string sourcePath, string destinationPath)
        {
            Directory.CreateDirectory(destinationPath);
            foreach (string directory in Directory.GetDirectories(sourcePath, "*", SearchOption.AllDirectories))
            {
                Directory.CreateDirectory(Path.Combine(destinationPath, Path.GetRelativePath(sourcePath, directory)));
            }
            foreach (string file in Directory.GetFiles(sourcePath, "*", SearchOption.AllDirectories))
            {
                string destinationFile = Path.Combine(destinationPath, Path.GetRelativePath(sourcePath, file));
                string? parent = Path.GetDirectoryName(destinationFile);
                if (!string.IsNullOrWhiteSpace(parent)) Directory.CreateDirectory(parent);
                File.Copy(file, destinationFile, overwrite: true);
            }
        }
    }
}
