using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace BlackbirdInterface
{
    internal readonly record struct SignatureIntelOptions(bool Enabled, bool MemoryScan, bool PageScan, bool HashScan);

    internal sealed partial class SignatureIntelService : IDisposable
    {
        private const long MaxFileBytes = 16L * 1024 * 1024;
        private const int MaxSampleBytes = 64 * 1024;
        private const int MaxEvidenceSampleBytes = 64;
        private const int ProcessMemoryScanCooldownSeconds = 10;
        private const int ProcessMemoryReadChunkBytes = 0x4000;
        private const int MaxProcessMemoryRegions = 512;
        private const int MaxProcessMemoryRegionBytes = 2 * 1024 * 1024;
        private const int MaxProcessMemoryTotalBytes = 64 * 1024 * 1024;
        private const int MaxProcessMemoryFindings = 64;
        private const uint MemCommit = 0x1000;
        private const uint PageNoAccess = 0x01;
        private const uint PageReadOnly = 0x02;
        private const uint PageReadWrite = 0x04;
        private const uint PageWriteCopy = 0x08;
        private const uint PageExecute = 0x10;
        private const uint PageExecuteRead = 0x20;
        private const uint PageExecuteReadWrite = 0x40;
        private const uint PageExecuteWriteCopy = 0x80;
        private const uint PageGuard = 0x100;
        private const uint ProcessQueryInformation = 0x0400;
        private const uint ProcessQueryLimitedInformation = 0x1000;
        private const uint ProcessVmRead = 0x0010;
        private static readonly JsonSerializerOptions JsonOptions =
            new()
            {
                PropertyNameCaseInsensitive = true,
                AllowTrailingCommas = true,
                ReadCommentHandling = JsonCommentHandling.Skip
            };

        private readonly Action<IReadOnlyList<HeuristicEventView>> _publish;
        private readonly Action<string>? _log;
        private readonly CancellationTokenSource _cts = new();
        private readonly AutoResetEvent _signal = new(false);
        private readonly ConcurrentQueue<WorkItem> _queue = new();
        private readonly ConcurrentDictionary<string, byte> _pending = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, DateTime> _processScanLastQueuedUtc =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly object _rulesLock = new();
        private readonly Task _worker;
        private SignatureIntelOptions _options;
        private Ruleset? _rules;
        private bool _disposed;

        internal SignatureIntelService(Action<IReadOnlyList<HeuristicEventView>> publish, Action<string>? log = null)
        {
            _publish = publish;
            _log = log;
            _worker = Task.Run(WorkerLoopAsync);
        }

        internal void Configure(SignatureIntelOptions options)
        {
            _options = options;
            _log?.Invoke(
                $"signature intel: enabled={options.Enabled} hash={options.HashScan} mem={options.MemoryScan} page={options.PageScan}");
        }

        internal IReadOnlyList<SignatureIntelRuleDocument> LoadRuleDocuments()
        {
            var documents = new List<SignatureIntelRuleDocument>();
            foreach ((string root, bool isUserRoot) in EnumerateRuleRoots())
            {
                if (!Directory.Exists(root))
                {
                    continue;
                }

                foreach (string path in Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories)
                             .Where(IsRuleDocumentPath)
                             .OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
                {
                    documents.Add(BuildRuleDocument(root, path, isUserRoot));
                }
            }

            return documents;
        }

        internal string ReadRuleDocument(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("Rule path is empty.", nameof(path));
            }

            string fullPath = Path.GetFullPath(path);
            return File.ReadAllText(fullPath, Encoding.UTF8);
        }

        internal string SaveUserRuleDocument(string fileName, string content)
        {
            if (string.IsNullOrWhiteSpace(content))
            {
                throw new InvalidOperationException("Rule content is empty.");
            }

            string trimmedName = SanitizeRuleFileName(fileName);
            if (string.IsNullOrWhiteSpace(trimmedName))
            {
                throw new InvalidOperationException("Rule file name is empty.");
            }

            string extension = Path.GetExtension(trimmedName);
            if (string.IsNullOrWhiteSpace(extension))
            {
                trimmedName += ".yar";
                extension = ".yar";
            }

            if (!IsRuleDocumentPath(trimmedName))
            {
                throw new InvalidOperationException(
                    "Only .yar, .yara, .yml, .yaml, and manifest .json rule files can be saved.");
            }

            if (IsYaraPath(trimmedName) && !ParseYara(content).Any())
            {
                throw new InvalidOperationException("No valid YARA rules were found in the editor content.");
            }

            if (IsSigmaPath(trimmedName) && !ParseSigmaDocuments(content).Any())
            {
                throw new InvalidOperationException("No valid SIGMA rules were found in the editor content.");
            }

            if (extension.Equals(".json", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    ManifestDocument? doc = JsonSerializer.Deserialize<ManifestDocument>(content, JsonOptions);
                    if (doc?.Rules == null || doc.Rules.Count == 0)
                    {
                        throw new InvalidOperationException("No manifest rules were found in the editor content.");
                    }
                }
                catch (JsonException ex)
                {
                    throw new InvalidOperationException($"Manifest JSON is invalid: {ex.Message}", ex);
                }
            }

            string root = EnsureUserRulesRoot();
            string fullPath = Path.Combine(root, trimmedName);
            File.WriteAllText(fullPath, NormalizeRuleText(content),
                              new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            ReloadRules();
            _log?.Invoke($"signature intel rules saved: {Path.GetFileName(fullPath)}");
            return fullPath;
        }

        internal string SaveUserYaraRule(string fileName, string content) => SaveUserRuleDocument(fileName, content);

        internal string ImportRuleDocument(string sourcePath)
        {
            if (string.IsNullOrWhiteSpace(sourcePath))
            {
                throw new ArgumentException("Rule import path is empty.", nameof(sourcePath));
            }

            string fullSourcePath = Path.GetFullPath(sourcePath);
            if (!File.Exists(fullSourcePath))
            {
                throw new FileNotFoundException("Rule file was not found.", fullSourcePath);
            }

            if (!IsRuleDocumentPath(fullSourcePath))
            {
                throw new InvalidOperationException(
                    "Only .yar, .yara, .yml, .yaml, and manifest .json rule files can be imported.");
            }

            string root = EnsureUserRulesRoot();
            string destinationPath = Path.Combine(root, Path.GetFileName(fullSourcePath));
            File.Copy(fullSourcePath, destinationPath, overwrite: true);
            ReloadRules();
            _log?.Invoke($"signature intel rules imported: {Path.GetFileName(destinationPath)}");
            return destinationPath;
        }

        internal void DeleteUserRuleDocument(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            string fullPath = Path.GetFullPath(path);
            string userRoot = Path.GetFullPath(EnsureUserRulesRoot())
                                  .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string userRootPrefix = userRoot + Path.DirectorySeparatorChar;
            if (!fullPath.Equals(userRoot, StringComparison.OrdinalIgnoreCase) &&
                !fullPath.StartsWith(userRootPrefix, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Only user-managed rule files can be deleted from the interface.");
            }

            if (File.Exists(fullPath))
            {
                File.Delete(fullPath);
                ReloadRules();
                _log?.Invoke($"signature intel rules deleted: {Path.GetFileName(fullPath)}");
            }
        }

        internal void ReloadRules()
        {
            lock (_rulesLock)
            {
                _rules = null;
                _cache.Clear();
            }

            _ = EnsureRulesLoaded();
        }

        internal void QueueFileScan(string? path, uint actorPid, uint targetPid, string source, string eventName,
                                    string trigger)
        {
            if (!_options.Enabled)
            {
                return;
            }

            string fullPath = NormalizePath(path);
            if (!ShouldScanPath(fullPath))
            {
                return;
            }

            string key = $"file|{fullPath}";
            if (!_pending.TryAdd(key, 0))
            {
                return;
            }

            _queue.Enqueue(
                new WorkItem(key, true, false, fullPath, null, 0, actorPid, targetPid, source, eventName, trigger));
            _signal.Set();
        }

        internal void QueueSampleScan(byte[]? sample, int sampleSize, bool pageSample, string? originPath,
                                      uint actorPid, uint targetPid, string source, string eventName, string trigger)
        {
            if (!_options.Enabled || sample == null || sampleSize <= 0)
            {
                return;
            }

            if (pageSample ? !_options.PageScan : !_options.MemoryScan)
            {
                return;
            }

            int size = Math.Min(Math.Min(sample.Length, sampleSize), MaxSampleBytes);
            if (size <= 0)
            {
                return;
            }

            byte[] copy = new byte[size];
            Buffer.BlockCopy(sample, 0, copy, 0, size);
            ulong hash = 14695981039346656037UL;
            for (int i = 0; i < size; i += 1)
            {
                hash ^= copy[i];
                hash *= 1099511628211UL;
            }

            string key = $"sample|{(pageSample ? "page" : "mem")}|{hash:X16}|{NormalizePath(originPath)}";
            if (!_pending.TryAdd(key, 0))
            {
                return;
            }

            _queue.Enqueue(new WorkItem(key, false, pageSample, NormalizePath(originPath), copy, size, actorPid,
                                        targetPid, source, eventName, trigger));
            _signal.Set();
        }

        internal void QueueProcessMemoryScan(uint processId, uint actorPid, uint targetPid, string source,
                                             string eventName, string trigger, bool force = false)
        {
            if (!_options.Enabled || !_options.MemoryScan || processId == 0)
            {
                return;
            }

            string key = $"process-memory|{processId}";
            DateTime now = DateTime.UtcNow;
            if (!force && _processScanLastQueuedUtc.TryGetValue(key, out DateTime lastQueued) &&
                (now - lastQueued).TotalSeconds < ProcessMemoryScanCooldownSeconds)
            {
                return;
            }

            if (!_pending.TryAdd(key, 0))
            {
                return;
            }

            _processScanLastQueuedUtc[key] = now;
            _queue.Enqueue(
                new WorkItem(key, IsFile: false, IsPage: false, Path: string.Empty, Sample: null, SampleSize: 0,
                             ActorPid: actorPid, TargetPid: targetPid == 0 ? processId : targetPid,
                             Source: source, EventName: eventName, Trigger: trigger, IsProcessMemory: true,
                             ProcessId: processId));
            _signal.Set();
        }

        internal IReadOnlyList<HeuristicEventView> ScanBufferForFindings(byte[]? sample, int sampleSize,
                                                                         bool pageSample, string? originPath,
                                                                         uint actorPid, uint targetPid, string source,
                                                                         string eventName, string trigger,
                                                                         int maxScanBytes = MaxSampleBytes)
        {
            if (!_options.Enabled || sample == null || sampleSize <= 0)
            {
                return Array.Empty<HeuristicEventView>();
            }

            if (pageSample ? !_options.PageScan : !_options.MemoryScan)
            {
                return Array.Empty<HeuristicEventView>();
            }

            int scanCap = Math.Max(1, maxScanBytes);
            int size = Math.Min(Math.Min(sample.Length, sampleSize), scanCap);
            if (size <= 0)
            {
                return Array.Empty<HeuristicEventView>();
            }

            var work =
                new WorkItem($"sync-sample|{Guid.NewGuid():N}", IsFile: false, IsPage: pageSample,
                             Path: NormalizePath(originPath), Sample: sample, SampleSize: size, ActorPid: actorPid,
                             TargetPid: targetPid, Source: source, EventName: eventName, Trigger: trigger);

            return ScanSample(work);
        }

        internal IReadOnlyList<HeuristicEventView> EvaluateEventRules(BrokerEtwEventView view)
        {
            if (!_options.Enabled)
            {
                return Array.Empty<HeuristicEventView>();
            }

            Ruleset rules = EnsureRulesLoaded();
            if (rules.SigmaRules.Count == 0)
            {
                return Array.Empty<HeuristicEventView>();
            }

            SignatureEventContext context = SignatureEventContext.FromEtw(view);
            return EvaluateSigmaRules(context, view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc,
                                      view.ActorPid, view.TargetPid, view.Source, view.EventName);
        }

        internal IReadOnlyList<HeuristicEventView> EvaluateEventRules(IoctlParsedEvent record)
        {
            if (!_options.Enabled)
            {
                return Array.Empty<HeuristicEventView>();
            }

            Ruleset rules = EnsureRulesLoaded();
            if (rules.SigmaRules.Count == 0)
            {
                return Array.Empty<HeuristicEventView>();
            }

            SignatureEventContext context = SignatureEventContext.FromIoctl(record);
            return EvaluateSigmaRules(context, DateTime.UtcNow, context.ActorPid, context.TargetPid, context.Source,
                                      context.EventName);
        }

        internal static string GetBundledRulesRoot() => Path.Combine(AppContext.BaseDirectory, "Rules",
                                                                     "SignatureIntel");

        internal static string
        GetUserRulesRoot() => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "BK",
                                           "Rules", "SignatureIntel");

        private static string EnsureUserRulesRoot()
        {
            string root = GetUserRulesRoot();
            Directory.CreateDirectory(root);
            return root;
        }

        private static bool IsRuleDocumentPath(string path)
        {
            return IsYaraPath(path) || IsSigmaPath(path) ||
                   Path.GetExtension(path).Equals(".json", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsYaraPath(string path)
        {
            string extension = Path.GetExtension(path);
            return extension.Equals(".yar", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".yara", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsSigmaPath(string path)
        {
            string extension = Path.GetExtension(path);
            return extension.Equals(".yml", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".yaml", StringComparison.OrdinalIgnoreCase);
        }

        private static SignatureIntelRuleDocument BuildRuleDocument(string root, string path, bool isUserRule)
        {
            string extension = Path.GetExtension(path);
            string kind;
            int ruleCount = 0;

            try
            {
                if (extension.Equals(".json", StringComparison.OrdinalIgnoreCase))
                {
                    kind = "Manifest";
                    ManifestDocument? doc = JsonSerializer.Deserialize<ManifestDocument>(
                        File.ReadAllText(path, Encoding.UTF8), JsonOptions);
                    ruleCount = doc?.Rules?.Count(x => x != null) ?? 0;
                }
                else if (IsYaraPath(path))
                {
                    kind = "YARA";
                    ruleCount = ParseYara(File.ReadAllText(path, Encoding.UTF8)).Count();
                }
                else
                {
                    kind = "SIGMA";
                    ruleCount = ParseSigmaDocuments(File.ReadAllText(path, Encoding.UTF8)).Count();
                }
            }
            catch
            {
                kind = extension.Equals(".json", StringComparison.OrdinalIgnoreCase) ? "Manifest"
                       : IsYaraPath(path) ? "YARA"
                                                                                     : "SIGMA";
            }

            string relativePath = Path.GetRelativePath(root, path);
            return new SignatureIntelRuleDocument(Path.GetFileName(path), Path.GetFullPath(path), relativePath, kind,
                                                  Math.Max(0, ruleCount), isUserRule);
        }

        private static string SanitizeRuleFileName(string fileName)
        {
            string safe = (fileName ?? string.Empty).Trim();
            foreach (char invalid in Path.GetInvalidFileNameChars())
            {
                safe = safe.Replace(invalid, '_');
            }

            return safe;
        }

        private static string NormalizeRuleText(string content)
        {
            string normalized = content.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
            return normalized.Replace("\n", Environment.NewLine, StringComparison.Ordinal);
        }
    }
}
