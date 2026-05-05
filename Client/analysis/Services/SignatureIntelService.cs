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

    internal sealed class SignatureIntelService : IDisposable
    {
        private const long MaxFileBytes = 16L * 1024 * 1024;
        private const int MaxSampleBytes = 4096;
        private static readonly JsonSerializerOptions JsonOptions =
            new() { PropertyNameCaseInsensitive = true, AllowTrailingCommas = true,
                    ReadCommentHandling = JsonCommentHandling.Skip };

        private readonly Action<IReadOnlyList<HeuristicEventView>> _publish;
        private readonly Action<string>? _log;
        private readonly CancellationTokenSource _cts = new();
        private readonly AutoResetEvent _signal = new(false);
        private readonly ConcurrentQueue<WorkItem> _queue = new();
        private readonly ConcurrentDictionary<string, byte> _pending = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);
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

        private async Task WorkerLoopAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                try
                {
                    if (!_queue.TryDequeue(out WorkItem? work))
                    {
                        _signal.WaitOne(250);
                        continue;
                    }

                    var findings = work.IsFile ? ScanFile(work) : ScanSample(work);
                    if (findings.Count != 0)
                    {
                        _publish(findings);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _log?.Invoke($"signature intel worker failed: {ex.Message}");
                    await Task.Delay(150, _cts.Token).ConfigureAwait(false);
                }
            }
        }

        private List<HeuristicEventView> ScanFile(WorkItem work)
        {
            try
            {
                FileInfo info = new(work.Path);
                if (!info.Exists)
                {
                    return new();
                }

                Ruleset rules = EnsureRulesLoaded();
                CacheEntry entry = _cache.AddOrUpdate(
                    work.Path,
                    _ => BuildCacheEntry(info, rules),
                    (_, existing) => existing.Matches(info) ? existing : BuildCacheEntry(info, rules));

                return entry.Findings
                    .Select(x =>
                                x.ToHeuristic(work.ActorPid, work.TargetPid, work.Source, work.EventName, work.Trigger))
                    .ToList();
            }
            finally
            {
                _pending.TryRemove(work.Key, out _);
            }
        }

        private List<HeuristicEventView> ScanSample(WorkItem work)
        {
            try
            {
                Ruleset rules = EnsureRulesLoaded();
                var findings = new List<HeuristicEventView>();
                if (work.Sample == null || work.SampleSize <= 0)
                {
                    return findings;
                }

                ReadOnlySpan<byte> bytes = work.Sample.AsSpan(0, work.SampleSize);
                foreach (YaraRule rule in rules.YaraRules)
                {
                    if (work.IsPage && !rule.PageScope)
                    {
                        continue;
                    }
                    if (!work.IsPage && !rule.MemoryScope)
                    {
                        continue;
                    }
                    if (!rule.IsMatch(bytes))
                    {
                        continue;
                    }

                    findings.Add(BuildHeuristic(
                        string.IsNullOrWhiteSpace(rule.Detection) ? "YARA_SAMPLE_MATCH" : rule.Detection, rule.Severity,
                        work.ActorPid, work.TargetPid, work.Source, work.EventName,
                        BuildRuleReason(rule.Title, work.Trigger, rule.MitreId, rule.MitreName, rule.SigmaId),
                        $"engine=yara scope={(work.IsPage ? "page" : "memory")} origin={Fallback(work.Path)} rule={rule.Name} sample={EventDetailFormatting.FormatSampleHex(work.Sample, work.SampleSize)}"));
                }

                return findings;
            }
            finally
            {
                _pending.TryRemove(work.Key, out _);
            }
        }

        private CacheEntry BuildCacheEntry(FileInfo info, Ruleset rules)
        {
            string path = info.FullName;
            string sha256 = string.Empty;
            string sha1 = string.Empty;
            string md5 = string.Empty;
            byte[]? content = null;
            SignatureTrustState signature = ClassifySignature(path);
            string signer = ResolveSigner(path);
            if (_options.HashScan)
            {
                try
                {
                    using FileStream stream =
                        File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    sha256 = Convert.ToHexString(SHA256.HashData(stream));
                    stream.Position = 0;
                    sha1 = Convert.ToHexString(SHA1.HashData(stream));
                    stream.Position = 0;
                    md5 = Convert.ToHexString(MD5.HashData(stream));
                }
                catch
                {
                }
            }

            bool needContent = info.Length > 0 && info.Length <= MaxFileBytes &&
                               (rules.YaraRules.Any(x => x.FileScope) ||
                                rules.ManifestRules.Any(x => !string.IsNullOrWhiteSpace(x.ContainsAscii)));
            if (needContent)
            {
                try
                {
                    content = File.ReadAllBytes(path);
                }
                catch
                {
                }
            }

            var findings = new List<MaterializedFinding>();
            if (signature is SignatureTrustState.Unsigned or SignatureTrustState.Invalid or SignatureTrustState.Expired)
            {
                findings.Add(new MaterializedFinding(
                    signature == SignatureTrustState.Invalid ? "FILE_SIGNATURE_TRUST_FAILURE"
                                                             : "FILE_UNSIGNED_EXECUTABLE",
                    signature == SignatureTrustState.Invalid ? 7u : 5u, $"signature={signature}",
                    $"path={path} signer={Fallback(signer)} sha256={Fallback(sha256)}"));
            }

            foreach (ManifestRule rule in rules.ManifestRules)
            {
                if (!RuleMatches(rule, path, info.Name, signature, signer, sha256, sha1, md5, content))
                {
                    continue;
                }
                findings.Add(new MaterializedFinding(
                    string.IsNullOrWhiteSpace(rule.Detection) ? "SIGNATURE_RULE_MATCH" : rule.Detection,
                    ParseSeverity(rule.Severity, 5),
                    BuildRuleReason(rule.Title, rule.Description, rule.MitreTechniqueId, rule.MitreTechnique,
                                    rule.SigmaRuleId),
                    $"path={path} sha256={Fallback(sha256)} signer={Fallback(signer)} rule={Fallback(rule.Id)}"));
            }

            if (content != null)
            {
                ReadOnlySpan<byte> bytes = content;
                foreach (YaraRule rule in rules.YaraRules)
                {
                    if (!rule.FileScope || !rule.IsMatch(bytes))
                    {
                        continue;
                    }
                    findings.Add(new MaterializedFinding(
                        string.IsNullOrWhiteSpace(rule.Detection) ? "YARA_FILE_MATCH" : rule.Detection, rule.Severity,
                        BuildRuleReason(rule.Title, "file-content", rule.MitreId, rule.MitreName, rule.SigmaId),
                        $"engine=yara path={path} rule={rule.Name}"));
                }
            }

            return new CacheEntry(info.Length, info.LastWriteTimeUtc, findings);
        }

        private Ruleset EnsureRulesLoaded()
        {
            if (_rules != null)
            {
                return _rules;
            }

            lock (_rulesLock)
            {
                if (_rules != null)
                {
                    return _rules;
                }

                var manifestRules = new List<ManifestRule>();
                var yaraRules = new List<YaraRule>();
                var sigmaRules = new List<SigmaRule>();

                foreach ((string root, _) in EnumerateRuleRoots())
                {
                    if (!Directory.Exists(root))
                    {
                        continue;
                    }

                    foreach (string path in Directory.EnumerateFiles(root, "*.json", SearchOption.AllDirectories))
                    {
                        try
                        {
                            ManifestDocument? doc = JsonSerializer.Deserialize<ManifestDocument>(
                                File.ReadAllText(path, Encoding.UTF8), JsonOptions);
                            if (doc?.Rules != null)
                            {
                                manifestRules.AddRange(doc.Rules.Where(x => x != null).Select(x => x!));
                            }
                        }
                        catch (Exception ex)
                        {
                            _log?.Invoke(
                                $"signature intel manifest load failed: {Path.GetFileName(path)} {ex.Message}");
                        }
                    }

                    foreach (string path in Directory.EnumerateFiles(root, "*.yar", SearchOption.AllDirectories)
                                 .Concat(Directory.EnumerateFiles(root, "*.yara", SearchOption.AllDirectories)))
                    {
                        try
                        {
                            yaraRules.AddRange(ParseYara(File.ReadAllText(path, Encoding.UTF8)));
                        }
                        catch (Exception ex)
                        {
                            _log?.Invoke($"signature intel yara load failed: {Path.GetFileName(path)} {ex.Message}");
                        }
                    }

                    foreach (string path in Directory.EnumerateFiles(root, "*.yml", SearchOption.AllDirectories)
                                 .Concat(Directory.EnumerateFiles(root, "*.yaml", SearchOption.AllDirectories)))
                    {
                        try
                        {
                            sigmaRules.AddRange(ParseSigmaDocuments(File.ReadAllText(path, Encoding.UTF8)));
                        }
                        catch (Exception ex)
                        {
                            _log?.Invoke($"signature intel sigma load failed: {Path.GetFileName(path)} {ex.Message}");
                        }
                    }
                }

                _rules = new Ruleset(manifestRules, yaraRules, sigmaRules);
                _log?.Invoke(
                    $"signature intel rules loaded: manifest={manifestRules.Count} yara={yaraRules.Count} sigma={sigmaRules.Count}");
                return _rules;
            }
        }

        private static IEnumerable<(string Root, bool IsUserRoot)> EnumerateRuleRoots()
        {
            yield return (GetBundledRulesRoot(), false);
            yield return (GetUserRulesRoot(), true);
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
                       : IsYaraPath(path)                                            ? "YARA"
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

        private static IEnumerable<YaraRule> ParseYara(string text)
        {
            foreach ((string Name, string Body)ruleBlock in EnumerateYaraRuleBlocks(text))
            {
                string meta = ExtractBlock(ruleBlock.Body, "meta:");
                string strings = ExtractBlock(ruleBlock.Body, "strings:");
                string condition = ExtractBlock(ruleBlock.Body, "condition:");
                if (strings.Length == 0)
                {
                    continue;
                }

                List<YaraPattern> patterns = ParseYaraStrings(strings);
                if (patterns.Count == 0)
                {
                    continue;
                }

                Dictionary<string, string> metaMap = ParseMeta(meta);
                string scope = metaMap.TryGetValue("scope", out string? scopeValue) ? scopeValue : "file,memory,page";
                yield return new YaraRule(
                    ruleBlock.Name,
                    metaMap.TryGetValue("title", out string? title) ? title : ruleBlock.Name,
                    metaMap.TryGetValue("detection", out string? detection) ? detection : ruleBlock.Name.ToUpperInvariant(),
                    metaMap.TryGetValue("mitre_technique_id", out string? mitreId) ? mitreId : string.Empty,
                    metaMap.TryGetValue("mitre_technique", out string? mitreName) ? mitreName : string.Empty,
                    metaMap.TryGetValue("sigma_rule_id", out string? sigmaId) ? sigmaId : string.Empty,
                    ParseSeverity(metaMap.TryGetValue("severity", out string? sev) ? sev : null, 6),
                    scope.Contains("file", StringComparison.OrdinalIgnoreCase),
                    scope.Contains("memory", StringComparison.OrdinalIgnoreCase),
                    scope.Contains("page", StringComparison.OrdinalIgnoreCase),
                    string.IsNullOrWhiteSpace(condition) ? "any of them" : condition.Trim(),
                    patterns);
            }
        }

        private static IEnumerable<(string Name, string Body)> EnumerateYaraRuleBlocks(string text)
        {
            var ruleRegex = new Regex(@"(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b",
                                      RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            int searchIndex = 0;
            while (searchIndex < text.Length)
            {
                Match match = ruleRegex.Match(text, searchIndex);
                if (!match.Success)
                {
                    yield break;
                }

                int open = text.IndexOf('{', match.Index + match.Length);
                if (open < 0)
                {
                    yield break;
                }

                int close = FindMatchingBrace(text, open);
                if (close < 0)
                {
                    yield break;
                }

                yield return (match.Groups[1].Value.Trim(), text.Substring(open + 1, close - open - 1));
                searchIndex = close + 1;
            }
        }

        private static int FindMatchingBrace(string text, int openIndex)
        {
            int depth = 0;
            bool inString = false;
            bool inLineComment = false;
            bool inBlockComment = false;
            for (int i = openIndex; i < text.Length; i += 1)
            {
                char c = text[i];
                char next = i + 1 < text.Length ? text[i + 1] : '\0';

                if (inLineComment)
                {
                    if (c is '\r' or '\n')
                    {
                        inLineComment = false;
                    }
                    continue;
                }

                if (inBlockComment)
                {
                    if (c == '*' && next == '/')
                    {
                        inBlockComment = false;
                        i += 1;
                    }
                    continue;
                }

                if (inString)
                {
                    if (c == '\\')
                    {
                        i += 1;
                        continue;
                    }
                    if (c == '"')
                    {
                        inString = false;
                    }
                    continue;
                }

                if (c == '/' && next == '/')
                {
                    inLineComment = true;
                    i += 1;
                    continue;
                }
                if (c == '/' && next == '*')
                {
                    inBlockComment = true;
                    i += 1;
                    continue;
                }
                if (c == '"')
                {
                    inString = true;
                    continue;
                }
                if (c == '{')
                {
                    depth += 1;
                    continue;
                }
                if (c == '}')
                {
                    depth -= 1;
                    if (depth == 0)
                    {
                        return i;
                    }
                }
            }

            return -1;
        }

        private static List<YaraPattern> ParseYaraStrings(string strings)
        {
            var patterns = new List<YaraPattern>();
            int index = 0;
            while (index < strings.Length)
            {
                int dollar = strings.IndexOf('$', index);
                if (dollar < 0)
                {
                    break;
                }

                int cursor = dollar + 1;
                while (cursor < strings.Length && (char.IsLetterOrDigit(strings[cursor]) || strings[cursor] == '_'))
                {
                    cursor += 1;
                }

                if (cursor == dollar + 1)
                {
                    index = cursor;
                    continue;
                }

                string identifier = strings[(dollar + 1)..cursor];
                cursor = SkipWhitespace(strings, cursor);
                if (cursor >= strings.Length || strings[cursor] != '=')
                {
                    index = cursor;
                    continue;
                }

                cursor = SkipWhitespace(strings, cursor + 1);
                if (cursor >= strings.Length)
                {
                    break;
                }

                if (strings[cursor] == '"')
                {
                    if (!TryReadQuoted(strings, cursor, out string value, out int afterString))
                    {
                        break;
                    }

                    string modifiers = ReadYaraModifiers(strings, afterString, out int afterModifiers);
                    bool nocase = modifiers.Contains("nocase", StringComparison.OrdinalIgnoreCase);
                    bool wide = modifiers.Contains("wide", StringComparison.OrdinalIgnoreCase);
                    bool ascii = modifiers.Contains("ascii", StringComparison.OrdinalIgnoreCase) || !wide;
                    byte[] decoded = DecodeYaraTextBytes(value);
                    if (ascii)
                    {
                        patterns.Add(YaraPattern.Ascii(identifier, decoded, nocase));
                    }
                    if (wide)
                    {
                        patterns.Add(YaraPattern.Wide(identifier, decoded, nocase));
                    }
                    index = afterModifiers;
                    continue;
                }

                if (strings[cursor] == '{')
                {
                    int close = FindHexPatternClose(strings, cursor);
                    if (close < 0)
                    {
                        break;
                    }

                    YaraPattern? pattern =
                        YaraPattern.Hex(identifier, strings.Substring(cursor + 1, close - cursor - 1));
                    if (pattern != null)
                    {
                        patterns.Add(pattern);
                    }
                    _ = ReadYaraModifiers(strings, close + 1, out int afterModifiers);
                    index = afterModifiers;
                    continue;
                }

                index = cursor + 1;
            }

            return patterns;
        }

        private static int SkipWhitespace(string text, int index)
        {
            while (index < text.Length && char.IsWhiteSpace(text[index]))
            {
                index += 1;
            }
            return index;
        }

        private static bool TryReadQuoted(string text, int start, out string value, out int after)
        {
            var sb = new StringBuilder();
            value = string.Empty;
            after = start;
            if (start >= text.Length || text[start] != '"')
            {
                return false;
            }

            for (int i = start + 1; i < text.Length; i += 1)
            {
                char c = text[i];
                if (c == '\\' && i + 1 < text.Length)
                {
                    sb.Append(c);
                    sb.Append(text[i + 1]);
                    i += 1;
                    continue;
                }
                if (c == '"')
                {
                    value = sb.ToString();
                    after = i + 1;
                    return true;
                }
                sb.Append(c);
            }

            return false;
        }

        private static string ReadYaraModifiers(string text, int start, out int after)
        {
            int end = start;
            while (end < text.Length && text[end] is not '\r' and not '\n')
            {
                end += 1;
            }

            after = end;
            return text[start..end];
        }

        private static int FindHexPatternClose(string text, int open)
        {
            int parenDepth = 0;
            for (int i = open + 1; i < text.Length; i += 1)
            {
                char c = text[i];
                if (c == '(')
                {
                    parenDepth += 1;
                }
                else if (c == ')' && parenDepth > 0)
                {
                    parenDepth -= 1;
                }
                else if (c == '}' && parenDepth == 0)
                {
                    return i;
                }
            }

            return -1;
        }

        private static byte[] DecodeYaraTextBytes(string value)
        {
            var bytes = new List<byte>();
            string text = value ?? string.Empty;
            for (int i = 0; i < text.Length; i += 1)
            {
                char c = text[i];
                if (c == '\\' && i + 1 < text.Length)
                {
                    char next = text[i + 1];
                    if (next == 'x' && i + 3 < text.Length &&
                        byte.TryParse(text.Substring(i + 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture,
                                      out byte hex))
                    {
                        bytes.Add(hex);
                        i += 3;
                        continue;
                    }

                    bytes.Add(next switch { 'n' => (byte)'\n', 'r' => (byte)'\r', 't' => (byte)'\t', '"' => (byte)'"',
                                            '\\' => (byte)'\\',
                                            _ => ToYaraByte(next) });
                    i += 1;
                    continue;
                }

                if (c <= 0x7F)
                {
                    bytes.Add((byte)c);
                }
                else
                {
                    bytes.AddRange(Encoding.UTF8.GetBytes(new[] { c }));
                }
            }

            return bytes.ToArray();
        }

        private static byte ToYaraByte(char value) => value <= byte.MaxValue ? (byte)value : (byte)'?';

        private static string ExtractBlock(string body, string marker)
        {
            int start = body.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (start < 0)
                return string.Empty;
            start += marker.Length;
            int end = body.Length;
            foreach (string next in new[] { "meta:", "strings:", "condition:" })
            {
                if (next.Equals(marker, StringComparison.OrdinalIgnoreCase))
                    continue;
                int pos = body.IndexOf(next, start, StringComparison.OrdinalIgnoreCase);
                if (pos >= 0 && pos < end)
                    end = pos;
            }
            return body[start..end];
        }

        private static Dictionary<string, string> ParseMeta(string meta)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string raw in meta.Split('\n'))
            {
                string line = raw.Trim();
                int eq = line.IndexOf('=');
                if (eq <= 0)
                    continue;
                map[line[..eq].Trim()] = line[(eq + 1)..].Trim().Trim('"');
            }
            return map;
        }

        private static IEnumerable<SigmaRule> ParseSigmaDocuments(string text)
        {
            foreach (string documentText in SplitYamlDocuments(text))
            {
                if (string.IsNullOrWhiteSpace(documentText))
                {
                    continue;
                }

                YamlNode? rootNode = ParseYamlDocument(documentText);
                if (rootNode is not YamlMap root)
                {
                    continue;
                }

                if (!root.Values.TryGetValue("detection", out YamlNode? detectionNode) ||
                    detectionNode is not YamlMap detectionMap)
                {
                    continue;
                }

                var selections = new Dictionary<string, SigmaSelection>(StringComparer.OrdinalIgnoreCase);
                string condition = string.Empty;
                foreach (KeyValuePair<string, YamlNode> item in detectionMap.Values)
                {
                    if (item.Key.Equals("condition", StringComparison.OrdinalIgnoreCase))
                    {
                        condition = ReadYamlScalar(item.Value);
                        continue;
                    }

                    SigmaSelection selection = ParseSigmaSelection(item.Value);
                    if (selection.Branches.Count != 0)
                    {
                        selections[item.Key] = selection;
                    }
                }

                if (selections.Count == 0)
                {
                    continue;
                }

                condition = string.IsNullOrWhiteSpace(condition) ? selections.Keys.First() : condition.Trim();
                SigmaLogsource logsource = ParseSigmaLogsource(root.Values.TryGetValue("logsource", out YamlNode? ls) ? ls : null);
                string id = ReadYamlMapScalar(root, "id");
                string title = ReadYamlMapScalar(root, "title");
                if (string.IsNullOrWhiteSpace(title))
                {
                    title = string.IsNullOrWhiteSpace(id) ? "SIGMA rule" : id;
                }

                string level = ReadYamlMapScalar(root, "level");
                IReadOnlyList<string> tags = ReadYamlStringList(root.Values.TryGetValue("tags", out YamlNode? tagNode) ? tagNode : null);
                string mitreId = ExtractMitreTechniqueId(tags);
                yield return new SigmaRule(string.IsNullOrWhiteSpace(id) ? StableRuleId(title) : id.Trim(),
                                           title.Trim(), ReadYamlMapScalar(root, "description"), level,
                                           ParseSeverity(level, 5), mitreId, condition, logsource, tags, selections);
            }
        }

        private IReadOnlyList<HeuristicEventView> EvaluateSigmaRules(SignatureEventContext context,
                                                                     DateTime timestampUtc, uint actorPid,
                                                                     uint targetPid, string source, string eventName)
        {
            Ruleset rules = EnsureRulesLoaded();
            if (rules.SigmaRules.Count == 0)
            {
                return Array.Empty<HeuristicEventView>();
            }

            var findings = new List<HeuristicEventView>();
            foreach (SigmaRule rule in rules.SigmaRules)
            {
                if (!rule.IsMatch(context, out string matchSummary))
                {
                    continue;
                }

                string detection =
                    $"SIGMA_{NormalizeDetectionToken(string.IsNullOrWhiteSpace(rule.Id) ? rule.Title : rule.Id)}";
                string reason =
                    BuildRuleReason(rule.Title, rule.Description, rule.MitreTechniqueId, string.Empty, rule.Id);
                string evidence =
                    $"engine=sigma sigma_id={EvidenceToken(rule.Id)} rule={EvidenceToken(rule.Title)} category={EvidenceToken(rule.Logsource.Category)} condition={EvidenceToken(rule.Condition)} fields={EvidenceToken(matchSummary)} event={EvidenceToken(context.Source)}/{EvidenceToken(context.EventName)}";
                HeuristicEventView heuristic =
                    BuildHeuristic(detection, rule.Severity, actorPid, targetPid, source, eventName, reason, evidence);
                heuristic.TimestampUtc = timestampUtc;
                heuristic.LastSeenUtc = timestampUtc;
                heuristic.CorrelationFlags = context.CorrelationFlags;
                heuristic.CorrelationAccessMask = context.CorrelationAccessMask;
                heuristic.CorrelationAgeMs = context.CorrelationAgeMs;
                findings.Add(heuristic);
            }

            return findings;
        }

        private static SigmaLogsource ParseSigmaLogsource(YamlNode? node)
        {
            if (node is not YamlMap map)
            {
                return new SigmaLogsource(string.Empty, string.Empty, string.Empty);
            }

            return new SigmaLogsource(ReadYamlMapScalar(map, "product"), ReadYamlMapScalar(map, "category"),
                                      ReadYamlMapScalar(map, "service"));
        }

        private static SigmaSelection ParseSigmaSelection(YamlNode node)
        {
            var branches = new List<SigmaSelectionBranch>();
            if (node is YamlMap map)
            {
                SigmaSelectionBranch branch = ParseSigmaBranch(map);
                if (branch.Conditions.Count != 0)
                {
                    branches.Add(branch);
                }
            }
            else if (node is YamlList list)
            {
                var keywordValues = new List<string>();
                foreach (YamlNode item in list.Items)
                {
                    if (item is YamlMap itemMap)
                    {
                        SigmaSelectionBranch branch = ParseSigmaBranch(itemMap);
                        if (branch.Conditions.Count != 0)
                        {
                            branches.Add(branch);
                        }
                    }
                    else
                    {
                        keywordValues.AddRange(ReadYamlStringList(item));
                    }
                }

                if (keywordValues.Count != 0)
                {
                    branches.Add(new SigmaSelectionBranch(
                        new[] { new SigmaFieldCondition("*", Array.Empty<string>(), keywordValues, false) }));
                }
            }
            else
            {
                IReadOnlyList<string> values = ReadYamlStringList(node);
                if (values.Count != 0)
                {
                    branches.Add(new SigmaSelectionBranch(
                        new[] { new SigmaFieldCondition("*", Array.Empty<string>(), values, false) }));
                }
            }

            return new SigmaSelection(branches);
        }

        private static SigmaSelectionBranch ParseSigmaBranch(YamlMap map)
        {
            var conditions = new List<SigmaFieldCondition>();
            foreach (KeyValuePair<string, YamlNode> entry in map.Values)
            {
                string[] parts =
                    entry.Key.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (parts.Length == 0)
                {
                    continue;
                }

                string field = parts[0];
                IReadOnlyList<string> modifiers =
                    parts.Skip(1).Select(x => x.Trim()).Where(x => x.Length != 0).ToArray();
                IReadOnlyList<string> values = ReadYamlStringList(entry.Value);
                bool requireAll = modifiers.Any(x => x.Equals("all", StringComparison.OrdinalIgnoreCase));
                conditions.Add(new SigmaFieldCondition(field, modifiers, values, requireAll));
            }

            return new SigmaSelectionBranch(conditions);
        }

        private static string ExtractMitreTechniqueId(IReadOnlyList<string> tags)
        {
            foreach (string tag in tags)
            {
                Match match = Regex.Match(tag, @"attack\.t(?<id>\d{4}(?:\.\d{3})?)", RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    return $"T{match.Groups["id"].Value}";
                }
            }

            return string.Empty;
        }

        private static string StableRuleId(string title)
        {
            string token = NormalizeDetectionToken(title).ToLowerInvariant();
            return string.IsNullOrWhiteSpace(token) ? "BK.sigma.rule" : $"BK.sigma.{token}";
        }

        private static string NormalizeDetectionToken(string value)
        {
            string token = Regex.Replace(value ?? string.Empty, @"[^A-Za-z0-9]+", "_").Trim('_');
            return string.IsNullOrWhiteSpace(token) ? "RULE_MATCH" : token.ToUpperInvariant();
        }

        private static string EvidenceToken(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return "unknown";
            }

            return value.Trim().Replace(' ', '_').Replace('\t', '_');
        }

        private static IEnumerable<string> SplitYamlDocuments(string text)
        {
            var current = new StringBuilder();
            foreach (string rawLine in text.Replace("\r\n", "\n", StringComparison.Ordinal)
                         .Replace('\r', '\n')
                         .Split('\n'))
            {
                string trimmed = rawLine.Trim();
                if (trimmed.Equals("---", StringComparison.Ordinal))
                {
                    if (current.Length != 0)
                    {
                        yield return current.ToString();
                        current.Clear();
                    }
                    continue;
                }

                if (trimmed.Equals("...", StringComparison.Ordinal))
                {
                    continue;
                }

                current.AppendLine(rawLine);
            }

            if (current.Length != 0)
            {
                yield return current.ToString();
            }
        }

        private static YamlNode? ParseYamlDocument(string text)
        {
            List<YamlLine> lines = BuildYamlLines(text);
            if (lines.Count == 0)
            {
                return null;
            }

            int index = 0;
            return ParseYamlBlock(lines, ref index, lines[0].Indent);
        }

        private static List<YamlLine> BuildYamlLines(string text)
        {
            var lines = new List<YamlLine>();
            foreach (string rawLine in text.Replace("\r\n", "\n", StringComparison.Ordinal)
                         .Replace('\r', '\n')
                         .Split('\n'))
            {
                string withoutComment = StripYamlComment(rawLine);
                if (string.IsNullOrWhiteSpace(withoutComment))
                {
                    continue;
                }

                string expanded = withoutComment.Replace("\t", "    ", StringComparison.Ordinal);
                int indent = 0;
                while (indent < expanded.Length && expanded[indent] == ' ')
                {
                    indent += 1;
                }

                string content = expanded[indent..].TrimEnd();
                if (content.Length == 0 || content.Equals("---", StringComparison.Ordinal) ||
                    content.Equals("...", StringComparison.Ordinal))
                {
                    continue;
                }

                lines.Add(new YamlLine(indent, content));
            }

            return lines;
        }

        private static string StripYamlComment(string line)
        {
            bool inSingle = false;
            bool inDouble = false;
            for (int i = 0; i < line.Length; i += 1)
            {
                char c = line[i];
                if (c == '\'' && !inDouble)
                {
                    inSingle = !inSingle;
                    continue;
                }

                if (c == '"' && !inSingle)
                {
                    bool escaped = i > 0 && line[i - 1] == '\\';
                    if (!escaped)
                    {
                        inDouble = !inDouble;
                    }
                    continue;
                }

                if (c == '#' && !inSingle && !inDouble && (i == 0 || char.IsWhiteSpace(line[i - 1])))
                {
                    return line[..i];
                }
            }

            return line;
        }

        private static YamlNode ParseYamlBlock(List<YamlLine> lines, ref int index, int indent)
        {
            if (index >= lines.Count)
            {
                return new YamlScalar(string.Empty);
            }

            return lines[index].Content.StartsWith("- ", StringComparison.Ordinal)
                       ? ParseYamlList(lines, ref index, indent)
                       : ParseYamlMap(lines, ref index, indent);
        }

        private static YamlNode ParseYamlList(List<YamlLine> lines, ref int index, int indent)
        {
            var items = new List<YamlNode>();
            while (index < lines.Count && lines[index].Indent == indent &&
                   lines[index].Content.StartsWith("- ", StringComparison.Ordinal))
            {
                string itemText = lines[index].Content[2..].Trim();
                index += 1;
                if (itemText.Length == 0)
                {
                    if (index < lines.Count && lines[index].Indent > indent)
                    {
                        items.Add(ParseYamlBlock(lines, ref index, lines[index].Indent));
                    }
                    else
                    {
                        items.Add(new YamlScalar(string.Empty));
                    }
                    continue;
                }

                int colon = FindYamlColon(itemText);
                if (colon > 0)
                {
                    var map = new YamlMap(new Dictionary<string, YamlNode>(StringComparer.OrdinalIgnoreCase));
                    AddYamlMapEntry(map, itemText, colon, lines, ref index, indent);
                    if (index < lines.Count && lines[index].Indent > indent)
                    {
                        YamlNode nested = ParseYamlBlock(lines, ref index, lines[index].Indent);
                        if (nested is YamlMap nestedMap)
                        {
                            foreach (KeyValuePair<string, YamlNode> pair in nestedMap.Values)
                            {
                                map.Values[pair.Key] = pair.Value;
                            }
                        }
                    }
                    items.Add(map);
                }
                else
                {
                    items.Add(ParseYamlScalarOrInlineList(itemText));
                }
            }

            return new YamlList(items);
        }

        private static YamlNode ParseYamlMap(List<YamlLine> lines, ref int index, int indent)
        {
            var map = new YamlMap(new Dictionary<string, YamlNode>(StringComparer.OrdinalIgnoreCase));
            while (index < lines.Count && lines[index].Indent == indent &&
                   !lines[index].Content.StartsWith("- ", StringComparison.Ordinal))
            {
                string content = lines[index].Content;
                int colon = FindYamlColon(content);
                index += 1;
                if (colon <= 0)
                {
                    continue;
                }

                AddYamlMapEntry(map, content, colon, lines, ref index, indent);
            }

            return map;
        }

        private static void AddYamlMapEntry(YamlMap map, string content, int colon, List<YamlLine> lines, ref int index,
                                            int indent)
        {
            string key = UnquoteYamlScalar(content[..colon].Trim());
            string valueText = content[(colon + 1)..].Trim();
            if (valueText.Length == 0)
            {
                if (index < lines.Count && lines[index].Indent > indent)
                {
                    map.Values[key] = ParseYamlBlock(lines, ref index, lines[index].Indent);
                }
                else
                {
                    map.Values[key] = new YamlScalar(string.Empty);
                }
                return;
            }

            if (valueText is "|" or ">")
            {
                bool folded = valueText == ">";
                var sb = new StringBuilder();
                while (index < lines.Count && lines[index].Indent > indent)
                {
                    if (sb.Length != 0)
                    {
                        sb.Append(folded ? ' ' : '\n');
                    }
                    sb.Append(lines[index].Content.Trim());
                    index += 1;
                }
                map.Values[key] = new YamlScalar(sb.ToString());
                return;
            }

            map.Values[key] = ParseYamlScalarOrInlineList(valueText);
        }

        private static int FindYamlColon(string text)
        {
            bool inSingle = false;
            bool inDouble = false;
            for (int i = 0; i < text.Length; i += 1)
            {
                char c = text[i];
                if (c == '\'' && !inDouble)
                {
                    inSingle = !inSingle;
                }
                else if (c == '"' && !inSingle)
                {
                    bool escaped = i > 0 && text[i - 1] == '\\';
                    if (!escaped)
                    {
                        inDouble = !inDouble;
                    }
                }
                else if (c == ':' && !inSingle && !inDouble)
                {
                    return i;
                }
            }

            return -1;
        }

        private static YamlNode ParseYamlScalarOrInlineList(string valueText)
        {
            string value = valueText.Trim();
            if (value.StartsWith("[", StringComparison.Ordinal) && value.EndsWith("]", StringComparison.Ordinal))
            {
                string inner = value[1.. ^ 1];
                return new YamlList(SplitYamlInlineList(inner)
                                        .Select(x => new YamlScalar(UnquoteYamlScalar(x)))
                                        .Cast<YamlNode>()
                                        .ToList());
            }

            return new YamlScalar(UnquoteYamlScalar(value));
        }

        private static IEnumerable<string> SplitYamlInlineList(string text)
        {
            var current = new StringBuilder();
            bool inSingle = false;
            bool inDouble = false;
            for (int i = 0; i < text.Length; i += 1)
            {
                char c = text[i];
                if (c == '\'' && !inDouble)
                {
                    inSingle = !inSingle;
                }
                else if (c == '"' && !inSingle)
                {
                    bool escaped = i > 0 && text[i - 1] == '\\';
                    if (!escaped)
                    {
                        inDouble = !inDouble;
                    }
                }

                if (c == ',' && !inSingle && !inDouble)
                {
                    yield return current.ToString().Trim();
                    current.Clear();
                    continue;
                }

                current.Append(c);
            }

            if (current.Length != 0)
            {
                yield return current.ToString().Trim();
            }
        }

        private static string UnquoteYamlScalar(string value)
        {
            string trimmed = value.Trim();
            if (trimmed.Length >= 2 && trimmed[0] == '\'' && trimmed[^1] == '\'')
            {
                return trimmed[1.. ^ 1].Replace("''", "'", StringComparison.Ordinal);
            }

            if (trimmed.Length >= 2 && trimmed[0] == '"' && trimmed[^1] == '"')
            {
                return trimmed[1.. ^ 1]
                    .Replace("\\\"", "\"", StringComparison.Ordinal)
                    .Replace("\\\\", "\\", StringComparison.Ordinal)
                    .Replace("\\n", "\n", StringComparison.Ordinal)
                    .Replace("\\r", "\r", StringComparison.Ordinal)
                    .Replace("\\t", "\t", StringComparison.Ordinal);
            }

            return trimmed;
        }

        private static string ReadYamlMapScalar(YamlMap map, string key)
        {
            return map.Values.TryGetValue(key, out YamlNode? node) ? ReadYamlScalar(node) : string.Empty;
        }

        private static string ReadYamlScalar(YamlNode node)
        {
            return node switch { YamlScalar scalar => scalar.Value,
                                 YamlList list => string.Join(",", list.Items.Select(ReadYamlScalar)),
                                 _ => string.Empty };
        }

        private static IReadOnlyList<string> ReadYamlStringList(YamlNode? node)
        {
            if (node == null)
            {
                return Array.Empty<string>();
            }

            if (node is YamlList list)
            {
                return list.Items.SelectMany(ReadYamlStringList)
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .Select(x => x.Trim())
                    .ToArray();
            }

            string scalar = ReadYamlScalar(node);
            return string.IsNullOrWhiteSpace(scalar) ? Array.Empty<string>() : new[] { scalar.Trim() };
        }

        private static bool RuleMatches(ManifestRule rule, string path, string fileName, SignatureTrustState signature,
                                        string signer, string sha256, string sha1, string md5, byte[]? content)
        {
            if (!string.IsNullOrWhiteSpace(rule.FileNameContains) &&
                fileName.IndexOf(rule.FileNameContains, StringComparison.OrdinalIgnoreCase) < 0)
                return false;
            if (!string.IsNullOrWhiteSpace(rule.PathContains) &&
                path.IndexOf(rule.PathContains, StringComparison.OrdinalIgnoreCase) < 0)
                return false;
            if (!string.IsNullOrWhiteSpace(rule.SignerState) &&
                !string.Equals(rule.SignerState, signature.ToString(), StringComparison.OrdinalIgnoreCase))
                return false;
            if (!string.IsNullOrWhiteSpace(rule.SignerContains) &&
                signer.IndexOf(rule.SignerContains, StringComparison.OrdinalIgnoreCase) < 0)
                return false;
            if (!string.IsNullOrWhiteSpace(rule.Sha256) &&
                !string.Equals(rule.Sha256, sha256, StringComparison.OrdinalIgnoreCase))
                return false;
            if (!string.IsNullOrWhiteSpace(rule.Sha1) &&
                !string.Equals(rule.Sha1, sha1, StringComparison.OrdinalIgnoreCase))
                return false;
            if (!string.IsNullOrWhiteSpace(rule.Md5) &&
                !string.Equals(rule.Md5, md5, StringComparison.OrdinalIgnoreCase))
                return false;
            if (!string.IsNullOrWhiteSpace(rule.ContainsAscii) &&
                (content == null || !ContainsAscii(content, rule.ContainsAscii, rule.ContainsAsciiNoCase)))
                return false;
            return true;
        }

        private static bool ContainsAscii(byte[] content, string text, bool nocase)
        {
            if (content.Length == 0 || text.Length == 0)
                return false;
            byte[] needle = Encoding.ASCII.GetBytes(nocase ? text.ToUpperInvariant() : text);
            for (int i = 0; i <= content.Length - needle.Length; i += 1)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j += 1)
                {
                    byte hay = content[i + j];
                    if (nocase)
                        hay = (byte) char.ToUpperInvariant((char)hay);
                    if (hay != needle[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                    return true;
            }
            return false;
        }

        private static bool ShouldScanPath(string path)
        {
            string ext = Path.GetExtension(path);
            return ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                   ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                   ext.Equals(".sys", StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizePath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return string.Empty;
            try
            {
                return Path.GetFullPath(path.Trim());
            }
            catch
            {
                return path.Trim();
            }
        }

        private static SignatureTrustState ClassifySignature(string path)
        {
            try
            {
#pragma warning disable SYSLIB0057
                X509Certificate cert = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
                using var cert2 = new X509Certificate2(cert);
                using var chain = new X509Chain { ChainPolicy = { RevocationMode = X509RevocationMode.NoCheck,
                                                                  VerificationFlags = X509VerificationFlags.NoFlag } };
                bool valid = chain.Build(cert2);
                if (cert2.NotAfter.ToUniversalTime() < DateTime.UtcNow)
                    return SignatureTrustState.Expired;
                return valid ? SignatureTrustState.Trusted : SignatureTrustState.Invalid;
            }
            catch (CryptographicException)
            {
                return SignatureTrustState.Unsigned;
            }
            catch
            {
                return SignatureTrustState.Unknown;
            }
        }

        private static string ResolveSigner(string path)
        {
            try
            {
#pragma warning disable SYSLIB0057
                X509Certificate cert = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
                using var cert2 = new X509Certificate2(cert);
                return cert2.Subject ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        private static uint ParseSeverity(string? text, uint fallback)
        {
            if (uint.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint value))
                return value;
            return (text ?? string.Empty).Trim().ToLowerInvariant() switch { "critical" => 8u,      "high" => 6u,
                                                                             "medium" => 4u,        "low" => 2u,
                                                                             "informational" => 1u, "info" => 1u,
                                                                             _ => fallback };
        }

        private static string BuildRuleReason(string? title, string? detail, string? mitreId, string? mitreName,
                                              string? sigmaId)
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(title))
                parts.Add(title.Trim());
            if (!string.IsNullOrWhiteSpace(detail))
                parts.Add(detail.Trim());
            if (!string.IsNullOrWhiteSpace(mitreId) || !string.IsNullOrWhiteSpace(mitreName))
                parts.Add($"MITRE {Fallback(mitreId)} {Fallback(mitreName)}".Trim());
            if (!string.IsNullOrWhiteSpace(sigmaId))
                parts.Add($"SIGMA {sigmaId.Trim()}");
            return parts.Count == 0 ? "offline signature-intel match" : string.Join(" | ", parts);
        }

        private static string Fallback(string? text) => string.IsNullOrWhiteSpace(text) ? "unknown" : text.Trim();

        private static HeuristicEventView BuildHeuristic(string detection, uint severity, uint actorPid, uint targetPid,
                                                         string source, string eventName, string reason,
                                                         string evidence)
        {
            DateTime now = DateTime.UtcNow;
            return new HeuristicEventView { TimestampUtc = now,        LastSeenUtc = now,     Severity = severity,
                                            DetectionName = detection, ActorPid = actorPid,   TargetPid = targetPid,
                                            Source = source,           EventName = eventName, Reason = reason,
                                            Evidence = evidence };
        }

        private static bool EvaluateYaraCondition(string condition, IReadOnlyDictionary<string, bool> hits)
        {
            string expression = Regex.Replace(
                condition ?? string.Empty, @"\b(?<q>any|all|\d+)\s+of\s+(?<target>them|\([^)]+\)|\$[A-Za-z0-9_*]+)",
                match => EvaluateYaraQuantifier(match.Groups["q"].Value, match.Groups["target"].Value, hits) ? "true"
                                                                                                             : "false",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

            return EvaluateBooleanExpression(expression, token => ResolveYaraConditionToken(token, hits), false);
        }

        private static bool EvaluateYaraQuantifier(string quantity, string target,
                                                   IReadOnlyDictionary<string, bool> hits)
        {
            IEnumerable<string> names;
            string trimmed = target.Trim();
            if (trimmed.Equals("them", StringComparison.OrdinalIgnoreCase))
            {
                names = hits.Keys;
            }
            else if (trimmed.StartsWith("(", StringComparison.Ordinal) &&
                     trimmed.EndsWith(")", StringComparison.Ordinal))
            {
                string[] requested =
                    trimmed[1.. ^ 1]
                        .Split(new[] { ',', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(x => x.Trim())
                        .ToArray();
                names = requested.SelectMany(name => name.EndsWith("*", StringComparison.Ordinal)
                                                         ? hits.Keys.Where(x => WildcardMatch(x, name))
                                                         : new[] { name });
            }
            else if (trimmed.EndsWith("*", StringComparison.Ordinal))
            {
                names = hits.Keys.Where(x => WildcardMatch(x, trimmed));
            }
            else
            {
                names = new[] { trimmed };
            }

            List<string> materialized =
                names.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            int hitCount = materialized.Count(name => hits.TryGetValue(name, out bool hit) && hit);
            if (quantity.Equals("all", StringComparison.OrdinalIgnoreCase))
            {
                return materialized.Count != 0 && hitCount == materialized.Count;
            }
            if (quantity.Equals("any", StringComparison.OrdinalIgnoreCase))
            {
                return hitCount > 0;
            }
            return int.TryParse(quantity, NumberStyles.Integer, CultureInfo.InvariantCulture, out int required) &&
                   hitCount >= required;
        }

        private static bool ResolveYaraConditionToken(string token, IReadOnlyDictionary<string, bool> hits)
        {
            if (hits.TryGetValue(token, out bool value))
            {
                return value;
            }

            if (token.EndsWith("*", StringComparison.Ordinal))
            {
                return hits.Any(x => WildcardMatch(x.Key, token) && x.Value);
            }

            return false;
        }

        private static bool EvaluateSigmaCondition(string condition, IReadOnlyDictionary<string, bool> selections)
        {
            string expression = Regex.Replace(
                condition ?? string.Empty, @"\b(?<q>1|any|all|\d+)\s+of\s+(?<target>them|[A-Za-z0-9_*]+)",
                match => EvaluateSigmaQuantifier(match.Groups["q"].Value, match.Groups["target"].Value, selections)
                             ? "true"
                             : "false",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

            return EvaluateBooleanExpression(expression, token => ResolveSigmaConditionToken(token, selections), false);
        }

        private static bool EvaluateSigmaQuantifier(string quantity, string target,
                                                    IReadOnlyDictionary<string, bool> selections)
        {
            IEnumerable<string> names = target.Equals("them", StringComparison.OrdinalIgnoreCase)
                                            ? selections.Keys
                                            : selections.Keys.Where(x => WildcardMatch(x, target));
            List<string> materialized = names.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            int hitCount = materialized.Count(name => selections.TryGetValue(name, out bool hit) && hit);
            if (quantity.Equals("all", StringComparison.OrdinalIgnoreCase))
            {
                return materialized.Count != 0 && hitCount == materialized.Count;
            }
            if (quantity.Equals("any", StringComparison.OrdinalIgnoreCase) ||
                quantity.Equals("1", StringComparison.OrdinalIgnoreCase))
            {
                return hitCount > 0;
            }
            return int.TryParse(quantity, NumberStyles.Integer, CultureInfo.InvariantCulture, out int required) &&
                   hitCount >= required;
        }

        private static bool ResolveSigmaConditionToken(string token, IReadOnlyDictionary<string, bool> selections)
        {
            if (selections.TryGetValue(token, out bool value))
            {
                return value;
            }

            if (token.EndsWith("*", StringComparison.Ordinal))
            {
                return selections.Any(x => WildcardMatch(x.Key, token) && x.Value);
            }

            return false;
        }

        private static bool EvaluateBooleanExpression(string expression, Func<string, bool> resolveIdentifier,
                                                      bool fallback)
        {
            try
            {
                var parser = new BooleanExpressionParser(expression, resolveIdentifier);
                return parser.Parse();
            }
            catch
            {
                return fallback;
            }
        }

        private static bool WildcardMatch(string value, string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                return string.IsNullOrEmpty(value);
            }

            string regex = "^" +
                           Regex.Escape(pattern)
                               .Replace("\\*", ".*", StringComparison.Ordinal)
                               .Replace("\\?", ".", StringComparison.Ordinal) +
                           "$";
            return Regex.IsMatch(value ?? string.Empty, regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }

        private static bool TryParseFlexibleInteger(string text, out long value)
        {
            value = 0;
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            string trimmed = text.Trim();
            if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                return long.TryParse(trimmed[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
            }

            return long.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
        }

        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;
            _cts.Cancel();
            _signal.Set();
            try
            {
                _worker.Wait(1000);
            }
            catch
            {
            }
            _cts.Dispose();
            _signal.Dispose();
        }

        private sealed record WorkItem(string Key, bool IsFile, bool IsPage, string Path, byte[]? Sample,
                                       int SampleSize, uint ActorPid, uint TargetPid, string Source, string EventName,
                                       string Trigger);
        private sealed record MaterializedFinding(string Detection, uint Severity, string Reason, string Evidence)
        {
            public HeuristicEventView ToHeuristic(uint actorPid, uint targetPid, string source, string eventName,
                                                  string trigger) =>
                BuildHeuristic(Detection, Severity, actorPid, targetPid, source, eventName,
                               string.IsNullOrWhiteSpace(trigger) ? Reason : $"{Reason} | trigger={trigger}", Evidence);
        }
        private sealed record CacheEntry(long Length, DateTime LastWriteUtc,
                                         IReadOnlyList<MaterializedFinding> Findings)
        {
            public bool Matches(FileInfo info) => info.Length == Length && info.LastWriteTimeUtc == LastWriteUtc;
        }
        private sealed record Ruleset(IReadOnlyList<ManifestRule> ManifestRules, IReadOnlyList<YaraRule> YaraRules,
                                      IReadOnlyList<SigmaRule> SigmaRules);
        internal sealed record SignatureIntelRuleDocument(string DisplayName, string FullPath, string RelativePath,
                                                          string Kind, int RuleCount, bool IsUserRule);
        private sealed class ManifestDocument
        {
            [JsonPropertyName("rules")]
            public List<ManifestRule?>? Rules { get; init; }
        }
        private sealed class ManifestRule
        {
            [JsonPropertyName("id")]
            public string Id { get; init; } = string.Empty;
            [JsonPropertyName("title")]
            public string Title {
                get; init;
            } = string.Empty;
            [JsonPropertyName("description")]
            public string Description {
                get; init;
            } = string.Empty;
            [JsonPropertyName("severity")]
            public string Severity {
                get; init;
            } = string.Empty;
            [JsonPropertyName("detection")]
            public string Detection {
                get; init;
            } = string.Empty;
            [JsonPropertyName("mitre_technique_id")]
            public string MitreTechniqueId {
                get; init;
            } = string.Empty;
            [JsonPropertyName("mitre_technique")]
            public string MitreTechnique {
                get; init;
            } = string.Empty;
            [JsonPropertyName("sigma_rule_id")]
            public string SigmaRuleId {
                get; init;
            } = string.Empty;
            [JsonPropertyName("sha256")]
            public string Sha256 {
                get; init;
            } = string.Empty;
            [JsonPropertyName("sha1")]
            public string Sha1 {
                get; init;
            } = string.Empty;
            [JsonPropertyName("md5")]
            public string Md5 {
                get; init;
            } = string.Empty;
            [JsonPropertyName("file_name_contains")]
            public string FileNameContains {
                get; init;
            } = string.Empty;
            [JsonPropertyName("path_contains")]
            public string PathContains {
                get; init;
            } = string.Empty;
            [JsonPropertyName("signer_state")]
            public string SignerState {
                get; init;
            } = string.Empty;
            [JsonPropertyName("signer_contains")]
            public string SignerContains {
                get; init;
            } = string.Empty;
            [JsonPropertyName("contains_ascii")]
            public string ContainsAscii {
                get; init;
            } = string.Empty;
            [JsonPropertyName("contains_ascii_nocase")]
            public bool ContainsAsciiNoCase {
                get; init;
            }
        }
        private sealed record YaraRule(string Name, string Title, string Detection, string MitreId, string MitreName,
                                       string SigmaId, uint Severity, bool FileScope, bool MemoryScope, bool PageScope,
                                       string Condition, IReadOnlyList<YaraPattern> Patterns)
        {
            public bool IsMatch(ReadOnlySpan<byte> bytes)
            {
                var hits = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
                for (int i = 0; i < Patterns.Count; i += 1)
                {
                    YaraPattern pattern = Patterns[i];
                    bool matched = pattern.IsMatch(bytes);
                    hits[pattern.Identifier] =
                        hits.TryGetValue(pattern.Identifier, out bool existing) ? existing || matched : matched;
                }
                return EvaluateYaraCondition(Condition, hits);
            }
        }

        private sealed class YaraPattern
        {
            private readonly byte[]? _ascii;
            private readonly IReadOnlyList<HexElement>? _hex;
            private readonly bool _nocase;

            private YaraPattern(string identifier, byte[] ascii, bool nocase)
            {
                Identifier = "$" + identifier.TrimStart('$');
                _ascii = ascii;
                _nocase = nocase;
            }

            private YaraPattern(string identifier, IReadOnlyList<HexElement> hex)
            {
                Identifier = "$" + identifier.TrimStart('$');
                _hex = hex;
            }

            public string Identifier { get; }

            public static YaraPattern Ascii(string identifier, byte[] bytes,
                                            bool nocase) => new(identifier, NormalizeAsciiBytes(bytes, nocase), nocase);

            public static YaraPattern Wide(string identifier, byte[] bytes, bool nocase)
            {
                byte[] normalized = NormalizeAsciiBytes(bytes, nocase);
                var wide = new byte[normalized.Length * 2];
                for (int i = 0; i < normalized.Length; i += 1)
                {
                    wide[i * 2] = normalized[i];
                }

                return new YaraPattern(identifier, wide, nocase);
            }

            private static byte[] NormalizeAsciiBytes(byte[] bytes, bool nocase)
            {
                byte[] normalized = (bytes ?? Array.Empty<byte>()).ToArray();
                if (!nocase)
                {
                    return normalized;
                }

                for (int i = 0; i < normalized.Length; i += 1)
                {
                    if (normalized[i] < 0x80)
                    {
                        normalized[i] = (byte) char.ToUpperInvariant((char)normalized[i]);
                    }
                }

                return normalized;
            }

            public static YaraPattern? Hex(string identifier, string text)
            {
                var parser = new HexPatternParser(text);
                IReadOnlyList<HexElement>? elements = parser.Parse();
                return elements == null || elements.Count == 0 ? null : new YaraPattern(identifier, elements);
            }

            public bool IsMatch(ReadOnlySpan<byte> bytes)
            {
                if (_ascii != null)
                {
                    return MatchAscii(bytes);
                }

                return _hex != null && MatchHex(bytes);
            }

            private bool MatchAscii(ReadOnlySpan<byte> bytes)
            {
                if (_ascii == null || bytes.Length < _ascii.Length)
                {
                    return false;
                }

                for (int i = 0; i <= bytes.Length - _ascii.Length; i += 1)
                {
                    bool ok = true;
                    for (int j = 0; j < _ascii.Length; j += 1)
                    {
                        byte hay = bytes[i + j];
                        if (_nocase && hay < 0x80)
                        {
                            hay = (byte) char.ToUpperInvariant((char)hay);
                        }
                        if (hay != _ascii[j])
                        {
                            ok = false;
                            break;
                        }
                    }
                    if (ok)
                    {
                        return true;
                    }
                }

                return false;
            }

            private bool MatchHex(ReadOnlySpan<byte> bytes)
            {
                if (_hex == null)
                {
                    return false;
                }

                for (int i = 0; i < bytes.Length; i += 1)
                {
                    if (MatchHexSequence(bytes, _hex, 0, i))
                    {
                        return true;
                    }
                }

                return false;
            }

            private static bool MatchHexSequence(ReadOnlySpan<byte> bytes, IReadOnlyList<HexElement> elements,
                                                 int elementIndex, int offset)
            {
                if (elementIndex >= elements.Count)
                {
                    return true;
                }

                if (offset > bytes.Length)
                {
                    return false;
                }

                HexElement element = elements[elementIndex];
                if (element.Kind == HexElementKind.Byte)
                {
                    if (offset >= bytes.Length)
                    {
                        return false;
                    }
                    if ((bytes[offset] & element.Mask) != element.Value)
                    {
                        return false;
                    }
                    return MatchHexSequence(bytes, elements, elementIndex + 1, offset + 1);
                }

                if (element.Kind == HexElementKind.Jump)
                {
                    int maxSkip = Math.Min(element.MaxJump, bytes.Length - offset);
                    for (int skip = Math.Max(0, element.MinJump); skip <= maxSkip; skip += 1)
                    {
                        if (MatchHexSequence(bytes, elements, elementIndex + 1, offset + skip))
                        {
                            return true;
                        }
                    }
                    return false;
                }

                foreach (IReadOnlyList<HexElement> alternative in element.Alternatives)
                {
                    foreach (int end in MatchHexAlternativeEnds(bytes, alternative, 0, offset))
                    {
                        if (MatchHexSequence(bytes, elements, elementIndex + 1, end))
                        {
                            return true;
                        }
                    }
                }

                return false;
            }

            private static List<int> MatchHexAlternativeEnds(ReadOnlySpan<byte> bytes,
                                                             IReadOnlyList<HexElement> elements, int elementIndex,
                                                             int offset)
            {
                var results = new List<int>();
                if (elementIndex >= elements.Count)
                {
                    results.Add(offset);
                    return results;
                }

                HexElement element = elements[elementIndex];
                if (element.Kind == HexElementKind.Byte)
                {
                    if (offset < bytes.Length && (bytes[offset] & element.Mask) == element.Value)
                    {
                        foreach (int end in MatchHexAlternativeEnds(bytes, elements, elementIndex + 1, offset + 1))
                        {
                            results.Add(end);
                        }
                    }
                    return results;
                }

                if (element.Kind == HexElementKind.Jump)
                {
                    int maxSkip = Math.Min(element.MaxJump, bytes.Length - offset);
                    for (int skip = Math.Max(0, element.MinJump); skip <= maxSkip; skip += 1)
                    {
                        foreach (int end in MatchHexAlternativeEnds(bytes, elements, elementIndex + 1, offset + skip))
                        {
                            results.Add(end);
                        }
                    }
                    return results;
                }

                foreach (IReadOnlyList<HexElement> alternative in element.Alternatives)
                {
                    foreach (int altEnd in MatchHexAlternativeEnds(bytes, alternative, 0, offset))
                    {
                        foreach (int end in MatchHexAlternativeEnds(bytes, elements, elementIndex + 1, altEnd))
                        {
                            results.Add(end);
                        }
                    }
                }

                return results;
            }
        }

        private enum HexElementKind
        {
            Byte,
            Jump,
            Alternative
        }

        private sealed record HexElement(HexElementKind Kind, byte Value, byte Mask, int MinJump, int MaxJump,
                                         IReadOnlyList<IReadOnlyList<HexElement>> Alternatives)
        {
            public static HexElement Byte(byte value, byte mask) =>
                new(HexElementKind.Byte, value, mask, 0, 0, Array.Empty<IReadOnlyList<HexElement>>());
            public static HexElement Jump(int min, int max) =>
                new(HexElementKind.Jump, 0, 0, min, max, Array.Empty<IReadOnlyList<HexElement>>());
            public static HexElement Alternative(IReadOnlyList<IReadOnlyList<HexElement>> alternatives) =>
                new(HexElementKind.Alternative, 0, 0, 0, 0, alternatives);
        }

        private sealed class HexPatternParser
        {
            private const int OpenEndedJumpCap = 512;
            private readonly string _text;
            private int _index;

            public HexPatternParser(string text) => _text = text ?? string.Empty;

            public IReadOnlyList<HexElement>? Parse()
            {
                List<HexElement>? elements = ParseSequence(stopAtPipeOrParen: false);
                return elements;
            }

            private List<HexElement>? ParseSequence(bool stopAtPipeOrParen)
            {
                var elements = new List<HexElement>();
                while (_index < _text.Length)
                {
                    SkipSpace();
                    if (_index >= _text.Length)
                    {
                        break;
                    }

                    char c = _text[_index];
                    if (stopAtPipeOrParen && (c == '|' || c == ')'))
                    {
                        break;
                    }

                    if (c == '[')
                    {
                        HexElement? jump = ParseJump();
                        if (jump == null)
                        {
                            return null;
                        }
                        elements.Add(jump);
                        continue;
                    }

                    if (c == '(')
                    {
                        HexElement? alternative = ParseAlternative();
                        if (alternative == null)
                        {
                            return null;
                        }
                        elements.Add(alternative);
                        continue;
                    }

                    HexElement? b = ParseByte();
                    if (b == null)
                    {
                        return null;
                    }
                    elements.Add(b);
                }

                return elements;
            }

            private HexElement? ParseJump()
            {
                int close = _text.IndexOf(']', _index + 1);
                if (close < 0)
                {
                    return null;
                }

                string token = _text.Substring(_index + 1, close - _index - 1).Trim();
                _index = close + 1;
                if (token.Length == 0 || token == "-")
                {
                    return HexElement.Jump(0, OpenEndedJumpCap);
                }

                string[] parts = token.Split('-', 2, StringSplitOptions.TrimEntries);
                if (parts.Length == 1)
                {
                    return int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out int exact)
                               ? HexElement.Jump(Math.Max(0, exact), Math.Max(0, exact))
                               : null;
                }

                int min =
                    string.IsNullOrWhiteSpace(parts[0]) ? 0
                    : int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsedMin)
                        ? parsedMin
                        : -1;
                int max =
                    string.IsNullOrWhiteSpace(parts[1]) ? OpenEndedJumpCap
                    : int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsedMax)
                        ? parsedMax
                        : -1;
                if (min < 0 || max < min)
                {
                    return null;
                }

                return HexElement.Jump(min, Math.Min(max, OpenEndedJumpCap));
            }

            private HexElement? ParseAlternative()
            {
                _index += 1;
                var alternatives = new List<IReadOnlyList<HexElement>>();
                while (_index < _text.Length)
                {
                    List<HexElement>? sequence = ParseSequence(stopAtPipeOrParen: true);
                    if (sequence == null)
                    {
                        return null;
                    }
                    alternatives.Add(sequence);
                    SkipSpace();
                    if (_index >= _text.Length)
                    {
                        return null;
                    }
                    if (_text[_index] == '|')
                    {
                        _index += 1;
                        continue;
                    }
                    if (_text[_index] == ')')
                    {
                        _index += 1;
                        return alternatives.Count == 0 ? null : HexElement.Alternative(alternatives);
                    }
                    return null;
                }

                return null;
            }

            private HexElement? ParseByte()
            {
                SkipSpace();
                if (_index >= _text.Length)
                {
                    return null;
                }

                int start = _index;
                while (_index < _text.Length && (Uri.IsHexDigit(_text[_index]) || _text[_index] == '?'))
                {
                    _index += 1;
                }

                string token = _text[start.._index];
                if (token.Length is not 1 and not 2)
                {
                    return null;
                }
                if (token.Length == 1)
                {
                    token += "?";
                }

                byte value = 0;
                byte mask = 0;
                for (int i = 0; i < 2; i += 1)
                {
                    char c = token[i];
                    if (c == '?')
                    {
                        continue;
                    }
                    if (!byte.TryParse(c.ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture,
                                       out byte nibble))
                    {
                        return null;
                    }
                    int shift = i == 0 ? 4 : 0;
                    value |= (byte)(nibble << shift);
                    mask |= (byte)(0xFu << shift);
                }

                return HexElement.Byte(value, mask);
            }

            private void SkipSpace()
            {
                while (_index < _text.Length && char.IsWhiteSpace(_text[_index]))
                {
                    _index += 1;
                }
            }
        }

        private sealed record SigmaRule(string Id, string Title, string Description, string Level, uint Severity,
                                        string MitreTechniqueId, string Condition, SigmaLogsource Logsource,
                                        IReadOnlyList<string> Tags,
                                        IReadOnlyDictionary<string, SigmaSelection> Selections)
        {
            public bool IsMatch(SignatureEventContext context, out string matchSummary)
            {
                matchSummary = string.Empty;
                if (!Logsource.Matches(context))
                {
                    return false;
                }

                var results = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
                var matched = new List<string>();
                foreach (KeyValuePair<string, SigmaSelection> selection in Selections)
                {
                    if (selection.Value.IsMatch(context, out string details))
                    {
                        results[selection.Key] = true;
                        matched.Add($"{selection.Key}:{details}");
                    }
                    else
                    {
                        results[selection.Key] = false;
                    }
                }

                bool condition = EvaluateSigmaCondition(Condition, results);
                matchSummary = matched.Count == 0 ? "none" : string.Join(",", matched);
                return condition;
            }
        }

        private sealed record SigmaLogsource(string Product, string Category, string Service)
        {
            public bool Matches(SignatureEventContext context)
            {
                if (!string.IsNullOrWhiteSpace(Product) &&
                    !Product.Equals("windows", StringComparison.OrdinalIgnoreCase) &&
                    !Product.Equals("BK", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                if (!string.IsNullOrWhiteSpace(Category) && !context.Categories.Contains(Category.Trim()))
                {
                    return false;
                }

                if (string.IsNullOrWhiteSpace(Service))
                {
                    return true;
                }

                string service = Service.Trim();
                return service.Equals("sysmon", StringComparison.OrdinalIgnoreCase) ||
                       service.Equals("security", StringComparison.OrdinalIgnoreCase) ||
                       service.Equals("BK", StringComparison.OrdinalIgnoreCase) ||
                       service.Equals(context.Service, StringComparison.OrdinalIgnoreCase) ||
                       service.Equals(context.Source, StringComparison.OrdinalIgnoreCase);
            }
        }

        private sealed record SigmaSelection(IReadOnlyList<SigmaSelectionBranch> Branches)
        {
            public bool IsMatch(SignatureEventContext context, out string details)
            {
                foreach (SigmaSelectionBranch branch in Branches)
                {
                    if (branch.IsMatch(context, out details))
                    {
                        return true;
                    }
                }

                details = string.Empty;
                return false;
            }
        }

        private sealed record SigmaSelectionBranch(IReadOnlyList<SigmaFieldCondition> Conditions)
        {
            public bool IsMatch(SignatureEventContext context, out string details)
            {
                var matched = new List<string>();
                foreach (SigmaFieldCondition condition in Conditions)
                {
                    if (!condition.IsMatch(context, out string fieldMatch))
                    {
                        details = string.Empty;
                        return false;
                    }
                    matched.Add(fieldMatch);
                }

                details = string.Join("+", matched);
                return true;
            }
        }

        private sealed record SigmaFieldCondition(string Field, IReadOnlyList<string> Modifiers,
                                                  IReadOnlyList<string> Values, bool RequireAllValues)
        {
            public bool IsMatch(SignatureEventContext context, out string matchSummary)
            {
                IReadOnlyList<string> actualValues =
                    Field == "*" ? new[] { context.AggregateText } : context.GetValues(Field);
                bool exists = actualValues.Any(x => !string.IsNullOrWhiteSpace(x));
                if (Modifiers.Any(x => x.Equals("exists", StringComparison.OrdinalIgnoreCase)))
                {
                    bool expected = Values.Count == 0 || !Values[0].Equals("false", StringComparison.OrdinalIgnoreCase);
                    matchSummary = $"{Field}:exists={exists}";
                    return exists == expected;
                }

                if (!exists)
                {
                    matchSummary = $"{Field}:missing";
                    return false;
                }

                if (Values.Count == 0)
                {
                    matchSummary = $"{Field}:present";
                    return true;
                }

                if (RequireAllValues)
                {
                    bool all = Values.All(expected => actualValues.Any(actual => MatchesValue(actual, expected)));
                    matchSummary = all ? $"{Field}:all" : $"{Field}:partial";
                    return all;
                }

                foreach (string expected in Values)
                {
                    foreach (string actual in actualValues)
                    {
                        if (MatchesValue(actual, expected))
                        {
                            matchSummary = $"{Field}:{expected}";
                            return true;
                        }
                    }
                }

                matchSummary = $"{Field}:no-match";
                return false;
            }

            private bool MatchesValue(string actual, string expected)
            {
                string mode =
                    Modifiers.FirstOrDefault(x => x.Equals("contains", StringComparison.OrdinalIgnoreCase) ||
                                                  x.Equals("startswith", StringComparison.OrdinalIgnoreCase) ||
                                                  x.Equals("endswith", StringComparison.OrdinalIgnoreCase) ||
                                                  x.Equals("re", StringComparison.OrdinalIgnoreCase) ||
                                                  x.Equals("gt", StringComparison.OrdinalIgnoreCase) ||
                                                  x.Equals("gte", StringComparison.OrdinalIgnoreCase) ||
                                                  x.Equals("lt", StringComparison.OrdinalIgnoreCase) ||
                                                  x.Equals("lte", StringComparison.OrdinalIgnoreCase)) ??
                    string.Empty;
                mode = mode.ToLowerInvariant();

                if (mode.Equals("re", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        return Regex.IsMatch(actual ?? string.Empty, expected ?? string.Empty,
                                             RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                    }
                    catch
                    {
                        return false;
                    }
                }

                if (mode is "gt" or "gte" or "lt" or "lte")
                {
                    if (!TryParseFlexibleInteger(actual, out long actualNumber) ||
                        !TryParseFlexibleInteger(expected, out long expectedNumber))
                    {
                        return false;
                    }

                    return mode switch { "gt" => actualNumber > expectedNumber, "gte" => actualNumber >= expectedNumber,
                                         "lt" => actualNumber < expectedNumber, "lte" => actualNumber <= expectedNumber,
                                         _ => false };
                }

                if (mode.Equals("contains", StringComparison.OrdinalIgnoreCase))
                {
                    return (actual ?? string.Empty)
                               .IndexOf(expected ?? string.Empty, StringComparison.OrdinalIgnoreCase) >= 0;
                }

                if (mode.Equals("startswith", StringComparison.OrdinalIgnoreCase))
                {
                    return (actual ?? string.Empty)
                        .StartsWith(expected ?? string.Empty, StringComparison.OrdinalIgnoreCase);
                }

                if (mode.Equals("endswith", StringComparison.OrdinalIgnoreCase))
                {
                    return (actual ?? string.Empty)
                        .EndsWith(expected ?? string.Empty, StringComparison.OrdinalIgnoreCase);
                }

                if ((expected ?? string.Empty).IndexOfAny(new[] { '*', '?' }) >= 0)
                {
                    return WildcardMatch(actual ?? string.Empty, expected ?? string.Empty);
                }

                return string.Equals(actual ?? string.Empty, expected ?? string.Empty,
                                     StringComparison.OrdinalIgnoreCase);
            }
        }

        private sealed class SignatureEventContext
        {
            private readonly Dictionary<string, List<string>> _fields = new(StringComparer.OrdinalIgnoreCase);

            private SignatureEventContext(string source, string eventName, string service, uint actorPid,
                                          uint targetPid)
            {
                Source = source;
                EventName = eventName;
                Service = service;
                ActorPid = actorPid;
                TargetPid = targetPid;
            }

            public string Source { get; }
            public string EventName { get; }
            public string Service { get; }
            public uint ActorPid { get; }
            public uint TargetPid { get; }
            public uint CorrelationFlags { get; private set; }
            public uint CorrelationAccessMask { get; private set; }
            public uint CorrelationAgeMs { get; private set; }
            public HashSet<string> Categories { get; } = new(StringComparer.OrdinalIgnoreCase);
            public string AggregateText =>
                string.Join(" ", _fields.Values.SelectMany(x => x).Where(x => !string.IsNullOrWhiteSpace(x)));

            public static SignatureEventContext FromEtw(BrokerEtwEventView view)
            {
                var context =
                    new SignatureEventContext(view.Source, view.EventName, "BK", view.ActorPid, view.TargetPid);
                context.CorrelationFlags = view.CorrelationFlags;
                context.CorrelationAccessMask = view.CorrelationAccessMask;
                context.CorrelationAgeMs = view.CorrelationAgeMs;
                context.AddCommonFields(view.Source, view.EventName, view.EventId, view.ActorPid, view.TargetPid,
                                        view.ProcessPid, view.ThreadId, view.CommandLine, view.ImagePath,
                                        view.OriginPath, view.Reason, view.DetectionName, view.Operation);
                context.Add("Task", view.Task);
                context.Add("Opcode", view.Opcode);
                context.Add("Flags", $"0x{view.Flags:X8}");
                context.Add("DetectionTraits", $"0x{view.DetectionTraits:X8}");
                context.Add("ParentProcessId", view.ParentPid);
                context.Add("CreatorProcessId", view.CreatorPid);
                context.Add("CallerProcessId", view.CallerPid);
                context.Add("DesiredAccess", $"0x{view.DesiredAccess:X8}");
                context.Add("GrantedAccess", $"0x{view.DesiredAccess:X8}");
                context.Add(
                    "CallTrace",
                    string.Join(";", (view.Stack ?? Array.Empty<ulong>()).Where(x => x != 0).Select(x => $"0x{x:X}")));
                context.Add("StartAddress", view.StartAddress == 0 ? string.Empty : $"0x{view.StartAddress:X}");
                context.Add("ImageLoaded", view.ImagePath);
                context.Add("TargetObject", CombinePath(view.KeyPath, view.ValueName));
                context.Add("RegistryKey", view.KeyPath);
                context.Add("RegistryValue", view.ValueName);
                context.Add("Details", view.Details);
                context.AddEtwCategories(view);
                return context;
            }

            public static SignatureEventContext FromIoctl(IoctlParsedEvent record)
            {
                string eventName =
                    record.Type switch { var t when t == BlackbirdNative.EventTypeHandle => "ProcessAccess",
                                         var t when t == BlackbirdNative.EventTypeThread => "CreateRemoteThread",
                                         var t when t == BlackbirdNative.EventTypeFileSystem => "FileEvent",
                                         var t when t == BlackbirdNative.EventTypeRegistry => "RegistryEvent",
                                         var t when t == BlackbirdNative.EventTypeEnterprise => "EnterpriseEvent",
                                         _ => "IoctlEvent" };
                uint actor =
                    record.Type switch { var t when t == BlackbirdNative.EventTypeFileSystem => record.FileProcessPid,
                                         var t when t == BlackbirdNative.EventTypeRegistry => record.RegistryProcessPid,
                                         var t when t == BlackbirdNative.EventTypeEnterprise =>
                                             record.EnterpriseProcessPid,
                                         var t when t == BlackbirdNative.EventTypeThread => record.CreatorPid,
                                         _ => record.CallerPid };
                uint target = record.Type == BlackbirdNative.EventTypeThread ? record.ProcessPid
                              : record.Type == BlackbirdNative.EventTypeEnterprise
                                  ? record.EnterpriseTargetProcessPid
                                  : record.TargetPid;
                var context = new SignatureEventContext("Kernel-IOCTL", eventName, "BK", actor, target);
                context.AddCommonFields("Kernel-IOCTL", eventName, record.Type, actor, target, record.ProcessPid,
                                        record.ThreadId, string.Empty, string.Empty, record.OriginPath, string.Empty,
                                        string.Empty, eventName);
                context.Add("DesiredAccess", $"0x{record.DesiredAccess:X8}");
                context.Add("GrantedAccess", $"0x{record.DesiredAccess:X8}");
                context.Add("SourceImage", record.OriginPath);
                context.Add("Image", record.OriginPath);
                context.Add(
                    "CallTrace",
                    string.Join(";",
                                (record.Frames ?? Array.Empty<ulong>()).Where(x => x != 0).Select(x => $"0x{x:X}")));
                context.Add("StartAddress", record.StartAddress == 0 ? string.Empty : $"0x{record.StartAddress:X}");
                context.Add("TargetFilename", record.FilePath);
                context.Add("FilePath", record.FilePath);
                context.Add("FileName", record.FilePath);
                context.Add("TargetObject", CombinePath(record.RegistryKeyPath, record.RegistryValueName));
                context.Add("RegistryKey", record.RegistryKeyPath);
                context.Add("RegistryValue", record.RegistryValueName);
                context.Add("FileOperation", $"0x{record.FileOperation:X}");
                context.Add("RegistryOperation", record.RegistryOperation);
                context.Add("EnterpriseOperation", record.EnterpriseOperation);
                context.Add("EnterpriseFlags", $"0x{record.EnterpriseFlags:X8}");
                context.AddIoctlCategories(record);
                return context;
            }

            public IReadOnlyList<string> GetValues(string field)
            {
                if (_fields.TryGetValue(field, out List<string>? values))
                {
                    return values;
                }

                return Array.Empty<string>();
            }

            private void AddCommonFields(string source, string eventName, uint eventId, uint actorPid, uint targetPid,
                                         uint processPid, uint threadId, string commandLine, string imagePath,
                                         string originPath, string reason, string detectionName, string operation)
            {
                Add("Product", "windows");
                Add("Provider_Name", source);
                Add("Source", source);
                Add("Channel", source);
                Add("EventID", eventId);
                Add("EventId", eventId);
                Add("EventName", eventName);
                Add("Operation", operation);
                Add("Image", imagePath);
                Add("ImagePath", imagePath);
                Add("ProcessPath", imagePath);
                Add("SourceImage", originPath);
                Add("OriginImage", originPath);
                Add("CommandLine", commandLine);
                Add("ProcessCommandLine", commandLine);
                Add("ProcessId", processPid == 0 ? actorPid : processPid);
                Add("SourceProcessId", actorPid);
                Add("TargetProcessId", targetPid);
                Add("ActorProcessId", actorPid);
                Add("ThreadId", threadId);
                Add("DetectionName", detectionName);
                Add("RuleName", detectionName);
                Add("Reason", reason);
            }

            private void AddEtwCategories(BrokerEtwEventView view)
            {
                Add("Family", view.Family);
                if (view.Family == BlackbirdNative.IpcEtwFamilyProcess &&
                    (view.Flags & BlackbirdNative.IpcEtwFlagProcessIsCreate) != 0)
                {
                    Categories.Add("process_creation");
                }
                else if (view.Family == BlackbirdNative.IpcEtwFamilyProcess ||
                         view.EventName.Contains("terminate", StringComparison.OrdinalIgnoreCase) ||
                         view.EventName.Contains("exit", StringComparison.OrdinalIgnoreCase))
                {
                    Categories.Add("process_termination");
                }
                if (view.Family == BlackbirdNative.IpcEtwFamilyImage || !string.IsNullOrWhiteSpace(view.ImagePath))
                {
                    Categories.Add("image_load");
                }
                if (view.Family == BlackbirdNative.IpcEtwFamilyRegistry || !string.IsNullOrWhiteSpace(view.KeyPath))
                {
                    Categories.Add("registry_event");
                    if (view.Operation.Contains("set", StringComparison.OrdinalIgnoreCase) ||
                        view.Operation.Contains("create", StringComparison.OrdinalIgnoreCase) ||
                        view.Operation.Contains("delete", StringComparison.OrdinalIgnoreCase))
                    {
                        Categories.Add("registry_set");
                    }
                }
                if (view.Family == BlackbirdNative.IpcEtwFamilySocket)
                {
                    Categories.Add("network_connection");
                }
                if ((view.Family == BlackbirdNative.IpcEtwFamilyThread &&
                     (view.Flags & BlackbirdNative.IpcEtwFlagThreadRemoteCreator) != 0) ||
                    view.Family == BlackbirdNative.IpcEtwFamilyApc)
                {
                    Categories.Add("create_remote_thread");
                }
                if (view.Family == BlackbirdNative.IpcEtwFamilyHandle ||
                    view.EventName.Contains("handle", StringComparison.OrdinalIgnoreCase))
                {
                    Categories.Add("process_access");
                }
                if (view.Family == BlackbirdNative.IpcEtwFamilyUserHook)
                {
                    Categories.Add("api_call");
                }
            }

            private void AddIoctlCategories(IoctlParsedEvent record)
            {
                if (record.Type == BlackbirdNative.EventTypeHandle)
                {
                    Categories.Add("process_access");
                }
                else if (record.Type == BlackbirdNative.EventTypeThread)
                {
                    if (record.CreatorPid != 0 && record.ProcessPid != 0 && record.CreatorPid != record.ProcessPid)
                    {
                        Categories.Add("create_remote_thread");
                    }
                }
                else if (record.Type == BlackbirdNative.EventTypeFileSystem)
                {
                    Categories.Add("file_event");
                    Categories.Add("file_create");
                    Categories.Add("file_delete");
                    Categories.Add("file_change");
                }
                else if (record.Type == BlackbirdNative.EventTypeRegistry)
                {
                    Categories.Add("registry_event");
                    if (record.RegistryOperation is BlackbirdNative.RegistryOperationSetValue or
                            BlackbirdNative.RegistryOperationCreateKey or BlackbirdNative
                                .RegistryOperationDeleteValue or BlackbirdNative.RegistryOperationDeleteKey)
                    {
                        Categories.Add("registry_set");
                    }
                }
                else if (record.Type == BlackbirdNative.EventTypeEnterprise)
                {
                    Categories.Add("enterprise_activity");
                    if ((record.EnterpriseFlags & (BlackbirdNative.EnterpriseFlagCredentialProcess |
                                                   BlackbirdNative.EnterpriseFlagCredentialFile |
                                                   BlackbirdNative.EnterpriseFlagSecurityHive |
                                                   BlackbirdNative.EnterpriseFlagKerberosNtlm)) != 0)
                    {
                        Categories.Add("credential_access");
                    }
                    if ((record.EnterpriseFlags & BlackbirdNative.EnterpriseFlagDriverArtifact) != 0)
                    {
                        Categories.Add("driver_load");
                    }
                    if ((record.EnterpriseFlags & BlackbirdNative.EnterpriseFlagAdNetwork) != 0)
                    {
                        Categories.Add("network_connection");
                    }
                    if ((record.EnterpriseFlags & BlackbirdNative.EnterpriseFlagWrite) != 0)
                    {
                        Categories.Add("registry_set");
                        Categories.Add("file_change");
                    }
                    if (record.EnterpriseTargetProcessPid != 0)
                    {
                        Categories.Add("process_access");
                    }
                }
            }

            private void Add(string key, uint value)
            {
                if (value != 0)
                {
                    Add(key, value.ToString(CultureInfo.InvariantCulture));
                }
            }

            private void Add(string key, ushort value)
            {
                if (value != 0)
                {
                    Add(key, value.ToString(CultureInfo.InvariantCulture));
                }
            }

            private void Add(string key, string? value)
            {
                if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value))
                {
                    return;
                }

                if (!_fields.TryGetValue(key, out List<string>? values))
                {
                    values = new List<string>();
                    _fields[key] = values;
                }

                string trimmed = value.Trim();
                if (!values.Any(existing => existing.Equals(trimmed, StringComparison.OrdinalIgnoreCase)))
                {
                    values.Add(trimmed);
                }
            }

            private static string CombinePath(string? left, string? right)
            {
                if (string.IsNullOrWhiteSpace(left))
                {
                    return right ?? string.Empty;
                }
                if (string.IsNullOrWhiteSpace(right))
                {
                    return left;
                }
                return left.TrimEnd('\\') + "\\" + right.TrimStart('\\');
            }
        }

        private sealed class BooleanExpressionParser
        {
            private readonly List<string> _tokens;
            private readonly Func<string, bool> _resolveIdentifier;
            private int _index;

            public BooleanExpressionParser(string expression, Func<string, bool> resolveIdentifier)
            {
                _tokens = Tokenize(expression ?? string.Empty);
                _resolveIdentifier = resolveIdentifier;
            }

            public bool Parse()
            {
                if (_tokens.Count == 0)
                {
                    return false;
                }

                bool value = ParseOr();
                if (_index != _tokens.Count)
                {
                    throw new FormatException("Unexpected trailing tokens in boolean expression.");
                }

                return value;
            }

            private bool ParseOr()
            {
                bool value = ParseAnd();
                while (Match("or"))
                {
                    value = ParseAnd() || value;
                }
                return value;
            }

            private bool ParseAnd()
            {
                bool value = ParseUnary();
                while (Match("and"))
                {
                    value = ParseUnary() && value;
                }
                return value;
            }

            private bool ParseUnary()
            {
                if (Match("not"))
                {
                    return !ParseUnary();
                }

                return ParsePrimary();
            }

            private bool ParsePrimary()
            {
                if (Match("("))
                {
                    bool value = ParseOr();
                    _ = Match(")");
                    return value;
                }

                if (_index >= _tokens.Count)
                {
                    return false;
                }

                string token = _tokens[_index++];
                if (token.Equals("true", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
                if (token.Equals("false", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
                return _resolveIdentifier(token);
            }

            private bool Match(string token)
            {
                if (_index < _tokens.Count && _tokens[_index].Equals(token, StringComparison.OrdinalIgnoreCase))
                {
                    _index += 1;
                    return true;
                }

                return false;
            }

            private static List<string> Tokenize(string expression)
            {
                var tokens = new List<string>();
                int index = 0;
                while (index < expression.Length)
                {
                    char c = expression[index];
                    if (char.IsWhiteSpace(c))
                    {
                        index += 1;
                        continue;
                    }
                    if (c is '(' or ')')
                    {
                        tokens.Add(c.ToString());
                        index += 1;
                        continue;
                    }

                    int start = index;
                    while (index < expression.Length && !char.IsWhiteSpace(expression[index]) &&
                           expression[index] is not '(' and not ')' and not ',')
                    {
                        index += 1;
                    }

                    if (index > start)
                    {
                        tokens.Add(expression[start..index].Trim());
                    }
                    else
                    {
                        index += 1;
                    }
                }

                return tokens;
            }
        }

        private sealed record YamlLine(int Indent, string Content);
        private abstract record YamlNode;
        private sealed record YamlScalar(string Value) : YamlNode;
        private sealed record YamlList(IReadOnlyList<YamlNode> Items) : YamlNode;
        private sealed record YamlMap(Dictionary<string, YamlNode> Values) : YamlNode;
    }
}
