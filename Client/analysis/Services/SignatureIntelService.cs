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
        private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true, AllowTrailingCommas = true, ReadCommentHandling = JsonCommentHandling.Skip };

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
            _log?.Invoke($"signature intel: enabled={options.Enabled} hash={options.HashScan} mem={options.MemoryScan} page={options.PageScan}");
        }

        internal void QueueFileScan(string? path, uint actorPid, uint targetPid, string source, string eventName, string trigger)
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

            _queue.Enqueue(new WorkItem(key, true, false, fullPath, null, 0, actorPid, targetPid, source, eventName, trigger));
            _signal.Set();
        }

        internal void QueueSampleScan(byte[]? sample, int sampleSize, bool pageSample, string? originPath, uint actorPid, uint targetPid, string source, string eventName, string trigger)
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

            _queue.Enqueue(new WorkItem(key, false, pageSample, NormalizePath(originPath), copy, size, actorPid, targetPid, source, eventName, trigger));
            _signal.Set();
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

                return entry.Findings.Select(x => x.ToHeuristic(work.ActorPid, work.TargetPid, work.Source, work.EventName, work.Trigger)).ToList();
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
                        string.IsNullOrWhiteSpace(rule.Detection) ? "YARA_SAMPLE_MATCH" : rule.Detection,
                        rule.Severity,
                        work.ActorPid,
                        work.TargetPid,
                        work.Source,
                        work.EventName,
                        BuildRuleReason(rule.Title, work.Trigger, rule.MitreId, rule.MitreName, rule.SigmaId),
                        $"scope={(work.IsPage ? "page" : "memory")} origin={Fallback(work.Path)} rule={rule.Name} sample={EventDetailFormatting.FormatSampleHex(work.Sample, work.SampleSize)}"));
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
                    using FileStream stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
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

            bool needContent = info.Length > 0 && info.Length <= MaxFileBytes && (rules.YaraRules.Any(x => x.FileScope) || rules.ManifestRules.Any(x => !string.IsNullOrWhiteSpace(x.ContainsAscii)));
            if (needContent)
            {
                try { content = File.ReadAllBytes(path); } catch { }
            }

            var findings = new List<MaterializedFinding>();
            if (signature is SignatureTrustState.Unsigned or SignatureTrustState.Invalid or SignatureTrustState.Expired)
            {
                findings.Add(new MaterializedFinding(signature == SignatureTrustState.Invalid ? "FILE_SIGNATURE_TRUST_FAILURE" : "FILE_UNSIGNED_EXECUTABLE", signature == SignatureTrustState.Invalid ? 7u : 5u, $"signature={signature}", $"path={path} signer={Fallback(signer)} sha256={Fallback(sha256)}"));
            }

            foreach (ManifestRule rule in rules.ManifestRules)
            {
                if (!RuleMatches(rule, path, info.Name, signature, signer, sha256, sha1, md5, content))
                {
                    continue;
                }
                findings.Add(new MaterializedFinding(string.IsNullOrWhiteSpace(rule.Detection) ? "SIGNATURE_RULE_MATCH" : rule.Detection, ParseSeverity(rule.Severity, 5), BuildRuleReason(rule.Title, rule.Description, rule.MitreTechniqueId, rule.MitreTechnique, rule.SigmaRuleId), $"path={path} sha256={Fallback(sha256)} signer={Fallback(signer)} rule={Fallback(rule.Id)}"));
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
                    findings.Add(new MaterializedFinding(string.IsNullOrWhiteSpace(rule.Detection) ? "YARA_FILE_MATCH" : rule.Detection, rule.Severity, BuildRuleReason(rule.Title, "file-content", rule.MitreId, rule.MitreName, rule.SigmaId), $"path={path} rule={rule.Name}"));
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

                string root = Path.Combine(AppContext.BaseDirectory, "Rules", "SignatureIntel");
                var manifestRules = new List<ManifestRule>();
                var yaraRules = new List<YaraRule>();

                if (Directory.Exists(root))
                {
                    foreach (string path in Directory.EnumerateFiles(root, "*.json", SearchOption.AllDirectories))
                    {
                        try
                        {
                            ManifestDocument? doc = JsonSerializer.Deserialize<ManifestDocument>(File.ReadAllText(path, Encoding.UTF8), JsonOptions);
                            if (doc?.Rules != null)
                            {
                                manifestRules.AddRange(doc.Rules.Where(x => x != null).Select(x => x!));
                            }
                        }
                        catch (Exception ex)
                        {
                            _log?.Invoke($"signature intel manifest load failed: {Path.GetFileName(path)} {ex.Message}");
                        }
                    }

                    foreach (string path in Directory.EnumerateFiles(root, "*.yar", SearchOption.AllDirectories).Concat(Directory.EnumerateFiles(root, "*.yara", SearchOption.AllDirectories)))
                    {
                        try { yaraRules.AddRange(ParseYara(File.ReadAllText(path, Encoding.UTF8))); } catch (Exception ex) { _log?.Invoke($"signature intel yara load failed: {Path.GetFileName(path)} {ex.Message}"); }
                    }
                }

                _rules = new Ruleset(manifestRules, yaraRules);
                _log?.Invoke($"signature intel rules loaded: manifest={manifestRules.Count} yara={yaraRules.Count}");
                return _rules;
            }
        }

        private static IEnumerable<YaraRule> ParseYara(string text)
        {
            foreach (Match match in Regex.Matches(text, @"rule\s+([A-Za-z0-9_]+)\s*\{(.*?)\}", RegexOptions.Singleline))
            {
                string name = match.Groups[1].Value.Trim();
                string body = match.Groups[2].Value;
                string meta = ExtractBlock(body, "meta:");
                string strings = ExtractBlock(body, "strings:");
                string condition = ExtractBlock(body, "condition:");
                if (strings.Length == 0)
                {
                    continue;
                }

                var patterns = new List<YaraPattern>();
                foreach (string raw in strings.Split('\n'))
                {
                    string line = raw.Trim();
                    Match ascii = Regex.Match(line, "^\\$[A-Za-z0-9_]+\\s*=\\s*\"([^\"]*)\"(.*)$");
                    if (ascii.Success)
                    {
                        patterns.Add(YaraPattern.Ascii(Regex.Unescape(ascii.Groups[1].Value), ascii.Groups[2].Value.Contains("nocase", StringComparison.OrdinalIgnoreCase)));
                        continue;
                    }

                    Match hex = Regex.Match(line, "^\\$[A-Za-z0-9_]+\\s*=\\s*\\{([^}]*)\\}");
                    if (hex.Success)
                    {
                        YaraPattern? p = YaraPattern.Hex(hex.Groups[1].Value);
                        if (p != null)
                        {
                            patterns.Add(p);
                        }
                    }
                }

                if (patterns.Count == 0)
                {
                    continue;
                }

                Dictionary<string, string> metaMap = ParseMeta(meta);
                string scope = metaMap.TryGetValue("scope", out string? scopeValue) ? scopeValue : "file,memory,page";
                yield return new YaraRule(
                    name,
                    metaMap.TryGetValue("title", out string? title) ? title : name,
                    metaMap.TryGetValue("detection", out string? detection) ? detection : name.ToUpperInvariant(),
                    metaMap.TryGetValue("mitre_technique_id", out string? mitreId) ? mitreId : string.Empty,
                    metaMap.TryGetValue("mitre_technique", out string? mitreName) ? mitreName : string.Empty,
                    metaMap.TryGetValue("sigma_rule_id", out string? sigmaId) ? sigmaId : string.Empty,
                    ParseSeverity(metaMap.TryGetValue("severity", out string? sev) ? sev : null, 6),
                    scope.Contains("file", StringComparison.OrdinalIgnoreCase),
                    scope.Contains("memory", StringComparison.OrdinalIgnoreCase),
                    scope.Contains("page", StringComparison.OrdinalIgnoreCase),
                    condition.Contains("all of them", StringComparison.OrdinalIgnoreCase) || condition.Contains(" and ", StringComparison.OrdinalIgnoreCase),
                    patterns);
            }
        }

        private static string ExtractBlock(string body, string marker)
        {
            int start = body.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (start < 0) return string.Empty;
            start += marker.Length;
            int end = body.Length;
            foreach (string next in new[] { "meta:", "strings:", "condition:" })
            {
                if (next.Equals(marker, StringComparison.OrdinalIgnoreCase)) continue;
                int pos = body.IndexOf(next, start, StringComparison.OrdinalIgnoreCase);
                if (pos >= 0 && pos < end) end = pos;
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
                if (eq <= 0) continue;
                map[line[..eq].Trim()] = line[(eq + 1)..].Trim().Trim('"');
            }
            return map;
        }

        private static bool RuleMatches(ManifestRule rule, string path, string fileName, SignatureTrustState signature, string signer, string sha256, string sha1, string md5, byte[]? content)
        {
            if (!string.IsNullOrWhiteSpace(rule.FileNameContains) && fileName.IndexOf(rule.FileNameContains, StringComparison.OrdinalIgnoreCase) < 0) return false;
            if (!string.IsNullOrWhiteSpace(rule.PathContains) && path.IndexOf(rule.PathContains, StringComparison.OrdinalIgnoreCase) < 0) return false;
            if (!string.IsNullOrWhiteSpace(rule.SignerState) && !string.Equals(rule.SignerState, signature.ToString(), StringComparison.OrdinalIgnoreCase)) return false;
            if (!string.IsNullOrWhiteSpace(rule.SignerContains) && signer.IndexOf(rule.SignerContains, StringComparison.OrdinalIgnoreCase) < 0) return false;
            if (!string.IsNullOrWhiteSpace(rule.Sha256) && !string.Equals(rule.Sha256, sha256, StringComparison.OrdinalIgnoreCase)) return false;
            if (!string.IsNullOrWhiteSpace(rule.Sha1) && !string.Equals(rule.Sha1, sha1, StringComparison.OrdinalIgnoreCase)) return false;
            if (!string.IsNullOrWhiteSpace(rule.Md5) && !string.Equals(rule.Md5, md5, StringComparison.OrdinalIgnoreCase)) return false;
            if (!string.IsNullOrWhiteSpace(rule.ContainsAscii) && (content == null || !ContainsAscii(content, rule.ContainsAscii, rule.ContainsAsciiNoCase))) return false;
            return true;
        }

        private static bool ContainsAscii(byte[] content, string text, bool nocase)
        {
            if (content.Length == 0 || text.Length == 0) return false;
            byte[] needle = Encoding.ASCII.GetBytes(nocase ? text.ToUpperInvariant() : text);
            for (int i = 0; i <= content.Length - needle.Length; i += 1)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j += 1)
                {
                    byte hay = content[i + j];
                    if (nocase) hay = (byte)char.ToUpperInvariant((char)hay);
                    if (hay != needle[j]) { match = false; break; }
                }
                if (match) return true;
            }
            return false;
        }

        private static bool ShouldScanPath(string path)
        {
            string ext = Path.GetExtension(path);
            return ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) || ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) || ext.Equals(".sys", StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizePath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return string.Empty;
            try { return Path.GetFullPath(path.Trim()); } catch { return path.Trim(); }
        }

        private static SignatureTrustState ClassifySignature(string path)
        {
            try
            {
#pragma warning disable SYSLIB0057
                X509Certificate cert = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
                using var cert2 = new X509Certificate2(cert);
                using var chain = new X509Chain { ChainPolicy = { RevocationMode = X509RevocationMode.NoCheck, VerificationFlags = X509VerificationFlags.NoFlag } };
                bool valid = chain.Build(cert2);
                if (cert2.NotAfter.ToUniversalTime() < DateTime.UtcNow) return SignatureTrustState.Expired;
                return valid ? SignatureTrustState.Trusted : SignatureTrustState.Invalid;
            }
            catch (CryptographicException) { return SignatureTrustState.Unsigned; }
            catch { return SignatureTrustState.Unknown; }
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
            catch { return string.Empty; }
        }

        private static uint ParseSeverity(string? text, uint fallback)
        {
            if (uint.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint value)) return value;
            return (text ?? string.Empty).Trim().ToLowerInvariant() switch { "critical" => 8u, "high" => 6u, "medium" => 4u, "low" => 2u, _ => fallback };
        }

        private static string BuildRuleReason(string? title, string? detail, string? mitreId, string? mitreName, string? sigmaId)
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(title)) parts.Add(title.Trim());
            if (!string.IsNullOrWhiteSpace(detail)) parts.Add(detail.Trim());
            if (!string.IsNullOrWhiteSpace(mitreId) || !string.IsNullOrWhiteSpace(mitreName)) parts.Add($"MITRE {Fallback(mitreId)} {Fallback(mitreName)}".Trim());
            if (!string.IsNullOrWhiteSpace(sigmaId)) parts.Add($"SIGMA {sigmaId.Trim()}");
            return parts.Count == 0 ? "offline signature-intel match" : string.Join(" | ", parts);
        }

        private static string Fallback(string? text) => string.IsNullOrWhiteSpace(text) ? "unknown" : text.Trim();

        private static HeuristicEventView BuildHeuristic(string detection, uint severity, uint actorPid, uint targetPid, string source, string eventName, string reason, string evidence)
        {
            DateTime now = DateTime.UtcNow;
            return new HeuristicEventView { TimestampUtc = now, LastSeenUtc = now, Severity = severity, DetectionName = detection, ActorPid = actorPid, TargetPid = targetPid, Source = source, EventName = eventName, Reason = reason, Evidence = evidence };
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _cts.Cancel();
            _signal.Set();
            try { _worker.Wait(1000); } catch { }
            _cts.Dispose();
            _signal.Dispose();
        }

        private sealed record WorkItem(string Key, bool IsFile, bool IsPage, string Path, byte[]? Sample, int SampleSize, uint ActorPid, uint TargetPid, string Source, string EventName, string Trigger);
        private sealed record MaterializedFinding(string Detection, uint Severity, string Reason, string Evidence)
        {
            public HeuristicEventView ToHeuristic(uint actorPid, uint targetPid, string source, string eventName, string trigger) => BuildHeuristic(Detection, Severity, actorPid, targetPid, source, eventName, string.IsNullOrWhiteSpace(trigger) ? Reason : $"{Reason} | trigger={trigger}", Evidence);
        }
        private sealed record CacheEntry(long Length, DateTime LastWriteUtc, IReadOnlyList<MaterializedFinding> Findings)
        {
            public bool Matches(FileInfo info) => info.Length == Length && info.LastWriteTimeUtc == LastWriteUtc;
        }
        private sealed record Ruleset(IReadOnlyList<ManifestRule> ManifestRules, IReadOnlyList<YaraRule> YaraRules);
        private sealed class ManifestDocument { [JsonPropertyName("rules")] public List<ManifestRule?>? Rules { get; init; } }
        private sealed class ManifestRule
        {
            [JsonPropertyName("id")] public string Id { get; init; } = string.Empty;
            [JsonPropertyName("title")] public string Title { get; init; } = string.Empty;
            [JsonPropertyName("description")] public string Description { get; init; } = string.Empty;
            [JsonPropertyName("severity")] public string Severity { get; init; } = string.Empty;
            [JsonPropertyName("detection")] public string Detection { get; init; } = string.Empty;
            [JsonPropertyName("mitre_technique_id")] public string MitreTechniqueId { get; init; } = string.Empty;
            [JsonPropertyName("mitre_technique")] public string MitreTechnique { get; init; } = string.Empty;
            [JsonPropertyName("sigma_rule_id")] public string SigmaRuleId { get; init; } = string.Empty;
            [JsonPropertyName("sha256")] public string Sha256 { get; init; } = string.Empty;
            [JsonPropertyName("sha1")] public string Sha1 { get; init; } = string.Empty;
            [JsonPropertyName("md5")] public string Md5 { get; init; } = string.Empty;
            [JsonPropertyName("file_name_contains")] public string FileNameContains { get; init; } = string.Empty;
            [JsonPropertyName("path_contains")] public string PathContains { get; init; } = string.Empty;
            [JsonPropertyName("signer_state")] public string SignerState { get; init; } = string.Empty;
            [JsonPropertyName("signer_contains")] public string SignerContains { get; init; } = string.Empty;
            [JsonPropertyName("contains_ascii")] public string ContainsAscii { get; init; } = string.Empty;
            [JsonPropertyName("contains_ascii_nocase")] public bool ContainsAsciiNoCase { get; init; }
        }
        private sealed record YaraRule(string Name, string Title, string Detection, string MitreId, string MitreName, string SigmaId, uint Severity, bool FileScope, bool MemoryScope, bool PageScope, bool RequireAll, IReadOnlyList<YaraPattern> Patterns)
        {
            public bool IsMatch(ReadOnlySpan<byte> bytes)
            {
                int hits = 0;
                for (int i = 0; i < Patterns.Count; i += 1)
                {
                    bool matched = Patterns[i].IsMatch(bytes);
                    if (RequireAll && !matched) return false;
                    if (matched) hits += 1;
                }
                return RequireAll ? hits == Patterns.Count : hits > 0;
            }
        }
        private sealed class YaraPattern
        {
            private readonly byte[]? _ascii;
            private readonly byte?[]? _hex;
            private readonly bool _nocase;
            private YaraPattern(byte[] ascii, bool nocase) { _ascii = ascii; _nocase = nocase; }
            private YaraPattern(byte?[] hex) { _hex = hex; }
            public static YaraPattern Ascii(string text, bool nocase) => new(Encoding.ASCII.GetBytes(nocase ? text.ToUpperInvariant() : text), nocase);
            public static YaraPattern? Hex(string text)
            {
                string[] tokens = text.Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                if (tokens.Length == 0) return null;
                var bytes = new byte?[tokens.Length];
                for (int i = 0; i < tokens.Length; i += 1)
                {
                    string token = tokens[i];
                    if (token is "?" or "??") { bytes[i] = null; continue; }
                    if (!byte.TryParse(token, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out byte value)) return null;
                    bytes[i] = value;
                }
                return new YaraPattern(bytes);
            }
            public bool IsMatch(ReadOnlySpan<byte> bytes)
            {
                if (_ascii != null) return MatchAscii(bytes);
                if (_hex != null) return MatchHex(bytes);
                return false;
            }
            private bool MatchAscii(ReadOnlySpan<byte> bytes)
            {
                if (_ascii == null || bytes.Length < _ascii.Length) return false;
                for (int i = 0; i <= bytes.Length - _ascii.Length; i += 1)
                {
                    bool ok = true;
                    for (int j = 0; j < _ascii.Length; j += 1)
                    {
                        byte hay = bytes[i + j];
                        if (_nocase) hay = (byte)char.ToUpperInvariant((char)hay);
                        if (hay != _ascii[j]) { ok = false; break; }
                    }
                    if (ok) return true;
                }
                return false;
            }
            private bool MatchHex(ReadOnlySpan<byte> bytes)
            {
                if (_hex == null || bytes.Length < _hex.Length) return false;
                for (int i = 0; i <= bytes.Length - _hex.Length; i += 1)
                {
                    bool ok = true;
                    for (int j = 0; j < _hex.Length; j += 1)
                    {
                        byte? expected = _hex[j];
                        if (expected.HasValue && bytes[i + j] != expected.Value) { ok = false; break; }
                    }
                    if (ok) return true;
                }
                return false;
            }
        }
    }
}
