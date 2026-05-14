using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
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
    internal sealed partial class SignatureIntelService
    {
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

                    var findings = work.IsProcessMemory ? ScanProcessMemory(work)
                                   : work.IsFile ? ScanFile(work)
                                                        : ScanSample(work);
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

                int size = Math.Min(work.SampleSize, work.Sample.Length);
                if (size <= 0)
                {
                    return findings;
                }

                return ScanYaraMemoryBytes(
                    rules, work, work.Sample.AsSpan(0, size), work.IsPage ? "page" : "memory", work.Path,
                    work.Sample, Math.Min(size, MaxEvidenceSampleBytes));
            }
            finally
            {
                _pending.TryRemove(work.Key, out _);
            }
        }

        private List<HeuristicEventView> ScanProcessMemory(WorkItem work)
        {
            try
            {
                var findings = new List<HeuristicEventView>();
                if (!_options.Enabled || !_options.MemoryScan || work.ProcessId == 0)
                {
                    return findings;
                }

                Ruleset rules = EnsureRulesLoaded();
                if (!rules.YaraRules.Any(static rule => rule.MemoryScope))
                {
                    return findings;
                }

                if (!TryOpenProcessForMemoryScan(work.ProcessId, out IntPtr processHandle, out string openError))
                {
                    _log?.Invoke($"signature intel process memory scan skipped pid={work.ProcessId}: {openError}");
                    return findings;
                }

                int visitedRegions = 0;
                int scannedRegions = 0;
                int skippedRegions = 0;
                long scannedBytes = 0;
                ulong address = 0;
                ulong maxAddress = GetMaxUserModeAddress();

                try
                {
                    while (!_cts.IsCancellationRequested && address < maxAddress &&
                           visitedRegions < MaxProcessMemoryRegions && scannedBytes < MaxProcessMemoryTotalBytes &&
                           findings.Count < MaxProcessMemoryFindings)
                    {
                        if (!TryQueryProcessMemory(processHandle, address,
                                                   out Kernel32Native.MemoryBasicInformation64 mbi))
                        {
                            break;
                        }

                        visitedRegions += 1;
                        ulong nextAddress = NextRegionAddress(address, mbi);
                        if (nextAddress <= address)
                        {
                            break;
                        }

                        if (IsProcessMemoryRegionScannable(mbi))
                        {
                            int remainingBytes =
                                (int)Math.Min(MaxProcessMemoryTotalBytes - scannedBytes, int.MaxValue);
                            int bytesToRead =
                                (int)Math.Min(Math.Min(mbi.RegionSize, (ulong)MaxProcessMemoryRegionBytes),
                                              (ulong)Math.Max(0, remainingBytes));
                            if (bytesToRead > 0 &&
                                TryReadProcessRegion(processHandle, mbi.BaseAddress, bytesToRead, out byte[] data,
                                                     out int bytesRead))
                            {
                                scannedRegions += 1;
                                scannedBytes += bytesRead;
                                ulong regionEnd = mbi.BaseAddress > ulong.MaxValue - (ulong)bytesRead
                                                      ? ulong.MaxValue
                                                      : mbi.BaseAddress + (ulong)bytesRead;
                                string extraEvidence =
                                    $"pid={work.ProcessId} region=0x{mbi.BaseAddress:X}-0x{regionEnd:X} regionBytes={bytesRead} protect=0x{mbi.Protect:X8} type=0x{mbi.Type:X8}";
                                List<HeuristicEventView> regionFindings = ScanYaraMemoryBytes(
                                    rules, work, data.AsSpan(0, bytesRead), "process-memory",
                                    $"pid:{work.ProcessId}", data, Math.Min(bytesRead, MaxEvidenceSampleBytes),
                                    extraEvidence);
                                foreach (HeuristicEventView finding in regionFindings)
                                {
                                    findings.Add(finding);
                                    if (findings.Count >= MaxProcessMemoryFindings)
                                    {
                                        break;
                                    }
                                }
                            }
                            else
                            {
                                skippedRegions += 1;
                            }
                        }

                        address = nextAddress;
                    }
                }
                finally
                {
                    _ = Kernel32Native.CloseHandle(processHandle);
                }

                _log?.Invoke(
                    $"signature intel process memory scan pid={work.ProcessId} regions={scannedRegions}/{visitedRegions} skipped={skippedRegions} bytes={scannedBytes} hits={findings.Count}");
                return findings;
            }
            finally
            {
                _pending.TryRemove(work.Key, out _);
            }
        }

        private List<HeuristicEventView> ScanYaraMemoryBytes(Ruleset rules, WorkItem work, ReadOnlySpan<byte> bytes,
                                                             string scope, string origin, byte[]? evidenceSample,
                                                             int evidenceSampleSize,
                                                             string extraEvidence = "")
        {
            var findings = new List<HeuristicEventView>();
            if (bytes.Length <= 0)
            {
                return findings;
            }

            foreach (YaraRule rule in rules.YaraRules)
            {
                if (!ShouldEvaluateMemoryRule(rule, work))
                {
                    continue;
                }
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

                string detection = string.IsNullOrWhiteSpace(rule.Detection)
                                       ? (work.IsProcessMemory ? "YARA_PROCESS_MEMORY_MATCH" : "YARA_SAMPLE_MATCH")
                                       : rule.Detection;
                string evidence = $"engine=yara scope={scope} origin={Fallback(origin)} rule={rule.Name}";
                if (!string.IsNullOrWhiteSpace(extraEvidence))
                {
                    evidence += " " + extraEvidence.Trim();
                }
                if (evidenceSample != null && evidenceSampleSize > 0)
                {
                    evidence +=
                        $" sample={EventDetailFormatting.FormatSampleHex(evidenceSample, evidenceSampleSize)}";
                }

                findings.Add(BuildHeuristic(
                    detection, rule.Severity, work.ActorPid, work.TargetPid, work.Source, work.EventName,
                    BuildRuleReason(rule.Title, work.Trigger, rule.MitreId, rule.MitreName, rule.SigmaId), evidence));
            }

            return findings;
        }

        private static bool ShouldEvaluateMemoryRule(YaraRule rule, WorkItem work)
        {
            string detection = rule.Detection ?? string.Empty;
            if (detection.Equals("YARA_AMSI_PATCH_BYTES", StringComparison.OrdinalIgnoreCase))
            {
                string eventName = work.EventName ?? string.Empty;
                return eventName.IndexOf("WriteVirtualMemory", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       eventName.IndexOf("WriteProcessMemory", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       eventName.IndexOf("memory.write", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            if (!detection.Equals("YARA_DIRECT_SYSCALL_STUB", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            string trigger = work.Trigger ?? string.Empty;
            string origin = work.Path ?? string.Empty;
            return trigger.IndexOf("direct-syscall", StringComparison.OrdinalIgnoreCase) >= 0 &&
                   origin.IndexOf("ntdll.dll", StringComparison.OrdinalIgnoreCase) < 0 &&
                   origin.IndexOf("win32u.dll", StringComparison.OrdinalIgnoreCase) < 0;
        }

        private static bool TryOpenProcessForMemoryScan(uint pid, out IntPtr handle, out string error)
        {
            error = string.Empty;
            handle = Kernel32Native.OpenProcess(
                ProcessVmRead | ProcessQueryInformation | ProcessQueryLimitedInformation, false, pid);
            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            {
                int err = Marshal.GetLastWin32Error();
                error = $"OpenProcess(PROCESS_VM_READ) failed win32={err}";
                return false;
            }

            return true;
        }

        private static bool TryQueryProcessMemory(IntPtr processHandle, ulong address,
                                                  out Kernel32Native.MemoryBasicInformation64 mbi)
        {
            UIntPtr result = Kernel32Native.VirtualQueryEx(
                processHandle, new IntPtr(unchecked((long)address)), out mbi,
                new UIntPtr((uint)Marshal.SizeOf<Kernel32Native.MemoryBasicInformation64>()));
            return result != UIntPtr.Zero;
        }

        private static bool TryReadProcessRegion(IntPtr processHandle, ulong baseAddress, int requestedBytes,
                                                 out byte[] data, out int bytesRead)
        {
            data = Array.Empty<byte>();
            bytesRead = 0;
            if (requestedBytes <= 0)
            {
                return false;
            }

            byte[] buffer = new byte[requestedBytes];
            byte[] chunkBuffer = new byte[Math.Min(ProcessMemoryReadChunkBytes, requestedBytes)];
            int total = 0;
            while (total < requestedBytes)
            {
                int chunk = Math.Min(chunkBuffer.Length, requestedBytes - total);
                bool ok =
                    Kernel32Native.ReadProcessMemory(processHandle, new IntPtr(unchecked((long)(baseAddress +
                                                                                                 (ulong)total))),
                                                     chunkBuffer, chunk, out IntPtr bytesReadPtr);
                long rawBytesRead = bytesReadPtr.ToInt64();
                int chunkRead = rawBytesRead <= 0 ? 0 : (int)Math.Min(rawBytesRead, chunk);
                if (!ok || chunkRead <= 0)
                {
                    break;
                }

                Buffer.BlockCopy(chunkBuffer, 0, buffer, total, chunkRead);
                total += chunkRead;
                if (chunkRead < chunk)
                {
                    break;
                }
            }

            if (total <= 0)
            {
                return false;
            }

            bytesRead = total;
            data = total == buffer.Length ? buffer : buffer[..total];
            return true;
        }

        private static bool IsProcessMemoryRegionScannable(Kernel32Native.MemoryBasicInformation64 mbi)
        {
            if (mbi.State != MemCommit || mbi.RegionSize == 0)
            {
                return false;
            }

            uint baseProtect = mbi.Protect & 0xFFu;
            if ((mbi.Protect & PageGuard) != 0 || baseProtect == 0 || baseProtect == PageNoAccess)
            {
                return false;
            }

            return baseProtect is PageReadOnly or PageReadWrite or PageWriteCopy or PageExecute or PageExecuteRead
                   or PageExecuteReadWrite or PageExecuteWriteCopy;
        }

        private static ulong NextRegionAddress(ulong address, Kernel32Native.MemoryBasicInformation64 mbi)
        {
            ulong baseAddress = mbi.BaseAddress == 0 ? address : mbi.BaseAddress;
            ulong regionSize = Math.Max(mbi.RegionSize, 0x1000UL);
            if (baseAddress > ulong.MaxValue - regionSize)
            {
                return ulong.MaxValue;
            }

            ulong next = baseAddress + regionSize;
            return next <= address ? address + 0x1000UL : next;
        }

        private static ulong GetMaxUserModeAddress() => IntPtr.Size == 8 ? 0x00007FFFFFFF0000UL : 0x7FFF0000UL;

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
    }
}
