using BlackbirdInterface.Capture;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace BlackbirdInterface
{
    internal sealed partial class PackerDetectionService
    {
        private void PublishImageScanFindings(ImageCodeScanResult? current, ImageCodeScanResult? previous,
                                              bool baselineOnly = false)
        {
            if (current == null || _disposed || baselineOnly || !CanPromoteDetections())
            {
                return;
            }

            if (Volatile.Read(ref _entrypointFindingPublished) == 0 &&
                TryBuildEntrypointFinding(current, out HeuristicEventView? entrypointFinding) &&
                entrypointFinding != null &&
                Interlocked.CompareExchange(ref _entrypointFindingPublished, 1, 0) == 0)
            {
                PublishSyntheticFinding(entrypointFinding, "entrypoint");
            }

            if (Volatile.Read(ref _earlyCodeFindingPublished) == 0 &&
                TryBuildEarlyCodeFinding(current, previous, out HeuristicEventView? earlyCodeFinding) &&
                earlyCodeFinding != null &&
                Interlocked.CompareExchange(ref _earlyCodeFindingPublished, 1, 0) == 0)
            {
                PublishSyntheticFinding(earlyCodeFinding, "early-code");
            }

            if (TryBuildStringDiffFinding(current, previous, out HeuristicEventView? stringDiffFinding) &&
                stringDiffFinding != null)
            {
                PublishSyntheticFinding(stringDiffFinding, $"string-diff-{current.Phase}");
            }
        }

        private bool TryBuildEntrypointFinding(ImageCodeScanResult scan, out HeuristicEventView? finding)
        {
            finding = null;
            PeImageLayout layout = scan.Layout;
            if (layout.AddressOfEntryPoint == 0)
            {
                return false;
            }

            PeSection? entry = scan.EntrySection;
            PeSection? expected = scan.ExpectedEntrySection;
            bool missingSection = entry == null;
            bool nonExecutableSection = entry != null && !entry.IsExecutable;
            bool outsideExpected = scan.EntryPointOutsideExpected;
            if (!missingSection && !nonExecutableSection && !outsideExpected)
            {
                return false;
            }

            ImageSectionComparison? entryComparison =
                entry == null ? null : scan.SectionComparisons.FirstOrDefault(x => ReferenceEquals(x.Section, entry));
            bool suspiciousExtra = entry != null && IsSuspiciousEntrypointSection(scan, entry, entryComparison);
            string dumpEvidence = suspiciousExtra || missingSection || nonExecutableSection
                                      ? TryCaptureProcessDumpEvidence("entrypoint-anomaly", scan)
                                      : "dump=not-requested";
            uint severity = missingSection || nonExecutableSection ? 9u : suspiciousExtra ? 8u : 6u;
            string expectedLabel = expected == null ? "none" : expected.RangeLabel;
            string entryLabel = entry == null ? "no-section" : entry.RangeLabel;
            string reason =
                missingSection ? "AddressOfEntryPoint does not resolve to a mapped PE section"
                : nonExecutableSection
                    ? $"AddressOfEntryPoint resolves to non-executable section {entry!.Name}"
                    : $"AddressOfEntryPoint resolves to {entry!.Name}, outside expected code range {expectedLabel}";
            string evidence =
                $"image={scan.ImagePath} imageBase=0x{scan.ImageBase:X} moduleSize=0x{scan.ModuleSize:X} " +
                $"aepRva=0x{layout.AddressOfEntryPoint:X} aepVa=0x{scan.EntryPointVa:X} " +
                $"entrySection={entryLabel} expectedRange={expectedLabel} " +
                $"entryExecutable={(entry?.IsExecutable.ToString(CultureInfo.InvariantCulture).ToLowerInvariant() ?? "unknown")} " +
                $"entryEntropy={entryComparison?.MemoryEntropy.ToString("F2", CultureInfo.InvariantCulture) ?? "n/a"} " +
                $"scanPhase={scan.Phase} suspiciousExtra={suspiciousExtra.ToString(CultureInfo.InvariantCulture).ToLowerInvariant()} {dumpEvidence}";

            DateTime now = DateTime.UtcNow;
            finding = new HeuristicEventView { TimestampUtc = now,
                                               LastSeenUtc = now,
                                               Severity = severity,
                                               DetectionName = "PACKER_ENTRYPOINT_OUTSIDE_EXPECTED_RANGE",
                                               ActorPid = (uint)_targetPid,
                                               TargetPid = (uint)_targetPid,
                                               Source = "BlackbirdImage",
                                               EventName = "EntrypointRange",
                                               Reason = reason,
                                               Evidence = evidence };
            return true;
        }

        private bool TryBuildEarlyCodeFinding(ImageCodeScanResult scan, ImageCodeScanResult? previous,
                                              out HeuristicEventView? finding)
        {
            finding = null;
            var mutated = scan.SectionComparisons.Where(x => IsEarlyCodeMutation(scan, previous, x))
                              .OrderByDescending(x => x.ChangeRatio)
                              .ThenByDescending(x => x.ChangedBytes)
                              .Take(6)
                              .ToArray();
            if (mutated.Length == 0)
            {
                return false;
            }

            string dumpEvidence = TryCaptureProcessDumpEvidence("early-code-unpack", scan);
            string mutationSummary = string.Join(
                "; ",
                mutated.Select(
                    x =>
                        $"{x.Section.Name}:changed={x.ChangedBytes}/{x.ComparedBytes}({x.ChangeRatio:P1}) entropy={x.FileEntropy:F2}->{x.MemoryEntropy:F2}"));
            string previousSignal = previous == null ? "previous=none" : BuildPreviousScanSignal(previous, mutated);
            string entrySection = scan.EntrySection == null ? "no-section" : scan.EntrySection.RangeLabel;
            string expected = scan.ExpectedEntrySection == null ? "none" : scan.ExpectedEntrySection.RangeLabel;
            string reason =
                scan.EntryPointOutsideExpected
                    ? "AEP starts in an unexpected executable section and early process memory no longer matches the image-backed code section"
                    : "early process code section diverged from the on-disk image with an entropy shift consistent with unpacking or decryption";
            string evidence =
                $"image={scan.ImagePath} imageBase=0x{scan.ImageBase:X} aepRva=0x{scan.Layout.AddressOfEntryPoint:X} " +
                $"aepVa=0x{scan.EntryPointVa:X} entrySection={entrySection} expectedRange={expected} " +
                $"scanPhase={scan.Phase} mutations=[{mutationSummary}] {previousSignal} {dumpEvidence}";

            DateTime now = DateTime.UtcNow;
            finding = new HeuristicEventView { TimestampUtc = now,
                                               LastSeenUtc = now,
                                               Severity = scan.EntryPointOutsideExpected ? 9u : 8u,
                                               DetectionName = "PACKER_EARLY_CODE_UNPACK_OR_DECRYPT",
                                               ActorPid = (uint)_targetPid,
                                               TargetPid = (uint)_targetPid,
                                               Source = "BlackbirdImage",
                                               EventName = "EarlyCodeMutation",
                                               Reason = reason,
                                               Evidence = evidence };
            return true;
        }

        private bool TryBuildStringDiffFinding(ImageCodeScanResult scan, ImageCodeScanResult? previous,
                                               out HeuristicEventView? finding)
        {
            finding = null;
            ImageStringDiff diff = scan.StringDiff;
            if (diff.MemoryOnlyStrings.Length == 0)
            {
                return false;
            }

            var previousValues = new HashSet<string>(StringComparer.Ordinal);
            if (previous?.StringDiff != null)
            {
                foreach (ImageStringHit hit in previous.StringDiff.MemoryOnlyStrings)
                {
                    previousValues.Add(hit.Value);
                }
            }

            var newSincePrevious = new List<ImageStringHit>();
            foreach (ImageStringHit hit in diff.MemoryOnlyStrings)
            {
                if (!previousValues.Contains(hit.Value))
                {
                    newSincePrevious.Add(hit);
                }
            }

            IEnumerable<ImageStringHit> evidenceSource =
                newSincePrevious.Count > 0 ? newSincePrevious : diff.MemoryOnlyStrings;
            ImageStringHit[] evidenceSamples = evidenceSource.Take(MaxStringEvidenceSamples).ToArray();
            string sampleEvidence = BuildStringHitEvidence(evidenceSamples);
            bool newStringsAppeared = previous != null && newSincePrevious.Count > 0;
            uint severity = newStringsAppeared && scan.EntryPointOutsideExpected ? 7u
                            : newStringsAppeared                                 ? 6u
                            : scan.EntryPointOutsideExpected                     ? 5u
                                                                                 : 4u;
            string reason =
                newStringsAppeared
                    ? "new memory-only strings appeared after early process execution, consistent with unpacking or in-memory decryption"
                    : "loaded image contains strings present in process memory but absent from the image on disk";
            string evidence =
                $"engine=string-diff image=\"{EscapeEvidenceValue(scan.ImagePath)}\" phase={scan.Phase} " +
                $"diskStrings={diff.DiskStringCount} memoryStrings={diff.MemoryStringCount} " +
                $"memoryOnly={diff.MemoryOnlyStrings.Length} newSincePrevious={newSincePrevious.Count} " +
                $"aepRva=0x{scan.Layout.AddressOfEntryPoint:X} entryOutsideExpected={scan.EntryPointOutsideExpected.ToString(CultureInfo.InvariantCulture).ToLowerInvariant()} " +
                $"samples=[{sampleEvidence}]";

            DateTime now = DateTime.UtcNow;
            finding = new HeuristicEventView { TimestampUtc = now,
                                               LastSeenUtc = now,
                                               Severity = severity,
                                               DetectionName = newStringsAppeared ? "MEMORY_STRING_DIFF_NEW_STRINGS"
                                                                                  : "MEMORY_STRING_DIFF",
                                               ActorPid = (uint)_targetPid,
                                               TargetPid = (uint)_targetPid,
                                               Source = "BlackbirdImage",
                                               EventName = "StringDiff",
                                               Reason = reason,
                                               Evidence = evidence };
            return true;
        }

        private static bool IsEarlyCodeMutation(ImageCodeScanResult scan, ImageCodeScanResult? previous,
                                                ImageSectionComparison comparison)
        {
            if (comparison.ComparedBytes < MinImageSectionCompareBytes ||
                comparison.ChangedBytes < MinImageSectionCompareBytes / 2)
            {
                return false;
            }

            bool textOrExecutable = comparison.Section.IsExecutable || IsCanonicalTextSection(comparison.Section);
            if (!textOrExecutable)
            {
                return false;
            }

            bool expectedOrNonEntryExecutable = ReferenceEquals(comparison.Section, scan.ExpectedEntrySection) ||
                                                !ReferenceEquals(comparison.Section, scan.EntrySection);
            double entropyDelta = Math.Abs(comparison.MemoryEntropy - comparison.FileEntropy);
            bool changedSincePrevious =
                previous?.SectionComparisons.Any(
                    x => string.Equals(x.Section.Name, comparison.Section.Name, StringComparison.OrdinalIgnoreCase) &&
                         x.MemoryHash != comparison.MemoryHash) == true;

            if (scan.EntryPointOutsideExpected && expectedOrNonEntryExecutable &&
                comparison.ChangeRatio >= EarlyCodeChangedRatioThreshold)
            {
                return true;
            }

            if (comparison.ChangeRatio >= StrongCodeChangedRatioThreshold &&
                entropyDelta >= EarlyCodeEntropyDeltaThreshold)
            {
                return true;
            }

            return changedSincePrevious && comparison.ChangeRatio >= EarlyCodeChangedRatioThreshold &&
                   entropyDelta >= EarlyCodeEntropyDeltaThreshold;
        }

        private string TryCaptureProcessDumpEvidence(string reason, ImageCodeScanResult scan)
        {
            int dumpState = Interlocked.CompareExchange(ref _processDumpCaptured, 1, 0);
            if (dumpState != 0)
            {
                return dumpState == 2 ? "dump=already-captured" : "dump=in-progress";
            }

            try
            {
                string dumpDirectory = Path.Combine(_workspaceRoot, "process-dumps");
                Directory.CreateDirectory(dumpDirectory);
                string safeReason = ToSafeFileStem(reason);
                string stem = $"{DateTime.UtcNow:yyyyMMdd_HHmmss_fff}_pid{_targetPid}_{safeReason}";
                string dumpPath = Path.Combine(dumpDirectory, stem + ".dmp");
                if (!ProcessSnapshotDumpService.TryCaptureFullMemoryDump((uint)_targetPid, dumpPath,
                                                                         out ProcessSnapshotDumpResult result))
                {
                    Interlocked.Exchange(ref _processDumpCaptured, 0);
                    _log?.Invoke($"PSS dump failed pid={_targetPid} reason={reason}: {result.Error}");
                    return $"dump=failed error=\"{EscapeEvidenceValue(result.Error)}\"";
                }

                var metadata = new ProcessDumpMetadata { DetectionReason = reason,
                                                         TargetPid = _targetPid,
                                                         ImagePath = scan.ImagePath,
                                                         ImageBase = $"0x{scan.ImageBase:X}",
                                                         AddressOfEntryPoint = $"0x{scan.Layout.AddressOfEntryPoint:X}",
                                                         DumpPath = Path.GetRelativePath(_workspaceRoot, dumpPath),
                                                         DumpBytes = result.DumpBytes,
                                                         CaptureMethod = result.CaptureMethod };
                File.WriteAllText(Path.Combine(dumpDirectory, stem + ".json"),
                                  JsonSerializer.Serialize(metadata, JsonOptions));
                Interlocked.Exchange(ref _processDumpCaptured, 2);
                _log?.Invoke(
                    $"PSS memory dump captured pid={_targetPid} bytes={result.DumpBytes} path={metadata.DumpPath}");
                return $"dump={metadata.DumpPath} dumpBytes={result.DumpBytes} dumpMethod={result.CaptureMethod}";
            }
            catch (Exception ex)
            {
                Interlocked.Exchange(ref _processDumpCaptured, 0);
                _log?.Invoke($"PSS dump failed pid={_targetPid} reason={reason}: {ex.Message}");
                return $"dump=failed error=\"{EscapeEvidenceValue(ex.Message)}\"";
            }
        }

        private void PublishSyntheticFinding(HeuristicEventView finding, string groupSuffix)
        {
            _publishFindings?.Invoke(new[] { finding });
            _store?.AppendSyntheticHeuristic(finding.TimestampUtc, _targetPid, 0, $"packer-{groupSuffix}",
                                             finding.DetectionName, $"{finding.DetectionName} sev={finding.Severity}",
                                             finding.Evidence,
                                             $"packer-image:{_targetPid}:{finding.DetectionName}:{groupSuffix}");
        }

        private static bool IsSuspiciousEntrypointSection(ImageCodeScanResult scan, PeSection section,
                                                          ImageSectionComparison? comparison)
        {
            if (!scan.EntryPointOutsideExpected)
            {
                return false;
            }

            bool nonStandardName = !IsCommonPeSectionName(section.Name);
            bool lastSection = scan.Layout.Sections.Count > 0 && ReferenceEquals(scan.Layout.Sections[^1], section);
            bool highEntropy = comparison != null && comparison.MemoryEntropy >= HighEntropyThreshold;
            return section.IsExecutable && (nonStandardName || lastSection || highEntropy);
        }

        private static bool IsEntrypointInsideExpectedSection(uint addressOfEntryPoint, PeSection? expected)
        {
            return expected != null && expected.ContainsRva(addressOfEntryPoint);
        }

        private static string BuildPreviousScanSignal(ImageCodeScanResult previous,
                                                      IReadOnlyList<ImageSectionComparison> currentMutations)
        {
            string changed =
                string.Join(",", currentMutations
                                     .Where(current => previous.SectionComparisons.Any(
                                                prior => string.Equals(prior.Section.Name, current.Section.Name,
                                                                       StringComparison.OrdinalIgnoreCase) &&
                                                         prior.MemoryHash != current.MemoryHash))
                                     .Select(x => x.Section.Name)
                                     .Take(8));
            return string.IsNullOrWhiteSpace(changed) ? "previous=stable-or-unavailable"
                                                      : $"changedSincePrevious={changed}";
        }

        private static string BuildStringHitEvidence(IReadOnlyList<ImageStringHit> hits)
        {
            if (hits.Count == 0)
            {
                return "none";
            }

            return string.Join(
                "; ",
                hits.Select(
                    hit => $"{hit.Encoding}:{hit.SectionName}:rva=0x{hit.Rva:X}:\"{EscapeEvidenceValue(hit.Value)}\""));
        }

        private static bool TryReadFileRange(string path, uint offset, int requestedBytes, out byte[] data,
                                             out string error)
        {
            data = Array.Empty<byte>();
            error = string.Empty;
            try
            {
                using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                if (offset >= (ulong)stream.Length)
                {
                    error = "offset beyond end of file";
                    return false;
                }

                int length = (int)Math.Min(requestedBytes, stream.Length - offset);
                data = new byte[length];
                stream.Position = offset;
                int total = 0;
                while (total < data.Length)
                {
                    int read = stream.Read(data, total, data.Length - total);
                    if (read <= 0)
                    {
                        break;
                    }

                    total += read;
                }

                if (total <= 0)
                {
                    error = "no bytes read";
                    return false;
                }

                if (total < data.Length)
                {
                    Array.Resize(ref data, total);
                }
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private static int CountChangedBytes(byte[] left, byte[] right, int length)
        {
            int count = 0;
            int capped = Math.Min(length, Math.Min(left.Length, right.Length));
            for (int i = 0; i < capped; i += 1)
            {
                if (left[i] != right[i])
                {
                    count += 1;
                }
            }

            return count;
        }

        private static bool IsCanonicalTextSection(PeSection section)
        {
            return section.Name.Equals(".text", StringComparison.OrdinalIgnoreCase) ||
                   section.Name.Equals("text", StringComparison.OrdinalIgnoreCase) ||
                   section.Name.Equals("CODE", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsCommonPeSectionName(string name)
        {
            string normalized = name.Trim().TrimEnd('\0');
            return normalized.Equals(".text", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Equals("text", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Equals("CODE", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Equals(".rdata", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Equals(".data", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Equals(".pdata", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Equals(".xdata", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Equals(".rsrc", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Equals(".reloc", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Equals(".tls", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Equals(".idata", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Equals(".edata", StringComparison.OrdinalIgnoreCase);
        }

        private static string SafeModuleFileName(ProcessModule module)
        {
            try
            {
                return module.FileName ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string NormalizePathForCompare(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return string.Empty;
            }

            try
            {
                return Path.GetFullPath(path.Trim());
            }
            catch
            {
                return path.Trim();
            }
        }

        private static bool PathsEqual(string? left, string? right)
        {
            string a = NormalizePathForCompare(left);
            string b = NormalizePathForCompare(right);
            return !string.IsNullOrWhiteSpace(a) && !string.IsNullOrWhiteSpace(b) &&
                   string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
        }

        private static string ToSafeFileStem(string value)
        {
            string trimmed = string.IsNullOrWhiteSpace(value) ? "dump" : value.Trim().ToLowerInvariant();
            var chars = trimmed.Select(ch => char.IsLetterOrDigit(ch) ? ch : '_').ToArray();
            string safe = new(chars);
            while (safe.Contains("__", StringComparison.Ordinal))
            {
                safe = safe.Replace("__", "_", StringComparison.Ordinal);
            }

            return safe.Trim('_') is { Length : > 0 } result ? result[..Math.Min(result.Length, 64)] : "dump";
        }

        private static string EscapeEvidenceValue(string value) => value.Replace("\"", "'", StringComparison.Ordinal);
    }
}
