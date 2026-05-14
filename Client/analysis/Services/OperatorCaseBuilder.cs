using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace BlackbirdInterface
{
    internal static class OperatorCaseBuilder
    {
        private const int MaxDetailsPerGroup = 64;
        private const int MaxSourceEvents = 5000;
        private const int MaxEvidencePackets = 250;
        private const int MaxTimelineItems = 600;
        private const int MaxIocs = 300;
        private const int MaxRawDetailChars = 4096;

        private static readonly Regex FilePathRegex =
            new(@"\b[A-Za-z]:\\(?:[^\\/:*?""<>|\r\n]+\\)*[^\\/:*?""<>|\s\r\n]+",
                RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex RegistryPathRegex = new(
            @"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS)\\[^\s;,""']+",
            RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

        private static readonly Regex Ipv4Regex =
            new(@"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
                RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex HashRegex = new(@"\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b",
                                                      RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex DomainRegex =
            new(@"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b",
                RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

        internal static OperatorCaseReport
        Build(int rootPid, IEnumerable<GroupedEventRow>? detectionRows, IEnumerable<GroupedEventRow>? etwRows,
              IEnumerable<GroupedEventRow>? filesystemRows, IEnumerable<GroupedEventRow>? registryRows,
              IEnumerable<GroupedEventRow>? relationRows, IEnumerable<DiagnosticsStateEntry>? diagnostics)
        {
            List<CaseEvent> detectionEvents =
                BuildCaseEvents("Detections", detectionRows, formatDetections: true).Take(MaxSourceEvents).ToList();

            List<CaseEvent> allEvents =
                MergeBounded(detectionEvents, BuildCaseEvents("ETW", etwRows, formatDetections: false),
                             BuildCaseEvents("Filesystem", filesystemRows, formatDetections: false),
                             BuildCaseEvents("Registry", registryRows, formatDetections: false),
                             BuildCaseEvents("Process Relations", relationRows, formatDetections: false));

            List<OperatorEvidencePacket> evidence = BuildEvidencePackets(detectionEvents).ToList();
            List<OperatorBehaviorChain> chains = BuildBehaviorChains(evidence).ToList();
            List<OperatorTimelineItem> timeline = BuildTimeline(allEvents).ToList();
            List<OperatorIocItem> iocs = BuildIocs(allEvents).ToList();
            List<OperatorHealthItem> health = BuildHealthItems(diagnostics).ToList();
            List<OperatorTuningHint> tuning = BuildTuningHints(evidence, allEvents, health).ToList();
            List<OperatorReplayDiffItem> replayDiffs =
                BuildReplayDiffs(chains, evidence, timeline, iocs, health).ToList();

            int riskScore = ComputeRiskScore(evidence, chains, health);
            string rootProcess = rootPid > 0
                                     ? OperatorDetectionFormatter.FormatProcessIdentity(unchecked((uint)rootPid))
                                     : "No active target";

            var report =
                new OperatorCaseReport { Title = "Operator Case",
                                         Subtitle = BuildSubtitle(rootProcess, detectionEvents.Count, timeline.Count),
                                         GeneratedAtUtc = DateTime.UtcNow,
                                         RootPid = rootPid,
                                         RootProcess = rootProcess,
                                         RiskScore = riskScore,
                                         RiskLabel = RiskLabel(riskScore),
                                         Verdict = BuildVerdict(chains, evidence, health),
                                         Summary = BuildSummary(chains, evidence, iocs, health),
                                         DetectionCount = detectionEvents.Count,
                                         EvidenceCount = evidence.Count,
                                         TimelineCount = timeline.Count,
                                         IocCount = iocs.Count,
                                         HealthIssueCount = health.Count(x => IsProblemStatus(x.Status)),
                                         BehaviorChains = chains,
                                         EvidencePackets = evidence,
                                         Timeline = timeline,
                                         Iocs = iocs,
                                         HealthItems = health,
                                         TuningHints = tuning,
                                         ReplayDiffs = replayDiffs };

            report.ReportText = BuildReportText(report);
            return report;
        }

        internal static void ApplyBaselineComparison(OperatorCaseReport report, OperatorCaseReport? baseline,
                                                     string baselineLabel)
        {
            if (report == null || baseline == null)
            {
                return;
            }

            string label = string.IsNullOrWhiteSpace(baselineLabel) ? baseline.RootProcess : baselineLabel.Trim();
            var replay = new List<OperatorReplayDiffItem>();
            int riskDelta = report.RiskScore - baseline.RiskScore;
            replay.Add(new OperatorReplayDiffItem {
                Scope = "Risk",
                Current = $"{report.RiskLabel} {report.RiskScore.ToString(CultureInfo.InvariantCulture)}/100",
                Baseline =
                    $"{label}: {baseline.RiskLabel} {baseline.RiskScore.ToString(CultureInfo.InvariantCulture)}/100",
                Interpretation =
                    riskDelta == 0
                        ? "Risk score is unchanged from baseline."
                        : $"Risk moved {riskDelta.ToString("+#;-#;0", CultureInfo.InvariantCulture)} point(s) from baseline."
            });

            AppendSetDiff(replay, "Behavior chains",
                          report.BehaviorChains.Select(static x => $"{x.Name}|{x.Actor}|{x.Target}"),
                          baseline.BehaviorChains.Select(static x => $"{x.Name}|{x.Actor}|{x.Target}"), label);

            AppendSetDiff(replay, "Evidence titles", report.EvidencePackets.Select(static x => x.Detection),
                          baseline.EvidencePackets.Select(static x => x.Detection), label);

            AppendSetDiff(replay, "IOC set", report.Iocs.Select(static x => $"{x.Type}|{x.Value}"),
                          baseline.Iocs.Select(static x => $"{x.Type}|{x.Value}"), label);

            int currentHealth = report.HealthItems.Count(static x => IsProblemStatus(x.Status));
            int baselineHealth = baseline.HealthItems.Count(static x => IsProblemStatus(x.Status));
            bool baselineHealthAvailable = HasAttachedHealthSnapshot(baseline);
            replay.Add(new OperatorReplayDiffItem {
                Scope = "Instrumentation trust",
                Current = $"{currentHealth.ToString(CultureInfo.InvariantCulture)} issue(s)/warning(s)",
                Baseline = baselineHealthAvailable
                               ? $"{label}: {baselineHealth.ToString(CultureInfo.InvariantCulture)} issue(s)/warning(s)"
                               : $"{label}: no health snapshot",
                Interpretation =
                    !baselineHealthAvailable
                        ? "Baseline health was not stored with the compared tab; trust current health before interpreting behavior diffs."
                    : currentHealth == baselineHealth ? "Instrumentation health issue count is unchanged."
                                                      : "Review health before trusting detection deltas."
            });

            report.ReplayDiffs = replay;
            report.Subtitle = $"{report.Subtitle} | baseline={label}";
            report.ReportText = BuildReportText(report);
        }

        private static IEnumerable<CaseEvent> BuildCaseEvents(string stream, IEnumerable<GroupedEventRow>? rows,
                                                              bool formatDetections)
        {
            if (rows == null)
            {
                yield break;
            }

            foreach (GroupedEventRow row in rows)
            {
                if (row.Details.Count == 0)
                {
                    yield return FromRow(stream, row, formatDetections);
                    continue;
                }

                int detailCount = 0;
                foreach (GroupedEventDetailRow detail in row.Details)
                {
                    if (detailCount++ >= MaxDetailsPerGroup)
                    {
                        break;
                    }

                    yield return FromDetail(stream, row, detail, formatDetections);
                }
            }
        }

        private static CaseEvent FromRow(string stream, GroupedEventRow row, bool formatDetection)
        {
            uint actorPid = TryParsePid(row.Actor);
            uint targetPid = TryParsePid(row.Target);
            string rawDetection = FirstNonEmpty(row.Detection, row.Event);
            string detection = formatDetection
                                   ? OperatorDetectionFormatter.Format(rawDetection, actorPid, targetPid, row.Event)
                                   : rawDetection;

            return new CaseEvent { Stream = stream,
                                   TimestampUtc = row.LastSeenUtc == default ? DateTime.UtcNow : row.LastSeenUtc,
                                   Event = FirstNonEmpty(row.Event, rawDetection),
                                   Severity = NormalizeSeverity(row.Severity),
                                   Detection = detection,
                                   Actor = CleanEntity(row.Actor, actorPid),
                                   Target = CleanEntity(row.Target, targetPid),
                                   ActorPid = actorPid,
                                   TargetPid = targetPid,
                                   Source = stream,
                                   Summary = Trim(row.ArgumentPreview, 512),
                                   Details = Trim(row.GroupKey, MaxRawDetailChars) };
        }

        private static CaseEvent FromDetail(string stream, GroupedEventRow row, GroupedEventDetailRow detail,
                                            bool formatDetection)
        {
            uint actorPid =
                detail.ActorPid != 0 ? detail.ActorPid : TryParsePid(FirstNonEmpty(detail.Actor, row.Actor));
            uint targetPid =
                detail.TargetPid != 0 ? detail.TargetPid : TryParsePid(FirstNonEmpty(detail.Target, row.Target));
            string rawDetection = FirstNonEmpty(detail.Detection, row.Detection, detail.Event, row.Event);
            string eventName = FirstNonEmpty(detail.Event, row.Event, rawDetection);
            string detection = formatDetection
                                   ? OperatorDetectionFormatter.Format(rawDetection, actorPid, targetPid, eventName)
                                   : rawDetection;

            return new CaseEvent { Stream = stream,
                                   TimestampUtc =
                                       detail.TimestampUtc == default ? row.LastSeenUtc : detail.TimestampUtc,
                                   Event = eventName,
                                   Severity = NormalizeSeverity(FirstNonEmpty(detail.Severity, row.Severity)),
                                   Detection = detection,
                                   Actor = CleanEntity(FirstNonEmpty(detail.Actor, row.Actor), actorPid),
                                   Target = CleanEntity(FirstNonEmpty(detail.Target, row.Target), targetPid),
                                   ActorPid = actorPid,
                                   TargetPid = targetPid,
                                   Source = FirstNonEmpty(detail.Source, stream),
                                   Summary = Trim(FirstNonEmpty(detail.ArgumentSummary, row.ArgumentPreview), 512),
                                   Details = Trim(detail.Details, MaxRawDetailChars) };
        }

        private static List<CaseEvent> MergeBounded(params IEnumerable<CaseEvent>[] sources)
        {
            var merged = new List<CaseEvent>(MaxSourceEvents);
            foreach (IEnumerable<CaseEvent> source in sources)
            {
                foreach (CaseEvent item in source)
                {
                    if (merged.Count >= MaxSourceEvents)
                    {
                        return merged;
                    }

                    merged.Add(item);
                }
            }

            return merged;
        }

        private static IEnumerable<OperatorEvidencePacket>
        BuildEvidencePackets(IReadOnlyList<CaseEvent> detectionEvents)
        {
            IEnumerable<IGrouping<string, CaseEvent>> groups =
                detectionEvents.Where(static x => !string.IsNullOrWhiteSpace(x.Detection))
                    .GroupBy(static x => EvidenceKey(x), StringComparer.OrdinalIgnoreCase);

            foreach (IGrouping<string, CaseEvent> group in groups
                         .OrderByDescending(static x => x.Max(y => SeverityScore(y.Severity)))
                         .ThenByDescending(static x => x.Max(y => y.TimestampUtc))
                         .Take(MaxEvidencePackets))
            {
                CaseEvent sample = group.OrderByDescending(static x => SeverityScore(x.Severity))
                                       .ThenByDescending(static x => x.TimestampUtc)
                                       .First();

                BehaviorProfile profile = Classify(sample);
                string severity = MaxSeverity(sample.Severity, profile.SeverityFloor);
                string evidenceSummary = BuildEvidenceSummary(sample, group.Count());

                yield return new OperatorEvidencePacket { CategoryKey = profile.Key,
                                                          Category = profile.ChainName,
                                                          TimestampUtc = sample.TimestampUtc,
                                                          Detection = sample.Detection,
                                                          Severity = severity,
                                                          Confidence = profile.Confidence,
                                                          Actor = sample.Actor,
                                                          Target = sample.Target,
                                                          ActorPid = sample.ActorPid,
                                                          TargetPid = sample.TargetPid,
                                                          Stream = sample.Stream,
                                                          Source = sample.Source,
                                                          Tactic = profile.Tactic,
                                                          Technique = profile.Technique,
                                                          TechniqueId = profile.TechniqueId,
                                                          WhatHappened = profile.WhatHappened,
                                                          WhyItMatters = profile.WhyItMatters,
                                                          OperatorAction = profile.OperatorAction,
                                                          Evidence = evidenceSummary,
                                                          RawDetails = sample.Details };
            }
        }

        private static IEnumerable<OperatorBehaviorChain>
        BuildBehaviorChains(IReadOnlyList<OperatorEvidencePacket> evidence)
        {
            foreach (IGrouping<string, OperatorEvidencePacket> group in evidence
                         .GroupBy(static x => $"{x.CategoryKey}|{x.Actor}|{x.Target}", StringComparer.OrdinalIgnoreCase)
                         .OrderByDescending(static x => x.Max(y => SeverityScore(y.Severity)))
                         .ThenByDescending(static x => x.Count())
                         .ThenByDescending(static x => x.Max(y => y.TimestampUtc))
                         .Take(40))
            {
                OperatorEvidencePacket sample = group.OrderByDescending(static x => SeverityScore(x.Severity))
                                                    .ThenByDescending(static x => x.TimestampUtc)
                                                    .First();

                int score = Math.Min(100, SeverityScore(sample.Severity) + Math.Min(20, group.Count() * 2));
                yield return new OperatorBehaviorChain { Name = sample.Category,
                                                         Severity = RiskLabel(score),
                                                         Score = score,
                                                         Actor = sample.Actor,
                                                         Target = sample.Target,
                                                         Tactic = sample.Tactic,
                                                         Technique = sample.Technique,
                                                         TechniqueId = sample.TechniqueId,
                                                         Verdict = BuildChainVerdict(sample, group.Count()),
                                                         Summary = BuildChainSummary(sample, group.Count()),
                                                         NextStep = sample.OperatorAction,
                                                         EvidenceCount = group.Count(),
                                                         FirstSeenUtc = group.Min(static x => x.TimestampUtc),
                                                         LastSeenUtc = group.Max(static x => x.TimestampUtc) };
            }
        }

        private static IEnumerable<OperatorTimelineItem> BuildTimeline(IReadOnlyList<CaseEvent> events)
        {
            foreach (CaseEvent item in events.OrderBy(static x => x.TimestampUtc)
                         .ThenBy(static x => x.Stream, StringComparer.OrdinalIgnoreCase)
                         .Take(MaxTimelineItems))
            {
                yield return new OperatorTimelineItem { TimestampUtc = item.TimestampUtc,
                                                        Stream = item.Stream,
                                                        Severity = item.Severity,
                                                        Event = item.Event,
                                                        Actor = item.Actor,
                                                        Target = item.Target,
                                                        Summary =
                                                            FirstNonEmpty(item.Detection, item.Summary, item.Event),
                                                        Details = FirstNonEmpty(item.Details, item.Summary) };
            }
        }

        private static IEnumerable<OperatorIocItem> BuildIocs(IReadOnlyList<CaseEvent> events)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (CaseEvent item in events.OrderByDescending(static x => SeverityScore(x.Severity))
                         .ThenByDescending(static x => x.TimestampUtc)
                         .Take(1500))
            {
                foreach (OperatorIocItem ioc in ExtractIocs(item))
                {
                    string key = $"{ioc.Type}|{ioc.Value}";
                    if (!seen.Add(key))
                    {
                        continue;
                    }

                    yield return ioc;
                    if (seen.Count >= MaxIocs)
                    {
                        yield break;
                    }
                }
            }
        }

        private static IEnumerable<OperatorIocItem> ExtractIocs(CaseEvent item)
        {
            string text = Trim($"{item.Summary} {item.Details}", MaxRawDetailChars);
            if (string.IsNullOrWhiteSpace(text))
            {
                yield break;
            }

            foreach (Match match in FilePathRegex.Matches(text).Cast<Match>().Take(12))
            {
                yield return NewIoc("File", match.Value.TrimEnd('.', ',', ';'), item);
            }

            foreach (Match match in RegistryPathRegex.Matches(text).Cast<Match>().Take(12))
            {
                yield return NewIoc("Registry", match.Value.TrimEnd('.', ',', ';'), item);
            }

            foreach (Match match in Ipv4Regex.Matches(text).Cast<Match>().Take(12))
            {
                yield return NewIoc("IPv4", match.Value, item);
            }

            foreach (Match match in HashRegex.Matches(text).Cast<Match>().Take(12))
            {
                yield return NewIoc("Hash", match.Value, item);
            }

            foreach (Match match in DomainRegex.Matches(text).Cast<Match>().Take(12))
            {
                string value = match.Value.TrimEnd('.', ',', ';').ToLowerInvariant();
                if (ShouldSkipDomain(value))
                {
                    continue;
                }

                yield return NewIoc("Domain", value, item);
            }
        }

        private static OperatorIocItem NewIoc(string type, string value, CaseEvent item) => new() {
            Type = type, Value = value, Source = item.Stream,
            Confidence = type.Equals("Domain", StringComparison.OrdinalIgnoreCase) ? "Medium" : "High",
            Context = FirstNonEmpty(item.Detection, item.Event)
        };

        private static IEnumerable<OperatorHealthItem> BuildHealthItems(IEnumerable<DiagnosticsStateEntry>? diagnostics)
        {
            IReadOnlyList<DiagnosticsStateEntry> entries =
                diagnostics == null ? Array.Empty<DiagnosticsStateEntry>() : diagnostics.ToList();
            if (entries.Count == 0)
            {
                yield return new OperatorHealthItem {
                    Status = "Unknown", Component = "Diagnostics snapshot",
                    Value = "No interface health snapshot was attached to this case.",
                    OperatorImpact =
                        "Capture evidence may still be valid, but instrumentation trust cannot be assessed here."
                };
                yield break;
            }

            foreach (DiagnosticsStateEntry entry in entries
                         .OrderByDescending(static x => HealthRank(HealthStatus(x.Value)))
                         .ThenBy(static x => x.Key, StringComparer.OrdinalIgnoreCase)
                         .Take(120))
            {
                string status = HealthStatus(entry.Value);
                yield return new OperatorHealthItem { Status = status, Component = entry.Key, Value = entry.Value,
                                                      OperatorImpact = HealthImpact(entry.Key, entry.Value, status) };
            }
        }

        private static IEnumerable<OperatorTuningHint> BuildTuningHints(IReadOnlyList<OperatorEvidencePacket> evidence,
                                                                        IReadOnlyList<CaseEvent> events,
                                                                        IReadOnlyList<OperatorHealthItem> health)
        {
            foreach (IGrouping<string, OperatorEvidencePacket> group in evidence
                         .GroupBy(static x => x.Detection, StringComparer.OrdinalIgnoreCase)
                         .Where(static x => x.Count() >= 8)
                         .OrderByDescending(static x => x.Count())
                         .Take(8))
            {
                yield return new OperatorTuningHint {
                    Scope = group.Key,
                    Finding =
                        $"{group.Count().ToString(CultureInfo.InvariantCulture)} evidence packets share this detection title.",
                    Recommendation =
                        "Fold repeats into a behavior chain and keep the newest/highest severity packet visible.",
                    Risk = "High volume can hide the one occurrence that explains actor, target, or first execution."
                };
            }

            foreach (IGrouping<string, CaseEvent> streamGroup in events
                         .GroupBy(static x => x.Stream, StringComparer.OrdinalIgnoreCase)
                         .Where(static x => x.Count() > 400)
                         .OrderByDescending(static x => x.Count())
                         .Take(5))
            {
                yield return new OperatorTuningHint {
                    Scope = streamGroup.Key,
                    Finding =
                        $"{streamGroup.Count().ToString(CultureInfo.InvariantCulture)} timeline records were present in this stream.",
                    Recommendation =
                        "Use stream filters for triage and pivot to evidence packets for high-signal context.",
                    Risk = "Large streams are useful for replay, but poor defaults make analysts hunt through noise."
                };
            }

            foreach (OperatorHealthItem item in health.Where(static x => IsProblemStatus(x.Status)).Take(8))
            {
                yield return new OperatorTuningHint {
                    Scope = item.Component, Finding = item.Value,
                    Recommendation = "Resolve this health state before trusting absence-of-signal conclusions.",
                    Risk = item.OperatorImpact
                };
            }

            if (evidence.Count == 0)
            {
                yield return new OperatorTuningHint {
                    Scope = "Evidence", Finding = "No detection evidence packets were built from the current snapshot.",
                    Recommendation =
                        "Confirm capture is attached, target is resumed, and controller/driver logs are writable.",
                    Risk = "Operators cannot distinguish a quiet process from broken instrumentation."
                };
            }
        }

        private static IEnumerable<OperatorReplayDiffItem>
        BuildReplayDiffs(IReadOnlyList<OperatorBehaviorChain> chains, IReadOnlyList<OperatorEvidencePacket> evidence,
                         IReadOnlyList<OperatorTimelineItem> timeline, IReadOnlyList<OperatorIocItem> iocs,
                         IReadOnlyList<OperatorHealthItem> health)
        {
            yield return new OperatorReplayDiffItem {
                Scope = "Timeline replay",
                Current = $"{timeline.Count.ToString(CultureInfo.InvariantCulture)} ordered timeline items",
                Baseline = "No comparison session selected",
                Interpretation =
                    "This case can be replayed from first to last observed event; baseline diff wiring is still a separate saved-session workflow."
            };

            yield return new OperatorReplayDiffItem {
                Scope = "Behavior chains",
                Current =
                    $"{chains.Count.ToString(CultureInfo.InvariantCulture)} chain(s), {evidence.Count.ToString(CultureInfo.InvariantCulture)} evidence packet(s)",
                Baseline = "No comparison session selected",
                Interpretation = "Use chain count and top severity as the stable operator summary for repeat runs."
            };

            yield return new OperatorReplayDiffItem {
                Scope = "IOC set", Current = $"{iocs.Count.ToString(CultureInfo.InvariantCulture)} extracted IOC(s)",
                Baseline = "No comparison session selected",
                Interpretation = "Export this set from the report tab when the run should seed external enrichment."
            };

            yield return new OperatorReplayDiffItem {
                Scope = "Instrumentation trust",
                Current =
                    $"{health.Count(static x => IsProblemStatus(x.Status)).ToString(CultureInfo.InvariantCulture)} health issue(s)",
                Baseline = "No comparison session selected",
                Interpretation =
                    "Compare health first; detection diffs are weak if hooks, ETW, controller IPC, or driver queues were degraded."
            };
        }

        private static void AppendSetDiff(ICollection<OperatorReplayDiffItem> target, string scope,
                                          IEnumerable<string> currentValues, IEnumerable<string> baselineValues,
                                          string baselineLabel)
        {
            HashSet<string> current = currentValues.Where(static x => !string.IsNullOrWhiteSpace(x))
                                          .Select(static x => x.Trim())
                                          .ToHashSet(StringComparer.OrdinalIgnoreCase);
            HashSet<string> baseline = baselineValues.Where(static x => !string.IsNullOrWhiteSpace(x))
                                           .Select(static x => x.Trim())
                                           .ToHashSet(StringComparer.OrdinalIgnoreCase);

            List<string> added = current.Except(baseline, StringComparer.OrdinalIgnoreCase).Take(4).ToList();
            List<string> removed = baseline.Except(current, StringComparer.OrdinalIgnoreCase).Take(4).ToList();
            string addedText = added.Count == 0 ? "none new" : "new: " + string.Join("; ", added);
            string removedText = removed.Count == 0 ? "none absent" : "absent: " + string.Join("; ", removed);

            target.Add(new OperatorReplayDiffItem {
                Scope = scope, Current = $"{current.Count.ToString(CultureInfo.InvariantCulture)} item(s); {addedText}",
                Baseline =
                    $"{baselineLabel}: {baseline.Count.ToString(CultureInfo.InvariantCulture)} item(s); {removedText}",
                Interpretation =
                    added.Count == 0 && removed.Count == 0
                        ? "No set-level change from baseline."
                        : "Prioritize new high-severity behavior first, then explain absent baseline behavior."
            });
        }

        private static int ComputeRiskScore(IReadOnlyList<OperatorEvidencePacket> evidence,
                                            IReadOnlyList<OperatorBehaviorChain> chains,
                                            IReadOnlyList<OperatorHealthItem> health)
        {
            if (evidence.Count == 0 && chains.Count == 0)
            {
                return health.Any(static x => IsProblemStatus(x.Status)) ? 25 : 10;
            }

            int topSeverity = evidence.Select(static x => SeverityScore(x.Severity)).DefaultIfEmpty(0).Max();
            int chainBonus = Math.Min(25, chains.Count * 5);
            int volumeBonus = Math.Min(15, evidence.Count / 4);
            int credentialBonus =
                evidence.Any(static x => x.CategoryKey.Equals("credential-access", StringComparison.OrdinalIgnoreCase))
                    ? 15
                    : 0;
            int injectionBonus =
                evidence.Any(static x => x.CategoryKey.Equals("process-injection", StringComparison.OrdinalIgnoreCase))
                    ? 10
                    : 0;
            int healthPenalty = Math.Min(10, health.Count(static x => IsProblemStatus(x.Status)) * 2);
            return Math.Clamp(topSeverity + chainBonus + volumeBonus + credentialBonus + injectionBonus - healthPenalty,
                              0, 100);
        }

        private static BehaviorProfile Classify(CaseEvent item)
        {
            string haystack = $"{item.Detection} {item.Event} {item.Summary} {item.Details}".ToUpperInvariant();

            if (ContainsAny(haystack, "SYSCALL_NUMBER_EXTRACTION", "NTDLL_DIRECT_SYSCALL_EXTRACTION"))
            {
                return new BehaviorProfile(
                    "syscall-extraction", "Syscall number extraction", "Defense Evasion",
                    "Native API direct syscall preparation", "T1106",
                    "The process inspected ntdll syscall stubs or export metadata to recover syscall numbers.",
                    "This is a common setup step before bypassing usermode API hooks with direct syscalls.",
                    "Inspect the caller memory region, correlate with later direct syscalls, and preserve the ntdll pages read.",
                    "High", "High");
            }

            if (ContainsAny(haystack, "DIRECT_SYSCALL"))
            {
                return new BehaviorProfile(
                    "direct-syscall", "Direct syscall bypass", "Defense Evasion", "Native API direct syscall", "T1106",
                    "The process issued or prepared a syscall path outside the normal hooked ntdll API surface.",
                    "Direct syscalls are used to bypass usermode monitoring and can hide process, memory, or thread operations.",
                    "Pivot to actor, target, syscall name, and the private/unknown caller region that issued it.",
                    "High", "High");
            }

            if (ContainsAny(haystack, "CREDENTIAL", "LSASS", "TOKEN_ACCESS", "SEDEBUG", "PRIVILEGED_ACCESS"))
            {
                return new BehaviorProfile(
                    "credential-access", "Credential or privileged process access", "Credential Access",
                    "OS credential or token access", "T1003/T1134",
                    "The actor requested sensitive access to a credential-bearing or privileged process.",
                    "This can indicate credential theft, token theft, or preparation for privileged process tampering.",
                    "Open handle evidence, confirm requested access mask, and inspect memory reads/writes after the handle.",
                    "High", "Critical");
            }

            if (ContainsAny(haystack, "REMOTE_APC", "REMOTE_THREAD", "THREAD_HIJACK", "THREAD_CONTEXT", "MANUAL_MAP",
                            "HOLLOW", "INJECTION", "CROSS_PROCESS_WRITE", "RWX", "WRITEPROCESS", "VIRTUALALLOCEX",
                            "PRIVATE_EXEC"))
            {
                return new BehaviorProfile(
                    "process-injection", "Process injection or hollowing", "Defense Evasion", "Process injection",
                    "T1055",
                    "The actor performed cross-process memory, thread, APC, or private executable memory activity.",
                    "These actions commonly transfer execution into another process without a normal image load.",
                    "Correlate allocation, write, protection flip, thread start, and image attribution around the target.",
                    "High", "High");
            }

            if (ContainsAny(haystack, "AMSI", "ETW", "HOOK", "IAT", "EAT", "NTDLL_IMAGE_PATH", "MULTIPLE_NTDLL",
                            "INSTRUMENTATION_CALLBACK"))
            {
                return new BehaviorProfile(
                    "sensor-tamper", "Sensor or runtime tampering", "Defense Evasion", "Impair defenses", "T1562.001",
                    "The process touched instrumentation, hook, ntdll, AMSI, ETW, or callback state.",
                    "Tampering can make other telemetry incomplete, so absence of later evidence may not be trustworthy.",
                    "Review integrity health, caller origin, modified pages, and any immediate drop in telemetry volume.",
                    "Medium", "High");
            }

            if (ContainsAny(haystack, "ANTI_DEBUG", "DEBUG_OBJECT", "DEBUG_PORT", "ANTI_VM", "SANDBOX",
                            "HARDWARE_BREAKPOINT", "PROCESS_QUERY"))
            {
                return new BehaviorProfile(
                    "anti-analysis", "Anti-analysis behavior", "Defense Evasion",
                    "Virtualization, sandbox, or debugger discovery", "T1497/T1622",
                    "The process queried or manipulated state commonly used to detect analysis environments.",
                    "Anti-analysis can explain dormant behavior, delayed execution, or targeted evasion of the lab.",
                    "Check timing, parent process, VM indicators, debugger queries, and whether behavior changed after query results.",
                    "Medium", "Medium");
            }

            if (ContainsAny(haystack, "REGISTRY", "RUN_KEY", "RUNKEY", "SERVICE", "STARTUP", "SCHEDULED_TASK",
                            "WMI_PERSISTENCE"))
            {
                return new BehaviorProfile(
                    "persistence", "Persistence modification", "Persistence",
                    "Registry, service, startup, or WMI persistence", "T1547.001/T1543.003",
                    "The process wrote or queried locations commonly used to survive reboot or user logon.",
                    "Persistence gives operators concrete remediation work and often yields strong IOCs.",
                    "Export the key/path, compare old and new value, and capture the responsible actor chain.",
                    "Medium", "High");
            }

            if (ContainsAny(haystack, "POWERSHELL", "LOLBIN", "SCRIPT", "MSHTA", "RUNDLL32", "REGSVR32", "WMI", "COM_"))
            {
                return new BehaviorProfile(
                    "living-off-land", "Living-off-the-land execution", "Execution",
                    "Command, script, WMI, COM, or signed binary proxy execution", "T1059/T1218/T1047",
                    "The process used an interpreter, automation surface, or trusted Windows binary in an execution chain.",
                    "This often hides malicious logic behind expected system tools and makes command-line context valuable.",
                    "Capture command line, parent process, loaded modules, and any child process graph edge.", "Medium",
                    "Medium");
            }

            if (ContainsAny(haystack, "NETWORK", "DNS", "HTTP", "HTTPS", "TLS", "SOCKET", "CONNECT", "C2"))
            {
                return new BehaviorProfile(
                    "network-activity", "Network activity", "Command and Control",
                    "Network connection or name resolution", "T1071/T1571",
                    "The process produced network-relevant telemetry.",
                    "Network IOCs are useful for containment, enrichment, and repeat-run comparison.",
                    "Export host/IP indicators and correlate with process ancestry and payload staging.", "Medium",
                    "Medium");
            }

            if (ContainsAny(haystack, "MEMORY_", "HIGH_ENTROPY", "UNPACK", "PACKER", "SECTION", "IMAGE_LOAD",
                            "DLL_LOAD", "HEADERLESS"))
            {
                return new BehaviorProfile(
                    "memory-anomaly", "Suspicious memory or image behavior", "Defense Evasion",
                    "Packed, unpacked, or non-standard image execution", "T1027",
                    "The process showed memory or module characteristics associated with unpacking or non-standard loading.",
                    "These findings can explain why static file reputation does not match runtime behavior.",
                    "Pivot to memory region attribution, dumped bytes, module path, and entropy changes.", "Medium",
                    "Medium");
            }

            if (ContainsAny(haystack, "FILE_", "CREATEFILE", "WRITEFILE", "DELETEFILE", "TEMP", "APPDATA"))
            {
                return new BehaviorProfile(
                    "filesystem-activity", "Filesystem staging", "Execution", "File creation, staging, or cleanup",
                    "T1074/T1105",
                    "The process touched file paths that may represent payload staging, configuration, or cleanup.",
                    "Filesystem artifacts are practical evidence for triage, reproduction, and IOC export.",
                    "Inspect path, signer, hash, write order, and whether execution followed creation.", "Low",
                    "Medium");
            }

            if (ContainsAny(haystack, "PARENT_PID", "PROCESS_START", "PROCESS_CREATE", "CHILD_PROCESS"))
            {
                return new BehaviorProfile(
                    "process-lineage", "Process lineage anomaly", "Execution",
                    "Process creation or parent-child relationship", "N/A",
                    "The process tree contains lineage or process creation evidence relevant to the run.",
                    "Lineage tells operators what started the behavior and where to pivot next.",
                    "Open the child process graph and inspect command line, parent PID, and sibling activity.", "Low",
                    "Medium");
            }

            return new BehaviorProfile(
                "observed-behavior", "Observed suspicious behavior", "Discovery", "Runtime telemetry correlation",
                "N/A",
                "The process produced detection telemetry that does not match a more specific case category yet.",
                "Unclassified evidence still matters when it clusters with higher-confidence behavior.",
                "Review raw details, actor, target, source stream, and surrounding timeline events.", "Low", "Low");
        }

        private static string BuildEvidenceSummary(CaseEvent sample, int occurrences)
        {
            var parts =
                new List<string> { $"occurrences={occurrences.ToString(CultureInfo.InvariantCulture)}",
                                   $"stream={sample.Stream}", $"source={sample.Source}", $"event={sample.Event}" };

            if (!string.IsNullOrWhiteSpace(sample.Summary))
            {
                parts.Add($"summary={sample.Summary}");
            }

            if (!string.IsNullOrWhiteSpace(sample.Details))
            {
                parts.Add($"details={Trim(sample.Details, 700)}");
            }

            return string.Join(" | ", parts);
        }

        private static string BuildChainVerdict(OperatorEvidencePacket sample, int evidenceCount)
        {
            string scope = HasExternalTarget(sample.ActorPid, sample.TargetPid) ? $"{sample.Actor} to {sample.Target}"
                                                                                : sample.Actor;
            return $"{sample.Category} observed in {scope} with {evidenceCount.ToString(CultureInfo.InvariantCulture)} supporting packet(s).";
        }

        private static string BuildChainSummary(OperatorEvidencePacket sample, int evidenceCount) =>
            $"{sample.WhatHappened} Evidence count={evidenceCount.ToString(CultureInfo.InvariantCulture)}; top detection={sample.Detection}.";

        private static string BuildVerdict(IReadOnlyList<OperatorBehaviorChain> chains,
                                           IReadOnlyList<OperatorEvidencePacket> evidence,
                                           IReadOnlyList<OperatorHealthItem> health)
        {
            if (evidence.Count == 0)
            {
                return health.Any(static x => IsProblemStatus(x.Status))
                           ? "Instrumentation has health issues and no detection evidence was available."
                           : "No detection evidence was available in the current snapshot.";
            }

            OperatorBehaviorChain top = chains.OrderByDescending(static x => x.Score).FirstOrDefault() ??
                                        new OperatorBehaviorChain { Name = "Suspicious runtime behavior" };
            return $"{top.Name} is the lead behavior. {evidence.Count.ToString(CultureInfo.InvariantCulture)} evidence packet(s) were extracted for operator review.";
        }

        private static string BuildSummary(IReadOnlyList<OperatorBehaviorChain> chains,
                                           IReadOnlyList<OperatorEvidencePacket> evidence,
                                           IReadOnlyList<OperatorIocItem> iocs,
                                           IReadOnlyList<OperatorHealthItem> health)
        {
            string lead = chains.Count == 0 ? "No behavior chain has been established yet." : chains[0].Summary;
            string healthText =
                health.Any(static x => IsProblemStatus(x.Status))
                    ? $"{health.Count(static x => IsProblemStatus(x.Status)).ToString(CultureInfo.InvariantCulture)} instrumentation health issue(s) need review."
                    : "Instrumentation health did not report blocking issues.";
            return $"{lead} Evidence packets={evidence.Count.ToString(CultureInfo.InvariantCulture)}, IOCs={iocs.Count.ToString(CultureInfo.InvariantCulture)}. {healthText}";
        }

        private static string BuildSubtitle(string rootProcess, int detections, int timelineCount) =>
            $"{rootProcess} | detections={detections.ToString(CultureInfo.InvariantCulture)} | timeline={timelineCount.ToString(CultureInfo.InvariantCulture)}";

        private static string BuildReportText(OperatorCaseReport report)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Operator Case: {report.RootProcess}");
            sb.AppendLine($"Generated: {report.GeneratedLabel}");
            sb.AppendLine($"Risk: {report.RiskLabel} ({report.RiskScore.ToString(CultureInfo.InvariantCulture)}/100)");
            sb.AppendLine($"Verdict: {report.Verdict}");
            sb.AppendLine();
            sb.AppendLine("Summary");
            sb.AppendLine(report.Summary);
            sb.AppendLine();

            sb.AppendLine("Behavior Chains");
            foreach (OperatorBehaviorChain chain in report.BehaviorChains.Take(12))
            {
                sb.AppendLine($"- [{chain.Severity}] {chain.Name}: {chain.Actor} -> {chain.Target}");
                sb.AppendLine($"  Tactic/Technique: {chain.Tactic} / {chain.Technique} {chain.TechniqueId}".TrimEnd());
                sb.AppendLine($"  Verdict: {chain.Verdict}");
            }

            if (report.BehaviorChains.Count == 0)
            {
                sb.AppendLine("- None");
            }

            sb.AppendLine();
            sb.AppendLine("Evidence Packets");
            foreach (OperatorEvidencePacket evidence in report.EvidencePackets.Take(20))
            {
                sb.AppendLine($"- [{evidence.Severity}] {evidence.TimeLabel} {evidence.Detection}");
                sb.AppendLine($"  Actor: {evidence.Actor}");
                sb.AppendLine($"  Target: {evidence.Target}");
                sb.AppendLine($"  Why it matters: {evidence.WhyItMatters}");
            }

            if (report.EvidencePackets.Count == 0)
            {
                sb.AppendLine("- None");
            }

            sb.AppendLine();
            sb.AppendLine("IOCs");
            foreach (OperatorIocItem ioc in report.Iocs.Take(40))
            {
                sb.AppendLine($"- {ioc.Type}: {ioc.Value} ({ioc.Source})");
            }

            if (report.Iocs.Count == 0)
            {
                sb.AppendLine("- None");
            }

            sb.AppendLine();
            sb.AppendLine("Instrumentation Health");
            foreach (OperatorHealthItem item in report.HealthItems.Where(static x => IsProblemStatus(x.Status))
                         .Take(20))
            {
                sb.AppendLine($"- [{item.Status}] {item.Component}: {item.Value}");
            }

            if (!report.HealthItems.Any(static x => IsProblemStatus(x.Status)))
            {
                sb.AppendLine("- No blocking health issues surfaced in the snapshot.");
            }

            sb.AppendLine();
            sb.AppendLine("Tuning Recommendations");
            foreach (OperatorTuningHint hint in report.TuningHints.Take(12))
            {
                sb.AppendLine($"- {hint.Scope}: {hint.Recommendation}");
            }

            if (report.TuningHints.Count == 0)
            {
                sb.AppendLine("- None");
            }

            sb.AppendLine();
            sb.AppendLine("Replay / Diff");
            foreach (OperatorReplayDiffItem diff in report.ReplayDiffs.Take(12))
            {
                sb.AppendLine($"- {diff.Scope}: current={diff.Current}; baseline={diff.Baseline}");
                sb.AppendLine($"  {diff.Interpretation}");
            }

            return sb.ToString();
        }

        private static string EvidenceKey(CaseEvent item) =>
            $"{item.Detection}|{item.Actor}|{item.Target}|{item.Source}|{Trim(item.Summary, 180)}";

        private static string CleanEntity(string value, uint pid)
        {
            if (!string.IsNullOrWhiteSpace(value) && !value.Equals("-", StringComparison.Ordinal))
            {
                return value.Trim();
            }

            return pid == 0 ? "-" : OperatorDetectionFormatter.FormatProcessIdentity(pid);
        }

        private static uint TryParsePid(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return 0;
            }

            string digits = new(value.Where(char.IsDigit).ToArray());
            return uint.TryParse(digits, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint pid) ? pid : 0;
        }

        private static string NormalizeSeverity(string severity)
        {
            string value = (severity ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(value))
            {
                return "Info";
            }

            return value switch { _ when value.Equals("Critical", StringComparison.OrdinalIgnoreCase) => "Critical",
                                  _ when value.Equals("High", StringComparison.OrdinalIgnoreCase) => "High",
                                  _ when value.Equals("Medium", StringComparison.OrdinalIgnoreCase) => "Medium",
                                  _ when value.Equals("Low", StringComparison.OrdinalIgnoreCase) => "Low",
                                  _ when value.Equals("Info", StringComparison.OrdinalIgnoreCase) => "Info",
                                  _ => value };
        }

        private static string MaxSeverity(string a, string b) => SeverityScore(a) >= SeverityScore(b)
                                                                     ? NormalizeSeverity(a)
                                                                     : NormalizeSeverity(b);

        private static int SeverityScore(string severity)
        {
            if (severity.Equals("Critical", StringComparison.OrdinalIgnoreCase))
            {
                return 95;
            }

            if (severity.Equals("High", StringComparison.OrdinalIgnoreCase))
            {
                return 80;
            }

            if (severity.Equals("Medium", StringComparison.OrdinalIgnoreCase))
            {
                return 55;
            }

            if (severity.Equals("Low", StringComparison.OrdinalIgnoreCase))
            {
                return 30;
            }

            if (severity.Equals("Info", StringComparison.OrdinalIgnoreCase))
            {
                return 15;
            }

            return 10;
        }

        private static string RiskLabel(int score)
        {
            if (score >= 90)
            {
                return "Critical";
            }

            if (score >= 70)
            {
                return "High";
            }

            if (score >= 45)
            {
                return "Medium";
            }

            if (score >= 20)
            {
                return "Low";
            }

            return "Info";
        }

        private static string HealthStatus(string value)
        {
            string text = (value ?? string.Empty).Trim();
            if (ContainsAny(text, "DISABLED IN ANALYST INTERFACE"))
            {
                return "Info";
            }

            if (ContainsAny(text, "FAILED", "ERROR", "ERR=", "TAMPERED", "MISSING", "ACCESS DENIED", "STOPPED",
                            "UNAVAILABLE", "IOCTL APPEND FAILED", "ETW APPEND FAILED"))
            {
                return "Issue";
            }

            if (ContainsAny(text, "UNKNOWN", "INACTIVE", "AWAITING", "DISABLED", "SKIPPED", "UNSUPPORTED"))
            {
                return "Warning";
            }

            if (ContainsAny(text, "OK", "READY", "LIVE", "ACTIVE", "ENABLED", "FOUND", "OPEN", "INITIALIZED"))
            {
                return "OK";
            }

            return "Info";
        }

        private static int HealthRank(string status)
        {
            if (status.Equals("Issue", StringComparison.OrdinalIgnoreCase))
            {
                return 3;
            }

            if (status.Equals("Warning", StringComparison.OrdinalIgnoreCase))
            {
                return 2;
            }

            if (status.Equals("Info", StringComparison.OrdinalIgnoreCase))
            {
                return 1;
            }

            return 0;
        }

        private static bool
        IsProblemStatus(string status) => status.Equals("Issue", StringComparison.OrdinalIgnoreCase) ||
                                          status.Equals("Warning", StringComparison.OrdinalIgnoreCase) ||
                                          status.Equals("Unknown", StringComparison.OrdinalIgnoreCase);

        private static bool HasAttachedHealthSnapshot(OperatorCaseReport report) =>
            !(report.HealthItems.Count == 1 &&
              report.HealthItems[0].Status.Equals("Unknown", StringComparison.OrdinalIgnoreCase) &&
              report.HealthItems[0].Component.Equals("Diagnostics snapshot", StringComparison.OrdinalIgnoreCase));

        private static string HealthImpact(string key, string value, string status)
        {
            string text = $"{key} {value}";
            if (status.Equals("OK", StringComparison.OrdinalIgnoreCase))
            {
                return "No immediate action needed.";
            }

            if (ContainsAny(text, "HOOK", "AMSI", "ETW INTEGRITY", "TAMPER"))
            {
                return "Instrumentation integrity may be degraded; validate related detections before closing the case.";
            }

            if (ContainsAny(text, "CONTROLLER", "IPC", "PIPE", "RING"))
            {
                return "Controller communication problems can block attach, launch gate release, or telemetry delivery.";
            }

            if (ContainsAny(text, "DRIVER", "QUEUE", "IOCTL"))
            {
                return "Driver or queue degradation can cause event loss or stale state.";
            }

            if (ContainsAny(text, "VIRTUALIZATION"))
            {
                return "Virtualization diagnostics may be stale until this state is resolved.";
            }

            return "Review this state before trusting absence of behavior.";
        }

        private static bool ShouldSkipDomain(string value)
        {
            string[] suffixes = { ".dll",    ".exe",      ".sys",   ".pdb",     ".json",      ".xml",
                                  ".config", ".manifest", ".local", ".windows", ".microsoft", ".net9.0-windows" };
            return value.Length < 4 || suffixes.Any(value.EndsWith);
        }

        private static bool
        HasExternalTarget(uint actorPid, uint targetPid) => actorPid != 0 && targetPid != 0 && actorPid != targetPid;

        private static bool ContainsAny(string value, params string[] needles)
        {
            foreach (string needle in needles)
            {
                if (value.Contains(needle, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static string FirstNonEmpty(params string[] values)
        {
            foreach (string value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value.Trim();
                }
            }

            return string.Empty;
        }

        private static string Trim(string value, int limit)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            string trimmed = value.Trim();
            return trimmed.Length <= limit ? trimmed : trimmed[..limit] + "...";
        }

        private sealed class CaseEvent
        {
            public string Stream { get; set; } = string.Empty;
            public DateTime TimestampUtc { get; set; }
            public string Event { get; set; } = string.Empty;
            public string Severity { get; set; } = string.Empty;
            public string Detection { get; set; } = string.Empty;
            public string Actor { get; set; } = string.Empty;
            public string Target { get; set; } = string.Empty;
            public uint ActorPid { get; set; }
            public uint TargetPid { get; set; }
            public string Source { get; set; } = string.Empty;
            public string Summary { get; set; } = string.Empty;
            public string Details { get; set; } = string.Empty;
        }

        private sealed class BehaviorProfile
        {
            public BehaviorProfile(string key, string chainName, string tactic, string technique, string techniqueId,
                                   string whatHappened, string whyItMatters, string operatorAction, string confidence,
                                   string severityFloor)
            {
                Key = key;
                ChainName = chainName;
                Tactic = tactic;
                Technique = technique;
                TechniqueId = techniqueId;
                WhatHappened = whatHappened;
                WhyItMatters = whyItMatters;
                OperatorAction = operatorAction;
                Confidence = confidence;
                SeverityFloor = severityFloor;
            }

            public string Key { get; }
            public string ChainName { get; }
            public string Tactic { get; }
            public string Technique { get; }
            public string TechniqueId { get; }
            public string WhatHappened { get; }
            public string WhyItMatters { get; }
            public string OperatorAction { get; }
            public string Confidence { get; }
            public string SeverityFloor { get; }
        }
    }
}
