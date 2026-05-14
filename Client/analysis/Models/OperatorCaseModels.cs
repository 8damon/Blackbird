using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace BlackbirdInterface
{
    internal sealed class OperatorCaseReport
    {
        public string Title { get; set; } = "Operator Case";
        public string Subtitle { get; set; } = string.Empty;
        public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
        public int RootPid { get; set; }
        public string RootProcess { get; set; } = string.Empty;
        public int RiskScore { get; set; }
        public string RiskLabel { get; set; } = "Unknown";
        public string Verdict { get; set; } = "No verdict";
        public string Summary { get; set; } = string.Empty;
        public int DetectionCount { get; set; }
        public int EvidenceCount { get; set; }
        public int TimelineCount { get; set; }
        public int IocCount { get; set; }
        public int HealthIssueCount { get; set; }
        public string ReportText { get; set; } = string.Empty;
        public List<OperatorBehaviorChain> BehaviorChains { get; set; } = new();
        public List<OperatorEvidencePacket> EvidencePackets { get; set; } = new();
        public List<OperatorTimelineItem> Timeline { get; set; } = new();
        public List<OperatorIocItem> Iocs { get; set; } = new();
        public List<OperatorHealthItem> HealthItems { get; set; } = new();
        public List<OperatorTuningHint> TuningHints { get; set; } = new();
        public List<OperatorReplayDiffItem> ReplayDiffs { get; set; } = new();

        public string GeneratedLabel =>
            GeneratedAtUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);

        public string IocText =>
            Iocs.Count == 0 ? string.Empty : string.Join(Environment.NewLine, Iocs.Select(x => $"{x.Type}: {x.Value}"));
    }

    internal sealed class OperatorBehaviorChain
    {
        public string Name { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public int Score { get; set; }
        public string Actor { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public string Tactic { get; set; } = string.Empty;
        public string Technique { get; set; } = string.Empty;
        public string TechniqueId { get; set; } = string.Empty;
        public string Verdict { get; set; } = string.Empty;
        public string Summary { get; set; } = string.Empty;
        public string NextStep { get; set; } = string.Empty;
        public int EvidenceCount { get; set; }
        public DateTime FirstSeenUtc { get; set; }
        public DateTime LastSeenUtc { get; set; }

        public string TimeRange => FirstSeenUtc == default || LastSeenUtc == default
                                       ? "-"
                                       : $"{FirstSeenUtc:HH:mm:ss.fff} - {LastSeenUtc:HH:mm:ss.fff}";
    }

    internal sealed class OperatorEvidencePacket
    {
        public string CategoryKey { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public DateTime TimestampUtc { get; set; }
        public string Detection { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string Confidence { get; set; } = string.Empty;
        public string Actor { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public uint ActorPid { get; set; }
        public uint TargetPid { get; set; }
        public string Stream { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string Tactic { get; set; } = string.Empty;
        public string Technique { get; set; } = string.Empty;
        public string TechniqueId { get; set; } = string.Empty;
        public string WhatHappened { get; set; } = string.Empty;
        public string WhyItMatters { get; set; } = string.Empty;
        public string OperatorAction { get; set; } = string.Empty;
        public string Evidence { get; set; } = string.Empty;
        public string RawDetails { get; set; } = string.Empty;

        public string TimeLabel =>
            TimestampUtc == default ? "-" : TimestampUtc.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture);

        public string Narrative => string.Join(
            Environment.NewLine + Environment.NewLine, new[] {
                $"Detection: {Detection}",
                $"Actor: {Actor}",
                $"Target: {Target}",
                $"Tactic: {Tactic}",
                $"Technique: {Technique} {TechniqueId}".TrimEnd(),
                $"What happened: {WhatHappened}",
                $"Why it matters: {WhyItMatters}",
                $"Operator action: {OperatorAction}",
                $"Evidence: {Evidence}",
                string.IsNullOrWhiteSpace(RawDetails)? string.Empty : $"Raw details: {RawDetails}"
            }
                                                           .Where(static x => !string.IsNullOrWhiteSpace(x)));
    }

    internal sealed class OperatorTimelineItem
    {
        public DateTime TimestampUtc { get; set; }
        public string Stream { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string Event { get; set; } = string.Empty;
        public string Actor { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public string Summary { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;

        public string TimeLabel =>
            TimestampUtc == default ? "-" : TimestampUtc.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture);
    }

    internal sealed class OperatorIocItem
    {
        public string Type { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string Confidence { get; set; } = string.Empty;
        public string Context { get; set; } = string.Empty;
    }

    internal sealed class OperatorHealthItem
    {
        public string Status { get; set; } = string.Empty;
        public string Component { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string OperatorImpact { get; set; } = string.Empty;
    }

    internal sealed class OperatorTuningHint
    {
        public string Scope { get; set; } = string.Empty;
        public string Finding { get; set; } = string.Empty;
        public string Recommendation { get; set; } = string.Empty;
        public string Risk { get; set; } = string.Empty;
    }

    internal sealed class OperatorReplayDiffItem
    {
        public string Scope { get; set; } = string.Empty;
        public string Current { get; set; } = string.Empty;
        public string Baseline { get; set; } = string.Empty;
        public string Interpretation { get; set; } = string.Empty;
    }
}
