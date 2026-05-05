using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace BlackbirdInterface
{
    internal enum SessionExportFormat
    {
        JsonLines,
        Csv,
        Cef,
        AttackCsv,
        DetectionJsonLines,
        DetectionCsv,
        DetectionCef,
        SplunkHecJson,
        ElasticEcsJsonLines
    }

    internal static class SessionExportService
    {
        private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

        internal static int Export(string path, SessionFileArchive archive, SessionExportFormat format)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("Export path is required.", nameof(path));
            }

            if (archive == null)
            {
                throw new ArgumentNullException(nameof(archive));
            }

            string? directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            List<SessionExportRecord> records =
                FlattenArchive(archive)
                    .Where(record => !IsDetectionOnlyFormat(format) || IsDetectionRecord(record))
                    .ToList();
            string tempPath = path + ".tmp";
            try
            {
                using var writer =
                    new StreamWriter(tempPath, false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                switch (format)
                {
                case SessionExportFormat.JsonLines:
                    WriteJsonLines(writer, records);
                    break;
                case SessionExportFormat.Csv:
                    WriteCsv(writer, records, includeAttackColumns: false);
                    break;
                case SessionExportFormat.Cef:
                    WriteCef(writer, records);
                    break;
                case SessionExportFormat.AttackCsv:
                    WriteCsv(writer, records, includeAttackColumns: true);
                    break;
                case SessionExportFormat.DetectionJsonLines:
                    WriteSiemJsonLines(writer, records);
                    break;
                case SessionExportFormat.DetectionCsv:
                    WriteCsv(writer, records, includeAttackColumns: true);
                    break;
                case SessionExportFormat.DetectionCef:
                    WriteCef(writer, records);
                    break;
                case SessionExportFormat.SplunkHecJson:
                    WriteSplunkHecJson(writer, records);
                    break;
                case SessionExportFormat.ElasticEcsJsonLines:
                    WriteElasticEcsJsonLines(writer, records);
                    break;
                default:
                    throw new InvalidOperationException($"Unsupported export format: {format}");
                }

                writer.Flush();

                if (File.Exists(path))
                {
                    File.Replace(tempPath, path, destinationBackupFileName: null, ignoreMetadataErrors: true);
                }
                else
                {
                    File.Move(tempPath, path);
                }

                return records.Count;
            }
            finally
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
        }

        private static IEnumerable<SessionExportRecord> FlattenArchive(SessionFileArchive archive)
        {
            foreach (SessionFileTab tab in archive.Tabs)
            {
                string tabTitle = string.IsNullOrWhiteSpace(tab.Title) ? $"PID {tab.Pid}" : tab.Title.Trim();

                foreach (TelemetryEvent ev in tab.Events.OrderBy(x => x.TimestampUtc))
                {
                    yield return new SessionExportRecord { TimestampUtc = ev.TimestampUtc,
                                                           Tab = tabTitle,
                                                           Pid = ev.PID != 0 ? ev.PID : tab.Pid,
                                                           Tid = ev.TID,
                                                           Stream = "timeline",
                                                           EventName = string.IsNullOrWhiteSpace(ev.SubType)
                                                                           ? ev.Group
                                                                           : $"{ev.Group}/{ev.SubType}",
                                                           Source = ev.ProcessName,
                                                           Summary = ev.Summary,
                                                           Details = ev.Details };
                }

                foreach (SessionExportRecord record in FlattenGroupedRows(tabTitle, tab.Pid, "etw", tab.EtwGroups))
                {
                    yield return record;
                }

                foreach (SessionExportRecord record in FlattenGroupedRows(tabTitle, tab.Pid, "heuristics",
                                                                          tab.HeuristicsGroups))
                {
                    yield return record;
                }

                foreach (SessionExportRecord record in FlattenGroupedRows(tabTitle, tab.Pid, "filesystem",
                                                                          tab.FilesystemGroups))
                {
                    yield return record;
                }

                foreach (SessionExportRecord record in FlattenGroupedRows(tabTitle, tab.Pid, "relations",
                                                                          tab.ProcessRelationsGroups))
                {
                    yield return record;
                }
            }
        }

        private static bool IsDetectionOnlyFormat(SessionExportFormat format) =>
            format is SessionExportFormat.DetectionJsonLines or SessionExportFormat.DetectionCsv or SessionExportFormat
                .DetectionCef or SessionExportFormat.SplunkHecJson or SessionExportFormat.ElasticEcsJsonLines;

        private static bool IsDetectionRecord(SessionExportRecord record)
        {
            if (record.Stream.Equals("heuristics", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (!record.Stream.Equals("etw", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string combined = $"{record.EventName} {record.Detection} {record.Summary} {record.Details}";
            return combined.Contains("Detection", StringComparison.OrdinalIgnoreCase) ||
                   combined.Contains("detection=", StringComparison.OrdinalIgnoreCase) ||
                   combined.Contains("engine=sigma", StringComparison.OrdinalIgnoreCase) ||
                   combined.Contains("engine=yara", StringComparison.OrdinalIgnoreCase);
        }

        private static IEnumerable<SessionExportRecord>
        FlattenGroupedRows(string tabTitle, int defaultPid, string stream, IEnumerable<GroupedEventRow> rows)
        {
            foreach (GroupedEventRow row in rows.OrderBy(x => x.LastSeenUtc))
            {
                if (row.Details.Count == 0)
                {
                    yield return new SessionExportRecord { TimestampUtc = row.LastSeenUtc,
                                                           Tab = tabTitle,
                                                           Pid = defaultPid,
                                                           Stream = stream,
                                                           EventName = row.Event,
                                                           Severity = row.Severity,
                                                           Detection = row.Detection,
                                                           Summary = row.GroupKey,
                                                           Hits = Math.Max(1, row.Hits) };
                    continue;
                }

                foreach (GroupedEventDetailRow detail in row.Details.OrderBy(x => x.TimestampUtc))
                {
                    yield return new SessionExportRecord {
                        TimestampUtc = detail.TimestampUtc,
                        Tab = tabTitle,
                        Pid = detail.ActorPid != 0 ? unchecked((int)detail.ActorPid) : defaultPid,
                        Tid = TryParseInt(detail.EventTid),
                        Stream = stream,
                        EventName = string.IsNullOrWhiteSpace(detail.Event) ? row.Event : detail.Event,
                        Severity = detail.Severity,
                        Detection = detail.Detection,
                        Source = detail.Source,
                        Actor = detail.Actor,
                        Target = detail.Target,
                        ActorPid = detail.ActorPid,
                        TargetPid = detail.TargetPid,
                        Summary = $"{detail.Event} {detail.Detection}".Trim(),
                        Details = detail.Details,
                        Hits = Math.Max(1, detail.HitCount)
                    };
                }
            }
        }

        private static void WriteJsonLines(TextWriter writer, IEnumerable<SessionExportRecord> records)
        {
            foreach (SessionExportRecord record in records)
            {
                writer.WriteLine(JsonSerializer.Serialize(record, JsonOptions));
            }
        }

        private static void WriteSiemJsonLines(TextWriter writer, IEnumerable<SessionExportRecord> records)
        {
            foreach (SessionExportRecord record in records)
            {
                writer.WriteLine(JsonSerializer.Serialize(BuildSiemEvent(record), JsonOptions));
            }
        }

        private static void WriteSplunkHecJson(TextWriter writer, IEnumerable<SessionExportRecord> records)
        {
            foreach (SessionExportRecord record in records)
            {
                var hec = new Dictionary < string, object
                    ?> { ["time"] = ToUnixTimeSeconds(record.TimestampUtc), ["host"] = Environment.MachineName,
                         ["source"] = "BK", ["sourcetype"] = "BK:detection", ["event"] = BuildSiemEvent(record) };
                writer.WriteLine(JsonSerializer.Serialize(hec, JsonOptions));
            }
        }

        private static void WriteElasticEcsJsonLines(TextWriter writer, IEnumerable<SessionExportRecord> records)
        {
            foreach (SessionExportRecord record in records)
            {
                writer.WriteLine(JsonSerializer.Serialize(BuildElasticEcsEvent(record), JsonOptions));
            }
        }

        private static void WriteCsv(TextWriter writer, IEnumerable<SessionExportRecord> records,
                                     bool includeAttackColumns)
        {
            var headers = new List<string> { "timestamp_utc", "tab",      "pid",        "tid",     "stream",
                                             "event",         "severity", "detection",  "source",  "actor",
                                             "actor_pid",     "target",   "target_pid", "summary", "details" };

            if (includeAttackColumns)
            {
                headers.AddRange(new[] { "mitre_tactic", "mitre_technique_id", "mitre_technique",
                                         "mitre_subtechnique_id", "mitre_subtechnique" });
            }

            writer.WriteLine(string.Join(",", headers.Select(EscapeCsv)));
            foreach (SessionExportRecord record in records)
            {
                var values = new List<string> {
                    record.TimestampUtc.ToString("O", CultureInfo.InvariantCulture),
                    record.Tab,
                    record.Pid.ToString(CultureInfo.InvariantCulture),
                    record.Tid.ToString(CultureInfo.InvariantCulture),
                    record.Stream,
                    record.EventName,
                    record.Severity,
                    record.Detection,
                    record.Source,
                    record.Actor,
                    record.ActorPid == 0 ? string.Empty : record.ActorPid.ToString(CultureInfo.InvariantCulture),
                    record.Target,
                    record.TargetPid == 0 ? string.Empty : record.TargetPid.ToString(CultureInfo.InvariantCulture),
                    record.Summary,
                    record.Details
                };

                if (includeAttackColumns)
                {
                    DetectionMetadata metadata = ExtractDetectionMetadata(record);
                    values.AddRange(
                        new[] { string.Empty, metadata.MitreTechniqueId, string.Empty, string.Empty, string.Empty });
                }

                writer.WriteLine(string.Join(",", values.Select(EscapeCsv)));
            }
        }

        private static void WriteCef(TextWriter writer, IEnumerable<SessionExportRecord> records)
        {
            foreach (SessionExportRecord record in records)
            {
                DetectionMetadata metadata = ExtractDetectionMetadata(record);
                string signature = string.IsNullOrWhiteSpace(record.Detection) ? record.EventName : record.Detection;
                string name = string.IsNullOrWhiteSpace(record.Summary) ? signature : record.Summary;
                int severity = MapSeverity(record.Severity);
                string extension =
                    $"rt={EscapeCefExtension(record.TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture))} " +
                    $"cs1Label=stream cs1={EscapeCefExtension(record.Stream)} " +
                    $"cs2Label=rule_engine cs2={EscapeCefExtension(metadata.Engine)} " +
                    $"cs3Label=mitre_technique_id cs3={EscapeCefExtension(metadata.MitreTechniqueId)} " +
                    $"cs4Label=rule_id cs4={EscapeCefExtension(metadata.RuleId)} " +
                    $"cn1Label=actor_pid cn1={record.ActorPid} " + $"cn2Label=target_pid cn2={record.TargetPid} " +
                    $"sproc={EscapeCefExtension(record.Source)} " + $"dproc={EscapeCefExtension(record.Target)} " +
                    $"src={EscapeCefExtension(record.Actor)} " + $"dst={EscapeCefExtension(record.Target)} " +
                    $"msg={EscapeCefExtension(record.Details)} " +
                    $"deviceProcessName={EscapeCefExtension(record.Tab)} " +
                    $"externalId={EscapeCefExtension(record.Pid.ToString(CultureInfo.InvariantCulture))}";

                writer.WriteLine(
                    $"CEF:0|BK|Platform|1.0|{EscapeCefHeader(signature)}|{EscapeCefHeader(name)}|{severity}|{extension}");
            }
        }

        private static Dictionary<string, object?> BuildSiemEvent(SessionExportRecord record)
        {
            DetectionMetadata metadata = ExtractDetectionMetadata(record);
            int severity = MapSeverity(record.Severity);
            return new Dictionary < string,
                   object ?> { ["@timestamp"] = record.TimestampUtc.ToString("O", CultureInfo.InvariantCulture),
                               ["host.name"] = Environment.MachineName,
                               ["event.kind"] = "alert",
                               ["event.module"] = "BK",
                               ["event.dataset"] = "BK.detections",
                               ["event.action"] = record.EventName,
                               ["event.severity"] = severity,
                               ["event.count"] = Math.Max(1, record.Hits),
                               ["rule.id"] = metadata.RuleId,
                               ["rule.name"] = metadata.RuleName,
                               ["rule.ruleset"] = metadata.Engine,
                               ["rule.category"] = metadata.Category,
                               ["threat.technique.id"] = metadata.MitreTechniqueId,
                               ["observer.vendor"] = "BK",
                               ["observer.product"] = "BK Analysis Interface",
                               ["BK.tab"] = record.Tab,
                               ["BK.stream"] = record.Stream,
                               ["BK.summary"] = record.Summary,
                               ["BK.details"] = record.Details,
                               ["detection.name"] = record.Detection,
                               ["severity.label"] = record.Severity,
                               ["source.process.name"] = record.Actor,
                               ["source.process.pid"] = OptionalNumber(record.ActorPid),
                               ["target.process.name"] = record.Target,
                               ["target.process.pid"] = OptionalNumber(record.TargetPid),
                               ["process.name"] = record.Source,
                               ["process.pid"] = OptionalNumber(record.Pid),
                               ["process.thread.id"] = OptionalNumber(record.Tid) };
        }

        private static Dictionary<string, object?> BuildElasticEcsEvent(SessionExportRecord record)
        {
            DetectionMetadata metadata = ExtractDetectionMetadata(record);
            int severity = MapSeverity(record.Severity);
            var threat = string.IsNullOrWhiteSpace(metadata.MitreTechniqueId) ? null : new Dictionary < string,
                object ?> { ["technique"] =
                                new[] { new Dictionary < string, object ?> { ["id"] = metadata.MitreTechniqueId } } };

            return new Dictionary < string,
                   object ?> { ["@timestamp"] = record.TimestampUtc.ToString("O", CultureInfo.InvariantCulture),
                               ["ecs"] = new Dictionary < string, object  ?> { ["version"] = "8.11.0" },
                               ["host"] = new Dictionary < string, object ?> { ["name"] = Environment.MachineName },
                ["event"] = new Dictionary < string,
                object ?> { ["kind"] = "alert", ["category"] = new[] { "malware" }, ["type"] = new[] { "indicator" },
                            ["module"] = "BK", ["dataset"] = "BK.detections", ["action"] = record.EventName,
                            ["severity"] = severity, ["risk_score"] = severity, ["reason"] = record.Summary,
                            ["count"] = Math.Max(1, record.Hits) },
                ["rule"] = new Dictionary < string,
                object ?> { ["id"] = metadata.RuleId, ["name"] = metadata.RuleName, ["ruleset"] = metadata.Engine,
                            ["category"] = metadata.Category },
                ["observer"] = new Dictionary < string,
                object ?> { ["vendor"] = "BK", ["product"] = "BK Analysis Interface", ["type"] = "sensor" },
                ["process"] = new Dictionary < string,
                object ?> { ["name"] = record.Source, ["pid"] = OptionalNumber(record.Pid),
                            ["thread"] = new Dictionary < string, object ?> { ["id"] = OptionalNumber(record.Tid) } },
                ["source"] = new Dictionary < string,
                object ?> { ["process"] = new Dictionary < string,
                            object ?> { ["name"] = record.Actor, ["pid"] = OptionalNumber(record.ActorPid) } },
                ["target"] = new Dictionary < string,
                object ?> { ["process"] = new Dictionary < string,
                            object ?> { ["name"] = record.Target, ["pid"] = OptionalNumber(record.TargetPid) } },
                ["threat"] = threat, ["BK"] = new Dictionary < string,
                object ?> { ["tab"] = record.Tab, ["stream"] = record.Stream, ["detection"] = record.Detection,
                            ["severity_label"] = record.Severity, ["details"] = record.Details } };
        }

        private static DetectionMetadata ExtractDetectionMetadata(SessionExportRecord record)
        {
            string combined = $"{record.Details} {record.Summary} {record.Detection}";
            string engine =
                FirstNonEmpty(ExtractKeyValue(combined, "engine"),
                              record.Detection.StartsWith("SIGMA_", StringComparison.OrdinalIgnoreCase)  ? "sigma"
                              : record.Detection.StartsWith("YARA_", StringComparison.OrdinalIgnoreCase) ? "yara"
                                                                                                         : "BK");
            string ruleId = FirstNonEmpty(ExtractKeyValue(combined, "sigma_id"), ExtractKeyValue(combined, "rule"),
                                          record.Detection);
            string ruleName = FirstNonEmpty(DecodeEvidenceToken(ExtractKeyValue(combined, "rule")), record.Detection,
                                            record.EventName);
            string category = FirstNonEmpty(ExtractKeyValue(combined, "category"), record.Stream);
            string mitreTechniqueId = ExtractMitreTechniqueId(combined);
            return new DetectionMetadata(engine, ruleId, ruleName, category, mitreTechniqueId);
        }

        private static string ExtractKeyValue(string text, string key)
        {
            Match match = Regex.Match(text ?? string.Empty, $@"(?:^|\s){Regex.Escape(key)}=(?<value>[^\s]+)",
                                      RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            return match.Success ? match.Groups["value"].Value.Trim() : string.Empty;
        }

        private static string DecodeEvidenceToken(string value) => (value ?? string.Empty).Trim().Replace('_', ' ');

        private static string ExtractMitreTechniqueId(string text)
        {
            Match match = Regex.Match(text ?? string.Empty, @"\bT\d{4}(?:\.\d{3})?\b",
                                      RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            return match.Success ? match.Value.ToUpperInvariant() : string.Empty;
        }

        private static string FirstNonEmpty(params string[] values) =>
            values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim() ?? string.Empty;

        private static double ToUnixTimeSeconds(DateTime timestampUtc)
        {
            DateTime utc = timestampUtc.Kind == DateTimeKind.Utc ? timestampUtc
                                                                 : DateTime.SpecifyKind(timestampUtc, DateTimeKind.Utc);
            return new DateTimeOffset(utc).ToUnixTimeMilliseconds() / 1000.0;
        }

        private static object? OptionalNumber(int value) => value == 0 ? null : value;

        private static object? OptionalNumber(uint value) => value == 0 ? null : value;

        private static int TryParseInt(string value) => int.TryParse(value, NumberStyles.Integer,
                                                                     CultureInfo.InvariantCulture, out int parsed)
                                                            ? parsed
                                                            : 0;

        private static int MapSeverity(string severity)
        {
            return (severity ?? string.Empty)
                .Trim()
                .ToLowerInvariant() switch { "critical" => 10,
                                             "high" => 8,
                                             "medium" => 5,
                                             "low" => 3,
                                             "informational" => 1,
                                             "info" => 1,
                                             _ => 4 };
        }

        private static string EscapeCsv(string value)
        {
            string text = value ?? string.Empty;
            if (!text.Contains('"') && !text.Contains(',') && !text.Contains('\n') && !text.Contains('\r'))
            {
                return text;
            }

            return "\"" + text.Replace("\"", "\"\"") + "\"";
        }

        private static string
        EscapeCefHeader(string value) => (value ?? string.Empty).Replace("\\", "\\\\").Replace("|", "\\|");

        private static string EscapeCefExtension(string value) =>
            (value ?? string.Empty).Replace("\\", "\\\\").Replace("=", "\\=").Replace("\r", " ").Replace("\n", " ");

        private sealed class SessionExportRecord
        {
            public DateTime TimestampUtc { get; init; }
            public string Tab { get; init; } = string.Empty;
            public int Pid { get; init; }
            public int Tid { get; init; }
            public string Stream { get; init; } = string.Empty;
            public string EventName { get; init; } = string.Empty;
            public string Severity { get; init; } = string.Empty;
            public string Detection { get; init; } = string.Empty;
            public string Source { get; init; } = string.Empty;
            public string Actor { get; init; } = string.Empty;
            public uint ActorPid { get; init; }
            public string Target { get; init; } = string.Empty;
            public uint TargetPid { get; init; }
            public string Summary { get; init; } = string.Empty;
            public string Details { get; init; } = string.Empty;
            public int Hits { get; init; } = 1;
        }

        private sealed record DetectionMetadata(string Engine, string RuleId, string RuleName, string Category,
                                                string MitreTechniqueId);
    }
}
