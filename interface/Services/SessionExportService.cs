using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace SleepwalkerInterface
{
    internal enum SessionExportFormat
    {
        JsonLines,
        Csv,
        Cef,
        AttackCsv
    }

    internal static class SessionExportService
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = false
        };

        internal static void Export(string path, SessionFileArchive archive, SessionExportFormat format)
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

            List<SessionExportRecord> records = FlattenArchive(archive).ToList();
            string tempPath = path + ".tmp";
            try
            {
                using var writer = new StreamWriter(tempPath, false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
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
                    yield return new SessionExportRecord
                    {
                        TimestampUtc = ev.TimestampUtc,
                        Tab = tabTitle,
                        Pid = ev.PID != 0 ? ev.PID : tab.Pid,
                        Tid = ev.TID,
                        Stream = "timeline",
                        EventName = string.IsNullOrWhiteSpace(ev.SubType) ? ev.Group : $"{ev.Group}/{ev.SubType}",
                        Source = ev.ProcessName,
                        Summary = ev.Summary,
                        Details = ev.Details
                    };
                }

                foreach (SessionExportRecord record in FlattenGroupedRows(tabTitle, tab.Pid, "etw", tab.EtwGroups))
                {
                    yield return record;
                }

                foreach (SessionExportRecord record in FlattenGroupedRows(tabTitle, tab.Pid, "heuristics", tab.HeuristicsGroups))
                {
                    yield return record;
                }

                foreach (SessionExportRecord record in FlattenGroupedRows(tabTitle, tab.Pid, "relations", tab.ProcessRelationsGroups))
                {
                    yield return record;
                }
            }
        }

        private static IEnumerable<SessionExportRecord> FlattenGroupedRows(
            string tabTitle,
            int defaultPid,
            string stream,
            IEnumerable<GroupedEventRow> rows)
        {
            foreach (GroupedEventRow row in rows.OrderBy(x => x.LastSeenUtc))
            {
                if (row.Details.Count == 0)
                {
                    yield return new SessionExportRecord
                    {
                        TimestampUtc = row.LastSeenUtc,
                        Tab = tabTitle,
                        Pid = defaultPid,
                        Stream = stream,
                        EventName = row.Event,
                        Severity = row.Severity,
                        Detection = row.Detection,
                        Summary = row.GroupKey
                    };
                    continue;
                }

                foreach (GroupedEventDetailRow detail in row.Details.OrderBy(x => x.TimestampUtc))
                {
                    yield return new SessionExportRecord
                    {
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
                        Details = detail.Details
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

        private static void WriteCsv(TextWriter writer, IEnumerable<SessionExportRecord> records, bool includeAttackColumns)
        {
            var headers = new List<string>
            {
                "timestamp_utc", "tab", "pid", "tid", "stream", "event", "severity", "detection",
                "source", "actor", "actor_pid", "target", "target_pid", "summary", "details"
            };

            if (includeAttackColumns)
            {
                headers.AddRange(new[]
                {
                    "mitre_tactic", "mitre_technique_id", "mitre_technique", "mitre_subtechnique_id", "mitre_subtechnique"
                });
            }

            writer.WriteLine(string.Join(",", headers.Select(EscapeCsv)));
            foreach (SessionExportRecord record in records)
            {
                var values = new List<string>
                {
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
                    values.AddRange(new[] { string.Empty, string.Empty, string.Empty, string.Empty, string.Empty });
                }

                writer.WriteLine(string.Join(",", values.Select(EscapeCsv)));
            }
        }

        private static void WriteCef(TextWriter writer, IEnumerable<SessionExportRecord> records)
        {
            foreach (SessionExportRecord record in records)
            {
                string signature = string.IsNullOrWhiteSpace(record.Detection) ? record.EventName : record.Detection;
                string name = string.IsNullOrWhiteSpace(record.Summary) ? signature : record.Summary;
                int severity = MapSeverity(record.Severity);
                string extension =
                    $"rt={EscapeCefExtension(record.TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture))} " +
                    $"cs1Label=stream cs1={EscapeCefExtension(record.Stream)} " +
                    $"sproc={EscapeCefExtension(record.Source)} " +
                    $"dproc={EscapeCefExtension(record.Target)} " +
                    $"src={EscapeCefExtension(record.Actor)} " +
                    $"dst={EscapeCefExtension(record.Target)} " +
                    $"msg={EscapeCefExtension(record.Details)} " +
                    $"deviceProcessName={EscapeCefExtension(record.Tab)} " +
                    $"externalId={EscapeCefExtension(record.Pid.ToString(CultureInfo.InvariantCulture))}";

                writer.WriteLine(
                    $"CEF:0|Sleepwalker|Platform|1.0|{EscapeCefHeader(signature)}|{EscapeCefHeader(name)}|{severity}|{extension}");
            }
        }

        private static int TryParseInt(string value)
            => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed) ? parsed : 0;

        private static int MapSeverity(string severity)
        {
            return (severity ?? string.Empty).Trim().ToLowerInvariant() switch
            {
                "critical" => 10,
                "high" => 8,
                "medium" => 5,
                "low" => 3,
                "info" => 1,
                _ => 4
            };
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

        private static string EscapeCefHeader(string value)
            => (value ?? string.Empty).Replace("\\", "\\\\").Replace("|", "\\|");

        private static string EscapeCefExtension(string value)
            => (value ?? string.Empty)
                .Replace("\\", "\\\\")
                .Replace("=", "\\=")
                .Replace("\r", " ")
                .Replace("\n", " ");

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
        }
    }
}
