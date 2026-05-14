using BlackbirdInterface.Capture;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.Windows.Media;
using System.Windows.Shapes;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private List<ApiCallGraphMainRowView> BuildApiCallGraphRows(IReadOnlyList<ApiCallGraphRowSnapshot> snapshot)
        {
            int maxHits = Math.Max(1, snapshot.Count == 0 ? 1 : snapshot.Max(x => Math.Max(1, x.Hits)));
            var rows = new List<ApiCallGraphMainRowView>(snapshot.Count);
            foreach (ApiCallGraphRowSnapshot row in snapshot)
            {
                uint target = row.TargetPid != 0 ? row.TargetPid : row.SourcePid;
                string sensor = string.IsNullOrWhiteSpace(row.SensorOrigin) ? "Unclassified" : row.SensorOrigin;
                string callerOrigin = NormalizeApiCallerOrigin(row.CallerOrigin);
                string originModule = NormalizeApiOriginModule(row.OriginModule);
                string key = BuildApiGraphKey(row.SourcePid, row.TargetPid, row.ThreadId, row.ApiName, sensor,
                                              callerOrigin, originModule);
                double heatPercent = Math.Clamp((row.Hits / (double)maxHits) * 100.0, 0.0, 100.0);
                rows.Add(new ApiCallGraphMainRowView {
                    GraphKey = key,
                    ThreadGroupKey = $"{row.SourcePid}|{row.ThreadId}",
                    ViewModeKey = "call",
                    ApiName = string.IsNullOrWhiteSpace(row.ApiName) ? "unknown" : row.ApiName,
                    OriginModule = originModule,
                    ActionLabel = row.ActionLabel,
                    SensorLabel = sensor,
                    CallerOriginKey = callerOrigin,
                    CallerOriginLabel = GetApiCallerOriginDisplayLabel(callerOrigin, sensor, originModule),
                    CallChainLabel = row.CallChainLabel,
                    CallerOriginBackground = BuildApiCallerOriginBackground(callerOrigin),
                    CallerOriginForeground = BuildApiCallerOriginForeground(callerOrigin),
                    SensorBackground = BuildApiSensorBackground(sensor),
                    SensorForeground = BuildApiSensorForeground(sensor),
                    HeatTrackBackground = BuildApiHeatTrackBackground(sensor, callerOrigin),
                    HeatFillBackground = BuildApiHeatFillBackground(sensor, callerOrigin),
                    RowBackground = BuildApiRowBackground(sensor, callerOrigin),
                    RowBorderBrush = BuildApiRowBorder(sensor, callerOrigin),
                    SourceLabel = FormatApiProcessLabel(row.SourcePid),
                    TargetLabel = FormatApiTargetLabel(row.SourcePid, target),
                    ThreadLabel =
                        row.ThreadId == 0 ? string.Empty : row.ThreadId.ToString(CultureInfo.InvariantCulture),
                    SizeLabel = row.ContextLabel,
                    ProtectLabel = row.FlagsLabel,
                    Field2Label = "Context",
                    Field4Label = "Flags",
                    Hits = Math.Max(1, row.Hits),
                    HeatPercent = heatPercent,
                    ActivityFillWidth = Math.Round((heatPercent / 100.0) * 110.0),
                    FirstSeen = FormatApiRelativeAge(row.FirstSeenUtc),
                    AbsoluteFirstSeen = row.FirstSeenUtc == default
                                            ? string.Empty
                                            : row.FirstSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff",
                                                                                      CultureInfo.InvariantCulture),
                    FirstSeenUtc = row.FirstSeenUtc,
                    LastSeen = FormatApiRelativeAge(row.LastSeenUtc),
                    AbsoluteLastSeen = row.LastSeenUtc == default
                                           ? string.Empty
                                           : row.LastSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff",
                                                                                    CultureInfo.InvariantCulture),
                    LastSeenUtc = row.LastSeenUtc,
                    DetailFull = row.DetailFull,
                    RawGraphKeys = new List<string> { key }
                });
            }

            return CollapseApiCallRowsByThread(rows);
        }

        private static List<ApiCallGraphMainRowView> CollapseApiCallRowsByThread(List<ApiCallGraphMainRowView> rows)
        {
            if (rows.Count <= 1)
            {
                return rows;
            }

            var collapsed = new List<ApiCallGraphMainRowView>(rows.Count);
            foreach (
                var group in rows.GroupBy(
                    row =>
                        $"{row.ViewModeKey}|{row.ApiName}|{row.SensorLabel}|{row.CallerOriginKey}|{row.OriginModule}|{row.SourceLabel}|{row.TargetLabel}",
       StringComparer.Ordinal))
            {
                List<ApiCallGraphMainRowView> members =
                    group.OrderByDescending(x => x.LastSeenUtc).ThenByDescending(x => x.Hits).ToList();
                int distinctThreads =
                    members.Select(x => string.IsNullOrWhiteSpace(x.ThreadLabel) ? "unknown" : x.ThreadLabel)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .Count();
                if (distinctThreads <= 1)
                {
                    collapsed.AddRange(members);
                    continue;
                }

                ApiCallGraphMainRowView latest = members[0];
                int hits = members.Sum(x => Math.Max(1, x.Hits));
                List<ApiThreadDetailRowView> threadDetails =
                    members
                        .Select(
                            x => new ApiThreadDetailRowView { ThreadLabel = FormatApiThreadDetailLabel(x.ThreadLabel),
                                                              SourceLabel = x.SourceLabel, TargetLabel = x.TargetLabel,
                                                              ArgumentSummary = BuildApiThreadArgumentSummary(x),
                                                              Hits = Math.Max(1, x.Hits), LastSeen = x.LastSeen })
                        .ToList();

                collapsed.Add(new ApiCallGraphMainRowView {
                    GraphKey = $"group|{latest.GraphKey}",
                    ThreadGroupKey = latest.ThreadGroupKey,
                    ViewModeKey = latest.ViewModeKey,
                    ApiName = latest.ApiName,
                    OriginModule = latest.OriginModule,
                    ActionLabel = latest.ActionLabel,
                    SensorLabel = latest.SensorLabel,
                    CallerOriginKey = latest.CallerOriginKey,
                    CallerOriginLabel = latest.CallerOriginLabel,
                    CallChainLabel = latest.CallChainLabel,
                    CallerOriginBackground = latest.CallerOriginBackground,
                    CallerOriginForeground = latest.CallerOriginForeground,
                    SensorBackground = latest.SensorBackground,
                    SensorForeground = latest.SensorForeground,
                    HeatTrackBackground = latest.HeatTrackBackground,
                    HeatFillBackground = latest.HeatFillBackground,
                    RowBackground = latest.RowBackground,
                    RowBorderBrush = latest.RowBorderBrush,
                    SourceLabel = latest.SourceLabel,
                    TargetLabel = latest.TargetLabel,
                    ThreadLabel = $"{distinctThreads} threads",
                    Field1Label = latest.Field1Label,
                    Field2Label = "Threads",
                    Field3Label = latest.Field3Label,
                    Field4Label = "Args",
                    BaseLabel = latest.BaseLabel,
                    SizeLabel = $"{distinctThreads} threads",
                    AllocTypeLabel = latest.AllocTypeLabel,
                    ProtectLabel = "multiple argument sets",
                    Hits = hits,
                    FirstSeen = latest.FirstSeen,
                    AbsoluteFirstSeen = latest.AbsoluteFirstSeen,
                    FirstSeenUtc = members.Where(x => x.FirstSeenUtc != default)
                                       .Select(x => x.FirstSeenUtc)
                                       .DefaultIfEmpty(latest.FirstSeenUtc)
                                       .Min(),
                    LastSeen = latest.LastSeen,
                    AbsoluteLastSeen = latest.AbsoluteLastSeen,
                    LastSeenUtc = members.Max(x => x.LastSeenUtc),
                    DetailFull = BuildApiCollapsedThreadDetail(latest, threadDetails),
                    RawGraphKeys = members
                                       .SelectMany(x => x.RawGraphKeys.Count == 0 ? Enumerable.Repeat(x.GraphKey, 1)
                                                                                  : x.RawGraphKeys.AsEnumerable())
                                       .Distinct(StringComparer.Ordinal)
                                       .ToList(),
                    ThreadDetails = threadDetails
                });
            }

            RecalculateApiHeat(collapsed);
            return collapsed;
        }

        private static string FormatApiThreadDetailLabel(string threadLabel) =>
            string.IsNullOrWhiteSpace(threadLabel)                            ? "T?"
            : threadLabel.StartsWith("T", StringComparison.OrdinalIgnoreCase) ? threadLabel
                                                                              : $"T{threadLabel}";

        private static string BuildApiThreadArgumentSummary(ApiCallGraphMainRowView row)
        {
            var parts = new List<string>(4);
            if (!string.IsNullOrWhiteSpace(row.SizeLabel))
            {
                parts.Add($"{row.Field2Label}: {row.SizeLabel}");
            }
            if (!string.IsNullOrWhiteSpace(row.ProtectLabel))
            {
                parts.Add($"{row.Field4Label}: {row.ProtectLabel}");
            }
            if (!string.IsNullOrWhiteSpace(row.ActionLabel))
            {
                parts.Add(row.ActionLabel);
            }
            if (parts.Count == 0 && !string.IsNullOrWhiteSpace(row.DetailFull))
            {
                parts.Add(SummarizeApiReason(row.DetailFull));
            }
            return parts.Count == 0 ? "arguments unavailable" : string.Join(" | ", parts);
        }

        private static string BuildApiCollapsedThreadDetail(ApiCallGraphMainRowView latest,
                                                            IReadOnlyList<ApiThreadDetailRowView> details)
        {
            var sb = new StringBuilder(512);
            if (!string.IsNullOrWhiteSpace(latest.DetailFull))
            {
                sb.AppendLine(latest.DetailFull);
                sb.AppendLine();
            }
            sb.AppendLine("Thread breakdown:");
            foreach (ApiThreadDetailRowView detail in details)
            {
                sb.Append(detail.ThreadLabel)
                    .Append(" hits=")
                    .Append(detail.Hits.ToString(CultureInfo.InvariantCulture))
                    .Append(" ")
                    .AppendLine(detail.ArgumentSummary);
            }
            return sb.ToString().TrimEnd();
        }

        private static void RecalculateApiHeat(IReadOnlyCollection<ApiCallGraphMainRowView> rows)
        {
            int maxHits = Math.Max(1, rows.Count == 0 ? 1 : rows.Max(x => Math.Max(1, x.Hits)));
            foreach (ApiCallGraphMainRowView row in rows)
            {
                double heatPercent = Math.Clamp((row.Hits / (double)maxHits) * 100.0, 0.0, 100.0);
                row.HeatPercent = heatPercent;
                row.ActivityFillWidth = Math.Round((heatPercent / 100.0) * 110.0);
            }
        }

        private List<ApiCallGraphMainRowView>
        BuildApiThreadTimelineRows(IReadOnlyList<ApiCallGraphRowSnapshot> snapshot)
        {
            var groups =
                snapshot
                    .GroupBy(
                        row =>
                            $"{row.SourcePid}|{row.TargetPid}|{row.ThreadId}|{NormalizeApiOriginModule(row.OriginModule)}|{row.ApiName}",
                        StringComparer.Ordinal)
                    .Select(
                        group =>
                        {
                            ApiCallGraphRowSnapshot latest = group.OrderByDescending(x => x.LastSeenUtc).First();
                            int hits = group.Sum(x => Math.Max(1, x.Hits));
                            DateTime firstSeenUtc = group.Where(x => x.FirstSeenUtc != default)
                                                        .Select(x => x.FirstSeenUtc)
                                                        .DefaultIfEmpty(latest.LastSeenUtc)
                                                        .Min();
                            DateTime lastSeenUtc = group.Max(x => x.LastSeenUtc);
                            string sensor =
                                group.Select(x => x.SensorOrigin).FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ??
                                "Unclassified";
                            string callerOrigin = NormalizeApiCallerOrigin(latest.CallerOrigin);
                            string originModule = NormalizeApiOriginModule(latest.OriginModule);
                            return new {
                                Key =
                                    $"thread|{latest.SourcePid}|{latest.TargetPid}|{latest.ThreadId}|{originModule}|{latest.ApiName}",
                                ThreadGroupKey = $"{latest.SourcePid}|{latest.ThreadId}",
                                Latest = latest,
                                Hits = hits,
                                FirstSeenUtc = firstSeenUtc,
                                LastSeenUtc = lastSeenUtc,
                                Sensor = sensor,
                                CallerOrigin = callerOrigin,
                                OriginModule = originModule,
                                OperationSummary = BuildApiOperationSummary(group)
                            };
                        })
                    .OrderBy(x => x.ThreadGroupKey, StringComparer.Ordinal)
                    .ThenBy(x => x.FirstSeenUtc)
                    .ThenBy(x => x.LastSeenUtc)
                    .Take(600)
                    .ToList();

            int maxHits = Math.Max(1, groups.Count == 0 ? 1 : groups.Max(x => Math.Max(1, x.Hits)));
            var rows = new List<ApiCallGraphMainRowView>(groups.Count);
            foreach (var group in groups)
            {
                ApiCallGraphRowSnapshot row = group.Latest;
                uint target = row.TargetPid != 0 ? row.TargetPid : row.SourcePid;
                double heatPercent = Math.Clamp((group.Hits / (double)maxHits) * 100.0, 0.0, 100.0);
                string threadLabel =
                    BuildThreadTimelineLabel(row.SourcePid, row.ThreadId, group.FirstSeenUtc, group.LastSeenUtc);
                rows.Add(new ApiCallGraphMainRowView {
                    GraphKey = group.Key,
                    ThreadGroupKey = group.ThreadGroupKey,
                    ViewModeKey = "thread",
                    ApiName = string.IsNullOrWhiteSpace(row.ApiName) ? "unknown" : row.ApiName,
                    OriginModule = group.OriginModule,
                    ActionLabel = string.IsNullOrWhiteSpace(row.ActionLabel) ? "Call activity" : row.ActionLabel,
                    SensorLabel = group.Sensor,
                    CallerOriginKey = group.CallerOrigin,
                    CallerOriginLabel =
                        GetApiCallerOriginDisplayLabel(group.CallerOrigin, group.Sensor, group.OriginModule),
                    CallChainLabel = BuildThreadTimelineCallChain(row, group.FirstSeenUtc, group.LastSeenUtc),
                    CallerOriginBackground = BuildApiCallerOriginBackground(group.CallerOrigin),
                    CallerOriginForeground = BuildApiCallerOriginForeground(group.CallerOrigin),
                    SensorBackground = BuildApiSensorBackground(group.Sensor),
                    SensorForeground = BuildApiSensorForeground(group.Sensor),
                    HeatTrackBackground = BuildApiHeatTrackBackground(group.Sensor, group.CallerOrigin),
                    HeatFillBackground = BuildApiHeatFillBackground(group.Sensor, group.CallerOrigin),
                    RowBackground = BuildApiRowBackground(group.Sensor, group.CallerOrigin),
                    RowBorderBrush = BuildApiRowBorder(group.Sensor, group.CallerOrigin),
                    SourceLabel = FormatApiProcessLabel(row.SourcePid),
                    TargetLabel = FormatApiTargetLabel(row.SourcePid, target),
                    ThreadLabel = threadLabel,
                    SizeLabel = group.OriginModule,
                    ProtectLabel = group.OperationSummary,
                    Field2Label = "Module",
                    Field4Label = "Ops",
                    Hits = group.Hits,
                    HeatPercent = heatPercent,
                    ActivityFillWidth = Math.Round((heatPercent / 100.0) * 110.0),
                    FirstSeen = FormatApiRelativeAge(group.FirstSeenUtc),
                    AbsoluteFirstSeen = group.FirstSeenUtc == default
                                            ? string.Empty
                                            : group.FirstSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff",
                                                                                        CultureInfo.InvariantCulture),
                    FirstSeenUtc = group.FirstSeenUtc,
                    LastSeen = FormatApiRelativeAge(group.LastSeenUtc),
                    AbsoluteLastSeen = group.LastSeenUtc == default
                                           ? string.Empty
                                           : group.LastSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff",
                                                                                      CultureInfo.InvariantCulture),
                    LastSeenUtc = group.LastSeenUtc,
                    DetailFull = BuildThreadTimelineDetail(row, group.FirstSeenUtc, group.LastSeenUtc, group.Hits,
                                                           group.OriginModule, group.OperationSummary)
                });
            }

            return rows;
        }

        private void RenderApiPresentationCanvas(IReadOnlyList<ApiCallGraphMainRowView> rows, string? selectedKey)
        {
            if (_apiViewPresentationMode == ApiViewPresentationMode.ThreadTimeline)
            {
                RenderApiThreadTimelineCanvas(rows, selectedKey);
                return;
            }

            var allowedKeys = new HashSet<string>(StringComparer.Ordinal);
            foreach (ApiCallGraphMainRowView row in rows)
            {
                if (row.RawGraphKeys.Count == 0)
                {
                    allowedKeys.Add(row.GraphKey);
                    continue;
                }
                foreach (string rawKey in row.RawGraphKeys)
                {
                    allowedKeys.Add(rawKey);
                }
            }
            List<ApiCallGraphRowSnapshot> snapshot =
                _apiGraphSnapshotRows
                    .Where(x => allowedKeys.Contains(BuildApiGraphKey(
                               x.SourcePid, x.TargetPid, x.ThreadId, x.ApiName,
                               string.IsNullOrWhiteSpace(x.SensorOrigin) ? "Unclassified" : x.SensorOrigin,
                               NormalizeApiCallerOrigin(x.CallerOrigin), NormalizeApiOriginModule(x.OriginModule))))
                    .OrderByDescending(x => x.Hits)
                    .ThenByDescending(x => x.LastSeenUtc)
                    .ToList();
            ApiCallGraphMainRowView? selectedRow =
                rows.FirstOrDefault(x => string.Equals(x.GraphKey, selectedKey, StringComparison.Ordinal));
            string? graphSelectedKey = selectedRow?.RawGraphKeys.Count > 0 ? selectedRow.RawGraphKeys[0] : selectedKey;
            RenderApiGraphCanvas(snapshot, graphSelectedKey);
        }

        private string BuildThreadTimelineLabel(uint pid, uint threadId, DateTime firstSeenUtc, DateTime lastSeenUtc)
        {
            string tid = threadId == 0 ? "T?" : $"T{threadId}";
            string lifetime = BuildThreadLifetimeSummary(pid, threadId, firstSeenUtc, lastSeenUtc);
            return string.IsNullOrWhiteSpace(lifetime) ? tid : $"{tid} · {lifetime}";
        }

        private string BuildThreadLifetimeSummary(uint pid, uint threadId, DateTime firstSeenUtc, DateTime lastSeenUtc)
        {
            if (_currentSession == null || threadId == 0)
            {
                return firstSeenUtc != default && lastSeenUtc > firstSeenUtc
                           ? $"{(lastSeenUtc - firstSeenUtc).TotalSeconds:0.0}s"
                           : string.Empty;
            }

            IEnumerable<ThreadLifecycleEventSample> history =
                _currentSession.ThreadLifecycleHistory.Where(x => x.ProcessPid == pid && x.ThreadId == threadId)
                    .OrderBy(x => x.TimestampUtc);
            ThreadLifecycleEventSample? start =
                history.FirstOrDefault(x => x.EventKind.Equals("Start", StringComparison.OrdinalIgnoreCase));
            ThreadLifecycleEventSample? exit =
                history.LastOrDefault(x => x.EventKind.Equals("Exit", StringComparison.OrdinalIgnoreCase));
            DateTime startUtc = start?.TimestampUtc ?? firstSeenUtc;
            DateTime endUtc = exit?.TimestampUtc ?? lastSeenUtc;
            if (startUtc == default || endUtc == default || endUtc < startUtc)
            {
                return string.Empty;
            }

            string state = exit == null ? "live" : "exited";
            return $"{(endUtc - startUtc).TotalSeconds:0.0}s {state}";
        }

        private static string BuildApiOperationSummary(IEnumerable<ApiCallGraphRowSnapshot> rows)
        {
            int query = 0, write = 0, exec = 0, map = 0, open = 0;
            foreach (ApiCallGraphRowSnapshot row in rows)
            {
                string text = $"{row.ApiName} {row.ActionLabel} {row.DetailFull}".ToLowerInvariant();
                int weight = Math.Max(1, row.Hits);
                if (text.Contains("query") || text.Contains("read"))
                    query += weight;
                if (text.Contains("write") || text.Contains("patch") || text.Contains("protect"))
                    write += weight;
                if (text.Contains("thread") || text.Contains("apc") || text.Contains("execute"))
                    exec += weight;
                if (text.Contains("map") || text.Contains("section") || text.Contains("image"))
                    map += weight;
                if (text.Contains("open") || text.Contains("handle") || text.Contains("token"))
                    open += weight;
            }

            var parts = new List<string>(5);
            if (query != 0)
                parts.Add($"query:{query}");
            if (write != 0)
                parts.Add($"write:{write}");
            if (exec != 0)
                parts.Add($"exec:{exec}");
            if (map != 0)
                parts.Add($"map:{map}");
            if (open != 0)
                parts.Add($"open:{open}");
            return parts.Count == 0 ? "mixed" : string.Join(" ", parts);
        }

        private string BuildThreadTimelineCallChain(ApiCallGraphRowSnapshot row, DateTime firstSeenUtc,
                                                    DateTime lastSeenUtc)
        {
            string module = NormalizeApiOriginModule(row.OriginModule);
            string first = firstSeenUtc == default
                               ? string.Empty
                               : firstSeenUtc.ToLocalTime().ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture);
            string last = lastSeenUtc == default
                              ? string.Empty
                              : lastSeenUtc.ToLocalTime().ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture);
            string summary = $"Module {module}";
            if (first.Length != 0 || last.Length != 0)
            {
                summary += $"{Environment.NewLine}Window {first} -> {last}";
            }
            if (!string.IsNullOrWhiteSpace(row.CallChainLabel))
            {
                summary += $"{Environment.NewLine}{Environment.NewLine}{row.CallChainLabel}";
            }
            return summary.Trim();
        }

        private string BuildThreadTimelineDetail(ApiCallGraphRowSnapshot row, DateTime firstSeenUtc,
                                                 DateTime lastSeenUtc, int hits, string originModule,
                                                 string operationSummary)
        {
            var sb = new StringBuilder(512);
            sb.AppendLine($"API: {row.ApiName}");
            sb.AppendLine($"Module: {originModule}");
            sb.AppendLine($"Hits: {hits.ToString(CultureInfo.InvariantCulture)}");
            if (firstSeenUtc != default)
                sb.AppendLine($"First Seen: {firstSeenUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss.fff}");
            if (lastSeenUtc != default)
                sb.AppendLine($"Last Seen: {lastSeenUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss.fff}");
            sb.AppendLine($"Ops: {operationSummary}");
            if (!string.IsNullOrWhiteSpace(row.ActionLabel))
                sb.AppendLine().AppendLine(row.ActionLabel);
            if (!string.IsNullOrWhiteSpace(row.DetailFull))
                sb.AppendLine().Append(row.DetailFull.Trim());
            return sb.ToString().TrimEnd();
        }

        private void RenderApiThreadTimelineCanvas(IReadOnlyList<ApiCallGraphMainRowView> rows, string? selectedKey)
        {
            if (ApiViewGraphCanvas == null)
            {
                return;
            }

            ApiViewGraphCanvas.Children.Clear();
            if (rows.Count == 0)
            {
                ApiViewGraphCanvas.Width = 540;
                ApiViewGraphCanvas.Height = 240;
                var empty =
                    new TextBlock { Text = "No thread timeline yet",
                                    Foreground = (System.Windows.Media.Brush)FindResource("WinMutedTextBrush") };
                Canvas.SetLeft(empty, 16);
                Canvas.SetTop(empty, 16);
                ApiViewGraphCanvas.Children.Add(empty);
                return;
            }

            DateTime minUtc = rows.Where(x => x.FirstSeenUtc != default)
                                  .Select(x => x.FirstSeenUtc)
                                  .DefaultIfEmpty(rows.Min(x => x.LastSeenUtc))
                                  .Min();
            DateTime maxUtc = rows.Select(x => x.LastSeenUtc).DefaultIfEmpty(minUtc).Max();
            if (maxUtc <= minUtc)
            {
                maxUtc = minUtc.AddSeconds(1);
            }

            var lanes =
                rows.GroupBy(x => x.ThreadGroupKey, StringComparer.Ordinal)
                    .Select(g => new { ThreadGroupKey = g.Key,
                                       Rows = g.OrderBy(x => x.FirstSeenUtc == default ? x.LastSeenUtc : x.FirstSeenUtc)
                                                  .ThenBy(x => x.LastSeenUtc)
                                                  .ThenByDescending(x => x.Hits)
                                                  .Take(14)
                                                  .ToList(),
                                       Hits = g.Sum(x => x.Hits), Label = g.First().ThreadLabel,
                                       First = g.Where(x => x.FirstSeenUtc != default)
                                                   .Select(x => x.FirstSeenUtc)
                                                   .DefaultIfEmpty(g.Min(x => x.LastSeenUtc))
                                                   .Min(),
                                       Last = g.Select(x => x.LastSeenUtc).DefaultIfEmpty(minUtc).Max() })
                    .OrderBy(x => x.First)
                    .ThenBy(x => x.ThreadGroupKey, StringComparer.Ordinal)
                    .Take(24)
                    .ToList();

            double left = 132;
            double right = 22;
            double top = 34;
            double rowHeight = 22;
            double laneHeaderHeight = 24;
            double laneGap = 10;
            double durationSeconds = Math.Max(1, (maxUtc - minUtc).TotalSeconds);
            double canvasWidth = Math.Max(920, Math.Min(2400, left + right + (durationSeconds * 90)));
            double width = canvasWidth - left - right;
            double canvasHeight = Math.Max(
                260, top + lanes.Sum(x => laneHeaderHeight + Math.Max(1, x.Rows.Count) * rowHeight + laneGap) + 24);
            ApiViewGraphCanvas.Width = canvasWidth;
            ApiViewGraphCanvas.Height = canvasHeight;

            double ToX(DateTime utc) =>
                left + ((utc - minUtc).TotalMilliseconds / (maxUtc - minUtc).TotalMilliseconds) * width;

            var axis = new System.Windows.Shapes.Line { X1 = left,
                                                        X2 = left + width,
                                                        Y1 = top - 10,
                                                        Y2 = top - 10,
                                                        Stroke = (System.Windows.Media.Brush)FindResource(
                                                            "WinSubtleBorderBrush"),
                                                        StrokeThickness = 1 };
            ApiViewGraphCanvas.Children.Add(axis);

            int tickCount = Math.Min(6, Math.Max(2, (int)Math.Ceiling(width / 220.0)));
            for (int tick = 0; tick <= tickCount; tick += 1)
            {
                double ratio = tick / (double)tickCount;
                DateTime tickUtc = minUtc.AddMilliseconds((maxUtc - minUtc).TotalMilliseconds * ratio);
                double x = left + width * ratio;
                var tickLine = new System.Windows.Shapes.Line {
                    X1 = x,
                    X2 = x,
                    Y1 = top - 14,
                    Y2 = canvasHeight - 18,
                    Stroke = (System.Windows.Media.Brush)FindResource("WinSubtleBorderBrush"),
                    StrokeThickness = 1,
                    Opacity = tick == 0 || tick == tickCount ? 0.55 : 0.22
                };
                ApiViewGraphCanvas.Children.Add(tickLine);
                var tickLabel =
                    new TextBlock { Text = tickUtc.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture),
                                    Foreground = (System.Windows.Media.Brush)FindResource("WinMutedTextBrush"),
                                    FontSize = 10 };
                Canvas.SetLeft(tickLabel, Math.Max(left, Math.Min(left + width - 54, x - 22)));
                Canvas.SetTop(tickLabel, 4);
                ApiViewGraphCanvas.Children.Add(tickLabel);
            }

            double yCursor = top;
            for (int i = 0; i < lanes.Count; i += 1)
            {
                double y = yCursor;
                double laneBlockHeight = laneHeaderHeight + Math.Max(1, lanes[i].Rows.Count) * rowHeight;
                var label = new TextBlock { Text = lanes[i].Label, Width = left - 18,
                                            TextTrimming = TextTrimming.CharacterEllipsis,
                                            Foreground = (System.Windows.Media.Brush)FindResource("WinTextBrush"),
                                            FontWeight = FontWeights.SemiBold };
                Canvas.SetLeft(label, 8);
                Canvas.SetTop(label, y + 2);
                ApiViewGraphCanvas.Children.Add(label);

                var laneBackground = new System.Windows.Shapes.Rectangle {
                    Width = width,
                    Height = laneBlockHeight,
                    Fill = System.Windows.Media.Brushes.Transparent,
                    Stroke = (System.Windows.Media.Brush)FindResource("WinSubtleBorderBrush"),
                    StrokeThickness = 1,
                    Opacity = 0.7
                };
                Canvas.SetLeft(laneBackground, left);
                Canvas.SetTop(laneBackground, y);
                ApiViewGraphCanvas.Children.Add(laneBackground);

                for (int rowIndex = 0; rowIndex < lanes[i].Rows.Count; rowIndex += 1)
                {
                    ApiCallGraphMainRowView row = lanes[i].Rows[rowIndex];
                    double rowY = y + laneHeaderHeight + rowIndex * rowHeight;
                    double x1 = ToX(row.FirstSeenUtc == default ? row.LastSeenUtc : row.FirstSeenUtc);
                    double x2 = ToX(row.LastSeenUtc);
                    if (x2 < x1)
                    {
                        (x1, x2) = (x2, x1);
                    }

                    double markerWidth = Math.Max(8, Math.Min(168, x2 - x1 + Math.Min(24, row.Hits * 1.6)));
                    bool selected = string.Equals(row.GraphKey, selectedKey, StringComparison.Ordinal);
                    var border = new Border {
                        Width = markerWidth,
                        Height = 18,
                        CornerRadius = new CornerRadius(4),
                        Background = row.HeatFillBackground,
                        BorderBrush = row.RowBorderBrush,
                        BorderThickness = new Thickness(selected ? 2 : 1),
                        Opacity = selected ? 1.0 : 0.88,
                        Child = new TextBlock { Text = $"{row.ApiName}  [{row.OriginModule}]",
                                                Margin = new Thickness(6, 1, 6, 0),
                                                Foreground = (System.Windows.Media.Brush)FindResource("WinTextBrush"),
                                                FontSize = 11, TextTrimming = TextTrimming.CharacterEllipsis }
                    };
                    Canvas.SetLeft(border, x1);
                    Canvas.SetTop(border, rowY + 1);
                    ApiViewGraphCanvas.Children.Add(border);
                }

                yCursor += laneBlockHeight + laneGap;
            }
        }
    }
}
