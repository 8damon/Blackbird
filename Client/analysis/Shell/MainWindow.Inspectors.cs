using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private void OpenEtwInspector()
        {
            var snapshot = EtwPaneHost.SnapshotItems();
            if (snapshot.Count == 0)
            {
                return;
            }

            TelemetryInspectorWindow.ShowForRows(this, "ETW Inspector",
                                                 "Grouped ETW uplink with per-occurrence drill-down", snapshot,
                                                 EtwPaneHost.GetSelectedGroupClone(), ResolveHandleEvidenceClone);
        }

        private void OpenHeuristicsInspector()
        {
            var snapshot = HeuristicsPaneHost.SnapshotItems();
            if (snapshot.Count == 0)
            {
                return;
            }

            TelemetryInspectorWindow.ShowForRows(
                this, "Detections", "Prioritized signals with actor, target, context, and evidence drill-down",
                snapshot, HeuristicsPaneHost.GetSelectedGroupClone(), ResolveHandleEvidenceClone);
        }

        private void OpenProcessRelationsInspector()
        {
            var snapshot = ProcessRelationsPaneHost.SnapshotItems();
            if (snapshot.Count == 0)
            {
                return;
            }

            TelemetryInspectorWindow.ShowForRows(
                this, "Process Relations", "Cross-process relation browser with actor-target drill-down", snapshot,
                ProcessRelationsPaneHost.GetSelectedGroupClone(), ResolveHandleEvidenceClone);
        }

        private void OpenFilesystemInspector()
        {
            var snapshot = FilesystemPaneHost.SnapshotItems();
            if (snapshot.Count == 0)
            {
                return;
            }

            TelemetryInspectorWindow.ShowForRows(
                this, "Filesystem", "Grouped filesystem activity with path and operation filters", snapshot,
                FilesystemPaneHost.GetSelectedGroupClone(), ResolveHandleEvidenceClone);
        }

        private void OpenRegistryInspector()
        {
            var snapshot = RegistryPaneHost.SnapshotItems();
            if (snapshot.Count == 0)
            {
                return;
            }

            TelemetryInspectorWindow.ShowForRows(
                this, "Registry", "Grouped registry operations with key path and operation filters", snapshot,
                RegistryPaneHost.GetSelectedGroupClone(), ResolveHandleEvidenceClone);
        }

        private void OpenOperatorCaseWindow()
        {
            int pid = _currentSession?.Pid ?? TryGetPid();
            OperatorCaseReport report =
                OperatorCaseBuilder.Build(pid, HeuristicsPaneHost.SnapshotItems(), EtwPaneHost.SnapshotItems(),
                                          FilesystemPaneHost.SnapshotItems(), RegistryPaneHost.SnapshotItems(),
                                          ProcessRelationsPaneHost.SnapshotItems(), DiagnosticsState.SnapshotEntries());

            ProcessSessionTab? baselineTab = FindOperatorCaseBaselineTab();
            if (baselineTab != null)
            {
                OperatorCaseReport baseline = OperatorCaseBuilder.Build(
                    baselineTab.Pid, SnapshotOperatorCaseRows(baselineTab, "heuristics"),
                    SnapshotOperatorCaseRows(baselineTab, "etw"), SnapshotOperatorCaseRows(baselineTab, "filesystem"),
                    SnapshotOperatorCaseRows(baselineTab, "registry"),
                    SnapshotOperatorCaseRows(baselineTab, "relations"), Array.Empty<DiagnosticsStateEntry>());

                OperatorCaseBuilder.ApplyBaselineComparison(
                    report, baseline, NormalizeSessionTitle(baselineTab.Title ?? $"PID {baselineTab.Pid}"));
            }

            OperatorCaseWindow.ShowForReport(this, report);
        }

        private ProcessSessionTab? FindOperatorCaseBaselineTab()
        {
            if (_currentSession == null || _processTabs.Count < 2)
            {
                return null;
            }

            string currentTitle = NormalizeSessionTitle(_currentSession.Title);
            string currentSubject = _currentSession.AnalysisSubjectPath;
            return _processTabs.Where(x => !ReferenceEquals(x, _currentSession))
                .OrderByDescending(
                    x => !string.IsNullOrWhiteSpace(currentSubject) &&
                         string.Equals(x.AnalysisSubjectPath, currentSubject, StringComparison.OrdinalIgnoreCase))
                .ThenByDescending(x => string.Equals(NormalizeSessionTitle(x.Title), currentTitle,
                                                     StringComparison.OrdinalIgnoreCase))
                .ThenByDescending(x => x.CaptureStartUtc)
                .FirstOrDefault();
        }

        private IReadOnlyList<GroupedEventRow> SnapshotOperatorCaseRows(ProcessSessionTab tab, string kind)
        {
            if (ReferenceEquals(tab, _currentSession))
            {
                return kind switch { "heuristics" => HeuristicsPaneHost.SnapshotItems(),
                                     "etw" => EtwPaneHost.SnapshotItems(),
                                     "filesystem" => FilesystemPaneHost.SnapshotItems(),
                                     "registry" => RegistryPaneHost.SnapshotItems(),
                                     "relations" => ProcessRelationsPaneHost.SnapshotItems(),
                                     _ => Array.Empty<GroupedEventRow>() };
            }

            Dictionary<int, List<GroupedEventRow>> source =
                kind switch { "heuristics" => _heuristicsHistoryByPid,
                              "etw" => _etwHistoryByPid,
                              "filesystem" => _filesystemHistoryByPid,
                              "registry" => _registryHistoryByPid,
                              "relations" => _relationsHistoryByPid,
                              _ => new Dictionary<int, List<GroupedEventRow>>() };

            return source.TryGetValue(tab.Pid, out List<GroupedEventRow>? rows)
                       ? rows.Select(static x => x.Clone()).ToList()
                       : Array.Empty<GroupedEventRow>();
        }

        private void OperatorCase_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            OpenOperatorCaseWindow();
        }

        private void SelectApiViewRowByApiName(string apiName)
        {
            if (ApiViewDataGrid == null || string.IsNullOrWhiteSpace(apiName))
            {
                return;
            }

            ApiCallGraphMainRowView? match =
                _apiViewRows.Where(x => string.Equals(x.ApiName, apiName, StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(x => x.Hits)
                    .ThenByDescending(x => x.LastSeen, StringComparer.Ordinal)
                    .FirstOrDefault();
            if (match == null)
            {
                return;
            }

            ApiViewDataGrid.SelectedItem = match;
            ApiViewDataGrid.ScrollIntoView(match);
            UpdateApiViewSelection(match);
        }

        private void OpenApiInspector(string apiName)
        {
            if (string.IsNullOrWhiteSpace(apiName))
            {
                return;
            }

            List<GroupedEventRow> snapshot = BuildApiInspectorSnapshot(apiName);
            if (snapshot.Count == 0)
            {
                return;
            }

            GroupedEventRow? selectedGroup = null;
            if (ApiViewDataGrid?.SelectedItem is ApiCallGraphMainRowView selectedRow &&
                string.Equals(selectedRow.ApiName, apiName, StringComparison.OrdinalIgnoreCase))
            {
                selectedGroup = snapshot.FirstOrDefault(
                    x => string.Equals(x.GroupKey, selectedRow.GraphKey, StringComparison.Ordinal));
            }

            string subtitle = $"{apiName} grouped by caller, target, thread, and sensor";
            TelemetryInspectorWindow.ShowForRows(this, $"{apiName} Inspector", subtitle, snapshot, selectedGroup,
                                                 ResolveHandleEvidenceClone);
        }

        private List<GroupedEventRow> BuildApiInspectorSnapshot(string apiName)
        {
            var rows = new List<GroupedEventRow>();
            foreach ((string graphKey, ApiCallGraphRowSnapshot row) in _apiGraphRowsByKey
                         .Where(x => string.Equals(x.Value.ApiName, apiName, StringComparison.OrdinalIgnoreCase))
                         .OrderByDescending(x => x.Value.Hits)
                         .ThenByDescending(x => x.Value.LastSeenUtc))
            {
                uint targetPid = row.TargetPid != 0 ? row.TargetPid : row.SourcePid;
                string sourceName = GetApiGraphProcessName(row.SourcePid);
                string targetName = GetApiGraphProcessName(targetPid);
                string sensor = _apiGraphSensorByKey.TryGetValue(graphKey, out string? sensorLabel) ? sensorLabel : row.SensorOrigin;
                string decodedAction = _apiGraphActionByKey.TryGetValue(graphKey, out string? actionText) ? actionText : row.ApiName;
                string detailText = _apiGraphDecodedByKey.TryGetValue(graphKey, out string? detail) ? detail : string.Empty;

                var grouped = new GroupedEventRow {
                    GroupKey = graphKey,       LastSeenUtc = row.LastSeenUtc,
                    Event = row.ApiName,       Severity = string.IsNullOrWhiteSpace(sensor) ? "API" : sensor,
                    Detection = decodedAction, Hits = Math.Max(1, row.Hits)
                };

                grouped.Details.Add(new GroupedEventDetailRow {
                    TimestampUtc = row.LastSeenUtc, Event = row.ApiName,
                    Severity = string.IsNullOrWhiteSpace(sensor) ? "API" : sensor, Detection = decodedAction,
                    Source = string.IsNullOrWhiteSpace(sensor) ? "API Graph" : sensor,
                    Actor = string.IsNullOrWhiteSpace(sourceName)
                                ? $"pid:{row.SourcePid.ToString(CultureInfo.InvariantCulture)}"
                                : sourceName,
                    Target = string.IsNullOrWhiteSpace(targetName)
                                 ? (targetPid == 0 ? string.Empty
                                                   : $"pid:{targetPid.ToString(CultureInfo.InvariantCulture)}")
                                 : targetName,
                    ActorPid = row.SourcePid, TargetPid = targetPid,
                    ActorToolTip = row.SourcePid == 0 ? string.Empty
                                                      : $"PID {row.SourcePid.ToString(CultureInfo.InvariantCulture)}",
                    TargetToolTip =
                        targetPid == 0 ? string.Empty : $"PID {targetPid.ToString(CultureInfo.InvariantCulture)}",
                    ArgumentSummary =
                        row.ThreadId == 0
                            ? string.Empty
                            : $"thread={row.ThreadId.ToString(CultureInfo.InvariantCulture)} hits={Math.Max(1, row.Hits).ToString(CultureInfo.InvariantCulture)}",
                    Details = detailText
                });

                rows.Add(grouped);
            }

            return rows;
        }

        private IoctlParsedEvent? ResolveHandleEvidenceClone(uint actorPid, uint targetPid)
        {
            if (actorPid == 0 || targetPid == 0)
            {
                return null;
            }

            if (TryGetHandleEvidence(actorPid, targetPid, out IoctlParsedEvent evidence))
            {
                return evidence.Clone();
            }

            return null;
        }
    }
}
