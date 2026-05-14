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
        private TelemetryEvent? HandleApiHookEvent(BrokerEtwEventView view)
        {
            if (!ShouldIncludeApiGraphView(view))
            {
                return null;
            }

            string apiName = !string.IsNullOrWhiteSpace(view.EventName)
                                 ? view.EventName
                                 : (!string.IsNullOrWhiteSpace(view.Operation) ? view.Operation : "unknown");
            string sensorOrigin = EventDetailFormatting.ClassifyHookSensorOrigin(view);
            uint sourcePid = view.ActorPid != 0 ? view.ActorPid : view.ProcessPid;
            if (sourcePid == 0)
            {
                sourcePid = view.EventProcessId;
            }
            uint targetPid = view.TargetPid != 0 ? view.TargetPid : sourcePid;
            uint threadId = view.ThreadId != 0 ? view.ThreadId : view.EventThreadId;
            if (sourcePid == 0)
            {
                return null;
            }

            string callerOrigin = NormalizeApiCallerOrigin(view.CallerOriginLabel);
            Dictionary<string, string> hookFields = BuildHookFieldMap(view);
            string originModule = NormalizeApiOriginModule(ResolveHookOriginModule(view, hookFields));
            string key =
                BuildApiGraphKey(sourcePid, targetPid, threadId, apiName, sensorOrigin, callerOrigin, originModule);
            int currentHits;
            if (_apiGraphRowsByKey.TryGetValue(key, out ApiCallGraphRowSnapshot? existing))
            {
                existing.Hits = Math.Max(1, existing.Hits + 1);
                existing.LastSeenUtc = view.TimestampUtc;
                existing.SensorOrigin = sensorOrigin;
                existing.CallerOrigin = callerOrigin;
                existing.OriginModule = originModule;
                currentHits = existing.Hits;
            }
            else
            {
                _apiGraphRowsByKey[key] = new ApiCallGraphRowSnapshot { ApiName = apiName,
                                                                        SensorOrigin = sensorOrigin,
                                                                        CallerOrigin = callerOrigin,
                                                                        OriginModule = originModule,
                                                                        SourcePid = sourcePid,
                                                                        TargetPid = targetPid,
                                                                        ThreadId = threadId,
                                                                        Hits = 1,
                                                                        FirstSeenUtc = view.TimestampUtc,
                                                                        LastSeenUtc = view.TimestampUtc };
                currentHits = 1;
            }

            string rawReason = view.Reason ?? string.Empty;
            _apiGraphReasonByKey[key] = rawReason;
            (string decodedAction, string decodedDetail) = BuildApiDecodedAction(view, rawReason);
            _apiGraphActionByKey[key] = decodedAction;
            _apiGraphDecodedByKey[key] = decodedDetail;
            string frameSummary = BuildHookFrameSummary(view, hookFields);
            _apiGraphFramesByKey[key] = frameSummary;
            _apiGraphSensorByKey[key] = sensorOrigin;
            ApiCallStructuredFields structured = BuildApiCallStructuredFields(apiName, rawReason, decodedAction, view);
            ApiCallGraphRowSnapshot snapshot = _apiGraphRowsByKey[key];
            snapshot.ActionLabel = decodedAction;
            snapshot.DetailFull = decodedDetail;
            snapshot.CallChainLabel = frameSummary;
            snapshot.ContextLabel = structured.Field2Value;
            snapshot.FlagsLabel = structured.Field4Value;

            ScheduleApiGraphSnapshot();
            if (string.IsNullOrWhiteSpace(decodedDetail))
            {
                return null;
            }

            if (!ShouldEmitApiTimelineEvent(key, currentHits, view.TimestampUtc))
            {
                return null;
            }

            return new TelemetryEvent { TimestampUtc = view.TimestampUtc,
                                        PID = unchecked((int)sourcePid),
                                        TID = unchecked((int)threadId),
                                        Group = EventDetailFormatting.HookTimelineGroup(view),
                                        SubType = apiName,
                                        Summary =
                                            $"{apiName} [caller {sourcePid} target {targetPid} hits {currentHits}]",
                                        Details = decodedDetail };
        }

        private bool ShouldIncludeApiGraphView(BrokerEtwEventView view)
        {
            return EventDetailFormatting.IsApiGraphCandidate(view);
        }

        private bool ShouldEmitApiTimelineEvent(string key, int hits, DateTime timestampUtc)
        {
            if (hits <= 1)
            {
                _apiGraphTimelineLastEmitByKey[key] = timestampUtc;
                return true;
            }

            if (!_apiGraphTimelineLastEmitByKey.TryGetValue(key, out DateTime lastEmitUtc))
            {
                _apiGraphTimelineLastEmitByKey[key] = timestampUtc;
                return true;
            }

            bool milestone = (hits & (hits - 1)) == 0 || (hits % 32) == 0;
            bool elapsed = (timestampUtc - lastEmitUtc) >= ApiTimelineEmissionWindow;
            if (!milestone && !elapsed)
            {
                return false;
            }

            _apiGraphTimelineLastEmitByKey[key] = timestampUtc;
            return true;
        }

        private void PublishApiGraphSnapshot()
        {
            BackfillApiGraphFromEtwHistoryIfNeeded();

            var snapshot = _apiGraphRowsByKey.Values.Select(static x => x.Clone())
                               .OrderByDescending(x => x.Hits)
                               .ThenByDescending(x => x.LastSeenUtc)
                               .Take(800)
                               .ToList();

            _apiGraphSnapshotRows.Clear();
            _apiGraphSnapshotRows.AddRange(snapshot);
            RefreshApiViewPresentation();
        }

        private void BackfillApiGraphFromEtwHistoryIfNeeded()
        {
            if (_apiGraphRowsByKey.Count != 0)
            {
                return;
            }

            IEnumerable<GroupedEventRow> sourceGroups =
                EtwPaneHost.ItemCount > 0
                    ? EtwPaneHost.SnapshotItems()
                    : (_currentSession != null && _etwHistoryByPid.TryGetValue(_currentSession.Pid, out var history)
                           ? history
                           : Array.Empty<GroupedEventRow>());
            foreach (GroupedEventDetailRow detail in sourceGroups.SelectMany(x => x.Details))
            {
                ObserveApiGraphDetailFallback(detail);
            }
        }

        private void ObserveApiGraphDetailFallback(GroupedEventDetailRow detail)
        {
            if (detail == null || string.IsNullOrWhiteSpace(detail.Event) || !IsLikelyApiHookDetail(detail))
            {
                return;
            }

            string apiName = detail.Event;
            string sensorOrigin = detail.Source.IndexOf("kernel", StringComparison.OrdinalIgnoreCase) >= 0
                                      ? "Kernel Hook"
                                  : detail.Source.IndexOf("hook", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                          detail.Detection.StartsWith("USERMODE_", StringComparison.OrdinalIgnoreCase)
                                      ? "Usermode Hook"
                                      : "Unclassified";
            string callerOrigin = "unknown";
            string originModule = "unknown";
            uint sourcePid = detail.ActorPid;
            uint targetPid = detail.TargetPid != 0 ? detail.TargetPid : detail.ActorPid;
            uint threadId = 0;
            _ = uint.TryParse(detail.EventTid, NumberStyles.Integer, CultureInfo.InvariantCulture, out threadId);
            string key =
                BuildApiGraphKey(sourcePid, targetPid, threadId, apiName, sensorOrigin, callerOrigin, originModule);
            if (_apiGraphRowsByKey.TryGetValue(key, out ApiCallGraphRowSnapshot? existing))
            {
                existing.Hits = Math.Max(1, existing.Hits + Math.Max(1, detail.HitCount));
                existing.LastSeenUtc = detail.TimestampUtc;
                return;
            }

            _apiGraphRowsByKey[key] = new ApiCallGraphRowSnapshot {
                ApiName = apiName,
                SensorOrigin = sensorOrigin,
                CallerOrigin = callerOrigin,
                OriginModule = originModule,
                ActionLabel = string.IsNullOrWhiteSpace(detail.Detection) ? apiName : detail.Detection,
                DetailFull = string.IsNullOrWhiteSpace(detail.Details) ? detail.ArgumentSummary : detail.Details,
                CallChainLabel = string.Empty,
                ContextLabel = detail.ArgumentSummary,
                FlagsLabel = string.IsNullOrWhiteSpace(detail.Flags) ? detail.Access : detail.Flags,
                SourcePid = sourcePid,
                TargetPid = targetPid,
                ThreadId = threadId,
                Hits = Math.Max(1, detail.HitCount),
                FirstSeenUtc = detail.TimestampUtc,
                LastSeenUtc = detail.TimestampUtc
            };
            _apiGraphSensorByKey[key] = sensorOrigin;
        }

        private static bool IsLikelyApiHookDetail(GroupedEventDetailRow detail)
        {
            if (detail.Source.IndexOf("hook", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }

            if (detail.Detection.StartsWith("USERMODE_", StringComparison.OrdinalIgnoreCase))
            {
                return !detail.Detection.Contains("INTEGRITY", StringComparison.OrdinalIgnoreCase);
            }

            return detail.Event.StartsWith("Nt", StringComparison.OrdinalIgnoreCase) ||
                   detail.Event.StartsWith("Zw", StringComparison.OrdinalIgnoreCase);
        }

        private bool ObserveExtendedActivity(BrokerEtwEventView view)
        {
            bool changed = false;
            if (TryBuildExtendedActivityRow(view, out ExtendedActivityRowSnapshot? row) && row != null)
            {
                changed |= UpsertExtendedActivityRow(row);
            }

            IReadOnlyList<ProcessCapabilityObservation> capabilities = ProcessCapabilityCatalog.Observe(view);
            for (int i = 0; i < capabilities.Count; i += 1)
            {
                ProcessCapabilityObservation capability = capabilities[i];
                var capabilityRow =
                    new ExtendedActivityRowSnapshot { TypeLabel = "Process Capability",
                                                      ActorLabel = FormatApiProcessLabel(capability.ActorPid),
                                                      TargetLabel = FormatApiTargetLabel(capability.ActorPid,
                                                                                         capability.TargetPid),
                                                      SubjectLabel = capability.Name,
                                                      OperationLabel = capability.State,
                                                      DetailLabel = capability.Detail,
                                                      LastSeenUtc = capability.TimestampUtc,
                                                      LastSeenLabel = FormatApiRelativeAge(capability.TimestampUtc),
                                                      Hits = 1 };
                changed |= UpsertExtendedActivityRow(capabilityRow);
            }

            return changed;
        }

        private bool UpsertExtendedActivityRow(ExtendedActivityRowSnapshot row)
        {
            string key = BuildExtendedActivityKey(row.TypeLabel, row.ActorLabel, row.TargetLabel, row.SubjectLabel,
                                                  row.OperationLabel);
            if (_extendedRowsByKey.TryGetValue(key, out ExtendedActivityRowSnapshot? existing))
            {
                existing.Hits = Math.Max(1, existing.Hits + 1);
                existing.LastSeenUtc = row.LastSeenUtc;
                existing.LastSeenLabel = row.LastSeenLabel;
                existing.DetailLabel = row.DetailLabel;
                return true;
            }

            _extendedRowsByKey[key] = row;
            return true;
        }

        private void ScheduleExtendedActivitySnapshot()
        {
            _extendedViewSnapshotDirty = true;
            _extendedViewRefreshTimer.Start();
        }

        private void FlushExtendedActivitySnapshot()
        {
            if (!_extendedViewSnapshotDirty)
            {
                _extendedViewRefreshTimer.Stop();
                return;
            }

            _extendedViewSnapshotDirty = false;
            PublishExtendedActivitySnapshot();
        }

        private void PublishExtendedActivitySnapshot()
        {
            List<ExtendedActivityRowSnapshot> snapshot = _extendedRowsByKey.Values.Select(static x => x.Clone())
                                                             .OrderByDescending(x => x.LastSeenUtc)
                                                             .ThenByDescending(x => x.Hits)
                                                             .Take(800)
                                                             .ToList();

            _extendedViewRows.ReplaceAll(snapshot);
            _extendedComRows.ReplaceAll(snapshot.Where(IsExtendedComRow).ToList());
            _extendedEtwRows.ReplaceAll(snapshot.Where(IsExtendedEtwRow).ToList());
            _extendedJobRows.ReplaceAll(snapshot.Where(IsExtendedJobRow).ToList());
            _extendedYaraRows.ReplaceAll(snapshot.Where(IsExtendedYaraRow).ToList());
            _extendedStringRows.ReplaceAll(snapshot.Where(IsExtendedStringRow).ToList());
            _extendedCapabilityRows.ReplaceAll(snapshot.Where(IsExtendedCapabilityRow).ToList());
            if (ExtendedViewSummaryBlock != null)
            {
                ExtendedViewSummaryBlock.Text =
                    snapshot.Count == 0 ? "No extended activity yet"
                                        : $"Activities: {snapshot.Count} / Hits: {snapshot.Sum(x => x.Hits)}";
            }
        }

        private static bool IsExtendedComRow(ExtendedActivityRowSnapshot row)
        {
            return row.TypeLabel.Contains("COM", StringComparison.OrdinalIgnoreCase) ||
                   row.TypeLabel.Contains("WMI", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsExtendedEtwRow(ExtendedActivityRowSnapshot row)
        {
            return row.TypeLabel.Contains("ETW", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsExtendedJobRow(ExtendedActivityRowSnapshot row)
        {
            return row.TypeLabel.Contains("Job", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsExtendedYaraRow(ExtendedActivityRowSnapshot row)
        {
            return row.TypeLabel.Contains("YARA", StringComparison.OrdinalIgnoreCase) ||
                   row.TypeLabel.Contains("SIGMA", StringComparison.OrdinalIgnoreCase) ||
                   row.TypeLabel.Contains("Rules", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsExtendedStringRow(ExtendedActivityRowSnapshot row)
        {
            return row.TypeLabel.Contains("String", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsExtendedCapabilityRow(ExtendedActivityRowSnapshot row)
        {
            return row.TypeLabel.Contains("Capability", StringComparison.OrdinalIgnoreCase);
        }

        private bool TryBuildExtendedActivityRow(BrokerEtwEventView view, out ExtendedActivityRowSnapshot? row)
        {
            row = null;
            string detection = view.DetectionName ?? string.Empty;
            string type;
            string operation;

            switch (detection)
            {
            case "USERMODE_COM_INIT":
                type = "COM Init";
                operation = "Initialize";
                break;
            case "USERMODE_COM_SECURITY_INIT":
                type = "COM Security";
                operation = "InitializeSecurity";
                break;
            case "USERMODE_COM_INSTANCE_CREATE":
                type = "COM Activation";
                operation = "CreateInstance";
                break;
            case "USERMODE_WMI_ACTIVITY":
                type = "WMI";
                operation = "Locator Activation";
                break;
            case "USERMODE_ETW_PROVIDER_REGISTER":
                type = "ETW Provider";
                operation = "Register";
                break;
            case "USERMODE_ETW_PROVIDER_UNREGISTER":
                type = "ETW Provider";
                operation = "Unregister";
                break;
            case "USERMODE_ETW_SESSION_CONTROL":
                type = "ETW Session";
                operation = "StartTrace";
                break;
            case "USERMODE_ETW_SUBSCRIPTION":
                type = "ETW Subscription";
                operation = "EnableTrace";
                break;
            case "USERMODE_JOB_OBJECT_ACTIVITY":
                type = "Job Object";
                operation = !string.IsNullOrWhiteSpace(view.EventName) ? view.EventName : "Activity";
                break;
            default:
                if (!TryBuildGenericExtendedActivityLabels(view, out type, out operation))
                {
                    return false;
                }
                break;
            }

            uint actorPid = ResolveExtendedActorPid(view);
            uint targetPid = ResolveExtendedTargetPid(view, actorPid);
            string subject = ExtractExtendedSubject(view);
            row = new ExtendedActivityRowSnapshot { TypeLabel = type,
                                                    ActorLabel = FormatApiProcessLabel(actorPid),
                                                    TargetLabel = FormatApiTargetLabel(actorPid, targetPid),
                                                    SubjectLabel = subject,
                                                    OperationLabel = operation,
                                                    DetailLabel =
                                                        FirstNonBlank(view.Reason, view.ArgumentSummary, view.Details),
                                                    LastSeenUtc = view.TimestampUtc,
                                                    LastSeenLabel = FormatApiRelativeAge(view.TimestampUtc),
                                                    Hits = 1 };
            return true;
        }

        private static bool TryBuildGenericExtendedActivityLabels(BrokerEtwEventView view, out string type,
                                                                  out string operation)
        {
            type = view.Family switch { BlackbirdNative.IpcEtwFamilyHandle => "Handle",
                                        BlackbirdNative.IpcEtwFamilyThread => "Thread",
                                        BlackbirdNative.IpcEtwFamilyProcess => "Process",
                                        BlackbirdNative.IpcEtwFamilyImage => "Image",
                                        BlackbirdNative.IpcEtwFamilyRegistry => "Registry",
                                        BlackbirdNative.IpcEtwFamilyApc => "APC",
                                        BlackbirdNative.IpcEtwFamilyDetection => "Detection",
                                        BlackbirdNative.IpcEtwFamilyThreatIntel => "Threat Intel",
                                        BlackbirdNative.IpcEtwFamilySocket => "Socket",
                                        BlackbirdNative.IpcEtwFamilyUserHook => "API",
                                        _ => string.IsNullOrWhiteSpace(view.Source) ? string.Empty : view.Source };
            operation = FirstNonBlank(view.Operation, view.EventName, view.DetectionName, "Activity");

            if (string.IsNullOrWhiteSpace(type))
            {
                return false;
            }

            return view.Family == BlackbirdNative.IpcEtwFamilyUserHook ||
                   view.Family == BlackbirdNative.IpcEtwFamilySocket ||
                   view.Family == BlackbirdNative.IpcEtwFamilyRegistry ||
                   view.Family == BlackbirdNative.IpcEtwFamilyImage ||
                   view.Family == BlackbirdNative.IpcEtwFamilyProcess ||
                   view.Family == BlackbirdNative.IpcEtwFamilyThread ||
                   view.Family == BlackbirdNative.IpcEtwFamilyHandle ||
                   !string.IsNullOrWhiteSpace(view.DetectionName) || view.Severity >= 2;
        }

        private static uint ResolveExtendedActorPid(BrokerEtwEventView view) =>
            FirstNonZero(view.ActorPid, view.CallerPid, view.CreatorPid, view.ProcessPid, view.EventProcessId);

        private static uint ResolveExtendedTargetPid(BrokerEtwEventView view, uint actorPid) =>
            FirstNonZero(view.TargetPid, view.ExplicitTargetPid, view.ProcessPid, view.EventProcessId, actorPid);

        private static string ExtractExtendedSubject(BrokerEtwEventView view)
        {
            string reason = view.Reason ?? string.Empty;
            string[] tokens = new[] { "class=", "provider=", "name=", "mode=", "class=" };
            foreach (string token in tokens)
            {
                int start = reason.IndexOf(token, StringComparison.OrdinalIgnoreCase);
                if (start < 0)
                {
                    continue;
                }

                start += token.Length;
                int end = reason.IndexOf(' ', start);
                if (end < 0)
                {
                    end = reason.Length;
                }

                string value = reason.Substring(start, end - start).Trim();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }

            return FirstNonBlank(view.KeyPath, view.ValueName, view.ImagePath, view.OriginPath, view.CommandLine,
                                 view.ClassName, view.ArgumentSummary, view.EventName, view.DetectionName);
        }

        private static uint FirstNonZero(params uint[] values)
        {
            foreach (uint value in values)
            {
                if (value != 0)
                {
                    return value;
                }
            }

            return 0;
        }

        private static string FirstNonBlank(params string?[] values)
        {
            foreach (string? value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value.Trim();
                }
            }

            return string.Empty;
        }

        private static string BuildExtendedActivityKey(string type, string actor, string target, string subject,
                                                       string operation)
        {
            return string.Join("|", type, actor, target, subject, operation);
        }

        private void RefreshApiViewPresentation()
        {
            string? selectedKey = (ApiViewDataGrid?.SelectedItem as ApiCallGraphMainRowView)?.GraphKey;
            bool apiViewVisible = _mainViewMode == MainInterfaceViewMode.Api && ApiViewBorder != null &&
                                  ApiViewBorder.Visibility == Visibility.Visible;
            List<ApiCallGraphMainRowView> sourceRows =
                _apiViewPresentationMode == ApiViewPresentationMode.ThreadTimeline
                    ? BuildApiThreadTimelineRows(_apiGraphSnapshotRows)
                    : BuildApiCallGraphRows(_apiGraphSnapshotRows);
            _apiViewSnapshotRows.Clear();
            _apiViewSnapshotRows.AddRange(sourceRows);

            List<ApiCallGraphMainRowView> filteredRows = ApplyApiViewFilters(sourceRows);
            _apiViewRows.ReplaceAll(filteredRows);

            if (ApiViewSummaryBlock != null)
            {
                string noun =
                    _apiViewPresentationMode == ApiViewPresentationMode.ThreadTimeline ? "Thread/API Rows" : "Patterns";
                ApiViewSummaryBlock.Text =
                    sourceRows.Count == 0 ? "No API hook data yet"
                    : filteredRows.Count == sourceRows.Count
                        ? $"{noun}: {filteredRows.Count} / Calls: {filteredRows.Sum(x => x.Hits)}"
                        : $"{noun}: {filteredRows.Count}/{sourceRows.Count} / Calls: {filteredRows.Sum(x => x.Hits)}";
            }
            if (apiViewVisible && ApiViewGraphCanvas != null)
            {
                RenderApiPresentationCanvas(filteredRows, selectedKey);
            }
            DiagnosticsState.SetValue(
                "API Graph",
                $"{(_apiViewPresentationMode == ApiViewPresentationMode.ThreadTimeline ? "threads" : "patterns")}={filteredRows.Count}/{sourceRows.Count} visible={apiViewVisible}");

            if (ApiViewDataGrid != null)
            {
                ApiCallGraphMainRowView? selected = null;
                if (!string.IsNullOrWhiteSpace(selectedKey))
                {
                    selected = _apiViewRows.FirstOrDefault(
                        x => string.Equals(x.GraphKey, selectedKey, StringComparison.Ordinal));
                }

                if (selected == null && _apiViewRows.Count > 0)
                {
                    selected = _apiViewRows[0];
                }

                ApiViewDataGrid.SelectedItem = selected;
                UpdateApiViewSelection(selected);
            }
        }

        private void RefreshApiGraphSelectionVisual()
        {
            if (_mainViewMode != MainInterfaceViewMode.Api || ApiViewBorder == null ||
                ApiViewBorder.Visibility != Visibility.Visible || ApiViewGraphCanvas == null)
            {
                return;
            }

            string? selectedKey = (ApiViewDataGrid?.SelectedItem as ApiCallGraphMainRowView)?.GraphKey;
            List<ApiCallGraphMainRowView> filteredRows = ApplyApiViewFilters(_apiViewSnapshotRows);
            RenderApiPresentationCanvas(filteredRows, selectedKey);
        }
    }
}
