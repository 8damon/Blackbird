using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace BlackbirdInterface
{
    public partial class EtwPane : UserControl
    {
        private const int MaxGroupCount = 256;
        private const int MaxDetailRowsPerGroup = 48;
        public event RoutedEventHandler? ReorderRequested;
        public event RoutedEventHandler? FloatRequested;
        public event RoutedEventHandler? CloseRequested;
        public event RoutedEventHandler? InspectRequested;

        private readonly GroupedEventPaneState _state = new();
        private bool _hasThreatIntelEvents;
        private string _feedFilter = "ALL FEEDS";
        private int _focusedPid;

        public int FocusedPid
        {
            set {
                _focusedPid = value;
                ApplyFilter();
            }
        }

        public EtwPane()
        {
            InitializeComponent();
            EventsGrid.ItemsSource = _state.VisibleItems;
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        internal int ItemCount => _state.ItemCount;
        internal int TotalRawCount => _state.TotalRawCount;
        internal int DetailRowCount => _state.TotalDetailRows;
        internal bool HasThreatIntelEvents => _hasThreatIntelEvents;

        internal void PushEvent(BrokerEtwEventView entry)
        {
            PushEvents(new[] { entry });
        }

        internal void PushEvents(IEnumerable<BrokerEtwEventView> entries)
        {
            foreach (BrokerEtwEventView entry in entries)
            {
                PushEventCore(entry);
            }

            UpdateSummary();
            UpdateNoDataOverlay();
        }

        private void PushEventCore(BrokerEtwEventView entry)
        {
            DateTime now = entry.LastSeenUtc == default ? entry.TimestampUtc : entry.LastSeenUtc;
            string eventName =
                EventDetailFormatting.IsThreatIntelEtwSource(entry) ? $"TI/{entry.EventName}" : entry.EventName;
            string severity = EventDetailFormatting.SeverityLabel(entry.Severity);
            string detection = BuildDetectionLabel(entry);
            string source = string.IsNullOrWhiteSpace(entry.Source) ? "BK" : entry.Source;
            string actor = ProcessIdentityResolver.Describe(entry.ActorPid);
            string target = ProcessIdentityResolver.Describe(entry.TargetPid);
            string actorToolTip = ProcessIdentityResolver.HoverText(entry.ActorPid);
            string targetToolTip = ProcessIdentityResolver.HoverText(entry.TargetPid);
            bool splitByArgumentSignature = ShouldSplitByArgumentSignature(entry, eventName);
            string argSig = splitByArgumentSignature ? entry.ArgumentSummary : string.Empty;
            string key = BuildAggregationKey(eventName, severity, detection, source, argSig, splitByArgumentSignature);

            _state.IncrementRawCount(1);
            if (EventDetailFormatting.IsThreatIntelEtwSource(entry))
            {
                _hasThreatIntelEvents = true;
            }

            if (_state.TryGetRow(key, out GroupedEventRow? existing))
            {
                existing.LastSeenUtc = now;
                existing.Hits = Math.Max(1, existing.Hits + 1);
                if (!string.IsNullOrWhiteSpace(argSig))
                {
                    existing.ArgumentPreview = argSig;
                }

                bool aggregated = false;
                if (string.IsNullOrEmpty(argSig) && existing.Details.Count > 0)
                {
                    GroupedEventDetailRow latestDetail = existing.Details[^1];
                    latestDetail.HitCount += 1;
                    latestDetail.TimestampUtc = now;
                    aggregated = true;
                }
                else if (!string.IsNullOrEmpty(argSig) &&
                    _state.TryGetDetail(key, argSig, out GroupedEventDetailRow? matchingDetail))
                {
                    matchingDetail.HitCount += 1;
                    matchingDetail.TimestampUtc = now;
                    aggregated = true;
                }

                if (!aggregated)
                {
                    string detailText = entry.Details;
                    var newDetail = new GroupedEventDetailRow { TimestampUtc = now,
                                                                Event = eventName,
                                                                Severity = severity,
                                                                Detection = detection,
                                                                Source = source,
                                                                Actor = actor,
                                                                Target = target,
                                                                ActorPid = entry.ActorPid,
                                                                TargetPid = entry.TargetPid,
                                                                ActorToolTip = actorToolTip,
                                                                TargetToolTip = targetToolTip,
                                                                ArgumentSummary = argSig,
                                                                HitCount = 1,
                                                                Details = detailText };
                    existing.Details.Add(newDetail);
                    _state.RegisterDetail(existing, newDetail);

                    if (existing.Details.Count > MaxDetailRowsPerGroup)
                    {
                        GroupedEventDetailRow evictedDetail = existing.Details[0];
                        existing.Details.RemoveAt(0);
                        _state.ReplaceDetailCount(_state.TotalDetailRows - 1);
                        _state.RemoveDetailReference(key, evictedDetail);
                    }
                }

                SyncVisibleRow(existing);
            }
            else
            {
                string detailText = entry.Details;
                var firstDetail = new GroupedEventDetailRow { TimestampUtc = now,
                                                              Event = eventName,
                                                              Severity = severity,
                                                              Detection = detection,
                                                              Source = source,
                                                              Actor = actor,
                                                              Target = target,
                                                              ActorPid = entry.ActorPid,
                                                              TargetPid = entry.TargetPid,
                                                              ActorToolTip = actorToolTip,
                                                              TargetToolTip = targetToolTip,
                                                              ArgumentSummary = argSig,
                                                              HitCount = 1,
                                                              Details = detailText };
                var row = new GroupedEventRow { GroupKey = key,           LastSeenUtc = now,        Event = eventName,
                                                Severity = severity,      Detection = detection,    Hits = 1,
                                                ArgumentPreview = argSig, Details = { firstDetail } };
                _state.TrackRow(row);

                SyncVisibleRow(row);
            }

            _state.EvictOverflow(MaxGroupCount);
        }

        internal IReadOnlyList<GroupedEventRow> SnapshotItems() => _state.SnapshotItems();

        private static string BuildAggregationKey(string eventName, string severity, string detection, string source,
                                                  string argumentSignature, bool splitByArgumentSignature)
        {
            string baseKey = $"{eventName}|{severity}|{detection}|{source}";
            if (!splitByArgumentSignature || string.IsNullOrWhiteSpace(argumentSignature))
            {
                return baseKey;
            }

            return $"{baseKey}|{argumentSignature}";
        }

        private static bool ShouldSplitByArgumentSignature(BrokerEtwEventView entry, string eventName)
        {
            string apiName = string.IsNullOrWhiteSpace(entry.Operation) ? eventName : entry.Operation.Trim();
            return apiName.Equals("NtQueryInformationProcess", StringComparison.OrdinalIgnoreCase) ||
                   apiName.Equals("NtQueryVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                   apiName.Equals("NtQuerySystemInformation", StringComparison.OrdinalIgnoreCase) ||
                   apiName.Equals("NtQuerySystemInformationEx", StringComparison.OrdinalIgnoreCase) ||
                   apiName.Equals("NtOpenProcess", StringComparison.OrdinalIgnoreCase) ||
                   apiName.Equals("NtOpenThread", StringComparison.OrdinalIgnoreCase);
        }

        internal GroupedEventRow? GetSelectedGroupClone() => _state.GetSelectedGroupClone(EventsGrid.SelectedItem);

        internal void LoadHistory(IEnumerable<GroupedEventRow> groups)
        {
            _hasThreatIntelEvents = false;
            _state.LoadHistory(
                groups,
                clone =>
                {
                    clone.Hits = Math.Max(1, clone.Hits);
                    clone.Details = clone.Details.OrderBy(x => x.TimestampUtc).ToList();
                    if (clone.Details.Any(x => x.Source.Equals("ThreatIntel", StringComparison.OrdinalIgnoreCase)))
                    {
                        _hasThreatIntelEvents = true;
                    }

                    return clone;
                });

            ApplyFilter();
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        public void ClearAll()
        {
            _state.Clear();
            _hasThreatIntelEvents = false;
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        internal void TrimDetailPayload(int keepPerGroup)
        {
            int keep = Math.Max(1, keepPerGroup);
            _state.TrimDetailPayload(keep);
            ApplyFilter();
        }

        private void UpdateSummary()
        {
            if (SummaryBlock == null)
            {
                return;
            }

            string tiState = _hasThreatIntelEvents ? "TI: integrated" : "TI: unavailable";
            SummaryBlock.Text = $"Groups: {_state.ItemCount} / Events: {_state.TotalRawCount} / {tiState}";
        }

        private void UpdateNoDataOverlay()
        {
            if (NoDataOverlay == null)
            {
                return;
            }

            NoDataOverlay.Visibility = _state.ItemCount == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void ApplyFilter()
        {
            _state.ApplyFilter(MatchesFilter);
        }

        private void SyncVisibleRow(GroupedEventRow row) => _state.SyncVisibleRow(row, MatchesFilter);

        private bool MatchesFilter(GroupedEventRow row)
        {
            if (_focusedPid != 0 &&
                !row.Details.Any(d => d.ActorPid == (uint)_focusedPid || d.TargetPid == (uint)_focusedPid))
                return false;

            string filter = _feedFilter;
            if (string.IsNullOrWhiteSpace(filter) || filter.Equals("ALL FEEDS", StringComparison.OrdinalIgnoreCase))
                return true;

            return filter.ToUpperInvariant() switch {
                "THREATINTEL" =>
                    row.Event.StartsWith("TI/", StringComparison.OrdinalIgnoreCase) ||
                    row.Details.Any(x => x.Source.Equals("ThreatIntel", StringComparison.OrdinalIgnoreCase)),
                "DETECTION" => row.Detection.Contains("DETECTION", StringComparison.OrdinalIgnoreCase) ||
                               row.Event.Contains("Detection", StringComparison.OrdinalIgnoreCase),
                "PROCESS/THREAD" => row.Event.Contains("Process", StringComparison.OrdinalIgnoreCase) ||
                                    row.Event.Contains("Thread", StringComparison.OrdinalIgnoreCase),
                _ => true
            };
        }

        private void EventsGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            _ = sender;
            _ = e;
            if (EventsGrid.SelectedItem is GroupedEventRow)
            {
                InspectRequested?.Invoke(this, new RoutedEventArgs());
            }
        }

        private void EventsContextInspect_Click(object sender, RoutedEventArgs e) => InspectRequested?.Invoke(this, e);

        private void EventsContextCopySummary_Click(object sender, RoutedEventArgs e)
        {
            if (EventsGrid.SelectedItem is GroupedEventRow row)
            {
                Clipboard.SetText(
                    $"{row.LastSeenUtc:O} {row.Event} {row.Severity} hits={row.Hits} {row.Detection} {row.ArgumentPreview}");
            }
        }

        private void EventsContextCopyDetails_Click(object sender, RoutedEventArgs e)
        {
            if (EventsGrid.SelectedItem is GroupedEventRow row)
            {
                Clipboard.SetText(string.Join(Environment.NewLine, row.Details.Select(d => d.Details)));
            }
        }

        private void EventsGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
        {
            DataGridRow? row = FindAncestor<DataGridRow>(e.OriginalSource as DependencyObject);
            if (row == null)
            {
                return;
            }

            row.IsSelected = true;
            row.Focus();
        }

        private static T? FindAncestor<T>(DependencyObject? source)
            where T : DependencyObject
        {
            while (source != null)
            {
                if (source is T match)
                {
                    return match;
                }

                source = VisualTreeHelper.GetParent(source);
            }

            return null;
        }

        private void EtwBtnInspect_Click(object sender, RoutedEventArgs e) => InspectRequested?.Invoke(this, e);
        private void FeedFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = e;
            ComboBox? combo = sender as ComboBox ?? FeedFilter;
            _feedFilter = ((combo?.SelectedItem as ComboBoxItem)?.Content as string ?? "ALL FEEDS").Trim();
            ApplyFilter();
            UpdateNoDataOverlay();
        }

        private void EtwBtnReorder_Click(object sender, RoutedEventArgs e) => ReorderRequested?.Invoke(this, e);
        private void EtwBtnFloat_Click(object sender, RoutedEventArgs e) => FloatRequested?.Invoke(this, e);
        private void EtwBtnClose_Click(object sender, RoutedEventArgs e) => CloseRequested?.Invoke(this, e);

        private static string BuildDetectionLabel(BrokerEtwEventView entry)
        {
            string sensorOrigin = EventDetailFormatting.ClassifyHookSensorOrigin(entry);
            if (!string.IsNullOrWhiteSpace(entry.DetectionName))
            {
                return sensorOrigin == "Unclassified" ? entry.DetectionName
                                                      : $"{sensorOrigin.ToUpperInvariant()} | {entry.DetectionName}";
            }

            string eventName = (entry.EventName ?? string.Empty).Trim();
            if (eventName.Equals("ThreadTelemetry", StringComparison.OrdinalIgnoreCase))
            {
                if (entry.CorrelationFlags != 0)
                {
                    return $"THREAD_ACTIVITY[{EventDetailFormatting.DescribeCorrelationFlags(entry.CorrelationFlags)}]";
                }

                return "THREAD_ACTIVITY";
            }

            if (eventName.Equals("HandleTelemetry", StringComparison.OrdinalIgnoreCase))
            {
                return "HANDLE_ACTIVITY";
            }

            if (eventName.Equals("ApcTelemetry", StringComparison.OrdinalIgnoreCase))
            {
                return "APC_ACTIVITY";
            }

            if (eventName.Equals("DetectionTelemetry", StringComparison.OrdinalIgnoreCase))
            {
                return "DETECTION_UNSPECIFIED";
            }

            if (!string.IsNullOrWhiteSpace(eventName) &&
                eventName.EndsWith("Telemetry", StringComparison.OrdinalIgnoreCase))
            {
                string baseName = eventName[..^ "Telemetry".Length].Trim();
                if (!string.IsNullOrWhiteSpace(baseName))
                {
                    return $"{baseName.ToUpperInvariant()}_ACTIVITY";
                }
            }

            if (entry.Task == 0 && entry.Opcode == 0 && entry.EventId == 0)
            {
                return "TELEMETRY";
            }

            if (!string.IsNullOrWhiteSpace(eventName))
            {
                return sensorOrigin == "Unclassified" ? eventName : $"{sensorOrigin.ToUpperInvariant()} | {eventName}";
            }

            return "UNCLASSIFIED_EVENT";
        }
    }
}
