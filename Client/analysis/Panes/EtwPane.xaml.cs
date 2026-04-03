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

        private readonly BulkObservableCollection<GroupedEventRow> _items = new();
        private readonly List<GroupedEventRow> _allItems = new();
        private readonly Dictionary<string, GroupedEventRow> _byKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, GroupedEventRow> _visibleByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, Dictionary<string, GroupedEventDetailRow>> _detailArgSigByGroupKey = new(StringComparer.Ordinal);
        private int _totalRawCount;
        private int _totalDetailRows;
        private bool _hasThreatIntelEvents;
        private string _feedFilter = "ALL FEEDS";

        public EtwPane()
        {
            InitializeComponent();
            EventsGrid.ItemsSource = _items;
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        internal int ItemCount => _items.Count;
        internal int TotalRawCount => _totalRawCount;
        internal int DetailRowCount => _totalDetailRows;
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
            string eventName = EventDetailFormatting.IsThreatIntelEtwSource(entry)
                ? $"TI/{entry.EventName}"
                : entry.EventName;
            string severity = EventDetailFormatting.SeverityLabel(entry.Severity);
            string detection = BuildDetectionLabel(entry);
            string source = string.IsNullOrWhiteSpace(entry.Source) ? "Blackbird" : entry.Source;
            string actor = ProcessIdentityResolver.Describe(entry.ActorPid);
            string target = ProcessIdentityResolver.Describe(entry.TargetPid);
            string actorToolTip = ProcessIdentityResolver.HoverText(entry.ActorPid);
            string targetToolTip = ProcessIdentityResolver.HoverText(entry.TargetPid);
            string detailText = entry.Details;
            string argSig = entry.ArgumentSummary;
            string key = BuildAggregationKey(entry, eventName, severity, detection, source, argSig);

            _totalRawCount += 1;
            if (EventDetailFormatting.IsThreatIntelEtwSource(entry))
            {
                _hasThreatIntelEvents = true;
            }

            if (_byKey.TryGetValue(key, out GroupedEventRow? existing))
            {
                existing.LastSeenUtc = now;
                existing.Hits = Math.Max(1, existing.Hits + 1);
                if (!string.IsNullOrWhiteSpace(argSig))
                {
                    existing.ArgumentPreview = argSig;
                }

                // Aggregate by argument signature: identical arg patterns increment the existing
                // detail row's HitCount rather than adding a duplicate row.
                bool aggregated = false;
                if (!string.IsNullOrEmpty(argSig) &&
                    _detailArgSigByGroupKey.TryGetValue(key, out Dictionary<string, GroupedEventDetailRow>? argMap) &&
                    argMap.TryGetValue(argSig, out GroupedEventDetailRow? matchingDetail))
                {
                    matchingDetail.HitCount += 1;
                    matchingDetail.TimestampUtc = now;
                    aggregated = true;
                }

                if (!aggregated)
                {
                    var newDetail = new GroupedEventDetailRow
                    {
                        TimestampUtc = now,
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
                        Details = detailText
                    };
                    existing.Details.Add(newDetail);
                    _totalDetailRows += 1;

                    if (!string.IsNullOrEmpty(argSig))
                    {
                        if (!_detailArgSigByGroupKey.TryGetValue(key, out Dictionary<string, GroupedEventDetailRow>? map))
                        {
                            map = new Dictionary<string, GroupedEventDetailRow>(StringComparer.Ordinal);
                            _detailArgSigByGroupKey[key] = map;
                        }
                        map[argSig] = newDetail;
                    }

                    if (existing.Details.Count > MaxDetailRowsPerGroup)
                    {
                        GroupedEventDetailRow evictedDetail = existing.Details[0];
                        existing.Details.RemoveAt(0);
                        _totalDetailRows = Math.Max(0, _totalDetailRows - 1);
                        if (!string.IsNullOrEmpty(evictedDetail.ArgumentSummary) &&
                            _detailArgSigByGroupKey.TryGetValue(key, out Dictionary<string, GroupedEventDetailRow>? evictMap) &&
                            evictMap.TryGetValue(evictedDetail.ArgumentSummary, out GroupedEventDetailRow? mapped) &&
                            ReferenceEquals(mapped, evictedDetail))
                        {
                            evictMap.Remove(evictedDetail.ArgumentSummary);
                        }
                    }
                }

                SyncVisibleRow(existing);
            }
            else
            {
                var firstDetail = new GroupedEventDetailRow
                {
                    TimestampUtc = now,
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
                    Details = detailText
                };
                var row = new GroupedEventRow
                {
                    GroupKey = key,
                    LastSeenUtc = now,
                    Event = eventName,
                    Severity = severity,
                    Detection = detection,
                    Hits = 1,
                    ArgumentPreview = argSig,
                    Details = { firstDetail }
                };
                _allItems.Add(row);
                _byKey[key] = row;
                _totalDetailRows += row.Details.Count;

                if (!string.IsNullOrEmpty(argSig))
                {
                    _detailArgSigByGroupKey[key] = new Dictionary<string, GroupedEventDetailRow>(StringComparer.Ordinal)
                    {
                        [argSig] = firstDetail
                    };
                }

                SyncVisibleRow(row);
            }

            while (_allItems.Count > MaxGroupCount)
            {
                GroupedEventRow evicted = _allItems[0];
                string evictKey = evicted.GroupKey;
                _allItems.RemoveAt(0);
                _byKey.Remove(evictKey);
                _detailArgSigByGroupKey.Remove(evictKey);
                _totalDetailRows = Math.Max(0, _totalDetailRows - evicted.Details.Count);
                if (_visibleByKey.Remove(evictKey))
                {
                    _items.Remove(evicted);
                }
            }

        }

        internal IReadOnlyList<GroupedEventRow> SnapshotItems()
            => _allItems.Select(x => x.Clone()).ToList();

        private static string BuildAggregationKey(
            BrokerEtwEventView entry,
            string eventName,
            string severity,
            string detection,
            string source,
            string argumentSignature)
        {
            string baseKey = $"{eventName}|{severity}|{detection}|{source}";
            if (string.IsNullOrWhiteSpace(argumentSignature))
            {
                return baseKey;
            }

            string apiName = string.IsNullOrWhiteSpace(entry.Operation) ? eventName : entry.Operation.Trim();
            bool splitByArgumentSignature =
                apiName.Equals("NtQueryInformationProcess", StringComparison.OrdinalIgnoreCase) ||
                apiName.Equals("NtQueryVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                apiName.Equals("NtQuerySystemInformation", StringComparison.OrdinalIgnoreCase) ||
                apiName.Equals("NtQuerySystemInformationEx", StringComparison.OrdinalIgnoreCase) ||
                apiName.Equals("NtOpenProcess", StringComparison.OrdinalIgnoreCase) ||
                apiName.Equals("NtOpenThread", StringComparison.OrdinalIgnoreCase);

            return splitByArgumentSignature
                ? $"{baseKey}|{argumentSignature}"
                : baseKey;
        }

        internal GroupedEventRow? GetSelectedGroupClone()
            => (EventsGrid.SelectedItem as GroupedEventRow)?.Clone();

        internal void LoadHistory(IEnumerable<GroupedEventRow> groups)
        {
            _items.Clear();
            _allItems.Clear();
            _byKey.Clear();
            _visibleByKey.Clear();
            _detailArgSigByGroupKey.Clear();
            _totalRawCount = 0;
            _totalDetailRows = 0;
            _hasThreatIntelEvents = false;

            foreach (GroupedEventRow source in groups)
            {
                GroupedEventRow clone = source.Clone();
                clone.Hits = Math.Max(1, clone.Hits);
                clone.Details = clone.Details.OrderBy(x => x.TimestampUtc).ToList();
                _allItems.Add(clone);
                _byKey[clone.GroupKey] = clone;
                _totalRawCount += clone.Hits;
                _totalDetailRows += clone.Details.Count;
                if (clone.Details.Any(x => x.Source.Equals("ThreatIntel", StringComparison.OrdinalIgnoreCase)))
                {
                    _hasThreatIntelEvents = true;
                }
                RebuildArgSigMap(clone);
            }

            ApplyFilter();
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        public void ClearAll()
        {
            _items.Clear();
            _allItems.Clear();
            _byKey.Clear();
            _visibleByKey.Clear();
            _detailArgSigByGroupKey.Clear();
            _totalRawCount = 0;
            _totalDetailRows = 0;
            _hasThreatIntelEvents = false;
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        internal void TrimDetailPayload(int keepPerGroup)
        {
            int keep = Math.Max(1, keepPerGroup);
            for (int i = 0; i < _allItems.Count; i += 1)
            {
                GroupedEventRow row = _allItems[i];
                if (row.Details.Count <= keep)
                {
                    continue;
                }

                int originalCount = row.Details.Count;
                row.Details = GroupedEventCompaction.SelectImportantDetails(row.Details, keep);
                _totalDetailRows -= Math.Max(0, originalCount - row.Details.Count);
                _byKey[row.GroupKey] = row;
                RebuildArgSigMap(row);
            }

            ApplyFilter();
        }

        private void RebuildArgSigMap(GroupedEventRow row)
        {
            _detailArgSigByGroupKey.Remove(row.GroupKey);
            var map = new Dictionary<string, GroupedEventDetailRow>(StringComparer.Ordinal);
            foreach (GroupedEventDetailRow detail in row.Details)
            {
                if (!string.IsNullOrEmpty(detail.ArgumentSummary))
                {
                    map[detail.ArgumentSummary] = detail;
                }
            }
            if (map.Count > 0)
            {
                _detailArgSigByGroupKey[row.GroupKey] = map;
            }
        }

        private void UpdateSummary()
        {
            if (SummaryBlock == null)
            {
                return;
            }

            string tiState = _hasThreatIntelEvents ? "TI: integrated" : "TI: unavailable";
            SummaryBlock.Text = $"Groups: {_items.Count} / Events: {_totalRawCount} / {tiState}";
        }

        private void UpdateNoDataOverlay()
        {
            if (NoDataOverlay == null)
            {
                return;
            }

            NoDataOverlay.Visibility = _items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void ApplyFilter()
        {
            var visible = new List<GroupedEventRow>();
            _visibleByKey.Clear();
            foreach (GroupedEventRow row in _allItems)
            {
                if (!MatchesFilter(row))
                {
                    continue;
                }

                visible.Add(row);
                _visibleByKey[row.GroupKey] = row;
            }

            _items.ReplaceAll(visible);
        }

        private void SyncVisibleRow(GroupedEventRow row)
        {
            bool matches = MatchesFilter(row);
            bool visible = _visibleByKey.ContainsKey(row.GroupKey);
            if (matches)
            {
                if (!visible)
                {
                    _items.Add(row);
                    _visibleByKey[row.GroupKey] = row;
                }

                return;
            }

            if (!visible)
            {
                return;
            }

            _visibleByKey.Remove(row.GroupKey);
            _items.Remove(row);
        }

        private bool MatchesFilter(GroupedEventRow row)
        {
            string filter = _feedFilter;
            if (string.IsNullOrWhiteSpace(filter) || filter.Equals("ALL FEEDS", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return filter.ToUpperInvariant() switch
            {
                "THREATINTEL" => row.Event.StartsWith("TI/", StringComparison.OrdinalIgnoreCase) ||
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
                return sensorOrigin == "Unclassified"
                    ? entry.DetectionName
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
                string baseName = eventName[..^"Telemetry".Length].Trim();
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
                return sensorOrigin == "Unclassified"
                    ? eventName
                    : $"{sensorOrigin.ToUpperInvariant()} | {eventName}";
            }

            return "UNCLASSIFIED_EVENT";
        }
    }
}
