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
        public event RoutedEventHandler? ReorderRequested;
        public event RoutedEventHandler? FloatRequested;
        public event RoutedEventHandler? CloseRequested;
        public event RoutedEventHandler? InspectRequested;

        private readonly BulkObservableCollection<GroupedEventRow> _items = new();
        private readonly Dictionary<string, GroupedEventRow> _byKey = new(StringComparer.Ordinal);
        private int _totalRawCount;
        private bool _hasThreatIntelEvents;

        public EtwPane()
        {
            InitializeComponent();
            EventsGrid.ItemsSource = _items;
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        internal int ItemCount => _items.Count;
        internal int TotalRawCount => _totalRawCount;
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
            string eventName = entry.Source.Equals("ThreatIntel", StringComparison.OrdinalIgnoreCase)
                ? $"TI/{entry.EventName}"
                : entry.EventName;
            string severity = EventDetailFormatting.SeverityLabel(entry.Severity);
            string detection = BuildDetectionLabel(entry);
            string source = string.IsNullOrWhiteSpace(entry.Source) ? "Blackbird" : entry.Source;
            string actor = ProcessIdentityResolver.Describe(entry.ActorPid);
            string target = ProcessIdentityResolver.Describe(entry.TargetPid);
            string detailText = entry.Details;
            string key =
                $"{eventName}|{severity}|{detection}|{source}";

            _totalRawCount += 1;
            if (source.Equals("ThreatIntel", StringComparison.OrdinalIgnoreCase))
            {
                _hasThreatIntelEvents = true;
            }

            if (_byKey.TryGetValue(key, out GroupedEventRow? existing))
            {
                existing.LastSeenUtc = now;
                existing.Hits = Math.Max(1, existing.Hits + 1);
                existing.Details.Add(new GroupedEventDetailRow
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
                    Details = detailText
                });

                if (existing.Details.Count > 4000)
                {
                    existing.Details.RemoveAt(0);
                }
            }
            else
            {
                var row = new GroupedEventRow
                {
                    GroupKey = key,
                    LastSeenUtc = now,
                    Event = eventName,
                    Severity = severity,
                    Detection = detection,
                    Hits = 1,
                    Details =
                    {
                        new GroupedEventDetailRow
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
                            Details = detailText
                        }
                    }
                };
                _items.Add(row);
                _byKey[key] = row;
            }

            while (_items.Count > 2000)
            {
                string evictKey = _items[0].GroupKey;
                _items.RemoveAt(0);
                _byKey.Remove(evictKey);
            }

        }

        internal IReadOnlyList<GroupedEventRow> SnapshotItems()
            => _items.Select(x => x.Clone()).ToList();

        internal GroupedEventRow? GetSelectedGroupClone()
            => (EventsGrid.SelectedItem as GroupedEventRow)?.Clone();

        internal void LoadHistory(IEnumerable<GroupedEventRow> groups)
        {
            _items.Clear();
            _byKey.Clear();
            _totalRawCount = 0;
            _hasThreatIntelEvents = false;

            var clones = new List<GroupedEventRow>();
            foreach (GroupedEventRow source in groups)
            {
                GroupedEventRow clone = source.Clone();
                clone.Hits = Math.Max(1, clone.Hits);
                clone.Details = clone.Details.OrderBy(x => x.TimestampUtc).ToList();
                clones.Add(clone);
                _byKey[clone.GroupKey] = clone;
                _totalRawCount += clone.Hits;
                if (clone.Details.Any(x => x.Source.Equals("ThreatIntel", StringComparison.OrdinalIgnoreCase)))
                {
                    _hasThreatIntelEvents = true;
                }
            }

            _items.ReplaceAll(clones);
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        public void ClearAll()
        {
            _items.Clear();
            _byKey.Clear();
            _totalRawCount = 0;
            _hasThreatIntelEvents = false;
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        internal void TrimDetailPayload(int keepPerGroup)
        {
            int keep = Math.Max(1, keepPerGroup);
            for (int i = 0; i < _items.Count; i += 1)
            {
                GroupedEventRow row = _items[i];
                if (row.Details.Count <= keep)
                {
                    continue;
                }

                row.Details = row.Details
                    .OrderByDescending(x => x.TimestampUtc)
                    .Take(keep)
                    .OrderBy(x => x.TimestampUtc)
                    .ToList();
                _byKey[row.GroupKey] = row;
            }
        }

        private void UpdateSummary()
        {
            string tiState = _hasThreatIntelEvents ? "TI: integrated" : "TI: unavailable";
            SummaryBlock.Text = $"Groups: {_items.Count} / Events: {_totalRawCount} / {tiState}";
        }

        private void UpdateNoDataOverlay()
        {
            NoDataOverlay.Visibility = _items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
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

        private void EtwBtnReorder_Click(object sender, RoutedEventArgs e) => ReorderRequested?.Invoke(this, e);
        private void EtwBtnFloat_Click(object sender, RoutedEventArgs e) => FloatRequested?.Invoke(this, e);
        private void EtwBtnClose_Click(object sender, RoutedEventArgs e) => CloseRequested?.Invoke(this, e);

        private static string BuildDetectionLabel(BrokerEtwEventView entry)
        {
            if (!string.IsNullOrWhiteSpace(entry.DetectionName))
            {
                return entry.DetectionName;
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
                return eventName;
            }

            return "UNCLASSIFIED_EVENT";
        }
    }
}
