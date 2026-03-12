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
    public partial class HeuristicsPane : UserControl
    {
        public event RoutedEventHandler? ReorderRequested;
        public event RoutedEventHandler? FloatRequested;
        public event RoutedEventHandler? CloseRequested;
        public event RoutedEventHandler? InspectRequested;

        private readonly BulkObservableCollection<GroupedEventRow> _items = new();
        private readonly Dictionary<string, GroupedEventRow> _byKey = new(StringComparer.Ordinal);
        private int _totalRawCount;

        internal int ItemCount => _items.Count;
        internal int TotalRawCount => _totalRawCount;

        public HeuristicsPane()
        {
            InitializeComponent();
            HeuristicsGrid.ItemsSource = _items;
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        internal void PushHeuristic(HeuristicEventView item)
        {
            PushHeuristics(new[] { item });
        }

        internal void PushHeuristics(IEnumerable<HeuristicEventView> items)
        {
            foreach (HeuristicEventView item in items)
            {
                PushHeuristicCore(item);
            }

            UpdateSummary();
            UpdateNoDataOverlay();
        }

        private void PushHeuristicCore(HeuristicEventView item)
        {
            DateTime now = item.LastSeenUtc == default ? item.TimestampUtc : item.LastSeenUtc;
            string eventName = string.IsNullOrWhiteSpace(item.EventName) ? "heuristic" : item.EventName;
            string source = string.IsNullOrWhiteSpace(item.Source) ? "unknown" : item.Source;
            string combinedEvent = NormalizeEventLabel($"{source}/{eventName}");
            string severity = EventDetailFormatting.SeverityLabel(item.Severity);
            string detection = string.IsNullOrWhiteSpace(item.DetectionName) ? "heuristic" : item.DetectionName;
            string actor = ProcessIdentityResolver.Describe(item.ActorPid);
            string target = ProcessIdentityResolver.Describe(item.TargetPid);
            string key = $"{combinedEvent}|{severity}|{detection}";
            int hits = Math.Max(1, item.RepeatCount);
            string detailsText = item.Details;

            _totalRawCount += hits;

            if (_byKey.TryGetValue(key, out GroupedEventRow? existing))
            {
                existing.LastSeenUtc = now;
                existing.Hits = Math.Max(1, existing.Hits + hits);
                existing.Details.Add(new GroupedEventDetailRow
                {
                    TimestampUtc = now,
                    Event = combinedEvent,
                    Severity = severity,
                    Detection = detection,
                    Source = source,
                    Actor = actor,
                    Target = target,
                    ActorPid = item.ActorPid,
                    TargetPid = item.TargetPid,
                    Details = detailsText
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
                    Event = combinedEvent,
                    Severity = severity,
                    Detection = detection,
                    Hits = hits,
                    Details =
                    {
                        new GroupedEventDetailRow
                        {
                            TimestampUtc = now,
                            Event = combinedEvent,
                            Severity = severity,
                            Detection = detection,
                            Source = source,
                            Actor = actor,
                            Target = target,
                            ActorPid = item.ActorPid,
                            TargetPid = item.TargetPid,
                            Details = detailsText
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
            => (HeuristicsGrid.SelectedItem as GroupedEventRow)?.Clone();

        internal void LoadHistory(IEnumerable<GroupedEventRow> groups)
        {
            _items.Clear();
            _byKey.Clear();
            _totalRawCount = 0;

            var clones = new List<GroupedEventRow>();
            foreach (GroupedEventRow source in groups)
            {
                GroupedEventRow clone = source.Clone();
                clone.Hits = Math.Max(1, clone.Hits);
                clone.Event = NormalizeEventLabel(clone.Event);
                clone.Details = clone.Details.OrderBy(x => x.TimestampUtc).ToList();
                for (int i = 0; i < clone.Details.Count; i += 1)
                {
                    clone.Details[i].Event = NormalizeEventLabel(clone.Details[i].Event);
                }
                clones.Add(clone);
                _byKey[clone.GroupKey] = clone;
                _totalRawCount += clone.Hits;
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
            SummaryBlock.Text = "No detections yet";
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
            SummaryBlock.Text = $"Groups: {_items.Count} / Events: {_totalRawCount}";
        }

        private void UpdateNoDataOverlay()
        {
            HeuristicsNoDataOverlay.Visibility = _items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void HeuristicsGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            _ = sender;
            _ = e;
            if (HeuristicsGrid.SelectedItem is GroupedEventRow)
            {
                InspectRequested?.Invoke(this, new RoutedEventArgs());
            }
        }

        private static string NormalizeEventLabel(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return "-";
            }

            return value.Replace('_', ' ').Trim();
        }

        private void HeurBtnReorder_Click(object sender, RoutedEventArgs e) => ReorderRequested?.Invoke(this, e);
        private void HeurBtnFloat_Click(object sender, RoutedEventArgs e) => FloatRequested?.Invoke(this, e);
        private void HeurBtnClose_Click(object sender, RoutedEventArgs e) => CloseRequested?.Invoke(this, e);
        private void HeurBtnInspect_Click(object sender, RoutedEventArgs e) => InspectRequested?.Invoke(this, e);
    }
}
