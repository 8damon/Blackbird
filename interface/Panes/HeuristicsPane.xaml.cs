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
        private readonly List<GroupedEventRow> _allItems = new();
        private readonly Dictionary<string, GroupedEventRow> _byKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, GroupedEventRow> _visibleByKey = new(StringComparer.Ordinal);
        private int _totalRawCount;
        private string _severityFilter = "ALL";

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
            string actorToolTip = ProcessIdentityResolver.HoverText(item.ActorPid);
            string targetToolTip = ProcessIdentityResolver.HoverText(item.TargetPid);
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
                    ActorToolTip = actorToolTip,
                    TargetToolTip = targetToolTip,
                    Details = detailsText
                });
                if (existing.Details.Count > 4000)
                {
                    existing.Details.RemoveAt(0);
                }

                SyncVisibleRow(existing);
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
                            ActorToolTip = actorToolTip,
                            TargetToolTip = targetToolTip,
                            Details = detailsText
                        }
                    }
                };
                _allItems.Add(row);
                _byKey[key] = row;
                SyncVisibleRow(row);
            }

            while (_allItems.Count > 2000)
            {
                GroupedEventRow evicted = _allItems[0];
                string evictKey = evicted.GroupKey;
                _allItems.RemoveAt(0);
                _byKey.Remove(evictKey);
                if (_visibleByKey.Remove(evictKey))
                {
                    _items.Remove(evicted);
                }
            }
        }

        internal IReadOnlyList<GroupedEventRow> SnapshotItems()
            => _allItems.Select(x => x.Clone()).ToList();

        internal GroupedEventRow? GetSelectedGroupClone()
            => (HeuristicsGrid.SelectedItem as GroupedEventRow)?.Clone();

        internal void LoadHistory(IEnumerable<GroupedEventRow> groups)
        {
            _items.Clear();
            _allItems.Clear();
            _byKey.Clear();
            _visibleByKey.Clear();
            _totalRawCount = 0;

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
                _allItems.Add(clone);
                _byKey[clone.GroupKey] = clone;
                _totalRawCount += clone.Hits;
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
            _totalRawCount = 0;
            SummaryBlock.Text = "No detections yet";
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

                row.Details = row.Details
                    .OrderByDescending(x => x.TimestampUtc)
                    .Take(keep)
                    .OrderBy(x => x.TimestampUtc)
                    .ToList();
                _byKey[row.GroupKey] = row;
            }

            ApplyFilter();
        }

        private void UpdateSummary()
        {
            if (SummaryBlock == null)
            {
                return;
            }

            SummaryBlock.Text = $"Groups: {_items.Count} / Events: {_totalRawCount}";
        }

        private void UpdateNoDataOverlay()
        {
            if (HeuristicsNoDataOverlay == null)
            {
                return;
            }

            HeuristicsNoDataOverlay.Visibility = _items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
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
            if (string.IsNullOrWhiteSpace(_severityFilter) || _severityFilter.Equals("ALL", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return row.Severity.Equals(_severityFilter, StringComparison.OrdinalIgnoreCase);
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
        private void SeverityFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = e;
            ComboBox? combo = sender as ComboBox ?? SeverityFilter;
            _severityFilter = ((combo?.SelectedItem as ComboBoxItem)?.Content as string ?? "ALL").Trim();
            ApplyFilter();
            UpdateNoDataOverlay();
        }
    }
}
