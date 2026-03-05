using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace SleepwalkerInterface
{
    public partial class HeuristicsPane : UserControl
    {
        public event RoutedEventHandler? ReorderRequested;
        public event RoutedEventHandler? FloatRequested;
        public event RoutedEventHandler? CloseRequested;

        private readonly ObservableCollection<GroupedEventRow> _items = new();
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
            DateTime now = item.LastSeenUtc == default ? item.TimestampUtc : item.LastSeenUtc;
            string eventName = string.IsNullOrWhiteSpace(item.EventName) ? "heuristic" : item.EventName;
            string source = string.IsNullOrWhiteSpace(item.Source) ? "unknown" : item.Source;
            string combinedEvent = $"{source}/{eventName}";
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
                    Details = detailsText
                });
                if (existing.Details.Count > 4000)
                {
                    existing.Details.RemoveAt(0);
                }

                int idx = _items.IndexOf(existing);
                if (idx >= 0)
                {
                    _items[idx] = existing;
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

            UpdateSummary();
            UpdateNoDataOverlay();
        }

        internal IReadOnlyList<GroupedEventRow> SnapshotItems()
            => _items.Select(x => x.Clone()).ToList();

        internal void LoadHistory(IEnumerable<GroupedEventRow> groups)
        {
            _items.Clear();
            _byKey.Clear();
            _totalRawCount = 0;

            foreach (GroupedEventRow source in groups)
            {
                GroupedEventRow clone = source.Clone();
                clone.Hits = Math.Max(1, clone.Hits);
                clone.Details = clone.Details.OrderBy(x => x.TimestampUtc).ToList();
                _items.Add(clone);
                _byKey[clone.GroupKey] = clone;
                _totalRawCount += clone.Hits;
            }

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
                _items[i] = row;
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
            GroupedEventRow? selected = GetRowFromSource(e.OriginalSource as DependencyObject)
                ?? HeuristicsGrid.SelectedItem as GroupedEventRow;
            if (selected == null)
            {
                return;
            }

            Window? owner = Window.GetWindow(this);
            IReadOnlyList<GroupedEventDetailRow> details = ResolveDetails(selected, owner);
            GroupedEventDetailsWindow.ShowUnified(
                owner,
                IntelDetailsCategory.Heuristics,
                $"Heuristic: {selected.Detection}",
                details);
        }

        private static GroupedEventRow? GetRowFromSource(DependencyObject? source)
        {
            while (source != null)
            {
                if (source is DataGridRow row && row.Item is GroupedEventRow item)
                {
                    return item;
                }

                source = VisualTreeHelper.GetParent(source);
            }

            return null;
        }

        private static IReadOnlyList<GroupedEventDetailRow> ResolveDetails(GroupedEventRow selected, Window? owner)
        {
            if (selected.Details.Count > 0)
            {
                return selected.Details;
            }

            IIntelDetailsProvider? provider = ResolveProvider(owner);
            if (provider == null)
            {
                return Array.Empty<GroupedEventDetailRow>();
            }

            IReadOnlyList<GroupedEventDetailRow> all = provider.GetIntelDetails(IntelDetailsCategory.Heuristics);
            List<GroupedEventDetailRow> exact = all
                .Where(x =>
                    x.Event.Equals(selected.Event, StringComparison.OrdinalIgnoreCase) &&
                    x.Severity.Equals(selected.Severity, StringComparison.OrdinalIgnoreCase) &&
                    x.Detection.Equals(selected.Detection, StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (exact.Count > 0)
            {
                return exact;
            }

            return all
                .Where(x => x.Detection.Equals(selected.Detection, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        private static IIntelDetailsProvider? ResolveProvider(Window? owner)
        {
            Window? cursor = owner;
            while (cursor != null)
            {
                if (cursor is IIntelDetailsProvider provider)
                {
                    return provider;
                }

                cursor = cursor.Owner;
            }

            if (Application.Current == null)
            {
                return null;
            }

            foreach (Window window in Application.Current.Windows)
            {
                if (window is IIntelDetailsProvider provider)
                {
                    return provider;
                }
            }

            return null;
        }

        private void HeurBtnReorder_Click(object sender, RoutedEventArgs e) => ReorderRequested?.Invoke(this, e);
        private void HeurBtnFloat_Click(object sender, RoutedEventArgs e) => FloatRequested?.Invoke(this, e);
        private void HeurBtnClose_Click(object sender, RoutedEventArgs e) => CloseRequested?.Invoke(this, e);
    }
}
