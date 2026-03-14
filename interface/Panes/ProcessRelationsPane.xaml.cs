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
    public partial class ProcessRelationsPane : UserControl
    {
        public event RoutedEventHandler? CloseRequested;
        public event RoutedEventHandler? InspectRequested;

        private readonly BulkObservableCollection<GroupedEventRow> _items = new();
        private readonly List<GroupedEventRow> _allItems = new();
        private readonly Dictionary<string, GroupedEventRow> _byKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, GroupedEventRow> _visibleByKey = new(StringComparer.Ordinal);
        private string _relationFilter = "ALL RELATIONS";

        internal int ItemCount => _items.Count;
        internal int TotalRawCount { get; private set; }

        public ProcessRelationsPane()
        {
            InitializeComponent();
            RelationsGrid.ItemsSource = _items;
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        internal void PushRelation(ProcessRelationView item)
        {
            PushRelations(new[] { item });
        }

        internal void PushRelations(IEnumerable<ProcessRelationView> items)
        {
            foreach (ProcessRelationView item in items)
            {
                PushRelationCore(item);
            }

            UpdateSummary();
            UpdateNoDataOverlay();
        }

        private void PushRelationCore(ProcessRelationView item)
        {
            DateTime now = item.LastSeenUtc == default ? item.FirstSeenUtc : item.LastSeenUtc;
            if (now == default)
            {
                now = DateTime.UtcNow;
            }

            string eventName = item.RelationType;
            string severity = EventDetailFormatting.SeverityLabelFromText(EventDetailFormatting.RelationSeverity(item));
            string source = ProcessIdentityResolver.Describe(item.SourcePid);
            string target = ProcessIdentityResolver.Describe(item.TargetPid);
            string sourceToolTip = ProcessIdentityResolver.HoverText(item.SourcePid);
            string targetToolTip = ProcessIdentityResolver.HoverText(item.TargetPid);
            string detection = string.Equals(eventName, "ThreadCreate", StringComparison.OrdinalIgnoreCase)
                ? "Cross-process thread creation activity"
                : "Cross-process handle activity";
            string accessText = EventDetailFormatting.DescribeHandleAccess(item.LastAccessMask);
            string flagsText = string.Equals(item.RelationType, "ThreadCreate", StringComparison.OrdinalIgnoreCase)
                ? EventDetailFormatting.DescribeThreadFlags(item.LastFlags)
                : EventDetailFormatting.DescribeHandleFlags(item.LastFlags);
            string details =
                $"sourcePid={item.SourcePid} targetPid={item.TargetPid} relationType={item.RelationType} access=0x{item.LastAccessMask:X8} ({accessText}) flags=0x{item.LastFlags:X8} ({flagsText})";
            string key = $"{eventName}|{severity}|{detection}";
            int hits = Math.Max(1, item.RepeatCount);

            TotalRawCount += hits;

            if (_byKey.TryGetValue(key, out GroupedEventRow? existing))
            {
                existing.LastSeenUtc = now;
                existing.Hits = Math.Max(1, existing.Hits + hits);
                existing.Details.Add(new GroupedEventDetailRow
                {
                    TimestampUtc = now,
                    Event = eventName,
                    Severity = severity,
                    Detection = detection,
                    Source = "Kernel-IOCTL",
                    Actor = source,
                    Target = target,
                    ActorPid = item.SourcePid,
                    TargetPid = item.TargetPid,
                    ActorToolTip = sourceToolTip,
                    TargetToolTip = targetToolTip,
                    Details = details
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
                    Event = eventName,
                    Severity = severity,
                    Detection = detection,
                    Hits = hits,
                    Details =
                    {
                        new GroupedEventDetailRow
                        {
                            TimestampUtc = now,
                            Event = eventName,
                            Severity = severity,
                            Detection = detection,
                            Source = "Kernel-IOCTL",
                            Actor = source,
                            Target = target,
                            ActorPid = item.SourcePid,
                            TargetPid = item.TargetPid,
                            ActorToolTip = sourceToolTip,
                            TargetToolTip = targetToolTip,
                            Details = details
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
            => (RelationsGrid.SelectedItem as GroupedEventRow)?.Clone();

        internal void LoadHistory(IEnumerable<GroupedEventRow> groups)
        {
            _items.Clear();
            _allItems.Clear();
            _byKey.Clear();
            _visibleByKey.Clear();
            TotalRawCount = 0;

            foreach (GroupedEventRow source in groups)
            {
                GroupedEventRow clone = source.Clone();
                clone.Severity = EventDetailFormatting.SeverityLabelFromText(clone.Severity);
                clone.Hits = Math.Max(1, clone.Hits);
                clone.Details = clone.Details
                    .OrderBy(x => x.TimestampUtc)
                    .Select(x =>
                    {
                        x.Severity = EventDetailFormatting.SeverityLabelFromText(x.Severity);
                        return x;
                    })
                    .ToList();
                _allItems.Add(clone);
                _byKey[clone.GroupKey] = clone;
                TotalRawCount += clone.Hits;
            }

            ApplyFilter();
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        internal void ClearAll()
        {
            _items.Clear();
            _allItems.Clear();
            _byKey.Clear();
            _visibleByKey.Clear();
            TotalRawCount = 0;
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

            SummaryBlock.Text = $"Groups: {_items.Count} / Events: {TotalRawCount}";
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
            string filter = _relationFilter;
            if (string.IsNullOrWhiteSpace(filter) || filter.Equals("ALL RELATIONS", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return filter.ToUpperInvariant() switch
            {
                "THREADCREATE" => row.Event.Contains("ThreadCreate", StringComparison.OrdinalIgnoreCase),
                "HANDLE" => !row.Event.Contains("ThreadCreate", StringComparison.OrdinalIgnoreCase),
                "HIGH+" => row.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase) ||
                           row.Severity.Equals("High", StringComparison.OrdinalIgnoreCase),
                _ => true
            };
        }

        private void RelationsGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            _ = sender;
            _ = e;
            if (RelationsGrid.SelectedItem is GroupedEventRow)
            {
                InspectRequested?.Invoke(this, new RoutedEventArgs());
            }
        }

        private void RelationsBtnClose_Click(object sender, RoutedEventArgs e) => CloseRequested?.Invoke(this, e);
        private void RelationsBtnInspect_Click(object sender, RoutedEventArgs e) => InspectRequested?.Invoke(this, e);
        private void RelationFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = e;
            ComboBox? combo = sender as ComboBox ?? RelationFilter;
            _relationFilter = ((combo?.SelectedItem as ComboBoxItem)?.Content as string ?? "ALL RELATIONS").Trim();
            ApplyFilter();
            UpdateNoDataOverlay();
        }
    }
}
