using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace BlackbirdInterface
{
    public partial class ProcessRelationsPane : UserControl
    {
        private const int MaxGroupCount = 192;
        private const int MaxDetailRowsPerGroup = 24;

        public event RoutedEventHandler? CloseRequested;
        public event RoutedEventHandler? InspectRequested;
        internal event EventHandler? GraphStateChanged;

        private readonly BulkObservableCollection<GroupedEventRow> _items = new();
        private readonly List<GroupedEventRow> _allItems = new();
        private readonly Dictionary<string, GroupedEventRow> _byKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, GroupedEventRow> _visibleByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, Dictionary<string, GroupedEventDetailRow>> _detailSigByGroupKey = new(StringComparer.Ordinal);
        private string _relationFilter = "ALL RELATIONS";
        private int _totalDetailRows;
        private uint _rootPid;

        internal int ItemCount => _items.Count;
        internal int TotalRawCount { get; private set; }
        internal int DetailRowCount => _totalDetailRows;
        internal int CurrentRootPid => unchecked((int)_rootPid);

        public ProcessRelationsPane()
        {
            InitializeComponent();
            RelationsGrid.ItemsSource = _items;
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        internal void SetRootPid(int pid)
        {
            _rootPid = pid > 0 ? (uint)pid : 0;
            UpdateSummary();
            RaiseGraphStateChanged();
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
            RaiseGraphStateChanged();
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
            string detection = eventName switch
            {
                "ProcessCreate" => "Child process launch and descendant tracking",
                "ThreadCreate" => "Cross-process thread creation activity",
                _ when _rootPid != 0 && item.TargetPid == _rootPid => "Another process opens a handle into the target",
                _ when _rootPid != 0 && item.SourcePid == _rootPid => "Target opens a handle into another process",
                _ => "Cross-process handle activity"
            };
            string accessText = EventDetailFormatting.DescribeHandleAccess(item.LastAccessMask);
            string flagsText = string.Equals(item.RelationType, "ThreadCreate", StringComparison.OrdinalIgnoreCase)
                ? EventDetailFormatting.DescribeThreadFlags(item.LastFlags)
                : EventDetailFormatting.DescribeHandleFlags(item.LastFlags);
            string originModule = string.IsNullOrWhiteSpace(item.OriginModule) ? "unknown" : item.OriginModule;
            string details = !string.IsNullOrWhiteSpace(item.DetailText)
                ? item.DetailText
                : $"sourcePid={item.SourcePid} targetPid={item.TargetPid} relationType={item.RelationType} access=0x{item.LastAccessMask:X8} ({accessText}) flags=0x{item.LastFlags:X8} ({flagsText}) originModule={originModule}";
            string detailSig = !string.IsNullOrWhiteSpace(item.DetailSignature)
                ? item.DetailSignature
                : $"{eventName}|{item.SourcePid}|{item.TargetPid}|{item.LastAccessMask:X8}|{item.LastFlags:X8}";
            string key = $"{eventName}|{item.SourcePid}|{item.TargetPid}|{detailSig}";
            int hits = Math.Max(1, item.RepeatCount);
            string sourceName = string.IsNullOrWhiteSpace(item.OriginSource) ? "Kernel-IOCTL" : item.OriginSource;

            TotalRawCount += hits;

            if (_byKey.TryGetValue(key, out GroupedEventRow? existing))
            {
                existing.LastSeenUtc = now;
                existing.Hits = Math.Max(1, existing.Hits + hits);
                existing.Severity = PickHigherSeverity(existing.Severity, severity);

                bool aggregated = false;
                if (_detailSigByGroupKey.TryGetValue(key, out Dictionary<string, GroupedEventDetailRow>? sigMap) &&
                    sigMap.TryGetValue(detailSig, out GroupedEventDetailRow? matchingDetail))
                {
                    matchingDetail.HitCount += hits;
                    matchingDetail.TimestampUtc = now;
                    matchingDetail.Details = details;
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
                        Source = sourceName,
                        Actor = source,
                        Target = target,
                        ActorPid = item.SourcePid,
                        TargetPid = item.TargetPid,
                        ActorToolTip = sourceToolTip,
                        TargetToolTip = targetToolTip,
                        ArgumentSummary = detailSig,
                        HitCount = hits,
                        Details = details
                    };
                    existing.Details.Add(newDetail);
                    _totalDetailRows += 1;

                    if (!_detailSigByGroupKey.TryGetValue(key, out Dictionary<string, GroupedEventDetailRow>? map))
                    {
                        map = new Dictionary<string, GroupedEventDetailRow>(StringComparer.Ordinal);
                        _detailSigByGroupKey[key] = map;
                    }

                    map[detailSig] = newDetail;

                    if (existing.Details.Count > MaxDetailRowsPerGroup)
                    {
                        GroupedEventDetailRow evictedDetail = existing.Details[0];
                        existing.Details.RemoveAt(0);
                        _totalDetailRows = Math.Max(0, _totalDetailRows - 1);
                        if (!string.IsNullOrEmpty(evictedDetail.ArgumentSummary) &&
                            _detailSigByGroupKey.TryGetValue(key, out Dictionary<string, GroupedEventDetailRow>? evictMap) &&
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
                            Source = sourceName,
                            Actor = source,
                            Target = target,
                            ActorPid = item.SourcePid,
                            TargetPid = item.TargetPid,
                            ActorToolTip = sourceToolTip,
                            TargetToolTip = targetToolTip,
                            ArgumentSummary = detailSig,
                            HitCount = hits,
                            Details = details
                        }
                    }
                };
                _allItems.Add(row);
                _byKey[row.GroupKey] = row;
                _detailSigByGroupKey[row.GroupKey] = new Dictionary<string, GroupedEventDetailRow>(StringComparer.Ordinal)
                {
                    [detailSig] = row.Details[0]
                };
                _totalDetailRows += row.Details.Count;
                SyncVisibleRow(row);
            }

            while (_allItems.Count > MaxGroupCount)
            {
                GroupedEventRow evicted = _allItems[0];
                string evictKey = evicted.GroupKey;
                _allItems.RemoveAt(0);
                _byKey.Remove(evictKey);
                _detailSigByGroupKey.Remove(evictKey);
                _totalDetailRows = Math.Max(0, _totalDetailRows - evicted.Details.Count);
                if (_visibleByKey.Remove(evictKey))
                {
                    _items.Remove(evicted);
                }
            }
        }

        internal IReadOnlyList<GroupedEventRow> SnapshotItems()
        {
            return _allItems.Select(x => x.Clone()).ToList();
        }

        internal GroupedEventRow? GetSelectedGroupClone()
        {
            return (RelationsGrid.SelectedItem as GroupedEventRow)?.Clone();
        }

        internal void LoadHistory(IEnumerable<GroupedEventRow> groups)
        {
            _items.Clear();
            _allItems.Clear();
            _byKey.Clear();
            _visibleByKey.Clear();
            _detailSigByGroupKey.Clear();
            TotalRawCount = 0;
            _totalDetailRows = 0;

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
                _totalDetailRows += clone.Details.Count;
                RebuildDetailSigMap(clone);
            }

            ApplyFilter();
            UpdateSummary();
            UpdateNoDataOverlay();
            RaiseGraphStateChanged();
        }

        internal void ClearAll()
        {
            _items.Clear();
            _allItems.Clear();
            _byKey.Clear();
            _visibleByKey.Clear();
            _detailSigByGroupKey.Clear();
            TotalRawCount = 0;
            _totalDetailRows = 0;
            UpdateSummary();
            UpdateNoDataOverlay();
            RaiseGraphStateChanged();
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
                row.Details = row.Details
                    .OrderByDescending(x => x.TimestampUtc)
                    .Take(keep)
                    .OrderBy(x => x.TimestampUtc)
                    .ToList();
                _totalDetailRows -= Math.Max(0, originalCount - row.Details.Count);
                _byKey[row.GroupKey] = row;
                RebuildDetailSigMap(row);
            }

            ApplyFilter();
            RaiseGraphStateChanged();
        }

        private void UpdateSummary()
        {
            if (SummaryBlock == null)
            {
                return;
            }

            string prefix = _rootPid != 0 ? $"Root PID {_rootPid} / " : string.Empty;
            SummaryBlock.Text = $"{prefix}Groups: {_items.Count} / Events: {TotalRawCount}";
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
                "PROCESSCREATE" => row.Event.Contains("ProcessCreate", StringComparison.OrdinalIgnoreCase),
                "THREADCREATE" => row.Event.Contains("ThreadCreate", StringComparison.OrdinalIgnoreCase),
                "HANDLE" => row.Event.Contains("Handle", StringComparison.OrdinalIgnoreCase),
                "HIGH+" => row.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase) ||
                           row.Severity.Equals("High", StringComparison.OrdinalIgnoreCase),
                _ => true
            };
        }

        private void RebuildDetailSigMap(GroupedEventRow row)
        {
            _detailSigByGroupKey.Remove(row.GroupKey);
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
                _detailSigByGroupKey[row.GroupKey] = map;
            }
        }

        private static string PickHigherSeverity(string current, string incoming)
        {
            return SeverityRank(incoming) > SeverityRank(current) ? incoming : current;
        }

        private static int SeverityRank(string severity)
        {
            return severity?.Trim().ToUpperInvariant() switch
            {
                "CRITICAL" => 4,
                "HIGH" => 3,
                "MEDIUM" => 2,
                "LOW" => 1,
                _ => 0
            };
        }

        private void RaiseGraphStateChanged()
        {
            GraphStateChanged?.Invoke(this, EventArgs.Empty);
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

        private void RelationsBtnClose_Click(object sender, RoutedEventArgs e)
        {
            CloseRequested?.Invoke(this, e);
        }

        private void RelationsBtnInspect_Click(object sender, RoutedEventArgs e)
        {
            InspectRequested?.Invoke(this, e);
        }

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
