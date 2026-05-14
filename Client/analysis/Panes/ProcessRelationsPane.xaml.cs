using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace BlackbirdInterface
{
    public partial class ProcessRelationsPane : UserControl
    {
        private const int MaxGroupCount = 192;
        private const int MaxDetailRowsPerGroup = 24;

        public event RoutedEventHandler? CloseRequested;
        public event RoutedEventHandler? InspectRequested;
        internal event EventHandler? GraphStateChanged;

        private readonly GroupedEventPaneState _state = new();
        private string _relationFilter = "ALL RELATIONS";
        private uint _rootPid;
        private int _focusedPid;

        public int FocusedPid
        {
            set {
                _focusedPid = value;
                ApplyFilter();
            }
        }

        internal int ItemCount => _state.ItemCount;
        internal int TotalRawCount => _state.TotalRawCount;
        internal int DetailRowCount => _state.TotalDetailRows;
        internal int CurrentRootPid => unchecked((int)_rootPid);

        public ProcessRelationsPane()
        {
            InitializeComponent();
            RelationsGrid.ItemsSource = _state.VisibleItems;
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
            string detection = eventName switch { "ProcessCreate" => "Child process launch and descendant tracking",
                                                  "ThreadCreate" => "Cross-process thread creation activity",
                                                  _ when _rootPid != 0 &&item.TargetPid == _rootPid =>
                                                      "Another process opens a handle into the target",
                                                  _ when _rootPid != 0 &&item.SourcePid == _rootPid =>
                                                      "Target opens a handle into another process",
                                                  _ => "Cross-process handle activity" };
            string accessText = EventDetailFormatting.DescribeHandleAccess(item.LastAccessMask);
            string flagsText = string.Equals(item.RelationType, "ThreadCreate", StringComparison.OrdinalIgnoreCase)
                                   ? EventDetailFormatting.DescribeThreadFlags(item.LastFlags)
                                   : EventDetailFormatting.DescribeHandleFlags(item.LastFlags);
            string originModule = string.IsNullOrWhiteSpace(item.OriginModule) ? "unknown" : item.OriginModule;
            string details =
                !string.IsNullOrWhiteSpace(item.DetailText)
                    ? item.DetailText
                    : $"sourcePid={item.SourcePid} targetPid={item.TargetPid} relationType={item.RelationType} access=0x{item.LastAccessMask:X8} ({accessText}) flags=0x{item.LastFlags:X8} ({flagsText}) originModule={originModule}";
            string detailSig =
                !string.IsNullOrWhiteSpace(item.DetailSignature)
                    ? item.DetailSignature
                    : $"{eventName}|{item.SourcePid}|{item.TargetPid}|{item.LastAccessMask:X8}|{item.LastFlags:X8}";
            string key = $"{eventName}|{item.SourcePid}|{item.TargetPid}|{detailSig}";
            int hits = Math.Max(1, item.RepeatCount);
            string sourceName = string.IsNullOrWhiteSpace(item.OriginSource) ? "Kernel-IOCTL" : item.OriginSource;

            _state.IncrementRawCount(hits);

            if (_state.TryGetRow(key, out GroupedEventRow? existing))
            {
                existing.LastSeenUtc = now;
                existing.Hits = Math.Max(1, existing.Hits + hits);
                existing.Severity = PickHigherSeverity(existing.Severity, severity);

                bool aggregated = false;
                if (_state.TryGetDetail(key, detailSig, out GroupedEventDetailRow? matchingDetail))
                {
                    matchingDetail.HitCount += hits;
                    matchingDetail.TimestampUtc = now;
                    matchingDetail.Details = details;
                    aggregated = true;
                }

                if (!aggregated)
                {
                    var newDetail = new GroupedEventDetailRow { TimestampUtc = now,
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
                                                                Details = details };
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
                var row = new GroupedEventRow {
                    GroupKey = key,
                    LastSeenUtc = now,
                    Event = eventName,
                    Severity = severity,
                    Detection = detection,
                    Hits = hits,
                    Details = { new GroupedEventDetailRow { TimestampUtc = now, Event = eventName, Severity = severity,
                                                            Detection = detection, Source = sourceName, Actor = source,
                                                            Target = target, ActorPid = item.SourcePid,
                                                            TargetPid = item.TargetPid, ActorToolTip = sourceToolTip,
                                                            TargetToolTip = targetToolTip, ArgumentSummary = detailSig,
                                                            HitCount = hits, Details = details } }
                };
                _state.TrackRow(row);
                SyncVisibleRow(row);
            }

            _state.EvictOverflow(MaxGroupCount);
        }

        internal IReadOnlyList<GroupedEventRow> SnapshotItems()
        {
            return _state.SnapshotItems();
        }

        internal GroupedEventRow? GetSelectedGroupClone()
        {
            return _state.GetSelectedGroupClone(RelationsGrid.SelectedItem);
        }

        internal void LoadHistory(IEnumerable<GroupedEventRow> groups)
        {
            _state.LoadHistory(groups, clone =>
                                       {
                                           clone.Severity = EventDetailFormatting.SeverityLabelFromText(clone.Severity);
                                           clone.Hits = Math.Max(1, clone.Hits);
                                           clone.Details =
                                               clone.Details.OrderBy(x => x.TimestampUtc)
                                                   .Select(x =>
                                                           {
                                                               x.Severity = EventDetailFormatting.SeverityLabelFromText(
                                                                   x.Severity);
                                                               return x;
                                                           })
                                                   .ToList();
                                           return clone;
                                       });

            ApplyFilter();
            UpdateSummary();
            UpdateNoDataOverlay();
            RaiseGraphStateChanged();
        }

        internal void ClearAll()
        {
            _state.Clear();
            UpdateSummary();
            UpdateNoDataOverlay();
            RaiseGraphStateChanged();
        }

        internal void TrimDetailPayload(int keepPerGroup)
        {
            int keep = Math.Max(1, keepPerGroup);
            _state.TrimDetailPayload(keep);

            ApplyFilter();
            RaiseGraphStateChanged();
        }

        private void UpdateSummary()
        {
        }

        private void UpdateNoDataOverlay()
        {
            if (NoDataOverlay == null)
            {
                return;
            }

            NoDataOverlay.Visibility = _state.ItemCount == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void ApplyFilter() => _state.ApplyFilter(MatchesFilter);

        private void SyncVisibleRow(GroupedEventRow row) => _state.SyncVisibleRow(row, MatchesFilter);

        private bool MatchesFilter(GroupedEventRow row)
        {
            if (_focusedPid != 0 &&
                !row.Details.Any(d => d.ActorPid == (uint)_focusedPid || d.TargetPid == (uint)_focusedPid))
                return false;

            string filter = _relationFilter;
            if (string.IsNullOrWhiteSpace(filter) || filter.Equals("ALL RELATIONS", StringComparison.OrdinalIgnoreCase))
                return true;

            return filter.ToUpperInvariant() switch {
                "PROCESSCREATE" => row.Event.Contains("ProcessCreate", StringComparison.OrdinalIgnoreCase),
                "THREADCREATE" => row.Event.Contains("ThreadCreate", StringComparison.OrdinalIgnoreCase),
                "HANDLE" => row.Event.Contains("Handle", StringComparison.OrdinalIgnoreCase),
                "HIGH+" => row.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase) ||
                           row.Severity.Equals("High", StringComparison.OrdinalIgnoreCase),
                _ => true
            };
        }

        private static string PickHigherSeverity(string current, string incoming)
        {
            return SeverityRank(incoming) > SeverityRank(current) ? incoming : current;
        }

        private static int SeverityRank(string severity)
        {
            return severity?.Trim().ToUpperInvariant() switch { "CRITICAL" => 4, "HIGH" => 3, "MEDIUM" => 2, "LOW" => 1,
                                                                _ => 0 };
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

        private void RelationsContextInspect_Click(object sender, RoutedEventArgs e) => InspectRequested?.Invoke(this,
                                                                                                                 e);

        private void RelationsContextCopySummary_Click(object sender, RoutedEventArgs e)
        {
            if (RelationsGrid.SelectedItem is GroupedEventRow row)
            {
                Clipboard.SetText(
                    $"{row.LastSeenUtc:O} {row.Event} {row.Severity} hits={row.Hits} {row.Detection} {row.ArgumentPreview}");
            }
        }

        private void RelationsContextCopyDetails_Click(object sender, RoutedEventArgs e)
        {
            if (RelationsGrid.SelectedItem is GroupedEventRow row)
            {
                Clipboard.SetText(string.Join(Environment.NewLine, row.Details.Select(d => d.Details)));
            }
        }

        private void RelationsGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
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
