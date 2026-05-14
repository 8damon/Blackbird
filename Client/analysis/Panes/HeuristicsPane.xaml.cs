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
        private const int MaxGroupCount = 256;
        private const int MaxDetailRowsPerGroup = 32;
        public event RoutedEventHandler? ReorderRequested;
        public event RoutedEventHandler? FloatRequested;
        public event RoutedEventHandler? CloseRequested;
        public event RoutedEventHandler? InspectRequested;

        private readonly GroupedEventPaneState _state = new();
        private string _severityFilter = "ALL";
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

        public HeuristicsPane()
        {
            InitializeComponent();
            HeuristicsGrid.ItemsSource = _state.VisibleItems;
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
            string signal = NormalizeEventLabel(eventName);
            string severity = EventDetailFormatting.SeverityLabel(item.Severity);
            string detection =
                NormalizeDetectionLabel(item.DetectionName, item.ActorPid, item.TargetPid, item.EventName);
            if (string.IsNullOrWhiteSpace(detection))
            {
                return;
            }

            string actor = FormatProcessIdentity(item.ActorPid);
            string target = FormatProcessIdentity(item.TargetPid);
            string actorToolTip = ProcessIdentityResolver.HoverText(item.ActorPid);
            string targetToolTip = ProcessIdentityResolver.HoverText(item.TargetPid);
            string context = BuildOperatorContext(item, signal);
            string key = $"det|{severity}|{detection}|{item.ActorPid}|{item.TargetPid}";
            int hits = Math.Max(1, item.RepeatCount);
            string detailsText = item.Details;

            _state.IncrementRawCount(hits);

            string detailSig = string.IsNullOrWhiteSpace(context) ? signal : context;

            if (_state.TryGetRow(key, out GroupedEventRow? existing))
            {
                existing.LastSeenUtc = now;
                existing.Hits = Math.Max(1, existing.Hits + hits);
                existing.Actor = actor;
                existing.Target = target;
                existing.ArgumentPreview = Truncate(context, 256);

                bool aggregated = false;
                if (_state.TryGetDetail(key, detailSig, out GroupedEventDetailRow? matchingDetail))
                {
                    matchingDetail.HitCount += hits;
                    matchingDetail.TimestampUtc = now;
                    aggregated = true;
                }

                if (!aggregated)
                {
                    var newDetail = new GroupedEventDetailRow { TimestampUtc = now,
                                                                Event = signal,
                                                                Severity = severity,
                                                                Detection = detection,
                                                                Source = source,
                                                                Actor = actor,
                                                                Target = target,
                                                                ActorPid = item.ActorPid,
                                                                TargetPid = item.TargetPid,
                                                                ActorToolTip = actorToolTip,
                                                                TargetToolTip = targetToolTip,
                                                                ArgumentSummary = detailSig,
                                                                HitCount = hits,
                                                                Details = detailsText };
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
                var firstDetail = new GroupedEventDetailRow { TimestampUtc = now,
                                                              Event = signal,
                                                              Severity = severity,
                                                              Detection = detection,
                                                              Source = source,
                                                              Actor = actor,
                                                              Target = target,
                                                              ActorPid = item.ActorPid,
                                                              TargetPid = item.TargetPid,
                                                              ActorToolTip = actorToolTip,
                                                              TargetToolTip = targetToolTip,
                                                              ArgumentSummary = detailSig,
                                                              HitCount = hits,
                                                              Details = detailsText };
                var row = new GroupedEventRow {
                    GroupKey = key,           LastSeenUtc = now,     Event = signal,
                    Severity = severity,      Detection = detection, Actor = actor,
                    Target = target,          Hits = hits,           ArgumentPreview = Truncate(context, 256),
                    Details = { firstDetail }
                };
                _state.TrackRow(row);
                SyncVisibleRow(row);
            }

            _state.EvictOverflow(MaxGroupCount);
        }

        internal IReadOnlyList<GroupedEventRow>
        SnapshotItems() => _state.SnapshotItems().Where(MatchesFilter).Select(static x => x.Clone()).ToList();

        internal GroupedEventRow? GetSelectedGroupClone() => _state.GetSelectedGroupClone(HeuristicsGrid.SelectedItem);

        internal void LoadHistory(IEnumerable<GroupedEventRow> groups)
        {
            _state.LoadHistory(groups, clone =>
                                       {
                                           clone.Hits = Math.Max(1, clone.Hits);
                                           clone.Event = NormalizeEventLabel(clone.Event);
                                           GroupedEventDetailRow? first = clone.Details.FirstOrDefault();
                                           clone.Detection =
                                               NormalizeDetectionLabel(clone.Detection, first?.ActorPid ?? 0,
                                                                       first?.TargetPid ?? 0, first?.Event);
                                           if (string.IsNullOrWhiteSpace(clone.Detection))
                                           {
                                               clone.GroupKey = $"suppressed:{clone.GroupKey}";
                                           }
                                           clone.Details = clone.Details.OrderBy(x => x.TimestampUtc).ToList();
                                           for (int i = 0; i < clone.Details.Count; i += 1)
                                           {
                                               clone.Details[i].Event = NormalizeEventLabel(clone.Details[i].Event);
                                               clone.Details[i].Detection = clone.Detection;
                                           }

                                           RefreshGroupDisplayFields(clone);

                                           return clone;
                                       });

            ApplyFilter();
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        public void ClearAll()
        {
            _state.Clear();
            SummaryBlock.Text = "No detections yet";
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

            SummaryBlock.Text = $"Groups: {_state.ItemCount} / Events: {_state.TotalRawCount}";
        }

        private void UpdateNoDataOverlay()
        {
            if (HeuristicsNoDataOverlay == null)
            {
                return;
            }

            HeuristicsNoDataOverlay.Visibility = _state.ItemCount == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void ApplyFilter()
        {
            _state.ApplyFilter(MatchesFilter);
        }

        private void SyncVisibleRow(GroupedEventRow row) => _state.SyncVisibleRow(row, MatchesFilter);

        private bool MatchesFilter(GroupedEventRow row)
        {
            if (string.IsNullOrWhiteSpace(row.Detection))
                return false;

            if (_focusedPid != 0 &&
                !row.Details.Any(d => d.ActorPid == (uint)_focusedPid || d.TargetPid == (uint)_focusedPid))
                return false;

            if (string.IsNullOrWhiteSpace(_severityFilter) ||
                _severityFilter.Equals("ALL", StringComparison.OrdinalIgnoreCase))
                return true;

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

        private void HeuristicsContextInspect_Click(object sender, RoutedEventArgs e) => InspectRequested?.Invoke(this,
                                                                                                                  e);

        private void HeuristicsContextCopySummary_Click(object sender, RoutedEventArgs e)
        {
            if (HeuristicsGrid.SelectedItem is GroupedEventRow row)
            {
                Clipboard.SetText(
                    $"{row.LastSeenUtc:O} {row.Event} {row.Severity} hits={row.Hits} {row.Detection} {row.ArgumentPreview}");
            }
        }

        private void HeuristicsContextCopyDetails_Click(object sender, RoutedEventArgs e)
        {
            if (HeuristicsGrid.SelectedItem is GroupedEventRow row)
            {
                Clipboard.SetText(string.Join(Environment.NewLine, row.Details.Select(d => d.Details)));
            }
        }

        private void HeuristicsGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
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

        private static string NormalizeEventLabel(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return "-";
            }

            return value.Replace('_', ' ').Trim();
        }

        private static string NormalizeDetectionLabel(string? value, uint actorPid, uint targetPid,
                                                      string? operation = null)
        {
            return OperatorDetectionFormatter.Format(value, actorPid, targetPid, operation);
        }

        private static string BuildOperatorContext(HeuristicEventView item, string signal)
        {
            string reason = CleanOperatorText(item.Reason);
            if (!string.IsNullOrWhiteSpace(reason))
            {
                return reason;
            }

            string evidence = CleanOperatorText(item.Evidence);
            if (!string.IsNullOrWhiteSpace(evidence))
            {
                return evidence;
            }

            return signal;
        }

        private static string CleanOperatorText(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            string text = value.Trim();
            if (text.StartsWith("reason=", StringComparison.OrdinalIgnoreCase))
            {
                text = text["reason=".Length..].Trim();
            }

            int corrIndex = text.IndexOf("; corrFlags=", StringComparison.OrdinalIgnoreCase);
            if (corrIndex > 0)
            {
                text = text[..corrIndex].Trim();
            }

            return Truncate(text.Replace("; ", " | "), 512);
        }

        private static void RefreshGroupDisplayFields(GroupedEventRow row)
        {
            GroupedEventDetailRow? latest = row.Details.OrderByDescending(x => x.TimestampUtc).FirstOrDefault();
            if (latest == null)
            {
                return;
            }

            row.Actor = string.IsNullOrWhiteSpace(row.Actor) ? latest.Actor : row.Actor;
            row.Target = string.IsNullOrWhiteSpace(row.Target) ? latest.Target : row.Target;
            row.ArgumentPreview = string.IsNullOrWhiteSpace(row.ArgumentPreview) ? Truncate(latest.ArgumentSummary, 256)
                                                                                 : row.ArgumentPreview;
        }

        private static string FormatProcessIdentity(uint pid)
        {
            if (pid == 0)
            {
                return "-";
            }

            return OperatorDetectionFormatter.FormatProcessIdentity(pid);
        }

        private static string Truncate(string? value, int max)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            string text = value.Trim();
            return text.Length <= max ? text : text[..Math.Max(0, max - 3)] + "...";
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
