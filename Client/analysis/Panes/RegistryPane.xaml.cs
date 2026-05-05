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
    public partial class RegistryPane : UserControl
    {
        private const int MaxGroupCount = 256;
        private const int MaxDetailRowsPerGroup = 32;
        public event RoutedEventHandler? CloseRequested;
        public event RoutedEventHandler? InspectRequested;

        private readonly GroupedEventPaneState _state = new();
        private string _categoryFilter = "ALL";
        private string _severityFilter = "ALL";
        private string _searchFilter = string.Empty;

        internal int ItemCount => _state.ItemCount;
        internal int TotalRawCount => _state.TotalRawCount;
        internal int DetailRowCount => _state.TotalDetailRows;

        public RegistryPane()
        {
            InitializeComponent();
            RegistryGrid.ItemsSource = _state.VisibleItems;

            CategoryFilter.ItemsSource = new[] { "ALL", "READ", "WRITE", "RECON", "DELETE" };
            CategoryFilter.SelectedIndex = 0;

            SeverityFilter.ItemsSource = new[] { "ALL", "Critical", "High", "Medium", "Low", "Info" };
            SeverityFilter.SelectedIndex = 0;

            UpdateSummary();
            UpdateNoDataOverlay();
        }

        internal void PushRegistryEvent(IoctlParsedEvent record)
        {
            PushRegistryEvents(new[] { record });
        }

        internal void PushRegistryEvents(IEnumerable<IoctlParsedEvent> records)
        {
            foreach (IoctlParsedEvent record in records)
            {
                PushRegistryEventCore(record);
            }

            UpdateSummary();
            UpdateNoDataOverlay();
        }

        private void PushRegistryEventCore(IoctlParsedEvent record)
        {
            DateTime now = DateTime.UtcNow;
            string operation = DescribeOperation(record.RegistryOperation);
            string category = CategoryOf(record.RegistryOperation);
            string severity = DetermineSeverity(record);
            string keyPath =
                string.IsNullOrWhiteSpace(record.RegistryKeyPath) ? "<unknown>" : record.RegistryKeyPath.Trim();
            string valueName = record.RegistryValueName ?? string.Empty;
            string actor = ProcessIdentityResolver.Describe(record.RegistryProcessPid);
            string actorTip = ProcessIdentityResolver.HoverText(record.RegistryProcessPid);
            string normalKey = NormalizeKey(keyPath);

            string details =
                $"seq={record.Sequence} op={operation} cat={category} pid={record.RegistryProcessPid} tid={record.RegistryThreadId} " +
                $"notifyClass={record.RegistryNotifyClass} dataType=0x{record.RegistryDataType:X} dataSize={record.RegistryDataSize} " +
                $"flags=0x{record.RegistryFlags:X8} session={record.RegistrySessionId} " +
                $"key={keyPath} value={valueName}";

            string key = $"{record.RegistryProcessPid}|{operation}|{normalKey}";
            string detailSig = BuildDetailSig(record);
            _state.IncrementRawCount(1);

            if (_state.TryGetRow(key, out GroupedEventRow? existing))
            {
                existing.LastSeenUtc = now;
                existing.Hits = Math.Max(1, existing.Hits + 1);
                existing.Severity = PickHigherSeverity(existing.Severity, severity);

                bool aggregated = false;
                if (_state.TryGetDetail(key, detailSig, out GroupedEventDetailRow? matchingDetail))
                {
                    matchingDetail.HitCount += 1;
                    matchingDetail.TimestampUtc = now;
                    matchingDetail.Details = details;
                    aggregated = true;
                }

                if (!aggregated)
                {
                    var newDetail = new GroupedEventDetailRow { TimestampUtc = now,
                                                                Event = operation,
                                                                Severity = severity,
                                                                Detection = keyPath,
                                                                Source = "Kernel-IOCTL",
                                                                Actor = actor,
                                                                Target = keyPath,
                                                                ActorPid = record.RegistryProcessPid,
                                                                TargetPid = 0,
                                                                ActorToolTip = actorTip,
                                                                ArgumentSummary = detailSig,
                                                                HitCount = 1,
                                                                Details = details };
                    existing.Details.Add(newDetail);
                    _state.RegisterDetail(existing, newDetail);

                    if (existing.Details.Count > MaxDetailRowsPerGroup)
                    {
                        GroupedEventDetailRow evicted = existing.Details[0];
                        existing.Details.RemoveAt(0);
                        _state.ReplaceDetailCount(_state.TotalDetailRows - 1);
                        _state.RemoveDetailReference(key, evicted);
                    }
                }

                SyncVisibleRow(existing);
            }
            else
            {
                string preview = BuildArgumentPreview(record, valueName);
                var row = new GroupedEventRow { GroupKey = key,
                                                LastSeenUtc = now,
                                                Event = operation,
                                                Severity = severity,
                                                Detection = keyPath,
                                                ArgumentPreview = preview,
                                                Hits = 1,
                                                Details = { new GroupedEventDetailRow {
                                                    TimestampUtc = now, Event = operation, Severity = severity,
                                                    Detection = keyPath, Source = "Kernel-IOCTL", Actor = actor,
                                                    Target = keyPath, ActorPid = record.RegistryProcessPid,
                                                    TargetPid = 0, ActorToolTip = actorTip, ArgumentSummary = detailSig,
                                                    HitCount = 1, Details = details
                                                } } };
                _state.TrackRow(row);
                SyncVisibleRow(row);
            }

            _state.EvictOverflow(MaxGroupCount);
        }

        internal IReadOnlyList<GroupedEventRow> SnapshotItems() => _state.SnapshotItems();

        internal GroupedEventRow? GetSelectedGroupClone() => _state.GetSelectedGroupClone(RegistryGrid.SelectedItem);

        internal void LoadHistory(IEnumerable<GroupedEventRow> groups)
        {
            _state.LoadHistory(groups, clone =>
                                       {
                                           clone.Hits = Math.Max(1, clone.Hits);
                                           clone.Details = clone.Details.OrderBy(x => x.TimestampUtc).ToList();
                                           return clone;
                                       });

            ApplyFilters();
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        internal void ClearAll()
        {
            _state.Clear();
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        internal void TrimDetailPayload(int keepPerGroup)
        {
            int keep = Math.Max(1, keepPerGroup);
            _state.TrimDetailPayload(keep);
            ApplyFilters();
        }

        private void ApplyFilters()
        {
            _state.ApplyFilter(MatchesFilters);
        }

        private void SyncVisibleRow(GroupedEventRow row) => _state.SyncVisibleRow(row, MatchesFilters);

        private bool MatchesFilters(GroupedEventRow row)
        {
            if (!string.Equals(_categoryFilter, "ALL", StringComparison.OrdinalIgnoreCase))
            {
                string rowCat = CategoryOf(OperationIdOf(row.Event));
                if (!string.Equals(rowCat, _categoryFilter, StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            if (!string.Equals(_severityFilter, "ALL", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(row.Severity, _severityFilter, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(_searchFilter))
                return true;

            if (ContainsIgnoreCase(row.Event, _searchFilter) || ContainsIgnoreCase(row.Severity, _searchFilter) ||
                ContainsIgnoreCase(row.Detection, _searchFilter) ||
                ContainsIgnoreCase(row.ArgumentPreview, _searchFilter))
            {
                return true;
            }

            foreach (GroupedEventDetailRow detail in row.Details)
            {
                if (ContainsIgnoreCase(detail.FilterText, _searchFilter))
                    return true;
            }

            return false;
        }

        private static bool ContainsIgnoreCase(string? text, string value)
        {
            if (string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(value))
                return false;
            return text.IndexOf(value, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private void UpdateSummary()
        {
        }

        private void UpdateNoDataOverlay()
        {
            if (NoDataOverlay == null)
                return;
            NoDataOverlay.Visibility = _state.ItemCount == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private static string DescribeOperation(uint operation)
        {
            return operation switch { BlackbirdNative.RegistryOperationQueryValue => "QUERY_VALUE",
                                      BlackbirdNative.RegistryOperationQueryKey => "QUERY_KEY",
                                      BlackbirdNative.RegistryOperationEnumerateKey => "ENUMERATE_KEY",
                                      BlackbirdNative.RegistryOperationEnumerateValue => "ENUMERATE_VALUE",
                                      BlackbirdNative.RegistryOperationSetValue => "SET_VALUE",
                                      BlackbirdNative.RegistryOperationCreateKey => "CREATE_KEY",
                                      BlackbirdNative.RegistryOperationOpenKey => "OPEN_KEY",
                                      BlackbirdNative.RegistryOperationDeleteValue => "DELETE_VALUE",
                                      BlackbirdNative.RegistryOperationDeleteKey => "DELETE_KEY",
                                      _ => "UNKNOWN" };
        }

        private static uint OperationIdOf(string operationName)
        {
            return operationName switch { "QUERY_VALUE" => BlackbirdNative.RegistryOperationQueryValue,
                                          "QUERY_KEY" => BlackbirdNative.RegistryOperationQueryKey,
                                          "ENUMERATE_KEY" => BlackbirdNative.RegistryOperationEnumerateKey,
                                          "ENUMERATE_VALUE" => BlackbirdNative.RegistryOperationEnumerateValue,
                                          "SET_VALUE" => BlackbirdNative.RegistryOperationSetValue,
                                          "CREATE_KEY" => BlackbirdNative.RegistryOperationCreateKey,
                                          "OPEN_KEY" => BlackbirdNative.RegistryOperationOpenKey,
                                          "DELETE_VALUE" => BlackbirdNative.RegistryOperationDeleteValue,
                                          "DELETE_KEY" => BlackbirdNative.RegistryOperationDeleteKey,
                                          _ => BlackbirdNative.RegistryOperationUnknown };
        }

        internal static string CategoryOf(uint operation)
        {
            return operation switch {
                BlackbirdNative.RegistryOperationQueryValue or BlackbirdNative.RegistryOperationQueryKey => "READ",
                BlackbirdNative.RegistryOperationSetValue or BlackbirdNative.RegistryOperationCreateKey => "WRITE",
                BlackbirdNative.RegistryOperationEnumerateKey or BlackbirdNative
                    .RegistryOperationEnumerateValue or BlackbirdNative.RegistryOperationOpenKey => "RECON",
                BlackbirdNative.RegistryOperationDeleteValue or BlackbirdNative.RegistryOperationDeleteKey => "DELETE",
                _ => "OTHER"
            };
        }

        private static string DetermineSeverity(IoctlParsedEvent record)
        {
            if ((record.RegistryFlags & BlackbirdNative.RegistryFlagSensitiveQuery) != 0)
            {
                return CategoryOf(record.RegistryOperation) == "WRITE" ? "Critical" : "High";
            }
            if ((record.RegistryFlags & BlackbirdNative.RegistryFlagHighValuePath) != 0)
            {
                return CategoryOf(record.RegistryOperation) == "WRITE" ? "Critical" : "High";
            }
            return CategoryOf(record.RegistryOperation) == "WRITE" ? "Medium" : "Low";
        }

        private static string BuildArgumentPreview(IoctlParsedEvent record, string valueName)
        {
            string tag = string.Empty;
            if ((record.RegistryFlags & BlackbirdNative.RegistryFlagSensitiveQuery) != 0)
                tag = "[Sensitive]";
            else if ((record.RegistryFlags & BlackbirdNative.RegistryFlagHighValuePath) != 0)
                tag = "[High-Value]";

            if (!string.IsNullOrEmpty(valueName) && !string.IsNullOrEmpty(tag))
                return $"{tag} {valueName}";
            if (!string.IsNullOrEmpty(valueName))
                return valueName;
            return tag;
        }

        private static string NormalizeKey(string key) => string.IsNullOrWhiteSpace(key)
                                                              ? "<unknown>"
                                                              : key.Trim().ToUpperInvariant();

        private static string BuildDetailSig(IoctlParsedEvent record) =>
            $"{record.RegistryProcessPid}|{record.RegistryThreadId}|{record.RegistryOperation}|{record.RegistryNotifyClass}|{record.RegistryDataType}|{NormalizeKey(record.RegistryKeyPath)}";

        private static string PickHigherSeverity(string current, string incoming) => SeverityRank(incoming) >
                                                                                             SeverityRank(current)
                                                                                         ? incoming
                                                                                         : current;

        private static int SeverityRank(string severity)
        {
            return severity?.Trim().ToUpperInvariant() switch { "CRITICAL" => 4, "HIGH" => 3, "MEDIUM" => 2, "LOW" => 1,
                                                                _ => 0 };
        }

        private void CategoryFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = e;
            ComboBox? combo = sender as ComboBox ?? CategoryFilter;
            _categoryFilter = ((combo?.SelectedItem as string) ?? "ALL").Trim();
            if (_categoryFilter.Length == 0)
                _categoryFilter = "ALL";
            ApplyFilters();
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        private void SeverityFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = e;
            ComboBox? combo = sender as ComboBox ?? SeverityFilter;
            _severityFilter = ((combo?.SelectedItem as string) ?? "ALL").Trim();
            if (_severityFilter.Length == 0)
                _severityFilter = "ALL";
            ApplyFilters();
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            _ = sender;
            _ = e;
            _searchFilter = (SearchBox.Text ?? string.Empty).Trim();
            ApplyFilters();
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        private void RegistryGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            _ = sender;
            _ = e;
            if (RegistryGrid.SelectedItem is GroupedEventRow row)
            {
                var detail =
                    new SimpleEventDetailWindow("Registry Event", row.Clone()) { Owner = Window.GetWindow(this) };
                detail.Show();
            }
        }

        private void RegistryBtnInspect_Click(object sender, RoutedEventArgs e) => InspectRequested?.Invoke(this, e);

        private void RegistryContextInspect_Click(object sender, RoutedEventArgs e) => InspectRequested?.Invoke(this,
                                                                                                                e);

        private void RegistryContextCopySummary_Click(object sender, RoutedEventArgs e)
        {
            if (RegistryGrid.SelectedItem is GroupedEventRow row)
            {
                Clipboard.SetText(
                    $"{row.LastSeenUtc:O} {row.Event} {row.Severity} hits={row.Hits} {row.Detection} {row.ArgumentPreview}");
            }
        }

        private void RegistryContextCopyDetails_Click(object sender, RoutedEventArgs e)
        {
            if (RegistryGrid.SelectedItem is GroupedEventRow row)
            {
                Clipboard.SetText(string.Join(Environment.NewLine, row.Details.Select(d => d.Details)));
            }
        }

        private void RegistryGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
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

        private void RegistryBtnClose_Click(object sender, RoutedEventArgs e) => CloseRequested?.Invoke(this, e);
    }
}
