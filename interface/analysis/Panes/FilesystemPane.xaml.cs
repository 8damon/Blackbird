using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace BlackbirdInterface
{
    public partial class FilesystemPane : UserControl
    {
        private const int MaxGroupCount = 192;
        private const int MaxDetailRowsPerGroup = 24;
        public event RoutedEventHandler? CloseRequested;
        public event RoutedEventHandler? InspectRequested;

        private readonly BulkObservableCollection<GroupedEventRow> _items = new();
        private readonly List<GroupedEventRow> _allItems = new();
        private readonly Dictionary<string, GroupedEventRow> _byKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, GroupedEventRow> _visibleByKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, Dictionary<string, GroupedEventDetailRow>> _detailSigByGroupKey = new(StringComparer.Ordinal);
        private int _totalRawCount;
        private int _totalDetailRows;
        private string _operationFilter = "ALL";
        private string _searchFilter = string.Empty;

        internal int ItemCount => _items.Count;
        internal int TotalRawCount => _totalRawCount;
        internal int DetailRowCount => _totalDetailRows;

        public FilesystemPane()
        {
            InitializeComponent();
            FilesystemGrid.ItemsSource = _items;

            OperationFilter.ItemsSource = new[]
            {
                "ALL",
                "CREATE",
                "READ",
                "WRITE",
                "CLOSE",
                "CLEANUP",
                "SET_INFORMATION",
                "QUERY_INFORMATION",
                "DIRECTORY_CONTROL",
                "FS_CONTROL"
            };
            OperationFilter.SelectedIndex = 0;

            UpdateSummary();
            UpdateNoDataOverlay();
        }

        internal void PushFileEvent(IoctlParsedEvent record)
        {
            PushFileEvents(new[] { record });
        }

        internal void PushFileEvents(IEnumerable<IoctlParsedEvent> records)
        {
            foreach (IoctlParsedEvent record in records)
            {
                PushFileEventCore(record);
            }

            UpdateSummary();
            UpdateNoDataOverlay();
        }

        private void PushFileEventCore(IoctlParsedEvent record)
        {
            DateTime now = DateTime.UtcNow;
            string operation = DescribeOperation(record.FileOperation);
            string severity = DetermineSeverityLabel(record);
            string path = string.IsNullOrWhiteSpace(record.FilePath) ? "<unknown>" : record.FilePath.Trim();
            string actor = ProcessIdentityResolver.Describe(record.FileProcessPid);
            string actorToolTip = ProcessIdentityResolver.HoverText(record.FileProcessPid);
            string normalizedPath = NormalizePathForKey(path);

            string details =
                $"seq={record.Sequence} operation={operation} pid={record.FileProcessPid} tid={record.FileThreadId} " +
                $"major={record.FileMajorCode} minor={record.FileMinorCode} status=0x{record.FileStatus:X8} info=0x{record.FileInformation:X} " +
                $"len=0x{record.FileLength:X} offset=0x{record.FileByteOffset:X} irpFlags=0x{record.FileIrpFlags:X8} " +
                $"createOptions=0x{record.FileCreateOptions:X8} createDisposition=0x{record.FileCreateDisposition:X8} " +
                $"desiredAccess=0x{record.FileDesiredAccess:X8} shareAccess=0x{record.FileShareAccess:X8} fileFlags=0x{record.FileFlags:X8} " +
                $"fileObject=0x{record.FileObject:X} fileId=0x{record.FileId:X} path={path}";

            string key = $"{record.FileProcessPid}|{operation}|{normalizedPath}";
            string detailSig = BuildDetailSignature(record);
            _totalRawCount += 1;

            if (_byKey.TryGetValue(key, out GroupedEventRow? existing))
            {
                existing.LastSeenUtc = now;
                existing.Hits = Math.Max(1, existing.Hits + 1);
                existing.Severity = PickHigherSeverity(existing.Severity, severity);

                bool aggregated = false;
                if (_detailSigByGroupKey.TryGetValue(key, out Dictionary<string, GroupedEventDetailRow>? sigMap) &&
                    sigMap.TryGetValue(detailSig, out GroupedEventDetailRow? matchingDetail))
                {
                    matchingDetail.HitCount += 1;
                    matchingDetail.TimestampUtc = now;
                    matchingDetail.Details = details;
                    aggregated = true;
                }

                if (!aggregated)
                {
                    var newDetail = new GroupedEventDetailRow
                    {
                        TimestampUtc = now,
                        Event = operation,
                        Severity = severity,
                        Detection = path,
                        Source = "Kernel-IOCTL",
                        Actor = actor,
                        Target = path,
                        ActorPid = record.FileProcessPid,
                        TargetPid = 0,
                        ActorToolTip = actorToolTip,
                        ArgumentSummary = detailSig,
                        HitCount = 1,
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
                    Event = operation,
                    Severity = severity,
                    Detection = path,
                    Hits = 1,
                    Details =
                    {
                        new GroupedEventDetailRow
                        {
                            TimestampUtc = now,
                            Event = operation,
                            Severity = severity,
                            Detection = path,
                            Source = "Kernel-IOCTL",
                            Actor = actor,
                            Target = path,
                            ActorPid = record.FileProcessPid,
                            TargetPid = 0,
                            ActorToolTip = actorToolTip,
                            ArgumentSummary = detailSig,
                            HitCount = 1,
                            Details = details
                        }
                    }
                };
                _allItems.Add(row);
                _byKey[key] = row;
                _detailSigByGroupKey[key] = new Dictionary<string, GroupedEventDetailRow>(StringComparer.Ordinal)
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
            => _allItems.Select(x => x.Clone()).ToList();

        internal GroupedEventRow? GetSelectedGroupClone()
            => (FilesystemGrid.SelectedItem as GroupedEventRow)?.Clone();

        internal void LoadHistory(IEnumerable<GroupedEventRow> groups)
        {
            _items.Clear();
            _allItems.Clear();
            _byKey.Clear();
            _visibleByKey.Clear();
            _detailSigByGroupKey.Clear();
            _totalRawCount = 0;
            _totalDetailRows = 0;

            foreach (GroupedEventRow source in groups)
            {
                GroupedEventRow clone = source.Clone();
                clone.Hits = Math.Max(1, clone.Hits);
                clone.Details = clone.Details.OrderBy(x => x.TimestampUtc).ToList();
                _allItems.Add(clone);
                _byKey[clone.GroupKey] = clone;
                _totalRawCount += clone.Hits;
                _totalDetailRows += clone.Details.Count;
                RebuildDetailSigMap(clone);
            }

            ApplyFilters();
            UpdateSummary();
            UpdateNoDataOverlay();
        }

        internal void ClearAll()
        {
            _items.Clear();
            _allItems.Clear();
            _byKey.Clear();
            _visibleByKey.Clear();
            _detailSigByGroupKey.Clear();
            _totalRawCount = 0;
            _totalDetailRows = 0;
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
                row.Details = row.Details
                    .OrderByDescending(x => x.TimestampUtc)
                    .Take(keep)
                    .OrderBy(x => x.TimestampUtc)
                    .ToList();
                _totalDetailRows -= Math.Max(0, originalCount - row.Details.Count);
                _byKey[row.GroupKey] = row;
                RebuildDetailSigMap(row);
            }
            ApplyFilters();
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

        private void ApplyFilters()
        {
            var visibleItems = new List<GroupedEventRow>();
            _visibleByKey.Clear();
            foreach (GroupedEventRow row in _allItems)
            {
                if (!MatchesFilters(row))
                {
                    continue;
                }

                visibleItems.Add(row);
                _visibleByKey[row.GroupKey] = row;
            }

            _items.ReplaceAll(visibleItems);
        }

        private void SyncVisibleRow(GroupedEventRow row)
        {
            bool matches = MatchesFilters(row);
            bool isVisible = _visibleByKey.ContainsKey(row.GroupKey);

            if (matches)
            {
                if (!isVisible)
                {
                    _items.Add(row);
                    _visibleByKey[row.GroupKey] = row;
                }
                return;
            }

            if (!isVisible)
            {
                return;
            }

            _visibleByKey.Remove(row.GroupKey);
            _items.Remove(row);
        }

        private bool MatchesFilters(GroupedEventRow row)
        {
            if (!string.Equals(_operationFilter, "ALL", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(row.Event, _operationFilter, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(_searchFilter))
            {
                return true;
            }

            if (ContainsIgnoreCase(row.Event, _searchFilter) ||
                ContainsIgnoreCase(row.Severity, _searchFilter) ||
                ContainsIgnoreCase(row.Detection, _searchFilter))
            {
                return true;
            }

            foreach (GroupedEventDetailRow detail in row.Details)
            {
                if (ContainsIgnoreCase(detail.FilterText, _searchFilter))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool ContainsIgnoreCase(string? text, string value)
        {
            if (string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            return text.IndexOf(value, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private void UpdateSummary()
        {
            if (SummaryBlock == null)
            {
                return;
            }

            SummaryBlock.Text = $"Shown {_items.Count}/{_allItems.Count} | Events {_totalRawCount}";
        }

        private void UpdateNoDataOverlay()
        {
            if (NoDataOverlay == null)
            {
                return;
            }

            NoDataOverlay.Visibility = _items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private static string DescribeOperation(uint operation)
        {
            return operation switch
            {
                BlackbirdNative.FileOperationCreate => "CREATE",
                BlackbirdNative.FileOperationRead => "READ",
                BlackbirdNative.FileOperationWrite => "WRITE",
                BlackbirdNative.FileOperationClose => "CLOSE",
                BlackbirdNative.FileOperationCleanup => "CLEANUP",
                BlackbirdNative.FileOperationSetInformation => "SET_INFORMATION",
                BlackbirdNative.FileOperationQueryInformation => "QUERY_INFORMATION",
                BlackbirdNative.FileOperationDirectoryControl => "DIRECTORY_CONTROL",
                BlackbirdNative.FileOperationFsControl => "FS_CONTROL",
                _ => "UNKNOWN"
            };
        }

        private static string DetermineSeverityLabel(IoctlParsedEvent record)
        {
            bool isWriteLike =
                record.FileOperation == BlackbirdNative.FileOperationWrite ||
                record.FileOperation == BlackbirdNative.FileOperationSetInformation ||
                record.FileOperation == BlackbirdNative.FileOperationFsControl;

            if (record.FileStatus != 0 && record.FileStatus != 0x00000000UL)
            {
                return "Medium";
            }

            return isWriteLike ? "Medium" : "Low";
        }

        private static string NormalizePathForKey(string path)
            => string.IsNullOrWhiteSpace(path) ? "<unknown>" : path.Trim().ToUpperInvariant();

        private static string BuildDetailSignature(IoctlParsedEvent record)
        {
            return
                $"{record.FileProcessPid}|{record.FileThreadId}|{record.FileOperation:X}|{record.FileStatus:X}|{record.FileMajorCode:X}|{record.FileMinorCode:X}|" +
                $"{record.FileCreateDisposition:X}|{record.FileDesiredAccess:X}|{record.FileShareAccess:X}|{record.FileFlags:X}|" +
                $"{record.FileObject:X}|{record.FileId:X}|{record.FileByteOffset:X}|{record.FileLength:X}|{record.FileInformation:X}|{record.FileIrpFlags:X8}";
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

        private void OperationFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = e;
            ComboBox? combo = sender as ComboBox ?? OperationFilter;
            _operationFilter = ((combo?.SelectedItem as string) ?? ((combo?.SelectedItem as ComboBoxItem)?.Content as string) ?? "ALL").Trim();
            if (_operationFilter.Length == 0)
            {
                _operationFilter = "ALL";
            }
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

        private void FilesystemGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            _ = sender;
            _ = e;
            if (FilesystemGrid.SelectedItem is GroupedEventRow row)
            {
                var detail = new SimpleEventDetailWindow("Filesystem Event", row.Clone())
                {
                    Owner = Window.GetWindow(this)
                };
                detail.Show();
            }
        }

        private void FilesystemBtnInspect_Click(object sender, RoutedEventArgs e) => InspectRequested?.Invoke(this, e);

        private void FilesystemBtnClose_Click(object sender, RoutedEventArgs e) => CloseRequested?.Invoke(this, e);
    }
}
