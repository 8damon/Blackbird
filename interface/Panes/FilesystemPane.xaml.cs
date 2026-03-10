using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace SleepwalkerInterface
{
    public partial class FilesystemPane : UserControl
    {
        public event RoutedEventHandler? CloseRequested;
        public event RoutedEventHandler? InspectRequested;

        private readonly ObservableCollection<GroupedEventRow> _items = new();
        private readonly List<GroupedEventRow> _allItems = new();
        private readonly Dictionary<string, GroupedEventRow> _byKey = new(StringComparer.Ordinal);
        private int _totalRawCount;
        private string _operationFilter = "ALL";
        private string _searchFilter = string.Empty;

        internal int ItemCount => _items.Count;
        internal int TotalRawCount => _totalRawCount;

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
            DateTime now = DateTime.UtcNow;
            string operation = DescribeOperation(record.FileOperation);
            string severity = DetermineSeverityLabel(record);
            string path = string.IsNullOrWhiteSpace(record.FilePath) ? "<unknown>" : record.FilePath.Trim();
            string actor = ProcessIdentityResolver.Describe(record.FileProcessPid);

            string details =
                $"seq={record.Sequence} operation={operation} pid={record.FileProcessPid} tid={record.FileThreadId} " +
                $"major={record.FileMajorCode} minor={record.FileMinorCode} status=0x{record.FileStatus:X8} info=0x{record.FileInformation:X} " +
                $"len=0x{record.FileLength:X} offset=0x{record.FileByteOffset:X} irpFlags=0x{record.FileIrpFlags:X8} " +
                $"createOptions=0x{record.FileCreateOptions:X8} createDisposition=0x{record.FileCreateDisposition:X8} " +
                $"desiredAccess=0x{record.FileDesiredAccess:X8} shareAccess=0x{record.FileShareAccess:X8} fileFlags=0x{record.FileFlags:X8} " +
                $"fileObject=0x{record.FileObject:X} fileId=0x{record.FileId:X} path={path}";

            string key = $"{operation}|{severity}|{path}";
            _totalRawCount += 1;

            if (_byKey.TryGetValue(key, out GroupedEventRow? existing))
            {
                existing.LastSeenUtc = now;
                existing.Hits = Math.Max(1, existing.Hits + 1);
                existing.Details.Add(new GroupedEventDetailRow
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
                    Details = details
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
                            Details = details
                        }
                    }
                };
                _allItems.Add(row);
                _byKey[key] = row;
            }

            while (_allItems.Count > 2000)
            {
                string evictKey = _allItems[0].GroupKey;
                _allItems.RemoveAt(0);
                _byKey.Remove(evictKey);
            }

            ApplyFilters();
            UpdateSummary();
            UpdateNoDataOverlay();
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
            _totalRawCount = 0;

            foreach (GroupedEventRow source in groups)
            {
                GroupedEventRow clone = source.Clone();
                clone.Hits = Math.Max(1, clone.Hits);
                clone.Details = clone.Details.OrderBy(x => x.TimestampUtc).ToList();
                _allItems.Add(clone);
                _byKey[clone.GroupKey] = clone;
                _totalRawCount += clone.Hits;
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
            _totalRawCount = 0;
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
                _allItems[i] = row;
                _byKey[row.GroupKey] = row;
            }
            ApplyFilters();
        }

        private void ApplyFilters()
        {
            _items.Clear();
            foreach (GroupedEventRow row in _allItems)
            {
                if (!MatchesFilters(row))
                {
                    continue;
                }

                _items.Add(row);
            }
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
            SummaryBlock.Text = $"Shown {_items.Count}/{_allItems.Count} | Events {_totalRawCount}";
        }

        private void UpdateNoDataOverlay()
        {
            NoDataOverlay.Visibility = _items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private static string DescribeOperation(uint operation)
        {
            return operation switch
            {
                SleepwalkerNative.FileOperationCreate => "CREATE",
                SleepwalkerNative.FileOperationRead => "READ",
                SleepwalkerNative.FileOperationWrite => "WRITE",
                SleepwalkerNative.FileOperationClose => "CLOSE",
                SleepwalkerNative.FileOperationCleanup => "CLEANUP",
                SleepwalkerNative.FileOperationSetInformation => "SET_INFORMATION",
                SleepwalkerNative.FileOperationQueryInformation => "QUERY_INFORMATION",
                SleepwalkerNative.FileOperationDirectoryControl => "DIRECTORY_CONTROL",
                SleepwalkerNative.FileOperationFsControl => "FS_CONTROL",
                _ => "UNKNOWN"
            };
        }

        private static string DetermineSeverityLabel(IoctlParsedEvent record)
        {
            bool isWriteLike =
                record.FileOperation == SleepwalkerNative.FileOperationWrite ||
                record.FileOperation == SleepwalkerNative.FileOperationSetInformation ||
                record.FileOperation == SleepwalkerNative.FileOperationFsControl;

            if (record.FileStatus != 0 && record.FileStatus != 0x00000000UL)
            {
                return "Medium";
            }

            return isWriteLike ? "Medium" : "Low";
        }

        private void OperationFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = sender;
            _ = e;
            _operationFilter = (OperationFilter.SelectedItem as string ?? "ALL").Trim();
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
