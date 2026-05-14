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
    public partial class FilesystemPane : UserControl
    {
        private const int MaxGroupCount = 192;
        private const int MaxDetailRowsPerGroup = 24;
        public event RoutedEventHandler? CloseRequested;
        public event RoutedEventHandler? InspectRequested;

        private readonly GroupedEventPaneState _state = new();
        private string _operationFilter = "ALL";
        private string _searchFilter = string.Empty;
        private int _focusedPid;

        public int FocusedPid
        {
            set {
                _focusedPid = value;
                ApplyFilters();
            }
        }

        internal int ItemCount => _state.ItemCount;
        internal int TotalRawCount => _state.TotalRawCount;
        internal int DetailRowCount => _state.TotalDetailRows;

        public FilesystemPane()
        {
            InitializeComponent();
            FilesystemGrid.ItemsSource = _state.VisibleItems;

            OperationFilter.ItemsSource = new[] { "ALL",
                                                  "CREATE",
                                                  "READ",
                                                  "WRITE",
                                                  "CLOSE",
                                                  "CLEANUP",
                                                  "SET_INFORMATION",
                                                  "QUERY_INFORMATION",
                                                  "DIRECTORY_CONTROL",
                                                  "FS_CONTROL" };
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
            if (IsBlackbirdInternalFilesystemPath(record.FilePath))
            {
                return;
            }

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
                                                                Detection = path,
                                                                Source = "Kernel-IOCTL",
                                                                Actor = actor,
                                                                Target = path,
                                                                ActorPid = record.FileProcessPid,
                                                                TargetPid = 0,
                                                                ActorToolTip = actorToolTip,
                                                                ArgumentSummary = detailSig,
                                                                HitCount = 1,
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
                var row = new GroupedEventRow { GroupKey = key,
                                                LastSeenUtc = now,
                                                Event = operation,
                                                Severity = severity,
                                                Detection = path,
                                                Hits = 1,
                                                Details = { new GroupedEventDetailRow {
                                                    TimestampUtc = now, Event = operation, Severity = severity,
                                                    Detection = path, Source = "Kernel-IOCTL", Actor = actor,
                                                    Target = path, ActorPid = record.FileProcessPid, TargetPid = 0,
                                                    ActorToolTip = actorToolTip, ArgumentSummary = detailSig,
                                                    HitCount = 1, Details = details
                                                } } };
                _state.TrackRow(row);
                SyncVisibleRow(row);
            }

            _state.EvictOverflow(MaxGroupCount);
        }

        internal IReadOnlyList<GroupedEventRow> SnapshotItems() => _state.SnapshotItems();

        internal GroupedEventRow? GetSelectedGroupClone() => _state.GetSelectedGroupClone(FilesystemGrid.SelectedItem);

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
            if (IsBlackbirdInternalFilesystemPath(row.Detection) ||
                row.Details.Any(static detail => IsBlackbirdInternalFilesystemPath(detail.Detection) ||
                                                 IsBlackbirdInternalFilesystemPath(detail.Target)))
            {
                return false;
            }

            if (_focusedPid != 0 &&
                !row.Details.Any(d => d.ActorPid == (uint)_focusedPid || d.TargetPid == (uint)_focusedPid))
                return false;

            if (!string.Equals(_operationFilter, "ALL", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(row.Event, _operationFilter, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(_searchFilter))
            {
                return true;
            }

            if (ContainsIgnoreCase(row.Event, _searchFilter) || ContainsIgnoreCase(row.Severity, _searchFilter) ||
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

            SummaryBlock.Text = $"Shown {_state.ItemCount}/{_state.AllItems.Count} | Events {_state.TotalRawCount}";
        }

        private void UpdateNoDataOverlay()
        {
            if (NoDataOverlay == null)
            {
                return;
            }

            NoDataOverlay.Visibility = _state.ItemCount == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private static string DescribeOperation(uint operation)
        {
            return operation switch { BlackbirdNative.FileOperationCreate => "CREATE",
                                      BlackbirdNative.FileOperationRead => "READ",
                                      BlackbirdNative.FileOperationWrite => "WRITE",
                                      BlackbirdNative.FileOperationClose => "CLOSE",
                                      BlackbirdNative.FileOperationCleanup => "CLEANUP",
                                      BlackbirdNative.FileOperationSetInformation => "SET_INFORMATION",
                                      BlackbirdNative.FileOperationQueryInformation => "QUERY_INFORMATION",
                                      BlackbirdNative.FileOperationDirectoryControl => "DIRECTORY_CONTROL",
                                      BlackbirdNative.FileOperationFsControl => "FS_CONTROL",
                                      _ => "UNKNOWN" };
        }

        private static string DetermineSeverityLabel(IoctlParsedEvent record)
        {
            bool isWriteLike = record.FileOperation == BlackbirdNative.FileOperationWrite ||
                               record.FileOperation == BlackbirdNative.FileOperationSetInformation ||
                               record.FileOperation == BlackbirdNative.FileOperationFsControl;

            if (record.FileStatus != 0 && record.FileStatus != 0x00000000UL)
            {
                return "Medium";
            }

            return isWriteLike ? "Medium" : "Low";
        }

        private static string NormalizePathForKey(string path) => string.IsNullOrWhiteSpace(path)
                                                                      ? "<unknown>"
                                                                      : path.Trim().ToUpperInvariant();

        private static bool IsBlackbirdInternalFilesystemPath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            string normalized = path.Replace('/', '\\').Trim();
            return normalized.Contains("\\ProgramData\\Blackbird", StringComparison.OrdinalIgnoreCase) ||
                   normalized.EndsWith("\\controller.log", StringComparison.OrdinalIgnoreCase) ||
                   normalized.EndsWith("\\controller.log.1", StringComparison.OrdinalIgnoreCase);
        }

        private static string BuildDetailSignature(IoctlParsedEvent record)
        {
            return $"{record.FileProcessPid}|{record.FileThreadId}|{record.FileOperation:X}|{record.FileStatus:X}|{record.FileMajorCode:X}|{record.FileMinorCode:X}|" +
                   $"{record.FileCreateDisposition:X}|{record.FileDesiredAccess:X}|{record.FileShareAccess:X}|{record.FileFlags:X}|" +
                   $"{record.FileObject:X}|{record.FileId:X}|{record.FileByteOffset:X}|{record.FileLength:X}|{record.FileInformation:X}|{record.FileIrpFlags:X8}";
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

        private void OperationFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = e;
            ComboBox? combo = sender as ComboBox ?? OperationFilter;
            _operationFilter =
                ((combo?.SelectedItem as string) ?? ((combo?.SelectedItem as ComboBoxItem)?.Content as string) ?? "ALL")
                    .Trim();
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
                var detail =
                    new SimpleEventDetailWindow("Filesystem Event", row.Clone()) { Owner = Window.GetWindow(this) };
                detail.Show();
            }
        }

        private void FilesystemBtnInspect_Click(object sender, RoutedEventArgs e) => InspectRequested?.Invoke(this, e);

        private void FilesystemContextInspect_Click(object sender, RoutedEventArgs e) => InspectRequested?.Invoke(this,
                                                                                                                  e);

        private void FilesystemContextCopySummary_Click(object sender, RoutedEventArgs e)
        {
            if (FilesystemGrid.SelectedItem is GroupedEventRow row)
            {
                Clipboard.SetText(
                    $"{row.LastSeenUtc:O} {row.Event} {row.Severity} hits={row.Hits} {row.Detection} {row.ArgumentPreview}");
            }
        }

        private void FilesystemContextCopyDetails_Click(object sender, RoutedEventArgs e)
        {
            if (FilesystemGrid.SelectedItem is GroupedEventRow row)
            {
                Clipboard.SetText(string.Join(Environment.NewLine, row.Details.Select(d => d.Details)));
            }
        }

        private void FilesystemGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
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

        private void FilesystemBtnClose_Click(object sender, RoutedEventArgs e) => CloseRequested?.Invoke(this, e);
    }
}
