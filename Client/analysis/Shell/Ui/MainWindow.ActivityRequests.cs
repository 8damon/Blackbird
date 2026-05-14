using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Input;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private void ExtendedActivityCopySummary_Click(object sender, RoutedEventArgs e)
        {
            if (TryGetSelectedExtendedActivityRow(sender, out ExtendedActivityRowSnapshot? row))
            {
                Clipboard.SetText(
                    $"{row.LastSeenUtc:O} {row.TypeLabel} {row.ActorLabel}->{row.TargetLabel} {row.SubjectLabel} {row.OperationLabel} hits={row.Hits}");
            }
        }

        private void ExtendedActivityCopyDetails_Click(object sender, RoutedEventArgs e)
        {
            if (TryGetSelectedExtendedActivityRow(sender, out ExtendedActivityRowSnapshot? row))
            {
                Clipboard.SetText(string.Join(
                    Environment.NewLine,
                    new[] { $"Type: {row.TypeLabel}", $"Actor: {row.ActorLabel}", $"Target: {row.TargetLabel}",
                            $"Subject: {row.SubjectLabel}", $"Operation: {row.OperationLabel}",
                            $"Last Seen: {row.LastSeenUtc:O}", $"Hits: {row.Hits}", $"Details: {row.DetailLabel}" }));
            }
        }

        private void ExtendedActivityGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
        {
            DataGridRow? row = FindAncestor<DataGridRow>(e.OriginalSource as DependencyObject);
            if (row == null)
            {
                return;
            }

            row.IsSelected = true;
            row.Focus();
        }

        private static bool TryGetSelectedExtendedActivityRow(object sender,
                                                              [NotNullWhen(true)] out ExtendedActivityRowSnapshot? row)
        {
            row = null;
            if (sender is MenuItem { Parent : ContextMenu { PlacementTarget : DataGrid grid } } &&
                grid.SelectedItem is ExtendedActivityRowSnapshot selected)
            {
                row = selected;
                return true;
            }

            return false;
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

        private void PerformancePaneHost_ThreadDoubleClicked(object? sender, ThreadUsageRow row)
        {
            int pid = _currentSession?.Pid ?? TryGetPid();
            var w = new ThreadStackWindow(
                pid, row.Tid, row.State, initialHistory: GetThreadStackHistory(pid, row.Tid, row.State),
                onSnapshotCaptured: snapshot => PersistThreadStackSnapshot(pid, row.Tid, row.State, snapshot),
                observationTimeUtcProvider: GetCurrentObservedUtc,
                liveCaptureAvailableProvider: () => _currentSession != null && _currentSession.Pid == pid &&
                                                    !_currentSession.TargetExited && !_currentSession.OfflineSnapshot,
                threadStateProvider: tid =>
                    PerformancePaneHost.SnapshotTopThreads().FirstOrDefault(x => x.Tid == tid)?.State ??
                    row.State) { Owner = this };
            w.Show();
        }

        private void OpenParallelStacksWindow()
        {
            int pid = _currentSession?.Pid ?? TryGetPid();
            IReadOnlyList<ThreadUsageRow> rows = PerformancePaneHost.SnapshotTopThreads();
            if (pid <= 0 || rows.Count == 0)
            {
                string reason =
                    PerformancePaneHost.IsTargetSuspended
                        ? "The target process is launch-suspended — thread sampling has not run yet. Resume the process first, then open parallel stacks."
                        : "No thread rows are available for stack comparison.";
                ThemedMessageBox.Show(this, reason, "Parallel Stacks", MessageBoxButton.OK,
                                      MessageBoxImage.Information);
                return;
            }

            var window = new ParallelStacksWindow(
                pid, rows, historyProvider: GetThreadStackHistory, observationTimeUtcProvider: GetCurrentObservedUtc,
                liveCaptureAvailableProvider: () => _currentSession != null && _currentSession.Pid == pid &&
                                                    !_currentSession.TargetExited && !_currentSession.OfflineSnapshot,
                threadSnapshotProvider: () => PerformancePaneHost.SnapshotTopThreads(),
                onSnapshotCaptured: (processId, tid, state, snapshot) =>
                    PersistThreadStackSnapshot(processId, tid, state, snapshot)) { Owner = this };
            window.Show();
        }
    }
}
