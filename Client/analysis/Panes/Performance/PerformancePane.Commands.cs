using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class PerformancePane
    {
        private void UpdateSubtitle()
        {
            var scope = _pid > 0 ? "Target Process" : "System-wide";
            if (_selectedSampleIndex < 0 || _selectedSampleIndex >= _historySamples.Count)
            {
                PerfSubTitle.Text = !_processLiveDataAvailable && _historySamples.Count > 0
                                        ? $"{scope} | No data at selected time"
                                        : $"{scope} | No data";
                return;
            }

            if (_lastSample == null)
            {
                PerfSubTitle.Text = $"{scope}";
                return;
            }

            double coresUsed = _lastSample.CpuPercent / 100.0 * Math.Max(1, _lastSample.CoreCount);
            PerfSubTitle.Text =
                $"{scope} | Cores used: {coresUsed:0.00}/{Math.Max(1, _lastSample.CoreCount)} ({_lastSample.CoresUsedPercent:0.0}%)";
        }

        private void PerfBtnReorder_Click(object sender,
                                          System.Windows.RoutedEventArgs e) => ReorderRequested?.Invoke(this, e);
        private void PerfBtnFloat_Click(object sender, System.Windows.RoutedEventArgs e) => FloatRequested?.Invoke(this,
                                                                                                                   e);
        private void PerfBtnClose_Click(object sender, System.Windows.RoutedEventArgs e) => CloseRequested?.Invoke(this,
                                                                                                                   e);

        private void TimeTravelToggle_Checked(object sender, RoutedEventArgs e)
        {
            _timeTravelEnabled = true;
            RebuildTimeTravelSliderBounds();
            int index = ResolveSampleIndexForCurrentView();
            ApplySampleIndex(index, updateSlider: true);
        }

        private void TimeTravelToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            _timeTravelEnabled = false;
            RebuildTimeTravelSliderBounds();
            if (_historySamples.Count > 0)
            {
                ApplySampleIndex(_historySamples.Count - 1, updateSlider: true);
                RebuildThreadLifecycleRows(DateTime.UtcNow);
            }
            else
            {
                UpdateSubtitle();
                UpdateLiveDataOverlays();
            }
        }

        private void TimeTravelSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (_timeTravelSliderProgrammatic || !_timeTravelEnabled)
            {
                return;
            }

            int index = (int)Math.Round(e.NewValue);
            ApplySampleIndex(index, updateSlider: false);
        }

        private void ThreadsGrid_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (ThreadsGrid.SelectedItem is ThreadUsageRow row)
                ThreadDoubleClicked?.Invoke(this, row);
        }

        private void ThreadContextOpenStack_Click(object sender, RoutedEventArgs e)
        {
            if (ThreadsGrid.SelectedItem is ThreadUsageRow row)
            {
                ThreadDoubleClicked?.Invoke(this, row);
            }
        }

        private void ThreadContextParallelStacks_Click(object sender, RoutedEventArgs e)
        {
            ParallelStacksRequested?.Invoke(this, e);
        }

        private void ThreadContextCopyTid_Click(object sender, RoutedEventArgs e)
        {
            if (ThreadsGrid.SelectedItem is ThreadUsageRow row)
            {
                Clipboard.SetText(row.Tid.ToString());
            }
        }

        private void MemoryAttributionGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (MemoryAttributionGrid.SelectedItem is not MemoryAttributionRow row)
                return;

            if (row.ThreadTid != 0)
            {
                OpenThreadStackFromMemoryRow(row);
                return;
            }
        }

        private void MemoryContextOpenStack_Click(object sender, RoutedEventArgs e)
        {
            if (MemoryAttributionGrid.SelectedItem is MemoryAttributionRow row)
            {
                OpenThreadStackFromMemoryRow(row);
            }
        }

        private void MemoryContextCopyBase_Click(object sender, RoutedEventArgs e)
        {
            if (MemoryAttributionGrid.SelectedItem is MemoryAttributionRow row &&
                !string.IsNullOrWhiteSpace(row.BaseAddress))
            {
                Clipboard.SetText(row.BaseAddress);
            }
        }

        private void ParallelStacksButton_Click(object sender,
                                                RoutedEventArgs e) => ParallelStacksRequested?.Invoke(this, e);

        private void ModulesGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (ModulesGrid.SelectedItem is not ModuleInfoRow row || string.IsNullOrWhiteSpace(row.Path))
                return;

            LaunchPeView(row.Path);
        }

        private void ModuleContextOpenPe_Click(object sender, RoutedEventArgs e)
        {
            if (ModulesGrid.SelectedItem is ModuleInfoRow row && !string.IsNullOrWhiteSpace(row.Path))
            {
                LaunchPeView(row.Path);
            }
        }

        private void ModuleContextCopyPath_Click(object sender, RoutedEventArgs e)
        {
            if (ModulesGrid.SelectedItem is ModuleInfoRow row && !string.IsNullOrWhiteSpace(row.Path))
            {
                Clipboard.SetText(row.Path);
            }
        }

        private void ModuleContextCopyBase_Click(object sender, RoutedEventArgs e)
        {
            if (ModulesGrid.SelectedItem is ModuleInfoRow row && !string.IsNullOrWhiteSpace(row.BaseAddress))
            {
                Clipboard.SetText(row.BaseAddress);
            }
        }

        private void Header_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (IsInteractiveElement(e.OriginalSource as DependencyObject))
                return;

            _headerMouseDown = true;
            _headerDragging = false;
            _headerMouseDownPos = e.GetPosition(this);
            CaptureMouse();
        }

        private void Header_MouseMove(object sender, MouseEventArgs e)
        {
            if (!_headerMouseDown || e.LeftButton != MouseButtonState.Pressed)
                return;

            var current = e.GetPosition(this);
            var screen = PointToScreen(current);

            if (!_headerDragging)
            {
                var dx = Math.Abs(current.X - _headerMouseDownPos.X);
                var dy = Math.Abs(current.Y - _headerMouseDownPos.Y);
                if (dx < 4 && dy < 4)
                    return;

                _headerDragging = true;
                HeaderDragStarted?.Invoke(this, new PaneHeaderDragEventArgs(screen));
            }

            HeaderDragDelta?.Invoke(this, new PaneHeaderDragEventArgs(screen));
        }

        private void Header_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            if (!_headerMouseDown)
                return;

            var screen = PointToScreen(e.GetPosition(this));
            if (_headerDragging)
                HeaderDragCompleted?.Invoke(this, new PaneHeaderDragEventArgs(screen));

            _headerMouseDown = false;
            _headerDragging = false;
            ReleaseMouseCapture();
        }

        private static bool IsInteractiveElement(DependencyObject? source)
        {
            while (source != null)
            {
                if (source is Button || source is ScrollBar || source is TextBox || source is ComboBox)
                    return true;
                source = VisualTreeHelper.GetParent(source);
            }

            return false;
        }

        private void DataGridRow_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
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

        private void ProcessDetailsLayout_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            UpdateDetailsLayout();
        }

        private void UpdateDetailsLayout()
        {
            if (ProcessDetailsLayout == null)
                return;

            bool shouldStack = ProcessDetailsLayout.ActualWidth < 920;
            if (shouldStack == _detailsStacked)
                return;

            _detailsStacked = shouldStack;

            if (!shouldStack)
            {
                ModulesColumn.Width = new GridLength(3, GridUnitType.Star);
                DetailsSplitterColumn.Width = new GridLength(2);
                MemoryColumn.Width = new GridLength(2, GridUnitType.Star);

                ProcessDetailsLayout.RowDefinitions[0].Height = new GridLength(1, GridUnitType.Star);
                ProcessDetailsLayout.RowDefinitions[1].Height = new GridLength(0);
                ProcessDetailsLayout.RowDefinitions[2].Height = new GridLength(0);

                Grid.SetRow(ModulesPanel, 0);
                Grid.SetColumn(ModulesPanel, 0);
                Grid.SetColumnSpan(ModulesPanel, 1);
                ModulesPanel.Padding = new Thickness(0);
                ModulesPanel.BorderThickness = new Thickness(0, 0, 1, 0);

                Grid.SetRow(DetailsSplitter, 0);
                Grid.SetColumn(DetailsSplitter, 1);
                Grid.SetColumnSpan(DetailsSplitter, 1);
                DetailsSplitter.Width = 2;
                DetailsSplitter.Height = double.NaN;
                DetailsSplitter.HorizontalAlignment = HorizontalAlignment.Stretch;
                DetailsSplitter.VerticalAlignment = VerticalAlignment.Stretch;
                DetailsSplitter.ResizeDirection = GridResizeDirection.Columns;
                DetailsSplitter.Style = null;

                Grid.SetRow(MemoryPanel, 0);
                Grid.SetColumn(MemoryPanel, 2);
                Grid.SetColumnSpan(MemoryPanel, 1);
                MemoryPanel.Padding = new Thickness(0);
                return;
            }

            ModulesColumn.Width = new GridLength(1, GridUnitType.Star);
            DetailsSplitterColumn.Width = new GridLength(0);
            MemoryColumn.Width = new GridLength(0);

            ProcessDetailsLayout.RowDefinitions[0].Height = new GridLength(1, GridUnitType.Star);
            ProcessDetailsLayout.RowDefinitions[1].Height = new GridLength(2);
            ProcessDetailsLayout.RowDefinitions[2].Height = new GridLength(1, GridUnitType.Star);

            Grid.SetRow(ModulesPanel, 0);
            Grid.SetColumn(ModulesPanel, 0);
            Grid.SetColumnSpan(ModulesPanel, 3);
            ModulesPanel.Padding = new Thickness(0);
            ModulesPanel.BorderThickness = new Thickness(0, 0, 0, 1);

            Grid.SetRow(DetailsSplitter, 1);
            Grid.SetColumn(DetailsSplitter, 0);
            Grid.SetColumnSpan(DetailsSplitter, 3);
            DetailsSplitter.Width = double.NaN;
            DetailsSplitter.Height = 2;
            DetailsSplitter.HorizontalAlignment = HorizontalAlignment.Stretch;
            DetailsSplitter.VerticalAlignment = VerticalAlignment.Stretch;
            DetailsSplitter.ResizeDirection = GridResizeDirection.Rows;
            DetailsSplitter.Style = null;

            Grid.SetRow(MemoryPanel, 2);
            Grid.SetColumn(MemoryPanel, 0);
            Grid.SetColumnSpan(MemoryPanel, 3);
            MemoryPanel.Padding = new Thickness(0);
        }

        private static void LaunchPeView(string modulePath)
        {
            string normalizedPath = modulePath.Trim();
            if (normalizedPath.Length == 0 || !File.Exists(normalizedPath))
                return;

            foreach (var peViewExe in EnumeratePeViewCandidates())
            {
                try
                {
                    var psi = new ProcessStartInfo { FileName = peViewExe, Arguments = $"\"{normalizedPath}\"",
                                                     UseShellExecute = true };
                    Process.Start(psi);
                    return;
                }
                catch (Win32Exception)
                {
                }
                catch (InvalidOperationException)
                {
                }
            }

            ThemedMessageBox.Show(
                Application.Current?.MainWindow,
                "Could not launch PeView. Ensure peview.exe is available in PATH or in a standard tools folder.",
                "PeView Not Found", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        private static IEnumerable<string> EnumeratePeViewCandidates()
        {
            yield return "peview.exe";
            yield return "PEview.exe";

            string baseDir = AppContext.BaseDirectory;
            yield return Path.Combine(baseDir, "peview.exe");
            yield return Path.Combine(baseDir, "tools", "peview.exe");

            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (!string.IsNullOrWhiteSpace(pf))
                yield return Path.Combine(pf, "Sysinternals", "peview.exe");

            string pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            if (!string.IsNullOrWhiteSpace(pf86))
                yield return Path.Combine(pf86, "Sysinternals", "peview.exe");
        }
    }
}
