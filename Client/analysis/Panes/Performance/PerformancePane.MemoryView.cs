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
        private void MemorySummaryToggle_Checked(object sender, RoutedEventArgs e)
        {
            _memoryTreemapEnabled = true;
            if (MemorySummaryToggle != null)
                MemorySummaryToggle.Content = "Table";
            UpdateMemorySummaryMode();
            UpdateMemoryTreemap();
            UpdateLiveDataOverlays();
        }

        private void MemorySummaryToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            _memoryTreemapEnabled = false;
            if (MemorySummaryToggle != null)
                MemorySummaryToggle.Content = "Treemap";
            UpdateMemorySummaryMode();
            UpdateLiveDataOverlays();
        }

        private void MemoryAttributionToggle_Checked(object sender, RoutedEventArgs e)
        {
            if (MemoryAttributionToggle != null)
            {
                MemoryAttributionToggle.IsChecked = false;
                MemoryAttributionToggle.Visibility = Visibility.Collapsed;
            }
        }

        private void MemoryAttributionToggle_Unchecked(object sender, RoutedEventArgs e)
        {
        }

        private void ThreadLifecycleToggle_Checked(object sender, RoutedEventArgs e)
        {
            if (ThreadsGrid != null)
                ThreadsGrid.Visibility = Visibility.Collapsed;
            if (ThreadLifecycleGrid != null)
                ThreadLifecycleGrid.Visibility = Visibility.Visible;
            UpdateLiveDataOverlays();
        }

        private void ThreadLifecycleToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            if (ThreadLifecycleGrid != null)
                ThreadLifecycleGrid.Visibility = Visibility.Collapsed;
            if (ThreadsGrid != null)
                ThreadsGrid.Visibility = Visibility.Visible;
            UpdateLiveDataOverlays();
        }

        private void UpdateMemorySummaryMode()
        {
            if (MemoryAttributionGrid == null || MemoryGrid == null || MemoryTreemapHost == null ||
                MemorySummaryToggle == null)
            {
                return;
            }

            MemoryAttributionGrid.Visibility = Visibility.Collapsed;
            MemorySummaryToggle.IsEnabled = true;
            MemoryGrid.Visibility = Visibility.Collapsed;
            MemoryTreemapHost.Visibility = Visibility.Collapsed;
            MemorySummaryToggle.IsEnabled = false;
            MemorySummaryToggle.Visibility = Visibility.Collapsed;
            if (MemoryPanel != null)
                MemoryPanel.Visibility = Visibility.Collapsed;
            if (MemoryColumn != null)
                MemoryColumn.Width = new GridLength(0);
            if (DetailsSplitterColumn != null)
                DetailsSplitterColumn.Width = new GridLength(0);
            if (DetailsSplitter != null)
                DetailsSplitter.Visibility = Visibility.Collapsed;
            if (MemoryAttributionToggle != null)
                MemoryAttributionToggle.Visibility = Visibility.Collapsed;
        }

        private void OpenThreadStackFromMemoryRow(MemoryAttributionRow row)
        {
            if (row.ThreadTid == 0)
            {
                return;
            }

            ThreadUsageRow? existing = TopThreads.FirstOrDefault(x => x.Tid == unchecked((int)row.ThreadTid));
            if (existing != null)
            {
                ThreadDoubleClicked?.Invoke(this, existing);
                return;
            }

            ThreadDoubleClicked?.Invoke(
                this, new ThreadUsageRow(
                          new ThreadUsageSample {
                              Tid = unchecked((int)row.ThreadTid), CpuMsDelta = 0,
                              State = _targetSuspended ? "Suspended" : "Observed",
                              WaitReason = _targetSuspended ? "Suspended" : string.Empty,
                              Kind = row.HighlightLabel.Equals("EXEC?", StringComparison.OrdinalIgnoreCase)
                                         ? "Memory Execution"
                                     : row.HighlightBand.Equals("ThreadStack", StringComparison.OrdinalIgnoreCase)
                                         ? "Thread Stack"
                                         : "TEB",
                              StartTimeUtc = null, TargetSuspended = _targetSuspended
                          },
                          _targetSuspended));
        }

        private void UpdateMemoryTreemap()
        {
            if (!_memoryTreemapEnabled)
                return;
            if (MemoryTreemapCanvas == null || MemoryTreemapNoData == null)
                return;

            double width = MemoryTreemapCanvas.ActualWidth;
            double height = MemoryTreemapCanvas.ActualHeight;
            if (width < 24 || height < 24)
                return;

            MemoryTreemapCanvas.Children.Clear();

            var entries = MemoryMetrics.Where(x => x.BytesValue.HasValue && x.BytesValue.Value > 0)
                              .OrderByDescending(x => x.BytesValue!.Value)
                              .Select(x => new MemoryTreemapEntry(x.Metric, x.Value, x.BytesValue!.Value))
                              .ToList();

            if (entries.Count == 0)
            {
                MemoryTreemapNoData.Visibility =
                    MemoryNoDataOverlay?.Visibility == Visibility.Visible ? Visibility.Collapsed : Visibility.Visible;
                return;
            }

            MemoryTreemapNoData.Visibility = Visibility.Collapsed;

            var plot = new Rect(0, 0, width, height);
            var layout = new List<(MemoryTreemapEntry Entry, Rect Rect)>();
            LayoutTreemap(entries, plot, plot.Width >= plot.Height, layout);

            var fills = new[] {
                Color.FromRgb(0x60, 0xA5, 0xFA), Color.FromRgb(0x34, 0xD3, 0x99), Color.FromRgb(0xF5, 0x9E, 0x0B),
                Color.FromRgb(0xA7, 0x8B, 0xFA), Color.FromRgb(0xF4, 0x72, 0xB6), Color.FromRgb(0x22, 0xD3, 0xEE),
                Color.FromRgb(0xFB, 0x71, 0x71),
            };

            for (int i = 0; i < layout.Count; i += 1)
            {
                var item = layout[i];
                var r = Shrink(item.Rect, 1.5);
                if (r.Width < 1 || r.Height < 1)
                    continue;

                var fillBrush = new SolidColorBrush(fills[i % fills.Length]);
                fillBrush.Opacity = 0.55;
                var border = new Border {
                    Width = r.Width,
                    Height = r.Height,
                    BorderThickness = new Thickness(1),
                    BorderBrush = UiPalette.BorderBrush,
                    Background = fillBrush,
                    Child =
                        new TextBlock {
                            Text = (r.Width < 60 || r.Height < 26) ? "" : $"{item.Entry.Name}\n{item.Entry.Display}",
                            Margin = new Thickness(5, 4, 5, 4), TextTrimming = TextTrimming.CharacterEllipsis,
                            TextWrapping = TextWrapping.Wrap, Foreground = UiPalette.TextBrush,
                            FontSize = r.Width < 120 || r.Height < 48 ? 10 : 11, FontWeight = FontWeights.SemiBold
                        }
                };

                Canvas.SetLeft(border, r.Left);
                Canvas.SetTop(border, r.Top);
                MemoryTreemapCanvas.Children.Add(border);
            }
        }

        private static Rect Shrink(Rect r, double amount)
        {
            if (amount <= 0)
                return r;

            double x = r.X + amount;
            double y = r.Y + amount;
            double w = Math.Max(0, r.Width - (amount * 2));
            double h = Math.Max(0, r.Height - (amount * 2));
            return new Rect(x, y, w, h);
        }

        private static void LayoutTreemap(List<MemoryTreemapEntry> entries, Rect area, bool splitHorizontal,
                                          List<(MemoryTreemapEntry Entry, Rect Rect)> output)
        {
            if (entries.Count == 0 || area.Width <= 0 || area.Height <= 0)
                return;

            if (entries.Count == 1)
            {
                output.Add((entries[0], area));
                return;
            }

            long total = entries.Sum(x => x.Bytes);
            if (total <= 0)
            {
                for (int i = 0; i < entries.Count; i += 1)
                {
                    output.Add((entries[i], area));
                }
                return;
            }

            long target = total / 2;
            long running = 0;
            int splitIndex = 0;
            while (splitIndex < entries.Count - 1 && running + entries[splitIndex].Bytes <= target)
            {
                running += entries[splitIndex].Bytes;
                splitIndex += 1;
            }

            if (splitIndex <= 0)
            {
                splitIndex = 1;
                running = entries[0].Bytes;
            }

            var a = entries.Take(splitIndex).ToList();
            var b = entries.Skip(splitIndex).ToList();
            double ratio = Math.Clamp(running / (double)total, 0.05, 0.95);

            if (splitHorizontal)
            {
                double widthA = area.Width * ratio;
                var rectA = new Rect(area.X, area.Y, widthA, area.Height);
                var rectB = new Rect(area.X + widthA, area.Y, area.Width - widthA, area.Height);
                LayoutTreemap(a, rectA, false, output);
                LayoutTreemap(b, rectB, false, output);
            }
            else
            {
                double heightA = area.Height * ratio;
                var rectA = new Rect(area.X, area.Y, area.Width, heightA);
                var rectB = new Rect(area.X, area.Y + heightA, area.Width, area.Height - heightA);
                LayoutTreemap(a, rectA, true, output);
                LayoutTreemap(b, rectB, true, output);
            }
        }

        private sealed class MemoryTreemapEntry
        {
            public MemoryTreemapEntry(string name, string display, long bytes)
            {
                Name = name;
                Display = display;
                Bytes = bytes;
            }

            public string Name { get; }
            public string Display { get; }
            public long Bytes { get; }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public nint BaseAddress;
            public nint AllocationBase;
            public uint AllocationProtect;
            public ushort PartitionId;
            public nuint RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }
    }
}
