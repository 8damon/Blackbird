using System;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace BlackbirdInterface
{
    public sealed class MemoryInspectorWindow : Window
    {
        private readonly Action<MemoryInspectorRow>? _rowActivated;
        private readonly Action<MemoryInspectorRow>? _rowDisassembly;
        private readonly int _pid;

        public MemoryInspectorWindow(ObservableCollection<MemoryInspectorRow> rows, int pid,
                                     Action<MemoryInspectorRow>? rowActivated = null,
                                     Action<MemoryInspectorRow>? rowDisassembly = null)
        {
            _rowActivated = rowActivated;
            _rowDisassembly = rowDisassembly;
            _pid = pid;
            Title = BuildTitle(pid);
            Width = 1760;
            Height = 760;
            MinWidth = 1320;
            MinHeight = 440;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            SetResourceReference(BackgroundProperty, "WinBgBrush");

            var grid = new DataGrid { AutoGenerateColumns = false,
                                      IsReadOnly = true,
                                      BorderThickness = new Thickness(0),
                                      GridLinesVisibility = DataGridGridLinesVisibility.None,
                                      HorizontalGridLinesBrush = Brushes.Transparent,
                                      VerticalGridLinesBrush = Brushes.Transparent,
                                      CanUserResizeRows = false,
                                      ColumnHeaderHeight = 24,
                                      RowHeight = 22,
                                      HeadersVisibility = DataGridHeadersVisibility.Column,
                                      ItemsSource = rows,
                                      EnableRowVirtualization = true,
                                      EnableColumnVirtualization = true,
                                      RowStyle = BuildRowStyle(),
                                      CellStyle = BuildCellStyle() };
            grid.MouseDoubleClick += Grid_MouseDoubleClick;

            grid.SetResourceReference(Control.BackgroundProperty, "WinPanelBrush");
            grid.SetResourceReference(Control.ForegroundProperty, "WinTextBrush");
            grid.SetResourceReference(Control.BorderBrushProperty, "WinBorderBrush");

            grid.Columns.Add(new DataGridTextColumn { Header = "Tag",
                                                      Binding = new System.Windows.Data.Binding("HighlightLabel"),
                                                      Width = 74, CellStyle = BuildTagCellStyle() });
            grid.Columns.Add(new DataGridTextColumn { Header = "Base",
                                                      Binding = new System.Windows.Data.Binding("BaseAddress"),
                                                      Width = 132 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Size",
                                                      Binding = new System.Windows.Data.Binding("Size"), Width = 92 });
            grid.Columns.Add(new DataGridTextColumn { Header = "State",
                                                      Binding = new System.Windows.Data.Binding("State"), Width = 82 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Type",
                                                      Binding = new System.Windows.Data.Binding("Type"), Width = 82 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Protect",
                                                      Binding = new System.Windows.Data.Binding("Protect"),
                                                      Width = 170 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Class",
                                                      Binding = new System.Windows.Data.Binding("Category"),
                                                      Width = 180 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Allocator / Thread",
                                                      Binding = new System.Windows.Data.Binding("Allocator"),
                                                      Width = 240 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Source",
                                                      Binding = new System.Windows.Data.Binding("Source"),
                                                      Width = 130 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Context",
                                                      Binding = new System.Windows.Data.Binding("Context"),
                                                      Width = 190 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Lifecycle",
                                                      Binding = new System.Windows.Data.Binding("Lifecycle"),
                                                      Width = 190 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Trust",
                                                      Binding = new System.Windows.Data.Binding("Trust"), Width = 92 });

            Content = new Border { BorderThickness = new Thickness(1), Child = grid };
            ((Border)Content).SetResourceReference(Border.BorderBrushProperty, "WinBorderBrush");

            WindowThemeHelper.WireThemeAwareTitleBar(this);
        }

        private void Grid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if ((sender as DataGrid)?.SelectedItem is not MemoryInspectorRow row)
                return;

            if (row.ThreadTid != 0)
            {
                _rowActivated?.Invoke(row);
                return;
            }

            if (BkdcNative.IsAvailable && row.BaseAddressValue != 0 && row.RegionSizeBytes != 0 &&
                row.Protect.Contains('X', StringComparison.OrdinalIgnoreCase))
            {
                _rowDisassembly?.Invoke(row);
            }
        }

        public void SetTargetPid(int pid)
        {
            Title = BuildTitle(pid);
        }

        private static string BuildTitle(int pid) => pid > 0 ? $"Memory Allocator Inspector (PID {pid})"
                                                             : "Memory Allocator Inspector";

        private static Style BuildRowStyle()
        {
            Style style = new(typeof(DataGridRow));
            style.Setters.Add(new Setter(Control.BackgroundProperty, ResolveBrush("WinPanelBrush", "#171717")));
            style.Setters.Add(new Setter(Control.ForegroundProperty, ResolveBrush("WinTextBrush", "#F2F2F2")));
            style.Setters.Add(new Setter(Control.FontWeightProperty, FontWeights.Normal));

            style.Triggers.Add(BuildPriorityTrigger("PrivateUnsigned", "MemoryPrivateUnsignedBackgroundBrush",
                                                    "MemoryPrivateUnsignedForegroundBrush", FontWeights.SemiBold));
            style.Triggers.Add(BuildPriorityTrigger("PrivateExecutable", "MemoryPrivateExecutableBackgroundBrush",
                                                    "MemoryPrivateExecutableForegroundBrush", FontWeights.SemiBold));
            style.Triggers.Add(BuildPriorityTrigger("Private", "MemoryPrivateBackgroundBrush",
                                                    "MemoryPrivateForegroundBrush", FontWeights.Normal));
            style.Triggers.Add(BuildPriorityTrigger("Unsigned", "MemoryUnsignedBackgroundBrush",
                                                    "MemoryUnsignedForegroundBrush", FontWeights.Normal));
            style.Triggers.Add(BuildPriorityTrigger("Image", "MemoryImageBackgroundBrush", "MemoryImageForegroundBrush",
                                                    FontWeights.Normal));
            style.Triggers.Add(BuildPriorityTrigger("Mapped", "MemoryMappedBackgroundBrush",
                                                    "MemoryMappedForegroundBrush", FontWeights.Normal));
            style.Triggers.Add(BuildHighlightTrigger("ThreadStack", "MemoryThreadStackBackgroundBrush",
                                                     "MemoryThreadStackForegroundBrush", FontWeights.SemiBold));
            style.Triggers.Add(BuildHighlightTrigger("Heap", "MemoryHeapBackgroundBrush", "MemoryHeapForegroundBrush",
                                                     FontWeights.SemiBold));
            style.Triggers.Add(BuildHighlightTrigger("Anchor", "MemoryAnchorBackgroundBrush",
                                                     "MemoryAnchorForegroundBrush", FontWeights.Normal));
            style.Triggers.Add(BuildHighlightTrigger("Runtime", "MemoryRuntimeBackgroundBrush",
                                                     "MemoryRuntimeForegroundBrush", FontWeights.Normal));
            return style;
        }

        private static Style BuildCellStyle()
        {
            Style style = new(typeof(DataGridCell));
            style.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.Transparent));
            style.Setters.Add(new Setter(Control.BorderBrushProperty, Brushes.Transparent));
            style.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0)));
            style.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(6, 0, 6, 0)));
            style.Setters.Add(new Setter(Control.FocusVisualStyleProperty, null));
            return style;
        }

        private static Style BuildTagCellStyle()
        {
            Style style = BuildCellStyle();
            style.Setters.Add(new Setter(Control.BorderBrushProperty, ResolveBrush("WinSubtleBorderBrush", "#303030")));
            style.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0, 0, 1, 0)));
            return style;
        }

        private static DataTrigger BuildPriorityTrigger(string priorityBand, string backgroundResourceKey,
                                                        string foregroundResourceKey, FontWeight weight)
        {
            DataTrigger trigger =
                new() { Binding = new System.Windows.Data.Binding("PriorityBand"), Value = priorityBand };
            trigger.Setters.Add(
                new Setter(Control.BackgroundProperty, ResolveBrush(backgroundResourceKey, "#FFF0F0F0")));
            trigger.Setters.Add(
                new Setter(Control.ForegroundProperty, ResolveBrush(foregroundResourceKey, "#FF202020")));
            trigger.Setters.Add(new Setter(Control.FontWeightProperty, weight));
            return trigger;
        }

        private static DataTrigger BuildHighlightTrigger(string highlightBand, string backgroundResourceKey,
                                                         string foregroundResourceKey, FontWeight weight)
        {
            DataTrigger trigger =
                new() { Binding = new System.Windows.Data.Binding("HighlightBand"), Value = highlightBand };
            trigger.Setters.Add(
                new Setter(Control.BackgroundProperty, ResolveBrush(backgroundResourceKey, "#FFF0F0F0")));
            trigger.Setters.Add(
                new Setter(Control.ForegroundProperty, ResolveBrush(foregroundResourceKey, "#FF202020")));
            trigger.Setters.Add(new Setter(Control.FontWeightProperty, weight));
            return trigger;
        }

        private static Brush ResolveBrush(string resourceKey, string fallbackHex)
        {
            if (!string.IsNullOrWhiteSpace(resourceKey) && Application.Current?.TryFindResource(resourceKey)
                                                               is Brush brush)
            {
                return brush;
            }

            return (Brush) new BrushConverter().ConvertFromString(fallbackHex)!;
        }
    }
}
