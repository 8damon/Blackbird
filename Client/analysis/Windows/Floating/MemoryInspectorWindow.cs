using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace BlackbirdInterface
{
    public sealed class MemoryInspectorWindow : Window
    {
        public MemoryInspectorWindow(ObservableCollection<MemoryInspectorRow> rows, int pid)
        {
            Title = BuildTitle(pid);
            Width = 1420;
            Height = 760;
            MinWidth = 1120;
            MinHeight = 440;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            SetResourceReference(BackgroundProperty, "WinBgBrush");

            var grid = new DataGrid
            {
                AutoGenerateColumns = false,
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
                CellStyle = BuildCellStyle()
            };

            grid.SetResourceReference(Control.BackgroundProperty, "WinPanelBrush");
            grid.SetResourceReference(Control.ForegroundProperty, "WinTextBrush");
            grid.SetResourceReference(Control.BorderBrushProperty, "WinBorderBrush");

            grid.Columns.Add(new DataGridTextColumn { Header = "Base", Binding = new System.Windows.Data.Binding("BaseAddress"), Width = 132 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Size", Binding = new System.Windows.Data.Binding("Size"), Width = 92 });
            grid.Columns.Add(new DataGridTextColumn { Header = "State", Binding = new System.Windows.Data.Binding("State"), Width = 82 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Type", Binding = new System.Windows.Data.Binding("Type"), Width = 82 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Protect", Binding = new System.Windows.Data.Binding("Protect"), Width = 170 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Class", Binding = new System.Windows.Data.Binding("Category"), Width = 140 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Allocator", Binding = new System.Windows.Data.Binding("Allocator"), Width = 210 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Source", Binding = new System.Windows.Data.Binding("Source"), Width = 130 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Trust", Binding = new System.Windows.Data.Binding("Trust"), Width = 92 });

            Content = new Border
            {
                BorderThickness = new Thickness(1),
                Child = grid
            };
            ((Border)Content).SetResourceReference(Border.BorderBrushProperty, "WinBorderBrush");

            WindowThemeHelper.ApplyDarkTitleBar(this);
        }

        public void SetTargetPid(int pid)
        {
            Title = BuildTitle(pid);
        }

        private static string BuildTitle(int pid)
            => pid > 0 ? $"Memory Allocator Inspector (PID {pid})" : "Memory Allocator Inspector";

        private static Style BuildRowStyle()
        {
            Style style = new(typeof(DataGridRow));
            style.Setters.Add(new Setter(Control.BackgroundProperty, ResolveBrush("WinPanelBrush", "#171717")));
            style.Setters.Add(new Setter(Control.ForegroundProperty, ResolveBrush("WinTextBrush", "#F2F2F2")));
            style.Setters.Add(new Setter(Control.FontWeightProperty, FontWeights.Normal));

            style.Triggers.Add(BuildPriorityTrigger("PrivateUnsigned", "#3F2418", "#FFD9B8", FontWeights.SemiBold));
            style.Triggers.Add(BuildPriorityTrigger("PrivateExecutable", "#341A1A", "#FFC7C7", FontWeights.SemiBold));
            style.Triggers.Add(BuildPriorityTrigger("Private", "#1D2438", "#C9D8FF", FontWeights.Normal));
            style.Triggers.Add(BuildPriorityTrigger("Unsigned", "#322715", "#FFE1A8", FontWeights.Normal));
            style.Triggers.Add(BuildPriorityTrigger("Image", "#25311B", "#D3F2B0", FontWeights.Normal));
            style.Triggers.Add(BuildPriorityTrigger("Mapped", "#241E35", "#D4C8FF", FontWeights.Normal));
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

        private static DataTrigger BuildPriorityTrigger(string priorityBand, string backgroundHex, string foregroundHex, FontWeight weight)
        {
            DataTrigger trigger = new()
            {
                Binding = new System.Windows.Data.Binding("PriorityBand"),
                Value = priorityBand
            };
            trigger.Setters.Add(new Setter(Control.BackgroundProperty, ResolveBrush(string.Empty, backgroundHex)));
            trigger.Setters.Add(new Setter(Control.ForegroundProperty, ResolveBrush(string.Empty, foregroundHex)));
            trigger.Setters.Add(new Setter(Control.FontWeightProperty, weight));
            return trigger;
        }

        private static Brush ResolveBrush(string resourceKey, string fallbackHex)
        {
            if (!string.IsNullOrWhiteSpace(resourceKey) &&
                Application.Current?.TryFindResource(resourceKey) is Brush brush)
            {
                return brush;
            }

            return (Brush)new BrushConverter().ConvertFromString(fallbackHex)!;
        }
    }
}
