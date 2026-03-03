using System;
using Microsoft.Win32;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.Windows.Media;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace SleepwalkerInterface
{
    public enum UiThemeMode
    {
        Auto,
        Dark,
        Light
    }

    public partial class App : Application
    {
        internal static bool IsDarkTheme { get; private set; } = true;
        internal static UiThemeMode CurrentThemeMode { get; private set; } = UiThemeMode.Auto;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            ShutdownMode = ShutdownMode.OnExplicitShutdown;

            var loading = new LoadingWindow();
            loading.SetProgress(12, "Initializing...");
            loading.Show();
            var loadingShownAtUtc = DateTime.UtcNow;

            ApplyTheme(UiThemeMode.Auto);
            OutputCapture.Initialize();

            Dispatcher.BeginInvoke(new Action(() => _ = ContinueStartupAsync(loading, loadingShownAtUtc)), DispatcherPriority.Loaded);
        }

        private async Task ContinueStartupAsync(LoadingWindow loading, DateTime loadingShownAtUtc)
        {
            loading.SetProgress(55, "Preparing workspace...");
            var main = new MainWindow
            {
                Background = Brushes.Black,
                ShowInTaskbar = false,
                Opacity = 0
            };
            MainWindow = main;
            Task firstRenderTask = WaitForFirstRenderAsync(main);
            main.Show();
            loading.SetProgress(85, "Finalizing interface...");

            const int minimumLoadingMs = 900;
            int elapsedMs = (int)(DateTime.UtcNow - loadingShownAtUtc).TotalMilliseconds;
            if (elapsedMs < minimumLoadingMs)
            {
                await Task.Delay(minimumLoadingMs - elapsedMs);
            }
            await Task.WhenAny(firstRenderTask, Task.Delay(2000));

            loading.SetProgress(100, "Ready");
            loading.Close();
            main.ShowInTaskbar = true;
            main.Opacity = 1;
            main.Activate();
            ShutdownMode = ShutdownMode.OnMainWindowClose;
        }

        private static Task WaitForFirstRenderAsync(Window window)
        {
            var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            void OnContentRendered(object? sender, EventArgs e)
            {
                window.ContentRendered -= OnContentRendered;
                tcs.TrySetResult(true);
            }

            window.ContentRendered += OnContentRendered;
            return tcs.Task;
        }

        internal static void SetThemeMode(UiThemeMode mode)
        {
            if (Current is App app)
            {
                app.ApplyTheme(mode);
            }
        }

        private void ApplyTheme(UiThemeMode mode)
        {
            CurrentThemeMode = mode;
            IsDarkTheme = mode switch
            {
                UiThemeMode.Dark => true,
                UiThemeMode.Light => false,
                _ => !IsWindowsLightThemeEnabled()
            };

            string themeSource = IsDarkTheme ? "Themes/DarkTheme.xaml" : "Themes/LightTheme.xaml";

            Resources.MergedDictionaries.Clear();
            Resources.MergedDictionaries.Add(new ResourceDictionary
            {
                Source = new Uri(themeSource, UriKind.Relative)
            });
            Resources["IsDarkTheme"] = IsDarkTheme;

            foreach (Window window in Windows)
            {
                WindowThemeHelper.ApplyTitleBarTheme(window, IsDarkTheme);
                RebindThemedControlStyles(window);
            }
        }

        private void RebindThemedControlStyles(Window window)
        {
            Style? dataGridStyle = TryFindResource("AppDataGridStyle") as Style;
            Style? dataGridRowStyle = TryFindResource("AppDataGridRowStyle") as Style;
            Style? dataGridCellStyle = TryFindResource("AppDataGridCellStyle") as Style;
            Style? dataGridHeaderStyle = TryFindResource("AppDataGridColumnHeaderStyle") as Style;
            Style? explorerListStyle = TryFindResource("ExplorerListStyle") as Style;
            Style? explorerItemStyle = TryFindResource("ExplorerItemStyle") as Style;

            foreach (var element in EnumerateVisualTree(window))
            {
                if (element is DataGrid grid)
                {
                    if (dataGridStyle != null &&
                        grid.ReadLocalValue(FrameworkElement.StyleProperty) == DependencyProperty.UnsetValue)
                    {
                        grid.Style = dataGridStyle;
                    }

                    if (dataGridRowStyle != null &&
                        grid.ReadLocalValue(DataGrid.RowStyleProperty) == DependencyProperty.UnsetValue)
                    {
                        grid.RowStyle = dataGridRowStyle;
                    }

                    if (dataGridCellStyle != null &&
                        grid.ReadLocalValue(DataGrid.CellStyleProperty) == DependencyProperty.UnsetValue)
                    {
                        grid.CellStyle = dataGridCellStyle;
                    }

                    if (dataGridHeaderStyle != null &&
                        grid.ReadLocalValue(DataGrid.ColumnHeaderStyleProperty) == DependencyProperty.UnsetValue)
                    {
                        grid.ColumnHeaderStyle = dataGridHeaderStyle;
                    }

                    continue;
                }

                if (element is ListBox list && string.Equals(list.Name, "GraphExplorer", StringComparison.Ordinal))
                {
                    if (explorerListStyle != null)
                    {
                        list.Style = explorerListStyle;
                    }

                    if (explorerItemStyle != null)
                    {
                        list.ItemContainerStyle = explorerItemStyle;
                    }

                    list.SetResourceReference(Control.BackgroundProperty, "WinPanelBrush");
                }
            }
        }

        private static IEnumerable<DependencyObject> EnumerateVisualTree(DependencyObject root)
        {
            var queue = new Queue<DependencyObject>();
            queue.Enqueue(root);
            while (queue.Count > 0)
            {
                var current = queue.Dequeue();
                yield return current;

                int count = VisualTreeHelper.GetChildrenCount(current);
                for (int i = 0; i < count; i += 1)
                {
                    queue.Enqueue(VisualTreeHelper.GetChild(current, i));
                }
            }
        }

        private static bool IsWindowsLightThemeEnabled()
        {
            try
            {
                using RegistryKey? key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
                object? value = key?.GetValue("AppsUseLightTheme");
                if (value is int i)
                {
                    return i != 0;
                }

                if (value is byte b)
                {
                    return b != 0;
                }
            }
            catch
            {
            }

            return false;
        }
    }
}
