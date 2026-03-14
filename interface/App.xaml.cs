using System;
using Microsoft.Win32;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.Windows.Media;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace BlackbirdInterface
{
    public enum UiThemeMode
    {
        Auto,
        Dark,
        Light
    }

    public partial class App : Application
    {
        private const string GettingStartedUrl = "https://github.com/8damon/Blackbird-Platform/blob/stable/Getting%20Started.md";
        internal static bool IsDarkTheme { get; private set; } = true;
        internal static UiThemeMode CurrentThemeMode { get; private set; } = UiThemeMode.Dark;
        internal static event Action<bool>? ThemeChanged;

        private sealed class StartupIntent
        {
            public bool StartLaunchFlow { get; init; }
            public string? SessionPath { get; init; }
        }

        protected override void OnStartup(StartupEventArgs e)
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;

            base.OnStartup(e);
            ApplyTheme(UiThemeMode.Dark);
            ContinueStartupSafe();
        }

        private async void ContinueStartupSafe()
        {
            try
            {
                await ContinueStartupAsync();
            }
            catch (Exception ex)
            {
                HandleStartupFailure(ex);
            }
        }

        private async Task ContinueStartupAsync()
        {
            StartupIntent? intent = ResolveStartupIntent();
            if (intent == null)
            {
                Shutdown();
                return;
            }

            await ShowVirtualizationPreflightAsync();
            if (!await EnsureStartupSystemsReadyAsync())
            {
                Shutdown();
                return;
            }
            EnsureStartMenuShortcut();

            var loading = new LoadingWindow();
            loading.SetProgress(8, "Initializing startup...", "Preparing main interface.");
            loading.Show();
            var loadingShownAtUtc = DateTime.UtcNow;

            loading.SetProgress(18, "Applying theme resources...", "Active theme resolved.");
            await YieldForUiFrameAsync();

            loading.SetProgress(35, "Initializing diagnostics...", "Starting output capture and runtime logging.");
            try
            {
                OutputCapture.Initialize();
            }
            catch (Exception ex)
            {
                loading.SetProgress(40, "Diagnostics degraded", "Continuing startup without output capture.");
                Debug.WriteLine($"OutputCapture.Initialize failed: {ex}");
            }
            await YieldForUiFrameAsync();

            loading.SetProgress(58, "Building interface resources...", "Constructing the main window and control tree.");
            var main = new MainWindow
            {
                ShowInTaskbar = false,
                Opacity = 0
            };
            main.WindowStartupLocation = WindowStartupLocation.Manual;
            main.WindowState = WindowState.Normal;
            main.Left = -32000;
            main.Top = -32000;
            await YieldForUiFrameAsync();

            loading.SetProgress(76, "Preparing final shell...", "Pre-rendering main window offscreen.");
            MainWindow = main;
            Task firstRenderTask = WaitForFirstRenderAsync(main);
            main.Show();
            await Task.WhenAny(firstRenderTask, Task.Delay(2500));
            await YieldForUiFrameAsync();

            loading.SetProgress(90, "Preparing final shell...", "Synchronizing final visual state.");

            const int minimumLoadingMs = 1150;
            int elapsedMs = (int)(DateTime.UtcNow - loadingShownAtUtc).TotalMilliseconds;
            if (elapsedMs < minimumLoadingMs)
            {
                await Task.Delay(minimumLoadingMs - elapsedMs);
            }

            loading.SetProgress(100, "Launching interface...", "Startup complete. Opening main window.");
            main.Left = 0;
            main.Top = 0;
            main.WindowState = WindowState.Maximized;
            main.ShowInTaskbar = true;
            main.Opacity = 1;
            main.Activate();
            await YieldForUiFrameAsync();
            loading.Close();

            if (intent.StartLaunchFlow)
            {
                await main.BeginStartupLaunchFlowAsync();
            }
            else if (!string.IsNullOrWhiteSpace(intent.SessionPath))
            {
                if (!main.TryOpenSessionFromStartupPath(intent.SessionPath, out string openError))
                {
                    ThemedMessageBox.Show(
                        main,
                        $"Failed to open session.\n\n{openError}",
                        "Open Session",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }
            }

            ShutdownMode = ShutdownMode.OnMainWindowClose;
        }

        private static async Task ShowVirtualizationPreflightAsync()
        {
            VirtualizationProbeReport report = await Task.Run(VirtualizationProbe.Run);
            MessageBoxImage icon = report.VmLikely ? MessageBoxImage.Information : MessageBoxImage.Warning;
            ThemedMessageBox.Show(
                Current?.MainWindow,
                report.BuildOperatorMessage(),
                "Environment Preflight",
                MessageBoxButton.OK,
                icon);
        }

        private static async Task<bool> EnsureStartupSystemsReadyAsync()
        {
            for (;;)
            {
                BlackbirdPreflightReport report = await Task.Run(() => BlackbirdPreflight.Run(0, ensureServicesRunning: true));
                if (report.StartupReady)
                {
                    return true;
                }

                MessageBoxResult choice = ThemedMessageBox.Show(
                    Current?.MainWindow,
                    report.BuildStartupFailureMessage() + "\nRetry startup preflight?",
                    "Startup System Preflight",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Error);
                if (choice != MessageBoxResult.Yes)
                {
                    return false;
                }
            }
        }

        private static void HandleStartupFailure(Exception ex)
        {
            Exception root = ex;
            while (root.InnerException != null)
            {
                root = root.InnerException;
            }

            string message =
                $"Startup failed.\n\n" +
                $"Top: {ex.GetType().Name}: {ex.Message}\n\n" +
                $"Root: {root.GetType().Name}: {root.Message}\n\n" +
                $"Top Stack:\n{ex.StackTrace}\n\n" +
                $"Root Stack:\n{root.StackTrace}";
            try
            {
                ThemedMessageBox.Show(
                    Current?.MainWindow,
                    message,
                    "Blackbird Startup Failure",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            catch
            {
            }

            if (Current != null)
            {
                Current.Shutdown();
            }
        }

        private StartupIntent? ResolveStartupIntent()
        {
            while (true)
            {
                var welcome = new StartupWelcomeWindow
                {
                    WindowStartupLocation = WindowStartupLocation.CenterScreen
                };
                // Keep first-launch UX discoverable even with borderless custom chrome.
                welcome.ShowInTaskbar = true;
                welcome.Topmost = true;
                welcome.Activate();
                welcome.Topmost = false;

                bool? result = welcome.ShowDialog();
                if (result != true)
                {
                    return null;
                }

                switch (welcome.SelectedAction)
                {
                case StartupWelcomeAction.Launch:
                    return new StartupIntent { StartLaunchFlow = true };
                case StartupWelcomeAction.OpenFile:
                {
                    string? sessionPath = PromptForSessionFile();
                    if (!string.IsNullOrWhiteSpace(sessionPath))
                    {
                        return new StartupIntent { SessionPath = sessionPath };
                    }
                    break;
                }
                case StartupWelcomeAction.GettingStarted:
                    OpenGettingStartedLink(welcome);
                    break;
                }
            }
        }

        private static void OpenGettingStartedLink(Window owner)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = GettingStartedUrl,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                ThemedMessageBox.Show(
                    owner,
                    $"Failed to open Getting Started.\n\n{ex.Message}\n\nURL: {GettingStartedUrl}",
                    "Getting Started",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private static string? PromptForSessionFile()
        {
            var dialog = new OpenFileDialog
            {
                Filter = "Blackbird Session Archive (*.swlkr;*.blackbird)|*.swlkr;*.blackbird|All files (*.*)|*.*",
                CheckFileExists = true,
                Multiselect = false
            };

            return dialog.ShowDialog() == true ? dialog.FileName : null;
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

        private static async Task YieldForUiFrameAsync()
        {
            await Application.Current.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.Render);
        }

        private static void EnsureStartMenuShortcut()
        {
            try
            {
                string? exePath = ResolveCurrentExecutablePath();
                if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
                {
                    return;
                }

                string programsDirectory = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
                    "Programs");
                Directory.CreateDirectory(programsDirectory);

                string shortcutPath = Path.Combine(programsDirectory, "Blackbird.lnk");

                Type? shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType == null)
                {
                    return;
                }

                object? shell = null;
                object? shortcut = null;
                try
                {
                    shell = Activator.CreateInstance(shellType);
                    if (shell == null)
                    {
                        return;
                    }

                    shortcut = shellType.InvokeMember(
                        "CreateShortcut",
                        BindingFlags.InvokeMethod,
                        binder: null,
                        target: shell,
                        args: new object[] { shortcutPath });
                    if (shortcut == null)
                    {
                        return;
                    }

                    Type shortcutType = shortcut.GetType();
                    shortcutType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, shortcut, new object[] { exePath });
                    shortcutType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, shortcut, new object[] { Path.GetDirectoryName(exePath) ?? string.Empty });
                    shortcutType.InvokeMember("Description", BindingFlags.SetProperty, null, shortcut, new object[] { "Blackbird analyst shell" });
                    shortcutType.InvokeMember("IconLocation", BindingFlags.SetProperty, null, shortcut, new object[] { $"{exePath},0" });
                    shortcutType.InvokeMember("Save", BindingFlags.InvokeMethod, null, shortcut, Array.Empty<object>());
                }
                finally
                {
                    if (shortcut != null)
                    {
                        Marshal.FinalReleaseComObject(shortcut);
                    }
                    if (shell != null)
                    {
                        Marshal.FinalReleaseComObject(shell);
                    }
                }
            }
            catch
            {
            }
        }

        private static string? ResolveCurrentExecutablePath()
        {
            string? processPath = Environment.ProcessPath;
            if (!string.IsNullOrWhiteSpace(processPath) &&
                string.Equals(Path.GetExtension(processPath), ".exe", StringComparison.OrdinalIgnoreCase))
            {
                return processPath;
            }

            using Process current = Process.GetCurrentProcess();
            string? mainModulePath = current.MainModule?.FileName;
            if (!string.IsNullOrWhiteSpace(mainModulePath) &&
                string.Equals(Path.GetExtension(mainModulePath), ".exe", StringComparison.OrdinalIgnoreCase))
            {
                return mainModulePath;
            }

            string? entryAssemblyPath = Assembly.GetEntryAssembly()?.Location;
            if (!string.IsNullOrWhiteSpace(entryAssemblyPath) &&
                string.Equals(Path.GetExtension(entryAssemblyPath), ".exe", StringComparison.OrdinalIgnoreCase))
            {
                return entryAssemblyPath;
            }

            return null;
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
            bool effectiveDark = ResolveEffectiveDarkMode(mode);
            string themeSource = effectiveDark ? "Themes/DarkTheme.xaml" : "Themes/LightTheme.xaml";

            Resources.MergedDictionaries.Clear();
            try
            {
                Resources.MergedDictionaries.Add(new ResourceDictionary
                {
                    Source = new Uri(themeSource, UriKind.Relative)
                });
            }
            catch
            {
                // Safe fallback while a light theme dictionary is not available.
                effectiveDark = true;
                Resources.MergedDictionaries.Clear();
                Resources.MergedDictionaries.Add(new ResourceDictionary
                {
                    Source = new Uri("Themes/DarkTheme.xaml", UriKind.Relative)
                });
            }

            IsDarkTheme = effectiveDark;
            Resources["IsDarkTheme"] = IsDarkTheme;

            foreach (Window window in Windows)
            {
                WindowThemeHelper.ApplyTitleBarTheme(window, IsDarkTheme);
                RebindThemedControlStyles(window);
            }

            ThemeChanged?.Invoke(IsDarkTheme);
        }

        private static bool ResolveEffectiveDarkMode(UiThemeMode mode)
        {
            switch (mode)
            {
            case UiThemeMode.Dark:
                return true;
            case UiThemeMode.Light:
                return false;
            case UiThemeMode.Auto:
            default:
                return !IsWindowsAppsLightThemeEnabled();
            }
        }

        private static bool IsWindowsAppsLightThemeEnabled()
        {
            try
            {
                using RegistryKey? key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
                object? raw = key?.GetValue("AppsUseLightTheme");
                if (raw is int intValue)
                {
                    return intValue != 0;
                }

                if (raw is long longValue)
                {
                    return longValue != 0;
                }
            }
            catch
            {
            }

            // Keep existing behavior when system preference cannot be read.
            return false;
        }

        private void RebindThemedControlStyles(Window window)
        {
            foreach (var element in EnumerateVisualTree(window))
            {
                if (element is DataGrid grid)
                {
                    if (grid.ReadLocalValue(FrameworkElement.StyleProperty) == DependencyProperty.UnsetValue)
                    {
                        grid.SetResourceReference(FrameworkElement.StyleProperty, "AppDataGridStyle");
                    }

                    if (grid.ReadLocalValue(DataGrid.RowStyleProperty) == DependencyProperty.UnsetValue)
                    {
                        grid.SetResourceReference(DataGrid.RowStyleProperty, "AppDataGridRowStyle");
                    }

                    if (grid.ReadLocalValue(DataGrid.CellStyleProperty) == DependencyProperty.UnsetValue)
                    {
                        grid.SetResourceReference(DataGrid.CellStyleProperty, "AppDataGridCellStyle");
                    }

                    if (grid.ReadLocalValue(DataGrid.ColumnHeaderStyleProperty) == DependencyProperty.UnsetValue)
                    {
                        grid.SetResourceReference(DataGrid.ColumnHeaderStyleProperty, "AppDataGridColumnHeaderStyle");
                    }

                    continue;
                }

                if (element is ListBox list && string.Equals(list.Name, "GraphExplorer", StringComparison.Ordinal))
                {
                    list.SetResourceReference(FrameworkElement.StyleProperty, "ExplorerListStyle");
                    list.SetResourceReference(ItemsControl.ItemContainerStyleProperty, "ExplorerItemStyle");
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

    }
}
