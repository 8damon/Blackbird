using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Input;

namespace SleepwalkerInterface
{
    public partial class MainWindow : Window
    {
        private readonly List<TelemetryEvent> _allEvents = new();
        private readonly ObservableCollection<TelemetryEvent> _focusedEvents = new();
        private const int MaxTimelineEvents = 50000;
        private const int TimelineTrimBatch = 512;
        private bool _viewportRefreshPending;
        private DateTime _latestEventTimestampUtc;

        private DateTime _captureStartUtc;
        private EventsFloatWindow? _eventsFloatWindow;
        private PerformanceFloatWindow? _performanceFloatWindow;
        private EtwFloatWindow? _etwFloatWindow;
        private HeuristicsFloatWindow? _heuristicsFloatWindow;
        private bool _eventsPaneVisible = true;
        private bool _performancePaneVisible = true;
        private bool _eventsPaneFloating;
        private bool _performancePaneFloating;
        private bool _etwPaneFloating;
        private bool _heuristicsPaneFloating;
        private bool _heuristicsOnTop;

        // Lane focus key (optional)
        private string? _laneFocusKey;

        // Performance sampler (system-wide for now, PID-aware if provided)
        private PerformanceSampler? _perf;

        // Explorer items
        private readonly ObservableCollection<GraphExplorerItem> _explorer = new();
        private readonly ObservableCollection<ProcessSessionTab> _processTabs = new();
        private readonly int _defaultPid = Process.GetCurrentProcess().Id;
        private bool _suppressTabSelectionChange;
        private ProcessSessionTab? _currentSession;
        private int _samplerPid;
        private bool _performanceOnTop;
        private bool _hasPerformanceData;
        private bool _hasIpcUplinkData;
        private bool _connectivityHealthy = true;
        private bool _themeSelectorReady;
        private bool _draggingEventsPaneHeader;
        private bool _draggingPerformancePaneHeader;
        private bool _openingProcessPicker;
        private Process? _targetExitWatchProcess;
        private int _targetExitWatchPid;
        private Vector _floatingPaneDragOffset;

        private const uint ProcessSynchronize = 0x00100000;
        private const uint ProcessVmRead = 0x0010;
        private const uint ProcessQueryLimitedInformation = 0x1000;

        public MainWindow()
        {
            InitializeComponent();
            SetResourceReference(BackgroundProperty, "WinBgBrush");
            RootGrid.SetResourceReference(Panel.BackgroundProperty, "WinBgBrush");
            WindowThemeHelper.ApplyDarkTitleBar(this);
            Loaded += OnLoaded;
            Closed += OnClosed;
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            PidBox.Text = _defaultPid.ToString();
            _samplerPid = _defaultPid;

            _captureStartUtc = DateTime.UtcNow;
            _latestEventTimestampUtc = _captureStartUtc;

            // Bind grid to focused items
            EventsPaneHost.Grid.ItemsSource = _focusedEvents;
            EventsPaneHost.SetHasData(false);

            // Timeline init
            EventsPaneHost.Timeline.CaptureStartUtc = _captureStartUtc;
            EventsPaneHost.Timeline.ViewDurationSeconds = 120;
            EventsPaneHost.Timeline.ViewStartSeconds = 0;

            // Timeline interactions
            EventsPaneHost.Timeline.RangeSelected += Timeline_RangeSelected;
            EventsPaneHost.Timeline.LaneInteraction += Timeline_LaneInteraction;
            EventsPaneHost.Timeline.SelectedEventChanged += Timeline_SelectedEventChanged;

            // Grid selection sync
            EventsPaneHost.Grid.SelectionChanged += Grid_SelectionChanged;

            // Scrollbar sync
            EventsPaneHost.Scroll.ValueChanged += Scroll_ValueChanged;

            // Pane header buttons
            EventsPaneHost.CloseRequested += (_, __) => HideEventsPane();
            EventsPaneHost.FloatRequested += (_, __) => ToggleFloatDock();
            EventsPaneHost.SettingsRequested += (_, __) => OpenLaneSettings();
            EventsPaneHost.HeaderDragStarted += (_, a) => BeginPaneHeaderDrag(isEventsPane: true, a.ScreenPosition);
            EventsPaneHost.HeaderDragDelta += (_, a) => ContinuePaneHeaderDrag(isEventsPane: true, a.ScreenPosition);
            EventsPaneHost.HeaderDragCompleted += (_, a) => EndPaneHeaderDrag(isEventsPane: true, a.ScreenPosition);
            PerformancePaneHost.CloseRequested += (_, __) => HidePerformancePane();
            PerformancePaneHost.ReorderRequested += (_, __) => TogglePaneOrder();
            PerformancePaneHost.FloatRequested += (_, __) => TogglePerformanceFloatDock();
            PerformancePaneHost.ThreadDoubleClicked += PerformancePaneHost_ThreadDoubleClicked;
            PerformancePaneHost.HeaderDragStarted += (_, a) => BeginPaneHeaderDrag(isEventsPane: false, a.ScreenPosition);
            PerformancePaneHost.HeaderDragDelta += (_, a) => ContinuePaneHeaderDrag(isEventsPane: false, a.ScreenPosition);
            PerformancePaneHost.HeaderDragCompleted += (_, a) => EndPaneHeaderDrag(isEventsPane: false, a.ScreenPosition);
            EtwPaneHost.ReorderRequested += (_, __) => ToggleIntelPaneOrder();
            EtwPaneHost.FloatRequested += (_, __) => ToggleEtwFloatDock();
            EtwPaneHost.CloseRequested += (_, __) => HideEtwPane();
            HeuristicsPaneHost.ReorderRequested += (_, __) => ToggleIntelPaneOrder();
            HeuristicsPaneHost.FloatRequested += (_, __) => ToggleHeuristicsFloatDock();
            HeuristicsPaneHost.CloseRequested += (_, __) => HideHeuristicsPane();
            IpcUplinkPaneHost.CloseRequested += (_, __) => HideIpcUplinkPane();

            // Explorer setup
            SetupExplorer();
            SetupProcessTabs();
            InitializeThemeSelector();
            InitializeBackendUi();
            ApplyUplinkStatusVisual(healthy: null);

            UpdateScrollBar();
            FocusViewport();

            // Performance sampler + UI sync
            _perf = new PerformanceSampler();
            _perf.SampleArrived += Perf_SampleArrived;

            // Make performance pane aware of capture start immediately
            PerformancePaneHost.SetCaptureStart(_captureStartUtc);
            PerformancePaneHost.SetPid(TryGetPid());
            SyncPerformanceViewToTimeline();
            StartLiveCaptureForPid(TryGetPid());
            _ = RunPreflightAsync(TryGetPid());
            StatusBlock.Text = $"Status: Connected to PID {TryGetPid()}";
            ApplyPaneOrder();
            ApplyIntelPaneOrder();
        }

        private void SetupProcessTabs()
        {
            ProcessTabs.ItemsSource = _processTabs;
            var initial = AddOrSelectProcessTab(_defaultPid, GetProcessTabTitle(_defaultPid), select: true);
            if (initial.CaptureStartUtc == default)
                initial.CaptureStartUtc = _captureStartUtc;
            _currentSession = initial;
        }

        private void OnClosed(object? sender, EventArgs e)
        {
            if (_perf != null)
            {
                _perf.SampleArrived -= Perf_SampleArrived;
                _perf.Stop();
                _perf = null;
            }

            if (_eventsFloatWindow != null)
            {
                _eventsFloatWindow.Closed -= EventsFloatWindow_Closed;
                _eventsFloatWindow.Close();
                _eventsFloatWindow = null;
            }
            if (_performanceFloatWindow != null)
            {
                _performanceFloatWindow.Closed -= PerformanceFloatWindow_Closed;
                _performanceFloatWindow.Close();
                _performanceFloatWindow = null;
            }
            if (_etwFloatWindow != null)
            {
                _etwFloatWindow.Closed -= EtwFloatWindow_Closed;
                _etwFloatWindow.Close();
                _etwFloatWindow = null;
            }
            if (_heuristicsFloatWindow != null)
            {
                _heuristicsFloatWindow.Closed -= HeuristicsFloatWindow_Closed;
                _heuristicsFloatWindow.Close();
                _heuristicsFloatWindow = null;
            }
            SaveIntelSessionState(_currentSession?.Pid ?? 0);
            StopTargetExitWatcher();
            StopBackendSession();
            HideDockPreview();
        }

        private void SetupExplorer()
        {
            _explorer.Clear();

            // Pane identity colors: events=blue, performance=green.
            _explorer.Add(new GraphExplorerItem("Events", new SolidColorBrush(Color.FromRgb(0x4C, 0x8F, 0xD2))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem("Performance", new SolidColorBrush(Color.FromRgb(0x58, 0xB6, 0x58))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem("Sleepwalker ETW", new SolidColorBrush(Color.FromRgb(0xD2, 0x89, 0x34))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem("ETW-TI", new SolidColorBrush(Color.FromRgb(0xB4, 0x6F, 0xE1))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem("Heuristics", new SolidColorBrush(Color.FromRgb(0xD2, 0x55, 0x55))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem("IPC Uplink", new SolidColorBrush(Color.FromRgb(0x4A, 0xC1, 0xC6)))
            {
                IsEnabled = false,
                ShowDetails = true,
                DetailPrimary = "Enable to inspect IPC internals",
                DetailSecondary = "Waiting for session diagnostics..."
            });

            GraphExplorer.ItemsSource = _explorer;

            foreach (var item in _explorer)
            {
                item.PropertyChanged += (_, args) =>
                {
                    if (string.Equals(args.PropertyName, nameof(GraphExplorerItem.IsEnabled), StringComparison.Ordinal))
                    {
                        ApplyDockVisibilityFromExplorer();
                    }
                };
            }

            RefreshExplorerDataBadges();
            ApplyDockVisibilityFromExplorer();
        }

        private GraphExplorerItem? FindExplorerItem(string name)
            => _explorer.FirstOrDefault(x => string.Equals(x.Name, name, StringComparison.OrdinalIgnoreCase));

        private void SetExplorerHasData(string name, bool hasData)
        {
            var item = FindExplorerItem(name);
            if (item != null)
                item.HasData = hasData;
        }

        private void RefreshExplorerDataBadges()
        {
            SetExplorerHasData("Events", _connectivityHealthy && _allEvents.Count > 0);
            SetExplorerHasData("Performance", _hasPerformanceData || (_currentSession?.PerformanceHistory.Count ?? 0) > 0);
            SetExplorerHasData("Sleepwalker ETW", EtwPaneHost.SleepwalkerCount > 0);
            SetExplorerHasData("ETW-TI", EtwPaneHost.TiCount > 0);
            SetExplorerHasData("Heuristics", HeuristicsPaneHost.ItemCount > 0);
            SetExplorerHasData("IPC Uplink", _hasIpcUplinkData);
        }

        private void ApplyDockVisibilityFromExplorer()
        {
            bool showEvents = _explorer.FirstOrDefault(x => x.Name == "Events")?.IsEnabled ?? true;
            bool showPerf = _explorer.FirstOrDefault(x => x.Name == "Performance")?.IsEnabled ?? true;
            bool showIpcUplink = _explorer.FirstOrDefault(x => x.Name == "IPC Uplink")?.IsEnabled ?? false;
            bool showSwEtw = _explorer.FirstOrDefault(x => x.Name == "Sleepwalker ETW")?.IsEnabled ?? true;
            bool showTiEtw = _explorer.FirstOrDefault(x => x.Name == "ETW-TI")?.IsEnabled ?? true;
            bool showEtw = showSwEtw || showTiEtw;
            bool showHeuristics = _explorer.FirstOrDefault(x => x.Name == "Heuristics")?.IsEnabled ?? true;

            if (!showEvents && _eventsFloatWindow != null)
                _eventsFloatWindow.Close();
            if (!showPerf && _performanceFloatWindow != null)
                _performanceFloatWindow.Close();
            if (!showEtw && _etwFloatWindow != null)
                _etwFloatWindow.Close();
            if (!showHeuristics && _heuristicsFloatWindow != null)
                _heuristicsFloatWindow.Close();

            bool showEventsContent = showEvents && _eventsPaneVisible && !_eventsPaneFloating;
            bool showPerformanceContent = showPerf && _performancePaneVisible && !_performancePaneFloating;
            bool showEtwContent = showEtw && !_etwPaneFloating;
            bool showHeuristicsContent = showHeuristics && !_heuristicsPaneFloating;

            EventsDockBorder.Visibility = showEventsContent ? Visibility.Visible : Visibility.Collapsed;
            PerformanceDockBorder.Visibility = showPerformanceContent ? Visibility.Visible : Visibility.Collapsed;

            CollapsedEventsBar.Visibility = (showEvents && !_eventsPaneVisible && !_eventsPaneFloating) ? Visibility.Visible : Visibility.Collapsed;
            CollapsedPerformanceBar.Visibility = (showPerf && !_performancePaneVisible && !_performancePaneFloating) ? Visibility.Visible : Visibility.Collapsed;

            DockGrid.RowDefinitions[0].Height = showEvents
                ? (_eventsPaneFloating ? new GridLength(0) : (_eventsPaneVisible ? new GridLength(4, GridUnitType.Star) : new GridLength(28)))
                : new GridLength(0);

            DockGrid.RowDefinitions[2].Height = showPerf
                ? (_performancePaneFloating ? new GridLength(0) : (_performancePaneVisible ? new GridLength(5, GridUnitType.Star) : new GridLength(28)))
                : new GridLength(0);

            DockGrid.RowDefinitions[1].Height = (showEventsContent && showPerformanceContent) ? new GridLength(2) : new GridLength(0);

            EtwDockBorder.Visibility = showEtwContent ? Visibility.Visible : Visibility.Collapsed;
            HeuristicsDockBorder.Visibility = showHeuristicsContent ? Visibility.Visible : Visibility.Collapsed;
            IpcUplinkDockBorder.Visibility = showIpcUplink ? Visibility.Visible : Visibility.Collapsed;
            IpcUplinkColumn.Width = showIpcUplink ? new GridLength(380) : new GridLength(0);
            IpcUplinkSplitterColumn.Width = showIpcUplink ? new GridLength(2) : new GridLength(0);
            IpcUplinkSplitter.Visibility = showIpcUplink ? Visibility.Visible : Visibility.Collapsed;

            bool row0Visible = (Grid.GetRow(EtwDockBorder) == 0 && showEtwContent) ||
                               (Grid.GetRow(HeuristicsDockBorder) == 0 && showHeuristicsContent);
            bool row2Visible = (Grid.GetRow(EtwDockBorder) == 2 && showEtwContent) ||
                               (Grid.GetRow(HeuristicsDockBorder) == 2 && showHeuristicsContent);
            IntelligenceDock.RowDefinitions[0].Height = row0Visible ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            IntelligenceDock.RowDefinitions[2].Height = row2Visible ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            IntelligenceDock.RowDefinitions[1].Height = (row0Visible && row2Visible) ? new GridLength(2) : new GridLength(0);

            bool showIntel = row0Visible || row2Visible;
            IntelligenceColumn.Width = showIntel ? new GridLength(430) : new GridLength(0);
            IntelligenceSplitterColumn.Width = showIntel ? new GridLength(2) : new GridLength(0);
            IntelligenceSplitter.Visibility = showIntel ? Visibility.Visible : Visibility.Collapsed;
            IntelligenceDock.Visibility = showIntel ? Visibility.Visible : Visibility.Collapsed;
            EtwPaneHost.SetSectionsVisible(showSwEtw, showTiEtw);
        }

        private void GraphExplorer_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            var element = e.OriginalSource as DependencyObject;
            if (element == null)
                return;

            var container = ItemsControl.ContainerFromElement(GraphExplorer, element) as ListBoxItem;
            if (container?.DataContext is not GraphExplorerItem item)
                return;

            item.IsEnabled = !item.IsEnabled;
            e.Handled = true;
        }

        private void Perf_SampleArrived(object? sender, PerformanceSample e)
        {
            if (_currentSession != null)
            {
                _currentSession.PerformanceHistory.Add(ClonePerformanceSample(e));
                if (_currentSession.PerformanceHistory.Count > 4000)
                    _currentSession.PerformanceHistory.RemoveRange(0, _currentSession.PerformanceHistory.Count - 4000);
            }

            // Update explorer mini previews
            // Events preview: events count in view window (cheap approximation)
            var evCount = _focusedEvents.Count;
            var eventsItem = _explorer.FirstOrDefault(x => x.Name == "Events");
            eventsItem?.PushPreviewValue(evCount);

            // Performance preview: CPU %
            var perfItem = _explorer.FirstOrDefault(x => x.Name == "Performance");
            perfItem?.PushPreviewValue(e.CpuPercent);
            _hasPerformanceData = true;
            SetExplorerHasData("Performance", true);

            // Feed performance pane
            PerformancePaneHost.PushSample(e);

            // Keep performance view aligned to timeline window
            SyncPerformanceViewToTimeline();
        }

        private void StartLiveCaptureForPid(int pid)
        {
            if (pid <= 0 || _perf == null)
                return;

            _perf.SetTargetPid(pid);
            _perf.Start();
            _samplerPid = pid;
            StartTargetExitWatcher(pid);
            StartBackendForPid(pid);
        }

        private void StartTargetExitWatcher(int pid)
        {
            StopTargetExitWatcher();
            if (pid <= 0)
                return;

            try
            {
                var process = Process.GetProcessById(pid);
                process.EnableRaisingEvents = true;
                process.Exited += TargetExitWatchProcess_Exited;
                _targetExitWatchProcess = process;
                _targetExitWatchPid = pid;
                if (process.HasExited)
                {
                    HandleTargetProcessExit(pid);
                }
            }
            catch
            {
                StopTargetExitWatcher();
            }
        }

        private void StopTargetExitWatcher()
        {
            if (_targetExitWatchProcess != null)
            {
                try
                {
                    _targetExitWatchProcess.Exited -= TargetExitWatchProcess_Exited;
                }
                catch
                {
                }

                try
                {
                    _targetExitWatchProcess.Dispose();
                }
                catch
                {
                }
            }

            _targetExitWatchProcess = null;
            _targetExitWatchPid = 0;
        }

        private void TargetExitWatchProcess_Exited(object? sender, EventArgs e)
        {
            int pid = 0;
            if (sender is Process p)
            {
                try
                {
                    pid = p.Id;
                }
                catch
                {
                    pid = 0;
                }
            }

            if (pid <= 0)
                pid = _targetExitWatchPid;

            Dispatcher.BeginInvoke(new Action(() => HandleTargetProcessExit(pid)));
        }

        private void HandleTargetProcessExit(int pid)
        {
            if (pid <= 0 || _currentSession == null || _currentSession.Pid != pid || _currentSession.TargetExited)
                return;

            _currentSession.TargetExited = true;
            MarkSessionExited(_currentSession);
            StopTargetExitWatcher();
            StopBackendSession();
            _perf?.Stop();
            _samplerPid = 0;

            AppendEvent(new TelemetryEvent
            {
                TimestampUtc = DateTime.UtcNow,
                PID = pid,
                TID = 0,
                Group = "Session",
                SubType = "ProcessExit",
                Summary = "TARGET PROCESS EXITED",
                Details = "Data capture stopped for this tab."
            });

            StatusBlock.Text = $"TARGET {pid} EXITED - DATA CAPTURE STOPPED";
            ThemedMessageBox.Show(
                this,
                $"Target process {pid} exited.\n\nData capture has been stopped for this tab.",
                "Target Exited",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }

        private static void MarkSessionExited(ProcessSessionTab tab)
        {
            const string suffix = " [EXITED]";
            if (!tab.Title.EndsWith(suffix, StringComparison.Ordinal))
            {
                tab.Title = tab.Title + suffix;
            }
        }

        private bool TryOpenTargetProcess(int pid, out string processName, out string failure, out bool accessDenied)
        {
            processName = string.Empty;
            failure = string.Empty;
            accessDenied = false;

            Process? process = null;
            try
            {
                process = Process.GetProcessById(pid);
                processName = process.ProcessName;
                if (process.HasExited)
                {
                    failure = $"TARGET PID {pid} HAS EXITED";
                    return false;
                }
            }
            catch (ArgumentException)
            {
                failure = $"PID {pid} NOT FOUND";
                return false;
            }
            catch (InvalidOperationException)
            {
                failure = $"PID {pid} IS NOT AVAILABLE";
                return false;
            }
            catch (Win32Exception ex)
            {
                accessDenied = ex.NativeErrorCode == 5;
                failure = accessDenied ? $"ACCESS DENIED TO PID {pid}" : $"FAILED TO OPEN PID {pid} (WIN32 {ex.NativeErrorCode})";
                return false;
            }
            finally
            {
                try
                {
                    process?.Dispose();
                }
                catch
                {
                }
            }

            IntPtr handle = OpenProcess(ProcessQueryLimitedInformation | ProcessVmRead | ProcessSynchronize, false, unchecked((uint)pid));
            if (handle == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                accessDenied = err == 5;
                failure = accessDenied ? $"ACCESS DENIED TO PID {pid}" : $"FAILED TO OPEN PID {pid} (WIN32 {err})";
                return false;
            }

            _ = CloseHandle(handle);
            return true;
        }

        private int TryGetPid()
        {
            if (PidBox == null) return 0;
            var s = PidBox.Text?.Trim();
            if (string.IsNullOrWhiteSpace(s))
                return _defaultPid;
            if (int.TryParse(s, out int pid) && pid > 0) return pid;
            return 0;
        }

        private string GetProcessTabTitle(int pid)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                return $"{p.ProcessName} ({pid})";
            }
            catch
            {
                return $"PID {pid}";
            }
        }

        private ProcessSessionTab AddOrSelectProcessTab(int pid, string title, bool select)
        {
            var existing = _processTabs.FirstOrDefault(t => t.Pid == pid);
            if (existing == null)
            {
                existing = new ProcessSessionTab
                {
                    Pid = pid,
                    Title = title,
                    CaptureStartUtc = DateTime.UtcNow
                };
                _processTabs.Add(existing);
            }
            else
            {
                existing.Title = title;
            }

            if (select)
            {
                _suppressTabSelectionChange = true;
                ProcessTabs.SelectedItem = existing;
                _suppressTabSelectionChange = false;
            }

            return existing;
        }

        private void SaveCurrentSessionState()
        {
            if (_currentSession == null)
                return;

            _currentSession.CaptureStartUtc = _captureStartUtc;
            _currentSession.LaneFocusKey = _laneFocusKey;
            _currentSession.ViewDurationSeconds = EventsPaneHost.Timeline.ViewDurationSeconds;
            _currentSession.ViewStartSeconds = EventsPaneHost.Timeline.ViewStartSeconds;

            _currentSession.Events.Clear();
            _currentSession.Events.AddRange(_allEvents.Select(CloneTelemetryEvent));
            SaveIntelSessionState(_currentSession.Pid);
        }

        private void RestoreSessionState(ProcessSessionTab tab)
        {
            _captureStartUtc = tab.CaptureStartUtc == default ? DateTime.UtcNow : tab.CaptureStartUtc;
            _laneFocusKey = tab.LaneFocusKey;

            _allEvents.Clear();
            _focusedEvents.Clear();
            EventsPaneHost.Timeline.Items.Clear();
            EventsPaneHost.Timeline.ClearAllLaneFilters();
            EventsPaneHost.Timeline.SelectedEvent = null;

            foreach (var ev in tab.Events.OrderBy(x => x.TimestampUtc))
            {
                var clone = CloneTelemetryEvent(ev);
                _allEvents.Add(clone);
                EventsPaneHost.Timeline.Items.Add(clone);
            }
            _latestEventTimestampUtc = _allEvents.Count > 0 ? _allEvents[^1].TimestampUtc : _captureStartUtc;

            EventsPaneHost.Timeline.CaptureStartUtc = _captureStartUtc;
            EventsPaneHost.Timeline.ViewDurationSeconds = Math.Clamp(tab.ViewDurationSeconds, 1, 120);
            EventsPaneHost.Timeline.ViewStartSeconds = Math.Max(0, tab.ViewStartSeconds);
            UpdateScrollBar();
            EventsPaneHost.Scroll.Value = Math.Min(EventsPaneHost.Scroll.Maximum, EventsPaneHost.Timeline.ViewStartSeconds);
            FocusViewport();

            PerformancePaneHost.SetCaptureStart(_captureStartUtc);
            PerformancePaneHost.SetPid(tab.Pid);
            PerformancePaneHost.LoadHistory(tab.PerformanceHistory);
            RestoreIntelSessionState(tab.Pid);
            SyncPerformanceViewToTimeline();
            _hasPerformanceData = tab.PerformanceHistory.Count > 0;
            SetExplorerHasData("Performance", tab.PerformanceHistory.Count > 0);
            EventsPaneHost.SetHasData(_allEvents.Count > 0);
            RefreshExplorerDataBadges();
        }

        private void SwitchToSession(ProcessSessionTab tab)
        {
            if (_currentSession != null && !ReferenceEquals(_currentSession, tab))
                SaveCurrentSessionState();

            _currentSession = tab;
            PidBox.Text = tab.Pid.ToString();

            RestoreSessionState(tab);

            if (tab.TargetExited)
            {
                StopTargetExitWatcher();
                StopBackendSession();
                _perf?.Stop();
                _samplerPid = 0;
                StatusBlock.Text = $"TARGET {tab.Pid} EXITED - DATA CAPTURE STOPPED";
                return;
            }

            if (!TryOpenTargetProcess(tab.Pid, out _, out var failure, out var accessDenied))
            {
                StopTargetExitWatcher();
                StopBackendSession();
                _perf?.Stop();
                _samplerPid = 0;
                if (!accessDenied)
                {
                    tab.TargetExited = true;
                    MarkSessionExited(tab);
                    StatusBlock.Text = $"TARGET {tab.Pid} EXITED - DATA CAPTURE STOPPED";
                }
                else
                {
                    StatusBlock.Text = $"ACCESS DENIED TO PID {tab.Pid} - DATA CAPTURE STOPPED";
                }
                return;
            }

            StartLiveCaptureForPid(tab.Pid);
        }

        private void SyncPerformanceViewToTimeline()
        {
            var viewStart = _captureStartUtc + TimeSpan.FromSeconds(EventsPaneHost.Timeline.ViewStartSeconds);
            var viewEnd = viewStart + TimeSpan.FromSeconds(EventsPaneHost.Timeline.ViewDurationSeconds);

            PerformancePaneHost.SetViewWindow(viewStart, viewEnd);
        }

        // -------------------------------
        // Core: Append events from your DLL pump
        // -------------------------------
        private void AppendEvent(TelemetryEvent ev)
        {
            _allEvents.Add(ev);
            EventsPaneHost.Timeline.Items.Add(ev);
            _currentSession?.Events.Add(CloneTelemetryEvent(ev));
            if (ev.TimestampUtc > _latestEventTimestampUtc)
            {
                _latestEventTimestampUtc = ev.TimestampUtc;
            }
            SetExplorerHasData("Events", _connectivityHealthy && _allEvents.Count > 0);
            EventsPaneHost.SetHasData(true);

            if (_allEvents.Count > MaxTimelineEvents + TimelineTrimBatch)
            {
                int removeCount = _allEvents.Count - MaxTimelineEvents;
                _allEvents.RemoveRange(0, removeCount);
            }

            if (EventsPaneHost.Timeline.Items.Count > MaxTimelineEvents + TimelineTrimBatch)
            {
                int removeCount = EventsPaneHost.Timeline.Items.Count - MaxTimelineEvents;
                for (int i = 0; i < removeCount; i += 1)
                {
                    EventsPaneHost.Timeline.Items.RemoveAt(0);
                }
            }

            if (_currentSession != null && _currentSession.Events.Count > MaxTimelineEvents)
            {
                _currentSession.Events.RemoveRange(0, _currentSession.Events.Count - MaxTimelineEvents);
            }

            ScheduleViewportRefresh();
        }

        internal void SetBackendConnectivity(bool healthy)
        {
            _connectivityHealthy = healthy;
            ApplyUplinkStatusVisual(healthy);
            EventsPaneHost.SetConnectivityHealthy(healthy);
            EventsPaneHost.SetHasData(_allEvents.Count > 0);
            RefreshExplorerDataBadges();
        }

        private void ApplyUplinkStatusVisual(bool? healthy)
        {
            if (StatusBlock == null || UplinkStatusBlock == null || BottomStatusBar == null)
                return;

            if (healthy == true)
            {
                StatusBlock.Text = "UPLINK CONNECTED";
                StatusBlock.SetResourceReference(TextBlock.ForegroundProperty, "StatusConnectedBrush");
                UplinkStatusBlock.Text = "UPLINK CONNECTED";
                UplinkStatusBlock.SetResourceReference(TextBlock.ForegroundProperty, "StatusConnectedBrush");
                BottomStatusBar.SetResourceReference(Border.BackgroundProperty, "WinPanelBrush");
                return;
            }

            if (healthy == false)
            {
                StatusBlock.Text = "UPLINK FAILED";
                StatusBlock.SetResourceReference(TextBlock.ForegroundProperty, "StatusFailedBrush");
                UplinkStatusBlock.Text = "UPLINK FAILED";
                UplinkStatusBlock.SetResourceReference(TextBlock.ForegroundProperty, "StatusFailedBrush");
                BottomStatusBar.SetResourceReference(Border.BackgroundProperty, "StatusBarFailedBrush");
                return;
            }

            StatusBlock.Text = "UPLINK CHECKING...";
            StatusBlock.SetResourceReference(TextBlock.ForegroundProperty, "WinMutedTextBrush");
            UplinkStatusBlock.Text = "UPLINK CHECKING...";
            UplinkStatusBlock.SetResourceReference(TextBlock.ForegroundProperty, "WinMutedTextBrush");
            BottomStatusBar.SetResourceReference(Border.BackgroundProperty, "WinPanelBrush");
        }

        private void InitializeThemeSelector()
        {
            if (ThemeSelector == null)
                return;

            ThemeSelector.SelectedIndex = App.CurrentThemeMode switch
            {
                UiThemeMode.Dark => 1,
                UiThemeMode.Light => 2,
                _ => (App.IsDarkTheme ? 1 : 2)
            };
            _themeSelectorReady = true;
        }

        private void ThemeSelector_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!_themeSelectorReady)
                return;

            UiThemeMode mode = ThemeSelector.SelectedIndex switch
            {
                1 => UiThemeMode.Dark,
                2 => UiThemeMode.Light,
                _ => UiThemeMode.Auto
            };

            App.SetThemeMode(mode);
        }

        // -------------------------------
        // Scroll / viewport
        // -------------------------------
        private void Scroll_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            EventsPaneHost.Timeline.ViewStartSeconds = EventsPaneHost.Scroll.Value;
            FocusViewport();
            SyncPerformanceViewToTimeline();
        }

        private void UpdateScrollBar()
        {
            if (_allEvents.Count == 0)
            {
                EventsPaneHost.Scroll.Maximum = 0;
                _latestEventTimestampUtc = _captureStartUtc;
                return;
            }

            var totalSeconds = (_latestEventTimestampUtc - _captureStartUtc).TotalSeconds;
            if (totalSeconds < 0)
            {
                totalSeconds = 0;
            }

            double max = Math.Max(0, totalSeconds - EventsPaneHost.Timeline.ViewDurationSeconds);
            EventsPaneHost.Scroll.Maximum = max;
        }

        private void FocusViewport()
        {
            var viewStart = _captureStartUtc + TimeSpan.FromSeconds(EventsPaneHost.Timeline.ViewStartSeconds);
            var viewEnd = viewStart + TimeSpan.FromSeconds(EventsPaneHost.Timeline.ViewDurationSeconds);

            RangeBlock.Text = $"Range: {viewStart:HH:mm:ss}Z - {viewEnd:HH:mm:ss}Z";

            _focusedEvents.Clear();
            if (_allEvents.Count == 0)
            {
                return;
            }

            int start = LowerBoundEventIndex(viewStart);
            int endExclusive = UpperBoundEventIndex(viewEnd);
            for (int i = start; i < endExclusive; i += 1)
            {
                var ev = _allEvents[i];
                if (!PassLaneFocus(ev))
                {
                    continue;
                }
                _focusedEvents.Add(ev);
            }
        }

        private void ScheduleViewportRefresh()
        {
            if (_viewportRefreshPending)
            {
                return;
            }

            _viewportRefreshPending = true;
            Dispatcher.BeginInvoke(new Action(() =>
            {
                _viewportRefreshPending = false;
                UpdateScrollBar();
                FocusViewport();
            }), System.Windows.Threading.DispatcherPriority.Background);
        }

        private int LowerBoundEventIndex(DateTime timestampUtc)
        {
            int lo = 0;
            int hi = _allEvents.Count;
            while (lo < hi)
            {
                int mid = lo + ((hi - lo) / 2);
                if (_allEvents[mid].TimestampUtc < timestampUtc)
                {
                    lo = mid + 1;
                }
                else
                {
                    hi = mid;
                }
            }

            return lo;
        }

        private int UpperBoundEventIndex(DateTime timestampUtc)
        {
            int lo = 0;
            int hi = _allEvents.Count;
            while (lo < hi)
            {
                int mid = lo + ((hi - lo) / 2);
                if (_allEvents[mid].TimestampUtc <= timestampUtc)
                {
                    lo = mid + 1;
                }
                else
                {
                    hi = mid;
                }
            }

            return lo;
        }

        private bool PassLaneFocus(TelemetryEvent ev)
        {
            if (string.IsNullOrWhiteSpace(_laneFocusKey))
                return true;

            // lane key is either "Group" or "Group/SubType"
            string key = string.IsNullOrWhiteSpace(ev.SubType) ? ev.Group : $"{ev.Group}/{ev.SubType}";
            return string.Equals(key, _laneFocusKey, StringComparison.OrdinalIgnoreCase)
                || string.Equals(ev.Group, _laneFocusKey, StringComparison.OrdinalIgnoreCase);
        }

        // -------------------------------
        // Timeline -> range selection
        // -------------------------------
        private void Timeline_RangeSelected(object? sender, TimeRangeSelectedEventArgs e)
        {
            var dur = (e.EndUtc - e.StartUtc).TotalSeconds;
            double newDuration = Math.Min(120, Math.Max(1, dur));

            EventsPaneHost.Timeline.ViewDurationSeconds = newDuration;

            var startSeconds = (e.StartUtc - _captureStartUtc).TotalSeconds;
            if (startSeconds < 0) startSeconds = 0;

            EventsPaneHost.Timeline.ViewStartSeconds = startSeconds;
            EventsPaneHost.Scroll.Value = Math.Min(EventsPaneHost.Scroll.Maximum, startSeconds);

            FocusViewport();
            SyncPerformanceViewToTimeline();
        }

        // -------------------------------
        // Timeline lane interactions
        // -------------------------------
        private void Timeline_LaneInteraction(object? sender, LaneInteractionEventArgs e)
        {
            if (e.Button == System.Windows.Input.MouseButton.Left && !e.IsArrow)
            {
                _laneFocusKey = e.LaneKey;
                FocusViewport();
                return;
            }

            if (e.Button != System.Windows.Input.MouseButton.Right)
                return;

            var menu = new ContextMenu();

            var miEnableDisable = new MenuItem { Header = EventsPaneHost.Timeline.IsLaneVisible(e.LaneKey) ? "Disable" : "Enable" };
            miEnableDisable.Click += (_, __) =>
            {
                bool nowVisible = !EventsPaneHost.Timeline.IsLaneVisible(e.LaneKey);
                EventsPaneHost.Timeline.SetLaneVisible(e.LaneKey, nowVisible);
                FocusViewport();
            };
            menu.Items.Add(miEnableDisable);

            var miFilter = new MenuItem { Header = "Filter to selection" };
            miFilter.Click += (_, __) =>
            {
                _laneFocusKey = e.LaneKey;
                FocusViewport();
            };
            menu.Items.Add(miFilter);

            var miClear = new MenuItem { Header = "Clear filter" };
            miClear.Click += (_, __) =>
            {
                _laneFocusKey = null;
                EventsPaneHost.Timeline.ClearAllLaneFilters();
                FocusViewport();
            };
            menu.Items.Add(miClear);

            menu.Items.Add(new Separator());

            var miColor = new MenuItem { Header = "Set colour (cycle)" };
            miColor.Click += (_, __) =>
            {
                Color[] options =
                {
                    Color.FromRgb(0x4C,0x8F,0xD2),
                    Color.FromRgb(0x6C,0xA4,0xDE),
                    Color.FromRgb(0x58,0xB6,0x58),
                    Color.FromRgb(0x7B,0xC7,0x7B),
                    Color.FromRgb(0x8D,0x97,0xA3),
                };

                int idx = (Math.Abs(e.LaneKey.GetHashCode()) % options.Length);
                var next = options[(idx + DateTime.UtcNow.Second) % options.Length];
                EventsPaneHost.Timeline.SetLaneColor(e.LaneKey, next);
            };
            menu.Items.Add(miColor);

            menu.IsOpen = true;
        }

        // -------------------------------
        // Selection sync
        // -------------------------------
        private void Timeline_SelectedEventChanged(object? sender, TelemetryEventSelectedEventArgs e)
        {
            if (e.Selected == null)
                return;

            EventsPaneHost.Grid.SelectedItem = e.Selected;
            EventsPaneHost.Grid.ScrollIntoView(e.Selected);
        }

        private void Grid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (EventsPaneHost.Grid.SelectedItem is TelemetryEvent te)
            {
                EventsPaneHost.Timeline.SelectedEvent = te;
            }
        }

        // -------------------------------
        // Pane: hide/collapse/float/dock/reset
        // -------------------------------
        private void HideEventsPane()
        {
            _eventsPaneVisible = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void ShowEventsPane()
        {
            _eventsPaneVisible = true;
            ApplyDockVisibilityFromExplorer();
        }

        private void HidePerformancePane()
        {
            _performancePaneVisible = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void HideEtwPane()
        {
            var sw = FindExplorerItem("Sleepwalker ETW");
            if (sw != null) sw.IsEnabled = false;
            var ti = FindExplorerItem("ETW-TI");
            if (ti != null) ti.IsEnabled = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void HideHeuristicsPane()
        {
            var heur = FindExplorerItem("Heuristics");
            if (heur != null) heur.IsEnabled = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void HideIpcUplinkPane()
        {
            var ipc = FindExplorerItem("IPC Uplink");
            if (ipc != null) ipc.IsEnabled = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void ShowPerformancePane()
        {
            _performancePaneVisible = true;
            ApplyDockVisibilityFromExplorer();
        }

        private void CollapsedEventsBar_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            ShowEventsPane();
            e.Handled = true;
        }

        private void CollapsedPerformanceBar_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            ShowPerformancePane();
            e.Handled = true;
        }

        private void CollapseOrExpandPane()
        {
            if (_eventsPaneVisible)
                HideEventsPane();
            else
                ShowEventsPane();
        }

        private void CollapseOrExpandPerformancePane()
        {
            if (_performancePaneVisible)
                HidePerformancePane();
            else
                ShowPerformancePane();
        }

        private void ToggleFloatDock()
        {
            if (_eventsFloatWindow == null)
            {
                UndockEventsPane();
            }
            else
            {
                RedockEventsPane();
            }
        }

        private void TogglePerformanceFloatDock()
        {
            if (_performanceFloatWindow == null)
            {
                UndockPerformancePane();
            }
            else
            {
                RedockPerformancePane();
            }
        }

        private void ToggleEtwFloatDock()
        {
            if (_etwFloatWindow == null)
                UndockEtwPane();
            else
                RedockEtwPane();
        }

        private void ToggleHeuristicsFloatDock()
        {
            if (_heuristicsFloatWindow == null)
                UndockHeuristicsPane();
            else
                RedockHeuristicsPane();
        }

        private void ResetDock_Click(object sender, RoutedEventArgs e)
        {
            _eventsFloatWindow?.Close();
            _performanceFloatWindow?.Close();
            _etwFloatWindow?.Close();
            _heuristicsFloatWindow?.Close();

            _laneFocusKey = null;
            EventsPaneHost.Timeline.ClearAllLaneFilters();
            EventsPaneHost.Timeline.ViewDurationSeconds = 120;
            EventsPaneHost.Timeline.ViewStartSeconds = 0;
            EventsPaneHost.Scroll.Value = 0;
            ShowEventsPane();
            ShowPerformancePane();
            var sw = FindExplorerItem("Sleepwalker ETW");
            if (sw != null) sw.IsEnabled = true;
            var ti = FindExplorerItem("ETW-TI");
            if (ti != null) ti.IsEnabled = true;
            var heur = FindExplorerItem("Heuristics");
            if (heur != null) heur.IsEnabled = true;
            var ipc = FindExplorerItem("IPC Uplink");
            if (ipc != null) ipc.IsEnabled = false;
            _performanceOnTop = false;
            _heuristicsOnTop = false;
            ApplyPaneOrder();
            ApplyIntelPaneOrder();
            HideDockPreview();
            FocusViewport();
            SyncPerformanceViewToTimeline();
        }

        // -------------------------------
        // Settings / diagnostics
        // -------------------------------
        private void OpenLaneSettings()
        {
            var w = new LaneSettingsWindow(this);
            w.Owner = this;
            w.Show();
        }

        private void Diagnostics_Click(object sender, RoutedEventArgs e)
        {
            var w = new DiagnosticsWindow(TryGetPid());
            w.Owner = this;
            w.Show();
        }

        private void PerformancePaneHost_ThreadDoubleClicked(object? sender, ThreadUsageRow row)
        {
            int pid = _currentSession?.Pid ?? TryGetPid();
            var w = new ThreadStackWindow(pid, row.Tid, row.State)
            {
                Owner = this
            };
            w.Show();
        }

        private async void FindProcess_Click(object sender, RoutedEventArgs e) => await OpenProcessPickerAndConnectAsync();

        private async void NewProcessTab_Click(object sender, RoutedEventArgs e) => await OpenProcessPickerAndConnectAsync();

        private void CloseProcessTab_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as FrameworkElement)?.Tag is not ProcessSessionTab tab)
                return;

            if (_processTabs.Count <= 1)
                return;

            bool wasSelected = ReferenceEquals(ProcessTabs.SelectedItem, tab);
            if (ReferenceEquals(_currentSession, tab))
                SaveCurrentSessionState();

            _processTabs.Remove(tab);

            if (_processTabs.Count == 0)
            {
                _currentSession = null;
                return;
            }

            if (wasSelected)
            {
                _currentSession = null;
                ProcessTabs.SelectedItem = _processTabs[0];
            }
        }

        private void ProcessTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_suppressTabSelectionChange)
                return;

            if (ProcessTabs.SelectedItem is not ProcessSessionTab tab)
                return;

            SwitchToSession(tab);
            if (tab.TargetExited)
            {
                StatusBlock.Text = $"TARGET {tab.Pid} EXITED - DATA CAPTURE STOPPED";
            }
            else
            {
                StatusBlock.Text = $"CONNECTED TO {tab.Title}";
            }
        }

        // -------------------------------
        // Stub buttons
        // -------------------------------
        private void Connect_Click(object sender, RoutedEventArgs e)
        {
            int pid = TryGetPid();
            if (pid <= 0)
            {
                StatusBlock.Text = "ENTER A VALID PID";
                return;
            }

            if (!TryOpenTargetProcess(pid, out var processName, out var failure, out var accessDenied))
            {
                StatusBlock.Text = failure;
                if (accessDenied)
                {
                    ThemedMessageBox.Show(
                        this,
                        $"Access denied while opening PID {pid}. The process handle could not be opened with required access rights.",
                        "Target Attach Failed",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                }

                return;
            }

            StatusBlock.Text = $"CONNECTED TO {processName} ({pid})";
            var tab = AddOrSelectProcessTab(pid, $"{processName} ({pid})", select: true);
            tab.TargetExited = false;
            if (!ReferenceEquals(_currentSession, tab))
            {
                SwitchToSession(tab);
            }
            else
            {
                StartLiveCaptureForPid(pid);
            }

            _ = RunPreflightAsync(pid);
        }

        private async void Launch_Click(object sender, RoutedEventArgs e) => await OpenProcessPickerAndConnectAsync();

        private async Task OpenProcessPickerAndConnectAsync()
        {
            if (_openingProcessPicker)
                return;

            _openingProcessPicker = true;
            LoadingWindow? loading = null;

            try
            {
                loading = new LoadingWindow
                {
                    Owner = this
                };
                loading.SetProgress(14, "Preparing process picker...", "Initializing process view shell.");
                loading.Show();
                await Dispatcher.InvokeAsync(() => { }, System.Windows.Threading.DispatcherPriority.Render);

                var picker = new ProcessPickerWindow
                {
                    Owner = this
                };

                loading.SetProgress(58, "Scanning processes...", "Building initial process list and filters.");
                picker.PrimeForFirstShow();
                await Dispatcher.InvokeAsync(() => { }, System.Windows.Threading.DispatcherPriority.Render);

                loading.SetProgress(100, "Opening picker...", "Process picker is ready.");
                await Task.Delay(90);
                loading.Close();
                loading = null;

                bool? result = picker.ShowDialog();
                if (result != true || picker.SelectedPid <= 0)
                    return;

                PidBox.Text = picker.SelectedPid.ToString();
                Connect_Click(this, new RoutedEventArgs());
            }
            finally
            {
                if (loading != null && loading.IsVisible)
                {
                    loading.Close();
                }

                _openingProcessPicker = false;
            }
        }

        private void Suspend_Click(object sender, RoutedEventArgs e) { }
        private void Restart_Click(object sender, RoutedEventArgs e) { }

        // -------------------------------
        // Demo feed
        // -------------------------------
        private void SeedFake()
        {
            var t0 = _captureStartUtc;

            AppendEvent(new TelemetryEvent { TimestampUtc = t0.AddSeconds(1), PID = 1234, TID = 10, Group = "Execution", SubType = "CreateProcess", Summary = "proc created" });
            AppendEvent(new TelemetryEvent { TimestampUtc = t0.AddSeconds(2), PID = 1234, TID = 11, Group = "Thread", SubType = "RemoteThread", Summary = "remote thread start" });
            AppendEvent(new TelemetryEvent { TimestampUtc = t0.AddSeconds(6), PID = 1234, TID = 12, Group = "Registry", SubType = "SetValue", Summary = "reg set value" });
            AppendEvent(new TelemetryEvent { TimestampUtc = t0.AddSeconds(12), PID = 1234, TID = 13, Group = "Handles", SubType = "Duplicate", Summary = "dup handle" });
            AppendEvent(new TelemetryEvent { TimestampUtc = t0.AddSeconds(35), PID = 1234, TID = 14, Group = "Injection", SubType = "MapView", Summary = "write+map" });
        }

        private void UndockEventsPane()
        {
            if (_eventsFloatWindow != null)
                return;

            if (EventsDockBorder.Child == EventsPaneHost)
                EventsDockBorder.Child = null;

            _eventsPaneFloating = true;
            _eventsPaneVisible = true;
            ApplyDockVisibilityFromExplorer();
            Dispatcher.BeginInvoke(new Action(() =>
            {
                if (_eventsFloatWindow != null)
                    return;

                _eventsFloatWindow = new EventsFloatWindow(EventsPaneHost)
                {
                    Owner = this,
                    ShowInTaskbar = false
                };
                _eventsFloatWindow.Closed += EventsFloatWindow_Closed;
                _eventsFloatWindow.Show();
            }), System.Windows.Threading.DispatcherPriority.Background);
        }

        private void RedockEventsPane()
        {
            if (_eventsFloatWindow != null)
            {
                _eventsFloatWindow.Closed -= EventsFloatWindow_Closed;
                if (_eventsFloatWindow.Content == EventsPaneHost)
                    _eventsFloatWindow.Content = null;
                _eventsFloatWindow.Close();
                _eventsFloatWindow = null;
            }

            _eventsPaneFloating = false;
            if (EventsDockBorder.Child == null)
                EventsDockBorder.Child = EventsPaneHost;
            _eventsPaneVisible = true;
            _draggingEventsPaneHeader = false;
            HideDockPreview();
            ApplyDockVisibilityFromExplorer();
        }

        private void UndockPerformancePane()
        {
            if (_performanceFloatWindow != null)
                return;

            if (PerformanceDockBorder.Child == PerformancePaneHost)
                PerformanceDockBorder.Child = null;

            _performancePaneFloating = true;
            _performancePaneVisible = true;
            ApplyDockVisibilityFromExplorer();
            Dispatcher.BeginInvoke(new Action(() =>
            {
                if (_performanceFloatWindow != null)
                    return;

                _performanceFloatWindow = new PerformanceFloatWindow(PerformancePaneHost)
                {
                    Owner = this,
                    ShowInTaskbar = false
                };
                _performanceFloatWindow.Closed += PerformanceFloatWindow_Closed;
                _performanceFloatWindow.Show();
            }), System.Windows.Threading.DispatcherPriority.Background);
        }

        private void RedockPerformancePane()
        {
            if (_performanceFloatWindow != null)
            {
                _performanceFloatWindow.Closed -= PerformanceFloatWindow_Closed;
                if (_performanceFloatWindow.Content == PerformancePaneHost)
                    _performanceFloatWindow.Content = null;
                _performanceFloatWindow.Close();
                _performanceFloatWindow = null;
            }

            _performancePaneFloating = false;
            if (PerformanceDockBorder.Child == null)
                PerformanceDockBorder.Child = PerformancePaneHost;
            _performancePaneVisible = true;
            _draggingPerformancePaneHeader = false;
            HideDockPreview();
            ApplyDockVisibilityFromExplorer();
        }

        private void UndockEtwPane()
        {
            if (_etwFloatWindow != null)
                return;

            if (EtwDockBorder.Child == EtwPaneHost)
                EtwDockBorder.Child = null;

            _etwPaneFloating = true;
            ApplyDockVisibilityFromExplorer();
            Dispatcher.BeginInvoke(new Action(() =>
            {
                if (_etwFloatWindow != null)
                    return;

                _etwFloatWindow = new EtwFloatWindow(EtwPaneHost)
                {
                    Owner = this,
                    ShowInTaskbar = false
                };
                _etwFloatWindow.Closed += EtwFloatWindow_Closed;
                _etwFloatWindow.Show();
            }), System.Windows.Threading.DispatcherPriority.Background);
        }

        private void RedockEtwPane()
        {
            if (_etwFloatWindow != null)
            {
                _etwFloatWindow.Closed -= EtwFloatWindow_Closed;
                if (_etwFloatWindow.Content == EtwPaneHost)
                    _etwFloatWindow.Content = null;
                _etwFloatWindow.Close();
                _etwFloatWindow = null;
            }

            _etwPaneFloating = false;
            if (EtwDockBorder.Child == null)
                EtwDockBorder.Child = EtwPaneHost;
            ApplyDockVisibilityFromExplorer();
        }

        private void UndockHeuristicsPane()
        {
            if (_heuristicsFloatWindow != null)
                return;

            if (HeuristicsDockBorder.Child == HeuristicsPaneHost)
                HeuristicsDockBorder.Child = null;

            _heuristicsPaneFloating = true;
            ApplyDockVisibilityFromExplorer();
            Dispatcher.BeginInvoke(new Action(() =>
            {
                if (_heuristicsFloatWindow != null)
                    return;

                _heuristicsFloatWindow = new HeuristicsFloatWindow(HeuristicsPaneHost)
                {
                    Owner = this,
                    ShowInTaskbar = false
                };
                _heuristicsFloatWindow.Closed += HeuristicsFloatWindow_Closed;
                _heuristicsFloatWindow.Show();
            }), System.Windows.Threading.DispatcherPriority.Background);
        }

        private void RedockHeuristicsPane()
        {
            if (_heuristicsFloatWindow != null)
            {
                _heuristicsFloatWindow.Closed -= HeuristicsFloatWindow_Closed;
                if (_heuristicsFloatWindow.Content == HeuristicsPaneHost)
                    _heuristicsFloatWindow.Content = null;
                _heuristicsFloatWindow.Close();
                _heuristicsFloatWindow = null;
            }

            _heuristicsPaneFloating = false;
            if (HeuristicsDockBorder.Child == null)
                HeuristicsDockBorder.Child = HeuristicsPaneHost;
            ApplyDockVisibilityFromExplorer();
        }

        private void EventsFloatWindow_Closed(object? sender, EventArgs e)
        {
            _eventsFloatWindow = null;
            if (EventsDockBorder.Child == null)
                RedockEventsPane();
        }

        private void PerformanceFloatWindow_Closed(object? sender, EventArgs e)
        {
            _performanceFloatWindow = null;
            if (PerformanceDockBorder.Child == null)
                RedockPerformancePane();
        }

        private void EtwFloatWindow_Closed(object? sender, EventArgs e)
        {
            _etwFloatWindow = null;
            if (EtwDockBorder.Child == null)
                RedockEtwPane();
        }

        private void HeuristicsFloatWindow_Closed(object? sender, EventArgs e)
        {
            _heuristicsFloatWindow = null;
            if (HeuristicsDockBorder.Child == null)
                RedockHeuristicsPane();
        }

        private void TogglePaneOrder()
        {
            _performanceOnTop = !_performanceOnTop;
            ApplyPaneOrder();
        }

        private void ToggleIntelPaneOrder()
        {
            _heuristicsOnTop = !_heuristicsOnTop;
            ApplyIntelPaneOrder();
        }

        private void ApplyPaneOrder()
        {
            if (_performanceOnTop)
            {
                Grid.SetRow(PerformancePaneRow, 0);
                Grid.SetRow(EventsPaneRow, 2);
                PerformancePaneRow.Margin = new Thickness(0, 0, 0, 3);
                EventsPaneRow.Margin = new Thickness(0, 3, 0, 0);
            }
            else
            {
                Grid.SetRow(EventsPaneRow, 0);
                Grid.SetRow(PerformancePaneRow, 2);
                EventsPaneRow.Margin = new Thickness(0, 0, 0, 3);
                PerformancePaneRow.Margin = new Thickness(0, 3, 0, 0);
            }
        }

        private void ApplyIntelPaneOrder()
        {
            if (_heuristicsOnTop)
            {
                Grid.SetRow(HeuristicsDockBorder, 0);
                Grid.SetRow(EtwDockBorder, 2);
                HeuristicsDockBorder.Margin = new Thickness(0, 0, 0, 3);
                EtwDockBorder.Margin = new Thickness(0, 3, 0, 0);
            }
            else
            {
                Grid.SetRow(EtwDockBorder, 0);
                Grid.SetRow(HeuristicsDockBorder, 2);
                EtwDockBorder.Margin = new Thickness(0, 0, 0, 3);
                HeuristicsDockBorder.Margin = new Thickness(0, 3, 0, 0);
            }

            ApplyDockVisibilityFromExplorer();
        }

        private void BeginPaneHeaderDrag(bool isEventsPane, Point screenPosition)
        {
            if (isEventsPane)
            {
                if (_eventsFloatWindow == null)
                    ToggleFloatDock();

                if (_eventsFloatWindow == null)
                    return;

                _draggingEventsPaneHeader = true;
                _draggingPerformancePaneHeader = false;
                _floatingPaneDragOffset = new Vector(
                    screenPosition.X - _eventsFloatWindow.Left,
                    screenPosition.Y - _eventsFloatWindow.Top);
            }
            else
            {
                if (_performanceFloatWindow == null)
                    TogglePerformanceFloatDock();

                if (_performanceFloatWindow == null)
                    return;

                _draggingPerformancePaneHeader = true;
                _draggingEventsPaneHeader = false;
                _floatingPaneDragOffset = new Vector(
                    screenPosition.X - _performanceFloatWindow.Left,
                    screenPosition.Y - _performanceFloatWindow.Top);
            }

            ContinuePaneHeaderDrag(isEventsPane, screenPosition);
        }

        private void ContinuePaneHeaderDrag(bool isEventsPane, Point screenPosition)
        {
            if (isEventsPane && !_draggingEventsPaneHeader)
                return;
            if (!isEventsPane && !_draggingPerformancePaneHeader)
                return;

            var floatingWindow = isEventsPane ? (Window?)_eventsFloatWindow : _performanceFloatWindow;
            if (floatingWindow == null)
                return;

            floatingWindow.Left = screenPosition.X - _floatingPaneDragOffset.X;
            floatingWindow.Top = screenPosition.Y - _floatingPaneDragOffset.Y;
            UpdateDockPreview(screenPosition);
        }

        private void EndPaneHeaderDrag(bool isEventsPane, Point screenPosition)
        {
            if (isEventsPane)
                _draggingEventsPaneHeader = false;
            else
                _draggingPerformancePaneHeader = false;

            var slot = GetDockDropSlot(screenPosition);
            HideDockPreview();

            if (slot == DockDropSlot.None)
                return;

            if (isEventsPane)
            {
                _eventsFloatWindow?.Close();
                _performanceOnTop = slot == DockDropSlot.Bottom;
            }
            else
            {
                _performanceFloatWindow?.Close();
                _performanceOnTop = slot == DockDropSlot.Top;
            }

            ApplyPaneOrder();
        }

        private DockDropSlot GetDockDropSlot(Point screenPosition)
        {
            if (DockGrid.ActualWidth < 8 || DockGrid.ActualHeight < 8)
                return DockDropSlot.None;

            var dockTopLeft = DockGrid.PointToScreen(new Point(0, 0));
            var dockRect = new Rect(dockTopLeft, new Size(DockGrid.ActualWidth, DockGrid.ActualHeight));
            if (!dockRect.Contains(screenPosition))
                return DockDropSlot.None;

            double relativeY = screenPosition.Y - dockRect.Top;
            return relativeY <= dockRect.Height * 0.5 ? DockDropSlot.Top : DockDropSlot.Bottom;
        }

        private void UpdateDockPreview(Point screenPosition)
        {
            var slot = GetDockDropSlot(screenPosition);
            DockPreviewTop.Visibility = slot == DockDropSlot.Top ? Visibility.Visible : Visibility.Collapsed;
            DockPreviewBottom.Visibility = slot == DockDropSlot.Bottom ? Visibility.Visible : Visibility.Collapsed;
        }

        private void HideDockPreview()
        {
            DockPreviewTop.Visibility = Visibility.Collapsed;
            DockPreviewBottom.Visibility = Visibility.Collapsed;
        }

        private enum DockDropSlot
        {
            None,
            Top,
            Bottom
        }

        private static TelemetryEvent CloneTelemetryEvent(TelemetryEvent src)
        {
            return new TelemetryEvent
            {
                TimestampUtc = src.TimestampUtc,
                PID = src.PID,
                TID = src.TID,
                Group = src.Group,
                SubType = src.SubType,
                ProcessName = src.ProcessName,
                Summary = src.Summary,
                Details = src.Details
            };
        }

        private static PerformanceSample ClonePerformanceSample(PerformanceSample src)
        {
            return new PerformanceSample
            {
                TimestampUtc = src.TimestampUtc,
                CoreCount = src.CoreCount,
                CpuPercent = src.CpuPercent,
                CoresUsedPercent = src.CoresUsedPercent,
                DiskReadBytesPerSec = src.DiskReadBytesPerSec,
                DiskWriteBytesPerSec = src.DiskWriteBytesPerSec,
                PrivateBytes = src.PrivateBytes,
                ReservedBytes = src.ReservedBytes,
                NetInBytesPerSec = src.NetInBytesPerSec,
                NetOutBytesPerSec = src.NetOutBytesPerSec,
                NetPacketsPerSec = src.NetPacketsPerSec,
                TopThreads = src.TopThreads.Select(t => new ThreadUsageSample
                {
                    Tid = t.Tid,
                    CpuMsDelta = t.CpuMsDelta,
                    State = t.State,
                    StartTimeUtc = t.StartTimeUtc
                }).ToList()
            };
        }

        // Lane focus API used by LaneSettingsWindow
        public void SetLaneFocus(string? laneKey)
        {
            _laneFocusKey = string.IsNullOrWhiteSpace(laneKey) ? null : laneKey;
            FocusViewport();
        }

        public string? GetLaneFocus() => _laneFocusKey;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);
    }

    public sealed class ProcessSessionTab : INotifyPropertyChanged
    {
        private int _pid;
        private string _title = "";
        public List<TelemetryEvent> Events { get; } = new();
        public List<PerformanceSample> PerformanceHistory { get; } = new();
        public DateTime CaptureStartUtc { get; set; } = DateTime.UtcNow;
        public double ViewDurationSeconds { get; set; } = 120;
        public double ViewStartSeconds { get; set; }
        public string? LaneFocusKey { get; set; }
        public bool TargetExited { get; set; }

        public int Pid
        {
            get => _pid;
            set
            {
                if (_pid == value) return;
                _pid = value;
                OnPropertyChanged();
            }
        }

        public string Title
        {
            get => _title;
            set
            {
                if (_title == value) return;
                _title = value;
                OnPropertyChanged();
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? prop = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));
    }
}
