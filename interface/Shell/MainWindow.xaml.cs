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
using System.Windows.Threading;

namespace SleepwalkerInterface
{
    public partial class MainWindow : Window, IIntelDetailsProvider
    {
        private readonly List<TelemetryEvent> _allEvents = new();
        private readonly ObservableCollection<TelemetryEvent> _focusedEvents = new();
        private const int MaxTimelineEvents = 50000;
        private const int TimelineTrimBatch = 512;
        private const double DefaultTimelineViewDurationSeconds = 120;
        private bool _viewportRefreshPending;
        private DateTime _latestEventTimestampUtc;

        private DateTime _captureStartUtc;
        private EventsFloatWindow? _eventsFloatWindow;
        private EventLogWindow? _eventLogWindow;
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
        private bool _draggingEventsPaneHeader;
        private bool _draggingPerformancePaneHeader;
        private bool _openingProcessPicker;
        private Process? _targetExitWatchProcess;
        private int _targetExitWatchPid;
        private Vector _floatingPaneDragOffset;
        private readonly DispatcherTimer _detachedEventLogRefreshTimer;
        private readonly DispatcherTimer _processStateRefreshTimer;
        private bool _scrollSyncPending;
        private bool _topTimeTravelSyncing;
        private bool _toolbarViewMenuSyncing;
        private bool _followLiveTimeline = true;
        private double _pendingScrollStartSeconds;
        private DateTime _scopeStatusCacheUtc;
        private int _scopeStatusCachePid;
        private IntelScopeStatus _scopeStatusCache = IntelScopeStatus.Unknown;
        private static readonly Brush ProcessStateRunningBackground = new SolidColorBrush(Color.FromRgb(0x14, 0x3A, 0x1E));
        private static readonly Brush ProcessStateRunningBorder = new SolidColorBrush(Color.FromRgb(0x49, 0xC1, 0x66));
        private static readonly Brush ProcessStateRunningForeground = new SolidColorBrush(Color.FromRgb(0xA9, 0xF5, 0xB8));
        private static readonly Brush ProcessStateWaitingBackground = new SolidColorBrush(Color.FromRgb(0x3D, 0x34, 0x16));
        private static readonly Brush ProcessStateWaitingBorder = new SolidColorBrush(Color.FromRgb(0xDE, 0xC2, 0x62));
        private static readonly Brush ProcessStateWaitingForeground = new SolidColorBrush(Color.FromRgb(0xF8, 0xE9, 0xAF));
        private static readonly Brush ProcessStateExitedBackground = new SolidColorBrush(Color.FromRgb(0x28, 0x1A, 0x1A));
        private static readonly Brush ProcessStateExitedBorder = new SolidColorBrush(Color.FromRgb(0x73, 0x4A, 0x4A));
        private static readonly Brush ProcessStateExitedForeground = new SolidColorBrush(Color.FromRgb(0xE1, 0xB4, 0xB4));
        private static readonly Brush ProcessStateUnknownBackground = new SolidColorBrush(Color.FromRgb(0x1E, 0x1E, 0x1E));
        private static readonly Brush ProcessStateUnknownBorder = new SolidColorBrush(Color.FromRgb(0x4A, 0x4A, 0x4A));
        private static readonly Brush ProcessStateUnknownForeground = new SolidColorBrush(Color.FromRgb(0xB8, 0xB8, 0xB8));

        private const uint ProcessSynchronize = 0x00100000;
        private const uint ProcessVmRead = 0x0010;
        private const uint ProcessQueryLimitedInformation = 0x1000;

        public MainWindow()
        {
            InitializeComponent();
            SetResourceReference(BackgroundProperty, "WinBgBrush");
            RootGrid.SetResourceReference(Panel.BackgroundProperty, "WinBgBrush");
            WindowThemeHelper.ApplyDarkTitleBar(this);
            _detachedEventLogRefreshTimer = new DispatcherTimer(DispatcherPriority.Background)
            {
                Interval = TimeSpan.FromMilliseconds(110)
            };
            _detachedEventLogRefreshTimer.Tick += DetachedEventLogRefreshTimer_Tick;
            _processStateRefreshTimer = new DispatcherTimer(DispatcherPriority.Background)
            {
                Interval = TimeSpan.FromMilliseconds(900)
            };
            _processStateRefreshTimer.Tick += (_, __) =>
            {
                ValidateCurrentSessionState();
                RefreshProcessStateBadge();
            };
            Loaded += OnLoaded;
            Closed += OnClosed;
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            PidBox.Text = string.Empty;
            _samplerPid = 0;

            _captureStartUtc = AnchorCaptureStartUtc(DefaultTimelineViewDurationSeconds);
            _latestEventTimestampUtc = DateTime.UtcNow;

            // Bind grid to focused items
            EventsPaneHost.Grid.ItemsSource = _focusedEvents;
            EventsPaneHost.SetHasData(false);
            EventsPaneHost.SetEventLogDetached(false);

            // Timeline init
            EventsPaneHost.Timeline.CaptureStartUtc = _captureStartUtc;
            EventsPaneHost.Timeline.ViewDurationSeconds = DefaultTimelineViewDurationSeconds;
            EventsPaneHost.Timeline.ViewStartSeconds = 0;

            // Timeline interactions
            EventsPaneHost.Timeline.RangeSelected += Timeline_RangeSelected;
            EventsPaneHost.Timeline.LaneInteraction += Timeline_LaneInteraction;
            EventsPaneHost.Timeline.SelectedEventChanged += Timeline_SelectedEventChanged;
            EventsPaneHost.Timeline.EventDoubleClicked += Timeline_EventDoubleClicked;

            // Grid selection sync
            EventsPaneHost.Grid.SelectionChanged += Grid_SelectionChanged;

            // Scrollbar sync
            EventsPaneHost.Scroll.ValueChanged += Scroll_ValueChanged;

            // Pane header buttons
            EventsPaneHost.CloseRequested += (_, __) => HideEventsPane();
            EventsPaneHost.FloatRequested += (_, __) => ToggleFloatDock();
            EventsPaneHost.LogPopoutRequested += (_, __) => ToggleEventLogDock();
            EventsPaneHost.SettingsRequested += (_, __) => OpenLaneSettings();
            EventsPaneHost.EventLogEntryOpenRequested += EventsPaneHost_EventLogEntryOpenRequested;
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
            EtwPaneHost.InspectRequested += (_, __) => OpenEtwInspector();
            HeuristicsPaneHost.ReorderRequested += (_, __) => ToggleIntelPaneOrder();
            HeuristicsPaneHost.FloatRequested += (_, __) => ToggleHeuristicsFloatDock();
            HeuristicsPaneHost.CloseRequested += (_, __) => HideHeuristicsPane();
            HeuristicsPaneHost.InspectRequested += (_, __) => OpenHeuristicsInspector();
            FilesystemPaneHost.CloseRequested += (_, __) => HideFilesystemPane();
            FilesystemPaneHost.InspectRequested += (_, __) => OpenFilesystemInspector();
            ProcessRelationsPaneHost.CloseRequested += (_, __) => HideProcessRelationsPane();
            ProcessRelationsPaneHost.InspectRequested += (_, __) => OpenProcessRelationsInspector();
            IpcUplinkPaneHost.CloseRequested += (_, __) => HideIpcUplinkPane();

            // Explorer setup
            SetupExplorer();
            SetupProcessTabs();
            InitializeBackendUi();
            ApplyUplinkStatusVisual(healthy: null);

            UpdateScrollBar();
            FocusViewport();
            UpdateTopTimeTravelBar();
            RebuildToolbarViewMenuOptions();

            // Performance sampler + UI sync
            _perf = new PerformanceSampler();
            _perf.SampleArrived += Perf_SampleArrived;

            // Make performance pane aware of capture start immediately
            PerformancePaneHost.SetCaptureStart(_captureStartUtc);
            PerformancePaneHost.SetPid(TryGetPid());
            PerformancePaneHost.SetProcessLiveDataAvailable(false);
            SyncPerformanceViewToTimeline();
            StatusBlock.Text = "NO TARGET SELECTED";
            ApplyPaneOrder();
            ApplyIntelPaneOrder();
            _processStateRefreshTimer.Start();
            RefreshProcessStateBadge();
        }

        private void SetupProcessTabs()
        {
            ProcessTabs.ItemsSource = _processTabs;
            _currentSession = null;
        }

        private void OnClosed(object? sender, EventArgs e)
        {
            _detachedEventLogRefreshTimer.Stop();
            _processStateRefreshTimer.Stop();

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
            if (_eventLogWindow != null)
            {
                _eventLogWindow.Closed -= EventLogWindow_Closed;
                _eventLogWindow.Close();
                _eventLogWindow = null;
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
            _explorer.Add(new GraphExplorerItem("ETW", new SolidColorBrush(Color.FromRgb(0xD2, 0x89, 0x34))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem("Heuristics", new SolidColorBrush(Color.FromRgb(0xD2, 0x55, 0x55))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem("Filesystem", new SolidColorBrush(Color.FromRgb(0x45, 0x8E, 0x7A))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem("Process Relations", new SolidColorBrush(Color.FromRgb(0xD2, 0xB8, 0x55))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem("IPC Uplink", new SolidColorBrush(Color.FromRgb(0x4A, 0xC1, 0xC6)))
            {
                IsEnabled = false,
                ShowDetails = false,
                DetailPrimary = "",
                DetailSecondary = ""
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
            {
                item.HasData = hasData;
                if (!hasData)
                {
                    item.ClearPreviewValues();
                }
            }
        }

        private void RefreshExplorerDataBadges()
        {
            SetExplorerHasData("Events", _allEvents.Count > 0);
            SetExplorerHasData("Performance", _hasPerformanceData || (_currentSession?.PerformanceHistory.Count ?? 0) > 0);
            SetExplorerHasData("ETW", EtwPaneHost.ItemCount > 0);
            SetExplorerHasData("Heuristics", HeuristicsPaneHost.ItemCount > 0);
            SetExplorerHasData("Filesystem", FilesystemPaneHost.ItemCount > 0);
            SetExplorerHasData("Process Relations", ProcessRelationsPaneHost.ItemCount > 0);
            SetExplorerHasData("IPC Uplink", _hasIpcUplinkData);
        }

        private void ApplyDockVisibilityFromExplorer()
        {
            bool showEvents = _explorer.FirstOrDefault(x => x.Name == "Events")?.IsEnabled ?? true;
            bool showPerf = _explorer.FirstOrDefault(x => x.Name == "Performance")?.IsEnabled ?? true;
            bool showIpcUplink = _explorer.FirstOrDefault(x => x.Name == "IPC Uplink")?.IsEnabled ?? false;
            bool showEtw = _explorer.FirstOrDefault(x => x.Name == "ETW")?.IsEnabled ?? true;
            bool showHeuristics = _explorer.FirstOrDefault(x => x.Name == "Heuristics")?.IsEnabled ?? true;
            bool showFilesystem = _explorer.FirstOrDefault(x => x.Name == "Filesystem")?.IsEnabled ?? true;
            bool showRelations = _explorer.FirstOrDefault(x => x.Name == "Process Relations")?.IsEnabled ?? true;

            if (!showEvents && _eventsFloatWindow != null)
                _eventsFloatWindow.Close();
            if (!showEvents && _eventLogWindow != null)
                _eventLogWindow.Close();
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
            bool showFilesystemContent = showFilesystem;
            bool showRelationsContent = showRelations;

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
            FilesystemDockBorder.Visibility = showFilesystemContent ? Visibility.Visible : Visibility.Collapsed;
            ProcessRelationsDockBorder.Visibility = showRelationsContent ? Visibility.Visible : Visibility.Collapsed;
            IpcUplinkDockBorder.Visibility = showIpcUplink ? Visibility.Visible : Visibility.Collapsed;
            IpcUplinkColumn.Width = showIpcUplink ? new GridLength(380) : new GridLength(0);
            IpcUplinkSplitterColumn.Width = showIpcUplink ? new GridLength(2) : new GridLength(0);
            IpcUplinkSplitter.Visibility = showIpcUplink ? Visibility.Visible : Visibility.Collapsed;

            bool row0Visible = (Grid.GetRow(EtwDockBorder) == 0 && showEtwContent) ||
                               (Grid.GetRow(HeuristicsDockBorder) == 0 && showHeuristicsContent);
            bool row2Visible = (Grid.GetRow(EtwDockBorder) == 2 && showEtwContent) ||
                               (Grid.GetRow(HeuristicsDockBorder) == 2 && showHeuristicsContent);
            bool row4Visible = showFilesystemContent;
            bool row6Visible = showRelationsContent;
            IntelligenceDock.RowDefinitions[0].Height = row0Visible ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            IntelligenceDock.RowDefinitions[2].Height = row2Visible ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            IntelligenceDock.RowDefinitions[4].Height = row4Visible ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            IntelligenceDock.RowDefinitions[6].Height = row6Visible ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            IntelligenceDock.RowDefinitions[1].Height = (row0Visible && row2Visible) ? new GridLength(2) : new GridLength(0);
            IntelligenceDock.RowDefinitions[3].Height = (row2Visible && row4Visible) ? new GridLength(2) : new GridLength(0);
            IntelligenceDock.RowDefinitions[5].Height = (row4Visible && row6Visible) ? new GridLength(2) : new GridLength(0);

            bool showIntel = row0Visible || row2Visible || row4Visible || row6Visible;
            IntelligenceColumn.Width = showIntel ? new GridLength(560) : new GridLength(0);
            IntelligenceSplitterColumn.Width = showIntel ? new GridLength(2) : new GridLength(0);
            IntelligenceSplitter.Visibility = showIntel ? Visibility.Visible : Visibility.Collapsed;
            IntelligenceDock.Visibility = showIntel ? Visibility.Visible : Visibility.Collapsed;
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
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.BeginInvoke(new Action(() => Perf_SampleArrived(sender, e)));
                return;
            }

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

            if (_currentSession != null &&
                _currentSession.Pid == pid &&
                _currentSession.Events.Count == 0 &&
                _currentSession.PerformanceHistory.Count == 0 &&
                _currentSession.ThreadLifecycleHistory.Count == 0)
            {
                double viewDuration = Math.Max(1, EventsPaneHost.Timeline.ViewDurationSeconds);
                _captureStartUtc = AnchorCaptureStartUtc(viewDuration);
                _latestEventTimestampUtc = DateTime.UtcNow;
                _currentSession.CaptureStartUtc = _captureStartUtc;
                _currentSession.ViewDurationSeconds = viewDuration;
                _currentSession.ViewStartSeconds = 0;

                EventsPaneHost.Timeline.CaptureStartUtc = _captureStartUtc;
                EventsPaneHost.Timeline.ViewDurationSeconds = viewDuration;
                EventsPaneHost.Timeline.ViewStartSeconds = 0;
                EventsPaneHost.Scroll.Value = 0;
                UpdateScrollBar();
                FocusViewport();
                PerformancePaneHost.SetCaptureStart(_captureStartUtc);
                SyncPerformanceViewToTimeline();
            }

            _perf.SetTargetPid(pid);
            _perf.Start();
            _samplerPid = pid;
            PerformancePaneHost.SetProcessLiveDataAvailable(true);
            StartTargetExitWatcher(pid);
            StartBackendForPid(pid);
            StatusBlock.Text = $"LIVE CAPTURE: {NormalizeSessionTitle(_currentSession?.Title ?? $"PID {pid}")}";
            RefreshProcessStateBadge();
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
                Dispatcher.BeginInvoke(new Action(ValidateCurrentSessionState));
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
            if (pid <= 0)
                return;

            ProcessSessionTab? exitedTab = _processTabs.FirstOrDefault(x => x.Pid == pid);
            if (exitedTab == null || exitedTab.TargetExited)
                return;

            exitedTab.TargetExited = true;
            MarkSessionExited(exitedTab);

            if (!ReferenceEquals(_currentSession, exitedTab))
            {
                SaveTabToBackingStore(exitedTab);
                RefreshProcessStateBadge();
                return;
            }

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

            SaveCurrentSessionState();
            EtwPaneHost.TrimDetailPayload(48);
            HeuristicsPaneHost.TrimDetailPayload(48);
            FilesystemPaneHost.TrimDetailPayload(48);
            ProcessRelationsPaneHost.TrimDetailPayload(48);

            StopTargetExitWatcher();
            StopBackendSession();
            _perf?.Stop();
            _samplerPid = 0;
            PerformancePaneHost.SetProcessLiveDataAvailable(false);

            StatusBlock.Text = $"Target {pid} exited. Capture stopped.";
            RefreshProcessStateBadge();
            ThemedMessageBox.ShowToast(
                this,
                $"Target process {pid} exited. Data capture has been stopped for this tab.",
                "Target Exited",
                MessageBoxImage.Warning,
                durationMs: 5000);
        }

        private void ValidateCurrentSessionState()
        {
            if (_currentSession == null || _currentSession.Pid <= 0 || _currentSession.OfflineSnapshot || _currentSession.TargetExited)
            {
                return;
            }

            if (TryOpenTargetProcess(_currentSession.Pid, out _, out _, out bool accessDenied))
            {
                return;
            }

            if (!accessDenied)
            {
                HandleTargetProcessExit(_currentSession.Pid);
            }
        }

        private static void MarkSessionExited(ProcessSessionTab tab)
        {
            tab.Title = NormalizeSessionTitle(tab.Title);
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

            IntPtr handle = Kernel32Native.OpenProcess(
                ProcessQueryLimitedInformation | ProcessVmRead | ProcessSynchronize,
                false,
                unchecked((uint)pid));
            if (handle == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                accessDenied = err == 5;
                failure = accessDenied ? $"ACCESS DENIED TO PID {pid}" : $"FAILED TO OPEN PID {pid} (WIN32 {err})";
                return false;
            }

            _ = Kernel32Native.CloseHandle(handle);
            return true;
        }

        private int TryGetPid()
        {
            if (PidBox == null) return 0;
            var s = PidBox.Text?.Trim();
            if (string.IsNullOrWhiteSpace(s))
                return _currentSession?.Pid ?? 0;
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
                double initialDuration = EventsPaneHost?.Timeline != null
                    ? Math.Clamp(EventsPaneHost.Timeline.ViewDurationSeconds, 1, 120)
                    : DefaultTimelineViewDurationSeconds;
                existing = new ProcessSessionTab
                {
                    Pid = pid,
                    Title = NormalizeSessionTitle(title),
                    CaptureStartUtc = AnchorCaptureStartUtc(initialDuration),
                    ViewDurationSeconds = initialDuration,
                    ViewStartSeconds = 0
                };
                _processTabs.Add(existing);
            }
            else
            {
                existing.Title = NormalizeSessionTitle(title);
            }

            if (select)
            {
                _suppressTabSelectionChange = true;
                ProcessTabs.SelectedItem = existing;
                _suppressTabSelectionChange = false;
            }

            return existing;
        }

        private static string NormalizeSessionTitle(string? title)
        {
            string value = string.IsNullOrWhiteSpace(title) ? "PID" : title.Trim();
            while (value.EndsWith("[EXITED]", StringComparison.OrdinalIgnoreCase))
            {
                value = value[..^"[EXITED]".Length].TrimEnd();
            }

            return value;
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
            SaveTabToBackingStore(_currentSession);
        }

        private void RestoreSessionState(ProcessSessionTab tab)
        {
            EnsureSessionMaterialized(tab);
            double restoredDuration = Math.Clamp(tab.ViewDurationSeconds <= 0 ? DefaultTimelineViewDurationSeconds : tab.ViewDurationSeconds, 1, 120);
            bool freshSession = !tab.OfflineSnapshot &&
                                tab.Events.Count == 0 &&
                                tab.PerformanceHistory.Count == 0 &&
                                tab.ThreadLifecycleHistory.Count == 0;
            if (freshSession)
            {
                tab.CaptureStartUtc = AnchorCaptureStartUtc(restoredDuration);
                tab.ViewStartSeconds = 0;
            }

            _captureStartUtc = tab.CaptureStartUtc == default ? AnchorCaptureStartUtc(restoredDuration) : tab.CaptureStartUtc;
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
            EventsPaneHost.Timeline.ViewDurationSeconds = restoredDuration;
            EventsPaneHost.Timeline.ViewStartSeconds = Math.Max(0, tab.ViewStartSeconds);
            UpdateScrollBar();
            EventsPaneHost.Scroll.Value = Math.Min(EventsPaneHost.Scroll.Maximum, EventsPaneHost.Timeline.ViewStartSeconds);
            FocusViewport();

            PerformancePaneHost.SetCaptureStart(_captureStartUtc);
            PerformancePaneHost.SetPid(tab.Pid);
            PerformancePaneHost.LoadHistory(tab.PerformanceHistory);
            PerformancePaneHost.LoadThreadLifecycleHistory(tab.ThreadLifecycleHistory);
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

            if (tab.OfflineSnapshot)
            {
                StopTargetExitWatcher();
                StopBackendSession();
                _perf?.Stop();
                _samplerPid = 0;
                PerformancePaneHost.SetProcessLiveDataAvailable(false);
                StatusBlock.Text = $"OFFLINE SESSION: {tab.Title}";
                RefreshProcessStateBadge();
                return;
            }

            if (tab.TargetExited)
            {
                StopTargetExitWatcher();
                StopBackendSession();
                _perf?.Stop();
                _samplerPid = 0;
                PerformancePaneHost.SetProcessLiveDataAvailable(false);
                StatusBlock.Text = $"Target {tab.Pid} exited. Capture stopped.";
                RefreshProcessStateBadge();
                return;
            }

            if (!TryOpenTargetProcess(tab.Pid, out _, out var failure, out var accessDenied))
            {
                StopTargetExitWatcher();
                StopBackendSession();
                _perf?.Stop();
                _samplerPid = 0;
                PerformancePaneHost.SetProcessLiveDataAvailable(false);
                if (!accessDenied)
                {
                    tab.TargetExited = true;
                    MarkSessionExited(tab);
                    StatusBlock.Text = $"Target {tab.Pid} exited. Capture stopped.";
                }
                else
                {
                    StatusBlock.Text = $"Access denied to PID {tab.Pid}. Capture stopped.";
                }
                RefreshProcessStateBadge();
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
            SetExplorerHasData("Events", _allEvents.Count > 0);
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
            if (UplinkStatusBlock == null || BottomStatusBar == null)
                return;

            if (healthy == true)
            {
                UplinkStatusBlock.Text = "UPLINK CONNECTED";
                UplinkStatusBlock.SetResourceReference(TextBlock.ForegroundProperty, "StatusConnectedBrush");
                BottomStatusBar.SetResourceReference(Border.BackgroundProperty, "StatusBarNeutralBrush");
                return;
            }

            if (healthy == false)
            {
                UplinkStatusBlock.Text = "UPLINK FAILED";
                UplinkStatusBlock.SetResourceReference(TextBlock.ForegroundProperty, "StatusFailedBrush");
                BottomStatusBar.SetResourceReference(Border.BackgroundProperty, "StatusBarFailedBrush");
                return;
            }

            UplinkStatusBlock.Text = "UPLINK CHECKING...";
            UplinkStatusBlock.SetResourceReference(TextBlock.ForegroundProperty, "WinMutedTextBrush");
            BottomStatusBar.SetResourceReference(Border.BackgroundProperty, "StatusBarNeutralBrush");
        }

        private void RefreshProcessStateBadge()
        {
            if (ProcessStateBadge == null || ProcessStateBlock == null)
            {
                return;
            }

            if (_currentSession == null || _currentSession.Pid <= 0)
            {
                SetProcessStateVisual("Disconnected", ProcessStateUnknownBackground, ProcessStateUnknownBorder, ProcessStateUnknownForeground);
                return;
            }

            string labelPrefix = $"PID {_currentSession.Pid}";
            if (_currentSession.OfflineSnapshot)
            {
                SetProcessStateVisual($"{labelPrefix} • Exited (offline capture)", ProcessStateExitedBackground, ProcessStateExitedBorder, ProcessStateExitedForeground);
                return;
            }

            if (_currentSession.TargetExited)
            {
                SetProcessStateVisual($"{labelPrefix} • Exited (capture available)", ProcessStateExitedBackground, ProcessStateExitedBorder, ProcessStateExitedForeground);
                return;
            }

            IntelScopeStatus scope = ((IIntelDetailsProvider)this).GetIntelScopeStatus();
            switch (scope)
            {
            case IntelScopeStatus.Running:
                SetProcessStateVisual($"{labelPrefix} • Connected / Running", ProcessStateRunningBackground, ProcessStateRunningBorder, ProcessStateRunningForeground);
                break;
            case IntelScopeStatus.Waiting:
                SetProcessStateVisual($"{labelPrefix} • Suspended / Waiting", ProcessStateWaitingBackground, ProcessStateWaitingBorder, ProcessStateWaitingForeground);
                break;
            case IntelScopeStatus.Exited:
                SetProcessStateVisual($"{labelPrefix} • Exited (capture available)", ProcessStateExitedBackground, ProcessStateExitedBorder, ProcessStateExitedForeground);
                break;
            default:
                SetProcessStateVisual($"{labelPrefix} • Connected / Unknown", ProcessStateUnknownBackground, ProcessStateUnknownBorder, ProcessStateUnknownForeground);
                break;
            }
        }

        private void SetProcessStateVisual(string text, Brush background, Brush border, Brush foreground)
        {
            ProcessStateBlock.Text = text;
            ProcessStateBadge.Background = background;
            ProcessStateBadge.BorderBrush = border;
            ProcessStateBlock.Foreground = foreground;
        }

        // -------------------------------
        // Scroll / viewport
        // -------------------------------
        private void Scroll_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            double viewport = Math.Max(1, EventsPaneHost.Scroll.ViewportSize);
            double maxStart = ComputeTimelineMaxStart(viewport);
            double clamped = Math.Max(0, Math.Min(maxStart, EventsPaneHost.Scroll.Value));
            _followLiveTimeline = maxStart <= 0.001 || Math.Abs(clamped - maxStart) < 0.25;
            _pendingScrollStartSeconds = clamped;
            EventsPaneHost.Timeline.ViewStartSeconds = clamped;

            if (_scrollSyncPending)
            {
                return;
            }

            _scrollSyncPending = true;
            Dispatcher.BeginInvoke(new Action(() =>
            {
                _scrollSyncPending = false;
                double replayViewport = Math.Max(1, EventsPaneHost.Scroll.ViewportSize);
                double replayMaxStart = ComputeTimelineMaxStart(replayViewport);
                double replayStart = Math.Max(0, Math.Min(replayMaxStart, _pendingScrollStartSeconds));
                EventsPaneHost.Timeline.ViewStartSeconds = replayStart;
                FocusViewport();
                UpdateTopTimeTravelBar();
                SyncPerformanceViewToTimeline();
            }), DispatcherPriority.Render);
        }

        private void UpdateScrollBar()
        {
            if (_allEvents.Count == 0)
            {
                EventsPaneHost.Scroll.Maximum = 0;
                EventsPaneHost.Scroll.ViewportSize = 1;
                EventsPaneHost.Scroll.SmallChange = 1;
                EventsPaneHost.Scroll.LargeChange = 1;
                EventsPaneHost.Scroll.Value = 0;
                EventsPaneHost.Timeline.ViewStartSeconds = 0;
                _latestEventTimestampUtc = _captureStartUtc;
                UpdateTopTimeTravelBar();
                return;
            }

            var totalSeconds = (_latestEventTimestampUtc - _captureStartUtc).TotalSeconds;
            if (totalSeconds < 0)
            {
                totalSeconds = 0;
            }

            double duration = Math.Max(1, EventsPaneHost.Timeline.ViewDurationSeconds);
            double maxValue = Math.Max(duration, totalSeconds);
            EventsPaneHost.Scroll.ViewportSize = duration;
            EventsPaneHost.Scroll.Maximum = maxValue;
            EventsPaneHost.Scroll.SmallChange = Math.Max(1, duration / 20.0);
            EventsPaneHost.Scroll.LargeChange = Math.Max(1, duration * 0.8);

            double maxStart = Math.Max(0, maxValue - duration);
            if (EventsPaneHost.Timeline.ViewStartSeconds > maxStart)
            {
                EventsPaneHost.Timeline.ViewStartSeconds = maxStart;
            }

            if (EventsPaneHost.Scroll.Value > maxStart)
            {
                EventsPaneHost.Scroll.Value = maxStart;
            }

            UpdateTopTimeTravelBar();
        }

        private void FocusViewport()
        {
            var viewStart = _captureStartUtc + TimeSpan.FromSeconds(EventsPaneHost.Timeline.ViewStartSeconds);
            var viewEnd = viewStart + TimeSpan.FromSeconds(EventsPaneHost.Timeline.ViewDurationSeconds);

            double durationSeconds = Math.Max(1, (viewEnd - viewStart).TotalSeconds);
            RangeBlock.Text = $"Range {viewStart:HH:mm:ss} | {viewEnd:HH:mm:ss}  ({durationSeconds:0}s)";

            _focusedEvents.Clear();
            if (_allEvents.Count == 0)
            {
                SetExplorerHasData("Events", false);
                EventsPaneHost.SetHeaderStats("View 0 | Total 0 | 0.0/s");
                UpdateDetachedEventLogWindow();
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

            FindExplorerItem("Events")?.PushPreviewValue(_focusedEvents.Count);
            SetExplorerHasData("Events", _allEvents.Count > 0);
            double viewSeconds = Math.Max(1.0, EventsPaneHost.Timeline.ViewDurationSeconds);
            double rate = _focusedEvents.Count / viewSeconds;
            EventsPaneHost.SetHeaderStats($"View {_focusedEvents.Count} | Total {_allEvents.Count} | {rate:0.0}/s");
            UpdateDetachedEventLogWindow();
            UpdateTopTimeTravelBar();
        }

        private void UpdateTopTimeTravelBar()
        {
            if (TopTimeTravelSlider == null || TopTimeTravelRangeBlock == null || EventsPaneHost?.Scroll == null || EventsPaneHost?.Timeline == null)
            {
                return;
            }

            double viewport = Math.Max(1, EventsPaneHost.Scroll.ViewportSize);
            double maxStart = ComputeTimelineMaxStart(viewport);
            double start = Math.Max(0, Math.Min(maxStart, EventsPaneHost.Timeline.ViewStartSeconds));

            _topTimeTravelSyncing = true;
            TopTimeTravelSlider.Minimum = 0;
            TopTimeTravelSlider.Maximum = Math.Max(0, maxStart);
            TopTimeTravelSlider.Value = start;
            TopTimeTravelSlider.SmallChange = Math.Max(1, viewport / 30.0);
            TopTimeTravelSlider.LargeChange = Math.Max(1, viewport * 0.5);
            TopTimeTravelSlider.IsEnabled = maxStart > 0.001;
            _topTimeTravelSyncing = false;

            DateTime viewStart = _captureStartUtc + TimeSpan.FromSeconds(start);
            DateTime viewEnd = viewStart + TimeSpan.FromSeconds(viewport);
            TopTimeTravelRangeBlock.Text = $"{viewStart:HH:mm:ss} | {viewEnd:HH:mm:ss}";
        }

        private void TopTimeTravelSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (_topTimeTravelSyncing || EventsPaneHost?.Scroll == null || EventsPaneHost?.Timeline == null)
            {
                return;
            }

            double viewport = Math.Max(1, EventsPaneHost.Scroll.ViewportSize);
            double maxStart = ComputeTimelineMaxStart(viewport);
            double targetStart = Math.Max(0, Math.Min(maxStart, e.NewValue));
            _followLiveTimeline = maxStart <= 0.001 || Math.Abs(targetStart - maxStart) < 0.25;
            EventsPaneHost.Scroll.Value = targetStart;
            EventsPaneHost.Timeline.ViewStartSeconds = targetStart;
            FocusViewport();
            SyncPerformanceViewToTimeline();
        }

        private void NudgeTopTimeTravel(double secondsDelta)
        {
            if (EventsPaneHost?.Scroll == null || EventsPaneHost?.Timeline == null)
            {
                return;
            }

            double viewport = Math.Max(1, EventsPaneHost.Scroll.ViewportSize);
            double maxStart = ComputeTimelineMaxStart(viewport);
            double current = EventsPaneHost.Scroll.Value;
            double target = Math.Max(0, Math.Min(maxStart, current + secondsDelta));
            _followLiveTimeline = maxStart <= 0.001 || Math.Abs(target - maxStart) < 0.25;
            EventsPaneHost.Scroll.Value = target;
            EventsPaneHost.Timeline.ViewStartSeconds = target;
            FocusViewport();
            SyncPerformanceViewToTimeline();
        }

        private void TopTimeTravelBack10_Click(object sender, RoutedEventArgs e) => NudgeTopTimeTravel(-10);
        private void TopTimeTravelBack1_Click(object sender, RoutedEventArgs e) => NudgeTopTimeTravel(-1);
        private void TopTimeTravelForward1_Click(object sender, RoutedEventArgs e) => NudgeTopTimeTravel(1);
        private void TopTimeTravelForward10_Click(object sender, RoutedEventArgs e) => NudgeTopTimeTravel(10);

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
                if (_followLiveTimeline && EventsPaneHost?.Scroll != null)
                {
                    double viewport = Math.Max(1, EventsPaneHost.Scroll.ViewportSize);
                    double maxStart = ComputeTimelineMaxStart(viewport);
                    EventsPaneHost.Timeline.ViewStartSeconds = maxStart;
                    EventsPaneHost.Scroll.Value = maxStart;
                }
                FocusViewport();
            }), System.Windows.Threading.DispatcherPriority.Background);
        }

        private double ComputeTimelineMaxStart(double viewportSeconds)
        {
            if (EventsPaneHost?.Scroll == null)
            {
                return 0;
            }

            double viewport = Math.Max(1, viewportSeconds);
            double lastEventSeconds = _allEvents.Count > 0
                ? Math.Max(0, (_allEvents[^1].TimestampUtc - _captureStartUtc).TotalSeconds)
                : 0;
            double maximum = Math.Max(viewport, Math.Max(EventsPaneHost.Scroll.Maximum, lastEventSeconds));
            return Math.Max(0, maximum - viewport);
        }

        private static DateTime AnchorCaptureStartUtc(double viewDurationSeconds)
        {
            double seconds = Math.Max(1, viewDurationSeconds);
            return DateTime.UtcNow - TimeSpan.FromSeconds(seconds);
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
            _followLiveTimeline = false;
            var dur = (e.EndUtc - e.StartUtc).TotalSeconds;
            double newDuration = Math.Min(120, Math.Max(1, dur));

            EventsPaneHost.Timeline.ViewDurationSeconds = newDuration;
            UpdateScrollBar();

            var startSeconds = (e.StartUtc - _captureStartUtc).TotalSeconds;
            if (startSeconds < 0) startSeconds = 0;
            double maxStart = Math.Max(0, EventsPaneHost.Scroll.Maximum - EventsPaneHost.Scroll.ViewportSize);
            if (startSeconds > maxStart) startSeconds = maxStart;

            EventsPaneHost.Timeline.ViewStartSeconds = startSeconds;
            EventsPaneHost.Scroll.Value = startSeconds;

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
        private void Timeline_EventDoubleClicked(object? sender, TelemetryEventSelectedEventArgs e)
        {
            _ = sender;
            _ = e;
        }

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
            var sw = FindExplorerItem("ETW");
            if (sw != null) sw.IsEnabled = false;
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

        private void HideFilesystemPane()
        {
            var fs = FindExplorerItem("Filesystem");
            if (fs != null) fs.IsEnabled = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void HideProcessRelationsPane()
        {
            var rel = FindExplorerItem("Process Relations");
            if (rel != null) rel.IsEnabled = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void SetExplorerPaneEnabled(string name, bool enabled)
        {
            var item = FindExplorerItem(name);
            if (item != null)
            {
                item.IsEnabled = enabled;
            }
        }

        private void ShowEtwPane()
        {
            SetExplorerPaneEnabled("ETW", true);
            ApplyDockVisibilityFromExplorer();
        }

        private void ShowHeuristicsPane()
        {
            SetExplorerPaneEnabled("Heuristics", true);
            ApplyDockVisibilityFromExplorer();
        }

        private void ShowIpcUplinkPane()
        {
            SetExplorerPaneEnabled("IPC Uplink", true);
            ApplyDockVisibilityFromExplorer();
        }

        private void ShowFilesystemPane()
        {
            SetExplorerPaneEnabled("Filesystem", true);
            ApplyDockVisibilityFromExplorer();
        }

        private void ShowProcessRelationsPane()
        {
            SetExplorerPaneEnabled("Process Relations", true);
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

        private void OpenOrActivateEventLogWindow()
        {
            if (_eventLogWindow == null)
            {
                UndockEventLog();
                return;
            }

            if (_eventLogWindow.WindowState == WindowState.Minimized)
            {
                _eventLogWindow.WindowState = WindowState.Normal;
            }
            _eventLogWindow.Activate();
        }

        private void OpenDiagnosticsWindow()
        {
            var w = new DiagnosticsWindow(TryGetPid())
            {
                Owner = this
            };
            w.Show();
        }

        private void ToolbarViewMenu_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = e;
            if (_toolbarViewMenuSyncing || !IsLoaded || sender is not ComboBox combo)
            {
                return;
            }

            string tag = combo.SelectedItem switch
            {
                ComboBoxItem item when item.Tag is string itemTag => itemTag,
                _ => string.Empty
            };
            if (string.IsNullOrWhiteSpace(tag))
            {
                return;
            }

            switch (tag)
            {
                case "events":
                    SetExplorerPaneEnabled("Events", true);
                    ShowEventsPane();
                    break;
                case "performance":
                    SetExplorerPaneEnabled("Performance", true);
                    ShowPerformancePane();
                    break;
                case "etw":
                    ShowEtwPane();
                    break;
                case "heuristics":
                    ShowHeuristicsPane();
                    break;
                case "filesystem":
                    ShowFilesystemPane();
                    break;
                case "process-relations":
                    ShowProcessRelationsPane();
                    break;
                case "ipc-uplink":
                    ShowIpcUplinkPane();
                    break;
                case "event-log":
                    SetExplorerPaneEnabled("Events", true);
                    ShowEventsPane();
                    OpenOrActivateEventLogWindow();
                    break;
                case "inspector-etw":
                    ShowEtwPane();
                    OpenEtwInspector();
                    break;
                case "inspector-heuristics":
                    ShowHeuristicsPane();
                    OpenHeuristicsInspector();
                    break;
                case "inspector-filesystem":
                    ShowFilesystemPane();
                    OpenFilesystemInspector();
                    break;
                case "inspector-relations":
                    ShowProcessRelationsPane();
                    OpenProcessRelationsInspector();
                    break;
                case "diagnostics":
                    OpenDiagnosticsWindow();
                    break;
            }

            combo.SelectedIndex = 0;
            RebuildToolbarViewMenuOptions();
        }

        private void ToolbarViewMenu_DropDownOpened(object sender, EventArgs e)
        {
            _ = sender;
            _ = e;
            RebuildToolbarViewMenuOptions();
        }

        private void RebuildToolbarViewMenuOptions()
        {
            if (ToolbarViewMenu == null)
            {
                return;
            }

            _toolbarViewMenuSyncing = true;
            ToolbarViewMenu.Items.Clear();
            ToolbarViewMenu.Items.Add(new ComboBoxItem { Content = "Open Window..." });

            AddToolbarViewOptionIfClosed("Events Pane", "events", IsEventsPaneOpen());
            AddToolbarViewOptionIfClosed("Performance Pane", "performance", IsPerformancePaneOpen());
            AddToolbarViewOptionIfClosed("ETW Pane", "etw", IsEtwPaneOpen());
            AddToolbarViewOptionIfClosed("Heuristics Pane", "heuristics", IsHeuristicsPaneOpen());
            AddToolbarViewOptionIfClosed("Filesystem Pane", "filesystem", IsFilesystemPaneOpen());
            AddToolbarViewOptionIfClosed("Process Relations Pane", "process-relations", IsRelationsPaneOpen());
            AddToolbarViewOptionIfClosed("IPC Uplink Pane", "ipc-uplink", IsIpcUplinkPaneOpen());
            AddToolbarViewOptionIfClosed("Event Log Window", "event-log", _eventLogWindow != null && _eventLogWindow.IsVisible);
            AddToolbarViewOptionIfClosed("ETW Inspector", "inspector-etw", IsWindowOpenByTitle("ETW Inspector"));
            AddToolbarViewOptionIfClosed("Heuristics Inspector", "inspector-heuristics", IsWindowOpenByTitle("Detection Chain"));
            AddToolbarViewOptionIfClosed("Filesystem Inspector", "inspector-filesystem", IsWindowOpenByTitle("Filesystem"));
            AddToolbarViewOptionIfClosed("Process Relations Inspector", "inspector-relations", IsWindowOpenByTitle("Process Relations"));
            AddToolbarViewOptionIfClosed("Diagnostics Window", "diagnostics", Application.Current.Windows.OfType<Window>().Any(w => w is DiagnosticsWindow && w.IsVisible));

            ToolbarViewMenu.SelectedIndex = 0;
            _toolbarViewMenuSyncing = false;
        }

        private void AddToolbarViewOptionIfClosed(string label, string tag, bool isOpen)
        {
            if (ToolbarViewMenu == null || isOpen)
            {
                return;
            }

            ToolbarViewMenu.Items.Add(new ComboBoxItem
            {
                Content = label,
                Tag = tag
            });
        }

        private bool IsEventsPaneOpen()
            => (FindExplorerItem("Events")?.IsEnabled ?? true) && (_eventsPaneVisible || _eventsPaneFloating || _eventsFloatWindow != null);

        private bool IsPerformancePaneOpen()
            => (FindExplorerItem("Performance")?.IsEnabled ?? true) && (_performancePaneVisible || _performancePaneFloating || _performanceFloatWindow != null);

        private bool IsEtwPaneOpen()
            => (FindExplorerItem("ETW")?.IsEnabled ?? true);

        private bool IsHeuristicsPaneOpen()
            => (FindExplorerItem("Heuristics")?.IsEnabled ?? true);

        private bool IsFilesystemPaneOpen()
            => (FindExplorerItem("Filesystem")?.IsEnabled ?? true);

        private bool IsRelationsPaneOpen()
            => (FindExplorerItem("Process Relations")?.IsEnabled ?? true);

        private bool IsIpcUplinkPaneOpen()
            => (FindExplorerItem("IPC Uplink")?.IsEnabled ?? false);

        private static bool IsWindowOpenByTitle(string title)
            => Application.Current?.Windows
                   .OfType<Window>()
                   .Any(w => w.IsVisible && string.Equals(w.Title, title, StringComparison.OrdinalIgnoreCase)) ?? false;

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

        private void ToggleEventLogDock()
        {
            if (_eventLogWindow == null)
            {
                UndockEventLog();
            }
            else
            {
                RedockEventLog();
            }
        }

        private void UndockEventLog()
        {
            if (_eventLogWindow != null)
            {
                return;
            }

            _eventLogWindow = new EventLogWindow
            {
                Owner = this,
                ShowInTaskbar = false
            };
            _eventLogWindow.EtwFeedRequested += EventLogWindow_EtwFeedRequested;
            _eventLogWindow.Closed += EventLogWindow_Closed;
            EventsPaneHost.SetEventLogDetached(true);
            UpdateDetachedEventLogWindow(immediate: true);
            _eventLogWindow.Show();
        }

        private void RedockEventLog()
        {
            if (_eventLogWindow != null)
            {
                _eventLogWindow.EtwFeedRequested -= EventLogWindow_EtwFeedRequested;
                _eventLogWindow.Closed -= EventLogWindow_Closed;
                _eventLogWindow.Close();
                _eventLogWindow = null;
            }

            EventsPaneHost.SetEventLogDetached(false);
        }

        private void EventLogWindow_Closed(object? sender, EventArgs e)
        {
            if (_eventLogWindow != null)
            {
                _eventLogWindow.EtwFeedRequested -= EventLogWindow_EtwFeedRequested;
            }
            _eventLogWindow = null;
            EventsPaneHost.SetEventLogDetached(false);
        }

        private void DetachedEventLogRefreshTimer_Tick(object? sender, EventArgs e)
        {
            _detachedEventLogRefreshTimer.Stop();
            _eventLogWindow?.RefreshEvents(_focusedEvents);
        }

        private void UpdateDetachedEventLogWindow(bool immediate = false)
        {
            if (_eventLogWindow == null)
            {
                return;
            }

            if (immediate)
            {
                _detachedEventLogRefreshTimer.Stop();
                _eventLogWindow.RefreshEvents(_focusedEvents);
                return;
            }

            _detachedEventLogRefreshTimer.Stop();
            _detachedEventLogRefreshTimer.Start();
        }

        private void EventLogWindow_EtwFeedRequested(object? sender, EventLogCardOpenRequestedEventArgs e)
        {
            _ = sender;
            _ = e;
        }

        private void EventsPaneHost_EventLogEntryOpenRequested(object? sender, EventLogEntryOpenRequestedEventArgs e)
        {
            _ = sender;
            _ = e;
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
            _eventLogWindow?.Close();
            _performanceFloatWindow?.Close();
            _etwFloatWindow?.Close();
            _heuristicsFloatWindow?.Close();

            _laneFocusKey = null;
            EventsPaneHost.Timeline.ClearAllLaneFilters();
            EventsPaneHost.Timeline.ViewDurationSeconds = 120;
            EventsPaneHost.Timeline.ViewStartSeconds = 0;
            EventsPaneHost.Scroll.Value = 0;
            _followLiveTimeline = true;
            ShowEventsPane();
            ShowPerformancePane();
            var sw = FindExplorerItem("ETW");
            if (sw != null) sw.IsEnabled = true;
            var heur = FindExplorerItem("Heuristics");
            if (heur != null) heur.IsEnabled = true;
            var fs = FindExplorerItem("Filesystem");
            if (fs != null) fs.IsEnabled = true;
            var rel = FindExplorerItem("Process Relations");
            if (rel != null) rel.IsEnabled = true;
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

        private void DockEventsToggle_Click(object sender, RoutedEventArgs e)
        {
            ToggleFloatDock();
        }

        private void DockPerfToggle_Click(object sender, RoutedEventArgs e)
        {
            TogglePerformanceFloatDock();
        }

        private void DockEtwToggle_Click(object sender, RoutedEventArgs e)
        {
            ToggleEtwFloatDock();
        }

        private void DockHeurToggle_Click(object sender, RoutedEventArgs e)
        {
            ToggleHeuristicsFloatDock();
        }

        private void DockSwapMain_Click(object sender, RoutedEventArgs e)
        {
            TogglePaneOrder();
        }

        private void DockSwapIntel_Click(object sender, RoutedEventArgs e)
        {
            ToggleIntelPaneOrder();
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
            _ = sender;
            _ = e;
            OpenDiagnosticsWindow();
        }

        private void PerformancePaneHost_ThreadDoubleClicked(object? sender, ThreadUsageRow row)
        {
            int pid = _currentSession?.Pid ?? TryGetPid();
            var w = new ThreadStackWindow(
                pid,
                row.Tid,
                row.State,
                observationTimeUtcProvider: GetCurrentObservedUtc,
                liveCaptureAvailableProvider: () =>
                    _currentSession != null &&
                    _currentSession.Pid == pid &&
                    !_currentSession.TargetExited &&
                    !_currentSession.OfflineSnapshot)
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
                PerformancePaneHost.SetProcessLiveDataAvailable(false);
                StatusBlock.Text = "NO TARGET SELECTED";
                RefreshProcessStateBadge();
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
            RefreshProcessStateBadge();
        }

        private DateTime GetCurrentObservedUtc()
        {
            if (EventsPaneHost?.Timeline == null)
            {
                return DateTime.UtcNow;
            }

            return _captureStartUtc +
                   TimeSpan.FromSeconds(EventsPaneHost.Timeline.ViewStartSeconds + EventsPaneHost.Timeline.ViewDurationSeconds);
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
                RefreshProcessStateBadge();
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

                RefreshProcessStateBadge();
                return;
            }

            StatusBlock.Text = $"CONNECTED TO {processName} ({pid})";
            var tab = AddOrSelectProcessTab(pid, $"{processName} ({pid})", select: true);
            tab.TargetExited = false;
            tab.OfflineSnapshot = false;
            if (!ReferenceEquals(_currentSession, tab))
            {
                SwitchToSession(tab);
            }
            else
            {
                StartLiveCaptureForPid(pid);
            }

            _ = RunPreflightAsync(pid);
            RefreshProcessStateBadge();
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

                loading.SetProgress(100, "Opening picker...", "Process picker will stream process metadata after opening.");
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

        internal void ConnectToStartupPid(int pid)
        {
            if (pid <= 0)
            {
                return;
            }

            PidBox.Text = pid.ToString();
            Connect_Click(this, new RoutedEventArgs());
        }

        internal async Task BeginStartupLaunchFlowAsync()
        {
            await OpenProcessPickerAndConnectAsync();
        }

        internal bool TryOpenSessionFromStartupPath(string path, out string error)
        {
            return TryOpenSessionArchivePath(path, merge: false, out error);
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
                    WaitReason = t.WaitReason,
                    Kind = t.Kind,
                    StartTimeUtc = t.StartTimeUtc
                }).ToList(),
                MemoryMetrics = src.MemoryMetrics.Select(m => new MemoryMetricSample
                {
                    Metric = m.Metric,
                    Value = m.Value,
                    BytesValue = m.BytesValue
                }).ToList(),
                MemoryPages = src.MemoryPages.Select(m => new MemoryPageSample
                {
                    BaseAddress = m.BaseAddress,
                    RegionSize = m.RegionSize,
                    State = m.State,
                    Protect = m.Protect,
                    Type = m.Type,
                    StateLabel = m.StateLabel,
                    ProtectLabel = m.ProtectLabel,
                    TypeLabel = m.TypeLabel,
                    Category = m.Category
                }).ToList()
            };
        }

        private static ThreadLifecycleEventSample CloneThreadLifecycleEvent(ThreadLifecycleEventSample src)
        {
            return new ThreadLifecycleEventSample
            {
                TimestampUtc = src.TimestampUtc,
                ProcessPid = src.ProcessPid,
                ThreadId = src.ThreadId,
                CreatorPid = src.CreatorPid,
                Flags = src.Flags,
                StartAddress = src.StartAddress,
                ImageBase = src.ImageBase,
                ImageSize = src.ImageSize,
                EventKind = src.EventKind,
                Notes = src.Notes
            };
        }

        // Lane focus API used by LaneSettingsWindow
        public void SetLaneFocus(string? laneKey)
        {
            _laneFocusKey = string.IsNullOrWhiteSpace(laneKey) ? null : laneKey;
            FocusViewport();
        }

        public string? GetLaneFocus() => _laneFocusKey;

    }

    public sealed class ProcessSessionTab : INotifyPropertyChanged
    {
        private int _pid;
        private string _title = "";
        public List<TelemetryEvent> Events { get; } = new();
        public List<PerformanceSample> PerformanceHistory { get; } = new();
        public List<ThreadLifecycleEventSample> ThreadLifecycleHistory { get; } = new();
        public DateTime CaptureStartUtc { get; set; } = DateTime.UtcNow;
        public double ViewDurationSeconds { get; set; } = 120;
        public double ViewStartSeconds { get; set; }
        public string? LaneFocusKey { get; set; }
        public bool TargetExited { get; set; }
        public bool OfflineSnapshot { get; set; }
        public string? BackingStorePath { get; set; }

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
