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
    public partial class MainWindow : Window, IIntelDetailsProvider
    {
        private readonly TelemetryEventStore _allEvents = new();
        private readonly BulkObservableCollection<TelemetryEvent> _focusedEvents = new();
        private readonly Dictionary<EventSelectionKey, IReadOnlyList<TelemetryEvent>> _focusedClusterMembers = new();
        private readonly BoundedStringPool _telemetryTextPool = new(8192);
        private readonly HashSet<string> _knownLaneKeys = new(StringComparer.Ordinal);
        private const double DefaultTimelineViewDurationSeconds = 120;
        private const int MaxControllerLaunchArgumentChars = 2048;
        private const int HookControllerCallTimeoutSeconds = 30;
        private static readonly TimeSpan HookControllerCallTimeout =
            TimeSpan.FromSeconds(HookControllerCallTimeoutSeconds);
        private bool _viewportRefreshPending;
        private DateTime _latestEventTimestampUtc;

        private DateTime _captureStartUtc;
        private EventsFloatWindow? _eventsFloatWindow;
        private EventLogWindow? _eventLogWindow;
        private PerformanceFloatWindow? _performanceFloatWindow;
        private EtwFloatWindow? _etwFloatWindow;
        private HeuristicsFloatWindow? _heuristicsFloatWindow;
        private ChildProcessGraphWindow? _childProcessGraphWindow;
        private bool _eventsPaneVisible = true;
        private bool _performancePaneVisible = true;
        private bool _eventsPaneFloating;
        private bool _performancePaneFloating;
        private bool _etwPaneFloating;
        private bool _heuristicsPaneFloating;
        private bool _heuristicsOnTop;

        private string? _laneFocusKey;

        private PerformanceSampler? _perf;

        private readonly ObservableCollection<GraphExplorerItem> _explorer = new();
        private readonly ObservableCollection<ProcessSessionTab> _processTabs = new();
        private readonly int _defaultPid = Process.GetCurrentProcess().Id;
        private bool _suppressTabSelectionChange;
        private ProcessSessionTab? _currentSession;
        private int _samplerPid;
        private bool _performanceOnTop;
        private bool _hasPerformanceData;
        private bool _connectivityHealthy = true;
        private bool _draggingEventsPaneHeader;
        private bool _draggingPerformancePaneHeader;
        private bool _openingProcessPicker;
        private bool _connectInProgress;
        private bool _pendingLaunchOptions;
        private bool _pendingUseUsermodeHooks;
        private bool _pendingAutoOpenApiGraph;
        private bool _pendingHookPreconfigured;
        private bool _pendingLaunchStartsSuspended;
        private bool _pendingLeaveSuspendedAfterReady;
        private bool _pendingLaunchOwnedByInterface;
        private bool _hookControllerCallInFlight;
        private AnalysisOperationGuard? _activeAnalysisOperation;
        private LiveAnalysisSessionLease? _liveAnalysisSession;
        private ProcessSessionTab? _queuedSessionSwitchTab;
        private bool _sessionSwitchQueued;
        private LaunchTargetKind _pendingAnalysisSubjectKind = LaunchTargetKind.Executable;
        private string _pendingAnalysisSubjectPath = string.Empty;
        private string _pendingAnalysisHostPath = string.Empty;
        private bool _isMainWindowShuttingDown;
        private BlackbirdBackendSession? _preparedLaunchBackendSession;
        private int _preparedLaunchBackendPid;
        private MainInterfaceViewMode _mainViewMode = MainInterfaceViewMode.Telemetry;
        private readonly BulkObservableCollection<ApiCallGraphMainRowView> _apiViewRows = new();
        private readonly BulkObservableCollection<ExtendedActivityRowSnapshot> _extendedViewRows = new();
        private readonly BulkObservableCollection<ExtendedActivityRowSnapshot> _extendedComRows = new();
        private readonly BulkObservableCollection<ExtendedActivityRowSnapshot> _extendedEtwRows = new();
        private readonly BulkObservableCollection<ExtendedActivityRowSnapshot> _extendedJobRows = new();
        private readonly BulkObservableCollection<ExtendedActivityRowSnapshot> _extendedYaraRows = new();
        private Process? _targetExitWatchProcess;
        private int _targetExitWatchPid;
        private Vector _floatingPaneDragOffset;
        private readonly DispatcherTimer _detachedEventLogRefreshTimer;
        private readonly DispatcherTimer _processStateRefreshTimer;
        private readonly DispatcherTimer _apiGraphRefreshTimer;
        private readonly DispatcherTimer _extendedViewRefreshTimer;
        private readonly DispatcherTimer _childProcessGraphRefreshTimer;
        private readonly DispatcherTimer _timelineLiveTickTimer;
        private bool _scrollSyncPending;
        private bool _topTimeTravelSyncing;
        private bool _toolbarViewMenuSyncing;
        private bool _followLiveTimeline = true;
        private bool _eventSelectionSyncing;
        private EventSelectionKey? _selectedEventAnchor;
        private double _pendingScrollStartSeconds;
        private bool _targetExecutionSuspended;
        private bool _signatureIntelEnabled = true;
        private bool _signatureIntelMemoryScanEnabled;
        private bool _signatureIntelPageScanEnabled;
        private readonly List<ApiCallGraphMainRowView> _apiViewSnapshotRows = new();
        private readonly List<ApiCallGraphRowSnapshot> _apiGraphSnapshotRows = new();
        private ApiViewPresentationMode _apiViewPresentationMode;
        private DateTime _scopeStatusCacheUtc;
        private int _scopeStatusCachePid;
        private IntelScopeStatus _scopeStatusCache = IntelScopeStatus.Unknown;
        private static readonly Brush ProcessStateRunningBackground =
            new SolidColorBrush(Color.FromRgb(0x14, 0x3A, 0x1E));
        private static readonly Brush ProcessStateRunningBorder = new SolidColorBrush(Color.FromRgb(0x49, 0xC1, 0x66));
        private static readonly Brush ProcessStateRunningForeground =
            new SolidColorBrush(Color.FromRgb(0xA9, 0xF5, 0xB8));
        private static readonly Brush ProcessStateWaitingBackground =
            new SolidColorBrush(Color.FromRgb(0x3D, 0x34, 0x16));
        private static readonly Brush ProcessStateWaitingBorder = new SolidColorBrush(Color.FromRgb(0xDE, 0xC2, 0x62));
        private static readonly Brush ProcessStateWaitingForeground =
            new SolidColorBrush(Color.FromRgb(0xF8, 0xE9, 0xAF));
        private static readonly Brush ProcessStateExitedBackground =
            new SolidColorBrush(Color.FromRgb(0x28, 0x1A, 0x1A));
        private static readonly Brush ProcessStateExitedBorder = new SolidColorBrush(Color.FromRgb(0x73, 0x4A, 0x4A));
        private static readonly Brush ProcessStateExitedForeground =
            new SolidColorBrush(Color.FromRgb(0xE1, 0xB4, 0xB4));
        private static readonly Brush ProcessStateUnknownBackground =
            new SolidColorBrush(Color.FromRgb(0x1E, 0x1E, 0x1E));
        private static readonly Brush ProcessStateUnknownBorder = new SolidColorBrush(Color.FromRgb(0x4A, 0x4A, 0x4A));
        private static readonly Brush ProcessStateUnknownForeground =
            new SolidColorBrush(Color.FromRgb(0xB8, 0xB8, 0xB8));
        private static readonly Brush ToolbarInactiveBackground = new SolidColorBrush(Color.FromRgb(0x18, 0x18, 0x18));
        private static readonly Brush ToolbarInactiveBorder = new SolidColorBrush(Color.FromRgb(0x46, 0x46, 0x46));
        private static readonly Brush ToolbarInactiveForeground = new SolidColorBrush(Color.FromRgb(0x7A, 0x7A, 0x7A));
        private static readonly Brush ToolbarTargetBackground = new SolidColorBrush(Color.FromRgb(0x4C, 0x14, 0x18));
        private static readonly Brush ToolbarTargetBorder = new SolidColorBrush(Color.FromRgb(0xE0, 0x52, 0x5A));
        private static readonly Brush ToolbarTargetForeground = new SolidColorBrush(Color.FromRgb(0xFF, 0xC6, 0xCB));
        private static readonly Brush ToolbarPauseBackground = new SolidColorBrush(Color.FromRgb(0x3B, 0x24, 0x11));
        private static readonly Brush ToolbarPauseBorder = new SolidColorBrush(Color.FromRgb(0xE1, 0x92, 0x2C));
        private static readonly Brush ToolbarPauseForeground = new SolidColorBrush(Color.FromRgb(0xF0, 0xAB, 0x4B));
        private static readonly Brush ToolbarResumeBackground = new SolidColorBrush(Color.FromRgb(0x14, 0x35, 0x1C));
        private static readonly Brush ToolbarResumeBorder = new SolidColorBrush(Color.FromRgb(0x4C, 0xC5, 0x68));
        private static readonly Brush ToolbarResumeForeground = new SolidColorBrush(Color.FromRgb(0x98, 0xEF, 0xAD));
        private static readonly Brush ToolbarStopBackground = new SolidColorBrush(Color.FromRgb(0x3D, 0x15, 0x1A));
        private static readonly Brush ToolbarStopBorder = new SolidColorBrush(Color.FromRgb(0xD6, 0x43, 0x43));
        private static readonly Brush ToolbarStopForeground = new SolidColorBrush(Color.FromRgb(0xF0, 0x74, 0x74));
        private const string WindowTitleBase = "Blackbird";

        private const uint ProcessTerminate = 0x0001;
        private const uint ProcessSynchronize = 0x00100000;
        private const uint ProcessSuspendResume = 0x0800;
        private const uint ProcessVmRead = 0x0010;
        private const uint ProcessQueryLimitedInformation = 0x1000;

        private enum MainInterfaceViewMode
        {
            Telemetry = 0,
            Api = 1,
            Extended = 2
        }

        private enum ApiViewPresentationMode
        {
            CallGraph = 0,
            ThreadTimeline = 1
        }

        public MainWindow()
        {
            InitializeComponent();
            if (Kernel32Native.EnableDebugPrivilege(out int debugPrivilegeError))
            {
                DiagnosticsState.SetValue("Target Handle Access", "SeDebugPrivilege enabled");
            }
            else
            {
                DiagnosticsState.SetValue("Target Handle Access",
                                          $"SeDebugPrivilege unavailable win32={debugPrivilegeError}");
            }
            if (ApiViewModeBox != null)
            {
                ApiViewModeBox.SelectedIndex = 0;
            }
            InitializeSignatureIntelSubsystem();
            InitializeInterfaceSettings();
            SetResourceReference(BackgroundProperty, "WinBgBrush");
            RootGrid.SetResourceReference(Panel.BackgroundProperty, "WinBgBrush");
            WindowThemeHelper.WireThemeAwareTitleBar(this);
            _detachedEventLogRefreshTimer =
                new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(110) };
            _detachedEventLogRefreshTimer.Tick += DetachedEventLogRefreshTimer_Tick;
            _processStateRefreshTimer =
                new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(900) };
            _processStateRefreshTimer.Tick += (_, __) =>
            {
                ValidateCurrentSessionState();
                RefreshProcessStateBadge();
            };
            _apiGraphRefreshTimer =
                new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(180) };
            _apiGraphRefreshTimer.Tick += ApiGraphRefreshTimer_Tick;
            _extendedViewRefreshTimer =
                new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(220) };
            _extendedViewRefreshTimer.Tick += (_, __) => FlushExtendedActivitySnapshot();
            _childProcessGraphRefreshTimer =
                new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(140) };
            _childProcessGraphRefreshTimer.Tick += ChildProcessGraphRefreshTimer_Tick;
            _timelineLiveTickTimer =
                new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(250) };
            _timelineLiveTickTimer.Tick += (_, __) =>
            {
                if (_followLiveTimeline && _allEvents.Count > 0 && !_viewportRefreshPending)
                {
                    UpdateScrollBar();
                    double viewport = Math.Max(1, EventsPaneHost?.Scroll?.ViewportSize ?? 1);
                    ApplyTimelineViewport(ComputeTimelineMaxStart(viewport), syncScroll: true,
                                          updateFollowState: false);
                }
            };
            Loaded += OnLoaded;
            Closing += OnClosing;
            Closed += OnClosed;
            RefreshToolbarCommandState();
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            PidBox.Text = string.Empty;
            _samplerPid = 0;

            _captureStartUtc = AnchorCaptureStartUtc(DefaultTimelineViewDurationSeconds);
            _latestEventTimestampUtc = _captureStartUtc;

            EventsPaneHost.Grid.ItemsSource = _focusedEvents;
            EventsPaneHost.SetHasData(false);
            EventsPaneHost.SetEventLogDetached(false);

            EventsPaneHost.Timeline.CaptureStartUtc = _captureStartUtc;
            EventsPaneHost.Timeline.ViewDurationSeconds = DefaultTimelineViewDurationSeconds;
            EventsPaneHost.Timeline.ViewStartSeconds = 0;

            EventsPaneHost.Timeline.LaneInteraction += Timeline_LaneInteraction;
            EventsPaneHost.Timeline.SelectedEventChanged += Timeline_SelectedEventChanged;
            EventsPaneHost.Timeline.EventDoubleClicked += Timeline_EventDoubleClicked;

            EventsPaneHost.Grid.SelectionChanged += Grid_SelectionChanged;

            EventsPaneHost.Scroll.ValueChanged += Scroll_ValueChanged;

            EventsPaneHost.CloseRequested += (_, __) => HideEventsPane();
            EventsPaneHost.FloatRequested += (_, __) => ToggleFloatDock();
            EventsPaneHost.LogPopoutRequested += (_, __) => ToggleEventLogDock();
            EventsPaneHost.SettingsRequested += (_, __) => OpenLaneSettings();
            EventsPaneHost.LaneFilterSelectionChanged += (_, key) => SetLaneFocus(key);
            EventsPaneHost.EventLogEntryOpenRequested += EventsPaneHost_EventLogEntryOpenRequested;
            EventsPaneHost.HeaderDragStarted += (_, a) => BeginPaneHeaderDrag(isEventsPane: true, a.ScreenPosition);
            EventsPaneHost.HeaderDragDelta += (_, a) => ContinuePaneHeaderDrag(isEventsPane: true, a.ScreenPosition);
            EventsPaneHost.HeaderDragCompleted += (_, a) => EndPaneHeaderDrag(isEventsPane: true, a.ScreenPosition);
            PerformancePaneHost.CloseRequested += (_, __) => HidePerformancePane();
            PerformancePaneHost.ReorderRequested += (_, __) => TogglePaneOrder();
            PerformancePaneHost.FloatRequested += (_, __) => TogglePerformanceFloatDock();
            PerformancePaneHost.ThreadDoubleClicked += PerformancePaneHost_ThreadDoubleClicked;
            PerformancePaneHost.DisassemblyRequested += PerformancePaneHost_DisassemblyRequested;
            PerformancePaneHost.ParallelStacksRequested += (_, __) => OpenParallelStacksWindow();
            PerformancePaneHost.HeaderDragStarted += (_, a) =>
                BeginPaneHeaderDrag(isEventsPane: false, a.ScreenPosition);
            PerformancePaneHost.HeaderDragDelta += (_, a) =>
                ContinuePaneHeaderDrag(isEventsPane: false, a.ScreenPosition);
            PerformancePaneHost.HeaderDragCompleted += (_, a) =>
                EndPaneHeaderDrag(isEventsPane: false, a.ScreenPosition);
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
            RegistryPaneHost.CloseRequested += (_, __) => HideRegistryPane();
            RegistryPaneHost.InspectRequested += (_, __) => OpenRegistryInspector();
            ProcessRelationsPaneHost.CloseRequested += (_, __) => HideProcessRelationsPane();
            ProcessRelationsPaneHost.InspectRequested += (_, __) => OpenProcessRelationsInspector();
            ProcessRelationsPaneHost.GraphStateChanged += ProcessRelationsPaneHost_GraphStateChanged;
            SetupExplorer();
            SetupProcessTabs();
            InitializeBackendUi();
            InitializeRuntimeConfigDefaults();
            ApiViewDataGrid.ItemsSource = _apiViewRows;
            if (ExtendedViewDataGrid != null)
            {
                ExtendedViewDataGrid.ItemsSource = _extendedViewRows;
            }
            if (ExtendedComDataGrid != null)
            {
                ExtendedComDataGrid.ItemsSource = _extendedComRows;
            }
            if (ExtendedEtwDataGrid != null)
            {
                ExtendedEtwDataGrid.ItemsSource = _extendedEtwRows;
            }
            if (ExtendedJobDataGrid != null)
            {
                ExtendedJobDataGrid.ItemsSource = _extendedJobRows;
            }
            if (ExtendedYaraDataGrid != null)
            {
                ExtendedYaraDataGrid.ItemsSource = _extendedYaraRows;
            }
            ApiViewDataGrid.SelectedIndex = -1;
            UpdateApiViewSelection(null);
            SetMainInterfaceViewMode(MainInterfaceViewMode.Telemetry);
            ApplyUplinkStatusVisual(healthy: null);

            UpdateScrollBar();
            FocusViewport();
            UpdateTopTimeTravelBar();
            RebuildToolbarViewMenuOptions();

            _perf = new PerformanceSampler();
            _perf.SampleArrived += Perf_SampleArrived;

            PerformancePaneHost.SetCaptureStart(_captureStartUtc);
            PerformancePaneHost.SetPid(TryGetPid());
            PerformancePaneHost.SetProcessLiveDataAvailable(false);
            PerformancePaneHost.SetTargetSuspended(false);
            SyncPerformanceViewToTimeline();
            StatusBlock.Text = "NO TARGET SELECTED";
            ApplyPaneOrder();
            ApplyIntelPaneOrder();
            _processStateRefreshTimer.Start();
            _apiGraphRefreshTimer.Start();
            _timelineLiveTickTimer.Start();
            RefreshProcessStateBadge();
        }

        private void SetupProcessTabs()
        {
            ProcessTabs.ItemsSource = _processTabs;
            _currentSession = null;
        }

        private void OnClosing(object? sender, CancelEventArgs e)
        {
            _ = sender;
            if (!PrepareSessionShutdown())
            {
                e.Cancel = true;
                return;
            }

            _isMainWindowShuttingDown = true;
            CancelActiveAnalysisOperationForShutdown();
        }

        private void OnClosed(object? sender, EventArgs e)
        {
            _isMainWindowShuttingDown = true;
            CancelActiveAnalysisOperationForShutdown();
            DisposeSignatureIntelSubsystem();
            _detachedEventLogRefreshTimer.Stop();
            _processStateRefreshTimer.Stop();
            _apiGraphRefreshTimer.Stop();
            _timelineLiveTickTimer.Stop();

            if (_perf != null)
            {
                _perf.SampleArrived -= Perf_SampleArrived;
                _perf.Stop();
                _perf = null;
            }

            if (_eventsFloatWindow != null)
            {
                _eventsFloatWindow.Closing -= EventsFloatWindow_Closing;
                _eventsFloatWindow.Closed -= EventsFloatWindow_Closed;
                if (_eventsFloatWindow.Content == EventsPaneHost)
                {
                    _eventsFloatWindow.Content = null;
                }
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
                _performanceFloatWindow.Closing -= PerformanceFloatWindow_Closing;
                _performanceFloatWindow.Closed -= PerformanceFloatWindow_Closed;
                if (_performanceFloatWindow.Content == PerformancePaneHost)
                {
                    _performanceFloatWindow.Content = null;
                }
                _performanceFloatWindow.Close();
                _performanceFloatWindow = null;
            }
            if (_etwFloatWindow != null)
            {
                _etwFloatWindow.Closing -= EtwFloatWindow_Closing;
                _etwFloatWindow.Closed -= EtwFloatWindow_Closed;
                if (_etwFloatWindow.Content == EtwPaneHost)
                {
                    _etwFloatWindow.Content = null;
                }
                _etwFloatWindow.Close();
                _etwFloatWindow = null;
            }
            if (_heuristicsFloatWindow != null)
            {
                _heuristicsFloatWindow.Closing -= HeuristicsFloatWindow_Closing;
                _heuristicsFloatWindow.Closed -= HeuristicsFloatWindow_Closed;
                if (_heuristicsFloatWindow.Content == HeuristicsPaneHost)
                {
                    _heuristicsFloatWindow.Content = null;
                }
                _heuristicsFloatWindow.Close();
                _heuristicsFloatWindow = null;
            }
            if (_childProcessGraphWindow != null)
            {
                SaveChildProcessGraphStateToSession();
                _childProcessGraphWindow.Closed -= ChildProcessGraphWindow_Closed;
                _childProcessGraphWindow.Close();
                _childProcessGraphWindow = null;
            }
            ProcessRelationsPaneHost.GraphStateChanged -= ProcessRelationsPaneHost_GraphStateChanged;
            _childProcessGraphRefreshTimer.Stop();
            SaveIntelSessionState(_currentSession?.Pid ?? 0);
            StopLiveAnalysisSession(LiveAnalysisStopReason.Shutdown, fastTeardown: true, stopPerformance: true);
            DisposePreparedLaunchBackendSession();
            TerminateLaunchOwnedTargetsOnShutdown();
            HideDockPreview();
            CleanupTemporarySessionBackingStores();
        }

        private void SetupExplorer()
        {
            _explorer.Clear();

            _explorer.Add(new GraphExplorerItem(
                "Events", new SolidColorBrush(Color.FromRgb(0xAA, 0x7D, 0x4A))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem(
                "Performance", new SolidColorBrush(Color.FromRgb(0x58, 0xB6, 0x58))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem(
                "ETW", new SolidColorBrush(Color.FromRgb(0xD2, 0x89, 0x34))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem(
                "Heuristics", new SolidColorBrush(Color.FromRgb(0xD2, 0x55, 0x55))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem(
                "Filesystem", new SolidColorBrush(Color.FromRgb(0x45, 0x8E, 0x7A))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem(
                "Registry", new SolidColorBrush(Color.FromRgb(0x7A, 0x5E, 0xA8))) { IsEnabled = true });
            _explorer.Add(new GraphExplorerItem(
                "Process Relations", new SolidColorBrush(Color.FromRgb(0xD2, 0xB8, 0x55))) { IsEnabled = true });

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

        private GraphExplorerItem? FindExplorerItem(string name) =>
            _explorer.FirstOrDefault(x => string.Equals(x.Name, name, StringComparison.OrdinalIgnoreCase));

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
            SetExplorerHasData("Performance",
                               _hasPerformanceData || (_currentSession?.PerformanceHistory.Count ?? 0) > 0);
            SetExplorerHasData("ETW", EtwPaneHost.ItemCount > 0);
            SetExplorerHasData("Heuristics", HeuristicsPaneHost.ItemCount > 0);
            SetExplorerHasData("Filesystem", FilesystemPaneHost.ItemCount > 0);
            SetExplorerHasData("Process Relations", ProcessRelationsPaneHost.ItemCount > 0);
        }

        private void ApplyDockVisibilityFromExplorer()
        {
            bool showEvents = _explorer.FirstOrDefault(x => x.Name == "Events")?.IsEnabled ?? true;
            bool showPerf = _explorer.FirstOrDefault(x => x.Name == "Performance")?.IsEnabled ?? true;
            bool showEtw = _explorer.FirstOrDefault(x => x.Name == "ETW")?.IsEnabled ?? true;
            bool showHeuristics = _explorer.FirstOrDefault(x => x.Name == "Heuristics")?.IsEnabled ?? true;
            bool showFilesystem = _explorer.FirstOrDefault(x => x.Name == "Filesystem")?.IsEnabled ?? true;
            bool showRegistry = _explorer.FirstOrDefault(x => x.Name == "Registry")?.IsEnabled ?? true;
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
            bool showRegistryContent = showRegistry;
            bool showRelationsContent = showRelations;

            EventsDockBorder.Visibility = showEventsContent ? Visibility.Visible : Visibility.Collapsed;
            PerformanceDockBorder.Visibility = showPerformanceContent ? Visibility.Visible : Visibility.Collapsed;

            CollapsedEventsBar.Visibility =
                (showEvents && !_eventsPaneVisible && !_eventsPaneFloating) ? Visibility.Visible : Visibility.Collapsed;
            CollapsedPerformanceBar.Visibility = (showPerf && !_performancePaneVisible && !_performancePaneFloating)
                                                     ? Visibility.Visible
                                                     : Visibility.Collapsed;

            DockGrid.RowDefinitions[0].Height =
                showEvents ? (_eventsPaneFloating
                                  ? new GridLength(0)
                                  : (_eventsPaneVisible ? new GridLength(4, GridUnitType.Star) : new GridLength(28)))
                           : new GridLength(0);

            DockGrid.RowDefinitions[2].Height =
                showPerf ? (_performancePaneFloating
                                ? new GridLength(0)
                                : (_performancePaneVisible ? new GridLength(5, GridUnitType.Star) : new GridLength(28)))
                         : new GridLength(0);

            DockGrid.RowDefinitions[1].Height =
                (showEventsContent && showPerformanceContent) ? new GridLength(2) : new GridLength(0);

            EtwDockBorder.Visibility = showEtwContent ? Visibility.Visible : Visibility.Collapsed;
            HeuristicsDockBorder.Visibility = showHeuristicsContent ? Visibility.Visible : Visibility.Collapsed;
            FilesystemDockBorder.Visibility = showFilesystemContent ? Visibility.Visible : Visibility.Collapsed;
            RegistryDockBorder.Visibility = showRegistryContent ? Visibility.Visible : Visibility.Collapsed;
            ProcessRelationsDockBorder.Visibility = showRelationsContent ? Visibility.Visible : Visibility.Collapsed;

            bool row0Visible = (Grid.GetRow(EtwDockBorder) == 0 && showEtwContent) ||
                               (Grid.GetRow(HeuristicsDockBorder) == 0 && showHeuristicsContent);
            bool row2Visible = (Grid.GetRow(EtwDockBorder) == 2 && showEtwContent) ||
                               (Grid.GetRow(HeuristicsDockBorder) == 2 && showHeuristicsContent);
            bool row4Visible = showFilesystemContent;
            bool row6Visible = showRegistryContent;
            bool row8Visible = showRelationsContent;
            IntelligenceDock.RowDefinitions[0].Height =
                row0Visible ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            IntelligenceDock.RowDefinitions[2].Height =
                row2Visible ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            IntelligenceDock.RowDefinitions[4].Height =
                row4Visible ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            IntelligenceDock.RowDefinitions[6].Height =
                row6Visible ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            IntelligenceDock.RowDefinitions[8].Height =
                row8Visible ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            IntelligenceDock.RowDefinitions[1].Height =
                (row0Visible && row2Visible) ? new GridLength(2) : new GridLength(0);
            IntelligenceDock.RowDefinitions[3].Height =
                (row2Visible && row4Visible) ? new GridLength(2) : new GridLength(0);
            IntelligenceDock.RowDefinitions[5].Height =
                (row4Visible && row6Visible) ? new GridLength(2) : new GridLength(0);
            IntelligenceDock.RowDefinitions[7].Height =
                (row6Visible && row8Visible) ? new GridLength(2) : new GridLength(0);

            bool showIntel = row0Visible || row2Visible || row4Visible || row6Visible || row8Visible;
            if (_mainViewMode != MainInterfaceViewMode.Telemetry)
            {
                showIntel = false;
            }
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
                _captureProjection?.ObservePerformance(e);
                _currentSession.PerformanceHistory.Add(ClonePerformanceSample(e));
                if (_currentSession.PerformanceHistory.Count > 4000)
                    _currentSession.PerformanceHistory.RemoveRange(0, _currentSession.PerformanceHistory.Count - 4000);
            }

            var evCount = _focusedEvents.Count;
            var eventsItem = _explorer.FirstOrDefault(x => x.Name == "Events");
            eventsItem?.PushPreviewValue(evCount);

            var perfItem = _explorer.FirstOrDefault(x => x.Name == "Performance");
            perfItem?.PushPreviewValue(e.CpuPercent);
            _hasPerformanceData = true;
            SetExplorerHasData("Performance", true);

            PerformancePaneHost.PushSample(e);

            SyncPerformanceViewToTimeline();
        }

        private void StartLiveCaptureForPid(int pid, bool useUsermodeHooks, bool launchStartsSuspended = false,
                                            bool fastBackendRestart = false)
        {
            if (pid <= 0 || _perf == null)
                return;

            _targetExecutionSuspended = launchStartsSuspended;

            if (_currentSession != null && _currentSession.Pid == pid && _currentSession.Events.Count == 0 &&
                _currentSession.PerformanceHistory.Count == 0 && _currentSession.ThreadLifecycleHistory.Count == 0)
            {
                double viewDuration = Math.Max(1, EventsPaneHost.Timeline.ViewDurationSeconds);
                _captureStartUtc = AnchorCaptureStartUtc(viewDuration);
                _latestEventTimestampUtc = _captureStartUtc;
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
            PerformancePaneHost.SetTargetSuspended(launchStartsSuspended);
            PerformancePaneHost.RefreshLiveProcessDetails();
            StartTargetExitWatcher(pid);
            EnsureLiveCaptureStoreForCurrentSession(pid);
            StartBackendForPid(pid, useUsermodeHooks, fastStopExistingSession: fastBackendRestart);
            if (_backendSession != null)
            {
                TrackLiveAnalysisSession(pid, _currentSession);
            }
            bool autoOpenApiGraph = _currentSession?.AutoOpenApiGraphOnNextStart == true;
            if (_currentSession != null)
            {
                _currentSession.AutoOpenApiGraphOnNextStart = false;
            }
            SetMainInterfaceViewMode(useUsermodeHooks && autoOpenApiGraph ? MainInterfaceViewMode.Api
                                                                          : MainInterfaceViewMode.Telemetry);
            StatusBlock.Text = $"LIVE CAPTURE: {NormalizeSessionTitle(_currentSession?.Title ?? $"PID {pid}")}";
            RefreshProcessStateBadge();
        }

        private void StartTargetExitWatcher(int pid)
        {
            StopTargetExitWatcher();
            if (pid <= 0)
                return;

            Process? process = null;
            try
            {
                process = Process.GetProcessById(pid);
                process.EnableRaisingEvents = true;
                process.Exited += TargetExitWatchProcess_Exited;
                _targetExitWatchProcess = process;
                _targetExitWatchPid = pid;
                process = null;
                if (_targetExitWatchProcess.HasExited)
                {
                    HandleTargetProcessExit(pid, BuildProcessExitReason(_targetExitWatchProcess));
                }
            }
            catch
            {
                process?.Dispose();
                _targetExitWatchProcess?.Dispose();
                _targetExitWatchProcess = null;
                _targetExitWatchPid = 0;
                if (!Dispatcher.HasShutdownStarted)
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
            string exitReason = string.Empty;
            if (sender is Process p)
            {
                try
                {
                    pid = p.Id;
                    exitReason = BuildProcessExitReason(p);
                }
                catch
                {
                    pid = 0;
                }
            }

            if (pid <= 0)
                pid = _targetExitWatchPid;

            Dispatcher.BeginInvoke(new Action(() => HandleTargetProcessExit(pid, exitReason)));
        }

        private static string BuildProcessExitReason(Process process)
        {
            try
            {
                return $"process exited exitCode=0x{unchecked((uint)process.ExitCode):X8}";
            }
            catch
            {
                return "process exited; exit code unavailable";
            }
        }

        private void HandleTargetProcessExit(int pid, string? observedReason = null)
        {
            if (pid <= 0)
                return;

            ProcessSessionTab? exitedTab = _processTabs.FirstOrDefault(x => x.Pid == pid);
            if (exitedTab == null || exitedTab.TargetExited)
                return;

            exitedTab.TargetExited = true;
            _targetExitReasonByPid.TryGetValue(unchecked((uint)pid), out string? remembered);
            string exitReason = !string.IsNullOrWhiteSpace(remembered)
                                    ? remembered
                                    : (!string.IsNullOrWhiteSpace(observedReason)
                                           ? observedReason.Trim()
                                           : "process exited; cause not observed before teardown");
            exitedTab.TargetExitReason = exitReason;
            MarkSessionExited(exitedTab);

            if (!ReferenceEquals(_currentSession, exitedTab))
            {
                if (exitedTab.ActivePauseStartUtc.HasValue)
                {
                    exitedTab.PausedTimelineSpans.Add(
                        new PausedTimelineSpan { StartUtc = exitedTab.ActivePauseStartUtc.Value,
                                                 EndUtc = DateTime.UtcNow });
                    exitedTab.ActivePauseStartUtc = null;
                }
                SaveTabToBackingStore(exitedTab);
                RefreshProcessStateBadge();
                return;
            }

            AppendEvent(new TelemetryEvent { TimestampUtc = DateTime.UtcNow, PID = pid, TID = 0, Group = "Session",
                                             SubType = "ProcessExit", Summary = "TARGET PROCESS EXITED",
                                             Details = $"{exitReason}. Data capture stopped for this tab." });

            StopLiveAnalysisSession(LiveAnalysisStopReason.TargetExited, preserveApiGraphSnapshot: true,
                                    fastTeardown: true, stopPerformance: true);
            if (exitedTab.ActivePauseStartUtc.HasValue)
            {
                exitedTab.PausedTimelineSpans.Add(
                    new PausedTimelineSpan { StartUtc = exitedTab.ActivePauseStartUtc.Value,
                                             EndUtc = DateTime.UtcNow });
                exitedTab.ActivePauseStartUtc = null;
            }
            SyncCurrentSessionStateToMemory();
            _ = TryPersistCurrentSessionAfterStop();

            StatusBlock.Text = $"Capture stopped; target exited: {exitReason}";
            RefreshProcessStateBadge();
            ThemedMessageBox.ShowToast(this, $"Target process {pid} exited: {exitReason}", "Target Exited",
                                       MessageBoxImage.Warning, durationMs: 5000);
        }

        private void ValidateCurrentSessionState()
        {
            if (_currentSession == null || _currentSession.Pid <= 0 || _currentSession.OfflineSnapshot ||
                _currentSession.TargetExited)
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
                if (ex.NativeErrorCode != 5)
                {
                    failure = $"FAILED TO OPEN PID {pid} (WIN32 {ex.NativeErrorCode})";
                    return false;
                }

                processName = $"PID {pid}";
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

            IntPtr handle = Kernel32Native.OpenProcess(ProcessQueryLimitedInformation | ProcessSynchronize, false,
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
            if (PidBox == null)
                return 0;
            var s = PidBox.Text?.Trim();
            if (string.IsNullOrWhiteSpace(s))
                return _currentSession?.Pid ?? 0;
            if (int.TryParse(s, out int pid) && pid > 0)
                return pid;
            return 0;
        }

        private string GetProcessTabTitle(int pid)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                return $"{p.ProcessName} (Silo)";
            }
            catch
            {
                return $"PID {pid} (Silo)";
            }
        }

        private void FlashSwitchToast(string label)
        {
            SwitchToastText.Text = label;
            SwitchToastBorder.Visibility = Visibility.Visible;

            var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(120));
            var fadeOut = new DoubleAnimation(
                1, 0, TimeSpan.FromMilliseconds(300)) { BeginTime = TimeSpan.FromMilliseconds(900) };
            fadeOut.Completed += (_, __) => SwitchToastBorder.Visibility = Visibility.Collapsed;

            var storyboard = new Storyboard();
            Storyboard.SetTarget(fadeIn, SwitchToastBorder);
            Storyboard.SetTargetProperty(fadeIn, new PropertyPath(OpacityProperty));
            Storyboard.SetTarget(fadeOut, SwitchToastBorder);
            Storyboard.SetTargetProperty(fadeOut, new PropertyPath(OpacityProperty));
            storyboard.Children.Add(fadeIn);
            storyboard.Children.Add(fadeOut);
            storyboard.Begin();
        }

        private ProcessSessionTab AddOrSelectProcessTab(int pid, string title, bool select)
        {
            var existing = _processTabs.FirstOrDefault(t => t.Pid == pid);
            if (existing == null)
            {
                double initialDuration = EventsPaneHost?.Timeline != null
                                             ? Math.Clamp(EventsPaneHost.Timeline.ViewDurationSeconds, 1, 120)
                                             : DefaultTimelineViewDurationSeconds;
                existing = new ProcessSessionTab { Pid = pid,
                                                   Title = NormalizeSessionTitle(title),
                                                   CaptureStartUtc = AnchorCaptureStartUtc(initialDuration),
                                                   ViewDurationSeconds = initialDuration,
                                                   ViewStartSeconds = 0,
                                                   KernelHooksEnabled = _kernelHooksArmed,
                                                   SignatureIntelEnabled = _signatureIntelEnabled,
                                                   SignatureIntelMemoryScanEnabled = _signatureIntelMemoryScanEnabled,
                                                   SignatureIntelPageScanEnabled = _signatureIntelPageScanEnabled };
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
                value = value[..^ "[EXITED]".Length].TrimEnd();
            }

            return value;
        }

        private void SyncCurrentSessionViewportStateToMemory()
        {
            if (_currentSession == null)
                return;

            _currentSession.CaptureStartUtc = _captureStartUtc;
            _currentSession.LaneFocusKey = _laneFocusKey;
            _currentSession.ViewDurationSeconds = EventsPaneHost.Timeline.ViewDurationSeconds;
            _currentSession.ViewStartSeconds = EventsPaneHost.Timeline.ViewStartSeconds;
            SaveIntelSessionState(_currentSession.Pid);
        }

        private void SyncCurrentSessionStateToMemory()
        {
            if (_currentSession == null)
                return;

            SyncCurrentSessionViewportStateToMemory();
            if (!CurrentSessionEventMirrorLooksCurrent())
            {
                _currentSession.Events.Clear();
                _currentSession.Events.AddRange(_allEvents.Select(CloneTelemetryEvent));
            }
        }

        private bool CurrentSessionEventMirrorLooksCurrent()
        {
            if (_currentSession == null || _currentSession.Events.Count != _allEvents.Count)
            {
                return false;
            }

            if (_allEvents.Count == 0)
            {
                return true;
            }

            TelemetryEvent mirrored = _currentSession.Events[^1];
            TelemetryEvent live = _allEvents[^1];
            return mirrored.TimestampUtc == live.TimestampUtc && mirrored.PID == live.PID &&
                   mirrored.TID == live.TID && string.Equals(mirrored.Group, live.Group, StringComparison.Ordinal) &&
                   string.Equals(mirrored.SubType, live.SubType, StringComparison.Ordinal);
        }

        private void SaveCurrentSessionState()
        {
            if (_currentSession == null)
                return;

            SyncCurrentSessionStateToMemory();
            if (_currentSession.OfflineSnapshot || _liveCaptureStore == null)
            {
                SaveTabToBackingStore(_currentSession);
            }
        }

        private bool TryPersistCurrentSessionAfterStop()
        {
            if (_currentSession == null)
            {
                return false;
            }

            try
            {
                SyncCurrentSessionStateToMemory();
                SaveTabToBackingStore(_currentSession);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void RestoreSessionState(ProcessSessionTab tab)
        {
            EnsureSessionMaterialized(tab);
            double restoredDuration = Math.Clamp(
                tab.ViewDurationSeconds <= 0 ? DefaultTimelineViewDurationSeconds : tab.ViewDurationSeconds, 1, 120);
            bool freshSession = !tab.OfflineSnapshot && tab.Events.Count == 0 && tab.PerformanceHistory.Count == 0 &&
                                tab.ThreadLifecycleHistory.Count == 0;
            if (freshSession)
            {
                tab.CaptureStartUtc = AnchorCaptureStartUtc(restoredDuration);
                tab.ViewStartSeconds = 0;
            }

            _captureStartUtc =
                tab.CaptureStartUtc == default ? AnchorCaptureStartUtc(restoredDuration) : tab.CaptureStartUtc;
            _laneFocusKey = tab.LaneFocusKey;

            _allEvents.Clear();
            _knownLaneKeys.Clear();
            _telemetryTextPool.Clear();
            _focusedEvents.Clear();
            EventsPaneHost.Timeline.Items.Clear();
            EventsPaneHost.Timeline.ClearAllLaneFilters();
            ClearSelectedEvent();

            IEnumerable<TelemetryEvent> restoreEvents =
                TelemetryEventsAreTimestampSorted(tab.Events) ? tab.Events : tab.Events.OrderBy(x => x.TimestampUtc);
            foreach (var ev in restoreEvents)
            {
                _allEvents.Add(NormalizeTelemetryEventForStore(ev));
            }
            _latestEventTimestampUtc = _allEvents.Count > 0 ? _allEvents[^1].TimestampUtc : _captureStartUtc;

            EventsPaneHost.Timeline.CaptureStartUtc = _captureStartUtc;
            EventsPaneHost.Timeline.ViewDurationSeconds = restoredDuration;
            EventsPaneHost.Timeline.ViewStartSeconds = Math.Max(0, tab.ViewStartSeconds);
            ApplyPausedTimelineRanges();
            UpdateScrollBar();
            EventsPaneHost.Scroll.Value =
                Math.Min(EventsPaneHost.Scroll.Maximum, EventsPaneHost.Timeline.ViewStartSeconds);
            FocusViewport();

            PerformancePaneHost.SetCaptureStart(_captureStartUtc);
            PerformancePaneHost.SetPid(tab.Pid);
            PerformancePaneHost.SetAnalysisSubject(tab.AnalysisSubjectPath, tab.AnalysisHostPath);
            DiagnosticsState.SetValue("Analysis Subject", tab.AnalysisSubjectKind == LaunchTargetKind.Dll &&
                                                                  !string.IsNullOrWhiteSpace(tab.AnalysisSubjectPath)
                                                              ? tab.AnalysisSubjectPath
                                                              : "Process image");
            PerformancePaneHost.LoadHistory(tab.PerformanceHistory);
            PerformancePaneHost.LoadMemoryRegionAttributionHistory(tab.MemoryRegionAttributionHistory);
            PerformancePaneHost.LoadThreadLifecycleHistory(tab.ThreadLifecycleHistory);
            PerformancePaneHost.LoadThreadStackHistory(tab.ThreadStackHistories);
            RestoreIntelSessionState(tab.Pid);
            SyncPerformanceViewToTimeline();
            _hasPerformanceData = tab.PerformanceHistory.Count > 0;
            SetExplorerHasData("Performance", tab.PerformanceHistory.Count > 0);
            EventsPaneHost.SetHasData(_allEvents.Count > 0);
            RefreshExplorerDataBadges();
            RefreshChildProcessGraphWindowIfOpen();
        }

        private void SwitchToSession(ProcessSessionTab tab)
        {
            if (ReferenceEquals(_currentSession, tab))
            {
                return;
            }

            if (_currentSession != null && !ReferenceEquals(_currentSession, tab))
            {
                SaveChildProcessGraphStateToSession(_currentSession);
                SyncCurrentSessionViewportStateToMemory();
                FlashSwitchToast($"Switched to {tab.Title}");
            }

            _currentSession = tab;
            PidBox.Text = tab.Pid.ToString();
            RefreshSubsystemSegmentationDiagnostics();
            RestoreChildProcessGraphStateFromSession(tab);

            RestoreSessionState(tab);

            if (tab.OfflineSnapshot)
            {
                StopLiveAnalysisSession(LiveAnalysisStopReason.SessionSwitch, preserveApiGraphSnapshot: true,
                                        fastTeardown: true, stopPerformance: true);
                StatusBlock.Text = $"OFFLINE SESSION: {tab.Title}";
                RefreshProcessStateBadge();
                return;
            }

            if (tab.TargetExited)
            {
                StopLiveAnalysisSession(LiveAnalysisStopReason.SessionSwitch, preserveApiGraphSnapshot: true,
                                        fastTeardown: true, stopPerformance: true);
                StatusBlock.Text = "Capture stopped; historical data remains available.";
                RefreshProcessStateBadge();
                return;
            }

            bool allowPreparedProtectedAttach =
                _preparedLaunchBackendSession != null && _preparedLaunchBackendPid == tab.Pid && tab.UseUsermodeHooks;

            if (!TryOpenTargetProcess(tab.Pid, out _, out var failure, out var accessDenied))
            {
                if (!allowPreparedProtectedAttach)
                {
                    StopLiveAnalysisSession(LiveAnalysisStopReason.SessionSwitch, preserveApiGraphSnapshot: true,
                                            fastTeardown: true, stopPerformance: true);
                    if (!accessDenied)
                    {
                        tab.TargetExited = true;
                        MarkSessionExited(tab);
                        StatusBlock.Text = "Capture stopped; historical data remains available.";
                    }
                    else
                    {
                        StatusBlock.Text = $"Access denied to PID {tab.Pid}. Capture stopped.";
                    }
                    RefreshProcessStateBadge();
                    return;
                }

                OutputCapture.AppendLine(
                    $"Protected launch session accepted without direct process-open access: PID {tab.Pid}");
            }

            bool launchStartsSuspended = tab.LaunchStartsSuspendedPending;
            tab.LaunchStartsSuspendedPending = false;
            StartLiveCaptureForPid(tab.Pid, tab.UseUsermodeHooks, launchStartsSuspended, fastBackendRestart: true);
        }

        private static bool TelemetryEventsAreTimestampSorted(IReadOnlyList<TelemetryEvent> events)
        {
            for (int i = 1; i < events.Count; i += 1)
            {
                if (events[i].TimestampUtc < events[i - 1].TimestampUtc)
                {
                    return false;
                }
            }

            return true;
        }

        private void SyncPerformanceViewToTimeline()
        {
            var viewStart = _captureStartUtc + TimeSpan.FromSeconds(EventsPaneHost.Timeline.ViewStartSeconds);
            var viewEnd = viewStart + TimeSpan.FromSeconds(EventsPaneHost.Timeline.ViewDurationSeconds);

            PerformancePaneHost.SetViewWindow(viewStart, viewEnd);
        }

        private void ApplyTimelineViewport(double targetStart, bool syncScroll, bool updateFollowState)
        {
            if (EventsPaneHost?.Scroll == null || EventsPaneHost?.Timeline == null)
            {
                return;
            }

            double viewport = Math.Max(1, EventsPaneHost.Scroll.ViewportSize);
            double maxStart = ComputeTimelineMaxStart(viewport);
            double clamped = Math.Max(0, Math.Min(maxStart, targetStart));
            if (updateFollowState)
            {
                _followLiveTimeline = maxStart <= 0.001 || Math.Abs(clamped - maxStart) < 0.25;
            }

            _pendingScrollStartSeconds = clamped;
            EventsPaneHost.Timeline.ViewStartSeconds = clamped;
            if (syncScroll && Math.Abs(EventsPaneHost.Scroll.Value - clamped) > 0.001)
            {
                EventsPaneHost.Scroll.Value = clamped;
            }

            FocusViewport();
            UpdateTopTimeTravelBar();
            SyncPerformanceViewToTimeline();
        }

        private void AppendEvent(TelemetryEvent ev)
        {
            AppendEvents(new[] { ev });
        }

        private void AppendEvents(IReadOnlyList<TelemetryEvent> events)
        {
            if (events.Count == 0)
            {
                return;
            }

            bool laneKeysChanged = false;
            for (int i = 0; i < events.Count; i += 1)
            {
                TelemetryEvent ev = NormalizeTelemetryEventForStore(events[i]);
                _allEvents.Add(ev);
                _currentSession?.Events.Add(ev);
                if (ev.TimestampUtc > _latestEventTimestampUtc)
                {
                    _latestEventTimestampUtc = ev.TimestampUtc;
                }
                if (!string.IsNullOrWhiteSpace(ev.Group) && _knownLaneKeys.Add(ev.Group))
                {
                    laneKeysChanged = true;
                }
            }

            SetExplorerHasData("Events", _allEvents.Count > 0);
            EventsPaneHost.SetHasData(true);
            if (laneKeysChanged)
            {
                EventsPaneHost.SetLaneFilterOptions(_knownLaneKeys.OrderBy(k => k));
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
            if (StatusBlock == null)
                return;

            if (healthy == true)
            {
                StatusBlock.SetResourceReference(TextBlock.ForegroundProperty, "WinMutedTextBrush");
                return;
            }

            if (healthy == false)
            {
                StatusBlock.SetResourceReference(TextBlock.ForegroundProperty, "StatusFailedBrush");
                return;
            }

            StatusBlock.SetResourceReference(TextBlock.ForegroundProperty, "WinMutedTextBrush");
        }

        private void UpdateWindowTitle()
        {
            string sessionLabel;
            if (_currentSession == null || _currentSession.Pid <= 0)
            {
                sessionLabel = "IDLE";
            }
            else if (_currentSession.OfflineSnapshot)
            {
                sessionLabel = $"OFFLINE SESSION: {NormalizeSessionTitle(_currentSession.Title)}";
            }
            else if (_currentSession.TargetExited)
            {
                sessionLabel = $"[CAPTURE {_currentSession.Pid} — STOPPED]";
            }
            else
            {
                string captureTitle = NormalizeSessionTitle(_currentSession.Title ?? $"PID {_currentSession.Pid}");
                sessionLabel = $"[CAPTURE {_currentSession.Pid} {captureTitle}]";
            }

            string newTitle = $"{WindowTitleBase} {sessionLabel}";
            if (!string.Equals(Title, newTitle, StringComparison.Ordinal))
            {
                Title = newTitle;
            }
        }

        private void RefreshProcessStateBadge()
        {
            UpdateWindowTitle();
            RefreshToolbarCommandState();

            if (ProcessStateBadge == null || ProcessStateBlock == null)
            {
                return;
            }

            if (_currentSession == null || _currentSession.Pid <= 0)
            {
                SetProcessStateVisual("Disconnected", ProcessStateUnknownBackground, ProcessStateUnknownBorder,
                                      ProcessStateUnknownForeground);
                return;
            }

            string labelPrefix = $"PID {_currentSession.Pid}";
            if (_currentSession.OfflineSnapshot)
            {
                SetProcessStateVisual($"{labelPrefix} • Exited (offline capture)", ProcessStateExitedBackground,
                                      ProcessStateExitedBorder, ProcessStateExitedForeground);
                return;
            }

            if (_currentSession.TargetExited)
            {
                string reason = string.IsNullOrWhiteSpace(_currentSession.TargetExitReason)
                                    ? "capture available"
                                    : _currentSession.TargetExitReason;
                SetProcessStateVisual($"{labelPrefix} • Exited ({reason})", ProcessStateExitedBackground,
                                      ProcessStateExitedBorder, ProcessStateExitedForeground);
                return;
            }

            IntelScopeStatus scope = ((IIntelDetailsProvider)this).GetIntelScopeStatus();
            switch (scope)
            {
            case IntelScopeStatus.Running:
                SetProcessStateVisual($"{labelPrefix} • Connected / Running", ProcessStateRunningBackground,
                                      ProcessStateRunningBorder, ProcessStateRunningForeground);
                break;
            case IntelScopeStatus.Waiting:
                SetProcessStateVisual($"{labelPrefix} • Suspended / Waiting", ProcessStateWaitingBackground,
                                      ProcessStateWaitingBorder, ProcessStateWaitingForeground);
                break;
            case IntelScopeStatus.Exited:
                SetProcessStateVisual($"{labelPrefix} • Exited (capture available)", ProcessStateExitedBackground,
                                      ProcessStateExitedBorder, ProcessStateExitedForeground);
                break;
            default:
                SetProcessStateVisual($"{labelPrefix} • Connected / Unknown", ProcessStateUnknownBackground,
                                      ProcessStateUnknownBorder, ProcessStateUnknownForeground);
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

        private void RefreshToolbarCommandState()
        {
            bool hasAttachedTarget = _currentSession != null && _currentSession.Pid > 0 &&
                                     !_currentSession.OfflineSnapshot && !_currentSession.TargetExited;

            bool canPause = hasAttachedTarget;
            bool canResume = hasAttachedTarget && _targetExecutionSuspended;
            if (canResume)
            {
                canPause = false;
            }

            SetToolbarCommandButtonState(TargetCommandButton, TargetCommandGlyph, true, ToolbarTargetBackground,
                                         ToolbarTargetBorder, ToolbarTargetForeground);
            SetToolbarCommandButtonState(PauseCommandButton, PauseCommandGlyph, canPause, ToolbarPauseBackground,
                                         ToolbarPauseBorder, ToolbarPauseForeground);
            SetToolbarCommandButtonState(ResumeCommandButton, ResumeCommandGlyph, canResume, ToolbarResumeBackground,
                                         ToolbarResumeBorder, ToolbarResumeForeground);
            SetToolbarCommandButtonState(TerminateCommandButton, TerminateCommandGlyph, hasAttachedTarget,
                                         ToolbarStopBackground, ToolbarStopBorder, ToolbarStopForeground);
            RefreshHooksButtonState();

            if (TimeTravelLiveNotice != null)
            {
                bool targetStopped = _currentSession != null && _currentSession.TargetExited;
                TimeTravelLiveNotice.Visibility = targetStopped ? Visibility.Collapsed : Visibility.Visible;
            }
        }

        private static void SetToolbarCommandButtonState(Button? button, Border? glyph, bool enabled,
                                                         Brush activeBackground, Brush activeBorder,
                                                         Brush activeForeground)
        {
            if (button == null || glyph == null)
            {
                return;
            }

            button.IsEnabled = enabled;
            button.Background = enabled ? activeBackground : ToolbarInactiveBackground;
            button.BorderBrush = enabled ? activeBorder : ToolbarInactiveBorder;
            button.Foreground = enabled ? activeForeground : ToolbarInactiveForeground;
            glyph.Background = enabled ? activeForeground : ToolbarInactiveForeground;
        }

        private void Scroll_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            double viewport = Math.Max(1, EventsPaneHost.Scroll.ViewportSize);
            double maxStart = ComputeTimelineMaxStart(viewport);
            double clamped = Math.Max(0, Math.Min(maxStart, EventsPaneHost.Scroll.Value));
            _pendingScrollStartSeconds = clamped;
            EventsPaneHost.Timeline.ViewStartSeconds = clamped;
            _followLiveTimeline = maxStart <= 0.001 || Math.Abs(clamped - maxStart) < 0.25;

            if (_scrollSyncPending)
            {
                return;
            }

            _scrollSyncPending = true;
            Dispatcher.BeginInvoke(new Action(() =>
                                              {
                                                  _scrollSyncPending = false;
                                                  ApplyTimelineViewport(_pendingScrollStartSeconds, syncScroll: false,
                                                                        updateFollowState: false);
                                              }),
                                   DispatcherPriority.Render);
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

            DateTime horizonUtc = GetTimelineHorizonUtc();
            var totalSeconds = (horizonUtc - _captureStartUtc).TotalSeconds;
            if (totalSeconds < 0)
            {
                totalSeconds = 0;
            }

            double duration = Math.Max(1, EventsPaneHost.Timeline.ViewDurationSeconds);
            double maxStart = Math.Max(0, totalSeconds - duration);
            EventsPaneHost.Scroll.ViewportSize = duration;
            EventsPaneHost.Scroll.Maximum = maxStart;
            EventsPaneHost.Scroll.SmallChange = Math.Max(1, duration / 20.0);
            EventsPaneHost.Scroll.LargeChange = Math.Max(1, duration * 0.8);

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
            var selectedAnchor = CaptureSelectedEventAnchor();

            double durationSeconds = Math.Max(1, (viewEnd - viewStart).TotalSeconds);
            RangeBlock.Text = $"Window {viewStart:HH:mm:ss}-{viewEnd:HH:mm:ss}  {durationSeconds:0}s";

            if (_allEvents.Count == 0)
            {
                _focusedEvents.ReplaceAll(Array.Empty<TelemetryEvent>());
                EventsPaneHost.Timeline.ReplaceItems(_focusedEvents);
                SetExplorerHasData("Events", false);
                EventsPaneHost.SetHeaderStats("View 0 | Total 0 | 0.0/s");
                ClearSelectedEvent();
                UpdateDetachedEventLogWindow();
                return;
            }

            int start = LowerBoundEventIndex(viewStart);
            int endExclusive = UpperBoundEventIndex(viewEnd);
            var rawVisibleEvents = new List<TelemetryEvent>(Math.Max(16, endExclusive - start));
            for (int i = start; i < endExclusive; i += 1)
            {
                var ev = _allEvents[i];
                if (!PassLaneFocus(ev))
                {
                    continue;
                }
                rawVisibleEvents.Add(ev);
            }

            var visibleEvents =
                ClusterViewportEvents(rawVisibleEvents, Math.Max(1.0, EventsPaneHost.Timeline.ViewDurationSeconds));
            _focusedEvents.ReplaceAll(visibleEvents);
            EventsPaneHost.Timeline.ReplaceItems(_focusedEvents);

            RestoreSelectedEventInFocusedView(selectedAnchor);
            FindExplorerItem("Events")?.PushPreviewValue(_focusedEvents.Count);
            SetExplorerHasData("Events", _allEvents.Count > 0);
            double viewSeconds = Math.Max(1.0, EventsPaneHost.Timeline.ViewDurationSeconds);
            double rate = rawVisibleEvents.Count / viewSeconds;
            EventsPaneHost.SetHeaderStats(
                $"View {_focusedEvents.Count} clustered | Raw {rawVisibleEvents.Count} | Total {_allEvents.Count} | {rate:0.0}/s");
            UpdateDetachedEventLogWindow();
            UpdateTopTimeTravelBar();
        }

        private IReadOnlyList<TelemetryEvent> ClusterViewportEvents(IReadOnlyList<TelemetryEvent> rawVisibleEvents,
                                                                    double viewDurationSeconds)
        {
            _focusedClusterMembers.Clear();
            if (rawVisibleEvents.Count == 0)
            {
                return Array.Empty<TelemetryEvent>();
            }

            if (rawVisibleEvents.Count <= 180)
            {
                for (int i = 0; i < rawVisibleEvents.Count; i += 1)
                {
                    TelemetryEvent raw = rawVisibleEvents[i];
                    _focusedClusterMembers[new EventSelectionKey(raw)] = new[] { raw };
                }

                return rawVisibleEvents;
            }

            int targetVisibleCount =
                Math.Clamp((int)Math.Round((EventsPaneHost?.Timeline?.ActualWidth ?? 1280.0) / 9.0), 80, 160);
            bool includeThreadId = rawVisibleEvents.Count <= 800;
            double bucketSeconds = Math.Max(0.12, viewDurationSeconds / Math.Max(60, targetVisibleCount));
            List<TelemetryEvent> clustered = new();

            for (int iteration = 0; iteration < 5; iteration += 1)
            {
                clustered = BuildClusteredViewportEvents(rawVisibleEvents, bucketSeconds, includeThreadId);
                if (clustered.Count <= targetVisibleCount)
                {
                    break;
                }

                if (includeThreadId && rawVisibleEvents.Count > targetVisibleCount * 2)
                {
                    includeThreadId = false;
                    continue;
                }

                bucketSeconds *= 1.7;
            }

            return clustered;
        }

        private List<TelemetryEvent> BuildClusteredViewportEvents(IReadOnlyList<TelemetryEvent> rawVisibleEvents,
                                                                  double bucketSeconds, bool includeThreadId)
        {
            var buckets = new Dictionary<string, List<TelemetryEvent>>(StringComparer.Ordinal);
            for (int i = 0; i < rawVisibleEvents.Count; i += 1)
            {
                TelemetryEvent ev = rawVisibleEvents[i];
                long bucketIndex = (long)Math.Floor(Math.Max(0, (ev.TimestampUtc - _captureStartUtc).TotalSeconds) /
                                                    Math.Max(0.01, bucketSeconds));
                string normalizedSummary = NormalizeClusterSummary(ev.Summary);
                int clusterTid = includeThreadId ? ev.TID : 0;
                string key =
                    $"{bucketIndex}|{ev.PID}|{clusterTid}|{ev.Group}|{ev.SubType}|{normalizedSummary}|{ev.ProcessName}";
                if (!buckets.TryGetValue(key, out List<TelemetryEvent>? members))
                {
                    members = new List<TelemetryEvent>(4);
                    buckets[key] = members;
                }

                members.Add(ev);
            }

            var displayEvents = new List<TelemetryEvent>(buckets.Count);
            foreach (List<TelemetryEvent> members in buckets.Values.OrderBy(x => x[^1].TimestampUtc))
            {
                if (members.Count == 1)
                {
                    TelemetryEvent raw = members[0];
                    _focusedClusterMembers[new EventSelectionKey(raw)] = members;
                    displayEvents.Add(raw);
                    continue;
                }

                TelemetryEvent first = members[0];
                TelemetryEvent last = members[^1];
                bool mixedThreads = members.Any(x => x.TID != first.TID);
                bool mixedProcesses = members.Any(x => x.PID != first.PID);
                string baseSummary = string.IsNullOrWhiteSpace(last.Summary) ? last.SubType : last.Summary;
                string summary = $"[{members.Count}x] {baseSummary}";
                string details =
                    $"cluster-count={members.Count}; first={first.TimestampUtc:O}; last={last.TimestampUtc:O}; " +
                    $"group={first.Group}; subtype={first.SubType}; mixedThreads={(mixedThreads ? "yes" : "no")}; mixedProcesses={(mixedProcesses ? "yes" : "no")}";

                var clustered = new TelemetryEvent { TimestampUtc = last.TimestampUtc,
                                                     PID = mixedProcesses ? 0 : first.PID,
                                                     TID = mixedThreads ? 0 : first.TID,
                                                     Group = first.Group,
                                                     SubType = first.SubType,
                                                     ProcessName = first.ProcessName,
                                                     Summary = summary,
                                                     Details = details };

                _focusedClusterMembers[new EventSelectionKey(clustered)] = members;
                displayEvents.Add(clustered);
            }

            return displayEvents;
        }

        private static string NormalizeClusterSummary(string? summary)
        {
            if (string.IsNullOrWhiteSpace(summary))
            {
                return string.Empty;
            }

            string normalized = summary.Trim();
            if (normalized.Length > 160)
            {
                normalized = normalized[..160];
            }

            return normalized;
        }

        private IReadOnlyList<TelemetryEvent> GetFocusedEventMembers(TelemetryEvent? displayEvent)
        {
            if (displayEvent == null)
            {
                return Array.Empty<TelemetryEvent>();
            }

            if (_focusedClusterMembers.TryGetValue(new EventSelectionKey(displayEvent), out IReadOnlyList<TelemetryEvent>? members))
            {
                return members;
            }

            return new[] { displayEvent };
        }

        private IReadOnlyList<TelemetryEvent> ExpandFocusedEventMembers(IEnumerable<TelemetryEvent> displayEvents)
        {
            var expanded = new List<TelemetryEvent>();
            foreach (TelemetryEvent ev in displayEvents)
            {
                expanded.AddRange(GetFocusedEventMembers(ev));
            }

            return expanded;
        }

        private void UpdateTopTimeTravelBar()
        {
            if (TopTimeTravelSlider == null || TopTimeTravelRangeBlock == null || EventsPaneHost?.Scroll == null ||
                EventsPaneHost?.Timeline == null)
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
            TopTimeTravelRangeBlock.Text = $"{viewStart:HH:mm:ss}-{viewEnd:HH:mm:ss}";
        }

        private void TopTimeTravelSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (_topTimeTravelSyncing || EventsPaneHost?.Scroll == null || EventsPaneHost?.Timeline == null)
            {
                return;
            }

            ApplyTimelineViewport(e.NewValue, syncScroll: true, updateFollowState: true);
        }

        private void NudgeTopTimeTravel(double secondsDelta)
        {
            if (EventsPaneHost?.Scroll == null || EventsPaneHost?.Timeline == null)
            {
                return;
            }

            ApplyTimelineViewport(EventsPaneHost.Scroll.Value + secondsDelta, syncScroll: true,
                                  updateFollowState: true);
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
            Dispatcher.BeginInvoke(
                new Action(
                    () =>
                    {
                        _viewportRefreshPending = false;
                        UpdateScrollBar();
                        if (_followLiveTimeline && EventsPaneHost?.Scroll != null)
                        {
                            ApplyTimelineViewport(
                                ComputeTimelineMaxStart(Math.Max(1, EventsPaneHost.Scroll.ViewportSize)),
                                syncScroll: true, updateFollowState: false);
                        }
                        else
                        {
                            FocusViewport();
                            UpdateTopTimeTravelBar();
                            SyncPerformanceViewToTimeline();
                        }
                        double viewStartSeconds = EventsPaneHost?.Timeline?.ViewStartSeconds ?? 0;
                        DiagnosticsState.SetValue(
                            "UI Viewport",
                            $"view={_focusedEvents.Count} total={_allEvents.Count} start={viewStartSeconds:0.0}s");
                    }),
                System.Windows.Threading.DispatcherPriority.Background);
        }

        private double ComputeTimelineMaxStart(double viewportSeconds)
        {
            double viewport = Math.Max(1, viewportSeconds);
            double totalSeconds = Math.Max(0, (GetTimelineHorizonUtc() - _captureStartUtc).TotalSeconds);
            return Math.Max(0, totalSeconds - viewport);
        }

        private DateTime GetTimelineHorizonUtc()
        {
            DateTime eventHorizon =
                _latestEventTimestampUtc > _captureStartUtc ? _latestEventTimestampUtc : _captureStartUtc;
            return eventHorizon;
        }

        private static DateTime AnchorCaptureStartUtc(double viewDurationSeconds)
        {
            double seconds = Math.Max(1, viewDurationSeconds);
            return DateTime.UtcNow - TimeSpan.FromSeconds(seconds);
        }

        private TelemetryEvent NormalizeTelemetryEventForStore(TelemetryEvent source)
        {
            string group = _telemetryTextPool.Intern(source.Group, 48);
            string subType = _telemetryTextPool.Intern(source.SubType, 96);
            string processName = _telemetryTextPool.Intern(source.ProcessName, 96);
            string summary = _telemetryTextPool.Intern(source.Summary, 160);
            string details = _telemetryTextPool.Intern(source.Details, 384);

            if (ReferenceEquals(group, source.Group) && ReferenceEquals(subType, source.SubType) &&
                ReferenceEquals(processName, source.ProcessName) && ReferenceEquals(summary, source.Summary) &&
                ReferenceEquals(details, source.Details))
            {
                return source;
            }

            return new TelemetryEvent { TimestampUtc = source.TimestampUtc,
                                        PID = source.PID,
                                        TID = source.TID,
                                        Group = group,
                                        SubType = subType,
                                        ProcessName = processName,
                                        Summary = summary,
                                        Details = details };
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

            string key = string.IsNullOrWhiteSpace(ev.SubType) ? ev.Group : $"{ev.Group}/{ev.SubType}";
            return string.Equals(key, _laneFocusKey, StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(ev.Group, _laneFocusKey, StringComparison.OrdinalIgnoreCase);
        }

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

            var miEnableDisable =
                new MenuItem { Header = EventsPaneHost.Timeline.IsLaneVisible(e.LaneKey) ? "Disable" : "Enable" };
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
                Color[] options = {
                    Color.FromRgb(0x4C, 0x8F, 0xD2), Color.FromRgb(0x6C, 0xA4, 0xDE), Color.FromRgb(0x58, 0xB6, 0x58),
                    Color.FromRgb(0x7B, 0xC7, 0x7B), Color.FromRgb(0x8D, 0x97, 0xA3),
                };

                int idx = (Math.Abs(e.LaneKey.GetHashCode()) % options.Length);
                var next = options[(idx + DateTime.UtcNow.Second) % options.Length];
                EventsPaneHost.Timeline.SetLaneColor(e.LaneKey, next);
            };
            menu.Items.Add(miColor);

            menu.IsOpen = true;
        }

        private void Timeline_EventDoubleClicked(object? sender, TelemetryEventSelectedEventArgs e)
        {
            _ = sender;
            _ = e;
        }

        private EventSelectionKey? CaptureSelectedEventAnchor()
        {
            if (_eventSelectionSyncing)
            {
                return _selectedEventAnchor;
            }

            if (EventsPaneHost.Grid.SelectedItem is TelemetryEvent selectedInGrid)
            {
                return new EventSelectionKey(selectedInGrid);
            }

            if (EventsPaneHost.Timeline.SelectedEvent is TelemetryEvent selectedInTimeline)
            {
                return new EventSelectionKey(selectedInTimeline);
            }

            return _selectedEventAnchor;
        }

        private void RestoreSelectedEventInFocusedView(EventSelectionKey? preferred)
        {
            if (preferred is not EventSelectionKey key || _focusedEvents.Count == 0)
            {
                if (preferred == null)
                {
                    ClearSelectedEvent();
                }
                return;
            }

            TelemetryEvent? matched = _focusedEvents.FirstOrDefault(ev => key.Matches(ev));
            if (matched != null)
            {
                ApplySelectedEvent(matched, scrollIntoView: false);
                return;
            }

            TelemetryEvent? clusteredMatch =
                _focusedEvents.FirstOrDefault(ev => GetFocusedEventMembers(ev).Any(raw => key.Matches(raw)));
            if (clusteredMatch != null)
            {
                ApplySelectedEvent(clusteredMatch, scrollIntoView: false);
                return;
            }

            if (_selectedEventAnchor.HasValue && !_selectedEventAnchor.Value.Equals(key))
            {
                TelemetryEvent? fallback = _focusedEvents.FirstOrDefault(ev => _selectedEventAnchor.Value.Matches(ev));
                if (fallback != null)
                {
                    ApplySelectedEvent(fallback, scrollIntoView: false);
                    return;
                }

                TelemetryEvent? clusteredFallback = _focusedEvents.FirstOrDefault(
                    ev => GetFocusedEventMembers(ev).Any(raw => _selectedEventAnchor.Value.Matches(raw)));
                if (clusteredFallback != null)
                {
                    ApplySelectedEvent(clusteredFallback, scrollIntoView: false);
                }
            }
        }

        private void ApplySelectedEvent(TelemetryEvent? selected, bool scrollIntoView)
        {
            if (EventsPaneHost?.Grid == null || EventsPaneHost?.Timeline == null)
            {
                return;
            }

            _eventSelectionSyncing = true;
            try
            {
                EventsPaneHost.Timeline.SelectedEvent = selected;
                EventsPaneHost.Grid.SelectedItem = selected;
                if (selected != null)
                {
                    UpdateSelectedEventAnchor(selected);
                    if (scrollIntoView)
                    {
                        EventsPaneHost.Grid.ScrollIntoView(selected);
                    }
                }
            }
            finally
            {
                _eventSelectionSyncing = false;
            }
        }

        private void UpdateSelectedEventAnchor(TelemetryEvent selected)
        {
            _selectedEventAnchor = new EventSelectionKey(selected);
        }

        private void ClearSelectedEvent()
        {
            if (EventsPaneHost?.Grid == null || EventsPaneHost?.Timeline == null)
            {
                _selectedEventAnchor = null;
                return;
            }

            _eventSelectionSyncing = true;
            try
            {
                EventsPaneHost.Grid.SelectedItem = null;
                EventsPaneHost.Timeline.SelectedEvent = null;
                _selectedEventAnchor = null;
            }
            finally
            {
                _eventSelectionSyncing = false;
            }
        }

        private void Timeline_SelectedEventChanged(object? sender, TelemetryEventSelectedEventArgs e)
        {
            if (_eventSelectionSyncing)
                return;

            if (e.Selected == null)
                return;

            ApplySelectedEvent(e.Selected, scrollIntoView: true);
        }

        private void Grid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_eventSelectionSyncing)
                return;

            if (EventsPaneHost.Grid.SelectedItem is TelemetryEvent te)
            {
                ApplySelectedEvent(te, scrollIntoView: false);
            }
        }

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
            if (sw != null)
                sw.IsEnabled = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void HideHeuristicsPane()
        {
            var heur = FindExplorerItem("Heuristics");
            if (heur != null)
                heur.IsEnabled = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void HideFilesystemPane()
        {
            var fs = FindExplorerItem("Filesystem");
            if (fs != null)
                fs.IsEnabled = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void HideRegistryPane()
        {
            var reg = FindExplorerItem("Registry");
            if (reg != null)
                reg.IsEnabled = false;
            ApplyDockVisibilityFromExplorer();
        }

        private void HideProcessRelationsPane()
        {
            var rel = FindExplorerItem("Process Relations");
            if (rel != null)
                rel.IsEnabled = false;
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

        private void ShowFilesystemPane()
        {
            SetExplorerPaneEnabled("Filesystem", true);
            ApplyDockVisibilityFromExplorer();
        }

        private void ShowRegistryPane()
        {
            SetExplorerPaneEnabled("Registry", true);
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

        private void SetMainInterfaceViewMode(MainInterfaceViewMode mode)
        {
            _mainViewMode = mode;
            if (DockGrid != null)
            {
                DockGrid.Visibility =
                    mode == MainInterfaceViewMode.Telemetry ? Visibility.Visible : Visibility.Collapsed;
            }
            if (ApiViewBorder != null)
            {
                ApiViewBorder.Visibility =
                    mode == MainInterfaceViewMode.Api ? Visibility.Visible : Visibility.Collapsed;
            }
            if (ExtendedViewBorder != null)
            {
                ExtendedViewBorder.Visibility =
                    mode == MainInterfaceViewMode.Extended ? Visibility.Visible : Visibility.Collapsed;
            }
            ApplyDockVisibilityFromExplorer();
            UpdateMainViewButtons(mode);

            if (IsLoaded)
            {
                RebuildToolbarViewMenuOptions();
            }
        }

        private void UpdateMainViewButtons(MainInterfaceViewMode mode)
        {
            SetMainViewButtonSelected(MainViewButton, mode == MainInterfaceViewMode.Telemetry);
            SetMainViewButtonSelected(ApiViewButton, mode == MainInterfaceViewMode.Api);
            SetMainViewButtonSelected(ExtendedViewButton, mode == MainInterfaceViewMode.Extended);
        }

        private static void SetMainViewButtonSelected(Button? button, bool selected)
        {
            if (button == null)
            {
                return;
            }
            button.IsEnabled = !selected;
            button.Opacity = selected ? 0.72 : 1.0;
        }

        private void MainView_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            SetMainInterfaceViewMode(MainInterfaceViewMode.Telemetry);
        }

        private void ApiView_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            SetMainInterfaceViewMode(MainInterfaceViewMode.Api);
        }

        private void ExtendedView_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            SetMainInterfaceViewMode(MainInterfaceViewMode.Extended);
        }

        private void OpenDiagnosticsWindow()
        {
            var w = new DiagnosticsWindow(TryGetPid()) { Owner = this };
            w.Show();
        }

        private void SignatureIntelRules_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            OpenSignatureIntelRulesWindow();
        }

        private void ProcessRelationsPaneHost_GraphStateChanged(object? sender, EventArgs e)
        {
            _ = sender;
            _ = e;
            ScheduleChildProcessGraphWindowRefresh();
        }

        private void OpenOrActivateChildProcessGraphWindow()
        {
            if (_childProcessGraphWindow == null)
            {
                _childProcessGraphWindow =
                    new ChildProcessGraphWindow(ProcessRelationsPaneHost.CurrentRootPid) { Owner = this };
                _childProcessGraphWindow.Closed += ChildProcessGraphWindow_Closed;
                RestoreChildProcessGraphStateFromSession();
                RefreshChildProcessGraphWindow();
                _childProcessGraphWindow.Show();
                RebuildToolbarViewMenuOptions();
                return;
            }

            RefreshChildProcessGraphWindow();
            if (_childProcessGraphWindow.WindowState == WindowState.Minimized)
            {
                _childProcessGraphWindow.WindowState = WindowState.Normal;
            }

            _childProcessGraphWindow.Activate();
        }

        private void RefreshChildProcessGraphWindowIfOpen()
        {
            if (_childProcessGraphWindow == null)
            {
                return;
            }

            RefreshChildProcessGraphWindow();
        }

        private void ScheduleChildProcessGraphWindowRefresh()
        {
            if (_childProcessGraphWindow == null)
            {
                return;
            }

            _childProcessGraphRefreshTimer.Stop();
            _childProcessGraphRefreshTimer.Start();
        }

        private void ChildProcessGraphRefreshTimer_Tick(object? sender, EventArgs e)
        {
            _ = sender;
            _ = e;
            _childProcessGraphRefreshTimer.Stop();
            RefreshChildProcessGraphWindowIfOpen();
        }

        private void RefreshChildProcessGraphWindow()
        {
            _childProcessGraphWindow?.UpdateGraph(ProcessRelationsPaneHost.SnapshotItems(),
                                                  ProcessRelationsPaneHost.CurrentRootPid);
        }

        private void ChildProcessGraphWindow_Closed(object? sender, EventArgs e)
        {
            _ = sender;
            _ = e;
            SaveChildProcessGraphStateToSession();
            if (_childProcessGraphWindow != null)
            {
                _childProcessGraphWindow.Closed -= ChildProcessGraphWindow_Closed;
            }

            _childProcessGraphWindow = null;
            RebuildToolbarViewMenuOptions();
        }

        private void SaveChildProcessGraphStateToSession(ProcessSessionTab? tab = null)
        {
            ProcessSessionTab? session = tab ?? _currentSession;
            if (session == null)
            {
                return;
            }

            session.ChildProcessExpandedKeys.Clear();
            if (_childProcessGraphWindow == null)
            {
                return;
            }

            foreach (string key in _childProcessGraphWindow.GetExpandedKeysSnapshot())
            {
                session.ChildProcessExpandedKeys.Add(key);
            }
        }

        private void RestoreChildProcessGraphStateFromSession(ProcessSessionTab? tab = null)
        {
            if (_childProcessGraphWindow == null)
            {
                return;
            }

            _childProcessGraphWindow.SetExpandedKeys((tab ?? _currentSession)?.ChildProcessExpandedKeys);
        }

        private void LayoutsComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = e;
            if (!IsLoaded || sender is not ComboBox combo)
                return;

            string? tag = (combo.SelectedItem as System.Windows.Controls.ContentControl)?.Tag as string;
            if (string.IsNullOrEmpty(tag))
                return;

            combo.SelectedIndex = 0;

            if (tag == "layout-simple")
            {
                ApplySimpleLayout();
            }
            else if (tag == "layout-advanced")
            {
                ApplyAdvancedLayout();
            }
        }

        private void ApplySimpleLayout()
        {
            if (EtwPaneHost != null)
                EtwPaneHost.Visibility = Visibility.Collapsed;
            if (HeuristicsPaneHost != null)
                HeuristicsPaneHost.Visibility = Visibility.Collapsed;
            if (FilesystemPaneHost != null)
                FilesystemPaneHost.Visibility = Visibility.Collapsed;
            if (ProcessRelationsPaneHost != null)
                ProcessRelationsPaneHost.Visibility = Visibility.Collapsed;
            if (IntelligenceColumn != null)
                IntelligenceColumn.Width = new GridLength(0);
            if (IntelligenceSplitterColumn != null)
                IntelligenceSplitterColumn.Width = new GridLength(0);
        }

        private void ApplyAdvancedLayout()
        {
            if (EtwPaneHost != null)
                EtwPaneHost.Visibility = Visibility.Visible;
            if (HeuristicsPaneHost != null)
                HeuristicsPaneHost.Visibility = Visibility.Visible;
            if (FilesystemPaneHost != null)
                FilesystemPaneHost.Visibility = Visibility.Visible;
            if (ProcessRelationsPaneHost != null)
                ProcessRelationsPaneHost.Visibility = Visibility.Visible;
            if (IntelligenceColumn != null)
                IntelligenceColumn.Width = new GridLength(560);
            if (IntelligenceSplitterColumn != null)
                IntelligenceSplitterColumn.Width = new GridLength(2);
        }

        private void ToolbarViewMenu_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = e;
            if (_toolbarViewMenuSyncing || !IsLoaded || sender is not ComboBox combo)
            {
                return;
            }

            string tag = combo.SelectedItem switch { ComboBoxItem item when item.Tag is string itemTag => itemTag,
                                                     _ => string.Empty };
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
            case "registry":
                ShowRegistryPane();
                break;
            case "process-relations":
                ShowProcessRelationsPane();
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
            case "inspector-registry":
                ShowRegistryPane();
                OpenRegistryInspector();
                break;
            case "inspector-relations":
                ShowProcessRelationsPane();
                OpenProcessRelationsInspector();
                break;
            case "diagnostics":
                OpenDiagnosticsWindow();
                break;
            case "signature-intel-rules":
                OpenSignatureIntelRulesWindow();
                break;
            case "child-process-graph":
                OpenOrActivateChildProcessGraphWindow();
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
            AddToolbarViewOptionIfClosed("Registry Pane", "registry", IsRegistryPaneOpen());
            AddToolbarViewOptionIfClosed("Process Relations Pane", "process-relations", IsRelationsPaneOpen());
            AddToolbarViewOptionIfClosed("Event Log Window", "event-log",
                                         _eventLogWindow != null && _eventLogWindow.IsVisible);
            AddToolbarViewOptionIfClosed("ETW Inspector", "inspector-etw", IsWindowOpenByTitle("ETW Inspector"));
            AddToolbarViewOptionIfClosed("Heuristics Inspector", "inspector-heuristics",
                                         IsWindowOpenByTitle("Detection Chain"));
            AddToolbarViewOptionIfClosed("Filesystem Inspector", "inspector-filesystem",
                                         IsWindowOpenByTitle("Filesystem"));
            AddToolbarViewOptionIfClosed("Registry Inspector", "inspector-registry", IsWindowOpenByTitle("Registry"));
            AddToolbarViewOptionIfClosed("Process Relations Inspector", "inspector-relations",
                                         IsWindowOpenByTitle("Process Relations"));
            AddToolbarViewOptionIfClosed(
                "Diagnostics Window", "diagnostics",
                Application.Current.Windows.OfType<Window>().Any(w => w is DiagnosticsWindow && w.IsVisible));
            AddToolbarViewOptionIfClosed(
                "Rules Intel", "signature-intel-rules",
                Application.Current.Windows.OfType<Window>().Any(w => w is SignatureIntelRulesWindow && w.IsVisible));
            AddToolbarViewOptionIfClosed("Child Process Graph", "child-process-graph",
                                         _childProcessGraphWindow != null && _childProcessGraphWindow.IsVisible);

            ToolbarViewMenu.SelectedIndex = 0;
            _toolbarViewMenuSyncing = false;
        }

        private void AddToolbarViewOptionIfClosed(string label, string tag, bool isOpen)
        {
            if (ToolbarViewMenu == null || isOpen)
            {
                return;
            }

            ToolbarViewMenu.Items.Add(new ComboBoxItem { Content = label, Tag = tag });
        }

        private bool IsEventsPaneOpen() => (FindExplorerItem("Events")?.IsEnabled ?? true) &&
                                           (_eventsPaneVisible || _eventsPaneFloating || _eventsFloatWindow != null);

        private bool IsPerformancePaneOpen() => (FindExplorerItem("Performance")?.IsEnabled ?? true) &&
                                                (_performancePaneVisible || _performancePaneFloating ||
                                                 _performanceFloatWindow != null);

        private bool IsEtwPaneOpen() => (FindExplorerItem("ETW")?.IsEnabled ?? true);

        private bool IsHeuristicsPaneOpen() => (FindExplorerItem("Heuristics")?.IsEnabled ?? true);

        private bool IsFilesystemPaneOpen() => (FindExplorerItem("Filesystem")?.IsEnabled ?? true);

        private bool IsRegistryPaneOpen() => (FindExplorerItem("Registry")?.IsEnabled ?? true);

        private bool IsRelationsPaneOpen() => (FindExplorerItem("Process Relations")?.IsEnabled ?? true);

        private static bool IsWindowOpenByTitle(string title) =>
            Application.Current?.Windows.OfType<Window>().Any(w => w.IsVisible &&
                                                                   string.Equals(w.Title, title,
                                                                                 StringComparison.OrdinalIgnoreCase)) ??
            false;

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

            _eventLogWindow = new EventLogWindow { Owner = this, ShowInTaskbar = false };
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
            if (e == null)
            {
                return;
            }

            var displayMatches =
                _focusedEvents
                    .Where(ev => EventMatchesLogCard(ev, e.Group, e.SubType, e.Summary, e.Details, e.Pid, e.Tid))
                    .ToList();
            OpenEventLogDetailWindow("Event Log Detail", ExpandFocusedEventMembers(displayMatches));
        }

        private void EventsPaneHost_EventLogEntryOpenRequested(object? sender, EventLogEntryOpenRequestedEventArgs e)
        {
            _ = sender;
            if (e?.Event == null)
            {
                return;
            }

            TelemetryEvent selected = e.Event;
            OpenEventLogDetailWindow("Event Detail", GetFocusedEventMembers(selected));
        }

        private void OpenEventLogDetailWindow(string title, IReadOnlyList<TelemetryEvent> matches)
        {
            if (matches == null || matches.Count == 0)
            {
                return;
            }

            GroupedEventRow row = BuildEventLogDetailRow(matches);
            var detail = new SimpleEventDetailWindow(title, row) { Owner = this };
            detail.Show();
            detail.Activate();
        }

        private static bool EventMatchesLogCard(TelemetryEvent ev, string group, string subType, string summary,
                                                string details, int pid, int tid)
        {
            if (ev == null)
            {
                return false;
            }

            return string.Equals(ev.Group ?? string.Empty, group ?? string.Empty, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(ev.SubType ?? string.Empty, subType ?? string.Empty,
                                 StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(ev.Summary ?? string.Empty, summary ?? string.Empty, StringComparison.Ordinal) &&
                   string.Equals(ev.Details ?? string.Empty, details ?? string.Empty, StringComparison.Ordinal) &&
                   ev.PID == pid && ev.TID == tid;
        }

        private static GroupedEventRow BuildEventLogDetailRow(IReadOnlyList<TelemetryEvent> matches)
        {
            TelemetryEvent first = matches[0];
            string group = string.IsNullOrWhiteSpace(first.Group) ? "Other" : first.Group;
            string subType = first.SubType ?? string.Empty;
            string eventName = string.IsNullOrWhiteSpace(subType) ? group : $"{group}/{subType}";
            string summary = first.Summary ?? string.Empty;
            string key =
                $"{group}\u001F{subType}\u001F{first.PID}\u001F{first.TID}\u001F{summary}\u001F{first.Details}";

            var row = new GroupedEventRow { GroupKey = key,      LastSeenUtc = matches.Max(x => x.TimestampUtc),
                                            Event = eventName,   Severity = "Event",
                                            Detection = summary, Hits = matches.Count };

            foreach (TelemetryEvent ev in matches.OrderByDescending(x => x.TimestampUtc))
            {
                string actor = string.IsNullOrWhiteSpace(ev.ProcessName) ? $"pid:{ev.PID}" : ev.ProcessName;
                string target = ev.TID > 0 ? $"tid={ev.TID}" : string.Empty;

                row.Details.Add(new GroupedEventDetailRow {
                    TimestampUtc = ev.TimestampUtc, Event = eventName, Severity = "Event",
                    Detection = ev.Summary ?? string.Empty, Source = group, Actor = actor, Target = target,
                    ActorPid = ev.PID > 0 ? unchecked((uint)ev.PID) : 0u, TargetPid = 0u,
                    ActorToolTip = ev.PID > 0 ? $"PID {ev.PID}" : string.Empty, Details = ev.Details ?? string.Empty
                });
            }

            return row;
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
            if (sw != null)
                sw.IsEnabled = true;
            var heur = FindExplorerItem("Heuristics");
            if (heur != null)
                heur.IsEnabled = true;
            var fs = FindExplorerItem("Filesystem");
            if (fs != null)
                fs.IsEnabled = true;
            var rel = FindExplorerItem("Process Relations");
            if (rel != null)
                rel.IsEnabled = true;
            var ipc = FindExplorerItem("IPC Uplink");
            if (ipc != null)
                ipc.IsEnabled = false;
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

        private void ChildProcessView_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            OpenOrActivateChildProcessGraphWindow();
        }

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

        private void PerformancePaneHost_DisassemblyRequested(object? sender, MemoryDisassemblyRequestedEventArgs e)
        {
            if (_backendSession == null || !BkdcNative.IsAvailable)
                return;
            var w = new DisassemblyWindow(_backendSession, e.ProcessId, e.BaseAddress, e.RegionSize, e.Label,
                                          e.SnapshotBytes, e.SnapshotOffset) { Owner = this };
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

        private async void FindProcess_Click(object sender, RoutedEventArgs e) =>
            await OpenProcessPickerAndConnectAsync(showLaunchOptions: true);

        private async void NewProcessTab_Click(object sender, RoutedEventArgs e) =>
            await OpenProcessPickerAndConnectAsync(showLaunchOptions: true);

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
                PerformancePaneHost.SetTargetSuspended(false);
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

            _queuedSessionSwitchTab = tab;
            if (_sessionSwitchQueued)
            {
                return;
            }

            _sessionSwitchQueued = true;
            Dispatcher.BeginInvoke(new Action(
                () =>
                {
                    _sessionSwitchQueued = false;
                    ProcessSessionTab? pending = _queuedSessionSwitchTab;
                    _queuedSessionSwitchTab = null;
                    if (pending == null || !ReferenceEquals(ProcessTabs.SelectedItem, pending) ||
                        _isMainWindowShuttingDown)
                    {
                        return;
                    }

                    SwitchToSession(pending);
                    RefreshProcessStateBadge();
                }), DispatcherPriority.Background);
        }

        private DateTime GetCurrentObservedUtc()
        {
            if (EventsPaneHost?.Timeline == null)
            {
                return DateTime.UtcNow;
            }

            return _captureStartUtc + TimeSpan.FromSeconds(EventsPaneHost.Timeline.ViewStartSeconds +
                                                           EventsPaneHost.Timeline.ViewDurationSeconds);
        }

        private static string ResolveHookDllPathFromInterfaceDirectory()
        {
            string baseDirectory = AppContext.BaseDirectory;
            if (string.IsNullOrWhiteSpace(baseDirectory))
            {
                baseDirectory = Environment.CurrentDirectory;
            }

            return Path.Combine(baseDirectory, "SR71.dll");
        }

        private static string ResolveDllHostPathFromInterfaceDirectory()
        {
            string baseDirectory = AppContext.BaseDirectory;
            if (string.IsNullOrWhiteSpace(baseDirectory))
            {
                baseDirectory = Environment.CurrentDirectory;
            }

            return Path.Combine(baseDirectory, "BlackbirdDllHost.exe");
        }

        private static string QuoteCommandLineArgument(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return "\"\"";
            }

            var builder = new System.Text.StringBuilder();
            builder.Append('"');
            int backslashes = 0;
            foreach (char ch in value)
            {
                if (ch == '\\')
                {
                    backslashes += 1;
                    continue;
                }

                if (ch == '"')
                {
                    builder.Append('\\', backslashes * 2 + 1);
                    builder.Append('"');
                    backslashes = 0;
                    continue;
                }

                if (backslashes > 0)
                {
                    builder.Append('\\', backslashes);
                    backslashes = 0;
                }
                builder.Append(ch);
            }

            if (backslashes > 0)
            {
                builder.Append('\\', backslashes * 2);
            }
            builder.Append('"');
            return builder.ToString();
        }

        private static string BuildDllHostCommandLineArguments(LaunchProfile launchProfile)
        {
            var args = new List<string> {
                "--dll",
                QuoteCommandLineArgument(launchProfile.AnalysisSubjectPath),
                "--mode",
                launchProfile.DllMode switch { DllLaunchMode.Export => "export", DllLaunchMode.Rundll => "rundll",
                                               DllLaunchMode.Register => "register",
                                               DllLaunchMode.Unregister => "unregister",
                                               DllLaunchMode.Install => "install",
                                               _ => "load" },
                "--wait-ms",
                launchProfile.DllWaitMilliseconds.ToString(System.Globalization.CultureInfo.InvariantCulture)
            };

            if (launchProfile.HasDllExportName)
            {
                args.Add("--export");
                args.Add(QuoteCommandLineArgument(launchProfile.DllExportName));
            }
            if (launchProfile.HasDllExportOrdinal)
            {
                args.Add("--ordinal");
                args.Add(launchProfile.DllExportOrdinal.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
            if (launchProfile.HasDllArgument)
            {
                args.Add("--arg");
                args.Add(QuoteCommandLineArgument(launchProfile.DllArgument));
            }
            if (launchProfile.HasDllLoadFlags)
            {
                args.Add("--load-flags");
                args.Add("0x" +
                         launchProfile.DllLoadFlags.ToString("X", System.Globalization.CultureInfo.InvariantCulture));
            }
            if (launchProfile.DllFreeOnExit)
            {
                args.Add("--free-on-exit");
            }
            if (launchProfile.DllInstallDisable)
            {
                args.Add("--install-disable");
            }

            return string.Join(" ", args);
        }

        private bool TrySendUserHookRequest(uint mode, uint processId, uint flags, string? imagePath,
                                            out BlackbirdNative.BkSetUserHookTargetResponse response, out string error)
        {
            response = default;
            error = string.Empty;

            if (!BkctlDeviceSession.TryOpen(out var control, out error))
            {
                return false;
            }

            using (control)
            {
                string hookPath = ResolveHookDllPathFromInterfaceDirectory();
                if (!File.Exists(hookPath))
                {
                    error = $"SetUserHookTarget failed because the hook DLL is missing: '{hookPath}'.";
                    return false;
                }

                if (!BlackbirdNative.SetUserHookTarget(control.Handle, mode, processId, flags, imagePath,
                                                       BlackbirdNative.AnalysisSubjectKindProcess, null, hookPath, null,
                                                       null, null, 0, 0, 0, false,
                                                       BlackbirdNative.LaunchIntegrityDefault, out response))
                {
                    error = BkctlDeviceSession.FormatUserHookOperationError(
                        "SetUserHookTarget", BlackbirdNative.LastError("SetUserHookTarget failed"), hookPath);
                    return false;
                }

                return true;
            }
        }

        private bool TryAttachUsermodeHooks(int pid, out string error)
        {
            error = string.Empty;
            if (pid <= 0)
            {
                error = "Invalid PID for hook attach.";
                return false;
            }

            if (!TrySendUserHookRequest(BlackbirdNative.IpcUserHookTargetAttach, unchecked((uint)pid), 0, null, out _,
                                        out error))
            {
                return false;
            }

            OutputCapture.AppendLine($"Hook attached via controller: PID {pid}");
            return true;
        }

        private bool EnsureNoHookControllerCallInFlight(string operation)
        {
            if (!_hookControllerCallInFlight)
            {
                return true;
            }

            string message =
                "A hook launch or attach request is still waiting for the controller to return. " +
                "Blackbird will not start another hook operation until that call unwinds.";
            StatusBlock.Text = "HOOK CONTROLLER REQUEST STILL IN PROGRESS";
            OutputCapture.AppendLine($"Blocked overlapping hook operation ({operation}): previous request in-flight.");
            ThemedMessageBox.Show(this, message, "Hook Operation In Progress", MessageBoxButton.OK,
                                  MessageBoxImage.Warning);
            return false;
        }

        private AnalysisOperationGuard BeginAnalysisOperation(string operation)
        {
            var guard = new AnalysisOperationGuard(this, operation);
            _activeAnalysisOperation = guard;
            return guard;
        }

        private void CancelActiveAnalysisOperationForShutdown()
        {
            AnalysisOperationGuard? guard = _activeAnalysisOperation;
            if (guard != null)
            {
                guard.Cancel();
                guard.CleanupAfterAbort();
            }

            CompleteHookControllerCall();
            _openingProcessPicker = false;
            _connectInProgress = false;
        }

        private void CleanupAbortedAnalysisOperation(AnalysisOperationGuard guard)
        {
            DisposePreparedLaunchBackendSession();
            ClearPendingLaunchOptions();

            if (guard.SessionStartAttempted || _isMainWindowShuttingDown)
            {
                StopLiveAnalysisSession(LiveAnalysisStopReason.OperationAbort, preserveApiGraphSnapshot: true,
                                        fastTeardown: true, stopPerformance: true);
            }

            if (guard.LaunchOwnedPid > 0)
            {
                if (TryTerminateTargetProcess(guard.LaunchOwnedPid, out string terminateError))
                {
                    AppendOutputFromAnyThread(
                        $"Analysis operation cleanup terminated launch-owned target: PID {guard.LaunchOwnedPid}");
                }
                else
                {
                    AppendOutputFromAnyThread(
                        $"Analysis operation cleanup could not terminate PID {guard.LaunchOwnedPid}: {terminateError}");
                }
            }
        }

        private void CompleteHookControllerCall()
        {
            _hookControllerCallInFlight = false;
        }

        private void TrackLiveAnalysisSession(int pid, ProcessSessionTab? tab)
        {
            _liveAnalysisSession = new LiveAnalysisSessionLease(pid, tab, tab?.LaunchOwnedByInterface == true);
        }

        private void StopLiveAnalysisSession(LiveAnalysisStopReason reason, bool preserveApiGraphSnapshot = false,
                                             bool fastTeardown = false, bool stopPerformance = false)
        {
            LiveAnalysisSessionLease? lease = _liveAnalysisSession;
            if (lease != null && !lease.TryBeginTeardown())
            {
                lease = null;
            }
            _liveAnalysisSession = null;

            StopTargetExitWatcher();
            StopBackendSession(preserveApiGraphSnapshot, fastTeardown);

            if (stopPerformance)
            {
                _perf?.Stop();
                _samplerPid = 0;
                if (PerformancePaneHost != null)
                {
                    PerformancePaneHost.SetProcessLiveDataAvailable(false);
                    PerformancePaneHost.SetTargetSuspended(false);
                }
                _targetExecutionSuspended = false;
            }

            string reasonText = reason switch { LiveAnalysisStopReason.Shutdown => "shutdown",
                                                LiveAnalysisStopReason.TargetExited => "target-exit",
                                                LiveAnalysisStopReason.OperationAbort => "operation-abort",
                                                LiveAnalysisStopReason.SessionSwitch => "session-switch",
                                                _ => "teardown" };
            if (lease != null)
            {
                AppendOutputFromAnyThread(
                    $"Live analysis session detached pid={lease.Pid} reason={reasonText} launchOwned={lease.LaunchOwnedByInterface}");
            }
        }

        private enum LiveAnalysisStopReason
        {
            SessionSwitch,
            TargetExited,
            OperationAbort,
            Shutdown
        }

        private sealed class LiveAnalysisSessionLease
        {
            private int _teardownStarted;

            internal LiveAnalysisSessionLease(int pid, ProcessSessionTab? tab, bool launchOwnedByInterface)
            {
                Pid = pid;
                Tab = tab;
                LaunchOwnedByInterface = launchOwnedByInterface;
            }

            internal int Pid { get; }
            internal ProcessSessionTab? Tab { get; }
            internal bool LaunchOwnedByInterface { get; }

            internal bool TryBeginTeardown()
            {
                return Interlocked.Exchange(ref _teardownStarted, 1) == 0;
            }
        }

        private sealed class AnalysisOperationGuard : IDisposable
        {
            private readonly MainWindow _owner;
            private int _disposed;
            private int _cleanupStarted;
            private bool _completed;

            internal AnalysisOperationGuard(MainWindow owner, string operation)
            {
                _owner = owner;
                Operation = operation;
                Cancellation = new CancellationTokenSource();
            }

            internal string Operation { get; }
            internal CancellationTokenSource Cancellation { get; }
            internal CancellationToken Token => Cancellation.Token;
            internal int LaunchOwnedPid { get; private set; }
            internal bool SessionStartAttempted { get; private set; }

            internal void TrackLaunchOwnedPid(int pid)
            {
                if (pid > 0)
                {
                    LaunchOwnedPid = pid;
                }
            }

            internal void MarkSessionStartAttempted()
            {
                SessionStartAttempted = true;
            }

            internal void Complete()
            {
                _completed = true;
            }

            internal void Cancel()
            {
                try
                {
                    Cancellation.Cancel();
                }
                catch
                {
                }
            }

            internal void CleanupAfterAbort()
            {
                if (_completed || Interlocked.Exchange(ref _cleanupStarted, 1) != 0)
                {
                    return;
                }

                _owner.CleanupAbortedAnalysisOperation(this);
            }

            public void Dispose()
            {
                if (Interlocked.Exchange(ref _disposed, 1) != 0)
                {
                    return;
                }

                if (ReferenceEquals(_owner._activeAnalysisOperation, this))
                {
                    _owner._activeAnalysisOperation = null;
                }

                CleanupAfterAbort();
                Cancellation.Dispose();
            }
        }

        private void AppendOutputFromAnyThread(string message)
        {
            if (Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished)
            {
                return;
            }

            if (Dispatcher.CheckAccess())
            {
                OutputCapture.AppendLine(message);
                return;
            }

            Dispatcher.BeginInvoke(new Action(() => OutputCapture.AppendLine(message)), DispatcherPriority.Background);
        }

        private void CompleteHookControllerCallFromWorker<T>(Task<T> task, Action<T>? lateResultCleanup)
        {
            Exception? cleanupError = null;
            if (task.Status == TaskStatus.RanToCompletion)
            {
                try
                {
                    lateResultCleanup?.Invoke(task.Result);
                }
                catch (Exception ex)
                {
                    cleanupError = ex;
                }
            }
            else if (task.IsFaulted)
            {
                _ = task.Exception;
            }

            if (cleanupError != null)
            {
                AppendOutputFromAnyThread($"Late hook controller cleanup failed: {cleanupError.Message}");
            }
            if (Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished)
            {
                return;
            }

            Dispatcher.BeginInvoke(new Action(CompleteHookControllerCall), DispatcherPriority.Background);
        }

        private async Task<(bool Completed, T Result)> RunHookControllerCallWithTimeoutAsync<T>(
            Func<T> operation, LoadingWindow loading, string timeoutStatus, string timeoutDetail,
            Action<T>? lateResultCleanup = null, CancellationToken cancellationToken = default)
        {
            _hookControllerCallInFlight = true;
            Task<T> operationTask = Task.Run(operation);
            loading.StartTimeout(HookControllerCallTimeout);

            Task delayTask = Task.Delay(HookControllerCallTimeout, cancellationToken);
            Task completed = await Task.WhenAny(operationTask, delayTask);
            if (!ReferenceEquals(completed, operationTask))
            {
                if (!cancellationToken.IsCancellationRequested && !_isMainWindowShuttingDown)
                {
                    loading.SetTimedOut(timeoutStatus, timeoutDetail, HookControllerCallTimeout);
                    OutputCapture.AppendLine(
                        $"Hook controller request timed out after {HookControllerCallTimeoutSeconds}s; waiting for native IPC unwind.");
                }
                else
                {
                    AppendOutputFromAnyThread("Hook controller request cancelled during interface teardown.");
                }
                _ = operationTask.ContinueWith(task => CompleteHookControllerCallFromWorker(task, lateResultCleanup),
                                               CancellationToken.None,
                                               TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                if (!cancellationToken.IsCancellationRequested && !_isMainWindowShuttingDown)
                {
                    await Task.Delay(700);
                }
                return (false, default!);
            }

            try
            {
                T result = await operationTask;
                return (true, result);
            }
            finally
            {
                loading.StopTimeout();
                CompleteHookControllerCall();
            }
        }

        private bool TryLaunchWithUsermodeHooksAndPrepareSession(string imagePath, bool useEarlyBirdApc,
                                                                 LaunchProfile launchProfile, out int pid,
                                                                 out BlackbirdBackendSession? preparedSession,
                                                                 out string error)
        {
            pid = 0;
            preparedSession = null;
            error = string.Empty;
            if (string.IsNullOrWhiteSpace(imagePath))
            {
                error = "Launch path is empty.";
                return false;
            }
            if (launchProfile.HasCommandLineArguments &&
                launchProfile.CommandLineArguments.Length >= MaxControllerLaunchArgumentChars)
            {
                error =
                    $"Launch arguments are too long for the controller IPC limit ({MaxControllerLaunchArgumentChars - 1} characters).";
                return false;
            }

            uint flags = useEarlyBirdApc ? BlackbirdNative.IpcUserHookFlagLaunchEarlybirdApc : 0;
            if (launchProfile.LeaveSuspendedAfterReady)
            {
                flags |= BlackbirdNative.IpcUserHookFlagDeferredLaunchGateRelease;
            }

            try
            {
                if (!BkctlDeviceSession.TryOpen(out var control, out error))
                {
                    return false;
                }

                using (control)
                {
                    string hookPath = ResolveHookDllPathFromInterfaceDirectory();
                    if (!File.Exists(hookPath))
                    {
                        error = $"Hook launch failed because the hook DLL is missing: '{hookPath}'.";
                        return false;
                    }

                    string environmentOverrides = launchProfile.ToIpcEnvironmentOverrideBlock();
                    if (!BlackbirdNative.SetUserHookTarget(
                            control.Handle, BlackbirdNative.IpcUserHookTargetLaunch, 0, flags, imagePath,
                            launchProfile.HasAnalysisSubject ? BlackbirdNative.AnalysisSubjectKindDll
                                                             : BlackbirdNative.AnalysisSubjectKindProcess,
                            launchProfile.HasAnalysisSubject ? launchProfile.AnalysisSubjectPath : null, hookPath,
                            launchProfile.HasWorkingDirectory ? launchProfile.WorkingDirectory : null,
                            string.IsNullOrWhiteSpace(environmentOverrides) ? null : environmentOverrides,
                            launchProfile.HasCommandLineArguments ? launchProfile.CommandLineArguments : null,
                            launchProfile.ParentProcessId, MapLaunchPriorityClass(launchProfile.Priority),
                            launchProfile.AffinityMask, launchProfile.InheritHandles,
                            (uint)launchProfile.IntegrityLevel,
                            out BlackbirdNative.BkSetUserHookTargetResponse response))
                    {
                        error = BkctlDeviceSession.FormatUserHookOperationError(
                            "SetUserHookTarget(launch)", BlackbirdNative.LastError("SetUserHookTarget(launch) failed"),
                            hookPath);
                        return false;
                    }

                    if (response.ProcessId == 0)
                    {
                        error = "Controller launch returned no PID.";
                        return false;
                    }

                    pid = unchecked((int)response.ProcessId);
                    preparedSession = BlackbirdBackendSession.StartFromHandle(pid, BlackbirdNative.StreamAll,
                                                                              useUsermodeHooks: true, control.Handle);
                    _ = control.DetachHandle();

                    OutputCapture.AppendLine(
                        launchProfile.HasAnalysisSubject
                            ? $"Hook launch via controller (earlybird-apc): host={imagePath} subject={launchProfile.AnalysisSubjectPath} \u2192 PID {pid} (pre-armed session)"
                            : $"Hook launch via controller (earlybird-apc): {imagePath} \u2192 PID {pid} (pre-armed session)");
                    return true;
                }
            }
            catch (Exception ex)
            {
                if (preparedSession != null)
                {
                    preparedSession.Dispose();
                    preparedSession = null;
                }
                if (string.IsNullOrWhiteSpace(error))
                {
                    error = ex.Message;
                }
                return false;
            }
        }

        private async void Connect_Click(object sender, RoutedEventArgs e)
        {
            using AnalysisOperationGuard operation = BeginAnalysisOperation("attach/analyze");
            await ConnectToCurrentPidAsync(operation.Token, operation);
            if (operation.SessionStartAttempted && !operation.Token.IsCancellationRequested && !_isMainWindowShuttingDown)
            {
                operation.Complete();
            }
        }

        private async Task ConnectToCurrentPidAsync(CancellationToken cancellationToken,
                                                    AnalysisOperationGuard? operationGuard = null)
        {
            if (_connectInProgress || cancellationToken.IsCancellationRequested || _isMainWindowShuttingDown)
            {
                return;
            }

            _connectInProgress = true;
            try
            {
                int pid = TryGetPid();
                if (pid <= 0)
                {
                    DisposePreparedLaunchBackendSession();
                    ClearPendingLaunchOptions();
                    StatusBlock.Text = "ENTER A VALID PID";
                    RefreshProcessStateBadge();
                    return;
                }

                bool hookPreconfigured = _pendingHookPreconfigured;
                bool allowPreparedLaunchAttach =
                    hookPreconfigured && _preparedLaunchBackendSession != null && _preparedLaunchBackendPid == pid;
                if (_pendingLaunchOwnedByInterface)
                {
                    operationGuard?.TrackLaunchOwnedPid(pid);
                }

                if (!TryOpenTargetProcess(pid, out var processName, out var failure, out var accessDenied))
                {
                    if (!allowPreparedLaunchAttach)
                    {
                        DisposePreparedLaunchBackendSession();
                        ClearPendingLaunchOptions();
                        StatusBlock.Text = failure;
                        if (accessDenied)
                        {
                            ThemedMessageBox.Show(
                                this,
                                $"Access denied while opening PID {pid}. The process handle could not be opened with required access rights.",
                                "Target Attach Failed", MessageBoxButton.OK, MessageBoxImage.Warning);
                        }

                        RefreshProcessStateBadge();
                        return;
                    }

                    processName = $"PID {pid}";
                    StatusBlock.Text = $"CONNECTED TO PROTECTED TARGET ({pid})";
                    OutputCapture.AppendLine(
                        $"Protected launch attach accepted via prepared controller session: PID {pid}");
                }
                else
                {
                    StatusBlock.Text = $"CONNECTED TO {processName} ({pid})";
                }

                var tab = AddOrSelectProcessTab(pid, $"{processName} ({pid})", select: true);
                if (_pendingLaunchOptions)
                {
                    tab.LaunchOwnedByInterface = _pendingLaunchOwnedByInterface;
                }
                if (_pendingAnalysisSubjectKind == LaunchTargetKind.Dll &&
                    !string.IsNullOrWhiteSpace(_pendingAnalysisSubjectPath))
                {
                    tab.AnalysisSubjectKind = LaunchTargetKind.Dll;
                    tab.AnalysisSubjectPath = _pendingAnalysisSubjectPath;
                    tab.AnalysisHostPath = _pendingAnalysisHostPath;
                    string subjectName = Path.GetFileName(_pendingAnalysisSubjectPath);
                    tab.Title = NormalizeSessionTitle(
                        $"{(string.IsNullOrWhiteSpace(subjectName) ? "DLL" : subjectName)} via BlackbirdDllHost ({pid})");
                    DiagnosticsState.SetValue("Analysis Subject", tab.AnalysisSubjectPath);
                }
                bool launchStartsSuspended = _pendingLaunchStartsSuspended;
                bool leaveSuspendedAfterReady = _pendingLeaveSuspendedAfterReady;
                if (hookPreconfigured)
                {
                    OutputCapture.AppendLine(
                        $"Protected launch attach state: pid={pid} backendPrepared={allowPreparedLaunchAttach} leaveSuspended={leaveSuspendedAfterReady} uiStartsSuspended={launchStartsSuspended}");
                }
                if (_pendingLaunchOptions)
                {
                    tab.UseUsermodeHooks = _pendingUseUsermodeHooks;
                    tab.AutoOpenApiGraphOnNextStart = _pendingAutoOpenApiGraph;
                }
                tab.LaunchStartsSuspendedPending = launchStartsSuspended;
                tab.DeferredLaunchGateResumePending = false;
                ClearPendingLaunchOptions();

                if (tab.UseUsermodeHooks && !hookPreconfigured)
                {
                    LoadingWindow? hookLoading = null;
                    try
                    {
                        if (cancellationToken.IsCancellationRequested || _isMainWindowShuttingDown)
                        {
                            DisposePreparedLaunchBackendSession();
                            return;
                        }
                        if (!EnsureNoHookControllerCallInFlight("attach usermode hooks"))
                        {
                            DisposePreparedLaunchBackendSession();
                            return;
                        }

                        hookLoading = new LoadingWindow { Owner = this };
                        hookLoading.SetProgress(38, "Attaching usermode hooks...",
                                                $"Injecting SR71.dll into PID {pid}. UI timeout is {HookControllerCallTimeoutSeconds}s.");
                        hookLoading.Show();
                        await Dispatcher.InvokeAsync(() =>
                                                     {},
                                                     DispatcherPriority.Render);

                        var hookWait = await RunHookControllerCallWithTimeoutAsync(
                                           () =>
                                           {
                                               bool ok = TryAttachUsermodeHooks(pid, out string err);
                                               return (ok, err);
                                           },
                                           hookLoading,
                                           "Hook attach timed out",
                                           $"The controller did not complete SR71 attach for PID {pid} within {HookControllerCallTimeoutSeconds}s.",
                                           cancellationToken: cancellationToken);

                        if (!hookWait.Completed)
                        {
                            DisposePreparedLaunchBackendSession();
                            if (cancellationToken.IsCancellationRequested || _isMainWindowShuttingDown)
                            {
                                return;
                            }
                            StatusBlock.Text = $"HOOK ATTACH TIMED OUT FOR PID {pid}";
                            ThemedMessageBox.Show(
                                this,
                                $"Timed out attaching usermode hooks to PID {pid}. The controller IPC call is still being allowed to unwind, and overlapping hook operations are blocked until it returns.",
                                "Hook Attach Timed Out", MessageBoxButton.OK, MessageBoxImage.Error);
                            RefreshProcessStateBadge();
                            return;
                        }

                        var hookResult = hookWait.Result;

                        if (!hookResult.ok)
                        {
                            DisposePreparedLaunchBackendSession();
                            StatusBlock.Text = $"HOOK ATTACH FAILED FOR PID {pid}";
                            ThemedMessageBox.Show(this,
                                                  $"Failed to attach usermode hooks for PID {pid}.\n\n{hookResult.err}",
                                                  "Hook Attach Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                            RefreshProcessStateBadge();
                            return;
                        }
                    }
                    finally
                    {
                        if (hookLoading != null && hookLoading.IsVisible)
                        {
                            hookLoading.Close();
                        }
                    }

                    if (!IsLoaded)
                    {
                        DisposePreparedLaunchBackendSession();
                        return;
                    }
                }

                if (cancellationToken.IsCancellationRequested || _isMainWindowShuttingDown)
                {
                    DisposePreparedLaunchBackendSession();
                    return;
                }

                tab.TargetExited = false;
                tab.TargetExitReason = string.Empty;
                tab.OfflineSnapshot = false;
                if (!ReferenceEquals(_currentSession, tab))
                {
                    operationGuard?.MarkSessionStartAttempted();
                    SwitchToSession(tab);
                }
                else
                {
                    operationGuard?.MarkSessionStartAttempted();
                    StartLiveCaptureForPid(pid, tab.UseUsermodeHooks, launchStartsSuspended);
                }

                if (hookPreconfigured && !leaveSuspendedAfterReady)
                {
                    OutputCapture.AppendLine($"Protected launch auto-resume requested: PID {pid}");
                    if (!TryControlTargetExecution(suspend: false, out string resumeError))
                    {
                        OutputCapture.AppendLine($"Protected launch auto-resume failed: PID {pid} error={resumeError}");
                        _targetExecutionSuspended = true;
                        PerformancePaneHost.SetTargetSuspended(true);
                        StatusBlock.Text = $"SESSION READY, TARGET STILL SUSPENDED: PID {pid}";
                        ThemedMessageBox.Show(
                            this,
                            $"Blackbird attached successfully, but the target could not be resumed automatically.\n\n{resumeError}",
                            "Launch Resume Failed", MessageBoxButton.OK, MessageBoxImage.Warning);
                        RefreshProcessStateBadge();
                        RefreshToolbarCommandState();
                        return;
                    }

                    _targetExecutionSuspended = false;
                    PerformancePaneHost.SetTargetSuspended(false);
                    StatusBlock.Text =
                        $"LIVE CAPTURE READY: {NormalizeSessionTitle(_currentSession?.Title ?? $"PID {pid}")}";
                    OutputCapture.AppendLine($"Protected launch auto-resume completed: PID {pid}");
                }
                else if (launchStartsSuspended)
                {
                    if (hookPreconfigured)
                    {
                        OutputCapture.AppendLine($"Protected launch left suspended by operator option: PID {pid}");
                    }
                    _targetExecutionSuspended = true;
                    PerformancePaneHost.SetTargetSuspended(true);
                    StatusBlock.Text =
                        $"LIVE CAPTURE READY, TARGET SUSPENDED: {NormalizeSessionTitle(_currentSession?.Title ?? $"PID {pid}")}";
                }

                _ = RunPreflightAsync(pid);
                RefreshProcessStateBadge();
            }
            finally
            {
                _connectInProgress = false;
            }
        }

        private async void Launch_Click(object sender, RoutedEventArgs e) =>
            await OpenProcessPickerAndConnectAsync(showLaunchOptions: true);

        private async Task OpenProcessPickerAndConnectAsync(bool showLaunchOptions)
        {
            if (_openingProcessPicker)
                return;

            DisposePreparedLaunchBackendSession();
            ClearPendingLaunchOptions();
            _openingProcessPicker = true;
            LoadingWindow? loading = null;

            try
            {
                loading = new LoadingWindow { Owner = this };
                loading.SetProgress(14, "Preparing process picker...", "Initializing process view shell.");
                loading.Show();
                await Dispatcher.InvokeAsync(() =>
                                             {},
                                             System.Windows.Threading.DispatcherPriority.Render);

                var picker = new ProcessPickerWindow { Owner = this, ShowLaunchOptions = showLaunchOptions };

                loading.SetProgress(62, "Preparing process list...", "Enumerating launch targets before showing picker.");
                await Dispatcher.InvokeAsync(() =>
                                             {},
                                             DispatcherPriority.Render);
                picker.PrimeForFirstShow();
                loading.SetProgress(100, "Opening picker...",
                                    "Process picker is ready.");
                await Dispatcher.InvokeAsync(() =>
                                             {},
                                             DispatcherPriority.Render);
                loading.Close();
                loading = null;

                bool? result = picker.ShowDialog();
                if (result != true)
                    return;

                int selectedPid = picker.SelectedPid;
                bool hookPreconfigured = false;
                bool useUsermodeHooks = false;
                bool autoOpenApiGraph = false;
                bool useEarlyBirdApcLaunch = false;
                LaunchTargetKind launchTargetKind =
                    picker.LaunchSelectedImage ? picker.SelectedLaunchTargetKind : LaunchTargetKind.Executable;
                LaunchProfile launchProfile = new();
                if (showLaunchOptions && (picker.LaunchSelectedImage || selectedPid > 0))
                {
                    var parametersWindow = new LaunchParametersWindow(isLaunchTarget: picker.LaunchSelectedImage,
                                                                      targetKind: launchTargetKind) { Owner = this };
                    bool? parametersAccepted = parametersWindow.ShowDialog();
                    if (parametersAccepted != true)
                    {
                        return;
                    }

                    useUsermodeHooks = parametersWindow.UseUsermodeHooks;
                    autoOpenApiGraph = parametersWindow.AutoOpenApiGraphWindow;
                    useEarlyBirdApcLaunch = parametersWindow.UseEarlyBirdApcLaunch;
                    launchProfile = parametersWindow.LaunchProfile;
                    launchProfile.TargetKind = launchTargetKind;
                }

                using AnalysisOperationGuard operation =
                    BeginAnalysisOperation(showLaunchOptions && picker.LaunchSelectedImage
                                               ? "launch/analyze"
                                               : "attach/analyze");

                if (showLaunchOptions && picker.LaunchSelectedImage)
                {
                    string selectedImagePath = picker.LaunchImagePath?.Trim() ?? string.Empty;
                    if (string.IsNullOrWhiteSpace(selectedImagePath))
                    {
                        ThemedMessageBox.Show(this, "Launch path is empty.", "Launch failed", MessageBoxButton.OK,
                                              MessageBoxImage.Error);
                        return;
                    }

                    string launchImagePath = selectedImagePath;
                    if (launchTargetKind == LaunchTargetKind.Dll)
                    {
                        string dllHostPath = ResolveDllHostPathFromInterfaceDirectory();
                        if (!File.Exists(dllHostPath))
                        {
                            ThemedMessageBox.Show(
                                this, $"DLL launch failed because the DLL host is missing: '{dllHostPath}'.",
                                "DLL launch failed", MessageBoxButton.OK, MessageBoxImage.Error);
                            return;
                        }

                        launchProfile.TargetKind = LaunchTargetKind.Dll;
                        launchProfile.AnalysisSubjectPath = selectedImagePath;
                        launchProfile.AnalysisHostPath = dllHostPath;
                        launchProfile.CommandLineArguments = BuildDllHostCommandLineArguments(launchProfile);
                        if (!launchProfile.HasWorkingDirectory)
                        {
                            launchProfile.WorkingDirectory = Path.GetDirectoryName(selectedImagePath) ?? string.Empty;
                        }
                        launchImagePath = dllHostPath;
                        useUsermodeHooks = true;
                        useEarlyBirdApcLaunch = true;
                    }

                    if (useUsermodeHooks)
                    {
                        LoadingWindow? launchLoading = null;
                        bool launchOk;
                        int launchedPid = 0;
                        BlackbirdBackendSession? preparedSession = null;
                        string launchError = string.Empty;
                        try
                        {
                            if (!EnsureNoHookControllerCallInFlight("launch target with hooks"))
                            {
                                return;
                            }

                            launchLoading = new LoadingWindow { Owner = this };
                            launchLoading.SetProgress(42, "Launching target with hooks...",
                                                      "Submitting launch + SR71 staging request. UI timeout is " +
                                                      HookControllerCallTimeoutSeconds + "s.");
                            launchLoading.Show();
                            await Dispatcher.InvokeAsync(() =>
                                                         {},
                                                         DispatcherPriority.Render);

                            var launchWait = await RunHookControllerCallWithTimeoutAsync(
                                                 () =>
                                                 {
                                                     bool ok = TryLaunchWithUsermodeHooksAndPrepareSession(
                                                         launchImagePath, useEarlyBirdApcLaunch, launchProfile,
                                                         out int taskPid, out BlackbirdBackendSession? taskSession,
                                                         out string taskError);
                                                     return (ok, taskPid, taskSession, taskError);
                                                 },
                                                 launchLoading,
                                                 "Hook launch timed out",
                                                 "The controller did not return from target launch and SR71 readiness " +
                                                 $"within {HookControllerCallTimeoutSeconds}s.",
                                                 lateResult =>
                                                 {
                                                     lateResult.taskSession?.Dispose();
                                                     if (lateResult.taskPid > 0)
                                                     {
                                                         if (TryTerminateTargetProcess(lateResult.taskPid,
                                                                                       out string terminateError))
                                                         {
                                                             AppendOutputFromAnyThread(
                                                                 $"Late hook launch result was terminated fail-closed: PID {lateResult.taskPid}");
                                                         }
                                                         else
                                                         {
                                                             AppendOutputFromAnyThread(
                                                                 $"Late hook launch result cleanup could not terminate PID {lateResult.taskPid}: {terminateError}");
                                                         }
                                                     }
                                                 },
                                                 cancellationToken: operation.Token);

                            if (!launchWait.Completed)
                            {
                                launchOk = false;
                                launchError =
                                    $"Controller hook launch did not return within {HookControllerCallTimeoutSeconds} seconds. " +
                                    "Blackbird has blocked overlapping hook launches until the native IPC call unwinds.";
                            }
                            else
                            {
                                launchOk = launchWait.Result.ok;
                                launchedPid = launchWait.Result.taskPid;
                                preparedSession = launchWait.Result.taskSession;
                                launchError = launchWait.Result.taskError;
                                if (launchedPid > 0)
                                {
                                    operation.TrackLaunchOwnedPid(launchedPid);
                                }
                            }
                        }
                        finally
                        {
                            if (launchLoading != null && launchLoading.IsVisible)
                            {
                                launchLoading.Close();
                            }
                        }

                        if (!launchOk)
                        {
                            if (preparedSession != null)
                            {
                                try
                                {
                                    preparedSession.Dispose();
                                }
                                catch
                                {
                                }
                            }

                            if (operation.Token.IsCancellationRequested || _isMainWindowShuttingDown)
                            {
                                return;
                            }

                            ThemedMessageBox.Show(this, launchError, "Hook launch failed", MessageBoxButton.OK,
                                                  MessageBoxImage.Error);
                            return;
                        }

                        selectedPid = launchedPid;
                        operation.TrackLaunchOwnedPid(selectedPid);
                        _preparedLaunchBackendSession = preparedSession;
                        _preparedLaunchBackendPid = selectedPid;
                        hookPreconfigured = true;
                    }
                    else
                    {
                        if (!BlackbirdNative.TryLaunchProcess(launchImagePath, launchProfile, out selectedPid,
                                                              out string launchError))
                        {
                            ThemedMessageBox.Show(this, launchError, "Launch failed", MessageBoxButton.OK,
                                                  MessageBoxImage.Error);
                            return;
                        }

                        operation.TrackLaunchOwnedPid(selectedPid);
                    }
                }

                if (selectedPid <= 0)
                {
                    return;
                }

                _pendingLaunchOptions = showLaunchOptions;
                _pendingUseUsermodeHooks = showLaunchOptions && useUsermodeHooks;
                _pendingAutoOpenApiGraph = showLaunchOptions && autoOpenApiGraph;
                _pendingHookPreconfigured = hookPreconfigured;
                _pendingLaunchStartsSuspended =
                    showLaunchOptions && picker.LaunchSelectedImage && launchProfile.LeaveSuspendedAfterReady;
                _pendingLeaveSuspendedAfterReady =
                    showLaunchOptions && picker.LaunchSelectedImage && launchProfile.LeaveSuspendedAfterReady;
                _pendingLaunchOwnedByInterface = showLaunchOptions && picker.LaunchSelectedImage;
                _pendingAnalysisSubjectKind = launchProfile.TargetKind;
                _pendingAnalysisSubjectPath =
                    launchProfile.HasAnalysisSubject ? launchProfile.AnalysisSubjectPath : string.Empty;
                _pendingAnalysisHostPath =
                    !string.IsNullOrWhiteSpace(launchProfile.AnalysisHostPath)
                        ? launchProfile.AnalysisHostPath
                        : (launchProfile.HasAnalysisSubject ? ResolveDllHostPathFromInterfaceDirectory()
                                                            : string.Empty);
                PidBox.Text = selectedPid.ToString();
                await ConnectToCurrentPidAsync(operation.Token, operation);
                if (operation.SessionStartAttempted && !operation.Token.IsCancellationRequested &&
                    !_isMainWindowShuttingDown)
                {
                    operation.Complete();
                }
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
            await OpenProcessPickerAndConnectAsync(showLaunchOptions: true);
        }

        private void ApplyPausedTimelineRanges()
        {
            if (EventsPaneHost?.Timeline == null)
            {
                return;
            }

            if (_currentSession == null)
            {
                EventsPaneHost.Timeline.SetPauseRanges(null);
                return;
            }

            var ranges = _currentSession.PausedTimelineSpans
                             .Select(x => new TimelinePauseRange { StartUtc = x.StartUtc, EndUtc = x.EndUtc })
                             .ToList();

            if (_currentSession.ActivePauseStartUtc.HasValue)
            {
                ranges.Add(new TimelinePauseRange { StartUtc = _currentSession.ActivePauseStartUtc.Value,
                                                    EndUtc = DateTime.UtcNow });
            }

            EventsPaneHost.Timeline.SetPauseRanges(ranges);
        }

        private void DisposePreparedLaunchBackendSession()
        {
            if (_preparedLaunchBackendSession != null)
            {
                try
                {
                    _preparedLaunchBackendSession.Dispose();
                }
                catch
                {
                }
            }

            _preparedLaunchBackendSession = null;
            _preparedLaunchBackendPid = 0;
        }

        private void ClearPendingLaunchOptions()
        {
            _pendingLaunchOptions = false;
            _pendingUseUsermodeHooks = false;
            _pendingAutoOpenApiGraph = false;
            _pendingHookPreconfigured = false;
            _pendingLaunchStartsSuspended = false;
            _pendingLeaveSuspendedAfterReady = false;
            _pendingLaunchOwnedByInterface = false;
            _pendingAnalysisSubjectKind = LaunchTargetKind.Executable;
            _pendingAnalysisSubjectPath = string.Empty;
            _pendingAnalysisHostPath = string.Empty;
        }

        private static uint MapLaunchPriorityClass(LaunchPriorityPreset priority) => priority switch {
            LaunchPriorityPreset.Idle => 0x00000040,
            LaunchPriorityPreset.BelowNormal => 0x00004000,
            LaunchPriorityPreset.Normal => 0x00000020,
            LaunchPriorityPreset.AboveNormal => 0x00008000,
            LaunchPriorityPreset.High => 0x00000080,
            LaunchPriorityPreset.Realtime => 0x00000100,
            _ => 0u
        };

        internal async Task<string> TryOpenSessionFromStartupPathAsync(string path)
        {
            return await TryOpenSessionArchivePathAsync(path, merge: false);
        }

        private void Suspend_Click(object sender, RoutedEventArgs e)
        {
            if (!TryControlTargetExecution(suspend: true, out string error))
            {
                ThemedMessageBox.Show(this, error, "Suspend Target", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            _targetExecutionSuspended = true;
            if (_currentSession != null && !_currentSession.OfflineSnapshot && !_currentSession.TargetExited &&
                !_currentSession.ActivePauseStartUtc.HasValue)
            {
                _currentSession.ActivePauseStartUtc = DateTime.UtcNow;
            }
            _perf?.Stop();
            PerformancePaneHost.SetTargetSuspended(true);
            PerformancePaneHost.SetProcessLiveDataAvailable(false);
            PerformancePaneHost.RefreshLiveProcessDetails();
            ApplyPausedTimelineRanges();
            SetIntegrityDiagnosticsForSuspension();
            StatusBlock.Text = $"TARGET PAUSED: PID {TryGetPid()}";
            RefreshProcessStateBadge();
            RefreshToolbarCommandState();
        }

        private void Resume_Click(object sender, RoutedEventArgs e)
        {
            if (!TryControlTargetExecution(suspend: false, out string error))
            {
                ThemedMessageBox.Show(this, error, "Resume Target", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (_currentSession != null)
            {
                _currentSession.DeferredLaunchGateResumePending = false;
            }
            _targetExecutionSuspended = false;
            ClearIntegrityDiagnosticsForSuspension();
            PerformancePaneHost.SetTargetSuspended(false);
            if (_currentSession != null && _currentSession.ActivePauseStartUtc.HasValue)
            {
                DateTime resumeUtc = DateTime.UtcNow;
                _currentSession.PausedTimelineSpans.Add(
                    new PausedTimelineSpan { StartUtc = _currentSession.ActivePauseStartUtc.Value,
                                             EndUtc = resumeUtc });
                _currentSession.ActivePauseStartUtc = null;
                _latestEventTimestampUtc = resumeUtc;
                ApplyPausedTimelineRanges();
                UpdateScrollBar();
                _followLiveTimeline = true;
                double viewport = Math.Max(1, EventsPaneHost.Scroll.ViewportSize);
                double maxStart = ComputeTimelineMaxStart(viewport);
                EventsPaneHost.Timeline.ViewStartSeconds = maxStart;
                EventsPaneHost.Scroll.Value = maxStart;
                SyncPerformanceViewToTimeline();
            }
            if (_currentSession != null && !_currentSession.OfflineSnapshot && !_currentSession.TargetExited &&
                _perf != null)
            {
                _perf.SetTargetPid(_currentSession.Pid);
                _perf.ResetBaselines();
                _perf.Start();
                _perf.RequestImmediateSample();
            }
            PerformancePaneHost.SetProcessLiveDataAvailable(true);
            PerformancePaneHost.RefreshLiveProcessDetails();
            SchedulePostResumeProcessRefresh(pid: _currentSession?.Pid ?? TryGetPid());
            StatusBlock.Text = $"TARGET RESUMED: PID {TryGetPid()}";
            RefreshProcessStateBadge();
            RefreshToolbarCommandState();
        }

        private void SchedulePostResumeProcessRefresh(int pid)
        {
            if (pid <= 0)
            {
                return;
            }

            _ = Task.Run(async () =>
                         {
                             await Task.Delay(250).ConfigureAwait(false);
                             await Dispatcher.InvokeAsync(
                                 () =>
                                 {
                                     ProcessSessionTab? session = _currentSession;
                                     if (_targetExecutionSuspended || session == null || session.Pid != pid ||
                                         session.TargetExited)
                                     {
                                         return;
                                     }

                                     _perf?.RequestImmediateSample();
                                     PerformancePaneHost.SetProcessLiveDataAvailable(true);
                                     PerformancePaneHost.RefreshLiveProcessDetails();
                                     RefreshProcessStateBadge();
                                     RefreshToolbarCommandState();
                                 },
                                 DispatcherPriority.Background);
                         });
        }

        private static readonly string[] _integrityDiagnosticKeys =
            ["Hook Integrity", "AMSI Integrity", "ETW Integrity"];

        private static void SetIntegrityDiagnosticsForSuspension()
        {
            foreach (string key in _integrityDiagnosticKeys)
            {
                string? current = DiagnosticsState.GetValue(key);
                if (current != null && current.Contains("Disabled", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (current == null || !current.Contains("TAMPERED", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue(key, "INACTIVE (target suspended)");
                }
            }
            if (DiagnosticsState.GetValue("Usermode Hooks")?.Contains("Disabled", StringComparison.OrdinalIgnoreCase) !=
                true)
            {
                DiagnosticsState.SetValue("Usermode Hooks", "INACTIVE (target suspended)");
            }
        }

        private static void ClearIntegrityDiagnosticsForSuspension()
        {
            foreach (string key in _integrityDiagnosticKeys)
            {
                string? current = DiagnosticsState.GetValue(key);
                if (current != null && current.Contains("INACTIVE", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue(key, "INACTIVE (resuming)");
                }
            }
            if (DiagnosticsState.GetValue("Usermode Hooks")?.Contains("INACTIVE", StringComparison.OrdinalIgnoreCase) ==
                true)
            {
                DiagnosticsState.SetValue("Usermode Hooks", "INACTIVE (resuming)");
            }
        }

        private void TerminateLaunchOwnedTargetsOnShutdown()
        {
            foreach (ProcessSessionTab tab in _processTabs)
            {
                if (!tab.LaunchOwnedByInterface || tab.OfflineSnapshot || tab.TargetExited || tab.Pid <= 0)
                {
                    continue;
                }

                if (TryTerminateTargetProcess(tab.Pid, out _))
                {
                    tab.TargetExited = true;
                }
            }
        }

        private void TerminateTarget_Click(object sender, RoutedEventArgs e)
        {
            int pid = _currentSession?.Pid ?? TryGetPid();
            if (pid <= 0)
            {
                ThemedMessageBox.Show(this, "No target process is selected.", "Terminate Target", MessageBoxButton.OK,
                                      MessageBoxImage.Warning);
                return;
            }

            if (_currentSession?.OfflineSnapshot == true)
            {
                ThemedMessageBox.Show(this, "Cannot terminate an offline session.", "Terminate Target",
                                      MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (_currentSession?.TargetExited == true)
            {
                ThemedMessageBox.Show(this, $"PID {pid} has already exited.", "Terminate Target", MessageBoxButton.OK,
                                      MessageBoxImage.Information);
                return;
            }

            var confirm = ThemedMessageBox.Show(this, $"Terminate PID {pid} and stop live capture for this tab?",
                                                "Terminate Target", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes)
            {
                return;
            }

            if (!TryTerminateTargetProcess(pid, out string error))
            {
                ThemedMessageBox.Show(this, error, "Terminate Target", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            HandleTargetProcessExit(pid);
        }
        private void Restart_Click(object sender, RoutedEventArgs e)
        {
        }

        private bool TryControlTargetExecution(bool suspend, out string error)
        {
            error = string.Empty;
            int pid = _currentSession?.Pid ?? TryGetPid();
            if (pid <= 0)
            {
                error = "No target process is selected.";
                return false;
            }

            if (_currentSession?.OfflineSnapshot == true)
            {
                error = "Cannot control execution for an offline session.";
                return false;
            }

            if (_currentSession?.TargetExited == true)
            {
                error = $"PID {pid} has already exited.";
                return false;
            }

            if (_backendSession == null)
            {
                error = "No active backend session.";
                return false;
            }

            bool ok = _backendSession.ControlProcessExecution(unchecked((uint)pid), suspend);
            if (!ok)
            {
                int ioErr = Marshal.GetLastWin32Error();
                error = $"{(suspend ? "Suspend" : "Resume")} failed via controller (win32={ioErr}).";
                return false;
            }

            return true;
        }

        private static string AppendEnvironmentOverride(string existing, string line)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                return existing ?? string.Empty;
            }

            if (string.IsNullOrWhiteSpace(existing))
            {
                return line;
            }

            string[] entries = existing.Replace("\r\n", "\n", StringComparison.Ordinal)
                                   .Replace('\r', '\n')
                                   .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            int separator = line.IndexOf('=');
            if (separator > 0)
            {
                string name = line[..separator];
                foreach (string entry in entries)
                {
                    int existingSeparator = entry.IndexOf('=');
                    if (existingSeparator > 0 &&
                        string.Equals(entry[..existingSeparator], name, StringComparison.OrdinalIgnoreCase))
                    {
                        return existing;
                    }
                }
            }

            return existing + "\n" + line;
        }

        private bool TryTerminateTargetProcess(int pid, out string error)
        {
            error = string.Empty;
            IntPtr handle = Kernel32Native.OpenProcess(
                ProcessTerminate | ProcessQueryLimitedInformation | ProcessSynchronize, false, unchecked((uint)pid));
            if (handle == IntPtr.Zero)
            {
                int openErr = Marshal.GetLastWin32Error();
                error = $"Failed to open PID {pid} for termination (win32={openErr}).";
                return false;
            }

            try
            {
                if (!Kernel32Native.TerminateProcess(handle, 1))
                {
                    int terminateErr = Marshal.GetLastWin32Error();
                    error = $"TerminateProcess failed for PID {pid} (win32={terminateErr}).";
                    return false;
                }

                return true;
            }
            finally
            {
                _ = Kernel32Native.CloseHandle(handle);
            }
        }

        private void SeedFake()
        {
            var t0 = _captureStartUtc;

            AppendEvent(new TelemetryEvent { TimestampUtc = t0.AddSeconds(1), PID = 1234, TID = 10, Group = "Execution",
                                             SubType = "CreateProcess", Summary = "proc created" });
            AppendEvent(new TelemetryEvent { TimestampUtc = t0.AddSeconds(2), PID = 1234, TID = 11, Group = "Thread",
                                             SubType = "RemoteThread", Summary = "remote thread start" });
            AppendEvent(new TelemetryEvent { TimestampUtc = t0.AddSeconds(6), PID = 1234, TID = 12, Group = "Registry",
                                             SubType = "SetValue", Summary = "reg set value" });
            AppendEvent(new TelemetryEvent { TimestampUtc = t0.AddSeconds(12), PID = 1234, TID = 13, Group = "Handles",
                                             SubType = "Duplicate", Summary = "dup handle" });
            AppendEvent(new TelemetryEvent { TimestampUtc = t0.AddSeconds(35), PID = 1234, TID = 14,
                                             Group = "Injection", SubType = "MapView", Summary = "write+map" });
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

                                                  _eventsFloatWindow = new EventsFloatWindow(
                                                      EventsPaneHost) { Owner = this, ShowInTaskbar = false };
                                                  _eventsFloatWindow.Closing += EventsFloatWindow_Closing;
                                                  _eventsFloatWindow.Closed += EventsFloatWindow_Closed;
                                                  _eventsFloatWindow.Show();
                                              }),
                                   System.Windows.Threading.DispatcherPriority.Background);
        }

        private void RedockEventsPane()
        {
            if (_eventsFloatWindow != null)
            {
                _eventsFloatWindow.Closing -= EventsFloatWindow_Closing;
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

                                                  _performanceFloatWindow = new PerformanceFloatWindow(
                                                      PerformancePaneHost) { Owner = this, ShowInTaskbar = false };
                                                  _performanceFloatWindow.Closing += PerformanceFloatWindow_Closing;
                                                  _performanceFloatWindow.Closed += PerformanceFloatWindow_Closed;
                                                  _performanceFloatWindow.Show();
                                              }),
                                   System.Windows.Threading.DispatcherPriority.Background);
        }

        private void RedockPerformancePane()
        {
            if (_performanceFloatWindow != null)
            {
                _performanceFloatWindow.Closing -= PerformanceFloatWindow_Closing;
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

                                                  _etwFloatWindow = new EtwFloatWindow(
                                                      EtwPaneHost) { Owner = this, ShowInTaskbar = false };
                                                  _etwFloatWindow.Closing += EtwFloatWindow_Closing;
                                                  _etwFloatWindow.Closed += EtwFloatWindow_Closed;
                                                  _etwFloatWindow.Show();
                                              }),
                                   System.Windows.Threading.DispatcherPriority.Background);
        }

        private void RedockEtwPane()
        {
            if (_etwFloatWindow != null)
            {
                _etwFloatWindow.Closing -= EtwFloatWindow_Closing;
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

                                                  _heuristicsFloatWindow = new HeuristicsFloatWindow(
                                                      HeuristicsPaneHost) { Owner = this, ShowInTaskbar = false };
                                                  _heuristicsFloatWindow.Closing += HeuristicsFloatWindow_Closing;
                                                  _heuristicsFloatWindow.Closed += HeuristicsFloatWindow_Closed;
                                                  _heuristicsFloatWindow.Show();
                                              }),
                                   System.Windows.Threading.DispatcherPriority.Background);
        }

        private void RedockHeuristicsPane()
        {
            if (_heuristicsFloatWindow != null)
            {
                _heuristicsFloatWindow.Closing -= HeuristicsFloatWindow_Closing;
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

        private void EventsFloatWindow_Closing(object? sender, CancelEventArgs e)
        {
            bool explorerEnabled = FindExplorerItem("Events")?.IsEnabled ?? true;
            if (_isMainWindowShuttingDown || !explorerEnabled || !_eventsPaneVisible ||
                sender is not EventsFloatWindow window || !ReferenceEquals(window.Content, EventsPaneHost))
            {
                return;
            }

            e.Cancel = true;
            RedockEventsPane();
        }

        private void PerformanceFloatWindow_Closed(object? sender, EventArgs e)
        {
            _performanceFloatWindow = null;
            if (PerformanceDockBorder.Child == null)
                RedockPerformancePane();
        }

        private void PerformanceFloatWindow_Closing(object? sender, CancelEventArgs e)
        {
            bool explorerEnabled = FindExplorerItem("Performance")?.IsEnabled ?? true;
            if (_isMainWindowShuttingDown || !explorerEnabled || !_performancePaneVisible ||
                sender is not PerformanceFloatWindow window || !ReferenceEquals(window.Content, PerformancePaneHost))
            {
                return;
            }

            e.Cancel = true;
            RedockPerformancePane();
        }

        private void EtwFloatWindow_Closed(object? sender, EventArgs e)
        {
            _etwFloatWindow = null;
            if (EtwDockBorder.Child == null)
                RedockEtwPane();
        }

        private void EtwFloatWindow_Closing(object? sender, CancelEventArgs e)
        {
            bool explorerEnabled = FindExplorerItem("ETW")?.IsEnabled ?? true;
            if (_isMainWindowShuttingDown || !explorerEnabled || sender is not EtwFloatWindow window ||
                !ReferenceEquals(window.Content, EtwPaneHost))
            {
                return;
            }

            e.Cancel = true;
            RedockEtwPane();
        }

        private void HeuristicsFloatWindow_Closed(object? sender, EventArgs e)
        {
            _heuristicsFloatWindow = null;
            if (HeuristicsDockBorder.Child == null)
                RedockHeuristicsPane();
        }

        private void HeuristicsFloatWindow_Closing(object? sender, CancelEventArgs e)
        {
            bool explorerEnabled = FindExplorerItem("Heuristics")?.IsEnabled ?? true;
            if (_isMainWindowShuttingDown || !explorerEnabled || sender is not HeuristicsFloatWindow window ||
                !ReferenceEquals(window.Content, HeuristicsPaneHost))
            {
                return;
            }

            e.Cancel = true;
            RedockHeuristicsPane();
        }

        private void ApiViewDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = sender;
            _ = e;
            UpdateApiViewSelection(ApiViewDataGrid?.SelectedItem as ApiCallGraphMainRowView);
            RefreshApiGraphSelectionVisual();
        }

        private void ApiViewTextFilter_Changed(object sender, TextChangedEventArgs e)
        {
            _ = sender;
            _ = e;
            RefreshApiViewPresentation();
        }

        private void ApiViewSelectionFilter_Changed(object sender, SelectionChangedEventArgs e)
        {
            _ = sender;
            _ = e;
            RefreshApiViewPresentation();
        }

        private void ApiViewMode_Changed(object sender, SelectionChangedEventArgs e)
        {
            _ = sender;
            _ = e;
            _apiViewPresentationMode = ApiViewModeBox?.SelectedIndex == 1 ? ApiViewPresentationMode.ThreadTimeline
                                                                          : ApiViewPresentationMode.CallGraph;
            RefreshApiViewPresentation();
        }

        private void ApiViewClearFilters_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;

            if (ApiFilterCallBox != null)
                ApiFilterCallBox.Text = string.Empty;
            if (ApiFilterActionBox != null)
                ApiFilterActionBox.Text = string.Empty;
            if (ApiFilterCallerBox != null)
                ApiFilterCallerBox.Text = string.Empty;
            if (ApiFilterTargetBox != null)
                ApiFilterTargetBox.Text = string.Empty;
            if (ApiFilterThreadBox != null)
                ApiFilterThreadBox.Text = string.Empty;
            if (ApiFilterRegionBox != null)
                ApiFilterRegionBox.Text = string.Empty;
            if (ApiFilterProtectBox != null)
                ApiFilterProtectBox.Text = string.Empty;
            if (ApiFilterMinHitsBox != null)
                ApiFilterMinHitsBox.Text = string.Empty;
            if (ApiFilterSensorBox != null)
                ApiFilterSensorBox.SelectedIndex = 0;
            if (ApiFilterOriginBox != null)
                ApiFilterOriginBox.SelectedIndex = 0;
            RefreshApiViewPresentation();
        }

        private void UpdateApiViewSelection(ApiCallGraphMainRowView? selected)
        {
            if (ApiViewSelectedTitleBlock == null || ApiViewSelectedMetaBlock == null ||
                ApiViewSelectedActionValue == null || ApiViewSelectedSensorValue == null ||
                ApiViewSelectedOriginValue == null || ApiViewSelectedFramesValue == null ||
                ApiViewSelectedSourceValue == null || ApiViewSelectedTargetValue == null ||
                ApiViewSelectedThreadValue == null || ApiViewSelectedHitsValue == null ||
                ApiViewSelectedField2Label == null || ApiViewSelectedField4Label == null ||
                ApiViewSelectedSizeValue == null || ApiViewSelectedProtectValue == null ||
                ApiViewSelectedDetailValue == null)
            {
                return;
            }

            if (selected == null)
            {
                ApiViewSelectedTitleBlock.Text = "No selection";
                ApiViewSelectedMetaBlock.Text = "Select a row to inspect decoded details";
                ApiViewSelectedActionValue.Text = string.Empty;
                ApiViewSelectedSensorValue.Text = string.Empty;
                ApiViewSelectedOriginValue.Text = string.Empty;
                ApiViewSelectedFramesValue.Text = string.Empty;
                ApiViewSelectedSourceValue.Text = string.Empty;
                ApiViewSelectedTargetValue.Text = string.Empty;
                ApiViewSelectedThreadValue.Text = string.Empty;
                ApiViewSelectedHitsValue.Text = string.Empty;
                ApiViewSelectedField2Label.Text = "Context";
                ApiViewSelectedField4Label.Text = "Flags";
                ApiViewSelectedSizeValue.Text = string.Empty;
                ApiViewSelectedProtectValue.Text = string.Empty;
                ApiViewSelectedDetailValue.Text = string.Empty;
                return;
            }

            ApiViewSelectedTitleBlock.Text = selected.ApiName;
            ApiViewSelectedMetaBlock.Text =
                $"Caller {selected.SourceLabel}  |  Target {selected.TargetLabel}  |  Thread {selected.ThreadLabel}  |  Hits {selected.Hits}  |  First Seen {selected.FirstSeen}  |  Last Seen {selected.LastSeen}" +
                (string.IsNullOrWhiteSpace(selected.AbsoluteLastSeen) ? string.Empty
                                                                      : $" ({selected.AbsoluteLastSeen})");
            ApiViewSelectedActionValue.Text = selected.ActionLabel;
            ApiViewSelectedSensorValue.Text = selected.SensorLabel;
            ApiViewSelectedOriginValue.Text = selected.CallerOriginLabel;
            ApiViewSelectedFramesValue.Text = selected.CallChainLabel;
            ApiViewSelectedSourceValue.Text = selected.SourceLabel;
            ApiViewSelectedTargetValue.Text = selected.TargetLabel;
            ApiViewSelectedThreadValue.Text = selected.ThreadLabel;
            ApiViewSelectedHitsValue.Text = selected.Hits.ToString();
            ApiViewSelectedField2Label.Text = selected.Field2Label;
            ApiViewSelectedField4Label.Text = selected.Field4Label;
            ApiViewSelectedSizeValue.Text = selected.SizeLabel;
            ApiViewSelectedProtectValue.Text = selected.ProtectLabel;
            ApiViewSelectedDetailValue.Text = selected.DetailFull;
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
                _floatingPaneDragOffset =
                    new Vector(screenPosition.X - _eventsFloatWindow.Left, screenPosition.Y - _eventsFloatWindow.Top);
            }
            else
            {
                if (_performanceFloatWindow == null)
                    TogglePerformanceFloatDock();

                if (_performanceFloatWindow == null)
                    return;

                _draggingPerformancePaneHeader = true;
                _draggingEventsPaneHeader = false;
                _floatingPaneDragOffset = new Vector(screenPosition.X - _performanceFloatWindow.Left,
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

            var floatingWindow = isEventsPane ? (Window ?) _eventsFloatWindow: _performanceFloatWindow;
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

        private readonly struct EventSelectionKey : IEquatable<EventSelectionKey>
        {
            public EventSelectionKey(TelemetryEvent ev)
            {
                TimestampUtc = ev.TimestampUtc;
                Pid = ev.PID;
                Tid = ev.TID;
                Group = ev.Group ?? string.Empty;
                SubType = ev.SubType ?? string.Empty;
                Summary = ev.Summary ?? string.Empty;
                Details = ev.Details ?? string.Empty;
            }

            private DateTime TimestampUtc { get; }
            private int Pid { get; }
            private int Tid { get; }
            private string Group { get; }
            private string SubType { get; }
            private string Summary { get; }
            private string Details { get; }

            public bool Matches(TelemetryEvent ev)
            {
                return ev.TimestampUtc == TimestampUtc && ev.PID == Pid && ev.TID == Tid &&
                       string.Equals(ev.Group ?? string.Empty, Group, StringComparison.OrdinalIgnoreCase) &&
                       string.Equals(ev.SubType ?? string.Empty, SubType, StringComparison.OrdinalIgnoreCase) &&
                       string.Equals(ev.Summary ?? string.Empty, Summary, StringComparison.Ordinal) &&
                       string.Equals(ev.Details ?? string.Empty, Details, StringComparison.Ordinal);
            }

            public bool Equals(EventSelectionKey other)
            {
                return TimestampUtc == other.TimestampUtc && Pid == other.Pid && Tid == other.Tid &&
                       string.Equals(Group, other.Group, StringComparison.OrdinalIgnoreCase) &&
                       string.Equals(SubType, other.SubType, StringComparison.OrdinalIgnoreCase) &&
                       string.Equals(Summary, other.Summary, StringComparison.Ordinal) &&
                       string.Equals(Details, other.Details, StringComparison.Ordinal);
            }

            public override bool Equals(object? obj) => obj is EventSelectionKey other && Equals(other);

            public override int GetHashCode()
            {
                HashCode hash = new();
                hash.Add(TimestampUtc);
                hash.Add(Pid);
                hash.Add(Tid);
                hash.Add(Group, StringComparer.OrdinalIgnoreCase);
                hash.Add(SubType, StringComparer.OrdinalIgnoreCase);
                hash.Add(Summary, StringComparer.Ordinal);
                hash.Add(Details, StringComparer.Ordinal);
                return hash.ToHashCode();
            }
        }

        private static TelemetryEvent CloneTelemetryEvent(TelemetryEvent src)
        {
            return new TelemetryEvent { TimestampUtc = src.TimestampUtc,
                                        PID = src.PID,
                                        TID = src.TID,
                                        Group = src.Group,
                                        SubType = src.SubType,
                                        ProcessName = src.ProcessName,
                                        Summary = src.Summary,
                                        Details = src.Details };
        }

        private static PerformanceSample ClonePerformanceSample(PerformanceSample src)
        {
            return new PerformanceSample {
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
                TopThreads = src.TopThreads
                                 .Select(t => new ThreadUsageSample { Tid = t.Tid, CpuMsDelta = t.CpuMsDelta,
                                                                      State = t.State, WaitReason = t.WaitReason,
                                                                      Kind = t.Kind, StartTimeUtc = t.StartTimeUtc,
                                                                      TargetSuspended = t.TargetSuspended })
                                 .ToList(),
                CoreUsage = src.CoreUsage
                                .Select(c => new CoreUsageSample { CoreIndex = c.CoreIndex, BusyPercent = c.BusyPercent,
                                                                   DominantTid = c.DominantTid,
                                                                   DominantThreadKind = c.DominantThreadKind,
                                                                   DominantThreadCpuMs = c.DominantThreadCpuMs,
                                                                   ThreadCount = c.ThreadCount })
                                .ToList(),
                MemoryMetrics = src.MemoryMetrics
                                    .Select(m => new MemoryMetricSample { Metric = m.Metric, Value = m.Value,
                                                                          BytesValue = m.BytesValue })
                                    .ToList(),
                MemoryPages = src.MemoryPages
                                  .Select(m => new MemoryPageSample { BaseAddress = m.BaseAddress,
                                                                      AllocationBase = m.AllocationBase,
                                                                      RegionSize = m.RegionSize,
                                                                      State = m.State,
                                                                      Protect = m.Protect,
                                                                      AllocationProtect = m.AllocationProtect,
                                                                      Type = m.Type,
                                                                      StateLabel = m.StateLabel,
                                                                      ProtectLabel = m.ProtectLabel,
                                                                      TypeLabel = m.TypeLabel,
                                                                      Category = m.Category,
                                                                      SpecialUse = m.SpecialUse,
                                                                      BackingPath = m.BackingPath,
                                                                      ModulePath = m.ModulePath,
                                                                      Sr71Owned = m.Sr71Owned,
                                                                      Sr71OwnerTag = m.Sr71OwnerTag,
                                                                      WorkingSetValid = m.WorkingSetValid,
                                                                      WorkingSetShared = m.WorkingSetShared,
                                                                      WorkingSetShareCount = m.WorkingSetShareCount,
                                                                      WorkingSetLocked = m.WorkingSetLocked,
                                                                      WorkingSetLargePage = m.WorkingSetLargePage,
                                                                      SnapshotOffset = m.SnapshotOffset,
                                                                      SnapshotBytes = m.SnapshotBytes?.ToArray() })
                                  .ToList()
            };
        }

        private static ThreadLifecycleEventSample CloneThreadLifecycleEvent(ThreadLifecycleEventSample src)
        {
            return new ThreadLifecycleEventSample { TimestampUtc = src.TimestampUtc,
                                                    ProcessPid = src.ProcessPid,
                                                    ThreadId = src.ThreadId,
                                                    CreatorPid = src.CreatorPid,
                                                    Flags = src.Flags,
                                                    StartAddress = src.StartAddress,
                                                    ImageBase = src.ImageBase,
                                                    ImageSize = src.ImageSize,
                                                    EventKind = src.EventKind,
                                                    Notes = src.Notes };
        }

        private static MemoryRegionAttributionSample
        CloneMemoryRegionAttributionSample(MemoryRegionAttributionSample src)
        {
            return new MemoryRegionAttributionSample { TimestampUtc = src.TimestampUtc,
                                                       ProcessStartKey = src.ProcessStartKey,
                                                       TargetPid = src.TargetPid,
                                                       ActorPid = src.ActorPid,
                                                       ActorTid = src.ActorTid,
                                                       AllocationBase = src.AllocationBase,
                                                       BaseAddress = src.BaseAddress,
                                                       RegionSize = src.RegionSize,
                                                       ApiName = src.ApiName,
                                                       EventKind = src.EventKind,
                                                       RegionKind = src.RegionKind,
                                                       RegionIdentity = src.RegionIdentity,
                                                       OriginPath = src.OriginPath,
                                                       SourceFamily = src.SourceFamily,
                                                       ExecutionContext = src.ExecutionContext,
                                                       CallerOrigin = src.CallerOrigin,
                                                       FirstUserFrame = src.FirstUserFrame,
                                                       FirstUserFrameModule = src.FirstUserFrameModule,
                                                       FrameSummary = src.FrameSummary,
                                                       UnwindClean = src.UnwindClean,
                                                       FrameChainHadGaps = src.FrameChainHadGaps,
                                                       ObservedByKernel = src.ObservedByKernel,
                                                       ObservedByUserHook = src.ObservedByUserHook,
                                                       BlackbirdOwned = src.BlackbirdOwned,
                                                       CrossProcess = src.CrossProcess,
                                                       ImageBacked = src.ImageBacked,
                                                       InitialProtection = src.InitialProtection,
                                                       CurrentProtection = src.CurrentProtection,
                                                       PreviousProtection = src.PreviousProtection,
                                                       FirstExecutableTransition = src.FirstExecutableTransition,
                                                       MapCount = src.MapCount,
                                                       WriteCount = src.WriteCount,
                                                       ProtectCount = src.ProtectCount,
                                                       ThreadStartCount = src.ThreadStartCount,
                                                       ProtectFlipCount = src.ProtectFlipCount,
                                                       RapidProtectFlipCount = src.RapidProtectFlipCount,
                                                       ExecutableFlipCount = src.ExecutableFlipCount,
                                                       GuardNoAccessFlipCount = src.GuardNoAccessFlipCount,
                                                       WritableExecutableFlipCount = src.WritableExecutableFlipCount,
                                                       ProtectionTransition = src.ProtectionTransition,
                                                       EntropyBits = src.EntropyBits,
                                                       MaxEntropyBits = src.MaxEntropyBits,
                                                       EntropyFlipCount = src.EntropyFlipCount,
                                                       RapidEntropyFlipCount = src.RapidEntropyFlipCount,
                                                       HighEntropyWriteCount = src.HighEntropyWriteCount,
                                                       SampleBytes = src.SampleBytes,
                                                       LifecycleSummary = src.LifecycleSummary,
                                                       ThreadStartObserved = src.ThreadStartObserved,
                                                       ThreadId = src.ThreadId,
                                                       ThreadStartAddress = src.ThreadStartAddress,
                                                       FunctionTableRegistered = src.FunctionTableRegistered,
                                                       FunctionTablePointer = src.FunctionTablePointer,
                                                       SignatureLevel = src.SignatureLevel,
                                                       SignatureType = src.SignatureType };
        }

        private sealed class ApiCallGraphMainRowView
        {
            public string GraphKey { get; set; } = string.Empty;
            public string ThreadGroupKey { get; set; } = string.Empty;
            public string ViewModeKey { get; set; } = "call";
            public string ApiName { get; set; } = string.Empty;
            public string OriginModule { get; set; } = string.Empty;
            public string ActionLabel { get; set; } = string.Empty;
            public string SensorLabel { get; set; } = string.Empty;
            public string CallerOriginKey { get; set; } = string.Empty;
            public string CallerOriginLabel { get; set; } = string.Empty;
            public string CallChainLabel { get; set; } = string.Empty;
            public Brush? CallerOriginBackground { get; set; }
            public Brush? CallerOriginForeground { get; set; }
            public Brush? SensorBackground { get; set; }
            public Brush? SensorForeground { get; set; }
            public Brush? HeatTrackBackground { get; set; }
            public Brush? HeatFillBackground { get; set; }
            public Brush? RowBackground { get; set; }
            public Brush? RowBorderBrush { get; set; }
            public string SourceLabel { get; set; } = string.Empty;
            public string TargetLabel { get; set; } = string.Empty;
            public string ThreadLabel { get; set; } = string.Empty;
            public string Field1Label { get; set; } = "Base";
            public string Field2Label { get; set; } = "Size";
            public string Field3Label { get; set; } = "Alloc Type";
            public string Field4Label { get; set; } = "Protect";
            public string BaseLabel { get; set; } = string.Empty;
            public string SizeLabel { get; set; } = string.Empty;
            public string AllocTypeLabel { get; set; } = string.Empty;
            public string ProtectLabel { get; set; } = string.Empty;
            public string LastSeen { get; set; } = string.Empty;
            public string AbsoluteLastSeen { get; set; } = string.Empty;
            public string FirstSeen { get; set; } = string.Empty;
            public string AbsoluteFirstSeen { get; set; } = string.Empty;
            public DateTime FirstSeenUtc { get; set; }
            public DateTime LastSeenUtc { get; set; }
            public int Hits { get; set; }
            public double HeatPercent { get; set; }
            public double ActivityFillWidth { get; set; }
            public string DetailFull { get; set; } = string.Empty;
        }

        public void SetLaneFocus(string? laneKey)
        {
            _laneFocusKey = string.IsNullOrWhiteSpace(laneKey) ? null : laneKey;
            FocusViewport();
        }

        public string? GetLaneFocus() => _laneFocusKey;
    }

    public sealed class PausedTimelineSpan
    {
        public DateTime StartUtc { get; set; }
        public DateTime EndUtc { get; set; }
    }

    public sealed class ProcessSessionTab : INotifyPropertyChanged
    {
        private int _pid;
        private string _title = "";
        public List<TelemetryEvent> Events { get; } = new();
        public List<PerformanceSample> PerformanceHistory { get; } = new();
        public List<MemoryRegionAttributionSample> MemoryRegionAttributionHistory { get; } = new();
        public List<ThreadLifecycleEventSample> ThreadLifecycleHistory { get; } = new();
        public List<ThreadStackHistoryArchiveEntry> ThreadStackHistories { get; } = new();
        internal HashSet<string> ChildProcessExpandedKeys { get; } = new(StringComparer.Ordinal);
        public DateTime CaptureStartUtc { get; set; } = DateTime.UtcNow;
        public double ViewDurationSeconds { get; set; } = 120;
        public double ViewStartSeconds { get; set; }
        public string? LaneFocusKey { get; set; }
        public bool UseUsermodeHooks { get; set; }
        public bool KernelHooksEnabled { get; set; } = true;
        public bool SignatureIntelEnabled { get; set; } = true;
        public bool SignatureIntelMemoryScanEnabled { get; set; }
        public bool SignatureIntelPageScanEnabled { get; set; }
        public bool AutoOpenApiGraphOnNextStart { get; set; }
        public bool LaunchStartsSuspendedPending { get; set; }
        public bool DeferredLaunchGateResumePending { get; set; }
        public bool LaunchOwnedByInterface { get; set; }
        public LaunchTargetKind AnalysisSubjectKind { get; set; } = LaunchTargetKind.Executable;
        public string AnalysisSubjectPath { get; set; } = string.Empty;
        public string AnalysisHostPath { get; set; } = string.Empty;
        public bool TargetExited { get; set; }
        public string TargetExitReason { get; set; } = string.Empty;
        public bool OfflineSnapshot { get; set; }
        public string? BackingStorePath { get; set; }
        public List<PausedTimelineSpan> PausedTimelineSpans { get; } = new();
        public DateTime? ActivePauseStartUtc { get; set; }

        public int Pid
        {
            get => _pid;
            set {
                if (_pid == value)
                    return;
                _pid = value;
                OnPropertyChanged();
            }
        }

        public string Title
        {
            get => _title;
            set {
                if (_title == value)
                    return;
                _title = value;
                OnPropertyChanged();
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? prop = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));
    }
}
