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
        private readonly BulkObservableCollection<ExtendedActivityRowSnapshot> _extendedStringRows = new();
        private readonly BulkObservableCollection<ExtendedActivityRowSnapshot> _extendedCapabilityRows = new();
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
        private bool _sr71PreResumeDropArmed;
        private int _sr71PreResumeDropPid;
        private DateTime? _sr71PreResumeDropUntilUtc;
        private bool _signatureIntelEnabled = true;
        private bool _signatureIntelMemoryScanEnabled = true;
        private bool _signatureIntelPageScanEnabled = true;
        private bool _useKernelDriver = true;
        private bool _startupDefaultUseUsermodeHooks = true;
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
        private static readonly string WindowTitleBase = ProductEdition.DisplayName;

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
            set
            {
                if (_pid == value)
                    return;
                _pid = value;
                OnPropertyChanged();
            }
        }

        public string Title
        {
            get => _title;
            set
            {
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
