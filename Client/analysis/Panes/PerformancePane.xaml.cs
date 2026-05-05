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
    public partial class PerformancePane : UserControl
    {
        public event RoutedEventHandler? ReorderRequested;
        public event RoutedEventHandler? CloseRequested;
        public event RoutedEventHandler? FloatRequested;
        public event EventHandler<ThreadUsageRow>? ThreadDoubleClicked;
        public event EventHandler<MemoryDisassemblyRequestedEventArgs>? DisassemblyRequested;
        public event RoutedEventHandler? ParallelStacksRequested;
        public event EventHandler<PaneHeaderDragEventArgs>? HeaderDragStarted;
        public event EventHandler<PaneHeaderDragEventArgs>? HeaderDragDelta;
        public event EventHandler<PaneHeaderDragEventArgs>? HeaderDragCompleted;

        private DateTime _captureStartUtc;
        private DateTime _viewStartUtc;
        private DateTime _viewEndUtc;
        private PerformanceSample? _lastSample;
        private readonly List<PerformanceSample> _historySamples = new();
        private readonly List<MemoryRegionAttributionSample> _memoryRegionAttributionHistory = new();
        private readonly List<ThreadLifecycleEventSample> _threadLifecycleHistory = new();
        private readonly List<ThreadStackHistoryArchiveEntry> _threadStackHistories = new();
        private bool _timeTravelEnabled = true;
        private bool _timeTravelSliderProgrammatic;
        private int _selectedSampleIndex = -1;
        private bool _memoryInspectorEnabled;
        private bool _closingMemoryInspectorWindow;

        private readonly TimeSeriesBuffer _cpu = new(2000);
        private readonly TimeSeriesBuffer _diskRead = new(2000);
        private readonly TimeSeriesBuffer _diskWrite = new(2000);
        private readonly TimeSeriesBuffer _ramPrivate = new(2000);
        private readonly TimeSeriesBuffer _netIn = new(2000);
        private readonly TimeSeriesBuffer _netOut = new(2000);
        private MemoryInspectorWindow? _memoryInspectorWindow;

        private int _pid;
        private string _analysisSubjectPath = string.Empty;
        private string _analysisHostPath = string.Empty;
        private DateTime _lastDetailsRefreshUtc;
        private bool _headerMouseDown;
        private bool _headerDragging;
        private Point _headerMouseDownPos;
        private bool _detailsStacked;
        private bool _memoryTreemapEnabled;
        private bool _showNetworkPeers;
        private bool _processLiveDataAvailable = true;
        private bool _targetSuspended;
        private readonly Dictionary<string, string> _reverseDnsCache = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _pendingReverseDnsLookups = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, NetworkPeerRow> _networkPeerByKey = new(StringComparer.OrdinalIgnoreCase);
        private readonly DispatcherTimer _memoryInspectorRefreshTimer;
        private bool _memoryInspectorRefreshPending;
        private DateTime _lastMemoryInspectorRefreshUtc;
        private static readonly TimeSpan MemoryInspectorRefreshCoalesceInterval = TimeSpan.FromMilliseconds(350);
        private static readonly TimeSpan MemoryInspectorRefreshMinimumDelay = TimeSpan.FromMilliseconds(40);

        public ObservableCollection<ThreadUsageRow> TopThreads { get; } = new();
        public ObservableCollection<CoreUsageRow> CoreUsageRows { get; } = new();
        public ObservableCollection<ModuleInfoRow> Modules { get; } = new();
        public ObservableCollection<PeInfoRow> PeInfo { get; } = new();
        public ObservableCollection<MemoryMetricRow> MemoryMetrics { get; } = new();
        public BulkObservableCollection<MemoryInspectorRow> MemoryInspectorRows { get; } = new();
        public ObservableCollection<ThreadLifecycleRow> ThreadLifecycleRows { get; } = new();
        public ObservableCollection<NetworkPeerRow> NetworkPeers { get; } = new();

        public PerformancePane()
        {
            InitializeComponent();
            _memoryInspectorRefreshTimer = new DispatcherTimer(DispatcherPriority.Background, Dispatcher);
            _memoryInspectorRefreshTimer.Interval = MemoryInspectorRefreshCoalesceInterval;
            _memoryInspectorRefreshTimer.Tick += (_, __) => FlushScheduledMemoryInspectorRefresh();
            if (ThreadsGrid != null)
                ThreadsGrid.ItemsSource = TopThreads;
            if (ModulesGrid != null)
                ModulesGrid.ItemsSource = Modules;
            if (PeInfoGrid != null)
                PeInfoGrid.ItemsSource = PeInfo;
            if (MemoryGrid != null)
                MemoryGrid.ItemsSource = MemoryMetrics;
            if (MemoryInspectorGrid != null)
                MemoryInspectorGrid.ItemsSource = MemoryInspectorRows;
            if (ThreadLifecycleGrid != null)
                ThreadLifecycleGrid.ItemsSource = ThreadLifecycleRows;
            if (NetworkPeersGrid != null)
                NetworkPeersGrid.ItemsSource = NetworkPeers;
            if (MemoryTreemapCanvas != null)
            {
                MemoryTreemapCanvas.SizeChanged += (_, __) => UpdateMemoryTreemap();
            }
            _showNetworkPeers = false;
            UpdateNetworkPaneView();
            ConfigureCharts();
            Loaded += (_, __) =>
            {
                _memoryTreemapEnabled = true;
                if (MemoryViewToggle != null)
                {
                    MemoryViewToggle.IsChecked = true;
                    MemoryViewToggle.Content = "Table";
                }
                if (MemoryGrid != null)
                    MemoryGrid.Visibility = Visibility.Collapsed;
                if (MemoryTreemapHost != null)
                    MemoryTreemapHost.Visibility = Visibility.Visible;
                if (MemoryInspectorGrid != null)
                    MemoryInspectorGrid.Visibility = Visibility.Collapsed;
                if (ThreadsGrid != null)
                    ThreadsGrid.Visibility = Visibility.Visible;
                if (ThreadLifecycleGrid != null)
                    ThreadLifecycleGrid.Visibility = Visibility.Collapsed;
                if (TimeTravelStampBlock != null)
                    TimeTravelStampBlock.Text = "LIVE";
                UpdateMemoryViewMode();
                UpdateDetailsLayout();
                UpdateLiveDataOverlays();
            };
        }

        private void NetworkViewSwitchButton_Click(object sender, RoutedEventArgs e)
        {
            _showNetworkPeers = !_showNetworkPeers;
            UpdateNetworkPaneView();
        }

        private void UpdateNetworkPaneView()
        {
            if (NetChart == null || NetworkPeersGrid == null || NetworkPaneTitle == null ||
                NetworkViewSwitchButton == null)
                return;

            if (_showNetworkPeers)
            {
                NetChart.Visibility = Visibility.Collapsed;
                NetworkPeersGrid.Visibility = Visibility.Visible;
                NetworkPaneTitle.Text = "Network Peers";
                NetworkViewSwitchButton.Content = "Traffic";
                return;
            }

            NetChart.Visibility = Visibility.Visible;
            NetworkPeersGrid.Visibility = Visibility.Collapsed;
            NetworkPaneTitle.Text = "Network Traffic";
            NetworkViewSwitchButton.Content = "Peers";
        }

        private static SolidColorBrush Brush(byte r, byte g, byte b)
        {
            var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
            brush.Freeze();
            return brush;
        }

        private void ConfigureCharts()
        {
            if (CpuChart != null)
            {
                CpuChart.SetSeries(new[] {
                    new ChartSeries("CPU %", Brush(0x35, 0xA8, 0xFF), SeriesScale.Percent, p => p.CpuPercent,
                                    ChartValueFormat.Percent),
                    new ChartSeries("Cores used %", Brush(0x7C, 0xD5, 0xFF), SeriesScale.Percent,
                                    p => p.CoresUsedPercent, ChartValueFormat.Percent),
                });
            }

            if (DiskChart != null)
            {
                DiskChart.SetSeries(new[] {
                    new ChartSeries("Read B/s", Brush(0xFF9A21), SeriesScale.AutoToViewMax, p => p.DiskReadBytesPerSec,
                                    ChartValueFormat.BytesPerSecond),
                    new ChartSeries("Write B/s", Brush(0xFF4545), SeriesScale.AutoToViewMax,
                                    p => p.DiskWriteBytesPerSec, ChartValueFormat.BytesPerSecond),
                });
            }

            if (RamChart != null)
            {
                RamChart.SetSeries(new[] {
                    new ChartSeries("Private bytes", Brush(0x43, 0xF2, 0x72), SeriesScale.AutoToViewMax,
                                    p => p.PrivateBytes, ChartValueFormat.Bytes),
                    new ChartSeries("Commit", Brush(0x66, 0xD9, 0xEF), SeriesScale.AutoToViewMax, p => p.CommitBytes,
                                    ChartValueFormat.Bytes),
                    new ChartSeries("MEM_IMAGE", Brush(0xFF, 0xC8, 0x57), SeriesScale.AutoToViewMax, p => p.ImageBytes,
                                    ChartValueFormat.Bytes),
                    new ChartSeries("MEM_MAPPED", Brush(0xB2, 0x8D, 0xFF), SeriesScale.AutoToViewMax,
                                    p => p.MappedBytes, ChartValueFormat.Bytes),
                });
            }

            if (NetChart != null)
            {
                NetChart.SetSeries(new[] {
                    new ChartSeries("Inbound B/s", Brush(0xA0, 0x5B, 0xFF), SeriesScale.AutoToViewMax,
                                    p => p.NetInBytesPerSec, ChartValueFormat.BytesPerSecond),
                    new ChartSeries("Outbound B/s", Brush(0xC0, 0x86, 0xFF), SeriesScale.AutoToViewMax,
                                    p => p.NetOutBytesPerSec, ChartValueFormat.BytesPerSecond),
                });
            }
        }

        private static SolidColorBrush Brush(uint rgb)
        {
            var r = (byte)((rgb >> 16) & 0xFF);
            var g = (byte)((rgb >> 8) & 0xFF);
            var b = (byte)(rgb & 0xFF);
            return Brush(r, g, b);
        }

        public void SetCaptureStart(DateTime captureStartUtc)
        {
            _captureStartUtc = captureStartUtc;
        }

        private DateTime GetObservedTimestampUtc()
        {
            if (_viewEndUtc != default)
            {
                return _viewEndUtc;
            }

            if (_historySamples.Count > 0)
            {
                return _historySamples[^1].TimestampUtc;
            }

            return DateTime.UtcNow;
        }

        private int ResolveSampleIndexForTimestamp(DateTime timestampUtc)
        {
            if (_historySamples.Count == 0)
            {
                return -1;
            }

            DateTime first = _historySamples[0].TimestampUtc;
            DateTime last = _historySamples[^1].TimestampUtc;
            DateTime target = timestampUtc == default ? last : timestampUtc;

            if (target < first)
            {
                return -1;
            }

            if (!_processLiveDataAvailable && target > last)
            {
                return -1;
            }

            return FindSampleIndexForTimestamp(target);
        }

        private int ResolveSampleIndexForCurrentView() => ResolveSampleIndexForTimestamp(GetObservedTimestampUtc());

        private bool HasHistoricalDataForObservedTime() => ResolveSampleIndexForCurrentView() >= 0;

        public void SetPid(int pid)
        {
            if (_pid != pid)
            {
                _historySamples.Clear();
                _threadLifecycleHistory.Clear();
                _selectedSampleIndex = -1;
                TopThreads.Clear();
                CoreUsageRows.Clear();
                ThreadLifecycleRows.Clear();
                MemoryMetrics.Clear();
                MemoryInspectorRows.Clear();
                _memoryRegionAttributionHistory.Clear();
                RebuildTimeTravelSliderBounds();
                if (TimeTravelStampBlock != null)
                {
                    TimeTravelStampBlock.Text = "LIVE";
                }
            }
            _pid = pid;
            UpdateMemoryInspectorWindowTitle();
        }

        public void SetAnalysisSubject(string? subjectPath, string? hostPath)
        {
            _analysisSubjectPath = subjectPath?.Trim() ?? string.Empty;
            _analysisHostPath = hostPath?.Trim() ?? string.Empty;
        }

        public void RefreshLiveProcessDetails()
        {
            RefreshProcessDetails();
        }

        public void ShowMemoryInspectorWindow()
        {
            EnsureMemoryInspectorWindow();
            if (_memoryInspectorWindow == null)
            {
                return;
            }

            if (_memoryInspectorWindow.WindowState == WindowState.Minimized)
            {
                _memoryInspectorWindow.WindowState = WindowState.Normal;
            }

            _memoryInspectorWindow.Activate();
            if (MemoryInspectorToggle != null && MemoryInspectorToggle.IsChecked != true)
            {
                MemoryInspectorToggle.IsChecked = true;
            }
        }

        public bool IsTargetSuspended => _targetSuspended;

        public void SetProcessLiveDataAvailable(bool available)
        {
            _processLiveDataAvailable = available;
            if (!available)
            {
                if (_targetSuspended)
                {
                    PreserveSuspendedThreadState();
                }
                else if (_historySamples.Count == 0)
                {
                    TopThreads.Clear();
                    CoreUsageRows.Clear();
                    ThreadLifecycleRows.Clear();
                    MemoryMetrics.Clear();
                    MemoryInspectorRows.Clear();
                    NetworkPeers.Clear();
                    UpdateMemoryTreemap();
                }
                else if (_selectedSampleIndex >= 0 && _selectedSampleIndex < _historySamples.Count)
                {
                    ApplySampleIndex(ResolveSampleIndexForCurrentView(), updateSlider: true);
                }
                else
                {
                    ApplySampleIndex(ResolveSampleIndexForCurrentView(), updateSlider: true);
                }
            }

            UpdateLiveDataOverlays();
        }

        public void SetTargetSuspended(bool suspended)
        {
            _targetSuspended = suspended;
            if (_selectedSampleIndex >= 0 && _selectedSampleIndex < _historySamples.Count)
            {
                ApplySampleIndex(_selectedSampleIndex, updateSlider: false);
            }
            else if (_historySamples.Count > 0)
            {
                ApplySampleIndex(_historySamples.Count - 1, updateSlider: false);
            }
            else if (suspended)
            {
                PreserveSuspendedThreadState();
                UpdateSubtitle();
                UpdateLiveDataOverlays();
            }
            else
            {
                UpdateLiveDataOverlays();
            }
        }

        private void PreserveSuspendedThreadState()
        {
            List<ThreadUsageSample> suspendedThreads = BuildSuspendedThreadSnapshot();
            if (suspendedThreads.Count == 0)
            {
                return;
            }

            ApplyUnifiedThreadRows(BuildUnifiedThreadRows(suspendedThreads, DateTime.UtcNow));
            if (_threadLifecycleHistory.Count > 0)
            {
                RebuildThreadLifecycleRows(DateTime.UtcNow);
            }
        }

        private List<ThreadUsageSample> BuildSuspendedThreadSnapshot()
        {
            if (_lastSample?.TopThreads.Count > 0)
            {
                return _lastSample.TopThreads.Select(CloneThreadUsageForSuspension)
                    .OrderByDescending(x => x.CpuMsDelta)
                    .Take(14)
                    .ToList();
            }

            if (TopThreads.Count > 0)
            {
                return TopThreads
                    .Select(row => new ThreadUsageSample { Tid = row.Tid, CpuMsDelta = row.CpuMs, State = row.State,
                                                           WaitReason = row.IsSuspended ? "Suspended" : string.Empty,
                                                           Kind = row.ThreadKind, StartTimeUtc = row.StartTimeUtc,
                                                           TargetSuspended = true })
                    .Take(14)
                    .ToList();
            }

            if (_threadLifecycleHistory.Count == 0)
            {
                return new List<ThreadUsageSample>();
            }

            var activeThreads = new Dictionary<uint, ThreadLifecycleEventSample>();
            for (int i = 0; i < _threadLifecycleHistory.Count; i += 1)
            {
                ThreadLifecycleEventSample sample = _threadLifecycleHistory[i];
                if (!sample.EventKind.Equals("Exit", StringComparison.OrdinalIgnoreCase))
                {
                    activeThreads[sample.ThreadId] = sample;
                }
                else
                {
                    activeThreads.Remove(sample.ThreadId);
                }
            }

            return activeThreads.Values.OrderByDescending(x => x.TimestampUtc)
                .Take(14)
                .Select(sample => new ThreadUsageSample { Tid = unchecked((int)sample.ThreadId), CpuMsDelta = 0,
                                                          State = "Suspended", WaitReason = "Suspended",
                                                          Kind = string.IsNullOrWhiteSpace(sample.EventKind)
                                                                     ? "Thread"
                                                                     : sample.EventKind,
                                                          StartTimeUtc = sample.TimestampUtc, TargetSuspended = true })
                .ToList();
        }

        private static ThreadUsageSample CloneThreadUsage(ThreadUsageSample sample)
        {
            return new ThreadUsageSample { Tid = sample.Tid,
                                           CpuMsDelta = sample.CpuMsDelta,
                                           State = sample.State,
                                           WaitReason = sample.WaitReason,
                                           Kind = sample.Kind,
                                           StartTimeUtc = sample.StartTimeUtc,
                                           TargetSuspended = sample.TargetSuspended };
        }

        private static ThreadUsageSample CloneThreadUsageForSuspension(ThreadUsageSample sample)
        {
            return new ThreadUsageSample { Tid = sample.Tid,      CpuMsDelta = sample.CpuMsDelta,
                                           State = sample.State,  WaitReason = "Suspended",
                                           Kind = sample.Kind,    StartTimeUtc = sample.StartTimeUtc,
                                           TargetSuspended = true };
        }

        public IReadOnlyList<ThreadUsageRow> SnapshotTopThreads() =>
            TopThreads
                .Select(row => new ThreadUsageRow(new ThreadUsageSample {
                            Tid = row.Tid, CpuMsDelta = row.CpuMs, State = row.State,
                            WaitReason = row.IsSuspended ? "Suspended" : string.Empty, Kind = row.ThreadKind,
                            StartTimeUtc = row.StartTimeUtc, TargetSuspended = row.IsSuspended
                        }))
                .ToList();

        public void SetViewWindow(DateTime viewStartUtc, DateTime viewEndUtc)
        {
            _viewStartUtc = viewStartUtc;
            _viewEndUtc = viewEndUtc;

            CpuChart?.SetView(_viewStartUtc, _viewEndUtc);
            DiskChart?.SetView(_viewStartUtc, _viewEndUtc);
            RamChart?.SetView(_viewStartUtc, _viewEndUtc);
            NetChart?.SetView(_viewStartUtc, _viewEndUtc);

            if (_timeTravelEnabled && _historySamples.Count > 0)
            {
                int index = ResolveSampleIndexForCurrentView();
                ApplySampleIndex(index, updateSlider: true);
            }

            UpdateSubtitle();
        }

        public void PushSample(PerformanceSample s)
        {
            _processLiveDataAvailable = true;
            _lastSample = CloneSample(s);
            _historySamples.Add(CloneSample(s));
            if (_historySamples.Count > 4000)
            {
                _historySamples.RemoveRange(0, _historySamples.Count - 4000);
            }
            RebuildTimeTravelSliderBounds();

            _cpu.Add(s.TimestampUtc, s.CpuPercent);
            _diskRead.Add(s.TimestampUtc, s.DiskReadBytesPerSec);
            _diskWrite.Add(s.TimestampUtc, s.DiskWriteBytesPerSec);
            _ramPrivate.Add(s.TimestampUtc, s.PrivateBytes);
            _netIn.Add(s.TimestampUtc, s.NetInBytesPerSec);
            _netOut.Add(s.TimestampUtc, s.NetOutBytesPerSec);

            CpuChart?.PushSample(s);
            DiskChart?.PushSample(s);
            RamChart?.PushSample(s);
            NetChart?.PushSample(s);

            if (!_timeTravelEnabled)
            {
                ApplySampleIndex(_historySamples.Count - 1, updateSlider: true);
            }

            if (!_timeTravelEnabled && (DateTime.UtcNow - _lastDetailsRefreshUtc).TotalSeconds >= 5.0)
            {
                RefreshProcessDetails();
                _lastDetailsRefreshUtc = DateTime.UtcNow;
            }

            UpdateSubtitle();
            UpdateLiveDataOverlays();
        }

        public void LoadHistory(IEnumerable<PerformanceSample> samples)
        {
            var list = samples.Select(CloneSample).OrderBy(x => x.TimestampUtc).ToList();
            _historySamples.Clear();
            _historySamples.AddRange(list);
            _selectedSampleIndex = _historySamples.Count - 1;

            CpuChart?.SetSamples(list);
            DiskChart?.SetSamples(list);
            RamChart?.SetSamples(list);
            NetChart?.SetSamples(list);

            if (list.Count > 0)
            {
                _lastSample = list[^1];
            }
            else
            {
                _lastSample = null;
            }

            RebuildTimeTravelSliderBounds();
            if (_historySamples.Count > 0)
            {
                int index = _timeTravelEnabled ? ResolveSampleIndexForCurrentView() : _historySamples.Count - 1;
                ApplySampleIndex(index, updateSlider: true);
            }
            else
            {
                TopThreads.Clear();
                CoreUsageRows.Clear();
                MemoryMetrics.Clear();
                MemoryInspectorRows.Clear();
                UpdateMemoryTreemap();
            }

            RefreshProcessDetails();
            UpdateSubtitle();
            UpdateLiveDataOverlays();
        }

        public void PushMemoryRegionAttributions(IEnumerable<MemoryRegionAttributionSample> samples)
        {
            bool appended = false;
            foreach (MemoryRegionAttributionSample sample in samples)
            {
                _memoryRegionAttributionHistory.Add(CloneMemoryRegionAttributionSample(sample));
                appended = true;
            }

            if (!appended)
            {
                return;
            }

            if (_memoryRegionAttributionHistory.Count > 40_000)
            {
                _memoryRegionAttributionHistory.RemoveRange(0, _memoryRegionAttributionHistory.Count - 40_000);
            }

            ScheduleMemoryInspectorRowsRefresh();

            UpdateLiveDataOverlays();
        }

        public void PushObservedModules(IEnumerable<ModuleInfoRow> modules)
        {
            var incoming = modules
                               .Where(static module => !string.IsNullOrWhiteSpace(module.Name) ||
                                                       !string.IsNullOrWhiteSpace(module.Path))
                               .ToList();
            if (incoming.Count == 0)
            {
                return;
            }

            var byKey = new Dictionary<string, ModuleInfoRow>(StringComparer.OrdinalIgnoreCase);
            foreach (ModuleInfoRow module in Modules)
            {
                byKey[BuildModuleKey(module)] = module;
            }

            foreach (ModuleInfoRow module in incoming)
            {
                byKey[BuildModuleKey(module)] = module;
            }

            Modules.Clear();
            foreach (ModuleInfoRow module in byKey.Values
                         .OrderBy(static module => module.Name, StringComparer.OrdinalIgnoreCase)
                         .Take(1024))
            {
                Modules.Add(module);
            }

            UpdateLiveDataOverlays();
        }

        public void LoadMemoryRegionAttributionHistory(IEnumerable<MemoryRegionAttributionSample> history)
        {
            _memoryRegionAttributionHistory.Clear();
            _memoryRegionAttributionHistory.AddRange(
                history.Select(CloneMemoryRegionAttributionSample).OrderBy(x => x.TimestampUtc));

            RefreshMemoryInspectorRowsForCurrentView();
        }

        public void PushThreadLifecycle(ThreadLifecycleEventSample sample)
        {
            PushThreadLifecycles(new[] { sample });
        }

        public void PushThreadLifecycles(IEnumerable<ThreadLifecycleEventSample> samples)
        {
            bool appended = false;
            foreach (ThreadLifecycleEventSample sample in samples)
            {
                _threadLifecycleHistory.Add(CloneThreadLifecycleEvent(sample));
                appended = true;
            }

            if (!appended)
            {
                return;
            }

            if (_threadLifecycleHistory.Count > 40_000)
            {
                _threadLifecycleHistory.RemoveRange(0, _threadLifecycleHistory.Count - 40_000);
            }

            if (!_timeTravelEnabled)
            {
                RebuildThreadLifecycleRows(DateTime.UtcNow);
            }

            ScheduleMemoryInspectorRowsRefresh();
            UpdateLiveDataOverlays();
        }

        public void LoadThreadLifecycleHistory(IEnumerable<ThreadLifecycleEventSample> history)
        {
            _threadLifecycleHistory.Clear();
            _threadLifecycleHistory.AddRange(history.Select(CloneThreadLifecycleEvent).OrderBy(x => x.TimestampUtc));

            DateTime cutoff =
                _historySamples.Count > 0 && _selectedSampleIndex >= 0 && _selectedSampleIndex < _historySamples.Count
                    ? _historySamples[_selectedSampleIndex].TimestampUtc
                    : DateTime.UtcNow;
            RebuildThreadLifecycleRows(cutoff);
            RefreshMemoryInspectorRowsForCurrentView();
            UpdateLiveDataOverlays();
        }

        public void LoadThreadStackHistory(IEnumerable<ThreadStackHistoryArchiveEntry> history)
        {
            _threadStackHistories.Clear();
            _threadStackHistories.AddRange(history.Select(x => x.Clone()));

            RefreshMemoryInspectorRowsForCurrentView();
            UpdateLiveDataOverlays();
        }

        private void RefreshMemoryInspectorRowsForCurrentView()
        {
            _memoryInspectorRefreshPending = false;
            if (_memoryInspectorRefreshTimer.IsEnabled)
            {
                _memoryInspectorRefreshTimer.Stop();
            }

            if (_selectedSampleIndex >= 0 && _selectedSampleIndex < _historySamples.Count)
            {
                RebuildMemoryInspectorRows(_historySamples[_selectedSampleIndex].MemoryPages,
                                           _historySamples[_selectedSampleIndex].TimestampUtc);
            }
            else if (_lastSample != null)
            {
                RebuildMemoryInspectorRows(_lastSample.MemoryPages, _lastSample.TimestampUtc);
            }
            else
            {
                RebuildMemoryInspectorRowsFromAttributions(DateTime.UtcNow);
            }

            _lastMemoryInspectorRefreshUtc = DateTime.UtcNow;
        }

        private void ScheduleMemoryInspectorRowsRefresh()
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.BeginInvoke(new Action(ScheduleMemoryInspectorRowsRefresh), DispatcherPriority.Background);
                return;
            }

            _memoryInspectorRefreshPending = true;
            if (_memoryInspectorRefreshTimer.IsEnabled)
            {
                return;
            }

            TimeSpan elapsed = DateTime.UtcNow - _lastMemoryInspectorRefreshUtc;
            TimeSpan delay = elapsed >= MemoryInspectorRefreshCoalesceInterval
                                 ? MemoryInspectorRefreshMinimumDelay
                                 : MemoryInspectorRefreshCoalesceInterval - elapsed;
            if (delay < MemoryInspectorRefreshMinimumDelay)
            {
                delay = MemoryInspectorRefreshMinimumDelay;
            }

            _memoryInspectorRefreshTimer.Interval = delay;
            _memoryInspectorRefreshTimer.Start();
        }

        private void FlushScheduledMemoryInspectorRefresh()
        {
            _memoryInspectorRefreshTimer.Stop();
            if (!_memoryInspectorRefreshPending)
            {
                return;
            }

            RefreshMemoryInspectorRowsForCurrentView();
        }

        private void RebuildTimeTravelSliderBounds()
        {
            if (TimeTravelSlider == null)
            {
                return;
            }

            _timeTravelSliderProgrammatic = true;
            TimeTravelSlider.Minimum = 0;
            TimeTravelSlider.Maximum = Math.Max(0, _historySamples.Count - 1);
            TimeTravelSlider.IsEnabled = _historySamples.Count > 1 && _timeTravelEnabled;
            if (_historySamples.Count == 0)
            {
                TimeTravelSlider.Value = 0;
                _selectedSampleIndex = -1;
            }
            else if (_selectedSampleIndex < 0 || _selectedSampleIndex >= _historySamples.Count)
            {
                _selectedSampleIndex = _historySamples.Count - 1;
                TimeTravelSlider.Value = _selectedSampleIndex;
            }
            _timeTravelSliderProgrammatic = false;
        }

        private int FindSampleIndexForTimestamp(DateTime timestampUtc)
        {
            if (_historySamples.Count == 0)
            {
                return -1;
            }

            DateTime target = timestampUtc == default ? _historySamples[^1].TimestampUtc : timestampUtc;
            int lo = 0;
            int hi = _historySamples.Count - 1;
            while (lo < hi)
            {
                int mid = lo + ((hi - lo + 1) / 2);
                if (_historySamples[mid].TimestampUtc <= target)
                {
                    lo = mid;
                }
                else
                {
                    hi = mid - 1;
                }
            }

            return lo;
        }

        private void ApplySampleIndex(int index, bool updateSlider)
        {
            if (_historySamples.Count == 0 || index < 0 || index >= _historySamples.Count)
            {
                _selectedSampleIndex = -1;
                TopThreads.Clear();
                CoreUsageRows.Clear();
                ThreadLifecycleRows.Clear();
                MemoryMetrics.Clear();
                MemoryInspectorRows.Clear();
                NetworkPeers.Clear();
                if (TimeTravelStampBlock != null)
                {
                    TimeTravelStampBlock.Text = "LIVE";
                }
                UpdateSubtitle();
                UpdateMemoryTreemap();
                UpdateLiveDataOverlays();
                return;
            }

            _selectedSampleIndex = index;
            PerformanceSample sample = _historySamples[index];
            _lastSample = sample;

            int selectedThreadTid = 0;
            int selectedThreadIndex = -1;
            if (ThreadsGrid?.SelectedItem is ThreadUsageRow selectedThread)
            {
                selectedThreadTid = selectedThread.Tid;
                selectedThreadIndex = ThreadsGrid.SelectedIndex;
            }

            var rebuiltThreads = BuildUnifiedThreadRows(sample.TopThreads, sample.TimestampUtc);
            if (selectedThreadTid > 0 && selectedThreadIndex >= 0 && selectedThreadIndex < rebuiltThreads.Count)
            {
                int selectedIndexInNew = rebuiltThreads.FindIndex(x => x.Tid == selectedThreadTid);
                if (selectedIndexInNew >= 0 && selectedIndexInNew != selectedThreadIndex)
                {
                    ThreadUsageRow pinned = rebuiltThreads[selectedIndexInNew];
                    rebuiltThreads.RemoveAt(selectedIndexInNew);
                    rebuiltThreads.Insert(selectedThreadIndex, pinned);
                }
            }

            ApplyUnifiedThreadRows(rebuiltThreads);
            ApplyCoreUsageRows(sample.CoreUsage, sample.CoreCount);
            if (selectedThreadTid > 0 && ThreadsGrid != null)
            {
                ThreadUsageRow? selectedAfter = TopThreads.FirstOrDefault(x => x.Tid == selectedThreadTid);
                if (selectedAfter != null)
                {
                    ThreadsGrid.SelectedItem = selectedAfter;
                }
            }

            MemoryMetrics.Clear();
            foreach (MemoryMetricSample metric in sample.MemoryMetrics)
            {
                MemoryMetrics.Add(new MemoryMetricRow { Metric = metric.Metric, Value = metric.Value,
                                                        BytesValue = metric.BytesValue });
            }
            RebuildMemoryInspectorRows(sample.MemoryPages, sample.TimestampUtc);
            RebuildThreadLifecycleRows(sample.TimestampUtc);

            if (TimeTravelStampBlock != null)
            {
                string mode = _timeTravelEnabled ? "T" : "LIVE";
                TimeTravelStampBlock.Text = $"{mode} {sample.TimestampUtc:HH:mm:ss}";
            }

            if (updateSlider && TimeTravelSlider != null)
            {
                _timeTravelSliderProgrammatic = true;
                TimeTravelSlider.Value = _selectedSampleIndex;
                _timeTravelSliderProgrammatic = false;
            }

            UpdateMemoryViewMode();
            UpdateMemoryTreemap();
            UpdateSubtitle();
            UpdateLiveDataOverlays();
        }

        private void RebuildMemoryInspectorRows(IEnumerable<MemoryPageSample> pages, DateTime cutoffUtc)
        {
            List<ThreadMemoryRange> threadRanges = BuildThreadMemoryRanges(_pid);
            MemoryAttributionLookup attributionLookup = BuildMemoryAttributionLookup(cutoffUtc);
            ThreadExecutionHeuristicIndex threadExecutionLookup = BuildThreadExecutionHeuristicIndex(cutoffUtc);
            List<MemoryInspectorRow> rows =
                pages
                    .Select(
                        page =>
                        {
                            MemoryRegionAttributionSample? attribution =
                                FindLatestMemoryRegionAttribution(page, attributionLookup);
                            ThreadExecutionMemoryHeuristic? threadHeuristic =
                                ShouldUseThreadExecutionHeuristic(page)
                                    ? threadExecutionLookup.FindBest(page.BaseAddress, page.RegionSize)
                                    : null;
                            string allocator = NormalizeDisplayText(DescribeAllocator(attribution, threadHeuristic));
                            string source =
                                NormalizeDisplayText(DescribeResolvedMemorySource(page, attribution, threadHeuristic));
                            string trust = DescribeResolvedMemoryTrust(page, attribution, threadHeuristic);
                            string context =
                                NormalizeDisplayText(DescribeResolvedMemoryContext(page, attribution, threadHeuristic));
                            string lifecycle =
                                NormalizeDisplayText(DescribeResolvedMemoryLifecycle(attribution, threadHeuristic));
                            string priorityBand =
                                DetermineMemoryPriorityBand(page, trust, attribution, threadHeuristic);
                            string category = NormalizeDisplayText(DescribeResolvedMemoryCategory(page));
                            string highlightBand = DetermineMemoryHighlightBand(category);
                            uint threadTid = ResolveThreadTidForPage(page, category, threadRanges);
                            if (threadTid == 0)
                            {
                                threadTid = ResolveThreadTidForAttribution(attribution);
                            }
                            if (threadTid == 0 && threadHeuristic != null)
                            {
                                threadTid = threadHeuristic.ThreadId;
                            }
                            string highlightLabel = DetermineMemoryHighlightLabel(category, highlightBand);
                            if (threadHeuristic != null && string.IsNullOrWhiteSpace(highlightLabel))
                            {
                                highlightLabel = "EXEC?";
                            }

                            return new MemoryInspectorRow { BaseAddress = $"0x{page.BaseAddress:X}",
                                                            Size = FormatBytes(
                                                                (long)Math.Min(page.RegionSize, (ulong) long.MaxValue)),
                                                            State = DescribeMemoryStateForInspector(page),
                                                            Type = DescribeMemoryTypeForInspector(page),
                                                            Protect = DescribeProtectionAcronym(page.Protect),
                                                            Category = category,
                                                            Allocator = allocator,
                                                            Source = source,
                                                            Context = context,
                                                            Lifecycle = lifecycle,
                                                            Trust = trust,
                                                            PriorityBand = priorityBand,
                                                            HighlightBand = highlightBand,
                                                            HighlightLabel = highlightLabel,
                                                            ThreadTid = threadTid,
                                                            SortRank = MemoryPriorityBandRank(priorityBand),
                                                            RegionSizeBytes = page.RegionSize,
                                                            BaseAddressValue = page.BaseAddress,
                                                            SnapshotOffset = page.SnapshotOffset,
                                                            SnapshotBytes = page.SnapshotBytes?.ToArray() };
                        })
                    .OrderBy(row => row.SortRank)
                    .ThenByDescending(row => row.RegionSizeBytes)
                    .ThenBy(row => row.BaseAddressValue)
                    .Take(768)
                    .ToList();

            ApplyMemoryInspectorRows(rows);
        }

        private MemoryAttributionLookup BuildMemoryAttributionLookup(DateTime cutoffUtc)
        {
            var lookup = new MemoryAttributionLookup();
            if (_pid <= 0 || _memoryRegionAttributionHistory.Count == 0)
            {
                return lookup;
            }

            uint targetPid = unchecked((uint)_pid);
            for (int i = _memoryRegionAttributionHistory.Count - 1; i >= 0; i -= 1)
            {
                MemoryRegionAttributionSample sample = _memoryRegionAttributionHistory[i];
                if (sample.TimestampUtc > cutoffUtc)
                {
                    continue;
                }
                if (sample.TargetPid != 0 && sample.TargetPid != targetPid)
                {
                    continue;
                }

                ulong baseAddress = sample.BaseAddress != 0 ? sample.BaseAddress : sample.AllocationBase;
                ulong size = sample.RegionSize;
                if (baseAddress == 0 || size == 0)
                {
                    continue;
                }

                lookup.Add(sample, baseAddress, size);
            }

            return lookup;
        }

        private ThreadExecutionHeuristicIndex BuildThreadExecutionHeuristicIndex(DateTime cutoffUtc)
        {
            const int maxSnapshotsPerThread = 16;
            const int maxFramesPerSnapshot = 16;

            var index = new ThreadExecutionHeuristicIndex();
            if (_pid <= 0)
            {
                return index;
            }

            uint targetPid = unchecked((uint)_pid);
            Dictionary<uint, ThreadLifecycleEventSample> latestThreadStarts =
                BuildLatestThreadStartMap(cutoffUtc, targetPid);
            foreach (ThreadLifecycleEventSample sample in latestThreadStarts.Values)
            {
                uint ownerPid = sample.ProcessPid != 0 ? sample.ProcessPid : targetPid;
                AddThreadExecutionEvidence(index, sample.ThreadId, ownerPid, sample.CreatorPid, sample.StartAddress,
                                           sample.TimestampUtc, "thread start", string.Empty, string.Empty, 85);
            }

            foreach (ThreadStackHistoryArchiveEntry history in _threadStackHistories)
            {
                if (history.Tid <= 0)
                {
                    continue;
                }

                uint tid = unchecked((uint)history.Tid);
                latestThreadStarts.TryGetValue(tid, out ThreadLifecycleEventSample? lifecycle);
                uint ownerPid = lifecycle != null && lifecycle.ProcessPid != 0 ? lifecycle.ProcessPid : targetPid;
                uint creatorPid = lifecycle?.CreatorPid ?? 0;
                foreach (ThreadStackSessionSnapshot snapshot in SelectThreadStackSnapshots(history, cutoffUtc,
                                                                                           maxSnapshotsPerThread))
                {
                    DateTime observedUtc = snapshot.CapturedAtUtc;
                    ulong rip = snapshot.ContextSnapshot?.Rip ?? 0;
                    AddThreadExecutionEvidence(index, tid, ownerPid, creatorPid, rip, observedUtc, "current RIP",
                                               string.Empty, string.Empty, 100);

                    int frameCount = 0;
                    foreach (StackFrameRow frame in snapshot.Frames.OrderBy(static frame => frame.Index))
                    {
                        if (frame.InstructionPointerRaw == 0)
                        {
                            continue;
                        }

                        string evidenceKind = frame.IsCurrent ? "current frame" : "stack frame";
                        int score = frame.IsCurrent ? 95 : 70;
                        AddThreadExecutionEvidence(index, tid, ownerPid, creatorPid, frame.InstructionPointerRaw,
                                                   observedUtc, evidenceKind, frame.Module, frame.Symbol, score);
                        frameCount += 1;
                        if (frameCount >= maxFramesPerSnapshot)
                        {
                            break;
                        }
                    }
                }
            }

            return index;
        }

        private Dictionary<uint, ThreadLifecycleEventSample> BuildLatestThreadStartMap(DateTime cutoffUtc,
                                                                                       uint targetPid)
        {
            var latestByTid = new Dictionary<uint, ThreadLifecycleEventSample>();
            foreach (ThreadLifecycleEventSample sample in _threadLifecycleHistory)
            {
                if (sample.TimestampUtc > cutoffUtc || sample.ThreadId == 0 ||
                    !IsThreadLifecycleForTarget(sample, targetPid))
                {
                    continue;
                }

                if (sample.EventKind.Equals("Exit", StringComparison.OrdinalIgnoreCase))
                {
                    latestByTid.Remove(sample.ThreadId);
                    continue;
                }

                if (sample.StartAddress == 0)
                {
                    continue;
                }

                latestByTid[sample.ThreadId] = sample;
            }

            return latestByTid;
        }

        private static bool IsThreadLifecycleForTarget(ThreadLifecycleEventSample sample, uint targetPid)
        {
            return targetPid == 0 || sample.ProcessPid == 0 || sample.ProcessPid == targetPid;
        }

        private static IEnumerable<ThreadStackSessionSnapshot>
        SelectThreadStackSnapshots(ThreadStackHistoryArchiveEntry history, DateTime cutoffUtc, int maxSnapshots)
        {
            int emitted = 0;
            for (int i = history.Snapshots.Count - 1; i >= 0 && emitted < maxSnapshots; i -= 1)
            {
                ThreadStackSessionSnapshot snapshot = history.Snapshots[i];
                if (snapshot.CapturedAtUtc > cutoffUtc)
                {
                    continue;
                }

                emitted += 1;
                yield return snapshot;
            }
        }

        private static void AddThreadExecutionEvidence(ThreadExecutionHeuristicIndex index, uint threadId,
                                                       uint ownerPid, uint creatorPid, ulong address,
                                                       DateTime observedUtc, string evidenceKind, string module,
                                                       string symbol, int score)
        {
            if (threadId == 0 || address == 0)
            {
                return;
            }

            index.Add(new ThreadExecutionMemoryHeuristic { ThreadId = threadId, OwnerPid = ownerPid,
                                                           CreatorPid = creatorPid, Address = address,
                                                           ObservedUtc = observedUtc, EvidenceKind = evidenceKind,
                                                           Module = module, Symbol = symbol, Score = score });
        }

        private void RebuildMemoryInspectorRowsFromAttributions(DateTime cutoffUtc)
        {
            var latestByBase = new Dictionary<ulong, MemoryRegionAttributionSample>();
            for (int i = 0; i < _memoryRegionAttributionHistory.Count; i += 1)
            {
                MemoryRegionAttributionSample sample = _memoryRegionAttributionHistory[i];
                ulong key = sample.AllocationBase != 0 ? sample.AllocationBase : sample.BaseAddress;
                if (key == 0)
                {
                    continue;
                }

                if (!latestByBase.TryGetValue(key, out MemoryRegionAttributionSample? existing) ||
                    sample.TimestampUtc > existing.TimestampUtc)
                {
                    latestByBase[key] = sample;
                }
            }

            var pages = latestByBase.Values.Select(ToSyntheticMemoryPage)
                            .Where(static page => page.BaseAddress != 0 && page.RegionSize != 0)
                            .ToList();

            if (pages.Count == 0)
            {
                MemoryInspectorRows.Clear();
                return;
            }

            RebuildMemoryInspectorRows(pages, cutoffUtc);
        }

        private static MemoryPageSample ToSyntheticMemoryPage(MemoryRegionAttributionSample sample)
        {
            uint protect = sample.CurrentProtection != 0 ? sample.CurrentProtection : sample.InitialProtection;
            string regionKind = string.IsNullOrWhiteSpace(sample.RegionKind) ? "Observed" : sample.RegionKind;
            uint type = regionKind.Equals("Image", StringComparison.OrdinalIgnoreCase)    ? 0x1000000u
                        : regionKind.Equals("Mapped", StringComparison.OrdinalIgnoreCase) ? 0x40000u
                                                                                          : 0x20000u;

            return new MemoryPageSample {
                BaseAddress = sample.BaseAddress != 0 ? sample.BaseAddress : sample.AllocationBase,
                AllocationBase = sample.AllocationBase != 0 ? sample.AllocationBase : sample.BaseAddress,
                RegionSize = sample.RegionSize == 0 ? 1UL : sample.RegionSize,
                State = 0x1000,
                Protect = protect,
                AllocationProtect = protect,
                Type = type,
                StateLabel = "MEM_COMMIT",
                ProtectLabel = protect == 0 ? "Observed" : EventDetailFormatting.DescribeMemoryProtection(protect),
                TypeLabel = type == 0x1000000u ? "MEM_IMAGE"
                            : type == 0x40000u ? "MEM_MAPPED"
                                               : "MEM_PRIVATE",
                Category = regionKind,
                SpecialUse = sample.EventKind,
                BackingPath = sample.OriginPath,
                ModulePath = sample.OriginPath,
                Sr71Owned = sample.BlackbirdOwned,
                Sr71OwnerTag = sample.BlackbirdOwned ? "BK Instrumentation" : string.Empty,
                SnapshotOffset = 0,
                SnapshotBytes = null
            };
        }

        private static string BuildModuleKey(ModuleInfoRow module)
        {
            string path = (module.Path ?? string.Empty).Trim();
            if (!string.IsNullOrWhiteSpace(path))
            {
                return path;
            }

            return $"{module.Name}|{module.BaseAddress}";
        }

        private void ApplyMemoryInspectorRows(IReadOnlyList<MemoryInspectorRow> rows)
        {
            if (ShouldBulkReplaceMemoryInspectorRows(rows))
            {
                MemoryInspectorRows.ReplaceAll(rows);
                return;
            }

            var desiredKeys = new HashSet<(ulong BaseAddress, ulong RegionSize)>(
                rows.Select(static row => (row.BaseAddressValue, row.RegionSizeBytes)));

            for (int i = MemoryInspectorRows.Count - 1; i >= 0; i -= 1)
            {
                MemoryInspectorRow existing = MemoryInspectorRows[i];
                if (!desiredKeys.Contains((existing.BaseAddressValue, existing.RegionSizeBytes)))
                {
                    MemoryInspectorRows.RemoveAt(i);
                }
            }

            var existingByKey =
                MemoryInspectorRows.ToDictionary(static row => (row.BaseAddressValue, row.RegionSizeBytes));

            for (int i = 0; i < rows.Count; i += 1)
            {
                MemoryInspectorRow incoming = rows[i];
                (ulong, ulong) key = (incoming.BaseAddressValue, incoming.RegionSizeBytes);
                if (existingByKey.TryGetValue(key, out MemoryInspectorRow? existing))
                {
                    existing.UpdateFrom(incoming);
                    int currentIndex = MemoryInspectorRows.IndexOf(existing);
                    if (currentIndex >= 0 && currentIndex != i)
                    {
                        MemoryInspectorRows.Move(currentIndex, i);
                    }
                    continue;
                }

                MemoryInspectorRows.Insert(i, incoming);
                existingByKey[key] = incoming;
            }

            while (MemoryInspectorRows.Count > rows.Count)
            {
                MemoryInspectorRows.RemoveAt(MemoryInspectorRows.Count - 1);
            }
        }

        private void RebuildThreadLifecycleRows(DateTime cutoffUtc)
        {
            ThreadLifecycleRows.Clear();
            IEnumerable<ThreadLifecycleEventSample> rows =
                _threadLifecycleHistory.Where(x => x.TimestampUtc <= cutoffUtc)
                    .OrderByDescending(x => x.TimestampUtc)
                    .Take(256);
            foreach (ThreadLifecycleEventSample row in rows)
            {
                ThreadLifecycleRows.Add(new ThreadLifecycleRow(row));
            }
        }

        private MemoryRegionAttributionSample? FindLatestMemoryRegionAttribution(MemoryPageSample page,
                                                                                 MemoryAttributionLookup lookup)
        {
            if (_pid <= 0 || page.BaseAddress == 0 || page.RegionSize == 0 || lookup.IsEmpty)
            {
                return null;
            }

            MemoryRegionAttributionSample? latestLifecycle = null;
            foreach (MemoryRegionAttributionSample candidate in lookup.FindOverlaps(page.BaseAddress, page.RegionSize))
            {
                ulong candidateBase = candidate.BaseAddress != 0 ? candidate.BaseAddress : candidate.AllocationBase;
                ulong candidateSize = candidate.RegionSize;
                if (!MemoryRegionsOverlap(page.BaseAddress, page.RegionSize, candidateBase, candidateSize))
                {
                    continue;
                }

                if (latestLifecycle == null)
                {
                    latestLifecycle = candidate;
                }

                if (IsPrimaryMemoryAttributionEvent(candidate))
                {
                    return candidate;
                }
            }

            return latestLifecycle;
        }

        private sealed class MemoryAttributionLookup
        {
            private const int BucketShift = 16;
            private const int MaxBucketsPerRegion = 4096;
            private readonly Dictionary<ulong, List<MemoryRegionAttributionSample>> _byBucket = new();
            private readonly List<MemoryRegionAttributionSample> _largeRegions = new();

            public bool IsEmpty => _byBucket.Count == 0 && _largeRegions.Count == 0;

            public void Add(MemoryRegionAttributionSample sample, ulong baseAddress, ulong size)
            {
                ulong start = baseAddress >> BucketShift;
                ulong endAddress = baseAddress + size - 1;
                if (endAddress < baseAddress)
                {
                    endAddress = ulong.MaxValue;
                }

                ulong end = endAddress >> BucketShift;
                ulong bucketCount = end >= start ? (end - start + 1) : 1;
                if (bucketCount > MaxBucketsPerRegion)
                {
                    _largeRegions.Add(sample);
                    return;
                }

                for (ulong bucket = start; bucket <= end; bucket += 1)
                {
                    AddToBucket(bucket, sample);
                    if (bucket == ulong.MaxValue)
                    {
                        break;
                    }
                }
            }

            public IEnumerable<MemoryRegionAttributionSample> FindOverlaps(ulong baseAddress, ulong size)
            {
                ulong start = baseAddress >> BucketShift;
                ulong endAddress = baseAddress + size - 1;
                if (endAddress < baseAddress)
                {
                    endAddress = ulong.MaxValue;
                }

                ulong end = endAddress >> BucketShift;
                var seen = new HashSet<MemoryRegionAttributionSample>();
                for (int i = 0; i < _largeRegions.Count; i += 1)
                {
                    if (seen.Add(_largeRegions[i]))
                    {
                        yield return _largeRegions[i];
                    }
                }

                ulong bucketCount = end >= start ? (end - start + 1) : 1;
                if (bucketCount > MaxBucketsPerRegion)
                {
                    foreach (List<MemoryRegionAttributionSample> bucketSamples in _byBucket.Values)
                    {
                        for (int i = 0; i < bucketSamples.Count; i += 1)
                        {
                            if (seen.Add(bucketSamples[i]))
                            {
                                yield return bucketSamples[i];
                            }
                        }
                    }

                    yield break;
                }

                for (ulong bucket = start; bucket <= end; bucket += 1)
                {
                    if (_byBucket.TryGetValue(bucket, out List<MemoryRegionAttributionSample>? samples))
                    {
                        for (int i = 0; i < samples.Count; i += 1)
                        {
                            if (seen.Add(samples[i]))
                            {
                                yield return samples[i];
                            }
                        }
                    }

                    if (bucket == ulong.MaxValue)
                    {
                        break;
                    }
                }
            }

            private void AddToBucket(ulong bucket, MemoryRegionAttributionSample sample)
            {
                if (!_byBucket.TryGetValue(bucket, out List<MemoryRegionAttributionSample>? samples))
                {
                    samples = new List<MemoryRegionAttributionSample>(2);
                    _byBucket[bucket] = samples;
                }

                samples.Add(sample);
            }
        }

        private sealed class ThreadExecutionMemoryHeuristic
        {
            public uint ThreadId { get; init; }
            public uint OwnerPid { get; init; }
            public uint CreatorPid { get; init; }
            public ulong Address { get; init; }
            public DateTime ObservedUtc { get; init; }
            public string EvidenceKind { get; init; } = string.Empty;
            public string Module { get; init; } = string.Empty;
            public string Symbol { get; init; } = string.Empty;
            public int Score { get; init; }
        }

        private sealed class ThreadExecutionHeuristicIndex
        {
            private const int BucketShift = 16;
            private const int MaxBucketsPerQuery = 4096;
            private readonly Dictionary<ulong, List<ThreadExecutionMemoryHeuristic>> _byBucket = new();
            private readonly List<ThreadExecutionMemoryHeuristic> _all = new();

            public void Add(ThreadExecutionMemoryHeuristic evidence)
            {
                _all.Add(evidence);
                ulong bucket = evidence.Address >> BucketShift;
                if (!_byBucket.TryGetValue(bucket, out List<ThreadExecutionMemoryHeuristic>? entries))
                {
                    entries = new List<ThreadExecutionMemoryHeuristic>(2);
                    _byBucket[bucket] = entries;
                }

                entries.Add(evidence);
            }

            public ThreadExecutionMemoryHeuristic? FindBest(ulong baseAddress, ulong size)
            {
                if (baseAddress == 0 || size == 0 || _all.Count == 0)
                {
                    return null;
                }

                ulong start = baseAddress >> BucketShift;
                ulong endAddress = baseAddress + size - 1;
                if (endAddress < baseAddress)
                {
                    endAddress = ulong.MaxValue;
                }

                ulong end = endAddress >> BucketShift;
                ulong bucketCount = end >= start ? end - start + 1 : 1;
                ThreadExecutionMemoryHeuristic? best = null;
                if (bucketCount > MaxBucketsPerQuery)
                {
                    foreach (ThreadExecutionMemoryHeuristic candidate in _all)
                    {
                        if (ContainsAddress(baseAddress, size, candidate.Address))
                        {
                            best = SelectBetter(best, candidate);
                        }
                    }

                    return best;
                }

                for (ulong bucket = start; bucket <= end; bucket += 1)
                {
                    if (_byBucket.TryGetValue(bucket, out List<ThreadExecutionMemoryHeuristic>? entries))
                    {
                        foreach (ThreadExecutionMemoryHeuristic candidate in entries)
                        {
                            if (ContainsAddress(baseAddress, size, candidate.Address))
                            {
                                best = SelectBetter(best, candidate);
                            }
                        }
                    }

                    if (bucket == ulong.MaxValue)
                    {
                        break;
                    }
                }

                return best;
            }

            private static ThreadExecutionMemoryHeuristic SelectBetter(ThreadExecutionMemoryHeuristic? current,
                                                                       ThreadExecutionMemoryHeuristic candidate)
            {
                if (current == null)
                {
                    return candidate;
                }

                if (candidate.Score != current.Score)
                {
                    return candidate.Score > current.Score ? candidate : current;
                }

                if (candidate.ObservedUtc != current.ObservedUtc)
                {
                    return candidate.ObservedUtc > current.ObservedUtc ? candidate : current;
                }

                return candidate.ThreadId < current.ThreadId ? candidate : current;
            }
        }

        private bool ShouldBulkReplaceMemoryInspectorRows(IReadOnlyList<MemoryInspectorRow> rows)
        {
            if (MemoryInspectorRows.Count == 0 || rows.Count == 0)
            {
                return true;
            }

            int commonPrefix = 0;
            int limit = Math.Min(MemoryInspectorRows.Count, rows.Count);
            while (commonPrefix < limit &&
                   MemoryInspectorRows[commonPrefix].BaseAddressValue == rows[commonPrefix].BaseAddressValue &&
                   MemoryInspectorRows[commonPrefix].RegionSizeBytes == rows[commonPrefix].RegionSizeBytes)
            {
                commonPrefix += 1;
            }

            int changedShape = Math.Max(MemoryInspectorRows.Count, rows.Count) - commonPrefix;
            return changedShape > 128;
        }

        private static bool MemoryRegionsOverlap(ulong leftBase, ulong leftSize, ulong rightBase, ulong rightSize)
        {
            if (leftBase == 0 || rightBase == 0 || leftSize == 0 || rightSize == 0)
            {
                return false;
            }

            ulong leftEnd = leftBase + leftSize;
            ulong rightEnd = rightBase + rightSize;
            if (leftEnd <= leftBase)
            {
                leftEnd = ulong.MaxValue;
            }
            if (rightEnd <= rightBase)
            {
                rightEnd = ulong.MaxValue;
            }

            return leftBase < rightEnd && rightBase < leftEnd;
        }

        private static bool ContainsAddress(ulong baseAddress, ulong size, ulong address)
        {
            if (baseAddress == 0 || size == 0 || address == 0)
            {
                return false;
            }

            ulong endAddress = baseAddress + size;
            if (endAddress <= baseAddress)
            {
                return address >= baseAddress;
            }

            return address >= baseAddress && address < endAddress;
        }

        private static bool ShouldUseThreadExecutionHeuristic(MemoryPageSample page)
        {
            if (page.BaseAddress == 0 || page.RegionSize == 0)
            {
                return false;
            }

            bool isPrivate = (page.Type & 0x00020000u) != 0;
            bool executable = IsExecutableProtect(page.Protect);
            bool hasBacking =
                !string.IsNullOrWhiteSpace(page.ModulePath) || !string.IsNullOrWhiteSpace(page.BackingPath);
            return isPrivate || executable || !hasBacking;
        }

        private static string DescribeAllocator(MemoryRegionAttributionSample? attribution,
                                                ThreadExecutionMemoryHeuristic? threadHeuristic = null)
        {
            if (attribution == null)
            {
                return threadHeuristic == null ? string.Empty : DescribeThreadExecutionAllocator(threadHeuristic);
            }

            string actor = ProcessIdentityResolver.Describe(attribution.ActorPid);
            string label =
                !string.IsNullOrWhiteSpace(attribution.EventKind)
                    ? attribution.EventKind.Trim()
                    : (!string.IsNullOrWhiteSpace(attribution.ApiName) ? attribution.ApiName.Trim() : "allocation");
            string allocator = $"{actor} via {label}";
            return threadHeuristic == null ? allocator
                                           : $"{allocator}; {DescribeThreadExecutionRunSummary(threadHeuristic)}";
        }

        private static string DescribeAllocatorSource(MemoryRegionAttributionSample? attribution)
        {
            if (attribution == null)
            {
                return string.Empty;
            }

            if (!string.IsNullOrWhiteSpace(attribution.OriginPath))
            {
                return EventDetailFormatting.ModuleNameFromPath(attribution.OriginPath);
            }

            if (!string.IsNullOrWhiteSpace(attribution.FirstUserFrameModule))
            {
                string module = EventDetailFormatting.ModuleNameFromPath(attribution.FirstUserFrameModule);
                if (EventDetailFormatting.IsBlackbirdInternalModule(module) && !attribution.BlackbirdOwned)
                {
                    return string.IsNullOrWhiteSpace(attribution.CallerOrigin) ? string.Empty
                                                                               : attribution.CallerOrigin;
                }

                return DescribeCallsiteOwnership(attribution.FirstUserFrameModule, attribution.OriginPath);
            }

            if (!string.IsNullOrWhiteSpace(attribution.CallerOrigin))
            {
                return attribution.CallerOrigin;
            }

            return string.Empty;
        }

        private static string DescribeThreadExecutionAllocator(ThreadExecutionMemoryHeuristic heuristic)
        {
            string label = $"TID {heuristic.ThreadId} {heuristic.EvidenceKind} (heuristic)";
            if (heuristic.OwnerPid != 0)
            {
                label += $"; owner {ProcessIdentityResolver.Describe(heuristic.OwnerPid)}";
            }
            if (heuristic.CreatorPid != 0 && heuristic.CreatorPid != heuristic.OwnerPid)
            {
                label += $"; creator {ProcessIdentityResolver.Describe(heuristic.CreatorPid)}";
            }

            return label;
        }

        private static string DescribeThreadExecutionRunSummary(ThreadExecutionMemoryHeuristic heuristic)
        {
            string label = $"ran TID {heuristic.ThreadId} {heuristic.EvidenceKind} (heuristic)";
            return heuristic.OwnerPid == 0 ? label
                                           : $"{label}; owner {ProcessIdentityResolver.Describe(heuristic.OwnerPid)}";
        }

        private static string DescribeThreadExecutionSource(ThreadExecutionMemoryHeuristic? heuristic)
        {
            if (heuristic == null)
            {
                return string.Empty;
            }

            if (!string.IsNullOrWhiteSpace(heuristic.Module))
            {
                string module = EventDetailFormatting.ModuleNameFromPath(heuristic.Module);
                return string.IsNullOrWhiteSpace(module) ? heuristic.Module.Trim() : module;
            }

            if (!string.IsNullOrWhiteSpace(heuristic.Symbol))
            {
                return heuristic.Symbol.Trim();
            }

            return "thread execution";
        }

        private static string DescribeThreadExecutionContext(ThreadExecutionMemoryHeuristic heuristic)
        {
            string context = $"Thread execution heuristic: {heuristic.EvidenceKind} @ 0x{heuristic.Address:X}";
            string callsite = DescribeThreadExecutionCallsite(heuristic);
            return string.IsNullOrWhiteSpace(callsite) ? context : $"{context} | {callsite}";
        }

        private static string DescribeThreadExecutionLifecycle(ThreadExecutionMemoryHeuristic heuristic)
        {
            string observed =
                heuristic.ObservedUtc == default ? "observed" : $"observed {heuristic.ObservedUtc:HH:mm:ss}";
            return $"{observed}; not a proven allocator";
        }

        private static string DescribeThreadExecutionCallsite(ThreadExecutionMemoryHeuristic heuristic)
        {
            string module = EventDetailFormatting.ModuleNameFromPath(heuristic.Module);
            if (!string.IsNullOrWhiteSpace(heuristic.Symbol))
            {
                return string.IsNullOrWhiteSpace(module) ? heuristic.Symbol.Trim()
                                                         : $"{module}!{heuristic.Symbol.Trim()}";
            }

            return string.IsNullOrWhiteSpace(module) ? string.Empty : module;
        }

        private static string DescribeResolvedMemorySource(MemoryPageSample page,
                                                           MemoryRegionAttributionSample? attribution,
                                                           ThreadExecutionMemoryHeuristic? threadHeuristic = null)
        {
            if (IsSr71OwnedMemoryPage(page, attribution))
            {
                string tag = Sr71OwnerLabel(page, attribution);
                return string.IsNullOrWhiteSpace(tag) ? "SR71.dll" : tag;
            }

            string modulePath = !string.IsNullOrWhiteSpace(page.ModulePath) ? page.ModulePath : page.BackingPath;
            if (!string.IsNullOrWhiteSpace(modulePath))
            {
                string fileName = Path.GetFileName(modulePath);
                return string.IsNullOrWhiteSpace(fileName) ? modulePath : fileName;
            }

            string allocatorSource = DescribeAllocatorSource(attribution);
            return string.IsNullOrWhiteSpace(allocatorSource) ? DescribeThreadExecutionSource(threadHeuristic)
                                                              : allocatorSource;
        }

        private static string DescribeAllocatorTrust(MemoryRegionAttributionSample? attribution)
        {
            if (attribution == null)
            {
                return "Unknown";
            }

            if (attribution.SignatureLevel != 0 || attribution.SignatureType != 0)
            {
                return "Signed";
            }

            if (attribution.UnwindClean)
            {
                return "Runtime-Clean";
            }

            if (!string.IsNullOrWhiteSpace(attribution.OriginPath))
            {
                return "Unsigned";
            }

            if (string.Equals(attribution.CallerOrigin, "system", StringComparison.OrdinalIgnoreCase))
            {
                return "System";
            }

            return "Unknown";
        }

        private static string DescribeResolvedMemoryTrust(MemoryPageSample page,
                                                          MemoryRegionAttributionSample? attribution,
                                                          ThreadExecutionMemoryHeuristic? threadHeuristic = null)
        {
            if (IsSr71OwnedMemoryPage(page, attribution))
            {
                return "SR71-Owned";
            }

            string trust = DescribeAllocatorTrust(attribution);
            if (!trust.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            {
                return trust;
            }

            if (!string.IsNullOrWhiteSpace(page.ModulePath) || LooksLikeImagePath(page.BackingPath))
            {
                return page.WorkingSetValid && !page.WorkingSetShared ? "Image-Private" : "Image";
            }

            if (!string.IsNullOrWhiteSpace(page.BackingPath))
            {
                return page.WorkingSetValid && !page.WorkingSetShared ? "Mapped-Private" : "Mapped";
            }

            if (threadHeuristic != null)
            {
                return "Heuristic";
            }

            return trust;
        }

        private static string DescribeResolvedMemoryContext(MemoryPageSample page,
                                                            MemoryRegionAttributionSample? attribution,
                                                            ThreadExecutionMemoryHeuristic? threadHeuristic = null)
        {
            if (IsSr71OwnedMemoryPage(page, attribution))
            {
                string tag = Sr71OwnerLabel(page, attribution);
                return string.IsNullOrWhiteSpace(tag) ? "BK Instrumentation" : tag;
            }

            if (attribution != null)
            {
                string context = attribution.ExecutionContext;
                if (string.IsNullOrWhiteSpace(context))
                {
                    context = attribution.CrossProcess                            ? "Cross-Process Runtime"
                              : attribution.ImageBacked                           ? "Loader / Image Mapping"
                              : string.IsNullOrWhiteSpace(attribution.RegionKind) ? string.Empty
                                                                                  : attribution.RegionKind;
                }

                string ownership = string.Empty;
                string firstFrameModule = EventDetailFormatting.ModuleNameFromPath(attribution.FirstUserFrameModule);
                if (!EventDetailFormatting.IsBlackbirdInternalModule(firstFrameModule))
                {
                    ownership = DescribeCallsiteOwnership(attribution.FirstUserFrameModule, attribution.OriginPath);
                }
                if (!string.IsNullOrWhiteSpace(ownership))
                {
                    context = string.IsNullOrWhiteSpace(context) ? ownership : $"{ownership} | {context}";
                }

                if (attribution.ObservedByKernel && attribution.ObservedByUserHook)
                {
                    context = $"{context} [kernel+user]".Trim();
                }
                else if (attribution.ObservedByKernel)
                {
                    context = $"{context} [kernel]".Trim();
                }
                else if (attribution.ObservedByUserHook)
                {
                    context = $"{context} [user]".Trim();
                }

                if (threadHeuristic != null)
                {
                    context = string.IsNullOrWhiteSpace(context)
                                  ? DescribeThreadExecutionContext(threadHeuristic)
                                  : $"{context} | {DescribeThreadExecutionContext(threadHeuristic)}";
                }

                return context;
            }

            if (threadHeuristic != null)
            {
                return DescribeThreadExecutionContext(threadHeuristic);
            }

            if (!string.IsNullOrWhiteSpace(page.ModulePath) || LooksLikeImagePath(page.BackingPath))
            {
                return page.WorkingSetValid && !page.WorkingSetShared ? "Image private copy" : "Image";
            }
            if (!string.IsNullOrWhiteSpace(page.BackingPath))
            {
                return page.WorkingSetValid && !page.WorkingSetShared ? "Mapped private copy" : "Mapped";
            }
            return "Private/Unknown";
        }

        private static string DescribeResolvedMemoryLifecycle(MemoryRegionAttributionSample? attribution,
                                                              ThreadExecutionMemoryHeuristic? threadHeuristic = null)
        {
            if (attribution == null)
            {
                return threadHeuristic == null ? string.Empty : DescribeThreadExecutionLifecycle(threadHeuristic);
            }

            string raw = string.IsNullOrWhiteSpace(attribution.LifecycleSummary) ? attribution.EventKind
                                                                                 : attribution.LifecycleSummary;
            string lifecycle = NormalizeLifecycleSummary(raw);
            if (threadHeuristic == null)
            {
                return lifecycle;
            }

            string heuristicLifecycle = DescribeThreadExecutionLifecycle(threadHeuristic);
            return string.IsNullOrWhiteSpace(lifecycle) ? heuristicLifecycle : $"{lifecycle}; {heuristicLifecycle}";
        }

        private static string NormalizeLifecycleSummary(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            string text = value.Trim();
            text = text.Replace("map:", "maps: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("alloc:", "allocs: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("protect:", "protects: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("rapid-pflip:", "rapid protection flips: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("pflip:", "protection flips: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("xflip:", "executable flips: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("wxflip:", "WX flips: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("rapid-eflip:", "rapid entropy flips: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("eflip:", "entropy flips: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("Hmax:", "max entropy: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("high-H:", "high entropy writes: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("first exec", "first executable", StringComparison.OrdinalIgnoreCase)
                       .Replace("rx", "RX", StringComparison.OrdinalIgnoreCase)
                       .Replace("rwx", "RWX", StringComparison.OrdinalIgnoreCase);

            return text switch { "PrivateAllocate" => "allocated private memory", "SectionMap" => "mapped section",
                                 "ImageMap" => "mapped image", "ProtectChange" => "protection changed",
                                 _ => text };
        }

        private static string DescribeMemoryStateForInspector(MemoryPageSample page)
        {
            return page.State switch {
                0x1000 => "Committed",
                0x2000 => "Reserved",
                0x10000 => "Free", _ when!string.IsNullOrWhiteSpace(page.StateLabel) => page.StateLabel.Trim(),
                _ => "Unclassified"
            };
        }

        private static string DescribeMemoryTypeForInspector(MemoryPageSample page)
        {
            string type = page.Type switch {
                0x20000 => "Private",
                0x40000 => "Mapped",
                0x1000000 => "Image", _ when!string.IsNullOrWhiteSpace(page.TypeLabel) => page.TypeLabel.Trim(),
                _ => "Unclassified"
            };

            if (page.WorkingSetValid && !page.WorkingSetShared && (page.Type == 0x40000 || page.Type == 0x1000000))
            {
                return $"{type} private copy";
            }

            return type;
        }

        private static bool IsPrimaryMemoryAttributionEvent(MemoryRegionAttributionSample sample)
        {
            return sample.EventKind.Equals("PrivateAllocate", StringComparison.OrdinalIgnoreCase) ||
                   sample.EventKind.Equals("SectionMap", StringComparison.OrdinalIgnoreCase) ||
                   sample.EventKind.Equals("ImageMap", StringComparison.OrdinalIgnoreCase) ||
                   sample.EventKind.Equals("ProtectChange", StringComparison.OrdinalIgnoreCase);
        }

        private static string DescribeResolvedMemoryCategory(MemoryPageSample page)
        {
            if (IsSr71OwnedMemoryPage(page, null))
            {
                return LooksLikeSr71ImagePath(page.ModulePath) || LooksLikeSr71ImagePath(page.BackingPath)
                           ? "SR71 Instrumentation"
                           : "BK Instrumentation";
            }

            if (string.IsNullOrWhiteSpace(page.Category))
            {
                return string.Empty;
            }

            if (!string.IsNullOrWhiteSpace(page.ModulePath) || LooksLikeImagePath(page.BackingPath))
            {
                if (page.Category.StartsWith("Mapped", StringComparison.OrdinalIgnoreCase))
                {
                    return "Image" + page.Category["Mapped".Length..];
                }

                if (page.Category.StartsWith("Unknown", StringComparison.OrdinalIgnoreCase))
                {
                    return "Image" + page.Category["Unknown".Length..];
                }
            }

            return page.Category;
        }

        private static bool IsSr71OwnedMemoryPage(MemoryPageSample page, MemoryRegionAttributionSample? attribution)
        {
            return page.Sr71Owned || attribution?.BlackbirdOwned == true || LooksLikeSr71ImagePath(page.ModulePath) ||
                   LooksLikeSr71ImagePath(page.BackingPath) || StartsWithBlackbirdInstrumentation(page.SpecialUse) ||
                   StartsWithBlackbirdInstrumentation(page.Sr71OwnerTag);
        }

        private static string Sr71OwnerLabel(MemoryPageSample page, MemoryRegionAttributionSample? attribution)
        {
            if (!string.IsNullOrWhiteSpace(page.Sr71OwnerTag))
            {
                return page.Sr71OwnerTag.Trim();
            }
            if (!string.IsNullOrWhiteSpace(page.SpecialUse) && StartsWithBlackbirdInstrumentation(page.SpecialUse))
            {
                return page.SpecialUse.Trim();
            }
            if (attribution?.BlackbirdOwned == true && !string.IsNullOrWhiteSpace(attribution.EventKind))
            {
                return attribution.EventKind.Trim();
            }
            return string.Empty;
        }

        private static bool StartsWithBlackbirdInstrumentation(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            string trimmed = value.Trim();
            return trimmed.StartsWith("SR71", StringComparison.OrdinalIgnoreCase) ||
                   trimmed.StartsWith("BK Instrument", StringComparison.OrdinalIgnoreCase);
        }

        private static bool LooksLikeSr71ImagePath(string? path) =>
            EventDetailFormatting.IsSr71Module(EventDetailFormatting.ModuleNameFromPath(path ?? string.Empty));

        private static string NormalizeDisplayText(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            string trimmed = value.Trim();
            return trimmed is "-" or "N/A" ? string.Empty : trimmed;
        }

        private static string DescribeProtectionAcronym(uint protect)
        {
            uint baseProtect = protect & 0xFFu;
            string label = baseProtect switch {
                0x01 => "NA",
                0x02 => "R",
                0x04 => "RW",
                0x08 => "W+C",
                0x10 => "X",
                0x20 => "RX",
                0x40 => "RWX",
                0x80 => "X+W+C",
                _ => string.Empty
            };

            if ((protect & 0x100u) != 0)
            {
                label = AppendProtectionFlag(label, "G");
            }
            if ((protect & 0x200u) != 0)
            {
                label = AppendProtectionFlag(label, "NC");
            }
            if ((protect & 0x400u) != 0)
            {
                label = AppendProtectionFlag(label, "WC");
            }

            return label;
        }

        private static string AppendProtectionFlag(string current, string suffix)
        {
            if (string.IsNullOrWhiteSpace(current))
            {
                return suffix;
            }

            return $"{current}|{suffix}";
        }

        private static uint ResolveThreadTidForPage(MemoryPageSample page, string category,
                                                    IReadOnlyList<ThreadMemoryRange> threadRanges)
        {
            if (threadRanges.Count == 0 || string.IsNullOrWhiteSpace(category))
            {
                return 0;
            }

            bool wantsStack = category.Contains("Thread Stack", StringComparison.OrdinalIgnoreCase);
            bool wantsTeb = category.Equals("TEB", StringComparison.OrdinalIgnoreCase);
            if (!wantsStack && !wantsTeb)
            {
                return 0;
            }

            ulong pageBase = page.BaseAddress;
            ulong pageEnd = pageBase + page.RegionSize;
            if (pageEnd <= pageBase)
            {
                pageEnd = ulong.MaxValue;
            }

            foreach (ThreadMemoryRange range in threadRanges)
            {
                ulong rangeBase = wantsStack ? range.StackLimit : range.TebAddress;
                ulong rangeSize =
                    wantsStack ? (range.StackBase > range.StackLimit ? range.StackBase - range.StackLimit : 0) : 0x2000;
                if (rangeBase == 0 || rangeSize == 0)
                {
                    continue;
                }

                ulong rangeEnd = rangeBase + rangeSize;
                if (rangeEnd <= rangeBase)
                {
                    rangeEnd = ulong.MaxValue;
                }

                if (pageBase < rangeEnd && rangeBase < pageEnd)
                {
                    return range.Tid;
                }
            }

            return 0;
        }

        private uint ResolveThreadTidForAttribution(MemoryRegionAttributionSample? attribution)
        {
            if (attribution == null)
            {
                return 0;
            }

            if (attribution.ThreadId != 0)
            {
                return attribution.ThreadId;
            }

            uint targetPid = _pid > 0 ? unchecked((uint)_pid) : attribution.TargetPid;
            if (attribution.ActorTid != 0 && (attribution.ActorPid == targetPid ||
                                              (attribution.ActorPid == 0 && attribution.TargetPid == targetPid)))
            {
                return attribution.ActorTid;
            }

            return 0;
        }

        private static List<ThreadMemoryRange> BuildThreadMemoryRanges(int pid)
        {
            const uint processQuery = 0x0400;
            const uint processVmRead = 0x0010;
            const uint processQueryLimited = 0x1000;

            if (pid <= 0)
            {
                return new List<ThreadMemoryRange>();
            }

            try
            {
                using Process process = Process.GetProcessById(pid);
                IntPtr processHandle = Kernel32Native.OpenProcess(processQuery | processVmRead | processQueryLimited,
                                                                  false, unchecked((uint)pid));
                if (processHandle == IntPtr.Zero)
                {
                    return new List<ThreadMemoryRange>();
                }

                var ranges = new List<ThreadMemoryRange>();
                try
                {
                    foreach (ProcessThread thread in process.Threads)
                    {
                        IntPtr threadHandle = OpenThread(ThreadQueryInformation | ThreadQueryLimitedInformation, false,
                                                         unchecked((uint)thread.Id));
                        if (threadHandle == IntPtr.Zero)
                        {
                            continue;
                        }

                        try
                        {
                            if (!TryGetThreadMemoryRange(processHandle, threadHandle, out ulong tebAddress,
                                                         out ulong stackBase, out ulong stackLimit))
                            {
                                continue;
                            }

                            ranges.Add(
                                new ThreadMemoryRange(unchecked((uint)thread.Id), tebAddress, stackBase, stackLimit));
                        }
                        finally
                        {
                            _ = Kernel32Native.CloseHandle(threadHandle);
                        }
                    }
                }
                finally
                {
                    _ = Kernel32Native.CloseHandle(processHandle);
                }

                return ranges;
            }
            catch
            {
                return new List<ThreadMemoryRange>();
            }
        }

        private static bool TryGetThreadMemoryRange(IntPtr processHandle, IntPtr threadHandle, out ulong tebAddress,
                                                    out ulong stackBase, out ulong stackLimit)
        {
            tebAddress = 0;
            stackBase = 0;
            stackLimit = 0;

            int status = NtQueryInformationThread(threadHandle, 0, out THREAD_BASIC_INFORMATION tbi,
                                                  Marshal.SizeOf<THREAD_BASIC_INFORMATION>(), out _);
            if (status != 0 || tbi.TebBaseAddress == IntPtr.Zero)
            {
                return false;
            }

            tebAddress = unchecked((ulong)tbi.TebBaseAddress.ToInt64());
            byte[] tibBuffer = new byte[Marshal.SizeOf<NT_TIB64>()];
            if (!ReadProcessMemory(processHandle, tbi.TebBaseAddress, tibBuffer, tibBuffer.Length,
                                   out IntPtr bytesRead) ||
                bytesRead.ToInt64() < tibBuffer.Length)
            {
                return tebAddress != 0;
            }

            GCHandle handle = GCHandle.Alloc(tibBuffer, GCHandleType.Pinned);
            try
            {
                NT_TIB64 tib = Marshal.PtrToStructure<NT_TIB64>(handle.AddrOfPinnedObject());
                stackBase = tib.StackBase;
                stackLimit = tib.StackLimit;
            }
            finally
            {
                handle.Free();
            }

            return true;
        }

        private static string DetermineMemoryHighlightBand(string category)
        {
            if (string.IsNullOrWhiteSpace(category))
            {
                return string.Empty;
            }

            string normalized = category.Trim();
            if (normalized.StartsWith("SR71", StringComparison.OrdinalIgnoreCase))
            {
                return "Runtime";
            }

            if (normalized.Contains("Thread Stack", StringComparison.OrdinalIgnoreCase))
            {
                return "ThreadStack";
            }

            if (normalized.Equals("Process Heap", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("Heap", StringComparison.OrdinalIgnoreCase) ||
                normalized.EndsWith(" Heap", StringComparison.OrdinalIgnoreCase))
            {
                return "Heap";
            }

            if (normalized.Contains("PEB", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("TEB", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("ApiSet", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("CodePage", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Activation Context", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Assembly Storage", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("GDI", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Shared Data", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("CSR", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Shim", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("AppCompat", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Process Parameters", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Process Heaps Array", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Loader Lock", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Patch Loader", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("CHPEV2", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("WER", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("LEAP_SECOND", StringComparison.OrdinalIgnoreCase))
            {
                return "Anchor";
            }

            if (normalized.Contains("Telemetry", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Image Header Hash", StringComparison.OrdinalIgnoreCase))
            {
                return "Runtime";
            }

            return string.Empty;
        }

        private static string DetermineMemoryHighlightLabel(string category, string highlightBand)
        {
            if (highlightBand.Equals("ThreadStack", StringComparison.OrdinalIgnoreCase))
            {
                return "STACK";
            }

            if (highlightBand.Equals("Heap", StringComparison.OrdinalIgnoreCase))
            {
                return "HEAP";
            }

            if (highlightBand.Equals("Anchor", StringComparison.OrdinalIgnoreCase))
            {
                return "CORE";
            }

            if (highlightBand.Equals("Runtime", StringComparison.OrdinalIgnoreCase))
            {
                return "RUNTIME";
            }

            if (!string.IsNullOrWhiteSpace(category) && category.Contains("Shared", StringComparison.OrdinalIgnoreCase))
            {
                return "SHARED";
            }

            return string.Empty;
        }

        private List<ThreadUsageRow> BuildUnifiedThreadRows(IEnumerable<ThreadUsageSample> topThreads,
                                                            DateTime cutoffUtc)
        {
            var normalizedThreads = topThreads.Take(20).Select(CloneThreadUsage).ToList();
            NormalizeThreadKinds(normalizedThreads);

            var rows =
                normalizedThreads.Take(20).Select(thread => new ThreadUsageRow(thread, _targetSuspended)).ToList();
            var seen = new HashSet<uint>(rows.Select(x => unchecked((uint)x.Tid)));

            Dictionary<uint, ThreadLifecycleEventSample> latestByTid = BuildLatestThreadLifecycleMap(cutoffUtc);
            foreach (ThreadLifecycleEventSample sample in latestByTid.Values.OrderByDescending(x => x.TimestampUtc)
                         .Take(20))
            {
                if (sample.ThreadId == 0 || seen.Contains(sample.ThreadId))
                {
                    continue;
                }

                string state = _targetSuspended                                                       ? "Suspended"
                               : sample.EventKind.Equals("Start", StringComparison.OrdinalIgnoreCase) ? "Started"
                                                                                                      : "Observed";
                string kind =
                    string.IsNullOrWhiteSpace(sample.EventKind) ? "Lifecycle" : $"Lifecycle/{sample.EventKind}";

                rows.Add(new ThreadUsageRow(
                    new ThreadUsageSample { Tid = unchecked((int)sample.ThreadId), CpuMsDelta = 0, State = state,
                                            WaitReason = _targetSuspended ? "Suspended" : string.Empty, Kind = kind,
                                            StartTimeUtc = sample.TimestampUtc, TargetSuspended = _targetSuspended },
                    _targetSuspended));
                seen.Add(sample.ThreadId);
            }

            var sorted = rows.OrderByDescending(x => x.CpuMs)
                             .ThenByDescending(x => x.StartTimeUtc ?? DateTime.MinValue)
                             .ThenBy(x => x.Tid)
                             .Take(24)
                             .ToList();

            int mainIdx = sorted.FindIndex(x => x.ThreadKind == "Main Thread");
            if (mainIdx > 0)
            {
                var main = sorted[mainIdx];
                sorted.RemoveAt(mainIdx);
                sorted.Insert(0, main);
            }

            return sorted;
        }

        private Dictionary<uint, ThreadLifecycleEventSample> BuildLatestThreadLifecycleMap(DateTime cutoffUtc)
        {
            var latestByTid = new Dictionary<uint, ThreadLifecycleEventSample>();
            foreach (ThreadLifecycleEventSample sample in _threadLifecycleHistory)
            {
                if (sample.TimestampUtc > cutoffUtc || sample.ThreadId == 0)
                {
                    continue;
                }

                if (sample.EventKind.Equals("Exit", StringComparison.OrdinalIgnoreCase))
                {
                    latestByTid.Remove(sample.ThreadId);
                    continue;
                }

                latestByTid[sample.ThreadId] = sample;
            }

            return latestByTid;
        }

        private void ApplyUnifiedThreadRows(IReadOnlyList<ThreadUsageRow> rows)
        {
            TopThreads.Clear();
            if (rows.Count == 0)
            {
                CoreUsageRows.Clear();
            }

            foreach (ThreadUsageRow row in rows)
            {
                TopThreads.Add(row);
            }
        }

        private void ApplyCoreUsageRows(IReadOnlyList<CoreUsageSample> cores, int coreCount)
        {
            CoreUsageRows.Clear();
            int count = Math.Max(coreCount, cores.Count);
            if (count <= 0)
            {
                return;
            }

            Dictionary<int, CoreUsageSample> byCore = cores.ToDictionary(x => x.CoreIndex, x => x);
            for (int i = 0; i < count; i += 1)
            {
                byCore.TryGetValue(i, out CoreUsageSample? sample);
                CoreUsageRows.Add(new CoreUsageRow(sample, i));
            }
        }

        private static string DetermineMemoryPriorityBand(MemoryPageSample page, string trust)
        {
            if (page.Sr71Owned)
            {
                return "Image";
            }

            bool isPrivate = (page.Type & 0x00020000u) != 0;
            bool isMapped = (page.Type & 0x00040000u) != 0;
            bool isImage = (page.Type & 0x01000000u) != 0;
            bool hasImageBacking = !string.IsNullOrWhiteSpace(page.ModulePath) || LooksLikeImagePath(page.BackingPath);
            bool isUnsigned = string.Equals(trust, "Unsigned", StringComparison.OrdinalIgnoreCase);
            bool isExecutable = IsExecutableProtect(page.Protect);
            bool isWritable = IsWritableProtect(page.Protect);

            if (isPrivate && isUnsigned)
            {
                return "PrivateUnsigned";
            }
            if (isPrivate && isExecutable && isWritable)
            {
                return "PrivateExecutable";
            }
            if (isPrivate)
            {
                return "Private";
            }
            if (isUnsigned)
            {
                return "Unsigned";
            }
            if (isImage || hasImageBacking)
            {
                return "Image";
            }
            if (isMapped)
            {
                return "Mapped";
            }

            return "Normal";
        }

        private static string DetermineMemoryPriorityBand(MemoryPageSample page, string trust,
                                                          MemoryRegionAttributionSample? attribution)
        {
            if (IsSr71OwnedMemoryPage(page, attribution))
            {
                return "Image";
            }

            if (attribution != null)
            {
                if (attribution.CrossProcess &&
                    (attribution.WriteCount != 0 || attribution.ProtectCount != 0 || attribution.ThreadStartCount != 0))
                {
                    return "PrivateUnsigned";
                }
                if (attribution.FirstExecutableTransition || attribution.ThreadStartCount != 0)
                {
                    return "PrivateExecutable";
                }
                if (attribution.ProtectFlipCount >= 3 || attribution.RapidProtectFlipCount >= 2 ||
                    attribution.GuardNoAccessFlipCount != 0 || attribution.WritableExecutableFlipCount != 0)
                {
                    return "PrivateExecutable";
                }
                if (attribution.HighEntropyWriteCount != 0 || attribution.EntropyFlipCount >= 2)
                {
                    return "Unsigned";
                }
                if (attribution.WriteCount != 0 && attribution.ImageBacked)
                {
                    return "Unsigned";
                }
            }

            return DetermineMemoryPriorityBand(page, trust);
        }

        private static string DetermineMemoryPriorityBand(MemoryPageSample page, string trust,
                                                          MemoryRegionAttributionSample? attribution,
                                                          ThreadExecutionMemoryHeuristic? threadHeuristic)
        {
            string band = DetermineMemoryPriorityBand(page, trust, attribution);
            if (threadHeuristic != null && (band.Equals("Private", StringComparison.OrdinalIgnoreCase) ||
                                            band.Equals("Mapped", StringComparison.OrdinalIgnoreCase) ||
                                            band.Equals("Normal", StringComparison.OrdinalIgnoreCase)))
            {
                return "PrivateExecutable";
            }

            return band;
        }

        private static bool LooksLikeImagePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            string extension = Path.GetExtension(path);
            return extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".mui", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".cpl", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".drv", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsExecutableProtect(uint protect)
        {
            uint baseProtect = protect & 0xFFu;
            return baseProtect == 0x10 || baseProtect == 0x20 || baseProtect == 0x40 || baseProtect == 0x80;
        }

        private static bool IsWritableProtect(uint protect)
        {
            uint baseProtect = protect & 0xFFu;
            return baseProtect == 0x04 || baseProtect == 0x08 || baseProtect == 0x40 || baseProtect == 0x80;
        }

        private static int MemoryPriorityBandRank(string priorityBand)
        {
            return priorityBand switch { "PrivateUnsigned" => 0,
                                         "PrivateExecutable" => 1,
                                         "Private" => 2,
                                         "Unsigned" => 3,
                                         "Image" => 4,
                                         "Mapped" => 5,
                                         _ => 6 };
        }

        private static PerformanceSample CloneSample(PerformanceSample src)
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
                CommitBytes = src.CommitBytes,
                ImageBytes = src.ImageBytes,
                MappedBytes = src.MappedBytes,
                PrivateVadBytes = src.PrivateVadBytes,
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

        private static string DescribeCallsiteOwnership(string? moduleName, string? originPath)
        {
            string module = !string.IsNullOrWhiteSpace(moduleName)
                                ? moduleName.Trim()
                                : EventDetailFormatting.ModuleNameFromPath(originPath ?? string.Empty);
            if (string.IsNullOrWhiteSpace(module))
            {
                return string.Empty;
            }

            string lowered = module.ToLowerInvariant();
            if (lowered is "ucrtbase.dll" or "msvcrt.dll" or "vcruntime140.dll" or "vcruntime140_1.dll" or
                           "concrt140.dll")
            {
                return "CRT/Runtime";
            }

            if (lowered is "ntdll.dll" or "kernel32.dll" or "kernelbase.dll" or "rpcrt4.dll" or "user32.dll" or
                           "gdi32.dll" or "advapi32.dll")
            {
                return "Windows OS";
            }

            if (lowered.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                return "Process Code";
            }

            return module;
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

        private void MemoryInspectorGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (MemoryInspectorGrid.SelectedItem is not MemoryInspectorRow row)
                return;

            if (row.ThreadTid != 0)
            {
                OpenThreadStackFromMemoryRow(row);
                return;
            }

            if (BkdcNative.IsAvailable && row.BaseAddressValue != 0 && row.RegionSizeBytes != 0 &&
                row.Protect.Contains('X', StringComparison.OrdinalIgnoreCase))
            {
                DisassemblyRequested?.Invoke(
                    this, new MemoryDisassemblyRequestedEventArgs(unchecked((uint)_pid), row.BaseAddressValue,
                                                                  row.RegionSizeBytes, $"{row.Category}  {row.Protect}",
                                                                  row.SnapshotBytes, row.SnapshotOffset));
            }
        }

        private void MemoryContextOpenStack_Click(object sender, RoutedEventArgs e)
        {
            if (MemoryInspectorGrid.SelectedItem is MemoryInspectorRow row)
            {
                OpenThreadStackFromMemoryRow(row);
            }
        }

        private void MemoryContextOpenDisassembly_Click(object sender, RoutedEventArgs e)
        {
            if (MemoryInspectorGrid.SelectedItem is not MemoryInspectorRow row || !BkdcNative.IsAvailable ||
                row.BaseAddressValue == 0 || row.RegionSizeBytes == 0)
            {
                return;
            }

            DisassemblyRequested?.Invoke(
                this, new MemoryDisassemblyRequestedEventArgs(unchecked((uint)_pid), row.BaseAddressValue,
                                                              row.RegionSizeBytes, $"{row.Category}  {row.Protect}",
                                                              row.SnapshotBytes, row.SnapshotOffset));
        }

        private void MemoryContextCopyBase_Click(object sender, RoutedEventArgs e)
        {
            if (MemoryInspectorGrid.SelectedItem is MemoryInspectorRow row &&
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

        private void RefreshProcessDetails()
        {
            int targetPid = _pid > 0 ? _pid : Environment.ProcessId;
            _ = Kernel32Native.EnableDebugPrivilege(out _);
            try
            {
                using var process = Process.GetProcessById(targetPid);

                RefreshModules(process);
                RefreshPeInfo(process);
                if (_historySamples.Count == 0 || _lastSample == null)
                {
                    RefreshThreadSnapshot(process);
                    RefreshMemoryMetrics(process);
                }
                RefreshNetworkPeers(targetPid);
                _processLiveDataAvailable = true;
                DiagnosticsState.SetValue("Target Handle Access", $"Direct inspection ready pid={targetPid}");
            }
            catch (Exception ex)
            {
                if (_historySamples.Count == 0)
                {
                    TopThreads.Clear();
                    CoreUsageRows.Clear();
                    ThreadLifecycleRows.Clear();
                    MemoryMetrics.Clear();
                    MemoryInspectorRows.Clear();
                }
                NetworkPeers.Clear();
                UpdateMemoryTreemap();
                _processLiveDataAvailable = false;
                DiagnosticsState.SetValue("Target Handle Access",
                                          $"Direct inspection failed pid={targetPid}: {ex.GetType().Name}");
            }

            UpdateLiveDataOverlays();
        }

        private void RefreshThreadSnapshot(Process process)
        {
            var rows = new List<ThreadUsageSample>();
            try
            {
                foreach (ProcessThread thread in process.Threads)
                {
                    string state = thread.ThreadState.ToString();
                    string waitReason = string.Empty;
                    if (thread.ThreadState == System.Diagnostics.ThreadState.Wait)
                    {
                        try
                        {
                            waitReason = thread.WaitReason.ToString();
                        }
                        catch
                        {
                            waitReason = string.Empty;
                        }
                    }

                    DateTime? startTime = null;
                    try
                    {
                        startTime = thread.StartTime.ToUniversalTime();
                    }
                    catch
                    {
                        startTime = null;
                    }

                    rows.Add(new ThreadUsageSample { Tid = thread.Id, CpuMsDelta = 0, State = state,
                                                     WaitReason = waitReason, Kind = InferThreadKind(state, waitReason),
                                                     StartTimeUtc = startTime, TargetSuspended = _targetSuspended });
                }
            }
            catch
            {
            }

            ApplyUnifiedThreadRows(BuildUnifiedThreadRows(
                rows.OrderByDescending(x => x.StartTimeUtc ?? DateTime.MinValue).Take(20), DateTime.UtcNow));
        }

        private static void NormalizeThreadKinds(List<ThreadUsageSample> threads)
        {
            if (threads.Count == 0)
            {
                return;
            }

            ThreadUsageSample? mainThread = threads.Where(static thread => thread.StartTimeUtc.HasValue)
                                                .OrderBy(static thread => thread.StartTimeUtc!.Value)
                                                .ThenBy(static thread => thread.Tid)
                                                .FirstOrDefault();

            if (mainThread != null)
            {
                mainThread.Kind = "Main Thread";
            }

            for (int i = 0; i < threads.Count; i += 1)
            {
                ThreadUsageSample thread = threads[i];
                if (ReferenceEquals(thread, mainThread))
                {
                    continue;
                }

                thread.Kind = InferThreadKind(thread.State, thread.WaitReason);
            }
        }

        private static string InferThreadKind(string state, string waitReason)
        {
            if (!string.IsNullOrWhiteSpace(waitReason))
            {
                if (waitReason.Equals("ExecutionDelay", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("WrQueue", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("WrLpcReceive", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("WrLpcReply", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("WrExecutive", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("WrUserRequest", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("WrKernel", StringComparison.OrdinalIgnoreCase))
                {
                    return "OS-Managed";
                }

                if (waitReason.Equals("Suspended", StringComparison.OrdinalIgnoreCase) ||
                    waitReason.Equals("UserRequest", StringComparison.OrdinalIgnoreCase))
                {
                    return "User Thread";
                }
            }

            if (state.Equals("Wait", StringComparison.OrdinalIgnoreCase) ||
                state.Equals("Transition", StringComparison.OrdinalIgnoreCase))
            {
                return "OS-Managed";
            }

            return "User Thread";
        }

        private void RefreshModules(Process process)
        {
            var rows = new List<ModuleInfoRow>();
            try
            {
                foreach (ProcessModule module in process.Modules)
                {
                    string role = ResolveModuleRole(module.FileName);
                    rows.Add(new ModuleInfoRow { Name = module.ModuleName,
                                                 BaseAddress = $"0x{module.BaseAddress.ToInt64():X}",
                                                 Size = FormatBytes(module.ModuleMemorySize), Path = module.FileName,
                                                 Role = role });
                }
            }
            catch (Exception ex)
            {
                DiagnosticsState.SetValue("Target Modules", $"Process.Modules failed: {ex.GetType().Name}");
            }

            Modules.Clear();
            foreach (var row in rows.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).Take(1024))
                Modules.Add(row);
            if (rows.Count > 0)
            {
                DiagnosticsState.SetValue("Target Modules", $"Loaded {rows.Count} modules");
            }
        }

        private string ResolveModuleRole(string? path)
        {
            if (!string.IsNullOrWhiteSpace(_analysisSubjectPath) &&
                string.Equals(path, _analysisSubjectPath, StringComparison.OrdinalIgnoreCase))
            {
                return "Subject";
            }

            if (!string.IsNullOrWhiteSpace(_analysisHostPath) &&
                string.Equals(path, _analysisHostPath, StringComparison.OrdinalIgnoreCase))
            {
                return "Host";
            }

            return string.Empty;
        }

        private void RefreshPeInfo(Process process)
        {
            var rows = new List<PeInfoRow>();

            rows.Add(new PeInfoRow("PID", process.Id.ToString()));
            rows.Add(new PeInfoRow("Process Name", process.ProcessName));
            try
            {
                rows.Add(new PeInfoRow("Start Time",
                                       process.StartTime.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'")));
            }
            catch
            {
            }
            try
            {
                rows.Add(new PeInfoRow("Priority Class", process.PriorityClass.ToString()));
            }
            catch
            {
            }

            string? imagePath = null;
            try
            {
                imagePath = process.MainModule?.FileName;
            }
            catch
            {
            }
            if (!string.IsNullOrWhiteSpace(imagePath))
            {
                rows.Add(new PeInfoRow("Image Path", imagePath));

                if (TryReadPeInfo(imagePath, out var pe))
                {
                    rows.Add(new PeInfoRow("PE Machine", pe.Machine));
                    rows.Add(new PeInfoRow("PE Type", pe.IsPePlus ? "PE32+" : "PE32"));
                    rows.Add(new PeInfoRow("Image Base", pe.ImageBase));
                    rows.Add(new PeInfoRow("Subsystem", pe.Subsystem));
                    rows.Add(new PeInfoRow("DLL Characteristics", pe.DllCharacteristics));
                }
            }

            if (TryGetMitigationFlags(process, out var mitigations))
            {
                foreach (var m in mitigations)
                    rows.Add(new PeInfoRow(m.Field, m.Value));
            }

            PeInfo.Clear();
            foreach (var row in rows)
                PeInfo.Add(row);
        }

        private static bool TryReadPeInfo(string path, out PeSummary pe)
        {
            pe = default;
            try
            {
                using var fs =
                    new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var br = new BinaryReader(fs);
                if (br.ReadUInt16() != 0x5A4D)
                    return false;

                fs.Position = 0x3C;
                int peOffset = br.ReadInt32();
                if (peOffset <= 0 || peOffset > fs.Length - 0x100)
                    return false;

                fs.Position = peOffset;
                if (br.ReadUInt32() != 0x00004550)
                    return false;

                ushort machine = br.ReadUInt16();
                _ = br.ReadUInt16();
                _ = br.ReadUInt32();
                _ = br.ReadUInt32();
                _ = br.ReadUInt32();
                ushort sizeOfOptionalHeader = br.ReadUInt16();
                _ = br.ReadUInt16();

                long optStart = fs.Position;
                ushort magic = br.ReadUInt16();
                bool isPePlus = magic == 0x20B;
                if (!isPePlus && magic != 0x10B)
                    return false;

                ushort subsystem;
                ushort dllChars;
                string imageBase;
                if (isPePlus)
                {
                    fs.Position = optStart + 0x18;
                    ulong imageBase64 = br.ReadUInt64();
                    fs.Position = optStart + 0x44;
                    subsystem = br.ReadUInt16();
                    dllChars = br.ReadUInt16();
                    imageBase = $"0x{imageBase64:X}";
                }
                else
                {
                    fs.Position = optStart + 0x1C;
                    uint imageBase32 = br.ReadUInt32();
                    fs.Position = optStart + 0x44;
                    subsystem = br.ReadUInt16();
                    dllChars = br.ReadUInt16();
                    imageBase = $"0x{imageBase32:X}";
                }

                pe =
                    new PeSummary { Machine = MachineToString(machine), IsPePlus = isPePlus, ImageBase = imageBase,
                                    Subsystem = SubsystemToString(subsystem), DllCharacteristics = $"0x{dllChars:X4}" };
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool TryGetMitigationFlags(Process process, out List<PeInfoRow> rows)
        {
            rows = new List<PeInfoRow>();
            try
            {
                if (GetProcessMitigationPolicy(process.Handle, ProcessMitigationPolicy.DepPolicy,
                                               out PROCESS_MITIGATION_DEP_POLICY dep,
                                               Marshal.SizeOf<PROCESS_MITIGATION_DEP_POLICY>()))
                {
                    rows.Add(new PeInfoRow("Mitigation DEP", (dep.Flags & 0x1) != 0 ? "Enabled" : "Disabled"));
                }

                if (GetProcessMitigationPolicy(process.Handle, ProcessMitigationPolicy.AslrPolicy,
                                               out PROCESS_MITIGATION_ASLR_POLICY aslr,
                                               Marshal.SizeOf<PROCESS_MITIGATION_ASLR_POLICY>()))
                {
                    rows.Add(new PeInfoRow("Mitigation ASLR", (aslr.Flags & 0x7) != 0 ? "Enabled" : "Disabled"));
                }

                if (GetProcessMitigationPolicy(process.Handle, ProcessMitigationPolicy.ControlFlowGuardPolicy,
                                               out PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg,
                                               Marshal.SizeOf<PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY>()))
                {
                    rows.Add(new PeInfoRow("Mitigation CFG", (cfg.Flags & 0x1) != 0 ? "Enabled" : "Disabled"));
                }

                if (GetProcessMitigationPolicy(process.Handle, ProcessMitigationPolicy.DynamicCodePolicy,
                                               out PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dyn,
                                               Marshal.SizeOf<PROCESS_MITIGATION_DYNAMIC_CODE_POLICY>()))
                {
                    rows.Add(
                        new PeInfoRow("Mitigation DynamicCode", (dyn.Flags & 0x1) != 0 ? "Prohibited" : "Allowed"));
                }

                return rows.Count > 0;
            }
            catch
            {
                return false;
            }
        }

        private static string MachineToString(ushort machine)
        {
            return machine switch {
                0x014C => "x86",
                0x8664 => "x64",
                0xAA64 => "ARM64",
                _ => $"0x{machine:X4}"
            };
        }

        private static string SubsystemToString(ushort subsystem)
        {
            return subsystem switch {
                2 => "Windows GUI",
                3 => "Windows CUI",
                _ => subsystem.ToString()
            };
        }

        private void RefreshMemoryMetrics(Process process)
        {
            var rows = new List<MemoryMetricRow> {
                new() { Metric = "Working Set", Value = FormatBytes(process.WorkingSet64),
                        BytesValue = process.WorkingSet64 },
                new() { Metric = "Peak Working Set", Value = FormatBytes(process.PeakWorkingSet64),
                        BytesValue = process.PeakWorkingSet64 },
                new() { Metric = "Private Bytes", Value = FormatBytes(process.PrivateMemorySize64),
                        BytesValue = process.PrivateMemorySize64 },
                new() { Metric = "Virtual Bytes", Value = FormatBytes(process.VirtualMemorySize64), BytesValue = null },
                new() { Metric = "Paged Memory", Value = FormatBytes(process.PagedMemorySize64),
                        BytesValue = process.PagedMemorySize64 },
                new() { Metric = "Nonpaged System Memory", Value = FormatBytes(process.NonpagedSystemMemorySize64),
                        BytesValue = process.NonpagedSystemMemorySize64 },
                new() { Metric = "Paged System Memory", Value = FormatBytes(process.PagedSystemMemorySize64),
                        BytesValue = process.PagedSystemMemorySize64 },
                new() { Metric = "Handle Count", Value = process.HandleCount.ToString(), BytesValue = null },
                new() { Metric = "Thread Count", Value = process.Threads.Count.ToString(), BytesValue = null }
            };

            MemoryMetrics.Clear();
            foreach (var row in rows)
                MemoryMetrics.Add(row);

            try
            {
                List<MemoryPageSample> pages = CaptureLiveMemoryPages(process);
                RebuildMemoryInspectorRows(pages, DateTime.UtcNow);
            }
            catch
            {
                MemoryInspectorRows.Clear();
            }

            UpdateMemoryTreemap();
            UpdateLiveDataOverlays();
        }

        private void RefreshNetworkPeers(int targetPid)
        {
            List<NetworkPeerRow> rows = ReadNetworkPeers(targetPid);
            /* Preserve hook-driven rows that have bytes/source already filled in;
               merge netstat data so we don't lose them on each refresh tick. */
            var existingByKey = new Dictionary<string, NetworkPeerRow>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in NetworkPeers)
            {
                if (!string.IsNullOrEmpty(r.RemoteAddress))
                    existingByKey[$"{r.Protocol}|{r.RemoteEndpoint}"] = r;
            }

            NetworkPeers.Clear();
            _networkPeerByKey.Clear();
            foreach (NetworkPeerRow row in rows)
            {
                string key = $"{row.Protocol}|{row.RemoteEndpoint}";
                if (existingByKey.TryGetValue(key, out var existing))
                {
                    row.BytesSent = existing.BytesSent;
                    row.BytesRecv = existing.BytesRecv;
                    row.FirstSeen = existing.FirstSeen;
                    row.LastSeen = existing.LastSeen;
                    row.Source = existing.Source;
                    if (string.IsNullOrEmpty(row.DnsName) || row.DnsName == "-")
                        row.DnsName = existing.DnsName;
                }
                NetworkPeers.Add(row);
                _networkPeerByKey[key] = row;
            }
        }

        internal void IngestNetworkEvent(BlackbirdNative.BkIpcEtwEvent ev)
        {
            var view = new BrokerEtwEventView { Family = ev.Family,
                                                Source = ev.Source == BlackbirdNative.IpcEtwSourceKernelNetwork
                                                             ? "KernelNetwork"
                                                             : "UserHook",
                                                SourceId = ev.Source,
                                                Reason = BlackbirdNative.WideBufferToString(ev.Reason),
                                                Operation = BlackbirdNative.AnsiBufferToString(ev.Operation),
                                                ActorPid = ev.EventProcessId };
            IngestNetworkView(view);
        }

        internal void IngestNetworkView(BrokerEtwEventView view)
        {
            if (Dispatcher.CheckAccess())
            {
                IngestNetworkEventOnUiThread(view);
            }
            else
            {
                Dispatcher.InvokeAsync(() => IngestNetworkEventOnUiThread(view));
            }
        }

        private static (string ip, int port, string hostname, long bytes, bool isSend, bool isConnect)
            ParseNetworkReason(string reason)
        {
            string ip = "", hostname = "";
            int port = 0;
            long bytes = 0;
            bool isSend = false, isConnect = false;

            if (string.IsNullOrEmpty(reason))
                return (ip, port, hostname, bytes, isSend, isConnect);

            if (reason.Contains("socket.connect") || reason.Contains("kernel.net op=CONNECT") ||
                reason.Contains("KERNEL_NETWORK_CONNECT"))
                isConnect = true;

            if (reason.Contains("api=WSASend") || reason.Contains("api=send") || reason.Contains("kernel.net op=SEND"))
                isSend = true;

            foreach (string token in reason.Split(' '))
            {
                if (token.StartsWith("ip=", StringComparison.OrdinalIgnoreCase))
                    ip = token.Substring(3);
                else if (token.StartsWith("dst=", StringComparison.OrdinalIgnoreCase))
                {
                    string dstPart = token.Substring(4);
                    int colon = dstPart.LastIndexOf(':');
                    if (colon >= 0)
                    {
                        ip = dstPart.Substring(0, colon);
                        int.TryParse(dstPart.Substring(colon + 1), out port);
                    }
                }
                else if (token.StartsWith("port=", StringComparison.OrdinalIgnoreCase))
                    int.TryParse(token.Substring(5), out port);
                else if (token.StartsWith("hostname=", StringComparison.OrdinalIgnoreCase))
                    hostname = token.Substring(9);
                else if (token.StartsWith("bytes=", StringComparison.OrdinalIgnoreCase))
                    long.TryParse(token.Substring(6), out bytes);
            }

            return (ip, port, hostname, bytes, isSend, isConnect);
        }

        private void IngestNetworkEventOnUiThread(BrokerEtwEventView? ev)
        {
            if (ev == null)
                return;
            string reason = ev.Reason ?? string.Empty;
            var (ip, port, hostname, bytes, isSend, isConnect) = ParseNetworkReason(reason);

            if (string.IsNullOrEmpty(ip))
                return;

            string remoteEndpoint = port > 0 ? $"{ip}:{port}" : ip;
            string op = ev.Operation ?? string.Empty;
            string protocol = reason.Contains("UDP") || op == "SEND_UDP" || op == "RECV_UDP" ? "UDP" : "TCP";
            string sourceLabel = ev.SourceId == BlackbirdNative.IpcEtwSourceKernelNetwork ? "kernel" : "hook";
            string key = $"{protocol}|{remoteEndpoint}";

            if (_networkPeerByKey.Count != NetworkPeers.Count)
            {
                RebuildNetworkPeerIndex();
            }

            if (_networkPeerByKey.TryGetValue(key, out NetworkPeerRow? row))
            {
                row.ConnectionCount++;
                row.LastSeen = DateTime.UtcNow;
                if (isSend)
                    row.BytesSent += bytes;
                else if (!isConnect)
                    row.BytesRecv += bytes;
                if (string.IsNullOrEmpty(row.DnsName) || row.DnsName == "-")
                {
                    if (!string.IsNullOrEmpty(hostname))
                        row.DnsName = hostname;
                    else
                        row.DnsName = ResolveDnsName(ip);
                }
                return;
            }

            /* New endpoint */
            string dnsName = !string.IsNullOrEmpty(hostname) ? hostname : ResolveDnsName(ip);
            var newRow = new NetworkPeerRow { RemoteEndpoint = remoteEndpoint,
                                              RemoteAddress = ip,
                                              DnsName = dnsName,
                                              Protocol = protocol,
                                              State = isConnect ? "CONNECTED" : "ACTIVE",
                                              ConnectionCount = 1,
                                              BytesSent = isSend ? bytes : 0,
                                              BytesRecv = (!isConnect && !isSend) ? bytes : 0,
                                              FirstSeen = DateTime.UtcNow,
                                              LastSeen = DateTime.UtcNow,
                                              Source = sourceLabel };

            if (NetworkPeers.Count >= 512)
            {
                NetworkPeerRow removed = NetworkPeers[0];
                _networkPeerByKey.Remove($"{removed.Protocol}|{removed.RemoteEndpoint}");
                NetworkPeers.RemoveAt(0);
            }

            NetworkPeers.Add(newRow);
            _networkPeerByKey[key] = newRow;
        }

        private void RebuildNetworkPeerIndex()
        {
            _networkPeerByKey.Clear();
            foreach (NetworkPeerRow row in NetworkPeers)
            {
                if (!string.IsNullOrWhiteSpace(row.Protocol) && !string.IsNullOrWhiteSpace(row.RemoteEndpoint))
                {
                    _networkPeerByKey[$"{row.Protocol}|{row.RemoteEndpoint}"] = row;
                }
            }
        }

        private List<NetworkPeerRow> ReadNetworkPeers(int targetPid)
        {
            var rows = new Dictionary<string, NetworkPeerRow>(StringComparer.OrdinalIgnoreCase);
            try
            {
                var psi = new ProcessStartInfo { FileName = "netstat",          Arguments = "-ano",
                                                 UseShellExecute = false,       RedirectStandardOutput = true,
                                                 RedirectStandardError = false, CreateNoWindow = true };

                using Process? process = Process.Start(psi);
                if (process == null)
                {
                    return new List<NetworkPeerRow>();
                }

                string ? line;
                while ((line = process.StandardOutput.ReadLine()) != null)
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }

                    string trimmed = line.Trim();
                    if (!trimmed.StartsWith("TCP", StringComparison.OrdinalIgnoreCase) &&
                        !trimmed.StartsWith("UDP", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    string[] tokens = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (tokens.Length < 4)
                    {
                        continue;
                    }

                    string protocol = tokens[0].ToUpperInvariant();
                    string remoteEndpoint = tokens[2];
                    string state = protocol == "TCP" && tokens.Length >= 5 ? tokens[3] : "N/A";
                    string pidToken = protocol == "TCP" && tokens.Length >= 5 ? tokens[^1] : tokens[3];
                    if (!int.TryParse(pidToken, out int pid) || pid != targetPid)
                    {
                        continue;
                    }

                    string remoteAddress = ExtractAddress(remoteEndpoint);
                    if (remoteAddress.Length == 0 || remoteAddress == "*" || remoteAddress == "0.0.0.0" ||
                        remoteAddress == "::")
                    {
                        continue;
                    }

                    string key = $"{protocol}|{remoteAddress}|{state}";
                    if (!rows.TryGetValue(key, out NetworkPeerRow? row))
                    {
                        row = new NetworkPeerRow { LocalEndpoint = tokens[1],
                                                   RemoteEndpoint = remoteEndpoint,
                                                   RemoteAddress = remoteAddress,
                                                   Protocol = protocol,
                                                   State = state,
                                                   DnsName = ResolveDnsName(remoteAddress, allowBlocking: true),
                                                   ConnectionCount = 1 };
                        rows[key] = row;
                    }
                    else
                    {
                        row.ConnectionCount += 1;
                    }
                }
            }
            catch
            {
                return new List<NetworkPeerRow>();
            }

            return rows.Values.OrderByDescending(x => x.ConnectionCount)
                .ThenBy(x => x.RemoteAddress, StringComparer.OrdinalIgnoreCase)
                .Take(128)
                .ToList();
        }

        private string ResolveDnsName(string remoteAddress, bool allowBlocking = false)
        {
            if (_reverseDnsCache.TryGetValue(remoteAddress, out string? cached))
            {
                return cached;
            }

            if (!IPAddress.TryParse(remoteAddress, out IPAddress? ip) ||
                IPAddress.IsLoopback(ip))
            {
                _reverseDnsCache[remoteAddress] = "-";
                return "-";
            }

            if (!allowBlocking)
            {
                QueueReverseDnsLookup(remoteAddress);
                return "-";
            }

            string host = "-";
            try
            {
                var lookup = System.Threading.Tasks.Task.Run(() => Dns.GetHostEntry(remoteAddress));
                _ = lookup.ContinueWith(static task =>
                                        { _ = task.Exception; },
                                        System.Threading.Tasks.TaskContinuationOptions.OnlyOnFaulted);
                if (lookup.Wait(120) && lookup.Result != null)
                {
                    host = string.IsNullOrWhiteSpace(lookup.Result.HostName) ? remoteAddress : lookup.Result.HostName;
                }
            }
            catch
            {
                host = "-";
            }

            _reverseDnsCache[remoteAddress] = host;
            return host;
        }

        private void QueueReverseDnsLookup(string remoteAddress)
        {
            if (!_pendingReverseDnsLookups.Add(remoteAddress))
            {
                return;
            }

            _ = System.Threading.Tasks.Task.Run(
                () =>
                {
                    string host = "-";
                    try
                    {
                        IPHostEntry entry = Dns.GetHostEntry(remoteAddress);
                        host = string.IsNullOrWhiteSpace(entry.HostName) ? remoteAddress : entry.HostName;
                    }
                    catch
                    {
                        host = "-";
                    }

                    Dispatcher.BeginInvoke(
                        new Action(() =>
                                   {
                                       _pendingReverseDnsLookups.Remove(remoteAddress);
                                       _reverseDnsCache[remoteAddress] = host;
                                       bool changed = false;
                                       foreach (NetworkPeerRow row in NetworkPeers)
                                       {
                                           if (string.Equals(row.RemoteAddress, remoteAddress,
                                                             StringComparison.OrdinalIgnoreCase) &&
                                               (string.IsNullOrEmpty(row.DnsName) || row.DnsName == "-"))
                                           {
                                               row.DnsName = host;
                                               changed = true;
                                           }
                                       }

                                       if (changed)
                                       {
                                           NetworkPeersGrid?.Items.Refresh();
                                       }
                                   }));
                });
        }

        private static string ExtractAddress(string endpoint)
        {
            if (string.IsNullOrWhiteSpace(endpoint))
            {
                return string.Empty;
            }

            string value = endpoint.Trim();
            if (value.StartsWith("[", StringComparison.Ordinal))
            {
                int close = value.IndexOf(']');
                if (close > 1)
                {
                    return value[1..close];
                }
            }

            int lastColon = value.LastIndexOf(':');
            if (lastColon > 0)
            {
                return value[..lastColon];
            }

            return value;
        }

        private void UpdateLiveDataOverlays()
        {
            string threadMessage = "No thread data in the selected range.";
            string memoryMessage = "No memory data in the selected range.";
            bool historicalDataVisible = HasHistoricalDataForObservedTime();

            if (!_processLiveDataAvailable)
            {
                if (_historySamples.Count == 0)
                {
                    threadMessage = "Live capture unavailable.";
                    memoryMessage = "Live capture unavailable.";
                }
                else if (!historicalDataVisible)
                {
                    threadMessage = "No captured thread data at the selected time.";
                    memoryMessage = "No captured memory data at the selected time.";
                }
                else
                {
                    threadMessage = "Live capture unavailable.";
                    memoryMessage = "Live capture unavailable.";
                }
            }

            if (ThreadsNoDataOverlay != null)
            {
                bool hasThreadData =
                    TopThreads.Count > 0 || ThreadLifecycleRows.Count > 0 || _threadLifecycleHistory.Count > 0;
                bool showThreadsNoData = !hasThreadData;
                ThreadsNoDataOverlay.Visibility = showThreadsNoData ? Visibility.Visible : Visibility.Collapsed;
                if (ThreadsNoDataMessageBlock != null)
                {
                    ThreadsNoDataMessageBlock.Text = threadMessage;
                }
            }

            if (MemoryNoDataOverlay != null)
            {
                bool hasMemoryData = MemoryInspectorRows.Count > 0 || MemoryMetrics.Count > 0 ||
                                     (_lastSample?.MemoryPages.Count ?? 0) > 0;
                bool showMemoryNoData = !hasMemoryData;
                MemoryNoDataOverlay.Visibility = showMemoryNoData ? Visibility.Visible : Visibility.Collapsed;
                if (MemoryTreemapNoData != null && showMemoryNoData)
                {
                    MemoryTreemapNoData.Visibility = Visibility.Collapsed;
                }
                if (MemoryNoDataMessageBlock != null)
                {
                    MemoryNoDataMessageBlock.Text = memoryMessage;
                }
            }

            if (NetworkNoDataOverlay != null)
            {
                bool hasTrafficData =
                    _historySamples.Any(sample => sample.NetInBytesPerSec > 0.01 || sample.NetOutBytesPerSec > 0.01 ||
                                                  sample.NetPacketsPerSec > 0.01);
                bool hasPeerData = NetworkPeers.Count > 0;
                bool showNetworkNoData = _showNetworkPeers ? !hasPeerData : !hasTrafficData;
                NetworkNoDataOverlay.Visibility = showNetworkNoData ? Visibility.Visible : Visibility.Collapsed;
            }
        }

        private static MemoryMetricRow CloneMetric(MemoryMetricRow src)
        {
            return new MemoryMetricRow { Metric = src.Metric, Value = src.Value, BytesValue = src.BytesValue };
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes >= 1024L * 1024 * 1024)
                return $"{bytes / (1024d * 1024 * 1024):0.##} GB";
            if (bytes >= 1024L * 1024)
                return $"{bytes / (1024d * 1024):0.##} MB";
            if (bytes >= 1024)
                return $"{bytes / 1024d:0.##} KB";
            return $"{bytes} B";
        }

        private static List<MemoryPageSample> CaptureLiveMemoryPages(Process process)
        {
            const uint memCommit = 0x1000;
            const uint processQuery = 0x0400;
            const uint processVmRead = 0x0010;
            const uint processQueryLimited = 0x1000;

            IntPtr hProcess = Kernel32Native.OpenProcess(processQuery | processVmRead | processQueryLimited, false,
                                                         unchecked((uint)process.Id));
            if (hProcess == IntPtr.Zero)
            {
                return new List<MemoryPageSample>();
            }

            var pages = new List<MemoryPageSample>(768);
            List<MemoryModuleMapEntry> modules = CaptureModuleMap(process);
            try
            {
                ulong address = 0;
                ulong maxAddress = Environment.Is64BitProcess ? 0x00007FFF_FFFFFFFFul : uint.MaxValue;
                nuint mbiSize = (nuint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
                var mappedPathCache = new Dictionary<ulong, string>();

                while (address < maxAddress && pages.Count < 1536)
                {
                    nuint ret = VirtualQueryEx(hProcess, (nint)address, out MEMORY_BASIC_INFORMATION mbi, mbiSize);
                    if (ret == 0)
                        break;

                    ulong regionSize = (ulong)mbi.RegionSize;
                    if (regionSize == 0)
                        break;

                    if (mbi.State == memCommit)
                    {
                        ulong baseAddress = (ulong)mbi.BaseAddress;
                        ulong allocationBase = (ulong)mbi.AllocationBase;
                        pages.Add(new MemoryPageSample {
                            BaseAddress = baseAddress, AllocationBase = allocationBase, RegionSize = regionSize,
                            State = mbi.State, Protect = mbi.Protect, AllocationProtect = mbi.AllocationProtect,
                            Type = mbi.Type, StateLabel = EventDetailFormatting.DescribeMemoryState(mbi.State),
                            ProtectLabel = EventDetailFormatting.DescribeMemoryProtection(mbi.Protect),
                            TypeLabel = EventDetailFormatting.DescribeMemoryType(mbi.Type),
                            BackingPath =
                                ResolveMappedBackingPath(hProcess, baseAddress, allocationBase, mappedPathCache),
                            ModulePath = ResolveMappedModulePath(modules, baseAddress, allocationBase, regionSize)
                        });
                        pages[^1].Sr71Owned = LooksLikeSr71ImagePath(pages[^1].ModulePath) ||
                                              LooksLikeSr71ImagePath(pages[^1].BackingPath);
                        if (pages[^1].Sr71Owned)
                        {
                            pages[^1].Sr71OwnerTag = "SR71 Instrumentation";
                        }
                        ApplyWorkingSetAttributes(hProcess, pages[^1]);
                        pages[^1].Category = BuildMemoryCategory(pages[^1]);
                    }

                    ulong next = (ulong)mbi.BaseAddress + regionSize;
                    if (next <= address)
                        break;

                    address = next;
                }
            }
            finally
            {
                _ = Kernel32Native.CloseHandle(hProcess);
            }

            return pages.OrderByDescending(x => x.RegionSize).ThenBy(x => x.BaseAddress).Take(768).ToList();
        }

        private static List<MemoryModuleMapEntry> CaptureModuleMap(Process process)
        {
            var rows = new List<MemoryModuleMapEntry>(128);
            try
            {
                foreach (ProcessModule module in process.Modules)
                {
                    ulong baseAddress = unchecked((ulong)module.BaseAddress.ToInt64());
                    ulong size = (ulong)Math.Max(module.ModuleMemorySize, 0);
                    if (baseAddress == 0 || size == 0)
                    {
                        continue;
                    }

                    rows.Add(new MemoryModuleMapEntry(baseAddress, baseAddress + size,
                                                      module.ModuleName ?? string.Empty,
                                                      module.FileName ?? string.Empty));
                }
            }
            catch
            {
            }

            rows.Sort((left, right) => left.BaseAddress.CompareTo(right.BaseAddress));
            return rows;
        }

        private static string ResolveMappedModulePath(IReadOnlyList<MemoryModuleMapEntry> modules, ulong baseAddress,
                                                      ulong allocationBase, ulong regionSize)
        {
            ulong regionEnd = baseAddress + regionSize;
            if (regionEnd <= baseAddress)
            {
                regionEnd = ulong.MaxValue;
            }

            for (int i = 0; i < modules.Count; i += 1)
            {
                MemoryModuleMapEntry module = modules[i];
                if ((allocationBase != 0 && allocationBase == module.BaseAddress) ||
                    (baseAddress >= module.BaseAddress && baseAddress < module.EndAddress) ||
                    (module.BaseAddress >= baseAddress && module.BaseAddress < regionEnd))
                {
                    return module.Path;
                }
            }

            return string.Empty;
        }

        private static string ResolveMappedBackingPath(IntPtr processHandle, ulong baseAddress, ulong allocationBase,
                                                       Dictionary<ulong, string> cache)
        {
            ulong key = allocationBase != 0 ? allocationBase : baseAddress;
            if (key == 0)
            {
                return string.Empty;
            }

            if (cache.TryGetValue(key, out string? existing))
            {
                return existing;
            }

            string mappedPath = QueryMappedFilename(processHandle, key);
            cache[key] = mappedPath;
            return mappedPath;
        }

        private static string QueryMappedFilename(IntPtr processHandle, ulong address)
        {
            const int memoryMappedFilenameInformation = 2;
            const int bufferBytes = 32768;

            if (processHandle == IntPtr.Zero || address == 0)
            {
                return string.Empty;
            }

            IntPtr buffer = Marshal.AllocHGlobal(bufferBytes);
            try
            {
                int status =
                    NtQueryVirtualMemory(processHandle, unchecked((nint)address), memoryMappedFilenameInformation,
                                         buffer, (uint)bufferBytes, out uint _);
                if (status < 0)
                {
                    return string.Empty;
                }

                UNICODE_STRING text = Marshal.PtrToStructure<UNICODE_STRING>(buffer);
                if (text.Buffer == IntPtr.Zero || text.Length == 0)
                {
                    return string.Empty;
                }

                return Marshal.PtrToStringUni(text.Buffer, text.Length / 2) ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string BuildMemoryCategory(MemoryPageSample page)
        {
            string specialUse = TryClassifySpecialUse(page);
            if (!string.IsNullOrWhiteSpace(specialUse))
            {
                return specialUse;
            }
            if (IsSr71OwnedMemoryPage(page, null))
            {
                return LooksLikeSr71ImagePath(page.ModulePath) || LooksLikeSr71ImagePath(page.BackingPath)
                           ? "SR71 Instrumentation"
                           : "BK Instrumentation";
            }

            uint baseProtect = page.Protect & 0xFFu;
            bool executable = baseProtect == 0x10 || baseProtect == 0x20 || baseProtect == 0x40 || baseProtect == 0x80;
            bool writable = baseProtect == 0x04 || baseProtect == 0x08 || baseProtect == 0x40 || baseProtect == 0x80;

            string typeLabel = page.Type switch {
                0x20000 => "Private",
                0x40000 => "Mapped",
                0x1000000 => "Image",
                _ => "Unknown"
            };

            if (page.WorkingSetValid && !page.WorkingSetShared && (page.Type == 0x40000 || page.Type == 0x1000000))
            {
                typeLabel += " Private Copy";
            }

            if (executable && writable)
                return $"{typeLabel} RWX";
            if (executable)
                return $"{typeLabel} RX";
            if (writable)
                return $"{typeLabel} RW";
            return typeLabel;
        }

        private static string TryClassifySpecialUse(MemoryPageSample page)
        {
            string path = $"{page.ModulePath}|{page.BackingPath}".ToLowerInvariant();
            bool privateWritable = page.Type == 0x20000 && IsWritableProtect(page.Protect);
            bool guard = (page.Protect & 0x100u) != 0;
            if (path.Contains("apiset"))
            {
                return "ApiSetMap";
            }
            if (path.Contains("apphelp") || path.Contains(".sdb") || path.Contains("shim"))
            {
                return "Shim Data";
            }
            if (path.Contains("winsxs") || path.Contains("activation") || path.Contains("actctx"))
            {
                return "Activation Context Data";
            }
            if (path.Contains("\\nls\\") || path.Contains("codepage"))
            {
                return "CodePage Data";
            }
            if (path.Contains("csr"))
            {
                return "CSRSS ReadOnly Shared Memory";
            }
            if (path.Contains("gdi"))
            {
                return "GDI Shared Handle Table";
            }
            if (path.Contains("wer"))
            {
                return "WER Registration Data";
            }
            if (path.Contains("telemetry"))
            {
                return "Telemetry Coverage";
            }
            if (guard && privateWritable)
            {
                return "Thread Stack Guard";
            }
            if (privateWritable && page.RegionSize >= 0x20000 && page.RegionSize <= 0x800000)
            {
                return "Heap";
            }

            return string.Empty;
        }

        private static void ApplyWorkingSetAttributes(IntPtr processHandle, MemoryPageSample page)
        {
            if (processHandle == IntPtr.Zero || page.BaseAddress == 0)
            {
                return;
            }

            var entries =
                new[] { new PSAPI_WORKING_SET_EX_INFORMATION { VirtualAddress = unchecked((IntPtr)page.BaseAddress) } };

            int size = Marshal.SizeOf<PSAPI_WORKING_SET_EX_INFORMATION>();
            if (!QueryWorkingSetEx(processHandle, entries, size))
            {
                return;
            }

            ulong flags = entries[0].VirtualAttributes.ToUInt64();
            page.WorkingSetValid = (flags & 0x1UL) != 0;
            page.WorkingSetShareCount = (uint)((flags >> 1) & 0x7UL);
            page.WorkingSetShared = ((flags >> 15) & 0x1UL) != 0;
            page.WorkingSetLocked = ((flags >> 22) & 0x1UL) != 0;
            page.WorkingSetLargePage = ((flags >> 23) & 0x1UL) != 0;
        }

        private static void AppendVadMetrics(Process process, List<MemoryMetricRow> rows)
        {
            const uint memCommit = 0x1000;
            const uint memPrivate = 0x20000;
            const uint memMapped = 0x40000;
            const uint memImage = 0x1000000;
            const uint pageNoAccess = 0x01;
            const uint pageReadOnly = 0x02;
            const uint pageReadWrite = 0x04;
            const uint pageExecuteRead = 0x20;
            const uint pageExecuteReadWrite = 0x40;
            const uint pageGuard = 0x100;

            const uint processQuery = 0x0400;
            const uint processVmRead = 0x0010;
            const uint processQueryLimited = 0x1000;

            IntPtr hProcess = Kernel32Native.OpenProcess(processQuery | processVmRead | processQueryLimited, false,
                                                         unchecked((uint)process.Id));
            if (hProcess == IntPtr.Zero)
                return;

            long regionCount = 0;
            long privateCount = 0;
            long imageCount = 0;
            long mappedCount = 0;
            ulong commitBytes = 0;
            ulong rwBytes = 0;
            ulong rxBytes = 0;
            ulong rwxBytes = 0;
            ulong guardBytes = 0;
            ulong roBytes = 0;

            try
            {
                ulong address = 0;
                ulong maxAddress = Environment.Is64BitProcess ? 0x00007FFF_FFFFFFFFul : uint.MaxValue;
                nuint mbiSize = (nuint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

                while (address < maxAddress)
                {
                    nuint ret = VirtualQueryEx(hProcess, (nint)address, out MEMORY_BASIC_INFORMATION mbi, mbiSize);
                    if (ret == 0)
                        break;

                    ulong regionSize = (ulong)mbi.RegionSize;
                    if (regionSize == 0)
                        break;

                    regionCount += 1;

                    if (mbi.State == memCommit)
                    {
                        commitBytes += regionSize;

                        if (mbi.Type == memPrivate)
                            privateCount += 1;
                        else if (mbi.Type == memImage)
                            imageCount += 1;
                        else if (mbi.Type == memMapped)
                            mappedCount += 1;

                        uint protect = mbi.Protect;
                        uint baseProtect = protect & 0xFFu;

                        if ((protect & pageGuard) != 0)
                            guardBytes += regionSize;

                        if (baseProtect == pageReadWrite)
                            rwBytes += regionSize;
                        else if (baseProtect == pageExecuteRead)
                            rxBytes += regionSize;
                        else if (baseProtect == pageExecuteReadWrite)
                            rwxBytes += regionSize;
                        else if (baseProtect == pageReadOnly || baseProtect == pageNoAccess)
                            roBytes += regionSize;
                    }

                    ulong next = (ulong)mbi.BaseAddress + regionSize;
                    if (next <= address)
                        break;

                    address = next;
                }
            }
            catch
            {
            }
            finally
            {
                _ = Kernel32Native.CloseHandle(hProcess);
            }

            rows.Add(new MemoryMetricRow { Metric = "VAD Regions", Value = regionCount.ToString(), BytesValue = null });
            rows.Add(new MemoryMetricRow { Metric = "VAD Commit", Value = FormatBytes((long)commitBytes),
                                           BytesValue = (long)commitBytes });
            rows.Add(new MemoryMetricRow { Metric = "VAD Private Regions", Value = privateCount.ToString(),
                                           BytesValue = null });
            rows.Add(
                new MemoryMetricRow { Metric = "VAD Image Regions", Value = imageCount.ToString(), BytesValue = null });
            rows.Add(new MemoryMetricRow { Metric = "VAD Mapped Regions", Value = mappedCount.ToString(),
                                           BytesValue = null });
            rows.Add(new MemoryMetricRow { Metric = "Prot RW", Value = FormatBytes((long)rwBytes),
                                           BytesValue = (long)rwBytes });
            rows.Add(new MemoryMetricRow { Metric = "Prot RX", Value = FormatBytes((long)rxBytes),
                                           BytesValue = (long)rxBytes });
            rows.Add(new MemoryMetricRow { Metric = "Prot RWX", Value = FormatBytes((long)rwxBytes),
                                           BytesValue = (long)rwxBytes });
            rows.Add(new MemoryMetricRow { Metric = "Prot RO/NoAccess", Value = FormatBytes((long)roBytes),
                                           BytesValue = (long)roBytes });
            rows.Add(new MemoryMetricRow { Metric = "Prot Guard", Value = FormatBytes((long)guardBytes),
                                           BytesValue = (long)guardBytes });
        }

        private void MemoryViewToggle_Checked(object sender, RoutedEventArgs e)
        {
            _memoryTreemapEnabled = true;
            if (MemoryViewToggle != null)
                MemoryViewToggle.Content = "Table";
            UpdateMemoryViewMode();
            UpdateMemoryTreemap();
            UpdateLiveDataOverlays();
        }

        private void MemoryViewToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            _memoryTreemapEnabled = false;
            if (MemoryViewToggle != null)
                MemoryViewToggle.Content = "Treemap";
            UpdateMemoryViewMode();
            UpdateLiveDataOverlays();
        }

        private void MemoryInspectorToggle_Checked(object sender, RoutedEventArgs e)
        {
            _memoryInspectorEnabled = true;
            EnsureMemoryInspectorWindow();
            UpdateMemoryViewMode();
            UpdateLiveDataOverlays();
        }

        private void MemoryInspectorToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            _memoryInspectorEnabled = false;
            CloseMemoryInspectorWindow();
            UpdateMemoryViewMode();
            UpdateLiveDataOverlays();
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

        private void UpdateMemoryViewMode()
        {
            if (MemoryInspectorGrid == null || MemoryGrid == null || MemoryTreemapHost == null ||
                MemoryViewToggle == null)
            {
                return;
            }

            MemoryInspectorGrid.Visibility = Visibility.Collapsed;
            MemoryViewToggle.IsEnabled = true;
            MemoryGrid.Visibility = _memoryTreemapEnabled ? Visibility.Collapsed : Visibility.Visible;
            MemoryTreemapHost.Visibility = _memoryTreemapEnabled ? Visibility.Visible : Visibility.Collapsed;
        }

        private void EnsureMemoryInspectorWindow()
        {
            if (_memoryInspectorWindow != null)
            {
                UpdateMemoryInspectorWindowTitle();
                if (!_memoryInspectorWindow.IsVisible)
                {
                    _memoryInspectorWindow.Show();
                }

                _memoryInspectorWindow.Activate();
                return;
            }

            _memoryInspectorWindow = new MemoryInspectorWindow(
                MemoryInspectorRows, _pid, rowActivated: OpenThreadStackFromMemoryRow,
                rowDisassembly: row =>
                {
                    if (BkdcNative.IsAvailable && row.BaseAddressValue != 0 && row.RegionSizeBytes != 0)
                    {
                        DisassemblyRequested?.Invoke(this, new MemoryDisassemblyRequestedEventArgs(
                                                               unchecked((uint)_pid), row.BaseAddressValue,
                                                               row.RegionSizeBytes, $"{row.Category}  {row.Protect}",
                                                               row.SnapshotBytes, row.SnapshotOffset));
                    }
                });
            Window? owner = Window.GetWindow(this);
            if (owner != null && !ReferenceEquals(owner, _memoryInspectorWindow))
            {
                _memoryInspectorWindow.Owner = owner;
            }

            _memoryInspectorWindow.Closing += MemoryInspectorWindow_Closing;
            _memoryInspectorWindow.Closed += MemoryInspectorWindow_Closed;
            _memoryInspectorWindow.Show();
            _memoryInspectorWindow.Activate();
        }

        private void CloseMemoryInspectorWindow()
        {
            if (_memoryInspectorWindow == null)
            {
                return;
            }

            MemoryInspectorWindow window = _memoryInspectorWindow;
            _memoryInspectorWindow = null;
            _closingMemoryInspectorWindow = true;
            window.Closing -= MemoryInspectorWindow_Closing;
            window.Closed -= MemoryInspectorWindow_Closed;
            window.Close();
            _closingMemoryInspectorWindow = false;
        }

        private void MemoryInspectorWindow_Closing(object? sender, CancelEventArgs e)
        {
            if (_closingMemoryInspectorWindow || sender is not MemoryInspectorWindow window)
            {
                return;
            }

            e.Cancel = true;
            window.Hide();

            if (_memoryInspectorEnabled)
            {
                _memoryInspectorEnabled = false;
                if (MemoryInspectorToggle != null && MemoryInspectorToggle.IsChecked == true)
                {
                    MemoryInspectorToggle.IsChecked = false;
                    return;
                }
            }

            UpdateMemoryViewMode();
            UpdateLiveDataOverlays();
        }

        private void MemoryInspectorWindow_Closed(object? sender, EventArgs e)
        {
            if (sender is MemoryInspectorWindow window)
            {
                window.Closing -= MemoryInspectorWindow_Closing;
                window.Closed -= MemoryInspectorWindow_Closed;
            }

            _memoryInspectorWindow = null;
            if (_memoryInspectorEnabled)
            {
                _memoryInspectorEnabled = false;
                if (MemoryInspectorToggle != null && MemoryInspectorToggle.IsChecked == true)
                {
                    MemoryInspectorToggle.IsChecked = false;
                }
                else
                {
                    UpdateMemoryViewMode();
                    UpdateLiveDataOverlays();
                }
            }
        }

        private void UpdateMemoryInspectorWindowTitle()
        {
            _memoryInspectorWindow?.SetTargetPid(_pid);
        }

        private void OpenThreadStackFromMemoryRow(MemoryInspectorRow row)
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

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern nuint VirtualQueryEx(IntPtr hProcess, nint lpAddress,
                                                   out MEMORY_BASIC_INFORMATION lpBuffer, nuint dwLength);

        private const uint ThreadQueryInformation = 0x0040;
        private const uint ThreadQueryLimitedInformation = 0x0800;

        [StructLayout(LayoutKind.Sequential)]
        private struct THREAD_BASIC_INFORMATION
        {
            public int ExitStatus;
            public IntPtr TebBaseAddress;
            public CLIENT_ID ClientId;
            public UIntPtr AffinityMask;
            public int Priority;
            public int BasePriority;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NT_TIB64
        {
            public ulong ExceptionList;
            public ulong StackBase;
            public ulong StackLimit;
            public ulong SubSystemTib;
            public ulong FiberData;
            public ulong ArbitraryUserPointer;
            public ulong Self;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationThread(IntPtr threadHandle, int threadInformationClass,
                                                           out THREAD_BASIC_INFORMATION threadInformation,
                                                           int threadInformationLength, out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint desiredAccess, bool inheritHandle, uint threadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
                                                     int nSize, out IntPtr lpNumberOfBytesRead);

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQueryVirtualMemory(IntPtr processHandle, nint baseAddress,
                                                       int memoryInformationClass, IntPtr memoryInformation,
                                                       uint memoryInformationLength, out uint returnLength);

        private enum ProcessMitigationPolicy
        {
            DepPolicy = 0,
            AslrPolicy = 1,
            DynamicCodePolicy = 2,
            StrictHandleCheckPolicy = 3,
            SystemCallDisablePolicy = 4,
            MitigationOptionsMask = 5,
            ExtensionPointDisablePolicy = 6,
            ControlFlowGuardPolicy = 7
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_MITIGATION_DEP_POLICY
        {
            public uint Flags;
            public byte Permanent;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public byte[] Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_MITIGATION_ASLR_POLICY
        {
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_MITIGATION_DYNAMIC_CODE_POLICY
        {
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY
        {
            public uint Flags;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessMitigationPolicy(IntPtr hProcess, ProcessMitigationPolicy mitigationPolicy,
                                                              out PROCESS_MITIGATION_DEP_POLICY lpBuffer, int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessMitigationPolicy(IntPtr hProcess, ProcessMitigationPolicy mitigationPolicy,
                                                              out PROCESS_MITIGATION_ASLR_POLICY lpBuffer,
                                                              int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessMitigationPolicy(IntPtr hProcess, ProcessMitigationPolicy mitigationPolicy,
                                                              out PROCESS_MITIGATION_DYNAMIC_CODE_POLICY lpBuffer,
                                                              int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessMitigationPolicy(IntPtr hProcess, ProcessMitigationPolicy mitigationPolicy,
                                                              out PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY lpBuffer,
                                                              int dwLength);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool QueryWorkingSetEx(IntPtr hProcess, [In, Out] PSAPI_WORKING_SET_EX_INFORMATION[] pv,
                                                     int cb);

        private struct PeSummary
        {
            public string Machine;
            public bool IsPePlus;
            public string ImageBase;
            public string Subsystem;
            public string DllCharacteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PSAPI_WORKING_SET_EX_INFORMATION
        {
            public IntPtr VirtualAddress;
            public UIntPtr VirtualAttributes;
        }

        private readonly record struct MemoryModuleMapEntry(ulong BaseAddress, ulong EndAddress, string Name,
                                                            string Path);
    }

    public sealed class ThreadUsageRow
    {
        public int Tid { get; }
        public double CpuMs { get; }
        public string State { get; }
        public string ThreadKind { get; }
        public string StartTime { get; }
        public DateTime? StartTimeUtc { get; }
        public bool IsSuspended { get; }
        public bool IsWaiting { get; }

        public ThreadUsageRow(ThreadUsageSample s, bool targetSuspendedOverride = false)
        {
            Tid = s.Tid;
            CpuMs = Math.Round(s.CpuMsDelta, 2);
            State = BuildDisplayState(s, targetSuspendedOverride);
            ThreadKind = string.IsNullOrWhiteSpace(s.Kind) ? "Normal" : s.Kind.Trim();
            StartTimeUtc = s.StartTimeUtc;
            IsSuspended = State.Contains("Suspended", StringComparison.OrdinalIgnoreCase);
            IsWaiting = State.Contains("Waiting", StringComparison.OrdinalIgnoreCase);
            StartTime = s.StartTimeUtc.HasValue ? s.StartTimeUtc.Value.ToString("HH:mm:ss") : "-";
        }

        private static string BuildDisplayState(ThreadUsageSample s, bool targetSuspendedOverride)
        {
            if (targetSuspendedOverride || s.TargetSuspended)
            {
                return "Suspended (controller)";
            }

            string state = string.IsNullOrWhiteSpace(s.State) ? "Unknown" : s.State.Trim();
            string wait = string.IsNullOrWhiteSpace(s.WaitReason) ? string.Empty : s.WaitReason.Trim();
            if (wait.Equals("Suspended", StringComparison.OrdinalIgnoreCase))
            {
                return "Suspended";
            }

            if (state.Equals("Wait", StringComparison.OrdinalIgnoreCase))
            {
                return wait.Length > 0 ? $"Waiting ({wait})" : "Waiting";
            }

            return state;
        }
    }

    public sealed class CoreUsageRow
    {
        public CoreUsageRow(CoreUsageSample? sample, int coreIndex)
        {
            double busy = sample?.BusyPercent ?? 0.0;
            CoreIndex = coreIndex;
            CoreLabel = coreIndex.ToString();
            BusyPercent = busy;
            Fill = BuildFill(busy);
            ToolTip =
                sample == null || sample.ThreadCount == 0
                    ? $"Core {coreIndex}: idle/no attribution"
                    : $"Core {coreIndex}: {busy:0.0}% busy, top TID {sample.DominantTid} ({sample.DominantThreadKind}, {sample.DominantThreadCpuMs:0.0} ms), threads {sample.ThreadCount}";
        }

        public int CoreIndex { get; }
        public string CoreLabel { get; }
        public double BusyPercent { get; }
        public Brush Fill { get; }
        public string ToolTip { get; }

        private static Brush BuildFill(double busyPercent)
        {
            double heat = Math.Clamp(busyPercent, 0.0, 100.0) / 100.0;
            byte r = (byte)Math.Clamp(28 + (int)Math.Round(180 * heat), 0, 255);
            byte g = (byte)Math.Clamp(42 + (int)Math.Round(90 * heat), 0, 255);
            byte b = (byte)Math.Clamp(50 - (int)Math.Round(22 * heat), 0, 255);
            var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
            brush.Freeze();
            return brush;
        }
    }

    public sealed class ModuleInfoRow
    {
        public string Name { get; init; } = "";
        public string Role { get; init; } = "";
        public string BaseAddress { get; init; } = "";
        public string Size { get; init; } = "";
        public string Path { get; init; } = "";
    }

    public sealed class MemoryMetricRow
    {
        public string Metric { get; init; } = "";
        public string Value { get; init; } = "";
        public long? BytesValue { get; init; }
    }

    public sealed class PeInfoRow
    {
        public PeInfoRow(string field, string value)
        {
            Field = field;
            Value = value;
        }

        public string Field { get; }
        public string Value { get; }
    }

    public sealed class NetworkPeerRow
    {
        public string LocalEndpoint { get; set; } = "";
        public string RemoteEndpoint { get; set; } = "";
        public string RemoteAddress { get; set; } = "";
        public string DnsName { get; set; } = "";
        public string Protocol { get; set; } = "";
        public string State { get; set; } = "";
        public int ConnectionCount { get; set; }
        public long BytesSent { get; set; }
        public long BytesRecv { get; set; }
        public DateTime FirstSeen { get; set; } = DateTime.UtcNow;
        public DateTime LastSeen { get; set; } = DateTime.UtcNow;
        public string Source { get; set; } = "";
    }

    public sealed class MemoryInspectorRow : INotifyPropertyChanged
    {
        private string _baseAddress = "";
        private string _size = "";
        private string _state = "";
        private string _type = "";
        private string _protect = "";
        private string _category = "";
        private string _allocator = "";
        private string _source = "";
        private string _context = "";
        private string _lifecycle = "";
        private string _trust = "";
        private string _priorityBand = "Normal";
        private string _highlightBand = "";
        private string _highlightLabel = "";
        private uint _threadTid;
        private int _sortRank;
        private ulong _regionSizeBytes;
        private ulong _baseAddressValue;
        private uint _snapshotOffset;
        private byte[]? _snapshotBytes;

        public event PropertyChangedEventHandler? PropertyChanged;

        public string BaseAddress
        {
            get => _baseAddress;
            set => SetField(ref _baseAddress, value, nameof(BaseAddress));
        }

        public string Size
        {
            get => _size;
            set => SetField(ref _size, value, nameof(Size));
        }

        public string State
        {
            get => _state;
            set => SetField(ref _state, value, nameof(State));
        }

        public string Type
        {
            get => _type;
            set => SetField(ref _type, value, nameof(Type));
        }

        public string Protect
        {
            get => _protect;
            set => SetField(ref _protect, value, nameof(Protect));
        }

        public string Category
        {
            get => _category;
            set => SetField(ref _category, value, nameof(Category));
        }

        public string Allocator
        {
            get => _allocator;
            set => SetField(ref _allocator, value, nameof(Allocator));
        }

        public string Source
        {
            get => _source;
            set => SetField(ref _source, value, nameof(Source));
        }

        public string Context
        {
            get => _context;
            set => SetField(ref _context, value, nameof(Context));
        }

        public string Lifecycle
        {
            get => _lifecycle;
            set => SetField(ref _lifecycle, value, nameof(Lifecycle));
        }

        public string Trust
        {
            get => _trust;
            set => SetField(ref _trust, value, nameof(Trust));
        }

        public string PriorityBand
        {
            get => _priorityBand;
            set => SetField(ref _priorityBand, value, nameof(PriorityBand));
        }

        public string HighlightBand
        {
            get => _highlightBand;
            set => SetField(ref _highlightBand, value, nameof(HighlightBand));
        }

        public string HighlightLabel
        {
            get => _highlightLabel;
            set => SetField(ref _highlightLabel, value, nameof(HighlightLabel));
        }

        public uint ThreadTid
        {
            get => _threadTid;
            set => SetField(ref _threadTid, value, nameof(ThreadTid));
        }

        public int SortRank
        {
            get => _sortRank;
            set => SetField(ref _sortRank, value, nameof(SortRank));
        }

        public ulong RegionSizeBytes
        {
            get => _regionSizeBytes;
            set => SetField(ref _regionSizeBytes, value, nameof(RegionSizeBytes));
        }

        public ulong BaseAddressValue
        {
            get => _baseAddressValue;
            set => SetField(ref _baseAddressValue, value, nameof(BaseAddressValue));
        }

        public uint SnapshotOffset
        {
            get => _snapshotOffset;
            set => SetField(ref _snapshotOffset, value, nameof(SnapshotOffset));
        }

        public byte[]? SnapshotBytes
        {
            get => _snapshotBytes;
            set => SetField(ref _snapshotBytes, value, nameof(SnapshotBytes));
        }

        public void UpdateFrom(MemoryInspectorRow other)
        {
            BaseAddress = other.BaseAddress;
            Size = other.Size;
            State = other.State;
            Type = other.Type;
            Protect = other.Protect;
            Category = other.Category;
            Allocator = other.Allocator;
            Source = other.Source;
            Context = other.Context;
            Lifecycle = other.Lifecycle;
            Trust = other.Trust;
            PriorityBand = other.PriorityBand;
            HighlightBand = other.HighlightBand;
            HighlightLabel = other.HighlightLabel;
            ThreadTid = other.ThreadTid;
            SortRank = other.SortRank;
            RegionSizeBytes = other.RegionSizeBytes;
            BaseAddressValue = other.BaseAddressValue;
            SnapshotOffset = other.SnapshotOffset;
            SnapshotBytes = other.SnapshotBytes?.ToArray();
        }

        private void SetField<T>(ref T field, T value, string propertyName)
        {
            if (EqualityComparer<T>.Default.Equals(field, value))
            {
                return;
            }

            field = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public sealed class ThreadLifecycleRow
    {
        public ThreadLifecycleRow(ThreadLifecycleEventSample sample)
        {
            Timestamp = sample.TimestampUtc.ToString("HH:mm:ss");
            EventKind = string.IsNullOrWhiteSpace(sample.EventKind) ? "Update" : sample.EventKind;
            Tid = sample.ThreadId;
            CreatorPid = sample.CreatorPid;
            Flags = $"0x{sample.Flags:X8}";
            StartAddress = sample.StartAddress == 0 ? string.Empty : $"0x{sample.StartAddress:X}";
        }

        public string Timestamp { get; }
        public string EventKind { get; }
        public uint Tid { get; }
        public uint CreatorPid { get; }
        public string Flags { get; }
        public string StartAddress { get; }
    }

    internal readonly record struct ThreadMemoryRange(uint Tid, ulong TebAddress, ulong StackBase, ulong StackLimit);
}
