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

namespace BlackbirdInterface
{
    public partial class PerformancePane : UserControl
    {
        public event RoutedEventHandler? ReorderRequested;
        public event RoutedEventHandler? CloseRequested;
        public event RoutedEventHandler? FloatRequested;
        public event EventHandler<ThreadUsageRow>? ThreadDoubleClicked;
        public event RoutedEventHandler? ParallelStacksRequested;
        public event EventHandler<PaneHeaderDragEventArgs>? HeaderDragStarted;
        public event EventHandler<PaneHeaderDragEventArgs>? HeaderDragDelta;
        public event EventHandler<PaneHeaderDragEventArgs>? HeaderDragCompleted;

        private DateTime _captureStartUtc;
        private DateTime _viewStartUtc;
        private DateTime _viewEndUtc;
        private PerformanceSample? _lastSample;
        private readonly List<PerformanceSample> _historySamples = new();
        private readonly List<ThreadLifecycleEventSample> _threadLifecycleHistory = new();
        private bool _timeTravelEnabled = true;
        private bool _timeTravelSliderProgrammatic;
        private int _selectedSampleIndex = -1;
        private bool _memoryInspectorEnabled;
        private bool _threadLifecycleEnabled;

        private readonly TimeSeriesBuffer _cpu = new(2000);
        private readonly TimeSeriesBuffer _diskRead = new(2000);
        private readonly TimeSeriesBuffer _diskWrite = new(2000);
        private readonly TimeSeriesBuffer _ramPrivate = new(2000);
        private readonly TimeSeriesBuffer _netIn = new(2000);
        private readonly TimeSeriesBuffer _netOut = new(2000);

        private int _pid;
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

        public ObservableCollection<ThreadUsageRow> TopThreads { get; } = new();
        public ObservableCollection<ModuleInfoRow> Modules { get; } = new();
        public ObservableCollection<PeInfoRow> PeInfo { get; } = new();
        public ObservableCollection<MemoryMetricRow> MemoryMetrics { get; } = new();
        public ObservableCollection<MemoryInspectorRow> MemoryInspectorRows { get; } = new();
        public ObservableCollection<ThreadLifecycleRow> ThreadLifecycleRows { get; } = new();
        public ObservableCollection<NetworkPeerRow> NetworkPeers { get; } = new();

        public PerformancePane()
        {
            InitializeComponent();
            if (ThreadsGrid != null) ThreadsGrid.ItemsSource = TopThreads;
            if (ModulesGrid != null) ModulesGrid.ItemsSource = Modules;
            if (PeInfoGrid != null) PeInfoGrid.ItemsSource = PeInfo;
            if (MemoryGrid != null) MemoryGrid.ItemsSource = MemoryMetrics;
            if (MemoryInspectorGrid != null) MemoryInspectorGrid.ItemsSource = MemoryInspectorRows;
            if (ThreadLifecycleGrid != null) ThreadLifecycleGrid.ItemsSource = ThreadLifecycleRows;
            if (NetworkPeersGrid != null) NetworkPeersGrid.ItemsSource = NetworkPeers;
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
                if (MemoryGrid != null) MemoryGrid.Visibility = Visibility.Collapsed;
                if (MemoryTreemapHost != null) MemoryTreemapHost.Visibility = Visibility.Visible;
                if (MemoryInspectorGrid != null) MemoryInspectorGrid.Visibility = Visibility.Collapsed;
                if (ThreadsGrid != null) ThreadsGrid.Visibility = Visibility.Visible;
                if (ThreadLifecycleGrid != null) ThreadLifecycleGrid.Visibility = Visibility.Collapsed;
                if (TimeTravelStampBlock != null) TimeTravelStampBlock.Text = "LIVE";
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
            if (NetChart == null || NetworkPeersGrid == null || NetworkPaneTitle == null || NetworkViewSwitchButton == null)
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
                CpuChart.SetSeries(new[]
                {
                    new ChartSeries("CPU %", Brush(0x35, 0xA8, 0xFF), SeriesScale.Percent, p => p.CpuPercent, ChartValueFormat.Percent),
                    new ChartSeries("Cores used %", Brush(0x7C, 0xD5, 0xFF), SeriesScale.Percent, p => p.CoresUsedPercent, ChartValueFormat.Percent),
                });
            }

            if (DiskChart != null)
            {
                DiskChart.SetSeries(new[]
                {
                    new ChartSeries("Read B/s", Brush(0xFF9A21), SeriesScale.AutoToViewMax, p => p.DiskReadBytesPerSec, ChartValueFormat.BytesPerSecond),
                    new ChartSeries("Write B/s", Brush(0xFF4545), SeriesScale.AutoToViewMax, p => p.DiskWriteBytesPerSec, ChartValueFormat.BytesPerSecond),
                });
            }

            if (RamChart != null)
            {
                RamChart.SetSeries(new[]
                {
                    new ChartSeries("Private bytes", Brush(0x43, 0xF2, 0x72), SeriesScale.AutoToViewMax, p => p.PrivateBytes, ChartValueFormat.Bytes),
                    new ChartSeries("Commit", Brush(0x66, 0xD9, 0xEF), SeriesScale.AutoToViewMax, p => p.CommitBytes, ChartValueFormat.Bytes),
                    new ChartSeries("MEM_IMAGE", Brush(0xFF, 0xC8, 0x57), SeriesScale.AutoToViewMax, p => p.ImageBytes, ChartValueFormat.Bytes),
                    new ChartSeries("MEM_MAPPED", Brush(0xB2, 0x8D, 0xFF), SeriesScale.AutoToViewMax, p => p.MappedBytes, ChartValueFormat.Bytes),
                });
            }

            if (NetChart != null)
            {
                NetChart.SetSeries(new[]
                {
                    new ChartSeries("Inbound B/s", Brush(0xA0, 0x5B, 0xFF), SeriesScale.AutoToViewMax, p => p.NetInBytesPerSec, ChartValueFormat.BytesPerSecond),
                    new ChartSeries("Outbound B/s", Brush(0xC0, 0x86, 0xFF), SeriesScale.AutoToViewMax, p => p.NetOutBytesPerSec, ChartValueFormat.BytesPerSecond),
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

        private int ResolveSampleIndexForCurrentView()
            => ResolveSampleIndexForTimestamp(GetObservedTimestampUtc());

        private bool HasHistoricalDataForObservedTime()
            => ResolveSampleIndexForCurrentView() >= 0;

        public void SetPid(int pid)
        {
            if (_pid != pid)
            {
                _historySamples.Clear();
                _threadLifecycleHistory.Clear();
                _selectedSampleIndex = -1;
                TopThreads.Clear();
                ThreadLifecycleRows.Clear();
                MemoryMetrics.Clear();
                MemoryInspectorRows.Clear();
                RebuildTimeTravelSliderBounds();
                if (TimeTravelStampBlock != null)
                {
                    TimeTravelStampBlock.Text = "LIVE";
                }
            }
            _pid = pid;
        }

        public void SetProcessLiveDataAvailable(bool available)
        {
            _processLiveDataAvailable = available;
            if (!available)
            {
                if (_historySamples.Count == 0)
                {
                    TopThreads.Clear();
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
            else
            {
                UpdateLiveDataOverlays();
            }
        }

        public IReadOnlyList<ThreadUsageRow> SnapshotTopThreads()
            => TopThreads.Select(row => new ThreadUsageRow(new ThreadUsageSample
            {
                Tid = row.Tid,
                CpuMsDelta = row.CpuMs,
                State = row.State,
                WaitReason = row.IsSuspended ? "Suspended" : string.Empty,
                Kind = row.ThreadKind,
                StartTimeUtc = row.StartTimeUtc,
                TargetSuspended = row.IsSuspended
            })).ToList();

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

            // keep buffers (not strictly necessary for drawing but useful if you want export later)
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
                int index = _timeTravelEnabled
                    ? ResolveSampleIndexForCurrentView()
                    : _historySamples.Count - 1;
                ApplySampleIndex(index, updateSlider: true);
            }
            else
            {
                TopThreads.Clear();
                MemoryMetrics.Clear();
                MemoryInspectorRows.Clear();
                UpdateMemoryTreemap();
            }

            RefreshProcessDetails();
            UpdateSubtitle();
            UpdateLiveDataOverlays();
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

            UpdateLiveDataOverlays();
        }

        public void LoadThreadLifecycleHistory(IEnumerable<ThreadLifecycleEventSample> history)
        {
            _threadLifecycleHistory.Clear();
            _threadLifecycleHistory.AddRange(history.Select(CloneThreadLifecycleEvent).OrderBy(x => x.TimestampUtc));

            DateTime cutoff = _historySamples.Count > 0 && _selectedSampleIndex >= 0 && _selectedSampleIndex < _historySamples.Count
                ? _historySamples[_selectedSampleIndex].TimestampUtc
                : DateTime.UtcNow;
            RebuildThreadLifecycleRows(cutoff);
            UpdateLiveDataOverlays();
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

            var rebuiltThreads = sample.TopThreads
                .Take(14)
                .Select(thread => new ThreadUsageRow(thread, _targetSuspended))
                .ToList();
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

            TopThreads.Clear();
            foreach (ThreadUsageRow thread in rebuiltThreads)
            {
                TopThreads.Add(thread);
            }
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
                MemoryMetrics.Add(new MemoryMetricRow
                {
                    Metric = metric.Metric,
                    Value = metric.Value,
                    BytesValue = metric.BytesValue
                });
            }
            RebuildMemoryInspectorRows(sample.MemoryPages);
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

        private void RebuildMemoryInspectorRows(IEnumerable<MemoryPageSample> pages)
        {
            MemoryInspectorRows.Clear();
            foreach (MemoryPageSample page in pages.Take(768))
            {
                MemoryInspectorRows.Add(new MemoryInspectorRow
                {
                    BaseAddress = $"0x{page.BaseAddress:X}",
                    Size = FormatBytes((long)Math.Min(page.RegionSize, (ulong)long.MaxValue)),
                    State = page.StateLabel,
                    Type = page.TypeLabel,
                    Protect = page.ProtectLabel,
                    Category = page.Category
                });
            }
        }

        private void RebuildThreadLifecycleRows(DateTime cutoffUtc)
        {
            ThreadLifecycleRows.Clear();
            IEnumerable<ThreadLifecycleEventSample> rows = _threadLifecycleHistory
                .Where(x => x.TimestampUtc <= cutoffUtc)
                .OrderByDescending(x => x.TimestampUtc)
                .Take(256);
            foreach (ThreadLifecycleEventSample row in rows)
            {
                ThreadLifecycleRows.Add(new ThreadLifecycleRow(row));
            }
        }

        private static PerformanceSample CloneSample(PerformanceSample src)
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
                CommitBytes = src.CommitBytes,
                ImageBytes = src.ImageBytes,
                MappedBytes = src.MappedBytes,
                PrivateVadBytes = src.PrivateVadBytes,
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
                    StartTimeUtc = t.StartTimeUtc,
                    TargetSuspended = t.TargetSuspended
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
            PerfSubTitle.Text = $"{scope} | Cores used: {coresUsed:0.00}/{Math.Max(1, _lastSample.CoreCount)} ({_lastSample.CoresUsedPercent:0.0}%)";
        }

        private void PerfBtnReorder_Click(object sender, System.Windows.RoutedEventArgs e) => ReorderRequested?.Invoke(this, e);
        private void PerfBtnFloat_Click(object sender, System.Windows.RoutedEventArgs e) => FloatRequested?.Invoke(this, e);
        private void PerfBtnClose_Click(object sender, System.Windows.RoutedEventArgs e) => CloseRequested?.Invoke(this, e);

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

        private void ParallelStacksButton_Click(object sender, RoutedEventArgs e)
            => ParallelStacksRequested?.Invoke(this, e);

        private void ModulesGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (ModulesGrid.SelectedItem is not ModuleInfoRow row || string.IsNullOrWhiteSpace(row.Path))
                return;

            LaunchPeView(row.Path);
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

        private void ProcessDetailsLayout_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            UpdateDetailsLayout();
        }

        private void UpdateDetailsLayout()
        {
            if (ProcessDetailsLayout == null)
                return;

            // Wide layouts get side-by-side modules/memory, narrow layouts stack vertically.
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
                    var psi = new ProcessStartInfo
                    {
                        FileName = peViewExe,
                        Arguments = $"\"{normalizedPath}\"",
                        UseShellExecute = true
                    };
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
                "PeView Not Found",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
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
            try
            {
                using var process = Process.GetProcessById(targetPid);

                RefreshModules(process);
                RefreshPeInfo(process);
                if (_historySamples.Count == 0 || _lastSample == null)
                {
                    RefreshMemoryMetrics(process);
                }
                RefreshNetworkPeers(targetPid);
                _processLiveDataAvailable = true;
            }
            catch
            {
                if (_historySamples.Count == 0)
                {
                    MemoryMetrics.Clear();
                    MemoryInspectorRows.Clear();
                }
                NetworkPeers.Clear();
                UpdateMemoryTreemap();
                _processLiveDataAvailable = false;
            }

            UpdateLiveDataOverlays();
        }

        private void RefreshModules(Process process)
        {
            var rows = new List<ModuleInfoRow>();
            try
            {
                foreach (ProcessModule module in process.Modules)
                {
                    rows.Add(new ModuleInfoRow
                    {
                        Name = module.ModuleName,
                        BaseAddress = $"0x{module.BaseAddress.ToInt64():X}",
                        Size = FormatBytes(module.ModuleMemorySize),
                        Path = module.FileName
                    });
                }
            }
            catch
            {
            }

            Modules.Clear();
            foreach (var row in rows.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).Take(1024))
                Modules.Add(row);
        }

        private void RefreshPeInfo(Process process)
        {
            var rows = new List<PeInfoRow>();

            rows.Add(new PeInfoRow("PID", process.Id.ToString()));
            rows.Add(new PeInfoRow("Process Name", process.ProcessName));
            try { rows.Add(new PeInfoRow("Start Time", process.StartTime.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'"))); } catch { }
            try { rows.Add(new PeInfoRow("Priority Class", process.PriorityClass.ToString())); } catch { }

            string? imagePath = null;
            try { imagePath = process.MainModule?.FileName; } catch { }
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
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var br = new BinaryReader(fs);
                if (br.ReadUInt16() != 0x5A4D) // MZ
                    return false;

                fs.Position = 0x3C;
                int peOffset = br.ReadInt32();
                if (peOffset <= 0 || peOffset > fs.Length - 0x100)
                    return false;

                fs.Position = peOffset;
                if (br.ReadUInt32() != 0x00004550) // PE\0\0
                    return false;

                ushort machine = br.ReadUInt16();
                _ = br.ReadUInt16(); // NumberOfSections
                _ = br.ReadUInt32(); // TimeDateStamp
                _ = br.ReadUInt32(); // PtrToSymTable
                _ = br.ReadUInt32(); // NumSymbols
                ushort sizeOfOptionalHeader = br.ReadUInt16();
                _ = br.ReadUInt16(); // characteristics

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

                pe = new PeSummary
                {
                    Machine = MachineToString(machine),
                    IsPePlus = isPePlus,
                    ImageBase = imageBase,
                    Subsystem = SubsystemToString(subsystem),
                    DllCharacteristics = $"0x{dllChars:X4}"
                };
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
                if (GetProcessMitigationPolicy(process.Handle, ProcessMitigationPolicy.DepPolicy, out PROCESS_MITIGATION_DEP_POLICY dep, Marshal.SizeOf<PROCESS_MITIGATION_DEP_POLICY>()))
                {
                    rows.Add(new PeInfoRow("Mitigation DEP", (dep.Flags & 0x1) != 0 ? "Enabled" : "Disabled"));
                }

                if (GetProcessMitigationPolicy(process.Handle, ProcessMitigationPolicy.AslrPolicy, out PROCESS_MITIGATION_ASLR_POLICY aslr, Marshal.SizeOf<PROCESS_MITIGATION_ASLR_POLICY>()))
                {
                    rows.Add(new PeInfoRow("Mitigation ASLR", (aslr.Flags & 0x7) != 0 ? "Enabled" : "Disabled"));
                }

                if (GetProcessMitigationPolicy(process.Handle, ProcessMitigationPolicy.ControlFlowGuardPolicy, out PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg, Marshal.SizeOf<PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY>()))
                {
                    rows.Add(new PeInfoRow("Mitigation CFG", (cfg.Flags & 0x1) != 0 ? "Enabled" : "Disabled"));
                }

                if (GetProcessMitigationPolicy(process.Handle, ProcessMitigationPolicy.DynamicCodePolicy, out PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dyn, Marshal.SizeOf<PROCESS_MITIGATION_DYNAMIC_CODE_POLICY>()))
                {
                    rows.Add(new PeInfoRow("Mitigation DynamicCode", (dyn.Flags & 0x1) != 0 ? "Prohibited" : "Allowed"));
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
            return machine switch
            {
                0x014C => "x86",
                0x8664 => "x64",
                0xAA64 => "ARM64",
                _ => $"0x{machine:X4}"
            };
        }

        private static string SubsystemToString(ushort subsystem)
        {
            return subsystem switch
            {
                2 => "Windows GUI",
                3 => "Windows CUI",
                _ => subsystem.ToString()
            };
        }

        private void RefreshMemoryMetrics(Process process)
        {
            var rows = new List<MemoryMetricRow>
            {
                new() { Metric = "Working Set", Value = FormatBytes(process.WorkingSet64), BytesValue = process.WorkingSet64 },
                new() { Metric = "Peak Working Set", Value = FormatBytes(process.PeakWorkingSet64), BytesValue = process.PeakWorkingSet64 },
                new() { Metric = "Private Bytes", Value = FormatBytes(process.PrivateMemorySize64), BytesValue = process.PrivateMemorySize64 },
                new() { Metric = "Virtual Bytes", Value = FormatBytes(process.VirtualMemorySize64), BytesValue = null },
                new() { Metric = "Paged Memory", Value = FormatBytes(process.PagedMemorySize64), BytesValue = process.PagedMemorySize64 },
                new() { Metric = "Nonpaged System Memory", Value = FormatBytes(process.NonpagedSystemMemorySize64), BytesValue = process.NonpagedSystemMemorySize64 },
                new() { Metric = "Paged System Memory", Value = FormatBytes(process.PagedSystemMemorySize64), BytesValue = process.PagedSystemMemorySize64 },
                new() { Metric = "Handle Count", Value = process.HandleCount.ToString(), BytesValue = null },
                new() { Metric = "Thread Count", Value = process.Threads.Count.ToString(), BytesValue = null }
            };

            MemoryMetrics.Clear();
            foreach (var row in rows)
                MemoryMetrics.Add(row);

            try
            {
                List<MemoryPageSample> pages = CaptureLiveMemoryPages(process);
                RebuildMemoryInspectorRows(pages);
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
            NetworkPeers.Clear();
            foreach (NetworkPeerRow row in rows)
            {
                NetworkPeers.Add(row);
            }
        }

        private List<NetworkPeerRow> ReadNetworkPeers(int targetPid)
        {
            var rows = new Dictionary<string, NetworkPeerRow>(StringComparer.OrdinalIgnoreCase);
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netstat",
                    Arguments = "-ano",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = false,
                    CreateNoWindow = true
                };

                using Process? process = Process.Start(psi);
                if (process == null)
                {
                    return new List<NetworkPeerRow>();
                }

                string? line;
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

                    string[] tokens = trimmed
                        .Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
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
                    if (remoteAddress.Length == 0 || remoteAddress == "*" || remoteAddress == "0.0.0.0" || remoteAddress == "::")
                    {
                        continue;
                    }

                    string key = $"{protocol}|{remoteAddress}|{state}";
                    if (!rows.TryGetValue(key, out NetworkPeerRow? row))
                    {
                        row = new NetworkPeerRow
                        {
                            LocalEndpoint = tokens[1],
                            RemoteEndpoint = remoteEndpoint,
                            RemoteAddress = remoteAddress,
                            Protocol = protocol,
                            State = state,
                            DnsName = ResolveDnsName(remoteAddress),
                            ConnectionCount = 1
                        };
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

            return rows.Values
                .OrderByDescending(x => x.ConnectionCount)
                .ThenBy(x => x.RemoteAddress, StringComparer.OrdinalIgnoreCase)
                .Take(128)
                .ToList();
        }

        private string ResolveDnsName(string remoteAddress)
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

            string host = "-";
            try
            {
                var lookup = System.Threading.Tasks.Task.Run(() => Dns.GetHostEntry(remoteAddress));
                if (lookup.Wait(120) && lookup.Result != null)
                {
                    host = string.IsNullOrWhiteSpace(lookup.Result.HostName)
                        ? remoteAddress
                        : lookup.Result.HostName;
                }
            }
            catch
            {
                host = "-";
            }

            _reverseDnsCache[remoteAddress] = host;
            return host;
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
                bool hasThreadData = _threadLifecycleEnabled ? ThreadLifecycleRows.Count > 0 : TopThreads.Count > 0;
                bool showThreadsNoData = !hasThreadData;
                ThreadsNoDataOverlay.Visibility = showThreadsNoData ? Visibility.Visible : Visibility.Collapsed;
                if (ThreadsNoDataMessageBlock != null)
                {
                    ThreadsNoDataMessageBlock.Text = threadMessage;
                }
            }

            if (MemoryNoDataOverlay != null)
            {
                bool hasMemoryData = _memoryInspectorEnabled ? MemoryInspectorRows.Count > 0 : MemoryMetrics.Count > 0;
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
                bool hasTrafficData = _historySamples.Any(sample =>
                    sample.NetInBytesPerSec > 0.01 ||
                    sample.NetOutBytesPerSec > 0.01 ||
                    sample.NetPacketsPerSec > 0.01);
                bool hasPeerData = NetworkPeers.Count > 0;
                bool showNetworkNoData = _showNetworkPeers ? !hasPeerData : !hasTrafficData;
                NetworkNoDataOverlay.Visibility = showNetworkNoData ? Visibility.Visible : Visibility.Collapsed;
            }
        }

        private static MemoryMetricRow CloneMetric(MemoryMetricRow src)
        {
            return new MemoryMetricRow
            {
                Metric = src.Metric,
                Value = src.Value,
                BytesValue = src.BytesValue
            };
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

            IntPtr hProcess = Kernel32Native.OpenProcess(
                processQuery | processVmRead | processQueryLimited,
                false,
                unchecked((uint)process.Id));
            if (hProcess == IntPtr.Zero)
            {
                return new List<MemoryPageSample>();
            }

            var pages = new List<MemoryPageSample>(768);
            try
            {
                ulong address = 0;
                ulong maxAddress = Environment.Is64BitProcess ? 0x00007FFF_FFFFFFFFul : uint.MaxValue;
                nuint mbiSize = (nuint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

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
                        pages.Add(new MemoryPageSample
                        {
                            BaseAddress = (ulong)mbi.BaseAddress,
                            RegionSize = regionSize,
                            State = mbi.State,
                            Protect = mbi.Protect,
                            Type = mbi.Type,
                            StateLabel = EventDetailFormatting.DescribeMemoryState(mbi.State),
                            ProtectLabel = EventDetailFormatting.DescribeMemoryProtection(mbi.Protect),
                            TypeLabel = EventDetailFormatting.DescribeMemoryType(mbi.Type),
                            Category = BuildMemoryCategory(mbi.Type, mbi.Protect)
                        });
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

            return pages
                .OrderByDescending(x => x.RegionSize)
                .ThenBy(x => x.BaseAddress)
                .Take(768)
                .ToList();
        }

        private static string BuildMemoryCategory(uint type, uint protect)
        {
            uint baseProtect = protect & 0xFFu;
            bool executable = baseProtect == 0x10 || baseProtect == 0x20 || baseProtect == 0x40 || baseProtect == 0x80;
            bool writable = baseProtect == 0x04 || baseProtect == 0x08 || baseProtect == 0x40 || baseProtect == 0x80;

            string typeLabel = type switch
            {
                0x20000 => "Private",
                0x40000 => "Mapped",
                0x1000000 => "Image",
                _ => "Unknown"
            };

            if (executable && writable)
                return $"{typeLabel} RWX";
            if (executable)
                return $"{typeLabel} RX";
            if (writable)
                return $"{typeLabel} RW";
            return typeLabel;
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

            IntPtr hProcess = Kernel32Native.OpenProcess(
                processQuery | processVmRead | processQueryLimited,
                false,
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

                        if (mbi.Type == memPrivate) privateCount += 1;
                        else if (mbi.Type == memImage) imageCount += 1;
                        else if (mbi.Type == memMapped) mappedCount += 1;

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
            rows.Add(new MemoryMetricRow { Metric = "VAD Commit", Value = FormatBytes((long)commitBytes), BytesValue = (long)commitBytes });
            rows.Add(new MemoryMetricRow { Metric = "VAD Private Regions", Value = privateCount.ToString(), BytesValue = null });
            rows.Add(new MemoryMetricRow { Metric = "VAD Image Regions", Value = imageCount.ToString(), BytesValue = null });
            rows.Add(new MemoryMetricRow { Metric = "VAD Mapped Regions", Value = mappedCount.ToString(), BytesValue = null });
            rows.Add(new MemoryMetricRow { Metric = "Prot RW", Value = FormatBytes((long)rwBytes), BytesValue = (long)rwBytes });
            rows.Add(new MemoryMetricRow { Metric = "Prot RX", Value = FormatBytes((long)rxBytes), BytesValue = (long)rxBytes });
            rows.Add(new MemoryMetricRow { Metric = "Prot RWX", Value = FormatBytes((long)rwxBytes), BytesValue = (long)rwxBytes });
            rows.Add(new MemoryMetricRow { Metric = "Prot RO/NoAccess", Value = FormatBytes((long)roBytes), BytesValue = (long)roBytes });
            rows.Add(new MemoryMetricRow { Metric = "Prot Guard", Value = FormatBytes((long)guardBytes), BytesValue = (long)guardBytes });
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
            UpdateMemoryViewMode();
            UpdateLiveDataOverlays();
        }

        private void MemoryInspectorToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            _memoryInspectorEnabled = false;
            UpdateMemoryViewMode();
            UpdateLiveDataOverlays();
        }

        private void ThreadLifecycleToggle_Checked(object sender, RoutedEventArgs e)
        {
            _threadLifecycleEnabled = true;
            if (ThreadsGrid != null)
                ThreadsGrid.Visibility = Visibility.Collapsed;
            if (ThreadLifecycleGrid != null)
                ThreadLifecycleGrid.Visibility = Visibility.Visible;
            UpdateLiveDataOverlays();
        }

        private void ThreadLifecycleToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            _threadLifecycleEnabled = false;
            if (ThreadLifecycleGrid != null)
                ThreadLifecycleGrid.Visibility = Visibility.Collapsed;
            if (ThreadsGrid != null)
                ThreadsGrid.Visibility = Visibility.Visible;
            UpdateLiveDataOverlays();
        }

        private void UpdateMemoryViewMode()
        {
            if (MemoryInspectorGrid == null || MemoryGrid == null || MemoryTreemapHost == null || MemoryViewToggle == null)
            {
                return;
            }

            MemoryInspectorGrid.Visibility = _memoryInspectorEnabled ? Visibility.Visible : Visibility.Collapsed;

            if (_memoryInspectorEnabled)
            {
                MemoryGrid.Visibility = Visibility.Collapsed;
                MemoryTreemapHost.Visibility = Visibility.Collapsed;
                MemoryViewToggle.IsEnabled = false;
                return;
            }

            MemoryViewToggle.IsEnabled = true;
            MemoryGrid.Visibility = _memoryTreemapEnabled ? Visibility.Collapsed : Visibility.Visible;
            MemoryTreemapHost.Visibility = _memoryTreemapEnabled ? Visibility.Visible : Visibility.Collapsed;
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

            var entries = MemoryMetrics
                .Where(x => x.BytesValue.HasValue && x.BytesValue.Value > 0)
                .OrderByDescending(x => x.BytesValue!.Value)
                .Select(x => new MemoryTreemapEntry(x.Metric, x.Value, x.BytesValue!.Value))
                .ToList();

            if (entries.Count == 0)
            {
                MemoryTreemapNoData.Visibility = MemoryNoDataOverlay?.Visibility == Visibility.Visible
                    ? Visibility.Collapsed
                    : Visibility.Visible;
                return;
            }

            MemoryTreemapNoData.Visibility = Visibility.Collapsed;

            var plot = new Rect(0, 0, width, height);
            var layout = new List<(MemoryTreemapEntry Entry, Rect Rect)>();
            LayoutTreemap(entries, plot, plot.Width >= plot.Height, layout);

            var fills = new[]
            {
                Color.FromRgb(0x60, 0xA5, 0xFA),
                Color.FromRgb(0x34, 0xD3, 0x99),
                Color.FromRgb(0xF5, 0x9E, 0x0B),
                Color.FromRgb(0xA7, 0x8B, 0xFA),
                Color.FromRgb(0xF4, 0x72, 0xB6),
                Color.FromRgb(0x22, 0xD3, 0xEE),
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
                var border = new Border
                {
                    Width = r.Width,
                    Height = r.Height,
                    BorderThickness = new Thickness(1),
                    BorderBrush = UiPalette.BorderBrush,
                    Background = fillBrush,
                    Child = new TextBlock
                    {
                        Text = (r.Width < 60 || r.Height < 26) ? "" : $"{item.Entry.Name}\n{item.Entry.Display}",
                        Margin = new Thickness(5, 4, 5, 4),
                        TextTrimming = TextTrimming.CharacterEllipsis,
                        TextWrapping = TextWrapping.Wrap,
                        Foreground = UiPalette.TextBrush,
                        FontSize = r.Width < 120 || r.Height < 48 ? 10 : 11,
                        FontWeight = FontWeights.SemiBold
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

        private static void LayoutTreemap(
            List<MemoryTreemapEntry> entries,
            Rect area,
            bool splitHorizontal,
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
        private static extern nuint VirtualQueryEx(
            IntPtr hProcess,
            nint lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer,
            nuint dwLength);

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
        private static extern bool GetProcessMitigationPolicy(
            IntPtr hProcess,
            ProcessMitigationPolicy mitigationPolicy,
            out PROCESS_MITIGATION_DEP_POLICY lpBuffer,
            int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessMitigationPolicy(
            IntPtr hProcess,
            ProcessMitigationPolicy mitigationPolicy,
            out PROCESS_MITIGATION_ASLR_POLICY lpBuffer,
            int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessMitigationPolicy(
            IntPtr hProcess,
            ProcessMitigationPolicy mitigationPolicy,
            out PROCESS_MITIGATION_DYNAMIC_CODE_POLICY lpBuffer,
            int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessMitigationPolicy(
            IntPtr hProcess,
            ProcessMitigationPolicy mitigationPolicy,
            out PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY lpBuffer,
            int dwLength);

        private struct PeSummary
        {
            public string Machine;
            public bool IsPePlus;
            public string ImageBase;
            public string Subsystem;
            public string DllCharacteristics;
        }
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
            if (wait.Equals("Suspended", StringComparison.OrdinalIgnoreCase) ||
                wait.Equals("UserRequest", StringComparison.OrdinalIgnoreCase))
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

    public sealed class ModuleInfoRow
    {
        public string Name { get; init; } = "";
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
    }

    public sealed class MemoryInspectorRow
    {
        public string BaseAddress { get; init; } = "";
        public string Size { get; init; } = "";
        public string State { get; init; } = "";
        public string Type { get; init; } = "";
        public string Protect { get; init; } = "";
        public string Category { get; init; } = "";
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
}

