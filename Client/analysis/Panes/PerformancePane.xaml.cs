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

        private readonly TimeSeriesBuffer _cpu = new(2000);
        private readonly TimeSeriesBuffer _diskRead = new(2000);
        private readonly TimeSeriesBuffer _diskWrite = new(2000);
        private readonly TimeSeriesBuffer _ramPrivate = new(2000);
        private readonly TimeSeriesBuffer _netIn = new(2000);
        private readonly TimeSeriesBuffer _netOut = new(2000);
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
        private readonly DispatcherTimer _memoryAttributionRefreshTimer;
        private bool _memoryAttributionRefreshPending;
        private DateTime _lastMemoryAttributionRefreshUtc;
        private static readonly TimeSpan MemoryAttributionRefreshCoalesceInterval = TimeSpan.FromMilliseconds(350);
        private static readonly TimeSpan MemoryAttributionRefreshMinimumDelay = TimeSpan.FromMilliseconds(40);

        public ObservableCollection<ThreadUsageRow> TopThreads { get; } = new();
        public ObservableCollection<CoreUsageRow> CoreUsageRows { get; } = new();
        public ObservableCollection<ModuleInfoRow> Modules { get; } = new();
        public ObservableCollection<PeInfoRow> PeInfo { get; } = new();
        public ObservableCollection<MemoryMetricRow> MemoryMetrics { get; } = new();
        public BulkObservableCollection<MemoryAttributionRow> MemoryAttributionRows { get; } = new();
        public ObservableCollection<ThreadLifecycleRow> ThreadLifecycleRows { get; } = new();
        public ObservableCollection<NetworkPeerRow> NetworkPeers { get; } = new();

        public PerformancePane()
        {
            InitializeComponent();
            _memoryAttributionRefreshTimer = new DispatcherTimer(DispatcherPriority.Background, Dispatcher);
            _memoryAttributionRefreshTimer.Interval = MemoryAttributionRefreshCoalesceInterval;
            _memoryAttributionRefreshTimer.Tick += (_, __) => FlushScheduledMemoryAttributionRefresh();
            if (ThreadsGrid != null)
                ThreadsGrid.ItemsSource = TopThreads;
            if (ModulesGrid != null)
                ModulesGrid.ItemsSource = Modules;
            if (PeInfoGrid != null)
                PeInfoGrid.ItemsSource = PeInfo;
            if (MemoryGrid != null)
                MemoryGrid.ItemsSource = MemoryMetrics;
            if (MemoryAttributionGrid != null)
                MemoryAttributionGrid.ItemsSource = MemoryAttributionRows;
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
                if (MemorySummaryToggle != null)
                {
                    MemorySummaryToggle.IsChecked = true;
                    MemorySummaryToggle.Content = "Table";
                }
                if (MemoryGrid != null)
                    MemoryGrid.Visibility = Visibility.Collapsed;
                if (MemoryTreemapHost != null)
                    MemoryTreemapHost.Visibility = Visibility.Visible;
                if (MemoryAttributionGrid != null)
                    MemoryAttributionGrid.Visibility = Visibility.Collapsed;
                if (MemoryPanel != null)
                    MemoryPanel.Visibility = Visibility.Collapsed;
                if (MemoryColumn != null)
                    MemoryColumn.Width = new GridLength(0);
                if (DetailsSplitterColumn != null)
                    DetailsSplitterColumn.Width = new GridLength(0);
                if (DetailsSplitter != null)
                    DetailsSplitter.Visibility = Visibility.Collapsed;
                if (MemorySummaryToggle != null)
                    MemorySummaryToggle.Visibility = Visibility.Collapsed;
                if (MemoryAttributionToggle != null)
                    MemoryAttributionToggle.Visibility = Visibility.Collapsed;
                if (ThreadsGrid != null)
                    ThreadsGrid.Visibility = Visibility.Visible;
                if (ThreadLifecycleGrid != null)
                    ThreadLifecycleGrid.Visibility = Visibility.Collapsed;
                if (TimeTravelStampBlock != null)
                    TimeTravelStampBlock.Text = "LIVE";
                UpdateMemorySummaryMode();
                UpdateDetailsLayout();
                UpdateLiveDataOverlays();
            };
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

    public sealed class MemoryAttributionRow : INotifyPropertyChanged
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

        public void UpdateFrom(MemoryAttributionRow other)
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
