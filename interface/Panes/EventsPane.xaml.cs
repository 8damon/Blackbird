using System;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace SleepwalkerInterface
{
    public sealed class EventLogEntryOpenRequestedEventArgs : EventArgs
    {
        public string Group { get; }
        public string SubType { get; }
        public string Summary { get; }
        public TelemetryEvent? Event { get; }

        public EventLogEntryOpenRequestedEventArgs(string group, string subType, string summary, TelemetryEvent? ev = null)
        {
            Group = group ?? string.Empty;
            SubType = subType ?? string.Empty;
            Summary = summary ?? string.Empty;
            Event = ev;
        }
    }

    public partial class EventsPane : UserControl
    {
        public event RoutedEventHandler? CloseRequested;
        public event RoutedEventHandler? FloatRequested;
        public event RoutedEventHandler? SettingsRequested;
        public event RoutedEventHandler? LogPopoutRequested;
        public event EventHandler<EventLogEntryOpenRequestedEventArgs>? EventLogEntryOpenRequested;
        public event EventHandler<PaneHeaderDragEventArgs>? HeaderDragStarted;
        public event EventHandler<PaneHeaderDragEventArgs>? HeaderDragDelta;
        public event EventHandler<PaneHeaderDragEventArgs>? HeaderDragCompleted;

        private bool _headerMouseDown;
        private bool _headerDragging;
        private Point _headerMouseDownPos;
        private bool _hasData;
        private bool _connectivityHealthy = true;
        private bool _eventLogDetached;

        public EventsPane()
        {
            InitializeComponent();
            EventTimeline.VerticalMetricsChanged += EventTimeline_VerticalMetricsChanged;
            EventTimeline.SizeChanged += (_, __) => SyncTimelineVerticalScroll();
            TimelineVerticalScroll.ValueChanged += TimelineVerticalScroll_ValueChanged;
            Loaded += (_, __) => SyncTimelineVerticalScroll();
            UpdateNoDataOverlay();
        }

        public TimelineControl Timeline => EventTimeline;
        public ScrollBar Scroll => TimelineScroll;
        public DataGrid Grid => EventGrid;

        public Button BtnCloseRef => BtnClose;
        public Button BtnFloatRef => BtnFloat;
        public Button BtnSettingsRef => BtnSettings;
        public Button BtnLogPopoutRef => BtnLogPopout;

        public void SetHasData(bool hasData)
        {
            _hasData = hasData;
            UpdateNoDataOverlay();
        }

        public void SetConnectivityHealthy(bool healthy)
        {
            _connectivityHealthy = healthy;
            UpdateNoDataOverlay();
        }

        public void SetEventLogDetached(bool detached)
        {
            _eventLogDetached = detached;
            EventLogRow.Height = detached ? new GridLength(0) : new GridLength(1, GridUnitType.Star);
            EventLogBorder.Visibility = detached ? Visibility.Collapsed : Visibility.Visible;
            BtnLogPopout.ToolTip = detached ? "Re-attach event log" : "Detach event log";
            BtnLogPopout.Content = detached ? "⇲" : "⇱";
        }

        public void SetHeaderStats(string statsText)
        {
            if (HeaderStatsBlock == null)
            {
                return;
            }

            HeaderStatsBlock.Text = string.IsNullOrWhiteSpace(statsText)
                ? "View 0 | Total 0 | 0.0/s"
                : statsText.Trim();
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e) => CloseRequested?.Invoke(this, e);
        private void BtnFloat_Click(object sender, RoutedEventArgs e) => FloatRequested?.Invoke(this, e);
        private void BtnSettings_Click(object sender, RoutedEventArgs e) => SettingsRequested?.Invoke(this, e);
        private void BtnLogPopout_Click(object sender, RoutedEventArgs e) => LogPopoutRequested?.Invoke(this, e);
        private void EventGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            TelemetryEvent? ev = GetEventFromSource(e.OriginalSource as DependencyObject)
                ?? EventGrid.SelectedItem as TelemetryEvent;
            if (ev == null)
                return;

            EventLogEntryOpenRequested?.Invoke(
                this,
                new EventLogEntryOpenRequestedEventArgs(ev.Group ?? string.Empty, ev.SubType ?? string.Empty, ev.Summary ?? string.Empty, ev));
        }

        private static TelemetryEvent? GetEventFromSource(DependencyObject? source)
        {
            while (source != null)
            {
                if (source is DataGridRow row && row.Item is TelemetryEvent ev)
                {
                    return ev;
                }

                source = VisualTreeHelper.GetParent(source);
            }

            return null;
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

        private void UpdateNoDataOverlay()
        {
            EventsNoDataOverlay.Visibility = (_hasData && _connectivityHealthy) ? Visibility.Collapsed : Visibility.Visible;
        }

        private void EventTimeline_VerticalMetricsChanged(object? sender, EventArgs e)
        {
            _ = sender;
            _ = e;
            SyncTimelineVerticalScroll();
        }

        private void TimelineVerticalScroll_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            _ = sender;
            if (EventTimeline == null || TimelineVerticalScroll == null)
            {
                return;
            }

            double viewport = Math.Max(1, TimelineVerticalScroll.ViewportSize);
            double maxStart = Math.Max(0, TimelineVerticalScroll.Maximum - viewport);
            double clamped = Math.Max(0, Math.Min(maxStart, e.NewValue));
            if (Math.Abs(EventTimeline.VerticalOffset - clamped) > 0.1)
            {
                EventTimeline.VerticalOffset = clamped;
            }
        }

        private void SyncTimelineVerticalScroll()
        {
            if (EventTimeline == null || TimelineVerticalScroll == null)
            {
                return;
            }

            double viewport = Math.Max(1, EventTimeline.VerticalViewport);
            double extent = Math.Max(viewport, EventTimeline.VerticalExtent);

            TimelineVerticalScroll.Minimum = 0;
            TimelineVerticalScroll.ViewportSize = viewport;
            TimelineVerticalScroll.Maximum = extent;
            TimelineVerticalScroll.SmallChange = Math.Max(8, EventTimeline.LaneHeight);
            TimelineVerticalScroll.LargeChange = Math.Max(32, viewport * 0.75);

            double maxStart = Math.Max(0, extent - viewport);
            double target = Math.Max(0, Math.Min(maxStart, EventTimeline.VerticalOffset));
            if (Math.Abs(TimelineVerticalScroll.Value - target) > 0.1)
            {
                TimelineVerticalScroll.Value = target;
            }

            TimelineVerticalScroll.Visibility = Visibility.Collapsed;
        }
    }
}
