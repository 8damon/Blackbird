using System;
using System.Windows.Controls;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace BlackbirdInterface
{
    public sealed class TimeRangeSelectedEventArgs : EventArgs
    {
        public DateTime StartUtc { get; }
        public DateTime EndUtc { get; }

        public TimeRangeSelectedEventArgs(DateTime startUtc, DateTime endUtc)
        {
            StartUtc = startUtc;
            EndUtc = endUtc;
        }
    }

    public sealed class LaneInteractionEventArgs : EventArgs
    {
        public string LaneKey { get; }     // "Execution" or "Execution/CreateProcess"
        public bool IsArrow { get; }       // clicked the dropdown arrow region
        public MouseButton Button { get; } // left/right click

        public LaneInteractionEventArgs(string laneKey, bool isArrow, MouseButton button)
        {
            LaneKey = laneKey;
            IsArrow = isArrow;
            Button = button;
        }
    }

    public sealed class TelemetryEventSelectedEventArgs : EventArgs
    {
        public TelemetryEvent? Selected { get; }
        public TelemetryEventSelectedEventArgs(TelemetryEvent? selected) => Selected = selected;
    }

    internal sealed class LaneRow
    {
        public string Key = "";
        public string Label = "";
        public bool IsGroupHeader;
        public bool HasChildren;
        public int Indent;
        public Rect Rect;
        public double Y;
        public double Height;
    }

    internal sealed class TimelineEventCluster
    {
        public TelemetryEvent Representative = null!;
        public int Count;
        public DateTime FirstTimestampUtc;
        public DateTime LastTimestampUtc;
        public double RenderX;
        public bool ContainsSelected;
    }

    public sealed class TimelinePauseRange
    {
        public DateTime StartUtc { get; init; }
        public DateTime EndUtc { get; init; }
    }

    public sealed class TimelineControl : FrameworkElement
    {
        public BulkObservableCollection<TelemetryEvent> Items { get; } = new();
        private readonly List<TimelinePauseRange> _pauseRanges = new();

        public DateTime CaptureStartUtc
        {
            get => (DateTime)GetValue(CaptureStartUtcProperty);
            set => SetValue(CaptureStartUtcProperty, value);
        }
        public static readonly DependencyProperty CaptureStartUtcProperty = DependencyProperty.Register(
            nameof(CaptureStartUtc), typeof(DateTime), typeof(TimelineControl),
            new FrameworkPropertyMetadata(DateTime.UtcNow, FrameworkPropertyMetadataOptions.AffectsRender));

        public double ViewDurationSeconds
        {
            get => (double)GetValue(ViewDurationSecondsProperty);
            set => SetValue(ViewDurationSecondsProperty, value);
        }
        public static readonly DependencyProperty ViewDurationSecondsProperty = DependencyProperty.Register(
            nameof(ViewDurationSeconds), typeof(double), typeof(TimelineControl),
            new FrameworkPropertyMetadata(120d, FrameworkPropertyMetadataOptions.AffectsRender));

        public double ViewStartSeconds
        {
            get => (double)GetValue(ViewStartSecondsProperty);
            set => SetValue(ViewStartSecondsProperty, value);
        }
        public static readonly DependencyProperty ViewStartSecondsProperty = DependencyProperty.Register(
            nameof(ViewStartSeconds), typeof(double), typeof(TimelineControl),
            new FrameworkPropertyMetadata(0d, FrameworkPropertyMetadataOptions.AffectsRender));

        public double VerticalOffset
        {
            get => (double)GetValue(VerticalOffsetProperty);
            set => SetValue(VerticalOffsetProperty, value);
        }
        public static readonly DependencyProperty VerticalOffsetProperty = DependencyProperty.Register(
            nameof(VerticalOffset), typeof(double), typeof(TimelineControl),
            new FrameworkPropertyMetadata(0d, FrameworkPropertyMetadataOptions.AffectsRender));

        public double VerticalExtent => _verticalExtent;
        public double VerticalViewport => _verticalViewport;

        public TelemetryEvent? SelectedEvent
        {
            get => (TelemetryEvent?)GetValue(SelectedEventProperty);
            set => SetValue(SelectedEventProperty, value);
        }
        public static readonly DependencyProperty SelectedEventProperty = DependencyProperty.Register(
            nameof(SelectedEvent), typeof(TelemetryEvent), typeof(TimelineControl),
            new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

        public event EventHandler<LaneInteractionEventArgs>? LaneInteraction;
        public event EventHandler<TelemetryEventSelectedEventArgs>? SelectedEventChanged;
        public event EventHandler<TelemetryEventSelectedEventArgs>? EventDoubleClicked;
        public event EventHandler? VerticalMetricsChanged;

        // Layout knobs
        public double LeftGutterWidth { get; set; } = 170;
        public double LaneHeight { get; set; } = 22;
        public double GroupHeaderHeight { get; set; } = 22;
        public double AxisHeight { get; set; } = 24;
        public double TopPadding { get; set; } = 6;
        public double ClusterPixelWidth { get; set; } = 3;
        public bool IsAxisOnly { get; set; } = false;

        private readonly HashSet<string> _hiddenLaneKeys = new(StringComparer.OrdinalIgnoreCase);
        // Collapsed groups. Groups are expanded by default.
        private readonly HashSet<string> _collapsedGroups = new(StringComparer.OrdinalIgnoreCase);

        private readonly Dictionary<string, Brush> _brushByKey = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Brush> _customBrushByKey = new(StringComparer.OrdinalIgnoreCase);

        private readonly List<(Rect rect, TimelineEventCluster cluster)> _hitRects = new();
        private readonly List<LaneRow> _laneRows = new();

        private bool _hasMouse;
        private Point _mouse;

        private TimelineEventCluster? _hoveredCluster;
        private bool _renderQueued;
        private bool _laneRowsDirty = true;
        private bool _suppressItemNotifications;
        private double _verticalExtent = 1;
        private double _verticalViewport = 1;
        private double _verticalOffsetReported = -1;

        public TimelineControl()
        {
            SnapsToDevicePixels = true;
            Focusable = true;

            // Disable hover tooltip popup. Hover still tracks for subtle marker emphasis.
            ToolTip = null;

            Items.CollectionChanged += Items_CollectionChanged;
        }

        private void Items_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
        {
            if (_suppressItemNotifications)
            {
                return;
            }

            _hoveredCluster = null;
            _laneRowsDirty = true;
            RequestRender();
        }

        public void ReplaceItems(IEnumerable<TelemetryEvent> items)
        {
            _suppressItemNotifications = true;
            try
            {
                Items.ReplaceAll(items);
            }
            finally
            {
                _suppressItemNotifications = false;
            }

            _hoveredCluster = null;
            _laneRowsDirty = true;
            RequestRender();
        }

        public void SetPauseRanges(IEnumerable<TimelinePauseRange>? ranges)
        {
            _pauseRanges.Clear();
            if (ranges != null)
            {
                _pauseRanges.AddRange(ranges.Where(x => x.EndUtc > x.StartUtc));
            }

            RequestRender();
        }

        private void RequestRender()
        {
            if (_renderQueued)
            {
                return;
            }

            _renderQueued = true;
            Dispatcher.BeginInvoke(new Action(() =>
                                              {
                                                  _renderQueued = false;
                                                  InvalidateVisual();
                                              }),
                                   System.Windows.Threading.DispatcherPriority.Render);
        }

        public void SetLaneVisible(string laneKey, bool visible)
        {
            if (visible)
                _hiddenLaneKeys.Remove(laneKey);
            else
                _hiddenLaneKeys.Add(laneKey);
            RequestRender();
        }

        public bool IsLaneVisible(string laneKey) => !_hiddenLaneKeys.Contains(laneKey);

        public void ClearAllLaneFilters()
        {
            _hiddenLaneKeys.Clear();
            RequestRender();
        }

        public void SetGroupExpanded(string group, bool expanded)
        {
            if (expanded)
                _collapsedGroups.Remove(group);
            else
                _collapsedGroups.Add(group);
            _laneRowsDirty = true;
            RequestRender();
        }

        public bool IsGroupExpanded(string group) => !_collapsedGroups.Contains(group);

        public void SetLaneColor(string laneKey, Color c)
        {
            var b = new SolidColorBrush(c);
            b.Freeze();
            _customBrushByKey[laneKey] = b;
            RequestRender();
        }

        private Brush BrushForKey(string laneKey)
        {
            if (_customBrushByKey.TryGetValue(laneKey, out var custom))
                return custom;

            if (_brushByKey.TryGetValue(laneKey, out var b))
                return b;

            Color[] palette = {
                Color.FromRgb(0x4C, 0x8F, 0xD2), Color.FromRgb(0x6C, 0xA4, 0xDE), Color.FromRgb(0x8A, 0xB9, 0xE9),
                Color.FromRgb(0x3E, 0x76, 0xAF), Color.FromRgb(0x58, 0xB6, 0x58), Color.FromRgb(0x7B, 0xC7, 0x7B),
                Color.FromRgb(0x8D, 0x97, 0xA3), Color.FromRgb(0x6D, 0x7A, 0x84),
            };

            int h = laneKey.GetHashCode();
            int idx = (h & 0x7fffffff) % palette.Length;

            var brush = new SolidColorBrush(palette[idx]);
            brush.Freeze();
            _brushByKey[laneKey] = brush;
            return brush;
        }

        protected override void OnMouseEnter(MouseEventArgs e)
        {
            bool changed = !_hasMouse;
            _hasMouse = true;
            base.OnMouseEnter(e);
            if (changed)
            {
                RequestRender();
            }
        }

        protected override void OnMouseLeave(MouseEventArgs e)
        {
            bool changed = _hasMouse || _hoveredCluster != null;
            _hasMouse = false;
            _hoveredCluster = null;
            base.OnMouseLeave(e);
            if (changed)
            {
                RequestRender();
            }
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            Point previousMouse = _mouse;
            TimelineEventCluster? previousHoveredCluster = _hoveredCluster;
            _mouse = e.GetPosition(this);
            bool mousePixelChanged = (int)previousMouse.X != (int)_mouse.X || (int)previousMouse.Y != (int)_mouse.Y;

            _hoveredCluster = HitTestCluster(_mouse);
            base.OnMouseMove(e);
            if (!ReferenceEquals(previousHoveredCluster, _hoveredCluster) || mousePixelChanged)
            {
                RequestRender();
            }
        }

        protected override void OnMouseDown(MouseButtonEventArgs e)
        {
            Focus();
            _mouse = e.GetPosition(this);

            // Lane gutter hit-test first (left side)
            if (_mouse.X <= LeftGutterWidth)
            {
                var lane = _laneRows.FirstOrDefault(r => r.Rect.Contains(_mouse));
                if (lane != null && !string.IsNullOrWhiteSpace(lane.Key))
                {
                    // Group headers toggle expansion on click; no separate arrow affordance.
                    if (lane.IsGroupHeader && e.ChangedButton == MouseButton.Left && lane.HasChildren)
                    {
                        bool newExpanded = _collapsedGroups.Contains(lane.Key);
                        SetGroupExpanded(lane.Key, newExpanded);
                        e.Handled = true;
                        return;
                    }

                    LaneInteraction?.Invoke(this, new LaneInteractionEventArgs(lane.Key, false, e.ChangedButton));
                    e.Handled = true;
                    return;
                }
            }

            // Event hit-test: click selects
            if (e.ChangedButton == MouseButton.Left)
            {
                foreach (var (rect, evt) in _hitRects)
                {
                    if (rect.Contains(_mouse))
                    {
                        SelectedEvent = evt.Representative;
                        SelectedEventChanged?.Invoke(this, new TelemetryEventSelectedEventArgs(evt.Representative));
                        if (e.ClickCount >= 2)
                        {
                            EventDoubleClicked?.Invoke(this, new TelemetryEventSelectedEventArgs(evt.Representative));
                        }
                        e.Handled = true;
                        RequestRender();
                        return;
                    }
                }
            }

            base.OnMouseDown(e);
        }

        private TimelineEventCluster? HitTestCluster(Point point)
        {
            foreach (var (rect, cluster) in _hitRects)
            {
                if (rect.Contains(point))
                {
                    return cluster;
                }
            }

            return null;
        }

        protected override void OnMouseUp(MouseButtonEventArgs e)
        {
            base.OnMouseUp(e);
        }

        protected override void OnMouseWheel(MouseWheelEventArgs e)
        {
            bool ctrl = (System.Windows.Input.Keyboard.Modifiers & System.Windows.Input.ModifierKeys.Control) != 0;

            if (ctrl)
            {
                // Horizontal zoom: scale ViewDurationSeconds around the cursor position
                double factor = e.Delta > 0 ? 0.8 : 1.25;
                double newDuration = Math.Max(2, Math.Min(86400, ViewDurationSeconds * factor));
                if (Math.Abs(newDuration - ViewDurationSeconds) > 0.01)
                {
                    var (pps, chartLeft, chartRight, _) = ComputeScale();
                    double cursorSec = ViewStartSeconds + Math.Max(0, _mouse.X - chartLeft) / Math.Max(1, pps);
                    double cursorFrac =
                        Math.Max(0, Math.Min(1, (_mouse.X - chartLeft) / Math.Max(1, chartRight - chartLeft)));
                    ViewStartSeconds = Math.Max(0, cursorSec - newDuration * cursorFrac);
                    ViewDurationSeconds = newDuration;
                    e.Handled = true;
                }
                return;
            }

            double vertViewport = Math.Max(1, _verticalViewport);
            double vertExtent = Math.Max(vertViewport, _verticalExtent);
            double maxOffset = Math.Max(0, vertExtent - vertViewport);
            if (maxOffset > 0.001)
            {
                double step = Math.Max(8, LaneHeight * 1.25);
                double delta = e.Delta > 0 ? -step : step;
                double next = Math.Max(0, Math.Min(maxOffset, VerticalOffset + delta));
                if (Math.Abs(next - VerticalOffset) > 0.01)
                {
                    VerticalOffset = next;
                    e.Handled = true;
                }
                return;
            }

            // No vertical overflow — zoom horizontally
            {
                double factor = e.Delta > 0 ? 0.8 : 1.25;
                double newDuration = Math.Max(2, Math.Min(86400, ViewDurationSeconds * factor));
                if (Math.Abs(newDuration - ViewDurationSeconds) > 0.01)
                {
                    var (pps, chartLeft, chartRight, _) = ComputeScale();
                    double cursorFrac =
                        Math.Max(0, Math.Min(1, (_mouse.X - chartLeft) / Math.Max(1, chartRight - chartLeft)));
                    double cursorSec = ViewStartSeconds + ViewDurationSeconds * cursorFrac;
                    ViewStartSeconds = Math.Max(0, cursorSec - newDuration * cursorFrac);
                    ViewDurationSeconds = newDuration;
                    e.Handled = true;
                }
            }

            base.OnMouseWheel(e);
        }

        private (double pps, double chartLeft, double chartRight, double axisTop) ComputeScale()
        {
            double w = Math.Max(1, ActualWidth);
            double chartLeft = LeftGutterWidth;
            double chartRight = Math.Max(chartLeft + 1, w - 10);
            double chartWidth = chartRight - chartLeft;

            double axisTop = Math.Max(TopPadding + 1, ActualHeight - AxisHeight);

            double pps = chartWidth / Math.Max(1, ViewDurationSeconds);
            return (pps, chartLeft, chartRight, axisTop);
        }

        protected override void OnRender(DrawingContext dc)
        {
            base.OnRender(dc);

            dc.DrawRectangle(UiPalette.SurfaceBrush, null, new Rect(0, 0, ActualWidth, ActualHeight));

            if (IsAxisOnly)
            {
                double axisW = Math.Max(1, ActualWidth);
                double axisH = Math.Max(1, ActualHeight);
                double axisChartLeft = LeftGutterWidth;
                double axisChartRight = Math.Max(axisChartLeft + 1, axisW - 10);
                double axisPps = (axisChartRight - axisChartLeft) / Math.Max(1, ViewDurationSeconds);
                var axisViewStart = CaptureStartUtc + TimeSpan.FromSeconds(ViewStartSeconds);
                var axisViewEnd = axisViewStart + TimeSpan.FromSeconds(ViewDurationSeconds);
                var axisDpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
                var axisTypeface = new Typeface("Segoe UI Variable Text, Segoe UI, Aptos");
                double savedAxisHeight = AxisHeight;
                AxisHeight = axisH;
                DrawTimeGridAndAxis(dc, axisViewStart, axisViewEnd, axisPps, axisChartLeft, axisChartRight, 0, axisDpi,
                                    axisTypeface);
                AxisHeight = savedAxisHeight;
                return;
            }

            _hitRects.Clear();

            var dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
            var typeface = new Typeface("Segoe UI Variable Text, Segoe UI, Aptos");

            var (pps, chartLeft, chartRight, axisTop) = ComputeScale();

            var viewStartUtc = CaptureStartUtc + TimeSpan.FromSeconds(ViewStartSeconds);
            var viewEndUtc = viewStartUtc + TimeSpan.FromSeconds(ViewDurationSeconds);

            EnsureLaneRows();
            double contentHeight =
                Math.Max(1, (_laneRows.Count == 0 ? 0 : _laneRows[^1].Y + _laneRows[^1].Height) - TopPadding);
            double viewportHeight = Math.Max(1, axisTop - TopPadding);
            double maxVerticalOffset = Math.Max(0, contentHeight - viewportHeight);
            double effectiveVerticalOffset = Math.Max(0, Math.Min(maxVerticalOffset, VerticalOffset));
            if (Math.Abs(effectiveVerticalOffset - VerticalOffset) > 0.01)
            {
                VerticalOffset = effectiveVerticalOffset;
            }
            UpdateVerticalMetrics(contentHeight, viewportHeight, effectiveVerticalOffset);

            // Draw lane separators + labels
            DrawLaneGutter(dc, axisTop, effectiveVerticalOffset, dpi, typeface);

            // Draw grid + bottom x-axis
            DrawTimeGridAndAxis(dc, viewStartUtc, viewEndUtc, pps, chartLeft, chartRight, axisTop, dpi, typeface);

            DrawPauseRanges(dc, viewStartUtc, viewEndUtc, pps, chartLeft, axisTop);

            // Collapse dense event bursts into lane/pixel clusters before drawing.
            var eventsByLane = BuildVisibleLaneClusters(viewStartUtc, viewEndUtc, pps, chartLeft, chartRight);

            // Plot events into visible lanes
            foreach (var lane in _laneRows.Where(r => !r.IsGroupHeader))
            {
                if (_hiddenLaneKeys.Contains(lane.Key))
                    continue;

                if (!eventsByLane.TryGetValue(lane.Key, out var laneEvents))
                    continue;

                double yTop = lane.Y - effectiveVerticalOffset + 3;
                double barH = Math.Max(6, lane.Height - 6);
                if (yTop + barH < 0 || yTop > axisTop)
                    continue;
                foreach (var cluster in laneEvents)
                {
                    double x = cluster.RenderX;

                    double centerY = yTop + (barH / 2);
                    double radius = Math.Max(3.0, Math.Min(7.0, barH * 0.42));
                    if (cluster.Count > 1)
                    {
                        radius = Math.Min(11.0, radius + Math.Log(cluster.Count, 2) * 0.55);
                    }
                    var rect = new Rect(x - radius, centerY - radius, radius * 2, radius * 2);

                    var fill = CreateEventFillBrush(BrushForKey(lane.Key), cluster.ContainsSelected);
                    var diamond = CreateDiamondGeometry(x, centerY, radius);
                    dc.DrawGeometry(fill, null, diamond);

                    if (cluster.Count > 1)
                    {
                        var clusterPen = new Pen(UiPalette.BorderBrush, 1);
                        clusterPen.Freeze();
                        dc.DrawGeometry(null, clusterPen, CreateDiamondGeometry(x, centerY, radius + 1));
                    }

                    // Selection / hover outline
                    if (cluster.ContainsSelected)
                    {
                        var selectionFill = new SolidColorBrush(Color.FromArgb(90, 0x72, 0xD2, 0xFF));
                        selectionFill.Freeze();
                        dc.DrawGeometry(selectionFill, null, CreateDiamondGeometry(x, centerY, radius + 3.2));

                        var pen = new Pen(new SolidColorBrush(Color.FromRgb(0x8C, 0xE2, 0xFF)), 2.2);
                        pen.Freeze();
                        dc.DrawGeometry(null, pen, CreateDiamondGeometry(x, centerY, radius + 3.6));
                    }
                    else if (ReferenceEquals(cluster, _hoveredCluster))
                    {
                        var pen = new Pen(UiPalette.GridStrongBrush, 1.3);
                        pen.Freeze();
                        dc.DrawGeometry(null, pen, CreateDiamondGeometry(x, centerY, radius + 1));
                    }

                    double hitPadding = cluster.Count > 1 ? 5 : 3;
                    var hitRect = new Rect(rect.X - hitPadding, rect.Y - hitPadding, rect.Width + (hitPadding * 2),
                                           rect.Height + (hitPadding * 2));
                    _hitRects.Add((hitRect, cluster));
                }
            }

            // Repaint axis/time labels over points so timestamps always stay readable.
            DrawTimeAxisOverlay(dc, viewStartUtc, viewEndUtc, pps, chartLeft, chartRight, axisTop, dpi, typeface);

            // Crosshair line + time label
            if (_hasMouse && _mouse.X >= chartLeft && _mouse.X <= chartRight && _mouse.Y <= axisTop)
            {
                var crossPen = new Pen(UiPalette.GridStrongBrush, 1);
                crossPen.Freeze();
                dc.DrawLine(crossPen, new Point(_mouse.X, 0), new Point(_mouse.X, axisTop));

                double hoverSeconds = ViewStartSeconds + (_mouse.X - chartLeft) / pps;
                if (hoverSeconds < 0)
                    hoverSeconds = 0;

                var hoverUtc = CaptureStartUtc + TimeSpan.FromSeconds(hoverSeconds);
                string tLabel = hoverUtc.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture) + "Z";

                var ft = new FormattedText(tLabel, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, typeface,
                                           11, UiPalette.TextBrush, dpi);

                double labelX = Math.Min(chartRight - ft.Width - 14, Math.Max(chartLeft + 4, _mouse.X + 8));
                double labelY = axisTop + Math.Max(2, (AxisHeight - ft.Height - 6) / 2);
                var bgRect = new Rect(labelX, labelY, ft.Width + 10, ft.Height + 6);
                dc.DrawRectangle(UiPalette.SurfaceAltBrush, new Pen(UiPalette.BorderBrush, 1), bgRect);
                dc.DrawText(ft, new Point(labelX + 5, labelY + 3));
            }

            if (_hasMouse && _hoveredCluster != null)
            {
                DrawHoverEventCard(dc, _hoveredCluster, _mouse, axisTop, chartLeft, chartRight, dpi, typeface);
            }
        }

        private static StreamGeometry CreateDiamondGeometry(double x, double centerY, double radius)
        {
            var diamond = new StreamGeometry();
            using (var ctx = diamond.Open())
            {
                ctx.BeginFigure(new Point(x, centerY - radius), true, true);
                ctx.LineTo(new Point(x + radius, centerY), true, false);
                ctx.LineTo(new Point(x, centerY + radius), true, false);
                ctx.LineTo(new Point(x - radius, centerY), true, false);
            }
            diamond.Freeze();
            return diamond;
        }

        private static Brush CreateEventFillBrush(Brush source, bool selected)
        {
            if (source is SolidColorBrush solid)
            {
                byte alpha = selected ? (byte)0xE0 : (byte)0x9E;
                var brush = new SolidColorBrush(Color.FromArgb(alpha, solid.Color.R, solid.Color.G, solid.Color.B));
                brush.Freeze();
                return brush;
            }

            Brush clone = source.Clone();
            clone.Opacity = selected ? 0.88 : 0.62;
            if (clone.CanFreeze)
            {
                clone.Freeze();
            }

            return clone;
        }

        private static void DrawHoverEventCard(DrawingContext dc, TimelineEventCluster cluster, Point mouse,
                                               double axisTop, double chartLeft, double chartRight, double dpi,
                                               Typeface typeface)
        {
            string title = BuildHoverTitle(cluster);
            string detail = BuildHoverDetail(cluster);
            var titleFt = new FormattedText(title, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, typeface,
                                            11, UiPalette.TextBrush, dpi);
            var detailFt = new FormattedText(detail, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, typeface,
                                             10, UiPalette.MutedTextBrush, dpi);

            double width = Math.Min(420, Math.Max(260, Math.Max(titleFt.Width, detailFt.Width) + 18));
            double height = titleFt.Height + detailFt.Height + 12;
            double x = Math.Min(chartRight - width - 6, Math.Max(chartLeft + 6, mouse.X + 12));
            double y = mouse.Y - height - 12;
            if (y < 4)
            {
                y = Math.Min(axisTop - height - 4, mouse.Y + 12);
            }
            y = Math.Max(4, Math.Min(axisTop - height - 4, y));

            dc.DrawRectangle(UiPalette.SurfaceAltBrush, new Pen(UiPalette.BorderBrush, 1),
                             new Rect(x, y, width, height));
            dc.DrawText(titleFt, new Point(x + 7, y + 3));
            dc.DrawText(detailFt, new Point(x + 7, y + 5 + titleFt.Height));
        }

        private void DrawPauseRanges(DrawingContext dc, DateTime viewStartUtc, DateTime viewEndUtc, double pps,
                                     double chartLeft, double axisTop)
        {
            if (_pauseRanges.Count == 0)
            {
                return;
            }

            var fill = new SolidColorBrush(Color.FromArgb(56, 0xF1, 0xD1, 0x5A));
            fill.Freeze();
            var edge = new Pen(new SolidColorBrush(Color.FromArgb(170, 0xE6, 0xBE, 0x3B)), 1);
            edge.Freeze();

            foreach (TimelinePauseRange range in _pauseRanges)
            {
                DateTime start = range.StartUtc < viewStartUtc ? viewStartUtc : range.StartUtc;
                DateTime end = range.EndUtc > viewEndUtc ? viewEndUtc : range.EndUtc;
                if (end <= start)
                {
                    continue;
                }

                double x1 = chartLeft + (start - viewStartUtc).TotalSeconds * pps;
                double x2 = chartLeft + (end - viewStartUtc).TotalSeconds * pps;
                if (x2 <= x1)
                {
                    x2 = x1 + 1;
                }

                dc.DrawRectangle(fill, edge, new Rect(x1, 0, x2 - x1, axisTop));
            }
        }

        private static string BuildHoverTitle(TimelineEventCluster cluster)
        {
            TelemetryEvent ev = cluster.Representative;
            string group = string.IsNullOrWhiteSpace(ev.Group) ? "Other" : ev.Group.Trim();
            string subType = string.IsNullOrWhiteSpace(ev.SubType) ? "event" : ev.SubType.Trim();
            if (cluster.Count <= 1)
            {
                return $"{ev.TimestampUtc:HH:mm:ss.fff}Z  {group}/{subType}";
            }

            return $"{cluster.Count} events  {group}/{subType}";
        }

        private static string BuildHoverDetail(TimelineEventCluster cluster)
        {
            TelemetryEvent ev = cluster.Representative;
            string summary = string.IsNullOrWhiteSpace(ev.Summary) ? "No summary" : ev.Summary.Trim();
            if (summary.Length > 120)
            {
                summary = summary[..120] + "...";
            }

            if (cluster.Count > 1)
            {
                string span =
                    cluster.FirstTimestampUtc == cluster.LastTimestampUtc
                        ? cluster.FirstTimestampUtc.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture) + "Z"
                        : $"{cluster.FirstTimestampUtc:HH:mm:ss.fff}Z \u2192 {cluster.LastTimestampUtc:HH:mm:ss.fff}Z";
                return $"PID {ev.PID}  TID {ev.TID}  {span}  {summary}";
            }

            return $"PID {ev.PID}  TID {ev.TID}  {summary}";
        }

        private void EnsureLaneRows()
        {
            if (!_laneRowsDirty)
            {
                return;
            }

            _laneRowsDirty = false;
            BuildLaneRows();
        }

        private void BuildLaneRows()
        {
            _laneRows.Clear();

            // Groups and subtypes currently observed
            var groups = Items.GroupBy(e => e.Group ?? "Other", StringComparer.OrdinalIgnoreCase)
                             .OrderBy(g => GroupSortRank(g.Key))
                             .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                             .ToList();

            double y = TopPadding;
            foreach (var g in groups)
            {
                var subTypes = g.Select(e => e.SubType ?? "")
                                   .Where(s => !string.IsNullOrWhiteSpace(s))
                                   .Distinct(StringComparer.OrdinalIgnoreCase)
                                   .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                                   .ToList();

                bool hasChildren = subTypes.Count > 0;
                bool expanded = hasChildren && !_collapsedGroups.Contains(g.Key);

                // Group header row
                var header =
                    new LaneRow { Key = g.Key, Label = g.Key, IsGroupHeader = true,      HasChildren = hasChildren,
                                  Indent = 0,  Y = y,         Height = GroupHeaderHeight };
                header.Rect = new Rect(0, y, LeftGutterWidth, header.Height);
                _laneRows.Add(header);
                y += header.Height;

                if (!expanded)
                {
                    // Collapsed: show aggregate lane (same key as group)
                    var lane = new LaneRow { Key = g.Key, Label = "All", IsGroupHeader = false, HasChildren = false,
                                             Indent = 14, Y = y,         Height = LaneHeight };
                    lane.Rect = new Rect(0, y, LeftGutterWidth, lane.Height);
                    _laneRows.Add(lane);
                    y += lane.Height;
                }
                else
                {
                    // Expanded: show one lane per subtype
                    foreach (var st in subTypes)
                    {
                        var laneKey = $"{g.Key}/{st}";
                        var lane = new LaneRow { Key = laneKey, Label = st, IsGroupHeader = false, HasChildren = false,
                                                 Indent = 18,   Y = y,      Height = LaneHeight };
                        lane.Rect = new Rect(0, y, LeftGutterWidth, lane.Height);
                        _laneRows.Add(lane);
                        y += lane.Height;
                    }
                }
            }
        }

        private static int GroupSortRank(string group)
        {
            if (string.IsNullOrWhiteSpace(group))
            {
                return 50;
            }

            return group.StartsWith("Filesystem", StringComparison.OrdinalIgnoreCase) ? 200 : 100;
        }

        private Dictionary<string, List<TimelineEventCluster>> BuildVisibleLaneClusters(DateTime viewStartUtc,
                                                                                        DateTime viewEndUtc, double pps,
                                                                                        double chartLeft,
                                                                                        double chartRight)
        {
            var byLane =
                new Dictionary<string, Dictionary<int, TimelineEventCluster>>(StringComparer.OrdinalIgnoreCase);
            double clusterWidth = Math.Max(1, ClusterPixelWidth);

            foreach (var ev in Items)
            {
                if (ev.TimestampUtc < viewStartUtc || ev.TimestampUtc > viewEndUtc)
                    continue;

                double rawX = chartLeft + (ev.TimestampUtc - viewStartUtc).TotalSeconds * pps;
                if (rawX < chartLeft || rawX > chartRight)
                    continue;

                int pixelBucket = (int)Math.Floor((rawX - chartLeft) / clusterWidth);
                string groupKey = ev.Group ?? "Other";
                AddCluster(byLane, groupKey, pixelBucket, rawX, ev, ReferenceEquals(ev, SelectedEvent));

                if (!string.IsNullOrWhiteSpace(ev.SubType))
                {
                    string subtypeKey = $"{groupKey}/{ev.SubType}";
                    AddCluster(byLane, subtypeKey, pixelBucket, rawX, ev, ReferenceEquals(ev, SelectedEvent));
                }
            }

            return byLane.ToDictionary(pair => pair.Key, pair => pair.Value.Values.OrderBy(x => x.RenderX).ToList(),
                                       StringComparer.OrdinalIgnoreCase);
        }

        private static void AddCluster(Dictionary<string, Dictionary<int, TimelineEventCluster>> byLane, string laneKey,
                                       int pixelBucket, double rawX, TelemetryEvent ev, bool containsSelected)
        {
            if (!byLane.TryGetValue(laneKey, out Dictionary<int, TimelineEventCluster>? laneClusters))
            {
                laneClusters = new Dictionary<int, TimelineEventCluster>();
                byLane[laneKey] = laneClusters;
            }

            if (!laneClusters.TryGetValue(pixelBucket, out TimelineEventCluster? cluster))
            {
                laneClusters[pixelBucket] = new TimelineEventCluster { Representative = ev,
                                                                       Count = 1,
                                                                       FirstTimestampUtc = ev.TimestampUtc,
                                                                       LastTimestampUtc = ev.TimestampUtc,
                                                                       RenderX = rawX,
                                                                       ContainsSelected = containsSelected };
                return;
            }

            cluster.Count += 1;
            if (ev.TimestampUtc < cluster.FirstTimestampUtc)
            {
                cluster.FirstTimestampUtc = ev.TimestampUtc;
            }

            if (ev.TimestampUtc > cluster.LastTimestampUtc)
            {
                cluster.LastTimestampUtc = ev.TimestampUtc;
                if (!cluster.ContainsSelected)
                {
                    cluster.Representative = ev;
                    cluster.RenderX = rawX;
                }
            }

            if (containsSelected)
            {
                cluster.Representative = ev;
                cluster.RenderX = rawX;
            }

            cluster.ContainsSelected |= containsSelected;
        }

        private void DrawLaneGutter(DrawingContext dc, double axisTop, double verticalOffset, double dpi,
                                    Typeface typeface)
        {
            var sepPen = new Pen(UiPalette.GridBrush, 1);
            sepPen.Freeze();

            // Gutter divider
            var gutterPen = new Pen(UiPalette.BorderBrush, 1);
            gutterPen.Freeze();
            dc.DrawLine(gutterPen, new Point(LeftGutterWidth, 0), new Point(LeftGutterWidth, ActualHeight));

            foreach (var row in _laneRows)
            {
                double drawY = row.Y - verticalOffset;
                row.Rect = new Rect(0, drawY, LeftGutterWidth, row.Height);
                if (drawY + row.Height < 0 || drawY > axisTop)
                {
                    continue;
                }

                dc.DrawLine(sepPen, new Point(0, drawY), new Point(ActualWidth, drawY));

                // Label text
                var color = row.IsGroupHeader ? UiPalette.Text : UiPalette.MutedText;
                var ft = new FormattedText(row.Label, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, typeface,
                                           row.IsGroupHeader ? 12 : 11, new SolidColorBrush(color), dpi);

                double x = 10 + row.Indent;
                dc.DrawText(ft, new Point(x, drawY + 3));

                // Disabled indicator
                if (_hiddenLaneKeys.Contains(row.Key))
                {
                    var dim = new SolidColorBrush(Color.FromArgb(70, 0xA0, 0xA0, 0xA0));
                    dim.Freeze();
                    dc.DrawRectangle(dim, null, new Rect(0, drawY, LeftGutterWidth, row.Height));
                }
            }
        }

        private void UpdateVerticalMetrics(double extent, double viewport, double offset)
        {
            double normExtent = Math.Max(1, extent);
            double normViewport = Math.Max(1, viewport);
            if (Math.Abs(_verticalExtent - normExtent) > 0.1 || Math.Abs(_verticalViewport - normViewport) > 0.1 ||
                Math.Abs(_verticalOffsetReported - offset) > 0.1)
            {
                _verticalExtent = normExtent;
                _verticalViewport = normViewport;
                _verticalOffsetReported = offset;
                VerticalMetricsChanged?.Invoke(this, EventArgs.Empty);
            }
        }

        private void DrawTimeGridAndAxis(DrawingContext dc, DateTime viewStartUtc, DateTime viewEndUtc, double pps,
                                         double chartLeft, double chartRight, double axisTop, double dpi,
                                         Typeface typeface)
        {
            double seconds = (viewEndUtc - viewStartUtc).TotalSeconds;

            double baseStep = seconds <= 30 ? 1 : seconds <= 120 ? 5 : seconds <= 300 ? 10 : 30;

            // Keep labels readable; don't crowd timestamps.
            double minLabelSpacingPx = 70;
            double minStepFromPixels = minLabelSpacingPx / Math.Max(1, pps);
            double step = NiceTimeStep(Math.Max(baseStep, minStepFromPixels));

            var gridPen = new Pen(UiPalette.GridBrush, 1);
            gridPen.Freeze();

            // Axis bar background
            dc.DrawRectangle(UiPalette.SurfaceAltBrush, null,
                             new Rect(chartLeft, axisTop, chartRight - chartLeft, AxisHeight));

            // Axis top line
            var axisPen = new Pen(UiPalette.BorderBrush, 1);
            axisPen.Freeze();
            dc.DrawLine(axisPen, new Point(chartLeft, axisTop), new Point(chartRight, axisTop));

            double startSec = Math.Floor(ViewStartSeconds / step) * step;
            double endSec = ViewStartSeconds + ViewDurationSeconds;

            for (double t = startSec; t <= endSec + 0.0001; t += step)
            {
                double x = chartLeft + (t - ViewStartSeconds) * pps;
                if (x < chartLeft || x > chartRight)
                    continue;

                // Vertical grid
                dc.DrawLine(gridPen, new Point(x, 0), new Point(x, axisTop));

                var tickUtc = CaptureStartUtc + TimeSpan.FromSeconds(t);
                string label = tickUtc.ToString("HH:mm:ss", CultureInfo.InvariantCulture);

                var ft = new FormattedText(label, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, typeface, 10,
                                           UiPalette.MutedTextBrush, dpi);

                dc.DrawText(ft, new Point(x + 4, axisTop + 4));
            }
        }

        private static double NiceTimeStep(double minStep)
        {
            double[] steps = { 1, 2, 5, 10, 15, 30, 60, 120, 300, 600 };
            foreach (var s in steps)
            {
                if (s >= minStep)
                    return s;
            }

            return 600;
        }

        private void DrawTimeAxisOverlay(DrawingContext dc, DateTime viewStartUtc, DateTime viewEndUtc, double pps,
                                         double chartLeft, double chartRight, double axisTop, double dpi,
                                         Typeface typeface)
        {
            double seconds = (viewEndUtc - viewStartUtc).TotalSeconds;
            double baseStep = seconds <= 30 ? 1 : seconds <= 120 ? 5 : seconds <= 300 ? 10 : 30;

            double minLabelSpacingPx = 70;
            double minStepFromPixels = minLabelSpacingPx / Math.Max(1, pps);
            double step = NiceTimeStep(Math.Max(baseStep, minStepFromPixels));

            // Axis bar background and top border.
            dc.DrawRectangle(UiPalette.SurfaceAltBrush, null,
                             new Rect(chartLeft, axisTop, chartRight - chartLeft, AxisHeight));
            var axisPen = new Pen(UiPalette.BorderBrush, 1);
            axisPen.Freeze();
            dc.DrawLine(axisPen, new Point(chartLeft, axisTop), new Point(chartRight, axisTop));

            double startSec = Math.Floor(ViewStartSeconds / step) * step;
            double endSec = ViewStartSeconds + ViewDurationSeconds;
            for (double t = startSec; t <= endSec + 0.0001; t += step)
            {
                double x = chartLeft + (t - ViewStartSeconds) * pps;
                if (x < chartLeft || x > chartRight)
                    continue;

                var tickUtc = CaptureStartUtc + TimeSpan.FromSeconds(t);
                string label = tickUtc.ToString("HH:mm:ss", CultureInfo.InvariantCulture);

                var ft = new FormattedText(label, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, typeface, 10,
                                           UiPalette.MutedTextBrush, dpi);

                dc.DrawText(ft, new Point(x + 4, axisTop + 4));
            }
        }

        private static string ToLaneKey(TelemetryEvent e)
        {
            if (string.IsNullOrWhiteSpace(e.SubType))
                return e.Group;
            return $"{e.Group}/{e.SubType}";
        }

        private static bool EventBelongsToLane(TelemetryEvent e, string laneKey)
        {
            if (string.IsNullOrWhiteSpace(laneKey))
                return false;

            if (laneKey.Contains('/'))
                return string.Equals(ToLaneKey(e), laneKey, StringComparison.OrdinalIgnoreCase);

            // Collapsed group lane should aggregate all subtypes in that group.
            return string.Equals(e.Group, laneKey, StringComparison.OrdinalIgnoreCase);
        }
    }
}
