using System;
using System.Windows.Controls;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;

namespace SleepwalkerInterface
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
        public string LaneKey { get; }          // "Execution" or "Execution/CreateProcess"
        public bool IsArrow { get; }            // clicked the dropdown arrow region
        public MouseButton Button { get; }      // left/right click

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

    public sealed class TimelineControl : FrameworkElement
    {
        public ObservableCollection<TelemetryEvent> Items { get; } = new();

        public DateTime CaptureStartUtc
        {
            get => (DateTime)GetValue(CaptureStartUtcProperty);
            set => SetValue(CaptureStartUtcProperty, value);
        }
        public static readonly DependencyProperty CaptureStartUtcProperty =
            DependencyProperty.Register(nameof(CaptureStartUtc), typeof(DateTime), typeof(TimelineControl),
                new FrameworkPropertyMetadata(DateTime.UtcNow, FrameworkPropertyMetadataOptions.AffectsRender));

        public double ViewDurationSeconds
        {
            get => (double)GetValue(ViewDurationSecondsProperty);
            set => SetValue(ViewDurationSecondsProperty, value);
        }
        public static readonly DependencyProperty ViewDurationSecondsProperty =
            DependencyProperty.Register(nameof(ViewDurationSeconds), typeof(double), typeof(TimelineControl),
                new FrameworkPropertyMetadata(120d, FrameworkPropertyMetadataOptions.AffectsRender));

        public double ViewStartSeconds
        {
            get => (double)GetValue(ViewStartSecondsProperty);
            set => SetValue(ViewStartSecondsProperty, value);
        }
        public static readonly DependencyProperty ViewStartSecondsProperty =
            DependencyProperty.Register(nameof(ViewStartSeconds), typeof(double), typeof(TimelineControl),
                new FrameworkPropertyMetadata(0d, FrameworkPropertyMetadataOptions.AffectsRender));

        public TelemetryEvent? SelectedEvent
        {
            get => (TelemetryEvent?)GetValue(SelectedEventProperty);
            set => SetValue(SelectedEventProperty, value);
        }
        public static readonly DependencyProperty SelectedEventProperty =
            DependencyProperty.Register(nameof(SelectedEvent), typeof(TelemetryEvent), typeof(TimelineControl),
                new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

        public event EventHandler<TimeRangeSelectedEventArgs>? RangeSelected;
        public event EventHandler<LaneInteractionEventArgs>? LaneInteraction;
        public event EventHandler<TelemetryEventSelectedEventArgs>? SelectedEventChanged;

        // Layout knobs
        public double LeftGutterWidth { get; set; } = 170;
        public double LaneHeight { get; set; } = 22;
        public double GroupHeaderHeight { get; set; } = 22;
        public double AxisHeight { get; set; } = 24;
        public double TopPadding { get; set; } = 6;

        private readonly HashSet<string> _hiddenLaneKeys = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _expandedGroups = new(StringComparer.OrdinalIgnoreCase);

        private readonly Dictionary<string, Brush> _brushByKey = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Brush> _customBrushByKey = new(StringComparer.OrdinalIgnoreCase);

        private readonly List<(Rect rect, TelemetryEvent evt)> _hitRects = new();
        private readonly List<LaneRow> _laneRows = new();

        private bool _hasMouse;
        private Point _mouse;

        private bool _selectingRange;
        private Point _selStart;
        private Point _selEnd;

        private readonly ToolTip _tip = new();
        private TelemetryEvent? _hoveredEvent;

        public TimelineControl()
        {
            SnapsToDevicePixels = true;
            Focusable = true;

            ToolTipService.SetInitialShowDelay(this, 0);
            ToolTipService.SetShowDuration(this, 60000);
            ToolTipService.SetBetweenShowDelay(this, 0);

            _tip.Placement = PlacementMode.Mouse;
            _tip.Background = UiPalette.SurfaceBrush;
            _tip.Foreground = UiPalette.TextBrush;
            _tip.BorderThickness = new Thickness(1);
            _tip.BorderBrush = UiPalette.BorderBrush;
            _tip.Padding = new Thickness(6);
            ToolTip = _tip;

            Items.CollectionChanged += Items_CollectionChanged;
        }

        private void Items_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e) => InvalidateVisual();

        public void SetLaneVisible(string laneKey, bool visible)
        {
            if (visible) _hiddenLaneKeys.Remove(laneKey);
            else _hiddenLaneKeys.Add(laneKey);
            InvalidateVisual();
        }

        public bool IsLaneVisible(string laneKey) => !_hiddenLaneKeys.Contains(laneKey);

        public void ClearAllLaneFilters()
        {
            _hiddenLaneKeys.Clear();
            InvalidateVisual();
        }

        public void SetGroupExpanded(string group, bool expanded)
        {
            if (expanded) _expandedGroups.Add(group);
            else _expandedGroups.Remove(group);
            InvalidateVisual();
        }

        public bool IsGroupExpanded(string group) => _expandedGroups.Contains(group);

        public void SetLaneColor(string laneKey, Color c)
        {
            var b = new SolidColorBrush(c);
            b.Freeze();
            _customBrushByKey[laneKey] = b;
            InvalidateVisual();
        }

        private Brush BrushForKey(string laneKey)
        {
            if (_customBrushByKey.TryGetValue(laneKey, out var custom))
                return custom;

            if (_brushByKey.TryGetValue(laneKey, out var b))
                return b;

            Color[] palette =
            {
                Color.FromRgb(0x4C,0x8F,0xD2),
                Color.FromRgb(0x6C,0xA4,0xDE),
                Color.FromRgb(0x8A,0xB9,0xE9),
                Color.FromRgb(0x3E,0x76,0xAF),
                Color.FromRgb(0x58,0xB6,0x58),
                Color.FromRgb(0x7B,0xC7,0x7B),
                Color.FromRgb(0x8D,0x97,0xA3),
                Color.FromRgb(0x6D,0x7A,0x84),
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
            _hasMouse = true;
            base.OnMouseEnter(e);
            InvalidateVisual();
        }

        protected override void OnMouseLeave(MouseEventArgs e)
        {
            _hasMouse = false;
            _tip.IsOpen = false;
            _hoveredEvent = null;
            base.OnMouseLeave(e);
            InvalidateVisual();
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            _mouse = e.GetPosition(this);

            if (_selectingRange)
            {
                _selEnd = _mouse;
                InvalidateVisual();
                return;
            }

            // Hover hit-test
            _hoveredEvent = null;
            foreach (var (rect, evt) in _hitRects)
            {
                if (rect.Contains(_mouse))
                {
                    _hoveredEvent = evt;
                    _tip.Content =
                        $"{evt.Type}\n" +
                        $"t={evt.TimestampUtc:HH:mm:ss.fff}Z  PID={evt.PID}  TID={evt.TID}\n" +
                        $"{(string.IsNullOrWhiteSpace(evt.Summary) ? evt.Details : evt.Summary)}";

                    _tip.IsOpen = true;
                    InvalidateVisual();
                    return;
                }
            }

            _tip.IsOpen = false;
            base.OnMouseMove(e);
            InvalidateVisual();
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
                        bool newExpanded = !_expandedGroups.Contains(lane.Key);
                        SetGroupExpanded(lane.Key, newExpanded);
                        e.Handled = true;
                        return;
                    }

                    LaneInteraction?.Invoke(this, new LaneInteractionEventArgs(lane.Key, false, e.ChangedButton));
                    e.Handled = true;
                    return;
                }
            }

            // Event hit-test: click selects (no need to drag)
            if (e.ChangedButton == MouseButton.Left)
            {
                foreach (var (rect, evt) in _hitRects)
                {
                    if (rect.Contains(_mouse))
                    {
                        SelectedEvent = evt;
                        SelectedEventChanged?.Invoke(this, new TelemetryEventSelectedEventArgs(evt));
                        e.Handled = true;
                        InvalidateVisual();
                        return;
                    }
                }

                // Otherwise start range selection
                _selectingRange = true;
                _selStart = _mouse;
                _selEnd = _selStart;
                CaptureMouse();
                InvalidateVisual();
            }

            base.OnMouseDown(e);
        }

        protected override void OnMouseUp(MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left && _selectingRange)
            {
                _selectingRange = false;
                ReleaseMouseCapture();

                var range = SelectionToTimeRange(_selStart, _selEnd);
                if (range != null)
                    RangeSelected?.Invoke(this, range);

                InvalidateVisual();
            }

            base.OnMouseUp(e);
        }

        private TimeRangeSelectedEventArgs? SelectionToTimeRange(Point a, Point b)
        {
            double x1 = Math.Min(a.X, b.X);
            double x2 = Math.Max(a.X, b.X);

            if (Math.Abs(x2 - x1) < 6)
                return null;

            var (pps, chartLeft, chartRight, axisTop) = ComputeScale();

            x1 = Math.Max(chartLeft, Math.Min(chartRight, x1));
            x2 = Math.Max(chartLeft, Math.Min(chartRight, x2));

            double t1 = ViewStartSeconds + (x1 - chartLeft) / pps;
            double t2 = ViewStartSeconds + (x2 - chartLeft) / pps;

            var startUtc = CaptureStartUtc + TimeSpan.FromSeconds(t1);
            var endUtc = CaptureStartUtc + TimeSpan.FromSeconds(t2);

            if (endUtc < startUtc) (startUtc, endUtc) = (endUtc, startUtc);

            return new TimeRangeSelectedEventArgs(startUtc, endUtc);
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

            _hitRects.Clear();
            _laneRows.Clear();

            var dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
            var typeface = new Typeface("Segoe UI");

            var (pps, chartLeft, chartRight, axisTop) = ComputeScale();

            var viewStartUtc = CaptureStartUtc + TimeSpan.FromSeconds(ViewStartSeconds);
            var viewEndUtc = viewStartUtc + TimeSpan.FromSeconds(ViewDurationSeconds);

            // Build lane rows from current data
            BuildLaneRows(axisTop);

            // Draw lane separators + labels
            DrawLaneGutter(dc, dpi, typeface);

            // Draw grid + bottom x-axis
            DrawTimeGridAndAxis(dc, viewStartUtc, viewEndUtc, pps, chartLeft, chartRight, axisTop, dpi, typeface);

            // Plot events into visible lanes
            foreach (var lane in _laneRows.Where(r => !r.IsGroupHeader))
            {
                if (_hiddenLaneKeys.Contains(lane.Key))
                    continue;

                double yTop = lane.Y + 3;
                double barH = Math.Max(6, lane.Height - 6);
                string laneKey = lane.Key;

                foreach (var ev in Items)
                {
                    if (!EventBelongsToLane(ev, laneKey))
                        continue;

                    if (ev.TimestampUtc < viewStartUtc || ev.TimestampUtc > viewEndUtc)
                        continue;

                    double x = chartLeft + (ev.TimestampUtc - viewStartUtc).TotalSeconds * pps;

                    double centerY = yTop + (barH / 2);
                    double radius = Math.Max(3.0, Math.Min(7.0, barH * 0.42));
                    var rect = new Rect(x - radius, centerY - radius, radius * 2, radius * 2);

                    var fill = BrushForKey(laneKey);
                    var diamond = new StreamGeometry();
                    using (var ctx = diamond.Open())
                    {
                        ctx.BeginFigure(new Point(x, centerY - radius), true, true);
                        ctx.LineTo(new Point(x + radius, centerY), true, false);
                        ctx.LineTo(new Point(x, centerY + radius), true, false);
                        ctx.LineTo(new Point(x - radius, centerY), true, false);
                    }
                    diamond.Freeze();
                    dc.DrawGeometry(fill, null, diamond);

                    // Selection / hover outline
                    if (ReferenceEquals(ev, SelectedEvent))
                    {
                        var pen = new Pen(UiPalette.AccentBrush, 1.5);
                        pen.Freeze();
                        dc.DrawRectangle(null, pen, new Rect(rect.X - 2, rect.Y - 2, rect.Width + 4, rect.Height + 4));
                    }
                    else if (ReferenceEquals(ev, _hoveredEvent))
                    {
                        var pen = new Pen(UiPalette.GridStrongBrush, 1);
                        pen.Freeze();
                        dc.DrawRectangle(null, pen, new Rect(rect.X - 1, rect.Y - 1, rect.Width + 2, rect.Height + 2));
                    }

                    var hitRect = new Rect(rect.X - 3, rect.Y - 3, rect.Width + 6, rect.Height + 6);
                    _hitRects.Add((hitRect, ev));
                }
            }

            // Crosshair line + time label
            if (_hasMouse && _mouse.X >= chartLeft && _mouse.X <= chartRight && _mouse.Y <= axisTop)
            {
                var crossPen = new Pen(UiPalette.GridStrongBrush, 1);
                crossPen.Freeze();
                dc.DrawLine(crossPen, new Point(_mouse.X, 0), new Point(_mouse.X, axisTop));

                double hoverSeconds = ViewStartSeconds + (_mouse.X - chartLeft) / pps;
                if (hoverSeconds < 0) hoverSeconds = 0;

                var hoverUtc = CaptureStartUtc + TimeSpan.FromSeconds(hoverSeconds);
                string tLabel = hoverUtc.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture) + "Z";

                var ft = new FormattedText(
                    tLabel,
                    CultureInfo.InvariantCulture,
                    FlowDirection.LeftToRight,
                    typeface,
                    11,
                    UiPalette.TextBrush,
                    dpi);

                var isDark = UiPalette.Text.R < 0x80;
                var labelBg = new SolidColorBrush(isDark
                    ? Color.FromArgb(235, 0x2B, 0x2F, 0x34)
                    : Color.FromArgb(235, 0xF8, 0xF8, 0xF8));
                labelBg.Freeze();

                var bgRect = new Rect(_mouse.X + 8, 4, ft.Width + 10, ft.Height + 6);
                dc.DrawRectangle(labelBg, new Pen(UiPalette.BorderBrush, 1), bgRect);
                dc.DrawText(ft, new Point(_mouse.X + 13, 7));
            }

            // Range selection overlay
            if (_selectingRange)
            {
                double x1 = Math.Min(_selStart.X, _selEnd.X);
                double x2 = Math.Max(_selStart.X, _selEnd.X);

                var accent = UiPalette.Accent;
                var selBrush = new SolidColorBrush(Color.FromArgb(55, accent.R, accent.G, accent.B));
                selBrush.Freeze();
                var selPen = new Pen(new SolidColorBrush(Color.FromArgb(120, accent.R, accent.G, accent.B)), 1);
                selPen.Freeze();

                dc.DrawRectangle(selBrush, selPen, new Rect(x1, 0, x2 - x1, axisTop));
            }
        }

        private void BuildLaneRows(double axisTop)
        {
            // Groups and subtypes currently observed
            var groups = Items
                .GroupBy(e => e.Group ?? "Other", StringComparer.OrdinalIgnoreCase)
                .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .ToList();

            double y = TopPadding;
            foreach (var g in groups)
            {
                var subTypes = g
                    .Select(e => e.SubType ?? "")
                    .Where(s => !string.IsNullOrWhiteSpace(s))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                bool hasChildren = subTypes.Count > 0;
                bool expanded = hasChildren && _expandedGroups.Contains(g.Key);

                // Group header row
                var header = new LaneRow
                {
                    Key = g.Key,
                    Label = g.Key,
                    IsGroupHeader = true,
                    HasChildren = hasChildren,
                    Indent = 0,
                    Y = y,
                    Height = GroupHeaderHeight
                };
                header.Rect = new Rect(0, y, LeftGutterWidth, header.Height);
                _laneRows.Add(header);
                y += header.Height;

                if (!expanded)
                {
                    // Collapsed: show aggregate lane (same key as group)
                    var lane = new LaneRow
                    {
                        Key = g.Key,
                        Label = "All",
                        IsGroupHeader = false,
                        HasChildren = false,
                        Indent = 14,
                        Y = y,
                        Height = LaneHeight
                    };
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
                        var lane = new LaneRow
                        {
                            Key = laneKey,
                            Label = st,
                            IsGroupHeader = false,
                            HasChildren = false,
                            Indent = 18,
                            Y = y,
                            Height = LaneHeight
                        };
                        lane.Rect = new Rect(0, y, LeftGutterWidth, lane.Height);
                        _laneRows.Add(lane);
                        y += lane.Height;
                    }
                }

                // stop if we're going to overlap the axis
                if (y >= axisTop - 4)
                    break;
            }
        }

        private void DrawLaneGutter(DrawingContext dc, double dpi, Typeface typeface)
        {
            var sepPen = new Pen(UiPalette.GridBrush, 1);
            sepPen.Freeze();

            // Gutter divider
            var gutterPen = new Pen(UiPalette.BorderBrush, 1);
            gutterPen.Freeze();
            dc.DrawLine(gutterPen, new Point(LeftGutterWidth, 0), new Point(LeftGutterWidth, ActualHeight));

            foreach (var row in _laneRows)
            {
                dc.DrawLine(sepPen, new Point(0, row.Y), new Point(ActualWidth, row.Y));

                // Label text
                var color = row.IsGroupHeader ? UiPalette.Text : UiPalette.MutedText;
                var ft = new FormattedText(
                    row.Label,
                    CultureInfo.InvariantCulture,
                    FlowDirection.LeftToRight,
                    typeface,
                    row.IsGroupHeader ? 12 : 11,
                    new SolidColorBrush(color),
                    dpi);

                double x = 10 + row.Indent;
                dc.DrawText(ft, new Point(x, row.Y + 3));

                // Disabled indicator
                if (_hiddenLaneKeys.Contains(row.Key))
                {
                    var dim = new SolidColorBrush(Color.FromArgb(70, 0xA0, 0xA0, 0xA0));
                    dim.Freeze();
                    dc.DrawRectangle(dim, null, new Rect(0, row.Y, LeftGutterWidth, row.Height));
                }
            }
        }

        private void DrawTimeGridAndAxis(DrawingContext dc, DateTime viewStartUtc, DateTime viewEndUtc,
                                         double pps, double chartLeft, double chartRight,
                                         double axisTop, double dpi, Typeface typeface)
        {
            double seconds = (viewEndUtc - viewStartUtc).TotalSeconds;

            double baseStep =
                seconds <= 30 ? 1 :
                seconds <= 120 ? 5 :
                seconds <= 300 ? 10 :
                30;

            // Keep labels readable; don't crowd timestamps.
            double minLabelSpacingPx = 70;
            double minStepFromPixels = minLabelSpacingPx / Math.Max(1, pps);
            double step = NiceTimeStep(Math.Max(baseStep, minStepFromPixels));

            var gridPen = new Pen(UiPalette.GridBrush, 1);
            gridPen.Freeze();

            // Axis bar background
            dc.DrawRectangle(UiPalette.SurfaceAltBrush, null, new Rect(chartLeft, axisTop, chartRight - chartLeft, AxisHeight));

            // Axis top line
            var axisPen = new Pen(UiPalette.BorderBrush, 1);
            axisPen.Freeze();
            dc.DrawLine(axisPen, new Point(chartLeft, axisTop), new Point(chartRight, axisTop));

            double startSec = Math.Floor(ViewStartSeconds / step) * step;
            double endSec = ViewStartSeconds + ViewDurationSeconds;

            for (double t = startSec; t <= endSec + 0.0001; t += step)
            {
                double x = chartLeft + (t - ViewStartSeconds) * pps;
                if (x < chartLeft || x > chartRight) continue;

                // Vertical grid
                dc.DrawLine(gridPen, new Point(x, 0), new Point(x, axisTop));

                var tickUtc = CaptureStartUtc + TimeSpan.FromSeconds(t);
                string label = tickUtc.ToString("HH:mm:ss", CultureInfo.InvariantCulture);

                var ft = new FormattedText(
                    label,
                    CultureInfo.InvariantCulture,
                    FlowDirection.LeftToRight,
                    typeface,
                    10,
                    UiPalette.MutedTextBrush,
                    dpi);

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
