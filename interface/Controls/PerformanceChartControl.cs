using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;

namespace BlackbirdInterface
{
    public enum SeriesScale
    {
        Percent,
        AutoToViewMax
    }

    public enum ChartValueFormat
    {
        Auto,
        Percent,
        Bytes,
        BytesPerSecond,
        CountPerSecond,
        Raw
    }

    public sealed class ChartSeries
    {
        public string Name { get; }
        public Brush Stroke { get; }
        public SeriesScale Scale { get; }
        public ChartValueFormat ValueFormat { get; }
        public double SmoothingAlpha { get; }
        public Func<PerformanceSample, double> Selector { get; }

        public ChartSeries(
            string name,
            Brush stroke,
            SeriesScale scale,
            Func<PerformanceSample, double> selector,
            ChartValueFormat valueFormat = ChartValueFormat.Auto,
            double smoothingAlpha = 0)
        {
            Name = name;
            Stroke = stroke;
            Scale = scale;
            ValueFormat = valueFormat;
            SmoothingAlpha = Math.Clamp(smoothingAlpha, 0d, 1d);
            Selector = selector;
        }
    }

    public sealed class PerformanceChartControl : FrameworkElement
    {
        public static readonly DependencyProperty TitleProperty =
            DependencyProperty.Register(nameof(Title), typeof(string), typeof(PerformanceChartControl),
                new FrameworkPropertyMetadata("", FrameworkPropertyMetadataOptions.AffectsRender));

        public string Title
        {
            get => (string)GetValue(TitleProperty);
            set => SetValue(TitleProperty, value);
        }

        private DateTime _viewStartUtc;
        private DateTime _viewEndUtc;
        private readonly List<PerformanceSample> _samples = new();
        private ChartSeries[] _series = Array.Empty<ChartSeries>();
        private double _smoothedAutoScaleMax = 1.0;
        private bool _hasMouse;
        private Point _mouse;
        private readonly ToolTip _tip = new();

        public PerformanceChartControl()
        {
            ClipToBounds = true;
            ToolTip = _tip;
            _tip.Placement = PlacementMode.RelativePoint;
            _tip.PlacementTarget = this;
            _tip.HorizontalOffset = 12;
            _tip.VerticalOffset = 12;
            _tip.StaysOpen = true;
        }

        public void SetSeries(IEnumerable<ChartSeries> series)
        {
            _series = series.ToArray();
            InvalidateVisual();
        }

        public void SetView(DateTime viewStartUtc, DateTime viewEndUtc)
        {
            _viewStartUtc = viewStartUtc;
            _viewEndUtc = viewEndUtc;
            InvalidateVisual();
        }

        public void PushSample(PerformanceSample s)
        {
            _samples.Add(s);
            // Keep a rolling window
            if (_samples.Count > 4000)
                _samples.RemoveRange(0, _samples.Count - 4000);

            InvalidateVisual();
        }

        public void ClearSamples()
        {
            _samples.Clear();
            InvalidateVisual();
        }

        public void SetSamples(IEnumerable<PerformanceSample> samples)
        {
            _samples.Clear();
            _samples.AddRange(samples);
            if (_samples.Count > 4000)
                _samples.RemoveRange(0, _samples.Count - 4000);
            InvalidateVisual();
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            _hasMouse = true;
            _mouse = e.GetPosition(this);
            InvalidateVisual();
            base.OnMouseMove(e);
        }

        protected override void OnMouseLeave(MouseEventArgs e)
        {
            _hasMouse = false;
            _tip.IsOpen = false;
            InvalidateVisual();
            base.OnMouseLeave(e);
        }

        protected override void OnRender(DrawingContext dc)
        {
            base.OnRender(dc);

            var w = ActualWidth;
            var h = ActualHeight;
            if (w < 50 || h < 50) return;

            // Frame
            dc.DrawRectangle(UiPalette.SurfaceBrush,
                new Pen(UiPalette.BorderBrush, 1),
                new Rect(0, 0, w, h));

            // Layout
            double padL = 92;
            double padR = 14;
            double padT = 48;
            double padB = 22;

            var plot = new Rect(padL, padT, Math.Max(1, w - padL - padR), Math.Max(1, h - padT - padB));

            // Title
            DrawText(dc, Title, 12, FontWeights.SemiBold, UiPalette.TextBrush, new Point(8, 5));
            DrawLegend(dc, new Rect(padL, 3, Math.Max(1, w - padL - padR), 18));

            DateTime renderStartUtc = _viewStartUtc;
            DateTime renderEndUtc = _viewEndUtc;
            if (renderEndUtc <= renderStartUtc)
            {
                renderEndUtc = renderStartUtc + TimeSpan.FromSeconds(1);
            }
            AdjustRightAnchoredLiveWindow(ref renderStartUtc, ref renderEndUtc);

            // Filter samples within effective view
            var viewSamples = _samples.Where(s => s.TimestampUtc >= renderStartUtc && s.TimestampUtc <= renderEndUtc).ToList();
            if (viewSamples.Count < 2 || _series.Length == 0)
            {
                DrawAxes(dc, plot, renderStartUtc, renderEndUtc, 100.0, ChartValueFormat.Percent);
                DrawText(dc, "NO DATA", 18, FontWeights.Bold, UiPalette.MutedTextBrush,
                    new Point(plot.Left + (plot.Width * 0.5) - 40, plot.Top + (plot.Height * 0.5) - 10));
                _tip.IsOpen = false;
                return;
            }

            var seriesValues = new Dictionary<ChartSeries, List<(PerformanceSample sample, double value)>>(_series.Length);
            foreach (var ser in _series)
            {
                bool hasSmoothed = false;
                double smoothed = 0;
                var values = new List<(PerformanceSample sample, double value)>(viewSamples.Count);
                foreach (var sample in viewSamples)
                {
                    double raw = ser.Selector(sample);
                    double value = ApplySmoothing(raw, ser.SmoothingAlpha, ref hasSmoothed, ref smoothed);
                    values.Add((sample, value));
                }
                seriesValues[ser] = values;
            }

            bool hasAutoScale = _series.Any(s => s.Scale == SeriesScale.AutoToViewMax);
            double autoScaleMax = 1.0;
            ChartValueFormat autoScaleFormat = ChartValueFormat.Raw;
            if (hasAutoScale)
            {
                foreach (var ser in _series.Where(s => s.Scale == SeriesScale.AutoToViewMax))
                {
                    if (autoScaleFormat == ChartValueFormat.Raw || autoScaleFormat == ChartValueFormat.Auto)
                        autoScaleFormat = ser.ValueFormat;

                    foreach (var point in seriesValues[ser])
                    {
                        if (point.value > autoScaleMax) autoScaleMax = point.value;
                    }
                }
            }

            double yAxisMax;
            if (hasAutoScale)
            {
                double target = Math.Max(1.0, autoScaleMax);
                if (target >= _smoothedAutoScaleMax)
                {
                    // rise quickly to new peaks
                    _smoothedAutoScaleMax = (_smoothedAutoScaleMax * 0.35) + (target * 0.65);
                }
                else
                {
                    // decay slowly to avoid axis jitter
                    _smoothedAutoScaleMax = (_smoothedAutoScaleMax * 0.90) + (target * 0.10);
                }
                yAxisMax = Math.Max(1.0, _smoothedAutoScaleMax);
            }
            else
            {
                _smoothedAutoScaleMax = 1.0;
                yAxisMax = 100.0;
            }
            DrawAxes(dc, plot, renderStartUtc, renderEndUtc, yAxisMax, hasAutoScale ? autoScaleFormat : ChartValueFormat.Percent);

            (ChartSeries ser, PerformanceSample sample, Point point, double raw)? hover = null;
            double hoverDist = double.MaxValue;

            // Draw series (clipped to plot bounds)
            double viewSeconds = (renderEndUtc - renderStartUtc).TotalSeconds;
            if (viewSeconds <= 0)
                viewSeconds = 1;

            dc.PushClip(new RectangleGeometry(plot));
            foreach (var ser in _series)
            {
                var pen = new Pen(ser.Stroke, 1.15);
                pen.Freeze();

                var geo = new StreamGeometry();
                using (var g = geo.Open())
                {
                    bool started = false;
                    if (viewSamples[0].TimestampUtc > renderStartUtc)
                    {
                        var first = seriesValues[ser][0];
                        double raw0 = first.value;
                        double scaled0 = ser.Scale == SeriesScale.Percent
                            ? Clamp(raw0, 0, 100)
                            : Clamp(raw0 / yAxisMax * 100.0, 0, 100);
                        double y0 = plot.Bottom - (scaled0 / 100.0) * plot.Height;
                        g.BeginFigure(new Point(plot.Left, y0), false, false);
                        started = true;
                    }

                    foreach (var point in seriesValues[ser])
                    {
                        double raw = point.value;
                        double scaledPercent = ser.Scale == SeriesScale.Percent
                            ? Clamp(raw, 0, 100)
                            : Clamp(raw / yAxisMax * 100.0, 0, 100);

                        double xNorm = (point.sample.TimestampUtc - renderStartUtc).TotalSeconds / viewSeconds; // 0..1
                        double x = plot.Left + xNorm * plot.Width;
                        double y = plot.Bottom - (scaledPercent / 100.0) * plot.Height;

                        if (_hasMouse && _mouse.X >= plot.Left && _mouse.X <= plot.Right && _mouse.Y >= plot.Top && _mouse.Y <= plot.Bottom)
                        {
                            double dist = Math.Abs(_mouse.X - x) + (Math.Abs(_mouse.Y - y) * 0.35);
                            if (dist < hoverDist)
                            {
                                hoverDist = dist;
                                hover = (ser, point.sample, new Point(x, y), raw);
                            }
                        }

                        if (!started)
                        {
                            g.BeginFigure(new Point(x, y), false, false);
                            started = true;
                        }
                        else
                        {
                            g.LineTo(new Point(x, y), true, false);
                        }
                    }

                }
                geo.Freeze();

                dc.DrawGeometry(null, pen, geo);
            }
            dc.Pop();

            if (hover != null)
            {
                var cross = new Pen(UiPalette.GridStrongBrush, 1);
                cross.Freeze();
                dc.DrawLine(cross, new Point(hover.Value.point.X, plot.Top), new Point(hover.Value.point.X, plot.Bottom));

                var markerBrush = new SolidColorBrush(Color.FromArgb(220, UiPalette.Text.R, UiPalette.Text.G, UiPalette.Text.B));
                markerBrush.Freeze();
                dc.DrawEllipse(markerBrush, new Pen(hover.Value.ser.Stroke, 1.4), hover.Value.point, 3.6, 3.6);

                _tip.Content =
                    $"{hover.Value.ser.Name}\n" +
                    $"{hover.Value.sample.TimestampUtc:HH:mm:ss.fff}Z\n" +
                    $"{FormatValue(hover.Value.ser, hover.Value.raw)}";
                _tip.PlacementRectangle = new Rect(_mouse.X, _mouse.Y, 0, 0);
                _tip.IsOpen = true;
            }
            else
            {
                _tip.IsOpen = false;
            }
        }

        private void DrawAxes(
            DrawingContext dc,
            Rect plot,
            DateTime viewStartUtc,
            DateTime viewEndUtc,
            double axisMaxValue,
            ChartValueFormat valueFormat)
        {
            var axisPen = new Pen(UiPalette.GridStrongBrush, 1);
            axisPen.Freeze();

            // Outer plot border
            dc.DrawRectangle(null, axisPen, plot);

            // Y ticks
            int yTicks = plot.Height < 95 ? 3 : 5;
            for (int i = 0; i <= yTicks; i++)
            {
                double pct = i * (100.0 / yTicks);
                double y = plot.Bottom - (pct / 100.0) * plot.Height;
                double axisValue = axisMaxValue * (i / (double)yTicks);

                dc.DrawLine(new Pen(UiPalette.GridBrush, 1), new Point(plot.Left, y), new Point(plot.Right, y));
                DrawText(dc, FormatAxisValue(axisValue, valueFormat), 10, FontWeights.Normal,
                    UiPalette.MutedTextBrush, new Point(6, y - 7));
            }

            // X ticks
            var total = (viewEndUtc - viewStartUtc).TotalSeconds;
            if (total <= 0) total = 1;

            int ticks = plot.Width < 280 ? 3 : 5;
            for (int i = 0; i <= ticks; i++)
            {
                double xNorm = i / (double)ticks;
                double x = plot.Left + xNorm * plot.Width;
                dc.DrawLine(new Pen(UiPalette.GridBrush, 1), new Point(x, plot.Top), new Point(x, plot.Bottom));

                var t = viewStartUtc.AddSeconds(total * xNorm);
                double tx = Math.Max(plot.Left, Math.Min(plot.Right - 42, x - 22));
                string text = plot.Width < 280
                    ? t.ToString("HH:mm", CultureInfo.InvariantCulture)
                    : t.ToString("HH:mm:ss", CultureInfo.InvariantCulture);
                DrawText(dc, text, 10, FontWeights.Normal,
                    UiPalette.MutedTextBrush, new Point(tx, plot.Bottom + 2));
            }
        }

        private void DrawLegend(DrawingContext dc, Rect legendArea)
        {
            if (_series.Length == 0) return;

            double x = legendArea.Left + 4;
            double y = legendArea.Top + 2;
            double maxX = legendArea.Right - 90;

            foreach (var ser in _series)
            {
                if (x > maxX)
                    break;

                dc.DrawRectangle(ser.Stroke, null, new Rect(x, y + 3, 10, 10));
                DrawText(dc, ser.Name, 10, FontWeights.Normal, UiPalette.MutedTextBrush, new Point(x + 14, y));
                x += 14 + Math.Max(52, (ser.Name.Length * 6.8));
            }
        }

        private static void DrawText(DrawingContext dc, string text, double size, FontWeight weight, Brush brush, Point p)
        {
            var ft = new FormattedText(
                text,
                CultureInfo.InvariantCulture,
                FlowDirection.LeftToRight,
                new Typeface(new FontFamily("Segoe UI"), FontStyles.Normal, weight, FontStretches.Normal),
                size,
                brush,
                1.0);

            dc.DrawText(ft, p);
        }

        private static string FormatValue(ChartSeries ser, double raw)
        {
            return FormatAxisValue(raw, ser.ValueFormat);
        }

        private static string FormatAxisValue(double value, ChartValueFormat format)
        {
            return format switch
            {
                ChartValueFormat.Percent => value.ToString("0.##", CultureInfo.InvariantCulture) + "%",
                ChartValueFormat.Bytes => FormatBytes(value),
                ChartValueFormat.BytesPerSecond => FormatBytes(value) + "/s",
                ChartValueFormat.CountPerSecond => value.ToString("0.##", CultureInfo.InvariantCulture) + "/s",
                ChartValueFormat.Raw => value.ToString("0.##", CultureInfo.InvariantCulture),
                _ => value.ToString("0.##", CultureInfo.InvariantCulture)
            };
        }

        private static string FormatBytes(double value)
        {
            if (value >= 1024d * 1024 * 1024)
                return (value / (1024d * 1024 * 1024)).ToString("0.##", CultureInfo.InvariantCulture) + " GB";
            if (value >= 1024d * 1024)
                return (value / (1024d * 1024)).ToString("0.##", CultureInfo.InvariantCulture) + " MB";
            if (value >= 1024d)
                return (value / 1024d).ToString("0.##", CultureInfo.InvariantCulture) + " KB";
            return value.ToString("0.##", CultureInfo.InvariantCulture) + " B";
        }

        private void AdjustRightAnchoredLiveWindow(ref DateTime viewStartUtc, ref DateTime viewEndUtc)
        {
            if (_samples.Count == 0 || viewEndUtc <= viewStartUtc)
            {
                return;
            }

            DateTime latestSampleUtc = _samples[^1].TimestampUtc;
            if (latestSampleUtc == default || viewEndUtc <= latestSampleUtc)
            {
                return;
            }

            // Only right-anchor in live/near-live windows. Historical windows keep absolute timestamps unchanged.
            if (viewEndUtc < DateTime.UtcNow - TimeSpan.FromSeconds(3))
            {
                return;
            }

            TimeSpan span = viewEndUtc - viewStartUtc;
            TimeSpan slack = viewEndUtc - latestSampleUtc;
            if (slack <= TimeSpan.Zero)
            {
                return;
            }

            if (slack > span)
            {
                slack = span;
            }

            viewStartUtc -= slack;
            viewEndUtc -= slack;
        }

        private static double ApplySmoothing(double value, double smoothingAlpha, ref bool hasSmoothed, ref double smoothed)
        {
            if (smoothingAlpha <= 0)
            {
                return value;
            }

            if (!hasSmoothed)
            {
                smoothed = value;
                hasSmoothed = true;
                return smoothed;
            }

            smoothed += (value - smoothed) * smoothingAlpha;
            return smoothed;
        }

        private static double Clamp(double v, double min, double max)
            => v < min ? min : (v > max ? max : v);
    }
}
