using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Windows;
using System.Windows.Media;

namespace SleepwalkerInterface
{
    public sealed class SparklinePreviewControl : FrameworkElement
    {
        public static readonly DependencyProperty ValuesProperty =
            DependencyProperty.Register(nameof(Values),
                typeof(INotifyCollectionChanged),
                typeof(SparklinePreviewControl),
                new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, OnValuesChanged));

        public static readonly DependencyProperty StrokeProperty =
            DependencyProperty.Register(nameof(Stroke),
                typeof(Brush),
                typeof(SparklinePreviewControl),
                new FrameworkPropertyMetadata(new SolidColorBrush(Color.FromRgb(0x97, 0xA1, 0xAD)), FrameworkPropertyMetadataOptions.AffectsRender));

        public INotifyCollectionChanged? Values
        {
            get => (INotifyCollectionChanged?)GetValue(ValuesProperty);
            set => SetValue(ValuesProperty, value);
        }

        public Brush Stroke
        {
            get => (Brush)GetValue(StrokeProperty);
            set => SetValue(StrokeProperty, value);
        }

        private static void OnValuesChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            if (d is not SparklinePreviewControl c) return;

            if (e.OldValue is INotifyCollectionChanged oldObs)
                oldObs.CollectionChanged -= c.OnCollectionChanged;

            if (e.NewValue is INotifyCollectionChanged newObs)
                newObs.CollectionChanged += c.OnCollectionChanged;
        }

        private void OnCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
            => Dispatcher.Invoke(InvalidateVisual);

        protected override void OnRender(DrawingContext dc)
        {
            base.OnRender(dc);

            var w = ActualWidth;
            var h = ActualHeight;
            if (w <= 4 || h <= 4)
                return;

            // Background is set by parent card; keep this transparent.

            // Try to read values (we expect ObservableCollection<double>)
            if (DataContext is GraphExplorerItem item)
            {
                Draw(dc, w, h, item.PreviewValues, Stroke);
            }
        }

        private static void Draw(DrawingContext dc, double w, double h, IList<double> vals, Brush stroke)
        {
            if (vals.Count < 2) return;

            double min = double.MaxValue, max = double.MinValue;
            for (int i = 0; i < vals.Count; i++)
            {
                var v = vals[i];
                if (v < min) min = v;
                if (v > max) max = v;
            }
            if (Math.Abs(max - min) < 1e-9)
            {
                min -= 1;
                max += 1;
            }

            var pen = new Pen(stroke, 1.5);
            pen.Freeze();

            var geo = new StreamGeometry();
            using (var g = geo.Open())
            {
                for (int i = 0; i < vals.Count; i++)
                {
                    double x = (i / (double)(vals.Count - 1)) * (w - 2) + 1;
                    double t = (vals[i] - min) / (max - min);
                    double y = (1.0 - t) * (h - 2) + 1;

                    if (i == 0) g.BeginFigure(new Point(x, y), false, false);
                    else g.LineTo(new Point(x, y), true, false);
                }
            }
            geo.Freeze();

            dc.DrawGeometry(null, pen, geo);
        }
    }
}
