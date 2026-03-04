using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace SleepwalkerInterface
{
    public partial class ThreadStackWindow : Window
    {
        public ObservableCollection<StackFrameRow> Frames { get; } = new();
        private readonly int _pid;
        private readonly int _tid;
        private readonly string _state;
        private ThreadStackResolveResult? _lastResolveResult;

        public ThreadStackWindow(int pid, int tid, string state)
        {
            InitializeComponent();
            WindowThemeHelper.ApplyDarkTitleBar(this);
            _pid = pid;
            _tid = tid;
            _state = state;
            HeaderBlock.Text = $"Thread {_tid} Stack | PID {_pid}";
            StackGrid.ItemsSource = Frames;

            Loaded += async (_, __) => await LoadFramesAsync();
        }

        private async Task LoadFramesAsync()
        {
            try
            {
                NoteBlock.Text = "Resolving stack...";

                var result = await Task.Run(() => ThreadStackResolver.Resolve(_pid, _tid, _state));
                _lastResolveResult = result;

                Frames.Clear();
                foreach (var frame in result.Frames)
                    Frames.Add(frame);

                ThreadMetaBlock.Text =
                    $"TEB: {(result.TebAddress == 0 ? "-" : $"0x{result.TebAddress:X}")}    " +
                    $"StackBase: {(result.StackBase == 0 ? "-" : $"0x{result.StackBase:X}")}    " +
                    $"StackTop: {(result.StackTop == 0 ? "-" : $"0x{result.StackTop:X}")}    " +
                    $"RSP: {(result.StackPointer == 0 ? "-" : $"0x{result.StackPointer:X}")}    " +
                    $"TEB Flags: {(result.TebFlags.HasValue ? $"0x{result.TebFlags.Value:X4}" : "-")}";

                NoteBlock.Text = $"{Frames.Count} frame(s)";
                RenderStackMap(result);
            }
            catch (Exception ex)
            {
                Frames.Clear();
                Frames.Add(new StackFrameRow
                {
                    Index = 0,
                    Address = "-",
                    Module = "-",
                    Symbol = ex.Message
                });
                ThreadMetaBlock.Text = "TEB: -    StackBase: -    StackTop: -    TEB Flags: -";
                NoteBlock.Text = "Failed to resolve stack.";
                _lastResolveResult = null;
                RenderStackMap(null);
            }
        }

        private void StackMapCanvas_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            if (_lastResolveResult != null)
            {
                RenderStackMap(_lastResolveResult);
            }
        }

        private void RenderStackMap(ThreadStackResolveResult? result)
        {
            StackMapCanvas.Children.Clear();

            if (result == null || result.StackBase <= result.StackTop || StackMapCanvas.ActualHeight < 10 || StackMapCanvas.ActualWidth < 10)
            {
                StackMapNoDataOverlay.Visibility = Visibility.Visible;
                StackBaseBlock.Text = "BASE: -";
                StackTopBlock.Text = "TOP: -";
                return;
            }

            StackMapNoDataOverlay.Visibility = Visibility.Collapsed;
            StackBaseBlock.Text = $"BASE: 0x{result.StackBase:X}";
            StackTopBlock.Text = $"TOP: 0x{result.StackTop:X}";

            double w = StackMapCanvas.ActualWidth;
            double h = StackMapCanvas.ActualHeight;
            double x0 = 26;
            double x1 = Math.Max(x0 + 20, w - 10);
            ulong range = result.StackBase - result.StackTop;
            if (range == 0)
            {
                StackMapNoDataOverlay.Visibility = Visibility.Visible;
                return;
            }

            var framePointers = Frames
                .Select(f => f.FramePointerRaw)
                .Where(v => v >= result.StackTop && v <= result.StackBase)
                .Distinct()
                .OrderByDescending(v => v)
                .ToList();

            if (framePointers.Count == 0)
            {
                StackMapNoDataOverlay.Visibility = Visibility.Visible;
                return;
            }

            Brush laneBrush = ResolveBrush("WinSubtleBorderBrush", Color.FromRgb(0x66, 0x66, 0x66));
            Brush frameBrush = ResolveBrush("WinAccentBrush", Color.FromRgb(0x4C, 0x8F, 0xD2));
            Brush rspBrush = ResolveBrush("StatusConnectedBrush", Color.FromRgb(0x59, 0xBA, 0x59));
            Brush textBrush = ResolveBrush("WinMutedTextBrush", Color.FromRgb(0x9A, 0x9A, 0x9A));
            Brush zoomBrush = ResolveBrush("ExplorerOverlayBrush", Color.FromArgb(0x88, 0x18, 0x18, 0x18));
            Brush zoomBorderBrush = ResolveBrush("WinBorderBrush", Color.FromRgb(0x42, 0x42, 0x42));

            static double MapInRange(ulong topAddress, ulong bottomAddress, ulong value, double yTop, double yBottom)
            {
                if (topAddress <= bottomAddress || yBottom <= yTop)
                {
                    return yTop;
                }

                double t = (topAddress - value) / (double)(topAddress - bottomAddress);
                if (t < 0) t = 0;
                if (t > 1) t = 1;
                return yTop + (t * (yBottom - yTop));
            }

            StackMapCanvas.Children.Add(new Rectangle
            {
                Width = x1 - x0,
                Height = h,
                Stroke = laneBrush,
                StrokeThickness = 1
            });
            Canvas.SetLeft(StackMapCanvas.Children[^1], x0);
            Canvas.SetTop(StackMapCanvas.Children[^1], 0);

            ulong usedHigh = framePointers[0];
            ulong usedLow = framePointers[framePointers.Count - 1];
            if (result.StackPointer >= result.StackTop && result.StackPointer <= result.StackBase)
            {
                if (result.StackPointer > usedHigh) usedHigh = result.StackPointer;
                if (result.StackPointer < usedLow) usedLow = result.StackPointer;
            }

            ulong pad = Math.Min((ulong)0x400, Math.Max((ulong)0x80, (usedHigh - usedLow) / 3));
            if (usedHigh + pad < result.StackBase)
            {
                usedHigh += pad;
            }
            else
            {
                usedHigh = result.StackBase;
            }

            if (usedLow > result.StackTop + pad)
            {
                usedLow -= pad;
            }
            else
            {
                usedLow = result.StackTop;
            }

            double zoomYTop = MapInRange(result.StackBase, result.StackTop, usedHigh, 0, h);
            double zoomYBottom = MapInRange(result.StackBase, result.StackTop, usedLow, 0, h);
            if (zoomYBottom < zoomYTop + 20)
            {
                double center = (zoomYTop + zoomYBottom) * 0.5;
                zoomYTop = Math.Max(0, center - 10);
                zoomYBottom = Math.Min(h, center + 10);
            }

            StackMapCanvas.Children.Add(new Rectangle
            {
                Width = x1 - x0,
                Height = Math.Max(1, zoomYBottom - zoomYTop),
                Fill = zoomBrush,
                Stroke = zoomBorderBrush,
                StrokeThickness = 1
            });
            Canvas.SetLeft(StackMapCanvas.Children[^1], x0);
            Canvas.SetTop(StackMapCanvas.Children[^1], zoomYTop);

            double lastLabelY = double.NegativeInfinity;
            const double minLabelGap = 12.0;
            for (int i = 0; i < framePointers.Count; i += 1)
            {
                ulong fp = framePointers[i];
                double y = MapInRange(usedHigh, usedLow, fp, zoomYTop, zoomYBottom);
                y = Math.Max(1, Math.Min(h - 1, y));

                StackMapCanvas.Children.Add(new Line
                {
                    X1 = x0,
                    X2 = x1,
                    Y1 = y,
                    Y2 = y,
                    Stroke = frameBrush,
                    StrokeThickness = 1.0,
                    Opacity = 0.7
                });

                if ((y - lastLabelY) >= minLabelGap)
                {
                    StackMapCanvas.Children.Add(new TextBlock
                    {
                        Text = $"0x{fp:X}",
                        FontSize = 10,
                        Foreground = textBrush
                    });
                    Canvas.SetLeft(StackMapCanvas.Children[^1], x0 + 4);
                    Canvas.SetTop(StackMapCanvas.Children[^1], Math.Max(0, y - 7));
                    lastLabelY = y;
                }
            }

            if (result.StackPointer >= result.StackTop && result.StackPointer <= result.StackBase)
            {
                double rspY = MapInRange(usedHigh, usedLow, result.StackPointer, zoomYTop, zoomYBottom);
                rspY = Math.Max(1, Math.Min(h - 1, rspY));
                StackMapCanvas.Children.Add(new Line
                {
                    X1 = x0 - 10,
                    X2 = x1,
                    Y1 = rspY,
                    Y2 = rspY,
                    Stroke = rspBrush,
                    StrokeThickness = 2.0,
                    Opacity = 0.9
                });
                StackMapCanvas.Children.Add(new TextBlock
                {
                    Text = "RSP",
                    FontSize = 10,
                    FontWeight = FontWeights.Bold,
                    Foreground = rspBrush
                });
                Canvas.SetLeft(StackMapCanvas.Children[^1], 2);
                Canvas.SetTop(StackMapCanvas.Children[^1], Math.Max(0, rspY - 8));
            }
        }

        private static Brush ResolveBrush(string key, Color fallback)
        {
            if (Application.Current?.TryFindResource(key) is Brush brush)
            {
                return brush;
            }

            var created = new SolidColorBrush(fallback);
            created.Freeze();
            return created;
        }

        private void Close_Click(object sender, RoutedEventArgs e) => Close();
    }

    public sealed class StackFrameRow
    {
        public int Index { get; init; }
        public string Address { get; init; } = "";
        public string Module { get; init; } = "";
        public string Symbol { get; init; } = "";
        public ulong InstructionPointerRaw { get; init; }
        public ulong FramePointerRaw { get; init; }
        public string FramePointer => FramePointerRaw == 0 ? "-" : $"0x{FramePointerRaw:X}";
    }
}
