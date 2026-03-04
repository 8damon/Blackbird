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
            double xContext = 10;
            double x0 = 28;
            double x1 = Math.Max(x0 + 20, w - 8);

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
            Brush contextBrush = ResolveBrush("WinBorderBrush", Color.FromRgb(0x48, 0x48, 0x48));

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

            ulong usedHigh = framePointers[0];
            ulong usedLow = framePointers[framePointers.Count - 1];
            if (result.StackPointer >= result.StackTop && result.StackPointer <= result.StackBase)
            {
                if (result.StackPointer > usedHigh)
                {
                    usedHigh = result.StackPointer;
                }

                if (result.StackPointer < usedLow)
                {
                    usedLow = result.StackPointer;
                }
            }

            ulong totalRange = result.StackBase - result.StackTop;
            if (totalRange == 0)
            {
                StackMapNoDataOverlay.Visibility = Visibility.Visible;
                return;
            }

            ulong usedRange = (usedHigh > usedLow) ? (usedHigh - usedLow) : 1;
            ulong padCandidate = usedRange / 2;
            if (padCandidate < 0x80)
            {
                padCandidate = 0x80;
            }

            ulong maxPad = totalRange / 4;
            ulong pad = (padCandidate < maxPad) ? padCandidate : maxPad;
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

            // Full stack context rail (absolute memory range).
            StackMapCanvas.Children.Add(new Line
            {
                X1 = xContext,
                X2 = xContext,
                Y1 = 4,
                Y2 = h - 4,
                Stroke = contextBrush,
                StrokeThickness = 1
            });

            double contextWinTop = MapInRange(result.StackBase, result.StackTop, usedHigh, 4, h - 4);
            double contextWinBottom = MapInRange(result.StackBase, result.StackTop, usedLow, 4, h - 4);
            StackMapCanvas.Children.Add(new Rectangle
            {
                Width = 6,
                Height = Math.Max(2, contextWinBottom - contextWinTop),
                Fill = zoomBrush,
                Stroke = zoomBorderBrush,
                StrokeThickness = 1
            });
            Canvas.SetLeft(StackMapCanvas.Children[^1], xContext - 3);
            Canvas.SetTop(StackMapCanvas.Children[^1], contextWinTop);

            // Active-window lane where frame pointers are expanded for readability.
            double zoomYTop = 8;
            double zoomYBottom = h - 8;
            if (zoomYBottom <= zoomYTop)
            {
                StackMapNoDataOverlay.Visibility = Visibility.Visible;
                return;
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

            var yExact = framePointers
                .Select(fp => Math.Max(zoomYTop, Math.Min(zoomYBottom, MapInRange(usedHigh, usedLow, fp, zoomYTop, zoomYBottom))))
                .ToArray();
            var yRendered = yExact.ToArray();

            const double minGap = 10.0;
            for (int i = 1; i < yRendered.Length; i += 1)
            {
                yRendered[i] = Math.Max(yRendered[i], yRendered[i - 1] + minGap);
            }
            for (int i = yRendered.Length - 2; i >= 0; i -= 1)
            {
                yRendered[i] = Math.Min(yRendered[i], yRendered[i + 1] - minGap);
            }

            if (yRendered.Length > 0)
            {
                if (yRendered[^1] > zoomYBottom)
                {
                    double shiftDown = yRendered[^1] - zoomYBottom;
                    for (int i = 0; i < yRendered.Length; i += 1)
                    {
                        yRendered[i] -= shiftDown;
                    }
                }
                if (yRendered[0] < zoomYTop)
                {
                    double shiftUp = zoomYTop - yRendered[0];
                    for (int i = 0; i < yRendered.Length; i += 1)
                    {
                        yRendered[i] += shiftUp;
                    }
                }
            }

            for (int i = 0; i < framePointers.Count; i += 1)
            {
                ulong fp = framePointers[i];
                double y = Math.Max(1, Math.Min(h - 1, yRendered[i]));
                double ye = Math.Max(1, Math.Min(h - 1, yExact[i]));

                if (Math.Abs(y - ye) > 1.5)
                {
                    StackMapCanvas.Children.Add(new Line
                    {
                        X1 = x1 - 12,
                        X2 = x1 - 2,
                        Y1 = ye,
                        Y2 = y,
                        Stroke = laneBrush,
                        StrokeThickness = 0.8,
                        Opacity = 0.65
                    });
                }

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

                StackMapCanvas.Children.Add(new TextBlock
                {
                    Text = $"0x{fp:X}",
                    FontSize = 10,
                    Foreground = textBrush
                });
                Canvas.SetLeft(StackMapCanvas.Children[^1], x0 + 4);
                Canvas.SetTop(StackMapCanvas.Children[^1], Math.Max(0, y - 7));
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

                double rspContextY = MapInRange(result.StackBase, result.StackTop, result.StackPointer, 4, h - 4);
                StackMapCanvas.Children.Add(new Ellipse
                {
                    Width = 5,
                    Height = 5,
                    Fill = rspBrush,
                    Stroke = rspBrush
                });
                Canvas.SetLeft(StackMapCanvas.Children[^1], xContext - 2.5);
                Canvas.SetTop(StackMapCanvas.Children[^1], rspContextY - 2.5);
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
