using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;

namespace BlackbirdInterface
{
    public partial class ParallelStacksWindow : Window
    {
        private readonly int _pid;
        private readonly List<ThreadUsageRow> _threads;
        private readonly List<ParallelStackRow> _rows = new();
        private bool _refreshInFlight;
        private Border? _selectedCard;

        public ParallelStacksWindow(int pid, IReadOnlyList<ThreadUsageRow> threads)
        {
            InitializeComponent();
            WindowThemeHelper.ApplyDarkTitleBar(this);

            _pid = pid;
            _threads = threads.Select(CloneThread).ToList();
            SubtitleBlock.Text = $"PID {_pid} | {_threads.Count} thread(s)";

            Loaded += async (_, __) => await RefreshStacksAsync();
        }

        private async Task RefreshStacksAsync()
        {
            if (_refreshInFlight)
            {
                return;
            }

            _refreshInFlight = true;
            try
            {
                SummaryBlock.Text = $"Resolving {_threads.Count} thread stack(s)...";
                List<ParallelStackRow> resolved = await Task.Run(() => ResolveRows());
                _rows.Clear();
                _rows.AddRange(resolved);

                SummaryBlock.Text = $"Resolved {_rows.Count} thread stack(s)";
                if (_rows.Count > 0)
                {
                    RenderStackMap();
                    SelectRow(_rows[0], _selectedCard);
                }
                else
                {
                    StacksCanvas.Children.Clear();
                    SelectedTitleBlock.Text = "No thread data";
                    SelectedMetaBlock.Text = "No stack snapshots could be resolved.";
                    DetailBox.Text = string.Empty;
                }
            }
            finally
            {
                _refreshInFlight = false;
            }
        }

        private List<ParallelStackRow> ResolveRows()
        {
            var results = new ParallelStackRow?[_threads.Count];
            using var gate = new SemaphoreSlim(4);
            var tasks = new List<Task>(_threads.Count);

            for (int i = 0; i < _threads.Count; i += 1)
            {
                int index = i;
                tasks.Add(Task.Run(async () =>
                {
                    await gate.WaitAsync().ConfigureAwait(false);
                    try
                    {
                        ThreadUsageRow thread = _threads[index];
                        ThreadStackResolveResult result = ThreadStackResolver.Resolve(_pid, thread.Tid, thread.State);
                        results[index] = BuildRow(thread, result);
                    }
                    finally
                    {
                        gate.Release();
                    }
                }));
            }

            Task.WaitAll(tasks.ToArray());
            return results.OfType<ParallelStackRow>().ToList();
        }

        private void RenderStackMap()
        {
            StacksCanvas.Children.Clear();
            _selectedCard = null;

            const double cardWidth = 280;
            const double cardHeight = 220;
            const double spacingX = 318;
            const double spacingY = 248;
            int columns = Math.Max(1, (int)Math.Ceiling(Math.Sqrt(Math.Max(1, _rows.Count))));
            ParallelStackRow? mainThread = _rows
                .OrderBy(row => row.StartTimeUtc ?? DateTime.MaxValue)
                .ThenBy(row => row.Tid)
                .FirstOrDefault();

            for (int i = 0; i < _rows.Count; i += 1)
            {
                ParallelStackRow row = _rows[i];
                int col = i % columns;
                int currentRow = i / columns;
                double x = 26 + (col * spacingX) + ((currentRow % 2 == 0) ? 0 : 18);
                double y = 24 + (currentRow * spacingY) + ((col % 2 == 0) ? 0 : 14);
                row.IsMainThread = ReferenceEquals(row, mainThread);
                Border card = BuildCard(row, cardWidth, cardHeight);
                Canvas.SetLeft(card, x);
                Canvas.SetTop(card, y);
                row.Card = card;
                row.Center = new Point(x + (cardWidth / 2.0), y + (cardHeight / 2.0));
            }

            DrawLooseLinks(mainThread);

            for (int i = 0; i < _rows.Count; i += 1)
            {
                StacksCanvas.Children.Add(_rows[i].Card!);
            }

            double width = 52 + (Math.Min(columns, Math.Max(1, _rows.Count)) * spacingX);
            double height = 48 + (((_rows.Count + columns - 1) / columns) * spacingY);
            StacksCanvas.Width = Math.Max(920, width);
            StacksCanvas.Height = Math.Max(620, height);
        }

        private void DrawLooseLinks(ParallelStackRow? mainThread)
        {
            if (_rows.Count <= 1)
            {
                return;
            }

            for (int i = 1; i < _rows.Count; i += 1)
            {
                ParallelStackRow from = _rows[i - 1];
                ParallelStackRow to = _rows[i];
                AddLooseLink(from.Center, to.Center, highlighted: false);
            }

            if (mainThread == null)
            {
                return;
            }

            for (int i = 0; i < _rows.Count; i += 1)
            {
                ParallelStackRow row = _rows[i];
                if (ReferenceEquals(row, mainThread))
                {
                    continue;
                }

                AddLooseLink(mainThread.Center, row.Center, highlighted: true);
            }
        }

        private void AddLooseLink(Point from, Point to, bool highlighted)
        {
            double dx = Math.Abs(to.X - from.X);
            double controlOffset = Math.Max(42, dx * 0.22);
            var figure = new PathFigure { StartPoint = from, IsClosed = false, IsFilled = false };
            figure.Segments.Add(new BezierSegment(
                new Point(from.X + controlOffset, from.Y),
                new Point(to.X - controlOffset, to.Y),
                to,
                true));

            var geometry = new PathGeometry();
            geometry.Figures.Add(figure);
            StacksCanvas.Children.Add(new Path
            {
                Data = geometry,
                Stroke = highlighted
                    ? new SolidColorBrush(Color.FromArgb(0x48, 0xD8, 0xD8, 0xD8))
                    : new SolidColorBrush(Color.FromArgb(0x22, 0x9A, 0x9A, 0x9A)),
                StrokeThickness = highlighted ? 1.6 : 1.0,
                StrokeDashArray = new DoubleCollection { 7, 9 },
                SnapsToDevicePixels = true
            });
        }

        private Border BuildCard(ParallelStackRow row, double width, double height)
        {
            var border = new Border
            {
                Width = width,
                Height = height,
                Padding = new Thickness(10, 8, 10, 8),
                CornerRadius = new CornerRadius(10),
                BorderThickness = row.IsMainThread ? new Thickness(2) : new Thickness(1),
                BorderBrush = row.IsMainThread
                    ? new SolidColorBrush(Color.FromRgb(0xC8, 0xC8, 0xC8))
                    : new SolidColorBrush(Color.FromRgb(0x46, 0x46, 0x46)),
                Background = new SolidColorBrush(Color.FromRgb(0x1A, 0x1A, 0x1A)),
                Cursor = Cursors.Hand,
                Tag = row,
                Effect = new System.Windows.Media.Effects.DropShadowEffect
                {
                    BlurRadius = 18,
                    ShadowDepth = 0,
                    Opacity = 0.32,
                    Color = Color.FromRgb(0x00, 0x00, 0x00)
                }
            };

            var stack = new StackPanel();
            stack.Children.Add(new TextBlock
            {
                Text = row.IsMainThread ? $"TID {row.Tid}  MAIN" : $"TID {row.Tid}",
                FontWeight = FontWeights.SemiBold,
                FontSize = 13,
                Foreground = Brushes.White
            });
            stack.Children.Add(new TextBlock
            {
                Text = row.State,
                Margin = new Thickness(0, 2, 0, 0),
                Foreground = new SolidColorBrush(Color.FromRgb(0xB9, 0xC2, 0xCC))
            });
            stack.Children.Add(new TextBlock
            {
                Text = row.Rip,
                Margin = new Thickness(0, 6, 0, 0),
                FontFamily = new FontFamily("Consolas"),
                Foreground = new SolidColorBrush(Color.FromRgb(0xD0, 0xD0, 0xD0))
            });
            stack.Children.Add(new TextBlock
            {
                Text = $"{row.FrameCount} frame(s)",
                Margin = new Thickness(0, 2, 0, 8),
                Foreground = new SolidColorBrush(Color.FromRgb(0x90, 0x90, 0x90))
            });

            for (int i = 0; i < row.FrameLines.Count; i += 1)
            {
                stack.Children.Add(new TextBlock
                {
                    Text = row.FrameLines[i],
                    Margin = new Thickness(0, i == 0 ? 0 : 4, 0, 0),
                    TextWrapping = TextWrapping.Wrap,
                    TextTrimming = TextTrimming.CharacterEllipsis,
                    FontFamily = new FontFamily("Consolas"),
                    Foreground = i == 0
                        ? new SolidColorBrush(Color.FromRgb(0xF3, 0xF3, 0xF3))
                        : new SolidColorBrush(Color.FromRgb(0xB7, 0xB7, 0xB7))
                });
            }

            border.Child = stack;
            border.MouseLeftButtonUp += Card_MouseLeftButtonUp;
            return border;
        }

        private static ParallelStackRow BuildRow(ThreadUsageRow thread, ThreadStackResolveResult result)
        {
            StackFrameRow? top = result.Frames.FirstOrDefault();
            string rip = top?.Address ??
                         (result.ContextSnapshot?.Rip is ulong value && value != 0 ? $"0x{value:X}" : "N/A");
            string topFrame = top == null
                ? (string.IsNullOrWhiteSpace(result.Note) ? "No stack frames" : result.Note)
                : $"{top.Module}!{top.Symbol}";

            var detail = new StringBuilder(2048);
            detail.Append("TID: ").AppendLine(thread.Tid.ToString());
            detail.Append("State: ").AppendLine(thread.State);
            detail.Append("RIP: ").AppendLine(rip);
            detail.Append("Frames: ").AppendLine(result.Frames.Count.ToString());
            if (result.TebAddress != 0)
            {
                detail.Append("TEB: 0x").Append(result.TebAddress.ToString("X")).AppendLine();
            }
            if (result.StackBase != 0 || result.StackTop != 0)
            {
                detail.Append("Stack: 0x").Append(result.StackTop.ToString("X"))
                      .Append(" -> 0x").Append(result.StackBase.ToString("X"))
                      .AppendLine();
            }
            if (!string.IsNullOrWhiteSpace(result.Note))
            {
                detail.Append("Note: ").AppendLine(result.Note);
            }

            detail.AppendLine();
            if (result.Frames.Count == 0)
            {
                detail.AppendLine("No frames resolved.");
            }
            else
            {
                for (int i = 0; i < result.Frames.Count; i += 1)
                {
                    StackFrameRow frame = result.Frames[i];
                    detail.Append('[').Append(i).Append("] ")
                          .Append(frame.Address).Append("  ")
                          .Append(frame.Module).Append("  ")
                          .AppendLine(frame.Symbol);
                }
            }

            return new ParallelStackRow
            {
                Tid = thread.Tid,
                State = thread.State,
                StartTimeUtc = thread.StartTimeUtc,
                Rip = rip,
                FrameCount = result.Frames.Count,
                TopFrame = topFrame,
                FrameLines = result.Frames.Take(6)
                    .Select(frame => $"{frame.Module}!{frame.Symbol}")
                    .ToList(),
                DetailText = detail.ToString().TrimEnd()
            };
        }

        private static ThreadUsageRow CloneThread(ThreadUsageRow row)
            => new(new ThreadUsageSample
            {
                Tid = row.Tid,
                CpuMsDelta = row.CpuMs,
                State = row.State,
                WaitReason = row.IsSuspended ? "Suspended" : string.Empty,
                Kind = row.ThreadKind,
                StartTimeUtc = row.StartTimeUtc,
                TargetSuspended = row.IsSuspended
            });

        private async void Refresh_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            await RefreshStacksAsync();
        }

        private void Close_Click(object sender, RoutedEventArgs e) => Close();

        private void Card_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            _ = sender;
            _ = e;
            if (sender is not Border border || border.Tag is not ParallelStackRow row)
            {
                return;
            }

            SelectRow(row, border);
        }

        private void SelectRow(ParallelStackRow row, Border? border)
        {
            if (_selectedCard != null)
            {
                _selectedCard.BorderBrush = new SolidColorBrush(Color.FromRgb(0x46, 0x46, 0x46));
                _selectedCard.BorderThickness = new Thickness(1);
            }

            _selectedCard = border ?? row.Card;
            if (_selectedCard != null)
            {
                _selectedCard.BorderBrush = new SolidColorBrush(Color.FromRgb(0x7C, 0xD5, 0xFF));
                _selectedCard.BorderThickness = new Thickness(2);
            }

            SelectedTitleBlock.Text = $"Thread {row.Tid}";
            SelectedMetaBlock.Text = $"{row.State} | RIP {row.Rip} | {row.FrameCount} frame(s)";
            DetailBox.Text = row.DetailText;
        }

        private sealed class ParallelStackRow
        {
            public int Tid { get; init; }
            public string State { get; init; } = string.Empty;
            public DateTime? StartTimeUtc { get; init; }
            public string Rip { get; init; } = string.Empty;
            public int FrameCount { get; init; }
            public string TopFrame { get; init; } = string.Empty;
            public List<string> FrameLines { get; init; } = new();
            public string DetailText { get; init; } = string.Empty;
            public bool IsMainThread { get; set; }
            public Point Center { get; set; }
            public Border? Card { get; set; }
        }
    }
}
