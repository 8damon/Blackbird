using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows;

namespace SleepwalkerInterface
{
    public partial class ThreadStackWindow : Window
    {
        public ObservableCollection<StackFrameRow> Frames { get; } = new();
        private readonly int _pid;
        private readonly int _tid;
        private readonly string _state;

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

                Frames.Clear();
                foreach (var frame in result.Frames)
                    Frames.Add(frame);

                ThreadMetaBlock.Text =
                    $"TEB: {(result.TebAddress == 0 ? "-" : $"0x{result.TebAddress:X}")}    " +
                    $"StackBase: {(result.StackBase == 0 ? "-" : $"0x{result.StackBase:X}")}    " +
                    $"StackTop: {(result.StackTop == 0 ? "-" : $"0x{result.StackTop:X}")}    " +
                    $"TEB Flags: {(result.TebFlags.HasValue ? $"0x{result.TebFlags.Value:X4}" : "-")}";

                NoteBlock.Text = $"{Frames.Count} frame(s)";
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
            }
        }

        private void Close_Click(object sender, RoutedEventArgs e) => Close();
    }

    public sealed class StackFrameRow
    {
        public int Index { get; init; }
        public string Address { get; init; } = "";
        public string Module { get; init; } = "";
        public string Symbol { get; init; } = "";
    }
}
