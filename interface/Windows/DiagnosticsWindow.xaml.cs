using System;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class DiagnosticsWindow : Window
    {
        private readonly int _targetPid;
        private readonly DispatcherTimer _stateTimer;

        public DiagnosticsWindow(int pid)
        {
            InitializeComponent();
            WindowThemeHelper.ApplyDarkTitleBar(this);

            _targetPid = pid > 0 ? pid : Environment.ProcessId;
            TargetBlock.Text = $"PID {_targetPid}";
            LoadSnapshot();
            RefreshState();

            _stateTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _stateTimer.Tick += (_, __) => RefreshState();
            _stateTimer.Start();

            OutputCapture.LineReceived += OutputCapture_LineReceived;
            Closed += (_, __) =>
            {
                OutputCapture.LineReceived -= OutputCapture_LineReceived;
                _stateTimer.Stop();
            };
        }

        private void LoadSnapshot()
        {
            var lines = OutputCapture.Snapshot();
            OutputBox.Text = string.Join(Environment.NewLine, lines);
            OutputBox.ScrollToEnd();
            OutputLinesBlock.Text = lines.Count.ToString();
        }

        private void RefreshState()
        {
            var lines = DiagnosticsState.SnapshotLines();
            StateBox.Text = string.Join(Environment.NewLine, lines);
            StateBox.ScrollToHome();
            StateLinesBlock.Text = lines.Count.ToString();
            RefreshStampBlock.Text = DateTime.Now.ToString("HH:mm:ss");
        }

        private void OutputCapture_LineReceived(string line)
        {
            _ = Dispatcher.BeginInvoke(new Action(() =>
            {
                if (OutputBox.LineCount > 5000)
                    OutputBox.Clear();

                if (OutputBox.Text.Length > 0)
                    OutputBox.AppendText(Environment.NewLine);
                OutputBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {line}");
                OutputBox.ScrollToEnd();
                OutputLinesBlock.Text = OutputBox.LineCount.ToString();
            }), DispatcherPriority.Background);
        }

        private void Clear_Click(object sender, RoutedEventArgs e)
        {
            OutputBox.Clear();
            OutputLinesBlock.Text = "0";
        }
        private void RefreshState_Click(object sender, RoutedEventArgs e) => RefreshState();

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }

        private void Close_Click(object sender, RoutedEventArgs e) => Close();
    }
}
