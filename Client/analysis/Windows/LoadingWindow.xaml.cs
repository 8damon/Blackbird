using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class LoadingWindow : Window
    {
        private readonly Queue<string> _recentSteps = new();
        private string _lastStep = string.Empty;
        private DispatcherTimer? _timeoutTimer;
        private DateTime _timeoutDeadlineUtc;
        private TimeSpan _timeoutDuration = TimeSpan.Zero;
        private const int MaxRecentSteps = 6;

        public LoadingWindow()
        {
            InitializeComponent();
            WindowThemeHelper.WireThemeAwareTitleBar(this);
            SetProgress(8, "Initializing...", "Preparing startup pipeline.");
        }

        public void SetProgress(double value, string status, string? detail = null)
        {
            if (value < 0)
                value = 0;
            if (value > 100)
                value = 100;

            LoadBar.Value = value;
            StatusBlock.Text = status;
            DetailBlock.Text = string.IsNullOrWhiteSpace(detail) ? "Working..." : detail;
            PercentBlock.Text = value.ToString("0", CultureInfo.InvariantCulture) + "%";
            AddStep(value, status);
        }

        public void StartTimeout(TimeSpan timeout)
        {
            StopTimeout(clearText: true);
            if (timeout <= TimeSpan.Zero)
            {
                return;
            }

            _timeoutDuration = timeout;
            _timeoutDeadlineUtc = DateTime.UtcNow.Add(timeout);
            _timeoutTimer = new DispatcherTimer(DispatcherPriority.Background,
                                                Dispatcher) { Interval = TimeSpan.FromMilliseconds(250) };
            _timeoutTimer.Tick += TimeoutTimer_Tick;
            _timeoutTimer.Start();
            UpdateTimeoutText();
        }

        public void StopTimeout() => StopTimeout(clearText: true);

        public void SetTimedOut(string status, string detail, TimeSpan timeout)
        {
            StopTimeout(clearText: false);
            SetProgress(100, status, detail);
            TimerBlock.Text = "Timed out after " + FormatDuration(timeout) + ".";
        }

        private void AddStep(double value, string status)
        {
            string stepLine = $"{value,3:0}%  {status}";
            if (string.Equals(stepLine, _lastStep, System.StringComparison.Ordinal))
            {
                return;
            }

            _lastStep = stepLine;
            _recentSteps.Enqueue(stepLine);
            while (_recentSteps.Count > MaxRecentSteps)
            {
                _recentSteps.Dequeue();
            }

            StepsBlock.Text = string.Join("\n", _recentSteps.ToArray().Reverse());
        }

        private void TimeoutTimer_Tick(object? sender, EventArgs e)
        {
            UpdateTimeoutText();
        }

        private void UpdateTimeoutText()
        {
            if (_timeoutDuration <= TimeSpan.Zero)
            {
                TimerBlock.Text = string.Empty;
                return;
            }

            TimeSpan remaining = _timeoutDeadlineUtc - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                TimerBlock.Text = "Timeout reached; waiting for controller unwind.";
                return;
            }

            TimerBlock.Text = "Timeout in " + FormatDuration(remaining) + ".";
        }

        private void StopTimeout(bool clearText)
        {
            if (_timeoutTimer != null)
            {
                _timeoutTimer.Stop();
                _timeoutTimer.Tick -= TimeoutTimer_Tick;
                _timeoutTimer = null;
            }

            _timeoutDuration = TimeSpan.Zero;
            _timeoutDeadlineUtc = default;
            if (clearText)
            {
                TimerBlock.Text = string.Empty;
            }
        }

        private static string FormatDuration(TimeSpan value)
        {
            if (value < TimeSpan.Zero)
            {
                value = TimeSpan.Zero;
            }

            int totalSeconds = Math.Max(0, (int)Math.Ceiling(value.TotalSeconds));
            int minutes = totalSeconds / 60;
            int seconds = totalSeconds % 60;
            return minutes > 0 ? minutes.ToString(CultureInfo.InvariantCulture) + "m " +
                                     seconds.ToString("00", CultureInfo.InvariantCulture) + "s"
                               : seconds.ToString(CultureInfo.InvariantCulture) + "s";
        }

        protected override void OnClosed(EventArgs e)
        {
            StopTimeout(clearText: true);
            base.OnClosed(e);
        }
    }
}
