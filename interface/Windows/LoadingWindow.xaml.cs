using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows;

namespace SleepwalkerInterface
{
    public partial class LoadingWindow : Window
    {
        private readonly Queue<string> _recentSteps = new();
        private string _lastStep = string.Empty;
        private const int MaxRecentSteps = 6;

        public LoadingWindow()
        {
            InitializeComponent();
            SetProgress(8, "Initializing...", "Preparing startup pipeline.");
        }

        public void SetProgress(double value, string status, string? detail = null)
        {
            if (value < 0) value = 0;
            if (value > 100) value = 100;

            LoadBar.Value = value;
            StatusBlock.Text = status;
            DetailBlock.Text = string.IsNullOrWhiteSpace(detail) ? "Working..." : detail;
            PercentBlock.Text = value.ToString("0", CultureInfo.InvariantCulture) + "%";
            AddStep(value, status);
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
    }
}
