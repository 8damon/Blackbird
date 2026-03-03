using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media;

namespace SleepwalkerInterface
{
    public sealed class GraphExplorerItem : INotifyPropertyChanged
    {
        private bool _isEnabled;
        private bool _hasData;

        public string Name { get; }
        public Brush AccentBrush { get; }

        // Tiny preview values (normalized for sparkline)
        public ObservableCollection<double> PreviewValues { get; } = new();

        public bool IsEnabled
        {
            get => _isEnabled;
            set
            {
                if (_isEnabled == value) return;
                _isEnabled = value;
                OnPropertyChanged();
            }
        }

        public bool HasData
        {
            get => _hasData;
            set
            {
                if (_hasData == value) return;
                _hasData = value;
                OnPropertyChanged();
            }
        }

        public GraphExplorerItem(string name, Brush accent)
        {
            Name = name;
            AccentBrush = accent;
        }

        public void PushPreviewValue(double v)
        {
            // Keep a small rolling window
            const int max = 60;
            PreviewValues.Add(v);
            while (PreviewValues.Count > max)
                PreviewValues.RemoveAt(0);
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? prop = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));
    }
}
