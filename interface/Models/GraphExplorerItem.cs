using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media;

namespace BlackbirdInterface
{
    public sealed class GraphExplorerItem : INotifyPropertyChanged
    {
        private bool _isEnabled;
        private bool _hasData;
        private bool _showDetails;
        private string _detailPrimary = "";
        private string _detailSecondary = "";

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

        public bool ShowDetails
        {
            get => _showDetails;
            set
            {
                if (_showDetails == value) return;
                _showDetails = value;
                OnPropertyChanged();
            }
        }

        public string DetailPrimary
        {
            get => _detailPrimary;
            set
            {
                if (string.Equals(_detailPrimary, value, StringComparison.Ordinal)) return;
                _detailPrimary = value;
                OnPropertyChanged();
            }
        }

        public string DetailSecondary
        {
            get => _detailSecondary;
            set
            {
                if (string.Equals(_detailSecondary, value, StringComparison.Ordinal)) return;
                _detailSecondary = value;
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

        public void ClearPreviewValues()
        {
            PreviewValues.Clear();
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? prop = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));
    }
}


