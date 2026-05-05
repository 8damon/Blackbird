using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace BlackbirdInterface
{
    internal sealed class InspectorKeyValueRow
    {
        public InspectorKeyValueRow()
        {
        }

        public InspectorKeyValueRow(string label, string value)
        {
            Label = label ?? string.Empty;
            Value = value ?? string.Empty;
        }

        public string Label { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
    }

    internal sealed class InspectorFieldNode : INotifyPropertyChanged
    {
        private bool _isExpanded = true;

        public string Name { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Kind { get; set; } = "pair";
        public ObservableCollection<InspectorFieldNode> Children { get; } = new();
        public bool IsExpanded
        {
            get => _isExpanded;
            set {
                if (_isExpanded == value)
                {
                    return;
                }

                _isExpanded = value;
                OnPropertyChanged();
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    internal sealed class InspectorStackRow
    {
        public string Index { get; set; } = string.Empty;
        public string Address { get; set; } = string.Empty;
        public string Notes { get; set; } = string.Empty;
    }
}
