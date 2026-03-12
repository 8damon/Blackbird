using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;

namespace BlackbirdInterface
{
    public sealed class BulkObservableCollection<T> : ObservableCollection<T>
    {
        private bool _suppressNotifications;

        public void ReplaceAll(IEnumerable<T> items)
        {
            _suppressNotifications = true;
            try
            {
                ClearItems();
                foreach (T item in items)
                {
                    Add(item);
                }
            }
            finally
            {
                _suppressNotifications = false;
            }

            RaiseReset();
        }

        public void AddRange(IEnumerable<T> items)
        {
            _suppressNotifications = true;
            try
            {
                foreach (T item in items)
                {
                    Add(item);
                }
            }
            finally
            {
                _suppressNotifications = false;
            }

            RaiseReset();
        }

        protected override void OnCollectionChanged(NotifyCollectionChangedEventArgs e)
        {
            if (_suppressNotifications)
            {
                return;
            }

            base.OnCollectionChanged(e);
        }

        protected override void OnPropertyChanged(PropertyChangedEventArgs e)
        {
            if (_suppressNotifications)
            {
                return;
            }

            base.OnPropertyChanged(e);
        }

        private void RaiseReset()
        {
            base.OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
            base.OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
            base.OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
        }
    }
}
