using System;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace SleepwalkerInterface
{
    public partial class EventsPane : UserControl
    {
        public event RoutedEventHandler? CloseRequested;
        public event RoutedEventHandler? FloatRequested;
        public event RoutedEventHandler? SettingsRequested;
        public event EventHandler<PaneHeaderDragEventArgs>? HeaderDragStarted;
        public event EventHandler<PaneHeaderDragEventArgs>? HeaderDragDelta;
        public event EventHandler<PaneHeaderDragEventArgs>? HeaderDragCompleted;

        private bool _headerMouseDown;
        private bool _headerDragging;
        private Point _headerMouseDownPos;
        private bool _hasData;
        private bool _connectivityHealthy = true;

        public EventsPane()
        {
            InitializeComponent();
            UpdateNoDataOverlay();
        }

        public TimelineControl Timeline => EventTimeline;
        public ScrollBar Scroll => TimelineScroll;
        public DataGrid Grid => EventGrid;

        public Button BtnCloseRef => BtnClose;
        public Button BtnFloatRef => BtnFloat;
        public Button BtnSettingsRef => BtnSettings;

        public void SetHasData(bool hasData)
        {
            _hasData = hasData;
            UpdateNoDataOverlay();
        }

        public void SetConnectivityHealthy(bool healthy)
        {
            _connectivityHealthy = healthy;
            UpdateNoDataOverlay();
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e) => CloseRequested?.Invoke(this, e);
        private void BtnFloat_Click(object sender, RoutedEventArgs e) => FloatRequested?.Invoke(this, e);
        private void BtnSettings_Click(object sender, RoutedEventArgs e) => SettingsRequested?.Invoke(this, e);

        private void Header_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (IsInteractiveElement(e.OriginalSource as DependencyObject))
                return;

            _headerMouseDown = true;
            _headerDragging = false;
            _headerMouseDownPos = e.GetPosition(this);
            CaptureMouse();
        }

        private void Header_MouseMove(object sender, MouseEventArgs e)
        {
            if (!_headerMouseDown || e.LeftButton != MouseButtonState.Pressed)
                return;

            var current = e.GetPosition(this);
            var screen = PointToScreen(current);

            if (!_headerDragging)
            {
                var dx = Math.Abs(current.X - _headerMouseDownPos.X);
                var dy = Math.Abs(current.Y - _headerMouseDownPos.Y);
                if (dx < 4 && dy < 4)
                    return;

                _headerDragging = true;
                HeaderDragStarted?.Invoke(this, new PaneHeaderDragEventArgs(screen));
            }

            HeaderDragDelta?.Invoke(this, new PaneHeaderDragEventArgs(screen));
        }

        private void Header_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            if (!_headerMouseDown)
                return;

            var screen = PointToScreen(e.GetPosition(this));

            if (_headerDragging)
                HeaderDragCompleted?.Invoke(this, new PaneHeaderDragEventArgs(screen));

            _headerMouseDown = false;
            _headerDragging = false;
            ReleaseMouseCapture();
        }

        private static bool IsInteractiveElement(DependencyObject? source)
        {
            while (source != null)
            {
                if (source is Button || source is ScrollBar || source is TextBox || source is ComboBox)
                    return true;
                source = VisualTreeHelper.GetParent(source);
            }

            return false;
        }

        private void UpdateNoDataOverlay()
        {
            EventsNoDataOverlay.Visibility = (_hasData && _connectivityHealthy) ? Visibility.Collapsed : Visibility.Visible;
        }
    }
}
