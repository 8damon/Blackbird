using System.Windows;

namespace BlackbirdInterface
{
    public sealed class EventsFloatWindow : Window
    {
        public EventsFloatWindow(EventsPane pane)
        {
            Title = "Events (Floating)";
            Width = 1100;
            Height = 700;
            Background = pane.Background;
            Content = pane;

            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            WindowThemeHelper.ApplyDarkTitleBar(this);
        }
    }
}

