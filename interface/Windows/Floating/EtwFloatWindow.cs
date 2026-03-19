using System.Windows;

namespace BlackbirdInterface
{
    public sealed class EtwFloatWindow : Window
    {
        public EtwFloatWindow(EtwPane pane)
        {
            Title = "ETW (Floating)";
            Width = 980;
            Height = 680;
            Background = pane.Background;
            Content = pane;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            WindowThemeHelper.ApplyDarkTitleBar(this);
        }
    }
}

