using System.Windows;

namespace SleepwalkerInterface
{
    public sealed class PerformanceFloatWindow : Window
    {
        public PerformanceFloatWindow(PerformancePane pane)
        {
            Title = "Performance (Floating)";
            Width = 1180;
            Height = 520;
            Background = pane.Background;
            Content = pane;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            WindowThemeHelper.ApplyDarkTitleBar(this);
        }
    }
}
