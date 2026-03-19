using System.Windows;

namespace BlackbirdInterface
{
    public sealed class HeuristicsFloatWindow : Window
    {
        public HeuristicsFloatWindow(HeuristicsPane pane)
        {
            Title = "Heuristics (Floating)";
            Width = 980;
            Height = 520;
            Background = pane.Background;
            Content = pane;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            WindowThemeHelper.ApplyDarkTitleBar(this);
        }
    }
}


