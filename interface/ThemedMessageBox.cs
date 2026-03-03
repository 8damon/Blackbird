using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace SleepwalkerInterface
{
    internal static class ThemedMessageBox
    {
        public static MessageBoxResult Show(
            Window? owner,
            string message,
            string title,
            MessageBoxButton buttons = MessageBoxButton.OK,
            MessageBoxImage image = MessageBoxImage.None)
        {
            var dialog = new Window
            {
                Title = title,
                Width = 520,
                Height = 220,
                MinWidth = 420,
                MinHeight = 180,
                WindowStartupLocation = owner == null ? WindowStartupLocation.CenterScreen : WindowStartupLocation.CenterOwner,
                Owner = owner,
                Background = GetBrush("MessageBoxBgBrush", Color.FromRgb(0x08, 0x08, 0x08)),
                Foreground = GetBrush("MessageBoxTextBrush", Color.FromRgb(0xE6, 0xE6, 0xE6)),
                ResizeMode = ResizeMode.NoResize,
                ShowInTaskbar = false
            };

            WindowThemeHelper.ApplyTitleBarTheme(dialog, App.IsDarkTheme);

            var root = new Grid { Margin = new Thickness(14) };
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.Resources[typeof(Button)] = BuildMessageButtonStyle();

            var header = new TextBlock
            {
                Text = title,
                FontWeight = FontWeights.SemiBold,
                FontSize = 14
            };
            root.Children.Add(header);

            string iconPrefix = image switch
            {
                MessageBoxImage.Warning => "[!] ",
                MessageBoxImage.Error => "[x] ",
                MessageBoxImage.Information => "[i] ",
                _ => ""
            };

            var messageBlock = new TextBlock
            {
                Text = iconPrefix + message,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 12, 0, 12),
                VerticalAlignment = VerticalAlignment.Top,
                Foreground = GetBrush("MessageBoxMutedTextBrush", Color.FromRgb(0xB0, 0xB0, 0xB0))
            };
            Grid.SetRow(messageBlock, 1);
            root.Children.Add(messageBlock);

            var buttonPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right
            };
            Grid.SetRow(buttonPanel, 2);
            root.Children.Add(buttonPanel);

            MessageBoxResult result = MessageBoxResult.None;

            void AddButton(string content, MessageBoxResult buttonResult, bool isDefault = false, bool isCancel = false)
            {
                var button = new Button
                {
                    Content = content,
                    MinWidth = 88,
                    Margin = new Thickness(6, 0, 0, 0),
                    IsDefault = isDefault,
                    IsCancel = isCancel
                };
                button.Click += (_, __) =>
                {
                    result = buttonResult;
                    dialog.DialogResult = true;
                    dialog.Close();
                };
                buttonPanel.Children.Add(button);
            }

            switch (buttons)
            {
                case MessageBoxButton.OK:
                    AddButton("OK", MessageBoxResult.OK, isDefault: true, isCancel: true);
                    break;
                case MessageBoxButton.OKCancel:
                    AddButton("Cancel", MessageBoxResult.Cancel, isCancel: true);
                    AddButton("OK", MessageBoxResult.OK, isDefault: true);
                    break;
                case MessageBoxButton.YesNo:
                    AddButton("No", MessageBoxResult.No, isCancel: true);
                    AddButton("Yes", MessageBoxResult.Yes, isDefault: true);
                    break;
                case MessageBoxButton.YesNoCancel:
                    AddButton("Cancel", MessageBoxResult.Cancel, isCancel: true);
                    AddButton("No", MessageBoxResult.No);
                    AddButton("Yes", MessageBoxResult.Yes, isDefault: true);
                    break;
            }

            dialog.Content = root;
            _ = dialog.ShowDialog();
            return result;
        }

        private static Brush GetBrush(string resourceKey, Color fallback)
        {
            if (Application.Current?.TryFindResource(resourceKey) is Brush b)
                return b;

            var brush = new SolidColorBrush(fallback);
            brush.Freeze();
            return brush;
        }

        private static Style BuildMessageButtonStyle()
        {
            var style = new Style(typeof(Button));
            style.Setters.Add(new Setter(Control.BackgroundProperty, new SolidColorBrush(Color.FromRgb(0x1C, 0x1C, 0x1C))));
            style.Setters.Add(new Setter(Control.ForegroundProperty, new SolidColorBrush(Color.FromRgb(0xE6, 0xE6, 0xE6))));
            style.Setters.Add(new Setter(Control.BorderBrushProperty, new SolidColorBrush(Color.FromRgb(0x2B, 0x2B, 0x2B))));
            style.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(1)));
            style.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(10, 4, 10, 4)));
            style.Setters.Add(new Setter(FrameworkElement.MinWidthProperty, 88d));
            style.Setters.Add(new Setter(FrameworkElement.MinHeightProperty, 24d));
            return style;
        }
    }
}
