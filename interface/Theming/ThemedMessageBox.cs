using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Threading;

namespace BlackbirdInterface
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
                Width = 540,
                Height = 230,
                MinWidth = 460,
                MinHeight = 190,
                WindowStartupLocation = owner == null ? WindowStartupLocation.CenterScreen : WindowStartupLocation.CenterOwner,
                Owner = owner,
                Background = GetBrush("MessageBoxBgBrush", Color.FromRgb(0x08, 0x08, 0x08)),
                Foreground = GetBrush("MessageBoxTextBrush", Color.FromRgb(0xE6, 0xE6, 0xE6)),
                ResizeMode = ResizeMode.NoResize,
                ShowInTaskbar = false,
                WindowStyle = WindowStyle.None,
                UseLayoutRounding = true,
                SnapsToDevicePixels = true
            };

            WindowThemeHelper.ApplyTitleBarTheme(dialog, App.IsDarkTheme);

            var root = new Border
            {
                Background = dialog.Background,
                BorderBrush = GetBrush("WinBorderBrush", Color.FromRgb(0x2B, 0x2B, 0x2B)),
                BorderThickness = new Thickness(1)
            };

            var layout = new Grid();
            layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            layout.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            layout.Resources[typeof(Button)] = BuildMessageButtonStyle();

            var titleBar = BuildTitleBar(dialog, title);
            Grid.SetRow(titleBar, 0);
            layout.Children.Add(titleBar);

            string iconPrefix = image switch
            {
                MessageBoxImage.Warning => "⚠ ",
                MessageBoxImage.Error => "⛔ ",
                MessageBoxImage.Information => "ℹ ",
                _ => ""
            };

            var messageBlock = new TextBlock
            {
                Text = iconPrefix + message,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(14, 12, 14, 12),
                VerticalAlignment = VerticalAlignment.Top,
                Foreground = GetBrush("MessageBoxMutedTextBrush", Color.FromRgb(0xB0, 0xB0, 0xB0))
            };
            Grid.SetRow(messageBlock, 1);
            layout.Children.Add(messageBlock);

            var buttonPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(8, 0, 10, 10)
            };
            Grid.SetRow(buttonPanel, 2);
            layout.Children.Add(buttonPanel);

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

            root.Child = layout;
            dialog.Content = root;
            _ = dialog.ShowDialog();
            return result;
        }

        public static void ShowToast(
            Window? owner,
            string message,
            string title = "Notification",
            MessageBoxImage image = MessageBoxImage.Information,
            int durationMs = 4200)
        {
            if (durationMs < 1500)
            {
                durationMs = 1500;
            }

            var toast = new Window
            {
                Title = title,
                Width = 460,
                Height = 152,
                MinWidth = 420,
                MinHeight = 132,
                MaxHeight = 260,
                WindowStyle = WindowStyle.None,
                ResizeMode = ResizeMode.NoResize,
                ShowInTaskbar = false,
                ShowActivated = false,
                Topmost = true,
                Background = GetBrush("MessageBoxBgBrush", Color.FromRgb(0x08, 0x08, 0x08)),
                Foreground = GetBrush("MessageBoxTextBrush", Color.FromRgb(0xE6, 0xE6, 0xE6)),
                UseLayoutRounding = true,
                SnapsToDevicePixels = true
            };

            if (owner != null && owner.IsVisible && !ReferenceEquals(owner, toast))
            {
                toast.Owner = owner;
            }

            WindowThemeHelper.ApplyTitleBarTheme(toast, App.IsDarkTheme);

            var shell = new Border
            {
                Background = toast.Background,
                BorderBrush = GetBrush("WinBorderBrush", Color.FromRgb(0x2B, 0x2B, 0x2B)),
                BorderThickness = new Thickness(1)
            };

            var layout = new Grid();
            layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            layout.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var titleBar = BuildTitleBar(toast, title);
            Grid.SetRow(titleBar, 0);
            layout.Children.Add(titleBar);

            string iconPrefix = image switch
            {
                MessageBoxImage.Warning => "⚠ ",
                MessageBoxImage.Error => "⛔ ",
                MessageBoxImage.Information => "ℹ ",
                _ => ""
            };

            var messageBlock = new TextBlock
            {
                Text = iconPrefix + message,
                Margin = new Thickness(14, 12, 14, 12),
                TextWrapping = TextWrapping.Wrap,
                Foreground = GetBrush("MessageBoxMutedTextBrush", Color.FromRgb(0xB0, 0xB0, 0xB0))
            };
            Grid.SetRow(messageBlock, 1);
            layout.Children.Add(messageBlock);

            shell.Child = layout;
            toast.Content = shell;

            toast.Loaded += (_, __) => PositionToast(toast, owner);
            if (owner != null)
            {
                EventHandler locationChanged = (_, __) => PositionToast(toast, owner);
                SizeChangedEventHandler sizeChanged = (_, __) => PositionToast(toast, owner);
                owner.LocationChanged += locationChanged;
                owner.SizeChanged += sizeChanged;
                toast.Closed += (_, __) =>
                {
                    owner.LocationChanged -= locationChanged;
                    owner.SizeChanged -= sizeChanged;
                };
            }

            var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(durationMs) };
            timer.Tick += (_, __) =>
            {
                timer.Stop();
                if (toast.IsVisible)
                {
                    toast.Close();
                }
            };
            toast.Closed += (_, __) => timer.Stop();

            toast.Show();
            timer.Start();
        }

        private static Border BuildTitleBar(Window host, string title)
        {
            var border = new Border
            {
                Background = GetBrush("WinHeaderBrush", Color.FromRgb(0x1B, 0x1B, 0x1B)),
                BorderBrush = GetBrush("WinBorderBrush", Color.FromRgb(0x2B, 0x2B, 0x2B)),
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(10, 6, 6, 6)
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var titleBlock = new TextBlock
            {
                Text = string.IsNullOrWhiteSpace(title) ? "Message" : title,
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center,
                Foreground = GetBrush("MessageBoxTextBrush", Color.FromRgb(0xE6, 0xE6, 0xE6))
            };
            grid.Children.Add(titleBlock);

            var closeButton = new Button
            {
                Content = "\uE8BB",
                FontFamily = new FontFamily("Segoe MDL2 Assets"),
                FontSize = 10,
                Width = 30,
                Height = 24,
                MinWidth = 30,
                MinHeight = 24,
                Padding = new Thickness(0),
                Margin = new Thickness(6, 0, 0, 0),
                Background = Brushes.Transparent,
                Foreground = GetBrush("MessageBoxTextBrush", Color.FromRgb(0xE6, 0xE6, 0xE6)),
                BorderBrush = Brushes.Transparent,
                BorderThickness = new Thickness(0),
                Style = BuildTitleCloseButtonStyle()
            };
            closeButton.Click += (_, __) => host.Close();
            Grid.SetColumn(closeButton, 1);
            grid.Children.Add(closeButton);

            border.MouseLeftButtonDown += (_, e) =>
            {
                if (e.LeftButton != System.Windows.Input.MouseButtonState.Pressed)
                {
                    return;
                }

                try
                {
                    host.DragMove();
                }
                catch
                {
                }
            };

            border.Child = grid;
            return border;
        }

        private static Style BuildTitleCloseButtonStyle()
        {
            var style = new Style(typeof(Button));
            style.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.Transparent));
            style.Setters.Add(new Setter(Control.BorderBrushProperty, Brushes.Transparent));
            style.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0)));

            var template = new ControlTemplate(typeof(Button));
            var border = new FrameworkElementFactory(typeof(Border));
            border.Name = "Root";
            border.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Control.BackgroundProperty));
            border.SetValue(Border.BorderBrushProperty, new TemplateBindingExtension(Control.BorderBrushProperty));
            border.SetValue(Border.BorderThicknessProperty, new TemplateBindingExtension(Control.BorderThicknessProperty));

            var presenter = new FrameworkElementFactory(typeof(ContentPresenter));
            presenter.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            presenter.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
            border.AppendChild(presenter);
            template.VisualTree = border;

            var over = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            over.Setters.Add(new Setter(Control.BackgroundProperty, new SolidColorBrush(Color.FromRgb(0xAA, 0x3A, 0x3A))));
            over.Setters.Add(new Setter(Control.BorderBrushProperty, new SolidColorBrush(Color.FromRgb(0xBC, 0x54, 0x54))));
            over.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(1)));

            var pressed = new Trigger { Property = ButtonBase.IsPressedProperty, Value = true };
            pressed.Setters.Add(new Setter(Control.BackgroundProperty, new SolidColorBrush(Color.FromRgb(0x91, 0x2E, 0x2E))));
            pressed.Setters.Add(new Setter(Control.BorderBrushProperty, new SolidColorBrush(Color.FromRgb(0xBC, 0x54, 0x54))));
            pressed.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(1)));

            template.Triggers.Add(over);
            template.Triggers.Add(pressed);
            style.Setters.Add(new Setter(Control.TemplateProperty, template));

            return style;
        }

        private static void PositionToast(Window toast, Window? owner)
        {
            Rect workArea = SystemParameters.WorkArea;
            double left = workArea.Right - toast.ActualWidth - 16;
            double top = workArea.Bottom - toast.ActualHeight - 16;

            if (owner != null && owner.IsVisible && owner.WindowState != WindowState.Minimized)
            {
                double ownerLeft = owner.Left + owner.ActualWidth - toast.ActualWidth - 16;
                double ownerTop = owner.Top + owner.ActualHeight - toast.ActualHeight - 16;
                left = Math.Max(workArea.Left + 8, Math.Min(workArea.Right - toast.ActualWidth - 8, ownerLeft));
                top = Math.Max(workArea.Top + 8, Math.Min(workArea.Bottom - toast.ActualHeight - 8, ownerTop));
            }

            toast.Left = left;
            toast.Top = top;
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
