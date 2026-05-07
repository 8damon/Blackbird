using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    internal sealed class FaultNotificationWindow : Window
    {
        private readonly DispatcherTimer _autoCloseTimer;
        private int _secondsRemaining = 60;

        internal FaultNotificationWindow(string source, Exception? ex)
        {
            string typeName = ex?.GetType().Name ?? "UnknownException";
            string shortMsg = ex?.Message ?? "(no message)";
            string fullTrace = ex?.ToString() ?? "(no stack trace)";

            Title = $"Blackbird — Unhandled Fault ({source})";
            Width = 560;
            SizeToContent = SizeToContent.Height;
            MinHeight = 160;
            MaxHeight = 360;
            ResizeMode = ResizeMode.NoResize;
            WindowStyle = WindowStyle.ToolWindow;
            Topmost = true;
            WindowStartupLocation = WindowStartupLocation.Manual;
            Background = new SolidColorBrush(Color.FromRgb(0x10, 0x10, 0x10));
            Foreground = new SolidColorBrush(Color.FromRgb(0xEC, 0xF0, 0xF3));

            PositionBottomRight();

            var root = new Border { BorderBrush = new SolidColorBrush(Color.FromRgb(0xDF, 0x63, 0x63)),
                                    BorderThickness = new Thickness(0, 3, 0, 0),
                                    Background = new SolidColorBrush(Color.FromRgb(0x10, 0x10, 0x10)),
                                    Padding = new Thickness(14, 12, 14, 12) };

            var panel = new StackPanel { Orientation = Orientation.Vertical };

            var headerPanel = new DockPanel { LastChildFill = true, Margin = new Thickness(0, 0, 0, 8) };
            var headerLabel = new TextBlock { Text = $"⚠  Unhandled fault — interface session continues",
                                              FontWeight = FontWeights.SemiBold, FontSize = 13,
                                              Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0xC5, 0xC5)) };
            DockPanel.SetDock(headerLabel, Dock.Left);
            headerPanel.Children.Add(headerLabel);
            panel.Children.Add(headerPanel);

            panel.Children.Add(new TextBlock { Text = $"{source}  ·  {typeName}", FontSize = 11,
                                               Foreground = new SolidColorBrush(Color.FromRgb(0x9A, 0xA5, 0xB4)),
                                               Margin = new Thickness(0, 0, 0, 6) });

            panel.Children.Add(new TextBlock { Text = shortMsg, FontSize = 12,
                                               Foreground = new SolidColorBrush(Color.FromRgb(0xEA, 0xEA, 0xEA)),
                                               TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 10) });

            var buttonRow = new StackPanel { Orientation = Orientation.Horizontal,
                                             HorizontalAlignment = HorizontalAlignment.Right };
            var autoCloseLabel = new TextBlock { Text = $"Dismissing in {_secondsRemaining}s", FontSize = 10,
                                                 VerticalAlignment = VerticalAlignment.Center,
                                                 Foreground = new SolidColorBrush(Color.FromRgb(0x6A, 0x74, 0x82)),
                                                 Margin = new Thickness(0, 0, 12, 0) };

            var copyButton = BuildButton("Copy trace", () =>
                                                       {
                                                           try
                                                           {
                                                               Clipboard.SetText(fullTrace);
                                                           }
                                                           catch
                                                           {
                                                           }
                                                       });

            var dismissButton = BuildButton("Dismiss", () => Close());

            buttonRow.Children.Add(autoCloseLabel);
            buttonRow.Children.Add(copyButton);
            buttonRow.Children.Add(dismissButton);
            panel.Children.Add(buttonRow);

            root.Child = panel;
            Content = root;

            _autoCloseTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _autoCloseTimer.Tick += (_, __) =>
            {
                _secondsRemaining--;
                if (_secondsRemaining <= 0)
                {
                    _autoCloseTimer.Stop();
                    Close();
                    return;
                }
                autoCloseLabel.Text = $"Dismissing in {_secondsRemaining}s";
            };

            Loaded += (_, __) => _autoCloseTimer.Start();
            Closed += (_, __) => _autoCloseTimer.Stop();
        }

        private static Button BuildButton(string text, Action onClick)
        {
            var btn = new Button { Content = text,
                                   Padding = new Thickness(12, 4, 12, 4),
                                   Margin = new Thickness(6, 0, 0, 0),
                                   Background = new SolidColorBrush(Color.FromRgb(0x18, 0x18, 0x18)),
                                   Foreground = new SolidColorBrush(Color.FromRgb(0xEC, 0xF0, 0xF3)),
                                   BorderBrush = new SolidColorBrush(Color.FromRgb(0x3A, 0x3A, 0x3A)),
                                   BorderThickness = new Thickness(1),
                                   FontSize = 11 };
            btn.Click += (_, __) => onClick();
            return btn;
        }

        private void PositionBottomRight()
        {
            try
            {
                double screenWidth = SystemParameters.WorkArea.Right;
                double screenHeight = SystemParameters.WorkArea.Bottom;
                Left = screenWidth - Width - 24;
                Top = screenHeight - 200 - 24;
            }
            catch
            {
                WindowStartupLocation = WindowStartupLocation.CenterScreen;
            }
        }
    }
}
