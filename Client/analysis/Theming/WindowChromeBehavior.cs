using System;
using System.Windows;
using System.Windows.Input;

namespace BlackbirdInterface
{
    internal static class WindowChromeBehavior
    {
        internal static void HandleTitleBarMouseLeftButtonDown(Window window, MouseButtonEventArgs e,
                                                               Action<Exception>? onDragMoveError = null)
        {
            if (e.LeftButton != MouseButtonState.Pressed)
            {
                return;
            }

            if (e.ClickCount >= 2)
            {
                ToggleMaximize(window);
                return;
            }

            try
            {
                window.DragMove();
            }
            catch (Exception ex)
            {
                onDragMoveError?.Invoke(ex);
            }
        }

        internal static void HandleRootDragMove(Window window, MouseButtonEventArgs e)
        {
            if (e.ChangedButton != MouseButton.Left || e.ClickCount != 1)
            {
                return;
            }

            try
            {
                window.DragMove();
            }
            catch
            {
            }
        }

        internal static void Minimize(Window window)
        {
            window.WindowState = WindowState.Minimized;
        }

        internal static void ToggleMaximize(Window window)
        {
            window.WindowState =
                window.WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        }

        internal static void Close(Window window)
        {
            window.Close();
        }
    }
}
