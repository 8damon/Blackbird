using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace BlackbirdInterface
{
    internal static class WindowThemeHelper
    {
        public static void ApplyDarkTitleBar(Window window)
        {
            bool useDark = App.IsDarkTheme;
            ApplyTitleBarTheme(window, useDark);
        }

        public static void ApplyTitleBarTheme(Window window, bool useDark)
        {
            if (window == null)
                return;

            void Apply()
            {
                var hwnd = new WindowInteropHelper(window).Handle;
                if (hwnd == IntPtr.Zero)
                    return;

                int darkFlag = useDark ? 1 : 0;
                const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
                const int DWMWA_USE_IMMERSIVE_DARK_MODE_OLD = 19;

                if (DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref darkFlag, sizeof(int)) != 0)
                    _ = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_OLD, ref darkFlag, sizeof(int));
            }

            if (new WindowInteropHelper(window).Handle != IntPtr.Zero)
            {
                Apply();
                return;
            }

            window.SourceInitialized += (_, __) => Apply();
        }

        [DllImport("dwmapi.dll", SetLastError = true)]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int dwAttribute, ref int pvAttribute, int cbAttribute);
    }
}

