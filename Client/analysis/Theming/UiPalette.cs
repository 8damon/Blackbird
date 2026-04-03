using System.Windows;
using System.Windows.Media;

namespace BlackbirdInterface
{
    internal static class UiPalette
    {
        public static Color Text => AsColor("WinTextBrush", Color.FromRgb(0xD8, 0xD8, 0xD8));
        public static Color MutedText => AsColor("WinMutedTextBrush", Color.FromRgb(0x9A, 0x9A, 0x9A));
        public static Color Accent => AsColor("WinAccentBrush", Color.FromRgb(0x8E, 0x20, 0x20));

        public static Brush SurfaceBrush => AsBrush("WinPanelBrush", Color.FromRgb(0x15, 0x15, 0x15));
        public static Brush SurfaceAltBrush => AsBrush("WinHeaderBrush", Color.FromRgb(0x1C, 0x1C, 0x1C));
        public static Brush BorderBrush => AsBrush("WinBorderBrush", Color.FromRgb(0x2B, 0x2B, 0x2B));
        public static Brush GridBrush => AsBrush("WinSubtleBorderBrush", Color.FromRgb(0x23, 0x23, 0x23));
        public static Brush GridStrongBrush => AsBrush("WinBorderBrush", Color.FromRgb(0x2B, 0x2B, 0x2B));
        public static Brush TextBrush => AsBrush("WinTextBrush", Color.FromRgb(0xD8, 0xD8, 0xD8));
        public static Brush MutedTextBrush => AsBrush("WinMutedTextBrush", Color.FromRgb(0x9A, 0x9A, 0x9A));
        public static Brush AccentBrush => AsBrush("WinAccentBrush", Color.FromRgb(0x8E, 0x20, 0x20));

        private static Brush AsBrush(string key, Color fallback)
        {
            if (Application.Current?.TryFindResource(key) is Brush brush)
                return brush;

            var b = new SolidColorBrush(fallback);
            b.Freeze();
            return b;
        }

        private static Color AsColor(string key, Color fallback)
        {
            if (Application.Current?.TryFindResource(key) is SolidColorBrush b)
                return b.Color;
            return fallback;
        }
    }
}

