using System;
using System.Windows;

namespace SleepwalkerInterface
{
    public sealed class PaneHeaderDragEventArgs : EventArgs
    {
        public Point ScreenPosition { get; }

        public PaneHeaderDragEventArgs(Point screenPosition)
        {
            ScreenPosition = screenPosition;
        }
    }
}
