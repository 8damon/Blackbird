using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Input;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private void SeedFake()
        {
            var t0 = _captureStartUtc;

            AppendEvent(new TelemetryEvent { TimestampUtc = t0.AddSeconds(1), PID = 1234, TID = 10, Group = "Execution",
                                             SubType = "CreateProcess", Summary = "proc created" });
            AppendEvent(new TelemetryEvent { TimestampUtc = t0.AddSeconds(2), PID = 1234, TID = 11, Group = "Thread",
                                             SubType = "RemoteThread", Summary = "remote thread start" });
            AppendEvent(new TelemetryEvent { TimestampUtc = t0.AddSeconds(6), PID = 1234, TID = 12, Group = "Registry",
                                             SubType = "SetValue", Summary = "reg set value" });
            AppendEvent(new TelemetryEvent { TimestampUtc = t0.AddSeconds(12), PID = 1234, TID = 13, Group = "Handles",
                                             SubType = "Duplicate", Summary = "dup handle" });
            AppendEvent(new TelemetryEvent { TimestampUtc = t0.AddSeconds(35), PID = 1234, TID = 14,
                                             Group = "Injection", SubType = "MapView", Summary = "write+map" });
        }

        private void UndockEventsPane()
        {
            if (_eventsFloatWindow != null)
                return;

            if (EventsDockBorder.Child == EventsPaneHost)
                EventsDockBorder.Child = null;

            _eventsPaneFloating = true;
            _eventsPaneVisible = true;
            ApplyDockVisibilityFromExplorer();
            Dispatcher.BeginInvoke(new Action(() =>
                                              {
                                                  if (_eventsFloatWindow != null)
                                                      return;

                                                  _eventsFloatWindow = new EventsFloatWindow(
                                                      EventsPaneHost) { Owner = this, ShowInTaskbar = false };
                                                  _eventsFloatWindow.Closing += EventsFloatWindow_Closing;
                                                  _eventsFloatWindow.Closed += EventsFloatWindow_Closed;
                                                  _eventsFloatWindow.Show();
                                              }),
                                   System.Windows.Threading.DispatcherPriority.Background);
        }

        private void RedockEventsPane()
        {
            if (_eventsFloatWindow != null)
            {
                _eventsFloatWindow.Closing -= EventsFloatWindow_Closing;
                _eventsFloatWindow.Closed -= EventsFloatWindow_Closed;
                if (_eventsFloatWindow.Content == EventsPaneHost)
                    _eventsFloatWindow.Content = null;
                _eventsFloatWindow.Close();
                _eventsFloatWindow = null;
            }

            _eventsPaneFloating = false;
            if (EventsDockBorder.Child == null)
                EventsDockBorder.Child = EventsPaneHost;
            _eventsPaneVisible = true;
            _draggingEventsPaneHeader = false;
            HideDockPreview();
            ApplyDockVisibilityFromExplorer();
        }

        private void UndockPerformancePane()
        {
            if (_performanceFloatWindow != null)
                return;

            if (PerformanceDockBorder.Child == PerformancePaneHost)
                PerformanceDockBorder.Child = null;

            _performancePaneFloating = true;
            _performancePaneVisible = true;
            ApplyDockVisibilityFromExplorer();
            Dispatcher.BeginInvoke(new Action(() =>
                                              {
                                                  if (_performanceFloatWindow != null)
                                                      return;

                                                  _performanceFloatWindow = new PerformanceFloatWindow(
                                                      PerformancePaneHost) { Owner = this, ShowInTaskbar = false };
                                                  _performanceFloatWindow.Closing += PerformanceFloatWindow_Closing;
                                                  _performanceFloatWindow.Closed += PerformanceFloatWindow_Closed;
                                                  _performanceFloatWindow.Show();
                                              }),
                                   System.Windows.Threading.DispatcherPriority.Background);
        }

        private void RedockPerformancePane()
        {
            if (_performanceFloatWindow != null)
            {
                _performanceFloatWindow.Closing -= PerformanceFloatWindow_Closing;
                _performanceFloatWindow.Closed -= PerformanceFloatWindow_Closed;
                if (_performanceFloatWindow.Content == PerformancePaneHost)
                    _performanceFloatWindow.Content = null;
                _performanceFloatWindow.Close();
                _performanceFloatWindow = null;
            }

            _performancePaneFloating = false;
            if (PerformanceDockBorder.Child == null)
                PerformanceDockBorder.Child = PerformancePaneHost;
            _performancePaneVisible = true;
            _draggingPerformancePaneHeader = false;
            HideDockPreview();
            ApplyDockVisibilityFromExplorer();
        }

        private void UndockEtwPane()
        {
            if (_etwFloatWindow != null)
                return;

            if (EtwDockBorder.Child == EtwPaneHost)
                EtwDockBorder.Child = null;

            _etwPaneFloating = true;
            ApplyDockVisibilityFromExplorer();
            Dispatcher.BeginInvoke(new Action(() =>
                                              {
                                                  if (_etwFloatWindow != null)
                                                      return;

                                                  _etwFloatWindow = new EtwFloatWindow(
                                                      EtwPaneHost) { Owner = this, ShowInTaskbar = false };
                                                  _etwFloatWindow.Closing += EtwFloatWindow_Closing;
                                                  _etwFloatWindow.Closed += EtwFloatWindow_Closed;
                                                  _etwFloatWindow.Show();
                                              }),
                                   System.Windows.Threading.DispatcherPriority.Background);
        }

        private void RedockEtwPane()
        {
            if (_etwFloatWindow != null)
            {
                _etwFloatWindow.Closing -= EtwFloatWindow_Closing;
                _etwFloatWindow.Closed -= EtwFloatWindow_Closed;
                if (_etwFloatWindow.Content == EtwPaneHost)
                    _etwFloatWindow.Content = null;
                _etwFloatWindow.Close();
                _etwFloatWindow = null;
            }

            _etwPaneFloating = false;
            if (EtwDockBorder.Child == null)
                EtwDockBorder.Child = EtwPaneHost;
            ApplyDockVisibilityFromExplorer();
        }

        private void UndockHeuristicsPane()
        {
            if (_heuristicsFloatWindow != null)
                return;

            if (HeuristicsDockBorder.Child == HeuristicsPaneHost)
                HeuristicsDockBorder.Child = null;

            _heuristicsPaneFloating = true;
            ApplyDockVisibilityFromExplorer();
            Dispatcher.BeginInvoke(new Action(() =>
                                              {
                                                  if (_heuristicsFloatWindow != null)
                                                      return;

                                                  _heuristicsFloatWindow = new HeuristicsFloatWindow(
                                                      HeuristicsPaneHost) { Owner = this, ShowInTaskbar = false };
                                                  _heuristicsFloatWindow.Closing += HeuristicsFloatWindow_Closing;
                                                  _heuristicsFloatWindow.Closed += HeuristicsFloatWindow_Closed;
                                                  _heuristicsFloatWindow.Show();
                                              }),
                                   System.Windows.Threading.DispatcherPriority.Background);
        }

        private void RedockHeuristicsPane()
        {
            if (_heuristicsFloatWindow != null)
            {
                _heuristicsFloatWindow.Closing -= HeuristicsFloatWindow_Closing;
                _heuristicsFloatWindow.Closed -= HeuristicsFloatWindow_Closed;
                if (_heuristicsFloatWindow.Content == HeuristicsPaneHost)
                    _heuristicsFloatWindow.Content = null;
                _heuristicsFloatWindow.Close();
                _heuristicsFloatWindow = null;
            }

            _heuristicsPaneFloating = false;
            if (HeuristicsDockBorder.Child == null)
                HeuristicsDockBorder.Child = HeuristicsPaneHost;
            ApplyDockVisibilityFromExplorer();
        }

        private void EventsFloatWindow_Closed(object? sender, EventArgs e)
        {
            _eventsFloatWindow = null;
            if (EventsDockBorder.Child == null)
                RedockEventsPane();
        }

        private void EventsFloatWindow_Closing(object? sender, CancelEventArgs e)
        {
            bool explorerEnabled = FindExplorerItem("Events")?.IsEnabled ?? true;
            if (_isMainWindowShuttingDown || !explorerEnabled || !_eventsPaneVisible ||
                sender is not EventsFloatWindow window || !ReferenceEquals(window.Content, EventsPaneHost))
            {
                return;
            }

            e.Cancel = true;
            RedockEventsPane();
        }

        private void PerformanceFloatWindow_Closed(object? sender, EventArgs e)
        {
            _performanceFloatWindow = null;
            if (PerformanceDockBorder.Child == null)
                RedockPerformancePane();
        }

        private void PerformanceFloatWindow_Closing(object? sender, CancelEventArgs e)
        {
            bool explorerEnabled = FindExplorerItem("Performance")?.IsEnabled ?? true;
            if (_isMainWindowShuttingDown || !explorerEnabled || !_performancePaneVisible ||
                sender is not PerformanceFloatWindow window || !ReferenceEquals(window.Content, PerformancePaneHost))
            {
                return;
            }

            e.Cancel = true;
            RedockPerformancePane();
        }

        private void EtwFloatWindow_Closed(object? sender, EventArgs e)
        {
            _etwFloatWindow = null;
            if (EtwDockBorder.Child == null)
                RedockEtwPane();
        }

        private void EtwFloatWindow_Closing(object? sender, CancelEventArgs e)
        {
            bool explorerEnabled = FindExplorerItem("ETW")?.IsEnabled ?? true;
            if (_isMainWindowShuttingDown || !explorerEnabled || sender is not EtwFloatWindow window ||
                !ReferenceEquals(window.Content, EtwPaneHost))
            {
                return;
            }

            e.Cancel = true;
            RedockEtwPane();
        }

        private void HeuristicsFloatWindow_Closed(object? sender, EventArgs e)
        {
            _heuristicsFloatWindow = null;
            if (HeuristicsDockBorder.Child == null)
                RedockHeuristicsPane();
        }

        private void HeuristicsFloatWindow_Closing(object? sender, CancelEventArgs e)
        {
            bool explorerEnabled = FindExplorerItem("Heuristics")?.IsEnabled ?? true;
            if (_isMainWindowShuttingDown || !explorerEnabled || sender is not HeuristicsFloatWindow window ||
                !ReferenceEquals(window.Content, HeuristicsPaneHost))
            {
                return;
            }

            e.Cancel = true;
            RedockHeuristicsPane();
        }
    }
}
