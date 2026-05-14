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
        private void ProcessRelationsPaneHost_GraphStateChanged(object? sender, EventArgs e)
        {
            _ = sender;
            _ = e;
            ScheduleChildProcessGraphWindowRefresh();
        }

        private void OpenOrActivateChildProcessGraphWindow()
        {
            if (_childProcessGraphWindow == null)
            {
                _childProcessGraphWindow =
                    new ChildProcessGraphWindow(ProcessRelationsPaneHost.CurrentRootPid) { Owner = this };
                _childProcessGraphWindow.Closed += ChildProcessGraphWindow_Closed;
                RestoreChildProcessGraphStateFromSession();
                RefreshChildProcessGraphWindow();
                _childProcessGraphWindow.Show();
                RebuildToolbarViewMenuOptions();
                return;
            }

            RefreshChildProcessGraphWindow();
            if (_childProcessGraphWindow.WindowState == WindowState.Minimized)
            {
                _childProcessGraphWindow.WindowState = WindowState.Normal;
            }

            _childProcessGraphWindow.Activate();
        }

        private void RefreshChildProcessGraphWindowIfOpen()
        {
            if (_childProcessGraphWindow == null)
            {
                return;
            }

            RefreshChildProcessGraphWindow();
        }

        private void ScheduleChildProcessGraphWindowRefresh()
        {
            if (_childProcessGraphWindow == null)
            {
                return;
            }

            _childProcessGraphRefreshTimer.Stop();
            _childProcessGraphRefreshTimer.Start();
        }

        private void ChildProcessGraphRefreshTimer_Tick(object? sender, EventArgs e)
        {
            _ = sender;
            _ = e;
            _childProcessGraphRefreshTimer.Stop();
            RefreshChildProcessGraphWindowIfOpen();
        }

        private void RefreshChildProcessGraphWindow()
        {
            _childProcessGraphWindow?.UpdateGraph(ProcessRelationsPaneHost.SnapshotItems(),
                                                  ProcessRelationsPaneHost.CurrentRootPid);
        }

        private void ChildProcessGraphWindow_Closed(object? sender, EventArgs e)
        {
            _ = sender;
            _ = e;
            SaveChildProcessGraphStateToSession();
            if (_childProcessGraphWindow != null)
            {
                _childProcessGraphWindow.Closed -= ChildProcessGraphWindow_Closed;
            }

            _childProcessGraphWindow = null;
            RebuildToolbarViewMenuOptions();
        }

        private void SaveChildProcessGraphStateToSession(ProcessSessionTab? tab = null)
        {
            ProcessSessionTab? session = tab ?? _currentSession;
            if (session == null)
            {
                return;
            }

            session.ChildProcessExpandedKeys.Clear();
            if (_childProcessGraphWindow == null)
            {
                return;
            }

            foreach (string key in _childProcessGraphWindow.GetExpandedKeysSnapshot())
            {
                session.ChildProcessExpandedKeys.Add(key);
            }
        }

        private void RestoreChildProcessGraphStateFromSession(ProcessSessionTab? tab = null)
        {
            if (_childProcessGraphWindow == null)
            {
                return;
            }

            _childProcessGraphWindow.SetExpandedKeys((tab ?? _currentSession)?.ChildProcessExpandedKeys);
        }

        private void LayoutsComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = e;
            if (!IsLoaded || sender is not ComboBox combo)
                return;

            string? tag = (combo.SelectedItem as System.Windows.Controls.ContentControl)?.Tag as string;
            if (string.IsNullOrEmpty(tag))
                return;

            combo.SelectedIndex = 0;

            if (tag == "layout-simple")
            {
                ApplySimpleLayout();
            }
            else if (tag == "layout-advanced")
            {
                ApplyAdvancedLayout();
            }
        }

        private void ApplySimpleLayout()
        {
            SetExplorerPaneEnabled("ETW", false);
            SetExplorerPaneEnabled("Heuristics", false);
            SetExplorerPaneEnabled("Filesystem", false);
            SetExplorerPaneEnabled("Registry", false);
            SetExplorerPaneEnabled("Process Relations", false);
            ApplyDockVisibilityFromExplorer();
            PersistCurrentInterfacePreferences();
        }

        private void ApplyAdvancedLayout()
        {
            SetExplorerPaneEnabled("Events", true);
            SetExplorerPaneEnabled("Performance", true);
            SetExplorerPaneEnabled("ETW", true);
            SetExplorerPaneEnabled("Heuristics", true);
            SetExplorerPaneEnabled("Filesystem", true);
            SetExplorerPaneEnabled("Registry", true);
            SetExplorerPaneEnabled("Process Relations", true);
            _eventsPaneVisible = true;
            _performancePaneVisible = true;
            ApplyDockVisibilityFromExplorer();
            PersistCurrentInterfacePreferences();
        }

        private void ToolbarViewMenu_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = e;
            if (_toolbarViewMenuSyncing || !IsLoaded || sender is not ComboBox combo)
            {
                return;
            }

            string tag = combo.SelectedItem switch { ComboBoxItem item when item.Tag is string itemTag => itemTag,
                                                     _ => string.Empty };
            if (string.IsNullOrWhiteSpace(tag))
            {
                return;
            }

            switch (tag)
            {
            case "events":
                SetExplorerPaneEnabled("Events", true);
                ShowEventsPane();
                break;
            case "performance":
                SetExplorerPaneEnabled("Performance", true);
                ShowPerformancePane();
                break;
            case "etw":
                ShowEtwPane();
                break;
            case "heuristics":
                ShowHeuristicsPane();
                break;
            case "filesystem":
                ShowFilesystemPane();
                break;
            case "registry":
                ShowRegistryPane();
                break;
            case "process-relations":
                ShowProcessRelationsPane();
                break;
            case "operator-case":
                OpenOperatorCaseWindow();
                break;
            case "event-log":
                SetExplorerPaneEnabled("Events", true);
                ShowEventsPane();
                OpenOrActivateEventLogWindow();
                break;
            case "inspector-etw":
                ShowEtwPane();
                OpenEtwInspector();
                break;
            case "inspector-heuristics":
                ShowHeuristicsPane();
                OpenHeuristicsInspector();
                break;
            case "inspector-filesystem":
                ShowFilesystemPane();
                OpenFilesystemInspector();
                break;
            case "inspector-registry":
                ShowRegistryPane();
                OpenRegistryInspector();
                break;
            case "inspector-relations":
                ShowProcessRelationsPane();
                OpenProcessRelationsInspector();
                break;
            case "diagnostics":
                OpenDiagnosticsWindow();
                break;
            case "signature-intel-rules":
                OpenSignatureIntelRulesWindow();
                break;
            case "child-process-graph":
                OpenOrActivateChildProcessGraphWindow();
                break;
            }

            combo.SelectedIndex = 0;
            RebuildToolbarViewMenuOptions();
        }

        private void ToolbarViewMenu_DropDownOpened(object sender, EventArgs e)
        {
            _ = sender;
            _ = e;
            RebuildToolbarViewMenuOptions();
        }

        private void RebuildToolbarViewMenuOptions()
        {
            if (ToolbarViewMenu == null)
            {
                return;
            }

            _toolbarViewMenuSyncing = true;
            ToolbarViewMenu.Items.Clear();
            ToolbarViewMenu.Items.Add(new ComboBoxItem { Content = "Open Window..." });

            AddToolbarViewOptionIfClosed("Events Pane", "events", IsEventsPaneOpen());
            AddToolbarViewOptionIfClosed("Performance Pane", "performance", IsPerformancePaneOpen());
            AddToolbarViewOptionIfClosed("ETW Pane", "etw", IsEtwPaneOpen());
            AddToolbarViewOptionIfClosed("Detections Pane", "heuristics", IsHeuristicsPaneOpen());
            AddToolbarViewOptionIfClosed("Filesystem Pane", "filesystem", IsFilesystemPaneOpen());
            AddToolbarViewOptionIfClosed("Registry Pane", "registry", IsRegistryPaneOpen());
            AddToolbarViewOptionIfClosed("Process Relations Pane", "process-relations", IsRelationsPaneOpen());
            AddToolbarViewOptionIfClosed("Operator Case", "operator-case", IsWindowOpenByTitle("Operator Case"));
            AddToolbarViewOptionIfClosed("Event Log Window", "event-log",
                                         _eventLogWindow != null && _eventLogWindow.IsVisible);
            AddToolbarViewOptionIfClosed("ETW Inspector", "inspector-etw", IsWindowOpenByTitle("ETW Inspector"));
            AddToolbarViewOptionIfClosed("Detections Inspector", "inspector-heuristics",
                                         IsWindowOpenByTitle("Detections"));
            AddToolbarViewOptionIfClosed("Filesystem Inspector", "inspector-filesystem",
                                         IsWindowOpenByTitle("Filesystem"));
            AddToolbarViewOptionIfClosed("Registry Inspector", "inspector-registry", IsWindowOpenByTitle("Registry"));
            AddToolbarViewOptionIfClosed("Process Relations Inspector", "inspector-relations",
                                         IsWindowOpenByTitle("Process Relations"));
            AddToolbarViewOptionIfClosed(
                "Diagnostics Window", "diagnostics",
                Application.Current.Windows.OfType<Window>().Any(w => w is DiagnosticsWindow && w.IsVisible));
            AddToolbarViewOptionIfClosed(
                "Rules Intel", "signature-intel-rules",
                Application.Current.Windows.OfType<Window>().Any(w => w is SignatureIntelRulesWindow && w.IsVisible));
            AddToolbarViewOptionIfClosed("Child Process Graph", "child-process-graph",
                                         _childProcessGraphWindow != null && _childProcessGraphWindow.IsVisible);

            ToolbarViewMenu.SelectedIndex = 0;
            _toolbarViewMenuSyncing = false;
        }

        private void AddToolbarViewOptionIfClosed(string label, string tag, bool isOpen)
        {
            if (ToolbarViewMenu == null || isOpen)
            {
                return;
            }

            ToolbarViewMenu.Items.Add(new ComboBoxItem { Content = label, Tag = tag });
        }

        private bool IsEventsPaneOpen() => (FindExplorerItem("Events")?.IsEnabled ?? true) &&
                                           (_eventsPaneVisible || _eventsPaneFloating || _eventsFloatWindow != null);

        private bool IsPerformancePaneOpen() => (FindExplorerItem("Performance")?.IsEnabled ?? true) &&
                                                (_performancePaneVisible || _performancePaneFloating ||
                                                 _performanceFloatWindow != null);

        private bool IsEtwPaneOpen() => (FindExplorerItem("ETW")?.IsEnabled ?? true);

        private bool IsHeuristicsPaneOpen() => (FindExplorerItem("Heuristics")?.IsEnabled ?? true);

        private bool IsFilesystemPaneOpen() => (FindExplorerItem("Filesystem")?.IsEnabled ?? true);

        private bool IsRegistryPaneOpen() => (FindExplorerItem("Registry")?.IsEnabled ?? true);

        private bool IsRelationsPaneOpen() => (FindExplorerItem("Process Relations")?.IsEnabled ?? true);

        private static bool IsWindowOpenByTitle(string title) =>
            Application.Current?.Windows.OfType<Window>().Any(w => w.IsVisible &&
                                                                   string.Equals(w.Title, title,
                                                                                 StringComparison.OrdinalIgnoreCase)) ??
            false;

        private void ToggleFloatDock()
        {
            if (_eventsFloatWindow == null)
            {
                UndockEventsPane();
            }
            else
            {
                RedockEventsPane();
            }
        }

        private void ToggleEventLogDock()
        {
            if (_eventLogWindow == null)
            {
                UndockEventLog();
            }
            else
            {
                RedockEventLog();
            }
        }

        private void UndockEventLog()
        {
            if (_eventLogWindow != null)
            {
                return;
            }

            _eventLogWindow = new EventLogWindow { Owner = this, ShowInTaskbar = false };
            _eventLogWindow.EtwFeedRequested += EventLogWindow_EtwFeedRequested;
            _eventLogWindow.Closed += EventLogWindow_Closed;
            EventsPaneHost.SetEventLogDetached(true);
            UpdateDetachedEventLogWindow(immediate: true);
            _eventLogWindow.Show();
        }

        private void RedockEventLog()
        {
            if (_eventLogWindow != null)
            {
                _eventLogWindow.EtwFeedRequested -= EventLogWindow_EtwFeedRequested;
                _eventLogWindow.Closed -= EventLogWindow_Closed;
                _eventLogWindow.Close();
                _eventLogWindow = null;
            }

            EventsPaneHost.SetEventLogDetached(false);
        }

        private void EventLogWindow_Closed(object? sender, EventArgs e)
        {
            if (_eventLogWindow != null)
            {
                _eventLogWindow.EtwFeedRequested -= EventLogWindow_EtwFeedRequested;
            }
            _eventLogWindow = null;
            EventsPaneHost.SetEventLogDetached(false);
        }

        private void DetachedEventLogRefreshTimer_Tick(object? sender, EventArgs e)
        {
            _detachedEventLogRefreshTimer.Stop();
            _eventLogWindow?.RefreshEvents(_focusedEvents);
        }

        private void UpdateDetachedEventLogWindow(bool immediate = false)
        {
            if (_eventLogWindow == null)
            {
                return;
            }

            if (immediate)
            {
                _detachedEventLogRefreshTimer.Stop();
                _eventLogWindow.RefreshEvents(_focusedEvents);
                return;
            }

            _detachedEventLogRefreshTimer.Stop();
            _detachedEventLogRefreshTimer.Start();
        }

        private void EventLogWindow_EtwFeedRequested(object? sender, EventLogCardOpenRequestedEventArgs e)
        {
            _ = sender;
            if (e == null)
            {
                return;
            }

            var displayMatches =
                _focusedEvents
                    .Where(ev => EventMatchesLogCard(ev, e.Group, e.SubType, e.Summary, e.Details, e.Pid, e.Tid))
                    .ToList();
            OpenEventLogDetailWindow("Event Log Detail", ExpandFocusedEventMembers(displayMatches));
        }

        private void EventsPaneHost_EventLogEntryOpenRequested(object? sender, EventLogEntryOpenRequestedEventArgs e)
        {
            _ = sender;
            if (e?.Event == null)
            {
                return;
            }

            TelemetryEvent selected = e.Event;
            OpenEventLogDetailWindow("Event Detail", GetFocusedEventMembers(selected));
        }

        private void OpenEventLogDetailWindow(string title, IReadOnlyList<TelemetryEvent> matches)
        {
            if (matches == null || matches.Count == 0)
            {
                return;
            }

            GroupedEventRow row = BuildEventLogDetailRow(matches);
            var detail = new SimpleEventDetailWindow(title, row) { Owner = this };
            detail.Show();
            detail.Activate();
        }

        private static bool EventMatchesLogCard(TelemetryEvent ev, string group, string subType, string summary,
                                                string details, int pid, int tid)
        {
            if (ev == null)
            {
                return false;
            }

            return string.Equals(ev.Group ?? string.Empty, group ?? string.Empty, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(ev.SubType ?? string.Empty, subType ?? string.Empty,
                                 StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(ev.Summary ?? string.Empty, summary ?? string.Empty, StringComparison.Ordinal) &&
                   string.Equals(ev.Details ?? string.Empty, details ?? string.Empty, StringComparison.Ordinal) &&
                   ev.PID == pid && ev.TID == tid;
        }

        private static GroupedEventRow BuildEventLogDetailRow(IReadOnlyList<TelemetryEvent> matches)
        {
            TelemetryEvent first = matches[0];
            string group = string.IsNullOrWhiteSpace(first.Group) ? "Other" : first.Group;
            string subType = first.SubType ?? string.Empty;
            string eventName = string.IsNullOrWhiteSpace(subType) ? group : $"{group}/{subType}";
            string summary = first.Summary ?? string.Empty;
            string key =
                $"{group}\u001F{subType}\u001F{first.PID}\u001F{first.TID}\u001F{summary}\u001F{first.Details}";

            var row = new GroupedEventRow { GroupKey = key,      LastSeenUtc = matches.Max(x => x.TimestampUtc),
                                            Event = eventName,   Severity = "Event",
                                            Detection = summary, Hits = matches.Count };

            foreach (TelemetryEvent ev in matches.OrderByDescending(x => x.TimestampUtc))
            {
                string actor = string.IsNullOrWhiteSpace(ev.ProcessName) ? $"pid:{ev.PID}" : ev.ProcessName;
                string target = ev.TID > 0 ? $"tid={ev.TID}" : string.Empty;

                row.Details.Add(new GroupedEventDetailRow {
                    TimestampUtc = ev.TimestampUtc, Event = eventName, Severity = "Event",
                    Detection = ev.Summary ?? string.Empty, Source = group, Actor = actor, Target = target,
                    ActorPid = ev.PID > 0 ? unchecked((uint)ev.PID) : 0u, TargetPid = 0u,
                    ActorToolTip = ev.PID > 0 ? $"PID {ev.PID}" : string.Empty, Details = ev.Details ?? string.Empty
                });
            }

            return row;
        }

        private void TogglePerformanceFloatDock()
        {
            if (_performanceFloatWindow == null)
            {
                UndockPerformancePane();
            }
            else
            {
                RedockPerformancePane();
            }
        }

        private void ToggleEtwFloatDock()
        {
            if (_etwFloatWindow == null)
                UndockEtwPane();
            else
                RedockEtwPane();
        }

        private void ToggleHeuristicsFloatDock()
        {
            if (_heuristicsFloatWindow == null)
                UndockHeuristicsPane();
            else
                RedockHeuristicsPane();
        }

        private void ResetDock_Click(object sender, RoutedEventArgs e)
        {
            _eventsFloatWindow?.Close();
            _eventLogWindow?.Close();
            _performanceFloatWindow?.Close();
            _etwFloatWindow?.Close();
            _heuristicsFloatWindow?.Close();

            _laneFocusKey = null;
            EventsPaneHost.Timeline.ClearAllLaneFilters();
            EventsPaneHost.Timeline.ViewDurationSeconds = 120;
            EventsPaneHost.Timeline.ViewStartSeconds = 0;
            EventsPaneHost.Scroll.Value = 0;
            _followLiveTimeline = true;
            ShowEventsPane();
            ShowPerformancePane();
            var sw = FindExplorerItem("ETW");
            if (sw != null)
                sw.IsEnabled = true;
            var heur = FindExplorerItem("Heuristics");
            if (heur != null)
                heur.IsEnabled = true;
            var fs = FindExplorerItem("Filesystem");
            if (fs != null)
                fs.IsEnabled = true;
            var rel = FindExplorerItem("Process Relations");
            if (rel != null)
                rel.IsEnabled = true;
            var ipc = FindExplorerItem("IPC Uplink");
            if (ipc != null)
                ipc.IsEnabled = false;
            _performanceOnTop = false;
            _heuristicsOnTop = false;
            ApplyPaneOrder();
            ApplyIntelPaneOrder();
            HideDockPreview();
            FocusViewport();
            SyncPerformanceViewToTimeline();
        }

        private void DockEventsToggle_Click(object sender, RoutedEventArgs e)
        {
            ToggleFloatDock();
        }

        private void DockPerfToggle_Click(object sender, RoutedEventArgs e)
        {
            TogglePerformanceFloatDock();
        }

        private void DockEtwToggle_Click(object sender, RoutedEventArgs e)
        {
            ToggleEtwFloatDock();
        }

        private void DockHeurToggle_Click(object sender, RoutedEventArgs e)
        {
            ToggleHeuristicsFloatDock();
        }

        private void DockSwapMain_Click(object sender, RoutedEventArgs e)
        {
            TogglePaneOrder();
        }

        private void DockSwapIntel_Click(object sender, RoutedEventArgs e)
        {
            ToggleIntelPaneOrder();
        }

        private void ChildProcessView_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            OpenOrActivateChildProcessGraphWindow();
        }

        private void OpenLaneSettings()
        {
            var w = new LaneSettingsWindow(this);
            w.Owner = this;
            w.Show();
        }

        private void Diagnostics_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            OpenDiagnosticsWindow();
        }
    }
}
