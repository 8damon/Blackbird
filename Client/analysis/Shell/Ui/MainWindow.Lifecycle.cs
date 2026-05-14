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
        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            PidBox.Text = string.Empty;
            _samplerPid = 0;

            _captureStartUtc = AnchorCaptureStartUtc(DefaultTimelineViewDurationSeconds);
            _latestEventTimestampUtc = _captureStartUtc;

            EventsPaneHost.Grid.ItemsSource = _focusedEvents;
            EventsPaneHost.SetHasData(false);
            EventsPaneHost.SetEventLogDetached(false);

            EventsPaneHost.Timeline.CaptureStartUtc = _captureStartUtc;
            EventsPaneHost.Timeline.ViewDurationSeconds = DefaultTimelineViewDurationSeconds;
            EventsPaneHost.Timeline.ViewStartSeconds = 0;

            EventsPaneHost.Timeline.LaneInteraction += Timeline_LaneInteraction;
            EventsPaneHost.Timeline.SelectedEventChanged += Timeline_SelectedEventChanged;
            EventsPaneHost.Timeline.EventDoubleClicked += Timeline_EventDoubleClicked;

            EventsPaneHost.Grid.SelectionChanged += Grid_SelectionChanged;

            EventsPaneHost.Scroll.ValueChanged += Scroll_ValueChanged;

            EventsPaneHost.CloseRequested += (_, __) => HideEventsPane();
            EventsPaneHost.FloatRequested += (_, __) => ToggleFloatDock();
            EventsPaneHost.LogPopoutRequested += (_, __) => ToggleEventLogDock();
            EventsPaneHost.SettingsRequested += (_, __) => OpenLaneSettings();
            EventsPaneHost.LaneFilterSelectionChanged += (_, key) => SetLaneFocus(key);
            EventsPaneHost.EventLogEntryOpenRequested += EventsPaneHost_EventLogEntryOpenRequested;
            EventsPaneHost.HeaderDragStarted += (_, a) => BeginPaneHeaderDrag(isEventsPane: true, a.ScreenPosition);
            EventsPaneHost.HeaderDragDelta += (_, a) => ContinuePaneHeaderDrag(isEventsPane: true, a.ScreenPosition);
            EventsPaneHost.HeaderDragCompleted += (_, a) => EndPaneHeaderDrag(isEventsPane: true, a.ScreenPosition);
            PerformancePaneHost.CloseRequested += (_, __) => HidePerformancePane();
            PerformancePaneHost.ReorderRequested += (_, __) => TogglePaneOrder();
            PerformancePaneHost.FloatRequested += (_, __) => TogglePerformanceFloatDock();
            PerformancePaneHost.ThreadDoubleClicked += PerformancePaneHost_ThreadDoubleClicked;
            PerformancePaneHost.ParallelStacksRequested += (_, __) => OpenParallelStacksWindow();
            PerformancePaneHost.HeaderDragStarted += (_, a) =>
                BeginPaneHeaderDrag(isEventsPane: false, a.ScreenPosition);
            PerformancePaneHost.HeaderDragDelta += (_, a) =>
                ContinuePaneHeaderDrag(isEventsPane: false, a.ScreenPosition);
            PerformancePaneHost.HeaderDragCompleted += (_, a) =>
                EndPaneHeaderDrag(isEventsPane: false, a.ScreenPosition);
            EtwPaneHost.ReorderRequested += (_, __) => ToggleIntelPaneOrder();
            EtwPaneHost.FloatRequested += (_, __) => ToggleEtwFloatDock();
            EtwPaneHost.CloseRequested += (_, __) => HideEtwPane();
            EtwPaneHost.InspectRequested += (_, __) => OpenEtwInspector();
            HeuristicsPaneHost.ReorderRequested += (_, __) => ToggleIntelPaneOrder();
            HeuristicsPaneHost.FloatRequested += (_, __) => ToggleHeuristicsFloatDock();
            HeuristicsPaneHost.CloseRequested += (_, __) => HideHeuristicsPane();
            HeuristicsPaneHost.InspectRequested += (_, __) => OpenHeuristicsInspector();
            FilesystemPaneHost.CloseRequested += (_, __) => HideFilesystemPane();
            FilesystemPaneHost.InspectRequested += (_, __) => OpenFilesystemInspector();
            RegistryPaneHost.CloseRequested += (_, __) => HideRegistryPane();
            RegistryPaneHost.InspectRequested += (_, __) => OpenRegistryInspector();
            ProcessRelationsPaneHost.CloseRequested += (_, __) => HideProcessRelationsPane();
            ProcessRelationsPaneHost.InspectRequested += (_, __) => OpenProcessRelationsInspector();
            ProcessRelationsPaneHost.GraphStateChanged += ProcessRelationsPaneHost_GraphStateChanged;
            SetupExplorer();
            ApplyInterfacePreferences(_interfacePreferences, persist: false);
            SetupProcessTabs();
            InitializeBackendUi();
            InitializeRuntimeConfigDefaults();
            ApiViewDataGrid.ItemsSource = _apiViewRows;
            if (ExtendedViewDataGrid != null)
            {
                ExtendedViewDataGrid.ItemsSource = _extendedViewRows;
            }
            if (ExtendedComDataGrid != null)
            {
                ExtendedComDataGrid.ItemsSource = _extendedComRows;
            }
            if (ExtendedEtwDataGrid != null)
            {
                ExtendedEtwDataGrid.ItemsSource = _extendedEtwRows;
            }
            if (ExtendedJobDataGrid != null)
            {
                ExtendedJobDataGrid.ItemsSource = _extendedJobRows;
            }
            if (ExtendedYaraDataGrid != null)
            {
                ExtendedYaraDataGrid.ItemsSource = _extendedYaraRows;
            }
            if (ExtendedStringsDataGrid != null)
            {
                ExtendedStringsDataGrid.ItemsSource = _extendedStringRows;
            }
            if (ExtendedCapabilitiesDataGrid != null)
            {
                ExtendedCapabilitiesDataGrid.ItemsSource = _extendedCapabilityRows;
            }
            ApiViewDataGrid.SelectedIndex = -1;
            UpdateApiViewSelection(null);
            SetMainInterfaceViewMode(MainInterfaceViewMode.Telemetry);
            ApplyUplinkStatusVisual(healthy: null);

            UpdateScrollBar();
            FocusViewport();
            UpdateTopTimeTravelBar();
            RebuildToolbarViewMenuOptions();

            _perf = new PerformanceSampler();
            _perf.SampleArrived += Perf_SampleArrived;

            PerformancePaneHost.SetCaptureStart(_captureStartUtc);
            PerformancePaneHost.SetPid(TryGetPid());
            PerformancePaneHost.SetProcessLiveDataAvailable(false);
            PerformancePaneHost.SetTargetSuspended(false);
            SyncPerformanceViewToTimeline();
            StatusBlock.Text = "NO TARGET SELECTED";
            ApplyPaneOrder();
            ApplyIntelPaneOrder();
            _processStateRefreshTimer.Start();
            _apiGraphRefreshTimer.Start();
            _timelineLiveTickTimer.Start();
            RefreshProcessStateBadge();
        }

        private void SetupProcessTabs()
        {
            ProcessTabs.ItemsSource = _processTabs;
            _currentSession = null;
        }

        private void OnClosing(object? sender, CancelEventArgs e)
        {
            _ = sender;
            if (!PrepareSessionShutdown())
            {
                e.Cancel = true;
                return;
            }

            _isMainWindowShuttingDown = true;
            CancelActiveAnalysisOperationForShutdown();
        }

        private void OnClosed(object? sender, EventArgs e)
        {
            _isMainWindowShuttingDown = true;
            CancelActiveAnalysisOperationForShutdown();
            PersistCurrentInterfacePreferences();
            DisposeSignatureIntelSubsystem();
            _detachedEventLogRefreshTimer.Stop();
            _processStateRefreshTimer.Stop();
            _apiGraphRefreshTimer.Stop();
            _timelineLiveTickTimer.Stop();

            if (_perf != null)
            {
                _perf.SampleArrived -= Perf_SampleArrived;
                _perf.Stop();
                _perf = null;
            }

            if (_eventsFloatWindow != null)
            {
                _eventsFloatWindow.Closing -= EventsFloatWindow_Closing;
                _eventsFloatWindow.Closed -= EventsFloatWindow_Closed;
                if (_eventsFloatWindow.Content == EventsPaneHost)
                {
                    _eventsFloatWindow.Content = null;
                }
                _eventsFloatWindow.Close();
                _eventsFloatWindow = null;
            }
            if (_eventLogWindow != null)
            {
                _eventLogWindow.Closed -= EventLogWindow_Closed;
                _eventLogWindow.Close();
                _eventLogWindow = null;
            }
            if (_performanceFloatWindow != null)
            {
                _performanceFloatWindow.Closing -= PerformanceFloatWindow_Closing;
                _performanceFloatWindow.Closed -= PerformanceFloatWindow_Closed;
                if (_performanceFloatWindow.Content == PerformancePaneHost)
                {
                    _performanceFloatWindow.Content = null;
                }
                _performanceFloatWindow.Close();
                _performanceFloatWindow = null;
            }
            if (_etwFloatWindow != null)
            {
                _etwFloatWindow.Closing -= EtwFloatWindow_Closing;
                _etwFloatWindow.Closed -= EtwFloatWindow_Closed;
                if (_etwFloatWindow.Content == EtwPaneHost)
                {
                    _etwFloatWindow.Content = null;
                }
                _etwFloatWindow.Close();
                _etwFloatWindow = null;
            }
            if (_heuristicsFloatWindow != null)
            {
                _heuristicsFloatWindow.Closing -= HeuristicsFloatWindow_Closing;
                _heuristicsFloatWindow.Closed -= HeuristicsFloatWindow_Closed;
                if (_heuristicsFloatWindow.Content == HeuristicsPaneHost)
                {
                    _heuristicsFloatWindow.Content = null;
                }
                _heuristicsFloatWindow.Close();
                _heuristicsFloatWindow = null;
            }
            if (_childProcessGraphWindow != null)
            {
                SaveChildProcessGraphStateToSession();
                _childProcessGraphWindow.Closed -= ChildProcessGraphWindow_Closed;
                _childProcessGraphWindow.Close();
                _childProcessGraphWindow = null;
            }
            ProcessRelationsPaneHost.GraphStateChanged -= ProcessRelationsPaneHost_GraphStateChanged;
            _childProcessGraphRefreshTimer.Stop();
            SaveIntelSessionState(_currentSession?.Pid ?? 0);
            StopLiveAnalysisSession(LiveAnalysisStopReason.Shutdown, fastTeardown: true, stopPerformance: true);
            DisposePreparedLaunchBackendSession();
            TerminateLaunchOwnedTargetsOnShutdown();
            HideDockPreview();
            CleanupTemporarySessionBackingStores();
        }
    }
}
