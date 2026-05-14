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
        private void SyncPerformanceViewToTimeline()
        {
            var viewStart = _captureStartUtc + TimeSpan.FromSeconds(EventsPaneHost.Timeline.ViewStartSeconds);
            var viewEnd = viewStart + TimeSpan.FromSeconds(EventsPaneHost.Timeline.ViewDurationSeconds);

            PerformancePaneHost.SetViewWindow(viewStart, viewEnd);
        }

        private void ApplyTimelineViewport(double targetStart, bool syncScroll, bool updateFollowState)
        {
            if (EventsPaneHost?.Scroll == null || EventsPaneHost?.Timeline == null)
            {
                return;
            }

            double viewport = Math.Max(1, EventsPaneHost.Scroll.ViewportSize);
            double maxStart = ComputeTimelineMaxStart(viewport);
            double clamped = Math.Max(0, Math.Min(maxStart, targetStart));
            if (updateFollowState)
            {
                _followLiveTimeline = maxStart <= 0.001 || Math.Abs(clamped - maxStart) < 0.25;
            }

            _pendingScrollStartSeconds = clamped;
            EventsPaneHost.Timeline.ViewStartSeconds = clamped;
            if (syncScroll && Math.Abs(EventsPaneHost.Scroll.Value - clamped) > 0.001)
            {
                EventsPaneHost.Scroll.Value = clamped;
            }

            FocusViewport();
            UpdateTopTimeTravelBar();
            SyncPerformanceViewToTimeline();
        }

        private void AppendEvent(TelemetryEvent ev)
        {
            AppendEvents(new[] { ev });
        }

        private void AppendEvents(IReadOnlyList<TelemetryEvent> events)
        {
            if (events.Count == 0)
            {
                return;
            }

            bool laneKeysChanged = false;
            for (int i = 0; i < events.Count; i += 1)
            {
                TelemetryEvent ev = NormalizeTelemetryEventForStore(events[i]);
                _allEvents.Add(ev);
                _currentSession?.Events.Add(ev);
                if (ev.TimestampUtc > _latestEventTimestampUtc)
                {
                    _latestEventTimestampUtc = ev.TimestampUtc;
                }
                if (!string.IsNullOrWhiteSpace(ev.Group) && _knownLaneKeys.Add(ev.Group))
                {
                    laneKeysChanged = true;
                }
            }

            SetExplorerHasData("Events", _allEvents.Count > 0);
            EventsPaneHost.SetHasData(true);
            if (laneKeysChanged)
            {
                EventsPaneHost.SetLaneFilterOptions(_knownLaneKeys.OrderBy(k => k));
            }
            ScheduleViewportRefresh();
        }

        internal void SetBackendConnectivity(bool healthy)
        {
            _connectivityHealthy = healthy;
            ApplyUplinkStatusVisual(healthy);
            EventsPaneHost.SetConnectivityHealthy(healthy);
            EventsPaneHost.SetHasData(_allEvents.Count > 0);
            RefreshExplorerDataBadges();
        }

        private void ApplyUplinkStatusVisual(bool? healthy)
        {
            if (StatusBlock == null)
                return;

            if (healthy == true)
            {
                StatusBlock.SetResourceReference(TextBlock.ForegroundProperty, "WinMutedTextBrush");
                return;
            }

            if (healthy == false)
            {
                StatusBlock.SetResourceReference(TextBlock.ForegroundProperty, "StatusFailedBrush");
                return;
            }

            StatusBlock.SetResourceReference(TextBlock.ForegroundProperty, "WinMutedTextBrush");
        }

        private void UpdateWindowTitle()
        {
            string sessionLabel;
            if (_currentSession == null || _currentSession.Pid <= 0)
            {
                sessionLabel = "IDLE";
            }
            else if (_currentSession.OfflineSnapshot)
            {
                sessionLabel = $"OFFLINE SESSION: {NormalizeSessionTitle(_currentSession.Title)}";
            }
            else if (_currentSession.TargetExited)
            {
                sessionLabel = $"[CAPTURE {_currentSession.Pid} — STOPPED]";
            }
            else
            {
                string captureTitle = NormalizeSessionTitle(_currentSession.Title ?? $"PID {_currentSession.Pid}");
                sessionLabel = $"[CAPTURE {_currentSession.Pid} {captureTitle}]";
            }

            string newTitle = $"{WindowTitleBase} {sessionLabel}";
            if (!string.Equals(Title, newTitle, StringComparison.Ordinal))
            {
                Title = newTitle;
            }
        }

        private void RefreshProcessStateBadge()
        {
            UpdateWindowTitle();
            RefreshToolbarCommandState();

            if (ProcessStateBadge == null || ProcessStateBlock == null)
            {
                return;
            }

            if (_currentSession == null || _currentSession.Pid <= 0)
            {
                SetProcessStateVisual("Disconnected", ProcessStateUnknownBackground, ProcessStateUnknownBorder,
                                      ProcessStateUnknownForeground);
                return;
            }

            string labelPrefix = $"PID {_currentSession.Pid}";
            if (_currentSession.OfflineSnapshot)
            {
                SetProcessStateVisual($"{labelPrefix} • Exited (offline capture)", ProcessStateExitedBackground,
                                      ProcessStateExitedBorder, ProcessStateExitedForeground);
                return;
            }

            if (_currentSession.TargetExited)
            {
                string reason = string.IsNullOrWhiteSpace(_currentSession.TargetExitReason)
                                    ? "capture available"
                                    : _currentSession.TargetExitReason;
                SetProcessStateVisual($"{labelPrefix} • Exited ({reason})", ProcessStateExitedBackground,
                                      ProcessStateExitedBorder, ProcessStateExitedForeground);
                return;
            }

            IntelScopeStatus scope = ((IIntelDetailsProvider)this).GetIntelScopeStatus();
            switch (scope)
            {
            case IntelScopeStatus.Running:
                SetProcessStateVisual($"{labelPrefix} • Connected / Running", ProcessStateRunningBackground,
                                      ProcessStateRunningBorder, ProcessStateRunningForeground);
                break;
            case IntelScopeStatus.Waiting:
                SetProcessStateVisual($"{labelPrefix} • Suspended / Waiting", ProcessStateWaitingBackground,
                                      ProcessStateWaitingBorder, ProcessStateWaitingForeground);
                break;
            case IntelScopeStatus.Exited:
                SetProcessStateVisual($"{labelPrefix} • Exited (capture available)", ProcessStateExitedBackground,
                                      ProcessStateExitedBorder, ProcessStateExitedForeground);
                break;
            default:
                SetProcessStateVisual($"{labelPrefix} • Connected / Unknown", ProcessStateUnknownBackground,
                                      ProcessStateUnknownBorder, ProcessStateUnknownForeground);
                break;
            }
        }

        private void SetProcessStateVisual(string text, Brush background, Brush border, Brush foreground)
        {
            ProcessStateBlock.Text = text;
            ProcessStateBadge.Background = background;
            ProcessStateBadge.BorderBrush = border;
            ProcessStateBlock.Foreground = foreground;
        }

        private void RefreshToolbarCommandState()
        {
            bool hasAttachedTarget = _currentSession != null && _currentSession.Pid > 0 &&
                                     !_currentSession.OfflineSnapshot && !_currentSession.TargetExited;

            bool canPause = hasAttachedTarget;
            bool canResume = hasAttachedTarget && _targetExecutionSuspended;
            if (canResume)
            {
                canPause = false;
            }

            SetToolbarCommandButtonState(TargetCommandButton, TargetCommandGlyph, true, ToolbarTargetBackground,
                                         ToolbarTargetBorder, ToolbarTargetForeground);
            SetToolbarCommandButtonState(PauseCommandButton, PauseCommandGlyph, canPause, ToolbarPauseBackground,
                                         ToolbarPauseBorder, ToolbarPauseForeground);
            SetToolbarCommandButtonState(ResumeCommandButton, ResumeCommandGlyph, canResume, ToolbarResumeBackground,
                                         ToolbarResumeBorder, ToolbarResumeForeground);
            SetToolbarCommandButtonState(TerminateCommandButton, TerminateCommandGlyph, hasAttachedTarget,
                                         ToolbarStopBackground, ToolbarStopBorder, ToolbarStopForeground);
            RefreshHooksButtonState();

            if (TimeTravelLiveNotice != null)
            {
                bool targetStopped = _currentSession != null && _currentSession.TargetExited;
                TimeTravelLiveNotice.Visibility = targetStopped ? Visibility.Collapsed : Visibility.Visible;
            }
        }

        private static void SetToolbarCommandButtonState(Button? button, Border? glyph, bool enabled,
                                                         Brush activeBackground, Brush activeBorder,
                                                         Brush activeForeground)
        {
            if (button == null || glyph == null)
            {
                return;
            }

            button.IsEnabled = enabled;
            button.Background = enabled ? activeBackground : ToolbarInactiveBackground;
            button.BorderBrush = enabled ? activeBorder : ToolbarInactiveBorder;
            button.Foreground = enabled ? activeForeground : ToolbarInactiveForeground;
            glyph.Background = enabled ? activeForeground : ToolbarInactiveForeground;
        }

        private void Scroll_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            double viewport = Math.Max(1, EventsPaneHost.Scroll.ViewportSize);
            double maxStart = ComputeTimelineMaxStart(viewport);
            double clamped = Math.Max(0, Math.Min(maxStart, EventsPaneHost.Scroll.Value));
            _pendingScrollStartSeconds = clamped;
            EventsPaneHost.Timeline.ViewStartSeconds = clamped;
            _followLiveTimeline = maxStart <= 0.001 || Math.Abs(clamped - maxStart) < 0.25;

            if (_scrollSyncPending)
            {
                return;
            }

            _scrollSyncPending = true;
            Dispatcher.BeginInvoke(new Action(() =>
                                              {
                                                  _scrollSyncPending = false;
                                                  ApplyTimelineViewport(_pendingScrollStartSeconds, syncScroll: false,
                                                                        updateFollowState: false);
                                              }),
                                   DispatcherPriority.Render);
        }

        private void UpdateScrollBar()
        {
            if (_allEvents.Count == 0)
            {
                EventsPaneHost.Scroll.Maximum = 0;
                EventsPaneHost.Scroll.ViewportSize = 1;
                EventsPaneHost.Scroll.SmallChange = 1;
                EventsPaneHost.Scroll.LargeChange = 1;
                EventsPaneHost.Scroll.Value = 0;
                EventsPaneHost.Timeline.ViewStartSeconds = 0;
                _latestEventTimestampUtc = _captureStartUtc;
                UpdateTopTimeTravelBar();
                return;
            }

            DateTime horizonUtc = GetTimelineHorizonUtc();
            var totalSeconds = (horizonUtc - _captureStartUtc).TotalSeconds;
            if (totalSeconds < 0)
            {
                totalSeconds = 0;
            }

            double duration = Math.Max(1, EventsPaneHost.Timeline.ViewDurationSeconds);
            double maxStart = Math.Max(0, totalSeconds - duration);
            EventsPaneHost.Scroll.ViewportSize = duration;
            EventsPaneHost.Scroll.Maximum = maxStart;
            EventsPaneHost.Scroll.SmallChange = Math.Max(1, duration / 20.0);
            EventsPaneHost.Scroll.LargeChange = Math.Max(1, duration * 0.8);

            if (EventsPaneHost.Timeline.ViewStartSeconds > maxStart)
            {
                EventsPaneHost.Timeline.ViewStartSeconds = maxStart;
            }

            if (EventsPaneHost.Scroll.Value > maxStart)
            {
                EventsPaneHost.Scroll.Value = maxStart;
            }

            UpdateTopTimeTravelBar();
        }

        private void FocusViewport()
        {
            var viewStart = _captureStartUtc + TimeSpan.FromSeconds(EventsPaneHost.Timeline.ViewStartSeconds);
            var viewEnd = viewStart + TimeSpan.FromSeconds(EventsPaneHost.Timeline.ViewDurationSeconds);
            var selectedAnchor = CaptureSelectedEventAnchor();

            double durationSeconds = Math.Max(1, (viewEnd - viewStart).TotalSeconds);
            RangeBlock.Text = $"Window {viewStart:HH:mm:ss}-{viewEnd:HH:mm:ss}  {durationSeconds:0}s";

            if (_allEvents.Count == 0)
            {
                _focusedEvents.ReplaceAll(Array.Empty<TelemetryEvent>());
                EventsPaneHost.Timeline.ReplaceItems(_focusedEvents);
                SetExplorerHasData("Events", false);
                EventsPaneHost.SetHeaderStats("View 0 | Total 0 | 0.0/s");
                ClearSelectedEvent();
                UpdateDetachedEventLogWindow();
                return;
            }

            int start = LowerBoundEventIndex(viewStart);
            int endExclusive = UpperBoundEventIndex(viewEnd);
            var rawVisibleEvents = new List<TelemetryEvent>(Math.Max(16, endExclusive - start));
            for (int i = start; i < endExclusive; i += 1)
            {
                var ev = _allEvents[i];
                if (!PassLaneFocus(ev))
                {
                    continue;
                }
                rawVisibleEvents.Add(ev);
            }

            var visibleEvents =
                ClusterViewportEvents(rawVisibleEvents, Math.Max(1.0, EventsPaneHost.Timeline.ViewDurationSeconds));
            _focusedEvents.ReplaceAll(visibleEvents);
            EventsPaneHost.Timeline.ReplaceItems(_focusedEvents);

            RestoreSelectedEventInFocusedView(selectedAnchor);
            FindExplorerItem("Events")?.PushPreviewValue(_focusedEvents.Count);
            SetExplorerHasData("Events", _allEvents.Count > 0);
            double viewSeconds = Math.Max(1.0, EventsPaneHost.Timeline.ViewDurationSeconds);
            double rate = rawVisibleEvents.Count / viewSeconds;
            EventsPaneHost.SetHeaderStats(
                $"View {_focusedEvents.Count} clustered | Raw {rawVisibleEvents.Count} | Total {_allEvents.Count} | {rate:0.0}/s");
            UpdateDetachedEventLogWindow();
            UpdateTopTimeTravelBar();
        }

        private IReadOnlyList<TelemetryEvent> ClusterViewportEvents(IReadOnlyList<TelemetryEvent> rawVisibleEvents,
                                                                    double viewDurationSeconds)
        {
            _focusedClusterMembers.Clear();
            if (rawVisibleEvents.Count == 0)
            {
                return Array.Empty<TelemetryEvent>();
            }

            if (rawVisibleEvents.Count <= 180)
            {
                for (int i = 0; i < rawVisibleEvents.Count; i += 1)
                {
                    TelemetryEvent raw = rawVisibleEvents[i];
                    _focusedClusterMembers[new EventSelectionKey(raw)] = new[] { raw };
                }

                return rawVisibleEvents;
            }

            int targetVisibleCount =
                Math.Clamp((int)Math.Round((EventsPaneHost?.Timeline?.ActualWidth ?? 1280.0) / 9.0), 80, 160);
            bool includeThreadId = rawVisibleEvents.Count <= 800;
            double bucketSeconds = Math.Max(0.12, viewDurationSeconds / Math.Max(60, targetVisibleCount));
            List<TelemetryEvent> clustered = new();

            for (int iteration = 0; iteration < 5; iteration += 1)
            {
                clustered = BuildClusteredViewportEvents(rawVisibleEvents, bucketSeconds, includeThreadId);
                if (clustered.Count <= targetVisibleCount)
                {
                    break;
                }

                if (includeThreadId && rawVisibleEvents.Count > targetVisibleCount * 2)
                {
                    includeThreadId = false;
                    continue;
                }

                bucketSeconds *= 1.7;
            }

            return clustered;
        }

        private List<TelemetryEvent> BuildClusteredViewportEvents(IReadOnlyList<TelemetryEvent> rawVisibleEvents,
                                                                  double bucketSeconds, bool includeThreadId)
        {
            var buckets = new Dictionary<string, List<TelemetryEvent>>(StringComparer.Ordinal);
            for (int i = 0; i < rawVisibleEvents.Count; i += 1)
            {
                TelemetryEvent ev = rawVisibleEvents[i];
                long bucketIndex = (long)Math.Floor(Math.Max(0, (ev.TimestampUtc - _captureStartUtc).TotalSeconds) /
                                                    Math.Max(0.01, bucketSeconds));
                string normalizedSummary = NormalizeClusterSummary(ev.Summary);
                int clusterTid = includeThreadId ? ev.TID : 0;
                string key =
                    $"{bucketIndex}|{ev.PID}|{clusterTid}|{ev.Group}|{ev.SubType}|{normalizedSummary}|{ev.ProcessName}";
                if (!buckets.TryGetValue(key, out List<TelemetryEvent>? members))
                {
                    members = new List<TelemetryEvent>(4);
                    buckets[key] = members;
                }

                members.Add(ev);
            }

            var displayEvents = new List<TelemetryEvent>(buckets.Count);
            foreach (List<TelemetryEvent> members in buckets.Values.OrderBy(x => x[^1].TimestampUtc))
            {
                if (members.Count == 1)
                {
                    TelemetryEvent raw = members[0];
                    _focusedClusterMembers[new EventSelectionKey(raw)] = members;
                    displayEvents.Add(raw);
                    continue;
                }

                TelemetryEvent first = members[0];
                TelemetryEvent last = members[^1];
                bool mixedThreads = members.Any(x => x.TID != first.TID);
                bool mixedProcesses = members.Any(x => x.PID != first.PID);
                string baseSummary = string.IsNullOrWhiteSpace(last.Summary) ? last.SubType : last.Summary;
                string summary = $"[{members.Count}x] {baseSummary}";
                string details =
                    $"cluster-count={members.Count}; first={first.TimestampUtc:O}; last={last.TimestampUtc:O}; " +
                    $"group={first.Group}; subtype={first.SubType}; mixedThreads={(mixedThreads ? "yes" : "no")}; mixedProcesses={(mixedProcesses ? "yes" : "no")}";

                var clustered = new TelemetryEvent { TimestampUtc = last.TimestampUtc,
                                                     PID = mixedProcesses ? 0 : first.PID,
                                                     TID = mixedThreads ? 0 : first.TID,
                                                     Group = first.Group,
                                                     SubType = first.SubType,
                                                     ProcessName = first.ProcessName,
                                                     Summary = summary,
                                                     Details = details };

                _focusedClusterMembers[new EventSelectionKey(clustered)] = members;
                displayEvents.Add(clustered);
            }

            return displayEvents;
        }

        private static string NormalizeClusterSummary(string? summary)
        {
            if (string.IsNullOrWhiteSpace(summary))
            {
                return string.Empty;
            }

            string normalized = summary.Trim();
            if (normalized.Length > 160)
            {
                normalized = normalized[..160];
            }

            return normalized;
        }

        private IReadOnlyList<TelemetryEvent> GetFocusedEventMembers(TelemetryEvent? displayEvent)
        {
            if (displayEvent == null)
            {
                return Array.Empty<TelemetryEvent>();
            }

            if (_focusedClusterMembers.TryGetValue(new EventSelectionKey(displayEvent), out IReadOnlyList<TelemetryEvent>? members))
            {
                return members;
            }

            return new[] { displayEvent };
        }

        private IReadOnlyList<TelemetryEvent> ExpandFocusedEventMembers(IEnumerable<TelemetryEvent> displayEvents)
        {
            var expanded = new List<TelemetryEvent>();
            foreach (TelemetryEvent ev in displayEvents)
            {
                expanded.AddRange(GetFocusedEventMembers(ev));
            }

            return expanded;
        }

        private void UpdateTopTimeTravelBar()
        {
            if (TopTimeTravelSlider == null || TopTimeTravelRangeBlock == null || EventsPaneHost?.Scroll == null ||
                EventsPaneHost?.Timeline == null)
            {
                return;
            }

            double viewport = Math.Max(1, EventsPaneHost.Scroll.ViewportSize);
            double maxStart = ComputeTimelineMaxStart(viewport);
            double start = Math.Max(0, Math.Min(maxStart, EventsPaneHost.Timeline.ViewStartSeconds));

            _topTimeTravelSyncing = true;
            TopTimeTravelSlider.Minimum = 0;
            TopTimeTravelSlider.Maximum = Math.Max(0, maxStart);
            TopTimeTravelSlider.Value = start;
            TopTimeTravelSlider.SmallChange = Math.Max(1, viewport / 30.0);
            TopTimeTravelSlider.LargeChange = Math.Max(1, viewport * 0.5);
            TopTimeTravelSlider.IsEnabled = maxStart > 0.001;
            _topTimeTravelSyncing = false;

            DateTime viewStart = _captureStartUtc + TimeSpan.FromSeconds(start);
            DateTime viewEnd = viewStart + TimeSpan.FromSeconds(viewport);
            TopTimeTravelRangeBlock.Text = $"{viewStart:HH:mm:ss}-{viewEnd:HH:mm:ss}";
        }

        private void TopTimeTravelSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (_topTimeTravelSyncing || EventsPaneHost?.Scroll == null || EventsPaneHost?.Timeline == null)
            {
                return;
            }

            ApplyTimelineViewport(e.NewValue, syncScroll: true, updateFollowState: true);
        }

        private void NudgeTopTimeTravel(double secondsDelta)
        {
            if (EventsPaneHost?.Scroll == null || EventsPaneHost?.Timeline == null)
            {
                return;
            }

            ApplyTimelineViewport(EventsPaneHost.Scroll.Value + secondsDelta, syncScroll: true,
                                  updateFollowState: true);
        }

        private void TopTimeTravelBack10_Click(object sender, RoutedEventArgs e) => NudgeTopTimeTravel(-10);
        private void TopTimeTravelBack1_Click(object sender, RoutedEventArgs e) => NudgeTopTimeTravel(-1);
        private void TopTimeTravelForward1_Click(object sender, RoutedEventArgs e) => NudgeTopTimeTravel(1);
        private void TopTimeTravelForward10_Click(object sender, RoutedEventArgs e) => NudgeTopTimeTravel(10);

        private void ScheduleViewportRefresh()
        {
            if (_viewportRefreshPending)
            {
                return;
            }

            _viewportRefreshPending = true;
            Dispatcher.BeginInvoke(
                new Action(
                    () =>
                    {
                        _viewportRefreshPending = false;
                        UpdateScrollBar();
                        if (_followLiveTimeline && EventsPaneHost?.Scroll != null)
                        {
                            ApplyTimelineViewport(
                                ComputeTimelineMaxStart(Math.Max(1, EventsPaneHost.Scroll.ViewportSize)),
                                syncScroll: true, updateFollowState: false);
                        }
                        else
                        {
                            FocusViewport();
                            UpdateTopTimeTravelBar();
                            SyncPerformanceViewToTimeline();
                        }
                        double viewStartSeconds = EventsPaneHost?.Timeline?.ViewStartSeconds ?? 0;
                        DiagnosticsState.SetValue(
                            "UI Viewport",
                            $"view={_focusedEvents.Count} total={_allEvents.Count} start={viewStartSeconds:0.0}s");
                    }),
                System.Windows.Threading.DispatcherPriority.Background);
        }

        private double ComputeTimelineMaxStart(double viewportSeconds)
        {
            double viewport = Math.Max(1, viewportSeconds);
            double totalSeconds = Math.Max(0, (GetTimelineHorizonUtc() - _captureStartUtc).TotalSeconds);
            return Math.Max(0, totalSeconds - viewport);
        }

        private DateTime GetTimelineHorizonUtc()
        {
            DateTime eventHorizon =
                _latestEventTimestampUtc > _captureStartUtc ? _latestEventTimestampUtc : _captureStartUtc;
            return eventHorizon;
        }

        private static DateTime AnchorCaptureStartUtc(double viewDurationSeconds)
        {
            double seconds = Math.Max(1, viewDurationSeconds);
            return DateTime.UtcNow - TimeSpan.FromSeconds(seconds);
        }

        private TelemetryEvent NormalizeTelemetryEventForStore(TelemetryEvent source)
        {
            string group = _telemetryTextPool.Intern(source.Group, 48);
            string subType = _telemetryTextPool.Intern(source.SubType, 96);
            string processName = _telemetryTextPool.Intern(source.ProcessName, 96);
            string summary = _telemetryTextPool.Intern(source.Summary, 160);
            string details = _telemetryTextPool.Intern(source.Details, 384);

            if (ReferenceEquals(group, source.Group) && ReferenceEquals(subType, source.SubType) &&
                ReferenceEquals(processName, source.ProcessName) && ReferenceEquals(summary, source.Summary) &&
                ReferenceEquals(details, source.Details))
            {
                return source;
            }

            return new TelemetryEvent { TimestampUtc = source.TimestampUtc,
                                        PID = source.PID,
                                        TID = source.TID,
                                        Group = group,
                                        SubType = subType,
                                        ProcessName = processName,
                                        Summary = summary,
                                        Details = details };
        }

        private int LowerBoundEventIndex(DateTime timestampUtc)
        {
            int lo = 0;
            int hi = _allEvents.Count;
            while (lo < hi)
            {
                int mid = lo + ((hi - lo) / 2);
                if (_allEvents[mid].TimestampUtc < timestampUtc)
                {
                    lo = mid + 1;
                }
                else
                {
                    hi = mid;
                }
            }

            return lo;
        }

        private int UpperBoundEventIndex(DateTime timestampUtc)
        {
            int lo = 0;
            int hi = _allEvents.Count;
            while (lo < hi)
            {
                int mid = lo + ((hi - lo) / 2);
                if (_allEvents[mid].TimestampUtc <= timestampUtc)
                {
                    lo = mid + 1;
                }
                else
                {
                    hi = mid;
                }
            }

            return lo;
        }

        private bool PassLaneFocus(TelemetryEvent ev)
        {
            if (string.IsNullOrWhiteSpace(_laneFocusKey))
                return true;

            string key = string.IsNullOrWhiteSpace(ev.SubType) ? ev.Group : $"{ev.Group}/{ev.SubType}";
            return string.Equals(key, _laneFocusKey, StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(ev.Group, _laneFocusKey, StringComparison.OrdinalIgnoreCase);
        }

        private void Timeline_LaneInteraction(object? sender, LaneInteractionEventArgs e)
        {
            if (e.Button == System.Windows.Input.MouseButton.Left && !e.IsArrow)
            {
                _laneFocusKey = e.LaneKey;
                FocusViewport();
                return;
            }

            if (e.Button != System.Windows.Input.MouseButton.Right)
                return;

            var menu = new ContextMenu();

            var miEnableDisable =
                new MenuItem { Header = EventsPaneHost.Timeline.IsLaneVisible(e.LaneKey) ? "Disable" : "Enable" };
            miEnableDisable.Click += (_, __) =>
            {
                bool nowVisible = !EventsPaneHost.Timeline.IsLaneVisible(e.LaneKey);
                EventsPaneHost.Timeline.SetLaneVisible(e.LaneKey, nowVisible);
                FocusViewport();
            };
            menu.Items.Add(miEnableDisable);

            var miFilter = new MenuItem { Header = "Filter to selection" };
            miFilter.Click += (_, __) =>
            {
                _laneFocusKey = e.LaneKey;
                FocusViewport();
            };
            menu.Items.Add(miFilter);

            var miClear = new MenuItem { Header = "Clear filter" };
            miClear.Click += (_, __) =>
            {
                _laneFocusKey = null;
                EventsPaneHost.Timeline.ClearAllLaneFilters();
                FocusViewport();
            };
            menu.Items.Add(miClear);

            menu.Items.Add(new Separator());

            var miColor = new MenuItem { Header = "Set colour (cycle)" };
            miColor.Click += (_, __) =>
            {
                Color[] options = {
                    Color.FromRgb(0x4C, 0x8F, 0xD2), Color.FromRgb(0x6C, 0xA4, 0xDE), Color.FromRgb(0x58, 0xB6, 0x58),
                    Color.FromRgb(0x7B, 0xC7, 0x7B), Color.FromRgb(0x8D, 0x97, 0xA3),
                };

                int idx = (Math.Abs(e.LaneKey.GetHashCode()) % options.Length);
                var next = options[(idx + DateTime.UtcNow.Second) % options.Length];
                EventsPaneHost.Timeline.SetLaneColor(e.LaneKey, next);
            };
            menu.Items.Add(miColor);

            menu.IsOpen = true;
        }

        private void Timeline_EventDoubleClicked(object? sender, TelemetryEventSelectedEventArgs e)
        {
            _ = sender;
            _ = e;
        }

        private EventSelectionKey? CaptureSelectedEventAnchor()
        {
            if (_eventSelectionSyncing)
            {
                return _selectedEventAnchor;
            }

            if (EventsPaneHost.Grid.SelectedItem is TelemetryEvent selectedInGrid)
            {
                return new EventSelectionKey(selectedInGrid);
            }

            if (EventsPaneHost.Timeline.SelectedEvent is TelemetryEvent selectedInTimeline)
            {
                return new EventSelectionKey(selectedInTimeline);
            }

            return _selectedEventAnchor;
        }

        private void RestoreSelectedEventInFocusedView(EventSelectionKey? preferred)
        {
            if (preferred is not EventSelectionKey key || _focusedEvents.Count == 0)
            {
                if (preferred == null)
                {
                    ClearSelectedEvent();
                }
                return;
            }

            TelemetryEvent? matched = _focusedEvents.FirstOrDefault(ev => key.Matches(ev));
            if (matched != null)
            {
                ApplySelectedEvent(matched, scrollIntoView: false);
                return;
            }

            TelemetryEvent? clusteredMatch =
                _focusedEvents.FirstOrDefault(ev => GetFocusedEventMembers(ev).Any(raw => key.Matches(raw)));
            if (clusteredMatch != null)
            {
                ApplySelectedEvent(clusteredMatch, scrollIntoView: false);
                return;
            }

            if (_selectedEventAnchor.HasValue && !_selectedEventAnchor.Value.Equals(key))
            {
                TelemetryEvent? fallback = _focusedEvents.FirstOrDefault(ev => _selectedEventAnchor.Value.Matches(ev));
                if (fallback != null)
                {
                    ApplySelectedEvent(fallback, scrollIntoView: false);
                    return;
                }

                TelemetryEvent? clusteredFallback = _focusedEvents.FirstOrDefault(
                    ev => GetFocusedEventMembers(ev).Any(raw => _selectedEventAnchor.Value.Matches(raw)));
                if (clusteredFallback != null)
                {
                    ApplySelectedEvent(clusteredFallback, scrollIntoView: false);
                }
            }
        }

        private void ApplySelectedEvent(TelemetryEvent? selected, bool scrollIntoView)
        {
            if (EventsPaneHost?.Grid == null || EventsPaneHost?.Timeline == null)
            {
                return;
            }

            _eventSelectionSyncing = true;
            try
            {
                EventsPaneHost.Timeline.SelectedEvent = selected;
                EventsPaneHost.Grid.SelectedItem = selected;
                if (selected != null)
                {
                    UpdateSelectedEventAnchor(selected);
                    if (scrollIntoView)
                    {
                        EventsPaneHost.Grid.ScrollIntoView(selected);
                    }
                }
            }
            finally
            {
                _eventSelectionSyncing = false;
            }
        }

        private void UpdateSelectedEventAnchor(TelemetryEvent selected)
        {
            _selectedEventAnchor = new EventSelectionKey(selected);
        }

        private void ClearSelectedEvent()
        {
            if (EventsPaneHost?.Grid == null || EventsPaneHost?.Timeline == null)
            {
                _selectedEventAnchor = null;
                return;
            }

            _eventSelectionSyncing = true;
            try
            {
                EventsPaneHost.Grid.SelectedItem = null;
                EventsPaneHost.Timeline.SelectedEvent = null;
                _selectedEventAnchor = null;
            }
            finally
            {
                _eventSelectionSyncing = false;
            }
        }

        private void Timeline_SelectedEventChanged(object? sender, TelemetryEventSelectedEventArgs e)
        {
            if (_eventSelectionSyncing)
                return;

            if (e.Selected == null)
                return;

            ApplySelectedEvent(e.Selected, scrollIntoView: true);
        }

        private void Grid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_eventSelectionSyncing)
                return;

            if (EventsPaneHost.Grid.SelectedItem is TelemetryEvent te)
            {
                ApplySelectedEvent(te, scrollIntoView: false);
            }
        }
    }
}
