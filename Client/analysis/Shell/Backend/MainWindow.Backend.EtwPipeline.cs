using BlackbirdInterface.Capture;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.Windows.Media;
using System.Windows.Shapes;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private void RememberObservedProcessStart(BrokerEtwEventView view)
        {
            DateTime observedUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc;
            ulong startKey = view.ProcessStartKey;

            if (view.ProcessPid != 0 && !_observedProcessStartUtcByPid.ContainsKey(view.ProcessPid))
            {
                _observedProcessStartUtcByPid[view.ProcessPid] = observedUtc;
            }

            if (view.EventProcessId != 0 && !_observedProcessStartUtcByPid.ContainsKey(view.EventProcessId))
            {
                _observedProcessStartUtcByPid[view.EventProcessId] = observedUtc;
            }

            if (startKey != 0)
            {
                if (view.ProcessPid != 0)
                {
                    _observedProcessStartKeyByPid[view.ProcessPid] = startKey;
                }
                if (view.TargetPid != 0)
                {
                    _observedProcessStartKeyByPid[view.TargetPid] = startKey;
                }
                if (view.EventProcessId != 0)
                {
                    _observedProcessStartKeyByPid[view.EventProcessId] = startKey;
                }
            }

            if (view.Family == BlackbirdNative.IpcEtwFamilyProcess &&
                (view.Flags & BlackbirdNative.IpcEtwFlagProcessIsCreate) != 0)
            {
                uint pid = view.ProcessPid != 0 ? view.ProcessPid : view.TargetPid;
                if (pid != 0)
                {
                    _observedProcessStartUtcByPid[pid] = observedUtc;
                    if (view.EventThreadId != 0)
                    {
                        _observedInitialThreadIdByPid[pid] = view.EventThreadId;
                    }
                }
            }
        }

        private bool TryDescribeHookStartupContext(BrokerEtwEventView view, out string headline, out string detail)
        {
            headline = string.Empty;
            detail = string.Empty;

            if (!EventDetailFormatting.IsApiGraphCandidate(view))
            {
                return false;
            }

            uint pid = view.ProcessPid != 0 ? view.ProcessPid : view.ActorPid;
            if (pid == 0)
            {
                return false;
            }

            if (!_observedProcessStartUtcByPid.TryGetValue(pid, out DateTime startUtc))
            {
                if (_currentSession != null && _currentSession.Pid == unchecked((int)pid))
                {
                    startUtc = _currentSession.CaptureStartUtc;
                }
                else
                {
                    return false;
                }
            }

            DateTime eventUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc;
            if (eventUtc < startUtc)
            {
                startUtc = eventUtc;
            }

            double ageMs = Math.Max(0, (eventUtc - startUtc).TotalMilliseconds);
            if (ageMs > 4000)
            {
                return false;
            }

            string callerOrigin = view.CallerOriginLabel;
            bool processImageCaller = callerOrigin.Equals("process-image", StringComparison.OrdinalIgnoreCase);
            bool plausibleStartupCaller = processImageCaller ||
                                          callerOrigin.Equals("system", StringComparison.OrdinalIgnoreCase) ||
                                          callerOrigin.Equals("non-system-dll", StringComparison.OrdinalIgnoreCase);
            if (!plausibleStartupCaller)
            {
                return false;
            }

            uint initialThreadId =
                _observedInitialThreadIdByPid.TryGetValue(pid, out uint trackedThreadId) ? trackedThreadId : 0;
            bool primaryThread = initialThreadId != 0 && view.EventThreadId == initialThreadId;
            string phase = ageMs <= 750 ? "very early process startup" : "early process startup";
            headline = ageMs <= 750 ? "Startup Path" : "Early Startup";

            if (processImageCaller && primaryThread && ageMs <= 750)
            {
                detail =
                    $"StartupContext: inferred {phase} on the initial thread from the process image; likely loader / CRT / compiler-generated initializer activity. " +
                    "TLS callbacks or .CRT$XL* initializer paths are possible here, but this remains an inference from timing and caller-origin telemetry.";
                return true;
            }

            if (primaryThread && ageMs <= 2000)
            {
                detail =
                    $"StartupContext: inferred {phase} on the initial thread; likely loader or CRT initialization traffic rather than steady-state behavior.";
                return true;
            }

            detail =
                $"StartupContext: inferred {phase}; this call landed inside the startup window and may still reflect loader, CRT, static-initializer, or DLL attach activity.";
            return true;
        }

        private void ConfigureSr71PreResumeGate(int pid, bool armed)
        {
            _sr71PreResumeDropPid = armed ? pid : 0;
            _sr71PreResumeDropArmed = armed;
            _sr71PreResumeDropUntilUtc = null;
            DebugConsoleService.ConfigureSr71PreResumeGate(pid, armed);
            CaptureExecutionPhase phase = armed ? CaptureExecutionPhase.PreResume : CaptureExecutionPhase.Active;
            _captureProjection?.SetExecutionPhase(phase, DateTime.UtcNow,
                                                  armed ? "sr71-pre-resume-gate-armed" : "sr71-gate-not-armed");
            _packerDetector?.SetExecutionPhase(
                _captureProjection?.ExecutionPhase ??
                CaptureExecutionPolicy.CreateState(phase, DateTime.UtcNow, CaptureExecutionPhaseState.ActiveDefault));
        }

        private void MarkSr71PreResumeGateReleased(DateTime resumeUtc)
        {
            if (_sr71PreResumeDropArmed)
            {
                _sr71PreResumeDropUntilUtc = resumeUtc;
                DebugConsoleService.ReleaseSr71PreResumeGate(resumeUtc);
            }

            CaptureExecutionPhase nextPhase =
                _captureProjection?.ExecutionPhase.Phase == CaptureExecutionPhase.PreResume
                    ? CaptureExecutionPhase.PostResumeStartup
                    : CaptureExecutionPhase.Active;
            _captureProjection?.SetExecutionPhase(nextPhase, resumeUtc, "target-resumed");
            _packerDetector?.SetExecutionPhase(
                _captureProjection?.ExecutionPhase ??
                CaptureExecutionPolicy.CreateState(nextPhase, resumeUtc, CaptureExecutionPhaseState.ActiveDefault));
        }

        private bool ShouldDropPreResumeSr71View(BrokerEtwEventView view)
        {
            return false;
        }

        private void PublishHeuristicViaProjection(ICollection<HeuristicEventView> fallback,
                                                   HeuristicEventView? finding)
        {
            if (finding == null)
            {
                return;
            }

            if (_captureProjection != null)
            {
                _captureProjection.ObserveHeuristics(new[] { finding });
                return;
            }

            fallback.Add(finding);
        }

        private void PublishHeuristicsViaProjection(IReadOnlyList<HeuristicEventView> findings)
        {
            if (findings.Count == 0)
            {
                return;
            }

            if (_captureProjection != null)
            {
                _captureProjection.ObserveHeuristics(findings);
            }
        }

        private static bool IsSr71PreResumeSource(BrokerEtwEventView view)
        {
            return view.Family == BlackbirdNative.IpcEtwFamilyUserHook ||
                   view.SourceId == BlackbirdNative.IpcEtwSourceUserHook ||
                   EventDetailFormatting.IsUserHookEtwSource(view) ||
                   EventDetailFormatting.IsUsermodeSensorTelemetry(view) ||
                   EventDetailFormatting.IsApiGraphCandidate(view) ||
                   view.Source.Contains("SR71", StringComparison.OrdinalIgnoreCase) ||
                   view.Source.Contains("UserHook", StringComparison.OrdinalIgnoreCase);
        }

        private static bool TouchesSr71PreResumePid(BrokerEtwEventView view, uint pid)
        {
            return view.ActorPid == pid || view.TargetPid == pid || view.ProcessPid == pid ||
                   view.EventProcessId == pid || view.CallerPid == pid || view.ExplicitTargetPid == pid ||
                   view.CreatorPid == pid;
        }

        private void HandleBrokerEtwView(BrokerEtwEventView view)
        {
            HandleBrokerEtwViews(new[] { view });
        }

        private void HandleBrokerEtwViews(IReadOnlyList<BrokerEtwEventView> views)
        {
            if (views.Count == 0)
            {
                return;
            }

            var etwRows = new List<BrokerEtwEventView>(views.Count);
            var heuristics = new List<HeuristicEventView>();
            var relations = new List<ProcessRelationView>();
            var memoryAttributions = new List<MemoryRegionAttributionSample>(16);
            var timelineEvents = new List<TelemetryEvent>(views.Count);

            for (int i = 0; i < views.Count; i += 1)
            {
                BrokerEtwEventView view = views[i];
                if (ShouldDropPreResumeSr71View(view))
                {
                    continue;
                }

                RememberObservedProcessStart(view);
                TelemetryEvent? apiTimelineEvent = null;
                UpdateHookPipelineDiagnostics(view);
                ObserveTargetOutputEvent(view);
                ObserveTargetLifecycleEvent(view);
                IReadOnlyList<HeuristicEventView> signatureIntelFindings = QueueSignatureIntelForView(view);
                if (signatureIntelFindings.Count > 0)
                {
                    PublishHeuristicsViaProjection(signatureIntelFindings);
                }
                PersistObservedHookStackSnapshot(view);
                QueueThreadStackFallbackCapture(view);
                MemoryRegionAttributionSample? memoryAttribution = CreateMemoryRegionAttributionSample(view);
                if (memoryAttribution != null)
                {
                    memoryAttributions.Add(memoryAttribution);
                    HeuristicEventView? memoryLifecycleHeuristic = EvaluateMemoryLifecycleHeuristic(memoryAttribution);
                    PublishHeuristicViaProjection(heuristics, memoryLifecycleHeuristic);
                }
                if (EventDetailFormatting.IsApiGraphCandidate(view))
                {
                    apiTimelineEvent = HandleApiHookEvent(view);
                    if (apiTimelineEvent != null)
                    {
                        timelineEvents.Add(apiTimelineEvent);
                    }

                    HeuristicEventView? memPatternHeuristic = EvaluateCrossProcessMemoryHeuristic(view);
                    PublishHeuristicViaProjection(heuristics, memPatternHeuristic);

                    HeuristicEventView? antiAnalysisHeuristic = EvaluateAntiAnalysisHeuristic(view);
                    PublishHeuristicViaProjection(heuristics, antiAnalysisHeuristic);

                    HeuristicEventView? imageMapHeuristic = EvaluateImageSectionMapHeuristic(view);
                    PublishHeuristicViaProjection(heuristics, imageMapHeuristic);
                }

                bool keepEtw = ShouldKeepEtwEvent(view);
                if (keepEtw)
                {
                    etwRows.Add(view);
                }

                if (ObserveExtendedActivity(view))
                {
                    ScheduleExtendedActivitySnapshot();
                }

                ProcessRelationView? relation = MapEtwRelation(view);
                if (relation != null)
                {
                    relations.Add(relation);
                }

                string detection = view.DetectionName;
                DiagnosticsState.SetValue("ETW Status", "Live");
                if (detection.Equals("USERMODE_PROCESS_TERMINATE_BREAKPOINT", StringComparison.OrdinalIgnoreCase))
                {
                    uint terminatedPid = view.TargetPid != 0    ? view.TargetPid
                                         : view.ProcessPid != 0 ? view.ProcessPid
                                                                : view.ActorPid;
                    string reason =
                        string.IsNullOrWhiteSpace(view.Reason)
                            ? $"NtTerminateProcess observed from {ProcessIdentityResolver.Describe(view.ActorPid)}"
                            : view.Reason;
                    RememberTargetExitReason(terminatedPid, reason);
                    DiagnosticsState.SetValue("Target Exit Cause", reason);
                }
                if (detection.Equals("KERNEL_HOOK_STATUS", StringComparison.OrdinalIgnoreCase))
                {
                    uint installed = view.CorrelationFlags;
                    uint total = view.CorrelationAccessMask;
                    uint requiredMiss = view.CorrelationAgeMs;
                    string hookStatus = requiredMiss == 0
                                            ? $"OK ({installed}/{total})"
                                            : $"DEGRADED ({installed}/{total}, {requiredMiss} required miss)";
                    DiagnosticsState.SetValue("Kernel Hooks", hookStatus);
                }
                if (IsHookTamperDetection(view))
                {
                    DiagnosticsState.SetValue("Hook Integrity", "TAMPERED");
                }
                else if (detection.Equals("USERMODE_HOOK_INTEGRITY_OK", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("Hook Integrity", "OK");
                    MarkSr71HookReadyFromTelemetry();
                }
                if (detection.Equals("AMSI_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("AMSI Integrity", "TAMPERED");
                }
                else if (detection.Equals("AMSI_PATCH_OK", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("AMSI Integrity", "OK");
                    MarkSr71HookReadyFromTelemetry();
                }
                if (detection.Equals("ETW_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("ETW Integrity", "TAMPERED");
                }
                else if (detection.Equals("ETW_PATCH_OK", StringComparison.OrdinalIgnoreCase))
                {
                    DiagnosticsState.SetValue("ETW Integrity", "OK");
                    MarkSr71HookReadyFromTelemetry();
                }

                string eventName = view.EventName ?? string.Empty;
                string displayDetection = BuildFallbackDetectionLabel(detection, eventName, view.Task, view.Opcode,
                                                                      view.EventId, view.CorrelationFlags);
                string source = view.Source;
                uint actor = view.ActorPid;
                bool isSocketEvent = view.Family == BlackbirdNative.IpcEtwFamilySocket ||
                                     EventDetailFormatting.IsKernelNetworkEtwSource(view);
                if (isSocketEvent)
                {
                    PerformancePaneHost.IngestNetworkView(view);
                }
                string socketOperation = string.IsNullOrWhiteSpace(view.Operation) ? eventName : view.Operation;
                if (string.IsNullOrWhiteSpace(socketOperation))
                {
                    socketOperation = $"OP{view.Opcode}";
                }
                string timelineGroup = BuildEtwTimelineGroup(view, isSocketEvent);
                string timelineSubtype = isSocketEvent ? socketOperation : eventName;
                string summary = isSocketEvent ? $"{socketOperation} pid={actor} task={view.Task} opcode={view.Opcode}"
                                               : (!string.IsNullOrWhiteSpace(displayDetection)
                                                      ? $"{source}/{displayDetection} sev={view.Severity}"
                                                      : $"{source}/{eventName} sev={view.Severity}");
                string timelineSignature = $"{timelineGroup}|{eventName}|{actor}|{view.EventThreadId}|{summary}";
                bool duplicateTimelineEvent =
                    string.Equals(_lastEtwTimelineSignature, timelineSignature, StringComparison.OrdinalIgnoreCase) &&
                    (view.TimestampUtc - _lastEtwTimelineTimestampUtc).TotalMilliseconds <= 900;

                HeuristicEventView? heuristic = CreatePromotedHeuristic(view);
                PublishHeuristicViaProjection(heuristics, heuristic);

                bool persistView = ShouldPersistEtwView(view, keepEtw, relation != null,
                                                        heuristic != null || signatureIntelFindings.Count > 0,
                                                        apiTimelineEvent != null);

                string displayDetails = string.Empty;
                if (keepEtw || apiTimelineEvent != null || persistView)
                {
                    EnsureEtwDisplayDetails(view);
                    displayDetails = view.DisplayDetails;
                }

                if (persistView)
                {
                    AppendEtwToCaptureStore(view);
                }

                if (keepEtw && !duplicateTimelineEvent)
                {
                    int timelinePid =
                        view.EventProcessId == 0 ? unchecked((int)actor) : unchecked((int)view.EventProcessId);
                    timelineEvents.Add(new TelemetryEvent { TimestampUtc = view.TimestampUtc, PID = timelinePid,
                                                            TID = unchecked((int)view.EventThreadId),
                                                            Group = timelineGroup, SubType = timelineSubtype,
                                                            Summary = summary, Details = displayDetails });
                    _lastEtwTimelineSignature = timelineSignature;
                    _lastEtwTimelineTimestampUtc = view.TimestampUtc;
                }
            }

            if (etwRows.Count > 0)
            {
                EtwPaneHost.PushEvents(etwRows);
                _explorer.FirstOrDefault(x => x.Name == "ETW")?.PushPreviewValue(EtwPaneHost.TotalRawCount);
                SetExplorerHasData("ETW", EtwPaneHost.ItemCount > 0);
            }

            if (timelineEvents.Count > 0)
            {
                AppendEvents(timelineEvents);
            }

            if (memoryAttributions.Count > 0)
            {
                PerformancePaneHost.PushMemoryRegionAttributions(memoryAttributions);
                if (_currentSession != null)
                {
                    for (int i = 0; i < memoryAttributions.Count; i += 1)
                    {
                        _currentSession.MemoryRegionAttributionHistory.Add(
                            CloneMemoryRegionAttributionSample(memoryAttributions[i]));
                    }

                    if (_currentSession.MemoryRegionAttributionHistory.Count > 12_000)
                    {
                        _currentSession.MemoryRegionAttributionHistory.RemoveRange(
                            0, _currentSession.MemoryRegionAttributionHistory.Count - 12_000);
                    }
                }
            }

            if (heuristics.Count > 0)
            {
                HeuristicsPaneHost.PushHeuristics(heuristics);
                bool extendedChanged = false;
                for (int i = 0; i < heuristics.Count; i += 1)
                {
                    extendedChanged |= ObserveSignatureIntelActivity(heuristics[i]);
                }
                if (extendedChanged)
                {
                    ScheduleExtendedActivitySnapshot();
                }
                _explorer.FirstOrDefault(x => x.Name == "Heuristics")
                    ?.PushPreviewValue(HeuristicsPaneHost.TotalRawCount);
                SetExplorerHasData("Heuristics", HeuristicsPaneHost.ItemCount > 0);
                DiagnosticsState.Increment("Heuristics", heuristics.Count);
            }

            if (relations.Count > 0)
            {
                ProcessRelationsPaneHost.PushRelations(relations);
                _explorer.FirstOrDefault(x => x.Name == "Process Relations")
                    ?.PushPreviewValue(ProcessRelationsPaneHost.TotalRawCount);
                SetExplorerHasData("Process Relations", ProcessRelationsPaneHost.ItemCount > 0);
            }
        }

        private static bool IsTargetOutputEvent(BrokerEtwEventView view) =>
            view.SourceId == BlackbirdNative.IpcEtwSourceBlackbird
            && view.EventName.Equals("TargetOutput", StringComparison.OrdinalIgnoreCase);

        private static bool IsTargetLifecycleEvent(BrokerEtwEventView view) =>
            view.SourceId == BlackbirdNative.IpcEtwSourceBlackbird
            && view.EventName.Equals("TargetExit", StringComparison.OrdinalIgnoreCase);

        private static void ObserveTargetOutputEvent(BrokerEtwEventView view)
        {
            if (!IsTargetOutputEvent(view))
            {
                return;
            }

            uint pid = view.ProcessPid != 0 ? view.ProcessPid : view.ActorPid;
            if (pid == 0 || pid > int.MaxValue)
            {
                return;
            }

            string stream = string.IsNullOrWhiteSpace(view.Operation) ? "stdout" : view.Operation.Trim();
            string message = !string.IsNullOrWhiteSpace(view.CommandLine) ? view.CommandLine : view.Reason;
            if (string.IsNullOrWhiteSpace(message))
            {
                return;
            }

            DebugConsoleService.WriteExternal($"TARGET/{stream}", unchecked((int)pid), message);
        }

        private void ObserveTargetLifecycleEvent(BrokerEtwEventView view)
        {
            if (!IsTargetLifecycleEvent(view))
            {
                return;
            }

            uint pid = view.ProcessPid != 0 ? view.ProcessPid : view.ActorPid;
            if (pid == 0 || pid > int.MaxValue)
            {
                return;
            }

            string message =
                string.IsNullOrWhiteSpace(view.Reason) ? $"target exited status=0x{view.CreateStatus:X8}" : view.Reason;
            RememberTargetExitReason(pid, message);
            DebugConsoleService.WriteExternal("TARGET/lifecycle", unchecked((int)pid), message);
        }

        private void RememberTargetExitReason(uint pid, string reason)
        {
            if (pid == 0 || string.IsNullOrWhiteSpace(reason))
            {
                return;
            }

            string normalized = reason.Trim();
            _targetExitReasonByPid[pid] = normalized;
            if (_currentSession != null && _currentSession.Pid == unchecked((int)pid))
            {
                _currentSession.TargetExitReason = normalized;
            }
        }

        private static bool ShouldPersistEtwView(BrokerEtwEventView view, bool keepEtw, bool hasRelation,
                                                 bool hasPromotedHeuristic, bool hasApiTimelineEvent)
        {
            if (hasRelation || hasPromotedHeuristic || hasApiTimelineEvent)
            {
                return true;
            }

            if (!keepEtw)
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(view.DetectionName) || view.Severity >= 4)
            {
                return true;
            }

            return view.Family is BlackbirdNative.IpcEtwFamilyThread or BlackbirdNative
                .IpcEtwFamilyApc or BlackbirdNative.IpcEtwFamilyUserHook or BlackbirdNative.IpcEtwFamilySocket;
        }

        private static string BuildEtwTimelineGroup(BrokerEtwEventView view, bool isSocketEvent)
        {
            if (isSocketEvent)
            {
                return "Sockets";
            }
            if (EventDetailFormatting.IsApiGraphCandidate(view) || EventDetailFormatting.IsKernelHookTelemetry(view) ||
                EventDetailFormatting.IsUserHookEtwSource(view))
            {
                return EventDetailFormatting.HookTimelineGroup(view);
            }
            if (EventDetailFormatting.IsThreatIntelEtwSource(view))
            {
                return "Threat Intel";
            }
            if (EventDetailFormatting.IsKernelNetworkEtwSource(view))
            {
                return "Network";
            }
            if (EventDetailFormatting.IsBlackbirdEtwSource(view))
            {
                return "Kernel";
            }
            return "ETW";
        }

        private void UpdateHookPipelineDiagnostics(BrokerEtwEventView view)
        {
            if (view.Family == BlackbirdNative.IpcEtwFamilyUserHook &&
                view.SourceId == BlackbirdNative.IpcEtwSourceUserHook)
            {
                long count = Interlocked.Increment(ref _usermodeHookEventCount);
                string kind = EventDetailFormatting.HookKindName(view.NotifyClass);
                string api = !string.IsNullOrWhiteSpace(view.Operation) ? view.Operation : view.EventName;
                string label = !string.IsNullOrWhiteSpace(api)    ? api
                               : !string.IsNullOrWhiteSpace(kind) ? kind
                                                                  : "event";
                DiagnosticsState.SetValue("Usermode Hooks", $"Active ({count} SR71 events, last={label})");
                DiagnosticsState.SetValue("HookDLL->Controller IPC", "Ready (SR71 telemetry)");
                DiagnosticsState.SetValue("HookDLL Hooks Set", $"OK ({kind})");
                MarkSr71HookReadyFromTelemetry();
                if (ShouldPromoteIntegrityStatus(DiagnosticsState.GetValue("Hook Integrity")))
                {
                    DiagnosticsState.SetValue("Hook Integrity", "OK");
                }
                if (ShouldPromoteIntegrityStatus(DiagnosticsState.GetValue("AMSI Integrity")))
                {
                    DiagnosticsState.SetValue("AMSI Integrity", "OK");
                }
                return;
            }

            if (EventDetailFormatting.IsKernelHookTelemetry(view))
            {
                long count = Interlocked.Increment(ref _kernelHookEventCount);
                string api = !string.IsNullOrWhiteSpace(view.Operation) ? view.Operation : view.EventName;
                DiagnosticsState.SetValue("Kernel Hooks", string.IsNullOrWhiteSpace(api)
                                                              ? $"Active ({count} events)"
                                                              : $"Active ({count} events, last={api})");
                return;
            }

            if (EventDetailFormatting.IsUsermodeSensorTelemetry(view))
            {
                string kind = EventDetailFormatting.HookKindName(view.NotifyClass);
                DiagnosticsState.SetValue("Usermode Hooks", $"Active ({kind})");
                DiagnosticsState.SetValue("HookDLL->Controller IPC", "Ready (SR71 telemetry)");
                DiagnosticsState.SetValue("HookDLL Hooks Set", $"OK ({kind})");
                MarkSr71HookReadyFromTelemetry();
                if (ShouldPromoteIntegrityStatus(DiagnosticsState.GetValue("Hook Integrity")))
                {
                    DiagnosticsState.SetValue("Hook Integrity", "OK");
                }
                if (ShouldPromoteIntegrityStatus(DiagnosticsState.GetValue("AMSI Integrity")))
                {
                    DiagnosticsState.SetValue("AMSI Integrity", "OK");
                }
            }
        }

        private static bool ShouldPromoteIntegrityStatus(string? current)
        {
            if (string.IsNullOrWhiteSpace(current))
            {
                return true;
            }

            return current.Contains("Unknown", StringComparison.OrdinalIgnoreCase) ||
                   current.Contains("Awaiting", StringComparison.OrdinalIgnoreCase) ||
                   current.Contains("Review", StringComparison.OrdinalIgnoreCase) ||
                   current.Contains("Disabled (no usermode hooks)", StringComparison.OrdinalIgnoreCase);
        }

        private static void MarkSr71HookReadyFromTelemetry()
        {
            string? hookReady = DiagnosticsState.GetValue("SR71 Hook Ready");
            if (string.IsNullOrWhiteSpace(hookReady) ||
                hookReady.Contains("Awaiting", StringComparison.OrdinalIgnoreCase) ||
                hookReady.Contains("DEGRADED", StringComparison.OrdinalIgnoreCase) ||
                hookReady.Contains("missing", StringComparison.OrdinalIgnoreCase))
            {
                DiagnosticsState.SetValue("SR71 Hook Ready", "OK observed via SR71 telemetry");
            }

            string? instrumentation = DiagnosticsState.GetValue("SR71 Instrumentation");
            if (string.IsNullOrWhiteSpace(instrumentation) ||
                instrumentation.Contains("Awaiting", StringComparison.OrdinalIgnoreCase) ||
                instrumentation.Contains("DEGRADED", StringComparison.OrdinalIgnoreCase))
            {
                DiagnosticsState.SetValue("SR71 Instrumentation", "OK observed via SR71 telemetry");
            }
        }

        private static void TryAppendObservedModule(BrokerEtwEventView view, List<ModuleInfoRow> rows)
        {
            string path = view.ImagePath ?? string.Empty;
            ulong baseAddress = view.ImageBase;
            ulong imageSize = view.ImageSize;

            if (string.IsNullOrWhiteSpace(path) && view.Family == BlackbirdNative.IpcEtwFamilyUserHook)
            {
                string apiName = !string.IsNullOrWhiteSpace(view.Operation) ? view.Operation : view.EventName;
                if (apiName.Equals("LdrLoadDll", StringComparison.OrdinalIgnoreCase) ||
                    apiName.StartsWith("LoadLibrary", StringComparison.OrdinalIgnoreCase))
                {
                    Dictionary<string, string> fields = BuildHookFieldMap(view);
                    path = DecodeModuleHookName(apiName, view);
                    baseAddress = FirstU64(fields, "handle", "module", "moduleHandle");
                }
            }

            if (string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            rows.Add(new ModuleInfoRow {
                Name = ModuleNameFromPath(path), BaseAddress = baseAddress == 0 ? "observed" : $"0x{baseAddress:X}",
                Size =
                    imageSize == 0 ? "observed" : FormatObservedBytes((long)Math.Min(imageSize, (ulong) long.MaxValue)),
                Path = path
            });
        }

        private static string FormatObservedBytes(long bytes)
        {
            string[] units = { "B", "KB", "MB", "GB", "TB" };
            double value = Math.Max(0, bytes);
            int unit = 0;
            while (value >= 1024 && unit < units.Length - 1)
            {
                value /= 1024;
                unit += 1;
            }

            return unit == 0 ? $"{bytes} B" : $"{value:0.0} {units[unit]}";
        }

        private static string ModuleNameFromPath(string path)
        {
            string value = (path ?? string.Empty).Trim();
            if (value.Length == 0)
            {
                return "unknown";
            }

            int slash = Math.Max(value.LastIndexOf('\\'), value.LastIndexOf('/'));
            return slash >= 0 && slash + 1 < value.Length ? value[(slash + 1)..] : value;
        }

        private void PersistObservedHookStackSnapshot(BrokerEtwEventView view)
        {
            if (view.Family != BlackbirdNative.IpcEtwFamilyUserHook ||
                view.SourceId != BlackbirdNative.IpcEtwSourceUserHook || view.StackCount == 0)
            {
                return;
            }

            uint pid = view.ProcessPid != 0 ? view.ProcessPid : view.ActorPid;
            uint tid = view.EventThreadId != 0 ? view.EventThreadId : view.ThreadId;
            if (pid == 0 || tid == 0 || pid > int.MaxValue || tid > int.MaxValue)
            {
                return;
            }

            DateTime capturedUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc;
            string throttleKey = $"{pid}:{tid}";
            if (_observedHookStackLastPersistByThread.TryGetValue(throttleKey, out DateTime lastPersistUtc) &&
                capturedUtc < lastPersistUtc.AddMilliseconds(250))
            {
                return;
            }

            ThreadStackSessionSnapshot? snapshot = CreateObservedHookStackSnapshot(view, capturedUtc);
            if (snapshot == null || snapshot.Frames.Count == 0)
            {
                return;
            }

            _observedHookStackLastPersistByThread[throttleKey] = capturedUtc;
            PersistThreadStackSnapshot(unchecked((int)pid), unchecked((int)tid), string.Empty, snapshot);
        }

        private void QueueThreadStackFallbackCapture(BrokerEtwEventView view)
        {
            if (view.StackCount != 0 || !ShouldCaptureThreadStackFallback(view))
            {
                return;
            }

            uint pid = view.ProcessPid != 0 ? view.ProcessPid
                       : view.ActorPid != 0 ? view.ActorPid
                                            : view.EventProcessId;
            uint tid = view.EventThreadId != 0 ? view.EventThreadId : view.ThreadId;
            if (pid == 0 || tid == 0 || pid > int.MaxValue || tid > int.MaxValue)
            {
                return;
            }

            DateTime capturedUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc;
            string key = $"{pid}:{tid}";
            if (_threadStackFallbackLastCaptureByThread.TryGetValue(key, out DateTime lastCaptureUtc) &&
                capturedUtc < lastCaptureUtc.AddSeconds(6))
            {
                return;
            }

            if (_pendingThreadStackFallbackCaptures.Count >= 32)
            {
                return;
            }

            if (!_pendingThreadStackFallbackCaptures.TryAdd(key, 0))
            {
                return;
            }

            _threadStackFallbackLastCaptureByThread[key] = capturedUtc;
            int capturePid = unchecked((int)pid);
            int captureTid = unchecked((int)tid);
            _ = Task.Run(() =>
                         {
                             ThreadStackResolveResult result =
                                 ThreadStackResolver.Resolve(capturePid, captureTid, string.Empty);
                             return CreateThreadStackFallbackSnapshot(capturedUtc, result);
                         })
                    .ContinueWith(
                        task =>
                        {
                            _pendingThreadStackFallbackCaptures.TryRemove(key, out _);
                            if (task.Status != TaskStatus.RanToCompletion || task.Result == null ||
                                task.Result.Frames.Count == 0)
                            {
                                return;
                            }

                            Dispatcher.BeginInvoke(
                                new Action(
                                    () =>
                                    {
                                        PersistThreadStackSnapshot(capturePid, captureTid, string.Empty, task.Result);
                                        DebugConsoleService.WriteLocal(
                                            $"[STACK] captured fallback thread stack pid={capturePid} tid={captureTid} frames={task.Result.Frames.Count}");
                                    }),
                                DispatcherPriority.Background);
                        },
                        TaskScheduler.Default);
        }

        private static bool ShouldCaptureThreadStackFallback(BrokerEtwEventView view)
        {
            if (!ThreadStackResolver.AutomaticFallbackCaptureEnabled)
            {
                return false;
            }

            if (view.Family != BlackbirdNative.IpcEtwFamilyUserHook)
            {
                return false;
            }

            string api = !string.IsNullOrWhiteSpace(view.Operation) ? view.Operation : view.EventName;
            if (string.IsNullOrWhiteSpace(api))
            {
                return false;
            }

            if (!api.StartsWith("Nt", StringComparison.OrdinalIgnoreCase) &&
                !api.StartsWith("Zw", StringComparison.OrdinalIgnoreCase) &&
                !api.StartsWith("Co", StringComparison.OrdinalIgnoreCase) &&
                !api.Contains("Trace", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            bool highSignal = view.Severity >= 4 || IsDirectSyscallDetection(view) ||
                              api.Equals("NtMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("ZwMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("NtCreateSection", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("ZwCreateSection", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("NtProtectVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("NtCreateThreadEx", StringComparison.OrdinalIgnoreCase);
            if (!highSignal)
            {
                return false;
            }

            return view.SourceId == BlackbirdNative.IpcEtwSourceBlackbird ||
                   view.SourceId == BlackbirdNative.IpcEtwSourceUserHook ||
                   EventDetailFormatting.IsKernelHookTelemetry(view);
        }

        private static ThreadStackSessionSnapshot? CreateThreadStackFallbackSnapshot(DateTime capturedUtc,
                                                                                     ThreadStackResolveResult result)
        {
            if (result.Frames.Count == 0)
            {
                return null;
            }

            return new ThreadStackSessionSnapshot { CapturedAtUtc = capturedUtc,
                                                    TebAddress = result.TebAddress,
                                                    StackBase = result.StackBase,
                                                    StackTop = result.StackTop,
                                                    TebFlags = result.TebFlags,
                                                    StackPointer = result.StackPointer,
                                                    ContextSnapshot =
                                                        CloneThreadContextSnapshot(result.ContextSnapshot),
                                                    Frames = result.Frames.Select(CloneStackFrameRow).ToList() };
        }

        private static StackFrameRow
        CloneStackFrameRow(StackFrameRow frame) => new() { Index = frame.Index,
                                                           Address = frame.Address,
                                                           Module = frame.Module,
                                                           Symbol = frame.Symbol,
                                                           InstructionPointerRaw = frame.InstructionPointerRaw,
                                                           FramePointerRaw = frame.FramePointerRaw,
                                                           FrameSpanBytes = frame.FrameSpanBytes,
                                                           IsCurrent = frame.IsCurrent };

        private static ThreadContextSnapshot? CloneThreadContextSnapshot(ThreadContextSnapshot? snapshot)
        {
            if (snapshot == null)
            {
                return null;
            }

            return new ThreadContextSnapshot {
                Rip = snapshot.Rip, Rsp = snapshot.Rsp, Rbp = snapshot.Rbp, Rax = snapshot.Rax,      Rbx = snapshot.Rbx,
                Rcx = snapshot.Rcx, Rdx = snapshot.Rdx, Rsi = snapshot.Rsi, Rdi = snapshot.Rdi,      R8 = snapshot.R8,
                R9 = snapshot.R9,   R10 = snapshot.R10, R11 = snapshot.R11, R12 = snapshot.R12,      R13 = snapshot.R13,
                R14 = snapshot.R14, R15 = snapshot.R15, Dr0 = snapshot.Dr0, Dr1 = snapshot.Dr1,      Dr2 = snapshot.Dr2,
                Dr3 = snapshot.Dr3, Dr6 = snapshot.Dr6, Dr7 = snapshot.Dr7, EFlags = snapshot.EFlags
            };
        }

        private static ThreadStackSessionSnapshot? CreateObservedHookStackSnapshot(BrokerEtwEventView view,
                                                                                   DateTime capturedUtc)
        {
            ulong[] stack = view.Stack ?? Array.Empty<ulong>();
            int count = Math.Min(Math.Min((int)view.StackCount, stack.Length), BlackbirdNative.MaxIpcStackFrames);
            if (count <= 0)
            {
                return null;
            }

            Dictionary<string, string> fields = BuildHookFieldMap(view);
            var frames = new List<StackFrameRow>(count);
            for (int i = 0; i < count; i += 1)
            {
                ulong ip = stack[i];
                if (ip == 0)
                {
                    continue;
                }

                string symbol = ReadTrimmedField(fields, $"stack{i}Symbol");
                string path = ReadTrimmedField(fields, $"stack{i}Path");
                string module = ModuleNameFromPath(path);
                if (module.Equals("unknown", StringComparison.OrdinalIgnoreCase))
                {
                    module = ExtractModuleFromSymbol(symbol);
                }

                frames.Add(new StackFrameRow { Index = frames.Count, Address = $"0x{ip:X}", Module = module,
                                               Symbol = string.IsNullOrWhiteSpace(symbol) ? $"0x{ip:X}" : symbol,
                                               InstructionPointerRaw = ip, IsCurrent = frames.Count == 0 });
            }

            if (frames.Count == 0)
            {
                return null;
            }

            ulong stackPointer = FirstU64(fields, "rsp", "sp", "stackPointer", "StackPointer");
            return new ThreadStackSessionSnapshot { CapturedAtUtc = capturedUtc, StackPointer = stackPointer,
                                                    Frames = frames };
        }

        private static string ReadTrimmedField(IReadOnlyDictionary<string, string> fields, string key)
        {
            return fields.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value)
                       ? value.Trim()
                       : string.Empty;
        }

        private static bool HasFailedHookStatus(BrokerEtwEventView view)
        {
            if (view.Family != BlackbirdNative.IpcEtwFamilyUserHook)
            {
                return false;
            }

            return TryReadNtStatus(BuildHookFieldMap(view), out int status, "status", "queryStatus", "callStatus") &&
                   status < 0;
        }

        private static bool TryReadNtStatus(IReadOnlyDictionary<string, string> fields, out int status,
                                            params string[] keys)
        {
            foreach (string key in keys)
            {
                if (fields.TryGetValue(key, out string? text) && TryParseNtStatus(text, out status))
                {
                    return true;
                }
            }

            status = 0;
            return false;
        }

        private static bool TryParseNtStatus(string? text, out int status)
        {
            status = 0;
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            string compact = text.Trim();
            if (compact.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                if (uint.TryParse(compact[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture,
                                  out uint hexValue))
                {
                    status = unchecked((int)hexValue);
                    return true;
                }

                return false;
            }

            if (int.TryParse(compact, NumberStyles.Integer, CultureInfo.InvariantCulture, out status))
            {
                return true;
            }

            if (uint.TryParse(compact, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint unsignedValue))
            {
                status = unchecked((int)unsignedValue);
                return true;
            }

            return false;
        }

        private static string ExtractModuleFromSymbol(string symbol)
        {
            string value = (symbol ?? string.Empty).Trim();
            int bang = value.IndexOf('!');
            return bang > 0 ? value[..bang].Trim() : string.Empty;
        }

        private static uint DirectSyscallSeverityFloor(BrokerEtwEventView view)
        {
            bool highRisk = IsHighRiskIoctlAccess(view.DesiredAccess, (view.Flags & HandleFlagThreadObject) != 0);
            if ((view.Flags & HandleFlagSyscallExportMismatch) != 0)
            {
                return 6;
            }
            if (highRisk || (view.Flags & HandleFlagStackSpoofSuspect) != 0)
            {
                return 5;
            }
            if ((view.Flags & HandleFlagExecProtect) != 0 && (view.Flags & HandleFlagFromNtdll) == 0)
            {
                return 4;
            }

            return 3;
        }

        private static string BuildDirectSyscallDetectionName(BrokerEtwEventView view)
        {
            string syscallName = EventDetailFormatting.ResolveDirectSyscallApi(view.DesiredAccess, view.Flags);
            return BuildDirectSyscallDetectionName(view.ActorPid, view.TargetPid, syscallName);
        }

        private static string BuildDirectSyscallDetectionName(uint actorPid, uint targetPid, string syscallName)
        {
            string detection =
                string.IsNullOrWhiteSpace(syscallName) ? "DIRECT_SYSCALL" : $"DIRECT_SYSCALL [{syscallName.Trim()}]";
            return OperatorDetectionFormatter.Format(detection, actorPid, targetPid);
        }

        private static string NormalizePromotedDetectionName(BrokerEtwEventView view, string detection)
        {
            string operation = string.IsNullOrWhiteSpace(view.Operation) ? view.EventName : view.Operation;
            return OperatorDetectionFormatter.Format(detection, view.ActorPid, view.TargetPid, operation);
        }

        private static string BuildEtwDirectSyscallEvidenceText(BrokerEtwEventView view)
        {
            string syscallName = EventDetailFormatting.ResolveDirectSyscallApi(view.DesiredAccess, view.Flags);
            string syscallLabel = EventDetailFormatting.BuildDirectSyscallLabel(
                view.DesiredAccess, view.Flags, view.DeepSample, (int)view.DeepSampleSize);
            string accessDecoded = EventDetailFormatting.DescribeHandleAccess(view.DesiredAccess);
            string flagsDecoded = EventDetailFormatting.DescribeHandleFlags(view.Flags);
            string originModule = EventDetailFormatting.ModuleNameFromPath(view.OriginPath);
            string sampleHex = EventDetailFormatting.FormatSampleHex(view.DeepSample, (int)view.DeepSampleSize);
            string sampleDisasm = EventDetailFormatting.InferSampleBytes(view.DeepSample, (int)view.DeepSampleSize);

            string stack0 = view.StackCount > 0 && view.Stack.Length > 0 ? $"0x{view.Stack[0]:X}" : "n/a";
            string stack1 = view.StackCount > 1 && view.Stack.Length > 1 ? $"0x{view.Stack[1]:X}" : "n/a";

            return $"etwEvidence class={view.ClassName} syscallName={syscallName} syscallLabel={syscallLabel.Replace(' ', '_')} " +
                   $"access=0x{view.DesiredAccess:X8} ({accessDecoded}) flags=0x{view.Flags:X8} ({flagsDecoded}) handleFlags=0x{view.Flags:X8} " +
                   $"origin=0x{view.OriginAddress:X} protect=0x{view.OriginProtect:X8} module={originModule} " +
                   $"path={view.OriginPath} allocationBase=0x{view.DeepAllocationBase:X} regionSize=0x{view.DeepRegionSize:X} " +
                   $"regionProtect=0x{view.DeepRegionProtect:X8} ({EventDetailFormatting.DescribeMemoryProtection(view.DeepRegionProtect)}) " +
                   $"stack0={stack0} stack1={stack1} deepSampleSize={view.DeepSampleSize} deepSample={sampleHex} sampleDisasmHint={sampleDisasm}";
        }

        private HeuristicEventView? CreatePromotedHeuristic(BrokerEtwEventView view)
        {
            if (IsBlackbirdOwnEvent(view) || HasFailedHookStatus(view))
                return null;

            string rawDetection = view.DetectionName;
            if (string.IsNullOrWhiteSpace(rawDetection) && IsDirectSyscallDetection(view))
            {
                rawDetection = BuildDirectSyscallDetectionName(view);
            }
            if (string.IsNullOrWhiteSpace(rawDetection) || !ShouldPromoteHeuristic(view))
            {
                return null;
            }

            uint actor = view.ActorPid;
            uint target = view.TargetPid;
            string detection = NormalizePromotedDetectionName(view, rawDetection);
            if (string.IsNullOrWhiteSpace(detection))
            {
                return null;
            }

            string reasonText = string.IsNullOrWhiteSpace(view.Reason) ? "<none>" : view.Reason;
            uint sanitizedCorrFlags = view.CorrelationFlags & CorrelationIntentMask;
            string corrFlagsDecoded = EventDetailFormatting.DescribeCorrelationFlags(sanitizedCorrFlags);
            string corrAccessDecoded = EventDetailFormatting.DescribeHandleAccess(view.CorrelationAccessMask);
            string heuristicEvidence = "<none>";
            bool hasEvidence = TryGetHandleEvidence(actor, target, out IoctlParsedEvent evidence);
            if (hasEvidence)
            {
                heuristicEvidence = BuildHandleEvidenceText(evidence);
            }
            if (IsDirectSyscallDetection(view))
            {
                if (hasEvidence && !ShouldKeepDirectSyscallHeuristicFromEvidence(evidence))
                {
                    return null;
                }
                if (!hasEvidence && view.Family == BlackbirdNative.IpcEtwFamilyHandle)
                {
                    heuristicEvidence = BuildEtwDirectSyscallEvidenceText(view);
                }
            }

            string rawCorrFlagsSuffix = view.CorrelationFlags == sanitizedCorrFlags
                                            ? string.Empty
                                            : $"; rawCorrFlags=0x{view.CorrelationFlags:X8}";
            uint severity = IsDirectSyscallDetection(view) ? Math.Max(view.Severity, DirectSyscallSeverityFloor(view))
                                                           : view.Severity;

            return new HeuristicEventView {
                TimestampUtc = view.TimestampUtc,
                LastSeenUtc = view.TimestampUtc,
                Severity = severity,
                DetectionName = detection,
                ActorPid = actor,
                TargetPid = target,
                Source = view.Source,
                EventName = view.EventName ?? string.Empty,
                CorrelationFlags = sanitizedCorrFlags,
                CorrelationAccessMask = view.CorrelationAccessMask,
                CorrelationAgeMs = view.CorrelationAgeMs,
                Reason =
                    $"reason={reasonText}; corrFlags={corrFlagsDecoded}; corrAccess={corrAccessDecoded}; corrAgeMs={view.CorrelationAgeMs}{rawCorrFlagsSuffix}",
                Evidence = heuristicEvidence,
                RepeatCount = 1
            };
        }

        private static string BuildFallbackDetectionLabel(string detectionName, string eventName, ushort task,
                                                          ushort opcode, ushort eventId, uint correlationFlags)
        {
            if (!string.IsNullOrWhiteSpace(detectionName) &&
                !detectionName.Equals("UNKNOWN", StringComparison.OrdinalIgnoreCase))
            {
                return detectionName;
            }

            string name = eventName?.Trim() ?? string.Empty;
            if (name.Equals("ThreadTelemetry", StringComparison.OrdinalIgnoreCase))
            {
                if (correlationFlags != 0)
                {
                    return $"THREAD_ACTIVITY[{EventDetailFormatting.DescribeCorrelationFlags(correlationFlags)}]";
                }

                return "THREAD_ACTIVITY";
            }

            if (name.Equals("HandleTelemetry", StringComparison.OrdinalIgnoreCase))
            {
                return "HANDLE_ACTIVITY";
            }

            if (name.Equals("ApcTelemetry", StringComparison.OrdinalIgnoreCase))
            {
                return "APC_ACTIVITY";
            }

            if (name.Equals("DetectionTelemetry", StringComparison.OrdinalIgnoreCase))
            {
                return "DETECTION_UNSPECIFIED";
            }

            if (!string.IsNullOrWhiteSpace(name) && name.EndsWith("Telemetry", StringComparison.OrdinalIgnoreCase))
            {
                string baseName = name[..^ "Telemetry".Length].Trim();
                if (!string.IsNullOrWhiteSpace(baseName))
                {
                    return $"{baseName.ToUpperInvariant()}_ACTIVITY";
                }
            }

            if (!string.IsNullOrWhiteSpace(detectionName))
            {
                return detectionName;
            }

            if (task == 0 && opcode == 0 && eventId == 0)
            {
                return "TELEMETRY";
            }

            if (!string.IsNullOrWhiteSpace(name))
            {
                return name;
            }

            return "UNCLASSIFIED_EVENT";
        }
    }
}
