using BlackbirdInterface.Capture;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private SignatureIntelService? _signatureIntel;

        private void InitializeSignatureIntelSubsystem()
        {
            DiagnosticsState.SetValue("Signature Intel", "Enabled memory=on page=on hash=on");
            _signatureIntel = new SignatureIntelService(
                findings =>
                {
                    if (findings.Count == 0 || Dispatcher.HasShutdownStarted)
                    {
                        return;
                    }

                    Dispatcher.BeginInvoke(new Action(() =>
                                                      {
                                                          if (Dispatcher.HasShutdownStarted || findings.Count == 0)
                                                          {
                                                              return;
                                                          }

                                                          if (_captureProjection != null)
                                                          {
                                                              _captureProjection.ObserveHeuristics(findings);
                                                              return;
                                                          }

                                                          HeuristicsPaneHost.PushHeuristics(findings);
                                                          bool extendedChanged = false;
                                                          foreach (HeuristicEventView finding in findings)
                                                          {
                                                              extendedChanged |= ObserveSignatureIntelActivity(finding);
                                                          }
                                                          if (extendedChanged)
                                                          {
                                                              ScheduleExtendedActivitySnapshot();
                                                          }
                                                          _explorer.FirstOrDefault(x => x.Name == "Heuristics")
                                                              ?.PushPreviewValue(HeuristicsPaneHost.TotalRawCount);
                                                          SetExplorerHasData("Heuristics",
                                                                             HeuristicsPaneHost.ItemCount > 0);
                                                          DiagnosticsState.Increment("Heuristics", findings.Count);
                                                      }),
                                           DispatcherPriority.Background);
                },
                message => OutputCapture.AppendLine(message));
            _signatureIntel.Configure(
                new SignatureIntelOptions(Enabled: _signatureIntelEnabled, MemoryScan: _signatureIntelMemoryScanEnabled,
                                          PageScan: _signatureIntelPageScanEnabled, HashScan: _signatureIntelEnabled));
        }

        private void DisposeSignatureIntelSubsystem()
        {
            _signatureIntel?.Dispose();
            _signatureIntel = null;
        }

        internal void ConfigureStartupSignatureIntel(bool enabled, bool enableMemoryScan, bool enablePageScan)
        {
            _signatureIntelEnabled = enabled;
            _signatureIntelMemoryScanEnabled = enabled && enableMemoryScan;
            _signatureIntelPageScanEnabled = enabled && enablePageScan;
            _signatureIntel?.Configure(
                new SignatureIntelOptions(Enabled: enabled, MemoryScan: _signatureIntelMemoryScanEnabled,
                                          PageScan: _signatureIntelPageScanEnabled, HashScan: enabled));
            if (_currentSession != null)
            {
                _currentSession.SignatureIntelEnabled = enabled;
                _currentSession.SignatureIntelMemoryScanEnabled = enabled && enableMemoryScan;
                _currentSession.SignatureIntelPageScanEnabled = enabled && enablePageScan;
            }

            RefreshSubsystemSegmentationDiagnostics();
        }

        private bool ObserveSignatureIntelActivity(HeuristicEventView finding)
        {
            if (finding == null)
            {
                return false;
            }

            string detection = finding.DetectionName ?? string.Empty;
            string evidence = finding.Evidence ?? string.Empty;
            string engine = ClassifySignatureIntelEngine(detection, evidence);
            if (string.IsNullOrWhiteSpace(engine))
            {
                return false;
            }

            string subject = ExtractSignatureIntelRuleName(evidence, detection);
            string operation = engine.Equals("Strings", StringComparison.OrdinalIgnoreCase)
                                   ? (evidence.IndexOf("newSincePrevious=0", StringComparison.OrdinalIgnoreCase) >= 0
                                          ? "Memory-Disk Diff"
                                          : "New Memory Strings")
                               : engine.Equals("SIGMA", StringComparison.OrdinalIgnoreCase) ? "Event Match"
                               : evidence.IndexOf("scope=process-memory", StringComparison.OrdinalIgnoreCase) >= 0
                                   ? "Process Memory Match"
                               : evidence.IndexOf("scope=page", StringComparison.OrdinalIgnoreCase) >= 0 ? "Page Match"
                               : evidence.IndexOf("scope=memory", StringComparison.OrdinalIgnoreCase) >= 0
                                   ? "Memory Match"
                                   : "File Match";
            string detail = engine.Equals("Strings", StringComparison.OrdinalIgnoreCase) ? evidence
                            : string.IsNullOrWhiteSpace(finding.Reason) ? evidence
                                                                                         : finding.Reason;

            string key = BuildExtendedActivityKey(
                engine, FormatApiProcessLabel(finding.ActorPid),
                FormatApiProcessLabel(finding.TargetPid != 0 ? finding.TargetPid : finding.ActorPid), subject,
                operation);

            if (_extendedRowsByKey.TryGetValue(key, out ExtendedActivityRowSnapshot? existing))
            {
                existing.Hits = Math.Max(1, existing.Hits + Math.Max(1, finding.RepeatCount));
                existing.LastSeenUtc = finding.LastSeenUtc;
                existing.LastSeenLabel = FormatApiRelativeAge(finding.LastSeenUtc);
                existing.DetailLabel = detail;
                return true;
            }

            _extendedRowsByKey[key] = new ExtendedActivityRowSnapshot
            {
                TypeLabel = engine,
                ActorLabel = FormatApiProcessLabel(finding.ActorPid),
                TargetLabel = FormatApiProcessLabel(finding.TargetPid != 0 ? finding.TargetPid : finding.ActorPid),
                SubjectLabel = subject,
                OperationLabel = operation,
                DetailLabel = detail,
                LastSeenUtc = finding.LastSeenUtc,
                LastSeenLabel = FormatApiRelativeAge(finding.LastSeenUtc),
                Hits = Math.Max(1, finding.RepeatCount)
            };
            return true;
        }

        private static string ClassifySignatureIntelEngine(string detection, string evidence)
        {
            if (detection.StartsWith("SIGMA_", StringComparison.OrdinalIgnoreCase) ||
                evidence.IndexOf("engine=sigma", StringComparison.OrdinalIgnoreCase) >= 0 ||
                evidence.IndexOf("sigma_id=", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "SIGMA";
            }

            if (detection.StartsWith("YARA_", StringComparison.OrdinalIgnoreCase) ||
                evidence.IndexOf("engine=yara", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "YARA";
            }

            if (detection.StartsWith("MEMORY_STRING_DIFF", StringComparison.OrdinalIgnoreCase) ||
                evidence.IndexOf("engine=string-diff", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "Strings";
            }

            return evidence.IndexOf("rule=", StringComparison.OrdinalIgnoreCase) >= 0 ? "Rules" : string.Empty;
        }

        private static string ExtractSignatureIntelRuleName(string evidence, string detection)
        {
            string[] tokens = new[] { "sigma_id=", "rule=", "image=", "path=", "origin=" };
            foreach (string token in tokens)
            {
                int start = evidence.IndexOf(token, StringComparison.OrdinalIgnoreCase);
                if (start < 0)
                {
                    continue;
                }

                start += token.Length;
                int end = evidence.IndexOf(' ', start);
                if (end < 0)
                {
                    end = evidence.Length;
                }

                string value = evidence[start..end].Trim();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }

            return string.IsNullOrWhiteSpace(detection) ? "rule match" : detection.Trim();
        }

        private void OpenSignatureIntelRulesWindow()
        {
            var window = new SignatureIntelRulesWindow(_signatureIntel,
                                                       message => OutputCapture.AppendLine(message))
            { Owner = this };
            window.Show();
        }

        private void QueueSignatureIntelForRootPid(int pid)
        {
            if (pid <= 0 || _signatureIntel == null || !_signatureIntelEnabled)
            {
                return;
            }

            if (TryResolveProcessImagePath((uint)pid, out string imagePath))
            {
                _signatureIntel.QueueFileScan(imagePath, (uint)pid, (uint)pid, "Interface", "SessionStart",
                                              "root-target");
            }

            _signatureIntel.QueueProcessMemoryScan((uint)pid, (uint)pid, (uint)pid, "Interface", "SessionStart",
                                                   "root-process-memory", force: true);
        }

        private IReadOnlyList<HeuristicEventView> QueueSignatureIntelForView(BrokerEtwEventView view)
        {
            if (_signatureIntel == null || !_signatureIntelEnabled || IsBlackbirdOwnEvent(view) ||
                HasFailedHookStatus(view))
            {
                return Array.Empty<HeuristicEventView>();
            }
            if (_captureProjection?.ExecutionPhase.IsPreResume == true &&
                TouchesCurrentTrackedTarget(view.ActorPid, view.TargetPid, view.ProcessPid, view.EventProcessId,
                                            view.CallerPid, view.ExplicitTargetPid))
            {
                return Array.Empty<HeuristicEventView>();
            }

            IReadOnlyList<HeuristicEventView> eventRuleFindings = _signatureIntel.EvaluateEventRules(view);

            if (ShouldQueueImagePathScan(view) && !string.IsNullOrWhiteSpace(view.ImagePath))
            {
                _signatureIntel.QueueFileScan(view.ImagePath, view.ActorPid, view.TargetPid, view.Source,
                                              string.IsNullOrWhiteSpace(view.EventName) ? "ImagePath" : view.EventName,
                                              "image-transition");
            }

            if (ShouldQueueTargetProcessScan(view) && view.TargetPid != 0 &&
                TryResolveProcessImagePath(view.TargetPid, out string targetImage))
            {
                _signatureIntel.QueueFileScan(targetImage, view.ActorPid, view.TargetPid, view.Source,
                                              string.IsNullOrWhiteSpace(view.EventName) ? "TargetPid" : view.EventName,
                                              "target-process");
            }

            if (_signatureIntelMemoryScanEnabled &&
                ShouldQueueProcessMemoryScan(view, out uint memoryScanPid, out string memoryScanTrigger))
            {
                _signatureIntel.QueueProcessMemoryScan(
                    memoryScanPid, view.ActorPid, memoryScanPid, view.Source,
                    string.IsNullOrWhiteSpace(view.EventName) ? "ProcessMemory" : view.EventName, memoryScanTrigger);
            }

            int sampleSize = (int)Math.Min(view.DeepSampleSize, (uint)(view.DeepSample?.Length ?? 0));
            if (sampleSize <= 0)
            {
                return eventRuleFindings;
            }

            bool pageSample = view.Family == BlackbirdNative.IpcEtwFamilyUserHook &&
                              (HasDetectionTrait(view, BlackbirdNative.IpcEtwTraitMemoryProtectRx) ||
                               HasDetectionTrait(view, BlackbirdNative.IpcEtwTraitMemoryAllocRw) ||
                               view.Operation.Contains("protect", StringComparison.OrdinalIgnoreCase) ||
                               view.Operation.Contains("alloc", StringComparison.OrdinalIgnoreCase) ||
                               view.EventName.Contains("protect", StringComparison.OrdinalIgnoreCase) ||
                               view.EventName.Contains("alloc", StringComparison.OrdinalIgnoreCase));

            if (pageSample && !_signatureIntelPageScanEnabled)
            {
                return eventRuleFindings;
            }

            if (!pageSample && !_signatureIntelMemoryScanEnabled)
            {
                return eventRuleFindings;
            }

            IReadOnlyList<HeuristicEventView> sampleFindings = _signatureIntel.ScanBufferForFindings(
                view.DeepSample, sampleSize, pageSample, view.OriginPath, view.ActorPid, view.TargetPid, view.Source,
                string.IsNullOrWhiteSpace(view.EventName) ? "Sample" : view.EventName,
                pageSample ? "page-sample" : "memory-sample", maxScanBytes: Math.Min(sampleSize, 64 * 1024));
            if (sampleFindings.Count > 0)
            {
                return eventRuleFindings.Count == 0 ? sampleFindings
                                                    : eventRuleFindings.Concat(sampleFindings).ToList();
            }

            _signatureIntel.QueueSampleScan(view.DeepSample, sampleSize, pageSample, view.OriginPath, view.ActorPid,
                                            view.TargetPid, view.Source,
                                            string.IsNullOrWhiteSpace(view.EventName) ? "Sample" : view.EventName,
                                            pageSample ? "page-sample" : "memory-sample");
            return eventRuleFindings;
        }

        private IReadOnlyList<HeuristicEventView> EvaluateSignatureIntelForIoctl(IoctlParsedEvent record)
        {
            if (_signatureIntel == null || !_signatureIntelEnabled)
            {
                return Array.Empty<HeuristicEventView>();
            }
            if (_captureProjection?.ExecutionPhase.IsPreResume == true &&
                TouchesCurrentTrackedTarget(record.CallerPid, record.TargetPid, record.ProcessPid,
                                            record.FileProcessPid, record.RegistryProcessPid))
            {
                return Array.Empty<HeuristicEventView>();
            }

            return _signatureIntel.EvaluateEventRules(record);
        }

        private bool TouchesCurrentTrackedTarget(params uint[] pids)
        {
            int currentPid = _currentSession?.Pid ?? TryGetPid();
            if (currentPid <= 0)
            {
                return false;
            }

            uint target = unchecked((uint)currentPid);
            return pids.Any(pid => pid == target);
        }

        private static bool TryResolveProcessImagePath(uint pid, out string imagePath)
        {
            imagePath = string.Empty;
            if (pid == 0)
            {
                return false;
            }

            try
            {
                using Process process = Process.GetProcessById(unchecked((int)pid));
                imagePath = process.MainModule?.FileName?.Trim() ?? string.Empty;
                return !string.IsNullOrWhiteSpace(imagePath);
            }
            catch
            {
                return false;
            }
        }

        private static bool ShouldQueueProcessMemoryScan(BrokerEtwEventView view, out uint processPid,
                                                         out string trigger)
        {
            processPid = FirstNonZero(view.TargetPid, view.ExplicitTargetPid, view.ProcessPid, view.EventProcessId,
                                      view.ActorPid);
            trigger = string.Empty;
            if (processPid == 0)
            {
                return false;
            }

            if (HasDetectionTrait(view, BlackbirdNative.IpcEtwTraitDirectSyscall))
            {
                trigger = "direct-syscall-process-memory";
                return true;
            }
            if (HasDetectionTrait(view, BlackbirdNative.IpcEtwTraitMemoryWriteVm))
            {
                trigger = "memory-write-process";
                return true;
            }
            if (HasDetectionTrait(view, BlackbirdNative.IpcEtwTraitMemoryProtectRx))
            {
                trigger = "memory-protect-process";
                return true;
            }
            if (HasDetectionTrait(view, BlackbirdNative.IpcEtwTraitMemoryAllocRw))
            {
                trigger = "memory-alloc-process";
                return true;
            }
            if (HasDetectionTrait(view, BlackbirdNative.IpcEtwTraitScanTargetProcess))
            {
                trigger = "target-process-memory";
                return true;
            }

            bool crossProcess = view.TargetPid != 0 && view.ActorPid != 0 && view.TargetPid != view.ActorPid;
            if (crossProcess &&
                (view.Family == BlackbirdNative.IpcEtwFamilyThread ||
                 view.Family == BlackbirdNative.IpcEtwFamilyApc))
            {
                trigger = "remote-exec-process-memory";
                return true;
            }

            string detection = view.DetectionName ?? string.Empty;
            string operation = view.Operation ?? string.Empty;
            string eventName = view.EventName ?? string.Empty;
            if (ContainsAnyOrdinalIgnoreCase(detection, "INJECT", "HOLLOW", "UNBACKED", "VM_WRITE",
                                             "REMOTE_THREAD") ||
                ContainsAnyOrdinalIgnoreCase(operation, "protect", "alloc", "writevirtualmemory",
                                             "writeprocessmemory", "mapviewofsection", "queueuserapc",
                                             "createremotethread") ||
                ContainsAnyOrdinalIgnoreCase(eventName, "protect", "alloc", "writevirtualmemory",
                                             "writeprocessmemory", "mapviewofsection", "queueuserapc",
                                             "createremotethread"))
            {
                trigger = "memory-event-process";
                return true;
            }

            return false;
        }

        private static bool ContainsAnyOrdinalIgnoreCase(string value, params string[] needles) =>
            !string.IsNullOrWhiteSpace(value) &&
            needles.Any(needle => value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0);

        private static bool ShouldQueueTargetProcessScan(BrokerEtwEventView view)
        {
            if (view.TargetPid == 0 || view.TargetPid == view.ActorPid)
            {
                return false;
            }

            if (HasDetectionTrait(view, BlackbirdNative.IpcEtwTraitScanTargetProcess) ||
                view.Family == BlackbirdNative.IpcEtwFamilyThread || view.Family == BlackbirdNative.IpcEtwFamilyApc)
            {
                return true;
            }

            string detection = view.DetectionName ?? string.Empty;
            string operation = view.Operation ?? string.Empty;
            string eventName = view.EventName ?? string.Empty;

            return detection.Contains("INJECT", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("REMOTE_THREAD", StringComparison.OrdinalIgnoreCase) ||
                   detection.Contains("VM_WRITE", StringComparison.OrdinalIgnoreCase) ||
                   operation.Contains("thread", StringComparison.OrdinalIgnoreCase) ||
                   operation.Contains("write", StringComparison.OrdinalIgnoreCase) ||
                   eventName.Contains("thread", StringComparison.OrdinalIgnoreCase);
        }

        private static bool ShouldQueueImagePathScan(BrokerEtwEventView view)
        {
            if (HasDetectionTrait(view, BlackbirdNative.IpcEtwTraitScanImagePath) ||
                view.Family == BlackbirdNative.IpcEtwFamilyProcess || view.Family == BlackbirdNative.IpcEtwFamilyImage)
            {
                return true;
            }

            string eventName = view.EventName ?? string.Empty;
            string operation = view.Operation ?? string.Empty;
            return eventName.Contains("load", StringComparison.OrdinalIgnoreCase) ||
                   eventName.Contains("create", StringComparison.OrdinalIgnoreCase) ||
                   operation.Contains("load", StringComparison.OrdinalIgnoreCase) ||
                   operation.Contains("create", StringComparison.OrdinalIgnoreCase);
        }
    }
}
