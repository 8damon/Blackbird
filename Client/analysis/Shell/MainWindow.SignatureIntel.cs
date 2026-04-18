using System;
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
            DiagnosticsState.SetValue("Signature Intel", "Available");
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

                                                          HeuristicsPaneHost.PushHeuristics(findings);
                                                          _explorer.FirstOrDefault(x => x.Name == "Heuristics")
                                                              ?.PushPreviewValue(HeuristicsPaneHost.TotalRawCount);
                                                          SetExplorerHasData("Heuristics",
                                                                             HeuristicsPaneHost.ItemCount > 0);
                                                          DiagnosticsState.Increment("Heuristics", findings.Count);
                                                      }),
                                           DispatcherPriority.Background);
                },
                message => OutputCapture.AppendLine(message));
        }

        private void DisposeSignatureIntelSubsystem()
        {
            _signatureIntel?.Dispose();
            _signatureIntel = null;
        }

        internal void ConfigureStartupSignatureIntel(bool enabled, bool enableMemoryScan, bool enablePageScan)
        {
            _signatureIntel?.Configure(new SignatureIntelOptions(Enabled: enabled, MemoryScan: enableMemoryScan,
                                                                 PageScan: enablePageScan, HashScan: enabled));
            DiagnosticsState.SetValue(
                "Signature Intel",
                enabled
                    ? $"Enabled memory={(enableMemoryScan ? "on" : "off")} page={(enablePageScan ? "on" : "off")} hash=on"
                    : "Disabled");
        }

        private void QueueSignatureIntelForRootPid(int pid)
        {
            if (pid <= 0 || _signatureIntel == null)
            {
                return;
            }

            if (TryResolveProcessImagePath((uint)pid, out string imagePath))
            {
                _signatureIntel.QueueFileScan(imagePath, (uint)pid, (uint)pid, "Interface", "SessionStart",
                                              "root-target");
            }
        }

        private void QueueSignatureIntelForView(BrokerEtwEventView view)
        {
            if (_signatureIntel == null)
            {
                return;
            }

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

            int sampleSize = (int)Math.Min(view.DeepSampleSize, (uint)(view.DeepSample?.Length ?? 0));
            if (sampleSize <= 0)
            {
                return;
            }

            bool pageSample = view.Family == BlackbirdNative.IpcEtwFamilyUserHook &&
                              (view.Operation.Contains("protect", StringComparison.OrdinalIgnoreCase) ||
                               view.Operation.Contains("alloc", StringComparison.OrdinalIgnoreCase) ||
                               view.EventName.Contains("protect", StringComparison.OrdinalIgnoreCase) ||
                               view.EventName.Contains("alloc", StringComparison.OrdinalIgnoreCase));

            _signatureIntel.QueueSampleScan(view.DeepSample, sampleSize, pageSample, view.OriginPath, view.ActorPid,
                                            view.TargetPid, view.Source,
                                            string.IsNullOrWhiteSpace(view.EventName) ? "Sample" : view.EventName,
                                            pageSample ? "page-sample" : "memory-sample");
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

        private static bool ShouldQueueTargetProcessScan(BrokerEtwEventView view)
        {
            if (view.TargetPid == 0 || view.TargetPid == view.ActorPid)
            {
                return false;
            }

            if (view.Family == BlackbirdNative.IpcEtwFamilyThread || view.Family == BlackbirdNative.IpcEtwFamilyApc)
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
            if (view.Family == BlackbirdNative.IpcEtwFamilyProcess || view.Family == BlackbirdNative.IpcEtwFamilyImage)
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
