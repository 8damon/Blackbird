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

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private void AppendIoctlToCaptureStore(DateTime timestampUtc, IoctlParsedEvent record)
        {
            BlackbirdCaptureLiveStore? store = _liveCaptureStore;
            if (store == null)
            {
                return;
            }

            try
            {
                store.AppendIoctl(timestampUtc, record);
            }
            catch (Exception ex)
            {
                DiagnosticsState.SetValue("Capture Store", $"IOCTL append failed: {ex.Message}");
            }
        }

        private void AppendEtwToCaptureStore(BrokerEtwEventView view)
        {
            BlackbirdCaptureLiveStore? store = _liveCaptureStore;
            if (store == null)
            {
                return;
            }

            try
            {
                store.AppendEtw(view);
            }
            catch (Exception ex)
            {
                DiagnosticsState.SetValue("Capture Store", $"ETW append failed: {ex.Message}");
            }
        }

        private static ulong BuildRelationKey(uint actorPid, uint targetPid) => ((ulong)actorPid << 32) | targetPid;

        private void RememberHandleEvidence(IoctlParsedEvent record)
        {
            if (record.Type != BlackbirdNative.EventTypeHandle || record.CallerPid == 0 || record.TargetPid == 0)
            {
                return;
            }

            uint highSignalMask = 0x00000800 | 0x00002000;
            bool highRiskAccess = (record.DesiredAccess & (0x0002u | 0x0008u | 0x0010u | 0x0020u | 0x0800u)) != 0;
            if (!highRiskAccess)
            {
                bool processAll = (record.DesiredAccess & 0x001F0FFFu) == 0x001F0FFFu;
                bool threadAll = (record.DesiredAccess & 0x001F03FFu) == 0x001F03FFu;
                highRiskAccess = processAll || threadAll;
            }
            bool suspicious = record.HandleClass == 2 || ((record.HandleFlags & highSignalMask) != 0);
            if (!highRiskAccess && !suspicious)
            {
                return;
            }

            _recentHandleEvidenceByPair[BuildRelationKey(record.CallerPid, record.TargetPid)] = record;
            _recentHandleEvidenceByPair[BuildRelationKey(record.TargetPid, record.CallerPid)] = record;

            DateTime now = DateTime.UtcNow;
            if ((now - _lastHandleEvidencePruneUtc).TotalSeconds < 20)
            {
                return;
            }

            _lastHandleEvidencePruneUtc = now;
            if (_recentHandleEvidenceByPair.Count > 4096)
            {
                _recentHandleEvidenceByPair.Clear();
            }
        }

        private bool TryGetHandleEvidence(uint actorPid, uint targetPid, out IoctlParsedEvent evidence)
        {
            if (_recentHandleEvidenceByPair.TryGetValue(BuildRelationKey(actorPid, targetPid), out IoctlParsedEvent? found))
            {
                evidence = found;
                return true;
            }

            evidence = new IoctlParsedEvent();
            return false;
        }

        private static bool IsBlackbirdOwnEvent(BrokerEtwEventView view)
        {
            if ((view.DetectionTraits & BlackbirdNative.IpcEtwTraitBlackbirdOwn) != 0 ||
                view.DetectionName.Equals("BK_INSTRUMENTATION", StringComparison.OrdinalIgnoreCase) ||
                view.Source.Equals("BK/SR71", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return EventDetailFormatting.IsBlackbirdInternalPath(view.OriginPath) ||
                   EventDetailFormatting.IsBlackbirdInternalPath(view.ImagePath);
        }

        private static bool ShouldKeepEtwEvent(BrokerEtwEventView view)
        {
            if (IsBlackbirdOwnEvent(view))
                return true;

            if (view.Family == BlackbirdNative.IpcEtwFamilyUserHook)
            {
                return true;
            }

            if (view.Family == BlackbirdNative.IpcEtwFamilySocket ||
                EventDetailFormatting.IsKernelNetworkEtwSource(view))
            {
                return true;
            }

            if (IsDirectSyscallDetection(view))
            {
                return true;
            }

            if (!string.IsNullOrWhiteSpace(view.DetectionName))
            {
                return true;
            }

            if (view.Severity >= 4)
            {
                return true;
            }

            if (EventDetailFormatting.IsThreatIntelEtwSource(view))
            {
                return view.Task == 1 || view.Task == 2 || view.Task == 7;
            }

            if (view.EventName.Equals("ThreadTelemetry", StringComparison.OrdinalIgnoreCase) ||
                view.EventName.Equals("ApcTelemetry", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return false;
        }

        private static bool ShouldPromoteHeuristic(BrokerEtwEventView view)
        {
            if (HasFailedHookStatus(view))
            {
                return false;
            }

            if (IsDirectSyscallDetection(view))
            {
                return view.Severity >= 2 || IsDirectSyscallHandleTelemetry(view);
            }

            if (string.IsNullOrWhiteSpace(view.DetectionName))
            {
                return false;
            }

            string det = view.DetectionName;
            if (IsHookTamperDetection(view))
            {
                return true;
            }
            if (det.Contains("AMSI_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("ETW_PATCH_TAMPERED", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (det.Equals("USERMODE_COM_INIT", StringComparison.OrdinalIgnoreCase) ||
                det.Equals("USERMODE_COM_SECURITY_INIT", StringComparison.OrdinalIgnoreCase) ||
                det.Equals("USERMODE_COM_INSTANCE_CREATE", StringComparison.OrdinalIgnoreCase) ||
                det.Equals("USERMODE_WMI_ACTIVITY", StringComparison.OrdinalIgnoreCase) ||
                det.Equals("USERMODE_ETW_SESSION_CONTROL", StringComparison.OrdinalIgnoreCase) ||
                det.Equals("USERMODE_ETW_SUBSCRIPTION", StringComparison.OrdinalIgnoreCase) ||
                det.Equals("USERMODE_ETW_PROVIDER_REGISTER", StringComparison.OrdinalIgnoreCase) ||
                det.Equals("USERMODE_ETW_PROVIDER_UNREGISTER", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (det.Contains("ANTI_DEBUG", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("ANTI_VM", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("ANTI_VIRTUAL", StringComparison.OrdinalIgnoreCase))
            {
                return view.Severity >= 4;
            }

            if (det.Contains("HOLLOW", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("INJECTION", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("THREAD_HIJACK", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("REMOTE_APC", StringComparison.OrdinalIgnoreCase))
            {
                return view.Severity >= 5;
            }

            if (det.Contains("REMOTE_THREAD_WITH_RECENT_HANDLE_INTENT", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("THREAD_ACTIVITY_WITH_THREAD_CONTEXT_INTENT", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("REMOTE_THREAD_OUTSIDE_MAIN_IMAGE", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return view.Severity >= 6;
        }
    }
}
