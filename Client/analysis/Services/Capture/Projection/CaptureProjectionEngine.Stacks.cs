using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace BlackbirdInterface.Capture
{
    internal sealed partial class CaptureProjectionEngine
    {
        private void PersistObservedHookStackSnapshot(BrokerEtwEventView view, DateTime observedUtc)
        {
            if (view.Family != BlackbirdNative.IpcEtwFamilyUserHook ||
                view.SourceId != BlackbirdNative.IpcEtwSourceUserHook || view.StackCount == 0 || view.Stack.Length == 0)
            {
                return;
            }

            uint pid = FirstNonZero(view.ProcessPid, view.ActorPid, view.EventProcessId);
            uint tid = FirstNonZero(view.EventThreadId, view.ThreadId);
            if (pid == 0 || tid == 0 || pid > int.MaxValue || tid > int.MaxValue)
            {
                return;
            }

            string throttleKey = $"{pid}:{tid}";
            if (_observedHookStackLastPersistByThread.TryGetValue(throttleKey, out DateTime lastPersistUtc) &&
                observedUtc < lastPersistUtc.AddMilliseconds(250))
            {
                return;
            }

            _observedHookStackLastPersistByThread[throttleKey] = observedUtc;
            PersistStackSnapshot(tid, "Observed hook stack", observedUtc, view.Stack);
            _observedHookStacks += 1;
        }

        private void QueueThreadStackFallbackCapture(BrokerEtwEventView view, DateTime observedUtc)
        {
            if (view.StackCount != 0 || !ShouldCaptureThreadStackFallback(view))
            {
                return;
            }

            uint pid = FirstNonZero(view.ProcessPid, view.ActorPid, view.EventProcessId);
            uint tid = FirstNonZero(view.EventThreadId, view.ThreadId);
            if (pid == 0 || tid == 0 || pid > int.MaxValue || tid > int.MaxValue)
            {
                return;
            }

            string key = $"{pid}:{tid}";
            if (_threadStackFallbackLastCaptureByThread.TryGetValue(key, out DateTime lastCaptureUtc) &&
                observedUtc < lastCaptureUtc.AddSeconds(6))
            {
                return;
            }

            if (_pendingThreadStackFallbackKeys.Count >= 32 || !_pendingThreadStackFallbackKeys.Add(key))
            {
                return;
            }

            _threadStackFallbackLastCaptureByThread[key] = observedUtc;
            int capturePid = unchecked((int)pid);
            int captureTid = unchecked((int)tid);
            Task task = Task.Run(() =>
                                 {
                                     ThreadStackResolveResult result =
                                         ThreadStackResolver.Resolve(capturePid, captureTid, "Hook fallback");
                                     return CreateThreadStackFallbackSnapshot(observedUtc, result);
                                 })
                            .ContinueWith(
                                task =>
                                {
                                    lock (_sync)
                                    {
                                        _pendingThreadStackFallbackKeys.Remove(key);
                                        if (task.Status == TaskStatus.RanToCompletion && task.Result != null &&
                                            task.Result.Frames.Count > 0)
                                        {
                                            PersistStackSnapshot(unchecked((uint)captureTid), "Fallback hook stack",
                                                                 task.Result);
                                            _fallbackStackCaptures += 1;
                                        }
                                        else
                                        {
                                            _fallbackStackMisses += 1;
                                        }
                                    }
                                },
                                TaskScheduler.Default);
            _pendingThreadStackCaptures.Add(task);
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

            string api = FirstNonEmpty(view.Operation, view.EventName);
            if (api.Length == 0)
            {
                return false;
            }

            bool kernelNtapi = EventDetailFormatting.IsKernelHookTelemetry(view) ||
                               (view.Reason?.Contains("kind=kernel_ntapi", StringComparison.OrdinalIgnoreCase) ==
                                true);
            if (!api.StartsWith("Nt", StringComparison.OrdinalIgnoreCase) &&
                !api.StartsWith("Zw", StringComparison.OrdinalIgnoreCase) &&
                !api.StartsWith("Co", StringComparison.OrdinalIgnoreCase) &&
                !api.Contains("Trace", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            bool highSignal = view.Severity >= 4 ||
                              (kernelNtapi && view.Severity >= 2) ||
                              api.Equals("NtMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("ZwMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("NtAllocateVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("NtAllocateVirtualMemoryEx", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("NtCreateSection", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("ZwCreateSection", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("NtCreateFile", StringComparison.OrdinalIgnoreCase) ||
                              api.Equals("NtOpenFile", StringComparison.OrdinalIgnoreCase) ||
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
    }
}
