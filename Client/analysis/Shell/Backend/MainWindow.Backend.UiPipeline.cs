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
        private void StartBackendTransformLoop(int generation)
        {
            StopBackendTransformLoop();

            var cts = new CancellationTokenSource();
            _backendTransformCts = cts;
            _backendTransformTask = Task.Run(() => BackendTransformLoop(generation, cts.Token));
        }

        private void StopBackendTransformLoop()
        {
            CancellationTokenSource? cts = _backendTransformCts;
            Task? task = _backendTransformTask;
            _backendTransformCts = null;
            _backendTransformTask = null;
            if (cts == null)
            {
                return;
            }

            try
            {
                cts.Cancel();
                _backendTransformSignal.Set();
                task?.Wait(300);
            }
            catch
            {
            }
            finally
            {
                cts.Dispose();
            }
        }

        private void BackendTransformLoop(int generation, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && generation == _backendGeneration)
            {
                bool producedUiWork = false;
                int transformed = 0;
                int etwBudget =
                    Math.Min(MaxBackendTransformItemsPerBatch / 2, Math.Max(128, MaxBackendTransformItemsPerBatch));

                while (transformed < etwBudget && _pendingEtwEvents.TryDequeue(out var etw))
                {
                    Interlocked.Decrement(ref _pendingEtwCount);
                    BrokerEtwEventView view = BrokerEtwEventMapper.FromNative(etw);
                    _captureProjection?.ObserveEtw(view);
                    _packerDetector?.ObserveEtw(view);
                    ProcessIdentityResolver.Prime(view.ActorPid);
                    ProcessIdentityResolver.Prime(view.TargetPid);

                    if (view.Family == BlackbirdNative.IpcEtwFamilyProcess &&
                        (view.Flags & BlackbirdNative.IpcEtwFlagProcessIsCreate) != 0)
                    {
                        uint etwCreator = view.CreatorPid != 0 ? view.CreatorPid : view.ActorPid;
                        uint etwChild = view.ProcessPid != 0 ? view.ProcessPid : view.TargetPid;
                        if (etwCreator != 0 && etwChild != 0 && etwCreator != etwChild &&
                            _filterTrackedPids.ContainsKey(etwCreator))
                        {
                            _filterTrackedPids.TryAdd(etwChild, 0);
                            QueueMonitoredProcessRegistration(generation, etwChild);
                        }
                    }

                    if (view.ActorPid != 0 && _filterTrackedPids.ContainsKey(view.ActorPid))
                    {
                        QueueMonitoredProcessRegistration(generation, view.ActorPid);
                    }

                    producedUiWork |= TryEnqueueUiWork(BackendUiWorkItem.FromEtw(view));
                    transformed += 1;
                }

                while (transformed < MaxBackendTransformItemsPerBatch && _pendingIoctlEvents.TryDequeue(out var ioctl))
                {
                    Interlocked.Decrement(ref _pendingIoctlCount);
                    DateTime nowUtc = DateTime.UtcNow;
                    _captureProjection?.ObserveIoctl(ioctl, nowUtc);
                    _packerDetector?.ObserveIoctl(ioctl);
                    bool acceptFilesystem = ShouldAcceptFilesystemRecord(ioctl);
                    if (acceptFilesystem)
                    {
                        RememberRecentImageFileAccess(ioctl, nowUtc);
                    }

                    IReadOnlyList<TelemetryEvent> filesystemClusterEvents =
                        acceptFilesystem ? AccumulateFilesystemTimelineCluster(ioctl, nowUtc)
                                         : Array.Empty<TelemetryEvent>();
                    if (filesystemClusterEvents.Count > 0)
                    {
                        for (int i = 0; i < filesystemClusterEvents.Count; i += 1)
                        {
                            if (TryEnqueueUiWork(
                                    BackendUiWorkItem.FromIoctl(filesystemClusterEvents[i], null, null, null, null)))
                            {
                                producedUiWork = true;
                            }
                            else
                            {
                                break;
                            }
                        }
                    }

                    if (ioctl.Type == BlackbirdNative.EventTypeThread && ioctl.ProcessPid != 0 &&
                        ioctl.CreatorPid != 0 && ioctl.ProcessPid != ioctl.CreatorPid &&
                        _filterTrackedPids.ContainsKey(ioctl.CreatorPid))
                    {
                        _filterTrackedPids.TryAdd(ioctl.ProcessPid, 0);
                    }

                    TelemetryEvent? telemetry = MapIoctlRecord(ioctl);
                    ProcessRelationView? relation = MapIoctlRelation(ioctl);
                    HeuristicEventView? heuristic = MapIoctlHeuristic(ioctl);
                    HeuristicEventView? uiHeuristic = heuristic;
                    if (heuristic != null && _captureProjection != null)
                    {
                        PublishHeuristicsViaProjection(new[] { heuristic });
                        uiHeuristic = null;
                    }
                    IReadOnlyList<HeuristicEventView> signatureIntelIoctlFindings =
                        ShouldEvaluateSignatureIntelForIoctl(ioctl, acceptFilesystem)
                            ? EvaluateSignatureIntelForIoctl(ioctl)
                            : Array.Empty<HeuristicEventView>();
                    if (signatureIntelIoctlFindings.Count > 0)
                    {
                        PublishHeuristicsViaProjection(signatureIntelIoctlFindings);
                    }
                    ThreadLifecycleEventSample? threadLifecycle = MapIoctlThreadLifecycle(ioctl);
                    IoctlParsedEvent? filesystem = acceptFilesystem ? MapIoctlFilesystem(ioctl) : null;
                    IoctlParsedEvent? registry = MapIoctlRegistry(ioctl);
                    if (relation != null)
                    {
                        ProcessIdentityResolver.Prime(relation.SourcePid);
                        ProcessIdentityResolver.Prime(relation.TargetPid);
                    }
                    if (heuristic != null)
                    {
                        ProcessIdentityResolver.Prime(heuristic.ActorPid);
                        ProcessIdentityResolver.Prime(heuristic.TargetPid);
                    }
                    if (signatureIntelIoctlFindings.Count > 0)
                    {
                        for (int i = 0; i < signatureIntelIoctlFindings.Count; i += 1)
                        {
                            ProcessIdentityResolver.Prime(signatureIntelIoctlFindings[i].ActorPid);
                            ProcessIdentityResolver.Prime(signatureIntelIoctlFindings[i].TargetPid);
                        }
                    }
                    if (filesystem != null)
                    {
                        ProcessIdentityResolver.Prime(filesystem.FileProcessPid);
                    }
                    if (registry != null)
                    {
                        ProcessIdentityResolver.Prime(registry.RegistryProcessPid);
                    }
                    if (acceptFilesystem &&
                        (ShouldPersistIoctlRecord(ioctl, telemetry, relation, heuristic, filesystem) ||
                         signatureIntelIoctlFindings.Count > 0))
                    {
                        AppendIoctlToCaptureStore(nowUtc, ioctl);
                    }

                    if (telemetry != null || relation != null || uiHeuristic != null || threadLifecycle != null ||
                        filesystem != null || registry != null)
                    {
                        producedUiWork |= TryEnqueueUiWork(BackendUiWorkItem.FromIoctl(
                            telemetry, relation, uiHeuristic, threadLifecycle, filesystem, registry));
                    }

                    transformed += 1;
                }

                int statusLines = 0;
                while (statusLines < MaxBackendStatusLinesPerTransformBatch &&
                       _pendingStatusLines.TryDequeue(out var statusLine))
                {
                    Interlocked.Decrement(ref _pendingStatusCount);
                    producedUiWork |= TryEnqueueUiWork(BackendUiWorkItem.FromStatus(statusLine));
                    statusLines += 1;
                }

                IReadOnlyList<TelemetryEvent> idleFilesystemClusters =
                    FlushFilesystemTimelineClusterIfNeeded(DateTime.UtcNow, force: false);
                if (idleFilesystemClusters.Count > 0)
                {
                    for (int i = 0; i < idleFilesystemClusters.Count; i += 1)
                    {
                        if (TryEnqueueUiWork(
                                BackendUiWorkItem.FromIoctl(idleFilesystemClusters[i], null, null, null, null)))
                        {
                            producedUiWork = true;
                        }
                        else
                        {
                            break;
                        }
                    }
                }

                if (producedUiWork)
                {
                    ScheduleBackendUiFlush(generation);
                    continue;
                }

                _backendTransformSignal.WaitOne(120);
            }
        }

        private void ScheduleBackendUiFlush(int generation)
        {
            if (Interlocked.Exchange(ref _backendUiFlushScheduled, 1) != 0)
            {
                return;
            }

            Dispatcher.BeginInvoke(new Action(() => FlushBackendUi(generation)), DispatcherPriority.Background);
        }

        private void FlushBackendUi(int generation)
        {
            Interlocked.Exchange(ref _backendUiFlushScheduled, 0);
            if (generation != _backendGeneration)
            {
                ClearPendingBackendUiQueues();
                return;
            }

            var stopwatch = Stopwatch.StartNew();
            int processed = 0;
            bool underPressure = Interlocked.Read(ref _pendingUiWorkCount) > (MaxPendingUiWorkItems / 2) ||
                                 Interlocked.Read(ref _pendingIoctlCount) > (MaxPendingIoctlEvents / 2) ||
                                 Interlocked.Read(ref _pendingEtwCount) > (MaxPendingEtwEvents / 2);
            int maxItemsThisFlush = underPressure ? MaxBackendUiItemsPerFlushUnderPressure : MaxBackendUiItemsPerFlush;
            TimeSpan budget = underPressure ? BackendUiFlushBudgetUnderPressure : BackendUiFlushBudget;
            var telemetryBatch = new List<TelemetryEvent>(96);
            var relationBatch = new List<ProcessRelationView>(32);
            var heuristicBatch = new List<HeuristicEventView>(32);
            var threadLifecycleBatch = new List<ThreadLifecycleEventSample>(32);
            var filesystemBatch = new List<IoctlParsedEvent>(32);
            var registryBatch = new List<IoctlParsedEvent>(32);
            var etwBatch = new List<BrokerEtwEventView>(96);
            var statusBatch = new List<string>(32);
            while (processed < maxItemsThisFlush && stopwatch.Elapsed < budget &&
                   _pendingUiWork.TryDequeue(out var uiWork))
            {
                Interlocked.Decrement(ref _pendingUiWorkCount);
                if (uiWork.Kind == BackendUiWorkKind.Status)
                {
                    if (statusBatch.Count < MaxBackendStatusLinesPerUiFlush &&
                        !string.IsNullOrWhiteSpace(uiWork.StatusLine))
                    {
                        statusBatch.Add(uiWork.StatusLine);
                    }
                }
                else if (uiWork.Kind == BackendUiWorkKind.Ioctl)
                {
                    if (uiWork.Telemetry != null)
                    {
                        telemetryBatch.Add(uiWork.Telemetry);
                    }
                    if (uiWork.Relation != null)
                    {
                        relationBatch.Add(uiWork.Relation);
                    }
                    if (uiWork.Heuristic != null)
                    {
                        heuristicBatch.Add(uiWork.Heuristic);
                    }
                    if (uiWork.ThreadLifecycle != null)
                    {
                        threadLifecycleBatch.Add(uiWork.ThreadLifecycle);
                    }
                    if (uiWork.Filesystem != null)
                    {
                        filesystemBatch.Add(uiWork.Filesystem);
                    }
                    if (uiWork.Registry != null)
                    {
                        registryBatch.Add(uiWork.Registry);
                    }
                }
                else if (uiWork.Kind == BackendUiWorkKind.Etw && uiWork.EtwView != null)
                {
                    etwBatch.Add(uiWork.EtwView);
                }

                processed += 1;
            }

            for (int i = 0; i < statusBatch.Count; i += 1)
            {
                OutputCapture.AppendLine(statusBatch[i]);
            }

            if (telemetryBatch.Count > 0)
            {
                AppendEvents(telemetryBatch);
            }

            if (relationBatch.Count > 0)
            {
                ProcessRelationsPaneHost.PushRelations(relationBatch);
                _explorer.FirstOrDefault(x => x.Name == "Process Relations")
                    ?.PushPreviewValue(ProcessRelationsPaneHost.TotalRawCount);
                SetExplorerHasData("Process Relations", ProcessRelationsPaneHost.ItemCount > 0);
            }

            if (heuristicBatch.Count > 0)
            {
                HeuristicsPaneHost.PushHeuristics(heuristicBatch);
                bool extendedChanged = false;
                for (int i = 0; i < heuristicBatch.Count; i += 1)
                {
                    extendedChanged |= ObserveSignatureIntelActivity(heuristicBatch[i]);
                }
                if (extendedChanged)
                {
                    ScheduleExtendedActivitySnapshot();
                }
                _explorer.FirstOrDefault(x => x.Name == "Heuristics")
                    ?.PushPreviewValue(HeuristicsPaneHost.TotalRawCount);
                SetExplorerHasData("Heuristics", HeuristicsPaneHost.ItemCount > 0);
                DiagnosticsState.Increment("Heuristics", heuristicBatch.Count);
            }

            if (threadLifecycleBatch.Count > 0)
            {
                PerformancePaneHost.PushThreadLifecycles(threadLifecycleBatch);
                if (_currentSession != null)
                {
                    for (int i = 0; i < threadLifecycleBatch.Count; i += 1)
                    {
                        _currentSession.ThreadLifecycleHistory.Add(CloneThreadLifecycleEvent(threadLifecycleBatch[i]));
                    }

                    if (_currentSession.ThreadLifecycleHistory.Count > 12_000)
                    {
                        _currentSession.ThreadLifecycleHistory.RemoveRange(
                            0, _currentSession.ThreadLifecycleHistory.Count - 12_000);
                    }
                }
            }

            if (filesystemBatch.Count > 0)
            {
                FilesystemPaneHost.PushFileEvents(filesystemBatch);
                _explorer.FirstOrDefault(x => x.Name == "Filesystem")
                    ?.PushPreviewValue(FilesystemPaneHost.TotalRawCount);
                SetExplorerHasData("Filesystem", FilesystemPaneHost.ItemCount > 0);
            }

            if (registryBatch.Count > 0)
            {
                RegistryPaneHost.PushRegistryEvents(registryBatch);
                _explorer.FirstOrDefault(x => x.Name == "Registry")?.PushPreviewValue(RegistryPaneHost.TotalRawCount);
                SetExplorerHasData("Registry", RegistryPaneHost.ItemCount > 0);
            }

            SpillCurrentSessionWorkingSetIfNeeded();

            if (etwBatch.Count > 0)
            {
                HandleBrokerEtwViews(etwBatch);
            }

            DiagnosticsState.SetValue(
                "UI Flush",
                $"items={processed} ms={stopwatch.Elapsed.TotalMilliseconds:0.0} pending={Interlocked.Read(ref _pendingUiWorkCount)}");

            if (HasPendingBackendUiData())
            {
                ScheduleBackendUiFlush(generation);
            }
        }

        private bool HasPendingBackendUiData()
        {
            return Interlocked.Read(ref _pendingIoctlCount) > 0 || Interlocked.Read(ref _pendingEtwCount) > 0 ||
                   Interlocked.Read(ref _pendingStatusCount) > 0 || Interlocked.Read(ref _pendingUiWorkCount) > 0;
        }

        private void ClearPendingBackendUiQueues()
        {
            while (_pendingIoctlEvents.TryDequeue(out _))
            {
            }

            while (_pendingEtwEvents.TryDequeue(out _))
            {
            }

            while (_pendingStatusLines.TryDequeue(out _))
            {
            }

            while (_pendingUiWork.TryDequeue(out _))
            {
            }

            Interlocked.Exchange(ref _pendingIoctlCount, 0);
            Interlocked.Exchange(ref _pendingEtwCount, 0);
            Interlocked.Exchange(ref _pendingStatusCount, 0);
            Interlocked.Exchange(ref _pendingUiWorkCount, 0);
            Interlocked.Exchange(ref _backendUiFlushScheduled, 0);
            ResetFilesystemTimelineCluster();
        }

        private bool TryEnqueueUiWork(BackendUiWorkItem item)
        {
            if (Interlocked.Read(ref _pendingUiWorkCount) >= MaxPendingUiWorkItems)
            {
                Interlocked.Increment(ref _droppedUiWorkForPressure);
                return false;
            }

            _pendingUiWork.Enqueue(item);
            Interlocked.Increment(ref _pendingUiWorkCount);
            return true;
        }

        private void QueueMonitoredProcessRegistration(int generation, uint pid)
        {
            if (pid == 0 || !_pendingMonitoredProcessRegistrations.TryAdd(pid, 0) || Dispatcher.HasShutdownStarted)
            {
                return;
            }

            Dispatcher.BeginInvoke(new Action(() =>
                                              {
                                                  _pendingMonitoredProcessRegistrations.TryRemove(pid, out _);
                                                  if (generation == _backendGeneration)
                                                  {
                                                      TryRegisterMonitoredProcess(pid);
                                                  }
                                              }),
                                   DispatcherPriority.Background);
        }
    }
}
