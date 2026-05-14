using BlackbirdInterface.Capture;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace BlackbirdInterface
{
    internal sealed partial class PackerDetectionService
    {
        internal void QueueInitialImageScan(string? imagePath)
        {
            if (_disposed || Interlocked.Exchange(ref _initialImageScanQueued, 1) != 0)
            {
                return;
            }

            _ = Task.Run(
                async () =>
                {
                    try
                    {
                        await Task.Delay(TimeSpan.FromMilliseconds(250), _cts.Token).ConfigureAwait(false);
                        ImageCodeScanResult? first = TryScanLoadedImage(imagePath, "initial-entry");
                        PublishImageScanFindings(first, previous: null, baselineOnly: true);

                        await WaitUntilDetectionPromotionAllowedAsync().ConfigureAwait(false);
                        await Task.Delay(TimeSpan.FromMilliseconds(1250), _cts.Token).ConfigureAwait(false);
                        ImageCodeScanResult? second = TryScanLoadedImage(imagePath, "early-code");
                        PublishImageScanFindings(second, previous: first, baselineOnly: !CanPromoteDetections());
                    }
                    catch (OperationCanceledException)
                    {
                    }
                    catch (Exception ex)
                    {
                        _log?.Invoke($"packer image scan failed pid={_targetPid}: {ex.Message}");
                    }
                },
                _cts.Token);
        }

        private async Task WaitUntilDetectionPromotionAllowedAsync()
        {
            while (!_cts.IsCancellationRequested && !CanPromoteDetections())
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100), _cts.Token).ConfigureAwait(false);
            }
        }

        private bool CanPromoteDetections()
        {
            lock (_sync)
            {
                return !_executionPhase.IsPreResume;
            }
        }

        internal void ObserveIoctl(IoctlParsedEvent record)
        {
            if (record == null || _disposed)
            {
                return;
            }

            if (record.Type == BlackbirdNative.EventTypeThread && IsTarget(record.ProcessPid) &&
                record.StartAddress != 0)
            {
                MarkExecution(record.StartAddress, record.ThreadFlags, "ioctl-thread-start");
            }

            uint targetPid = record.TargetPid != 0 ? record.TargetPid : record.ProcessPid;
            if (!TouchesTarget(record.CallerPid, targetPid, record.ProcessPid, record.FileProcessPid))
            {
                return;
            }
            if (!CanPromoteDetections())
            {
                return;
            }

            bool staged = record.Type == BlackbirdNative.EventTypeHandle &&
                          ((record.HandleFlags & 0x1u) != 0 || IsExecutableProtection(record.OriginProtect));
            UpdateMemoryCandidate(
                actorPid: record.CallerPid, targetPid: targetPid, allocationBase: record.DeepAllocationBase,
                regionSize: record.DeepRegionSize,
                protect: record.DeepRegionProtect != 0 ? record.DeepRegionProtect : record.OriginProtect,
                state: record.DeepRegionState, type: record.DeepRegionType, addressHint: record.OriginAddress,
                sample: record.DeepSample,
                sampleSize: (int)Math.Min(record.DeepSampleSize, (uint)(record.DeepSample?.Length ?? 0)),
                stagedMemory: staged, directSyscall: IsDirectSyscallHandleSignal(record.HandleFlags), source: "ioctl",
                reason: staged ? "kernel-memory-handle-evidence" : "kernel-region-evidence");
        }

        internal void ObserveEtw(BrokerEtwEventView view)
        {
            if (view == null || _disposed)
            {
                return;
            }

            if ((view.DetectionTraits & BlackbirdNative.IpcEtwTraitBlackbirdOwn) != 0)
            {
                return;
            }
            if (HasFailedHookStatus(view) || EventDetailFormatting.IsBlackbirdInternalPath(view.OriginPath) ||
                EventDetailFormatting.IsBlackbirdInternalPath(view.ImagePath))
            {
                return;
            }

            if (!TouchesTarget(view.ActorPid, view.TargetPid, view.ProcessPid, view.EventProcessId, view.CallerPid,
                               view.ExplicitTargetPid))
            {
                return;
            }
            if (!CanPromoteDetections())
            {
                return;
            }

            bool staged = HasAnyTrait(view.DetectionTraits, BlackbirdNative.IpcEtwTraitMemoryAllocRw |
                                                                BlackbirdNative.IpcEtwTraitMemoryWriteVm |
                                                                BlackbirdNative.IpcEtwTraitMemoryProtectRx |
                                                                BlackbirdNative.IpcEtwTraitImageTamper) ||
                          ContainsAny(view.EventName, "alloc", "protect", "write", "map", "unmap") ||
                          ContainsAny(view.Operation, "alloc", "protect", "write", "map", "unmap");

            bool direct = HasAnyTrait(view.DetectionTraits, BlackbirdNative.IpcEtwTraitDirectSyscall) ||
                          (view.Flags & BlackbirdNative.IpcEtwFlagSyscallExportMismatch) != 0;

            UpdateMemoryCandidate(
                actorPid: view.ActorPid, targetPid: view.TargetPid != 0 ? view.TargetPid : view.ProcessPid,
                allocationBase: view.DeepAllocationBase, regionSize: view.DeepRegionSize,
                protect: view.DeepRegionProtect != 0 ? view.DeepRegionProtect : view.OriginProtect,
                state: view.DeepRegionState, type: view.DeepRegionType,
                addressHint: view.OriginAddress != 0 ? view.OriginAddress : view.StartAddress, sample: view.DeepSample,
                sampleSize: (int)Math.Min(view.DeepSampleSize, (uint)(view.DeepSample?.Length ?? 0)),
                stagedMemory: staged, directSyscall: direct,
                source: string.IsNullOrWhiteSpace(view.Source) ? "etw" : view.Source,
                reason: staged ? "memory-api-transition" : "region-observation");

            if (view.StartAddress != 0 &&
                (view.Family == BlackbirdNative.IpcEtwFamilyThread || view.StartRegionProtect != 0 ||
                 (view.Flags & BlackbirdNative.IpcEtwFlagHookCallerHasUnmapped) != 0))
            {
                MarkExecution(view.StartAddress, view.Flags, "etw-thread-or-caller");
                if (IsCommittedPrivateExecutable(view.StartRegionState, view.StartRegionType, view.StartRegionProtect))
                {
                    MarkPrivateExecutable(view.StartAddress, view.StartRegionProtect, view.StartRegionState,
                                          view.StartRegionType, "start-region-private-exec");
                }
            }
        }

        internal void Flush(TimeSpan timeout)
        {
            if (!CanPromoteDetections())
            {
                return;
            }

            DateTime deadline = DateTime.UtcNow + timeout;
            lock (_sync)
            {
                foreach (CandidateRegion candidate in _candidates.Values)
                {
                    TryQueueCandidateLocked(candidate);
                }
            }

            while (DateTime.UtcNow < deadline)
            {
                if (_dumpQueue.IsEmpty && Volatile.Read(ref _activeDumpWorkers) == 0)
                {
                    return;
                }

                Thread.Sleep(25);
            }
        }

        private void UpdateMemoryCandidate(uint actorPid, uint targetPid, ulong allocationBase, ulong regionSize,
                                           uint protect, uint state, uint type, ulong addressHint, byte[]? sample,
                                           int sampleSize, bool stagedMemory, bool directSyscall, string source,
                                           string reason)
        {
            if (!CanPromoteDetections())
            {
                return;
            }

            ulong key = NormalizeRegionKey(allocationBase != 0 ? allocationBase : addressHint);
            if (key == 0)
            {
                return;
            }

            double entropy = ComputeEntropy(sample, sampleSize);
            bool sampleHasPe = LooksLikePeImage(sample, sampleSize);
            bool sampleHasMarker = ContainsPackerMarker(sample, sampleSize);

            lock (_sync)
            {
                CandidateRegion candidate = GetOrCreateCandidateLocked(key);
                candidate.LastSeenUtc = DateTime.UtcNow;
                candidate.ActorPid = actorPid;
                candidate.TargetPid = targetPid != 0 ? targetPid : (uint)_targetPid;
                candidate.RegionSize = NormalizeRegionSize(regionSize, candidate.RegionSize);
                candidate.LastProtect = protect != 0 ? protect : candidate.LastProtect;
                candidate.LastState = state != 0 ? state : candidate.LastState;
                candidate.LastType = type != 0 ? type : candidate.LastType;
                candidate.AddressHint = addressHint != 0 ? addressHint : candidate.AddressHint;

                if (IsCommittedPrivateExecutable(state, type, protect))
                {
                    candidate.HasPrivateExecutable = true;
                    candidate.AddSignal("private committed executable region observed");
                }

                if (stagedMemory)
                {
                    candidate.HasMemoryStaging = true;
                    candidate.AddSignal(reason);
                }

                if (directSyscall)
                {
                    candidate.HasDirectSyscall = true;
                    candidate.AddSignal("direct syscall or syscall-export mismatch observed");
                }

                if (sampleHasPe)
                {
                    candidate.HasPeHeaderSample = true;
                    candidate.AddSignal("PE header observed in private memory sample");
                }

                if (sampleHasMarker)
                {
                    candidate.HasPackerMarkerSample = true;
                    candidate.AddSignal("known packer marker observed in memory sample");
                }

                if (entropy >= HighEntropyThreshold)
                {
                    candidate.HighEntropySampleCount += 1;
                    candidate.AddSignal($"high entropy memory sample {entropy:F2} bits/byte");
                }

                if (!double.IsNaN(entropy))
                {
                    if (!double.IsNaN(candidate.LastEntropy) && Math.Abs(candidate.LastEntropy - entropy) >= 0.75)
                    {
                        candidate.EntropyFlipCount += 1;
                        candidate.AddSignal($"entropy shift {candidate.LastEntropy:F2}->{entropy:F2} bits/byte");
                    }

                    candidate.LastEntropy = entropy;
                }

                if (!string.IsNullOrWhiteSpace(source))
                {
                    candidate.AddSignal($"source={source.Trim()}");
                }

                TryQueueCandidateLocked(candidate);
            }
        }

        private void MarkExecution(ulong startAddress, uint flags, string reason)
        {
            if (!CanPromoteDetections())
            {
                return;
            }

            ulong key = FindCandidateKeyForAddress(startAddress);
            if (key == 0)
            {
                key = NormalizeRegionKey(startAddress);
            }

            if (key == 0)
            {
                return;
            }

            lock (_sync)
            {
                CandidateRegion candidate = GetOrCreateCandidateLocked(key);
                candidate.LastSeenUtc = DateTime.UtcNow;
                candidate.ExecutionAddress = startAddress;
                candidate.HasExecution = true;
                candidate.AddSignal(
                    $"{reason} private+0x{Math.Max(0, unchecked((long)(startAddress - candidate.BaseAddress))):X}");

                if ((flags &
                     (BlackbirdNative.IpcEtwFlagThreadOutsideMainImage | BlackbirdNative.IpcEtwFlagThreadRemoteCreator |
                      BlackbirdNative.IpcEtwFlagHookCallerHasUnmapped |
                      BlackbirdNative.IpcEtwFlagSyscallExportMismatch)) != 0)
                {
                    candidate.HasHighSignalExecution = true;
                    candidate.AddSignal($"execution flags=0x{flags:X8}");
                }

                TryQueueCandidateLocked(candidate);
            }
        }

        private void MarkPrivateExecutable(ulong address, uint protect, uint state, uint type, string reason)
        {
            if (!CanPromoteDetections())
            {
                return;
            }

            ulong key = FindCandidateKeyForAddress(address);
            if (key == 0)
            {
                key = NormalizeRegionKey(address);
            }

            if (key == 0)
            {
                return;
            }

            lock (_sync)
            {
                CandidateRegion candidate = GetOrCreateCandidateLocked(key);
                candidate.LastSeenUtc = DateTime.UtcNow;
                candidate.AddressHint = address;
                candidate.LastProtect = protect;
                candidate.LastState = state;
                candidate.LastType = type;
                candidate.HasPrivateExecutable = true;
                candidate.AddSignal(reason);
                TryQueueCandidateLocked(candidate);
            }
        }

        private ulong FindCandidateKeyForAddress(ulong address)
        {
            if (address == 0)
            {
                return 0;
            }

            lock (_sync)
            {
                foreach (CandidateRegion candidate in _candidates.Values)
                {
                    ulong end = candidate.BaseAddress + Math.Max(candidate.RegionSize, DefaultProbeRegionSize);
                    if (address >= candidate.BaseAddress && address < end)
                    {
                        return candidate.BaseAddress;
                    }
                }
            }

            return 0;
        }

        private CandidateRegion GetOrCreateCandidateLocked(ulong key)
        {
            if (_candidates.TryGetValue(key, out CandidateRegion? existing))
            {
                return existing;
            }

            var candidate =
                new CandidateRegion(key) { FirstSeenUtc = DateTime.UtcNow, LastSeenUtc = DateTime.UtcNow,
                                           RegionSize = DefaultProbeRegionSize, TargetPid = (uint)_targetPid };
            _candidates[key] = candidate;
            return candidate;
        }

        private void TryQueueCandidateLocked(CandidateRegion candidate)
        {
            if (candidate.DumpQueued || candidate.Dumped || candidate.DumpRejected)
            {
                return;
            }

            if (Volatile.Read(ref _dumpCount) >= MaxDumpCount)
            {
                return;
            }

            if (!candidate.HasPrivateExecutable || !candidate.HasMemoryStaging || !candidate.HasExecution)
            {
                return;
            }

            candidate.DumpQueued = true;
            _dumpQueue.Enqueue(candidate.BaseAddress);
            _dumpSignal.Release();
        }
    }
}
