using BlackbirdInterface.Capture;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace BlackbirdInterface
{
    internal sealed class PackerDetectionService : IDisposable
    {
        private const uint MemCommit = 0x1000;
        private const uint MemPrivate = 0x20000;
        private const uint PageExecute = 0x10;
        private const uint PageExecuteRead = 0x20;
        private const uint PageExecuteReadWrite = 0x40;
        private const uint PageExecuteWriteCopy = 0x80;
        private const uint ProcessQueryInformation = 0x0400;
        private const uint ProcessVmRead = 0x0010;
        private const ulong PageMask = 0xFFFFFFFFFFFFF000UL;
        private const ulong DefaultProbeRegionSize = 0x10000;
        private const ulong MaxCandidateRegionSize = 64UL * 1024UL * 1024UL;
        private const ulong MinProbeRegionSize = 0x4000;
        private const int MaxDumpCount = 4;
        private const int MaxDumpBytes = 8 * 1024 * 1024;
        private const int MaxYaraScanBytes = 2 * 1024 * 1024;
        private const int ReadChunkBytes = 0x4000;
        private const double HighEntropyThreshold = 7.15;
        private static readonly JsonSerializerOptions JsonOptions =
            new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };

        private readonly int _targetPid;
        private readonly string _workspaceRoot;
        private readonly BlackbirdCaptureLiveStore? _store;
        private readonly Action<string>? _log;
        private readonly SignatureIntelService _signatures;
        private readonly ConcurrentQueue<ulong> _dumpQueue = new();
        private readonly SemaphoreSlim _dumpSignal = new(0);
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _worker;
        private readonly object _sync = new();
        private readonly Dictionary<ulong, CandidateRegion> _candidates = new();
        private int _activeDumpWorkers;
        private int _dumpCount;
        private bool _disposed;

        internal PackerDetectionService(int targetPid, string workspaceRoot, BlackbirdCaptureLiveStore? store,
                                        Action<string>? log)
        {
            _targetPid = targetPid;
            _workspaceRoot = Path.GetFullPath(workspaceRoot);
            _store = store;
            _log = log;
            _signatures = new SignatureIntelService(
                _ =>
                {},
                message => _log?.Invoke(message));
            _signatures.Configure(
                new SignatureIntelOptions(Enabled: true, MemoryScan: true, PageScan: true, HashScan: false));
            _worker = Task.Run(WorkerLoopAsync);
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

            if (!TouchesTarget(view.ActorPid, view.TargetPid, view.ProcessPid, view.EventProcessId, view.CallerPid,
                               view.ExplicitTargetPid))
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

        private async Task WorkerLoopAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                try
                {
                    await _dumpSignal.WaitAsync(_cts.Token).ConfigureAwait(false);
                    while (_dumpQueue.TryDequeue(out ulong key))
                    {
                        CandidateSnapshot ? snapshot;
                        lock (_sync)
                        {
                            snapshot = _candidates.TryGetValue(key, out CandidateRegion? candidate)
                                ? candidate.ToSnapshot()
                                : null;
                        }

                        if (snapshot == null)
                        {
                            continue;
                        }

                        Interlocked.Increment(ref _activeDumpWorkers);
                        try
                        {
                            TryDumpCandidate(snapshot);
                        }
                        finally
                        {
                            Interlocked.Decrement(ref _activeDumpWorkers);
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _log?.Invoke($"packer detector worker failed: {ex.Message}");
                }
            }
        }

        private void TryDumpCandidate(CandidateSnapshot snapshot)
        {
            if (Volatile.Read(ref _dumpCount) >= MaxDumpCount)
            {
                return;
            }

            if (!TryOpenProcessForQuery((uint)_targetPid, out IntPtr processHandle, out string openError))
            {
                _log?.Invoke($"packer probe skipped base=0x{snapshot.BaseAddress:X}: {openError}");
                return;
            }

            try
            {
                ulong queryAddress = snapshot.ExecutionAddress != 0 ? snapshot.ExecutionAddress
                                     : snapshot.AddressHint != 0    ? snapshot.AddressHint
                                                                    : snapshot.BaseAddress;
                if (!TryQueryMemory(processHandle, queryAddress, out MemoryBasicInformation64 mbi) ||
                    !IsCommittedPrivateExecutable(mbi.State, mbi.Type, mbi.Protect) ||
                    mbi.RegionSize < MinProbeRegionSize)
                {
                    _log?.Invoke(
                        $"packer probe rejected base=0x{snapshot.BaseAddress:X}: current region is not committed private executable");
                    MarkCandidateRejected(snapshot.BaseAddress);
                    return;
                }

                ulong dumpBase = snapshot.BaseAddress != 0 ? snapshot.BaseAddress : mbi.BaseAddress;
                ulong desiredSize = Math.Max(Math.Max(snapshot.RegionSize, mbi.RegionSize), MinProbeRegionSize);
                int requestedBytes = (int)Math.Min(Math.Min(desiredSize, (ulong)MaxDumpBytes), int.MaxValue);
                if (requestedBytes < (int)MinProbeRegionSize)
                {
                    MarkCandidateRejected(snapshot.BaseAddress);
                    return;
                }

                if (!ReadProcessBytes((uint)_targetPid, dumpBase, requestedBytes, out byte[] dump,
                                      out string readError) ||
                    dump.Length < (int)MinProbeRegionSize)
                {
                    dumpBase = mbi.BaseAddress;
                    requestedBytes = (int)Math.Min(Math.Min(mbi.RegionSize, (ulong)MaxDumpBytes), int.MaxValue);
                    if (!ReadProcessBytes((uint)_targetPid, dumpBase, requestedBytes, out dump, out readError) ||
                        dump.Length < (int)MinProbeRegionSize)
                    {
                        _log?.Invoke($"packer probe read failed base=0x{snapshot.BaseAddress:X}: {readError}");
                        MarkCandidateRejected(snapshot.BaseAddress);
                        return;
                    }
                }

                IReadOnlyList<HeuristicEventView> yaraFindings = _signatures.ScanBufferForFindings(
                    dump, Math.Min(dump.Length, MaxYaraScanBytes), pageSample: true,
                    originPath: $"private+0x0 base=0x{dumpBase:X}", actorPid: (uint)_targetPid,
                    targetPid: (uint)_targetPid, source: "BlackbirdRunner", eventName: "PackerDump",
                    trigger: "private-exec-staged-executed", maxScanBytes: MaxYaraScanBytes);

                bool dumpHasPe = LooksLikePeImage(dump, dump.Length);
                bool dumpHasMarker = ContainsPackerMarker(dump, Math.Min(dump.Length, MaxYaraScanBytes));
                double dumpEntropy =
                    ComputeEntropy(dump, Math.Min(dump.Length, Math.Min(MaxYaraScanBytes, 1024 * 1024)));
                bool strong = dumpHasPe || yaraFindings.Count > 0 ||
                              (snapshot.HasDirectSyscall && dumpHasMarker && dumpEntropy >= HighEntropyThreshold);

                if (!strong)
                {
                    _log?.Invoke(
                        $"packer probe rejected base=0x{snapshot.BaseAddress:X}: no PE/YARA/packer marker after private-exec correlation");
                    MarkCandidateRejected(snapshot.BaseAddress);
                    return;
                }

                int dumpOrdinal = Interlocked.Increment(ref _dumpCount);
                string sha256 = ComputeSha256Hex(dump);
                string dumpDirectory = Path.Combine(_workspaceRoot, "packer-dumps");
                Directory.CreateDirectory(dumpDirectory);
                string stem = $"{DateTime.UtcNow:yyyyMMdd_HHmmss_fff}_pid{_targetPid}_private_{dumpBase:X}";
                string dumpPath = Path.Combine(dumpDirectory, stem + ".bin");
                string metadataPath = Path.Combine(dumpDirectory, stem + ".json");
                File.WriteAllBytes(dumpPath, dump);

                var metadata = new PackerDumpMetadata {
                    Detection = dumpHasPe ? "PACKER_UNPACKED_PRIVATE_IMAGE" : "PACKER_PRIVATE_EXEC_PAYLOAD",
                    TargetPid = _targetPid,
                    DumpOrdinal = dumpOrdinal,
                    BaseAddress = $"0x{dumpBase:X}",
                    RegionSize = $"0x{desiredSize:X}",
                    DumpBytes = dump.Length,
                    Sha256 = sha256,
                    EntropyBitsPerByte = double.IsNaN(dumpEntropy) ? null : Math.Round(dumpEntropy, 3),
                    HasPeHeader = dumpHasPe,
                    HasPackerMarker = dumpHasMarker,
                    YaraMatches = yaraFindings.Select(x => x.DetectionName)
                                      .Where(x => !string.IsNullOrWhiteSpace(x))
                                      .Distinct(StringComparer.OrdinalIgnoreCase)
                                      .ToArray(),
                    Signals = snapshot.Signals,
                    DumpPath = Path.GetRelativePath(_workspaceRoot, dumpPath)
                };
                File.WriteAllText(metadataPath, JsonSerializer.Serialize(metadata, JsonOptions));

                string evidence = BuildEvidence(metadata, snapshot, mbi);
                _store?.AppendSyntheticHeuristic(DateTime.UtcNow, _targetPid, 0, "packer-dump", metadata.Detection,
                                                 $"{metadata.Detection} dumpBytes={dump.Length} sha256={sha256}",
                                                 evidence, $"packer:{_targetPid}:{dumpBase:X}:{sha256}",
                                                 payloadBytes: dump);

                MarkCandidateDumped(snapshot.BaseAddress);
                _log?.Invoke(
                    $"packer dump captured pid={_targetPid} base=0x{dumpBase:X} bytes={dump.Length} sha256={sha256}");
            }
            finally
            {
                CloseHandle(processHandle);
            }
        }

        private static string BuildEvidence(PackerDumpMetadata metadata, CandidateSnapshot snapshot,
                                            MemoryBasicInformation64 mbi)
        {
            string yara = metadata.YaraMatches.Length == 0 ? "none" : string.Join(",", metadata.YaraMatches.Take(12));
            string signals = snapshot.Signals.Length == 0 ? "none" : string.Join("; ", snapshot.Signals.Take(12));
            return "strict private-exec packer correlation: " +
                   $"pid={metadata.TargetPid} region=private+0x0 base={metadata.BaseAddress} size={metadata.RegionSize} " +
                   $"protect=0x{mbi.Protect:X8} dumpBytes={metadata.DumpBytes} sha256={metadata.Sha256} " +
                   $"pe={metadata.HasPeHeader.ToString(CultureInfo.InvariantCulture).ToLowerInvariant()} " +
                   $"marker={metadata.HasPackerMarker.ToString(CultureInfo.InvariantCulture).ToLowerInvariant()} " +
                   $"entropy={metadata.EntropyBitsPerByte?.ToString(CultureInfo.InvariantCulture) ?? "n/a"} " +
                   $"yara={yara} signals={signals} dump={metadata.DumpPath}";
        }

        private static bool ReadProcessBytes(uint processId, ulong baseAddress, int requestedBytes, out byte[] data,
                                             out string error)
        {
            data = Array.Empty<byte>();
            error = string.Empty;

            if (!BkctlDeviceSession.TryOpen(out BkctlDeviceSession control, out error, ensureClientProtocol: true))
            {
                return false;
            }

            using (control)
            {
                byte[] buffer = new byte[requestedBytes];
                int total = 0;
                while (total < requestedBytes)
                {
                    uint chunk = (uint)Math.Min(ReadChunkBytes, requestedBytes - total);
                    byte[] chunkBuffer = new byte[chunk];
                    bool ok = BlackbirdNative.QueryProcessMemory(control.Handle, processId, baseAddress + (ulong)total,
                                                                 chunk, chunkBuffer, chunk, out uint bytesRead);
                    if (!ok || bytesRead == 0)
                    {
                        if (total > 0)
                        {
                            break;
                        }

                        int err = Marshal.GetLastWin32Error();
                        error = $"QueryProcessMemory failed err={err}";
                        return false;
                    }

                    int copy = (int)Math.Min(bytesRead, chunk);
                    Buffer.BlockCopy(chunkBuffer, 0, buffer, total, copy);
                    total += copy;
                    if (copy < chunk)
                    {
                        break;
                    }
                }

                if (total <= 0)
                {
                    error = "QueryProcessMemory returned no bytes";
                    return false;
                }

                data = total == buffer.Length ? buffer : buffer[..total];
                return true;
            }
        }

        private void MarkCandidateRejected(ulong baseAddress)
        {
            lock (_sync)
            {
                if (_candidates.TryGetValue(baseAddress, out CandidateRegion? candidate))
                {
                    candidate.DumpQueued = false;
                    candidate.DumpRejected = true;
                }
            }
        }

        private void MarkCandidateDumped(ulong baseAddress)
        {
            lock (_sync)
            {
                if (_candidates.TryGetValue(baseAddress, out CandidateRegion? candidate))
                {
                    candidate.Dumped = true;
                    candidate.DumpQueued = false;
                }
            }
        }

        private static bool TryOpenProcessForQuery(uint pid, out IntPtr handle, out string error)
        {
            error = string.Empty;
            handle = OpenProcess(ProcessQueryInformation | ProcessVmRead, false, pid);
            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            {
                int err = Marshal.GetLastWin32Error();
                error = $"OpenProcess failed err={err}";
                return false;
            }

            return true;
        }

        private static bool TryQueryMemory(IntPtr processHandle, ulong address, out MemoryBasicInformation64 mbi)
        {
            UIntPtr result = VirtualQueryEx(processHandle, new IntPtr(unchecked((long)address)), out mbi,
                                            new UIntPtr((uint)Marshal.SizeOf<MemoryBasicInformation64>()));
            return result != UIntPtr.Zero;
        }

        private bool TouchesTarget(params uint[] pids)
        {
            uint target = (uint)_targetPid;
            return pids.Any(pid => pid == target);
        }

        private bool IsTarget(uint pid) => pid == (uint)_targetPid;

        private static bool HasAnyTrait(uint value, uint mask) => (value & mask) != 0;

        private static bool ContainsAny(string? value, params string[] needles)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            return needles.Any(needle => value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static ulong NormalizeRegionKey(ulong address) => address == 0 ? 0 : address & PageMask;

        private static ulong NormalizeRegionSize(ulong observed, ulong current)
        {
            ulong value = observed == 0 ? current : observed;
            value = Math.Max(value, DefaultProbeRegionSize);
            return Math.Min(value, MaxCandidateRegionSize);
        }

        private static bool IsCommittedPrivateExecutable(uint state, uint type, uint protect)
        {
            return state == MemCommit && type == MemPrivate && IsExecutableProtection(protect);
        }

        private static bool IsExecutableProtection(uint protect)
        {
            uint baseProtect = protect & 0xFFu;
            return baseProtect is PageExecute or PageExecuteRead or PageExecuteReadWrite or PageExecuteWriteCopy;
        }

        private static bool IsDirectSyscallHandleSignal(uint handleFlags)
        {
            const uint syscallMismatch = 0x00002000;
            const uint stackSpoofSuspect = 0x00000800;
            return (handleFlags & (syscallMismatch | stackSpoofSuspect)) != 0;
        }

        private static bool LooksLikePeImage(byte[]? data, int length)
        {
            if (data == null || length < 0x40 || data.Length < 0x40)
            {
                return false;
            }

            int capped = Math.Min(length, data.Length);
            if (data[0] != 0x4D || data[1] != 0x5A)
            {
                return false;
            }

            int peOffset = BitConverter.ToInt32(data, 0x3C);
            return peOffset > 0 && peOffset <= capped - 4 && peOffset <= 0x1000 && data[peOffset] == 0x50 &&
                   data[peOffset + 1] == 0x45 && data[peOffset + 2] == 0x00 && data[peOffset + 3] == 0x00;
        }

        private static bool ContainsPackerMarker(byte[]? data, int length)
        {
            if (data == null || length <= 0)
            {
                return false;
            }

            ReadOnlySpan<byte> bytes = data.AsSpan(0, Math.Min(length, data.Length));
            return ContainsAscii(bytes, "UPX!") || ContainsAscii(bytes, "UPX0") || ContainsAscii(bytes, "UPX1") ||
                   ContainsAscii(bytes, "VMProtect") || ContainsAscii(bytes, "Themida") ||
                   ContainsAscii(bytes, "WinLicense") || ContainsAscii(bytes, "Enigma Protector") ||
                   ContainsAscii(bytes, "MPRESS");
        }

        private static bool ContainsAscii(ReadOnlySpan<byte> haystack, string needle)
        {
            if (haystack.Length == 0 || string.IsNullOrEmpty(needle))
            {
                return false;
            }

            byte[] pattern = System.Text.Encoding.ASCII.GetBytes(needle);
            return haystack.IndexOf(pattern) >= 0;
        }

        private static double ComputeEntropy(byte[]? data, int length)
        {
            if (data == null || length <= 0)
            {
                return double.NaN;
            }

            int size = Math.Min(length, data.Length);
            if (size <= 0)
            {
                return double.NaN;
            }

            Span<int> histogram = stackalloc int[256];
            for (int i = 0; i < size; i += 1)
            {
                histogram[data[i]] += 1;
            }

            double entropy = 0;
            for (int i = 0; i < histogram.Length; i += 1)
            {
                int count = histogram[i];
                if (count == 0)
                {
                    continue;
                }

                double p = count / (double)size;
                entropy -= p * Math.Log(p, 2);
            }

            return entropy;
        }

        private static string ComputeSha256Hex(byte[] bytes)
        {
            byte[] hash = SHA256.HashData(bytes);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            try
            {
                Flush(TimeSpan.FromSeconds(2));
            }
            catch
            {
            }

            _cts.Cancel();
            _dumpSignal.Release();
            try
            {
                _worker.Wait(1500);
            }
            catch
            {
            }

            _signatures.Dispose();
            _cts.Dispose();
            _dumpSignal.Dispose();
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
                                                 uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern UIntPtr VirtualQueryEx(IntPtr processHandle, IntPtr address,
                                                     out MemoryBasicInformation64 buffer, UIntPtr length);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [StructLayout(LayoutKind.Sequential)]
        private struct MemoryBasicInformation64
        {
            public ulong BaseAddress;
            public ulong AllocationBase;
            public uint AllocationProtect;
            public ushort PartitionId;
            public ulong RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        private sealed class CandidateRegion
        {
            private readonly List<string> _signals = new();

            public CandidateRegion(ulong baseAddress) => BaseAddress = baseAddress;

            public ulong BaseAddress { get; }
            public ulong RegionSize { get; set; }
            public ulong AddressHint { get; set; }
            public ulong ExecutionAddress { get; set; }
            public uint ActorPid { get; set; }
            public uint TargetPid { get; set; }
            public uint LastProtect { get; set; }
            public uint LastState { get; set; }
            public uint LastType { get; set; }
            public bool HasPrivateExecutable { get; set; }
            public bool HasMemoryStaging { get; set; }
            public bool HasExecution { get; set; }
            public bool HasHighSignalExecution { get; set; }
            public bool HasDirectSyscall { get; set; }
            public bool HasPeHeaderSample { get; set; }
            public bool HasPackerMarkerSample { get; set; }
            public int HighEntropySampleCount { get; set; }
            public int EntropyFlipCount { get; set; }
            public double LastEntropy { get; set; } = double.NaN;
            public DateTime FirstSeenUtc { get; set; }
            public DateTime LastSeenUtc { get; set; }
            public bool DumpQueued { get; set; }
            public bool Dumped { get; set; }
            public bool DumpRejected { get; set; }

            public void AddSignal(string signal)
            {
                if (string.IsNullOrWhiteSpace(signal))
                {
                    return;
                }

                string trimmed = signal.Trim();
                if (_signals.Any(x => string.Equals(x, trimmed, StringComparison.OrdinalIgnoreCase)))
                {
                    return;
                }

                if (_signals.Count < 24)
                {
                    _signals.Add(trimmed);
                }
            }

            public CandidateSnapshot ToSnapshot() => new(BaseAddress, RegionSize, AddressHint, ExecutionAddress,
                                                         ActorPid, TargetPid, LastProtect, LastState, LastType,
                                                         HasPrivateExecutable, HasMemoryStaging, HasExecution,
                                                         HasHighSignalExecution, HasDirectSyscall, HasPeHeaderSample,
                                                         HasPackerMarkerSample, HighEntropySampleCount,
                                                         EntropyFlipCount, _signals.ToArray());
        }

        private sealed record CandidateSnapshot(ulong BaseAddress, ulong RegionSize, ulong AddressHint,
                                                ulong ExecutionAddress, uint ActorPid, uint TargetPid, uint LastProtect,
                                                uint LastState, uint LastType, bool HasPrivateExecutable,
                                                bool HasMemoryStaging, bool HasExecution, bool HasHighSignalExecution,
                                                bool HasDirectSyscall, bool HasPeHeaderSample,
                                                bool HasPackerMarkerSample, int HighEntropySampleCount,
                                                int EntropyFlipCount, string[] Signals);

        private sealed class PackerDumpMetadata
        {
            public string Detection { get; init; } = string.Empty;
            public int TargetPid { get; init; }
            public int DumpOrdinal { get; init; }
            public string BaseAddress { get; init; } = string.Empty;
            public string RegionSize { get; init; } = string.Empty;
            public int DumpBytes { get; init; }
            public string Sha256 { get; init; } = string.Empty;
            public double? EntropyBitsPerByte { get; init; }
            public bool HasPeHeader { get; init; }
            public bool HasPackerMarker { get; init; }
            public string[] YaraMatches { get; init; } = Array.Empty<string>();
            public string[] Signals { get; init; } = Array.Empty<string>();
            public string DumpPath { get; init; } = string.Empty;
        }
    }
}
