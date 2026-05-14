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
            if (!CanPromoteDetections())
            {
                return;
            }

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
    }
}
