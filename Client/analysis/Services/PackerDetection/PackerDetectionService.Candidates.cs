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
