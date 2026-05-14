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
    internal sealed partial class PackerDetectionService : IDisposable
    {
        private const uint MemCommit = 0x1000;
        private const uint MemPrivate = 0x20000;
        private const uint PageExecute = 0x10;
        private const uint PageExecuteRead = 0x20;
        private const uint PageExecuteReadWrite = 0x40;
        private const uint PageExecuteWriteCopy = 0x80;
        private const uint ProcessQueryInformation = 0x0400;
        private const uint ProcessQueryLimitedInformation = 0x1000;
        private const uint ProcessVmRead = 0x0010;
        private const uint ImageScnCntCode = 0x00000020;
        private const uint ImageScnMemExecute = 0x20000000;
        private const ulong PageMask = 0xFFFFFFFFFFFFF000UL;
        private const ulong DefaultProbeRegionSize = 0x10000;
        private const ulong MaxCandidateRegionSize = 64UL * 1024UL * 1024UL;
        private const ulong MinProbeRegionSize = 0x4000;
        private const int MaxDumpCount = 4;
        private const int MaxDumpBytes = 8 * 1024 * 1024;
        private const int MaxYaraScanBytes = 2 * 1024 * 1024;
        private const int ReadChunkBytes = 0x4000;
        private const int MaxPeHeaderBytes = 1024 * 1024;
        private const int MaxImageSectionCompareBytes = 256 * 1024;
        private const int MinImageSectionCompareBytes = 0x1000;
        private const int MaxStringSectionScanBytes = 512 * 1024;
        private const int MaxStringTotalScanBytes = 4 * 1024 * 1024;
        private const int MaxExtractedStringsPerImage = 8192;
        private const int MaxStringEvidenceSamples = 24;
        private const int MinExtractedStringChars = 5;
        private const int MaxExtractedStringChars = 128;
        private const int MinStringSectionScanBytes = 0x100;
        private const double EarlyCodeChangedRatioThreshold = 0.18;
        private const double StrongCodeChangedRatioThreshold = 0.45;
        private const double EarlyCodeEntropyDeltaThreshold = 0.45;
        private const double HighEntropyThreshold = 7.15;
        private static readonly string[] OwnToolStringNeedles = { "SR71",
                                                                  "sr71.dll",
                                                                  "BlackbirdUsermodeIntercept",
                                                                  "BlackbirdController",
                                                                  "BlackbirdInterface",
                                                                  "BlackbirdRunner",
                                                                  "J58.dll",
                                                                  "\\UserMode\\hook\\",
                                                                  "/UserMode/hook/" };
        private static readonly JsonSerializerOptions JsonOptions =
            new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };

        private readonly int _targetPid;
        private readonly string _workspaceRoot;
        private readonly BlackbirdCaptureLiveStore? _store;
        private readonly Action<string>? _log;
        private readonly Action<IReadOnlyList<HeuristicEventView>>? _publishFindings;
        private readonly SignatureIntelService _signatures;
        private readonly ConcurrentQueue<ulong> _dumpQueue = new();
        private readonly SemaphoreSlim _dumpSignal = new(0);
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _worker;
        private readonly object _sync = new();
        private readonly Dictionary<ulong, CandidateRegion> _candidates = new();
        private CaptureExecutionPhaseState _executionPhase = CaptureExecutionPhaseState.ActiveDefault;
        private int _activeDumpWorkers;
        private int _dumpCount;
        private int _initialImageScanQueued;
        private int _entrypointFindingPublished;
        private int _earlyCodeFindingPublished;
        private int _processDumpCaptured;
        private bool _disposed;

        internal PackerDetectionService(int targetPid, string workspaceRoot, BlackbirdCaptureLiveStore? store,
                                        Action<string>? log,
                                        Action<IReadOnlyList<HeuristicEventView>>? publishFindings = null)
        {
            _targetPid = targetPid;
            _workspaceRoot = Path.GetFullPath(workspaceRoot);
            _store = store;
            _log = log;
            _publishFindings = publishFindings;
            _signatures = new SignatureIntelService(
                _ =>
                {},
                message => _log?.Invoke(message));
            _signatures.Configure(
                new SignatureIntelOptions(Enabled: true, MemoryScan: true, PageScan: true, HashScan: false));
            _worker = Task.Run(WorkerLoopAsync);
        }

        internal void SetExecutionPhase(CaptureExecutionPhaseState state)
        {
            lock (_sync)
            {
                _executionPhase = state;
                if (state.Phase == CaptureExecutionPhase.PreResume)
                {
                    _candidates.Clear();
                }
            }
        }
    }
}
