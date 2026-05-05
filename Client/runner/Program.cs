using BlackbirdInterface;
using BlackbirdInterface.Capture;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace BlackbirdRunner
{
    internal static class Program
    {
        private static async Task<int> Main(string[] args)
        {
            if (!RunnerOptions.TryParse(args, out RunnerOptions options, out string error))
            {
                Console.Error.WriteLine(error);
                Console.Error.WriteLine(
                    "Usage: BlackbirdRunner.exe --headless-capture --job-id <id> --job-dir <dir> --scan-seconds <seconds> [--integrity-level default|medium|system]");
                return 2;
            }

            var runner = new CaptureRunner(options);
            return await runner.RunAsync().ConfigureAwait(false);
        }
    }

    internal sealed class CaptureRunner
    {
        private readonly RunnerOptions _options;
        private readonly string _samplePath;
        private readonly string _sampleNamePath;
        private readonly string _requestPath;
        private readonly string _progressPath;
        private readonly string _resultPath;
        private readonly string _workspacePath;
        private readonly string _archiveBuildRoot;
        private readonly string _runDirectory;
        private readonly string _runnerLogPath;
        private readonly object _logLock = new();
        private int _ioctlEvents;
        private int _etwEvents;

        internal CaptureRunner(RunnerOptions options)
        {
            _options = options;
            _samplePath = Path.Combine(options.JobDirectory, "sample.bin");
            _sampleNamePath = Path.Combine(options.JobDirectory, "sample.name.txt");
            _requestPath = Path.Combine(options.JobDirectory, "capture-request.json");
            _progressPath = Path.Combine(options.JobDirectory, "progress.json");
            _resultPath = Path.Combine(options.JobDirectory, "result.bkcap");
            _workspacePath = Path.Combine(options.JobDirectory, "capture-workspace");
            _archiveBuildRoot = ResolveArchiveBuildRoot(options.JobDirectory, options.JobId);
            _runDirectory = Path.Combine(options.JobDirectory, "run");
            _runnerLogPath = Path.Combine(options.JobDirectory, "runner.log");
        }

        internal async Task<int> RunAsync()
        {
            Directory.CreateDirectory(_options.JobDirectory);
            WriteLog(
                $"runner start job={_options.JobId} pid={Environment.ProcessId} scanSeconds={_options.ScanSeconds} integrity={_options.IntegrityLevel}");
            WriteProgress("initializing", 16, "runner process initialized");

            try
            {
                if (!Kernel32Native.EnableDebugPrivilege(out int privilegeError))
                {
                    WriteLog($"SeDebugPrivilege enable failed err={privilegeError}");
                    WriteProgress("warning", 18, $"SeDebugPrivilege unavailable err={privilegeError}",
                                  lastError: privilegeError);
                }

                if (!File.Exists(_samplePath))
                {
                    throw new FileNotFoundException("Uploaded sample was not found.", _samplePath);
                }

                string displayName = ReadDisplayName();
                PeKind peKind = PeImageInspector.ReadKind(_samplePath);
                WriteLog($"sample name={displayName} kind={peKind}");

                if (File.Exists(_resultPath))
                {
                    File.Delete(_resultPath);
                }
                if (Directory.Exists(_workspacePath))
                {
                    Directory.Delete(_workspacePath, recursive: true);
                }
                if (Directory.Exists(_runDirectory))
                {
                    Directory.Delete(_runDirectory, recursive: true);
                }
                if (Directory.Exists(_archiveBuildRoot))
                {
                    Directory.Delete(_archiveBuildRoot, recursive: true);
                }
                Directory.CreateDirectory(_runDirectory);

                LaunchPlan plan = BuildLaunchPlan(displayName, peKind);
                if (!RuntimeConfigService.TryApply(plan.Profile,
                                                   out BlackbirdNative.BkRuntimeConfigResponse runtimeConfig,
                                                   out string runtimeError))
                {
                    WriteLog($"runtime config arm failed: {runtimeError}");
                    WriteProgress("failed", 100, $"failed to arm Blackbird runtime config: {runtimeError}",
                                  terminalState: 2, lastError: 2);
                    return 2;
                }

                WriteLog("runtime config armed " +
                         $"effective={RuntimeConfigService.DescribeFlags(runtimeConfig.EffectiveFlags)} " +
                         $"persistent={RuntimeConfigService.DescribeFlags(runtimeConfig.PersistentFlags)} " +
                         $"mode={RuntimeConfigService.DescribeMode(runtimeConfig.Mode)}");
                WriteProgress("launching", 22, $"launching {plan.KindLabel}");
                if (!AnalysisLaunchService.TryLaunchWithUsermodeHooksAndPrepareSession(
                        plan.ImagePath,
                        useEarlyBirdApc: true,
                        plan.Profile,
                        out AnalysisLaunchResult? launch,
                        out string launchError) || launch == null)
                {
                    WriteLog($"launch failed: {launchError}");
                    WriteProgress("failed", 100, launchError, terminalState: 2, lastError: 2);
                    return 2;
                }

                using BlackbirdBackendSession session = launch.Session;
                WriteLog($"target launched pid={launch.ProcessId} image={plan.ImagePath}");
                if (RuntimeConfigService.TryRead(out BlackbirdNative.BkRuntimeConfigResponse activeConfig,
                                                 out string activeConfigError))
                {
                    WriteLog("runtime config after session " +
                             $"effective={RuntimeConfigService.DescribeFlags(activeConfig.EffectiveFlags)} " +
                             $"runtime={RuntimeConfigService.DescribeFlags(activeConfig.RuntimeFlags)} " +
                             $"persistent={RuntimeConfigService.DescribeFlags(activeConfig.PersistentFlags)} " +
                             $"mode={RuntimeConfigService.DescribeMode(activeConfig.Mode)}");
                }
                else
                {
                    WriteLog($"runtime config after session read failed: {activeConfigError}");
                }
                WriteProgress("capturing", 34, $"target launched pid={launch.ProcessId}", targetPid: launch.ProcessId);

                using BlackbirdCaptureLiveStore store =
                    CaptureArchiveStorage.OpenLiveStore(_workspacePath, launch.ProcessId, displayName);
                using PackerDetectionService packerDetector = new(launch.ProcessId, _workspacePath, store, WriteLog);
                var projection = new CaptureProjectionEngine(launch.ProcessId, _options.JobId, "BlackbirdRunner");
                var performanceSampler = new PerformanceSampler();
                performanceSampler.SetTargetPid(launch.ProcessId);
                performanceSampler.SampleArrived += (_, sample) => projection.ObservePerformance(sample);
                performanceSampler.Start();
                DateTime captureStartedUtc = DateTime.UtcNow;
                projection.CaptureStaticProcessSnapshot(plan.ImagePath, displayName, peKind.ToString(), plan.Profile);

                session.IoctlEvent += record =>
                {
                    Interlocked.Increment(ref _ioctlEvents);
                    DateTime nowUtc = DateTime.UtcNow;
                    store.AppendIoctl(nowUtc, record);
                    projection.ObserveIoctl(record, nowUtc);
                    packerDetector.ObserveIoctl(record);
                };
                session.EtwEvent += etw =>
                {
                    Interlocked.Increment(ref _etwEvents);
                    BrokerEtwEventView mapped = BrokerEtwEventMapper.FromNative(etw);
                    store.AppendEtw(mapped);
                    projection.ObserveEtw(mapped);
                    packerDetector.ObserveEtw(mapped);
                };
                session.Status += line =>
                {
                    WriteLog($"session: {line}");
                    projection.ObserveStatus(line);
                };

                int exitCode;
                try
                {
                    exitCode = await WaitForTargetAsync(launch.ProcessId, _options.ScanSeconds, projection)
                                   .ConfigureAwait(false);
                }
                finally
                {
                    performanceSampler.Stop();
                }

                session.Dispose();
                WriteProgress("finalizing", 88,
                              $"finalizing capture ioctl={_ioctlEvents} etw={_etwEvents} targetExit={exitCode}",
                              targetPid: launch.ProcessId);

                packerDetector.Flush(TimeSpan.FromSeconds(4));
                projection.WaitForPendingStackCaptures(TimeSpan.FromSeconds(2));
                store.Flush();
                CaptureLoadedWorkspace loaded = CaptureArchiveStorage.LoadWorkspace(_workspacePath);
                string runSummary =
                    projection.FinalizeRun(exitCode, _ioctlEvents, _etwEvents, DateTime.UtcNow - captureStartedUtc);
                WriteLog($"capture summary: {runSummary}");
                SessionFileTab? capturedTab = loaded.Archive.Tabs.FirstOrDefault(x => x.Pid == launch.ProcessId) ??
                                              loaded.Archive.Tabs.FirstOrDefault();
                if (capturedTab != null)
                {
                    if (loaded.TabPaths.TryGetValue(capturedTab.Pid, out string? tabPath))
                    {
                        capturedTab.CaptureStorePath = tabPath;
                    }
                    projection.ApplyToTab(capturedTab, plan.Profile, plan.ImagePath, displayName, exitCode);
                    LogTabStats("tab-before-final-archive", capturedTab);
                }
                LogWorkspaceStats("workspace-before-final-archive", _workspacePath);
                LogArchiveBuildRoot("archive-build-root", _archiveBuildRoot);
                CaptureArchiveStorage.SaveWorkspace(_resultPath, loaded.Archive, _archiveBuildRoot);

                FileInfo result = new(_resultPath);
                if (!result.Exists || result.Length == 0)
                {
                    throw new InvalidDataException("Capture archive was not created.");
                }

                string sha256 = ComputeSha256Hex(_resultPath);
                WriteLog($"artifact ready path={_resultPath} bytes={result.Length} sha256={sha256}");
                WriteProgress("artifact-ready", 100,
                              $"capture artifact finalized ioctl={_ioctlEvents} etw={_etwEvents}", terminalState: 1,
                              targetPid: launch.ProcessId, artifactReady: true, artifactSize: result.Length,
                              artifactSha256: sha256);
                return 0;
            }
            catch (Exception ex)
            {
                WriteLog($"fatal: {ex}");
                WriteProgress("failed", 100, ex.Message, terminalState: 2, lastError: 1);
                return 1;
            }
            finally
            {
                TryDeleteSampleMaterial();
                TryDeleteDirectory(_archiveBuildRoot);
            }
        }

        private LaunchPlan BuildLaunchPlan(string displayName, PeKind peKind)
        {
            LaunchOptions launchOptions = ReadLaunchOptions();
            LaunchIntegrityLevel integrityLevel = ResolveIntegrityLevel(launchOptions);
            bool isDll = peKind == PeKind.Dll || displayName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase);
            if (isDll)
            {
                string dllPath = Path.Combine(_runDirectory, EnsureExtension(SanitizeFileName(displayName), ".dll"));
                File.Copy(_samplePath, dllPath, overwrite: true);

                string dllHostPath = AnalysisLaunchService.ResolveDllHostPath();
                if (!File.Exists(dllHostPath))
                {
                    throw new FileNotFoundException("BlackbirdDllHost.exe is required for DLL capture.", dllHostPath);
                }

                var profile =
                    new LaunchProfile { TargetKind = LaunchTargetKind.Dll,
                                        AnalysisSubjectPath = dllPath,
                                        AnalysisHostPath = dllHostPath,
                                        WorkingDirectory = ResolveWorkingDirectory(launchOptions.WorkingDirectory),
                                        DllMode = ResolveDllMode(launchOptions.DllMode),
                                        DllExportName = launchOptions.DllExportName ?? string.Empty,
                                        DllExportOrdinal = launchOptions.DllExportOrdinal,
                                        DllArgument = launchOptions.DllArgument ?? string.Empty,
                                        DllLoadFlags = launchOptions.DllLoadFlags,
                                        DllFreeOnExit = launchOptions.DllFreeOnExit,
                                        DllInstallDisable = launchOptions.DllInstallDisable,
                                        DllWaitMilliseconds =
                                            checked((uint)Math.Min(uint.MaxValue, _options.ScanSeconds * 1000L)),
                                        IntegrityLevel = integrityLevel };
                ApplyCommonLaunchOptions(profile, launchOptions);
                profile.CommandLineArguments = AnalysisLaunchService.BuildDllHostCommandLineArguments(profile);
                return new LaunchPlan(dllHostPath, profile, "dll");
            }

            string exePath = Path.Combine(_runDirectory, EnsureExtension(SanitizeFileName(displayName), ".exe"));
            File.Copy(_samplePath, exePath, overwrite: true);
            var exeProfile =
                new LaunchProfile { TargetKind = LaunchTargetKind.Executable,
                                    WorkingDirectory = ResolveWorkingDirectory(launchOptions.WorkingDirectory),
                                    CommandLineArguments = launchOptions.CommandLineArguments ?? string.Empty,
                                    IntegrityLevel = integrityLevel };
            ApplyCommonLaunchOptions(exeProfile, launchOptions);
            return new LaunchPlan(exePath, exeProfile, "process");
        }

        private LaunchOptions ReadLaunchOptions()
        {
            if (!File.Exists(_requestPath))
            {
                return new LaunchOptions();
            }

            using JsonDocument document = JsonDocument.Parse(File.ReadAllText(_requestPath));
            if (!document.RootElement.TryGetProperty("launchOptions", out JsonElement optionsElement))
            {
                return new LaunchOptions();
            }

            return JsonSerializer.Deserialize<LaunchOptions>(
                       optionsElement.GetRawText(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ??
                   new LaunchOptions();
        }

        private string ResolveWorkingDirectory(string? workingDirectory)
        {
            string value = (workingDirectory ?? string.Empty).Trim();
            if (value.Length == 0)
            {
                return _runDirectory;
            }

            return Path.IsPathRooted(value) ? value : Path.GetFullPath(Path.Combine(_runDirectory, value));
        }

        private LaunchIntegrityLevel ResolveIntegrityLevel(LaunchOptions launchOptions)
        {
            return RunnerOptions.TryParseIntegrityLevel(launchOptions.IntegrityLevel, out LaunchIntegrityLevel parsed)
                       ? parsed
                       : _options.IntegrityLevel;
        }

        private static void ApplyCommonLaunchOptions(LaunchProfile profile, LaunchOptions launchOptions)
        {
            profile.EnvironmentOverridesText = launchOptions.EnvironmentOverrides ?? string.Empty;
            profile.ParentProcessId = launchOptions.ParentProcessId;
            profile.InheritHandles = launchOptions.InheritHandles;
            profile.ConcealHookPresence = launchOptions.ConcealHookPresence;
            profile.EnableKernelHooks = launchOptions.EnableKernelHooks;
            profile.EnableAntiVirtualizationMasking = launchOptions.EnableAntiVirtualizationMasking;
            profile.EnableControllerConcealment = launchOptions.EnableControllerConcealment;
            profile.EnableInterfaceProtectedAccess = launchOptions.EnableInterfaceProtectedAccess;
            profile.EnableControllerProtectedAccess = launchOptions.EnableControllerProtectedAccess;
            profile.Priority = ResolvePriority(launchOptions.Priority);
            if (LaunchProfile.TryParseAffinityMask(launchOptions.AffinityMask, out ulong affinityMask))
            {
                profile.AffinityMask = affinityMask;
            }
        }

        private static LaunchPriorityPreset ResolvePriority(string? value)
        {
            return (value ?? string.Empty)
                .Trim()
                .ToLowerInvariant() switch { "idle" => LaunchPriorityPreset.Idle,
                                             "below-normal" or "belownormal" => LaunchPriorityPreset.BelowNormal,
                                             "normal" => LaunchPriorityPreset.Normal,
                                             "above-normal" or "abovenormal" => LaunchPriorityPreset.AboveNormal,
                                             "high" => LaunchPriorityPreset.High,
                                             "realtime" or "real-time" => LaunchPriorityPreset.Realtime,
                                             _ => LaunchPriorityPreset.Inherit };
        }

        private static DllLaunchMode ResolveDllMode(string? value)
        {
            return (value ?? string.Empty)
                .Trim()
                .ToLowerInvariant() switch { "export" => DllLaunchMode.Export,
                                             "rundll" => DllLaunchMode.Rundll,
                                             "register" => DllLaunchMode.Register,
                                             "unregister" => DllLaunchMode.Unregister,
                                             "install" => DllLaunchMode.Install,
                                             _ => DllLaunchMode.Load };
        }

        private async Task<int> WaitForTargetAsync(int pid, uint scanSeconds, CaptureProjectionEngine projection)
        {
            DateTime captureStartUtc = DateTime.UtcNow;
            TimeSpan scanLimit = TimeSpan.FromSeconds(Math.Max(1u, scanSeconds));
            TimeSpan childDiscoveryGrace = TimeSpan.FromSeconds(3);
            int exitCode = 0;
            bool rootExited = false;
            DateTime? noLiveTrackedSinceUtc = null;
            while (true)
            {
                DateTime nowUtc = DateTime.UtcNow;
                TimeSpan elapsed = nowUtc - captureStartUtc;
                _ = projection.RefreshTrackedProcessTree("toolhelp-descendant");

                int[] trackedPids = projection.SnapshotTrackedPids().Append(pid).Where(x => x > 0).Distinct().ToArray();
                List<int> livePids = new();

                foreach (int trackedPid in trackedPids)
                {
                    using Process? process = TryGetProcess(trackedPid);
                    if (process == null)
                    {
                        if (trackedPid == pid)
                        {
                            rootExited = true;
                        }
                        continue;
                    }

                    if (process.HasExited)
                    {
                        if (trackedPid == pid)
                        {
                            rootExited = true;
                            exitCode = process.ExitCode;
                        }
                        continue;
                    }

                    livePids.Add(trackedPid);
                }

                if (livePids.Count == 0)
                {
                    noLiveTrackedSinceUtc ??= nowUtc;
                    if (rootExited && nowUtc - noLiveTrackedSinceUtc >= childDiscoveryGrace)
                    {
                        return exitCode;
                    }
                }
                else
                {
                    noLiveTrackedSinceUtc = null;
                }

                if (elapsed >= scanLimit)
                {
                    break;
                }

                double elapsedSeconds = Math.Max(0, elapsed.TotalSeconds);
                int progress = Math.Min(84, 34 + (int)(elapsedSeconds * 50 / Math.Max(1, scanSeconds)));
                WriteProgress(
                    "capturing", progress,
                    $"capturing root={pid} live=[{string.Join(",", livePids.Take(12))}] tracked={trackedPids.Length} ioctl={Volatile.Read(ref _ioctlEvents)} etw={Volatile.Read(ref _etwEvents)}",
                    targetPid: pid);
                TimeSpan remaining = scanLimit - elapsed;
                TimeSpan delay = remaining < TimeSpan.FromSeconds(1) ? remaining : TimeSpan.FromSeconds(1);
                if (delay > TimeSpan.Zero)
                {
                    await Task.Delay(delay).ConfigureAwait(false);
                }
            }

            int[] terminatePids = projection.SnapshotTrackedPids().Append(pid).Where(x => x > 0).Distinct().ToArray();
            WriteLog($"scan limit reached; terminating tracked pids={string.Join(",", terminatePids)}");
            foreach (int terminatePid in terminatePids)
            {
                try
                {
                    using Process? process = TryGetProcess(terminatePid);
                    if (process != null && !process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                    }
                }
                catch (Exception ex)
                {
                    WriteLog($"target termination failed pid={terminatePid}: {ex.Message}");
                }
            }

            return exitCode;
        }

        private static Process? TryGetProcess(int pid)
        {
            try
            {
                return Process.GetProcessById(pid);
            }
            catch (ArgumentException)
            {
                return null;
            }
            catch (InvalidOperationException)
            {
                return null;
            }
        }

        private void WriteProgress(string phase, int progressPercent, string detail, int terminalState = 0,
                                   int lastError = 0, int targetPid = 0, bool artifactReady = false,
                                   long artifactSize = 0, string artifactSha256 = "")
        {
            var payload = new { schema = "BK.capture.progress.v1",
                                jobId = _options.JobId,
                                phase,
                                progressPercent = Math.Clamp(progressPercent, 0, 100),
                                terminalState,
                                targetPid,
                                runnerPid = Environment.ProcessId,
                                scanSeconds = _options.ScanSeconds,
                                artifactReady,
                                artifactSize,
                                artifactSha256,
                                lastError,
                                timestampUtc = DateTime.UtcNow.ToString("O"),
                                detail };

            string tempPath = _progressPath + ".tmp";
            string json = JsonSerializer.Serialize(payload);
            File.WriteAllText(tempPath, json);
            if (File.Exists(_progressPath))
            {
                File.Replace(tempPath, _progressPath, destinationBackupFileName: null, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(tempPath, _progressPath);
            }
        }

        private void WriteLog(string line)
        {
            string text = $"[{DateTime.UtcNow:O}] {line}{Environment.NewLine}";
            lock (_logLock)
            {
                File.AppendAllText(_runnerLogPath, text);
            }
            Console.WriteLine(line);
        }

        private string ReadDisplayName()
        {
            try
            {
                if (File.Exists(_sampleNamePath))
                {
                    string value = File.ReadAllText(_sampleNamePath).Trim();
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        return value;
                    }
                }
            }
            catch
            {
            }

            return "sample.exe";
        }

        private static string SanitizeFileName(string value)
        {
            string name = Path.GetFileName(value);
            if (string.IsNullOrWhiteSpace(name))
            {
                return "sample";
            }

            foreach (char invalid in Path.GetInvalidFileNameChars())
            {
                name = name.Replace(invalid, '_');
            }

            return name;
        }

        private static string EnsureExtension(string fileName, string extension)
        {
            if (string.IsNullOrWhiteSpace(Path.GetExtension(fileName)))
            {
                return fileName + extension;
            }

            return fileName;
        }

        private void TryDeleteSampleMaterial()
        {
            TryDeleteFile(_samplePath);
            TryDeleteFile(_sampleNamePath);
            TryDeleteFile(_requestPath);
            TryDeleteDirectory(_runDirectory);
            TryDeleteDirectory(_workspacePath);
        }

        private void TryDeleteFile(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch (Exception ex)
            {
                WriteLog($"cleanup file failed path={path} error={ex.Message}");
            }
        }

        private void TryDeleteDirectory(string path)
        {
            try
            {
                if (Directory.Exists(path))
                {
                    Directory.Delete(path, recursive: true);
                }
            }
            catch (Exception ex)
            {
                WriteLog($"cleanup directory failed path={path} error={ex.Message}");
            }
        }

        private static string ComputeSha256Hex(string path)
        {
            using FileStream stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }

        private static string ResolveArchiveBuildRoot(string jobDirectory, string jobId)
        {
            string? configuredRoot = Environment.GetEnvironmentVariable("BLACKBIRD_ARCHIVE_BUILD_ROOT");
            if (string.IsNullOrWhiteSpace(configuredRoot))
            {
                return Path.Combine(jobDirectory, "archive-build");
            }

            return Path.Combine(configuredRoot, SanitizePathToken(jobId));
        }

        private static string SanitizePathToken(string value)
        {
            string sanitized = new(value.Where(ch => char.IsLetterOrDigit(ch) || ch == '-' || ch == '_').ToArray());
            return string.IsNullOrWhiteSpace(sanitized) ? Guid.NewGuid().ToString("N") : sanitized;
        }

        private void LogArchiveBuildRoot(string label, string rootPath)
        {
            try
            {
                string fullRoot = Path.GetFullPath(rootPath);
                string? driveRoot = Path.GetPathRoot(fullRoot);
                long availableBytes = 0;
                if (!string.IsNullOrWhiteSpace(driveRoot))
                {
                    availableBytes = new DriveInfo(driveRoot).AvailableFreeSpace;
                }

                WriteLog($"{label}: path={fullRoot} availableBytes={availableBytes}");
            }
            catch (Exception ex)
            {
                WriteLog($"{label}: stats failed: {ex.Message}");
            }
        }

        private void LogWorkspaceStats(string label, string workspacePath)
        {
            try
            {
                string tabRoot = Path.Combine(workspacePath, "tabs");
                string[] segmentFiles = Directory.Exists(tabRoot)
                                            ? Directory.GetFiles(tabRoot, "*.bbseg", SearchOption.AllDirectories)
                                            : Array.Empty<string>();
                string[] blobFiles = Directory.Exists(tabRoot)
                                         ? Directory.GetFiles(tabRoot, "*.bbblob", SearchOption.AllDirectories)
                                         : Array.Empty<string>();
                string[] sectionFiles = Directory.Exists(tabRoot)
                                            ? Directory.GetFiles(tabRoot, "*.bbsec", SearchOption.AllDirectories)
                                            : Array.Empty<string>();
                long indexBytes =
                    Directory.Exists(tabRoot)
                        ? Directory.GetFiles(tabRoot, "index.sqlite", SearchOption.AllDirectories).Sum(SafeFileLength)
                        : 0;
                long materializedBytes =
                    Directory.Exists(tabRoot)
                        ? Directory.GetFiles(tabRoot, "materialized.json", SearchOption.AllDirectories)
                              .Sum(SafeFileLength)
                        : 0;
                WriteLog($"{label}: segments={segmentFiles.Length} segmentBytes={segmentFiles.Sum(SafeFileLength)} " +
                         $"blobs={blobFiles.Length} blobBytes={blobFiles.Sum(SafeFileLength)} " +
                         $"sections={sectionFiles.Length} sectionBytes={sectionFiles.Sum(SafeFileLength)} " +
                         $"indexBytes={indexBytes} materializedBytes={materializedBytes}");
            }
            catch (Exception ex)
            {
                WriteLog($"{label}: stats failed: {ex.Message}");
            }
        }

        private void LogTabStats(string label, SessionFileTab tab)
        {
            WriteLog(
                $"{label}: pid={tab.Pid} events={tab.Events.Count} " +
                $"perf={tab.PerformanceHistory.Count} memoryAttribution={tab.MemoryRegionAttributionHistory.Count} " +
                $"threadLifecycle={tab.ThreadLifecycleHistory.Count} etwGroups={tab.EtwGroups.Count} " +
                $"heuristics={tab.HeuristicsGroups.Count} filesystem={tab.FilesystemGroups.Count} " +
                $"registry={tab.RegistryGroups.Count} relations={tab.ProcessRelationsGroups.Count} " +
                $"apiGraph={tab.ApiGraphRows.Count} extended={tab.ExtendedActivityRows.Count} " +
                $"threadStacks={tab.ThreadStackHistories.Count}");
        }

        private static long SafeFileLength(string path)
        {
            try
            {
                return new FileInfo(path).Length;
            }
            catch
            {
                return 0;
            }
        }

        private sealed record LaunchPlan(string ImagePath, LaunchProfile Profile, string KindLabel);
    }

    internal sealed class LaunchOptions
    {
        public string CommandLineArguments { get; init; } = string.Empty;
        public string WorkingDirectory { get; init; } = string.Empty;
        public string EnvironmentOverrides { get; init; } = string.Empty;
        public string IntegrityLevel { get; init; } = string.Empty;
        public string Priority { get; init; } = string.Empty;
        public string AffinityMask { get; init; } = string.Empty;
        public uint ParentProcessId { get; init; }
        public bool InheritHandles { get; init; }
        public bool ConcealHookPresence { get; init; }
        public bool EnableKernelHooks { get; init; } = true;
        public bool EnableAntiVirtualizationMasking { get; init; }
        public bool EnableControllerConcealment { get; init; }
        public bool EnableInterfaceProtectedAccess { get; init; }
        public bool EnableControllerProtectedAccess { get; init; } = true;
        public string DllMode { get; init; } = string.Empty;
        public string DllExportName { get; init; } = string.Empty;
        public uint DllExportOrdinal { get; init; }
        public string DllArgument { get; init; } = string.Empty;
        public uint DllLoadFlags { get; init; }
        public bool DllFreeOnExit { get; init; }
        public bool DllInstallDisable { get; init; }
    }

    internal sealed class RunnerOptions
    {
        public string JobId { get; init; } = string.Empty;
        public string JobDirectory { get; init; } = string.Empty;
        public uint ScanSeconds { get; init; }
        public LaunchIntegrityLevel IntegrityLevel { get; init; } = LaunchIntegrityLevel.Default;

        internal static bool TryParse(string[] args, out RunnerOptions options, out string error)
        {
            options = new RunnerOptions();
            error = string.Empty;

            bool headlessCapture = false;
            string jobId = string.Empty;
            string jobDirectory = string.Empty;
            uint scanSeconds = 300;
            LaunchIntegrityLevel integrityLevel = LaunchIntegrityLevel.Default;

            for (int i = 0; i < args.Length; i += 1)
            {
                string arg = args[i];
                if (arg.Equals("--headless-capture", StringComparison.OrdinalIgnoreCase))
                {
                    headlessCapture = true;
                    continue;
                }

                if (arg.Equals("--job-id", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    jobId = args[++i];
                    continue;
                }

                if (arg.Equals("--job-dir", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    jobDirectory = args[++i];
                    continue;
                }

                if (arg.Equals("--scan-seconds", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    if (!uint.TryParse(args[++i], out scanSeconds))
                    {
                        error = "--scan-seconds must be an unsigned integer.";
                        return false;
                    }
                    continue;
                }

                if (arg.Equals("--integrity-level", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    if (!TryParseIntegrityLevel(args[++i], out integrityLevel))
                    {
                        error = "--integrity-level must be default, untrusted, low, medium, high, or system.";
                        return false;
                    }
                    continue;
                }

                error = $"Unknown or incomplete argument: {arg}";
                return false;
            }

            if (!headlessCapture)
            {
                error = "--headless-capture is required.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(jobId))
            {
                error = "--job-id is required.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(jobDirectory))
            {
                error = "--job-dir is required.";
                return false;
            }

            options =
                new RunnerOptions { JobId = jobId, JobDirectory = Path.GetFullPath(jobDirectory),
                                    ScanSeconds = Math.Clamp(scanSeconds, 5u, 3600u), IntegrityLevel = integrityLevel };
            return true;
        }

        internal static bool TryParseIntegrityLevel(string? value, out LaunchIntegrityLevel level)
        {
            level = LaunchIntegrityLevel.Default;
            switch ((value ?? string.Empty).Trim().ToLowerInvariant())
            {
            case "":
            case "default":
            case "asinvoker":
            case "as-invoker":
                level = LaunchIntegrityLevel.Default;
                return true;
            case "untrusted":
                level = LaunchIntegrityLevel.Untrusted;
                return true;
            case "low":
                level = LaunchIntegrityLevel.Low;
                return true;
            case "normal":
            case "user":
            case "medium":
                level = LaunchIntegrityLevel.Medium;
                return true;
            case "high":
            case "elevated":
                level = LaunchIntegrityLevel.High;
                return true;
            case "system":
            case "localsystem":
            case "local-system":
                level = LaunchIntegrityLevel.System;
                return true;
            default:
                if (!uint.TryParse(value, out uint raw) || raw > (uint)LaunchIntegrityLevel.System)
                {
                    return false;
                }

                level = (LaunchIntegrityLevel)raw;
                return true;
            }
        }
    }

    internal enum PeKind
    {
        Unknown,
        Executable,
        Dll
    }

    internal static class PeImageInspector
    {
        private const ushort ImageFileDll = 0x2000;

        internal static PeKind ReadKind(string path)
        {
            Span<byte> header = stackalloc byte[4096];
            using FileStream stream = File.OpenRead(path);
            int read = stream.Read(header);
            if (read < 0x40 || header[0] != (byte)'M' || header[1] != (byte)'Z')
            {
                return PeKind.Unknown;
            }

            int peOffset = BitConverter.ToInt32(header.Slice(0x3C, 4));
            if (peOffset < 0 || peOffset + 24 > read)
            {
                return PeKind.Unknown;
            }

            if (header[peOffset] != (byte)'P' || header[peOffset + 1] != (byte)'E' || header[peOffset + 2] != 0 ||
                header[peOffset + 3] != 0)
            {
                return PeKind.Unknown;
            }

            ushort characteristics = BitConverter.ToUInt16(header.Slice(peOffset + 22, 2));
            return (characteristics & ImageFileDll) != 0 ? PeKind.Dll : PeKind.Executable;
        }
    }
}
