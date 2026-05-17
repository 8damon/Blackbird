using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private const uint StackEvidenceMemCommit = 0x00001000u;
        private const uint StackEvidenceMemPrivate = 0x00020000u;
        private const uint StackEvidencePageExecute = 0x10u;
        private const uint StackEvidencePageExecuteRead = 0x20u;
        private const uint StackEvidencePageExecuteReadWrite = 0x40u;
        private const uint StackEvidencePageExecuteWriteCopy = 0x80u;

        private static readonly TimeSpan StackModuleCacheTtl = TimeSpan.FromSeconds(2);
        private readonly object _stackEvidenceCacheLock = new();
        private readonly Dictionary<uint, StackModuleCacheEntry> _stackModuleCacheByPid = new();
        private readonly Dictionary<StackFrameMemoryCacheKey, StackFrameMemoryInfo> _stackFrameMemoryCache = new();

        private bool TryBuildRequiredStackEvidence(BrokerEtwEventView view, string detectionContext,
                                                   out string evidence, out string rejectReason)
        {
            evidence = string.Empty;
            rejectReason = string.Empty;

            if (!RequiresResolvedTargetStackEvidence(view, detectionContext))
            {
                return true;
            }

            uint pid = ResolveStackEvidencePid(view);
            if (pid == 0 || pid > int.MaxValue)
            {
                rejectReason = "stackReject=no-process-pid";
                return false;
            }

            ulong[] stack = view.Stack ?? Array.Empty<ulong>();
            int declaredCount = view.StackCount > int.MaxValue ? int.MaxValue : (int)view.StackCount;
            int cappedCount = Math.Min(declaredCount, BlackbirdNative.MaxIpcStackFrames);
            int count = Math.Min(cappedCount, stack.Length);
            if (declaredCount <= 0 || count <= 0)
            {
                if (TryBuildRequiredFallbackStackEvidence(view, pid, out evidence, out rejectReason))
                {
                    return true;
                }

                rejectReason = "stackReject=no-captured-frames";
                return false;
            }

            if (count < declaredCount && declaredCount <= BlackbirdNative.MaxIpcStackFrames)
            {
                rejectReason = $"stackReject=truncated-stack declared={declaredCount} captured={count}";
                return false;
            }

            Dictionary<string, string> fields = BuildHookFieldMap(view);
            StackModuleRange[] moduleRanges = GetStackModuleRanges(pid);
            IntPtr processHandle = IntPtr.Zero;
            bool closeProcessHandle = false;
            StackFrameEvidence? targetFrame = null;
            StackFrameEvidence? privateFrame = null;
            int resolvedFrames = 0;
            int nonZeroFrames = 0;

            try
            {
                for (int i = 0; i < count; i += 1)
                {
                    ulong ip = stack[i];
                    if (ip == 0)
                    {
                        continue;
                    }

                    nonZeroFrames += 1;
                    StackFrameEvidence frame = ResolveStackFrameEvidence(view, pid, ip, i, fields, moduleRanges,
                                                                         ref processHandle, ref closeProcessHandle);
                    if (!frame.Resolved)
                    {
                        rejectReason = $"stackReject=unresolved-frame frame={i} ip=0x{ip:X} detail={frame.Detail}";
                        return false;
                    }

                    resolvedFrames += 1;
                    if (targetFrame == null && frame.IsTargetImage)
                    {
                        targetFrame = frame;
                    }
                    if (privateFrame == null && frame.IsExecutablePrivateMemory)
                    {
                        privateFrame = frame;
                    }
                }
            }
            finally
            {
                if (closeProcessHandle)
                {
                    Kernel32Native.CloseHandle(processHandle);
                }
            }

            if (nonZeroFrames == 0)
            {
                rejectReason = "stackReject=no-nonzero-frames";
                return false;
            }

            StackFrameEvidence? decisiveFrame = targetFrame ?? privateFrame;
            if (decisiveFrame == null)
            {
                rejectReason =
                    $"stackReject=no-target-or-private-frame frames={nonZeroFrames} resolved={resolvedFrames}";
                return false;
            }

            string kind = decisiveFrame.IsTargetImage ? "target-frame" : "private-exec";
            string pathText = string.IsNullOrWhiteSpace(decisiveFrame.Path)
                                  ? string.Empty
                                  : $" path={FormatEvidenceValue(decisiveFrame.Path)}";
            string regionText = decisiveFrame.MemoryInfo.HasValue
                                    ? $" regionBase=0x{decisiveFrame.MemoryInfo.Value.BaseAddress:X} regionSize=0x{decisiveFrame.MemoryInfo.Value.RegionSize:X} protect=0x{decisiveFrame.MemoryInfo.Value.Protect:X8}"
                                    : string.Empty;
            evidence =
                $"stackEvidence={kind} frame={decisiveFrame.Index} ip=0x{decisiveFrame.Address:X} module={decisiveFrame.Module}{pathText}{regionText} frames={nonZeroFrames} resolved={resolvedFrames}";
            return true;
        }

        private bool TryBuildRequiredFallbackStackEvidence(BrokerEtwEventView view, uint pid, out string evidence,
                                                           out string rejectReason)
        {
            evidence = string.Empty;
            rejectReason = string.Empty;

            uint tid = view.EventThreadId != 0 ? view.EventThreadId : view.ThreadId;
            if (pid == 0 || tid == 0 || pid > int.MaxValue || tid > int.MaxValue)
            {
                rejectReason = "stackReject=no-fallback-thread";
                return false;
            }

            DateTime observedUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc;
            ThreadStackSessionSnapshot? snapshot =
                GetThreadStackHistory(unchecked((int)pid), unchecked((int)tid), string.Empty)
                    .Where(x => x.Frames.Count > 0)
                    .OrderBy(x => Math.Abs((x.CapturedAtUtc - observedUtc).TotalMilliseconds))
                    .FirstOrDefault();
            if (snapshot == null)
            {
                rejectReason = "stackReject=no-fallback-stack";
                return false;
            }

            double deltaMs = Math.Abs((snapshot.CapturedAtUtc - observedUtc).TotalMilliseconds);
            if (deltaMs > 5000)
            {
                rejectReason = $"stackReject=stale-fallback-stack deltaMs={deltaMs:0}";
                return false;
            }

            Dictionary<string, string> fields = BuildHookFieldMap(view);
            StackModuleRange[] moduleRanges = GetStackModuleRanges(pid);
            IntPtr processHandle = IntPtr.Zero;
            bool closeProcessHandle = false;
            StackFrameEvidence? targetFrame = null;
            StackFrameEvidence? privateFrame = null;
            int resolvedFrames = 0;
            int inspectedFrames = 0;

            try
            {
                int maxFrames = Math.Min(snapshot.Frames.Count, BlackbirdNative.MaxIpcStackFrames);
                for (int i = 0; i < maxFrames; i += 1)
                {
                    ulong ip = snapshot.Frames[i].InstructionPointerRaw;
                    if (ip == 0)
                    {
                        continue;
                    }

                    inspectedFrames += 1;
                    StackFrameEvidence frame = ResolveStackFrameEvidence(view, pid, ip, i, fields, moduleRanges,
                                                                         ref processHandle, ref closeProcessHandle);
                    if (!frame.Resolved)
                    {
                        continue;
                    }

                    resolvedFrames += 1;
                    if (targetFrame == null && frame.IsTargetImage)
                    {
                        targetFrame = frame;
                    }
                    if (privateFrame == null && frame.IsExecutablePrivateMemory)
                    {
                        privateFrame = frame;
                    }
                }
            }
            finally
            {
                if (closeProcessHandle)
                {
                    Kernel32Native.CloseHandle(processHandle);
                }
            }

            if (inspectedFrames == 0)
            {
                rejectReason = "stackReject=fallback-no-nonzero-frames";
                return false;
            }

            StackFrameEvidence? decisiveFrame = targetFrame ?? privateFrame;
            if (decisiveFrame == null)
            {
                rejectReason =
                    $"stackReject=fallback-no-target-or-private-frame frames={inspectedFrames} resolved={resolvedFrames}";
                return false;
            }

            string kind = decisiveFrame.IsTargetImage ? "target-frame" : "private-exec";
            string pathText = string.IsNullOrWhiteSpace(decisiveFrame.Path)
                                  ? string.Empty
                                  : $" path={FormatEvidenceValue(decisiveFrame.Path)}";
            string regionText = decisiveFrame.MemoryInfo.HasValue
                                    ? $" regionBase=0x{decisiveFrame.MemoryInfo.Value.BaseAddress:X} regionSize=0x{decisiveFrame.MemoryInfo.Value.RegionSize:X} protect=0x{decisiveFrame.MemoryInfo.Value.Protect:X8}"
                                    : string.Empty;
            evidence =
                $"stackEvidence=fallback-{kind} frame={decisiveFrame.Index} ip=0x{decisiveFrame.Address:X} module={decisiveFrame.Module}{pathText}{regionText} frames={inspectedFrames} resolved={resolvedFrames} deltaMs={deltaMs:0}";
            return true;
        }

        private static bool RequiresResolvedTargetStackEvidence(BrokerEtwEventView view, string detectionContext)
        {
            string detection = detectionContext ?? string.Empty;
            if (IsHookTamperDetection(view) ||
                detection.Contains("HOOK_TAMPER", StringComparison.OrdinalIgnoreCase) ||
                detection.Contains("AMSI_PATCH", StringComparison.OrdinalIgnoreCase) ||
                detection.Contains("ETW_PATCH", StringComparison.OrdinalIgnoreCase) ||
                detection.Contains("INTEGRITY_OK", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return view.Family == BlackbirdNative.IpcEtwFamilyUserHook ||
                   view.SourceId == BlackbirdNative.IpcEtwSourceUserHook ||
                   EventDetailFormatting.IsUsermodeSensorTelemetry(view) ||
                   EventDetailFormatting.IsApiGraphCandidate(view);
        }

        private static uint ResolveStackEvidencePid(BrokerEtwEventView view) =>
            view.ProcessPid != 0 ? view.ProcessPid :
            view.ActorPid != 0 ? view.ActorPid :
            view.EventProcessId;

        private StackFrameEvidence ResolveStackFrameEvidence(BrokerEtwEventView view, uint pid, ulong address,
                                                             int index,
                                                             IReadOnlyDictionary<string, string> fields,
                                                             IReadOnlyList<StackModuleRange> moduleRanges,
                                                             ref IntPtr processHandle,
                                                             ref bool closeProcessHandle)
        {
            string symbol = ReadTrimmedField(fields, $"stack{index}Symbol");
            string path = ReadTrimmedField(fields, $"stack{index}Path");
            string module = ModuleNameFromPath(path);
            StackModuleRange? range = FindStackModule(moduleRanges, address);
            if (range is StackModuleRange moduleRange)
            {
                path = moduleRange.Path;
                module = moduleRange.Name;
            }
            else if (module.Equals("unknown", StringComparison.OrdinalIgnoreCase))
            {
                module = ExtractModuleFromSymbol(symbol);
            }

            bool hasModule = !string.IsNullOrWhiteSpace(module) &&
                             !module.Equals("unknown", StringComparison.OrdinalIgnoreCase);
            if (hasModule)
            {
                bool target = IsTargetStackModule(view, pid, path, module,
                                                  range?.IsMainModule == true || range?.PathMatchesMainModule == true);
                return new StackFrameEvidence(index, address, module, path, symbol, true, target, false, null,
                                              range.HasValue ? "module-range" : "symbol");
            }

            if (TryClassifyStackFrameMemory(pid, address, ref processHandle, ref closeProcessHandle,
                                            out StackFrameMemoryInfo memoryInfo))
            {
                if (memoryInfo.IsCommittedPrivate && memoryInfo.IsExecutable)
                {
                    return new StackFrameEvidence(index, address, "private-memory", string.Empty, symbol, true, false,
                                                  true, memoryInfo, "private-exec");
                }

                return new StackFrameEvidence(index, address, "unknown", string.Empty, symbol, false, false, false,
                                              memoryInfo,
                                              $"memory type=0x{memoryInfo.Type:X8} state=0x{memoryInfo.State:X8} protect=0x{memoryInfo.Protect:X8}");
            }

            return new StackFrameEvidence(index, address, "unknown", string.Empty, symbol, false, false, false, null,
                                          "virtual-query-failed");
        }

        private bool IsTargetStackModule(BrokerEtwEventView view, uint pid, string path, string module,
                                         bool isMainModule)
        {
            ProcessSessionTab? session = _currentSession;
            string subjectPath = session != null && session.Pid == unchecked((int)pid)
                                     ? session.AnalysisSubjectPath
                                     : string.Empty;
            string subjectName = SafeFileName(subjectPath);
            if (!string.IsNullOrWhiteSpace(subjectPath))
            {
                if (PathsEqual(path, subjectPath))
                {
                    return true;
                }

                return string.IsNullOrWhiteSpace(path) && !string.IsNullOrWhiteSpace(subjectName) &&
                       module.Equals(subjectName, StringComparison.OrdinalIgnoreCase);
            }

            if (isMainModule)
            {
                return true;
            }

            string processMainPath = GetStackProcessMainModulePath(pid);
            if (!string.IsNullOrWhiteSpace(processMainPath) && PathsEqual(path, processMainPath))
            {
                return true;
            }

            if (string.IsNullOrWhiteSpace(processMainPath) && !IsSystemOrInternalStackModule(path, module))
            {
                return true;
            }

            return false;
        }

        private StackModuleRange[] GetStackModuleRanges(uint pid)
        {
            DateTime now = DateTime.UtcNow;
            lock (_stackEvidenceCacheLock)
            {
                if (_stackModuleCacheByPid.TryGetValue(pid, out StackModuleCacheEntry? cached) &&
                    now - cached.UpdatedUtc <= StackModuleCacheTtl)
                {
                    return cached.Modules;
                }
            }

            StackModuleRange[] modules = BuildStackModuleRanges(pid);
            lock (_stackEvidenceCacheLock)
            {
                if (_stackModuleCacheByPid.Count > 64)
                {
                    _stackModuleCacheByPid.Clear();
                }

                _stackModuleCacheByPid[pid] = new StackModuleCacheEntry(now, modules);
            }

            return modules;
        }

        private string GetStackProcessMainModulePath(uint pid)
        {
            StackModuleRange[] modules = GetStackModuleRanges(pid);
            for (int i = 0; i < modules.Length; i += 1)
            {
                if (modules[i].IsMainModule)
                {
                    return modules[i].Path;
                }
            }

            return string.Empty;
        }

        private static StackModuleRange[] BuildStackModuleRanges(uint pid)
        {
            try
            {
                using Process process = Process.GetProcessById(unchecked((int)pid));
                string mainPath = string.Empty;
                try
                {
                    mainPath = process.MainModule?.FileName ?? string.Empty;
                }
                catch (Win32Exception)
                {
                }
                catch (InvalidOperationException)
                {
                }

                var modules = new List<StackModuleRange>();
                foreach (ProcessModule module in process.Modules)
                {
                    ulong start = unchecked((ulong)module.BaseAddress.ToInt64());
                    ulong size = module.ModuleMemorySize <= 0 ? 0UL : unchecked((ulong)module.ModuleMemorySize);
                    ulong end = size == 0 || start + size < start ? ulong.MaxValue : start + size;
                    string path = module.FileName ?? string.Empty;
                    string name = !string.IsNullOrWhiteSpace(module.ModuleName)
                                      ? module.ModuleName
                                      : EventDetailFormatting.ModuleNameFromPath(path);
                    bool pathMatchesMain = PathsEqual(path, mainPath);
                    modules.Add(new StackModuleRange(start, end, name, path, pathMatchesMain, pathMatchesMain));
                }

                modules.Sort(static (left, right) => left.Start.CompareTo(right.Start));
                return modules.ToArray();
            }
            catch
            {
                return Array.Empty<StackModuleRange>();
            }
        }

        private static StackModuleRange? FindStackModule(IReadOnlyList<StackModuleRange> modules, ulong address)
        {
            for (int i = 0; i < modules.Count; i += 1)
            {
                StackModuleRange module = modules[i];
                if (address >= module.Start && address < module.End)
                {
                    return module;
                }
            }

            return null;
        }

        private bool TryClassifyStackFrameMemory(uint pid, ulong address, ref IntPtr processHandle,
                                                 ref bool closeProcessHandle, out StackFrameMemoryInfo info)
        {
            var key = new StackFrameMemoryCacheKey(pid, address & ~0xFFFUL);
            lock (_stackEvidenceCacheLock)
            {
                if (_stackFrameMemoryCache.TryGetValue(key, out info))
                {
                    return info.QuerySucceeded;
                }
            }

            if (processHandle == IntPtr.Zero)
            {
                processHandle = Kernel32Native.OpenProcess(ProcessQueryLimitedInformation | ProcessVmRead, false, pid);
                closeProcessHandle = processHandle != IntPtr.Zero;
            }

            if (processHandle == IntPtr.Zero)
            {
                info = StackFrameMemoryInfo.Failed;
                CacheStackFrameMemoryInfo(key, info);
                return false;
            }

            UIntPtr result = Kernel32Native.VirtualQueryEx(
                processHandle, new IntPtr(unchecked((long)address)), out Kernel32Native.MemoryBasicInformation64 mbi,
                new UIntPtr((uint)Marshal.SizeOf<Kernel32Native.MemoryBasicInformation64>()));
            if (result == UIntPtr.Zero)
            {
                info = StackFrameMemoryInfo.Failed;
                CacheStackFrameMemoryInfo(key, info);
                return false;
            }

            info = new StackFrameMemoryInfo(true, mbi.BaseAddress, mbi.AllocationBase, mbi.RegionSize, mbi.State,
                                            mbi.Protect, mbi.Type);
            CacheStackFrameMemoryInfo(key, info);
            return true;
        }

        private void CacheStackFrameMemoryInfo(StackFrameMemoryCacheKey key, StackFrameMemoryInfo info)
        {
            lock (_stackEvidenceCacheLock)
            {
                if (_stackFrameMemoryCache.Count > 8192)
                {
                    _stackFrameMemoryCache.Clear();
                }

                _stackFrameMemoryCache[key] = info;
            }
        }

        private static bool IsSystemOrInternalStackModule(string path, string module)
        {
            if (EventDetailFormatting.IsBlackbirdInternalPath(path) ||
                EventDetailFormatting.IsBlackbirdInternalModule(module))
            {
                return true;
            }

            string normalizedPath = (path ?? string.Empty).Trim().Replace('/', '\\');
            string windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
            if (!string.IsNullOrWhiteSpace(normalizedPath) && !string.IsNullOrWhiteSpace(windir) &&
                normalizedPath.StartsWith(windir + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            string name = EventDetailFormatting.ModuleNameFromPath(module);
            return name.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("win32u.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("kernel32.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("kernelbase.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("user32.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("gdi32.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("gdi32full.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("advapi32.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("sechost.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("rpcrt4.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("combase.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("ole32.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("oleaut32.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("ws2_32.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("ucrtbase.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("vcruntime140.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("msvcrt.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("clr.dll", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("coreclr.dll", StringComparison.OrdinalIgnoreCase);
        }

        private static bool PathsEqual(string? left, string? right)
        {
            string normalizedLeft = NormalizePathForStackCompare(left);
            string normalizedRight = NormalizePathForStackCompare(right);
            return normalizedLeft.Length != 0 && normalizedRight.Length != 0 &&
                   string.Equals(normalizedLeft, normalizedRight, StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizePathForStackCompare(string? path)
        {
            string value = (path ?? string.Empty).Trim();
            if (value.Length == 0)
            {
                return string.Empty;
            }

            try
            {
                return Path.GetFullPath(value).TrimEnd('\\');
            }
            catch
            {
                return value.Replace('/', '\\').TrimEnd('\\');
            }
        }

        private static string SafeFileName(string? path)
        {
            string value = (path ?? string.Empty).Trim();
            if (value.Length == 0)
            {
                return string.Empty;
            }

            try
            {
                return Path.GetFileName(value);
            }
            catch
            {
                return EventDetailFormatting.ModuleNameFromPath(value);
            }
        }

        private static string FormatEvidenceValue(string value)
        {
            string text = (value ?? string.Empty).Trim();
            if (text.Length == 0)
            {
                return "<none>";
            }

            return text.IndexOf(' ') >= 0 ? $"\"{text.Replace("\"", "'")}\"" : text;
        }

        private readonly record struct StackFrameMemoryCacheKey(uint Pid, ulong PageAddress);

        private readonly record struct StackModuleRange(ulong Start, ulong End, string Name, string Path,
                                                        bool IsMainModule, bool PathMatchesMainModule);

        private sealed record StackModuleCacheEntry(DateTime UpdatedUtc, StackModuleRange[] Modules);

        private readonly record struct StackFrameMemoryInfo(bool QuerySucceeded, ulong BaseAddress,
                                                            ulong AllocationBase, ulong RegionSize, uint State,
                                                            uint Protect, uint Type)
        {
            internal static StackFrameMemoryInfo Failed => new(false, 0, 0, 0, 0, 0, 0);

            internal bool IsCommittedPrivate => QuerySucceeded && State == StackEvidenceMemCommit &&
                                                (Type & StackEvidenceMemPrivate) != 0;

            internal bool IsExecutable
            {
                get {
                    uint baseProtect = Protect & 0xFFu;
                    return baseProtect == StackEvidencePageExecute ||
                           baseProtect == StackEvidencePageExecuteRead ||
                           baseProtect == StackEvidencePageExecuteReadWrite ||
                           baseProtect == StackEvidencePageExecuteWriteCopy;
                }
            }
        }

        private sealed record StackFrameEvidence(int Index, ulong Address, string Module, string Path, string Symbol,
                                                 bool Resolved, bool IsTargetImage,
                                                 bool IsExecutablePrivateMemory,
                                                 StackFrameMemoryInfo? MemoryInfo, string Detail);
    }
}
