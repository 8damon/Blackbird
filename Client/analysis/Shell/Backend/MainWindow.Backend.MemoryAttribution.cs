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
using System.Windows.Shapes;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private bool TryBuildMemoryAction(string apiName, BrokerEtwEventView view,
                                          IReadOnlyDictionary<string, string> fields, out string action,
                                          out string detail)
        {
            action = string.Empty;
            detail = string.Empty;
            DateTime now = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc;

            if (apiName.Equals("NtAllocateVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                ulong baseAddress = FirstU64(fields, "base", "c0", "a1");
                ulong regionSize = FirstU64(fields, "size", "c1", "a3");
                ulong allocationType = FirstU64(fields, "allocType", "c2", "a4");
                uint protect = (uint)FirstU64(fields, "protect", "c3", "a5");
                ulong page = baseAddress & ~0xFFFUL;
                if (page != 0)
                {
                    ApiMemoryPageSignal state = GetOrCreateApiMemoryPageSignal(page);
                    if (protect != 0)
                    {
                        state.Protect = protect;
                        state.LastProtectChangeUtc = now;
                    }
                }

                string protectLabel = DescribeMemoryProtect(protect);
                (string contextActionSuffix, string contextDetail) =
                    DescribeMemoryRegionContext(view, baseAddress, regionSize);
                action = $"Allocates 0x{regionSize:X} bytes at 0x{baseAddress:X} ({protectLabel}){contextActionSuffix}";
                detail = $"Action: memory.alloc\n" + $"API: {apiName}\n" + $"Base: 0x{baseAddress:X}\n" +
                         $"Size: 0x{regionSize:X}\n" +
                         $"AllocType: 0x{allocationType:X} ({DescribeMemoryAllocationType((uint)allocationType)})\n" +
                         $"Protect: 0x{protect:X} ({protectLabel})\n" + contextDetail.TrimEnd();
                return true;
            }

            if (apiName.Equals("NtProtectVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                ulong baseAddress = FirstU64(fields, "base", "c0", "a1");
                ulong regionSize = FirstU64(fields, "size", "c1", "a2");
                uint newProtect = (uint)FirstU64(fields, "newProtect", "c2", "a3");
                ulong page = baseAddress & ~0xFFFUL;
                ApiMemoryPageSignal state = GetOrCreateApiMemoryPageSignal(page);

                bool protectChanged = state.Protect != 0 && newProtect != 0 && state.Protect != newProtect;
                bool rapidFlip = false;
                if (protectChanged)
                {
                    state.ProtectFlipCount += 1;
                    rapidFlip = state.LastProtectChangeUtc != default &&
                                (now - state.LastProtectChangeUtc).TotalMilliseconds <= 900;
                }

                if (newProtect != 0)
                {
                    state.Protect = newProtect;
                }
                state.LastProtectChangeUtc = now;

                string protectLabel = DescribeMemoryProtect(newProtect);
                (string contextActionSuffix, string contextDetail) =
                    DescribeMemoryRegionContext(view, baseAddress, regionSize);
                action = $"Changes protection to {protectLabel} at 0x{baseAddress:X}{contextActionSuffix}";
                detail = $"Action: memory.protect\n" + $"API: {apiName}\n" + $"Base: 0x{baseAddress:X}\n" +
                         $"Size: 0x{regionSize:X}\n" + $"NewProtect: 0x{newProtect:X} ({protectLabel})\n" +
                         $"ProtectFlips: {state.ProtectFlipCount}\n" + $"RapidFlip: {(rapidFlip ? "yes" : "no")}\n" +
                         contextDetail.TrimEnd();
                return true;
            }

            if (apiName.Equals("NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                ulong baseAddress = FirstU64(fields, "base", "c0", "a1");
                ulong size = FirstU64(fields, "size", "c1", "a3");
                ulong page = baseAddress & ~0xFFFUL;
                ApiMemoryPageSignal state = GetOrCreateApiMemoryPageSignal(page);
                int sampleLen = (int)Math.Min(view.DeepSampleSize, (uint)(view.DeepSample?.Length ?? 0));
                double entropy = ComputeSampleEntropyBits(view.DeepSample, sampleLen);
                if (entropy < 0 && TryReadDouble(fields, out double parsedEntropy, "entropy"))
                {
                    entropy = parsedEntropy;
                }

                bool entropyChanged = !double.IsNaN(state.LastEntropyBits) && entropy >= 0 &&
                                      Math.Abs(state.LastEntropyBits - entropy) >= MemoryEntropyFlipDeltaBits;
                bool rapidEntropyFlip = false;
                if (entropyChanged)
                {
                    state.EntropyFlipCount += 1;
                    rapidEntropyFlip = state.LastEntropyChangeUtc != default &&
                                       (now - state.LastEntropyChangeUtc).TotalMilliseconds <= 900;
                }

                if (entropy >= 0)
                {
                    state.LastEntropyBits = entropy;
                    state.LastEntropyChangeUtc = now;
                }

                string entropyText = entropy >= 0 ? entropy.ToString("F2", CultureInfo.InvariantCulture) : "n/a";
                (string contextActionSuffix, string contextDetail) =
                    DescribeMemoryRegionContext(view, baseAddress, size);
                action = $"Writes 0x{size:X} bytes at 0x{baseAddress:X} (entropy {entropyText}){contextActionSuffix}";
                detail = $"Action: memory.write\n" + $"API: {apiName}\n" + $"Base: 0x{baseAddress:X}\n" +
                         $"Size: 0x{size:X}\n" + $"Entropy(bits/byte): {entropyText}\n" +
                         $"EntropyFlips: {state.EntropyFlipCount}\n" + $"ProtectFlips: {state.ProtectFlipCount}\n" +
                         $"RapidEntropyFlip: {(rapidEntropyFlip ? "yes" : "no")}\n" + $"SampleBytes: {sampleLen}\n" +
                         contextDetail.TrimEnd();
                return true;
            }

            return false;
        }

        private MemoryRegionAttributionSample? CreateMemoryRegionAttributionSample(BrokerEtwEventView view)
        {
            if (IsBlackbirdOwnEvent(view) || HasFailedHookStatus(view))
            {
                return null;
            }

            string apiName =
                string.IsNullOrWhiteSpace(view.EventName) ? view.Operation ?? string.Empty : view.EventName;
            Dictionary<string, string> fields = BuildHookFieldMap(view);
            string eventKind = string.Empty;
            string regionKind = string.Empty;
            ulong allocationBase = 0;
            ulong baseAddress = 0;
            ulong regionSize = 0;
            ulong threadStartAddress = 0;
            uint initialProtection = 0;
            uint currentProtection = 0;
            uint previousProtection = 0;
            uint protectFlipCount = 0;
            uint sampleBytes = 0;
            bool threadStartObserved = false;
            bool functionTableRegistered = false;
            ulong functionTablePointer = 0;
            double entropyBits = -1;

            switch (view.Family)
            {
            case BlackbirdNative.IpcEtwFamilyImage:
                eventKind = "ImageMap";
                regionKind = "Image";
                allocationBase = view.ImageBase;
                baseAddress = view.ImageBase;
                regionSize = view.ImageSize;
                currentProtection = view.StartRegionProtect;
                initialProtection = currentProtection;
                break;
            case BlackbirdNative.IpcEtwFamilyThread:
                eventKind = "ThreadStart";
                regionKind = view.ImageBase != 0 ? "Image" : "Unknown";
                allocationBase = view.ImageBase != 0 ? view.ImageBase : NormalizeRegionAddress(view.StartAddress);
                baseAddress = allocationBase;
                regionSize = view.ImageSize != 0 ? view.ImageSize : 1;
                currentProtection = view.StartRegionProtect;
                initialProtection = currentProtection;
                threadStartObserved = true;
                threadStartAddress = view.StartAddress;
                break;
            case BlackbirdNative.IpcEtwFamilyUserHook:
                if (string.IsNullOrWhiteSpace(apiName))
                {
                    return null;
                }

                if (apiName.Equals("NtAllocateVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                    apiName.Equals("NtAllocateVirtualMemoryEx", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "PrivateAllocate";
                    regionKind = "Private";
                    allocationBase = FirstU64(fields, "base", "c1", "a1");
                    baseAddress = allocationBase;
                    regionSize = FirstU64(fields, "size", "c3", "a3");
                    currentProtection = (uint)FirstU64(fields, "protect", "c3", "a5", "c5");
                    initialProtection = currentProtection;
                }
                else if (apiName.Equals("NtProtectVirtualMemory", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "ProtectChange";
                    allocationBase = FirstU64(fields, "base", "c1", "a1");
                    baseAddress = allocationBase;
                    regionSize = FirstU64(fields, "size", "c2", "a2");
                    currentProtection = (uint)FirstU64(fields, "newProtect", "c2", "a3", "c3");
                    previousProtection = (uint)FirstU64(fields, "oldProtect", "a4", "c4");
                    protectFlipCount = (uint)FirstU64(fields, "protectFlips");
                    sampleBytes = (uint)FirstU64(fields, "sampleBytes");
                }
                else if (apiName.Equals("NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "MemoryWrite";
                    allocationBase = FirstU64(fields, "base", "c1", "a1");
                    baseAddress = allocationBase;
                    regionSize = Math.Max(1UL, FirstU64(fields, "size", "c3", "a3"));
                    protectFlipCount = (uint)FirstU64(fields, "protectFlips");
                    sampleBytes = (uint)FirstU64(fields, "sampleBytes");
                    if (TryReadDouble(fields, out double parsedEntropy, "entropy"))
                    {
                        entropyBits = parsedEntropy;
                    }
                }
                else if (apiName.Equals("NtMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                         apiName.Equals("NtMapViewOfSectionEx", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "SectionMap";
                    regionKind = IsHookImageSection(view) ? "Image" : "Mapped";
                    allocationBase = FirstU64(fields, "baseAddress", "base", "c2", "a2");
                    baseAddress = allocationBase;
                    regionSize = FirstU64(fields, "viewSize", "size", "c3", "a4", "a6");
                    currentProtection = (uint)FirstU64(fields, "win32Protect", "a6", "c6", "c5");
                    initialProtection = currentProtection;
                }
                else if (apiName.Equals("RtlAddFunctionTable", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "FunctionTableRegister";
                    functionTablePointer = FirstU64(fields, "table", "a0");
                    allocationBase = FirstU64(fields, "baseAddress", "a2");
                    baseAddress = allocationBase;
                    regionSize = 1;
                    functionTableRegistered = true;
                }
                else if (apiName.Equals("RtlInstallFunctionTableCallback", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "FunctionTableCallback";
                    functionTablePointer = FirstU64(fields, "tableId", "a0");
                    allocationBase = FirstU64(fields, "baseAddress", "a1");
                    baseAddress = allocationBase;
                    regionSize = Math.Max(1UL, FirstU64(fields, "length", "a2"));
                    functionTableRegistered = true;
                }
                else if (apiName.Equals("RtlDeleteFunctionTable", StringComparison.OrdinalIgnoreCase))
                {
                    functionTablePointer = FirstU64(fields, "table", "a0");
                    eventKind = "FunctionTableDelete";
                    allocationBase = ResolveFunctionTableBase(view, functionTablePointer);
                    baseAddress = allocationBase;
                    regionSize = 1;
                    functionTableRegistered = false;
                }
                else
                {
                    return null;
                }
                break;
            default:
                return null;
            }

            if (sampleBytes == 0 && view.DeepSampleSize != 0)
            {
                sampleBytes = view.DeepSampleSize;
            }
            if (entropyBits < 0 && view.DeepSample.Length > 1)
            {
                int sampleLength = sampleBytes == 0 ? view.DeepSample.Length
                                                    : (int)Math.Min(sampleBytes, (uint)view.DeepSample.Length);
                entropyBits = ComputeSampleEntropyBits(view.DeepSample, sampleLength);
            }

            uint targetPid = ResolveMemoryRegionTargetPid(view);
            if (targetPid == 0)
            {
                return null;
            }

            if (allocationBase == 0)
            {
                allocationBase = NormalizeRegionAddress(baseAddress != 0 ? baseAddress : threadStartAddress);
            }
            if (baseAddress == 0)
            {
                baseAddress = allocationBase;
            }
            if (allocationBase == 0 || baseAddress == 0)
            {
                return null;
            }
            if (regionSize == 0)
            {
                if (threadStartObserved || eventKind.StartsWith("FunctionTable", StringComparison.OrdinalIgnoreCase))
                {
                    regionSize = 1;
                }
                else
                {
                    return null;
                }
            }

            ulong processStartKey = ResolveObservedProcessStartKey(targetPid, view.ProcessStartKey);
            if (view.Family == BlackbirdNative.IpcEtwFamilyThread && threadStartAddress != 0 &&
                TryResolveKnownRegionForAddress(targetPid, processStartKey, threadStartAddress, out _,
                                                out ulong existingBaseAddress, out ulong existingRegionSize,
                                                out string existingRegionKind, out uint existingProtection))
            {
                allocationBase = existingBaseAddress;
                baseAddress = existingBaseAddress;
                regionSize = existingRegionSize;
                regionKind = existingRegionKind;
                if (currentProtection == 0)
                {
                    currentProtection = existingProtection;
                }
                if (initialProtection == 0)
                {
                    initialProtection = existingProtection;
                }
            }

            string regionIdentity = BuildRegionIdentity(processStartKey, targetPid, allocationBase);
            string firstUserFrameModule = ResolveHookOriginModule(view, fields);
            bool hookFamily = view.Family == BlackbirdNative.IpcEtwFamilyUserHook;
            string frameSummary = view.Family == BlackbirdNative.IpcEtwFamilyUserHook
                                      ? BuildHookFrameSummary(view, fields)
                                      : string.Empty;

            ProcessIdentityResolver.Prime(view.ActorPid);
            ProcessIdentityResolver.Prime(targetPid);

            string executionContext = string.Empty;
            if (TryDescribeHookExecutionContext(view, fields, out string contextHeadline, out _))
            {
                executionContext = contextHeadline;
            }

            var sample = new MemoryRegionAttributionSample {
                TimestampUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc,
                ProcessStartKey = processStartKey,
                TargetPid = targetPid,
                ActorPid = view.ActorPid != 0 ? view.ActorPid : targetPid,
                ActorTid = view.ThreadId != 0 ? view.ThreadId : view.EventThreadId,
                AllocationBase = allocationBase,
                BaseAddress = baseAddress,
                RegionSize = regionSize,
                ApiName = apiName,
                EventKind = eventKind,
                RegionKind =
                    string.IsNullOrWhiteSpace(regionKind) ? InferRegionKind(view, currentProtection) : regionKind,
                RegionIdentity = regionIdentity,
                OriginPath = view.OriginPath ?? view.ImagePath ?? string.Empty,
                SourceFamily = view.Family == BlackbirdNative.IpcEtwFamilyUserHook ? "Hook"
                               : view.Family == BlackbirdNative.IpcEtwFamilyImage  ? "ImageLoad"
                               : view.Family == BlackbirdNative.IpcEtwFamilyThread ? "Thread"
                                                                                   : "ETW",
                ExecutionContext = executionContext,
                CallerOrigin = view.CallerOriginLabel,
                FirstUserFrame = view.OriginAddress,
                FirstUserFrameModule = firstUserFrameModule,
                FrameSummary = frameSummary,
                UnwindClean = hookFamily && IsHookUnwindClean(view.Flags),
                FrameChainHadGaps = hookFamily && HookFrameChainHasGaps(view.Flags),
                ObservedByKernel = hookFamily && view.SourceId == BlackbirdNative.IpcEtwSourceBlackbird,
                ObservedByUserHook = hookFamily && view.SourceId == BlackbirdNative.IpcEtwSourceUserHook,
                BlackbirdOwned = IsBlackbirdOwnEvent(view),
                CrossProcess = targetPid != 0 && view.ActorPid != 0 && targetPid != view.ActorPid,
                ImageBacked = string.Equals(regionKind, "Image", StringComparison.OrdinalIgnoreCase) ||
                              IsHookImageSection(view) || view.Family == BlackbirdNative.IpcEtwFamilyImage,
                InitialProtection = initialProtection,
                CurrentProtection = currentProtection,
                PreviousProtection = previousProtection,
                ProtectFlipCount = protectFlipCount,
                EntropyBits = entropyBits,
                SampleBytes = sampleBytes,
                ThreadStartObserved = threadStartObserved,
                ThreadId = threadStartObserved ? (view.ThreadId != 0 ? view.ThreadId : view.EventThreadId) : 0,
                ThreadStartAddress = threadStartAddress,
                FunctionTableRegistered = functionTableRegistered,
                FunctionTablePointer = functionTablePointer,
                SignatureLevel = view.SignatureLevel,
                SignatureType = view.SignatureType
            };

            return FinalizeMemoryRegionAttribution(sample);
        }

        private MemoryRegionAttributionSample FinalizeMemoryRegionAttribution(MemoryRegionAttributionSample sample)
        {
            if (string.IsNullOrWhiteSpace(sample.RegionIdentity))
            {
                return sample;
            }

            if (!_regionLifecycleByIdentity.TryGetValue(sample.RegionIdentity, out RegionLifecycleState? state))
            {
                state = new RegionLifecycleState();
                _regionLifecycleByIdentity[sample.RegionIdentity] = state;
            }

            if (state.TargetPid == 0)
            {
                state.TargetPid = sample.TargetPid;
            }
            if (state.ProcessStartKey == 0)
            {
                state.ProcessStartKey = sample.ProcessStartKey;
            }
            if (state.BaseAddress == 0)
            {
                state.BaseAddress = sample.AllocationBase != 0 ? sample.AllocationBase : sample.BaseAddress;
            }
            if (string.IsNullOrWhiteSpace(state.ExecutionContext) &&
                !string.IsNullOrWhiteSpace(sample.ExecutionContext))
            {
                state.ExecutionContext = sample.ExecutionContext;
            }
            if (state.RegionSize == 0 && sample.RegionSize != 0)
            {
                state.RegionSize = sample.RegionSize;
            }
            else if (sample.RegionSize > state.RegionSize)
            {
                state.RegionSize = sample.RegionSize;
            }
            if (string.IsNullOrWhiteSpace(state.RegionKind) && !string.IsNullOrWhiteSpace(sample.RegionKind))
            {
                state.RegionKind = sample.RegionKind;
            }
            if (!state.ObservedByKernel && sample.ObservedByKernel)
            {
                state.ObservedByKernel = true;
            }
            if (!state.ObservedByUserHook && sample.ObservedByUserHook)
            {
                state.ObservedByUserHook = true;
            }
            if (!state.BlackbirdOwned && sample.BlackbirdOwned)
            {
                state.BlackbirdOwned = true;
            }
            if (!state.CrossProcess && sample.CrossProcess)
            {
                state.CrossProcess = true;
            }
            if (!state.ImageBacked && sample.ImageBacked)
            {
                state.ImageBacked = true;
            }

            if (sample.InitialProtection != 0 && state.InitialProtection == 0)
            {
                state.InitialProtection = sample.InitialProtection;
            }

            if (sample.CurrentProtection == 0 && state.CurrentProtection != 0)
            {
                sample.CurrentProtection = state.CurrentProtection;
            }

            if (sample.InitialProtection == 0 && state.InitialProtection != 0)
            {
                sample.InitialProtection = state.InitialProtection;
            }

            uint reportedProtectFlipCount = sample.ProtectFlipCount;
            DateTime observedUtc = sample.TimestampUtc == default ? DateTime.UtcNow : sample.TimestampUtc;
            if (sample.CurrentProtection != 0)
            {
                uint previousProtection =
                    sample.PreviousProtection != 0 ? sample.PreviousProtection : state.CurrentProtection;
                if (sample.PreviousProtection == 0 && previousProtection != 0 &&
                    (sample.EventKind.Equals("ProtectChange", StringComparison.OrdinalIgnoreCase) ||
                     sample.EventKind.Equals("SectionMap", StringComparison.OrdinalIgnoreCase) ||
                     sample.EventKind.Equals("ImageMap", StringComparison.OrdinalIgnoreCase)))
                {
                    sample.PreviousProtection = previousProtection;
                }

                bool executableNow = IsExecutableProtection(sample.CurrentProtection);
                bool executableBefore = IsExecutableProtection(previousProtection);
                if (!state.FirstExecutableTransitionSeen && executableNow && !executableBefore)
                {
                    sample.FirstExecutableTransition = true;
                    state.FirstExecutableTransitionSeen = true;
                }

                bool protectionChanged = previousProtection != 0 &&
                                         !ProtectionValuesEquivalent(previousProtection, sample.CurrentProtection);
                bool protectSignalEvent =
                    sample.EventKind.Equals("ProtectChange", StringComparison.OrdinalIgnoreCase) ||
                    reportedProtectFlipCount > state.ProtectFlipCount;
                if (protectionChanged && protectSignalEvent)
                {
                    string transition = BuildProtectionTransitionLabel(previousProtection, sample.CurrentProtection);
                    sample.ProtectionTransition = transition;
                    state.LastProtectionTransition = transition;

                    if (reportedProtectFlipCount > state.ProtectFlipCount)
                    {
                        state.ProtectFlipCount = reportedProtectFlipCount;
                    }
                    else
                    {
                        state.ProtectFlipCount += 1;
                    }

                    double protectDeltaMs = state.LastProtectChangeUtc == default
                                                ? double.MaxValue
                                                : (observedUtc - state.LastProtectChangeUtc).TotalMilliseconds;
                    if (protectDeltaMs >= 0 && protectDeltaMs <= 1000)
                    {
                        state.RapidProtectFlipCount += 1;
                    }
                    state.LastProtectChangeUtc = observedUtc;

                    if (executableNow != executableBefore)
                    {
                        state.ExecutableFlipCount += 1;
                    }
                    if (IsGuardNoAccessProtectionTransition(previousProtection, sample.CurrentProtection))
                    {
                        state.GuardNoAccessFlipCount += 1;
                    }
                    if (IsWritableExecutableProtectionTransition(previousProtection, sample.CurrentProtection))
                    {
                        state.WritableExecutableFlipCount += 1;
                    }
                }
                else if (string.IsNullOrWhiteSpace(sample.ProtectionTransition))
                {
                    sample.ProtectionTransition = state.LastProtectionTransition;
                }

                if (state.InitialProtection == 0)
                {
                    state.InitialProtection = sample.CurrentProtection;
                }
                state.PreviousProtection = previousProtection;
                state.CurrentProtection = sample.CurrentProtection;
            }

            if (sample.EventKind.Equals("SectionMap", StringComparison.OrdinalIgnoreCase) ||
                sample.EventKind.Equals("ImageMap", StringComparison.OrdinalIgnoreCase))
            {
                state.MapCount += 1;
            }
            else if (sample.EventKind.Equals("MemoryWrite", StringComparison.OrdinalIgnoreCase))
            {
                state.WriteCount += 1;
            }
            else if (sample.EventKind.Equals("ProtectChange", StringComparison.OrdinalIgnoreCase))
            {
                state.ProtectCount += 1;
            }

            if (sample.ThreadStartObserved)
            {
                state.ThreadStartCount += 1;
                if (!state.FirstThreadStartSeen)
                {
                    state.FirstThreadStartSeen = true;
                    state.FirstThreadStartAddress = sample.ThreadStartAddress;
                }
                else
                {
                    sample.ThreadStartObserved = false;
                }
            }

            if (sample.EventKind.Equals("FunctionTableRegister", StringComparison.OrdinalIgnoreCase) ||
                sample.EventKind.Equals("FunctionTableCallback", StringComparison.OrdinalIgnoreCase))
            {
                state.FunctionTableRegistered = true;
            }
            else if (sample.EventKind.Equals("FunctionTableDelete", StringComparison.OrdinalIgnoreCase))
            {
                state.FunctionTableRegistered = false;
            }

            if (reportedProtectFlipCount > state.ProtectFlipCount)
            {
                state.ProtectFlipCount = reportedProtectFlipCount;
            }
            if (sample.EntropyBits >= 0)
            {
                bool entropyChanged =
                    state.LastEntropyBits >= 0 &&
                    Math.Abs(state.LastEntropyBits - sample.EntropyBits) >= MemoryEntropyFlipDeltaBits;
                if (entropyChanged)
                {
                    state.EntropyFlipCount += 1;
                    double entropyDeltaMs = state.LastEntropyChangeUtc == default
                                                ? double.MaxValue
                                                : (observedUtc - state.LastEntropyChangeUtc).TotalMilliseconds;
                    if (entropyDeltaMs >= 0 && entropyDeltaMs <= 1000)
                    {
                        state.RapidEntropyFlipCount += 1;
                    }
                    state.LastEntropyChangeUtc = observedUtc;
                }

                if (sample.EventKind.Equals("MemoryWrite", StringComparison.OrdinalIgnoreCase) &&
                    sample.EntropyBits >= MemoryHighEntropyBits &&
                    (sample.SampleBytes == 0 || sample.SampleBytes >= MemoryEntropyMinSampleBytes))
                {
                    state.HighEntropyWriteCount += 1;
                }

                state.LastEntropyBits = sample.EntropyBits;
                if (state.MaxEntropyBits < 0 || sample.EntropyBits > state.MaxEntropyBits)
                {
                    state.MaxEntropyBits = sample.EntropyBits;
                }
            }
            if (sample.SampleBytes > state.LastSampleBytes)
            {
                state.LastSampleBytes = sample.SampleBytes;
            }

            if (sample.TargetPid != 0 && sample.BaseAddress != 0)
            {
                if (sample.ApiName.Equals("RtlAddFunctionTable", StringComparison.OrdinalIgnoreCase) &&
                    sample.FunctionTablePointer != 0)
                {
                    string tableKey = BuildFunctionTablePointerKey(sample.TargetPid, sample.FunctionTablePointer);
                    _functionTableBaseByPointer[tableKey] = sample.BaseAddress;
                }
                else if (sample.ApiName.Equals("RtlDeleteFunctionTable", StringComparison.OrdinalIgnoreCase) &&
                         sample.FunctionTablePointer != 0)
                {
                    _functionTableBaseByPointer.Remove(
                        BuildFunctionTablePointerKey(sample.TargetPid, sample.FunctionTablePointer));
                }
            }

            sample.FunctionTableRegistered = state.FunctionTableRegistered || sample.FunctionTableRegistered;
            sample.MapCount = state.MapCount;
            sample.WriteCount = state.WriteCount;
            sample.ProtectCount = state.ProtectCount;
            sample.ThreadStartCount = state.ThreadStartCount;
            sample.ProtectFlipCount = Math.Max(sample.ProtectFlipCount, state.ProtectFlipCount);
            sample.RapidProtectFlipCount = state.RapidProtectFlipCount;
            sample.ExecutableFlipCount = state.ExecutableFlipCount;
            sample.GuardNoAccessFlipCount = state.GuardNoAccessFlipCount;
            sample.WritableExecutableFlipCount = state.WritableExecutableFlipCount;
            if (string.IsNullOrWhiteSpace(sample.ProtectionTransition))
            {
                sample.ProtectionTransition = state.LastProtectionTransition;
            }
            if (sample.EntropyBits < 0)
            {
                sample.EntropyBits = state.LastEntropyBits;
            }
            sample.MaxEntropyBits = state.MaxEntropyBits;
            sample.EntropyFlipCount = state.EntropyFlipCount;
            sample.RapidEntropyFlipCount = state.RapidEntropyFlipCount;
            sample.HighEntropyWriteCount = state.HighEntropyWriteCount;
            if (sample.SampleBytes == 0)
            {
                sample.SampleBytes = state.LastSampleBytes;
            }
            sample.ObservedByKernel = sample.ObservedByKernel || state.ObservedByKernel;
            sample.ObservedByUserHook = sample.ObservedByUserHook || state.ObservedByUserHook;
            sample.BlackbirdOwned = sample.BlackbirdOwned || state.BlackbirdOwned;
            sample.CrossProcess = sample.CrossProcess || state.CrossProcess;
            sample.ImageBacked = sample.ImageBacked || state.ImageBacked;
            if (string.IsNullOrWhiteSpace(sample.ExecutionContext))
            {
                sample.ExecutionContext = state.ExecutionContext;
            }
            sample.LifecycleSummary = BuildMemoryLifecycleSummary(sample);
            return sample;
        }

        private static string BuildMemoryLifecycleSummary(MemoryRegionAttributionSample sample)
        {
            var parts = new List<string>(6);
            if (sample.MapCount != 0)
            {
                parts.Add($"map:{sample.MapCount}");
            }
            if (sample.WriteCount != 0)
            {
                parts.Add($"write:{sample.WriteCount}");
            }
            if (sample.ProtectCount != 0)
            {
                parts.Add($"protect:{sample.ProtectCount}");
            }
            if (sample.ThreadStartCount != 0)
            {
                parts.Add($"thread:{sample.ThreadStartCount}");
            }
            if (sample.FirstExecutableTransition)
            {
                parts.Add("first-exec");
            }
            if (sample.FunctionTableRegistered)
            {
                parts.Add("unwind");
            }

            string summary = parts.Count == 0 ? sample.EventKind : string.Join(" ", parts);
            if (sample.CrossProcess)
            {
                summary += " xproc";
            }
            if (sample.ImageBacked)
            {
                summary += " image";
            }
            if (sample.ProtectFlipCount != 0)
            {
                summary += $" pflip:{sample.ProtectFlipCount}";
            }
            if (sample.RapidProtectFlipCount != 0)
            {
                summary += $" rapid-pflip:{sample.RapidProtectFlipCount}";
            }
            if (!string.IsNullOrWhiteSpace(sample.ProtectionTransition))
            {
                summary += $" transition:{sample.ProtectionTransition}";
            }
            if (sample.ExecutableFlipCount != 0)
            {
                summary += $" xflip:{sample.ExecutableFlipCount}";
            }
            if (sample.GuardNoAccessFlipCount != 0)
            {
                summary += $" guard/noaccess:{sample.GuardNoAccessFlipCount}";
            }
            if (sample.WritableExecutableFlipCount != 0)
            {
                summary += $" wxflip:{sample.WritableExecutableFlipCount}";
            }
            if (sample.EntropyBits >= 0)
            {
                summary += $" H:{sample.EntropyBits:F1}";
            }
            if (sample.MaxEntropyBits >= 0 && sample.MaxEntropyBits > sample.EntropyBits + 0.05)
            {
                summary += $" Hmax:{sample.MaxEntropyBits:F1}";
            }
            if (sample.EntropyFlipCount != 0)
            {
                summary += $" eflip:{sample.EntropyFlipCount}";
            }
            if (sample.RapidEntropyFlipCount != 0)
            {
                summary += $" rapid-eflip:{sample.RapidEntropyFlipCount}";
            }
            if (sample.HighEntropyWriteCount != 0)
            {
                summary += $" high-H:{sample.HighEntropyWriteCount}";
            }

            return summary.Trim();
        }

        private uint ResolveMemoryRegionTargetPid(BrokerEtwEventView view)
        {
            return view.Family switch {
                BlackbirdNative.IpcEtwFamilyImage => view.ProcessPid != 0 ? view.ProcessPid : view.EventProcessId,
                BlackbirdNative.IpcEtwFamilyThread =>
                    view.ProcessPid != 0 ? view.ProcessPid
                                         : (view.TargetPid != 0 ? view.TargetPid : view.EventProcessId),
                BlackbirdNative.IpcEtwFamilyUserHook =>
                    view.TargetPid != 0 ? view.TargetPid : (view.ProcessPid != 0 ? view.ProcessPid : view.ActorPid),
                _ => 0
            };
        }

        private ulong ResolveObservedProcessStartKey(uint pid, ulong eventStartKey)
        {
            if (eventStartKey != 0)
            {
                _observedProcessStartKeyByPid[pid] = eventStartKey;
                return eventStartKey;
            }

            return _observedProcessStartKeyByPid.TryGetValue(pid, out ulong cached) ? cached : 0;
        }

        private static string BuildRegionIdentity(ulong processStartKey, uint targetPid, ulong allocationBase) =>
            $"{targetPid:X8}:{processStartKey:X16}:{allocationBase:X16}";

        private static string BuildFunctionTablePointerKey(uint pid,
                                                           ulong functionTable) => $"{pid:X8}:{functionTable:X16}";

        private ulong ResolveFunctionTableBase(BrokerEtwEventView view, ulong functionTable)
        {
            if (view.ProcessPid != 0 && functionTable != 0)
            {
                string key = BuildFunctionTablePointerKey(view.ProcessPid, functionTable);
                if (_functionTableBaseByPointer.TryGetValue(key, out ulong baseAddress) && baseAddress != 0)
                {
                    return baseAddress;
                }
            }

            return 0;
        }

        private bool TryResolveKnownRegionForAddress(uint targetPid, ulong processStartKey, ulong address,
                                                     out string regionIdentity, out ulong baseAddress,
                                                     out ulong regionSize, out string regionKind,
                                                     out uint currentProtection)
        {
            regionIdentity = string.Empty;
            baseAddress = 0;
            regionSize = 0;
            regionKind = string.Empty;
            currentProtection = 0;

            if (targetPid == 0 || address == 0 || _regionLifecycleByIdentity.Count == 0)
            {
                return false;
            }

            RegionLifecycleState? best = null;
            foreach ((string candidateIdentity, RegionLifecycleState candidate) in _regionLifecycleByIdentity)
            {
                if (candidate.TargetPid != targetPid || candidate.BaseAddress == 0 || candidate.RegionSize == 0)
                {
                    continue;
                }
                if (processStartKey != 0 && candidate.ProcessStartKey != 0 &&
                    candidate.ProcessStartKey != processStartKey)
                {
                    continue;
                }

                ulong regionEnd = candidate.BaseAddress + candidate.RegionSize;
                if (regionEnd <= candidate.BaseAddress)
                {
                    regionEnd = ulong.MaxValue;
                }
                if (address < candidate.BaseAddress || address >= regionEnd)
                {
                    continue;
                }

                if (best == null || candidate.BaseAddress >= best.BaseAddress)
                {
                    best = candidate;
                    regionIdentity = candidateIdentity;
                }
            }

            if (best == null)
            {
                return false;
            }

            baseAddress = best.BaseAddress;
            regionSize = best.RegionSize;
            regionKind = best.RegionKind;
            currentProtection = best.CurrentProtection;
            return true;
        }

        private static ulong NormalizeRegionAddress(ulong address) => address == 0 ? 0 : (address & ~0xFFFUL);

        private static bool IsExecutableProtection(uint protection)
        {
            uint normalized = protection & 0xFFu;
            return normalized == 0x10u || normalized == 0x20u || normalized == 0x40u || normalized == 0x80u;
        }

        private static bool IsWritableProtection(uint protection)
        {
            uint normalized = protection & 0xFFu;
            return normalized == 0x04u || normalized == 0x08u || normalized == 0x40u || normalized == 0x80u;
        }

        private static bool IsNoAccessProtection(uint protection)
        {
            return (protection & 0xFFu) == 0x01u;
        }

        private static bool HasGuardProtection(uint protection)
        {
            return (protection & 0x100u) != 0;
        }

        private static bool IsWritableExecutableProtection(uint protection)
        {
            uint normalized = protection & 0xFFu;
            return normalized == 0x40u || normalized == 0x80u;
        }

        private static uint NormalizeProtectionForFlip(uint protection)
        {
            return protection & 0x1FFu;
        }

        private static bool ProtectionValuesEquivalent(uint left, uint right)
        {
            return NormalizeProtectionForFlip(left) == NormalizeProtectionForFlip(right);
        }

        private static bool IsGuardNoAccessProtectionTransition(uint previousProtection, uint currentProtection)
        {
            return IsNoAccessProtection(previousProtection) || IsNoAccessProtection(currentProtection) ||
                   HasGuardProtection(previousProtection) || HasGuardProtection(currentProtection);
        }

        private static bool IsWritableExecutableProtectionTransition(uint previousProtection, uint currentProtection)
        {
            return IsWritableExecutableProtection(previousProtection) ||
                   IsWritableExecutableProtection(currentProtection) ||
                   (IsWritableProtection(previousProtection) && IsExecutableProtection(currentProtection)) ||
                   (IsExecutableProtection(previousProtection) && IsWritableProtection(currentProtection));
        }

        private static string BuildProtectionTransitionLabel(uint previousProtection, uint currentProtection)
        {
            return $"{CompactMemoryProtectionLabel(previousProtection)}->{CompactMemoryProtectionLabel(currentProtection)}";
        }

        private static string CompactMemoryProtectionLabel(uint protection)
        {
            string baseLabel = (protection & 0xFFu) switch {
                0x01u => "NO_ACCESS",
                0x02u => "R",
                0x04u => "RW",
                0x08u => "WC",
                0x10u => "X",
                0x20u => "RX",
                0x40u => "RWX",
                0x80u => "XWC",
                _ => protection == 0 ? "UNKNOWN" : $"0x{protection & 0xFFu:X}"
            };

            return HasGuardProtection(protection) ? $"GUARD|{baseLabel}" : baseLabel;
        }

        private static bool IsMemoryPatternMilestone(uint count)
        {
            return count == 2 || count == 3 || count == 5 || count == 10 || count == 25 || count == 50 ||
                   (count >= 100 && count % 100 == 0);
        }

        private static bool IsHighEntropyWriteMilestone(uint count)
        {
            return count == 1 || count == 3 || count == 10 || count == 25 || count == 50 ||
                   (count >= 100 && count % 100 == 0);
        }

        private static bool HasUsableEntropySample(MemoryRegionAttributionSample sample)
        {
            return sample.EntropyBits >= 0 &&
                   (sample.SampleBytes == 0 || sample.SampleBytes >= MemoryEntropyMinSampleBytes);
        }

        private static uint ComputeMemoryLifecycleSeverity(MemoryRegionAttributionSample sample, bool protectSignal,
                                                           bool entropySignal)
        {
            uint severity = protectSignal ? 5u : 4u;
            if (protectSignal)
            {
                if (sample.ProtectFlipCount >= 50 || sample.RapidProtectFlipCount >= 10)
                {
                    severity = Math.Max(severity, 9u);
                }
                else if (sample.ProtectFlipCount >= 10 || sample.RapidProtectFlipCount >= 4)
                {
                    severity = Math.Max(severity, 8u);
                }
                else if (sample.ProtectFlipCount >= 5 || sample.GuardNoAccessFlipCount != 0 ||
                         sample.WritableExecutableFlipCount != 0)
                {
                    severity = Math.Max(severity, 7u);
                }
                else if (sample.ProtectFlipCount >= 2 || sample.RapidProtectFlipCount != 0 ||
                         sample.ExecutableFlipCount != 0)
                {
                    severity = Math.Max(severity, 6u);
                }
            }

            if (entropySignal)
            {
                if (sample.MaxEntropyBits >= 7.7 || sample.HighEntropyWriteCount >= 10)
                {
                    severity = Math.Max(severity, 7u);
                }
                else if (sample.EntropyBits >= MemoryHighEntropyBits || sample.EntropyFlipCount >= 3)
                {
                    severity = Math.Max(severity, 5u);
                }
            }

            if (sample.CrossProcess)
            {
                severity = Math.Max(severity, 7u);
            }
            if (sample.FunctionTableRegistered && sample.ProtectFlipCount != 0)
            {
                severity = Math.Max(severity, 7u);
            }

            return Math.Min(severity, 9u);
        }

        private static bool IsHookUnwindClean(uint flags)
        {
            return (flags & BlackbirdNative.IpcEtwFlagModuleChainSane) != 0 &&
                   (flags & BlackbirdNative.IpcEtwFlagUnwindMetadataValid) != 0 &&
                   (flags & BlackbirdNative.IpcEtwFlagTebStackBoundsValid) != 0 &&
                   (flags & BlackbirdNative.IpcEtwFlagFramesOutsideTebStack) == 0;
        }

        private static bool HookFrameChainHasGaps(uint flags)
        {
            return (flags & BlackbirdNative.IpcEtwFlagModuleChainSane) == 0 ||
                   (flags & BlackbirdNative.IpcEtwFlagFramesOutsideTebStack) != 0;
        }

        private static string InferRegionKind(BrokerEtwEventView view, uint protection)
        {
            if (view.Family == BlackbirdNative.IpcEtwFamilyImage)
            {
                return "Image";
            }

            if (view.EventName.Equals("NtAllocateVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                view.EventName.Equals("NtAllocateVirtualMemoryEx", StringComparison.OrdinalIgnoreCase))
            {
                return "Private";
            }

            if (view.EventName.Equals("NtMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                view.EventName.Equals("NtMapViewOfSectionEx", StringComparison.OrdinalIgnoreCase))
            {
                return IsExecutableProtection(protection) ? "Mapped-Executable" : "Mapped";
            }

            return "Unknown";
        }
    }
}
