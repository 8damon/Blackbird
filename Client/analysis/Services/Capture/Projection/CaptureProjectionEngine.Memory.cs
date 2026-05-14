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
        private void ProcessMemoryAttribution(BrokerEtwEventView view, DateTime observedUtc)
        {
            uint targetPid = ResolveMemoryTargetPid(view);
            if (targetPid == 0)
            {
                return;
            }

            string apiName = FirstNonEmpty(view.EventName, view.Operation, view.DetectionName);
            string eventKind = string.Empty;
            string regionKind = string.Empty;
            ulong baseAddress = 0;
            ulong regionSize = 0;
            uint currentProtect = 0;
            uint previousProtect = 0;
            uint sampleBytes = 0;
            bool threadStartObserved = false;
            ulong threadStartAddress = 0;

            if (view.Family == BlackbirdNative.IpcEtwFamilyImage && view.ImageBase != 0)
            {
                eventKind = "ImageMap";
                regionKind = "Image";
                baseAddress = view.ImageBase;
                regionSize = view.ImageSize;
                currentProtect = view.StartRegionProtect;
            }
            else if (view.Family == BlackbirdNative.IpcEtwFamilyThread && view.StartAddress != 0)
            {
                eventKind = "ThreadStart";
                regionKind = view.ImageBase != 0 ? "Image" : "Unknown";
                baseAddress = view.ImageBase != 0 ? view.ImageBase : NormalizeRegionAddress(view.StartAddress);
                regionSize = view.ImageSize != 0 ? view.ImageSize : 1;
                currentProtect = view.StartRegionProtect;
                threadStartObserved = true;
                threadStartAddress = view.StartAddress;
            }
            else if (view.Family == BlackbirdNative.IpcEtwFamilyUserHook && !string.IsNullOrWhiteSpace(apiName))
            {
                Dictionary<string, string> fields = view.GetOrCreateHookFieldMap();
                if (apiName.Equals("NtAllocateVirtualMemory", StringComparison.OrdinalIgnoreCase) ||
                    apiName.Equals("NtAllocateVirtualMemoryEx", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "PrivateAllocate";
                    regionKind = "Private";
                    baseAddress = FirstU64(fields, "base", "baseAddress", "c1", "a1");
                    regionSize = FirstU64(fields, "size", "regionSize", "c3", "a3");
                    currentProtect = (uint)FirstU64(fields, "protect", "c3", "a5", "c5");
                }
                else if (apiName.Equals("NtProtectVirtualMemory", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "ProtectChange";
                    baseAddress = FirstU64(fields, "base", "baseAddress", "c1", "a1");
                    regionSize = FirstU64(fields, "size", "regionSize", "c2", "a2");
                    currentProtect = (uint)FirstU64(fields, "newProtect", "protect", "c2", "a3", "c3");
                    previousProtect = (uint)FirstU64(fields, "oldProtect", "a4", "c4");
                }
                else if (apiName.Equals("NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "MemoryWrite";
                    baseAddress = FirstU64(fields, "base", "baseAddress", "c1", "a1");
                    regionSize = Math.Max(1UL, FirstU64(fields, "size", "regionSize", "c3", "a3"));
                    sampleBytes = (uint)Math.Min(uint.MaxValue, view.DeepSampleSize);
                }
                else if (apiName.Equals("NtMapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                         apiName.Equals("NtMapViewOfSectionEx", StringComparison.OrdinalIgnoreCase))
                {
                    eventKind = "SectionMap";
                    regionKind = (view.Flags & BlackbirdNative.IpcEtwFlagHookSectionImage) != 0 ? "Image" : "Mapped";
                    baseAddress = FirstU64(fields, "baseAddress", "base", "c2", "a2");
                    regionSize = FirstU64(fields, "viewSize", "size", "c3", "a4", "a6");
                    currentProtect = (uint)FirstU64(fields, "win32Protect", "protect", "a6", "c6", "c5");
                }
                else
                {
                    return;
                }
            }
            else
            {
                return;
            }

            if (baseAddress == 0)
            {
                baseAddress = NormalizeRegionAddress(threadStartAddress);
            }
            if (baseAddress == 0)
            {
                return;
            }

            string regionIdentity = $"memory:{targetPid}:{baseAddress:X}";
            string lifecycle =
                $"{eventKind} pid={targetPid} base=0x{baseAddress:X} size=0x{regionSize:X} protect={EventDetailFormatting.DescribeMemoryProtection(currentProtect)} api={apiName}";
            AddMemoryAttribution(new MemoryRegionAttributionSample {
                TimestampUtc = observedUtc,
                ProcessStartKey = view.ProcessStartKey,
                TargetPid = targetPid,
                ActorPid = ResolveActorPid(view),
                ActorTid = view.ThreadId != 0 ? view.ThreadId : view.EventThreadId,
                AllocationBase = baseAddress,
                BaseAddress = baseAddress,
                RegionSize = regionSize == 0 ? 1 : regionSize,
                ApiName = apiName,
                EventKind = eventKind,
                RegionKind = string.IsNullOrWhiteSpace(regionKind) ? "Unknown" : regionKind,
                RegionIdentity = regionIdentity,
                OriginPath = FirstNonEmpty(view.OriginPath, view.ImagePath),
                SourceFamily = DescribeEtwFamily(view.Family),
                CallerOrigin = view.CallerOriginLabel,
                FirstUserFrame = view.OriginAddress,
                FrameSummary = BuildStackSummary(view.Stack, view.StackCount),
                UnwindClean = (view.Flags & BlackbirdNative.IpcEtwFlagUnwindMetadataValid) != 0,
                FrameChainHadGaps = (view.Flags & BlackbirdNative.IpcEtwFlagFramesOutsideTebStack) != 0,
                ObservedByKernel = view.SourceId == BlackbirdNative.IpcEtwSourceBlackbird,
                ObservedByUserHook = view.SourceId == BlackbirdNative.IpcEtwSourceUserHook,
                CrossProcess = ResolveActorPid(view) != 0 && ResolveActorPid(view) != targetPid,
                ImageBacked = string.Equals(regionKind, "Image", StringComparison.OrdinalIgnoreCase),
                InitialProtection = currentProtect,
                CurrentProtection = currentProtect,
                PreviousProtection = previousProtect,
                SampleBytes = sampleBytes,
                LifecycleSummary = lifecycle,
                ThreadStartObserved = threadStartObserved,
                ThreadId = threadStartObserved ? (view.ThreadId != 0 ? view.ThreadId : view.EventThreadId) : 0,
                ThreadStartAddress = threadStartAddress,
                SignatureLevel = view.SignatureLevel,
                SignatureType = view.SignatureType
            });

            AddExtended("Memory", PidLabel(ResolveActorPid(view)), PidLabel(targetPid), $"0x{baseAddress:X}", eventKind,
                        observedUtc, 1, lifecycle);
        }
    }
}
