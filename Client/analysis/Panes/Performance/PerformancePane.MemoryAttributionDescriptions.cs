using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class PerformancePane
    {
        private bool ShouldBulkReplaceMemoryAttributionRows(IReadOnlyList<MemoryAttributionRow> rows)
        {
            if (MemoryAttributionRows.Count == 0 || rows.Count == 0)
            {
                return true;
            }

            int commonPrefix = 0;
            int limit = Math.Min(MemoryAttributionRows.Count, rows.Count);
            while (commonPrefix < limit &&
                   MemoryAttributionRows[commonPrefix].BaseAddressValue == rows[commonPrefix].BaseAddressValue &&
                   MemoryAttributionRows[commonPrefix].RegionSizeBytes == rows[commonPrefix].RegionSizeBytes)
            {
                commonPrefix += 1;
            }

            int changedShape = Math.Max(MemoryAttributionRows.Count, rows.Count) - commonPrefix;
            return changedShape > 128;
        }

        private static bool MemoryRegionsOverlap(ulong leftBase, ulong leftSize, ulong rightBase, ulong rightSize)
        {
            if (leftBase == 0 || rightBase == 0 || leftSize == 0 || rightSize == 0)
            {
                return false;
            }

            ulong leftEnd = leftBase + leftSize;
            ulong rightEnd = rightBase + rightSize;
            if (leftEnd <= leftBase)
            {
                leftEnd = ulong.MaxValue;
            }
            if (rightEnd <= rightBase)
            {
                rightEnd = ulong.MaxValue;
            }

            return leftBase < rightEnd && rightBase < leftEnd;
        }

        private static bool ContainsAddress(ulong baseAddress, ulong size, ulong address)
        {
            if (baseAddress == 0 || size == 0 || address == 0)
            {
                return false;
            }

            ulong endAddress = baseAddress + size;
            if (endAddress <= baseAddress)
            {
                return address >= baseAddress;
            }

            return address >= baseAddress && address < endAddress;
        }

        private static bool ShouldUseThreadExecutionHeuristic(MemoryPageSample page)
        {
            if (page.BaseAddress == 0 || page.RegionSize == 0)
            {
                return false;
            }

            bool isPrivate = (page.Type & 0x00020000u) != 0;
            bool executable = IsExecutableProtect(page.Protect);
            bool hasBacking =
                !string.IsNullOrWhiteSpace(page.ModulePath) || !string.IsNullOrWhiteSpace(page.BackingPath);
            return isPrivate || executable || !hasBacking;
        }

        private static string DescribeAllocator(MemoryRegionAttributionSample? attribution,
                                                ThreadExecutionMemoryHeuristic? threadHeuristic = null)
        {
            if (attribution == null)
            {
                return threadHeuristic == null ? string.Empty : DescribeThreadExecutionAllocator(threadHeuristic);
            }

            string actor = ProcessIdentityResolver.Describe(attribution.ActorPid);
            string label =
                !string.IsNullOrWhiteSpace(attribution.EventKind)
                    ? attribution.EventKind.Trim()
                    : (!string.IsNullOrWhiteSpace(attribution.ApiName) ? attribution.ApiName.Trim() : "allocation");
            string allocator = $"{actor} via {label}";
            return threadHeuristic == null ? allocator
                                           : $"{allocator}; {DescribeThreadExecutionRunSummary(threadHeuristic)}";
        }

        private static string DescribeAllocatorSource(MemoryRegionAttributionSample? attribution)
        {
            if (attribution == null)
            {
                return string.Empty;
            }

            if (!string.IsNullOrWhiteSpace(attribution.OriginPath))
            {
                return EventDetailFormatting.ModuleNameFromPath(attribution.OriginPath);
            }

            if (!string.IsNullOrWhiteSpace(attribution.FirstUserFrameModule))
            {
                string module = EventDetailFormatting.ModuleNameFromPath(attribution.FirstUserFrameModule);
                if (EventDetailFormatting.IsBlackbirdInternalModule(module) && !attribution.BlackbirdOwned)
                {
                    return string.IsNullOrWhiteSpace(attribution.CallerOrigin) ? string.Empty
                                                                               : attribution.CallerOrigin;
                }

                return DescribeCallsiteOwnership(attribution.FirstUserFrameModule, attribution.OriginPath);
            }

            if (!string.IsNullOrWhiteSpace(attribution.CallerOrigin))
            {
                return attribution.CallerOrigin;
            }

            return string.Empty;
        }

        private static string DescribeThreadExecutionAllocator(ThreadExecutionMemoryHeuristic heuristic)
        {
            string label = $"TID {heuristic.ThreadId} {heuristic.EvidenceKind} (heuristic)";
            if (heuristic.OwnerPid != 0)
            {
                label += $"; owner {ProcessIdentityResolver.Describe(heuristic.OwnerPid)}";
            }
            if (heuristic.CreatorPid != 0 && heuristic.CreatorPid != heuristic.OwnerPid)
            {
                label += $"; creator {ProcessIdentityResolver.Describe(heuristic.CreatorPid)}";
            }

            return label;
        }

        private static string DescribeThreadExecutionRunSummary(ThreadExecutionMemoryHeuristic heuristic)
        {
            string label = $"ran TID {heuristic.ThreadId} {heuristic.EvidenceKind} (heuristic)";
            return heuristic.OwnerPid == 0 ? label
                                           : $"{label}; owner {ProcessIdentityResolver.Describe(heuristic.OwnerPid)}";
        }

        private static string DescribeThreadExecutionSource(ThreadExecutionMemoryHeuristic? heuristic)
        {
            if (heuristic == null)
            {
                return string.Empty;
            }

            if (!string.IsNullOrWhiteSpace(heuristic.Module))
            {
                string module = EventDetailFormatting.ModuleNameFromPath(heuristic.Module);
                return string.IsNullOrWhiteSpace(module) ? heuristic.Module.Trim() : module;
            }

            if (!string.IsNullOrWhiteSpace(heuristic.Symbol))
            {
                return heuristic.Symbol.Trim();
            }

            return "thread execution";
        }

        private static string DescribeThreadExecutionContext(ThreadExecutionMemoryHeuristic heuristic)
        {
            string context = $"Thread execution heuristic: {heuristic.EvidenceKind} @ 0x{heuristic.Address:X}";
            string callsite = DescribeThreadExecutionCallsite(heuristic);
            return string.IsNullOrWhiteSpace(callsite) ? context : $"{context} | {callsite}";
        }

        private static string DescribeThreadExecutionLifecycle(ThreadExecutionMemoryHeuristic heuristic)
        {
            string observed =
                heuristic.ObservedUtc == default ? "observed" : $"observed {heuristic.ObservedUtc:HH:mm:ss}";
            return $"{observed}; not a proven allocator";
        }

        private static string DescribeThreadExecutionCallsite(ThreadExecutionMemoryHeuristic heuristic)
        {
            string module = EventDetailFormatting.ModuleNameFromPath(heuristic.Module);
            if (!string.IsNullOrWhiteSpace(heuristic.Symbol))
            {
                return string.IsNullOrWhiteSpace(module) ? heuristic.Symbol.Trim()
                                                         : $"{module}!{heuristic.Symbol.Trim()}";
            }

            return string.IsNullOrWhiteSpace(module) ? string.Empty : module;
        }

        private static string DescribeResolvedMemorySource(MemoryPageSample page,
                                                           MemoryRegionAttributionSample? attribution,
                                                           ThreadExecutionMemoryHeuristic? threadHeuristic = null)
        {
            if (IsSr71OwnedMemoryPage(page, attribution))
            {
                string tag = Sr71OwnerLabel(page, attribution);
                return string.IsNullOrWhiteSpace(tag) ? "SR71.dll" : tag;
            }

            string modulePath = !string.IsNullOrWhiteSpace(page.ModulePath) ? page.ModulePath : page.BackingPath;
            if (!string.IsNullOrWhiteSpace(modulePath))
            {
                string fileName = Path.GetFileName(modulePath);
                return string.IsNullOrWhiteSpace(fileName) ? modulePath : fileName;
            }

            string allocatorSource = DescribeAllocatorSource(attribution);
            return string.IsNullOrWhiteSpace(allocatorSource) ? DescribeThreadExecutionSource(threadHeuristic)
                                                              : allocatorSource;
        }

        private static string DescribeAllocatorTrust(MemoryRegionAttributionSample? attribution)
        {
            if (attribution == null)
            {
                return "Unknown";
            }

            if (attribution.SignatureLevel != 0 || attribution.SignatureType != 0)
            {
                return "Signed";
            }

            if (attribution.UnwindClean)
            {
                return "Runtime-Clean";
            }

            if (!string.IsNullOrWhiteSpace(attribution.OriginPath))
            {
                return "Unsigned";
            }

            if (string.Equals(attribution.CallerOrigin, "system", StringComparison.OrdinalIgnoreCase))
            {
                return "System";
            }

            return "Unknown";
        }

        private static string DescribeResolvedMemoryTrust(MemoryPageSample page,
                                                          MemoryRegionAttributionSample? attribution,
                                                          ThreadExecutionMemoryHeuristic? threadHeuristic = null)
        {
            if (IsSr71OwnedMemoryPage(page, attribution))
            {
                return "SR71-Owned";
            }

            string trust = DescribeAllocatorTrust(attribution);
            if (!trust.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            {
                return trust;
            }

            if (!string.IsNullOrWhiteSpace(page.ModulePath) || LooksLikeImagePath(page.BackingPath))
            {
                return page.WorkingSetValid && !page.WorkingSetShared ? "Image-Private" : "Image";
            }

            if (!string.IsNullOrWhiteSpace(page.BackingPath))
            {
                return page.WorkingSetValid && !page.WorkingSetShared ? "Mapped-Private" : "Mapped";
            }

            if (threadHeuristic != null)
            {
                return "Heuristic";
            }

            return trust;
        }

        private static string DescribeResolvedMemoryContext(MemoryPageSample page,
                                                            MemoryRegionAttributionSample? attribution,
                                                            ThreadExecutionMemoryHeuristic? threadHeuristic = null)
        {
            if (IsSr71OwnedMemoryPage(page, attribution))
            {
                string tag = Sr71OwnerLabel(page, attribution);
                return string.IsNullOrWhiteSpace(tag) ? "BK Instrumentation" : tag;
            }

            if (attribution != null)
            {
                string context = attribution.ExecutionContext;
                if (string.IsNullOrWhiteSpace(context))
                {
                    context = attribution.CrossProcess                            ? "Cross-Process Runtime"
                              : attribution.ImageBacked                           ? "Loader / Image Mapping"
                              : string.IsNullOrWhiteSpace(attribution.RegionKind) ? string.Empty
                                                                                  : attribution.RegionKind;
                }

                string ownership = string.Empty;
                string firstFrameModule = EventDetailFormatting.ModuleNameFromPath(attribution.FirstUserFrameModule);
                if (!EventDetailFormatting.IsBlackbirdInternalModule(firstFrameModule))
                {
                    ownership = DescribeCallsiteOwnership(attribution.FirstUserFrameModule, attribution.OriginPath);
                }
                if (!string.IsNullOrWhiteSpace(ownership))
                {
                    context = string.IsNullOrWhiteSpace(context) ? ownership : $"{ownership} | {context}";
                }

                if (attribution.ObservedByKernel && attribution.ObservedByUserHook)
                {
                    context = $"{context} [kernel+user]".Trim();
                }
                else if (attribution.ObservedByKernel)
                {
                    context = $"{context} [kernel]".Trim();
                }
                else if (attribution.ObservedByUserHook)
                {
                    context = $"{context} [user]".Trim();
                }

                if (threadHeuristic != null)
                {
                    context = string.IsNullOrWhiteSpace(context)
                                  ? DescribeThreadExecutionContext(threadHeuristic)
                                  : $"{context} | {DescribeThreadExecutionContext(threadHeuristic)}";
                }

                return context;
            }

            if (threadHeuristic != null)
            {
                return DescribeThreadExecutionContext(threadHeuristic);
            }

            if (!string.IsNullOrWhiteSpace(page.ModulePath) || LooksLikeImagePath(page.BackingPath))
            {
                return page.WorkingSetValid && !page.WorkingSetShared ? "Image private copy" : "Image";
            }
            if (!string.IsNullOrWhiteSpace(page.BackingPath))
            {
                return page.WorkingSetValid && !page.WorkingSetShared ? "Mapped private copy" : "Mapped";
            }
            return "Private/Unknown";
        }

        private static string DescribeResolvedMemoryLifecycle(MemoryRegionAttributionSample? attribution,
                                                              ThreadExecutionMemoryHeuristic? threadHeuristic = null)
        {
            if (attribution == null)
            {
                return threadHeuristic == null ? string.Empty : DescribeThreadExecutionLifecycle(threadHeuristic);
            }

            string raw = string.IsNullOrWhiteSpace(attribution.LifecycleSummary) ? attribution.EventKind
                                                                                 : attribution.LifecycleSummary;
            string lifecycle = NormalizeLifecycleSummary(raw);
            if (threadHeuristic == null)
            {
                return lifecycle;
            }

            string heuristicLifecycle = DescribeThreadExecutionLifecycle(threadHeuristic);
            return string.IsNullOrWhiteSpace(lifecycle) ? heuristicLifecycle : $"{lifecycle}; {heuristicLifecycle}";
        }

        private static string NormalizeLifecycleSummary(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            string text = value.Trim();
            text = text.Replace("map:", "maps: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("alloc:", "allocs: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("protect:", "protects: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("rapid-pflip:", "rapid protection flips: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("pflip:", "protection flips: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("xflip:", "executable flips: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("wxflip:", "WX flips: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("rapid-eflip:", "rapid entropy flips: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("eflip:", "entropy flips: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("Hmax:", "max entropy: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("high-H:", "high entropy writes: ", StringComparison.OrdinalIgnoreCase)
                       .Replace("first exec", "first executable", StringComparison.OrdinalIgnoreCase)
                       .Replace("rx", "RX", StringComparison.OrdinalIgnoreCase)
                       .Replace("rwx", "RWX", StringComparison.OrdinalIgnoreCase);

            return text switch { "PrivateAllocate" => "allocated private memory", "SectionMap" => "mapped section",
                                 "ImageMap" => "mapped image", "ProtectChange" => "protection changed",
                                 _ => text };
        }

        private static string DescribeMemoryStateForInspector(MemoryPageSample page)
        {
            return page.State switch {
                0x1000 => "Committed",
                0x2000 => "Reserved",
                0x10000 => "Free", _ when!string.IsNullOrWhiteSpace(page.StateLabel) => page.StateLabel.Trim(),
                _ => "Unclassified"
            };
        }

        private static string DescribeMemoryTypeForInspector(MemoryPageSample page)
        {
            string type = page.Type switch {
                0x20000 => "Private",
                0x40000 => "Mapped",
                0x1000000 => "Image", _ when!string.IsNullOrWhiteSpace(page.TypeLabel) => page.TypeLabel.Trim(),
                _ => "Unclassified"
            };

            if (page.WorkingSetValid && !page.WorkingSetShared && (page.Type == 0x40000 || page.Type == 0x1000000))
            {
                return $"{type} private copy";
            }

            return type;
        }

        private static bool IsPrimaryMemoryAttributionEvent(MemoryRegionAttributionSample sample)
        {
            return sample.EventKind.Equals("PrivateAllocate", StringComparison.OrdinalIgnoreCase) ||
                   sample.EventKind.Equals("SectionMap", StringComparison.OrdinalIgnoreCase) ||
                   sample.EventKind.Equals("ImageMap", StringComparison.OrdinalIgnoreCase) ||
                   sample.EventKind.Equals("ProtectChange", StringComparison.OrdinalIgnoreCase);
        }

        private static string DescribeResolvedMemoryCategory(MemoryPageSample page)
        {
            if (IsSr71OwnedMemoryPage(page, null))
            {
                return LooksLikeSr71ImagePath(page.ModulePath) || LooksLikeSr71ImagePath(page.BackingPath)
                           ? "SR71 Instrumentation"
                           : "BK Instrumentation";
            }

            if (string.IsNullOrWhiteSpace(page.Category))
            {
                return string.Empty;
            }

            if (!string.IsNullOrWhiteSpace(page.ModulePath) || LooksLikeImagePath(page.BackingPath))
            {
                if (page.Category.StartsWith("Mapped", StringComparison.OrdinalIgnoreCase))
                {
                    return "Image" + page.Category["Mapped".Length..];
                }

                if (page.Category.StartsWith("Unknown", StringComparison.OrdinalIgnoreCase))
                {
                    return "Image" + page.Category["Unknown".Length..];
                }
            }

            return page.Category;
        }

        private static bool IsSr71OwnedMemoryPage(MemoryPageSample page, MemoryRegionAttributionSample? attribution)
        {
            return page.Sr71Owned || attribution?.BlackbirdOwned == true || LooksLikeSr71ImagePath(page.ModulePath) ||
                   LooksLikeSr71ImagePath(page.BackingPath) || StartsWithBlackbirdInstrumentation(page.SpecialUse) ||
                   StartsWithBlackbirdInstrumentation(page.Sr71OwnerTag);
        }

        private static string Sr71OwnerLabel(MemoryPageSample page, MemoryRegionAttributionSample? attribution)
        {
            if (!string.IsNullOrWhiteSpace(page.Sr71OwnerTag))
            {
                return page.Sr71OwnerTag.Trim();
            }
            if (!string.IsNullOrWhiteSpace(page.SpecialUse) && StartsWithBlackbirdInstrumentation(page.SpecialUse))
            {
                return page.SpecialUse.Trim();
            }
            if (attribution?.BlackbirdOwned == true && !string.IsNullOrWhiteSpace(attribution.EventKind))
            {
                return attribution.EventKind.Trim();
            }
            return string.Empty;
        }

        private static bool StartsWithBlackbirdInstrumentation(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            string trimmed = value.Trim();
            return trimmed.StartsWith("SR71", StringComparison.OrdinalIgnoreCase) ||
                   trimmed.StartsWith("BK Instrument", StringComparison.OrdinalIgnoreCase);
        }

        private static bool LooksLikeSr71ImagePath(string? path) =>
            EventDetailFormatting.IsSr71Module(EventDetailFormatting.ModuleNameFromPath(path ?? string.Empty));

        private static string NormalizeDisplayText(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            string trimmed = value.Trim();
            return trimmed is "-" or "N/A" ? string.Empty : trimmed;
        }

        private static string DescribeProtectionAcronym(uint protect)
        {
            uint baseProtect = protect & 0xFFu;
            string label = baseProtect switch {
                0x01 => "NA",
                0x02 => "R",
                0x04 => "RW",
                0x08 => "W+C",
                0x10 => "X",
                0x20 => "RX",
                0x40 => "RWX",
                0x80 => "X+W+C",
                _ => string.Empty
            };

            if ((protect & 0x100u) != 0)
            {
                label = AppendProtectionFlag(label, "G");
            }
            if ((protect & 0x200u) != 0)
            {
                label = AppendProtectionFlag(label, "NC");
            }
            if ((protect & 0x400u) != 0)
            {
                label = AppendProtectionFlag(label, "WC");
            }

            return label;
        }

        private static string AppendProtectionFlag(string current, string suffix)
        {
            if (string.IsNullOrWhiteSpace(current))
            {
                return suffix;
            }

            return $"{current}|{suffix}";
        }

        private static uint ResolveThreadTidForPage(MemoryPageSample page, string category,
                                                    IReadOnlyList<ThreadMemoryRange> threadRanges)
        {
            if (threadRanges.Count == 0 || string.IsNullOrWhiteSpace(category))
            {
                return 0;
            }

            bool wantsStack = category.Contains("Thread Stack", StringComparison.OrdinalIgnoreCase);
            bool wantsTeb = category.Equals("TEB", StringComparison.OrdinalIgnoreCase);
            if (!wantsStack && !wantsTeb)
            {
                return 0;
            }

            ulong pageBase = page.BaseAddress;
            ulong pageEnd = pageBase + page.RegionSize;
            if (pageEnd <= pageBase)
            {
                pageEnd = ulong.MaxValue;
            }

            foreach (ThreadMemoryRange range in threadRanges)
            {
                ulong rangeBase = wantsStack ? range.StackLimit : range.TebAddress;
                ulong rangeSize =
                    wantsStack ? (range.StackBase > range.StackLimit ? range.StackBase - range.StackLimit : 0) : 0x2000;
                if (rangeBase == 0 || rangeSize == 0)
                {
                    continue;
                }

                ulong rangeEnd = rangeBase + rangeSize;
                if (rangeEnd <= rangeBase)
                {
                    rangeEnd = ulong.MaxValue;
                }

                if (pageBase < rangeEnd && rangeBase < pageEnd)
                {
                    return range.Tid;
                }
            }

            return 0;
        }

        private uint ResolveThreadTidForAttribution(MemoryRegionAttributionSample? attribution)
        {
            if (attribution == null)
            {
                return 0;
            }

            if (attribution.ThreadId != 0)
            {
                return attribution.ThreadId;
            }

            uint targetPid = _pid > 0 ? unchecked((uint)_pid) : attribution.TargetPid;
            if (attribution.ActorTid != 0 && (attribution.ActorPid == targetPid ||
                                              (attribution.ActorPid == 0 && attribution.TargetPid == targetPid)))
            {
                return attribution.ActorTid;
            }

            return 0;
        }

        private static List<ThreadMemoryRange> BuildThreadMemoryRanges(int pid)
        {
            const uint processQuery = 0x0400;
            const uint processVmRead = 0x0010;
            const uint processQueryLimited = 0x1000;

            if (pid <= 0)
            {
                return new List<ThreadMemoryRange>();
            }

            try
            {
                using Process process = Process.GetProcessById(pid);
                IntPtr processHandle = Kernel32Native.OpenProcess(processQuery | processVmRead | processQueryLimited,
                                                                  false, unchecked((uint)pid));
                if (processHandle == IntPtr.Zero)
                {
                    return new List<ThreadMemoryRange>();
                }

                var ranges = new List<ThreadMemoryRange>();
                try
                {
                    foreach (ProcessThread thread in process.Threads)
                    {
                        IntPtr threadHandle = OpenThread(ThreadQueryInformation | ThreadQueryLimitedInformation, false,
                                                         unchecked((uint)thread.Id));
                        if (threadHandle == IntPtr.Zero)
                        {
                            continue;
                        }

                        try
                        {
                            if (!TryGetThreadMemoryRange(processHandle, threadHandle, out ulong tebAddress,
                                                         out ulong stackBase, out ulong stackLimit))
                            {
                                continue;
                            }

                            ranges.Add(
                                new ThreadMemoryRange(unchecked((uint)thread.Id), tebAddress, stackBase, stackLimit));
                        }
                        finally
                        {
                            _ = Kernel32Native.CloseHandle(threadHandle);
                        }
                    }
                }
                finally
                {
                    _ = Kernel32Native.CloseHandle(processHandle);
                }

                return ranges;
            }
            catch
            {
                return new List<ThreadMemoryRange>();
            }
        }

        private static bool TryGetThreadMemoryRange(IntPtr processHandle, IntPtr threadHandle, out ulong tebAddress,
                                                    out ulong stackBase, out ulong stackLimit)
        {
            tebAddress = 0;
            stackBase = 0;
            stackLimit = 0;

            int status = NtQueryInformationThread(threadHandle, 0, out THREAD_BASIC_INFORMATION tbi,
                                                  Marshal.SizeOf<THREAD_BASIC_INFORMATION>(), out _);
            if (status != 0 || tbi.TebBaseAddress == IntPtr.Zero)
            {
                return false;
            }

            tebAddress = unchecked((ulong)tbi.TebBaseAddress.ToInt64());
            byte[] tibBuffer = new byte[Marshal.SizeOf<NT_TIB64>()];
            if (!ReadProcessMemory(processHandle, tbi.TebBaseAddress, tibBuffer, tibBuffer.Length,
                                   out IntPtr bytesRead) ||
                bytesRead.ToInt64() < tibBuffer.Length)
            {
                return tebAddress != 0;
            }

            GCHandle handle = GCHandle.Alloc(tibBuffer, GCHandleType.Pinned);
            try
            {
                NT_TIB64 tib = Marshal.PtrToStructure<NT_TIB64>(handle.AddrOfPinnedObject());
                stackBase = tib.StackBase;
                stackLimit = tib.StackLimit;
            }
            finally
            {
                handle.Free();
            }

            return true;
        }

        private static string DetermineMemoryHighlightBand(string category)
        {
            if (string.IsNullOrWhiteSpace(category))
            {
                return string.Empty;
            }

            string normalized = category.Trim();
            if (normalized.StartsWith("SR71", StringComparison.OrdinalIgnoreCase))
            {
                return "Runtime";
            }

            if (normalized.Contains("Thread Stack", StringComparison.OrdinalIgnoreCase))
            {
                return "ThreadStack";
            }

            if (normalized.Equals("Process Heap", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("Heap", StringComparison.OrdinalIgnoreCase) ||
                normalized.EndsWith(" Heap", StringComparison.OrdinalIgnoreCase))
            {
                return "Heap";
            }

            if (normalized.Contains("PEB", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("TEB", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("ApiSet", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("CodePage", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Activation Context", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Assembly Storage", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("GDI", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Shared Data", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("CSR", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Shim", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("AppCompat", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Process Parameters", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Process Heaps Array", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Loader Lock", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Patch Loader", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("CHPEV2", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("WER", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("LEAP_SECOND", StringComparison.OrdinalIgnoreCase))
            {
                return "Anchor";
            }

            if (normalized.Contains("Telemetry", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("Image Header Hash", StringComparison.OrdinalIgnoreCase))
            {
                return "Runtime";
            }

            return string.Empty;
        }

        private static string DetermineMemoryHighlightLabel(string category, string highlightBand)
        {
            if (highlightBand.Equals("ThreadStack", StringComparison.OrdinalIgnoreCase))
            {
                return "STACK";
            }

            if (highlightBand.Equals("Heap", StringComparison.OrdinalIgnoreCase))
            {
                return "HEAP";
            }

            if (highlightBand.Equals("Anchor", StringComparison.OrdinalIgnoreCase))
            {
                return "CORE";
            }

            if (highlightBand.Equals("Runtime", StringComparison.OrdinalIgnoreCase))
            {
                return "RUNTIME";
            }

            if (!string.IsNullOrWhiteSpace(category) && category.Contains("Shared", StringComparison.OrdinalIgnoreCase))
            {
                return "SHARED";
            }

            return string.Empty;
        }
    }
}
