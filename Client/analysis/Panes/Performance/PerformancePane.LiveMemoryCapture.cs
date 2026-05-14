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
        private void UpdateLiveDataOverlays()
        {
            string threadMessage = "No thread data in the selected range.";
            string memoryMessage = "No memory data in the selected range.";
            bool historicalDataVisible = HasHistoricalDataForObservedTime();

            if (!_processLiveDataAvailable)
            {
                if (_historySamples.Count == 0)
                {
                    threadMessage = "Live capture unavailable.";
                    memoryMessage = "Live capture unavailable.";
                }
                else if (!historicalDataVisible)
                {
                    threadMessage = "No captured thread data at the selected time.";
                    memoryMessage = "No captured memory data at the selected time.";
                }
                else
                {
                    threadMessage = "Live capture unavailable.";
                    memoryMessage = "Live capture unavailable.";
                }
            }

            if (ThreadsNoDataOverlay != null)
            {
                bool hasThreadData =
                    TopThreads.Count > 0 || ThreadLifecycleRows.Count > 0 || _threadLifecycleHistory.Count > 0;
                bool showThreadsNoData = !hasThreadData;
                ThreadsNoDataOverlay.Visibility = showThreadsNoData ? Visibility.Visible : Visibility.Collapsed;
                if (ThreadsNoDataMessageBlock != null)
                {
                    ThreadsNoDataMessageBlock.Text = threadMessage;
                }
            }

            if (MemoryNoDataOverlay != null)
            {
                bool hasMemoryData = MemoryAttributionRows.Count > 0 || MemoryMetrics.Count > 0 ||
                                     (_lastSample?.MemoryPages.Count ?? 0) > 0;
                bool showMemoryNoData = !hasMemoryData;
                MemoryNoDataOverlay.Visibility = showMemoryNoData ? Visibility.Visible : Visibility.Collapsed;
                if (MemoryTreemapNoData != null && showMemoryNoData)
                {
                    MemoryTreemapNoData.Visibility = Visibility.Collapsed;
                }
                if (MemoryNoDataMessageBlock != null)
                {
                    MemoryNoDataMessageBlock.Text = memoryMessage;
                }
            }

            if (NetworkNoDataOverlay != null)
            {
                bool hasTrafficData =
                    _historySamples.Any(sample => sample.NetInBytesPerSec > 0.01 || sample.NetOutBytesPerSec > 0.01 ||
                                                  sample.NetPacketsPerSec > 0.01);
                bool hasPeerData = NetworkPeers.Count > 0;
                bool showNetworkNoData = _showNetworkPeers ? !hasPeerData : !hasTrafficData;
                NetworkNoDataOverlay.Visibility = showNetworkNoData ? Visibility.Visible : Visibility.Collapsed;
            }
        }

        private static MemoryMetricRow CloneMetric(MemoryMetricRow src)
        {
            return new MemoryMetricRow { Metric = src.Metric, Value = src.Value, BytesValue = src.BytesValue };
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes >= 1024L * 1024 * 1024)
                return $"{bytes / (1024d * 1024 * 1024):0.##} GB";
            if (bytes >= 1024L * 1024)
                return $"{bytes / (1024d * 1024):0.##} MB";
            if (bytes >= 1024)
                return $"{bytes / 1024d:0.##} KB";
            return $"{bytes} B";
        }

        private static List<MemoryPageSample> CaptureLiveMemoryPages(Process process)
        {
            const uint memCommit = 0x1000;
            const uint processQuery = 0x0400;
            const uint processVmRead = 0x0010;
            const uint processQueryLimited = 0x1000;

            IntPtr hProcess = Kernel32Native.OpenProcess(processQuery | processVmRead | processQueryLimited, false,
                                                         unchecked((uint)process.Id));
            if (hProcess == IntPtr.Zero)
            {
                return new List<MemoryPageSample>();
            }

            var pages = new List<MemoryPageSample>(768);
            List<MemoryModuleMapEntry> modules = CaptureModuleMap(process);
            try
            {
                ulong address = 0;
                ulong maxAddress = Environment.Is64BitProcess ? 0x00007FFF_FFFFFFFFul : uint.MaxValue;
                nuint mbiSize = (nuint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
                var mappedPathCache = new Dictionary<ulong, string>();

                while (address < maxAddress && pages.Count < 1536)
                {
                    nuint ret = VirtualQueryEx(hProcess, (nint)address, out MEMORY_BASIC_INFORMATION mbi, mbiSize);
                    if (ret == 0)
                        break;

                    ulong regionSize = (ulong)mbi.RegionSize;
                    if (regionSize == 0)
                        break;

                    if (mbi.State == memCommit)
                    {
                        ulong baseAddress = (ulong)mbi.BaseAddress;
                        ulong allocationBase = (ulong)mbi.AllocationBase;
                        pages.Add(new MemoryPageSample {
                            BaseAddress = baseAddress, AllocationBase = allocationBase, RegionSize = regionSize,
                            State = mbi.State, Protect = mbi.Protect, AllocationProtect = mbi.AllocationProtect,
                            Type = mbi.Type, StateLabel = EventDetailFormatting.DescribeMemoryState(mbi.State),
                            ProtectLabel = EventDetailFormatting.DescribeMemoryProtection(mbi.Protect),
                            TypeLabel = EventDetailFormatting.DescribeMemoryType(mbi.Type),
                            BackingPath =
                                ResolveMappedBackingPath(hProcess, baseAddress, allocationBase, mappedPathCache),
                            ModulePath = ResolveMappedModulePath(modules, baseAddress, allocationBase, regionSize)
                        });
                        pages[^1].Sr71Owned = LooksLikeSr71ImagePath(pages[^1].ModulePath) ||
                                              LooksLikeSr71ImagePath(pages[^1].BackingPath);
                        if (pages[^1].Sr71Owned)
                        {
                            pages[^1].Sr71OwnerTag = "SR71 Instrumentation";
                        }
                        ApplyWorkingSetAttributes(hProcess, pages[^1]);
                        pages[^1].Category = BuildMemoryCategory(pages[^1]);
                    }

                    ulong next = (ulong)mbi.BaseAddress + regionSize;
                    if (next <= address)
                        break;

                    address = next;
                }
            }
            finally
            {
                _ = Kernel32Native.CloseHandle(hProcess);
            }

            return pages.OrderByDescending(x => x.RegionSize).ThenBy(x => x.BaseAddress).Take(768).ToList();
        }

        private static List<MemoryModuleMapEntry> CaptureModuleMap(Process process)
        {
            var rows = new List<MemoryModuleMapEntry>(128);
            try
            {
                foreach (ProcessModule module in process.Modules)
                {
                    ulong baseAddress = unchecked((ulong)module.BaseAddress.ToInt64());
                    ulong size = (ulong)Math.Max(module.ModuleMemorySize, 0);
                    if (baseAddress == 0 || size == 0)
                    {
                        continue;
                    }

                    rows.Add(new MemoryModuleMapEntry(baseAddress, baseAddress + size,
                                                      module.ModuleName ?? string.Empty,
                                                      module.FileName ?? string.Empty));
                }
            }
            catch
            {
            }

            rows.Sort((left, right) => left.BaseAddress.CompareTo(right.BaseAddress));
            return rows;
        }

        private static string ResolveMappedModulePath(IReadOnlyList<MemoryModuleMapEntry> modules, ulong baseAddress,
                                                      ulong allocationBase, ulong regionSize)
        {
            ulong regionEnd = baseAddress + regionSize;
            if (regionEnd <= baseAddress)
            {
                regionEnd = ulong.MaxValue;
            }

            for (int i = 0; i < modules.Count; i += 1)
            {
                MemoryModuleMapEntry module = modules[i];
                if ((allocationBase != 0 && allocationBase == module.BaseAddress) ||
                    (baseAddress >= module.BaseAddress && baseAddress < module.EndAddress) ||
                    (module.BaseAddress >= baseAddress && module.BaseAddress < regionEnd))
                {
                    return module.Path;
                }
            }

            return string.Empty;
        }

        private static string ResolveMappedBackingPath(IntPtr processHandle, ulong baseAddress, ulong allocationBase,
                                                       Dictionary<ulong, string> cache)
        {
            ulong key = allocationBase != 0 ? allocationBase : baseAddress;
            if (key == 0)
            {
                return string.Empty;
            }

            if (cache.TryGetValue(key, out string? existing))
            {
                return existing;
            }

            string mappedPath = QueryMappedFilename(processHandle, key);
            cache[key] = mappedPath;
            return mappedPath;
        }

        private static string QueryMappedFilename(IntPtr processHandle, ulong address)
        {
            const int memoryMappedFilenameInformation = 2;
            const int bufferBytes = 32768;

            if (processHandle == IntPtr.Zero || address == 0)
            {
                return string.Empty;
            }

            IntPtr buffer = Marshal.AllocHGlobal(bufferBytes);
            try
            {
                int status =
                    NtQueryVirtualMemory(processHandle, unchecked((nint)address), memoryMappedFilenameInformation,
                                         buffer, (uint)bufferBytes, out uint _);
                if (status < 0)
                {
                    return string.Empty;
                }

                UNICODE_STRING text = Marshal.PtrToStructure<UNICODE_STRING>(buffer);
                if (text.Buffer == IntPtr.Zero || text.Length == 0)
                {
                    return string.Empty;
                }

                return Marshal.PtrToStringUni(text.Buffer, text.Length / 2) ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string BuildMemoryCategory(MemoryPageSample page)
        {
            string specialUse = TryClassifySpecialUse(page);
            if (!string.IsNullOrWhiteSpace(specialUse))
            {
                return specialUse;
            }
            if (IsSr71OwnedMemoryPage(page, null))
            {
                return LooksLikeSr71ImagePath(page.ModulePath) || LooksLikeSr71ImagePath(page.BackingPath)
                           ? "SR71 Instrumentation"
                           : "BK Instrumentation";
            }

            uint baseProtect = page.Protect & 0xFFu;
            bool executable = baseProtect == 0x10 || baseProtect == 0x20 || baseProtect == 0x40 || baseProtect == 0x80;
            bool writable = baseProtect == 0x04 || baseProtect == 0x08 || baseProtect == 0x40 || baseProtect == 0x80;

            string typeLabel = page.Type switch {
                0x20000 => "Private",
                0x40000 => "Mapped",
                0x1000000 => "Image",
                _ => "Unknown"
            };

            if (page.WorkingSetValid && !page.WorkingSetShared && (page.Type == 0x40000 || page.Type == 0x1000000))
            {
                typeLabel += " Private Copy";
            }

            if (executable && writable)
                return $"{typeLabel} RWX";
            if (executable)
                return $"{typeLabel} RX";
            if (writable)
                return $"{typeLabel} RW";
            return typeLabel;
        }

        private static string TryClassifySpecialUse(MemoryPageSample page)
        {
            string path = $"{page.ModulePath}|{page.BackingPath}".ToLowerInvariant();
            bool privateWritable = page.Type == 0x20000 && IsWritableProtect(page.Protect);
            bool guard = (page.Protect & 0x100u) != 0;
            if (path.Contains("apiset"))
            {
                return "ApiSetMap";
            }
            if (path.Contains("apphelp") || path.Contains(".sdb") || path.Contains("shim"))
            {
                return "Shim Data";
            }
            if (path.Contains("winsxs") || path.Contains("activation") || path.Contains("actctx"))
            {
                return "Activation Context Data";
            }
            if (path.Contains("\\nls\\") || path.Contains("codepage"))
            {
                return "CodePage Data";
            }
            if (path.Contains("csr"))
            {
                return "CSRSS ReadOnly Shared Memory";
            }
            if (path.Contains("gdi"))
            {
                return "GDI Shared Handle Table";
            }
            if (path.Contains("wer"))
            {
                return "WER Registration Data";
            }
            if (path.Contains("telemetry"))
            {
                return "Telemetry Coverage";
            }
            if (guard && privateWritable)
            {
                return "Thread Stack Guard";
            }
            if (privateWritable && page.RegionSize >= 0x20000 && page.RegionSize <= 0x800000)
            {
                return "Heap";
            }

            return string.Empty;
        }

        private static void ApplyWorkingSetAttributes(IntPtr processHandle, MemoryPageSample page)
        {
            if (processHandle == IntPtr.Zero || page.BaseAddress == 0)
            {
                return;
            }

            var entries =
                new[] { new PSAPI_WORKING_SET_EX_INFORMATION { VirtualAddress = unchecked((IntPtr)page.BaseAddress) } };

            int size = Marshal.SizeOf<PSAPI_WORKING_SET_EX_INFORMATION>();
            if (!QueryWorkingSetEx(processHandle, entries, size))
            {
                return;
            }

            ulong flags = entries[0].VirtualAttributes.ToUInt64();
            page.WorkingSetValid = (flags & 0x1UL) != 0;
            page.WorkingSetShareCount = (uint)((flags >> 1) & 0x7UL);
            page.WorkingSetShared = ((flags >> 15) & 0x1UL) != 0;
            page.WorkingSetLocked = ((flags >> 22) & 0x1UL) != 0;
            page.WorkingSetLargePage = ((flags >> 23) & 0x1UL) != 0;
        }

        private static void AppendVadMetrics(Process process, List<MemoryMetricRow> rows)
        {
            const uint memCommit = 0x1000;
            const uint memPrivate = 0x20000;
            const uint memMapped = 0x40000;
            const uint memImage = 0x1000000;
            const uint pageNoAccess = 0x01;
            const uint pageReadOnly = 0x02;
            const uint pageReadWrite = 0x04;
            const uint pageExecuteRead = 0x20;
            const uint pageExecuteReadWrite = 0x40;
            const uint pageGuard = 0x100;

            const uint processQuery = 0x0400;
            const uint processVmRead = 0x0010;
            const uint processQueryLimited = 0x1000;

            IntPtr hProcess = Kernel32Native.OpenProcess(processQuery | processVmRead | processQueryLimited, false,
                                                         unchecked((uint)process.Id));
            if (hProcess == IntPtr.Zero)
                return;

            long regionCount = 0;
            long privateCount = 0;
            long imageCount = 0;
            long mappedCount = 0;
            ulong commitBytes = 0;
            ulong rwBytes = 0;
            ulong rxBytes = 0;
            ulong rwxBytes = 0;
            ulong guardBytes = 0;
            ulong roBytes = 0;

            try
            {
                ulong address = 0;
                ulong maxAddress = Environment.Is64BitProcess ? 0x00007FFF_FFFFFFFFul : uint.MaxValue;
                nuint mbiSize = (nuint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

                while (address < maxAddress)
                {
                    nuint ret = VirtualQueryEx(hProcess, (nint)address, out MEMORY_BASIC_INFORMATION mbi, mbiSize);
                    if (ret == 0)
                        break;

                    ulong regionSize = (ulong)mbi.RegionSize;
                    if (regionSize == 0)
                        break;

                    regionCount += 1;

                    if (mbi.State == memCommit)
                    {
                        commitBytes += regionSize;

                        if (mbi.Type == memPrivate)
                            privateCount += 1;
                        else if (mbi.Type == memImage)
                            imageCount += 1;
                        else if (mbi.Type == memMapped)
                            mappedCount += 1;

                        uint protect = mbi.Protect;
                        uint baseProtect = protect & 0xFFu;

                        if ((protect & pageGuard) != 0)
                            guardBytes += regionSize;

                        if (baseProtect == pageReadWrite)
                            rwBytes += regionSize;
                        else if (baseProtect == pageExecuteRead)
                            rxBytes += regionSize;
                        else if (baseProtect == pageExecuteReadWrite)
                            rwxBytes += regionSize;
                        else if (baseProtect == pageReadOnly || baseProtect == pageNoAccess)
                            roBytes += regionSize;
                    }

                    ulong next = (ulong)mbi.BaseAddress + regionSize;
                    if (next <= address)
                        break;

                    address = next;
                }
            }
            catch
            {
            }
            finally
            {
                _ = Kernel32Native.CloseHandle(hProcess);
            }

            rows.Add(new MemoryMetricRow { Metric = "VAD Regions", Value = regionCount.ToString(), BytesValue = null });
            rows.Add(new MemoryMetricRow { Metric = "VAD Commit", Value = FormatBytes((long)commitBytes),
                                           BytesValue = (long)commitBytes });
            rows.Add(new MemoryMetricRow { Metric = "VAD Private Regions", Value = privateCount.ToString(),
                                           BytesValue = null });
            rows.Add(
                new MemoryMetricRow { Metric = "VAD Image Regions", Value = imageCount.ToString(), BytesValue = null });
            rows.Add(new MemoryMetricRow { Metric = "VAD Mapped Regions", Value = mappedCount.ToString(),
                                           BytesValue = null });
            rows.Add(new MemoryMetricRow { Metric = "Prot RW", Value = FormatBytes((long)rwBytes),
                                           BytesValue = (long)rwBytes });
            rows.Add(new MemoryMetricRow { Metric = "Prot RX", Value = FormatBytes((long)rxBytes),
                                           BytesValue = (long)rxBytes });
            rows.Add(new MemoryMetricRow { Metric = "Prot RWX", Value = FormatBytes((long)rwxBytes),
                                           BytesValue = (long)rwxBytes });
            rows.Add(new MemoryMetricRow { Metric = "Prot RO/NoAccess", Value = FormatBytes((long)roBytes),
                                           BytesValue = (long)roBytes });
            rows.Add(new MemoryMetricRow { Metric = "Prot Guard", Value = FormatBytes((long)guardBytes),
                                           BytesValue = (long)guardBytes });
        }
    }
}
