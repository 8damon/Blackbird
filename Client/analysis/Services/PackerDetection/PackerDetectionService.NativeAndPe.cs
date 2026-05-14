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

        private sealed class PeImageLayout
        {
            private PeImageLayout(string imagePath, uint addressOfEntryPoint, ulong preferredImageBase,
                                  uint sizeOfImage, IReadOnlyList<PeSection> sections)
            {
                ImagePath = imagePath;
                AddressOfEntryPoint = addressOfEntryPoint;
                PreferredImageBase = preferredImageBase;
                SizeOfImage = sizeOfImage;
                Sections = sections;
            }

            public string ImagePath { get; }
            public uint AddressOfEntryPoint { get; }
            public ulong PreferredImageBase { get; }
            public uint SizeOfImage { get; }
            public IReadOnlyList<PeSection> Sections { get; }

            public PeSection? FindSection(uint rva)
            {
                for (int i = 0; i < Sections.Count; i += 1)
                {
                    if (Sections[i].ContainsRva(rva))
                    {
                        return Sections[i];
                    }
                }

                return null;
            }

            public PeSection? FindExpectedEntrypointSection()
            {
                PeSection? canonical = Sections.FirstOrDefault(IsCanonicalTextSection);
                if (canonical != null)
                {
                    return canonical;
                }

                return Sections.FirstOrDefault(static section => section.IsExecutable && section.ContainsCode) ??
                       Sections.FirstOrDefault(static section => section.IsExecutable);
            }

            public static bool TryLoad(string imagePath, out PeImageLayout? layout, out string error)
            {
                layout = null;
                error = string.Empty;
                try
                {
                    using FileStream stream = new(imagePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    int headerBytes = (int)Math.Min(stream.Length, MaxPeHeaderBytes);
                    if (headerBytes < 0x100)
                    {
                        error = "file is too small to contain PE headers";
                        return false;
                    }

                    byte[] header = new byte[headerBytes];
                    int total = 0;
                    while (total < header.Length)
                    {
                        int read = stream.Read(header, total, header.Length - total);
                        if (read <= 0)
                        {
                            break;
                        }

                        total += read;
                    }

                    if (total < 0x100)
                    {
                        error = "could not read PE headers";
                        return false;
                    }

                    if (ReadUInt16(header, 0) != 0x5A4D)
                    {
                        error = "missing MZ header";
                        return false;
                    }

                    int peOffset = ReadInt32(header, 0x3C);
                    if (peOffset <= 0 || peOffset > header.Length - 0x18)
                    {
                        error = "invalid PE header offset";
                        return false;
                    }

                    if (ReadUInt32(header, peOffset) != 0x00004550)
                    {
                        error = "missing PE signature";
                        return false;
                    }

                    int fileHeaderOffset = peOffset + 4;
                    ushort sectionCount = ReadUInt16(header, fileHeaderOffset + 2);
                    ushort optionalHeaderSize = ReadUInt16(header, fileHeaderOffset + 16);
                    int optionalHeaderOffset = fileHeaderOffset + 20;
                    if (optionalHeaderOffset + optionalHeaderSize > header.Length || optionalHeaderSize < 0x60)
                    {
                        error = "optional header is truncated";
                        return false;
                    }

                    ushort magic = ReadUInt16(header, optionalHeaderOffset);
                    bool pe32Plus = magic == 0x20B;
                    if (!pe32Plus && magic != 0x10B)
                    {
                        error = $"unsupported optional header magic 0x{magic:X}";
                        return false;
                    }

                    uint addressOfEntryPoint = ReadUInt32(header, optionalHeaderOffset + 16);
                    ulong preferredImageBase = pe32Plus ? ReadUInt64(header, optionalHeaderOffset + 24)
                                                        : ReadUInt32(header, optionalHeaderOffset + 28);
                    uint sizeOfImage = ReadUInt32(header, optionalHeaderOffset + 56);
                    int sectionOffset = optionalHeaderOffset + optionalHeaderSize;
                    if (sectionCount > 96)
                    {
                        sectionCount = 96;
                    }

                    if (sectionOffset + (sectionCount * 40) > header.Length)
                    {
                        error = "section table is truncated";
                        return false;
                    }

                    var sections = new List<PeSection>(sectionCount);
                    for (int i = 0; i < sectionCount; i += 1)
                    {
                        int baseOffset = sectionOffset + (i * 40);
                        string name = ReadSectionName(header, baseOffset);
                        uint virtualSize = ReadUInt32(header, baseOffset + 8);
                        uint virtualAddress = ReadUInt32(header, baseOffset + 12);
                        uint rawDataSize = ReadUInt32(header, baseOffset + 16);
                        uint rawDataPointer = ReadUInt32(header, baseOffset + 20);
                        uint characteristics = ReadUInt32(header, baseOffset + 36);
                        sections.Add(new PeSection(name, virtualAddress, virtualSize, rawDataPointer, rawDataSize,
                                                   characteristics));
                    }

                    layout =
                        new PeImageLayout(imagePath, addressOfEntryPoint, preferredImageBase, sizeOfImage, sections);
                    return true;
                }
                catch (Exception ex)
                {
                    error = ex.Message;
                    return false;
                }
            }

            private static string ReadSectionName(byte[] buffer, int offset)
            {
                int length = 0;
                while (length < 8 && offset + length < buffer.Length && buffer[offset + length] != 0)
                {
                    length += 1;
                }

                return length == 0 ? "<unnamed>" : System.Text.Encoding.ASCII.GetString(buffer, offset, length);
            }

            private static ushort ReadUInt16(byte[] buffer, int offset) => BitConverter.ToUInt16(buffer, offset);
            private static uint ReadUInt32(byte[] buffer, int offset) => BitConverter.ToUInt32(buffer, offset);
            private static ulong ReadUInt64(byte[] buffer, int offset) => BitConverter.ToUInt64(buffer, offset);
            private static int ReadInt32(byte[] buffer, int offset) => BitConverter.ToInt32(buffer, offset);
        }

        private sealed class PeSection
        {
            public PeSection(string name, uint virtualAddress, uint virtualSize, uint rawDataPointer, uint rawDataSize,
                             uint characteristics)
            {
                Name = string.IsNullOrWhiteSpace(name) ? "<unnamed>" : name.Trim();
                VirtualAddress = virtualAddress;
                VirtualSize = virtualSize;
                RawDataPointer = rawDataPointer;
                RawDataSize = rawDataSize;
                Characteristics = characteristics;
            }

            public string Name { get; }
            public uint VirtualAddress { get; }
            public uint VirtualSize { get; }
            public uint RawDataPointer { get; }
            public uint RawDataSize { get; }
            public uint Characteristics { get; }
            public bool IsExecutable => (Characteristics & ImageScnMemExecute) != 0;
            public bool ContainsCode => (Characteristics & ImageScnCntCode) != 0;
            public bool ContainsInitializedData => (Characteristics & 0x00000040) != 0;
            public uint VirtualSpan => Math.Max(Math.Max(VirtualSize, RawDataSize), 1);
            public string RangeLabel => $"{Name}[0x{VirtualAddress:X}-0x{VirtualAddress + VirtualSpan:X})";

            public bool ContainsRva(uint rva)
            {
                uint span = VirtualSpan;
                return rva >= VirtualAddress && rva < VirtualAddress + span;
            }
        }

        private sealed record ImageCodeScanResult(string Phase, string ImagePath, ulong ImageBase, int ModuleSize,
                                                  PeImageLayout Layout, PeSection? EntrySection,
                                                  PeSection? ExpectedEntrySection, bool EntryPointOutsideExpected,
                                                  ImageSectionComparison[] SectionComparisons,
                                                  ImageStringDiff StringDiff)
        {
            public ulong EntryPointVa => ImageBase + Layout.AddressOfEntryPoint;
        }

        private sealed record ImageSectionComparison(PeSection Section, int ComparedBytes, int ChangedBytes,
                                                     double ChangeRatio, double FileEntropy, double MemoryEntropy,
                                                     string MemoryHash);

        private sealed record ImageStringDiff(int DiskStringCount, int MemoryStringCount,
                                              ImageStringHit[] MemoryOnlyStrings);

        private sealed record ImageStringHit(string Value, string SectionName, ulong Rva, string Encoding);

        private sealed class ProcessDumpMetadata
        {
            public string DetectionReason { get; init; } = string.Empty;
            public int TargetPid { get; init; }
            public string ImagePath { get; init; } = string.Empty;
            public string ImageBase { get; init; } = string.Empty;
            public string AddressOfEntryPoint { get; init; } = string.Empty;
            public long DumpBytes { get; init; }
            public string DumpPath { get; init; } = string.Empty;
            public string CaptureMethod { get; init; } = string.Empty;
        }

        private readonly record struct ProcessSnapshotDumpResult(bool Success, string Error, long DumpBytes,
                                                                 string CaptureMethod);
    }
}
