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
        private ImageCodeScanResult? TryScanLoadedImage(string? requestedImagePath, string phase)
        {
            if (!TryResolveProcessMainImage((uint)_targetPid, requestedImagePath, out string imagePath,
                                            out ulong imageBase, out int moduleSize, out string resolveError))
            {
                _log?.Invoke($"packer image scan skipped pid={_targetPid} phase={phase}: {resolveError}");
                return null;
            }

            if (!PeImageLayout.TryLoad(imagePath, out PeImageLayout? layout, out string parseError) || layout == null)
            {
                _log?.Invoke($"packer image scan skipped pid={_targetPid} image={imagePath}: {parseError}");
                return null;
            }

            PeSection? entrySection = layout.FindSection(layout.AddressOfEntryPoint);
            PeSection? expectedSection = layout.FindExpectedEntrypointSection();
            bool entryOutsideExpected = layout.AddressOfEntryPoint != 0 &&
                                        !IsEntrypointInsideExpectedSection(layout.AddressOfEntryPoint, expectedSection);

            var comparisons = new List<ImageSectionComparison>(layout.Sections.Count);
            foreach (PeSection section in layout.Sections)
            {
                bool compareSection = section.IsExecutable || IsCanonicalTextSection(section) ||
                                      ReferenceEquals(section, entrySection) ||
                                      ReferenceEquals(section, expectedSection);
                if (!compareSection)
                {
                    continue;
                }

                ImageSectionComparison? comparison = TryCompareLoadedSection(imagePath, imageBase, section);
                if (comparison != null)
                {
                    comparisons.Add(comparison);
                }
            }

            ImageStringDiff stringDiff = BuildImageStringDiff(imagePath, imageBase, layout);
            return new ImageCodeScanResult(phase, imagePath, imageBase, moduleSize, layout, entrySection,
                                           expectedSection, entryOutsideExpected, comparisons.ToArray(), stringDiff);
        }

        private static bool TryResolveProcessMainImage(uint pid, string? requestedImagePath, out string imagePath,
                                                       out ulong imageBase, out int moduleSize, out string error)
        {
            imagePath = string.Empty;
            imageBase = 0;
            moduleSize = 0;
            error = string.Empty;

            try
            {
                using Process process = Process.GetProcessById(unchecked((int)pid));
                string requestedFullPath = NormalizePathForCompare(requestedImagePath);
                try
                {
                    ProcessModule? main = process.MainModule;
                    if (main != null)
                    {
                        imagePath = SafeModuleFileName(main);
                        imageBase = unchecked((ulong)main.BaseAddress.ToInt64());
                        moduleSize = main.ModuleMemorySize;
                    }
                }
                catch
                {
                }

                if (!string.IsNullOrWhiteSpace(requestedFullPath))
                {
                    try
                    {
                        foreach (ProcessModule module in process.Modules.Cast<ProcessModule>().Take(2048))
                        {
                            string modulePath = SafeModuleFileName(module);
                            if (!PathsEqual(modulePath, requestedFullPath))
                            {
                                continue;
                            }

                            imagePath = modulePath;
                            imageBase = unchecked((ulong)module.BaseAddress.ToInt64());
                            moduleSize = module.ModuleMemorySize;
                            break;
                        }
                    }
                    catch
                    {
                    }
                }

                if (string.IsNullOrWhiteSpace(imagePath) && !string.IsNullOrWhiteSpace(requestedImagePath))
                {
                    imagePath = requestedImagePath.Trim();
                }

                if (imageBase == 0)
                {
                    error = "main module base address unavailable";
                    return false;
                }

                if (string.IsNullOrWhiteSpace(imagePath) || !File.Exists(imagePath))
                {
                    error = string.IsNullOrWhiteSpace(imagePath) ? "main module path unavailable"
                                                                 : $"main module path not readable: {imagePath}";
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private ImageSectionComparison? TryCompareLoadedSection(string imagePath, ulong imageBase, PeSection section)
        {
            int compareBytes =
                (int)Math.Min(MaxImageSectionCompareBytes, Math.Min(section.RawDataSize, section.VirtualSpan));
            if (compareBytes < MinImageSectionCompareBytes || section.RawDataPointer == 0)
            {
                return null;
            }

            if (!TryReadFileRange(imagePath, section.RawDataPointer, compareBytes, out byte[] fileBytes,
                                  out string fileError))
            {
                _log?.Invoke(
                    $"packer image scan section read failed pid={_targetPid} section={section.Name}: {fileError}");
                return null;
            }

            if (!ReadProcessBytes((uint)_targetPid, imageBase + section.VirtualAddress, fileBytes.Length,
                                  out byte[] memoryBytes, out string memoryError))
            {
                _log?.Invoke(
                    $"packer image scan memory read failed pid={_targetPid} section={section.Name}: {memoryError}");
                return null;
            }

            int compared = Math.Min(fileBytes.Length, memoryBytes.Length);
            if (compared < MinImageSectionCompareBytes)
            {
                return null;
            }

            int changed = CountChangedBytes(fileBytes, memoryBytes, compared);
            double fileEntropy = ComputeEntropy(fileBytes, compared);
            double memoryEntropy = ComputeEntropy(memoryBytes, compared);
            string memoryHash = ComputeSha256Hex(memoryBytes.AsSpan(0, compared).ToArray());
            return new ImageSectionComparison(section, compared, changed, changed / (double)compared, fileEntropy,
                                              memoryEntropy, memoryHash);
        }

        private ImageStringDiff BuildImageStringDiff(string imagePath, ulong imageBase, PeImageLayout layout)
        {
            var fileStrings = new Dictionary<string, ImageStringHit>(StringComparer.Ordinal);
            var memoryStrings = new Dictionary<string, ImageStringHit>(StringComparer.Ordinal);

            CollectImageSectionStrings(imagePath, imageBase, layout, fromMemory: false, fileStrings);
            CollectImageSectionStrings(imagePath, imageBase, layout, fromMemory: true, memoryStrings);

            ImageStringHit[] memoryOnly = memoryStrings.Where(pair => !fileStrings.ContainsKey(pair.Key))
                                              .Select(pair => pair.Value)
                                              .OrderBy(hit => hit.SectionName, StringComparer.OrdinalIgnoreCase)
                                              .ThenBy(hit => hit.Rva)
                                              .ThenBy(hit => hit.Value, StringComparer.Ordinal)
                                              .Take(MaxExtractedStringsPerImage)
                                              .ToArray();

            return new ImageStringDiff(fileStrings.Count, memoryStrings.Count, memoryOnly);
        }

        private void CollectImageSectionStrings(string imagePath, ulong imageBase, PeImageLayout layout,
                                                bool fromMemory, Dictionary<string, ImageStringHit> hits)
        {
            int scannedBytes = 0;
            foreach (PeSection section in layout.Sections)
            {
                if (hits.Count >= MaxExtractedStringsPerImage || scannedBytes >= MaxStringTotalScanBytes ||
                    !ShouldScanSectionForStrings(section))
                {
                    continue;
                }

                int available = fromMemory ? (int)Math.Min(section.VirtualSpan, int.MaxValue)
                                           : (int)Math.Min(section.RawDataSize, int.MaxValue);
                int requested =
                    Math.Min(MaxStringSectionScanBytes, Math.Min(available, MaxStringTotalScanBytes - scannedBytes));
                if (requested < MinStringSectionScanBytes)
                {
                    continue;
                }

                byte[] bytes;
                string error;
                if (fromMemory)
                {
                    if (!ReadProcessBytes((uint)_targetPid, imageBase + section.VirtualAddress, requested, out bytes,
                                          out error))
                    {
                        _log?.Invoke(
                            $"string diff memory read failed pid={_targetPid} section={section.Name}: {error}");
                        continue;
                    }
                }
                else
                {
                    if (section.RawDataPointer == 0 ||
                        !TryReadFileRange(imagePath, section.RawDataPointer, requested, out bytes, out error))
                    {
                        continue;
                    }
                }

                scannedBytes += bytes.Length;
                ExtractStringsFromBuffer(bytes, section, hits);
            }
        }

        private static bool ShouldScanSectionForStrings(PeSection section)
        {
            string name = section.Name.Trim();
            if (name.Equals(".reloc", StringComparison.OrdinalIgnoreCase) ||
                name.Equals(".pdata", StringComparison.OrdinalIgnoreCase) ||
                name.Equals(".xdata", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return section.IsExecutable || section.ContainsCode || section.ContainsInitializedData ||
                   !IsCommonPeSectionName(name) || name.IndexOf("data", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   name.IndexOf("text", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static void ExtractStringsFromBuffer(byte[] bytes, PeSection section,
                                                     Dictionary<string, ImageStringHit> hits)
        {
            ExtractAsciiStrings(bytes, section, hits);
            ExtractUtf16Strings(bytes, section, hits);
        }

        private static void ExtractAsciiStrings(byte[] bytes, PeSection section,
                                                Dictionary<string, ImageStringHit> hits)
        {
            int start = -1;
            for (int i = 0; i <= bytes.Length; i += 1)
            {
                bool printable = i < bytes.Length && IsPrintableAscii(bytes[i]);
                if (printable)
                {
                    if (start < 0)
                    {
                        start = i;
                    }
                    continue;
                }

                if (start >= 0 && i - start >= MinExtractedStringChars)
                {
                    AddStringHit(Encoding.ASCII.GetString(bytes, start, i - start), section,
                                 section.VirtualAddress + (ulong)start, "ascii", hits);
                }

                start = -1;
            }
        }

        private static void ExtractUtf16Strings(byte[] bytes, PeSection section,
                                                Dictionary<string, ImageStringHit> hits)
        {
            for (int alignment = 0; alignment < 2; alignment += 1)
            {
                int start = -1;
                int chars = 0;
                for (int i = alignment; i + 1 < bytes.Length; i += 2)
                {
                    bool printable = bytes[i + 1] == 0 && IsPrintableAscii(bytes[i]);
                    if (printable)
                    {
                        if (start < 0)
                        {
                            start = i;
                        }
                        chars += 1;
                        continue;
                    }

                    if (start >= 0 && chars >= MinExtractedStringChars)
                    {
                        AddStringHit(BuildUtf16String(bytes, start, chars), section,
                                     section.VirtualAddress + (ulong)start, "utf16le", hits);
                    }

                    start = -1;
                    chars = 0;
                }

                if (start >= 0 && chars >= MinExtractedStringChars)
                {
                    AddStringHit(BuildUtf16String(bytes, start, chars), section, section.VirtualAddress + (ulong)start,
                                 "utf16le", hits);
                }
            }
        }

        private static string BuildUtf16String(byte[] bytes, int start, int charCount)
        {
            int capped = Math.Min(charCount, MaxExtractedStringChars + 1);
            char[] chars = new char[capped];
            for (int i = 0; i < capped; i += 1)
            {
                chars[i] = (char)bytes[start + (i * 2)];
            }

            return new string(chars);
        }

        private static void AddStringHit(string value, PeSection section, ulong rva, string encoding,
                                         Dictionary<string, ImageStringHit> hits)
        {
            if (ContainsOwnToolString(value))
            {
                return;
            }

            string normalized = NormalizeExtractedString(value);
            if (ShouldDropExtractedString(normalized))
            {
                return;
            }

            if (!hits.ContainsKey(normalized))
            {
                if (hits.Count >= MaxExtractedStringsPerImage)
                {
                    return;
                }

                hits[normalized] = new ImageStringHit(normalized, section.Name, rva, encoding);
            }
        }

        private static string NormalizeExtractedString(string value)
        {
            string trimmed = value.Trim();
            if (trimmed.Length <= MaxExtractedStringChars)
            {
                return trimmed;
            }

            return trimmed[..MaxExtractedStringChars] + "...";
        }

        private static bool ShouldDropExtractedString(string value)
        {
            if (value.Length < MinExtractedStringChars || ContainsOwnToolString(value))
            {
                return true;
            }

            int alphaNumeric = 0;
            var distinct = new HashSet<char>();
            foreach (char ch in value)
            {
                if (char.IsLetterOrDigit(ch))
                {
                    alphaNumeric += 1;
                }

                if (distinct.Count <= 4)
                {
                    distinct.Add(ch);
                }
            }

            if (alphaNumeric < 2)
            {
                return true;
            }

            return value.Length >= 8 && distinct.Count <= 2;
        }

        private static bool ContainsOwnToolString(string value)
        {
            for (int i = 0; i < OwnToolStringNeedles.Length; i += 1)
            {
                if (value.IndexOf(OwnToolStringNeedles[i], StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool HasFailedHookStatus(BrokerEtwEventView view)
        {
            if (view.Family != BlackbirdNative.IpcEtwFamilyUserHook)
            {
                return false;
            }

            Dictionary<string, string> fields = EventDetailsParsing.ParseRawFields(view.Reason);
            return TryReadNtStatus(fields, out int status, "status", "queryStatus", "callStatus") && status < 0;
        }

        private static bool TryReadNtStatus(IReadOnlyDictionary<string, string> fields, out int status,
                                            params string[] keys)
        {
            foreach (string key in keys)
            {
                if (fields.TryGetValue(key, out string? text) && TryParseNtStatus(text, out status))
                {
                    return true;
                }
            }

            status = 0;
            return false;
        }

        private static bool TryParseNtStatus(string? text, out int status)
        {
            status = 0;
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            string compact = text.Trim();
            if (compact.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                if (uint.TryParse(compact[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture,
                                  out uint hexValue))
                {
                    status = unchecked((int)hexValue);
                    return true;
                }

                return false;
            }

            if (int.TryParse(compact, NumberStyles.Integer, CultureInfo.InvariantCulture, out status))
            {
                return true;
            }

            if (uint.TryParse(compact, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint unsignedValue))
            {
                status = unchecked((int)unsignedValue);
                return true;
            }

            return false;
        }

        private static bool IsPrintableAscii(byte value) => value >= 0x20 && value <= 0x7E;
    }
}
