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
        private static bool ReadProcessBytes(uint processId, ulong baseAddress, int requestedBytes, out byte[] data,
                                             out string error)
        {
            return ReadProcessBytesUserMode(processId, baseAddress, requestedBytes, out data, out error);
        }

        private static bool ReadProcessBytesUserMode(uint processId, ulong baseAddress, int requestedBytes,
                                                     out byte[] data, out string error)
        {
            data = Array.Empty<byte>();
            error = string.Empty;
            if (processId == 0 || requestedBytes <= 0)
            {
                error = "invalid process id or read size";
                return false;
            }

            IntPtr processHandle = Kernel32Native.OpenProcess(
                ProcessVmRead | ProcessQueryInformation | ProcessQueryLimitedInformation, false, processId);
            if (processHandle == IntPtr.Zero || processHandle == new IntPtr(-1))
            {
                int err = Marshal.GetLastWin32Error();
                error = $"OpenProcess(PROCESS_VM_READ) failed win32={err} ({new Win32Exception(err).Message})";
                return false;
            }

            try
            {
                byte[] buffer = new byte[requestedBytes];
                int total = 0;
                while (total < requestedBytes)
                {
                    int chunk = Math.Min(ReadChunkBytes, requestedBytes - total);
                    var chunkBuffer = new byte[chunk];
                    bool ok =
                        Kernel32Native.ReadProcessMemory(processHandle, unchecked((IntPtr)(baseAddress + (ulong)total)),
                                                         chunkBuffer, chunk, out IntPtr bytesReadPtr);
                    int bytesRead = unchecked((int)bytesReadPtr.ToInt64());
                    if (!ok || bytesRead <= 0)
                    {
                        if (total > 0)
                        {
                            break;
                        }

                        int err = Marshal.GetLastWin32Error();
                        error = $"ReadProcessMemory failed win32={err} ({new Win32Exception(err).Message})";
                        return false;
                    }

                    int copy = Math.Min(bytesRead, chunk);
                    Buffer.BlockCopy(chunkBuffer, 0, buffer, total, copy);
                    total += copy;
                    if (copy < chunk)
                    {
                        break;
                    }
                }

                if (total <= 0)
                {
                    error = "ReadProcessMemory returned no bytes";
                    return false;
                }

                data = total == buffer.Length ? buffer : buffer[..total];
                return true;
            }
            finally
            {
                _ = Kernel32Native.CloseHandle(processHandle);
            }
        }

        private void MarkCandidateRejected(ulong baseAddress)
        {
            lock (_sync)
            {
                if (_candidates.TryGetValue(baseAddress, out CandidateRegion? candidate))
                {
                    candidate.DumpQueued = false;
                    candidate.DumpRejected = true;
                }
            }
        }

        private void MarkCandidateDumped(ulong baseAddress)
        {
            lock (_sync)
            {
                if (_candidates.TryGetValue(baseAddress, out CandidateRegion? candidate))
                {
                    candidate.Dumped = true;
                    candidate.DumpQueued = false;
                }
            }
        }

        private static bool TryOpenProcessForQuery(uint pid, out IntPtr handle, out string error)
        {
            error = string.Empty;
            handle = OpenProcess(ProcessQueryInformation | ProcessVmRead, false, pid);
            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            {
                int err = Marshal.GetLastWin32Error();
                error = $"OpenProcess failed err={err}";
                return false;
            }

            return true;
        }

        private static bool TryQueryMemory(IntPtr processHandle, ulong address, out MemoryBasicInformation64 mbi)
        {
            UIntPtr result = VirtualQueryEx(processHandle, new IntPtr(unchecked((long)address)), out mbi,
                                            new UIntPtr((uint)Marshal.SizeOf<MemoryBasicInformation64>()));
            return result != UIntPtr.Zero;
        }

        private bool TouchesTarget(params uint[] pids)
        {
            uint target = (uint)_targetPid;
            return pids.Any(pid => pid == target);
        }

        private bool IsTarget(uint pid) => pid == (uint)_targetPid;

        private static bool HasAnyTrait(uint value, uint mask) => (value & mask) != 0;

        private static bool ContainsAny(string? value, params string[] needles)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            return needles.Any(needle => value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static ulong NormalizeRegionKey(ulong address) => address == 0 ? 0 : address & PageMask;

        private static ulong NormalizeRegionSize(ulong observed, ulong current)
        {
            ulong value = observed == 0 ? current : observed;
            value = Math.Max(value, DefaultProbeRegionSize);
            return Math.Min(value, MaxCandidateRegionSize);
        }

        private static bool IsCommittedPrivateExecutable(uint state, uint type, uint protect)
        {
            return state == MemCommit && type == MemPrivate && IsExecutableProtection(protect);
        }

        private static bool IsExecutableProtection(uint protect)
        {
            uint baseProtect = protect & 0xFFu;
            return baseProtect is PageExecute or PageExecuteRead or PageExecuteReadWrite or PageExecuteWriteCopy;
        }

        private static bool IsDirectSyscallHandleSignal(uint handleFlags)
        {
            const uint syscallMismatch = 0x00002000;
            const uint stackSpoofSuspect = 0x00000800;
            return (handleFlags & (syscallMismatch | stackSpoofSuspect)) != 0;
        }

        private static bool LooksLikePeImage(byte[]? data, int length)
        {
            if (data == null || length < 0x40 || data.Length < 0x40)
            {
                return false;
            }

            int capped = Math.Min(length, data.Length);
            if (data[0] != 0x4D || data[1] != 0x5A)
            {
                return false;
            }

            int peOffset = BitConverter.ToInt32(data, 0x3C);
            return peOffset > 0 && peOffset <= capped - 4 && peOffset <= 0x1000 && data[peOffset] == 0x50 &&
                   data[peOffset + 1] == 0x45 && data[peOffset + 2] == 0x00 && data[peOffset + 3] == 0x00;
        }

        private static bool ContainsPackerMarker(byte[]? data, int length)
        {
            if (data == null || length <= 0)
            {
                return false;
            }

            ReadOnlySpan<byte> bytes = data.AsSpan(0, Math.Min(length, data.Length));
            return ContainsAscii(bytes, "UPX!") || ContainsAscii(bytes, "UPX0") || ContainsAscii(bytes, "UPX1") ||
                   ContainsAscii(bytes, "VMProtect") || ContainsAscii(bytes, "Themida") ||
                   ContainsAscii(bytes, "WinLicense") || ContainsAscii(bytes, "Enigma Protector") ||
                   ContainsAscii(bytes, "MPRESS");
        }

        private static bool ContainsAscii(ReadOnlySpan<byte> haystack, string needle)
        {
            if (haystack.Length == 0 || string.IsNullOrEmpty(needle))
            {
                return false;
            }

            byte[] pattern = System.Text.Encoding.ASCII.GetBytes(needle);
            return haystack.IndexOf(pattern) >= 0;
        }

        private static double ComputeEntropy(byte[]? data, int length)
        {
            if (data == null || length <= 0)
            {
                return double.NaN;
            }

            int size = Math.Min(length, data.Length);
            if (size <= 0)
            {
                return double.NaN;
            }

            Span<int> histogram = stackalloc int[256];
            for (int i = 0; i < size; i += 1)
            {
                histogram[data[i]] += 1;
            }

            double entropy = 0;
            for (int i = 0; i < histogram.Length; i += 1)
            {
                int count = histogram[i];
                if (count == 0)
                {
                    continue;
                }

                double p = count / (double)size;
                entropy -= p * Math.Log(p, 2);
            }

            return entropy;
        }

        private static string ComputeSha256Hex(byte[] bytes)
        {
            byte[] hash = SHA256.HashData(bytes);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
    }
}
