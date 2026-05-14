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
        private static class ProcessSnapshotDumpService
        {
            private const uint ProcessDuplicateHandle = 0x0040;
            private const uint ProcessCreateProcess = 0x0080;
            private const uint ContextAllAmd64 = 0x0010003F;
            private const int MiniDumpCallbackTypeIsProcessSnapshot = 16;
            private const int HResultSFalse = 1;

            [Flags]
            private enum PssCaptureFlags : uint
            {
                VaClone = 0x00000001,
                Handles = 0x00000004,
                HandleNameInformation = 0x00000008,
                HandleBasicInformation = 0x00000010,
                Threads = 0x00000080,
                ThreadContext = 0x00000100,
                VaSpace = 0x00000800,
                VaSpaceSectionInformation = 0x00001000
            }

            [Flags]
            private enum MiniDumpType : uint
            {
                MiniDumpWithFullMemory = 0x00000002,
                MiniDumpWithHandleData = 0x00000004,
                MiniDumpWithUnloadedModules = 0x00000020,
                MiniDumpWithFullMemoryInfo = 0x00000800,
                MiniDumpWithThreadInfo = 0x00001000
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct MiniDumpCallbackInputHeader
            {
                public uint ProcessId;
                public IntPtr ProcessHandle;
                public uint CallbackType;
            }

            [UnmanagedFunctionPointer(CallingConvention.Winapi)]
            private delegate bool MiniDumpCallbackRoutine(IntPtr callbackParam, IntPtr callbackInput,
                                                          IntPtr callbackOutput);

            [StructLayout(LayoutKind.Sequential)]
            private struct MiniDumpCallbackInformation
            {
                public MiniDumpCallbackRoutine CallbackRoutine;
                public IntPtr CallbackParam;
            }

            public static bool TryCaptureFullMemoryDump(uint processId, string dumpPath,
                                                        out ProcessSnapshotDumpResult result)
            {
                result = new ProcessSnapshotDumpResult(false, string.Empty, 0, "PssCaptureSnapshot+MiniDumpWriteDump");
                IntPtr processHandle =
                    Kernel32Native.OpenProcess(ProcessQueryInformation | ProcessQueryLimitedInformation |
                                                   ProcessVmRead | ProcessDuplicateHandle | ProcessCreateProcess,
                                               false, processId);
                if (processHandle == IntPtr.Zero || processHandle == new IntPtr(-1))
                {
                    int err = Marshal.GetLastWin32Error();
                    result =
                        result with { Error = $"OpenProcess failed win32={err} ({new Win32Exception(err).Message})" };
                    return false;
                }

                IntPtr snapshotHandle = IntPtr.Zero;
                try
                {
                    PssCaptureFlags flags = PssCaptureFlags.VaClone | PssCaptureFlags.Handles |
                                            PssCaptureFlags.HandleNameInformation |
                                            PssCaptureFlags.HandleBasicInformation | PssCaptureFlags.Threads |
                                            PssCaptureFlags.ThreadContext | PssCaptureFlags.VaSpace |
                                            PssCaptureFlags.VaSpaceSectionInformation;
                    uint status = PssCaptureSnapshot(processHandle, flags, ContextAllAmd64, out snapshotHandle);
                    if (status != 0)
                    {
                        flags = PssCaptureFlags.VaClone | PssCaptureFlags.Threads | PssCaptureFlags.VaSpace |
                                PssCaptureFlags.VaSpaceSectionInformation;
                        status = PssCaptureSnapshot(processHandle, flags, 0, out snapshotHandle);
                    }

                    if (status != 0 || snapshotHandle == IntPtr.Zero || snapshotHandle == new IntPtr(-1))
                    {
                        result = result with { Error = $"PssCaptureSnapshot failed win32={status}" };
                        return false;
                    }

                    Directory.CreateDirectory(Path.GetDirectoryName(dumpPath) ?? ".");
                    using FileStream dumpStream = new(dumpPath, FileMode.Create, FileAccess.ReadWrite, FileShare.Read);
                    MiniDumpCallbackRoutine callback = MiniDumpCallback;
                    var callbackInfo =
                        new MiniDumpCallbackInformation { CallbackRoutine = callback, CallbackParam = IntPtr.Zero };
                    MiniDumpType dumpType = MiniDumpType.MiniDumpWithFullMemory | MiniDumpType.MiniDumpWithHandleData |
                                            MiniDumpType.MiniDumpWithUnloadedModules |
                                            MiniDumpType.MiniDumpWithFullMemoryInfo |
                                            MiniDumpType.MiniDumpWithThreadInfo;
                    bool ok = MiniDumpWriteDump(snapshotHandle, processId, dumpStream.SafeFileHandle, dumpType,
                                                IntPtr.Zero, IntPtr.Zero, ref callbackInfo);
                    GC.KeepAlive(callback);
                    if (!ok)
                    {
                        int err = Marshal.GetLastWin32Error();
                        result = result with {
                            Error =
                                $"MiniDumpWriteDump(PSS snapshot) failed win32={err} ({new Win32Exception(err).Message})"
                        };
                        return false;
                    }

                    dumpStream.Flush(true);
                    result = result with { Success = true, DumpBytes = dumpStream.Length };
                    return true;
                }
                finally
                {
                    if (snapshotHandle != IntPtr.Zero && snapshotHandle != new IntPtr(-1))
                    {
                        _ = PssFreeSnapshot(processHandle, snapshotHandle);
                    }

                    _ = Kernel32Native.CloseHandle(processHandle);
                }
            }

            private static bool MiniDumpCallback(IntPtr callbackParam, IntPtr callbackInput, IntPtr callbackOutput)
            {
                try
                {
                    if (callbackInput != IntPtr.Zero && callbackOutput != IntPtr.Zero)
                    {
                        MiniDumpCallbackInputHeader input =
                            Marshal.PtrToStructure<MiniDumpCallbackInputHeader>(callbackInput);
                        if (input.CallbackType == MiniDumpCallbackTypeIsProcessSnapshot)
                        {
                            Marshal.WriteInt32(callbackOutput, HResultSFalse);
                        }
                    }
                }
                catch
                {
                }

                return true;
            }

            [DllImport("kernel32.dll", EntryPoint = "PssCaptureSnapshot", SetLastError = true)]
            private static extern uint PssCaptureSnapshot(IntPtr processHandle, PssCaptureFlags captureFlags,
                                                          uint threadContextFlags, out IntPtr snapshotHandle);

            [DllImport("kernel32.dll", EntryPoint = "PssFreeSnapshot", SetLastError = true)]
            private static extern uint PssFreeSnapshot(IntPtr processHandle, IntPtr snapshotHandle);

            [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", SetLastError = true)]
            [return:MarshalAs(UnmanagedType.Bool)]
            private static extern bool MiniDumpWriteDump(IntPtr processHandle, uint processId,
                                                         SafeFileHandle fileHandle, MiniDumpType dumpType,
                                                         IntPtr exceptionParam, IntPtr userStreamParam,
                                                         ref MiniDumpCallbackInformation callbackParam);
        }
    }
}
