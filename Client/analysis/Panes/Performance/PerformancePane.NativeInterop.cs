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
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern nuint VirtualQueryEx(IntPtr hProcess, nint lpAddress,
                                                   out MEMORY_BASIC_INFORMATION lpBuffer, nuint dwLength);

        private const uint ThreadQueryInformation = 0x0040;
        private const uint ThreadQueryLimitedInformation = 0x0800;

        [StructLayout(LayoutKind.Sequential)]
        private struct THREAD_BASIC_INFORMATION
        {
            public int ExitStatus;
            public IntPtr TebBaseAddress;
            public CLIENT_ID ClientId;
            public UIntPtr AffinityMask;
            public int Priority;
            public int BasePriority;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NT_TIB64
        {
            public ulong ExceptionList;
            public ulong StackBase;
            public ulong StackLimit;
            public ulong SubSystemTib;
            public ulong FiberData;
            public ulong ArbitraryUserPointer;
            public ulong Self;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationThread(IntPtr threadHandle, int threadInformationClass,
                                                           out THREAD_BASIC_INFORMATION threadInformation,
                                                           int threadInformationLength, out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint desiredAccess, bool inheritHandle, uint threadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
                                                     int nSize, out IntPtr lpNumberOfBytesRead);

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQueryVirtualMemory(IntPtr processHandle, nint baseAddress,
                                                       int memoryInformationClass, IntPtr memoryInformation,
                                                       uint memoryInformationLength, out uint returnLength);

        private enum ProcessMitigationPolicy
        {
            DepPolicy = 0,
            AslrPolicy = 1,
            DynamicCodePolicy = 2,
            StrictHandleCheckPolicy = 3,
            SystemCallDisablePolicy = 4,
            MitigationOptionsMask = 5,
            ExtensionPointDisablePolicy = 6,
            ControlFlowGuardPolicy = 7
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_MITIGATION_DEP_POLICY
        {
            public uint Flags;
            public byte Permanent;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public byte[] Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_MITIGATION_ASLR_POLICY
        {
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_MITIGATION_DYNAMIC_CODE_POLICY
        {
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY
        {
            public uint Flags;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessMitigationPolicy(IntPtr hProcess, ProcessMitigationPolicy mitigationPolicy,
                                                              out PROCESS_MITIGATION_DEP_POLICY lpBuffer, int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessMitigationPolicy(IntPtr hProcess, ProcessMitigationPolicy mitigationPolicy,
                                                              out PROCESS_MITIGATION_ASLR_POLICY lpBuffer,
                                                              int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessMitigationPolicy(IntPtr hProcess, ProcessMitigationPolicy mitigationPolicy,
                                                              out PROCESS_MITIGATION_DYNAMIC_CODE_POLICY lpBuffer,
                                                              int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessMitigationPolicy(IntPtr hProcess, ProcessMitigationPolicy mitigationPolicy,
                                                              out PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY lpBuffer,
                                                              int dwLength);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool QueryWorkingSetEx(IntPtr hProcess, [In, Out] PSAPI_WORKING_SET_EX_INFORMATION[] pv,
                                                     int cb);

        private struct PeSummary
        {
            public string Machine;
            public bool IsPePlus;
            public string ImageBase;
            public string Subsystem;
            public string DllCharacteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PSAPI_WORKING_SET_EX_INFORMATION
        {
            public IntPtr VirtualAddress;
            public UIntPtr VirtualAttributes;
        }

        private readonly record struct MemoryModuleMapEntry(ulong BaseAddress, ulong EndAddress, string Name,
                                                            string Path);
    }
}
