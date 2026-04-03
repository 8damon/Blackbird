using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace BlackbirdInterface
{
    internal static partial class BlackbirdNative
    {
        private const uint CreateSuspendedFlag = 0x00000004;
        private const uint ExtendedStartupInfoPresentFlag = 0x00080000;
        private const uint UnicodeEnvironmentFlag = 0x00000400;
        private const uint ProcessCreateProcessAccess = 0x0080;
        private const uint ProcessDupHandleAccess = 0x0040;
        private const uint ProcessQueryLimitedInformationAccess = 0x1000;
        private const uint ProcThreadAttributeParentProcess = 0x00020000;
        private const uint PriorityClassIdle = 0x00000040;
        private const uint PriorityClassBelowNormal = 0x00004000;
        private const uint PriorityClassNormal = 0x00000020;
        private const uint PriorityClassAboveNormal = 0x00008000;
        private const uint PriorityClassHigh = 0x00000080;
        private const uint PriorityClassRealtime = 0x00000100;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfo
        {
            public int cb;
            public string? lpReserved;
            public string? lpDesktop;
            public string? lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfoEx
        {
            public StartupInfo StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessW(
            string? lpApplicationName,
            StringBuilder lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string? lpCurrentDirectory,
            [In] ref StartupInfoEx lpStartupInfo,
            out ProcessInformation lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetPriorityClass(IntPtr hProcess, uint dwPriorityClass);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetProcessAffinityMask(IntPtr hProcess, IntPtr dwProcessAffinityMask);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        internal static bool TryLaunchProcess(string imagePath, LaunchProfile profile, out int pid, out string error)
        {
            pid = 0;
            error = string.Empty;
            IntPtr parentHandle = IntPtr.Zero;
            IntPtr attributeList = IntPtr.Zero;
            IntPtr envBlock = IntPtr.Zero;
            IntPtr parentValue = IntPtr.Zero;
            ProcessInformation processInfo = default;

            try
            {
                var startupInfo = new StartupInfoEx();
                startupInfo.StartupInfo.cb = Marshal.SizeOf<StartupInfoEx>();

                uint creationFlags = UnicodeEnvironmentFlag | CreateSuspendedFlag;

                if (profile.HasParentProcess)
                {
                    parentHandle = OpenProcess(
                        ProcessCreateProcessAccess | ProcessDupHandleAccess | ProcessQueryLimitedInformationAccess,
                        false,
                        profile.ParentProcessId);
                    if (parentHandle == IntPtr.Zero || parentHandle == new IntPtr(-1))
                    {
                        error = LastError("OpenProcess(parent) failed").Message;
                        return false;
                    }

                    IntPtr attributeListSize = IntPtr.Zero;
                    _ = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeListSize);
                    attributeList = Marshal.AllocHGlobal(attributeListSize);
                    if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeListSize))
                    {
                        error = LastError("InitializeProcThreadAttributeList failed").Message;
                        return false;
                    }

                    parentValue = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteIntPtr(parentValue, parentHandle);
                    if (!UpdateProcThreadAttribute(
                            attributeList,
                            0,
                            (IntPtr)ProcThreadAttributeParentProcess,
                            parentValue,
                            (IntPtr)IntPtr.Size,
                            IntPtr.Zero,
                            IntPtr.Zero))
                    {
                        error = LastError("UpdateProcThreadAttribute(parent) failed").Message;
                        return false;
                    }

                    startupInfo.lpAttributeList = attributeList;
                    creationFlags |= ExtendedStartupInfoPresentFlag;
                }

                string? currentDirectory = profile.HasWorkingDirectory ? profile.WorkingDirectory : null;
                string? environment = BuildEnvironmentBlock(profile);
                if (environment != null)
                {
                    envBlock = Marshal.StringToHGlobalUni(environment);
                }

                StringBuilder commandLine = new StringBuilder();
                commandLine.Append('"');
                commandLine.Append(imagePath);
                commandLine.Append('"');

                if (!CreateProcessW(
                        imagePath,
                        commandLine,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        profile.InheritHandles,
                        creationFlags,
                        envBlock,
                        currentDirectory,
                        ref startupInfo,
                        out processInfo))
                {
                    error = LastError("CreateProcessW failed").Message;
                    return false;
                }

                if (profile.Priority != LaunchPriorityPreset.Inherit &&
                    !SetPriorityClass(processInfo.hProcess, MapPriorityClass(profile.Priority)))
                {
                    error = LastError("SetPriorityClass failed").Message;
                    _ = TerminateProcess(processInfo.hProcess, 1);
                    return false;
                }

                if (profile.HasAffinityMask &&
                    !SetProcessAffinityMask(processInfo.hProcess, unchecked((IntPtr)(long)profile.AffinityMask)))
                {
                    error = LastError("SetProcessAffinityMask failed").Message;
                    _ = TerminateProcess(processInfo.hProcess, 1);
                    return false;
                }

                if (!profile.LeaveSuspendedAfterReady)
                {
                    uint resumeResult = ResumeThread(processInfo.hThread);
                    if (resumeResult == uint.MaxValue)
                    {
                        error = LastError("ResumeThread failed").Message;
                        _ = TerminateProcess(processInfo.hProcess, 1);
                        return false;
                    }
                }

                pid = unchecked((int)processInfo.dwProcessId);
                return true;
            }
            finally
            {
                if (processInfo.hThread != IntPtr.Zero)
                {
                    _ = CloseHandle(processInfo.hThread);
                }
                if (processInfo.hProcess != IntPtr.Zero)
                {
                    _ = CloseHandle(processInfo.hProcess);
                }
                if (attributeList != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(attributeList);
                    Marshal.FreeHGlobal(attributeList);
                }
                if (parentValue != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(parentValue);
                }
                if (parentHandle != IntPtr.Zero && parentHandle != new IntPtr(-1))
                {
                    _ = CloseHandle(parentHandle);
                }
                if (envBlock != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(envBlock);
                }
            }
        }

        private static string? BuildEnvironmentBlock(LaunchProfile profile)
        {
            if (!profile.TryParseEnvironmentOverrides(out List<KeyValuePair<string, string>> overrides, out _)
                || overrides.Count == 0)
            {
                return null;
            }

            var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
            {
                string key = entry.Key?.ToString() ?? string.Empty;
                if (key.Length == 0)
                {
                    continue;
                }

                environment[key] = entry.Value?.ToString() ?? string.Empty;
            }

            foreach (KeyValuePair<string, string> pair in overrides)
            {
                environment[pair.Key] = pair.Value;
            }

            var ordered = new SortedDictionary<string, string>(environment, StringComparer.OrdinalIgnoreCase);
            StringBuilder block = new StringBuilder();
            foreach (KeyValuePair<string, string> pair in ordered)
            {
                block.Append(pair.Key);
                block.Append('=');
                block.Append(pair.Value);
                block.Append('\0');
            }

            block.Append('\0');
            return block.ToString();
        }

        private static uint MapPriorityClass(LaunchPriorityPreset priority) => priority switch
        {
            LaunchPriorityPreset.Idle => PriorityClassIdle,
            LaunchPriorityPreset.BelowNormal => PriorityClassBelowNormal,
            LaunchPriorityPreset.Normal => PriorityClassNormal,
            LaunchPriorityPreset.AboveNormal => PriorityClassAboveNormal,
            LaunchPriorityPreset.High => PriorityClassHigh,
            LaunchPriorityPreset.Realtime => PriorityClassRealtime,
            _ => 0u
        };
    }
}
