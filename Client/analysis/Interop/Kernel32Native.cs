using System;
using System.Runtime.InteropServices;

namespace BlackbirdInterface
{
    internal static class Kernel32Native
    {
        private static readonly IntPtr InvalidHandleValue = new(-1);
        internal const uint EventModifyState = 0x0002;
        internal const uint Synchronize = 0x00100000;

        internal static IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId)
        {
            return OpenProcessNative(desiredAccess, inheritHandle, processId);
        }

        internal static bool CloseHandle(IntPtr handle)
        {
            if (handle == IntPtr.Zero || handle == InvalidHandleValue)
            {
                return false;
            }

            return CloseHandleNative(handle);
        }

        internal static int NtSuspendProcess(IntPtr processHandle) => NtSuspendProcessNative(processHandle);
        internal static int NtResumeProcess(IntPtr processHandle) => NtResumeProcessNative(processHandle);
        internal static bool TerminateProcess(IntPtr processHandle, uint exitCode) => TerminateProcessNative(processHandle, exitCode);
        internal static IntPtr OpenEvent(uint desiredAccess, bool inheritHandle, string name) =>
            OpenEventNative(desiredAccess, inheritHandle, name);
        internal static bool SetEvent(IntPtr handle) => SetEventNative(handle);

        [DllImport("kernel32.dll", EntryPoint = "OpenProcess", SetLastError = true)]
        private static extern IntPtr OpenProcessNative(uint desiredAccess, bool inheritHandle, uint processId);

        [DllImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandleNative(IntPtr hObject);

        [DllImport("kernel32.dll", EntryPoint = "TerminateProcess", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcessNative(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", EntryPoint = "OpenEventW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenEventNative(uint dwDesiredAccess, bool bInheritHandle, string lpName);

        [DllImport("kernel32.dll", EntryPoint = "SetEvent", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetEventNative(IntPtr hEvent);

        [DllImport("ntdll.dll", EntryPoint = "NtSuspendProcess")]
        private static extern int NtSuspendProcessNative(IntPtr processHandle);

        [DllImport("ntdll.dll", EntryPoint = "NtResumeProcess")]
        private static extern int NtResumeProcessNative(IntPtr processHandle);
    }
}


