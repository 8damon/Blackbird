using System;
using System.Runtime.InteropServices;

namespace SleepwalkerInterface
{
    internal static class Kernel32Native
    {
        private static readonly IntPtr InvalidHandleValue = new(-1);

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

        [DllImport("kernel32.dll", EntryPoint = "OpenProcess", SetLastError = true)]
        private static extern IntPtr OpenProcessNative(uint desiredAccess, bool inheritHandle, uint processId);

        [DllImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandleNative(IntPtr hObject);
    }
}
