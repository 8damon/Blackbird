using System;
using System.Runtime.InteropServices;

namespace BlackbirdInterface
{
    internal static class Kernel32Native
    {
        private static readonly IntPtr InvalidHandleValue = new(-1);
        private const int SecurityDescriptorRevision = 1;
        internal const uint CreateEventManualReset = 0x00000001;
        internal const uint CreateEventInitialSet = 0x00000002;
        internal const uint EventModifyState = 0x0002;
        internal const uint Synchronize = 0x00100000;
        private const uint TokenAdjustPrivileges = 0x0020;
        private const uint TokenQuery = 0x0008;
        private const uint SePrivilegeEnabled = 0x00000002;

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            internal int Length;
            internal IntPtr SecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            internal bool InheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Luid
        {
            internal uint LowPart;
            internal int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TokenPrivileges
        {
            internal uint PrivilegeCount;
            internal Luid Luid;
            internal uint Attributes;
        }

        internal static IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId)
        {
            return OpenProcessNative(desiredAccess, inheritHandle, processId);
        }

        internal static bool EnableDebugPrivilege(out int win32Error)
        {
            win32Error = 0;
            IntPtr token = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out token))
                {
                    win32Error = Marshal.GetLastWin32Error();
                    return false;
                }

                if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out Luid luid))
                {
                    win32Error = Marshal.GetLastWin32Error();
                    return false;
                }

                var privileges =
                    new TokenPrivileges { PrivilegeCount = 1, Luid = luid, Attributes = SePrivilegeEnabled };
                if (!AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    win32Error = Marshal.GetLastWin32Error();
                    return false;
                }

                win32Error = Marshal.GetLastWin32Error();
                return win32Error == 0;
            }
            finally
            {
                _ = CloseHandle(token);
            }
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
        internal static bool TerminateProcess(IntPtr processHandle,
                                              uint exitCode) => TerminateProcessNative(processHandle, exitCode);
        internal static IntPtr OpenEvent(uint desiredAccess, bool inheritHandle,
                                         string name) => OpenEventNative(desiredAccess, inheritHandle, name);
        internal static IntPtr CreateEventEx(string name, uint flags,
                                             uint desiredAccess) => CreateEventExNative(IntPtr.Zero, name, flags,
                                                                                        desiredAccess);
        internal static IntPtr CreateEventExWithWorldAccess(string name, uint flags, uint desiredAccess)
        {
            IntPtr securityDescriptor = IntPtr.Zero;
            IntPtr securityAttributesBuffer = IntPtr.Zero;
            try
            {
                if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                        "D:P(A;;0x00100000;;;WD)(A;;0x001F0003;;;SY)(A;;0x001F0003;;;BA)(A;;0x001F0003;;;OW)",
                        SecurityDescriptorRevision, out securityDescriptor, IntPtr.Zero))
                {
                    return IntPtr.Zero;
                }

                var securityAttributes =
                    new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(),
                                             SecurityDescriptor = securityDescriptor, InheritHandle = false };
                securityAttributesBuffer = Marshal.AllocHGlobal(securityAttributes.Length);
                Marshal.StructureToPtr(securityAttributes, securityAttributesBuffer, false);
                return CreateEventExNative(securityAttributesBuffer, name, flags, desiredAccess);
            }
            finally
            {
                if (securityAttributesBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(securityAttributesBuffer);
                }
                if (securityDescriptor != IntPtr.Zero)
                {
                    _ = LocalFree(securityDescriptor);
                }
            }
        }
        internal static bool SetEvent(IntPtr handle) => SetEventNative(handle);

        [DllImport("kernel32.dll", EntryPoint = "OpenProcess", SetLastError = true)]
        private static extern IntPtr OpenProcessNative(uint desiredAccess, bool inheritHandle, uint processId);

        [DllImport("kernel32.dll", EntryPoint = "GetCurrentProcess")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", EntryPoint = "OpenProcessToken", SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", EntryPoint = "LookupPrivilegeValueW", CharSet = CharSet.Unicode,
                   SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValue(string? systemName, string name, out Luid luid);

        [DllImport("advapi32.dll", EntryPoint = "AdjustTokenPrivileges", SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges,
                                                         ref TokenPrivileges newState, uint bufferLength,
                                                         IntPtr previousState, IntPtr returnLength);

        [DllImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandleNative(IntPtr hObject);

        [DllImport("kernel32.dll", EntryPoint = "TerminateProcess", SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcessNative(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", EntryPoint = "OpenEventW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenEventNative(uint dwDesiredAccess, bool bInheritHandle, string lpName);

        [DllImport("kernel32.dll", EntryPoint = "CreateEventExW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateEventExNative(IntPtr lpEventAttributes, string lpName, uint dwFlags,
                                                         uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                   CharSet = CharSet.Unicode, SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string stringSecurityDescriptor,
                                                                                       int stringSdRevision,
                                                                                       out IntPtr securityDescriptor,
                                                                                       IntPtr securityDescriptorSize);

        [DllImport("kernel32.dll", EntryPoint = "LocalFree", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", EntryPoint = "SetEvent", SetLastError = true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetEventNative(IntPtr hEvent);

        [DllImport("ntdll.dll", EntryPoint = "NtSuspendProcess")]
        private static extern int NtSuspendProcessNative(IntPtr processHandle);

        [DllImport("ntdll.dll", EntryPoint = "NtResumeProcess")]
        private static extern int NtResumeProcessNative(IntPtr processHandle);
    }
}
