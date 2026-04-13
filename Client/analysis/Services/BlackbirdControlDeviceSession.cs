using System;
using System.ComponentModel;

namespace BlackbirdInterface
{
    internal sealed class BlackbirdControlDeviceSession : IDisposable
    {
        private IntPtr _handle;
        private bool _disposed;

        private BlackbirdControlDeviceSession(IntPtr handle)
        {
            _handle = handle;
        }

        public IntPtr Handle => _handle;

        public static bool TryOpen(out BlackbirdControlDeviceSession session, out string error, bool ensureClientProtocol = true)
        {
            session = null!;
            error = string.Empty;

            if (ensureClientProtocol && !BlackbirdNative.UseClientProtocol(null, 1500))
            {
                error = FormatControlOpenError(
                    "UseClientProtocol",
                    BlackbirdNative.LastError("UseClientProtocol failed"));
                return false;
            }

            IntPtr handle = BlackbirdNative.OpenControlDevice();
            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            {
                error = FormatControlOpenError(
                    "OpenControlDevice",
                    BlackbirdNative.LastError("OpenControlDevice failed"));
                return false;
            }

            session = new BlackbirdControlDeviceSession(handle);
            return true;
        }

        public static string FormatControlOpenError(string operation, Win32Exception error)
        {
            string detail = error.Message;
            return error.NativeErrorCode switch
            {
                2 => $"{operation} failed because the controller component was not found. {detail}",
                5 => $"{operation} failed with access denied. Run the interface/controller elevated and confirm the device ACL allows this client. {detail}",
                6 => $"{operation} failed because the controller/device handle is invalid. {detail}",
                53 => $"{operation} failed because the controller transport is unavailable. {detail}",
                67 => $"{operation} failed because the controller pipe or device name is invalid. {detail}",
                1460 => $"{operation} timed out waiting for the controller transport. {detail}",
                _ => $"{operation} failed. {detail}"
            };
        }

        public static string FormatUserHookOperationError(string operation, Win32Exception error, string? hookPath = null)
        {
            string detail = error.Message;
            return error.NativeErrorCode switch
            {
                2 => $"{operation} failed because the hook DLL was not found at '{hookPath ?? "SR71.dll"}'. {detail}",
                3 => $"{operation} failed because the hook DLL path is invalid: '{hookPath ?? "SR71.dll"}'. {detail}",
                5 => $"{operation} failed with access denied. Run the interface/controller elevated and confirm the target process can be opened for injection. {detail}",
                6 => $"{operation} failed because the controller handle is invalid or no longer open. {detail}",
                87 => $"{operation} failed because the hook request parameters were rejected. {detail}",
                126 => $"{operation} failed because a required hook dependency could not be loaded. {detail}",
                127 => $"{operation} failed because a required export was not found in the hook chain. {detail}",
                193 => $"{operation} failed because the hook DLL is the wrong architecture or not a valid image for this target. {detail}",
                299 => $"{operation} failed because the target process could not be read completely. This usually means the target is exiting, protected, or missing required access rights. {detail}",
                577 => $"{operation} failed because Windows blocked the hook image from loading. Check signing policy and image trust state. {detail}",
                998 => $"{operation} failed because the target process memory could not be accessed safely. {detail}",
                1114 => $"{operation} failed because the hook DLL initialization routine did not complete successfully. {detail}",
                1314 => $"{operation} failed because the required privileges are not present. Run elevated and ensure the controller can enable debug privileges. {detail}",
                1460 => $"{operation} timed out waiting for the hook/controller ready handshake. {detail}",
                _ => $"{operation} failed. {detail}"
            };
        }

        public IntPtr DetachHandle()
        {
            IntPtr handle = _handle;
            _handle = IntPtr.Zero;
            _disposed = true;
            return handle;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            if (_handle != IntPtr.Zero && _handle != new IntPtr(-1))
            {
                _ = BlackbirdNative.CloseControlDevice(_handle);
            }

            _handle = IntPtr.Zero;
        }
    }
}
