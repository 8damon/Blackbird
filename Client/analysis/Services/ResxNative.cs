using System;
using System.Runtime.InteropServices;

namespace BlackbirdInterface
{
    internal static class ResxNative
    {
        private const int RsxStatusOk = 0;
        private static bool s_disabled;
        private static string s_disabledError = string.Empty;

        internal static bool TryGetVersion(out string version, out string error)
        {
            version = string.Empty;
            return TryCallString((out IntPtr output) => Native.RsxVersion(out output), out version, out error);
        }

        internal static bool TryPeInfo(string imagePath, string optionsJson, out string json, out string error)
        {
            return TryCallString(
                (out IntPtr output) => Native.RsxPeInfo(imagePath, optionsJson, out output),
                out json,
                out error);
        }

        internal static bool TryShowSymbols(string imagePath, string optionsJson, out string json, out string error)
        {
            return TryCallString(
                (out IntPtr output) => Native.RsxShowSyms(imagePath, optionsJson, out output),
                out json,
                out error);
        }

        private static bool TryCallString(RsxStringCall call, out string value, out string error)
        {
            value = string.Empty;
            error = string.Empty;
            if (s_disabled)
            {
                error = s_disabledError;
                return false;
            }

            IntPtr output = IntPtr.Zero;
            try
            {
                int status = call(out output);
                if (output != IntPtr.Zero)
                {
                    value = Marshal.PtrToStringUTF8(output) ?? string.Empty;
                }

                if (status == RsxStatusOk)
                {
                    return true;
                }

                error = string.IsNullOrWhiteSpace(value)
                            ? $"RESX returned status {status}."
                            : $"RESX returned status {status}: {value}";
                return false;
            }
            catch (DllNotFoundException ex)
            {
                error = $"RESX.dll was not found: {ex.Message}";
                Disable(error);
                return false;
            }
            catch (BadImageFormatException ex)
            {
                error = $"RESX.dll architecture is incompatible: {ex.Message}";
                Disable(error);
                return false;
            }
            catch (EntryPointNotFoundException ex)
            {
                error = $"RESX.dll does not expose the expected API: {ex.Message}";
                Disable(error);
                return false;
            }
            catch (Exception ex)
            {
                error = $"RESX call failed: {ex.Message}";
                return false;
            }
            finally
            {
                if (output != IntPtr.Zero)
                {
                    Native.RsxFreeString(output);
                }
            }
        }

        private static void Disable(string error)
        {
            s_disabled = true;
            s_disabledError = error;
        }

        private delegate int RsxStringCall(out IntPtr output);

        private static class Native
        {
            [DllImport("RESX.dll", CallingConvention = CallingConvention.Cdecl)]
            internal static extern void RsxFreeString(IntPtr value);

            [DllImport("RESX.dll", CallingConvention = CallingConvention.Cdecl)]
            internal static extern int RsxVersion(out IntPtr output);

            [DllImport("RESX.dll", CallingConvention = CallingConvention.Cdecl)]
            internal static extern int RsxPeInfo(
                [MarshalAs(UnmanagedType.LPUTF8Str)] string imagePath,
                [MarshalAs(UnmanagedType.LPUTF8Str)] string optionsJson,
                out IntPtr output);

            [DllImport("RESX.dll", CallingConvention = CallingConvention.Cdecl)]
            internal static extern int RsxShowSyms(
                [MarshalAs(UnmanagedType.LPUTF8Str)] string imagePath,
                [MarshalAs(UnmanagedType.LPUTF8Str)] string optionsJson,
                out IntPtr output);
        }
    }
}
