using System;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        internal bool MarkInterfaceReady(out string error)
        {
            error = string.Empty;

            if (!TryOpenRuntimeConfigHandle(out IntPtr handle, out error))
            {
                return false;
            }

            try
            {
                if (!BlackbirdNative.MarkInterfaceReady(handle, unchecked((uint)Environment.ProcessId)))
                {
                    error = BlackbirdNative.LastError("MarkInterfaceReady failed").Message;
                    return false;
                }

                return true;
            }
            finally
            {
                _ = BlackbirdNative.CloseControlDevice(handle);
            }
        }

        internal bool ApplyStartupRuntimeSelections(bool enableAntiVirtualizationMasking, bool enableControllerConcealment,
                                                    bool enableInterfaceProtectedAccess, bool enableControllerProtectedAccess, out string error)
        {
            var profile = new LaunchProfile
            {
                EnableAntiVirtualizationMasking = enableAntiVirtualizationMasking,
                EnableControllerConcealment = enableControllerConcealment,
                EnableInterfaceProtectedAccess = enableInterfaceProtectedAccess,
                EnableControllerProtectedAccess = enableControllerProtectedAccess
            };

            return ApplySelectedRuntimeConfig(profile, out error);
        }
    }
}
