using System;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        internal bool MarkInterfaceReady(out string error)
        {
            error = string.Empty;

            if (!BlackbirdControlDeviceSession.TryOpen(out var control, out error))
            {
                return false;
            }

            using (control)
            {
                if (!BlackbirdNative.MarkInterfaceReady(control.Handle, unchecked((uint)Environment.ProcessId)))
                {
                    error = BlackbirdControlDeviceSession.FormatControlOpenError(
                        "MarkInterfaceReady",
                        BlackbirdNative.LastError("MarkInterfaceReady failed"));
                    return false;
                }

                return true;
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
