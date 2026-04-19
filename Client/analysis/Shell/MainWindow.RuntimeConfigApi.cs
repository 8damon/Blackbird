using System;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        internal bool ApplyStartupRuntimeSelections(bool enableKernelHooks, bool enableAntiVirtualizationMasking, bool enableControllerConcealment,
                                                    bool enableInterfaceProtectedAccess, bool enableControllerProtectedAccess, out string error)
        {
            var profile = new LaunchProfile
            {
                EnableKernelHooks = enableKernelHooks,
                EnableAntiVirtualizationMasking = enableAntiVirtualizationMasking,
                EnableControllerConcealment = enableControllerConcealment,
                EnableInterfaceProtectedAccess = enableInterfaceProtectedAccess,
                EnableControllerProtectedAccess = enableControllerProtectedAccess
            };

            return ApplySelectedRuntimeConfig(profile, out error);
        }
    }
}
