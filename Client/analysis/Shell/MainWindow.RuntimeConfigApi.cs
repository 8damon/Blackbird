using System;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        internal void ConfigureStartupDriverMode(bool useKernelDriver, bool defaultUseUsermodeHooks)
        {
            _useKernelDriver = useKernelDriver;
            _startupDefaultUseUsermodeHooks = defaultUseUsermodeHooks;

            DiagnosticsState.SetValue("KM Driver", useKernelDriver ? "Enabled" : "Driverless mode");
            DiagnosticsState.SetValue("SR71 Hooks",
                                      defaultUseUsermodeHooks ? "Enabled by default" : "Disabled by default");
            if (!useKernelDriver)
            {
                SetKernelHooksArmed(false);
            }
        }

        internal bool ApplyStartupRuntimeSelections(bool enableKernelHooks, bool enableAntiVirtualizationMasking,
                                                    bool enableQpcTimingCompensation, bool enableControllerConcealment,
                                                    bool enableInterfaceProtectedAccess,
                                                    bool enableControllerProtectedAccess, out string error)
        {
            var profile = new LaunchProfile { EnableKernelHooks = enableKernelHooks,
                                              EnableAntiVirtualizationMasking = enableAntiVirtualizationMasking,
                                              EnableQpcTimingCompensation = enableQpcTimingCompensation,
                                              EnableControllerConcealment = enableControllerConcealment,
                                              EnableInterfaceProtectedAccess = enableInterfaceProtectedAccess,
                                              EnableControllerProtectedAccess = enableControllerProtectedAccess };

            return ApplySelectedRuntimeConfig(profile, out error);
        }
    }
}
