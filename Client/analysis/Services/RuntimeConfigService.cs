using System;

namespace BlackbirdInterface
{
    internal static class RuntimeConfigService
    {
        internal const uint MutableMask =
            BlackbirdNative.RuntimeFlagAntiVirtualization | BlackbirdNative.RuntimeFlagSelfHide |
            BlackbirdNative.RuntimeFlagInterfaceProtectedAccess | BlackbirdNative.RuntimeFlagControllerProtectedAccess |
            BlackbirdNative.RuntimeFlagNtApiHooksDisarmed | BlackbirdNative.RuntimeFlagQpcTimingDisabled;
        internal const uint DescribeMask = MutableMask | BlackbirdNative.RuntimeFlagControllerProtectedAccess;
        internal static bool TryRead(out BlackbirdNative.BkRuntimeConfigResponse config, out string error)
        {
            config = default;
            error = string.Empty;

            if (!BkctlDeviceSession.TryOpen(out var control, out error))
            {
                return false;
            }

            using (control)
            {
                if (!BlackbirdNative.GetRuntimeConfig(control.Handle, out config))
                {
                    error = BkctlDeviceSession.FormatControlOpenError(
                        "GetRuntimeConfig", BlackbirdNative.LastError("GetRuntimeConfig failed"));
                    return false;
                }

                return true;
            }
        }

        internal static bool TryReadQpcTimingState(out BlackbirdNative.BkQpcTimingState state, out string error)
        {
            state = default;
            error = string.Empty;

            if (!BkctlDeviceSession.TryOpen(out var control, out error))
            {
                return false;
            }

            using (control)
            {
                if (!BlackbirdNative.GetQpcTimingState(control.Handle, out state))
                {
                    error = BkctlDeviceSession.FormatControlOpenError(
                        "GetQpcTimingState", BlackbirdNative.LastError("GetQpcTimingState failed"));
                    return false;
                }

                return true;
            }
        }

        internal static bool TryApply(LaunchProfile launchProfile, out BlackbirdNative.BkRuntimeConfigResponse config,
                                      out string error)
        {
            uint flags = BuildFlags(launchProfile);
            return TryApplyFlags(flags, MutableMask, out config, out error);
        }

        internal static bool TryApplyFlags(uint flags, uint mask, out BlackbirdNative.BkRuntimeConfigResponse config,
                                           out string error)
        {
            config = default;
            error = string.Empty;

            if (!BkctlDeviceSession.TryOpen(out var control, out error))
            {
                return false;
            }

            using (control)
            {
                if (!BlackbirdNative.SetRuntimeConfig(control.Handle, flags, mask))
                {
                    error = BkctlDeviceSession.FormatControlOpenError(
                        "SetRuntimeConfig", BlackbirdNative.LastError("SetRuntimeConfig failed"));
                    return false;
                }

                if (!BlackbirdNative.GetRuntimeConfig(control.Handle, out config))
                {
                    error = BkctlDeviceSession.FormatControlOpenError(
                        "GetRuntimeConfig", BlackbirdNative.LastError("GetRuntimeConfig failed"));
                    return false;
                }

                return true;
            }
        }

        internal static uint BuildFlags(LaunchProfile launchProfile)
        {
            uint flags = 0;
            bool hooksArmed = launchProfile.EnableKernelHooks;

            if (!hooksArmed)
            {
                flags |= BlackbirdNative.RuntimeFlagNtApiHooksDisarmed;
            }
            if (hooksArmed && launchProfile.EnableAntiVirtualizationMasking)
            {
                flags |= BlackbirdNative.RuntimeFlagAntiVirtualization;
            }
            if (!hooksArmed || !launchProfile.EnableAntiVirtualizationMasking ||
                !launchProfile.EnableQpcTimingCompensation)
            {
                flags |= BlackbirdNative.RuntimeFlagQpcTimingDisabled;
            }
            if (launchProfile.EnableControllerConcealment)
            {
                flags |= BlackbirdNative.RuntimeFlagSelfHide;
            }
            if (launchProfile.EnableInterfaceProtectedAccess)
            {
                flags |= BlackbirdNative.RuntimeFlagInterfaceProtectedAccess;
            }
            if (launchProfile.EnableControllerProtectedAccess)
            {
                flags |= BlackbirdNative.RuntimeFlagControllerProtectedAccess;
            }

            return flags;
        }

        internal static string DescribeFlags(uint flags)
        {
            string hooksState =
                (flags & BlackbirdNative.RuntimeFlagNtApiHooksDisarmed) != 0 ? "hooks-disarmed" : "hooks-armed";
            string antiVirtualization =
                (flags & BlackbirdNative.RuntimeFlagAntiVirtualization) != 0 ? "av" : string.Empty;
            string qpcTiming = ((flags & BlackbirdNative.RuntimeFlagAntiVirtualization) != 0 &&
                                (flags & BlackbirdNative.RuntimeFlagQpcTimingDisabled) == 0)
                                   ? "qpc-time"
                                   : string.Empty;
            string qpcDisabled = ((flags & BlackbirdNative.RuntimeFlagAntiVirtualization) != 0 &&
                                  (flags & BlackbirdNative.RuntimeFlagQpcTimingDisabled) != 0)
                                     ? "qpc-off"
                                     : string.Empty;
            string selfHide = (flags & BlackbirdNative.RuntimeFlagSelfHide) != 0 ? "hide" : string.Empty;
            string interfaceProtected =
                (flags & BlackbirdNative.RuntimeFlagInterfaceProtectedAccess) != 0 ? "iface-protect" : string.Empty;
            string controllerProtected =
                (flags & BlackbirdNative.RuntimeFlagControllerProtectedAccess) != 0 ? "ctrl-protect" : string.Empty;

            string[] active = new[] { hooksState, antiVirtualization, qpcTiming,          qpcDisabled,
                                      selfHide,   interfaceProtected, controllerProtected };
            string joined = string.Join(",", Array.FindAll(active, static value => value.Length != 0));
            return joined.Length != 0 ? joined : "off";
        }

        internal static string DescribeMode(uint mode) => mode == BlackbirdNative.RuntimeModeGuided ? "GUIDED"
                                                                                                    : "LOITER";
    }
}
