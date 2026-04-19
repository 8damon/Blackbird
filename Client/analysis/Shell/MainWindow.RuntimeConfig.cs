using System;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private const uint RuntimeConfigMask = BlackbirdNative.RuntimeFlagAntiVirtualization |
                                               BlackbirdNative.RuntimeFlagSelfHide |
                                               BlackbirdNative.RuntimeFlagInterfaceProtectedAccess |
                                               BlackbirdNative.RuntimeFlagControllerProtectedAccess |
                                               BlackbirdNative.RuntimeFlagNtApiHooksDisarmed;
        private const uint RuntimeConfigTeardownProtectionMask = BlackbirdNative.RuntimeFlagSelfHide |
                                                                 BlackbirdNative.RuntimeFlagInterfaceProtectedAccess |
                                                                 BlackbirdNative.RuntimeFlagControllerProtectedAccess;
        private uint _persistentRuntimeFlags;
        private uint _effectiveRuntimeFlags;

        private static string DescribeRuntimeFlags(uint flags)
        {
            if ((flags & RuntimeConfigMask) == 0)
            {
                return "off";
            }

            string antiVirtualization = (flags & BlackbirdNative.RuntimeFlagAntiVirtualization) != 0 ? "av" : string.Empty;
            string selfHide = (flags & BlackbirdNative.RuntimeFlagSelfHide) != 0 ? "hide" : string.Empty;
            string interfaceProtected = (flags & BlackbirdNative.RuntimeFlagInterfaceProtectedAccess) != 0 ? "iface-protect" : string.Empty;
            string controllerProtected = (flags & BlackbirdNative.RuntimeFlagControllerProtectedAccess) != 0 ? "ctrl-protect" : string.Empty;
            string hooksDisarmed = (flags & BlackbirdNative.RuntimeFlagNtApiHooksDisarmed) != 0 ? "hooks-disarmed" : string.Empty;

            string[] active = new[] { antiVirtualization, selfHide, interfaceProtected, controllerProtected, hooksDisarmed };
            string joined = string.Join(",", Array.FindAll(active, static value => value.Length != 0));
            return joined.Length != 0 ? joined : "off";
        }
        private static string DescribeRuntimeMode(uint mode) => mode == BlackbirdNative.RuntimeModeGuided ? "GUIDED" : "LOITER";

        private void UpdateRuntimeConfigState(BlackbirdNative.BkRuntimeConfigResponse config)
        {
            _persistentRuntimeFlags = config.PersistentFlags;
            _effectiveRuntimeFlags = config.EffectiveFlags;
            DiagnosticsState.SetValue("RuntimeConfig", $"persistent={DescribeRuntimeFlags(config.PersistentFlags)} runtime={DescribeRuntimeFlags(config.RuntimeFlags)} effective={DescribeRuntimeFlags(config.EffectiveFlags)} mode={DescribeRuntimeMode(config.Mode)}");
        }

        private bool TryReadRuntimeConfig(out BlackbirdNative.BkRuntimeConfigResponse config, out string error)
        {
            config = default;
            error = string.Empty;

            if (!BlackbirdControlDeviceSession.TryOpen(out var control, out error))
            {
                return false;
            }

            using (control)
            {
                if (!BlackbirdNative.GetRuntimeConfig(control.Handle, out config))
                {
                    error = BlackbirdControlDeviceSession.FormatControlOpenError(
                        "GetRuntimeConfig",
                        BlackbirdNative.LastError("GetRuntimeConfig failed"));
                    return false;
                }

                UpdateRuntimeConfigState(config);
                return true;
            }
        }

        private bool TryApplyRuntimeConfig(uint flags, uint mask, out BlackbirdNative.BkRuntimeConfigResponse config, out string error)
        {
            config = default;
            error = string.Empty;

            if (!BlackbirdControlDeviceSession.TryOpen(out var control, out error))
            {
                return false;
            }

            using (control)
            {
                if (!BlackbirdNative.SetRuntimeConfig(control.Handle, flags, mask))
                {
                    error = BlackbirdControlDeviceSession.FormatControlOpenError(
                        "SetRuntimeConfig",
                        BlackbirdNative.LastError("SetRuntimeConfig failed"));
                    return false;
                }

                if (!BlackbirdNative.GetRuntimeConfig(control.Handle, out config))
                {
                    error = BlackbirdControlDeviceSession.FormatControlOpenError(
                        "GetRuntimeConfig",
                        BlackbirdNative.LastError("GetRuntimeConfig failed"));
                    return false;
                }

                UpdateRuntimeConfigState(config);
                return true;
            }
        }

        private void InitializeRuntimeConfigDefaults()
        {
            if (!TryReadRuntimeConfig(out var config, out string error))
            {
                OutputCapture.AppendLine($"Runtime config unavailable: {error}");
                DiagnosticsState.SetValue("RuntimeConfig", $"Unavailable: {error}");
                return;
            }

            _persistentRuntimeFlags = config.PersistentFlags;
            _effectiveRuntimeFlags = config.EffectiveFlags;
            OutputCapture.AppendLine($"Runtime config initialized: effective={DescribeRuntimeFlags(config.EffectiveFlags)} mode={DescribeRuntimeMode(config.Mode)}");
        }

        private bool ApplySelectedRuntimeConfig(LaunchProfile launchProfile, out string error)
        {
            uint flags = 0;
            error = string.Empty;

            bool hooksArmed = launchProfile.EnableKernelHooks;

            if (!hooksArmed)
            {
                flags |= BlackbirdNative.RuntimeFlagNtApiHooksDisarmed;
            }
            // Anti-virt requires hooks; force off if hooks are disarmed
            if (hooksArmed && launchProfile.EnableAntiVirtualizationMasking)
            {
                flags |= BlackbirdNative.RuntimeFlagAntiVirtualization;
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

            if (!TryApplyRuntimeConfig(flags, RuntimeConfigMask, out var config, out error))
            {
                return false;
            }

            SetKernelHooksArmed(hooksArmed);
            OutputCapture.AppendLine($"Runtime config applied: effective={DescribeRuntimeFlags(config.EffectiveFlags)} mode={DescribeRuntimeMode(config.Mode)}");
            return true;
        }

        private void DisarmTeardownProtectionBestEffort()
        {
            if (_teardownProtectionDisarmAttempted)
            {
                return;
            }

            _teardownProtectionDisarmAttempted = true;

            if ((_effectiveRuntimeFlags & RuntimeConfigTeardownProtectionMask) == 0 &&
                (_persistentRuntimeFlags & RuntimeConfigTeardownProtectionMask) == 0)
            {
                return;
            }

            if (!TryApplyRuntimeConfig(0, RuntimeConfigTeardownProtectionMask, out var config, out string error))
            {
                OutputCapture.AppendLine($"Runtime protection teardown disarm failed: {error}");
                DiagnosticsState.SetValue("RuntimeConfig Teardown", $"Disarm failed: {error}");
                return;
            }

            OutputCapture.AppendLine($"Runtime protection teardown disarmed: effective={DescribeRuntimeFlags(config.EffectiveFlags)}");
            DiagnosticsState.SetValue("RuntimeConfig Teardown", $"Disarmed: effective={DescribeRuntimeFlags(config.EffectiveFlags)}");
        }
    }
}
