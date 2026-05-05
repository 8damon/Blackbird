using System;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private uint _persistentRuntimeFlags;
        private uint _effectiveRuntimeFlags;

        private static string DescribeRuntimeFlags(uint flags) => RuntimeConfigService.DescribeFlags(flags);
        private static string DescribeRuntimeMode(uint mode) => RuntimeConfigService.DescribeMode(mode);

        private void UpdateRuntimeConfigState(BlackbirdNative.BkRuntimeConfigResponse config)
        {
            _persistentRuntimeFlags = config.PersistentFlags;
            _effectiveRuntimeFlags = config.EffectiveFlags;
            SetKernelHooksArmed((config.EffectiveFlags & BlackbirdNative.RuntimeFlagNtApiHooksDisarmed) == 0);
            DiagnosticsState.SetValue(
                "RuntimeConfig",
                $"persistent={DescribeRuntimeFlags(config.PersistentFlags)} runtime={DescribeRuntimeFlags(config.RuntimeFlags)} effective={DescribeRuntimeFlags(config.EffectiveFlags)} mode={DescribeRuntimeMode(config.Mode)}");
            UpdateQpcTimingDiagnostics(config.EffectiveFlags);
        }

        private static void UpdateQpcTimingDiagnostics(uint effectiveFlags)
        {
            bool enabled = (effectiveFlags & BlackbirdNative.RuntimeFlagAntiVirtualization) != 0 &&
                           (effectiveFlags & BlackbirdNative.RuntimeFlagNtApiHooksDisarmed) == 0 &&
                           (effectiveFlags & BlackbirdNative.RuntimeFlagQpcTimingDisabled) == 0;
            if (!enabled)
            {
                DiagnosticsState.SetValue("QPC Timing", "Disabled");
                return;
            }

            if (RuntimeConfigService.TryReadQpcTimingState(out var state, out string error))
            {
                DiagnosticsState.SetValue(
                    "QPC Timing",
                    $"Active queries={state.QueryCount} pairs={state.PairCount} corrected={state.CorrectedCount} slots={state.ActiveThreadSlots} bias={state.AutoBiasTicks}");
            }
            else
            {
                DiagnosticsState.SetValue("QPC Timing", $"Unavailable: {error}");
            }
        }

        private bool TryReadRuntimeConfig(out BlackbirdNative.BkRuntimeConfigResponse config, out string error)
        {
            config = default;
            error = string.Empty;

            bool ok = RuntimeConfigService.TryRead(out config, out error);
            if (ok)
            {
                UpdateRuntimeConfigState(config);
            }
            return ok;
        }

        private bool TryApplyRuntimeConfig(uint flags, uint mask, out BlackbirdNative.BkRuntimeConfigResponse config,
                                           out string error)
        {
            config = default;
            error = string.Empty;

            bool ok = RuntimeConfigService.TryApplyFlags(flags, mask, out config, out error);
            if (ok)
            {
                UpdateRuntimeConfigState(config);
            }
            return ok;
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
            OutputCapture.AppendLine(
                $"Runtime config initialized: effective={DescribeRuntimeFlags(config.EffectiveFlags)} mode={DescribeRuntimeMode(config.Mode)}");
        }

        private bool ApplySelectedRuntimeConfig(LaunchProfile launchProfile, out string error)
        {
            error = string.Empty;
            if (!RuntimeConfigService.TryApply(launchProfile, out var config, out error))
            {
                return false;
            }

            UpdateRuntimeConfigState(config);
            SetKernelHooksArmed(launchProfile.EnableKernelHooks);
            OutputCapture.AppendLine(
                $"Runtime config applied: effective={DescribeRuntimeFlags(config.EffectiveFlags)} mode={DescribeRuntimeMode(config.Mode)}");
            return true;
        }

    }
}
