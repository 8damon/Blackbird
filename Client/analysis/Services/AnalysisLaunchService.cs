using System;
using System.Collections.Generic;
using System.IO;

namespace BlackbirdInterface
{
    internal sealed class AnalysisLaunchResult
    {
        public int ProcessId { get; init; }
        public BlackbirdBackendSession Session { get; init; } = null!;
    }

    internal static class AnalysisLaunchService
    {
        private const int MaxControllerLaunchArgumentChars = 2048;

        internal static string ResolveHookDllPath() => BlackbirdPackageResolver.ResolveRuntimeFile("SR71.dll");

        internal static string
        ResolveDllHostPath() => BlackbirdPackageResolver.ResolveRuntimeFile("BlackbirdDllHost.exe");

        internal static bool TryLaunchWithUsermodeHooksAndPrepareSession(string imagePath, bool useEarlyBirdApc,
                                                                         LaunchProfile launchProfile,
                                                                         bool useKernelDriver,
                                                                         out AnalysisLaunchResult? result,
                                                                         out string error)
        {
            result = null;
            error = string.Empty;

            if (string.IsNullOrWhiteSpace(imagePath))
            {
                error = "Launch path is empty.";
                return false;
            }

            if (!File.Exists(imagePath))
            {
                error = $"Launch image was not found: '{imagePath}'.";
                return false;
            }

            if (launchProfile.HasCommandLineArguments &&
                launchProfile.CommandLineArguments.Length >= MaxControllerLaunchArgumentChars)
            {
                error =
                    $"Launch arguments are too long for the controller IPC limit ({MaxControllerLaunchArgumentChars - 1} characters).";
                return false;
            }

            uint flags = useEarlyBirdApc ? BlackbirdNative.IpcUserHookFlagLaunchEarlybirdApc : 0;
            if (launchProfile.LeaveSuspendedAfterReady)
            {
                flags |= BlackbirdNative.IpcUserHookFlagDeferredLaunchGateRelease;
            }
            if (!useKernelDriver)
            {
                flags |= BlackbirdNative.IpcUserHookFlagUsermodeOnly;
            }

            BlackbirdBackendSession? preparedSession = null;
            try
            {
                if (!BkctlDeviceSession.TryOpen(out var control, out error))
                {
                    return false;
                }

                using (control)
                {
                    string hookPath = ResolveHookDllPath();
                    if (!File.Exists(hookPath))
                    {
                        error = $"Hook launch failed because the hook DLL is missing: '{hookPath}'.";
                        return false;
                    }

                    string environmentOverrides = launchProfile.ToIpcEnvironmentOverrideBlock();
                    if (!BlackbirdNative.SetUserHookTarget(
                            control.Handle, BlackbirdNative.IpcUserHookTargetLaunch, 0, flags, imagePath,
                            launchProfile.HasAnalysisSubject ? BlackbirdNative.AnalysisSubjectKindDll
                                                             : BlackbirdNative.AnalysisSubjectKindProcess,
                            launchProfile.HasAnalysisSubject ? launchProfile.AnalysisSubjectPath : null, hookPath,
                            launchProfile.HasWorkingDirectory ? launchProfile.WorkingDirectory : null,
                            string.IsNullOrWhiteSpace(environmentOverrides) ? null : environmentOverrides,
                            launchProfile.HasCommandLineArguments ? launchProfile.CommandLineArguments : null,
                            launchProfile.ParentProcessId, MapLaunchPriorityClass(launchProfile.Priority),
                            launchProfile.AffinityMask, launchProfile.InheritHandles,
                            (uint)launchProfile.IntegrityLevel,
                            out BlackbirdNative.BkSetUserHookTargetResponse response))
                    {
                        error = BkctlDeviceSession.FormatUserHookOperationError(
                            "SetUserHookTarget(launch)", BlackbirdNative.LastError("SetUserHookTarget(launch) failed"),
                            hookPath);
                        return false;
                    }

                    if (response.ProcessId == 0)
                    {
                        error = "Controller launch returned no PID.";
                        return false;
                    }

                    int pid = unchecked((int)response.ProcessId);
                    preparedSession =
                        BlackbirdBackendSession.StartFromHandle(pid, BlackbirdNative.StreamAll, useUsermodeHooks: true,
                                                                control.Handle, useKernelDriver: useKernelDriver);
                    _ = control.DetachHandle();

                    result = new AnalysisLaunchResult { ProcessId = pid, Session = preparedSession };
                    preparedSession = null;
                    return true;
                }
            }
            catch (Exception ex)
            {
                if (string.IsNullOrWhiteSpace(error))
                {
                    error = ex.Message;
                }

                return false;
            }
            finally
            {
                preparedSession?.Dispose();
            }
        }

        internal static string BuildDllHostCommandLineArguments(LaunchProfile launchProfile)
        {
            var args = new List<string> {
                "--dll",
                QuoteCommandLineArgument(launchProfile.AnalysisSubjectPath),
                "--mode",
                launchProfile.DllMode switch { DllLaunchMode.Export => "export", DllLaunchMode.Rundll => "rundll",
                                               DllLaunchMode.Register => "register",
                                               DllLaunchMode.Unregister => "unregister",
                                               DllLaunchMode.Install => "install",
                                               _ => "load" },
                "--wait-ms",
                launchProfile.DllWaitMilliseconds.ToString(System.Globalization.CultureInfo.InvariantCulture)
            };

            if (launchProfile.HasDllExportName)
            {
                args.Add("--export");
                args.Add(QuoteCommandLineArgument(launchProfile.DllExportName));
            }
            if (launchProfile.HasDllExportOrdinal)
            {
                args.Add("--ordinal");
                args.Add(launchProfile.DllExportOrdinal.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
            if (launchProfile.HasDllArgument)
            {
                args.Add("--arg");
                args.Add(QuoteCommandLineArgument(launchProfile.DllArgument));
            }
            if (launchProfile.HasDllLoadFlags)
            {
                args.Add("--load-flags");
                args.Add("0x" +
                         launchProfile.DllLoadFlags.ToString("X", System.Globalization.CultureInfo.InvariantCulture));
            }
            if (launchProfile.DllFreeOnExit)
            {
                args.Add("--free-on-exit");
            }
            if (launchProfile.DllInstallDisable)
            {
                args.Add("--install-disable");
            }

            return string.Join(" ", args);
        }

        internal static string QuoteCommandLineArgument(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return "\"\"";
            }

            var builder = new System.Text.StringBuilder();
            builder.Append('"');
            int backslashes = 0;
            foreach (char ch in value)
            {
                if (ch == '\\')
                {
                    backslashes += 1;
                    continue;
                }

                if (ch == '"')
                {
                    builder.Append('\\', backslashes * 2 + 1);
                    builder.Append('"');
                    backslashes = 0;
                    continue;
                }

                if (backslashes > 0)
                {
                    builder.Append('\\', backslashes);
                    backslashes = 0;
                }
                builder.Append(ch);
            }

            if (backslashes > 0)
            {
                builder.Append('\\', backslashes * 2);
            }
            builder.Append('"');
            return builder.ToString();
        }

        private static string ResolveBaseDirectory()
        {
            string baseDirectory = AppContext.BaseDirectory;
            if (string.IsNullOrWhiteSpace(baseDirectory))
            {
                baseDirectory = Environment.CurrentDirectory;
            }

            return baseDirectory;
        }

        private static uint MapLaunchPriorityClass(LaunchPriorityPreset priority) => priority switch {
            LaunchPriorityPreset.Idle => 0x00000040,
            LaunchPriorityPreset.BelowNormal => 0x00004000,
            LaunchPriorityPreset.Normal => 0x00000020,
            LaunchPriorityPreset.AboveNormal => 0x00008000,
            LaunchPriorityPreset.High => 0x00000080,
            LaunchPriorityPreset.Realtime => 0x00000100,
            _ => 0u
        };
    }
}
