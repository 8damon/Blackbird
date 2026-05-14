using System;
using System.Collections.Generic;

namespace BlackbirdInterface
{
    internal sealed class ProcessCapabilityObservation
    {
        public string Name { get; init; } = string.Empty;
        public string State { get; init; } = string.Empty;
        public string Source { get; init; } = string.Empty;
        public string Evidence { get; init; } = string.Empty;
        public string Detail { get; init; } = string.Empty;
        public uint ActorPid { get; init; }
        public uint TargetPid { get; init; }
        public DateTime TimestampUtc { get; init; }
    }

    internal static class ProcessCapabilityCatalog
    {
        private const string StateCapable = "Capable";
        private const string StateActive = "Active";

        private readonly struct ModuleCapability
        {
            internal ModuleCapability(string moduleName, string capability, string detail)
            {
                ModuleName = moduleName;
                Capability = capability;
                Detail = detail;
            }

            internal string ModuleName { get; }
            internal string Capability { get; }
            internal string Detail { get; }
        }

        private static readonly ModuleCapability[] ModuleCapabilities = {
            new("dbghelp.dll", "Process Dumping", "DbgHelp debug/minidump APIs are available"),
            new("dbgcore.dll", "Process Dumping", "DbgCore dump support is available"),
            new("dbgeng.dll", "Process Debugging", "Debug engine runtime is loaded"),
            new("comsvcs.dll", "Process Dumping", "COM+ services dump helpers are available"),
            new("combase.dll", "COM Automation", "COM runtime is loaded"),
            new("ole32.dll", "COM Automation", "OLE/COM runtime is loaded"),
            new("oleaut32.dll", "COM Automation", "OLE Automation runtime is loaded"),
            new("clbcatq.dll", "COM Automation", "COM catalog runtime is loaded"),
            new("wbemprox.dll", "WMI", "WMI proxy runtime is loaded"),
            new("fastprox.dll", "WMI", "WMI fast proxy runtime is loaded"),
            new("wmiutils.dll", "WMI", "WMI utility runtime is loaded"),
            new("wbemcomn.dll", "WMI", "WMI common runtime is loaded"),
            new("taskschd.dll", "Task Scheduler", "Task Scheduler COM API is available"),
            new("jscript.dll", "Script Engine", "JScript engine is loaded"),
            new("jscript9.dll", "Script Engine", "JScript9 engine is loaded"),
            new("vbscript.dll", "Script Engine", "VBScript engine is loaded"),
            new("scrobj.dll", "Script Engine", "Windows Script Component runtime is loaded"),
            new("rpcrt4.dll", "RPC", "RPC runtime is loaded"),
            new("secur32.dll", "Identity / SSPI", "SSPI security package broker is loaded"),
            new("sspicli.dll", "Identity / SSPI", "SSPI client runtime is loaded"),
            new("vaultcli.dll", "Credential Vault", "Windows Vault client runtime is loaded"),
            new("crypt32.dll", "Crypto / Certificates", "CryptoAPI certificate runtime is loaded"),
            new("crypt32.dll", "DPAPI", "CryptoAPI DPAPI surface is available"),
            new("cryptsp.dll", "Crypto / DPAPI", "Crypto service provider runtime is loaded"),
            new("ncrypt.dll", "CNG / Key Storage", "CNG key storage runtime is loaded"),
            new("bcrypt.dll", "CNG Crypto", "CNG primitive runtime is loaded"),
            new("rsaenh.dll", "Legacy Crypto Provider", "Enhanced RSA provider is loaded"),
            new("dnsapi.dll", "DNS", "Windows DNS API is loaded"),
            new("ws2_32.dll", "Network Sockets", "Winsock runtime is loaded"),
            new("winhttp.dll", "HTTP Client", "WinHTTP runtime is loaded"),
            new("wininet.dll", "HTTP Client", "WinINet runtime is loaded"),
            new("urlmon.dll", "URLMon", "URLMon download/runtime surface is loaded"),
            new("schannel.dll", "TLS / SChannel", "SChannel TLS provider is loaded"),
            new("wldap32.dll", "LDAP / Active Directory", "LDAP client runtime is loaded"),
            new("netapi32.dll", "NetAPI / SMB Admin", "NetAPI management runtime is loaded"),
            new("samcli.dll", "SAM / Account Management", "SAM client runtime is loaded"),
            new("ntdsapi.dll", "Directory Services", "NTDS API runtime is loaded"),
            new("user32.dll", "Desktop / Input", "User32 desktop and input surface is loaded"),
            new("gdi32.dll", "Screen Capture", "GDI drawing/capture surface is loaded"),
            new("gdi32full.dll", "Screen Capture", "GDI full runtime is loaded"),
            new("dxgi.dll", "Screen Capture", "DXGI desktop duplication surface may be available"),
            new("d3d11.dll", "Screen Capture", "D3D11 graphics surface is loaded"),
            new("setupapi.dll", "Device / Driver Management", "SetupAPI device management runtime is loaded"),
            new("cfgmgr32.dll", "Device / Driver Management", "Configuration Manager runtime is loaded"),
            new("fltlib.dll", "Filter Driver Management", "Filter Manager user API is loaded"),
            new("wevtapi.dll", "Windows Event Log", "Windows Event Log API is loaded"),
            new("tdh.dll", "ETW Consumer", "Trace Data Helper runtime is loaded")
        };

        internal static bool HasCapabilityModule(string? imagePath)
        {
            string module = EventDetailFormatting.ModuleNameFromPath(imagePath);
            if (IsIgnoredModule(module))
            {
                return false;
            }

            for (int i = 0; i < ModuleCapabilities.Length; i += 1)
            {
                if (module.Equals(ModuleCapabilities[i].ModuleName, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        internal static IReadOnlyList<ProcessCapabilityObservation> Observe(BrokerEtwEventView view)
        {
            if (view == null)
            {
                return Array.Empty<ProcessCapabilityObservation>();
            }

            var observations = new List<ProcessCapabilityObservation>(4);
            DateTime timestampUtc = view.TimestampUtc == default ? DateTime.UtcNow : view.TimestampUtc;
            uint actorPid =
                FirstNonZero(view.ActorPid, view.CallerPid, view.CreatorPid, view.ProcessPid, view.EventProcessId);
            uint targetPid =
                FirstNonZero(view.TargetPid, view.ExplicitTargetPid, view.ProcessPid, view.EventProcessId, actorPid);

            ObserveModule(view, actorPid, targetPid, timestampUtc, observations);
            ObserveActiveApi(view, actorPid, targetPid, timestampUtc, observations);
            return observations;
        }

        private static void ObserveModule(BrokerEtwEventView view, uint actorPid, uint targetPid, DateTime timestampUtc,
                                          List<ProcessCapabilityObservation> observations)
        {
            if (view.Family != BlackbirdNative.IpcEtwFamilyImage &&
                !view.DetectionName.Equals("USERMODE_MODULE_LOAD", StringComparison.OrdinalIgnoreCase) &&
                !IsModuleLoadOperation(view.Operation) && !IsModuleLoadOperation(view.EventName))
            {
                return;
            }

            string imagePath = FirstNonBlank(
                view.ImagePath, ExtractReasonValue(view.Reason, "name"), ExtractReasonValue(view.Reason, "imagePath"),
                ExtractReasonValue(view.Reason, "modulePath"), ExtractReasonValue(view.Reason, "path"));
            string module = EventDetailFormatting.ModuleNameFromPath(imagePath);
            if (IsIgnoredModule(module))
            {
                return;
            }

            for (int i = 0; i < ModuleCapabilities.Length; i += 1)
            {
                ModuleCapability capability = ModuleCapabilities[i];
                if (!module.Equals(capability.ModuleName, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                observations.Add(BuildObservation(
                    capability.Capability, StateCapable, "module-load", capability.Detail, actorPid, targetPid,
                    timestampUtc,
                    $"module={module}; path={FirstNonBlank(imagePath, module)}; source={view.Source}; detection={view.DetectionName}"));
            }
        }

        private static void ObserveActiveApi(BrokerEtwEventView view, uint actorPid, uint targetPid,
                                             DateTime timestampUtc, List<ProcessCapabilityObservation> observations)
        {
            string detection = view.DetectionName ?? string.Empty;
            string api = FirstNonBlank(view.Operation, view.EventName, detection);

            switch (detection)
            {
            case "USERMODE_COM_INIT":
            case "USERMODE_COM_SECURITY_INIT":
            case "USERMODE_COM_INSTANCE_CREATE":
                observations.Add(
                    BuildActive("COM Automation", "COM API was invoked", view, actorPid, targetPid, timestampUtc));
                break;
            case "USERMODE_WMI_ACTIVITY":
                observations.Add(BuildActive("COM Automation", "COM activation was observed", view, actorPid, targetPid,
                                             timestampUtc));
                observations.Add(
                    BuildActive("WMI", "WMI locator activation was observed", view, actorPid, targetPid, timestampUtc));
                break;
            case "USERMODE_ETW_PROVIDER_REGISTER":
            case "USERMODE_ETW_PROVIDER_UNREGISTER":
            case "USERMODE_ETW_SESSION_CONTROL":
            case "USERMODE_ETW_SUBSCRIPTION":
                observations.Add(BuildActive("ETW / Eventing", "ETW provider/session API was invoked", view, actorPid,
                                             targetPid, timestampUtc));
                break;
            case "USERMODE_NETWORK_CONNECT":
            case "USERMODE_NETWORK_IO":
                observations.Add(BuildActive("Network Sockets", "Winsock network API was invoked", view, actorPid,
                                             targetPid, timestampUtc));
                break;
            case "USERMODE_DOMAIN_RESOLUTION":
                observations.Add(
                    BuildActive("DNS", "DNS resolution API was invoked", view, actorPid, targetPid, timestampUtc));
                observations.Add(BuildActive("Network Sockets", "Network resolution path was invoked", view, actorPid,
                                             targetPid, timestampUtc));
                break;
            case "USERMODE_JOB_OBJECT_ACTIVITY":
                observations.Add(
                    BuildActive("Job Control", "Job object API was invoked", view, actorPid, targetPid, timestampUtc));
                break;
            case "USERMODE_IDENTITY_API":
                observations.Add(BuildActive("Identity / SSPI", "Identity, LSA, SSPI, or CNG key API was invoked", view,
                                             actorPid, targetPid, timestampUtc));
                break;
            case "CREDENTIAL_STORE_ACCESS":
            case "CREDENTIAL_STORE_ENUM":
                observations.Add(BuildActive("CredMan/Vault", "Windows credential manager API was invoked", view,
                                             actorPid, targetPid, timestampUtc));
                observations.Add(BuildActive("Credential Access", "Credential-store API activity was observed", view,
                                             actorPid, targetPid, timestampUtc));
                break;
            case "VAULT_SECRET_ACCESS":
                observations.Add(BuildActive("CredMan/Vault", "Windows Vault API was invoked", view, actorPid,
                                             targetPid, timestampUtc));
                observations.Add(BuildActive("Credential Access", "Vault access API activity was observed", view,
                                             actorPid, targetPid, timestampUtc));
                break;
            case "DPAPI_UNPROTECT":
                observations.Add(BuildActive("DPAPI", "DPAPI or NCrypt unprotect API was invoked", view, actorPid,
                                             targetPid, timestampUtc));
                observations.Add(BuildActive("Credential Access", "Secret-unprotect API activity was observed", view,
                                             actorPid, targetPid, timestampUtc));
                break;
            case "USERMODE_FUNCTION_TABLE_ACTIVITY":
            case "DYNAMIC_FUNCTION_TABLE_ABUSE":
                observations.Add(BuildActive("Dynamic Unwind Metadata", "Runtime function table API was invoked", view,
                                             actorPid, targetPid, timestampUtc));
                break;
            case "USERMODE_PROCESS_RECON":
                observations.Add(BuildActive("Process Recon", "Process/system information API was invoked", view,
                                             actorPid, targetPid, timestampUtc));
                break;
            }

            if (api.Equals("MiniDumpWriteDump", StringComparison.OrdinalIgnoreCase))
            {
                observations.Add(BuildActive("Process Dumping", "MiniDumpWriteDump was invoked", view, actorPid,
                                             targetPid, timestampUtc));
            }
        }

        private static ProcessCapabilityObservation BuildActive(string capability, string evidence,
                                                                BrokerEtwEventView view, uint actorPid, uint targetPid,
                                                                DateTime timestampUtc)
        {
            string api = FirstNonBlank(view.Operation, view.EventName, view.DetectionName, "api");
            return BuildObservation(
                capability, StateActive, "api", evidence, actorPid, targetPid, timestampUtc,
                $"api={api}; detection={view.DetectionName}; reason={FirstNonBlank(view.Reason, view.ArgumentSummary, view.Details)}");
        }

        private static ProcessCapabilityObservation BuildObservation(string capability, string state, string source,
                                                                     string evidence, uint actorPid, uint targetPid,
                                                                     DateTime timestampUtc, string detail)
        {
            return new ProcessCapabilityObservation {
                Name = capability,
                State = state,
                Source = source,
                Evidence = evidence,
                ActorPid = actorPid,
                TargetPid = targetPid == 0 ? actorPid : targetPid,
                TimestampUtc = timestampUtc,
                Detail = $"capability={capability}; state={state}; source={source}; evidence={evidence}; {detail}"
            };
        }

        private static bool IsModuleLoadOperation(string? value)
        {
            return value != null && (value.Equals("LoadLibraryA", StringComparison.OrdinalIgnoreCase) ||
                                     value.Equals("LoadLibraryW", StringComparison.OrdinalIgnoreCase) ||
                                     value.Equals("LoadLibraryExA", StringComparison.OrdinalIgnoreCase) ||
                                     value.Equals("LoadLibraryExW", StringComparison.OrdinalIgnoreCase) ||
                                     value.Equals("LdrLoadDll", StringComparison.OrdinalIgnoreCase) ||
                                     value.Equals("ImageTelemetry", StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsIgnoredModule(string module)
        {
            return string.IsNullOrWhiteSpace(module) || module.Equals("unknown", StringComparison.OrdinalIgnoreCase) ||
                   EventDetailFormatting.IsBlackbirdInternalModule(module);
        }

        private static string ExtractReasonValue(string? reason, string key)
        {
            if (string.IsNullOrWhiteSpace(reason) || string.IsNullOrWhiteSpace(key))
            {
                return string.Empty;
            }

            string token = key.Trim() + "=";
            int start = reason.IndexOf(token, StringComparison.OrdinalIgnoreCase);
            if (start < 0)
            {
                return string.Empty;
            }

            start += token.Length;
            if (start >= reason.Length)
            {
                return string.Empty;
            }

            int end = reason.IndexOf(' ', start);
            if (end < 0)
            {
                end = reason.Length;
            }

            return reason.Substring(start, end - start).Trim().Trim('"');
        }

        private static uint FirstNonZero(params uint[] values)
        {
            foreach (uint value in values)
            {
                if (value != 0)
                {
                    return value;
                }
            }

            return 0;
        }

        private static string FirstNonBlank(params string?[] values)
        {
            foreach (string? value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value.Trim();
                }
            }

            return string.Empty;
        }
    }
}
