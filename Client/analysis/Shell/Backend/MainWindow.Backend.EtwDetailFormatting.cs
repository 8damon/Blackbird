using BlackbirdInterface.Capture;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.Windows.Media;
using System.Windows.Shapes;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private string BuildEtwDisplayDetail(BrokerEtwEventView view)
        {
            string rawReason = view.Reason ?? string.Empty;
            if (EventDetailFormatting.IsApiGraphCandidate(view))
            {
                return BuildApiDecodedAction(view, rawReason).Detail;
            }

            return BuildGenericEtwDisplayDetail(view, BuildHookFieldMap(view), includeHeadline: true);
        }

        private string BuildFallbackApiDetail(string apiName, BrokerEtwEventView view, string rawReason, string action)
        {
            Dictionary<string, string> fields = BuildHookFieldMap(rawReason, Array.Empty<ulong>(), 0);
            string argumentText = BuildResolvedHookArgumentsText(apiName, view, fields);
            if (string.IsNullOrWhiteSpace(argumentText))
            {
                return action;
            }

            return $"{action}{Environment.NewLine}{Environment.NewLine}{argumentText}";
        }

        private string BuildGenericEtwDisplayDetail(BrokerEtwEventView view, IReadOnlyDictionary<string, string> fields,
                                                    bool includeHeadline)
        {
            var sb = new StringBuilder(512);
            string eventName = string.IsNullOrWhiteSpace(view.EventName) ? "unknown" : view.EventName.Trim();
            string detection = view.DetectionName?.Trim() ?? string.Empty;
            string operation = view.Operation?.Trim() ?? string.Empty;
            string actor = ProcessIdentityResolver.Describe(view.ActorPid);
            string target = ProcessIdentityResolver.Describe(view.TargetPid);

            if (includeHeadline)
            {
                sb.AppendLine(!string.IsNullOrWhiteSpace(detection) ? detection : eventName);
            }

            if (!string.IsNullOrWhiteSpace(view.Source))
            {
                sb.Append("Source: ").AppendLine(view.Source);
            }

            sb.Append("Event: ").AppendLine(eventName);
            if (!string.IsNullOrWhiteSpace(operation) &&
                !operation.Equals(eventName, StringComparison.OrdinalIgnoreCase))
            {
                sb.Append("Operation: ").AppendLine(operation);
            }

            if (!string.IsNullOrWhiteSpace(detection))
            {
                sb.Append("Detection: ").AppendLine(detection);
            }

            if (view.ActorPid != 0)
            {
                sb.Append("Actor: ").AppendLine(actor);
            }

            if (view.TargetPid != 0)
            {
                sb.Append("Target: ").AppendLine(target);
            }

            if (!string.IsNullOrWhiteSpace(view.ArgumentSummary))
            {
                sb.Append("Arguments: ").AppendLine(view.ArgumentSummary);
            }

            string frameSummary = BuildHookFrameSummary(view, fields);
            if (!string.IsNullOrWhiteSpace(frameSummary))
            {
                sb.AppendLine(frameSummary);
            }

            if (includeHeadline &&
                TryDescribeHookExecutionContext(view, fields, out string executionHeadline, out string executionDetail))
            {
                sb.Append(executionHeadline).Append(": ").AppendLine(executionDetail);
            }

            if (!string.IsNullOrWhiteSpace(view.ClassName))
            {
                sb.Append("Class: ").AppendLine(view.ClassName);
            }

            if (view.DesiredAccess != 0)
            {
                sb.Append("DesiredAccess: 0x")
                    .Append(view.DesiredAccess.ToString("X8", CultureInfo.InvariantCulture))
                    .AppendLine();
            }

            if (view.CorrelationFlags != 0)
            {
                sb.Append("CorrelationFlags: ")
                    .Append(EventDetailFormatting.DescribeCorrelationFlags(view.CorrelationFlags))
                    .Append(" (0x")
                    .Append(view.CorrelationFlags.ToString("X8", CultureInfo.InvariantCulture))
                    .AppendLine(")");
            }

            if (view.CorrelationAccessMask != 0)
            {
                sb.Append("CorrelationAccess: ")
                    .Append(EventDetailFormatting.DescribeHandleAccess(view.CorrelationAccessMask))
                    .Append(" (0x")
                    .Append(view.CorrelationAccessMask.ToString("X8", CultureInfo.InvariantCulture))
                    .AppendLine(")");
            }

            if (view.CorrelationAgeMs != 0)
            {
                sb.Append("CorrelationAgeMs: ")
                    .Append(view.CorrelationAgeMs.ToString(CultureInfo.InvariantCulture))
                    .AppendLine();
            }

            if (!string.IsNullOrWhiteSpace(view.ImagePath))
            {
                sb.Append("ImagePath: ").AppendLine(view.ImagePath);
            }

            if (!string.IsNullOrWhiteSpace(view.OriginPath))
            {
                sb.Append("OriginPath: ").AppendLine(view.OriginPath);
            }

            if (!string.IsNullOrWhiteSpace(view.KeyPath))
            {
                sb.Append("KeyPath: ").AppendLine(view.KeyPath);
            }

            if (!string.IsNullOrWhiteSpace(view.ValueName))
            {
                sb.Append("ValueName: ").AppendLine(view.ValueName);
            }

            if (fields.TryGetValue("status", out string? status) && !string.IsNullOrWhiteSpace(status))
            {
                sb.Append("Status: ").AppendLine(status);
            }

            return sb.ToString().Trim();
        }

        private string GetApiGraphProcessName(uint pid)
        {
            if (pid == 0)
            {
                return string.Empty;
            }

            if (_currentSession != null && _currentSession.Pid == unchecked((int)pid))
            {
                return ExtractProcessName(_currentSession.Title);
            }

            ProcessSessionTab? knownTab = _processTabs.FirstOrDefault(x => x.Pid == unchecked((int)pid));
            if (knownTab != null)
            {
                string knownName = ExtractProcessName(knownTab.Title);
                if (!string.IsNullOrWhiteSpace(knownName))
                {
                    return knownName;
                }
            }

            try
            {
                using Process process = Process.GetProcessById(unchecked((int)pid));
                return process.ProcessName;
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string ExtractProcessName(string? title)
        {
            if (string.IsNullOrWhiteSpace(title))
            {
                return string.Empty;
            }

            string trimmed = title.Trim();
            int suffixIndex = trimmed.LastIndexOf(" (", StringComparison.Ordinal);
            if (suffixIndex > 0 && trimmed.EndsWith(")", StringComparison.Ordinal))
            {
                return trimmed[..suffixIndex].Trim();
            }

            return trimmed;
        }

        private (string ActionSuffix, string DetailText) DescribeMemoryContextFromPages(ulong baseAddress)
        {
            PerformanceSample? latestSample =
                _currentSession?.PerformanceHistory.Count > 0 ? _currentSession.PerformanceHistory[^1] : null;
            MemoryPageSample? page = latestSample?.MemoryPages.FirstOrDefault(
                x => baseAddress >= x.BaseAddress && baseAddress < (x.BaseAddress + x.RegionSize));
            if (page == null)
            {
                return (string.Empty, string.Empty);
            }

            string suffix = string.IsNullOrWhiteSpace(page.Category) ? string.Empty
                                                                     : $" in {page.Category.ToLowerInvariant()} region";
            string detail = $"Region: {page.Category} | Protect: {page.ProtectLabel} | Type: {page.TypeLabel}\n";
            return (suffix, detail);
        }

        private string DescribeMemoryImageContext(BrokerEtwEventView view, ulong baseAddress)
        {
            if (view.ImageBase == 0 || view.ImageSize == 0)
            {
                return string.Empty;
            }

            ulong imageEnd = view.ImageBase + view.ImageSize;
            if (baseAddress < view.ImageBase || baseAddress >= imageEnd)
            {
                return string.Empty;
            }

            string moduleName = EventDetailFormatting.ModuleNameFromPath(view.ImagePath);
            if (string.IsNullOrWhiteSpace(moduleName))
            {
                moduleName = "image";
            }

            string imagePathLine =
                string.IsNullOrWhiteSpace(view.ImagePath) ? string.Empty : $"ImagePath: {view.ImagePath}\n";
            return $"Image: {moduleName}\n" + imagePathLine + $"ImageBase: 0x{view.ImageBase:X}\n" +
                   $"ImageSize: 0x{view.ImageSize:X}\n";
        }

        private (string ActionSuffix, string DetailText)
            DescribeMemoryRegionContext(BrokerEtwEventView view, ulong baseAddress, ulong regionSize)
        {
            if (baseAddress == 0)
            {
                return (string.Empty, string.Empty);
            }

            string imageContext = DescribeMemoryImageContext(view, baseAddress);
            if (!string.IsNullOrWhiteSpace(imageContext))
            {
                string moduleName = EventDetailFormatting.ModuleNameFromPath(view.ImagePath);
                string suffix = string.IsNullOrWhiteSpace(moduleName) ? string.Empty : $" in image {moduleName}";
                return (suffix, imageContext);
            }

            (string pageActionSuffix, string pageContext) = DescribeMemoryContextFromPages(baseAddress);
            if (!string.IsNullOrWhiteSpace(pageContext))
            {
                return (pageActionSuffix, pageContext);
            }

            if (view.DeepRegionType != 0 || view.DeepRegionProtect != 0 || regionSize != 0)
            {
                string typeLabel = EventDetailFormatting.DescribeMemoryType(
                    view.DeepRegionType != 0 ? view.DeepRegionType : view.StartRegionType);
                string protectLabel = EventDetailFormatting.DescribeMemoryProtection(
                    view.DeepRegionProtect != 0 ? view.DeepRegionProtect : view.StartRegionProtect);
                string detailText = string.Empty;
                if (!string.IsNullOrWhiteSpace(typeLabel))
                {
                    detailText += $"RegionType: {typeLabel}\n";
                }
                if (!string.IsNullOrWhiteSpace(protectLabel))
                {
                    detailText += $"RegionProtect: {protectLabel}\n";
                }
                return (string.Empty, detailText);
            }

            return (string.Empty, string.Empty);
        }

        private ApiMemoryPageSignal GetOrCreateApiMemoryPageSignal(ulong page)
        {
            if (!_apiMemorySignalsByPage.TryGetValue(page, out ApiMemoryPageSignal? state))
            {
                state = new ApiMemoryPageSignal();
                _apiMemorySignalsByPage[page] = state;
            }

            return state;
        }

        private static Dictionary<string, string> ParseReasonFields(string rawReason)
        {
            return EventDetailsParsing.ParseRawFields(rawReason);
        }

        private static Dictionary<string, string> BuildHookFieldMap(string rawReason, IReadOnlyList<ulong>? hookArgs,
                                                                    uint hookArgCount)
        {
            Dictionary<string, string> fields = ParseReasonFields(rawReason);
            int count = Math.Min((int)hookArgCount, hookArgs?.Count ?? 0);
            for (int i = 0; i < count; i += 1)
            {
                string key = $"a{i}";
                if (!fields.ContainsKey(key))
                {
                    fields[key] = $"0x{hookArgs![i]:X}";
                }
            }

            return fields;
        }

        private static Dictionary<string, string>
        BuildHookFieldMap(BrokerEtwEventView view) => view.GetOrCreateHookFieldMap();

        private static bool
        IsHookKernelCaller(BrokerEtwEventView view) => (view.Flags & BlackbirdNative.IpcEtwFlagHookKernelCaller) != 0;

        private static bool IsHookCurrentProcessTarget(BrokerEtwEventView view)
        {
            if ((view.Flags & BlackbirdNative.IpcEtwFlagHookTargetCurrentProcess) != 0)
            {
                return true;
            }

            uint processPid = view.ProcessPid != 0 ? view.ProcessPid : view.ActorPid;
            return processPid != 0 && (view.TargetPid == 0 || view.TargetPid == processPid);
        }

        private static bool
        IsHookImageSection(BrokerEtwEventView view) => (view.Flags & BlackbirdNative.IpcEtwFlagHookSectionImage) != 0;

        private bool TryDescribeHookExecutionContext(BrokerEtwEventView view,
                                                     IReadOnlyDictionary<string, string> fields, out string headline,
                                                     out string detail)
        {
            headline = string.Empty;
            detail = string.Empty;

            if (!EventDetailFormatting.IsApiGraphCandidate(view))
            {
                return false;
            }

            string apiName = string.IsNullOrWhiteSpace(view.Operation) ? view.EventName : view.Operation;
            bool kernelCaller = IsHookKernelCaller(view);
            bool currentTarget = IsHookCurrentProcessTarget(view);
            bool imageSection = IsHookImageSection(view);

            if (kernelCaller)
            {
                headline = "Kernel Caller";
                detail =
                    "ExecutionContext: this hook fired on a KernelMode caller path. Treat the call as kernel-originated activity or loader/manager plumbing, not a normal user thread directly invoking the API.";
                return true;
            }

            if ((apiName.Equals("NtCreateSection", StringComparison.OrdinalIgnoreCase) ||
                 apiName.Equals("NtMapViewOfSection", StringComparison.OrdinalIgnoreCase)) &&
                currentTarget && imageSection)
            {
                headline = "Loader / Image Mapping";
                detail =
                    "ExecutionContext: image-backed section creation or mapping into the current process. This is commonly loader-style PE/DLL mapping and should be separated from private-memory execution or post-start runtime tampering.";
                return true;
            }

            if (TryDescribeHookStartupContext(view, out string startupHeadline, out string startupDetail))
            {
                headline = startupHeadline;
                detail = startupDetail;
                return true;
            }

            if (!currentTarget && view.TargetPid != 0)
            {
                headline = "Cross-Process Runtime";
                detail =
                    $"ExecutionContext: the API targets another process ({ProcessIdentityResolver.Describe(view.TargetPid)}). This is actual runtime cross-process activity, not local loader setup.";
                return true;
            }

            headline = "User Runtime";
            detail = "ExecutionContext: user-mode call path against the current process outside the startup window.";
            return true;
        }

        private string BuildResolvedHookArgumentsText(string apiName, BrokerEtwEventView view,
                                                      IReadOnlyDictionary<string, string> fields)
        {
            List<(string Name, string Value)> args = ResolveHookArguments(apiName, view, fields);
            if (args.Count == 0)
            {
                return string.Empty;
            }

            var sb = new StringBuilder(256);
            sb.AppendLine("Arguments:");
            for (int i = 0; i < args.Count; i += 1)
            {
                sb.Append("  ").Append(args[i].Name).Append(": ").AppendLine(args[i].Value);
            }

            return sb.ToString().TrimEnd();
        }

        private List<(string Name, string Value)> ResolveHookArguments(string apiName, BrokerEtwEventView view,
                                                                       IReadOnlyDictionary<string, string> fields)
        {
            string name = apiName?.Trim() ?? string.Empty;
            var args = new List<(string Name, string Value)>(8);

            switch (name)
            {
            case "NtWriteVirtualMemory":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "BaseAddress", ResolvePointer(view, fields, "a1", "c1", "base"));
                AddResolvedArg(args, "Buffer", ResolvePointer(view, fields, "a2", "c2"));
                AddResolvedArg(args, "BufferSize", ResolveSize(fields, "a3", "c3", "size"));
                AddResolvedArg(args, "BytesWritten", ResolvePointer(view, fields, "a4", "c4"));
                break;
            case "NtReadVirtualMemory":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "BaseAddress", ResolvePointer(view, fields, "a1", "c1", "base"));
                AddResolvedArg(args, "Buffer", ResolvePointer(view, fields, "a2", "c2"));
                AddResolvedArg(args, "BufferSize", ResolveSize(fields, "a3", "c3", "size"));
                AddResolvedArg(args, "BytesRead", ResolvePointer(view, fields, "a4", "c4"));
                break;
            case "NtAllocateVirtualMemory":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "BaseAddress*", ResolvePointer(view, fields, "a1", "c1", "base"));
                AddResolvedArg(args, "ZeroBits", ResolveHex(fields, "a2", "c2"));
                AddResolvedArg(args, "RegionSize*", ResolveSize(fields, "a3", "c3", "size"));
                AddResolvedArg(args, "AllocationType", ResolveAllocationType(fields, "a4", "c4", "allocType"));
                AddResolvedArg(args, "Protect", ResolveProtect(fields, "a5", "c5", "protect"));
                break;
            case "NtAllocateVirtualMemoryEx":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "BaseAddress*", ResolvePointer(view, fields, "a1", "c1", "base"));
                AddResolvedArg(args, "ZeroBits", ResolveHex(fields, "a2", "c2"));
                AddResolvedArg(args, "RegionSize*", ResolveSize(fields, "a3", "c3", "size"));
                AddResolvedArg(args, "AllocationType", ResolveAllocationType(fields, "a4", "c4", "allocType"));
                AddResolvedArg(args, "ExtendedParameters", ResolvePointer(view, fields, "a5", "c5"));
                AddResolvedArg(args, "ExtendedParameterCount", ResolveHex(fields, "a6", "c6"));
                break;
            case "NtProtectVirtualMemory":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "BaseAddress*", ResolvePointer(view, fields, "a1", "c1", "base"));
                AddResolvedArg(args, "RegionSize*", ResolveSize(fields, "a2", "c2", "size"));
                AddResolvedArg(args, "NewProtect", ResolveProtect(fields, "a3", "c3", "newProtect"));
                AddResolvedArg(args, "OldProtect*", ResolvePointer(view, fields, "a4", "c4"));
                break;
            case "NtCreateSection":
                AddResolvedArg(args, "SectionHandle*", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "DesiredAccess", ResolveHex(fields, "a1", "c1"));
                AddResolvedArg(args, "ObjectAttributes", ResolvePointer(view, fields, "a2", "c2"));
                AddResolvedArg(args, "MaximumSize", ResolveSize(fields, "a3", "c3"));
                AddResolvedArg(args, "SectionPageProtection", ResolveProtect(fields, "a4", "c4"));
                AddResolvedArg(args, "AllocationAttributes", ResolveHex(fields, "a5", "c5"));
                AddResolvedArg(args, "FileHandle", ResolvePointer(view, fields, "a6", "c6"));
                break;
            case "NtMapViewOfSection":
                AddResolvedArg(args, "SectionHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a1", "c1"));
                AddResolvedArg(args, "BaseAddress*", ResolvePointer(view, fields, "a2", "c2", "base"));
                AddResolvedArg(args, "ViewSize*", ResolveSize(fields, "a6", "c3", "size"));
                AddResolvedArg(args, "InheritDisposition", ResolveHex(fields, "a7", "c4"));
                AddResolvedArg(args, "AllocationType", ResolveAllocationType(fields, "c5"));
                AddResolvedArg(args, "Win32Protect", ResolveProtect(fields, "c6"));
                break;
            case "NtMapViewOfSectionEx":
                AddResolvedArg(args, "SectionHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a1", "c1"));
                AddResolvedArg(args, "BaseAddress*", ResolvePointer(view, fields, "a2", "c2", "base"));
                AddResolvedArg(args, "SectionOffset*", ResolvePointer(view, fields, "a3", "c7"));
                AddResolvedArg(args, "ViewSize*", ResolveSize(fields, "a4", "c3", "size"));
                AddResolvedArg(args, "AllocationType", ResolveAllocationType(fields, "a5", "c4"));
                AddResolvedArg(args, "Win32Protect", ResolveProtect(fields, "a6", "c5"));
                AddResolvedArg(args, "ExtendedParameters", ResolvePointer(view, fields, "a7", "c6"));
                break;
            case "NtQueryInformationProcess":
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "ProcessInformationClass", ResolveProcessInformationClass(fields, "a1", "c1"));
                AddResolvedArg(args, "ProcessInformation", ResolvePointer(view, fields, "a2", "c2"));
                AddResolvedArg(args, "ProcessInformationLength", ResolveSize(fields, "a3", "c3"));
                AddResolvedArg(args, "ReturnLength", ResolvePointer(view, fields, "a4", "c4"));
                break;
            case "NtQueryInformationThread":
                AddResolvedArg(args, "ThreadHandle", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "ThreadInformationClass", ResolveHex(fields, "a1", "c1"));
                AddResolvedArg(args, "ThreadInformation", ResolvePointer(view, fields, "a2", "c2"));
                AddResolvedArg(args, "ThreadInformationLength", ResolveSize(fields, "a3", "c3"));
                AddResolvedArg(args, "ReturnLength", ResolvePointer(view, fields, "a4", "c4"));
                break;
            case "NtQuerySystemInformation":
            case "NtQuerySystemInformationEx":
                AddResolvedArg(args, "SystemInformationClass", ResolveSystemInformationClass(fields, "a0", "c0"));
                AddResolvedArg(args, "InputBuffer", ResolvePointer(view, fields, "a1", "c1"));
                AddResolvedArg(args, "InputBufferLength", ResolveSize(fields, "a2", "c2"));
                AddResolvedArg(args, "SystemInformation", ResolvePointer(view, fields, "a3", "c3"));
                AddResolvedArg(args, "SystemInformationLength", ResolveSize(fields, "a4", "c4"));
                AddResolvedArg(args, "ReturnLength", ResolvePointer(view, fields, "a5", "c5"));
                break;
            case "NtQueryPerformanceCounter":
                AddResolvedArg(args, "RawCounter", ResolveHex(fields, "rawCounter", "a0", "c0"));
                AddResolvedArg(args, "VirtualCounter", ResolveHex(fields, "virtualCounter", "a1", "c1"));
                AddResolvedArg(args, "RawDelta", ResolveHex(fields, "rawDelta", "a2", "c2"));
                AddResolvedArg(args, "VirtualDelta", ResolveHex(fields, "virtualDelta", "a3", "c3"));
                AddResolvedArg(args, "CorrectionTicks", ResolveHex(fields, "correctionTicks", "a4", "c4"));
                AddResolvedArg(args, "SourceFlags", ResolveHex(fields, "sourceFlags", "a5", "c5"));
                AddResolvedArg(args, "AutoBiasTicks", ResolveHex(fields, "autoBiasTicks", "a6", "c6"));
                break;
            case "NtCreateThreadEx":
                AddResolvedArg(args, "ThreadHandle*", ResolvePointer(view, fields, "a0", "c0"));
                AddResolvedArg(args, "DesiredAccess", ResolveHex(fields, "a1", "c1"));
                AddResolvedArg(args, "ProcessHandle", ResolvePointer(view, fields, "a2", "c2"));
                AddResolvedArg(args, "StartRoutine", ResolvePointer(view, fields, "a3", "c3"));
                AddResolvedArg(args, "Argument", ResolvePointer(view, fields, "a4", "c4"));
                AddResolvedArg(args, "CreateFlags", ResolveHex(fields, "a5", "c5"));
                AddResolvedArg(args, "StackSize", ResolveSize(fields, "a6", "c6"));
                AddResolvedArg(args, "MaximumStackSize", ResolveSize(fields, "a7", "c7"));
                break;
            case "RtlAddFunctionTable":
                AddResolvedArg(args, "FunctionTable", ResolvePointer(view, fields, "a0"));
                AddResolvedArg(args, "EntryCount", ResolveHex(fields, "a1"));
                AddResolvedArg(args, "BaseAddress", ResolvePointer(view, fields, "a2", "baseAddress"));
                break;
            case "RtlInstallFunctionTableCallback":
                AddResolvedArg(args, "TableIdentifier", ResolvePointer(view, fields, "a0"));
                AddResolvedArg(args, "BaseAddress", ResolvePointer(view, fields, "a1", "baseAddress"));
                AddResolvedArg(args, "Length", ResolveSize(fields, "a2", "length"));
                AddResolvedArg(args, "Callback", ResolvePointer(view, fields, "a3", "callback"));
                break;
            case "RtlDeleteFunctionTable":
                AddResolvedArg(args, "FunctionTable", ResolvePointer(view, fields, "a0", "table"));
                break;
            default:
                for (int i = 0; i < 8; i += 1)
                {
                    string value = ResolvePointer(view, fields, $"a{i}", $"c{i}");
                    AddResolvedArg(args, $"Arg{i}", value);
                }
                break;
            }

            return args;
        }

        private static void AddResolvedArg(List<(string Name, string Value)> args, string name, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                args.Add((name, value));
            }
        }

        private string ResolvePointer(BrokerEtwEventView view, IReadOnlyDictionary<string, string> fields,
                                      params string[] keys)
        {
            ulong value = FirstU64(fields, keys);
            return value == 0 ? string.Empty : FormatObservedPointer(view, value);
        }

        private static string ResolveSize(IReadOnlyDictionary<string, string> fields, params string[] keys)
        {
            ulong value = FirstU64(fields, keys);
            return value == 0 ? string.Empty : $"0x{value:X}";
        }

        private static string ResolveHex(IReadOnlyDictionary<string, string> fields, params string[] keys)
        {
            ulong value = FirstU64(fields, keys);
            return value == 0 ? string.Empty : $"0x{value:X}";
        }

        private static string ResolveProtect(IReadOnlyDictionary<string, string> fields, params string[] keys)
        {
            uint value = (uint)FirstU64(fields, keys);
            return value == 0 ? string.Empty : $"0x{value:X} ({DescribeMemoryProtect(value)})";
        }

        private static string ResolveAllocationType(IReadOnlyDictionary<string, string> fields, params string[] keys)
        {
            uint value = (uint)FirstU64(fields, keys);
            return value == 0 ? string.Empty : $"0x{value:X} ({DescribeMemoryAllocationType(value)})";
        }

        private static string ResolveProcessInformationClass(IReadOnlyDictionary<string, string> fields,
                                                             params string[] keys)
        {
            uint value = (uint)FirstU64(fields, keys);
            if (value == 0)
            {
                return string.Empty;
            }

            string label = value switch {
                0 => "ProcessBasicInformation",
                7 => "ProcessDebugPort",
                26 => "ProcessWow64Information",
                27 => "ProcessImageFileName",
                29 => "ProcessBreakOnTermination",
                30 => "ProcessDebugObjectHandle",
                31 => "ProcessDebugFlags",
                43 => "ProcessImageFileNameWin32",
                _ => "Unknown"
            };

            return $"0x{value:X} ({label})";
        }

        private static string ResolveSystemInformationClass(IReadOnlyDictionary<string, string> fields,
                                                            params string[] keys)
        {
            uint value = (uint)FirstU64(fields, keys);
            if (value == 0)
            {
                return string.Empty;
            }

            string label = value switch {
                5 => "SystemProcessInformation",
                11 => "SystemModuleInformation",
                35 => "SystemKernelDebuggerInformation",
                76 => "SystemFirmwareTableInformation",
                103 => "SystemCodeIntegrityInformation",
                _ => "Unknown"
            };

            return $"0x{value:X} ({label})";
        }

        private static string BuildGenericApiActionLabel(string apiName, IReadOnlyDictionary<string, string> fields)
        {
            if (apiName.Equals("NtCreateThreadEx", StringComparison.OrdinalIgnoreCase))
            {
                ulong startAddress = FirstU64(fields, "a3", "c3");
                ulong targetHandle = FirstU64(fields, "a2", "c0");
                return $"Creates thread (start 0x{startAddress:X}) via target handle 0x{targetHandle:X}";
            }

            if (apiName.Equals("NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                ulong address = FirstU64(fields, "a1", "c0");
                ulong size = FirstU64(fields, "a3", "c1");
                return $"Writes 0x{size:X} bytes into virtual memory at 0x{address:X}";
            }

            if (apiName.Equals("NtReadVirtualMemory", StringComparison.OrdinalIgnoreCase))
            {
                ulong address = FirstU64(fields, "a1", "c0");
                ulong size = FirstU64(fields, "a3", "c1");
                return $"Reads 0x{size:X} bytes from virtual memory at 0x{address:X}";
            }

            if (apiName.Equals("RtlAddFunctionTable", StringComparison.OrdinalIgnoreCase) ||
                apiName.Equals("RtlInstallFunctionTableCallback", StringComparison.OrdinalIgnoreCase))
            {
                ulong baseAddress = FirstU64(fields, "baseAddress", "a2", "a1");
                return $"Registers unwind metadata for region near 0x{baseAddress:X}";
            }

            if (apiName.Equals("RtlDeleteFunctionTable", StringComparison.OrdinalIgnoreCase))
            {
                ulong table = FirstU64(fields, "table", "a0");
                return $"Deletes dynamic unwind metadata table 0x{table:X}";
            }

            if (apiName.Equals("WSASend", StringComparison.OrdinalIgnoreCase) ||
                apiName.Equals("send", StringComparison.OrdinalIgnoreCase))
            {
                return "Sends network payload";
            }

            if (apiName.Equals("WSARecv", StringComparison.OrdinalIgnoreCase) ||
                apiName.Equals("recv", StringComparison.OrdinalIgnoreCase))
            {
                return "Receives network payload";
            }

            if (fields.TryGetValue("kind", out string? kind) && !string.IsNullOrWhiteSpace(kind))
            {
                return $"{kind} call: {apiName}";
            }

            return apiName;
        }

        private static ulong FirstU64(IReadOnlyDictionary<string, string> fields, params string[] keys)
        {
            foreach (string key in keys)
            {
                if (fields.TryGetValue(key, out string? value) && TryReadU64(value, out ulong parsed))
                {
                    return parsed;
                }
            }

            return 0;
        }

        private static bool TryReadU64(string? text, out ulong value)
        {
            value = 0;
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            string compact = text.Trim();
            if (compact.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                return ulong.TryParse(compact[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
            }

            return ulong.TryParse(compact, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
        }

        private static bool TryReadDouble(IReadOnlyDictionary<string, string> fields, out double value,
                                          params string[] keys)
        {
            foreach (string key in keys)
            {
                if (fields.TryGetValue(key, out string? text) &&
                    double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out value))
                {
                    return true;
                }
            }

            value = 0;
            return false;
        }

        private static string DescribeMemoryProtect(uint protect)
        {
            return EventDetailFormatting.DescribeMemoryProtection(protect);
        }

        private static string DescribeMemoryAllocationType(uint allocType)
        {
            var labels = new List<string>(4);
            if ((allocType & 0x1000) != 0)
            {
                labels.Add("MEM_COMMIT");
            }
            if ((allocType & 0x2000) != 0)
            {
                labels.Add("MEM_RESERVE");
            }
            if ((allocType & 0x1000000) != 0)
            {
                labels.Add("MEM_LARGE_PAGES");
            }
            if ((allocType & 0x20000) != 0)
            {
                labels.Add("MEM_PHYSICAL");
            }

            return labels.Count == 0 ? "<none>" : string.Join(" | ", labels);
        }

        private static double ComputeSampleEntropyBits(byte[]? data, int length)
        {
            if (data == null || data.Length == 0 || length <= 1)
            {
                return -1;
            }

            int sampleLength = Math.Min(length, data.Length);
            Span<int> counts = stackalloc int[256];
            for (int i = 0; i < sampleLength; i += 1)
            {
                counts[data[i]] += 1;
            }

            double entropy = 0;
            for (int i = 0; i < counts.Length; i += 1)
            {
                int count = counts[i];
                if (count == 0)
                {
                    continue;
                }

                double p = count / (double)sampleLength;
                entropy -= p * Math.Log(p, 2.0);
            }

            return entropy;
        }

        private sealed class ApiMemoryPageSignal
        {
            public uint Protect { get; set; }
            public int ProtectFlipCount { get; set; }
            public double LastEntropyBits { get; set; } = double.NaN;
            public int EntropyFlipCount { get; set; }
            public DateTime LastProtectChangeUtc { get; set; }
            public DateTime LastEntropyChangeUtc { get; set; }
        }

        private sealed class RecentImageFileAccess
        {
            public DateTime TimestampUtc { get; init; }
            public uint Pid { get; init; }
            public uint Tid { get; init; }
            public uint Operation { get; init; }
            public string Path { get; init; } = string.Empty;
            public string FileName { get; init; } = string.Empty;
        }

        private sealed class RecentImageMapState
        {
            public DateTime FirstSeenUtc { get; set; }
            public DateTime LastSeenUtc { get; set; }
            public string Path { get; set; } = string.Empty;
            public string LastApi { get; set; } = string.Empty;
            public int Count { get; set; }
            public RecentImageFileAccess? LastLinkedFileAccess { get; set; }

            public RecentImageMapState Clone() => new() { FirstSeenUtc = FirstSeenUtc,
                                                          LastSeenUtc = LastSeenUtc,
                                                          Path = Path,
                                                          LastApi = LastApi,
                                                          Count = Count,
                                                          LastLinkedFileAccess = LastLinkedFileAccess };
        }

        private readonly struct ApiCallStructuredFields
        {
            internal string Action { get; init; }
            internal string Field1Label { get; init; }
            internal string Field2Label { get; init; }
            internal string Field3Label { get; init; }
            internal string Field4Label { get; init; }
            internal string Field1Value { get; init; }
            internal string Field2Value { get; init; }
            internal string Field3Value { get; init; }
            internal string Field4Value { get; init; }
        }

        private enum BackendUiWorkKind
        {
            Ioctl,
            Etw,
            Status
        }

        private readonly struct BackendUiWorkItem
        {
            internal BackendUiWorkKind Kind { get; }
            internal TelemetryEvent? Telemetry { get; }
            internal ProcessRelationView? Relation { get; }
            internal HeuristicEventView? Heuristic { get; }
            internal ThreadLifecycleEventSample? ThreadLifecycle { get; }
            internal IoctlParsedEvent? Filesystem { get; }
            internal IoctlParsedEvent? Registry { get; }
            internal BrokerEtwEventView? EtwView { get; }
            internal string? StatusLine { get; }

            private BackendUiWorkItem(BackendUiWorkKind kind, TelemetryEvent? telemetry, ProcessRelationView? relation,
                                      HeuristicEventView? heuristic, ThreadLifecycleEventSample? threadLifecycle,
                                      IoctlParsedEvent? filesystem, IoctlParsedEvent? registry,
                                      BrokerEtwEventView? etwView, string? statusLine)
            {
                Kind = kind;
                Telemetry = telemetry;
                Relation = relation;
                Heuristic = heuristic;
                ThreadLifecycle = threadLifecycle;
                Filesystem = filesystem;
                Registry = registry;
                EtwView = etwView;
                StatusLine = statusLine;
            }

            internal static BackendUiWorkItem
                FromIoctl(TelemetryEvent? telemetry, ProcessRelationView? relation, HeuristicEventView? heuristic,
                          ThreadLifecycleEventSample? threadLifecycle, IoctlParsedEvent? filesystem,
                          IoctlParsedEvent? registry = null) => new(BackendUiWorkKind.Ioctl, telemetry, relation,
                                                                    heuristic, threadLifecycle, filesystem, registry,
                                                                    null, null);

            internal static BackendUiWorkItem FromEtw(BrokerEtwEventView etwView) => new(BackendUiWorkKind.Etw, null,
                                                                                         null, null, null, null, null,
                                                                                         etwView, null);

            internal static BackendUiWorkItem FromStatus(string statusLine) => new(BackendUiWorkKind.Status, null, null,
                                                                                   null, null, null, null, null,
                                                                                   statusLine);
        }
    }
}
