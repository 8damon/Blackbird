using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace BlackbirdInterface
{
    internal sealed partial class SignatureIntelService
    {
        private sealed record SigmaRule(string Id, string Title, string Description, string Level, uint Severity,
                                        string MitreTechniqueId, string Condition, SigmaLogsource Logsource,
                                        IReadOnlyList<string> Tags,
                                        IReadOnlyDictionary<string, SigmaSelection> Selections)
        {
            public bool IsMatch(SignatureEventContext context, out string matchSummary)
            {
                matchSummary = string.Empty;
                if (!Logsource.Matches(context))
                {
                    return false;
                }

                var results = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
                var matched = new List<string>();
                foreach (KeyValuePair<string, SigmaSelection> selection in Selections)
                {
                    if (selection.Value.IsMatch(context, out string details))
                    {
                        results[selection.Key] = true;
                        matched.Add($"{selection.Key}:{details}");
                    }
                    else
                    {
                        results[selection.Key] = false;
                    }
                }

                bool condition = EvaluateSigmaCondition(Condition, results);
                matchSummary = matched.Count == 0 ? "none" : string.Join(",", matched);
                return condition;
            }
        }

        private sealed record SigmaLogsource(string Product, string Category, string Service)
        {
            public bool Matches(SignatureEventContext context)
            {
                if (!string.IsNullOrWhiteSpace(Product) &&
                    !Product.Equals("windows", StringComparison.OrdinalIgnoreCase) &&
                    !Product.Equals("BK", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                if (!string.IsNullOrWhiteSpace(Category) && !context.Categories.Contains(Category.Trim()))
                {
                    return false;
                }

                if (string.IsNullOrWhiteSpace(Service))
                {
                    return true;
                }

                string service = Service.Trim();
                return service.Equals("sysmon", StringComparison.OrdinalIgnoreCase) ||
                       service.Equals("security", StringComparison.OrdinalIgnoreCase) ||
                       service.Equals("BK", StringComparison.OrdinalIgnoreCase) ||
                       service.Equals(context.Service, StringComparison.OrdinalIgnoreCase) ||
                       service.Equals(context.Source, StringComparison.OrdinalIgnoreCase);
            }
        }

        private sealed record SigmaSelection(IReadOnlyList<SigmaSelectionBranch> Branches)
        {
            public bool IsMatch(SignatureEventContext context, out string details)
            {
                foreach (SigmaSelectionBranch branch in Branches)
                {
                    if (branch.IsMatch(context, out details))
                    {
                        return true;
                    }
                }

                details = string.Empty;
                return false;
            }
        }

        private sealed record SigmaSelectionBranch(IReadOnlyList<SigmaFieldCondition> Conditions)
        {
            public bool IsMatch(SignatureEventContext context, out string details)
            {
                var matched = new List<string>();
                foreach (SigmaFieldCondition condition in Conditions)
                {
                    if (!condition.IsMatch(context, out string fieldMatch))
                    {
                        details = string.Empty;
                        return false;
                    }
                    matched.Add(fieldMatch);
                }

                details = string.Join("+", matched);
                return true;
            }
        }

        private sealed record SigmaFieldCondition(string Field, IReadOnlyList<string> Modifiers,
                                                  IReadOnlyList<string> Values, bool RequireAllValues)
        {
            public bool IsMatch(SignatureEventContext context, out string matchSummary)
            {
                IReadOnlyList<string> actualValues =
                    Field == "*" ? new[] { context.AggregateText } : context.GetValues(Field);
                bool exists = actualValues.Any(x => !string.IsNullOrWhiteSpace(x));
                if (Modifiers.Any(x => x.Equals("exists", StringComparison.OrdinalIgnoreCase)))
                {
                    bool expected = Values.Count == 0 || !Values[0].Equals("false", StringComparison.OrdinalIgnoreCase);
                    matchSummary = $"{Field}:exists={exists}";
                    return exists == expected;
                }

                if (!exists)
                {
                    matchSummary = $"{Field}:missing";
                    return false;
                }

                if (Values.Count == 0)
                {
                    matchSummary = $"{Field}:present";
                    return true;
                }

                if (RequireAllValues)
                {
                    bool all = Values.All(expected => actualValues.Any(actual => MatchesValue(actual, expected)));
                    matchSummary = all ? $"{Field}:all" : $"{Field}:partial";
                    return all;
                }

                foreach (string expected in Values)
                {
                    foreach (string actual in actualValues)
                    {
                        if (MatchesValue(actual, expected))
                        {
                            matchSummary = $"{Field}:{expected}";
                            return true;
                        }
                    }
                }

                matchSummary = $"{Field}:no-match";
                return false;
            }

            private bool MatchesValue(string actual, string expected)
            {
                string mode =
                    Modifiers.FirstOrDefault(x => x.Equals("contains", StringComparison.OrdinalIgnoreCase) ||
                                                  x.Equals("startswith", StringComparison.OrdinalIgnoreCase) ||
                                                  x.Equals("endswith", StringComparison.OrdinalIgnoreCase) ||
                                                  x.Equals("re", StringComparison.OrdinalIgnoreCase) ||
                                                  x.Equals("gt", StringComparison.OrdinalIgnoreCase) ||
                                                  x.Equals("gte", StringComparison.OrdinalIgnoreCase) ||
                                                  x.Equals("lt", StringComparison.OrdinalIgnoreCase) ||
                                                  x.Equals("lte", StringComparison.OrdinalIgnoreCase)) ??
                    string.Empty;
                mode = mode.ToLowerInvariant();

                if (mode.Equals("re", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        return Regex.IsMatch(actual ?? string.Empty, expected ?? string.Empty,
                                             RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                    }
                    catch
                    {
                        return false;
                    }
                }

                if (mode is "gt" or "gte" or "lt" or "lte")
                {
                    if (!TryParseFlexibleInteger(actual, out long actualNumber) ||
                        !TryParseFlexibleInteger(expected, out long expectedNumber))
                    {
                        return false;
                    }

                    return mode switch { "gt" => actualNumber > expectedNumber, "gte" => actualNumber >= expectedNumber,
                                         "lt" => actualNumber < expectedNumber, "lte" => actualNumber <= expectedNumber,
                                         _ => false };
                }

                if (mode.Equals("contains", StringComparison.OrdinalIgnoreCase))
                {
                    return (actual ?? string.Empty)
                               .IndexOf(expected ?? string.Empty, StringComparison.OrdinalIgnoreCase) >= 0;
                }

                if (mode.Equals("startswith", StringComparison.OrdinalIgnoreCase))
                {
                    return (actual ?? string.Empty)
                        .StartsWith(expected ?? string.Empty, StringComparison.OrdinalIgnoreCase);
                }

                if (mode.Equals("endswith", StringComparison.OrdinalIgnoreCase))
                {
                    return (actual ?? string.Empty)
                        .EndsWith(expected ?? string.Empty, StringComparison.OrdinalIgnoreCase);
                }

                if ((expected ?? string.Empty).IndexOfAny(new[] { '*', '?' }) >= 0)
                {
                    return WildcardMatch(actual ?? string.Empty, expected ?? string.Empty);
                }

                return string.Equals(actual ?? string.Empty, expected ?? string.Empty,
                                     StringComparison.OrdinalIgnoreCase);
            }
        }

        private sealed class SignatureEventContext
        {
            private readonly Dictionary<string, List<string>> _fields = new(StringComparer.OrdinalIgnoreCase);

            private SignatureEventContext(string source, string eventName, string service, uint actorPid,
                                          uint targetPid)
            {
                Source = source;
                EventName = eventName;
                Service = service;
                ActorPid = actorPid;
                TargetPid = targetPid;
            }

            public string Source { get; }
            public string EventName { get; }
            public string Service { get; }
            public uint ActorPid { get; }
            public uint TargetPid { get; }
            public uint CorrelationFlags { get; private set; }
            public uint CorrelationAccessMask { get; private set; }
            public uint CorrelationAgeMs { get; private set; }
            public HashSet<string> Categories { get; } = new(StringComparer.OrdinalIgnoreCase);
            public string AggregateText =>
                string.Join(" ", _fields.Values.SelectMany(x => x).Where(x => !string.IsNullOrWhiteSpace(x)));

            public static SignatureEventContext FromEtw(BrokerEtwEventView view)
            {
                var context =
                    new SignatureEventContext(view.Source, view.EventName, "BK", view.ActorPid, view.TargetPid);
                context.CorrelationFlags = view.CorrelationFlags;
                context.CorrelationAccessMask = view.CorrelationAccessMask;
                context.CorrelationAgeMs = view.CorrelationAgeMs;
                context.AddCommonFields(view.Source, view.EventName, view.EventId, view.ActorPid, view.TargetPid,
                                        view.ProcessPid, view.ThreadId, view.CommandLine, view.ImagePath,
                                        view.OriginPath, view.Reason, view.DetectionName, view.Operation);
                context.Add("Task", view.Task);
                context.Add("Opcode", view.Opcode);
                context.Add("Flags", $"0x{view.Flags:X8}");
                context.Add("DetectionTraits", $"0x{view.DetectionTraits:X8}");
                context.Add("ParentProcessId", view.ParentPid);
                context.Add("CreatorProcessId", view.CreatorPid);
                context.Add("CallerProcessId", view.CallerPid);
                context.Add("DesiredAccess", $"0x{view.DesiredAccess:X8}");
                context.Add("GrantedAccess", $"0x{view.DesiredAccess:X8}");
                context.Add(
                    "CallTrace",
                    string.Join(";", (view.Stack ?? Array.Empty<ulong>()).Where(x => x != 0).Select(x => $"0x{x:X}")));
                context.Add("StartAddress", view.StartAddress == 0 ? string.Empty : $"0x{view.StartAddress:X}");
                context.Add("ImageLoaded", view.ImagePath);
                context.Add("TargetObject", CombinePath(view.KeyPath, view.ValueName));
                context.Add("RegistryKey", view.KeyPath);
                context.Add("RegistryValue", view.ValueName);
                context.Add("Details", view.Details);
                context.AddEtwCategories(view);
                return context;
            }

            public static SignatureEventContext FromIoctl(IoctlParsedEvent record)
            {
                string eventName =
                    record.Type switch { var t when t == BlackbirdNative.EventTypeHandle => "ProcessAccess",
                                         var t when t == BlackbirdNative.EventTypeThread => "CreateRemoteThread",
                                         var t when t == BlackbirdNative.EventTypeFileSystem => "FileEvent",
                                         var t when t == BlackbirdNative.EventTypeRegistry => "RegistryEvent",
                                         _ => "IoctlEvent" };
                uint actor =
                    record.Type switch { var t when t == BlackbirdNative.EventTypeFileSystem => record.FileProcessPid,
                                         var t when t == BlackbirdNative.EventTypeRegistry => record.RegistryProcessPid,
                                         var t when t == BlackbirdNative.EventTypeThread => record.CreatorPid,
                                         _ => record.CallerPid };
                uint target = record.Type == BlackbirdNative.EventTypeThread ? record.ProcessPid : record.TargetPid;
                var context = new SignatureEventContext("Kernel-IOCTL", eventName, "BK", actor, target);
                context.AddCommonFields("Kernel-IOCTL", eventName, record.Type, actor, target, record.ProcessPid,
                                        record.ThreadId, string.Empty, string.Empty, record.OriginPath, string.Empty,
                                        string.Empty, eventName);
                context.Add("DesiredAccess", $"0x{record.DesiredAccess:X8}");
                context.Add("GrantedAccess", $"0x{record.DesiredAccess:X8}");
                context.Add("SourceImage", record.OriginPath);
                context.Add("Image", record.OriginPath);
                context.Add(
                    "CallTrace",
                    string.Join(";",
                                (record.Frames ?? Array.Empty<ulong>()).Where(x => x != 0).Select(x => $"0x{x:X}")));
                context.Add("StartAddress", record.StartAddress == 0 ? string.Empty : $"0x{record.StartAddress:X}");
                context.Add("TargetFilename", record.FilePath);
                context.Add("FilePath", record.FilePath);
                context.Add("FileName", record.FilePath);
                context.Add("TargetObject", CombinePath(record.RegistryKeyPath, record.RegistryValueName));
                context.Add("RegistryKey", record.RegistryKeyPath);
                context.Add("RegistryValue", record.RegistryValueName);
                context.Add("FileOperation", $"0x{record.FileOperation:X}");
                context.Add("RegistryOperation", record.RegistryOperation);
                context.AddIoctlCategories(record);
                return context;
            }

            public IReadOnlyList<string> GetValues(string field)
            {
                if (_fields.TryGetValue(field, out List<string>? values))
                {
                    return values;
                }

                return Array.Empty<string>();
            }

            private void AddCommonFields(string source, string eventName, uint eventId, uint actorPid, uint targetPid,
                                         uint processPid, uint threadId, string commandLine, string imagePath,
                                         string originPath, string reason, string detectionName, string operation)
            {
                Add("Product", "windows");
                Add("Provider_Name", source);
                Add("Source", source);
                Add("Channel", source);
                Add("EventID", eventId);
                Add("EventId", eventId);
                Add("EventName", eventName);
                Add("Operation", operation);
                Add("Image", imagePath);
                Add("ImagePath", imagePath);
                Add("ProcessPath", imagePath);
                Add("SourceImage", originPath);
                Add("OriginImage", originPath);
                Add("CommandLine", commandLine);
                Add("ProcessCommandLine", commandLine);
                Add("ProcessId", processPid == 0 ? actorPid : processPid);
                Add("SourceProcessId", actorPid);
                Add("TargetProcessId", targetPid);
                Add("ActorProcessId", actorPid);
                Add("ThreadId", threadId);
                Add("DetectionName", detectionName);
                Add("RuleName", detectionName);
                Add("Reason", reason);
            }

            private void AddEtwCategories(BrokerEtwEventView view)
            {
                Add("Family", view.Family);
                if (view.Family == BlackbirdNative.IpcEtwFamilyProcess &&
                    (view.Flags & BlackbirdNative.IpcEtwFlagProcessIsCreate) != 0)
                {
                    Categories.Add("process_creation");
                }
                else if (view.Family == BlackbirdNative.IpcEtwFamilyProcess ||
                         view.EventName.Contains("terminate", StringComparison.OrdinalIgnoreCase) ||
                         view.EventName.Contains("exit", StringComparison.OrdinalIgnoreCase))
                {
                    Categories.Add("process_termination");
                }
                if (view.Family == BlackbirdNative.IpcEtwFamilyImage || !string.IsNullOrWhiteSpace(view.ImagePath))
                {
                    Categories.Add("image_load");
                }
                if (view.Family == BlackbirdNative.IpcEtwFamilyRegistry || !string.IsNullOrWhiteSpace(view.KeyPath))
                {
                    Categories.Add("registry_event");
                    if (view.Operation.Contains("set", StringComparison.OrdinalIgnoreCase) ||
                        view.Operation.Contains("create", StringComparison.OrdinalIgnoreCase) ||
                        view.Operation.Contains("delete", StringComparison.OrdinalIgnoreCase))
                    {
                        Categories.Add("registry_set");
                    }
                }
                if (view.Family == BlackbirdNative.IpcEtwFamilySocket)
                {
                    Categories.Add("network_connection");
                }
                if ((view.Family == BlackbirdNative.IpcEtwFamilyThread &&
                     (view.Flags & BlackbirdNative.IpcEtwFlagThreadRemoteCreator) != 0) ||
                    view.Family == BlackbirdNative.IpcEtwFamilyApc)
                {
                    Categories.Add("create_remote_thread");
                }
                if (view.Family == BlackbirdNative.IpcEtwFamilyHandle ||
                    view.EventName.Contains("handle", StringComparison.OrdinalIgnoreCase))
                {
                    Categories.Add("process_access");
                }
                if (view.Family == BlackbirdNative.IpcEtwFamilyUserHook)
                {
                    Categories.Add("api_call");
                }
            }

            private void AddIoctlCategories(IoctlParsedEvent record)
            {
                if (record.Type == BlackbirdNative.EventTypeHandle)
                {
                    Categories.Add("process_access");
                }
                else if (record.Type == BlackbirdNative.EventTypeThread)
                {
                    if (record.CreatorPid != 0 && record.ProcessPid != 0 && record.CreatorPid != record.ProcessPid)
                    {
                        Categories.Add("create_remote_thread");
                    }
                }
                else if (record.Type == BlackbirdNative.EventTypeFileSystem)
                {
                    Categories.Add("file_event");
                    Categories.Add("file_create");
                    Categories.Add("file_delete");
                    Categories.Add("file_change");
                }
                else if (record.Type == BlackbirdNative.EventTypeRegistry)
                {
                    Categories.Add("registry_event");
                    if (record.RegistryOperation is BlackbirdNative.RegistryOperationSetValue or
                            BlackbirdNative.RegistryOperationCreateKey or BlackbirdNative
                                .RegistryOperationDeleteValue or BlackbirdNative.RegistryOperationDeleteKey)
                    {
                        Categories.Add("registry_set");
                    }
                }
            }

            private void Add(string key, uint value)
            {
                if (value != 0)
                {
                    Add(key, value.ToString(CultureInfo.InvariantCulture));
                }
            }

            private void Add(string key, ushort value)
            {
                if (value != 0)
                {
                    Add(key, value.ToString(CultureInfo.InvariantCulture));
                }
            }

            private void Add(string key, string? value)
            {
                if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value))
                {
                    return;
                }

                if (!_fields.TryGetValue(key, out List<string>? values))
                {
                    values = new List<string>();
                    _fields[key] = values;
                }

                string trimmed = value.Trim();
                if (!values.Any(existing => existing.Equals(trimmed, StringComparison.OrdinalIgnoreCase)))
                {
                    values.Add(trimmed);
                }
            }

            private static string CombinePath(string? left, string? right)
            {
                if (string.IsNullOrWhiteSpace(left))
                {
                    return right ?? string.Empty;
                }
                if (string.IsNullOrWhiteSpace(right))
                {
                    return left;
                }
                return left.TrimEnd('\\') + "\\" + right.TrimStart('\\');
            }
        }

        private sealed class BooleanExpressionParser
        {
            private readonly List<string> _tokens;
            private readonly Func<string, bool> _resolveIdentifier;
            private int _index;

            public BooleanExpressionParser(string expression, Func<string, bool> resolveIdentifier)
            {
                _tokens = Tokenize(expression ?? string.Empty);
                _resolveIdentifier = resolveIdentifier;
            }

            public bool Parse()
            {
                if (_tokens.Count == 0)
                {
                    return false;
                }

                bool value = ParseOr();
                if (_index != _tokens.Count)
                {
                    throw new FormatException("Unexpected trailing tokens in boolean expression.");
                }

                return value;
            }

            private bool ParseOr()
            {
                bool value = ParseAnd();
                while (Match("or"))
                {
                    value = ParseAnd() || value;
                }
                return value;
            }

            private bool ParseAnd()
            {
                bool value = ParseUnary();
                while (Match("and"))
                {
                    value = ParseUnary() && value;
                }
                return value;
            }

            private bool ParseUnary()
            {
                if (Match("not"))
                {
                    return !ParseUnary();
                }

                return ParsePrimary();
            }

            private bool ParsePrimary()
            {
                if (Match("("))
                {
                    bool value = ParseOr();
                    _ = Match(")");
                    return value;
                }

                if (_index >= _tokens.Count)
                {
                    return false;
                }

                string token = _tokens[_index++];
                if (token.Equals("true", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
                if (token.Equals("false", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
                return _resolveIdentifier(token);
            }

            private bool Match(string token)
            {
                if (_index < _tokens.Count && _tokens[_index].Equals(token, StringComparison.OrdinalIgnoreCase))
                {
                    _index += 1;
                    return true;
                }

                return false;
            }

            private static List<string> Tokenize(string expression)
            {
                var tokens = new List<string>();
                int index = 0;
                while (index < expression.Length)
                {
                    char c = expression[index];
                    if (char.IsWhiteSpace(c))
                    {
                        index += 1;
                        continue;
                    }
                    if (c is '(' or ')')
                    {
                        tokens.Add(c.ToString());
                        index += 1;
                        continue;
                    }

                    int start = index;
                    while (index < expression.Length && !char.IsWhiteSpace(expression[index]) &&
                           expression[index] is not '(' and not ')' and not ',')
                    {
                        index += 1;
                    }

                    if (index > start)
                    {
                        tokens.Add(expression[start..index].Trim());
                    }
                    else
                    {
                        index += 1;
                    }
                }

                return tokens;
            }
        }

        private sealed record YamlLine(int Indent, string Content);
        private abstract record YamlNode;
        private sealed record YamlScalar(string Value) : YamlNode;
        private sealed record YamlList(IReadOnlyList<YamlNode> Items) : YamlNode;
        private sealed record YamlMap(Dictionary<string, YamlNode> Values) : YamlNode;
    }
}
