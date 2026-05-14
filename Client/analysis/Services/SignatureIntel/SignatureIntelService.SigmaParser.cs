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
        private static IEnumerable<SigmaRule> ParseSigmaDocuments(string text)
        {
            foreach (string documentText in SplitYamlDocuments(text))
            {
                if (string.IsNullOrWhiteSpace(documentText))
                {
                    continue;
                }

                YamlNode? rootNode = ParseYamlDocument(documentText);
                if (rootNode is not YamlMap root)
                {
                    continue;
                }

                if (!root.Values.TryGetValue("detection", out YamlNode? detectionNode) ||
                    detectionNode is not YamlMap detectionMap)
                {
                    continue;
                }

                var selections = new Dictionary<string, SigmaSelection>(StringComparer.OrdinalIgnoreCase);
                string condition = string.Empty;
                foreach (KeyValuePair<string, YamlNode> item in detectionMap.Values)
                {
                    if (item.Key.Equals("condition", StringComparison.OrdinalIgnoreCase))
                    {
                        condition = ReadYamlScalar(item.Value);
                        continue;
                    }

                    SigmaSelection selection = ParseSigmaSelection(item.Value);
                    if (selection.Branches.Count != 0)
                    {
                        selections[item.Key] = selection;
                    }
                }

                if (selections.Count == 0)
                {
                    continue;
                }

                condition = string.IsNullOrWhiteSpace(condition) ? selections.Keys.First() : condition.Trim();
                SigmaLogsource logsource = ParseSigmaLogsource(root.Values.TryGetValue("logsource", out YamlNode? ls) ? ls : null);
                string id = ReadYamlMapScalar(root, "id");
                string title = ReadYamlMapScalar(root, "title");
                if (string.IsNullOrWhiteSpace(title))
                {
                    title = string.IsNullOrWhiteSpace(id) ? "SIGMA rule" : id;
                }

                string level = ReadYamlMapScalar(root, "level");
                IReadOnlyList<string> tags = ReadYamlStringList(root.Values.TryGetValue("tags", out YamlNode? tagNode) ? tagNode : null);
                string mitreId = ExtractMitreTechniqueId(tags);
                yield return new SigmaRule(string.IsNullOrWhiteSpace(id) ? StableRuleId(title) : id.Trim(),
                                           title.Trim(), ReadYamlMapScalar(root, "description"), level,
                                           ParseSeverity(level, 5), mitreId, condition, logsource, tags, selections);
            }
        }

        private IReadOnlyList<HeuristicEventView> EvaluateSigmaRules(SignatureEventContext context,
                                                                     DateTime timestampUtc, uint actorPid,
                                                                     uint targetPid, string source, string eventName)
        {
            Ruleset rules = EnsureRulesLoaded();
            if (rules.SigmaRules.Count == 0)
            {
                return Array.Empty<HeuristicEventView>();
            }

            var findings = new List<HeuristicEventView>();
            foreach (SigmaRule rule in rules.SigmaRules)
            {
                if (!rule.IsMatch(context, out string matchSummary))
                {
                    continue;
                }

                string detection =
                    $"SIGMA_{NormalizeDetectionToken(string.IsNullOrWhiteSpace(rule.Id) ? rule.Title : rule.Id)}";
                string reason =
                    BuildRuleReason(rule.Title, rule.Description, rule.MitreTechniqueId, string.Empty, rule.Id);
                string evidence =
                    $"engine=sigma sigma_id={EvidenceToken(rule.Id)} rule={EvidenceToken(rule.Title)} category={EvidenceToken(rule.Logsource.Category)} condition={EvidenceToken(rule.Condition)} fields={EvidenceToken(matchSummary)} event={EvidenceToken(context.Source)}/{EvidenceToken(context.EventName)}";
                HeuristicEventView heuristic =
                    BuildHeuristic(detection, rule.Severity, actorPid, targetPid, source, eventName, reason, evidence);
                heuristic.TimestampUtc = timestampUtc;
                heuristic.LastSeenUtc = timestampUtc;
                heuristic.CorrelationFlags = context.CorrelationFlags;
                heuristic.CorrelationAccessMask = context.CorrelationAccessMask;
                heuristic.CorrelationAgeMs = context.CorrelationAgeMs;
                findings.Add(heuristic);
            }

            return findings;
        }

        private static SigmaLogsource ParseSigmaLogsource(YamlNode? node)
        {
            if (node is not YamlMap map)
            {
                return new SigmaLogsource(string.Empty, string.Empty, string.Empty);
            }

            return new SigmaLogsource(ReadYamlMapScalar(map, "product"), ReadYamlMapScalar(map, "category"),
                                      ReadYamlMapScalar(map, "service"));
        }

        private static SigmaSelection ParseSigmaSelection(YamlNode node)
        {
            var branches = new List<SigmaSelectionBranch>();
            if (node is YamlMap map)
            {
                SigmaSelectionBranch branch = ParseSigmaBranch(map);
                if (branch.Conditions.Count != 0)
                {
                    branches.Add(branch);
                }
            }
            else if (node is YamlList list)
            {
                var keywordValues = new List<string>();
                foreach (YamlNode item in list.Items)
                {
                    if (item is YamlMap itemMap)
                    {
                        SigmaSelectionBranch branch = ParseSigmaBranch(itemMap);
                        if (branch.Conditions.Count != 0)
                        {
                            branches.Add(branch);
                        }
                    }
                    else
                    {
                        keywordValues.AddRange(ReadYamlStringList(item));
                    }
                }

                if (keywordValues.Count != 0)
                {
                    branches.Add(new SigmaSelectionBranch(
                        new[] { new SigmaFieldCondition("*", Array.Empty<string>(), keywordValues, false) }));
                }
            }
            else
            {
                IReadOnlyList<string> values = ReadYamlStringList(node);
                if (values.Count != 0)
                {
                    branches.Add(new SigmaSelectionBranch(
                        new[] { new SigmaFieldCondition("*", Array.Empty<string>(), values, false) }));
                }
            }

            return new SigmaSelection(branches);
        }

        private static SigmaSelectionBranch ParseSigmaBranch(YamlMap map)
        {
            var conditions = new List<SigmaFieldCondition>();
            foreach (KeyValuePair<string, YamlNode> entry in map.Values)
            {
                string[] parts =
                    entry.Key.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (parts.Length == 0)
                {
                    continue;
                }

                string field = parts[0];
                IReadOnlyList<string> modifiers =
                    parts.Skip(1).Select(x => x.Trim()).Where(x => x.Length != 0).ToArray();
                IReadOnlyList<string> values = ReadYamlStringList(entry.Value);
                bool requireAll = modifiers.Any(x => x.Equals("all", StringComparison.OrdinalIgnoreCase));
                conditions.Add(new SigmaFieldCondition(field, modifiers, values, requireAll));
            }

            return new SigmaSelectionBranch(conditions);
        }

        private static string ExtractMitreTechniqueId(IReadOnlyList<string> tags)
        {
            foreach (string tag in tags)
            {
                Match match = Regex.Match(tag, @"attack\.t(?<id>\d{4}(?:\.\d{3})?)", RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    return $"T{match.Groups["id"].Value}";
                }
            }

            return string.Empty;
        }

        private static string StableRuleId(string title)
        {
            string token = NormalizeDetectionToken(title).ToLowerInvariant();
            return string.IsNullOrWhiteSpace(token) ? "BK.sigma.rule" : $"BK.sigma.{token}";
        }

        private static string NormalizeDetectionToken(string value)
        {
            string token = Regex.Replace(value ?? string.Empty, @"[^A-Za-z0-9]+", "_").Trim('_');
            return string.IsNullOrWhiteSpace(token) ? "RULE_MATCH" : token.ToUpperInvariant();
        }

        private static string EvidenceToken(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return "unknown";
            }

            return value.Trim().Replace(' ', '_').Replace('\t', '_');
        }

        private static IEnumerable<string> SplitYamlDocuments(string text)
        {
            var current = new StringBuilder();
            foreach (string rawLine in text.Replace("\r\n", "\n", StringComparison.Ordinal)
                         .Replace('\r', '\n')
                         .Split('\n'))
            {
                string trimmed = rawLine.Trim();
                if (trimmed.Equals("---", StringComparison.Ordinal))
                {
                    if (current.Length != 0)
                    {
                        yield return current.ToString();
                        current.Clear();
                    }
                    continue;
                }

                if (trimmed.Equals("...", StringComparison.Ordinal))
                {
                    continue;
                }

                current.AppendLine(rawLine);
            }

            if (current.Length != 0)
            {
                yield return current.ToString();
            }
        }

        private static YamlNode? ParseYamlDocument(string text)
        {
            List<YamlLine> lines = BuildYamlLines(text);
            if (lines.Count == 0)
            {
                return null;
            }

            int index = 0;
            return ParseYamlBlock(lines, ref index, lines[0].Indent);
        }

        private static List<YamlLine> BuildYamlLines(string text)
        {
            var lines = new List<YamlLine>();
            foreach (string rawLine in text.Replace("\r\n", "\n", StringComparison.Ordinal)
                         .Replace('\r', '\n')
                         .Split('\n'))
            {
                string withoutComment = StripYamlComment(rawLine);
                if (string.IsNullOrWhiteSpace(withoutComment))
                {
                    continue;
                }

                string expanded = withoutComment.Replace("\t", "    ", StringComparison.Ordinal);
                int indent = 0;
                while (indent < expanded.Length && expanded[indent] == ' ')
                {
                    indent += 1;
                }

                string content = expanded[indent..].TrimEnd();
                if (content.Length == 0 || content.Equals("---", StringComparison.Ordinal) ||
                    content.Equals("...", StringComparison.Ordinal))
                {
                    continue;
                }

                lines.Add(new YamlLine(indent, content));
            }

            return lines;
        }

        private static string StripYamlComment(string line)
        {
            bool inSingle = false;
            bool inDouble = false;
            for (int i = 0; i < line.Length; i += 1)
            {
                char c = line[i];
                if (c == '\'' && !inDouble)
                {
                    inSingle = !inSingle;
                    continue;
                }

                if (c == '"' && !inSingle)
                {
                    bool escaped = i > 0 && line[i - 1] == '\\';
                    if (!escaped)
                    {
                        inDouble = !inDouble;
                    }
                    continue;
                }

                if (c == '#' && !inSingle && !inDouble && (i == 0 || char.IsWhiteSpace(line[i - 1])))
                {
                    return line[..i];
                }
            }

            return line;
        }

        private static YamlNode ParseYamlBlock(List<YamlLine> lines, ref int index, int indent)
        {
            if (index >= lines.Count)
            {
                return new YamlScalar(string.Empty);
            }

            return lines[index].Content.StartsWith("- ", StringComparison.Ordinal)
                       ? ParseYamlList(lines, ref index, indent)
                       : ParseYamlMap(lines, ref index, indent);
        }

        private static YamlNode ParseYamlList(List<YamlLine> lines, ref int index, int indent)
        {
            var items = new List<YamlNode>();
            while (index < lines.Count && lines[index].Indent == indent &&
                   lines[index].Content.StartsWith("- ", StringComparison.Ordinal))
            {
                string itemText = lines[index].Content[2..].Trim();
                index += 1;
                if (itemText.Length == 0)
                {
                    if (index < lines.Count && lines[index].Indent > indent)
                    {
                        items.Add(ParseYamlBlock(lines, ref index, lines[index].Indent));
                    }
                    else
                    {
                        items.Add(new YamlScalar(string.Empty));
                    }
                    continue;
                }

                int colon = FindYamlColon(itemText);
                if (colon > 0)
                {
                    var map = new YamlMap(new Dictionary<string, YamlNode>(StringComparer.OrdinalIgnoreCase));
                    AddYamlMapEntry(map, itemText, colon, lines, ref index, indent);
                    if (index < lines.Count && lines[index].Indent > indent)
                    {
                        YamlNode nested = ParseYamlBlock(lines, ref index, lines[index].Indent);
                        if (nested is YamlMap nestedMap)
                        {
                            foreach (KeyValuePair<string, YamlNode> pair in nestedMap.Values)
                            {
                                map.Values[pair.Key] = pair.Value;
                            }
                        }
                    }
                    items.Add(map);
                }
                else
                {
                    items.Add(ParseYamlScalarOrInlineList(itemText));
                }
            }

            return new YamlList(items);
        }

        private static YamlNode ParseYamlMap(List<YamlLine> lines, ref int index, int indent)
        {
            var map = new YamlMap(new Dictionary<string, YamlNode>(StringComparer.OrdinalIgnoreCase));
            while (index < lines.Count && lines[index].Indent == indent &&
                   !lines[index].Content.StartsWith("- ", StringComparison.Ordinal))
            {
                string content = lines[index].Content;
                int colon = FindYamlColon(content);
                index += 1;
                if (colon <= 0)
                {
                    continue;
                }

                AddYamlMapEntry(map, content, colon, lines, ref index, indent);
            }

            return map;
        }

        private static void AddYamlMapEntry(YamlMap map, string content, int colon, List<YamlLine> lines, ref int index,
                                            int indent)
        {
            string key = UnquoteYamlScalar(content[..colon].Trim());
            string valueText = content[(colon + 1)..].Trim();
            if (valueText.Length == 0)
            {
                if (index < lines.Count && lines[index].Indent > indent)
                {
                    map.Values[key] = ParseYamlBlock(lines, ref index, lines[index].Indent);
                }
                else
                {
                    map.Values[key] = new YamlScalar(string.Empty);
                }
                return;
            }

            if (valueText is "|" or ">")
            {
                bool folded = valueText == ">";
                var sb = new StringBuilder();
                while (index < lines.Count && lines[index].Indent > indent)
                {
                    if (sb.Length != 0)
                    {
                        sb.Append(folded ? ' ' : '\n');
                    }
                    sb.Append(lines[index].Content.Trim());
                    index += 1;
                }
                map.Values[key] = new YamlScalar(sb.ToString());
                return;
            }

            map.Values[key] = ParseYamlScalarOrInlineList(valueText);
        }

        private static int FindYamlColon(string text)
        {
            bool inSingle = false;
            bool inDouble = false;
            for (int i = 0; i < text.Length; i += 1)
            {
                char c = text[i];
                if (c == '\'' && !inDouble)
                {
                    inSingle = !inSingle;
                }
                else if (c == '"' && !inSingle)
                {
                    bool escaped = i > 0 && text[i - 1] == '\\';
                    if (!escaped)
                    {
                        inDouble = !inDouble;
                    }
                }
                else if (c == ':' && !inSingle && !inDouble)
                {
                    return i;
                }
            }

            return -1;
        }

        private static YamlNode ParseYamlScalarOrInlineList(string valueText)
        {
            string value = valueText.Trim();
            if (value.StartsWith("[", StringComparison.Ordinal) && value.EndsWith("]", StringComparison.Ordinal))
            {
                string inner = value[1.. ^ 1];
                return new YamlList(SplitYamlInlineList(inner)
                                        .Select(x => new YamlScalar(UnquoteYamlScalar(x)))
                                        .Cast<YamlNode>()
                                        .ToList());
            }

            return new YamlScalar(UnquoteYamlScalar(value));
        }

        private static IEnumerable<string> SplitYamlInlineList(string text)
        {
            var current = new StringBuilder();
            bool inSingle = false;
            bool inDouble = false;
            for (int i = 0; i < text.Length; i += 1)
            {
                char c = text[i];
                if (c == '\'' && !inDouble)
                {
                    inSingle = !inSingle;
                }
                else if (c == '"' && !inSingle)
                {
                    bool escaped = i > 0 && text[i - 1] == '\\';
                    if (!escaped)
                    {
                        inDouble = !inDouble;
                    }
                }

                if (c == ',' && !inSingle && !inDouble)
                {
                    yield return current.ToString().Trim();
                    current.Clear();
                    continue;
                }

                current.Append(c);
            }

            if (current.Length != 0)
            {
                yield return current.ToString().Trim();
            }
        }

        private static string UnquoteYamlScalar(string value)
        {
            string trimmed = value.Trim();
            if (trimmed.Length >= 2 && trimmed[0] == '\'' && trimmed[^1] == '\'')
            {
                return trimmed[1.. ^ 1].Replace("''", "'", StringComparison.Ordinal);
            }

            if (trimmed.Length >= 2 && trimmed[0] == '"' && trimmed[^1] == '"')
            {
                return trimmed[1.. ^ 1]
                    .Replace("\\\"", "\"", StringComparison.Ordinal)
                    .Replace("\\\\", "\\", StringComparison.Ordinal)
                    .Replace("\\n", "\n", StringComparison.Ordinal)
                    .Replace("\\r", "\r", StringComparison.Ordinal)
                    .Replace("\\t", "\t", StringComparison.Ordinal);
            }

            return trimmed;
        }

        private static string ReadYamlMapScalar(YamlMap map, string key)
        {
            return map.Values.TryGetValue(key, out YamlNode? node) ? ReadYamlScalar(node) : string.Empty;
        }

        private static string ReadYamlScalar(YamlNode node)
        {
            return node switch { YamlScalar scalar => scalar.Value,
                                 YamlList list => string.Join(",", list.Items.Select(ReadYamlScalar)),
                                 _ => string.Empty };
        }

        private static IReadOnlyList<string> ReadYamlStringList(YamlNode? node)
        {
            if (node == null)
            {
                return Array.Empty<string>();
            }

            if (node is YamlList list)
            {
                return list.Items.SelectMany(ReadYamlStringList)
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .Select(x => x.Trim())
                    .ToArray();
            }

            string scalar = ReadYamlScalar(node);
            return string.IsNullOrWhiteSpace(scalar) ? Array.Empty<string>() : new[] { scalar.Trim() };
        }
    }
}
