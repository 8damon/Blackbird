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
        private static IEnumerable<YaraRule> ParseYara(string text)
        {
            foreach ((string Name, string Body)ruleBlock in EnumerateYaraRuleBlocks(text))
            {
                string meta = ExtractBlock(ruleBlock.Body, "meta:");
                string strings = ExtractBlock(ruleBlock.Body, "strings:");
                string condition = ExtractBlock(ruleBlock.Body, "condition:");
                if (strings.Length == 0)
                {
                    continue;
                }

                List<YaraPattern> patterns = ParseYaraStrings(strings);
                if (patterns.Count == 0)
                {
                    continue;
                }

                Dictionary<string, string> metaMap = ParseMeta(meta);
                string scope = metaMap.TryGetValue("scope", out string? scopeValue) ? scopeValue : "file,memory,page";
                yield return new YaraRule(
                    ruleBlock.Name,
                    metaMap.TryGetValue("title", out string? title) ? title : ruleBlock.Name,
                    metaMap.TryGetValue("detection", out string? detection) ? detection : ruleBlock.Name.ToUpperInvariant(),
                    metaMap.TryGetValue("mitre_technique_id", out string? mitreId) ? mitreId : string.Empty,
                    metaMap.TryGetValue("mitre_technique", out string? mitreName) ? mitreName : string.Empty,
                    metaMap.TryGetValue("sigma_rule_id", out string? sigmaId) ? sigmaId : string.Empty,
                    ParseSeverity(metaMap.TryGetValue("severity", out string? sev) ? sev : null, 6),
                    scope.Contains("file", StringComparison.OrdinalIgnoreCase),
                    scope.Contains("memory", StringComparison.OrdinalIgnoreCase),
                    scope.Contains("page", StringComparison.OrdinalIgnoreCase),
                    string.IsNullOrWhiteSpace(condition) ? "any of them" : condition.Trim(),
                    patterns);
            }
        }

        private static IEnumerable<(string Name, string Body)> EnumerateYaraRuleBlocks(string text)
        {
            var ruleRegex = new Regex(@"(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b",
                                      RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            int searchIndex = 0;
            while (searchIndex < text.Length)
            {
                Match match = ruleRegex.Match(text, searchIndex);
                if (!match.Success)
                {
                    yield break;
                }

                int open = text.IndexOf('{', match.Index + match.Length);
                if (open < 0)
                {
                    yield break;
                }

                int close = FindMatchingBrace(text, open);
                if (close < 0)
                {
                    yield break;
                }

                yield return (match.Groups[1].Value.Trim(), text.Substring(open + 1, close - open - 1));
                searchIndex = close + 1;
            }
        }

        private static int FindMatchingBrace(string text, int openIndex)
        {
            int depth = 0;
            bool inString = false;
            bool inLineComment = false;
            bool inBlockComment = false;
            for (int i = openIndex; i < text.Length; i += 1)
            {
                char c = text[i];
                char next = i + 1 < text.Length ? text[i + 1] : '\0';

                if (inLineComment)
                {
                    if (c is '\r' or '\n')
                    {
                        inLineComment = false;
                    }
                    continue;
                }

                if (inBlockComment)
                {
                    if (c == '*' && next == '/')
                    {
                        inBlockComment = false;
                        i += 1;
                    }
                    continue;
                }

                if (inString)
                {
                    if (c == '\\')
                    {
                        i += 1;
                        continue;
                    }
                    if (c == '"')
                    {
                        inString = false;
                    }
                    continue;
                }

                if (c == '/' && next == '/')
                {
                    inLineComment = true;
                    i += 1;
                    continue;
                }
                if (c == '/' && next == '*')
                {
                    inBlockComment = true;
                    i += 1;
                    continue;
                }
                if (c == '"')
                {
                    inString = true;
                    continue;
                }
                if (c == '{')
                {
                    depth += 1;
                    continue;
                }
                if (c == '}')
                {
                    depth -= 1;
                    if (depth == 0)
                    {
                        return i;
                    }
                }
            }

            return -1;
        }

        private static List<YaraPattern> ParseYaraStrings(string strings)
        {
            var patterns = new List<YaraPattern>();
            int index = 0;
            while (index < strings.Length)
            {
                int dollar = strings.IndexOf('$', index);
                if (dollar < 0)
                {
                    break;
                }

                int cursor = dollar + 1;
                while (cursor < strings.Length && (char.IsLetterOrDigit(strings[cursor]) || strings[cursor] == '_'))
                {
                    cursor += 1;
                }

                if (cursor == dollar + 1)
                {
                    index = cursor;
                    continue;
                }

                string identifier = strings[(dollar + 1)..cursor];
                cursor = SkipWhitespace(strings, cursor);
                if (cursor >= strings.Length || strings[cursor] != '=')
                {
                    index = cursor;
                    continue;
                }

                cursor = SkipWhitespace(strings, cursor + 1);
                if (cursor >= strings.Length)
                {
                    break;
                }

                if (strings[cursor] == '"')
                {
                    if (!TryReadQuoted(strings, cursor, out string value, out int afterString))
                    {
                        break;
                    }

                    string modifiers = ReadYaraModifiers(strings, afterString, out int afterModifiers);
                    bool nocase = modifiers.Contains("nocase", StringComparison.OrdinalIgnoreCase);
                    bool wide = modifiers.Contains("wide", StringComparison.OrdinalIgnoreCase);
                    bool ascii = modifiers.Contains("ascii", StringComparison.OrdinalIgnoreCase) || !wide;
                    byte[] decoded = DecodeYaraTextBytes(value);
                    if (ascii)
                    {
                        patterns.Add(YaraPattern.Ascii(identifier, decoded, nocase));
                    }
                    if (wide)
                    {
                        patterns.Add(YaraPattern.Wide(identifier, decoded, nocase));
                    }
                    index = afterModifiers;
                    continue;
                }

                if (strings[cursor] == '{')
                {
                    int close = FindHexPatternClose(strings, cursor);
                    if (close < 0)
                    {
                        break;
                    }

                    YaraPattern? pattern =
                        YaraPattern.Hex(identifier, strings.Substring(cursor + 1, close - cursor - 1));
                    if (pattern != null)
                    {
                        patterns.Add(pattern);
                    }
                    _ = ReadYaraModifiers(strings, close + 1, out int afterModifiers);
                    index = afterModifiers;
                    continue;
                }

                index = cursor + 1;
            }

            return patterns;
        }

        private static int SkipWhitespace(string text, int index)
        {
            while (index < text.Length && char.IsWhiteSpace(text[index]))
            {
                index += 1;
            }
            return index;
        }

        private static bool TryReadQuoted(string text, int start, out string value, out int after)
        {
            var sb = new StringBuilder();
            value = string.Empty;
            after = start;
            if (start >= text.Length || text[start] != '"')
            {
                return false;
            }

            for (int i = start + 1; i < text.Length; i += 1)
            {
                char c = text[i];
                if (c == '\\' && i + 1 < text.Length)
                {
                    sb.Append(c);
                    sb.Append(text[i + 1]);
                    i += 1;
                    continue;
                }
                if (c == '"')
                {
                    value = sb.ToString();
                    after = i + 1;
                    return true;
                }
                sb.Append(c);
            }

            return false;
        }

        private static string ReadYaraModifiers(string text, int start, out int after)
        {
            int end = start;
            while (end < text.Length && text[end] is not '\r' and not '\n')
            {
                end += 1;
            }

            after = end;
            return text[start..end];
        }

        private static int FindHexPatternClose(string text, int open)
        {
            int parenDepth = 0;
            for (int i = open + 1; i < text.Length; i += 1)
            {
                char c = text[i];
                if (c == '(')
                {
                    parenDepth += 1;
                }
                else if (c == ')' && parenDepth > 0)
                {
                    parenDepth -= 1;
                }
                else if (c == '}' && parenDepth == 0)
                {
                    return i;
                }
            }

            return -1;
        }

        private static byte[] DecodeYaraTextBytes(string value)
        {
            var bytes = new List<byte>();
            string text = value ?? string.Empty;
            for (int i = 0; i < text.Length; i += 1)
            {
                char c = text[i];
                if (c == '\\' && i + 1 < text.Length)
                {
                    char next = text[i + 1];
                    if (next == 'x' && i + 3 < text.Length &&
                        byte.TryParse(text.Substring(i + 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture,
                                      out byte hex))
                    {
                        bytes.Add(hex);
                        i += 3;
                        continue;
                    }

                    bytes.Add(next switch { 'n' => (byte)'\n', 'r' => (byte)'\r', 't' => (byte)'\t', '"' => (byte)'"',
                                            '\\' => (byte)'\\',
                                            _ => ToYaraByte(next) });
                    i += 1;
                    continue;
                }

                if (c <= 0x7F)
                {
                    bytes.Add((byte)c);
                }
                else
                {
                    bytes.AddRange(Encoding.UTF8.GetBytes(new[] { c }));
                }
            }

            return bytes.ToArray();
        }

        private static byte ToYaraByte(char value) => value <= byte.MaxValue ? (byte)value : (byte)'?';

        private static string ExtractBlock(string body, string marker)
        {
            int start = body.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (start < 0)
                return string.Empty;
            start += marker.Length;
            int end = body.Length;
            foreach (string next in new[] { "meta:", "strings:", "condition:" })
            {
                if (next.Equals(marker, StringComparison.OrdinalIgnoreCase))
                    continue;
                int pos = body.IndexOf(next, start, StringComparison.OrdinalIgnoreCase);
                if (pos >= 0 && pos < end)
                    end = pos;
            }
            return body[start..end];
        }

        private static Dictionary<string, string> ParseMeta(string meta)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string raw in meta.Split('\n'))
            {
                string line = raw.Trim();
                int eq = line.IndexOf('=');
                if (eq <= 0)
                    continue;
                map[line[..eq].Trim()] = line[(eq + 1)..].Trim().Trim('"');
            }
            return map;
        }
    }
}
