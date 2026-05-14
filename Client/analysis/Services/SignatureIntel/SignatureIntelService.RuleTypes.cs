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
        private sealed record WorkItem(string Key, bool IsFile, bool IsPage, string Path, byte[]? Sample,
                                       int SampleSize, uint ActorPid, uint TargetPid, string Source, string EventName,
                                       string Trigger, bool IsProcessMemory = false, uint ProcessId = 0);
        private sealed record MaterializedFinding(string Detection, uint Severity, string Reason, string Evidence)
        {
            public HeuristicEventView ToHeuristic(uint actorPid, uint targetPid, string source, string eventName,
                                                  string trigger) =>
                BuildHeuristic(Detection, Severity, actorPid, targetPid, source, eventName,
                               string.IsNullOrWhiteSpace(trigger) ? Reason : $"{Reason} | trigger={trigger}", Evidence);
        }
        private sealed record CacheEntry(long Length, DateTime LastWriteUtc,
                                         IReadOnlyList<MaterializedFinding> Findings)
        {
            public bool Matches(FileInfo info) => info.Length == Length && info.LastWriteTimeUtc == LastWriteUtc;
        }
        private sealed record Ruleset(IReadOnlyList<ManifestRule> ManifestRules, IReadOnlyList<YaraRule> YaraRules,
                                      IReadOnlyList<SigmaRule> SigmaRules);
        internal sealed record SignatureIntelRuleDocument(string DisplayName, string FullPath, string RelativePath,
                                                          string Kind, int RuleCount, bool IsUserRule);
        private sealed class ManifestDocument
        {
            [JsonPropertyName("rules")]
            public List<ManifestRule?>? Rules { get; init; }
        }
        private sealed class ManifestRule
        {
            [JsonPropertyName("id")]
            public string Id { get; init; } = string.Empty;
            [JsonPropertyName("title")]
            public string Title { get; init; } = string.Empty;
            [JsonPropertyName("description")]
            public string Description { get; init; } = string.Empty;
            [JsonPropertyName("severity")]
            public string Severity { get; init; } = string.Empty;
            [JsonPropertyName("detection")]
            public string Detection { get; init; } = string.Empty;
            [JsonPropertyName("mitre_technique_id")]
            public string MitreTechniqueId { get; init; } = string.Empty;
            [JsonPropertyName("mitre_technique")]
            public string MitreTechnique { get; init; } = string.Empty;
            [JsonPropertyName("sigma_rule_id")]
            public string SigmaRuleId { get; init; } = string.Empty;
            [JsonPropertyName("sha256")]
            public string Sha256 { get; init; } = string.Empty;
            [JsonPropertyName("sha1")]
            public string Sha1 { get; init; } = string.Empty;
            [JsonPropertyName("md5")]
            public string Md5 { get; init; } = string.Empty;
            [JsonPropertyName("file_name_contains")]
            public string FileNameContains { get; init; } = string.Empty;
            [JsonPropertyName("path_contains")]
            public string PathContains { get; init; } = string.Empty;
            [JsonPropertyName("signer_state")]
            public string SignerState { get; init; } = string.Empty;
            [JsonPropertyName("signer_contains")]
            public string SignerContains { get; init; } = string.Empty;
            [JsonPropertyName("contains_ascii")]
            public string ContainsAscii { get; init; } = string.Empty;
            [JsonPropertyName("contains_ascii_nocase")]
            public bool ContainsAsciiNoCase { get; init; }
        }
        private sealed record YaraRule(string Name, string Title, string Detection, string MitreId, string MitreName,
                                       string SigmaId, uint Severity, bool FileScope, bool MemoryScope, bool PageScope,
                                       string Condition, IReadOnlyList<YaraPattern> Patterns)
        {
            public bool IsMatch(ReadOnlySpan<byte> bytes)
            {
                var hits = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
                for (int i = 0; i < Patterns.Count; i += 1)
                {
                    YaraPattern pattern = Patterns[i];
                    bool matched = pattern.IsMatch(bytes);
                    hits[pattern.Identifier] =
                        hits.TryGetValue(pattern.Identifier, out bool existing) ? existing || matched : matched;
                }
                return EvaluateYaraCondition(Condition, hits);
            }
        }

        private sealed class YaraPattern
        {
            private readonly byte[]? _ascii;
            private readonly IReadOnlyList<HexElement>? _hex;
            private readonly bool _nocase;

            private YaraPattern(string identifier, byte[] ascii, bool nocase)
            {
                Identifier = "$" + identifier.TrimStart('$');
                _ascii = ascii;
                _nocase = nocase;
            }

            private YaraPattern(string identifier, IReadOnlyList<HexElement> hex)
            {
                Identifier = "$" + identifier.TrimStart('$');
                _hex = hex;
            }

            public string Identifier { get; }

            public static YaraPattern Ascii(string identifier, byte[] bytes,
                                            bool nocase) => new(identifier, NormalizeAsciiBytes(bytes, nocase), nocase);

            public static YaraPattern Wide(string identifier, byte[] bytes, bool nocase)
            {
                byte[] normalized = NormalizeAsciiBytes(bytes, nocase);
                var wide = new byte[normalized.Length * 2];
                for (int i = 0; i < normalized.Length; i += 1)
                {
                    wide[i * 2] = normalized[i];
                }

                return new YaraPattern(identifier, wide, nocase);
            }

            private static byte[] NormalizeAsciiBytes(byte[] bytes, bool nocase)
            {
                byte[] normalized = (bytes ?? Array.Empty<byte>()).ToArray();
                if (!nocase)
                {
                    return normalized;
                }

                for (int i = 0; i < normalized.Length; i += 1)
                {
                    if (normalized[i] < 0x80)
                    {
                        normalized[i] = (byte)char.ToUpperInvariant((char)normalized[i]);
                    }
                }

                return normalized;
            }

            public static YaraPattern? Hex(string identifier, string text)
            {
                var parser = new HexPatternParser(text);
                IReadOnlyList<HexElement>? elements = parser.Parse();
                return elements == null || elements.Count == 0 ? null : new YaraPattern(identifier, elements);
            }

            public bool IsMatch(ReadOnlySpan<byte> bytes)
            {
                if (_ascii != null)
                {
                    return MatchAscii(bytes);
                }

                return _hex != null && MatchHex(bytes);
            }

            private bool MatchAscii(ReadOnlySpan<byte> bytes)
            {
                if (_ascii == null || bytes.Length < _ascii.Length)
                {
                    return false;
                }

                for (int i = 0; i <= bytes.Length - _ascii.Length; i += 1)
                {
                    bool ok = true;
                    for (int j = 0; j < _ascii.Length; j += 1)
                    {
                        byte hay = bytes[i + j];
                        if (_nocase && hay < 0x80)
                        {
                            hay = (byte)char.ToUpperInvariant((char)hay);
                        }
                        if (hay != _ascii[j])
                        {
                            ok = false;
                            break;
                        }
                    }
                    if (ok)
                    {
                        return true;
                    }
                }

                return false;
            }

            private bool MatchHex(ReadOnlySpan<byte> bytes)
            {
                if (_hex == null)
                {
                    return false;
                }

                for (int i = 0; i < bytes.Length; i += 1)
                {
                    if (MatchHexSequence(bytes, _hex, 0, i))
                    {
                        return true;
                    }
                }

                return false;
            }

            private static bool MatchHexSequence(ReadOnlySpan<byte> bytes, IReadOnlyList<HexElement> elements,
                                                 int elementIndex, int offset)
            {
                if (elementIndex >= elements.Count)
                {
                    return true;
                }

                if (offset > bytes.Length)
                {
                    return false;
                }

                HexElement element = elements[elementIndex];
                if (element.Kind == HexElementKind.Byte)
                {
                    if (offset >= bytes.Length)
                    {
                        return false;
                    }
                    if ((bytes[offset] & element.Mask) != element.Value)
                    {
                        return false;
                    }
                    return MatchHexSequence(bytes, elements, elementIndex + 1, offset + 1);
                }

                if (element.Kind == HexElementKind.Jump)
                {
                    int maxSkip = Math.Min(element.MaxJump, bytes.Length - offset);
                    for (int skip = Math.Max(0, element.MinJump); skip <= maxSkip; skip += 1)
                    {
                        if (MatchHexSequence(bytes, elements, elementIndex + 1, offset + skip))
                        {
                            return true;
                        }
                    }
                    return false;
                }

                foreach (IReadOnlyList<HexElement> alternative in element.Alternatives)
                {
                    foreach (int end in MatchHexAlternativeEnds(bytes, alternative, 0, offset))
                    {
                        if (MatchHexSequence(bytes, elements, elementIndex + 1, end))
                        {
                            return true;
                        }
                    }
                }

                return false;
            }

            private static List<int> MatchHexAlternativeEnds(ReadOnlySpan<byte> bytes,
                                                             IReadOnlyList<HexElement> elements, int elementIndex,
                                                             int offset)
            {
                var results = new List<int>();
                if (elementIndex >= elements.Count)
                {
                    results.Add(offset);
                    return results;
                }

                HexElement element = elements[elementIndex];
                if (element.Kind == HexElementKind.Byte)
                {
                    if (offset < bytes.Length && (bytes[offset] & element.Mask) == element.Value)
                    {
                        foreach (int end in MatchHexAlternativeEnds(bytes, elements, elementIndex + 1, offset + 1))
                        {
                            results.Add(end);
                        }
                    }
                    return results;
                }

                if (element.Kind == HexElementKind.Jump)
                {
                    int maxSkip = Math.Min(element.MaxJump, bytes.Length - offset);
                    for (int skip = Math.Max(0, element.MinJump); skip <= maxSkip; skip += 1)
                    {
                        foreach (int end in MatchHexAlternativeEnds(bytes, elements, elementIndex + 1, offset + skip))
                        {
                            results.Add(end);
                        }
                    }
                    return results;
                }

                foreach (IReadOnlyList<HexElement> alternative in element.Alternatives)
                {
                    foreach (int altEnd in MatchHexAlternativeEnds(bytes, alternative, 0, offset))
                    {
                        foreach (int end in MatchHexAlternativeEnds(bytes, elements, elementIndex + 1, altEnd))
                        {
                            results.Add(end);
                        }
                    }
                }

                return results;
            }
        }

        private enum HexElementKind
        {
            Byte,
            Jump,
            Alternative
        }

        private sealed record HexElement(HexElementKind Kind, byte Value, byte Mask, int MinJump, int MaxJump,
                                         IReadOnlyList<IReadOnlyList<HexElement>> Alternatives)
        {
            public static HexElement Byte(byte value, byte mask) =>
                new(HexElementKind.Byte, value, mask, 0, 0, Array.Empty<IReadOnlyList<HexElement>>());
            public static HexElement Jump(int min, int max) =>
                new(HexElementKind.Jump, 0, 0, min, max, Array.Empty<IReadOnlyList<HexElement>>());
            public static HexElement Alternative(IReadOnlyList<IReadOnlyList<HexElement>> alternatives) =>
                new(HexElementKind.Alternative, 0, 0, 0, 0, alternatives);
        }

        private sealed class HexPatternParser
        {
            private const int OpenEndedJumpCap = 512;
            private readonly string _text;
            private int _index;

            public HexPatternParser(string text) => _text = text ?? string.Empty;

            public IReadOnlyList<HexElement>? Parse()
            {
                List<HexElement>? elements = ParseSequence(stopAtPipeOrParen: false);
                return elements;
            }

            private List<HexElement>? ParseSequence(bool stopAtPipeOrParen)
            {
                var elements = new List<HexElement>();
                while (_index < _text.Length)
                {
                    SkipSpace();
                    if (_index >= _text.Length)
                    {
                        break;
                    }

                    char c = _text[_index];
                    if (stopAtPipeOrParen && (c == '|' || c == ')'))
                    {
                        break;
                    }

                    if (c == '[')
                    {
                        HexElement? jump = ParseJump();
                        if (jump == null)
                        {
                            return null;
                        }
                        elements.Add(jump);
                        continue;
                    }

                    if (c == '(')
                    {
                        HexElement? alternative = ParseAlternative();
                        if (alternative == null)
                        {
                            return null;
                        }
                        elements.Add(alternative);
                        continue;
                    }

                    HexElement? b = ParseByte();
                    if (b == null)
                    {
                        return null;
                    }
                    elements.Add(b);
                }

                return elements;
            }

            private HexElement? ParseJump()
            {
                int close = _text.IndexOf(']', _index + 1);
                if (close < 0)
                {
                    return null;
                }

                string token = _text.Substring(_index + 1, close - _index - 1).Trim();
                _index = close + 1;
                if (token.Length == 0 || token == "-")
                {
                    return HexElement.Jump(0, OpenEndedJumpCap);
                }

                string[] parts = token.Split('-', 2, StringSplitOptions.TrimEntries);
                if (parts.Length == 1)
                {
                    return int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out int exact)
                               ? HexElement.Jump(Math.Max(0, exact), Math.Max(0, exact))
                               : null;
                }

                int min =
                    string.IsNullOrWhiteSpace(parts[0]) ? 0
                    : int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsedMin)
                        ? parsedMin
                        : -1;
                int max =
                    string.IsNullOrWhiteSpace(parts[1]) ? OpenEndedJumpCap
                    : int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsedMax)
                        ? parsedMax
                        : -1;
                if (min < 0 || max < min)
                {
                    return null;
                }

                return HexElement.Jump(min, Math.Min(max, OpenEndedJumpCap));
            }

            private HexElement? ParseAlternative()
            {
                _index += 1;
                var alternatives = new List<IReadOnlyList<HexElement>>();
                while (_index < _text.Length)
                {
                    List<HexElement>? sequence = ParseSequence(stopAtPipeOrParen: true);
                    if (sequence == null)
                    {
                        return null;
                    }
                    alternatives.Add(sequence);
                    SkipSpace();
                    if (_index >= _text.Length)
                    {
                        return null;
                    }
                    if (_text[_index] == '|')
                    {
                        _index += 1;
                        continue;
                    }
                    if (_text[_index] == ')')
                    {
                        _index += 1;
                        return alternatives.Count == 0 ? null : HexElement.Alternative(alternatives);
                    }
                    return null;
                }

                return null;
            }

            private HexElement? ParseByte()
            {
                SkipSpace();
                if (_index >= _text.Length)
                {
                    return null;
                }

                int start = _index;
                while (_index < _text.Length && (Uri.IsHexDigit(_text[_index]) || _text[_index] == '?'))
                {
                    _index += 1;
                }

                string token = _text[start.._index];
                if (token.Length is not 1 and not 2)
                {
                    return null;
                }
                if (token.Length == 1)
                {
                    token += "?";
                }

                byte value = 0;
                byte mask = 0;
                for (int i = 0; i < 2; i += 1)
                {
                    char c = token[i];
                    if (c == '?')
                    {
                        continue;
                    }
                    if (!byte.TryParse(c.ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture,
                                       out byte nibble))
                    {
                        return null;
                    }
                    int shift = i == 0 ? 4 : 0;
                    value |= (byte)(nibble << shift);
                    mask |= (byte)(0xFu << shift);
                }

                return HexElement.Byte(value, mask);
            }

            private void SkipSpace()
            {
                while (_index < _text.Length && char.IsWhiteSpace(_text[_index]))
                {
                    _index += 1;
                }
            }
        }
    }
}
