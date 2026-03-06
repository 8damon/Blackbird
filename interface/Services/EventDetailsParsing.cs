using System;
using System.Collections.Generic;
using System.Globalization;

namespace SleepwalkerInterface
{
    internal static class EventDetailsParsing
    {
        internal static bool TryParseHexU32(string? text, out uint value)
        {
            value = 0;
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            string token = NormalizeHexToken(text);
            return uint.TryParse(token, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
        }

        internal static bool TryParseHexU64(string? text, out ulong value)
        {
            value = 0;
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            string token = NormalizeHexToken(text);
            return ulong.TryParse(token, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
        }

        internal static bool TryParseUInt(string? text, out uint value)
        {
            value = 0;
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            return uint.TryParse(text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
        }

        internal static bool TryParsePidFromIdentity(string? text, out uint value)
        {
            value = 0;
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            string trimmed = text.Trim();
            int length = 0;
            while (length < trimmed.Length && char.IsDigit(trimmed[length]))
            {
                length += 1;
            }

            if (length == 0)
            {
                return false;
            }

            return uint.TryParse(trimmed[..length], NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
        }

        internal static string ReadTokenValue(string text, string prefix)
        {
            if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(prefix))
            {
                return string.Empty;
            }

            int index = text.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            if (index < 0)
            {
                return string.Empty;
            }

            int start = index + prefix.Length;
            if (start >= text.Length)
            {
                return string.Empty;
            }

            int end = start;
            while (end < text.Length && !char.IsWhiteSpace(text[end]))
            {
                end += 1;
            }

            return text[start..end].Trim();
        }

        internal static string SliceBetween(string text, string startToken, string endToken)
        {
            if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(startToken))
            {
                return string.Empty;
            }

            int start = text.IndexOf(startToken, StringComparison.OrdinalIgnoreCase);
            if (start < 0)
            {
                return string.Empty;
            }

            start += startToken.Length;
            if (start >= text.Length)
            {
                return string.Empty;
            }

            if (string.IsNullOrEmpty(endToken))
            {
                return text[start..].Trim();
            }

            int end = text.IndexOf(endToken, start, StringComparison.OrdinalIgnoreCase);
            if (end < 0)
            {
                return text[start..].Trim();
            }

            return text[start..end].Trim();
        }

        internal static string ReadRestAfter(string text, string token)
        {
            if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(token))
            {
                return string.Empty;
            }

            int index = text.IndexOf(token, StringComparison.OrdinalIgnoreCase);
            if (index < 0)
            {
                return string.Empty;
            }

            int start = index + token.Length;
            if (start >= text.Length)
            {
                return string.Empty;
            }

            return text[start..].Trim();
        }

        internal static Dictionary<string, string> ParseRawFields(string? details)
        {
            var parsed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(details))
            {
                return parsed;
            }

            string text = details.Trim();
            int index = 0;
            while (index < text.Length)
            {
                while (index < text.Length && char.IsWhiteSpace(text[index]))
                {
                    index += 1;
                }

                if (index >= text.Length)
                {
                    break;
                }

                int keyStart = index;
                while (index < text.Length && text[index] != '=' && !char.IsWhiteSpace(text[index]))
                {
                    index += 1;
                }

                if (index >= text.Length || text[index] != '=')
                {
                    while (index < text.Length && !char.IsWhiteSpace(text[index]))
                    {
                        index += 1;
                    }
                    continue;
                }

                string key = text[keyStart..index].Trim();
                index += 1;

                int valueStart = index;
                while (index < text.Length)
                {
                    if (!char.IsWhiteSpace(text[index]))
                    {
                        index += 1;
                        continue;
                    }

                    int probe = index;
                    while (probe < text.Length && char.IsWhiteSpace(text[probe]))
                    {
                        probe += 1;
                    }

                    if (probe >= text.Length)
                    {
                        index = probe;
                        break;
                    }

                    int nextKeyStart = probe;
                    while (probe < text.Length && text[probe] != '=' && !char.IsWhiteSpace(text[probe]))
                    {
                        probe += 1;
                    }

                    if (probe < text.Length && text[probe] == '=' && probe > nextKeyStart)
                    {
                        break;
                    }

                    index += 1;
                }

                string value = text[valueStart..index].Trim();
                if (!string.IsNullOrWhiteSpace(key))
                {
                    parsed[key] = value;
                }
            }

            return parsed;
        }

        internal static string FallbackText(string? value, string fallback = "-")
        {
            return string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
        }

        private static string NormalizeHexToken(string text)
        {
            string token = text.Trim();
            if (token.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                token = token[2..];
            }

            int end = token.IndexOfAny(new[] { ' ', ';', ',', ')' });
            if (end >= 0)
            {
                token = token[..end];
            }

            return token;
        }
    }
}
