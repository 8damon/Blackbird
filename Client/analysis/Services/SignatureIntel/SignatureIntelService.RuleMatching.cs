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
        private static bool RuleMatches(ManifestRule rule, string path, string fileName, SignatureTrustState signature,
                                        string signer, string sha256, string sha1, string md5, byte[]? content)
        {
            if (!string.IsNullOrWhiteSpace(rule.FileNameContains) &&
                fileName.IndexOf(rule.FileNameContains, StringComparison.OrdinalIgnoreCase) < 0)
                return false;
            if (!string.IsNullOrWhiteSpace(rule.PathContains) &&
                path.IndexOf(rule.PathContains, StringComparison.OrdinalIgnoreCase) < 0)
                return false;
            if (!string.IsNullOrWhiteSpace(rule.SignerState) &&
                !string.Equals(rule.SignerState, signature.ToString(), StringComparison.OrdinalIgnoreCase))
                return false;
            if (!string.IsNullOrWhiteSpace(rule.SignerContains) &&
                signer.IndexOf(rule.SignerContains, StringComparison.OrdinalIgnoreCase) < 0)
                return false;
            if (!string.IsNullOrWhiteSpace(rule.Sha256) &&
                !string.Equals(rule.Sha256, sha256, StringComparison.OrdinalIgnoreCase))
                return false;
            if (!string.IsNullOrWhiteSpace(rule.Sha1) &&
                !string.Equals(rule.Sha1, sha1, StringComparison.OrdinalIgnoreCase))
                return false;
            if (!string.IsNullOrWhiteSpace(rule.Md5) &&
                !string.Equals(rule.Md5, md5, StringComparison.OrdinalIgnoreCase))
                return false;
            if (!string.IsNullOrWhiteSpace(rule.ContainsAscii) &&
                (content == null || !ContainsAscii(content, rule.ContainsAscii, rule.ContainsAsciiNoCase)))
                return false;
            return true;
        }

        private static bool ContainsAscii(byte[] content, string text, bool nocase)
        {
            if (content.Length == 0 || text.Length == 0)
                return false;
            byte[] needle = Encoding.ASCII.GetBytes(nocase ? text.ToUpperInvariant() : text);
            for (int i = 0; i <= content.Length - needle.Length; i += 1)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j += 1)
                {
                    byte hay = content[i + j];
                    if (nocase)
                        hay = (byte) char.ToUpperInvariant((char)hay);
                    if (hay != needle[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                    return true;
            }
            return false;
        }

        private static bool ShouldScanPath(string path)
        {
            string ext = Path.GetExtension(path);
            return ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                   ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                   ext.Equals(".sys", StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizePath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return string.Empty;
            try
            {
                return Path.GetFullPath(path.Trim());
            }
            catch
            {
                return path.Trim();
            }
        }

        private static SignatureTrustState ClassifySignature(string path)
        {
            try
            {
#pragma warning disable SYSLIB0057
                X509Certificate cert = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
                using var cert2 = new X509Certificate2(cert);
                using var chain = new X509Chain { ChainPolicy = { RevocationMode = X509RevocationMode.NoCheck,
                                                                  VerificationFlags = X509VerificationFlags.NoFlag } };
                bool valid = chain.Build(cert2);
                if (cert2.NotAfter.ToUniversalTime() < DateTime.UtcNow)
                    return SignatureTrustState.Expired;
                return valid ? SignatureTrustState.Trusted : SignatureTrustState.Invalid;
            }
            catch (CryptographicException)
            {
                return SignatureTrustState.Unsigned;
            }
            catch
            {
                return SignatureTrustState.Unknown;
            }
        }

        private static string ResolveSigner(string path)
        {
            try
            {
#pragma warning disable SYSLIB0057
                X509Certificate cert = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
                using var cert2 = new X509Certificate2(cert);
                return cert2.Subject ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        private static uint ParseSeverity(string? text, uint fallback)
        {
            if (uint.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint value))
                return value;
            return (text ?? string.Empty).Trim().ToLowerInvariant() switch { "critical" => 8u,      "high" => 6u,
                                                                             "medium" => 4u,        "low" => 2u,
                                                                             "informational" => 1u, "info" => 1u,
                                                                             _ => fallback };
        }

        private static string BuildRuleReason(string? title, string? detail, string? mitreId, string? mitreName,
                                              string? sigmaId)
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(title))
                parts.Add(title.Trim());
            if (!string.IsNullOrWhiteSpace(detail))
                parts.Add(detail.Trim());
            if (!string.IsNullOrWhiteSpace(mitreId) || !string.IsNullOrWhiteSpace(mitreName))
                parts.Add($"MITRE {Fallback(mitreId)} {Fallback(mitreName)}".Trim());
            if (!string.IsNullOrWhiteSpace(sigmaId))
                parts.Add($"SIGMA {sigmaId.Trim()}");
            return parts.Count == 0 ? "offline signature-intel match" : string.Join(" | ", parts);
        }

        private static string Fallback(string? text) => string.IsNullOrWhiteSpace(text) ? "unknown" : text.Trim();

        private static HeuristicEventView BuildHeuristic(string detection, uint severity, uint actorPid, uint targetPid,
                                                         string source, string eventName, string reason,
                                                         string evidence)
        {
            DateTime now = DateTime.UtcNow;
            return new HeuristicEventView { TimestampUtc = now,        LastSeenUtc = now,     Severity = severity,
                                            DetectionName = detection, ActorPid = actorPid,   TargetPid = targetPid,
                                            Source = source,           EventName = eventName, Reason = reason,
                                            Evidence = evidence };
        }

        private static bool EvaluateYaraCondition(string condition, IReadOnlyDictionary<string, bool> hits)
        {
            string expression = Regex.Replace(
                condition ?? string.Empty, @"\b(?<q>any|all|\d+)\s+of\s+(?<target>them|\([^)]+\)|\$[A-Za-z0-9_*]+)",
                match => EvaluateYaraQuantifier(match.Groups["q"].Value, match.Groups["target"].Value, hits) ? "true"
                                                                                                             : "false",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

            return EvaluateBooleanExpression(expression, token => ResolveYaraConditionToken(token, hits), false);
        }

        private static bool EvaluateYaraQuantifier(string quantity, string target,
                                                   IReadOnlyDictionary<string, bool> hits)
        {
            IEnumerable<string> names;
            string trimmed = target.Trim();
            if (trimmed.Equals("them", StringComparison.OrdinalIgnoreCase))
            {
                names = hits.Keys;
            }
            else if (trimmed.StartsWith("(", StringComparison.Ordinal) &&
                     trimmed.EndsWith(")", StringComparison.Ordinal))
            {
                string[] requested =
                    trimmed[1.. ^ 1]
                        .Split(new[] { ',', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(x => x.Trim())
                        .ToArray();
                names = requested.SelectMany(name => name.EndsWith("*", StringComparison.Ordinal)
                                                         ? hits.Keys.Where(x => WildcardMatch(x, name))
                                                         : new[] { name });
            }
            else if (trimmed.EndsWith("*", StringComparison.Ordinal))
            {
                names = hits.Keys.Where(x => WildcardMatch(x, trimmed));
            }
            else
            {
                names = new[] { trimmed };
            }

            List<string> materialized =
                names.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            int hitCount = materialized.Count(name => hits.TryGetValue(name, out bool hit) && hit);
            if (quantity.Equals("all", StringComparison.OrdinalIgnoreCase))
            {
                return materialized.Count != 0 && hitCount == materialized.Count;
            }
            if (quantity.Equals("any", StringComparison.OrdinalIgnoreCase))
            {
                return hitCount > 0;
            }
            return int.TryParse(quantity, NumberStyles.Integer, CultureInfo.InvariantCulture, out int required) &&
                   hitCount >= required;
        }

        private static bool ResolveYaraConditionToken(string token, IReadOnlyDictionary<string, bool> hits)
        {
            if (hits.TryGetValue(token, out bool value))
            {
                return value;
            }

            if (token.EndsWith("*", StringComparison.Ordinal))
            {
                return hits.Any(x => WildcardMatch(x.Key, token) && x.Value);
            }

            return false;
        }

        private static bool EvaluateSigmaCondition(string condition, IReadOnlyDictionary<string, bool> selections)
        {
            string expression = Regex.Replace(
                condition ?? string.Empty, @"\b(?<q>1|any|all|\d+)\s+of\s+(?<target>them|[A-Za-z0-9_*]+)",
                match => EvaluateSigmaQuantifier(match.Groups["q"].Value, match.Groups["target"].Value, selections)
                             ? "true"
                             : "false",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

            return EvaluateBooleanExpression(expression, token => ResolveSigmaConditionToken(token, selections), false);
        }

        private static bool EvaluateSigmaQuantifier(string quantity, string target,
                                                    IReadOnlyDictionary<string, bool> selections)
        {
            IEnumerable<string> names = target.Equals("them", StringComparison.OrdinalIgnoreCase)
                                            ? selections.Keys
                                            : selections.Keys.Where(x => WildcardMatch(x, target));
            List<string> materialized = names.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            int hitCount = materialized.Count(name => selections.TryGetValue(name, out bool hit) && hit);
            if (quantity.Equals("all", StringComparison.OrdinalIgnoreCase))
            {
                return materialized.Count != 0 && hitCount == materialized.Count;
            }
            if (quantity.Equals("any", StringComparison.OrdinalIgnoreCase) ||
                quantity.Equals("1", StringComparison.OrdinalIgnoreCase))
            {
                return hitCount > 0;
            }
            return int.TryParse(quantity, NumberStyles.Integer, CultureInfo.InvariantCulture, out int required) &&
                   hitCount >= required;
        }

        private static bool ResolveSigmaConditionToken(string token, IReadOnlyDictionary<string, bool> selections)
        {
            if (selections.TryGetValue(token, out bool value))
            {
                return value;
            }

            if (token.EndsWith("*", StringComparison.Ordinal))
            {
                return selections.Any(x => WildcardMatch(x.Key, token) && x.Value);
            }

            return false;
        }

        private static bool EvaluateBooleanExpression(string expression, Func<string, bool> resolveIdentifier,
                                                      bool fallback)
        {
            try
            {
                var parser = new BooleanExpressionParser(expression, resolveIdentifier);
                return parser.Parse();
            }
            catch
            {
                return fallback;
            }
        }

        private static bool WildcardMatch(string value, string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                return string.IsNullOrEmpty(value);
            }

            string regex = "^" +
                           Regex.Escape(pattern)
                               .Replace("\\*", ".*", StringComparison.Ordinal)
                               .Replace("\\?", ".", StringComparison.Ordinal) +
                           "$";
            return Regex.IsMatch(value ?? string.Empty, regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }

        private static bool TryParseFlexibleInteger(string text, out long value)
        {
            value = 0;
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            string trimmed = text.Trim();
            if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                return long.TryParse(trimmed[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
            }

            return long.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
        }

        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;
            _cts.Cancel();
            _signal.Set();
            try
            {
                _worker.Wait(1000);
            }
            catch
            {
            }
            _cts.Dispose();
            _signal.Dispose();
        }
    }
}
