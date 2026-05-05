param(
    [string]$SourceRoot = "Yara",
    [string]$OutputRoot = "Client\analysis\Rules\SignatureIntel\Bundled\Packer",
    [int]$MaxRules = 600,
    [switch]$IncludeCrypto
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Remove-YaraComments {
    param([string]$Text)
    $withoutBlock = [regex]::Replace($Text, '/\*.*?\*/', '', 'Singleline')
    return [regex]::Replace($withoutBlock, '(?m)//.*$', '')
}

function Find-MatchingBrace {
    param([string]$Text, [int]$OpenIndex)
    $depth = 0
    $inString = $false
    $lineComment = $false
    $blockComment = $false

    for ($i = $OpenIndex; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]
        $next = if ($i + 1 -lt $Text.Length) { $Text[$i + 1] } else { [char]0 }

        if ($lineComment) {
            if ($c -eq "`r" -or $c -eq "`n") { $lineComment = $false }
            continue
        }
        if ($blockComment) {
            if ($c -eq '*' -and $next -eq '/') { $blockComment = $false; $i++ }
            continue
        }
        if ($inString) {
            if ($c -eq '\') { $i++; continue }
            if ($c -eq '"') { $inString = $false }
            continue
        }
        if ($c -eq '/' -and $next -eq '/') { $lineComment = $true; $i++; continue }
        if ($c -eq '/' -and $next -eq '*') { $blockComment = $true; $i++; continue }
        if ($c -eq '"') { $inString = $true; continue }
        if ($c -eq '{') { $depth++; continue }
        if ($c -eq '}') {
            $depth--
            if ($depth -eq 0) { return $i }
        }
    }

    return -1
}

function Get-YaraRuleBlocks {
    param([string]$Text)
    $ruleRegex = [regex]'(?i)(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b'
    $index = 0
    while ($index -lt $Text.Length) {
        $match = $ruleRegex.Match($Text, $index)
        if (-not $match.Success) { break }

        $open = $Text.IndexOf('{', $match.Index + $match.Length)
        if ($open -lt 0) { break }
        $close = Find-MatchingBrace -Text $Text -OpenIndex $open
        if ($close -lt 0) { break }

        [pscustomobject]@{
            Name = $match.Groups[1].Value
            Body = $Text.Substring($open + 1, $close - $open - 1)
        }
        $index = $close + 1
    }
}

function Get-Section {
    param([string]$Body, [string]$Name, [string[]]$Stops)
    $startMatch = [regex]::Match($Body, "(?im)^\s*$([regex]::Escape($Name))\s*:")
    if (-not $startMatch.Success) { return "" }

    $start = $startMatch.Index + $startMatch.Length
    $end = $Body.Length
    foreach ($stop in $Stops) {
        $stopMatch = [regex]::Match($Body.Substring($start), "(?im)^\s*$([regex]::Escape($stop))\s*:")
        if ($stopMatch.Success) {
            $candidate = $start + $stopMatch.Index
            if ($candidate -lt $end) { $end = $candidate }
        }
    }

    return $Body.Substring($start, $end - $start).Trim()
}

function Test-SupportedCondition {
    param([string]$Condition)
    if ([string]::IsNullOrWhiteSpace($Condition)) { return $false }
    $clean = Remove-YaraComments $Condition
    if ($clean -match '(?i)(\b(pe|elf|math|hash|dotnet)\.|uint(8|16|32|64)?\s*\(|filesize|entrypoint|\bat\b|\bin\b|for\s+.*\bof\b|#\w+|@\w+|!\w+|[<>]=?|==|!=)') {
        return $false
    }
    if ($clean -match '[^\sA-Za-z0-9_\$\(\),\*]') {
        return $false
    }
    return $clean -match '(?i)(\$[A-Za-z0-9_\*]+|\b(any|all|\d+)\s+of\s+(them|\([^\)]*\)|\$[A-Za-z0-9_\*]+))'
}

function Test-PackerRuleName {
    param([string]$Name)
    return $Name -match '(?i)(pack|packer|packed|protect|protector|crypter|cryptor|compress|stub|upx|themida|winlicense|vmprotect|enigma|aspack|asprotect|mpress|upack|nspack|fsg|mew|petite|molebox|obsidium|armadillo|rlpack|pecompact|kkrunchy|yoda|telock|neolite|bero|execryptor|polyene|morphine|peid)'
}

function Format-Indented {
    param([string]$Text, [string]$Indent = "        ")
    $normalized = $Text -replace "`r`n", "`n"
    $normalized = $normalized -replace "`r", "`n"
    $lines = $normalized.Split("`n")
    return ($lines | ForEach-Object { if ([string]::IsNullOrWhiteSpace($_)) { "" } else { $Indent + $_.TrimEnd() } }) -join "`r`n"
}

function Convert-RuleName {
    param([string]$Name, [hashtable]$Seen)
    $safe = [regex]::Replace($Name, '[^A-Za-z0-9_]', '_')
    if ($safe -notmatch '^[A-Za-z_]') { $safe = "rule_$safe" }
    $base = "bb_thirdparty_$safe"
    $candidate = $base
    $index = 2
    while ($Seen.ContainsKey($candidate)) {
        $candidate = "${base}_$index"
        $index++
    }
    $Seen[$candidate] = $true
    return $candidate
}

$sourceFull = Resolve-Path $SourceRoot
$outputFull = Join-Path (Get-Location) $OutputRoot
New-Item -ItemType Directory -Force -Path $outputFull | Out-Null

$relativeSources = @(
    "rules-master\packers\packer.yar",
    "rules-master\packers\peid.yar",
    "rules-master\packers\packer_compiler_signatures.yar",
    "rules-master\packers\JJencode.yar",
    "rules-master\packers\Javascript_exploit_and_obfuscation.yar"
)
if ($IncludeCrypto) {
    $relativeSources += @(
        "rules-master\crypto\crypto_signatures.yar",
        "crypto\rules.yar"
    )
}

$seen = @{}
$accepted = New-Object System.Collections.Generic.List[string]
$manifest = New-Object System.Collections.Generic.List[object]
$parsed = 0
$skipped = 0

foreach ($relative in $relativeSources) {
    $path = Join-Path $sourceFull $relative
    if (-not (Test-Path $path)) { continue }
    $text = Get-Content -Raw -LiteralPath $path
    foreach ($rule in Get-YaraRuleBlocks -Text $text) {
        $parsed++
        if ($accepted.Count -ge $MaxRules) { break }
        if (-not (Test-PackerRuleName -Name $rule.Name)) {
            $skipped++
            continue
        }

        $strings = Get-Section -Body $rule.Body -Name "strings" -Stops @("condition", "meta")
        $condition = Get-Section -Body $rule.Body -Name "condition" -Stops @("meta", "strings")
        if ([string]::IsNullOrWhiteSpace($strings) -or [string]::IsNullOrWhiteSpace($condition)) {
            $skipped++
            continue
        }
        if ($strings -match '(?m)\$[A-Za-z0-9_]+\s*=\s*/') {
            $skipped++
            continue
        }
        if (-not (Test-SupportedCondition -Condition $condition)) {
            $skipped++
            continue
        }

        $name = Convert-RuleName -Name $rule.Name -Seen $seen
        $detectionName = "YARA_PACKER_" + ([regex]::Replace($rule.Name, '[^A-Za-z0-9]+', '_').Trim('_').ToUpperInvariant())
        if ([string]::IsNullOrWhiteSpace($detectionName) -or $detectionName -eq "YARA_PACKER_") {
            $detectionName = "YARA_PACKER_THIRDPARTY"
        }

        $accepted.Add(@"
rule $name
{
    meta:
        title = "$($rule.Name.Replace('"', ''))"
        detection = "$detectionName"
        severity = "5"
        mitre_technique_id = "T1027.002"
        mitre_technique = "Software Packing"
        sigma_rule_id = "blackbird.thirdparty.$name"
        scope = "file,memory,page"
        source_path = "$($relative.Replace('\', '/'))"
    strings:
$(Format-Indented -Text $strings)
    condition:
$(Format-Indented -Text $condition)
}
"@)
        $manifest.Add([pscustomobject]@{
            outputRule = $name
            sourceRule = $rule.Name
            sourcePath = $relative.Replace('\', '/')
        })
    }
}

$header = @"
/*
    Generated by Scripts/Build-YaraBundle.ps1.
    This bundle intentionally keeps only string/hex rules with simple boolean conditions
    supported by Blackbird's managed signature engine. Source rules remain under /Yara.
    Preserve and review the upstream /Yara license files before redistributing this bundle.
*/

"@

$bundlePath = Join-Path $outputFull "thirdparty-packer-normalized.yar"
Set-Content -LiteralPath $bundlePath -Encoding UTF8 -Value ($header + ($accepted -join "`r`n`r`n"))

$manifestPath = Join-Path $outputFull "thirdparty-packer-normalized.manifest.txt"
$manifestRoot = [pscustomobject]@{
    generatedUtc = (Get-Date).ToUniversalTime().ToString("o")
    sourceRoot = $SourceRoot
    parsedRules = $parsed
    acceptedRules = $accepted.Count
    skippedRules = $skipped
    maxRules = $MaxRules
    includeCrypto = [bool]$IncludeCrypto
    rules = $manifest
}
Set-Content -LiteralPath $manifestPath -Encoding UTF8 -Value ($manifestRoot | ConvertTo-Json -Depth 5)

Write-Host "YARA bundle written: $bundlePath"
Write-Host "Parsed=$parsed Accepted=$($accepted.Count) Skipped=$skipped"
