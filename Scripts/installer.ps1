param(
    [string]$DriverName = "blackbird",
    [string]$ControllerName = "BlackbirdController",
    [string]$DriverSys = "..\blackbird.sys",
    [string]$ControllerExe = "..\BlackbirdController.exe",
    [string]$NetSvcExe = "",
    [string]$PreviewHostExe = "",
    [string]$RunnerExe = "",
    [string]$SensorCoreDll = "..\J58.dll",
    [string]$HookDll = "..\SR71.dll",
    [string]$InstanceName = "Blackbird Default",
    [string]$InstanceAltitude = "385000.424244",
    [uint32]$InstanceFlags = 0,
    [Alias("av")]
    [switch]$EnableAntiVirtualization,
    [Alias("hide")]
    [switch]$EnableControllerHiding,
    [string]$EnrollmentPath = "",
    [ValidatePattern('^$|^[0-9a-fA-F]{64}$')]
    [string]$OperatorFingerprint = "",
    [ValidatePattern('^$|^[0-9a-fA-F]{64}$')]
    [string]$ExpectedServerOperatorFingerprint = "",
    [string[]]$OperatorRemoteAddress = @(),
    [switch]$SkipEnrollmentPrompt
)

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptRoot "..")).Path
$osVersion = [Environment]::OSVersion.Version
$osBuild = $osVersion.Build
$script:OperatorFirewallRemoteAddresses = @()

foreach ($address in @($OperatorRemoteAddress)) {
    if (-not [string]::IsNullOrWhiteSpace($address) -and $script:OperatorFirewallRemoteAddresses -notcontains $address.Trim()) {
        $script:OperatorFirewallRemoteAddresses += $address.Trim()
    }
}

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}

if ($osBuild -lt 19041) {
    Write-Warning "OS build $osBuild detected. This driver toolchain commonly requires Windows 10 2004+ (build 19041+) for kernel exports."
}

function Write-Stage {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Index,
        [Parameter(Mandatory = $true)]
        [int]$Total,
        [Parameter(Mandatory = $true)]
        [string]$Activity,
        [Parameter(Mandatory = $true)]
        [string]$Status
    )

    $percent = [Math]::Floor(($Index / $Total) * 100)
    Write-Progress -Id 1 -Activity $Activity -Status $Status -PercentComplete $percent
    Write-Host ""
    Write-Host ("[{0}/{1}] {2}" -f $Index, $Total, $Status) -ForegroundColor Cyan
}

function Write-VerboseLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host $Message -ForegroundColor DarkGray
}

function Write-InfoLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host ("[info] {0}" -f $Message) -ForegroundColor Gray
}

function Test-HexFingerprint {
    param([string]$Value)
    return -not [string]::IsNullOrWhiteSpace($Value) -and $Value -match '^[0-9a-fA-F]{64}$'
}

function Add-OperatorFingerprint {
    param(
        [string[]]$Fingerprints,
        [string]$Candidate
    )

    if (-not (Test-HexFingerprint $Candidate)) {
        return $Fingerprints
    }

    $normalized = $Candidate.ToLowerInvariant()
    if ($Fingerprints -notcontains $normalized) {
        $Fingerprints += $normalized
    }
    return $Fingerprints
}

function Get-JsonPropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        $Object,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Convert-BytesToHex {
    param([byte[]]$Bytes)

    return -join ($Bytes | ForEach-Object { $_.ToString("x2") })
}

function Get-EnrollmentSignatureMessage {
    param($Enrollment)

    $fingerprintList = Get-JsonPropertyValue -Object $Enrollment -Name "operatorFingerprints"
    $fingerprints = @()
    foreach ($fingerprint in @($fingerprintList)) {
        $fingerprints += [string]$fingerprint
    }

    $parts = @(
        "BLACKBIRD_VM_ENROLLMENT_SIGNATURE_V1",
        [string](Get-JsonPropertyValue -Object $Enrollment -Name "protocol"),
        [string](Get-JsonPropertyValue -Object $Enrollment -Name "kind"),
        [string](Get-JsonPropertyValue -Object $Enrollment -Name "enrollmentId"),
        [string](Get-JsonPropertyValue -Object $Enrollment -Name "machineName"),
        [string](Get-JsonPropertyValue -Object $Enrollment -Name "createdUtc"),
        [string](Get-JsonPropertyValue -Object $Enrollment -Name "operatorFingerprint"),
        ($fingerprints -join ","),
        [string](Get-JsonPropertyValue -Object $Enrollment -Name "serverOperatorFingerprint")
    )

    return ($parts -join "`n")
}

function Assert-EnrollmentSignature {
    param(
        $Enrollment,
        [string]$ExpectedFingerprint = ""
    )

    $serverFingerprint = [string](Get-JsonPropertyValue -Object $Enrollment -Name "serverOperatorFingerprint")
    $publicKeyBase64 = [string](Get-JsonPropertyValue -Object $Enrollment -Name "serverOperatorPublicKey")
    $algorithm = [string](Get-JsonPropertyValue -Object $Enrollment -Name "signatureAlgorithm")
    $signatureBase64 = [string](Get-JsonPropertyValue -Object $Enrollment -Name "enrollmentSignature")

    if (-not (Test-HexFingerprint $serverFingerprint) -or
        [string]::IsNullOrWhiteSpace($publicKeyBase64) -or
        [string]::IsNullOrWhiteSpace($signatureBase64) -or
        $algorithm -ne "ECDSA-P256-SHA256-FIXED") {
        throw "The VM enrollment package is unsigned or uses an unsupported signature format."
    }

    $normalizedServerFingerprint = $serverFingerprint.ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($ExpectedFingerprint) -and
        $normalizedServerFingerprint -ne $ExpectedFingerprint.ToLowerInvariant()) {
        throw "The VM enrollment package server fingerprint does not match the expected server fingerprint."
    }

    try {
        $publicBytes = [Convert]::FromBase64String($publicKeyBase64)
        $signatureBytes = [Convert]::FromBase64String($signatureBase64)
    }
    catch {
        throw "The VM enrollment package signature material could not be decoded."
    }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $actualFingerprint = Convert-BytesToHex -Bytes ($sha256.ComputeHash($publicBytes))
    }
    finally {
        $sha256.Dispose()
    }
    if ($actualFingerprint -ne $normalizedServerFingerprint) {
        throw "The VM enrollment package public key does not match the server fingerprint."
    }

    $messageBytes = [Text.Encoding]::UTF8.GetBytes((Get-EnrollmentSignatureMessage -Enrollment $Enrollment))
    $key = $null
    $ecdsa = $null
    try {
        $key = [System.Security.Cryptography.CngKey]::Import(
            $publicBytes,
            [System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob
        )
        $ecdsa = [System.Security.Cryptography.ECDsaCng]::new($key)
        try {
            $verified = $ecdsa.VerifyData(
                $messageBytes,
                $signatureBytes,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256
            )
        }
        catch {
            $ecdsa.HashAlgorithm = [System.Security.Cryptography.CngAlgorithm]::Sha256
            $verified = $ecdsa.VerifyData($messageBytes, $signatureBytes)
        }
    }
    catch {
        throw "The VM enrollment package signature could not be verified."
    }
    finally {
        if ($null -ne $ecdsa) { $ecdsa.Dispose() }
        if ($null -ne $key) { $key.Dispose() }
    }

    if (-not $verified) {
        throw "The VM enrollment package signature is invalid."
    }

    return $normalizedServerFingerprint
}

function Test-EnrollmentHasAnySignatureFields {
    param($Enrollment)

    return -not [string]::IsNullOrWhiteSpace([string](Get-JsonPropertyValue -Object $Enrollment -Name "serverOperatorFingerprint")) -or
        -not [string]::IsNullOrWhiteSpace([string](Get-JsonPropertyValue -Object $Enrollment -Name "serverOperatorPublicKey")) -or
        -not [string]::IsNullOrWhiteSpace([string](Get-JsonPropertyValue -Object $Enrollment -Name "signatureAlgorithm")) -or
        -not [string]::IsNullOrWhiteSpace([string](Get-JsonPropertyValue -Object $Enrollment -Name "enrollmentSignature"))
}

function Test-EnrollmentHasCompleteSignatureFields {
    param($Enrollment)

    $serverFingerprint = [string](Get-JsonPropertyValue -Object $Enrollment -Name "serverOperatorFingerprint")
    $publicKeyBase64 = [string](Get-JsonPropertyValue -Object $Enrollment -Name "serverOperatorPublicKey")
    $algorithm = [string](Get-JsonPropertyValue -Object $Enrollment -Name "signatureAlgorithm")
    $signatureBase64 = [string](Get-JsonPropertyValue -Object $Enrollment -Name "enrollmentSignature")

    return (Test-HexFingerprint $serverFingerprint) -and
        -not [string]::IsNullOrWhiteSpace($publicKeyBase64) -and
        -not [string]::IsNullOrWhiteSpace($signatureBase64) -and
        $algorithm -eq "ECDSA-P256-SHA256-FIXED"
}

function Confirm-EnrollmentServerFingerprint {
    param(
        $Enrollment,
        [string]$ExpectedFingerprint = "",
        [switch]$SkipPrompt
    )

    if (-not (Test-EnrollmentHasCompleteSignatureFields -Enrollment $Enrollment)) {
        if ((Test-EnrollmentHasAnySignatureFields -Enrollment $Enrollment) -or
            -not [string]::IsNullOrWhiteSpace($ExpectedFingerprint)) {
            throw "The VM enrollment package is unsigned or uses an unsupported signature format."
        }

        Write-Warning "VM enrollment package is unsigned; trusting the staged operator fingerprint(s) without package-signature verification."
        return ""
    }

    $serverFingerprint = Assert-EnrollmentSignature -Enrollment $Enrollment -ExpectedFingerprint $ExpectedFingerprint
    if (-not [string]::IsNullOrWhiteSpace($ExpectedFingerprint)) {
        return $serverFingerprint
    }
    if ($SkipPrompt) {
        throw "ExpectedServerOperatorFingerprint is required when installing from an enrollment package without confirmation prompts."
    }

    Write-Host ""
    Write-Host "VM enrollment trust"
    Write-Host "-------------------"
    Write-Host "Server operator fingerprint:"
    Write-Host "  $serverFingerprint"
    Write-Host ""
    $confirmation = Read-Host "Type the server operator fingerprint to trust this enrollment"
    if ($confirmation.Trim().ToLowerInvariant() -ne $serverFingerprint) {
        throw "Server operator fingerprint confirmation did not match."
    }
    return $serverFingerprint
}

function Set-RestrictedBlackbirdAcl {
    param([string]$TargetPath)

    $item = Get-Item -LiteralPath $TargetPath -Force
    $acl = Get-Acl -LiteralPath $TargetPath
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) {
        [void]$acl.RemoveAccessRuleAll($rule)
    }

    $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
    if ($item.PSIsContainer) {
        $inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    }
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $principals = @(
        (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")),
        (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544"))
    )

    foreach ($principal in $principals) {
        $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $principal,
            $rights,
            $inheritance,
            $propagation,
            $allow
        )
        [void]$acl.AddAccessRule($accessRule)
    }

    Set-Acl -LiteralPath $TargetPath -AclObject $acl
}

function Set-ReadableBlackbirdLogAcl {
    param([string]$TargetPath)

    $item = Get-Item -LiteralPath $TargetPath -Force
    $acl = Get-Acl -LiteralPath $TargetPath
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) {
        [void]$acl.RemoveAccessRuleAll($rule)
    }

    $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
    if ($item.PSIsContainer) {
        $inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    }
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $fullControlPrincipals = @(
        (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")),
        (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544"))
    )
    $readPrincipals = @(
        (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-545"))
    )

    foreach ($principal in $fullControlPrincipals) {
        $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $principal,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            $propagation,
            $allow
        )
        [void]$acl.AddAccessRule($accessRule)
    }
    foreach ($principal in $readPrincipals) {
        $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $principal,
            [System.Security.AccessControl.FileSystemRights]"ReadAndExecute, Write",
            $inheritance,
            $propagation,
            $allow
        )
        [void]$acl.AddAccessRule($accessRule)
    }

    Set-Acl -LiteralPath $TargetPath -AclObject $acl
}

function Protect-BlackbirdNodeStorage {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    Set-RestrictedBlackbirdAcl -TargetPath $Path
    Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        Set-RestrictedBlackbirdAcl -TargetPath $_.FullName
    }

    $logsPath = Join-Path $Path "logs"
    New-Item -ItemType Directory -Force -Path $logsPath | Out-Null
    Set-ReadableBlackbirdLogAcl -TargetPath $logsPath
    Get-ChildItem -LiteralPath $logsPath -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        Set-ReadableBlackbirdLogAcl -TargetPath $_.FullName
    }
}

function Get-EnrollmentOperatorFingerprints {
    param($Enrollment)

    $fingerprints = @()
    $singleFingerprint = Get-JsonPropertyValue -Object $Enrollment -Name "operatorFingerprint"
    $fingerprintList = Get-JsonPropertyValue -Object $Enrollment -Name "operatorFingerprints"

    if ($singleFingerprint) {
        $fingerprints = @(Add-OperatorFingerprint -Fingerprints $fingerprints -Candidate ([string]$singleFingerprint))
    }
    if ($fingerprintList) {
        foreach ($candidate in @($fingerprintList)) {
            $fingerprints = @(Add-OperatorFingerprint -Fingerprints $fingerprints -Candidate ([string]$candidate))
        }
    }

    return @($fingerprints)
}

function Add-FirewallRemoteAddress {
    param([string]$Candidate)

    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        return
    }

    $normalized = $Candidate.Trim()
    if ($script:OperatorFirewallRemoteAddresses -notcontains $normalized) {
        $script:OperatorFirewallRemoteAddresses += $normalized
    }
}

function Add-EnrollmentFirewallRemoteAddresses {
    param($Enrollment)

    foreach ($propertyName in @("operatorRemoteAddress", "operatorRemoteAddresses", "allowedOperatorCidrs", "allowedOperatorHosts")) {
        $value = Get-JsonPropertyValue -Object $Enrollment -Name $propertyName
        if ($null -eq $value) {
            continue
        }

        foreach ($item in @($value)) {
            Add-FirewallRemoteAddress -Candidate ([string]$item)
        }
    }
}

function Read-EnrollmentDocument {
    param([string]$Path)

    $raw = Get-Content -Raw -LiteralPath $Path
    $trimmed = $raw.Trim()
    if ($trimmed.StartsWith("{")) {
        return $trimmed | ConvertFrom-Json
    }

    $lines = $trimmed -split "\r?\n"
    if ($lines.Count -lt 2 -or $lines[0].Trim() -ne "BLACKBIRD-VM-ENROLLMENT/1") {
        throw "The VM enrollment package format is not recognized."
    }

    $encoded = (($lines | Select-Object -Skip 1) -join "").Trim()
    try {
        $bytes = [Convert]::FromBase64String($encoded)
        $json = [Text.Encoding]::UTF8.GetString($bytes)
        return $json | ConvertFrom-Json
    }
    catch {
        throw "The VM enrollment package could not be decoded."
    }
}

function Initialize-NodeOperatorEnrollment {
    param(
        [string]$EnrollmentPath,
        [string]$OperatorFingerprint,
        [string]$ExpectedServerFingerprint,
        [switch]$SkipPrompt
    )

    $resolvedEnrollment = $null
    $operatorFingerprints = @()
    $candidatePaths = @()
    $operatorFingerprints = @(Add-OperatorFingerprint -Fingerprints $operatorFingerprints -Candidate $OperatorFingerprint)
    if (-not [string]::IsNullOrWhiteSpace($EnrollmentPath)) {
        $candidatePaths += $EnrollmentPath
    }
    $candidatePaths += (Join-Path $scriptRoot "blackbird-vm-enrollment.blackbird")
    $candidatePaths += (Join-Path $repoRoot "blackbird-vm-enrollment.blackbird")
    $candidatePaths += (Join-Path $repoRoot "Scripts\blackbird-vm-enrollment.blackbird")
    $candidatePaths += (Join-Path $scriptRoot "enroll.json")
    $candidatePaths += (Join-Path $repoRoot "enroll.json")

    foreach ($candidate in $candidatePaths) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        $pathToTry = $candidate
        if (-not [System.IO.Path]::IsPathRooted($pathToTry)) {
            $pathToTry = Join-Path $repoRoot $pathToTry
        }

        $resolved = Resolve-Path -LiteralPath $pathToTry -ErrorAction SilentlyContinue
        if ($null -ne $resolved) {
            $resolvedEnrollment = $resolved.Path
            break
        }
    }

    if (-not $resolvedEnrollment) {
        $packageCandidates = @()
        $packageCandidates += @(Get-ChildItem -LiteralPath $scriptRoot -Filter "*.blackbird" -File -ErrorAction SilentlyContinue)
        $packageCandidates += @(Get-ChildItem -LiteralPath $repoRoot -Filter "*.blackbird" -File -ErrorAction SilentlyContinue)
        $scriptsDir = Join-Path $repoRoot "Scripts"
        if (Test-Path -LiteralPath $scriptsDir -PathType Container) {
            $packageCandidates += @(Get-ChildItem -LiteralPath $scriptsDir -Filter "*.blackbird" -File -ErrorAction SilentlyContinue)
        }
        if ($packageCandidates.Count -gt 0) {
            $resolvedEnrollment = $packageCandidates[0].FullName
        }
    }

    if ($resolvedEnrollment) {
        Write-InfoLog "Using VM enrollment file: $resolvedEnrollment"
        $enrollment = Read-EnrollmentDocument -Path $resolvedEnrollment
        $confirmedServerFingerprint = Confirm-EnrollmentServerFingerprint `
            -Enrollment $enrollment `
            -ExpectedFingerprint $ExpectedServerFingerprint `
            -SkipPrompt:$SkipPrompt
        if (-not [string]::IsNullOrWhiteSpace($confirmedServerFingerprint)) {
            Write-InfoLog "Verified VM enrollment signature for server operator $confirmedServerFingerprint"
        }
        else {
            Write-InfoLog "Using unsigned legacy VM enrollment package"
        }
        Add-EnrollmentFirewallRemoteAddresses -Enrollment $enrollment
        foreach ($fingerprint in @(Get-EnrollmentOperatorFingerprints -Enrollment $enrollment)) {
            $operatorFingerprints = @(Add-OperatorFingerprint -Fingerprints $operatorFingerprints -Candidate $fingerprint)
        }
    }

    if ($operatorFingerprints.Count -eq 0 -and -not $SkipPrompt) {
        Write-Host ""
        Write-Host "VM operator trust"
        Write-Host "-----------------"
        Write-Host "No valid enrollment fingerprint was found."
        Write-Host "OperatorFingerprint is not yes/no; it is the 64-character hex fingerprint of the analyst/operator public identity."
        Write-Host "Enterprise enrollment packages can provision remote command trust for closed node-control builds."
        Write-Host "Paste the approved operator fingerprint, or press Enter to install without enabling remote command trust."
        $OperatorFingerprint = Read-Host "Operator fingerprint (64 hex)"
        $operatorFingerprints = @(Add-OperatorFingerprint -Fingerprints $operatorFingerprints -Candidate $OperatorFingerprint)
    }

    if ($operatorFingerprints.Count -eq 0) {
        Write-InfoLog "No valid operator fingerprint supplied. NetSvc secure command registration will remain untrusted until provisioned."
        return
    }

    $nodeRoot = Join-Path $env:ProgramData "Blackbird\Node"
    $trustDir = Join-Path $nodeRoot "trust"
    $enrollmentDir = Join-Path $nodeRoot "enrollment"
    New-Item -ItemType Directory -Force -Path $trustDir, $enrollmentDir | Out-Null
    Protect-BlackbirdNodeStorage -Path $nodeRoot

    foreach ($fingerprint in $operatorFingerprints) {
        $operatorKey = "HKLM:\SOFTWARE\Blackbird\Node\Trust\Operators\$fingerprint"
        New-Item -Path $operatorKey -Force | Out-Null
        New-ItemProperty -Path $operatorKey -Name "Enabled" -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path $operatorKey -Name "CreatedUtc" -PropertyType String -Value ([DateTime]::UtcNow.ToString("o")) -Force | Out-Null
    }

    Set-Content -Path (Join-Path $trustDir "trusted-operator.txt") -Value ($operatorFingerprints -join "`r`n") -NoNewline -Encoding ASCII

    if ($resolvedEnrollment) {
        ($enrollment | ConvertTo-Json -Depth 4) | Set-Content -Path (Join-Path $enrollmentDir "enroll.json") -Encoding UTF8
    }
    else {
        $enrollment = [ordered]@{
            protocol = 1
            enrollmentId = "installer-$([Guid]::NewGuid().ToString('N'))"
            machineName = $env:COMPUTERNAME
            createdUtc = ([DateTime]::UtcNow.ToString("o"))
            operatorFingerprint = $operatorFingerprints[0]
            operatorFingerprints = @($operatorFingerprints)
            operatorRemoteAddresses = @($script:OperatorFirewallRemoteAddresses)
        }
        ($enrollment | ConvertTo-Json -Depth 4) | Set-Content -Path (Join-Path $enrollmentDir "enroll.json") -Encoding UTF8
    }

    Write-InfoLog "Provisioned VM operator trust for $($operatorFingerprints.Count) fingerprint(s)"
    Protect-BlackbirdNodeStorage -Path $nodeRoot
}

function Format-CommandArgs {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    return ($Arguments | ForEach-Object {
            if ($_ -match '\s') { ('"{0}"' -f $_) } else { $_ }
        }) -join ' '
}

function Resolve-ArtifactPath {
    param(
        [string]$PreferredPath = "",
        [Parameter(Mandatory = $true)]
        [string[]]$FallbackPaths,
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [switch]$Optional
    )

    $candidates = @($PreferredPath) + $FallbackPaths
    Write-VerboseLog "Resolving $Label. Candidates: $($candidates -join ', ')"
    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        $pathToTry = $candidate
        if (-not [System.IO.Path]::IsPathRooted($pathToTry)) {
            $pathToTry = Join-Path $repoRoot $pathToTry
        }

        Write-VerboseLog "Trying $Label candidate: $pathToTry"
        $resolved = Resolve-Path -LiteralPath $pathToTry -ErrorAction SilentlyContinue
        if ($null -ne $resolved) {
            Write-InfoLog "Resolved $Label to $($resolved.Path)"
            return $resolved.Path
        }
    }

    if ($Optional) {
        Write-InfoLog "Optional $Label not found. Continuing without it."
        return $null
    }

    throw "$Label not found. Tried: $($candidates -join ', ')"
}

function Resolve-SiblingArtifactPath {
    param(
        [string]$SiblingOf = "",
        [Parameter(Mandatory = $true)]
        [string]$FileName,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($SiblingOf)) {
        return $null
    }

    $parent = Split-Path -Parent $SiblingOf
    if ([string]::IsNullOrWhiteSpace($parent)) {
        return $null
    }

    $candidate = Join-Path $parent $FileName
    Write-VerboseLog "Trying $Label sibling candidate: $candidate"
    $resolved = Resolve-Path -LiteralPath $candidate -ErrorAction SilentlyContinue
    if ($null -ne $resolved) {
        Write-InfoLog "Resolved $Label to $($resolved.Path)"
        return $resolved.Path
    }

    return $null
}

function Invoke-Sc {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [int[]]$AllowedExitCodes = @(0)
    )

    $cmdText = Format-CommandArgs -Arguments $Arguments
    Write-VerboseLog "sc.exe $cmdText"
    $output = & sc.exe @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($output) {
        foreach ($line in $output) {
            Write-VerboseLog "sc.exe> $line"
        }
    }
    Write-VerboseLog "sc.exe exit=$exitCode allowed=$($AllowedExitCodes -join ',')"
    if ($AllowedExitCodes -notcontains $exitCode) {
        $detail = (($output | ForEach-Object { "$_" }) -join [Environment]::NewLine).Trim()
        if ([string]::IsNullOrWhiteSpace($detail)) {
            $detail = "(no output)"
        }
        throw "sc.exe $($Arguments -join ' ') failed with exit code $exitCode`n$detail"
    }
}

function Test-ServiceExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    Write-VerboseLog "Checking service existence: $ServiceName"
    & sc.exe query $ServiceName 2>&1 | Out-Null
    Write-VerboseLog "Service $ServiceName exists=$($LASTEXITCODE -eq 0)"
    return $LASTEXITCODE -eq 0
}

function Get-ServiceSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    $output = & sc.exe queryex $ServiceName 2>&1
    $exitCode = $LASTEXITCODE
    $text = (($output | ForEach-Object { "$_" }) -join [Environment]::NewLine)
    $stateName = "ABSENT"
    $serviceProcessId = 0
    $waitHint = 0

    if ($exitCode -eq 0 -and $text -match "STATE\s*:\s*\d+\s+([A-Z_]+)") {
        $stateName = $matches[1]
    }
    if ($exitCode -eq 0 -and $text -match "(?m)^\s*PID\s*:\s*(\d+)") {
        $serviceProcessId = [int]$matches[1]
    }
    if ($exitCode -eq 0 -and $text -match "(?m)^\s*WAIT_HINT\s*:\s*(0x[0-9A-Fa-f]+|\d+)") {
        $raw = $matches[1]
        if ($raw.StartsWith("0x", [System.StringComparison]::OrdinalIgnoreCase)) {
            $waitHint = [Convert]::ToInt32($raw.Substring(2), 16)
        }
        else {
            $waitHint = [int]$raw
        }
    }

    return [pscustomobject]@{
        Exists    = ($exitCode -eq 0)
        ExitCode  = $exitCode
        StateName = $stateName
        ProcessId = $serviceProcessId
        WaitHint  = $waitHint
        Text      = $text
    }
}

function Wait-ServiceNameAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [int]$TimeoutSeconds = 30
    )

    Write-VerboseLog "Waiting for service name availability: $ServiceName (timeout ${TimeoutSeconds}s)"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempt = 0
    $lastSnapshot = $null

    while ((Get-Date) -lt $deadline) {
        $attempt++
        $snapshot = Get-ServiceSnapshot -ServiceName $ServiceName
        $lastSnapshot = $snapshot

        if (-not $snapshot.Exists) {
            Write-VerboseLog "Service name available after $attempt attempt(s): $ServiceName"
            return $true
        }

        if ($attempt -eq 1 -or ($attempt % 5) -eq 0) {
            Write-VerboseLog ("Service name still unavailable: {0} state={1} pid={2} scExit={3}" -f `
                    $ServiceName, $snapshot.StateName, $snapshot.ProcessId, $snapshot.ExitCode)
        }

        $sleepMs = 500
        if ($snapshot.WaitHint -gt 0) {
            $sleepMs = [Math]::Min([Math]::Max([int]($snapshot.WaitHint / 4), 250), 2000)
        }
        Start-Sleep -Milliseconds $sleepMs
    }

    if ($null -ne $lastSnapshot) {
        Write-Host "    Service '$ServiceName' is still registered: state=$($lastSnapshot.StateName) pid=$($lastSnapshot.ProcessId)" -ForegroundColor Yellow
        if (-not [string]::IsNullOrWhiteSpace($lastSnapshot.Text)) {
            $lastSnapshot.Text -split "`r?`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkYellow }
        }
    }
    Write-VerboseLog "Service name did not become available in time: $ServiceName"
    return $false
}

function New-ServiceWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [Parameter(Mandatory = $true)]
        [string[]]$CreateArguments,
        [int]$TimeoutSeconds = 30
    )

    if (-not (Wait-ServiceNameAvailable -ServiceName $ServiceName -TimeoutSeconds $TimeoutSeconds)) {
        throw "Service '$ServiceName' is still present or marked for deletion. Close Services.msc or other tools holding service handles, then rerun installer."
    }

    Invoke-Sc -Arguments $CreateArguments
}

function Wait-UntilFileUnlocked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [int]$TimeoutSeconds = 20
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-VerboseLog "Unlock check skipped; file not present: $Path"
        return $true
    }

    Write-VerboseLog "Waiting for file unlock: $Path (timeout ${TimeoutSeconds}s)"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempt = 0
    while ((Get-Date) -lt $deadline) {
        $attempt++
        try {
            $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $stream.Close()
            Write-VerboseLog "File unlocked after $attempt attempt(s): $Path"
            return $true
        }
        catch {
            if ($attempt -eq 1 -or ($attempt % 5) -eq 0) {
                Write-VerboseLog "File still locked on attempt ${attempt}: $Path"
            }
            Start-Sleep -Milliseconds 300
        }
    }

    Write-VerboseLog "Unlock wait timed out: $Path"
    return $false
}

function Assert-PathExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Label missing: $Path"
    }
}

function Ensure-MinifilterRegistry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [string]$InstanceName = "Blackbird Default",
        [string]$Altitude = "385000.424244",
        [uint32]$InstanceFlags = 0
    )

    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $instancesKey = Join-Path $serviceKey "Instances"
    $instanceKey = Join-Path $instancesKey $InstanceName

    Write-VerboseLog "Ensuring minifilter registry for $ServiceName at altitude $Altitude"
    if (-not (Test-Path -LiteralPath $serviceKey)) {
        throw "Service key '$serviceKey' is missing after sc.exe create. Aborting to avoid partial minifilter setup."
    }
    if (-not (Test-Path -LiteralPath $instancesKey)) {
        New-Item -Path $instancesKey | Out-Null
    }
    if (-not (Test-Path -LiteralPath $instanceKey)) {
        New-Item -Path $instanceKey | Out-Null
    }

    New-ItemProperty -Path $serviceKey -Name "DebugFlags" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $instancesKey -Name "DefaultInstance" -PropertyType String -Value $InstanceName -Force | Out-Null
    New-ItemProperty -Path $instanceKey -Name "Altitude" -PropertyType String -Value $Altitude -Force | Out-Null
    New-ItemProperty -Path $instanceKey -Name "Flags" -PropertyType DWord -Value $InstanceFlags -Force | Out-Null
}

function Set-DriverRuntimeDefaults {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [Parameter(Mandatory = $true)]
        [bool]$EnableAntiVirtualization,
        [Parameter(Mandatory = $true)]
        [bool]$EnableSelfHide,
        [Parameter(Mandatory = $true)]
        [bool]$EnableControllerProtectedAccess
    )

    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $parametersKey = Join-Path $serviceKey "Parameters"

    if (-not (Test-Path -LiteralPath $serviceKey)) {
        throw "Service key '$serviceKey' is missing after driver creation."
    }
    if (-not (Test-Path -LiteralPath $parametersKey)) {
        New-Item -Path $parametersKey | Out-Null
    }

    New-ItemProperty -Path $parametersKey -Name "EnableAntiVirtualization" -PropertyType DWord -Value ([int]$EnableAntiVirtualization) -Force | Out-Null
    New-ItemProperty -Path $parametersKey -Name "EnableSelfHide" -PropertyType DWord -Value ([int]$EnableSelfHide) -Force | Out-Null
    New-ItemProperty -Path $parametersKey -Name "EnableControllerProtectedAccess" -PropertyType DWord -Value ([int]$EnableControllerProtectedAccess) -Force | Out-Null
    Write-InfoLog ("Driver runtime defaults: av={0} hide={1} ctrl-protect={2}" -f ([int]$EnableAntiVirtualization), ([int]$EnableSelfHide), ([int]$EnableControllerProtectedAccess))
}

function Backup-RegistryValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,
        [Parameter(Mandatory = $true)]
        [string]$BackupPath,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $sourceKey = Get-Item -LiteralPath $SourcePath -ErrorAction SilentlyContinue
    $present = $false
    $kind = "None"
    $value = ""

    if ($null -ne $sourceKey -and ($sourceKey.GetValueNames() -contains $Name)) {
        $present = $true
        $kind = $sourceKey.GetValueKind($Name).ToString()
        $rawValue = $sourceKey.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($null -ne $rawValue) {
            $value = [string]$rawValue
        }
    }

    New-ItemProperty -Path $BackupPath -Name "${Name}_Present" -PropertyType DWord -Value ([int]$present) -Force | Out-Null
    New-ItemProperty -Path $BackupPath -Name "${Name}_Kind" -PropertyType String -Value $kind -Force | Out-Null
    New-ItemProperty -Path $BackupPath -Name "${Name}_Value" -PropertyType String -Value $value -Force | Out-Null
}

function Ensure-BlackbirdCrashDumpSettings {
    $crashControlKey = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
    $backupKey = "HKLM:\SOFTWARE\Blackbird\Installer\CrashControlBackup"
    $managedValues = @(
        "CrashDumpEnabled",
        "AlwaysKeepMemoryDump",
        "LogEvent",
        "DumpFile",
        "MinidumpDir"
    )

    if (-not (Test-Path -LiteralPath $crashControlKey)) {
        New-Item -Path $crashControlKey -Force | Out-Null
    }

    if (-not (Test-Path -LiteralPath $backupKey)) {
        New-Item -Path $backupKey -Force | Out-Null
        foreach ($name in $managedValues) {
            Backup-RegistryValue -SourcePath $crashControlKey -BackupPath $backupKey -Name $name
        }
        New-ItemProperty -Path $backupKey -Name "Managed" -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path $backupKey -Name "BackupCreatedUtc" -PropertyType String -Value ([DateTime]::UtcNow.ToString("o")) -Force | Out-Null
    }
    else {
        Write-InfoLog "Existing Blackbird crash dump backup found; preserving original CrashControl baseline."
    }

    New-ItemProperty -Path $crashControlKey -Name "CrashDumpEnabled" -PropertyType DWord -Value 2 -Force | Out-Null
    New-ItemProperty -Path $crashControlKey -Name "AlwaysKeepMemoryDump" -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -Path $crashControlKey -Name "LogEvent" -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -Path $crashControlKey -Name "DumpFile" -PropertyType ExpandString -Value "%SystemRoot%\MEMORY.DMP" -Force | Out-Null
    New-ItemProperty -Path $crashControlKey -Name "MinidumpDir" -PropertyType ExpandString -Value "%SystemRoot%\Minidump" -Force | Out-Null
    Write-InfoLog "Configured Windows kernel crash dumps for Blackbird crash analysis."
}
function Get-ServicesUsingMinifilterAltitude {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Altitude,
        [string]$ExcludeServiceName = ""
    )

    $servicesRoot = "HKLM:\SYSTEM\CurrentControlSet\Services"
    $matches = New-Object System.Collections.Generic.List[string]

    Write-VerboseLog "Scanning services for altitude conflicts at $Altitude"
    foreach ($serviceKey in (Get-ChildItem -Path $servicesRoot -ErrorAction SilentlyContinue)) {
        $serviceName = $serviceKey.PSChildName
        if ([string]::IsNullOrWhiteSpace($serviceName)) {
            continue
        }
        if (-not [string]::IsNullOrWhiteSpace($ExcludeServiceName) -and
            $serviceName.Equals($ExcludeServiceName, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $instancesPath = Join-Path $serviceKey.PSPath "Instances"
        if (-not (Test-Path -LiteralPath $instancesPath)) {
            continue
        }

        $instanceKeys = Get-ChildItem -Path $instancesPath -ErrorAction SilentlyContinue
        foreach ($instanceKey in $instanceKeys) {
            $props = Get-ItemProperty -LiteralPath $instanceKey.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $props) {
                continue
            }
            if (-not ($props.PSObject.Properties.Name -contains "Altitude")) {
                continue
            }
            if ([string]$props.Altitude -eq $Altitude) {
                [void]$matches.Add($serviceName)
                break
            }
        }
    }

    return $matches.ToArray() | Sort-Object -Unique
}

function Remove-MinifilterServiceArtifacts {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    if ([string]::IsNullOrWhiteSpace($ServiceName)) {
        return
    }

    Write-InfoLog "Removing stale minifilter artifacts for $ServiceName"
    Invoke-Sc -Arguments @("stop", $ServiceName) -AllowedExitCodes @(0, 5, 1060, 1062)
    Write-VerboseLog "fltmc.exe unload $ServiceName"
    $fltOut = & fltmc.exe unload $ServiceName 2>&1
    if ($fltOut) {
        foreach ($line in $fltOut) {
            Write-VerboseLog "fltmc> $line"
        }
    }
    Write-VerboseLog "fltmc unload exit=$LASTEXITCODE"
    if ($LASTEXITCODE -ne 0) {
        $null = $fltOut
    }
    Invoke-Sc -Arguments @("delete", $ServiceName) -AllowedExitCodes @(0, 1060, 1072)

    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    if (Test-Path -LiteralPath $serviceKey) {
        Remove-Item -LiteralPath $serviceKey -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Remove-ProjectAltitudeConflicts {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Altitude,
        [Parameter(Mandatory = $true)]
        [string]$CurrentServiceName,
        [Parameter(Mandatory = $true)]
        [string[]]$ProjectServiceNames
    )

    $conflicts = @(Get-ServicesUsingMinifilterAltitude -Altitude $Altitude -ExcludeServiceName $CurrentServiceName)
    if ($conflicts.Count -eq 0) {
        return @()
    }

    $projectLookup = @{}
    foreach ($name in $ProjectServiceNames) {
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $projectLookup[$name.ToLowerInvariant()] = $true
        }
    }

    $unknown = New-Object System.Collections.Generic.List[string]
    foreach ($svc in $conflicts) {
        if ($projectLookup.ContainsKey($svc.ToLowerInvariant())) {
            Write-Host "    Removing stale project minifilter service '$svc' with conflicting altitude $Altitude..." -ForegroundColor Yellow
            Remove-MinifilterServiceArtifacts -ServiceName $svc
        }
        else {
            [void]$unknown.Add($svc)
        }
    }

    return $unknown.ToArray() | Sort-Object -Unique
}

function Get-RecentServiceEvents {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [int]$MaxEvents = 5
    )

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = "System"
            ProviderName = "Service Control Manager"
        } -MaxEvents 80 | Where-Object {
            $_.Message -match [Regex]::Escape($ServiceName)
        } | Select-Object -First $MaxEvents

        if ($null -eq $events -or $events.Count -eq 0) {
            return "No recent Service Control Manager events matched '$ServiceName'."
        }

        $lines = @()
        foreach ($evt in $events) {
            $msg = ($evt.Message -replace "\r?\n", " ").Trim()
            if ($msg.Length -gt 220) {
                $msg = $msg.Substring(0, 220) + "..."
            }
            $lines += "[{0}] EventID {1}: {2}" -f $evt.TimeCreated, $evt.Id, $msg
        }
        return ($lines -join [Environment]::NewLine)
    }
    catch {
        return "Failed to query Service Control Manager events: $($_.Exception.Message)"
    }
}

function Get-MinifilterRegistryDump {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [string]$InstanceName = "Blackbird Default"
    )

    $base = "HKLM\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $commands = @(
        @("query", $base),
        @("query", "$base\Instances"),
        @("query", "$base\Instances\$InstanceName")
    )

    $lines = @()
    foreach ($cmd in $commands) {
        $target = $cmd[1]
        $lines += "reg.exe $($cmd -join ' ')"
        $out = & reg.exe @cmd 2>&1
        if ($LASTEXITCODE -eq 0) {
            $lines += ($out | ForEach-Object { "  $_" })
        }
        else {
            $lines += "  (query failed: exit $LASTEXITCODE)"
            $lines += ($out | ForEach-Object { "  $_" })
        }
    }

    return ($lines -join [Environment]::NewLine)
}

function Assert-ServiceRunning {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedStatePattern,
        [Parameter(Mandatory = $true)]
        [string]$FailureLabel,
        [int]$TimeoutSeconds = 45
    )

    $deadline = [DateTime]::UtcNow.AddSeconds([Math]::Max(5, $TimeoutSeconds))
    $lastText = ""

    while ([DateTime]::UtcNow -lt $deadline) {
        $output = & sc.exe query $ServiceName 2>&1
        $text = (($output | ForEach-Object { "$_" }) -join [Environment]::NewLine)
        $lastText = $text

        if ($LASTEXITCODE -eq 0 -and $text -match $ExpectedStatePattern) {
            return
        }

        $sleepMs = 500
        $isPendingState = $LASTEXITCODE -eq 0 -and $text -match "STATE\s*:\s*\d+\s+(START_PENDING|STOP_PENDING|PAUSE_PENDING|CONTINUE_PENDING)"
        if ($isPendingState) {
            if ($text -match "WAIT_HINT\s*:\s*0x([0-9A-Fa-f]+)") {
                $waitHintMs = [Convert]::ToInt32($matches[1], 16)
                $sleepMs = [Math]::Min([Math]::Max([int]($waitHintMs / 4), 250), 2000)
            }
            elseif ($text -match "WAIT_HINT\s*:\s*(\d+)") {
                $waitHintMs = [int]$matches[1]
                $sleepMs = [Math]::Min([Math]::Max([int]($waitHintMs / 4), 250), 2000)
            }
        }

        Start-Sleep -Milliseconds $sleepMs
    }

    throw "$FailureLabel`n$lastText"
}

function Ensure-FirewallRulePresent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName,
        [Parameter(Mandatory = $true)]
        [ValidateSet("TCP", "UDP", "ICMPv4")]
        [string]$Protocol,
        [string]$LocalPort = "",
        [string]$IcmpType = "",
        [string[]]$RemoteAddress = @("LocalSubnet")
    )

    $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        $existing | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }

    $params = @{
        DisplayName = $DisplayName
        Direction   = "Inbound"
        Protocol    = $Protocol
        Action      = "Allow"
        Profile     = "Any"
        RemoteAddress = $RemoteAddress
    }

    if (-not [string]::IsNullOrWhiteSpace($LocalPort)) {
        $params.LocalPort = $LocalPort
    }
    if (-not [string]::IsNullOrWhiteSpace($IcmpType)) {
        $params.IcmpType = $IcmpType
    }

    New-NetFirewallRule @params | Out-Null
}

$totalStages = 9
$activity = "Blackbird installation"

Write-Host ""
Write-Host "Blackbird Installer"
Write-Host "-------------------"

Initialize-NodeOperatorEnrollment `
    -EnrollmentPath $EnrollmentPath `
    -OperatorFingerprint $OperatorFingerprint `
    -ExpectedServerFingerprint $ExpectedServerOperatorFingerprint `
    -SkipPrompt:$SkipEnrollmentPrompt

Write-Stage -Index 1 -Total $totalStages -Activity $activity -Status "Removing previous installation"
$removerScript = Join-Path $scriptRoot "remover.ps1"
if (Test-Path -LiteralPath $removerScript) {
    & $removerScript -DriverName $DriverName -ControllerName $ControllerName
}

Write-Stage -Index 2 -Total $totalStages -Activity $activity -Status "Resolving build artifacts"
$driverSrc = Resolve-ArtifactPath `
    -PreferredPath $DriverSys `
    -FallbackPaths @(
        "vcxproj\x64\Debug\blackbird.sys",
        "vcxproj\x64\Release\blackbird.sys",
        "vcxproj\x64\TEMPUS_DEBUG\blackbird.sys",
        "x64\Debug\blackbird.sys",
        "x64\Release\blackbird.sys",
        "x64\TEMPUS_DEBUG\blackbird.sys",
        "blackbird.sys"
    ) `
    -Label "Driver .sys"

$controllerSrc = Resolve-ArtifactPath `
    -PreferredPath $ControllerExe `
    -FallbackPaths @(
        "vcxproj\x64\Debug\BlackbirdController.exe",
        "vcxproj\x64\Release\BlackbirdController.exe",
        "vcxproj\x64\TEMPUS_DEBUG\BlackbirdController.exe",
        "x64\Debug\BlackbirdController.exe",
        "x64\Release\BlackbirdController.exe",
        "x64\TEMPUS_DEBUG\BlackbirdController.exe",
        "BlackbirdController.exe"
    ) `
    -Label "Controller .exe"

$netSvcSrc = Resolve-ArtifactPath `
    -PreferredPath $NetSvcExe `
    -FallbackPaths @(
        "Lib\NetworkServiceLayer\target\release\BlackbirdNetSvc.exe",
        "Lib\NetworkServiceLayer\target\debug\BlackbirdNetSvc.exe",
        "x64\Release\BlackbirdNetSvc.exe",
        "vcxproj\x64\Release\BlackbirdNetSvc.exe",
        "x64\TEMPUS_DEBUG\BlackbirdNetSvc.exe",
        "vcxproj\x64\TEMPUS_DEBUG\BlackbirdNetSvc.exe",
        "x64\Debug\BlackbirdNetSvc.exe",
        "vcxproj\x64\Debug\BlackbirdNetSvc.exe",
        "BlackbirdNetSvc.exe"
    ) `
    -Label "Network service .exe" `
    -Optional

$previewHostPreferred = $PreviewHostExe
if ([string]::IsNullOrWhiteSpace($previewHostPreferred)) {
    $previewHostPreferred = Resolve-SiblingArtifactPath `
        -SiblingOf $netSvcSrc `
        -FileName "BlackbirdPreviewHost.exe" `
        -Label "Preview host .exe"
}

$previewHostSrc = Resolve-ArtifactPath `
    -PreferredPath $previewHostPreferred `
    -FallbackPaths @(
        "Lib\NetworkServiceLayer\target\release\BlackbirdPreviewHost.exe",
        "Lib\NetworkServiceLayer\target\debug\BlackbirdPreviewHost.exe",
        "x64\Release\BlackbirdPreviewHost.exe",
        "vcxproj\x64\Release\BlackbirdPreviewHost.exe",
        "x64\TEMPUS_DEBUG\BlackbirdPreviewHost.exe",
        "vcxproj\x64\TEMPUS_DEBUG\BlackbirdPreviewHost.exe",
        "x64\Debug\BlackbirdPreviewHost.exe",
        "vcxproj\x64\Debug\BlackbirdPreviewHost.exe",
        "BlackbirdPreviewHost.exe"
    ) `
    -Label "Preview host .exe" `
    -Optional

if (-not $previewHostSrc) {
    $previewHostSrc = Resolve-SiblingArtifactPath `
        -SiblingOf $netSvcSrc `
        -FileName "BlackbirdPreviewHost.exe" `
        -Label "Preview host .exe"
}

$runnerSrc = Resolve-ArtifactPath `
    -PreferredPath $RunnerExe `
    -FallbackPaths @(
        "x64\Release\BlackbirdRunner.exe",
        "vcxproj\x64\Release\BlackbirdRunner.exe",
        "x64\Release\net9.0-windows\BlackbirdRunner.exe",
        "x64\TEMPUS_DEBUG\BlackbirdRunner.exe",
        "vcxproj\x64\TEMPUS_DEBUG\BlackbirdRunner.exe",
        "x64\TEMPUS_DEBUG\net9.0-windows\BlackbirdRunner.exe",
        "x64\Debug\BlackbirdRunner.exe",
        "vcxproj\x64\Debug\BlackbirdRunner.exe",
        "x64\Debug\net9.0-windows\BlackbirdRunner.exe",
        "BlackbirdRunner.exe"
    ) `
    -Label "Runner .exe" `
    -Optional

if ($netSvcSrc -and -not $previewHostSrc) {
    throw "Network service build was found, but BlackbirdPreviewHost.exe was not. Build/copy the preview host next to BlackbirdNetSvc.exe before installing."
}

$sensorCoreSrc = Resolve-ArtifactPath `
    -PreferredPath $SensorCoreDll `
    -FallbackPaths @(
        "vcxproj\x64\Debug\J58.dll",
        "vcxproj\x64\Release\J58.dll",
        "vcxproj\x64\TEMPUS_DEBUG\J58.dll",
        "x64\Debug\J58.dll",
        "x64\Release\J58.dll",
        "x64\TEMPUS_DEBUG\J58.dll",
        "J58.dll"
    ) `
    -Label "SensorCore .dll"

$hookDllSrc = Resolve-ArtifactPath `
    -PreferredPath $HookDll `
    -FallbackPaths @(
        "vcxproj\x64\Debug\SR71.dll",
        "vcxproj\x64\Release\SR71.dll",
        "vcxproj\x64\TEMPUS_DEBUG\SR71.dll",
        "UserMode\hook\vcxproj\x64\Debug\SR71.dll",
        "UserMode\hook\vcxproj\x64\Release\SR71.dll",
        "UserMode\hook\vcxproj\x64\TEMPUS_DEBUG\SR71.dll",
        "x64\Debug\SR71.dll",
        "x64\Release\SR71.dll",
        "x64\TEMPUS_DEBUG\SR71.dll",
        "SR71.dll"
    ) `
    -Label "SR71 hook .dll"

$driverDst = Join-Path $env:windir "System32\drivers\blackbird.sys"
$controllerDir = Join-Path $env:ProgramFiles "Blackbird"
$controllerDst = Join-Path $controllerDir "BlackbirdController.exe"
$netSvcDst = Join-Path $controllerDir "BlackbirdNetSvc.exe"
$previewHostDst = Join-Path $controllerDir "BlackbirdPreviewHost.exe"
$runnerDst = Join-Path $controllerDir "BlackbirdRunner.exe"
$sensorCoreDst = Join-Path $controllerDir "J58.dll"
$hookDllDst = Join-Path $controllerDir "SR71.dll"

Write-InfoLog "Driver source: $driverSrc"
Write-InfoLog "Controller source: $controllerSrc"
if ($netSvcSrc) {
    Write-InfoLog "Network service source: $netSvcSrc"
} else {
    Write-InfoLog "Network service source: optional component absent"
}
if ($previewHostSrc) {
    Write-InfoLog "Preview host source: $previewHostSrc"
} else {
    Write-InfoLog "Preview host source: optional component absent"
}
if ($runnerSrc) {
    Write-InfoLog "Runner source: $runnerSrc"
} else {
    Write-InfoLog "Runner source: optional component absent"
}
Write-InfoLog "SensorCore source: $sensorCoreSrc"
Write-InfoLog "SR71 source: $hookDllSrc"

Write-Stage -Index 3 -Total $totalStages -Activity $activity -Status "Stopping existing services and copying binaries"
Invoke-Sc -Arguments @("stop", $ControllerName) -AllowedExitCodes @(0, 1060, 1062)
if (-not (Wait-UntilFileUnlocked -Path $controllerDst -TimeoutSeconds 20)) {
    throw "$controllerDst is still locked after controller service stop. Reboot then rerun installer."
}
if ($netSvcSrc -and -not (Wait-UntilFileUnlocked -Path $netSvcDst -TimeoutSeconds 20)) {
    throw "$netSvcDst is still locked after controller service stop. Reboot then rerun installer."
}
if ($previewHostSrc -and -not (Wait-UntilFileUnlocked -Path $previewHostDst -TimeoutSeconds 20)) {
    throw "$previewHostDst is still locked after controller service stop. Reboot then rerun installer."
}
if ($runnerSrc -and -not (Wait-UntilFileUnlocked -Path $runnerDst -TimeoutSeconds 20)) {
    throw "$runnerDst is still locked after controller service stop. Reboot then rerun installer."
}
if (-not (Wait-UntilFileUnlocked -Path $sensorCoreDst -TimeoutSeconds 20)) {
    throw "$sensorCoreDst is still locked after controller service stop. Reboot then rerun installer."
}
if (-not (Wait-UntilFileUnlocked -Path $hookDllDst -TimeoutSeconds 20)) {
    throw "$hookDllDst is still locked after controller service stop. Reboot then rerun installer."
}
Write-VerboseLog "fltmc.exe unload $DriverName"
$fltUnloadOut = & fltmc.exe unload $DriverName 2>&1
if ($fltUnloadOut) {
    foreach ($line in $fltUnloadOut) {
        Write-VerboseLog "fltmc> $line"
    }
}
Write-VerboseLog "fltmc unload exit=$LASTEXITCODE"
Invoke-Sc -Arguments @("stop", $DriverName) -AllowedExitCodes @(0, 1060, 1062, 1243)
if (-not (Wait-UntilFileUnlocked -Path $driverDst -TimeoutSeconds 20)) {
    throw "$driverDst is still locked after driver stop/unload. Reboot then rerun installer."
}
Write-VerboseLog "Ensuring controller directory exists: $controllerDir"
New-Item -ItemType Directory -Path $controllerDir -Force | Out-Null
Write-InfoLog "Copying driver: $driverSrc -> $driverDst"
Copy-Item -LiteralPath $driverSrc -Destination $driverDst -Force
Write-InfoLog "Copying controller: $controllerSrc -> $controllerDst"
Copy-Item -LiteralPath $controllerSrc -Destination $controllerDst -Force
if ($netSvcSrc) {
    Write-InfoLog "Copying network service: $netSvcSrc -> $netSvcDst"
    Copy-Item -LiteralPath $netSvcSrc -Destination $netSvcDst -Force
} else {
    Write-InfoLog "Skipping optional network service copy"
}
if ($previewHostSrc) {
    Write-InfoLog "Copying preview host: $previewHostSrc -> $previewHostDst"
    Copy-Item -LiteralPath $previewHostSrc -Destination $previewHostDst -Force
} else {
    Write-InfoLog "Skipping optional preview host copy"
}
if ($runnerSrc) {
    Write-InfoLog "Copying runner: $runnerSrc -> $runnerDst"
    Copy-Item -LiteralPath $runnerSrc -Destination $runnerDst -Force
} else {
    Write-InfoLog "Skipping optional runner copy"
}
Write-InfoLog "Copying SensorCore: $sensorCoreSrc -> $sensorCoreDst"
Copy-Item -LiteralPath $sensorCoreSrc -Destination $sensorCoreDst -Force
Write-InfoLog "Copying SR71: $hookDllSrc -> $hookDllDst"
Copy-Item -LiteralPath $hookDllSrc -Destination $hookDllDst -Force

Assert-PathExists -Path $driverDst -Label "Installed driver"
Assert-PathExists -Path $controllerDst -Label "Installed controller"
if ($netSvcSrc) {
    Assert-PathExists -Path $netSvcDst -Label "Installed network service"
}
if ($previewHostSrc) {
    Assert-PathExists -Path $previewHostDst -Label "Installed preview host"
}
if ($runnerSrc) {
    Assert-PathExists -Path $runnerDst -Label "Installed runner"
}
Assert-PathExists -Path $sensorCoreDst -Label "Installed SensorCore"
Assert-PathExists -Path $hookDllDst -Label "Installed SR71"

Write-Stage -Index 4 -Total $totalStages -Activity $activity -Status "Checking minifilter altitude conflicts"
$unknownPreCreateConflicts = Remove-ProjectAltitudeConflicts `
    -Altitude $InstanceAltitude `
    -CurrentServiceName $DriverName `
    -ProjectServiceNames @($DriverName)
if ($unknownPreCreateConflicts.Count -gt 0) {
    $list = $unknownPreCreateConflicts -join ", "
    throw "Altitude $InstanceAltitude is already used by non-project minifilter service(s): $list. Change -InstanceAltitude or remove the conflicting filter(s)."
}

Write-Stage -Index 5 -Total $totalStages -Activity $activity -Status "Registering services"
Invoke-Sc -Arguments @("stop", $ControllerName) -AllowedExitCodes @(0, 1060, 1062)
Invoke-Sc -Arguments @("delete", $ControllerName) -AllowedExitCodes @(0, 1060, 1072)
Invoke-Sc -Arguments @("stop", $DriverName) -AllowedExitCodes @(0, 1060, 1062)
Invoke-Sc -Arguments @("delete", $DriverName) -AllowedExitCodes @(0, 1060, 1072)
New-ServiceWithRetry -ServiceName $DriverName -CreateArguments @(
    "create", $DriverName,
    "type=", "filesys",
    "start=", "system",
    "error=", "normal",
    "group=", "FSFilter Activity Monitor",
    "depend=", "FltMgr",
    "binPath=", $driverDst,
    "DisplayName=", "Blackbird Driver"
) 
Invoke-Sc -Arguments @("qc", $DriverName)
Ensure-MinifilterRegistry -ServiceName $DriverName -InstanceName $InstanceName -Altitude $InstanceAltitude -InstanceFlags $InstanceFlags
Set-DriverRuntimeDefaults -ServiceName $DriverName -EnableAntiVirtualization $EnableAntiVirtualization.IsPresent -EnableSelfHide $EnableControllerHiding.IsPresent -EnableControllerProtectedAccess $true

New-ServiceWithRetry -ServiceName $ControllerName -CreateArguments @("create", $ControllerName, "type=", "own", "start=", "auto", "obj=", "LocalSystem", "binPath=", $controllerDst, "DisplayName=", "Blackbird Controller Service")
Invoke-Sc -Arguments @("failure", $ControllerName, "reset=", "60", "actions=", "restart/5000/restart/5000/restart/5000")

if (-not (Test-ServiceExists -ServiceName $DriverName)) {
    throw "Driver service '$DriverName' was not created."
}
if (-not (Test-ServiceExists -ServiceName $ControllerName)) {
    throw "Controller service '$ControllerName' was not created."
}

Write-Stage -Index 6 -Total $totalStages -Activity $activity -Status "Configuring crash dump policy"
Ensure-BlackbirdCrashDumpSettings

Write-Stage -Index 7 -Total $totalStages -Activity $activity -Status "Configuring firewall rules"
$firewallRemoteAddress = @($script:OperatorFirewallRemoteAddresses)
if ($firewallRemoteAddress.Count -eq 0) {
    $firewallRemoteAddress = @("LocalSubnet")
    Write-Warning "No operator firewall remote address was supplied by -OperatorRemoteAddress or enrollment metadata; using LocalSubnet."
}
Write-InfoLog "Firewall remote address scope: $($firewallRemoteAddress -join ', ')"
Ensure-FirewallRulePresent -DisplayName "Blackbird Operator UDP Discovery" -Protocol UDP -LocalPort "49371" -RemoteAddress $firewallRemoteAddress
Ensure-FirewallRulePresent -DisplayName "Blackbird Operator TCP Status" -Protocol TCP -LocalPort "49372" -RemoteAddress $firewallRemoteAddress
Ensure-FirewallRulePresent -DisplayName "Blackbird Operator TCP Command" -Protocol TCP -LocalPort "49373" -RemoteAddress $firewallRemoteAddress
Ensure-FirewallRulePresent -DisplayName "Blackbird Operator ICMPv4" -Protocol ICMPv4 -IcmpType "8" -RemoteAddress $firewallRemoteAddress

Write-Stage -Index 8 -Total $totalStages -Activity $activity -Status "Starting driver"
$driverRecovered = $false
try {
    Invoke-Sc -Arguments @("start", $DriverName)
}
catch {
    $driverStartError = $_.Exception.Message
    if ($driverStartError -match "exit code 1243") {
        Write-Host "    sc start returned 1243. Attempting minifilter load via fltmc..." -ForegroundColor Yellow
        $fltOut = & fltmc.exe load $DriverName 2>&1
        $fltCode = $LASTEXITCODE
        if ($fltCode -eq 0) {
            Write-Host "    fltmc load succeeded." -ForegroundColor Green
        }
        else {
            Write-Host "    fltmc load failed (exit $fltCode):" -ForegroundColor Yellow
            $fltOut | ForEach-Object { Write-Host "    $_" }
        }
    }

    if ($driverStartError -match "already exists at this altitude|2149515281") {
        Write-Host "    Detected minifilter altitude collision. Attempting conflict cleanup + retry..." -ForegroundColor Yellow
        $unknownRetryConflicts = Remove-ProjectAltitudeConflicts `
            -Altitude $InstanceAltitude `
            -CurrentServiceName $DriverName `
            -ProjectServiceNames @($DriverName)

        if ($unknownRetryConflicts.Count -eq 0) {
            try {
                Ensure-MinifilterRegistry -ServiceName $DriverName -InstanceName $InstanceName -Altitude $InstanceAltitude -InstanceFlags $InstanceFlags
Set-DriverRuntimeDefaults -ServiceName $DriverName -EnableAntiVirtualization $EnableAntiVirtualization.IsPresent -EnableSelfHide $EnableControllerHiding.IsPresent -EnableControllerProtectedAccess $true
                Invoke-Sc -Arguments @("start", $DriverName)
                Write-Host "    Driver start succeeded after altitude conflict remediation." -ForegroundColor Green
                $driverRecovered = $true
            }
            catch {
                $driverStartError = $_.Exception.Message
            }
        }
        else {
            $unknownList = $unknownRetryConflicts -join ", "
            Write-Host "    unresolved altitude conflicts (non-project services): $unknownList" -ForegroundColor Yellow
        }
    }

    if (-not $driverRecovered) {
        Write-Host "[!] Failed to start driver service '$DriverName'." -ForegroundColor Red
        Write-Host "    sc query output:" -ForegroundColor Yellow
        & sc.exe query $DriverName 2>&1 | ForEach-Object { Write-Host "    $_" }
        Write-Host "    sc qc output:" -ForegroundColor Yellow
        & sc.exe qc $DriverName 2>&1 | ForEach-Object { Write-Host "    $_" }
        Write-Host "    fltmgr status:" -ForegroundColor Yellow
        & sc.exe query fltmgr 2>&1 | ForEach-Object { Write-Host "    $_" }
        Write-Host "    minifilter registry keys:" -ForegroundColor Yellow
        (Get-MinifilterRegistryDump -ServiceName $DriverName -InstanceName $InstanceName) -split "`r?`n" | ForEach-Object { Write-Host "    $_" }
        Write-Host "    recent SCM events:" -ForegroundColor Yellow
        (Get-RecentServiceEvents -ServiceName $DriverName) -split "`r?`n" | ForEach-Object { Write-Host "    $_" }
        Write-Host "    conflicting altitude services:" -ForegroundColor Yellow
        $altitudeConflicts = Get-ServicesUsingMinifilterAltitude -Altitude $InstanceAltitude -ExcludeServiceName ""
        if ($altitudeConflicts.Count -eq 0) {
            Write-Host "    (none detected in Services\\*\\Instances)"
        }
        else {
            $altitudeConflicts | ForEach-Object { Write-Host "    $_" }
        }
        Write-Host "    hint: exit code 127 usually means a missing kernel export (driver built for newer OS APIs)." -ForegroundColor Yellow
        throw
    }
}

Assert-ServiceRunning -ServiceName $DriverName -ExpectedStatePattern "STATE\s*:\s*\d+\s+RUNNING" -FailureLabel "Driver service failed to reach RUNNING state."

Write-Stage -Index 9 -Total $totalStages -Activity $activity -Status "Starting controller"
Invoke-Sc -Arguments @("start", $ControllerName)
Assert-ServiceRunning -ServiceName $ControllerName -ExpectedStatePattern "STATE\s*:\s*\d+\s+RUNNING" -FailureLabel "Controller service failed to reach RUNNING state."

Write-Progress -Id 1 -Activity $activity -Completed

Write-Host "[*] Installed and started $DriverName + $ControllerName"
Write-Host "    Driver:     $driverDst"
Write-Host "    Controller: $controllerDst"
Write-Host "    SensorCore: $sensorCoreDst"

