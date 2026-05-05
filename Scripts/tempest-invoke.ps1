param(
    [string]$DriverName = "blackbird",
    [string]$ControllerName = "BlackbirdController",
    [string]$DriverSys = "",
    [string]$ControllerExe = "",
    [string]$NetSvcExe = "",
    [string]$PreviewHostExe = "",
    [string]$RunnerExe = "",
    [string]$SensorCoreDll = "",
    [string]$HookDll = "",
    [string]$InstanceName = "Blackbird Default",
    [string]$InstanceAltitude = "385000.424244",
    [uint32]$InstanceFlags = 0,
    [Alias("av")]
    [switch]$EnableAntiVirtualization,
    [Alias("hide")]
    [switch]$EnableControllerHiding,
    [string]$ControllerArgs = ""   # passed as binPath suffix if set (e.g. "--debug --verbose")
)

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptRoot "..")).Path
$osVersion = [Environment]::OSVersion.Version
$osBuild = $osVersion.Build

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

function Write-DebugLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host ("[dbg]  {0}" -f $Message) -ForegroundColor Magenta
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

function Wait-ServiceNameAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [int]$TimeoutSeconds = 30
    )

    Write-VerboseLog "Waiting for service name availability: $ServiceName (timeout ${TimeoutSeconds}s)"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempt = 0

    while ((Get-Date) -lt $deadline) {
        $attempt++
        & sc.exe query $ServiceName 2>&1 | Out-Null
        $queryExit = $LASTEXITCODE

        if ($queryExit -eq 1060) {
            Write-VerboseLog "Service name available after $attempt attempt(s): $ServiceName"
            return $true
        }

        if ($attempt -eq 1 -or ($attempt % 5) -eq 0) {
            Write-VerboseLog "Service name still unavailable on attempt ${attempt}: $ServiceName (sc exit $queryExit)"
        }

        Start-Sleep -Milliseconds 500
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
        throw "Service '$ServiceName' is still present or marked for deletion. Close Services.msc or other tools holding service handles, then rerun."
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

    New-ItemProperty -Path $serviceKey -Name "DebugFlags" -PropertyType DWord -Value 1 -Force | Out-Null
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
    New-ItemProperty -Path $parametersKey -Name "DebugMode" -PropertyType DWord -Value 1 -Force | Out-Null
    Write-DebugLog ("Driver runtime: av={0} hide={1} ctrl-protect={2} DebugMode=1" -f ([int]$EnableAntiVirtualization), ([int]$EnableSelfHide), ([int]$EnableControllerProtectedAccess))
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
            LogName      = "System"
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
        [string]$IcmpType = ""
    )

    $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        return
    }

    $params = @{
        DisplayName   = $DisplayName
        Direction     = "Inbound"
        Protocol      = $Protocol
        Action        = "Allow"
        Profile       = "Any"
        RemoteAddress = "LocalSubnet"
    }

    if (-not [string]::IsNullOrWhiteSpace($LocalPort)) {
        $params.LocalPort = $LocalPort
    }
    if (-not [string]::IsNullOrWhiteSpace($IcmpType)) {
        $params.IcmpType = $IcmpType
    }

    New-NetFirewallRule @params | Out-Null
}

# ─── Entry ────────────────────────────────────────────────────────────────────

$totalStages = 7
$activity = "Blackbird debug invoke (Tempest)"

Write-Host ""
Write-Host "Blackbird Debug Invoke - Tempest" -ForegroundColor Magenta
Write-Host "---------------------------------" -ForegroundColor DarkMagenta
Write-Host "  DebugFlags=1  DebugMode=1  Controller in console" -ForegroundColor DarkMagenta
Write-Host ""

# Stage 1 — tear down any prior installation
Write-Stage -Index 1 -Total $totalStages -Activity $activity -Status "Removing previous installation"
$removerScript = Join-Path $scriptRoot "remover.ps1"
if (Test-Path -LiteralPath $removerScript) {
    & $removerScript -DriverName $DriverName -ControllerName $ControllerName
}

# Stage 2 — resolve Debug build artifacts (Debug first, then TEMPUS_DEBUG, then Release as last resort)
Write-Stage -Index 2 -Total $totalStages -Activity $activity -Status "Resolving debug build artifacts"

$driverSrc = Resolve-ArtifactPath `
    -PreferredPath $DriverSys `
    -FallbackPaths @(
        "vcxproj\x64\Debug\blackbird.sys",
        "vcxproj\x64\TEMPUS_DEBUG\blackbird.sys",
        "vcxproj\x64\Release\blackbird.sys",
        "x64\Debug\blackbird.sys",
        "x64\TEMPUS_DEBUG\blackbird.sys",
        "x64\Release\blackbird.sys",
        "blackbird.sys"
    ) `
    -Label "Driver .sys"

$controllerSrc = Resolve-ArtifactPath `
    -PreferredPath $ControllerExe `
    -FallbackPaths @(
        "vcxproj\x64\Debug\BlackbirdController.exe",
        "vcxproj\x64\TEMPUS_DEBUG\BlackbirdController.exe",
        "vcxproj\x64\Release\BlackbirdController.exe",
        "x64\Debug\BlackbirdController.exe",
        "x64\TEMPUS_DEBUG\BlackbirdController.exe",
        "x64\Release\BlackbirdController.exe",
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
        "x64\Debug\BlackbirdRunner.exe",
        "vcxproj\x64\Debug\BlackbirdRunner.exe",
        "x64\Debug\net9.0-windows\BlackbirdRunner.exe",
        "x64\TEMPUS_DEBUG\BlackbirdRunner.exe",
        "vcxproj\x64\TEMPUS_DEBUG\BlackbirdRunner.exe",
        "x64\TEMPUS_DEBUG\net9.0-windows\BlackbirdRunner.exe",
        "x64\Release\BlackbirdRunner.exe",
        "vcxproj\x64\Release\BlackbirdRunner.exe",
        "x64\Release\net9.0-windows\BlackbirdRunner.exe",
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
        "vcxproj\x64\TEMPUS_DEBUG\J58.dll",
        "vcxproj\x64\Release\J58.dll",
        "x64\Debug\J58.dll",
        "x64\TEMPUS_DEBUG\J58.dll",
        "x64\Release\J58.dll",
        "J58.dll"
    ) `
    -Label "SensorCore .dll"

$hookDllSrc = Resolve-ArtifactPath `
    -PreferredPath $HookDll `
    -FallbackPaths @(
        "vcxproj\x64\Debug\SR71.dll",
        "vcxproj\x64\TEMPUS_DEBUG\SR71.dll",
        "vcxproj\x64\Release\SR71.dll",
        "UserMode\hook\vcxproj\x64\Debug\SR71.dll",
        "UserMode\hook\vcxproj\x64\TEMPUS_DEBUG\SR71.dll",
        "UserMode\hook\vcxproj\x64\Release\SR71.dll",
        "x64\Debug\SR71.dll",
        "x64\TEMPUS_DEBUG\SR71.dll",
        "x64\Release\SR71.dll",
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

Write-DebugLog "Driver source:     $driverSrc"
Write-DebugLog "Controller source: $controllerSrc"
if ($netSvcSrc) {
    Write-DebugLog "NetSvc source:     $netSvcSrc"
} else {
    Write-DebugLog "NetSvc source:     optional component absent"
}
if ($previewHostSrc) {
    Write-DebugLog "PreviewHost source: $previewHostSrc"
} else {
    Write-DebugLog "PreviewHost source: optional component absent"
}
if ($runnerSrc) {
    Write-DebugLog "Runner source:     $runnerSrc"
} else {
    Write-DebugLog "Runner source:     optional component absent"
}
Write-DebugLog "SensorCore source: $sensorCoreSrc"
Write-DebugLog "SR71 source:       $hookDllSrc"

# Stage 3 — copy binaries
Write-Stage -Index 3 -Total $totalStages -Activity $activity -Status "Stopping services and copying binaries"

Invoke-Sc -Arguments @("stop", $ControllerName) -AllowedExitCodes @(0, 1060, 1062)
Invoke-Sc -Arguments @("stop", $DriverName) -AllowedExitCodes @(0, 1060, 1062, 1243)
Write-VerboseLog "fltmc.exe unload $DriverName"
$fltUnloadOut = & fltmc.exe unload $DriverName 2>&1
if ($fltUnloadOut) {
    foreach ($line in $fltUnloadOut) {
        Write-VerboseLog "fltmc> $line"
    }
}
Write-VerboseLog "fltmc unload exit=$LASTEXITCODE"

if (-not (Wait-UntilFileUnlocked -Path $driverDst -TimeoutSeconds 20)) {
    throw "$driverDst is still locked after driver stop/unload. Reboot then rerun."
}
if (-not (Wait-UntilFileUnlocked -Path $controllerDst -TimeoutSeconds 20)) {
    throw "$controllerDst is still locked. Kill any running BlackbirdController process then rerun."
}
if ($netSvcSrc -and -not (Wait-UntilFileUnlocked -Path $netSvcDst -TimeoutSeconds 20)) {
    throw "$netSvcDst is still locked. Kill any running BlackbirdNetSvc process then rerun."
}
if ($previewHostSrc -and -not (Wait-UntilFileUnlocked -Path $previewHostDst -TimeoutSeconds 20)) {
    throw "$previewHostDst is still locked. Kill any running BlackbirdPreviewHost process then rerun."
}
if ($runnerSrc -and -not (Wait-UntilFileUnlocked -Path $runnerDst -TimeoutSeconds 20)) {
    throw "$runnerDst is still locked. Kill any running BlackbirdRunner process then rerun."
}
if (-not (Wait-UntilFileUnlocked -Path $sensorCoreDst -TimeoutSeconds 20)) {
    throw "$sensorCoreDst is still locked. Kill any running BlackbirdController process then rerun."
}
if (-not (Wait-UntilFileUnlocked -Path $hookDllDst -TimeoutSeconds 20)) {
    throw "$hookDllDst is still locked. Kill any running target using SR71 then rerun."
}

New-Item -ItemType Directory -Path $controllerDir -Force | Out-Null
Write-InfoLog "Copying driver:     $driverSrc -> $driverDst"
Copy-Item -LiteralPath $driverSrc -Destination $driverDst -Force
Write-InfoLog "Copying controller: $controllerSrc -> $controllerDst"
Copy-Item -LiteralPath $controllerSrc -Destination $controllerDst -Force
if ($netSvcSrc) {
    Write-InfoLog "Copying NetSvc:     $netSvcSrc -> $netSvcDst"
    Copy-Item -LiteralPath $netSvcSrc -Destination $netSvcDst -Force
} else {
    Write-InfoLog "Skipping optional NetSvc copy"
}
if ($previewHostSrc) {
    Write-InfoLog "Copying PreviewHost: $previewHostSrc -> $previewHostDst"
    Copy-Item -LiteralPath $previewHostSrc -Destination $previewHostDst -Force
} else {
    Write-InfoLog "Skipping optional PreviewHost copy"
}
if ($runnerSrc) {
    Write-InfoLog "Copying Runner:     $runnerSrc -> $runnerDst"
    Copy-Item -LiteralPath $runnerSrc -Destination $runnerDst -Force
} else {
    Write-InfoLog "Skipping optional Runner copy"
}
Write-InfoLog "Copying SensorCore: $sensorCoreSrc -> $sensorCoreDst"
Copy-Item -LiteralPath $sensorCoreSrc -Destination $sensorCoreDst -Force
Write-InfoLog "Copying SR71:       $hookDllSrc -> $hookDllDst"
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

# Stage 4 — altitude conflict check
Write-Stage -Index 4 -Total $totalStages -Activity $activity -Status "Checking minifilter altitude conflicts"

$unknownPreCreateConflicts = Remove-ProjectAltitudeConflicts `
    -Altitude $InstanceAltitude `
    -CurrentServiceName $DriverName `
    -ProjectServiceNames @($DriverName)
if ($unknownPreCreateConflicts.Count -gt 0) {
    $list = $unknownPreCreateConflicts -join ", "
    throw "Altitude $InstanceAltitude is already used by non-project minifilter service(s): $list. Change -InstanceAltitude or remove the conflicting filter(s)."
}

# Stage 5 — register driver service (demand, not auto — debug sessions are explicit)
Write-Stage -Index 5 -Total $totalStages -Activity $activity -Status "Registering driver service (demand start, debug registry)"

Invoke-Sc -Arguments @("stop", $DriverName) -AllowedExitCodes @(0, 1060, 1062)
Invoke-Sc -Arguments @("delete", $DriverName) -AllowedExitCodes @(0, 1060)
New-ServiceWithRetry -ServiceName $DriverName -CreateArguments @(
    "create", $DriverName,
    "type=", "filesys",
    "start=", "demand",
    "error=", "normal",
    "group=", "FSFilter Activity Monitor",
    "depend=", "FltMgr",
    "binPath=", $driverDst,
    "DisplayName=", "Blackbird Driver (Debug)"
)
Invoke-Sc -Arguments @("qc", $DriverName)

# DebugFlags=1 enables kernel-side debug output paths
Ensure-MinifilterRegistry -ServiceName $DriverName -InstanceName $InstanceName -Altitude $InstanceAltitude -InstanceFlags $InstanceFlags
Set-DriverRuntimeDefaults -ServiceName $DriverName -EnableAntiVirtualization $EnableAntiVirtualization.IsPresent -EnableSelfHide $EnableControllerHiding.IsPresent -EnableControllerProtectedAccess $true

if (-not (Test-ServiceExists -ServiceName $DriverName)) {
    throw "Driver service '$DriverName' was not created."
}

# Stage 6 — start driver
Write-Stage -Index 6 -Total $totalStages -Activity $activity -Status "Starting driver"

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
            Write-Host "    Unresolved altitude conflicts (non-project services): $unknownList" -ForegroundColor Yellow
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
            Write-Host "    (none detected in Services\*\Instances)"
        }
        else {
            $altitudeConflicts | ForEach-Object { Write-Host "    $_" }
        }
        Write-Host "    hint: exit code 127 usually means a missing kernel export (driver built for newer OS APIs)." -ForegroundColor Yellow
        throw
    }
}

Assert-ServiceRunning -ServiceName $DriverName -ExpectedStatePattern "STATE\s*:\s*\d+\s+RUNNING" -FailureLabel "Driver service failed to reach RUNNING state."

# Stage 7 — firewall rules + register and start controller service
Write-Stage -Index 7 -Total $totalStages -Activity $activity -Status "Configuring firewall and starting controller service"

Ensure-FirewallRulePresent -DisplayName "Blackbird Operator UDP Discovery" -Protocol UDP -LocalPort "49371"
Ensure-FirewallRulePresent -DisplayName "Blackbird Operator TCP Status"    -Protocol TCP -LocalPort "49372"
Ensure-FirewallRulePresent -DisplayName "Blackbird Operator TCP Command"   -Protocol TCP -LocalPort "49373"
Ensure-FirewallRulePresent -DisplayName "Blackbird Operator ICMPv4"        -Protocol ICMPv4 -IcmpType "8"

Invoke-Sc -Arguments @("stop", $ControllerName) -AllowedExitCodes @(0, 1060, 1062)
Invoke-Sc -Arguments @("delete", $ControllerName) -AllowedExitCodes @(0, 1060)

$controllerBinPath = if ([string]::IsNullOrWhiteSpace($ControllerArgs)) {
    $controllerDst
} else {
    "`"$controllerDst`" $ControllerArgs"
}

New-ServiceWithRetry -ServiceName $ControllerName -CreateArguments @(
    "create", $ControllerName,
    "type=", "own",
    "start=", "demand",
    "obj=", "LocalSystem",
    "binPath=", $controllerBinPath,
    "DisplayName=", "Blackbird Controller Service (Debug)"
)

if (-not (Test-ServiceExists -ServiceName $ControllerName)) {
    throw "Controller service '$ControllerName' was not created."
}

Invoke-Sc -Arguments @("start", $ControllerName)
Assert-ServiceRunning -ServiceName $ControllerName -ExpectedStatePattern "STATE\s*:\s*\d+\s+RUNNING" -FailureLabel "Controller service failed to reach RUNNING state."

$controllerPid = (Get-CimInstance Win32_Service -Filter "Name='$ControllerName'" -ErrorAction SilentlyContinue).ProcessId
Write-DebugLog "Controller service PID: $controllerPid"

Write-Progress -Id 1 -Activity $activity -Completed

Write-Host ""
Write-Host "[*] Tempest debug session active" -ForegroundColor Green
Write-Host "    Driver:     $driverDst  (DebugFlags=1, DebugMode=1)" -ForegroundColor Green
Write-Host "    Controller: $controllerDst  (PID $controllerPid)" -ForegroundColor Green
Write-Host "    SensorCore: $sensorCoreDst" -ForegroundColor Green
Write-Host ""
Write-Host "    Streaming OutputDebugString from controller - Ctrl+C to detach" -ForegroundColor DarkGray
Write-Host "    To tear down: sc stop $ControllerName ; sc stop $DriverName" -ForegroundColor DarkGray
Write-Host ""

# ─── OutputDebugString listener (DBWIN shared memory protocol) ────────────────
# Same mechanism as DebugView. Layout: [DWORD pid][char[4092] msg, null-term, ANSI]

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class DbgMon {
    public const uint PAGE_READWRITE    = 0x04;
    public const uint FILE_MAP_READ     = 0x0004;
    public const uint WAIT_OBJECT_0     = 0x00000000;
    public const uint WAIT_TIMEOUT      = 0x00000102;
    public const uint INFINITE          = 0xFFFFFFFF;

    [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr CreateFileMapping(IntPtr hFile, IntPtr attr, uint protect,
                                                  uint sizeHi, uint sizeLo, string name);
    [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr MapViewOfFile(IntPtr hMap, uint access,
                                              uint offHi, uint offLo, UIntPtr bytes);
    [DllImport("kernel32")] public static extern bool UnmapViewOfFile(IntPtr p);
    [DllImport("kernel32")] public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr CreateEvent(IntPtr attr, bool manualReset,
                                            bool initialState, string name);
    [DllImport("kernel32")] public static extern bool SetEvent(IntPtr h);
    [DllImport("kernel32")] public static extern uint WaitForSingleObject(IntPtr h, uint ms);
}
'@ -ErrorAction SilentlyContinue

$INVALID_HANDLE = [IntPtr]::new(-1)
$hMap   = [DbgMon]::CreateFileMapping($INVALID_HANDLE, [IntPtr]::Zero, [DbgMon]::PAGE_READWRITE, 0, 4096, "DBWIN_BUFFER")
$pView  = [DbgMon]::MapViewOfFile($hMap, [DbgMon]::FILE_MAP_READ, 0, 0, [UIntPtr]::new(0))
$hReady = [DbgMon]::CreateEvent([IntPtr]::Zero, $false, $false, "DBWIN_BUFFER_READY")
$hData  = [DbgMon]::CreateEvent([IntPtr]::Zero, $false, $false, "DBWIN_DATA_READY")

if ($hMap -eq [IntPtr]::Zero -or $pView -eq [IntPtr]::Zero -or
    $hReady -eq [IntPtr]::Zero -or $hData -eq [IntPtr]::Zero) {
    Write-Warning "Failed to open DBWIN shared memory - is another debugger (DebugView) already attached?"
    Write-Warning "Debug output will not be streamed. Detach any other listener and rerun."
} else {
    [DbgMon]::SetEvent($hReady) | Out-Null

    try {
        while ($true) {
            $wait = [DbgMon]::WaitForSingleObject($hData, 500)

            if ($wait -eq [DbgMon]::WAIT_OBJECT_0) {
                $pid32  = [System.Runtime.InteropServices.Marshal]::ReadInt32($pView, 0)
                $msgPtr = [IntPtr]::new($pView.ToInt64() + 4)
                $msg    = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($msgPtr)

                if ($pid32 -eq $controllerPid) {
                    $trimmed = $msg.TrimEnd("`r", "`n", " ")
                    if ($trimmed.Length -gt 0) {
                        Write-Host $trimmed -ForegroundColor White
                    }
                }

                [DbgMon]::SetEvent($hReady) | Out-Null
            }
        }
    }
    finally {
        [DbgMon]::UnmapViewOfFile($pView) | Out-Null
        [DbgMon]::CloseHandle($hMap)      | Out-Null
        [DbgMon]::CloseHandle($hReady)    | Out-Null
        [DbgMon]::CloseHandle($hData)     | Out-Null
        Write-Host ""
        Write-Host "[detached]" -ForegroundColor DarkGray
    }
}
