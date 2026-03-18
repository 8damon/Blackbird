param(
    [string]$DriverName = "blackbird",
    [string]$ControllerName = "BlackbirdController",
    [string]$DriverSys = "..\blackbird.sys",
    [string]$ControllerExe = "..\BlackbirdController.exe",
    [string]$SensorCoreDll = "..\J58.dll",
    [string]$InstanceName = "Blackbird Default",
    [string]$InstanceAltitude = "385000.424244",
    [uint32]$InstanceFlags = 0
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

function Resolve-ArtifactPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PreferredPath,
        [Parameter(Mandatory = $true)]
        [string[]]$FallbackPaths,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $candidates = @($PreferredPath) + $FallbackPaths
    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        $pathToTry = $candidate
        if (-not [System.IO.Path]::IsPathRooted($pathToTry)) {
            $pathToTry = Join-Path $repoRoot $pathToTry
        }

        $resolved = Resolve-Path -LiteralPath $pathToTry -ErrorAction SilentlyContinue
        if ($null -ne $resolved) {
            return $resolved.Path
        }
    }

    throw "$Label not found. Tried: $($candidates -join ', ')"
}

function Invoke-Sc {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [int[]]$AllowedExitCodes = @(0)
    )

    $output = & sc.exe @Arguments 2>&1
    $exitCode = $LASTEXITCODE
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

    & sc.exe query $ServiceName 2>&1 | Out-Null
    return $LASTEXITCODE -eq 0
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

function Get-ServicesUsingMinifilterAltitude {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Altitude,
        [string]$ExcludeServiceName = ""
    )

    $servicesRoot = "HKLM:\SYSTEM\CurrentControlSet\Services"
    $matches = New-Object System.Collections.Generic.List[string]

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

    Invoke-Sc -Arguments @("stop", $ServiceName) -AllowedExitCodes @(0, 5, 1060, 1062)
    $fltOut = & fltmc.exe unload $ServiceName 2>&1
    if ($LASTEXITCODE -ne 0) {
        # ignore unload failures; service delete + registry cleanup is enough for stale entries
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
        [string]$IcmpType = ""
    )

    $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        return
    }

    $params = @{
        DisplayName = $DisplayName
        Direction   = "Inbound"
        Protocol    = $Protocol
        Action      = "Allow"
        Profile     = "Any"
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

$totalStages = 8
$activity = "Blackbird installation"

Write-Host ""
Write-Host "Blackbird Installer"
Write-Host "-------------------"

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
        "x64\Debug\blackbird.sys",
        "x64\Release\blackbird.sys",
        "blackbird.sys"
    ) `
    -Label "Driver .sys"

$controllerSrc = Resolve-ArtifactPath `
    -PreferredPath $ControllerExe `
    -FallbackPaths @(
        "vcxproj\x64\Debug\BlackbirdController.exe",
        "vcxproj\x64\Release\BlackbirdController.exe",
        "x64\Debug\BlackbirdController.exe",
        "x64\Release\BlackbirdController.exe",
        "BlackbirdController.exe"
    ) `
    -Label "Controller .exe"

$sensorCoreSrc = Resolve-ArtifactPath `
    -PreferredPath $SensorCoreDll `
    -FallbackPaths @(
        "vcxproj\x64\Debug\J58.dll",
        "vcxproj\x64\Release\J58.dll",
        "x64\Debug\J58.dll",
        "x64\Release\J58.dll",
        "J58.dll"
    ) `
    -Label "SensorCore .dll"

$driverDst = Join-Path $env:windir "System32\drivers\blackbird.sys"
$controllerDir = Join-Path $env:ProgramFiles "Blackbird"
$controllerDst = Join-Path $controllerDir "BlackbirdController.exe"
$sensorCoreDst = Join-Path $controllerDir "J58.dll"

Write-Host "[+] Driver: $driverSrc"
Write-Host "[+] Controller: $controllerSrc"
Write-Host "[+] SensorCore: $sensorCoreSrc"

Write-Stage -Index 3 -Total $totalStages -Activity $activity -Status "Copying binaries"
New-Item -ItemType Directory -Path $controllerDir -Force | Out-Null
Copy-Item -LiteralPath $driverSrc -Destination $driverDst -Force
Copy-Item -LiteralPath $controllerSrc -Destination $controllerDst -Force
Copy-Item -LiteralPath $sensorCoreSrc -Destination $sensorCoreDst -Force

Assert-PathExists -Path $driverDst -Label "Installed driver"
Assert-PathExists -Path $controllerDst -Label "Installed controller"
Assert-PathExists -Path $sensorCoreDst -Label "Installed SensorCore"

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
Invoke-Sc -Arguments @("stop", $DriverName) -AllowedExitCodes @(0, 1060, 1062)
Invoke-Sc -Arguments @("delete", $DriverName) -AllowedExitCodes @(0, 1060)
Invoke-Sc -Arguments @(
    "create", $DriverName,
    "type=", "filesys",
    "start=", "demand",
    "error=", "normal",
    "group=", "FSFilter Activity Monitor",
    "depend=", "FltMgr",
    "binPath=", $driverDst,
    "DisplayName=", "Blackbird Driver"
)
Invoke-Sc -Arguments @("qc", $DriverName)
Ensure-MinifilterRegistry -ServiceName $DriverName -InstanceName $InstanceName -Altitude $InstanceAltitude -InstanceFlags $InstanceFlags

Invoke-Sc -Arguments @("stop", $ControllerName) -AllowedExitCodes @(0, 1060, 1062)
Invoke-Sc -Arguments @("delete", $ControllerName) -AllowedExitCodes @(0, 1060)
Invoke-Sc -Arguments @("create", $ControllerName, "type=", "own", "start=", "auto", "obj=", "LocalSystem", "binPath=", "`"$controllerDst`"", "DisplayName=", "Blackbird Controller Service")
Invoke-Sc -Arguments @("failure", $ControllerName, "reset=", "60", "actions=", "restart/5000/restart/5000/restart/5000")

if (-not (Test-ServiceExists -ServiceName $DriverName)) {
    throw "Driver service '$DriverName' was not created."
}
if (-not (Test-ServiceExists -ServiceName $ControllerName)) {
    throw "Controller service '$ControllerName' was not created."
}

Write-Stage -Index 6 -Total $totalStages -Activity $activity -Status "Configuring firewall rules"
Ensure-FirewallRulePresent -DisplayName "Blackbird Operator UDP Discovery" -Protocol UDP -LocalPort "49371"
Ensure-FirewallRulePresent -DisplayName "Blackbird Operator TCP Status" -Protocol TCP -LocalPort "49372"
Ensure-FirewallRulePresent -DisplayName "Blackbird Operator TCP Command" -Protocol TCP -LocalPort "49373"
Ensure-FirewallRulePresent -DisplayName "Blackbird Operator ICMPv4" -Protocol ICMPv4 -IcmpType "8"

Write-Stage -Index 7 -Total $totalStages -Activity $activity -Status "Starting driver"
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

    if ($driverRecovered) {
        # continue installation flow
    }
    else {
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

Write-Stage -Index 8 -Total $totalStages -Activity $activity -Status "Starting controller"
Invoke-Sc -Arguments @("start", $ControllerName)
Assert-ServiceRunning -ServiceName $ControllerName -ExpectedStatePattern "STATE\s*:\s*\d+\s+RUNNING" -FailureLabel "Controller service failed to reach RUNNING state."

Write-Progress -Id 1 -Activity $activity -Completed

Write-Host "[*] Installed and started $DriverName + $ControllerName"
Write-Host "    Driver:     $driverDst"
Write-Host "    Controller: $controllerDst"
Write-Host "    SensorCore: $sensorCoreDst"





