param(
    [string]$DriverName = "blackbird",
    [string]$ControllerName = "BlackbirdController",
    [string]$DriverSys = "..\blackbird.sys",
    [string]$ControllerExe = "..\BlackbirdController.exe",
    [string]$SensorCoreDll = "..\BlackbirdSensorCore.dll",
    [string]$InstanceName = "Blackbird Default",
    [string]$InstanceAltitude = "385000.424244",
    [uint32]$InstanceFlags = 0,
    [string[]]$LegacyDriverNames = @("sleepwlkr", "sleepwalker")
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
        "vcxproj\x64\Debug\BlackbirdSensorCore.dll",
        "vcxproj\x64\Release\BlackbirdSensorCore.dll",
        "x64\Debug\BlackbirdSensorCore.dll",
        "x64\Release\BlackbirdSensorCore.dll",
        "BlackbirdSensorCore.dll"
    ) `
    -Label "SensorCore .dll"

$driverDst = Join-Path $env:windir "System32\drivers\blackbird.sys"
$controllerDir = Join-Path $env:ProgramFiles "Blackbird"
$controllerDst = Join-Path $controllerDir "BlackbirdController.exe"
$sensorCoreDst = Join-Path $controllerDir "BlackbirdSensorCore.dll"

New-Item -ItemType Directory -Path $controllerDir -Force | Out-Null
Copy-Item -LiteralPath $driverSrc -Destination $driverDst -Force
Copy-Item -LiteralPath $controllerSrc -Destination $controllerDst -Force
Copy-Item -LiteralPath $sensorCoreSrc -Destination $sensorCoreDst -Force

foreach ($legacyName in $LegacyDriverNames) {
    if ([string]::IsNullOrWhiteSpace($legacyName) -or
        $legacyName.Equals($DriverName, [System.StringComparison]::OrdinalIgnoreCase)) {
        continue
    }
    Remove-MinifilterServiceArtifacts -ServiceName $legacyName
}

$unknownPreCreateConflicts = Remove-ProjectAltitudeConflicts `
    -Altitude $InstanceAltitude `
    -CurrentServiceName $DriverName `
    -ProjectServiceNames (@($LegacyDriverNames) + @($DriverName))
if ($unknownPreCreateConflicts.Count -gt 0) {
    $list = $unknownPreCreateConflicts -join ", "
    throw "Altitude $InstanceAltitude is already used by non-project minifilter service(s): $list. Change -InstanceAltitude or remove the conflicting filter(s)."
}

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
            -ProjectServiceNames (@($LegacyDriverNames) + @($DriverName))

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

Invoke-Sc -Arguments @("start", $ControllerName)

Write-Host "[*] Installed and started $DriverName + $ControllerName"
Write-Host "    Driver:     $driverDst"
Write-Host "    Controller: $controllerDst"
Write-Host "    SensorCore: $sensorCoreDst"
