param(
    [string]$DriverName = "sleepwlkr",
    [string]$ControllerName = "SleepwlkrController",
    [string]$DriverSys = "..\sleepwlkr.sys",
    [string]$ControllerExe = "..\SleepwlkrController.exe",
    [string]$SensorCoreDll = "..\SleepwalkerSensorCore.dll"
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

$driverSrc = Resolve-ArtifactPath `
    -PreferredPath $DriverSys `
    -FallbackPaths @(
        "vcxproj\x64\Debug\sleepwlkr.sys",
        "vcxproj\x64\Release\sleepwlkr.sys",
        "x64\Debug\sleepwlkr.sys",
        "x64\Release\sleepwlkr.sys",
        "sleepwlkr.sys"
    ) `
    -Label "Driver .sys"

$controllerSrc = Resolve-ArtifactPath `
    -PreferredPath $ControllerExe `
    -FallbackPaths @(
        "vcxproj\x64\Debug\SleepwlkrController.exe",
        "vcxproj\x64\Release\SleepwlkrController.exe",
        "x64\Debug\SleepwlkrController.exe",
        "x64\Release\SleepwlkrController.exe",
        "SleepwlkrController.exe"
    ) `
    -Label "Controller .exe"

$sensorCoreSrc = Resolve-ArtifactPath `
    -PreferredPath $SensorCoreDll `
    -FallbackPaths @(
        "vcxproj\x64\Debug\SleepwalkerSensorCore.dll",
        "vcxproj\x64\Release\SleepwalkerSensorCore.dll",
        "x64\Debug\SleepwalkerSensorCore.dll",
        "x64\Release\SleepwalkerSensorCore.dll",
        "SleepwalkerSensorCore.dll"
    ) `
    -Label "SensorCore .dll"

$driverDst = Join-Path $env:windir "System32\drivers\sleepwlkr.sys"
$controllerDir = Join-Path $env:ProgramFiles "Sleepwalker"
$controllerDst = Join-Path $controllerDir "SleepwlkrController.exe"
$sensorCoreDst = Join-Path $controllerDir "SleepwalkerSensorCore.dll"

New-Item -ItemType Directory -Path $controllerDir -Force | Out-Null
Copy-Item -LiteralPath $driverSrc -Destination $driverDst -Force
Copy-Item -LiteralPath $controllerSrc -Destination $controllerDst -Force
Copy-Item -LiteralPath $sensorCoreSrc -Destination $sensorCoreDst -Force

Invoke-Sc -Arguments @("stop", $DriverName) -AllowedExitCodes @(0, 1060, 1062)
Invoke-Sc -Arguments @("delete", $DriverName) -AllowedExitCodes @(0, 1060)
Invoke-Sc -Arguments @("create", $DriverName, "type=", "kernel", "start=", "demand", "error=", "normal", "binPath=", $driverDst, "DisplayName=", "Sleepwalker Driver")

Invoke-Sc -Arguments @("stop", $ControllerName) -AllowedExitCodes @(0, 1060, 1062)
Invoke-Sc -Arguments @("delete", $ControllerName) -AllowedExitCodes @(0, 1060)
Invoke-Sc -Arguments @("create", $ControllerName, "type=", "own", "start=", "auto", "obj=", "LocalSystem", "binPath=", "`"$controllerDst`"", "DisplayName=", "Sleepwalker Controller Service")
Invoke-Sc -Arguments @("failure", $ControllerName, "reset=", "60", "actions=", "restart/5000/restart/5000/restart/5000")

try {
    Invoke-Sc -Arguments @("start", $DriverName)
}
catch {
    Write-Host "[!] Failed to start driver service '$DriverName'." -ForegroundColor Red
    Write-Host "    sc query output:" -ForegroundColor Yellow
    & sc.exe query $DriverName 2>&1 | ForEach-Object { Write-Host "    $_" }
    Write-Host "    recent SCM events:" -ForegroundColor Yellow
    (Get-RecentServiceEvents -ServiceName $DriverName) -split "`r?`n" | ForEach-Object { Write-Host "    $_" }
    Write-Host "    hint: exit code 127 usually means a missing kernel export (driver built for newer OS APIs)." -ForegroundColor Yellow
    throw
}

Invoke-Sc -Arguments @("start", $ControllerName)

Write-Host "[*] Installed and started $DriverName + $ControllerName"
Write-Host "    Driver:     $driverDst"
Write-Host "    Controller: $controllerDst"
Write-Host "    SensorCore: $sensorCoreDst"
