param(
    [string]$DriverName = "sleepwlkr",
    [string]$ControllerName = "SleepwlkrController",
    [string]$DriverSys = ".\x64\Debug\sleepwlkr.sys",
    [string]$ControllerExe = ".\x64\Debug\SleepwlkrController.exe"
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
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

        $resolved = Resolve-Path -LiteralPath $candidate -ErrorAction SilentlyContinue
        if ($null -ne $resolved) {
            return $resolved.Path
        }
    }

    throw "$Label not found. Tried: $($candidates -join ', ')"
}

$driverSrc = Resolve-ArtifactPath `
    -PreferredPath $DriverSys `
    -FallbackPaths @(".\x64\Debug\sleepwlkr.sys", ".\x64\Release\sleepwlkr.sys", ".\sleepwlkr.sys") `
    -Label "Driver .sys"

$controllerSrc = Resolve-ArtifactPath `
    -PreferredPath $ControllerExe `
    -FallbackPaths @(".\x64\Debug\SleepwlkrController.exe", ".\x64\Release\SleepwlkrController.exe", ".\SleepwlkrController.exe") `
    -Label "Controller .exe"

$driverDst = Join-Path $env:windir "System32\drivers\sleepwlkr.sys"
$controllerDir = Join-Path $env:ProgramFiles "Sleepwalker"
$controllerDst = Join-Path $controllerDir "SleepwlkrController.exe"

New-Item -ItemType Directory -Path $controllerDir -Force | Out-Null
Copy-Item -LiteralPath $driverSrc -Destination $driverDst -Force
Copy-Item -LiteralPath $controllerSrc -Destination $controllerDst -Force

sc.exe stop $DriverName | Out-Null
sc.exe delete $DriverName | Out-Null
sc.exe create $DriverName type= kernel start= demand error= normal binPath= "$driverDst" DisplayName= "Sleepwalker Driver" | Out-Null

sc.exe stop $ControllerName | Out-Null
sc.exe delete $ControllerName | Out-Null
sc.exe create $ControllerName type= own start= auto obj= LocalSystem binPath= "`"$controllerDst`"" DisplayName= "Sleepwalker Controller Service" | Out-Null
sc.exe failure $ControllerName reset= 60 actions= restart/5000/restart/5000/restart/5000 | Out-Null

sc.exe start $DriverName | Out-Null
sc.exe start $ControllerName | Out-Null

Write-Host "[*] Installed and started $DriverName + $ControllerName"
Write-Host "    Driver:     $driverDst"
Write-Host "    Controller: $controllerDst"
