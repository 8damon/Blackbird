[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [ValidateSet("x64", "ARM64")]
    [string]$Platform = "x64",

    [switch]$SkipDriver,
    [switch]$SkipOfflineSmoke,
    [switch]$RunDriverDependentTests
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$driverProject = Join-Path $repoRoot "VCXProj\Blackbird.vcxproj"
$sensorProject = Join-Path $repoRoot "VCXProj\BlackbirdSensorCore.vcxproj"
$controllerProject = Join-Path $repoRoot "VCXProj\BlackbirdController.vcxproj"
$examplesProject = Join-Path $repoRoot "VCXProj\BlackbirdExamples.vcxproj"
$ioctlTestProject = Join-Path $repoRoot "VCXProj\BlackbirdIoctlTest.vcxproj"
$interfaceProject = Join-Path $repoRoot "VCXProj\BlackbirdInterface.csproj"
$operatorProject = Join-Path $repoRoot "VCXProj\BlackbirdOperator.csproj"
$hookProject = Join-Path $repoRoot "UserMode\hook\vcxproj\BlackbirdHook.vcxproj"
$offlineSmokeExe = Join-Path $repoRoot "$Platform\$Configuration\DetectionExamples\DetectionExamples.exe"
$driverTestSuiteExe = Join-Path $repoRoot "$Platform\$Configuration\BlackbirdTestSuite.exe"

function Resolve-MSBuildPath {
    $vswherePath = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswherePath) {
        $installPath = & $vswherePath -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($installPath)) {
            $amd64Candidate = Join-Path $installPath "MSBuild\Current\Bin\amd64\MSBuild.exe"
            if (Test-Path $amd64Candidate) {
                return $amd64Candidate
            }

            $candidate = Join-Path $installPath "MSBuild\Current\Bin\MSBuild.exe"
            if (Test-Path $candidate) {
                return $candidate
            }
        }
    }

    $command = Get-Command msbuild.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    throw "MSBuild.exe was not found. Install Visual Studio Build Tools / Visual Studio with MSBuild."
}

function Invoke-MSBuildProject {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProjectPath,

        [Parameter(Mandatory = $true)]
        [string]$ProjectLabel,

        [string]$PlatformValue = $Platform,

        [hashtable]$ExtraProperties = @{}
    )

    $args = @(
        $ProjectPath,
        "/t:Build",
        "/p:Configuration=$Configuration",
        "/p:Platform=$PlatformValue",
        "/m",
        "/nologo"
    )

    foreach ($entry in $ExtraProperties.GetEnumerator()) {
        $args += "/p:$($entry.Key)=$($entry.Value)"
    }

    Write-Host ""
    Write-Host "==> Building $ProjectLabel"
    & $script:MSBuildPath @args
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed for $ProjectLabel."
    }
}

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$Arguments = @(),

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    Write-Host ""
    Write-Host "==> Running $Label"
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE."
    }
}

$script:MSBuildPath = Resolve-MSBuildPath

Write-Host "Blackbird CI surface"
Write-Host "  repoRoot       : $repoRoot"
Write-Host "  msbuild        : $script:MSBuildPath"
Write-Host "  configuration  : $Configuration"
Write-Host "  platform       : $Platform"
Write-Host "  skipDriver     : $SkipDriver"
Write-Host "  skipSmoke      : $SkipOfflineSmoke"
Write-Host "  runDriverTests : $RunDriverDependentTests"

Invoke-MSBuildProject -ProjectPath $sensorProject -ProjectLabel "BlackbirdSensorCore"
Invoke-MSBuildProject -ProjectPath $controllerProject -ProjectLabel "BlackbirdController"
Invoke-MSBuildProject -ProjectPath $hookProject -ProjectLabel "BlackbirdHook"
Invoke-MSBuildProject -ProjectPath $examplesProject -ProjectLabel "DetectionExamples"
Invoke-MSBuildProject -ProjectPath $ioctlTestProject -ProjectLabel "BlackbirdTestSuite"
Invoke-MSBuildProject -ProjectPath $interfaceProject -ProjectLabel "BlackbirdInterface" -PlatformValue "AnyCPU"
Invoke-MSBuildProject -ProjectPath $operatorProject -ProjectLabel "BlackbirdOperator" -PlatformValue "AnyCPU"

if (-not $SkipDriver) {
    Invoke-MSBuildProject -ProjectPath $driverProject -ProjectLabel "BlackbirdDriver" -ExtraProperties @{ SignMode = "None" }
}

if (-not $SkipOfflineSmoke) {
    if (-not (Test-Path $offlineSmokeExe)) {
        throw "Offline smoke binary not found: $offlineSmokeExe"
    }

    Invoke-NativeCommand -FilePath $offlineSmokeExe -Arguments @("--list") -Label "DetectionExamples --list"
}

if ($RunDriverDependentTests) {
    if (-not (Test-Path $driverTestSuiteExe)) {
        throw "Driver-dependent test suite not found: $driverTestSuiteExe"
    }

    Write-Warning "Running BlackbirdTestSuite requires the broker/controller path and a loaded driver."
    Invoke-NativeCommand -FilePath $driverTestSuiteExe -Label "BlackbirdTestSuite"
}

Write-Host ""
Write-Host "Blackbird CI surface completed successfully."
