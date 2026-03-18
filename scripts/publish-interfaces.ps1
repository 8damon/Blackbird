[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64",
    [bool]$SelfContained = $true,
    [bool]$PublishSingleFile = $true
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$interfaceProject = Join-Path $repoRoot "interface\BlackbirdInterface.csproj"
$operatorProject = Join-Path $repoRoot "host\BlackbirdOperator\BlackbirdOperator.csproj"
$stageRoot = Join-Path $repoRoot ".publish\interfaces"
$outputRoot = Join-Path $repoRoot "x64\$Configuration"
$interfaceStage = Join-Path $stageRoot "BlackbirdInterface"
$operatorStage = Join-Path $stageRoot "BlackbirdOperator"

function Invoke-Publish {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProjectPath,

        [Parameter(Mandatory = $true)]
        [string]$StagePath
    )

    if (Test-Path $StagePath) {
        Remove-Item -Recurse -Force $StagePath
    }

    $publishArgs = @(
        "publish",
        $ProjectPath,
        "-c", $Configuration,
        "-r", $Runtime,
        "--self-contained", $SelfContained.ToString().ToLowerInvariant(),
        "-p:PublishSingleFile=$($PublishSingleFile.ToString().ToLowerInvariant())",
        "-o", $StagePath,
        "-nologo"
    )

    & dotnet @publishArgs
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish failed for $ProjectPath"
    }
}

function Copy-PackagedExe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StagePath,

        [Parameter(Mandatory = $true)]
        [string]$FileName
    )

    $sourcePath = Join-Path $StagePath $FileName
    if (-not (Test-Path $sourcePath)) {
        throw "Published file not found: $sourcePath"
    }

    Copy-Item -Force $sourcePath (Join-Path $outputRoot $FileName)
}

New-Item -ItemType Directory -Force -Path $stageRoot | Out-Null
New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null

Invoke-Publish -ProjectPath $interfaceProject -StagePath $interfaceStage
Invoke-Publish -ProjectPath $operatorProject -StagePath $operatorStage

Copy-PackagedExe -StagePath $interfaceStage -FileName "BlackbirdInterface.exe"
Copy-PackagedExe -StagePath $operatorStage -FileName "BlackbirdOperator.exe"

Write-Host ""
Write-Host "Published interface binaries:"
Write-Host "  $(Join-Path $outputRoot 'BlackbirdInterface.exe')"
Write-Host "  $(Join-Path $outputRoot 'BlackbirdOperator.exe')"
