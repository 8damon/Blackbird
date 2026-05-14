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
$interfaceProject = Join-Path $repoRoot "vcxproj\BlackbirdInterface.csproj"
$runnerProject = Join-Path $repoRoot "vcxproj\BlackbirdRunner.csproj"
$stageRoot = Join-Path $repoRoot ".publish\dotnet"
$outputRoot = Join-Path $repoRoot "x64\$Configuration"
$interfaceStage = Join-Path $stageRoot "BlackbirdInterface"
$runnerStage = Join-Path $stageRoot "BlackbirdRunner"

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
        "-p:SelfContained=$($SelfContained.ToString().ToLowerInvariant())",
        "-p:PublishSingleFile=$($PublishSingleFile.ToString().ToLowerInvariant())",
        "-p:IncludeNativeLibrariesForSelfExtract=true",
        "-p:EnableCompressionInSingleFile=false",
        "-p:PublishTrimmed=false",
        "-p:DebugType=None",
        "-p:DebugSymbols=false",
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

function Assert-SingleFileExe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StagePath,

        [Parameter(Mandatory = $true)]
        [string]$FileName
    )

    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    $exePath = Join-Path $StagePath $FileName
    if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
        throw "Published executable not found: $exePath"
    }

    $exe = Get-Item -LiteralPath $exePath
    if ($SelfContained -and $PublishSingleFile -and $exe.Length -lt 1048576) {
        throw "$FileName does not look self-contained/single-file; size is $($exe.Length) bytes."
    }

    foreach ($sidecar in @("$baseName.dll", "$baseName.deps.json", "$baseName.runtimeconfig.json")) {
        $sidecarPath = Join-Path $outputRoot $sidecar
        if (Test-Path -LiteralPath $sidecarPath -PathType Leaf) {
            Remove-Item -LiteralPath $sidecarPath -Force
        }
    }
}

New-Item -ItemType Directory -Force -Path $stageRoot | Out-Null
New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null

Invoke-Publish -ProjectPath $interfaceProject -StagePath $interfaceStage
Invoke-Publish -ProjectPath $runnerProject -StagePath $runnerStage

Assert-SingleFileExe -StagePath $interfaceStage -FileName "BlackbirdInterface.exe"
Assert-SingleFileExe -StagePath $runnerStage -FileName "BlackbirdRunner.exe"
Copy-PackagedExe -StagePath $interfaceStage -FileName "BlackbirdInterface.exe"
Copy-PackagedExe -StagePath $runnerStage -FileName "BlackbirdRunner.exe"

Write-Host ""
Write-Host "Published .NET single-file binaries:"
Write-Host "  $(Join-Path $outputRoot 'BlackbirdInterface.exe')"
Write-Host "  $(Join-Path $outputRoot 'BlackbirdRunner.exe')"
