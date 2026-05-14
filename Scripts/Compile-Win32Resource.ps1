param(
    [Parameter(Mandatory = $true)]
    [string]$Source,

    [Parameter(Mandatory = $true)]
    [string]$Output
)

$ErrorActionPreference = 'Stop'

function Find-RcExe {
    $fromPath = Get-Command rc.exe -ErrorAction SilentlyContinue
    if ($fromPath -ne $null) {
        return $fromPath.Source
    }

    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (Test-Path -LiteralPath $kitsRoot) {
        $candidate = Get-ChildItem -LiteralPath $kitsRoot -Directory |
            Sort-Object Name -Descending |
            ForEach-Object {
                $x64 = Join-Path $_.FullName 'x64\rc.exe'
                if (Test-Path -LiteralPath $x64) { return $x64 }
                $x86 = Join-Path $_.FullName 'x86\rc.exe'
                if (Test-Path -LiteralPath $x86) { return $x86 }
            } |
            Select-Object -First 1

        if ($candidate) {
            return $candidate
        }
    }

    throw 'rc.exe was not found in PATH or the Windows 10 SDK.'
}

$sourcePath = Resolve-Path -LiteralPath $Source
$outputPath = [System.IO.Path]::GetFullPath($Output)
$outputDir = Split-Path -Parent $outputPath
if (![string]::IsNullOrWhiteSpace($outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$rcExe = Find-RcExe
& $rcExe /nologo "/fo$outputPath" $sourcePath
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
