<#
.SYNOPSIS
  Builds the Permanent Beta test fixtures with MSVC and generates their answer keys.

.DESCRIPTION
  For each fixture under corpus/fixtures/<name>/ (with v1/ and v2/ source folders) and each flag set, compiles
  both versions to target/fixtures/<name>/<flags>/v{1,2}/ with an .exe, .pdb and linker .map file, then writes
  truth.json (the true old -> new function mapping, joined by symbol name from the map files).

  Requires Visual Studio (or Build Tools) with the C++ x64 toolset, and cargo on PATH.

.EXAMPLE
  pwsh corpus/build-fixtures.ps1
  pwsh corpus/build-fixtures.ps1 -Fixture basic -Flags o2-icf
#>
[CmdletBinding()]
param(
    [string[]] $Fixture,
    [string[]] $Flags
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$fixturesDir = Join-Path $PSScriptRoot 'fixtures'
$outRoot = Join-Path $repo 'target/fixtures'

# Flag sets. Every set uses:
#   /INCREMENTAL:NO  incremental linking routes calls through jump thunks, which would confuse matching
#   /Z7 + /Brepro    byte-identical .obj files and identical code layout across runs. The .exe still differs in
#                    the PE timestamp and PDB signature (linker-generated), so its SHA-256 changes per build.
#   /DEBUG:FULL      a self-contained PDB
#   /MAP             linker map file, the source of the answer key
$common = @{
    cl   = @('/nologo', '/EHsc', '/MD', '/Z7', '/Brepro', '/permissive-', '/W4')
    link = @('/nologo', '/DEBUG:FULL', '/MAP', '/INCREMENTAL:NO', '/Brepro', '/OPT:REF')
}
$flagSets = [ordered]@{
    'o2'     = @{ cl = @('/O2'); link = @('/OPT:NOICF') }
    'o2-icf' = @{ cl = @('/O2'); link = @('/OPT:ICF') }
    'od'     = @{ cl = @('/Od'); link = @('/OPT:NOICF') }
}

function Import-VsDevEnvironment {
    if (Get-Command cl.exe -ErrorAction SilentlyContinue) { return }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found; install Visual Studio with the C++ toolset." }
    $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw "No Visual Studio installation with the x64 C++ toolset was found." }
    $vcvars = Join-Path $vs 'VC/Auxiliary/Build/vcvars64.bat'
    $env:PATH = "$(Split-Path $vswhere);$env:PATH"  # vcvars64 calls vswhere itself
    # Run vcvars64 in cmd and copy the resulting environment into this session.
    cmd /c "`"$vcvars`" >nul && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "env:$($Matches[1])" -Value $Matches[2] }
    }
    if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) { throw "cl.exe still not on PATH after vcvars64." }
}

function Invoke-Native([string] $exe, [string[]] $arguments) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "$exe failed with exit code $LASTEXITCODE" }
}

Import-VsDevEnvironment

$fixtureNames = if ($Fixture) { $Fixture } else { Get-ChildItem $fixturesDir -Directory | ForEach-Object Name }
$flagNames = if ($Flags) { $Flags } else { $flagSets.Keys }

foreach ($name in $fixtureNames) {
    foreach ($flagName in $flagNames) {
        if (-not $flagSets.Contains($flagName)) { throw "Unknown flag set '$flagName'. Known: $($flagSets.Keys -join ', ')" }
        $set = $flagSets[$flagName]
        $variantDir = Join-Path $outRoot "$name/$flagName"

        foreach ($version in 'v1', 'v2') {
            $src = Join-Path $fixturesDir "$name/$version/fixture.cpp"
            $out = Join-Path $variantDir $version
            New-Item -ItemType Directory -Force $out | Out-Null
            Write-Host "building $name/$flagName/$version"
            Invoke-Native 'cl.exe' (@($common.cl) + @($set.cl) + @(
                    '/c', $src, "/Fo$out\fixture.obj"))
            Invoke-Native 'link.exe' (@($common.link) + @($set.link) + @(
                    "$out\fixture.obj", "/OUT:$out\fixture.exe", "/PDB:$out\fixture.pdb", "/MAP:$out\fixture.map"))
        }

        Invoke-Native 'cargo' @('run', '-q', '-p', 'permanent-beta-corpus', '--', 'truth',
            '--old', "$variantDir\v1\fixture.map", '--new', "$variantDir\v2\fixture.map",
            '--object', 'fixture.obj', '--out', "$variantDir\truth.json")
        Write-Host "wrote $variantDir\truth.json"
    }
}
