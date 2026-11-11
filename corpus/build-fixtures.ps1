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
  pwsh corpus/build-fixtures.ps1 -Score
#>
[CmdletBinding()]
param(
    [string[]] $Fixture,
    [string[]] $Flags,
    # After building, analyze, match and score each fixture against its expected.toml (fails on a gate failure).
    [switch] $Score,
    # Use the already built target/debug/pbeta-corpus.exe instead of `cargo run` (corpus/verify.ps1 builds it once,
    # so parallel jobs never relink a binary another one is running).
    [switch] $NoBuild
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib/msvc.ps1')
$repo = Split-Path -Parent $PSScriptRoot
$fixturesDir = Join-Path $PSScriptRoot 'fixtures'
$outRoot = Join-Path $repo 'target/fixtures'
$fixtureCl = @('/EHsc', '/permissive-', '/W4')

Import-VsDevEnvironment

function Invoke-Corpus([string[]] $arguments) {
    if ($NoBuild) {
        Invoke-Native (Join-Path $repo 'target\debug\pbeta-corpus.exe') $arguments
    } else {
        Invoke-Native 'cargo' (@('run', '-q', '-p', 'permanent-beta-corpus', '--') + $arguments)
    }
}

$fixtureNames = if ($Fixture) { $Fixture } else { Get-ChildItem $fixturesDir -Directory | ForEach-Object Name }
# PGO needs a training workload, which the fixtures don't have.
$flagNames = if ($Flags) { $Flags } else { Get-PlainMsvcFlagSetNames }

foreach ($name in $fixtureNames) {
    foreach ($flagName in $flagNames) {
        $set = Get-MsvcFlagSet $flagName
        $variantDir = Join-Path $outRoot "$name/$flagName"

        foreach ($version in 'v1', 'v2') {
            $src = Join-Path $fixturesDir "$name/$version/fixture.cpp"
            $out = Join-Path $variantDir $version
            New-Item -ItemType Directory -Force $out | Out-Null
            Write-Host "building $name/$flagName/$version"
            Invoke-Native 'cl.exe' (@($MsvcCommon.cl) + $fixtureCl + @($set.cl) + @(
                    '/c', $src, "/Fo$out\fixture.obj"))
            Invoke-Native 'link.exe' (@($MsvcCommon.link) + @($set.link) + @(
                    "$out\fixture.obj", "/OUT:$out\fixture.exe", "/PDB:$out\fixture.pdb", "/MAP:$out\fixture.map"))
        }

        Invoke-Corpus @('truth',
            '--old', "$variantDir\v1\fixture.map", '--new', "$variantDir\v2\fixture.map",
            '--object', 'fixture.obj', '--out', "$variantDir\truth.json")
        Write-Host "wrote $variantDir\truth.json"
    }

    $expected = Join-Path $fixturesDir "$name/expected.toml"
    if ($Score -and (Test-Path $expected)) {
        Invoke-Corpus @('score',
            '--built', (Join-Path $outRoot $name), '--expected', $expected)
    }
}
