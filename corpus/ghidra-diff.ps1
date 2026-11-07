<#
.SYNOPSIS
  M1 diff report: Ghidra's functions vs the native analyzer's vs the PDB's, on built corpus binaries.

.DESCRIPTION
  For each selected build (default: the newest tag of every corpus project, every flag set):
    1. Copies the .exe alone into target/ghidra/<project>_<flags>_<tag>/ and runs Ghidra headless on the copy,
       with every PDB analyzer off (integrations/ghidra/scripts/DisablePdb.java), then ExportFunctions.java.
    2. Analyzes the .exe natively (with --pdb, which also writes the PDB's procedures) and again with Ghidra's
       boundaries (`pbeta analyze --functions-from`).
    3. Writes three `pbeta analysis-diff` reports (text and JSON): native vs Ghidra, Ghidra vs PDB, native vs
       PDB. Disagreements are reported, never resolved.

  Needs the corpus built (corpus/build-projects.ps1), a JDK 25+, and Ghidra 12.x with GHIDRA_INSTALL_DIR set.
  Local only: not run in CI (design §13 question 7).

.EXAMPLE
  pwsh corpus/ghidra-diff.ps1
  pwsh corpus/ghidra-diff.ps1 -Project zlib -Flags o2 -Pseudocode
#>
[CmdletBinding()]
param(
    [string[]] $Project = @('zlib', 'lua', 'zstd'),
    [string[]] $Flags = @('o2', 'o2-icf', 'od'),
    # Also decompile every function into the export (slower; pseudocode goes into the Ghidra-based analysis).
    [switch] $Pseudocode
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$scripts = Join-Path $repo 'integrations/ghidra/scripts'
$outRoot = Join-Path $repo 'target/ghidra'

$ghidra = $env:GHIDRA_INSTALL_DIR
if (-not $ghidra) { $ghidra = [Environment]::GetEnvironmentVariable('GHIDRA_INSTALL_DIR', 'User') }
$headless = if ($ghidra) { Join-Path $ghidra 'support/analyzeHeadless.bat' }
if (-not $headless -or -not (Test-Path $headless)) {
    throw "Ghidra not found: set GHIDRA_INSTALL_DIR to the Ghidra install folder (the one holding support/)."
}
$props = Get-Content (Join-Path $ghidra 'Ghidra/application.properties') -ErrorAction SilentlyContinue
$version = ($props | Where-Object { $_ -like 'application.version=*' }) -replace '^application.version=', ''
if (-not $version -or [version]($version -replace '[^0-9.].*$', '') -lt [version]'12.0') {
    throw "Ghidra 12.0 or newer needed (found '$version' at $ghidra)."
}

& cargo build -q --release -p permanent-beta-cli
if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
$pbeta = Join-Path $repo 'target/release/pbeta.exe'

function Invoke-Pbeta([string[]] $argv) {
    & $pbeta @argv
    # analysis-diff exits 1 when the analyses disagree, which is the expected outcome here.
    if ($LASTEXITCODE -gt 1) { throw "pbeta $($argv -join ' ') failed ($LASTEXITCODE)" }
}

$rows = @()
foreach ($p in $Project) {
    $recipe = Import-PowerShellDataFile (Join-Path $PSScriptRoot "projects/$p/recipe.psd1")
    $tag = $recipe.Versions[-1]
    foreach ($f in $Flags) {
        $build = Join-Path $repo "target/corpus/$p/builds/$f/$tag"
        $exe = Get-ChildItem $build -Filter *.exe | Select-Object -First 1
        if (-not $exe) { Write-Warning "no build in $build (run corpus/build-projects.ps1)"; continue }
        $pdb = [IO.Path]::ChangeExtension($exe.FullName, '.pdb')
        $key = "${p}_${f}_$tag"
        $out = Join-Path $outRoot $key
        Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force (Join-Path $out 'in'), (Join-Path $out 'project') | Out-Null
        $copy = Join-Path $out "in/$($exe.Name)"
        Copy-Item $exe.FullName $copy

        Write-Host "== ${key}: Ghidra headless"
        $export = Join-Path $out 'ghidra.json'
        $post = @('ExportFunctions.java', $export) + $(if ($Pseudocode) { @('pseudocode') } else { @() })
        $started = Get-Date
        & $headless (Join-Path $out 'project') pb -import $copy -scriptPath $scripts `
            -preScript DisablePdb.java -postScript @post -deleteProject *> (Join-Path $out 'ghidra.log')
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $export)) {
            throw "Ghidra failed on $key; see $(Join-Path $out 'ghidra.log')"
        }
        $seconds = [int]((Get-Date) - $started).TotalSeconds
        if (-not (Select-String -Path (Join-Path $out 'ghidra.log') -Pattern 'disabled analyzer: PDB' -Quiet)) {
            throw "${key}: the PDB analyzers weren't disabled; see ghidra.log"
        }

        $native = Join-Path $out 'native.json'
        $pdbFns = Join-Path $out 'pdb.json'
        $ghidraAnalysis = Join-Path $out 'ghidra-analysis.json'
        Invoke-Pbeta @('analyze', $exe.FullName, '--out', $native, '--pdb', $pdb, '--pdb-functions', $pdbFns)
        Invoke-Pbeta @('analyze', $exe.FullName, '--out', $ghidraAnalysis, '--functions-from', $export)

        $row = [ordered]@{ build = $key; ghidra_s = $seconds }
        foreach ($pair in @(@('native', $native, 'ghidra', $ghidraAnalysis), @('ghidra', $ghidraAnalysis, 'pdb', $pdbFns),
                @('native', $native, 'pdb', $pdbFns))) {
            $name = "$($pair[0])-vs-$($pair[2])"
            Invoke-Pbeta @('analysis-diff', $pair[1], $pair[3], '--limit', '1000') > (Join-Path $out "$name.txt")
            Invoke-Pbeta @('analysis-diff', $pair[1], $pair[3], '--json') > (Join-Path $out "$name.json")
            $d = Get-Content (Join-Path $out "$name.json") -Raw | ConvertFrom-Json
            $row["$name"] = "agree $($d.agreeing), only $($pair[0]) $($d.only_a.Count), only $($pair[2]) $($d.only_b.Count), " +
                "size $($d.size_differs.Count), hash $($d.hash_differs.Count)"
        }
        $rows += [pscustomobject]$row
    }
}

$rows | Format-List
Write-Host "reports in $outRoot/<build>/*-vs-*.txt"
