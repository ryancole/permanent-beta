<#
.SYNOPSIS
  Measures replay (design §7.3) on real code: zlib's minigzip, recorded in one release and replayed on the next.

.DESCRIPTION
  Hooks the functions in corpus/replay/zlib.template.toml in the old build's minigzip (record mode of the hook
  DLL), records two runs (compressing zlib's deflate.c, then decompressing the result), and replays every hook's
  cases on the same function of the new build. Old and new functions are paired by symbol from the linker maps
  (the answer key), so every pair is correct: this measures replay, not matching. A correct pair must never fail;
  the point is how many cases replay at all, and why the others don't.

  Local only, like ghidra-diff.ps1. Needs the corpus built (build-projects.ps1, zlib) and the hook DLL and
  launcher (build-hooks.ps1). Writes target/replay/zlib/<flags>-<old>-<new>/: the spec, the recordings and
  replay.json with every case's outcome.

.EXAMPLE
  pwsh corpus/replay-measure.ps1
  pwsh corpus/replay-measure.ps1 -Flags od -Old v1.2.13 -New v1.3
#>
param(
    [string] $Flags = 'o2',
    [string] $Old = 'v1.3',
    [string] $New = 'v1.3.1',
    [switch] $NoBuild
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$out = Join-Path $repo "target\replay\zlib\$Flags-$Old-$New"
New-Item -ItemType Directory -Force $out | Out-Null
$builds = Join-Path $repo "target\corpus\zlib\builds\$Flags"
$pbeta = Join-Path $repo 'target\debug\pbeta.exe'
$corpus = Join-Path $repo 'target\debug\pbeta-corpus.exe'
$bin = Join-Path $repo 'target\hooks\bin'
foreach ($need in "$builds\$Old\minigzip.exe", "$builds\$New\minigzip.exe", "$bin\hookdll.dll", "$bin\launcher.exe") {
    if (-not (Test-Path $need)) { throw "missing $need (run build-projects.ps1 and build-hooks.ps1 first)" }
}
if (-not $NoBuild) {
    cargo build -q --manifest-path "$repo\Cargo.toml" -p permanent-beta-cli -p permanent-beta-corpus --features permanent-beta-cli/emulator
    if ($LASTEXITCODE) { throw 'cargo build failed' }
}

foreach ($v in $Old, $New) {
    # inflate keeps a `struct inflate_state` behind z_stream's `internal_state* state` (deflate's type): its layout,
    # which no signature uses, and the alias below let the recorder follow it to the window.
    & $pbeta analyze "$builds\$v\minigzip.exe" --pdb "$builds\$v\minigzip.pdb" --type inflate_state --out "$out\$v.json" | Out-Null
    if ($LASTEXITCODE) { throw "analyze $v failed" }
}
& $corpus hook-manifest --template (Join-Path $PSScriptRoot 'replay\zlib.template.toml') --map "$builds\$Old\minigzip.map" `
    --analysis "$out\$Old.json" --out "$out\hooks.toml"
if ($LASTEXITCODE) { throw 'hook-manifest failed' }
& $pbeta harness-spec --hooks "$out\hooks.toml" --analysis "$out\$Old.json" --out "$out\spec.toml" `
    --pointer-alias z_stream_s.state=inflate_state | Out-Null
if ($LASTEXITCODE) { throw 'harness-spec failed' }

$input = Join-Path $repo "target\corpus-src\zlib\$Old\deflate.c"
$runs = @(
    @{ Name = 'compress'; Args = @('-c', $input); Stdout = "$out\in.gz" },
    @{ Name = 'decompress'; Args = @('-d', '-c', "$out\in.gz"); Stdout = "$out\out.txt" }
)
$recs = @()
foreach ($r in $runs) {
    $rec = "$out\rec-$($r.Name)"
    Remove-Item -Recurse -Force $rec -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $rec | Out-Null
    $env:PBETA_RECORD = $rec
    $env:PBETA_SPEC = "$out\spec.toml"
    try {
        & "$bin\launcher.exe" "$bin\hookdll.dll" "$out\hooks.toml" "$out\trace-$($r.Name).jsonl" "$builds\$Old\minigzip.exe" @($r.Args) > $r.Stdout
        if ($LASTEXITCODE) { throw "minigzip ($($r.Name)) exited with $LASTEXITCODE" }
    } finally {
        Remove-Item Env:PBETA_RECORD, Env:PBETA_SPEC
    }
    $recs += $rec
}
if ((Get-FileHash $input).Hash -ne (Get-FileHash "$out\out.txt").Hash) { throw 'the round trip under the recorder changed the data' }

# Functions by symbol from a linker map: name -> RVA.
function Get-MapRvas([string] $map) {
    $h = @{}
    foreach ($line in Get-Content $map) {
        if ($line -match '^\s*0001:[0-9a-f]+\s+(\S+)\s+([0-9a-f]{16})\s+f') {
            $h[$Matches[1]] = '0x{0:x}' -f ([Convert]::ToInt64($Matches[2], 16) - 0x140000000)
        }
    }
    $h
}
$oldRva = Get-MapRvas "$builds\$Old\minigzip.map"
$newRva = Get-MapRvas "$builds\$New\minigzip.map"
$caseArgs = @(); foreach ($r in $recs) { $caseArgs += @('--cases', $r) }
$rows = @()
$all = @()
$names = Get-Content "$out\hooks.toml" | Select-String '^name = "(.+)"' | ForEach-Object { $_.Matches[0].Groups[1].Value }
foreach ($h in $names) {
    if (-not $newRva[$h]) { $rows += [pscustomobject]@{ Hook = $h; Outcome = "not in $New" }; continue }
    $j = & $pbeta (@('replay') + $caseArgs + @('--binary', "$builds\$New\minigzip.exe", '--old-rva', $oldRva[$h],
            '--new-rva', $newRva[$h], '--new-analysis', "$out\$New.json", '--old-analysis', "$out\$Old.json", '--json'))
    $o = ($j | Out-String) | ConvertFrom-Json
    $all += [pscustomobject]@{ Hook = $h; Result = $o }
    $rows += [pscustomobject]@{
        Hook    = $h
        Outcome = $o.outcome
        Cases   = (@($o.cases | Group-Object outcome | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ', ')
        Detail  = if ($o.detail.Length -gt 160) { $o.detail.Substring(0, 160) + '...' } else { $o.detail }
    }
}
$all | ConvertTo-Json -Depth 8 | Set-Content "$out\replay.json"
$rows | Format-Table -AutoSize -Wrap | Out-String -Width 250 | Write-Host
$failed = @($rows | Where-Object Outcome -eq 'fail')
$passed = @($rows | Where-Object Outcome -eq 'pass')
Write-Host "zlib $Flags $Old -> ${New}: $($passed.Count) of $($rows.Count) hooks replay (all matching), $($failed.Count) fail"
# Every pair is correct by the answer key: a failure is replay's error.
if ($failed.Count) { throw "replay failed a correct pair: $($failed.Hook -join ', ')" }
