<#
.SYNOPSIS
  Measures replay (design §7.3) on real code: a corpus project's tool (zlib's minigzip, zstd's zstd), recorded
  in one release and replayed on the next.

.DESCRIPTION
  Hooks the functions in corpus/replay/<project>.template.toml in the old build's tool (record mode of the hook
  DLL), records two runs (compressing one of the project's own source files, then decompressing the result), and
  replays every hook's cases on the same function of the new build. Old and new functions are paired by symbol
  from the linker maps (the answer key), so every pair is correct: this measures replay, not matching. A correct
  pair must never fail; the point is how many cases replay at all, and why the others don't.

  Each hook's cases are also replayed on every other function of the new build (`pbeta replay --others`), the
  control for replay itself: they must pass on none of them, except a function with identical code (the same
  normalized hash), one that calls the target (a forwarding wrapper: zlib's crc32 calls crc32_z) or one the
  target calls (or takes the address of). One that passes fails the measurement, like a correct pair failing,
  unless corpus/replay/<project>.known-confusions.json lists it for these flags and new release (examined: an
  inlined copy, which nothing links to the target); a listed one that no longer happens fails too, so the list
  can't go stale. -SkipOthers leaves the control out (it's most of the run time).

  Speed: hooks are replayed -HookParallel at a time, and each replay's control splits the cores between them
  (PBETA_REPLAY_THREADS, unless set). A recording is reused when nothing it depends on changed (the hook DLL, the
  launcher, the spec, the hooks, the old binary, the input and the run's arguments: `key.txt` in the recording);
  -Rerecord records anyway. corpus/verify.ps1 runs every measurement at once.

  Local only, like ghidra-diff.ps1. Needs the corpus built (build-projects.ps1, the project) and the hook DLL and
  launcher (build-hooks.ps1). Writes target/replay/<project>/<flags>-<old>-<new>/: the spec, the recordings and
  replay.json with every case's outcome.

.EXAMPLE
  pwsh corpus/replay-measure.ps1
  pwsh corpus/replay-measure.ps1 -Flags od -Old v1.2.13 -New v1.3
  pwsh corpus/replay-measure.ps1 -Project zstd
#>
param(
    [ValidateSet('zlib', 'zstd')]
    [string] $Project = 'zlib',
    [string] $Flags = 'o2',
    [string] $Old,
    [string] $New,
    [switch] $NoBuild,
    [switch] $SkipOthers,
    [switch] $Rerecord,
    [int] $HookParallel = 4
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
# Per project: the tool, the default releases, the file compressed (from the old release's sources), and the two
# runs: `{in}` the input, `{z}` the compressed file, `{back}` the decompressed one; `Stdout` where the run's output
# goes. zstd runs single-threaded: the recorder follows each thread, but replay knows nothing of the others.
$projects = @{
    zlib = @{
        Exe = 'minigzip'; Old = 'v1.3'; New = 'v1.3.1'; Input = 'deflate.c'
        Compress = @('-c', '{in}'); CompressStdout = '{z}'
        Decompress = @('-d', '-c', '{z}'); DecompressStdout = '{back}'
    }
    zstd = @{
        Exe = 'zstd'; Old = 'v1.5.6'; New = 'v1.5.7'; Input = 'lib\compress\zstd_compress.c'
        Compress = @('-q', '-f', '-3', '--single-thread', '{in}', '-o', '{z}'); CompressStdout = '{out}\stdout-compress.txt'
        Decompress = @('-q', '-f', '-d', '{z}', '-o', '{back}'); DecompressStdout = '{out}\stdout-decompress.txt'
    }
}
$p = $projects[$Project]
if (-not $Old) { $Old = $p.Old }
if (-not $New) { $New = $p.New }
$exe = $p.Exe
$out = Join-Path $repo "target\replay\$Project\$Flags-$Old-$New"
New-Item -ItemType Directory -Force $out | Out-Null
$builds = Join-Path $repo "target\corpus\$Project\builds\$Flags"
$pbeta = Join-Path $repo 'target\debug\pbeta.exe'
$corpus = Join-Path $repo 'target\debug\pbeta-corpus.exe'
$bin = Join-Path $repo 'target\hooks\bin'
foreach ($need in "$builds\$Old\$exe.exe", "$builds\$New\$exe.exe", "$bin\hookdll.dll", "$bin\launcher.exe") {
    if (-not (Test-Path $need)) { throw "missing $need (run build-projects.ps1 and build-hooks.ps1 first)" }
}
if (-not $NoBuild) {
    cargo build -q --manifest-path "$repo\Cargo.toml" -p permanent-beta-cli -p permanent-beta-corpus --features permanent-beta-cli/emulator
    if ($LASTEXITCODE) { throw 'cargo build failed' }
}

foreach ($v in $Old, $New) {
    # zlib's inflate keeps a `struct inflate_state` behind z_stream's `internal_state* state` (deflate's type): the
    # PDB's locals say so (`pointer_aliases`), and the record spec follows it to the window.
    & $pbeta analyze "$builds\$v\$exe.exe" --pdb "$builds\$v\$exe.pdb" --out "$out\$v.json" | Out-Null
    if ($LASTEXITCODE) { throw "analyze $v failed" }
}
& $corpus hook-manifest --template (Join-Path $PSScriptRoot "replay\$Project.template.toml") --map "$builds\$Old\$exe.map" `
    --analysis "$out\$Old.json" --out "$out\hooks.toml"
if ($LASTEXITCODE) { throw 'hook-manifest failed' }
& $pbeta harness-spec --hooks "$out\hooks.toml" --analysis "$out\$Old.json" --out "$out\spec.toml" | Out-Null
if ($LASTEXITCODE) { throw 'harness-spec failed' }

$inputFile = Join-Path $repo "target\corpus-src\$Project\$Old\$($p.Input)"
$fill = { param([string] $a) $a.Replace('{in}', $inputFile).Replace('{z}', "$out\in.z").Replace('{back}', "$out\out.txt").Replace('{out}', $out) }
$runs = @(
    @{ Name = 'compress'; Args = @($p.Compress | ForEach-Object { & $fill $_ }); Stdout = (& $fill $p.CompressStdout) },
    @{ Name = 'decompress'; Args = @($p.Decompress | ForEach-Object { & $fill $_ }); Stdout = (& $fill $p.DecompressStdout) }
)
# What a recording depends on: when none of it changed, the recording is reused.
function Get-RecordingKey($run) {
    @(
        (Get-FileHash "$bin\hookdll.dll").Hash, (Get-FileHash "$bin\launcher.exe").Hash,
        (Get-FileHash "$out\spec.toml").Hash, (Get-FileHash "$out\hooks.toml").Hash,
        (Get-FileHash "$builds\$Old\$exe.exe").Hash, (Get-FileHash $inputFile).Hash, ($run.Args -join ' ')
    ) -join "`n"
}
$recs = @()
foreach ($r in $runs) {
    $rec = "$out\rec-$($r.Name)"
    $key = Get-RecordingKey $r
    if (-not $Rerecord -and (Test-Path "$rec\key.txt") -and (Test-Path $r.Stdout) -and
        ([IO.File]::ReadAllText("$rec\key.txt") -eq $key)) {
        Write-Host "reusing the $($r.Name) recording (nothing it depends on changed)"
        $recs += $rec
        continue
    }
    Remove-Item -Recurse -Force $rec -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $rec | Out-Null
    $env:PBETA_RECORD = $rec
    $env:PBETA_SPEC = "$out\spec.toml"
    try {
        & "$bin\launcher.exe" "$bin\hookdll.dll" "$out\hooks.toml" "$out\trace-$($r.Name).jsonl" "$builds\$Old\$exe.exe" @($r.Args) > $r.Stdout
        if ($LASTEXITCODE) { throw "$exe ($($r.Name)) exited with $LASTEXITCODE" }
    } finally {
        Remove-Item Env:PBETA_RECORD, Env:PBETA_SPEC
    }
    [IO.File]::WriteAllText("$rec\key.txt", $key)
    $recs += $rec
}
if ((Get-FileHash $inputFile).Hash -ne (Get-FileHash "$out\out.txt").Hash) { throw 'the round trip under the recorder changed the data' }

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
$oldRva = Get-MapRvas "$builds\$Old\$exe.map"
$newRva = Get-MapRvas "$builds\$New\$exe.map"
$caseArgs = @(); foreach ($r in $recs) { $caseArgs += @('--cases', $r) }
$names = @(Get-Content "$out\hooks.toml" | Select-String '^name = "(.+)"' | ForEach-Object { $_.Matches[0].Groups[1].Value })
# Each replay's control gets a share of the cores (one emulator per thread).
if (-not $env:PBETA_REPLAY_THREADS) {
    $env:PBETA_REPLAY_THREADS = [Math]::Max(1, [int]([Environment]::ProcessorCount / [Math]::Max(1, $HookParallel)))
}
$replay = @{
    Pbeta = $pbeta; Cases = $caseArgs; Binary = "$builds\$New\$exe.exe"; NewJson = "$out\$New.json"
    OldJson = "$out\$Old.json"; Others = -not $SkipOthers; OldRva = $oldRva; NewRva = $newRva; Names = $names
}
$results = @(0..($names.Count - 1) | ForEach-Object -ThrottleLimit ([Math]::Max(1, $HookParallel)) -Parallel {
        $a = $using:replay
        $h = $a.Names[$_]
        $o = $null
        if ($a.NewRva[$h]) {
            $j = & $a.Pbeta (@('replay') + $a.Cases + @('--binary', $a.Binary, '--old-rva', $a.OldRva[$h],
                    '--new-rva', $a.NewRva[$h], '--new-analysis', $a.NewJson, '--old-analysis', $a.OldJson, '--json') +
                $(if ($a.Others) { @('--others') } else { @() }))
            $o = ($j | Out-String) | ConvertFrom-Json
        }
        [pscustomobject]@{ Index = $_; Hook = $h; Result = $o }
    } | Sort-Object Index)
$rows = @()
$all = @()
foreach ($r in $results) {
    $h = $r.Hook
    $o = $r.Result
    if (-not $o) { $rows += [pscustomobject]@{ Hook = $h; Outcome = "not in $New" }; continue }
    $all += [pscustomobject]@{ Hook = $h; Result = $o }
    $rows += [pscustomobject]@{
        Hook         = $h
        Outcome      = $o.outcome
        Cases        = (@($o.cases | Group-Object outcome | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ', ')
        Others       = if ($o.others) { "pass $(@($o.others.passed).Count), same code $(@($o.others.same_code).Count), wrapper $(@($o.others.calls_target).Count), callee $(@($o.others.called_by_target).Count)" } else { '' }
        OthersPassed = if ($o.others) { @($o.others.passed) } else { @() }
        Replayed     = [bool] $o.others
        Detail       = if ($o.detail.Length -gt 160) { $o.detail.Substring(0, 160) + '...' } else { $o.detail }
    }
}
$all | ConvertTo-Json -Depth 8 | Set-Content "$out\replay.json"
$rows | Format-Table Hook, Outcome, Cases, Others, Detail -AutoSize -Wrap | Out-String -Width 250 | Write-Host
$failed = @($rows | Where-Object Outcome -eq 'fail')
$passed = @($rows | Where-Object Outcome -eq 'pass')
Write-Host "$Project $Flags $Old -> ${New}: $($passed.Count) of $($rows.Count) hooks replay (all matching), $($failed.Count) fail"
# Every pair is correct by the answer key: a failure is replay's error.
if ($failed.Count) { throw "replay failed a correct pair: $($failed.Hook -join ', ')" }
# A hook's cases passing on a function with other code: replay can't tell the wrong function from the right one.
# Pairs examined and listed in <project>.known-confusions.json (for these flags and new release) are reported
# apart; any other fails the measurement, and so does a listed pair that no longer happens.
$knownFile = Join-Path $PSScriptRoot "replay\$Project.known-confusions.json"
$known = @(if (Test-Path $knownFile) {
        (Get-Content -Raw $knownFile | ConvertFrom-Json).known | Where-Object { $_.flags -eq $Flags -and $_.new -eq $New }
    })
$nameAt = @{}
foreach ($k in $newRva.Keys) { $nameAt[$newRva[$k]] = $k }
$unknown = @()
$seen = @()
foreach ($r in $rows) {
    foreach ($rva in $r.OthersPassed) {
        $name = $nameAt[$rva]
        $match = @($known | Where-Object { $_.hook -eq $r.Hook -and $_.passes_on -eq $name })
        if ($match.Count) { $seen += $match[0] } else { $unknown += "$($r.Hook) on $rva$(if ($name) { " ($name)" })" }
    }
}
$stale = @($known | Where-Object {
        $k = $_
        ($rows | Where-Object { $_.Hook -eq $k.hook -and $_.Replayed }) -and -not ($seen | Where-Object { $_ -eq $k })
    })
if (-not $SkipOthers) {
    $confused = @($rows | Where-Object { $_.OthersPassed.Count })
    Write-Host "control: $($confused.Count) of $($rows.Count) hooks' cases pass on another function of $New ($($seen.Count) known, $($unknown.Count) not)"
    foreach ($k in $seen) { Write-Host "  known: $($k.hook) passes on $($k.passes_on): $($k.reason)" }
}
if ($unknown.Count) { throw "replay passed wrong functions: $($unknown -join '; ')" }
if ($stale.Count) {
    throw "known confusions no longer seen (remove them from $knownFile): $(($stale | ForEach-Object { "$($_.hook) on $($_.passes_on)" }) -join '; ')"
}
