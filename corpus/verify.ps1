<#
.SYNOPSIS
  Runs every corpus measurement at once: replay on zlib and zstd (corpus/replay-measure.ps1), the M4 hook loop with
  replay (corpus/build-hooks.ps1 -Run -Replay) and the fixture scorecards (corpus/build-fixtures.ps1 -Score).

.DESCRIPTION
  Builds once, sequentially (pbeta and pbeta-corpus with the emulator, the hook DLL, launcher and sample apps, the
  fixtures), then starts each measurement as its own job with -NoBuild, so no job rebuilds a file another one is
  running. The replays split the machine's cores between them (PBETA_REPLAY_THREADS). Each job's output goes to
  target/verify/<job>.log; the summary lists every job's result, the key lines of its log and how long it took.
  Exit code 1 if any job failed.

  -Quick leaves out the wrong-target control (`replay-measure.ps1 -SkipOthers`), most of the replay time: for
  iterating. Run it without -Quick before a commit. -Only runs some of the jobs (by name, see the summary).

.EXAMPLE
  pwsh corpus/verify.ps1
  pwsh corpus/verify.ps1 -Quick
  pwsh corpus/verify.ps1 -Only zstd-o2,fixtures
#>
param(
    [switch] $Quick,
    [string[]] $Only,
    [switch] $Rerecord
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$logs = Join-Path $repo 'target\verify'
New-Item -ItemType Directory -Force $logs | Out-Null
$measure = Join-Path $PSScriptRoot 'replay-measure.ps1'
$extra = @('-NoBuild') + $(if ($Quick) { @('-SkipOthers') } else { @() }) + $(if ($Rerecord) { @('-Rerecord') } else { @() })
$jobs = @(
    @{ Name = 'zlib-o2'; File = $measure; Args = @('-Project', 'zlib') + $extra; Replay = $true },
    @{ Name = 'zlib-od'; File = $measure; Args = @('-Project', 'zlib', '-Flags', 'od', '-Old', 'v1.2.13', '-New', 'v1.3') + $extra; Replay = $true },
    @{ Name = 'zstd-o2'; File = $measure; Args = @('-Project', 'zstd') + $extra; Replay = $true },
    @{ Name = 'zstd-od'; File = $measure; Args = @('-Project', 'zstd', '-Flags', 'od', '-Old', 'v1.5.5', '-New', 'v1.5.6') + $extra; Replay = $true },
    @{ Name = 'hook-loop'; File = (Join-Path $PSScriptRoot 'build-hooks.ps1'); Args = @('-Run', '-Replay', '-NoBuild'); Replay = $false },
    @{ Name = 'fixtures'; File = (Join-Path $PSScriptRoot 'build-fixtures.ps1'); Args = @('-Score', '-NoBuild'); Replay = $false }
)
if ($Only) { $jobs = @($jobs | Where-Object { $Only -contains $_.Name }) }
if (-not $jobs) { throw "no job named $($Only -join ', ')" }

$started = Get-Date
Write-Host 'building pbeta and pbeta-corpus (emulator), the hook DLL and apps, the fixtures'
cargo build -q --manifest-path "$repo\Cargo.toml" -p permanent-beta-cli -p permanent-beta-corpus --features permanent-beta-cli/emulator
if ($LASTEXITCODE) { throw 'cargo build failed' }
foreach ($b in @(
        @{ File = 'build-hooks.ps1'; Args = @(); Log = 'build-hooks' },
        @{ File = 'build-fixtures.ps1'; Args = @('-NoBuild'); Log = 'build-fixtures' })) {
    pwsh -NoProfile -File (Join-Path $PSScriptRoot $b.File) @($b.Args) *> (Join-Path $logs "$($b.Log).log")
    if ($LASTEXITCODE) { throw "$($b.File) failed: see target\verify\$($b.Log).log" }
}
$built = Get-Date

# Hooks replayed at a time in each replay job, and threads per replay's control: the cores, shared.
$hookParallel = 4
$replayJobs = @($jobs | Where-Object Replay).Count
$env:PBETA_REPLAY_THREADS = [Math]::Max(1, [int]([Environment]::ProcessorCount / [Math]::Max(1, $replayJobs * $hookParallel)))
Write-Host "starting $($jobs.Count) jobs ($env:PBETA_REPLAY_THREADS threads per replay)"
$running = foreach ($j in $jobs) {
    $log = Join-Path $logs "$($j.Name).log"
    $jobArgs = @($j.Args) + $(if ($j.Replay) { @('-HookParallel', $hookParallel) } else { @() })
    $job = Start-Job -Name $j.Name -ArgumentList $j.File, $jobArgs, $log, $repo -ScriptBlock {
        param($file, $arguments, $log, $repo)
        Set-Location $repo
        $s = Get-Date
        pwsh -NoProfile -File $file @arguments *> $log
        [pscustomobject]@{ Exit = $LASTEXITCODE; Minutes = ((Get-Date) - $s).TotalMinutes }
    }
    [pscustomobject]@{ Name = $j.Name; Job = $job; Log = $log }
}
$null = $running.Job | Wait-Job

$rows = foreach ($r in $running) {
    $res = Receive-Job $r.Job
    Remove-Job $r.Job
    $key = @(Get-Content $r.Log -ErrorAction SilentlyContinue |
            Select-String 'hooks replay|^control:|replayable:|WRONG|gate:|FAILED|hooks ok' |
            ForEach-Object { $_.Line.Trim() } | Select-Object -Unique -First 6) -join ' | '
    [pscustomobject]@{
        Job     = $r.Name
        Result  = if ($res.Exit -eq 0) { 'ok' } else { "FAILED ($($res.Exit))" }
        Minutes = '{0:n1}' -f $res.Minutes
        Summary = $key
    }
}
$rows | Format-Table -AutoSize -Wrap | Out-String -Width 250 | Write-Host
Write-Host ('build {0:n1} min, jobs {1:n1} min, total {2:n1} min{3}; logs in target\verify' -f
    ($built - $started).TotalMinutes, ((Get-Date) - $built).TotalMinutes, ((Get-Date) - $started).TotalMinutes,
    $(if ($Quick) { ' (-Quick: no wrong-target control)' } else { '' }))
if (@($rows | Where-Object Result -ne 'ok').Count) { exit 1 }
