<#
.SYNOPSIS
  M4 hook-repair loop: builds the sample app (v1, v2, v3), Microsoft Detours, the hook DLL and its launcher, and
  with -Run repairs real Detours hooks v1 -> v2 -> v3 and checks them by running them.

.DESCRIPTION
  Build (always):
    1. Clones Microsoft Detours at a pinned commit into target/hooks-src/Detours (skipped if present) and builds
       its x64 library with nmake. Detours is MIT-licensed and never committed.
    2. Builds corpus/hooks/app/v{1,2,3}/app.cpp with the shared MSVC flags (corpus/lib/msvc.ps1) into
       target/hooks/<flags>/v{1,2,3}/ (app.exe, .pdb, .map), and hookdll.dll + launcher.exe into target/hooks/bin.

  Run (-Run), per flag set:
    3. `pbeta analyze` each version. Writes the v1 manifest from corpus/hooks/hooks.template.toml (symbols
       resolved through v1's map, bound to v1's build id).
    4. Runs v1 under the hooks and records its trace (the baseline). Every hook must attach and fire.
    5. For v1 -> v2 and v2 -> v3, from the previous manifest (hooks still bound to an older build are repaired
       from that build: --earlier):
       a. `pbeta repair --trial-out`: a trial manifest binds hooks whose only missing evidence is behavioral to
          their candidates. The new version runs under it (the trial run).
       b. `pbeta repair --old-trace ... --new-trace <trial run>` decides with that behavioral evidence and writes
          the repaired manifest, with AOB patterns regenerated from the new binary (--new-binary).
       c. Answer key (linker maps): a wrong relocation, or a pattern that doesn't find exactly its hook, fails.
       d. The new version runs under the repaired manifest; `pbeta trace-diff` compares each hook with the last
          run that applied it: a hook that doesn't fire, fires differently, crashes the app, or is applied
          although repair sent it to review fails.
       e. Every resolved hook must have a passing behavioral check; every prototype proposal must compile.
    6. `pbeta header` builds hooks.gen.h from the three manifests; it must compile as C and C++.
    7. Negative control: swaps two relocated hooks' RVAs in the v2 manifest and checks that both the answer key
       and the trace diff catch it.
  Fails on any wrong relocation, behavioral mismatch, or a missed negative control.

  Requires Visual Studio (or Build Tools) with the x64 C++ toolset, git (first run), and cargo.

.EXAMPLE
  pwsh corpus/build-hooks.ps1 -Run
  pwsh corpus/build-hooks.ps1 -Flags o2 -Run
#>
[CmdletBinding()]
param(
    [string[]] $Flags,
    [switch] $Run
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib/msvc.ps1')
$repo = Split-Path -Parent $PSScriptRoot
$hooksDir = Join-Path $PSScriptRoot 'hooks'
$outRoot = Join-Path $repo 'target/hooks'
$detoursDir = Join-Path $repo 'target/hooks-src/Detours'
$versions = 'v1', 'v2', 'v3'

# microsoft/Detours main as of 2026-11-06 (v4.0.1 plus later fixes).
$detoursRepo = 'https://github.com/microsoft/Detours'
$detoursCommit = '1dbd4ea281d73d478aa8d09a8b83fbd265f715f7'

function Build-Detours {
    if (-not (Test-Path (Join-Path $detoursDir '.git'))) {
        Write-Host "cloning Detours $detoursCommit"
        New-Item -ItemType Directory -Force $detoursDir | Out-Null
        Invoke-Native 'git' @('-C', $detoursDir, 'init', '--quiet')
        Invoke-Native 'git' @('-C', $detoursDir, 'fetch', '--quiet', '--depth', '1', $detoursRepo, $detoursCommit)
        Invoke-Native 'git' @('-C', $detoursDir, '-c', 'advice.detachedHead=false', 'checkout', '--quiet', 'FETCH_HEAD')
    }
    $lib = Join-Path $detoursDir 'lib.X64/detours.lib'
    if (-not (Test-Path $lib)) {
        Write-Host 'building Detours (x64)'
        Push-Location (Join-Path $detoursDir 'src')
        try {
            $env:DETOURS_TARGET_PROCESSOR = 'X64'
            Invoke-Native 'nmake' @('/nologo')
        } finally { Pop-Location }
    }
    if (-not (Test-Path $lib)) { throw "Detours build produced no $lib" }
}

function Build-Harness {
    $bin = Join-Path $outRoot 'bin'
    New-Item -ItemType Directory -Force $bin | Out-Null
    $inc = "/I$(Join-Path $detoursDir 'include')"
    $lib = Join-Path $detoursDir 'lib.X64/detours.lib'
    $cl = @('/nologo', '/MD', '/O2', '/EHsc', '/W4', '/WX', '/std:c++17', '/Zi', '/D_CRT_SECURE_NO_WARNINGS', $inc)
    Write-Host 'building hookdll.dll and launcher.exe'
    Invoke-Native 'cl.exe' ($cl + @('/LD', (Join-Path $hooksDir 'hookdll/hookdll.cpp'), "/Fo$bin\", "/Fd$bin\hookdll-cl.pdb",
            "/Fe$bin\hookdll.dll", '/link', $lib, "/PDB:$bin\hookdll.pdb"))
    Invoke-Native 'cl.exe' ($cl + @((Join-Path $hooksDir 'launcher/launcher.cpp'), "/Fo$bin\", "/Fd$bin\launcher-cl.pdb",
            "/Fe$bin\launcher.exe", '/link', $lib, "/PDB:$bin\launcher.pdb"))
}

function Build-App([string] $flagName) {
    $set = Get-MsvcFlagSet $flagName
    foreach ($version in $versions) {
        $out = Join-Path $outRoot "$flagName/$version"
        New-Item -ItemType Directory -Force $out | Out-Null
        Write-Host "building app $version [$flagName]"
        Invoke-Native 'cl.exe' (@($MsvcCommon.cl) + @('/EHsc', '/permissive-', '/W4') + @($set.cl) + @(
                '/c', (Join-Path $hooksDir "app/$version/app.cpp"), "/Fo$out\app.obj"))
        Invoke-Native 'link.exe' (@($MsvcCommon.link) + @($set.link) + @(
                "$out\app.obj", "/OUT:$out\app.exe", "/PDB:$out\app.pdb", "/MAP:$out\app.map"))
    }
}

# Runs `exe args`; returns its exit code, failing only on codes not in $ok.
function Invoke-Allowing([string] $exe, [string[]] $arguments, [int[]] $ok) {
    & $exe @arguments | Out-Host
    $code = $LASTEXITCODE
    if ($ok -notcontains $code) { throw "$exe failed with exit code $code" }
    $code
}

# Declarations a proposed shim needs to compile on its own: the existing detour (Hook_<name>) and the pointer
# it calls the original through (Real_<name>), both from the hook's prototype in the manifest.
function Get-ShimStub([string] $hook, [string] $dir, [string] $version) {
    $manifest = Get-Content "$dir\$version\hooks.toml" -Raw
    $m = [regex]::Match($manifest, "(?s)name = `"$hook`".*?prototype = `"([^`"]+)`"")
    if (-not $m.Success) { throw "no prototype for $hook in $dir\$version\hooks.toml" }
    $proto = $m.Groups[1].Value
    $p = [regex]::Match($proto, '^(.*?)\b(\w+)\((.*)\)$')
    $ret, $name, $params = $p.Groups[1].Value.Trim(), $p.Groups[2].Value, $p.Groups[3].Value
    "$ret Hook_$name($params);`n$ret (*Real_$name)($params) = nullptr;"
}

function Invoke-Loop([string] $flagName) {
    $dir = Join-Path $outRoot $flagName
    $bin = Join-Path $outRoot 'bin'
    $pbeta = Join-Path $repo 'target/debug/pbeta.exe'
    $corpus = Join-Path $repo 'target/debug/pbeta-corpus.exe'
    $expected = Join-Path $hooksDir 'expected.toml'
    # Hooks whose signature changes (log_event gains a parameter in v2): in review, they must come with a
    # prototype proposal.
    $proposalExpected = @('log_event')

    foreach ($version in $versions) {
        Invoke-Native $pbeta @('analyze', "$dir\$version\app.exe", '--out', "$dir\$version\analysis.json")
    }
    Invoke-Native $corpus @('hook-manifest', '--template', (Join-Path $hooksDir 'hooks.template.toml'),
        '--map', "$dir\v1\app.map", '--analysis', "$dir\v1\analysis.json", '--out', "$dir\v1\hooks.toml")

    # The launcher returns the app's exit code; trace-diff judges the run (a crash leaves no "end" event).
    $runApp = {
        param([string] $version, [string] $manifest, [string] $trace)
        & "$bin\launcher.exe" "$bin\hookdll.dll" $manifest $trace "$dir\$version\app.exe" | Out-Host
        $LASTEXITCODE
    }

    Write-Host "`n== [$flagName] v1 baseline"
    $code = & $runApp 'v1' "$dir\v1\hooks.toml" "$dir\v1\trace.jsonl"
    if ($code -ne 0) { throw "v1 exited with $code under the hooks" }
    Invoke-Native $pbeta @('trace-diff', '--baseline', "$dir\v1\trace.jsonl", '--hooks', "$dir\v1\hooks.toml")

    for ($i = 1; $i -lt $versions.Count; $i++) {
        $old, $new = $versions[$i - 1], $versions[$i]
        $step = "$old-$new"
        # Older builds, most recent first: hooks an earlier step sent to review are still bound to one of them.
        $older = @($versions[0..($i - 1)])
        [array]::Reverse($older)
        $earlier = @($older | Select-Object -Skip 1)
        $pair = @('--old', "$dir\$old\analysis.json", '--new', "$dir\$new\analysis.json", '--hooks', "$dir\$old\hooks.toml",
            '--new-binary', "$dir\$new\app.exe")
        foreach ($e in $earlier) { $pair += @('--earlier', "$dir\$e\analysis.json") }
        $oldTraces = @()
        foreach ($o in $older) { $oldTraces += @('--old-trace', "$dir\$o\trace.jsonl") }
        Write-Host "`n== [$flagName] $step"

        # a. Trial run: review candidates that only lack behavioral evidence run in place, in a test run.
        $null = Invoke-Allowing $pbeta (@('repair') + $pair + @('--trial-out', "$dir\$new\trial.toml")) @(0, 1)
        $code = & $runApp $new "$dir\$new\trial.toml" "$dir\$new\trial.jsonl"
        if ($code -ne 0) { Write-Host "$new exited with $code in the trial run" }

        # b. Decide with the behavioral evidence of the trial run.
        $decide = @('repair') + $pair + $oldTraces + @('--new-trace', "$dir\$new\trial.jsonl", '--out', "$dir\$new\hooks.toml")
        & $pbeta @decide --json | Set-Content "$dir\$new\repair.json"
        if ($LASTEXITCODE -notin 0, 1) { throw "pbeta repair failed with exit code $LASTEXITCODE" }
        $null = Invoke-Allowing $pbeta $decide @(0, 1)

        # c. Answer key.
        $keyArgs = @('hook-check', '--old-map', "$dir\$old\app.map", '--new-map', "$dir\$new\app.map",
            '--old-hooks', "$dir\$old\hooks.toml", '--new-hooks', "$dir\$new\hooks.toml",
            '--old-analysis', "$dir\$old\analysis.json", '--new-analysis', "$dir\$new\analysis.json",
            '--new-binary', "$dir\$new\app.exe", '--expected', $expected, '--flags', $flagName, '--step', $step)
        foreach ($e in $earlier) { $keyArgs += @('--earlier-map', "$dir\$e\app.map", '--earlier-analysis', "$dir\$e\analysis.json") }
        $truth = Invoke-Allowing $corpus $keyArgs @(0, 1)
        if ($truth -ne 0) { $script:failures += "$step answer-key check" }

        # d. Run under the repaired manifest and diff against the runs that applied each hook.
        $code = & $runApp $new "$dir\$new\hooks.toml" "$dir\$new\trace.jsonl"
        if ($code -ne 0) { Write-Host "$new exited with $code under the repaired hooks" }
        $diffArgs = @('trace-diff', '--new', "$dir\$new\trace.jsonl", '--hooks', "$dir\$new\hooks.toml",
            '--repair', "$dir\$new\repair.json")
        foreach ($o in $older) { $diffArgs += @('--old', "$dir\$o\trace.jsonl") }
        $diff = Invoke-Allowing $pbeta $diffArgs @(0, 1)
        if ($diff -ne 0 -or $code -ne 0) { $script:failures += "$step trace diff" }

        # e. Behavioral evidence and proposals.
        $repairJson = Get-Content "$dir\$new\repair.json" -Raw | ConvertFrom-Json
        foreach ($r in $repairJson.repairs) {
            $b = @($r.verification.checks | Where-Object check -eq 'behavioral')
            if ($r.action.action -ne 'needs_review' -and -not $r.reviewed_by -and $b.outcome -ne 'pass') {
                $script:failures += "$step $($r.hook): resolved without a passing behavioral check ($($b.detail))"
            }
            if ($b.outcome -eq 'fail') { $script:failures += "$step $($r.hook): behavioral check failed ($($b.detail))" }
            foreach ($p in @($r.proposals)) {
                if (-not $p) { continue }
                $shimCpp = "$dir\$new\shim-$($r.hook)-$($p.candidate).cpp"
                Set-Content $shimCpp ("#include <cstdint>`n" + (Get-ShimStub $r.hook $dir $old) + "`n" + $p.shim)
                & cl.exe /nologo /Zs /std:c++17 /W4 /WX /wd4505 $shimCpp | Out-Host
                if ($LASTEXITCODE -ne 0) { $script:failures += "$step $($r.hook): proposed shim doesn't compile ($shimCpp)" }
            }
        }
        foreach ($h in $proposalExpected) {
            $r = $repairJson.repairs | Where-Object hook -eq $h
            if ($r -and $r.action.action -eq 'needs_review' -and -not @($r.proposals | Where-Object { $_ }).Count) {
                $script:failures += "$step ${h}: in review without a prototype proposal"
            }
        }

        $diffJson = & $pbeta @diffArgs --json | ConvertFrom-Json
        $trialed = @((Get-Content "$dir\$new\trial.toml" -Raw | Select-String -Pattern '(?m)^trial = true' -AllMatches).Matches).Count
        foreach ($r in $repairJson.repairs) {
            $action = $r.action.action
            if ($action -eq 'needs_review') { $action = "review: $($r.action.reason)" }
            if ($r.from_build) { $action += ' (from v1)' }
            $h = $diffJson.hooks | Where-Object hook -eq $r.hook
            $script:summary += [pscustomobject]@{
                Flags = $flagName; Step = $step; Hook = $r.hook; Repair = $action; Behavior = $h.outcome
            }
        }
        Write-Host "[$flagName] $step trial bindings: $trialed"
    }

    # Offsets header from every manifest of the line; it must compile as C and as C++.
    $header = "$dir\hooks.gen.h"
    Invoke-Native $pbeta (@('header', '--out', $header) + @($versions | ForEach-Object { @('--hooks', "$dir\$_\hooks.toml") }))
    foreach ($lang in 'c', 'cpp') {
        $src = "$dir\header-check.$lang"
        Set-Content $src "#include `"hooks.gen.h`"`nint main(void) { return pbeta_find_build(`"`") == NULL ? 0 : 1; }"
        & cl.exe /nologo /Zs /W4 /WX /wd4505 "/I$dir" $src | Out-Host
        if ($LASTEXITCODE -ne 0) { $script:failures += "hooks.gen.h doesn't compile as $lang" }
    }

    # Negative control: a wrong relocation must be caught by the answer key and by the trace diff.
    Write-Host "`n== [$flagName] negative control: swap two relocated hooks in the v2 manifest"
    $swapped = "$dir\v2\hooks.swapped.toml"
    Invoke-Native $corpus @('hook-swap', '--hooks', "$dir\v2\hooks.toml", '--a', 'price_lookup', '--b', 'stock_level',
        '--out', $swapped)
    $truth = Invoke-Allowing $corpus @('hook-check', '--old-map', "$dir\v1\app.map", '--new-map', "$dir\v2\app.map",
        '--old-hooks', "$dir\v1\hooks.toml", '--new-hooks', $swapped,
        '--old-analysis', "$dir\v1\analysis.json", '--new-analysis', "$dir\v2\analysis.json") @(0, 1)
    if ($truth -ne 1) { $script:failures += 'negative control: answer key missed the swapped hooks' }
    $null = & $runApp 'v2' $swapped "$dir\v2\trace.swapped.jsonl"
    $diff = Invoke-Allowing $pbeta @('trace-diff', '--old', "$dir\v1\trace.jsonl", '--new', "$dir\v2\trace.swapped.jsonl",
        '--hooks', $swapped) @(0, 1)
    if ($diff -ne 1) { $script:failures += 'negative control: trace diff missed the swapped hooks' }
}

Import-VsDevEnvironment
Build-Detours
Build-Harness
$flagNames = if ($Flags) { $Flags } else { @('o2', 'od') }
foreach ($flagName in $flagNames) { Build-App $flagName }

if ($Run) {
    Invoke-Native 'cargo' @('build', '-q', '-p', 'permanent-beta-cli', '-p', 'permanent-beta-corpus')
    $script:failures = @()
    $script:summary = @()
    foreach ($flagName in $flagNames) {
        $before = $script:failures.Count
        Invoke-Loop $flagName
        for ($i = $before; $i -lt $script:failures.Count; $i++) { $script:failures[$i] = "[$flagName] $($script:failures[$i])" }
    }
    Write-Host "`nPer-hook results (Repair: pbeta repair's outcome; Behavior: trace diff against the previous version)"
    $script:summary | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    $failures = $script:failures
    if ($failures) {
        Write-Host "`nFAILED:"
        $failures | ForEach-Object { Write-Host "  $_" }
        exit 1
    }
    Write-Host "`nhook-repair loop passed for $($flagNames -join ', ')"
}
# Explicitly: the negative control's last native command exits 1 by design, and CI's pwsh wrapper would
# otherwise pass that $LASTEXITCODE on as the script's result.
exit 0
