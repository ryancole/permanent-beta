<#
.SYNOPSIS
  End-to-end test of the hook host (harness/host): builds, repairs and runs a test app under the host, and checks
  both what the app computes and what the host logs. Takes about a minute. Exit code 0 if every check passes.

.DESCRIPTION
  1. Builds the host (build.ps1), pbeta (debug), the test app twice (test/hosttest.cpp; v2 with /DV2, so every
     function moves) and the handler DLL (test/hosttest_handlers.cpp).
  2. Writes a hook manifest for v1 from its analysis, binds it and repairs it to v2 with pbeta (every hook must
     resolve), so the v2 addresses come from pbeta, not from the test.
  3. For each scenario, sets the hooks' actions, runs `pbeta host-config` on both manifests and runs both builds
     under pbeta-launch. Checks the app's output (a corrupted register or stack argument gives a wrong number) and
     the host's log (decoded arguments and results).

  Scenarios: every hook logging (output identical to an unhooked run); `return` and `skip`; handlers that replace
  the original or call through; and negatives: a build the config doesn't list (no hooks), a pattern that doesn't
  match (that hook refused), a handler DLL without the export (refused).

  Output in target/host-test.
#>
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$out = Join-Path $repo 'target/host-test'
$host_ = Join-Path $repo 'target/host'
$failures = 0

function Invoke-Native([string] $exe, [string[]] $arguments) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "$exe failed with exit code $LASTEXITCODE" }
}

function Check([bool] $ok, [string] $what) {
    if ($ok) {
        Write-Host "  ok    $what"
    } else {
        Write-Host "  FAIL  $what" -ForegroundColor Red
        $script:failures++
    }
}

# --- build -------------------------------------------------------------------------------------------------

& (Join-Path $PSScriptRoot 'build.ps1') | Out-Null   # also puts cl.exe on PATH for this session
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    $env:PATH = "$(Split-Path $vswhere);$env:PATH"
    cmd /c "`"$(Join-Path $vs 'VC/Auxiliary/Build/vcvars64.bat')`" >nul && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "env:$($Matches[1])" -Value $Matches[2] }
    }
}
Push-Location $repo
try {
    Invoke-Native 'cargo' @('build', '--quiet', '-p', 'permanent-beta-cli')
} finally {
    Pop-Location
}
$pbeta = Join-Path $repo 'target/debug/pbeta.exe'
$launch = Join-Path $host_ 'pbeta-launch.exe'

if (Test-Path $out) { Remove-Item -Recurse -Force $out }
$work = Join-Path $out 'work'
New-Item -ItemType Directory -Force $out, $work | Out-Null
$src = Join-Path $PSScriptRoot 'test'
$cl = @('/nologo', '/MT', '/O2', '/W4', '/WX', '/EHsc', '/Zi', '/utf-8')
foreach ($v in 'v1', 'v2') {
    $dir = Join-Path $out $v
    New-Item -ItemType Directory -Force $dir | Out-Null
    $def = if ($v -eq 'v2') { @('/DV2') } else { @() }
    Invoke-Native 'cl.exe' ($cl + $def + @((Join-Path $src 'hosttest.cpp'), "/Fo$dir\", "/Fd$dir\hosttest-cl.pdb",
            "/Fe$dir\hosttest.exe", '/link', '/DEBUG:FULL', '/INCREMENTAL:NO', "/PDB:$dir\hosttest.pdb")) | Out-Null
}
Invoke-Native 'cl.exe' ($cl + @('/LD', "/I$host_\include", (Join-Path $src 'hosttest_handlers.cpp'), "/Fo$work\",
        "/Fd$work\handlers-cl.pdb", "/Fe$work\hosttest_handlers.dll", '/link', "/IMPLIB:$work\handlers.lib")) | Out-Null
$exe = @{ v1 = Join-Path $out 'v1/hosttest.exe'; v2 = Join-Path $out 'v2/hosttest.exe' }

# --- the hooks, located by pbeta -------------------------------------------------------------------------------

$prototypes = [ordered]@{
    add3        = 'int add3(int a, int b, int c)'
    sum12       = 'long long sum12(long long a1, long long a2, long long a3, long long a4, long long a5, long long a6, long long a7, long long a8, long long a9, long long a10, long long a11, long long a12)'
    mix         = 'double mix(int a, double b, int c, float d)'
    scalef      = 'float scalef(float x, float y)'
    store       = 'void store(int* out, int v)'
    count_chars = 'size_t count_chars(const char* s, const wchar_t* w)'
    fib         = 'unsigned long long fib(unsigned n)'
}
foreach ($v in 'v1', 'v2') {
    Invoke-Native $pbeta @('analyze', $exe[$v], '--pdb', (Join-Path $out "$v/hosttest.pdb"), '--out', "$work\$v.json") | Out-Null
}
$functions = (Get-Content "$work\v1.json" -Raw | ConvertFrom-Json).functions
$manifest = foreach ($name in $prototypes.Keys) {
    $f = $functions | Where-Object { $_.name -eq $name }
    if (-not $f) { throw "no function $name in the v1 analysis" }
    "[[hook]]`nname = `"$name`"`ndetour = `"log`"`nprototype = `"$($prototypes[$name])`"`n`n[hook.target]`nbuild = `"v1`"`nrva = $($f.rva)`n"
}
Set-Content "$work\hooks.v1.toml" ($manifest -join "`n") -NoNewline
Invoke-Native $pbeta @('bind', '--hooks', "$work\hooks.v1.toml", '--binary', $exe.v1) | Out-Null
& $pbeta repair --old "$work\v1.json" --new "$work\v2.json" --hooks "$work\hooks.v1.toml" --new-binary $exe.v2 `
    --out "$work\hooks.v2.toml" | Out-Null
Write-Host 'repair v1 -> v2'
Check ($LASTEXITCODE -eq 0) 'every hook resolved'

# --- running -------------------------------------------------------------------------------------------------

# Manifests with these actions (hook name -> detour; the rest log), and the host config for them.
function New-Config([string] $name, [hashtable] $actions, [string[]] $builds = @('v1', 'v2')) {
    $hooks = @()
    foreach ($b in $builds) {
        $text = Get-Content "$work\hooks.$b.toml" -Raw
        foreach ($k in $actions.Keys) {
            $text = $text -replace "(name = `"$k`"\r?\n)detour = `"[^`"]*`"", "`$1detour = `"$($actions[$k])`""
        }
        $path = "$work\$name.$b.toml"
        Set-Content $path $text -NoNewline
        $hooks += @('--hooks', $path)
    }
    $config = "$work\$name.host.toml"
    Invoke-Native $pbeta (@('host-config') + $hooks + @('--out', $config)) | Out-Null
    $config
}

# Runs a build under the host: its output lines and the host's log lines.
function Invoke-Hosted([string] $config, [string] $build, [string] $tag) {
    $log = "$work\$tag.$build.log"
    $output = & $launch --log $log $config $exe[$build]
    $code = $LASTEXITCODE
    [pscustomobject]@{
        Output = @($output)
        Log    = if (Test-Path $log) { @(Get-Content $log -Encoding utf8) } else { @() }
        Code   = $code
    }
}

function Lines([string[]] $lines) { ($lines | Where-Object { $_ -notmatch '^banner ' }) -join "`n" }
function Has([string[]] $log, [string] $line) { $log -contains $line }
function Count([string[]] $log, [string] $prefix) { @($log | Where-Object { $_.StartsWith($prefix) }).Count }

$baseline = @(
    'add3 9', 'add3 0', 'sum12 650', 'mix 6.75', 'scalef 6', 'store 7', 'count_chars 10', 'fib 55', 'threads 2006000'
) -join "`n"

Write-Host 'unhooked'
foreach ($b in 'v1', 'v2') {
    $plain = & $exe[$b]
    Check ((Lines $plain) -eq $baseline) "$b prints the expected results"
}

Write-Host 'log: every hook logs, the original runs'
$config = New-Config 'log' @{}
foreach ($b in 'v1', 'v2') {
    $r = Invoke-Hosted $config $b 'log'
    Check ($r.Code -eq 0 -and (Lines $r.Output) -eq $baseline) "$b output unchanged"
    Check ((Count $r.Log '') -gt 0 -and @($r.Log | Where-Object { $_ -match ': attached at ' }).Count -eq 7) "$b all 7 hooks attached"
    Check (Has $r.Log 'add3(a=2, b=3, c=4) -> 9') "$b add3 arguments and result"
    Check (Has $r.Log 'add3(a=-1, b=-2, c=3) -> 0') "$b negative integers"
    Check (Has $r.Log 'sum12(a1=1, a2=2, a3=3, a4=4, a5=5, a6=6, a7=7, a8=8, a9=9, a10=10, a11=11, a12=12) -> 650') "$b eight stack arguments"
    Check (Has $r.Log 'mix(a=2, b=1.5, c=3, d=0.25) -> 6.75') "$b mixed integer and float slots, double result"
    Check (Has $r.Log 'scalef(x=1.5, y=4) -> 6') "$b float arguments and result"
    Check (@($r.Log | Where-Object { $_ -match '^store\(out=0x[0-9a-f]+, v=7\)$' }).Count -eq 1) "$b void result"
    Check (@($r.Log | Where-Object { $_ -match '^count_chars\(s=0x[0-9a-f]+ "hello", w=0x[0-9a-f]+ "wörld"\) -> 10$' }).Count -eq 1) "$b char and wchar_t strings"
    Check ((Count $r.Log 'fib(') -eq 177 -and (Has $r.Log 'fib(n=10) -> 55')) "$b recursion (177 calls)"
    Check ((Count $r.Log 'add3(') -eq 4002) "$b calls from 4 threads (4002 add3 lines)"
}

Write-Host 'return and skip: the original never runs'
$config = New-Config 'short' @{ add3 = 'return 42'; store = 'skip'; mix = 'skip' }
$expected = @('add3 42', 'add3 42', 'sum12 650', 'mix 0', 'scalef 6', 'store 0', 'count_chars 10', 'fib 55',
    'threads 168000') -join "`n"
foreach ($b in 'v1', 'v2') {
    $r = Invoke-Hosted $config $b 'short'
    Check ($r.Code -eq 0 -and (Lines $r.Output) -eq $expected) "$b output: add3 returns 42, store and mix skipped"
    Check (Has $r.Log 'add3(a=2, b=3, c=4) -> 42 (return 42: returned without calling it)') "$b return logged"
    Check (@($r.Log | Where-Object { $_ -match '^store\(out=0x[0-9a-f]+, v=7\) \(skip: returned without calling it\)$' }).Count -eq 1) "$b skip logged"
}

Write-Host 'handlers: one replaces the original, two call through'
$config = New-Config 'handlers' @{
    add3 = 'hosttest_handlers.dll!add3'; sum12 = 'hosttest_handlers.dll!sum12'; mix = 'hosttest_handlers.dll!mix'
}
$expected = @('add3 24', 'add3 6', 'sum12 651', 'mix 13.5', 'scalef 6', 'store 7', 'count_chars 10', 'fib 55',
    'threads 1998000') -join "`n"
foreach ($b in 'v1', 'v2') {
    $r = Invoke-Hosted $config $b 'handlers'
    Check ($r.Code -eq 0 -and (Lines $r.Output) -eq $expected) "$b output from the handlers"
    Check (@($r.Log | Where-Object { $_ -match '^(add3|sum12|mix): attached at .*, handled by hosttest_handlers\.dll!' }).Count -eq 3) "$b 3 handlers attached"
    Check (Has $r.Log 'handler: sum12 -> 650') "$b handler logs through the host"
}

Write-Host 'handler stubs: pbeta handler-stubs writes every handler, each calls through'
# Every hook handled by a generated stub. fib and count_chars lose their manifest prototype, so their stubs come
# from the PDB signatures (unsigned __int64, const wchar_t*). A stub with a wrong prototype corrupts a result.
$actions = @{}
foreach ($name in $prototypes.Keys) { $actions[$name] = "stubs.dll!$name" }
$config = New-Config 'stubs' $actions
foreach ($b in 'v1', 'v2') {
    $path = "$work\stubs.$b.toml"
    $text = Get-Content $path -Raw
    foreach ($name in 'fib', 'count_chars') {
        $text = $text -replace "(name = `"$name`"\r?\n(?:[a-z]+ = `"[^`"]*`"\r?\n)*?)prototype = `"[^`"]*`"\r?\n", '$1'
    }
    Set-Content $path $text -NoNewline
}
Check (-not ((Get-Content "$work\stubs.v1.toml" -Raw) -match 'prototype = "[^"]*fib\(')) 'fib has no manifest prototype'
Invoke-Native $pbeta @('handler-stubs', '--hooks', "$work\stubs.v1.toml", '--hooks', "$work\stubs.v2.toml",
    '--analysis', "$work\v1.json", '--analysis', "$work\v2.json", '--out', "$work\stubs.cpp") | Out-Null
$stubs = Get-Content "$work\stubs.cpp" -Raw
Check (([regex]::Matches($stubs, 'PBETA_HOOK\(')).Count -eq 7) '7 stubs generated'
Check ($stubs -match '// fib: PDB signature') 'fib stub from the PDB signature'
Invoke-Native 'cl.exe' ($cl + @('/LD', "/I$host_\include", "$work\stubs.cpp", "/Fo$work\", "/Fd$work\stubs-cl.pdb",
        "/Fe$work\stubs.dll", '/link', "/IMPLIB:$work\stubs.lib")) | Out-Null
foreach ($b in 'v1', 'v2') {
    $r = Invoke-Hosted $config $b 'stubs'
    Check ($r.Code -eq 0 -and (Lines $r.Output) -eq $baseline) "$b output unchanged through the stubs"
    Check (@($r.Log | Where-Object { $_ -match ', handled by stubs\.dll!' }).Count -eq 7) "$b 7 stubs attached"
}
& $pbeta handler-stubs --hooks "$work\stubs.v1.toml" --out "$work\stubs.cpp" 2>&1 | Out-Null
Check ($LASTEXITCODE -ne 0) 'negative: an existing handler file is not overwritten'

Write-Host 'negative: a build the config does not list'
$config = New-Config 'v2only' @{ add3 = 'return 42' } @('v2')
$r = Invoke-Hosted $config 'v1' 'v2only'
Check ($r.Code -eq 0 -and (Lines $r.Output) -eq $baseline) 'v1 runs unhooked'
Check (@($r.Log | Where-Object { $_ -match ', 0 hook\(s\) in the config for it$' }).Count -eq 1 -and
    -not ($r.Log | Where-Object { $_ -match ': attached at ' })) 'v1: no hooks attached'

Write-Host "negative: a pattern that doesn't match"
$config = New-Config 'pattern' @{ sum12 = 'return 42' } @('v2')
$text = Get-Content $config -Raw
$changed = $text -replace '(name = "sum12"\r?\nrva = "[^"]+"\r?\npattern = )"[^"]*"', '$1"CC CC CC CC CC CC CC CC"'
Check ($changed -ne $text) 'v2 config: sum12 has a pattern to break'
Set-Content $config $changed -NoNewline
$r = Invoke-Hosted $config 'v2' 'pattern'
Check ($r.Code -eq 0 -and (Lines $r.Output) -eq $baseline) 'v2 runs with sum12 unhooked'
Check (@($r.Log | Where-Object { $_ -match "^sum12: skipped \(the code at 0x[0-9a-f]+ doesn't match its pattern\)$" }).Count -eq 1) 'sum12 refused'

Write-Host 'negative: a handler DLL without the export'
$config = New-Config 'noexport' @{ add3 = 'hosttest_handlers.dll!nothere' }
foreach ($b in 'v1', 'v2') {
    $r = Invoke-Hosted $config $b 'noexport'
    Check ($r.Code -eq 0 -and (Lines $r.Output) -eq $baseline) "$b runs with add3 unhooked"
    Check (@($r.Log | Where-Object { $_ -match "^add3: skipped \(hosttest_handlers\.dll doesn't export nothere" }).Count -eq 1) "$b add3 refused"
}

Write-Host ''
if ($failures -eq 0) {
    Write-Host 'hook host: every check passed'
    exit 0
}
Write-Host "hook host: $failures check(s) failed (logs in $work)" -ForegroundColor Red
exit 1
