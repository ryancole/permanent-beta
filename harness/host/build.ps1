<#
.SYNOPSIS
  Builds the pbeta hook host: pbeta-host.dll, pbeta-launch.exe and the handler header, into target/host.

.DESCRIPTION
  Uses Microsoft Detours (MIT) built in target/hooks-src/Detours. If it isn't there, clones it at the same pinned
  commit as corpus/build-hooks.ps1 and builds its x64 library with nmake (needs git and the MSVC x64 toolset).

  Output (target/host):
    pbeta-host.dll, pbeta-launch.exe     the host and its launcher (keep them in the same folder)
    include/pbeta_handler.h              for handler DLLs
    lib/detours.lib, include/detours.h   not needed by handlers; there for anyone extending the host
#>
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$here = $PSScriptRoot
$detoursDir = Join-Path $repo 'target/hooks-src/Detours'
# microsoft/Detours main as of 2026-11-06 (v4.0.1 plus later fixes); the same commit as corpus/build-hooks.ps1.
$detoursRepo = 'https://github.com/microsoft/Detours'
$detoursCommit = '1dbd4ea281d73d478aa8d09a8b83fbd265f715f7'
$out = Join-Path $repo 'target/host'

function Invoke-Native([string] $exe, [string[]] $arguments) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "$exe failed with exit code $LASTEXITCODE" }
}

if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    if (-not (Test-Path $vswhere)) { throw 'vswhere.exe not found; install Visual Studio with the C++ toolset.' }
    $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw 'No Visual Studio installation with the x64 C++ toolset was found.' }
    $env:PATH = "$(Split-Path $vswhere);$env:PATH"
    cmd /c "`"$(Join-Path $vs 'VC/Auxiliary/Build/vcvars64.bat')`" >nul && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "env:$($Matches[1])" -Value $Matches[2] }
    }
}

$lib = Join-Path $detoursDir 'lib.X64/detours.lib'
if (-not (Test-Path $lib)) {
    if (-not (Test-Path (Join-Path $detoursDir '.git'))) {
        Write-Host "cloning Detours $detoursCommit"
        New-Item -ItemType Directory -Force $detoursDir | Out-Null
        Invoke-Native 'git' @('-C', $detoursDir, 'init', '--quiet')
        Invoke-Native 'git' @('-C', $detoursDir, 'fetch', '--quiet', '--depth', '1', $detoursRepo, $detoursCommit)
        Invoke-Native 'git' @('-C', $detoursDir, '-c', 'advice.detachedHead=false', 'checkout', '--quiet', 'FETCH_HEAD')
    }
    Write-Host 'building Detours (x64)'
    Push-Location (Join-Path $detoursDir 'src')
    try {
        $env:DETOURS_TARGET_PROCESSOR = 'X64'
        Invoke-Native 'nmake.exe' @('/nologo')
    } finally {
        Pop-Location
    }
    if (-not (Test-Path $lib)) { throw "Detours build produced no $lib" }
}

$obj = Join-Path $out 'obj'
New-Item -ItemType Directory -Force $out, $obj, (Join-Path $out 'include'), (Join-Path $out 'lib') | Out-Null
$inc = "/I$(Join-Path $detoursDir 'include')"
$cl = @('/nologo', '/MT', '/O2', '/EHsc', '/W4', '/WX', '/std:c++17', '/Zi', '/D_CRT_SECURE_NO_WARNINGS', $inc)

Write-Host 'building pbeta-host.dll and pbeta-launch.exe'
Invoke-Native 'ml64.exe' @('/nologo', '/c', '/W3', '/WX', '/Zi', "/Fo$obj\host_thunk.obj", (Join-Path $here 'host_thunk.asm'))
Invoke-Native 'cl.exe' ($cl + @('/LD', (Join-Path $here 'pbeta_host.cpp'), "$obj\host_thunk.obj", "/Fo$obj\",
        "/Fd$obj\pbeta-host-cl.pdb", "/Fe$out\pbeta-host.dll", '/link', $lib, "/PDB:$out\pbeta-host.pdb",
        "/IMPLIB:$obj\pbeta-host.lib"))
Invoke-Native 'cl.exe' ($cl + @((Join-Path $here 'pbeta_launch.cpp'), "/Fo$obj\", "/Fd$obj\pbeta-launch-cl.pdb",
        "/Fe$out\pbeta-launch.exe", '/link', $lib, "/PDB:$out\pbeta-launch.pdb"))

Copy-Item (Join-Path $here 'include/pbeta_handler.h') (Join-Path $out 'include') -Force
Copy-Item (Join-Path $detoursDir 'include/detours.h'), (Join-Path $detoursDir 'include/detver.h') (Join-Path $out 'include') -Force
Copy-Item $lib (Join-Path $out 'lib') -Force
Write-Host "built $out"
