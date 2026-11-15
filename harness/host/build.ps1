<#
.SYNOPSIS
  Builds the pbeta hook host: pbeta-host.dll, pbeta-launch.exe and the handler header, into target/host (x64) or,
  with -Arch x86, target/host-x86 (for 32-bit programs).

.DESCRIPTION
  Uses Microsoft Detours (MIT) built in target/hooks-src/Detours. If it isn't there, clones it at the same pinned
  commit as corpus/build-hooks.ps1 and builds its x64 library with nmake (needs git and the MSVC x64 toolset).

  Output (target/host):
    pbeta-host.dll, pbeta-launch.exe     the host and its launcher (keep them in the same folder)
    include/pbeta_handler.h              for handler DLLs
    lib/detours.lib, include/detours.h   not needed by handlers; there for anyone extending the host
#>
param(
    [ValidateSet('x64', 'x86')] [string] $Arch = 'x64'
)
$ErrorActionPreference = 'Stop'
$x86 = $Arch -eq 'x86'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$here = $PSScriptRoot
$detoursDir = Join-Path $repo 'target/hooks-src/Detours'
# microsoft/Detours main as of 2026-11-06 (v4.0.1 plus later fixes); the same commit as corpus/build-hooks.ps1.
$detoursRepo = 'https://github.com/microsoft/Detours'
$detoursCommit = '1dbd4ea281d73d478aa8d09a8b83fbd265f715f7'
$out = Join-Path $repo $(if ($x86) { 'target/host-x86' } else { 'target/host' })

function Invoke-Native([string] $exe, [string[]] $arguments) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "$exe failed with exit code $LASTEXITCODE" }
}

# The compiler environment for this architecture (vcvars sets VSCMD_ARG_TGT_ARCH), unless it's already set up.
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue) -or ($env:VSCMD_ARG_TGT_ARCH -and $env:VSCMD_ARG_TGT_ARCH -ne $Arch)) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    if (-not (Test-Path $vswhere)) { throw 'vswhere.exe not found; install Visual Studio with the C++ toolset.' }
    $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw 'No Visual Studio installation with the x64 C++ toolset was found.' }
    $env:PATH = "$(Split-Path $vswhere);$env:PATH"
    $vcvars = if ($x86) { 'vcvars32.bat' } else { 'vcvars64.bat' }
    cmd /c "`"$(Join-Path $vs "VC/Auxiliary/Build/$vcvars")`" >nul && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "env:$($Matches[1])" -Value $Matches[2] }
    }
}

$detoursArch = if ($x86) { 'X86' } else { 'X64' }
$lib = Join-Path $detoursDir "lib.$detoursArch/detours.lib"
if (-not (Test-Path $lib)) {
    if (-not (Test-Path (Join-Path $detoursDir '.git'))) {
        Write-Host "cloning Detours $detoursCommit"
        New-Item -ItemType Directory -Force $detoursDir | Out-Null
        Invoke-Native 'git' @('-C', $detoursDir, 'init', '--quiet')
        Invoke-Native 'git' @('-C', $detoursDir, 'fetch', '--quiet', '--depth', '1', $detoursRepo, $detoursCommit)
        Invoke-Native 'git' @('-C', $detoursDir, '-c', 'advice.detachedHead=false', 'checkout', '--quiet', 'FETCH_HEAD')
    }
    Write-Host "building Detours ($Arch)"
    Push-Location (Join-Path $detoursDir 'src')
    try {
        $env:DETOURS_TARGET_PROCESSOR = $detoursArch
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
if ($x86) {
    # /safeseh: the thunk registers no exception handlers, so the DLL can keep /SAFESEH.
    Invoke-Native 'ml.exe' @('/nologo', '/c', '/W3', '/WX', '/Zi', '/safeseh', "/Fo$obj\host_thunk.obj",
        (Join-Path $here 'host_thunk32.asm'))
} else {
    Invoke-Native 'ml64.exe' @('/nologo', '/c', '/W3', '/WX', '/Zi', "/Fo$obj\host_thunk.obj", (Join-Path $here 'host_thunk.asm'))
}
Invoke-Native 'cl.exe' ($cl + @('/LD', (Join-Path $here 'pbeta_host.cpp'), "$obj\host_thunk.obj", "/Fo$obj\",
        "/Fd$obj\pbeta-host-cl.pdb", "/Fe$out\pbeta-host.dll", '/link', $lib, "/PDB:$out\pbeta-host.pdb",
        "/IMPLIB:$obj\pbeta-host.lib"))
Invoke-Native 'cl.exe' ($cl + @((Join-Path $here 'pbeta_launch.cpp'), "/Fo$obj\", "/Fd$obj\pbeta-launch-cl.pdb",
        "/Fe$out\pbeta-launch.exe", '/link', $lib, "/PDB:$out\pbeta-launch.pdb"))

Copy-Item (Join-Path $here 'include/pbeta_handler.h') (Join-Path $out 'include') -Force
Copy-Item (Join-Path $detoursDir 'include/detours.h'), (Join-Path $detoursDir 'include/detver.h') (Join-Path $out 'include') -Force
Copy-Item $lib (Join-Path $out 'lib') -Force
Write-Host "built $out"
