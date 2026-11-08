# Shared MSVC build settings for corpus/build-fixtures.ps1 and corpus/build-projects.ps1. Dot-source it.
#
# Every build uses:
#   /INCREMENTAL:NO  incremental linking routes calls through jump thunks, which would confuse matching
#   /Z7 + /Brepro    byte-identical .obj files and identical code layout across runs. The .exe still differs in
#                    the PE timestamp and PDB signature (linker-generated), so its SHA-256 changes per build.
#   /DEBUG:FULL      a self-contained PDB
#   /MAP             linker map file, the source of the answer key
#
# Flag sets: /O2 with and without identical-COMDAT folding, /Od, /O2 with whole-program optimization (/GL + /LTCG:
# cross-object inlining and layout), and /O2 with profile-guided optimization (`Pgo`: built instrumented, run on
# the recipe's `Train` workload, then relinked with the profile; hot/cold splitting and profile-driven inlining).
# PGO needs a training workload, so only the real-world projects build it (build-projects.ps1).

$MsvcCommon = @{
    cl   = @('/nologo', '/MD', '/Z7', '/Brepro')
    link = @('/nologo', '/DEBUG:FULL', '/MAP', '/INCREMENTAL:NO', '/Brepro', '/OPT:REF')
}

$MsvcFlagSets = [ordered]@{
    'o2'     = @{ cl = @('/O2'); link = @('/OPT:NOICF') }
    'o2-icf' = @{ cl = @('/O2'); link = @('/OPT:ICF') }
    'od'     = @{ cl = @('/Od'); link = @('/OPT:NOICF') }
    'o2-ltcg' = @{ cl = @('/O2', '/GL'); link = @('/LTCG', '/OPT:NOICF') }
    'o2-pgo'  = @{ cl = @('/O2', '/GL'); link = @('/LTCG', '/OPT:NOICF'); Pgo = $true }
}

# Flag sets that build without a training workload.
function Get-PlainMsvcFlagSetNames { @($MsvcFlagSets.Keys | Where-Object { -not $MsvcFlagSets[$_].Pgo }) }

function Get-MsvcFlagSet([string] $name) {
    if (-not $MsvcFlagSets.Contains($name)) {
        throw "Unknown flag set '$name'. Known: $($MsvcFlagSets.Keys -join ', ')"
    }
    $MsvcFlagSets[$name]
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
