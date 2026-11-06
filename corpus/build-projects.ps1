<#
.SYNOPSIS
  Builds real-world open-source projects across release tags with MSVC and generates answer keys.

.DESCRIPTION
  For each project under corpus/projects/<name>/ (a recipe.psd1, and optionally expected.toml):
    1. Shallow-clones each release tag into target/corpus-src/<name>/<tag>/ (skipped if already present) and
       records the exact commit in target/corpus-src/<name>/sources.json.
    2. Builds each tag under each flag set into target/corpus/<name>/builds/<flags>/<tag>/ (.exe, .pdb, .map).
    3. For each consecutive pair of tags, creates target/corpus/<name>/<flags>__<old>__<new>/ with v1/ and v2/
       copies and truth.json (functions from the project's own object files, joined by name).
  With -Score, runs `pbeta-corpus score` against the project's expected.toml.

  Needs git and network access the first time (to clone), Visual Studio with the x64 C++ toolset, and cargo.

.EXAMPLE
  pwsh corpus/build-projects.ps1
  pwsh corpus/build-projects.ps1 -Project zlib -Flags o2 -Score
#>
[CmdletBinding()]
param(
    [string[]] $Project,
    [string[]] $Flags,
    [switch] $Score
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib/msvc.ps1')
$repo = Split-Path -Parent $PSScriptRoot
$projectsDir = Join-Path $PSScriptRoot 'projects'
$srcRoot = Join-Path $repo 'target/corpus-src'
$outRoot = Join-Path $repo 'target/corpus'

function Get-Sources($recipe) {
    $base = Join-Path $srcRoot $recipe.Name
    $provenance = [ordered]@{ repo = $recipe.Repo; license = $recipe.License; tags = [ordered]@{} }
    foreach ($tag in $recipe.Versions) {
        $dir = Join-Path $base $tag
        if (-not (Test-Path (Join-Path $dir '.git'))) {
            Write-Host "cloning $($recipe.Name) $tag"
            Invoke-Native 'git' @('-c', 'advice.detachedHead=false', 'clone', '--quiet', '--depth', '1',
                '--branch', $tag, $recipe.Repo, $dir)
        }
        $provenance.tags[$tag] = (git -C $dir rev-parse HEAD).Trim()
    }
    $provenance | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $base 'sources.json')
}

function Build-Version($recipe, [string] $tag, [string] $flagName) {
    $set = Get-MsvcFlagSet $flagName
    $src = Join-Path $srcRoot "$($recipe.Name)/$tag"
    $out = Join-Path $outRoot "$($recipe.Name)/builds/$flagName/$tag"
    New-Item -ItemType Directory -Force $out | Out-Null
    Write-Host "building $($recipe.Name) $tag [$flagName]"

    $defines = @($recipe.Defines | ForEach-Object { "/D$_" })
    $sources = @($recipe.Sources | ForEach-Object { Join-Path $src $_ })
    # Trailing backslash: /Fo names each object after its source file inside that directory.
    Invoke-Native 'cl.exe' (@($MsvcCommon.cl) + @($recipe.Cl) + @($set.cl) + $defines + @("/I$src", '/c') +
        $sources + @("/Fo$out\"))
    $objs = @($recipe.Sources | ForEach-Object { Join-Path $out ([IO.Path]::GetFileNameWithoutExtension($_) + '.obj') })
    $exe = $recipe.Exe
    Invoke-Native 'link.exe' (@($MsvcCommon.link) + @($set.link) + $objs + @(
            "/OUT:$out\$exe.exe", "/PDB:$out\$exe.pdb", "/MAP:$out\$exe.map"))
}

Import-VsDevEnvironment

$projectNames = if ($Project) { $Project } else { Get-ChildItem $projectsDir -Directory | ForEach-Object Name }
$flagNames = if ($Flags) { $Flags } else { $MsvcFlagSets.Keys }

foreach ($name in $projectNames) {
    $recipe = Import-PowerShellDataFile (Join-Path $projectsDir "$name/recipe.psd1")
    Get-Sources $recipe
    $exe = $recipe.Exe

    foreach ($flagName in $flagNames) {
        foreach ($tag in $recipe.Versions) { Build-Version $recipe $tag $flagName }

        for ($i = 0; $i -lt $recipe.Versions.Count - 1; $i++) {
            $old, $new = $recipe.Versions[$i], $recipe.Versions[$i + 1]
            $variant = Join-Path $outRoot "$name/$flagName`__$old`__$new"
            foreach ($pair in @(@('v1', $old), @('v2', $new))) {
                $dest = Join-Path $variant $pair[0]
                New-Item -ItemType Directory -Force $dest | Out-Null
                $from = Join-Path $outRoot "$name/builds/$flagName/$($pair[1])"
                Copy-Item "$from\$exe.exe", "$from\$exe.map" $dest -Force
            }
            Invoke-Native 'cargo' @('run', '-q', '-p', 'permanent-beta-corpus', '--', 'truth',
                '--old', "$variant\v1\$exe.map", '--new', "$variant\v2\$exe.map", '--out', "$variant\truth.json")
            Write-Host "wrote $variant\truth.json"
        }
    }

    $expected = Join-Path $projectsDir "$name/expected.toml"
    if ($Score -and (Test-Path $expected)) {
        Invoke-Native 'cargo' @('run', '-q', '-p', 'permanent-beta-corpus', '--', 'score',
            '--built', (Join-Path $outRoot $name), '--expected', $expected)
    }
}
