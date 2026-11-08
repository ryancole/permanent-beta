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
    $includes = @("/I$src") + @($recipe.Include | Where-Object { $_ } | ForEach-Object { "/I$(Join-Path $src $_)" })
    # Sources may use wildcards (e.g. 'lib/compress/*.c'), resolved per tag because files come and go between
    # releases. Each pattern must match something.
    $sources = @(foreach ($pattern in $recipe.Sources) {
            $path = Join-Path $src $pattern
            if ($pattern -match '[*?]') {
                $found = @(Get-ChildItem $path -File | Sort-Object Name | ForEach-Object FullName)
                if ($found.Count -eq 0) { throw "$($recipe.Name) ${tag}: '$pattern' matches no files" }
                $found
            } else { $path }
        })
    # /Fo names each object after its source file in one directory, so base names must be unique.
    $dupes = @($sources | Group-Object { [IO.Path]::GetFileNameWithoutExtension($_) } | Where-Object Count -gt 1)
    if ($dupes) { throw "$($recipe.Name) ${tag}: duplicate source base names: $($dupes.Name -join ', ')" }
    # `PgoCl`: extra compiler options for PGO builds only, e.g. to make the training run deterministic (`{recipe}`
    # expands to the recipe's directory).
    $pgoCl = @()
    if ($set.Pgo -and $recipe.PgoCl) {
        $recipeDir = Join-Path $projectsDir $recipe.Name
        $pgoCl = @($recipe.PgoCl | ForEach-Object { $_.Replace('{recipe}', $recipeDir) })
    }
    # Trailing backslash: /Fo names each object after its source file inside that directory.
    Invoke-Native 'cl.exe' (@($MsvcCommon.cl) + @($recipe.Cl) + @($set.cl) + $pgoCl + $defines + $includes +
        @('/c') + $sources + @("/Fo$out\"))
    $objs = @($sources | ForEach-Object { Join-Path $out ([IO.Path]::GetFileNameWithoutExtension($_) + '.obj') })
    $exe = $recipe.Exe
    $link = @($MsvcCommon.link) + @($set.link) + $objs + @("/OUT:$out\$exe.exe", "/PDB:$out\$exe.pdb", "/MAP:$out\$exe.map")
    if (-not $set.Pgo) {
        Invoke-Native 'link.exe' $link
        return
    }
    # Profile-guided: link instrumented, train, relink with the profile (the linker merges the .pgc files the
    # training run left next to the .pgd).
    $pgd = "$out\$exe.pgd"
    Remove-Item "$out\$exe*.pgc", $pgd -ErrorAction SilentlyContinue
    Invoke-Native 'link.exe' ($link + @("/GENPROFILE:PGD=$pgd"))
    Invoke-Training $recipe $src $out
    if (-not (Get-ChildItem "$out\$exe!*.pgc" -ErrorAction SilentlyContinue)) {
        throw "$($recipe.Name) ${tag}: the training run left no profile (.pgc)"
    }
    # The executable the training just ran can stay locked for a moment after it exits (seen once: LNK1104,
    # most likely an antivirus scan of the new binary). Retry that error only, a few times.
    for ($attempt = 1; ; $attempt++) {
        & link.exe @($link + @("/USEPROFILE:PGD=$pgd"))
        if ($LASTEXITCODE -eq 0) { break }
        if ($LASTEXITCODE -ne 1104 -or $attempt -ge 5) { throw "link.exe failed with exit code $LASTEXITCODE" }
        Write-Host "link.exe: $exe.exe is still locked (LNK1104); retrying in 2 s"
        Start-Sleep -Seconds 2
    }
}

# Run the recipe's `Train` workload against the instrumented build in $out. Each step: `Args` for the program
# (`{src}`, `{out}` and `{recipe}` expand to the source, build and recipe directories; no spaces, since arguments
# are passed unquoted), optional `Cwd` and `Stdout` (a file to write standard output to). Exit codes are ignored: a test driver may report failures, and the profile is still valid.
function Invoke-Training($recipe, [string] $src, [string] $out) {
    if (-not $recipe.Train) { throw "$($recipe.Name): the o2-pgo flag set needs a Train workload in recipe.psd1" }
    $recipeDir = Join-Path $projectsDir $recipe.Name
    $expand = { param($s) $s.Replace('{src}', $src).Replace('{out}', $out).Replace('{recipe}', $recipeDir) }
    foreach ($step in $recipe.Train) {
        $arguments = @($step.Args | ForEach-Object { & $expand $_ })
        $cwd = if ($step.Cwd) { & $expand $step.Cwd } else { $out }
        $options = @{
            FilePath = "$out\$($recipe.Exe).exe"; WorkingDirectory = $cwd; NoNewWindow = $true; Wait = $true
            RedirectStandardError = "$out\train.err"
        }
        $options.RedirectStandardOutput = if ($step.Stdout) { & $expand $step.Stdout } else { "$out\train.out" }
        if ($arguments.Count) { $options.ArgumentList = $arguments }
        Start-Process @options
    }
}

Import-VsDevEnvironment

$projectNames = if ($Project) { $Project } else { Get-ChildItem $projectsDir -Directory | ForEach-Object Name }
$flagNames = if ($Flags) { $Flags } else { $MsvcFlagSets.Keys }

foreach ($name in $projectNames) {
    $recipe = Import-PowerShellDataFile (Join-Path $projectsDir "$name/recipe.psd1")
    Get-Sources $recipe
    $exe = $recipe.Exe

    foreach ($flagName in $flagNames) {
        # `SkipFlags` in a recipe: flag sets not scored for that project yet (each with its reason in the recipe).
        if ($recipe.SkipFlags -and $recipe.SkipFlags -contains $flagName) {
            Write-Host "skipping $name [$flagName]: listed in the recipe's SkipFlags"
            continue
        }
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
            # Renames declared for the newer tag (checked by hand against the sources).
            $renames = @()
            if ($recipe.Renames -and $recipe.Renames.ContainsKey($new)) {
                $table = $recipe.Renames[$new]
                $renames = @($table.Keys | Sort-Object | ForEach-Object { '--rename'; "$_=$($table[$_])" })
            }
            Invoke-Native 'cargo' (@('run', '-q', '-p', 'permanent-beta-corpus', '--', 'truth',
                    '--old', "$variant\v1\$exe.map", '--new', "$variant\v2\$exe.map", '--out', "$variant\truth.json") +
                $renames)
            Write-Host "wrote $variant\truth.json"
        }
    }

    $expected = Join-Path $projectsDir "$name/expected.toml"
    if ($Score -and (Test-Path $expected)) {
        Invoke-Native 'cargo' @('run', '-q', '-p', 'permanent-beta-corpus', '--', 'score',
            '--built', (Join-Path $outRoot $name), '--expected', $expected)
    }
}
