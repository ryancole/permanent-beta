# Toolchain for building with permanent-beta-replay's `emulator` feature (Unicorn; third_party/README.md). Dot-source
# it after corpus/lib/msvc.ps1 and call Use-EmulatorToolchain: it puts CMake and Ninja on PATH and sets
# LIBCLANG_PATH for bindgen, from the PATH, an LLVM install, or `python -m pip install --user cmake ninja libclang`.

function Use-EmulatorToolchain {
    Import-VsDevEnvironment
    $userScripts = Get-ChildItem "$env:APPDATA\Python\Python3*\Scripts" -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    foreach ($tool in 'cmake', 'ninja') {
        if (Get-Command $tool -ErrorAction SilentlyContinue) { continue }
        if ($userScripts -and (Test-Path (Join-Path $userScripts.FullName "$tool.exe"))) {
            $env:PATH = "$($userScripts.FullName);$env:PATH"
        } else {
            throw "$tool not found: install it (e.g. python -m pip install --user cmake ninja)"
        }
    }
    if (-not ($env:LIBCLANG_PATH -and (Test-Path (Join-Path $env:LIBCLANG_PATH 'libclang.dll')))) {
        $candidates = @("$env:ProgramFiles\LLVM\bin")
        if ($userScripts) { $candidates += Join-Path (Split-Path $userScripts.FullName) 'site-packages\clang\native' }
        $found = $candidates | Where-Object { Test-Path (Join-Path $_ 'libclang.dll') } | Select-Object -First 1
        if (-not $found) { throw 'libclang.dll not found: install LLVM, or python -m pip install --user libclang' }
        $env:LIBCLANG_PATH = $found
    }
}
