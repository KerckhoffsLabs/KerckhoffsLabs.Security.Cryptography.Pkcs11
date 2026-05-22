# Builds SoftHSMv2 (OpenSSL backend) from the vendor/softhsmv2 submodule on Windows via
# CMake + vcpkg, and copies the shared library (as libsofthsm2.dll, matching the name the
# test fixture looks for) and softhsm2-util.exe into the test output directory under
# runtimes/win-x64/native (or win-arm64/native). Windows counterpart of build-softhsmv2.sh.
#
# Usage: pwsh build-softhsmv2.ps1 -TestOutputDir <path> [-VcpkgRoot <path>]
#
# Requires: Visual Studio C++ build tools, CMake, and vcpkg (for OpenSSL). On the GitHub
# windows-latest runner these are preinstalled and VcpkgRoot defaults to
# $env:VCPKG_INSTALLATION_ROOT. See vendor/softhsmv2/CMAKE-WIN-NOTES.md.
#
# Mirrors build-softhsmv2.sh in option set (ECC/EDDSA on, p11-kit and non-paged-memory off),
# output layout, idempotency, and the ML-DSA marker. It stays on CMake+vcpkg rather than
# autotools because that is the practical Windows toolchain; consequently it cannot produce an
# ML-DSA-capable token (the CMake ENABLE_MLDSA option is a no-op — only the autotools path used
# by the .sh wires ML-DSA), so the marker stays absent and ML-DSA tests self-skip on Windows.
#
# Idempotent: skips rebuild when outputs are newer than the submodule HEAD.

param(
    [Parameter(Mandatory=$true)]
    [string]$TestOutputDir,

    [string]$VcpkgRoot = $env:VCPKG_INSTALLATION_ROOT
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$srcDir   = Join-Path $repoRoot 'vendor\softhsmv2'

if (-not (Test-Path $srcDir)) {
    Write-Error "softhsmv2 submodule missing at $srcDir. Run: git submodule update --init --recursive"
}
if (-not $VcpkgRoot -or -not (Test-Path $VcpkgRoot)) {
    Write-Error "vcpkg not found. Pass -VcpkgRoot or set VCPKG_INSTALLATION_ROOT (needed for the OpenSSL dependency)."
}

$arch    = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
$rid     = if ($arch -eq [System.Runtime.InteropServices.Architecture]::Arm64) { 'win-arm64' } else { 'win-x64' }
$triplet = if ($rid -eq 'win-arm64') { 'arm64-windows' } else { 'x64-windows' }
$cmakeA  = if ($rid -eq 'win-arm64') { 'ARM64' } else { 'x64' }

$destDir  = Join-Path $TestOutputDir "runtimes\$rid\native"
$destLib  = Join-Path $destDir 'libsofthsm2.dll'
$destUtil = Join-Path $destDir 'softhsm2-util.exe'
New-Item -ItemType Directory -Force -Path $destDir | Out-Null

# Skip rebuild if both primary outputs are newer than the submodule HEAD commit.
$headTs = [int](& git -C $srcDir log -1 --format=%ct HEAD).Trim()
function Test-NewerThanHead([string]$path) {
    if (-not (Test-Path $path)) { return $false }
    $epoch = [datetime]'1970-01-01T00:00:00Z'
    $ts = [int][double]::Parse(((Get-Item $path).LastWriteTimeUtc - $epoch).TotalSeconds)
    return $ts -gt $headTs
}
if ((Test-NewerThanHead $destLib) -and (Test-NewerThanHead $destUtil)) {
    Write-Host "softhsmv2 up to date at $destDir"
    return
}

Write-Host "Building SoftHSMv2 for $rid (OpenSSL via vcpkg)..."

# OpenSSL dependency through vcpkg, matched to the CMake toolchain below.
$vcpkgExe = Join-Path $VcpkgRoot 'vcpkg.exe'
& $vcpkgExe install "openssl:$triplet" | Write-Host
if ($LASTEXITCODE -ne 0) { Write-Error "vcpkg install openssl:$triplet failed ($LASTEXITCODE)" }

$buildDir  = Join-Path $srcDir '_cmake_build_win'
$toolchain = Join-Path $VcpkgRoot 'scripts\buildsystems\vcpkg.cmake'
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

# Multi-config VS generator (default on windows-latest); --config Release selects the config.
cmake -S $srcDir -B $buildDir `
    -A $cmakeA `
    "-DCMAKE_TOOLCHAIN_FILE=$toolchain" `
    "-DVCPKG_TARGET_TRIPLET=$triplet" `
    -DBUILD_TESTS=OFF `
    -DWITH_CRYPTO_BACKEND=openssl `
    -DWITH_OBJECTSTORE_BACKEND_DB=OFF `
    -DENABLE_ECC=ON `
    -DENABLE_EDDSA=ON `
    -DENABLE_P11_KIT=OFF `
    -DDISABLE_NON_PAGED_MEMORY=ON `
    -Wno-dev | Write-Host
if ($LASTEXITCODE -ne 0) { Write-Error "cmake configure failed ($LASTEXITCODE)" }

cmake --build $buildDir --config Release --parallel | Write-Host
if ($LASTEXITCODE -ne 0) { Write-Error "cmake build failed ($LASTEXITCODE)" }

# Locate outputs (target name is 'softhsm2' -> softhsm2.dll on MSVC; exclude the static lib).
$srcLib = Get-ChildItem -Path $buildDir -Recurse -Filter '*softhsm2*.dll' |
          Where-Object { $_.Name -notmatch 'static' } | Select-Object -First 1
$srcUtil = Get-ChildItem -Path $buildDir -Recurse -Filter 'softhsm2-util.exe' | Select-Object -First 1

if (-not $srcLib) {
    $produced = (Get-ChildItem -Path $buildDir -Recurse -Filter '*.dll' | Select-Object -ExpandProperty FullName) -join "`n"
    Write-Error "build succeeded but no softhsm2 DLL found under $buildDir.`nProduced:`n$produced"
}
if (-not $srcUtil) { Write-Error "build succeeded but softhsm2-util.exe not found under $buildDir" }

Copy-Item $srcLib.FullName  $destLib  -Force
Copy-Item $srcUtil.FullName $destUtil -Force

# libsofthsm2.dll and softhsm2-util.exe depend on the vcpkg OpenSSL runtime DLLs
# (libcrypto-*.dll); place them next to the library so LoadLibrary/the util resolve them.
$vcpkgBin = Join-Path $VcpkgRoot "installed\$triplet\bin"
if (Test-Path $vcpkgBin) {
    Get-ChildItem -Path $vcpkgBin -Filter 'libcrypto*.dll' | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $destDir $_.Name) -Force
    }
    Get-ChildItem -Path $vcpkgBin -Filter 'libssl*.dll' | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $destDir $_.Name) -Force
    }
}

Write-Host "Installed $destLib"
Write-Host "Installed $destUtil"

# Mirror build-softhsmv2.sh: record whether ML-DSA was compiled in, so the test suite can gate
# its ML-DSA cases on a cheap file check. ML-DSA only compiles in when WITH_ML_DSA is defined,
# which requires OpenSSL 3.5+ AND the autotools build (the CMake ENABLE_MLDSA option is a no-op
# that never sets WITH_ML_DSA). This Windows CMake build therefore never produces an ML-DSA-capable
# token, so the marker stays absent and the ML-DSA tests self-skip — but we honour config.h so the
# gate stays correct if the CMake build ever wires ML-DSA up.
$destMarker = Join-Path $destDir 'softhsm-mldsa.enabled'
$configH = Join-Path $buildDir 'config.h'
if ((Test-Path $configH) -and (Select-String -Path $configH -Pattern '^#define WITH_ML_DSA' -Quiet)) {
    New-Item -ItemType File -Force -Path $destMarker | Out-Null
    Write-Host "ML-DSA: enabled (marker written)"
} else {
    Remove-Item -Force -ErrorAction SilentlyContinue -Path $destMarker
    Write-Host "ML-DSA: not available in this build"
}
