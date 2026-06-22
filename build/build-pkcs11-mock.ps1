# Builds pkcs11-mock and copies the matching-architecture DLL into the Pkcs11.Tests
# output directory under runtimes/<rid>/native.
#
# Usage: pwsh build-pkcs11-mock.ps1 -TestOutputDir <path> [-Rid win-x64|win-x86|win-arm64]
#
# -Rid selects which architecture's mock to install. It MUST match the architecture the
# tests run as (the testhost), which is the .NET SDK's architecture — the build target
# passes $(NETCoreSdkPortableRuntimeIdentifier). The x86 test process cannot load an x64
# mock (BadImageFormat), so this must not be guessed from the (64-bit) pwsh host.
#
# pkcs11-mock is a single translation unit that exports its PKCS#11 entry points via
# CRYPTOKI_EXPORTS (__declspec(dllexport)). We drive the build ourselves rather than the
# upstream build.bat: build.bat only probes three hardcoded VS editions
# (Community/Professional/Enterprise) for vcvarsall.bat and returns exit 0 even when it
# fails to find them, so a runner image that ships only Build Tools (or installs VS at a
# vswhere-locatable path) silently produces no DLL. We locate vcvarsall via vswhere (with a
# hardcoded-edition fallback) and propagate the real exit code.

param(
    [Parameter(Mandatory=$true)]
    [string]$TestOutputDir,
    [string]$Rid = ''
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$mockDir  = Join-Path $repoRoot 'vendor\pkcs11-mock'

if (-not (Test-Path $mockDir)) {
    Write-Error "pkcs11-mock submodule missing at $mockDir. Run: git submodule update --init --recursive"
}

if ($Rid) {
    $rid = $Rid
} else {
    # Fallback only when no RID is passed: detect from the host architecture.
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    $rid = if ($arch -eq [System.Runtime.InteropServices.Architecture]::Arm64) { 'win-arm64' } else { 'win-x64' }
}
$destDir  = Join-Path $TestOutputDir "runtimes\$rid\native"
$destFile = Join-Path $destDir 'pkcs11-mock.dll'

New-Item -ItemType Directory -Force -Path $destDir | Out-Null

# Skip rebuild if dest is newer than mock submodule HEAD.
$mockHeadTs = [int](& git -C $mockDir log -1 --format=%ct HEAD).Trim()
if (Test-Path $destFile) {
    $epoch = [datetime]'1970-01-01T00:00:00Z'
    $destTs = [int][double]::Parse(((Get-Item $destFile).LastWriteTimeUtc - $epoch).TotalSeconds)
    if ($destTs -gt $mockHeadTs) {
        Write-Host "pkcs11-mock up to date at $destFile"
        return
    }
}

# Locate vcvarsall.bat: prefer vswhere (canonical, finds any edition/install path incl.
# Build Tools), and fall back to the well-known per-edition paths for older images.
function Find-VcVarsAll {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $installPath = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath 2>$null | Select-Object -First 1
        if ($installPath) {
            $cand = Join-Path $installPath 'VC\Auxiliary\Build\vcvarsall.bat'
            if (Test-Path $cand) { return $cand }
        }
    }
    foreach ($ed in 'Enterprise','Professional','Community','BuildTools') {
        $cand = "C:\Program Files\Microsoft Visual Studio\2022\$ed\VC\Auxiliary\Build\vcvarsall.bat"
        if (Test-Path $cand) { return $cand }
    }
    return $null
}

Write-Host "Building pkcs11-mock for $rid..."

$winBuildDir = Join-Path $mockDir 'build\windows'
$vcvars = Find-VcVarsAll
if (-not $vcvars) { Write-Error "vcvarsall.bat (VS 2022 with the C++ toolset) not found via vswhere or the standard install paths." }
Write-Host "Using vcvarsall: $vcvars"

if ($rid -eq 'win-arm64') {
    # Upstream build.bat / pkcs11-mock.sln only define Win32 + x64 platforms — there is no ARM64
    # configuration to drive via msbuild. Compile the single source directly with the native ARM64
    # toolchain. /MT statically links the CRT so the produced DLL has no vcruntime dependency to
    # resolve at load time (matching the /MT x86/x64 builds).
    $srcDir  = Join-Path $mockDir 'src'
    $srcFile = Join-Path $srcDir 'pkcs11-mock.c'
    $outDll  = Join-Path $winBuildDir 'pkcs11-mock-arm64.dll'

    Push-Location $winBuildDir
    try {
        $clArgs = "/nologo /W4 /O2 /MT /LD /D WIN32 /D NDEBUG /D _WINDOWS /D _USRDLL /D CRYPTOKI_EXPORTS /D _UNICODE /D UNICODE /I`"$srcDir`" `"$srcFile`" /Fe:`"$outDll`""
        $cmd = "call `"$vcvars`" arm64 && cl $clArgs"
        Write-Host "cl (arm64): $cmd"
        $result = cmd /c $cmd '2>&1'
        $result | Write-Host
        if ($LASTEXITCODE -ne 0) { Write-Error "arm64 cl build failed ($LASTEXITCODE)" }
    } finally {
        Pop-Location
    }
}
else {
    # x86 / x64: build the upstream solution with msbuild for just the target platform. The
    # GitHub Windows runners are x64 hosts, so use the amd64 host toolset (it cross-compiles
    # Win32 fine) and select the target via /p:Platform.
    $platform = if ($rid -eq 'win-x86') { 'Win32' } else { 'x64' }

    Push-Location $winBuildDir
    try {
        $msbuild = "msbuild pkcs11-mock.sln /nologo /v:minimal /p:Configuration=Release /p:Platform=$platform /target:Rebuild"
        $cmd = "call `"$vcvars`" amd64 && $msbuild"
        Write-Host "msbuild ($rid -> $platform): $msbuild"
        $result = cmd /c $cmd '2>&1'
        $result | Write-Host
        if ($LASTEXITCODE -ne 0) { Write-Error "msbuild ($rid) failed ($LASTEXITCODE)" }
    } finally {
        Pop-Location
    }
}

# Upstream produces pkcs11-mock-x64.dll, pkcs11-mock-x86.dll (and arm64 from the cl build above).
# Select the architecture that matches the target RID.
$archSuffix = switch ($rid) {
    'win-x86'   { 'x86' }
    'win-arm64' { 'arm64' }
    default     { 'x64' }
}
$srcLib = Get-ChildItem -Path $winBuildDir -Filter "pkcs11-mock-$archSuffix.dll" -Recurse |
          Select-Object -First 1

if (-not $srcLib) {
    # Fallback: list what was actually produced to aid debugging.
    $produced = Get-ChildItem -Path $winBuildDir -Filter '*.dll' -Recurse | Select-Object -ExpandProperty FullName
    Write-Error "build succeeded but no pkcs11-mock-$archSuffix.dll ($rid) found under $winBuildDir.`nProduced files:`n$($produced -join "`n")"
}

Copy-Item -Path $srcLib.FullName -Destination $destFile -Force
Write-Host "Installed $destFile"
