# Builds pkcs11-mock and copies the matching-architecture DLL into the Pkcs11.Tests
# output directory under runtimes/<rid>/native.
#
# Usage: pwsh build-pkcs11-mock.ps1 -TestOutputDir <path> [-Rid win-x64|win-x86|win-arm64]
#
# -Rid selects which architecture's mock to install. It MUST match the architecture the
# tests run as (the testhost), which is the .NET SDK's architecture — the build target
# passes $(NETCoreSdkPortableRuntimeIdentifier). The x86 test process cannot load an x64
# mock (BadImageFormat), so this must not be guessed from the (64-bit) pwsh host.
# build.bat builds Win32 + x64 (pkcs11-mock-x86.dll / pkcs11-mock-x64.dll); the upstream solution
# has no ARM64 platform, so win-arm64 is compiled directly with the native ARM64 cl.exe below.
#
# NOTE: Windows build uses build.bat + the Visual Studio solution under
# vendor/pkcs11-mock/build/windows. Requires VS Build Tools or a
# full Visual Studio installation with the C++ workload.

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

Write-Host "Building pkcs11-mock for $rid..."

$winBuildDir = Join-Path $mockDir 'build\windows'

if ($rid -eq 'win-arm64') {
    # Upstream build.bat / pkcs11-mock.sln only define Win32 + x64 platforms — there is no ARM64
    # configuration to drive via msbuild. pkcs11-mock is a single translation unit that exports its
    # PKCS#11 entry points via CRYPTOKI_EXPORTS (__declspec(dllexport)), so compile it directly with
    # the native ARM64 toolchain. /MT statically links the CRT so the produced DLL has no vcruntime
    # dependency to resolve at load time (matching the /MT x86/x64 builds).
    $vcvars = $null
    foreach ($ed in 'Enterprise','Professional','Community','BuildTools') {
        $cand = "C:\Program Files\Microsoft Visual Studio\2022\$ed\VC\Auxiliary\Build\vcvarsall.bat"
        if (Test-Path $cand) { $vcvars = $cand; break }
    }
    if (-not $vcvars) { Write-Error "vcvarsall.bat (VS 2022 with the ARM64 C++ toolset) not found." }

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
    Push-Location $winBuildDir
    try {
        $result = cmd /c 'build.bat' '2>&1'
        $result | Write-Host
        if ($LASTEXITCODE -ne 0) {
            Write-Error "build.bat exited with code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }
}

# Upstream produces pkcs11-mock-x64.dll, pkcs11-mock-x86.dll (and arm64 where supported).
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
