# Builds pkcs11-mock and copies the matching-architecture DLL into the Pkcs11.Tests
# output directory under runtimes/<rid>/native.
#
# Usage: pwsh build-pkcs11-mock.ps1 -TestOutputDir <path> [-Rid win-x64|win-x86|win-arm64]
#
# -Rid selects which architecture's mock to install. It MUST match the architecture the
# tests run as (the testhost), which is the .NET SDK's architecture — the build target
# passes $(NETCoreSdkPortableRuntimeIdentifier). The x86 test process cannot load an x64
# mock (BadImageFormat), so this must not be guessed from the (64-bit) pwsh host.
# build.bat builds both Win32 and x64, producing pkcs11-mock-x86.dll and pkcs11-mock-x64.dll.
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
