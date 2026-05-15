# Builds pkcs11-mock and copies the resulting DLL into the Pkcs11.Tests
# output directory under runtimes/win-x64/native (or win-arm64/native).
#
# Usage: pwsh build-pkcs11-mock.ps1 -TestOutputDir <path>
#
# NOTE: Windows build uses build.bat + the Visual Studio solution under
# third-party/pkcs11-mock/build/windows. Requires VS Build Tools or a
# full Visual Studio installation with the C++ workload.

param(
    [Parameter(Mandatory=$true)]
    [string]$TestOutputDir
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$mockDir  = Join-Path $repoRoot 'vendor\pkcs11-mock'

if (-not (Test-Path $mockDir)) {
    Write-Error "pkcs11-mock submodule missing at $mockDir. Run: git submodule update --init --recursive"
}

$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
$rid = if ($arch -eq [System.Runtime.InteropServices.Architecture]::Arm64) { 'win-arm64' } else { 'win-x64' }
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

# Upstream produces pkcs11-mock-x64.dll and pkcs11-mock-x86.dll.
# Select the architecture that matches the current RID.
$archSuffix = if ($rid -eq 'win-arm64') { 'arm64' } else { 'x64' }
$srcLib = Get-ChildItem -Path $winBuildDir -Filter "pkcs11-mock*.dll" -Recurse |
          Where-Object { $_.Name -match $archSuffix } |
          Select-Object -First 1

if (-not $srcLib) {
    # Fallback: list what was actually produced to aid debugging.
    $produced = Get-ChildItem -Path $winBuildDir -Filter '*.dll' -Recurse | Select-Object -ExpandProperty FullName
    Write-Error "build succeeded but no $archSuffix .dll found under $winBuildDir.`nProduced files:`n$($produced -join "`n")"
}

Copy-Item -Path $srcLib.FullName -Destination $destFile -Force
Write-Host "Installed $destFile"
