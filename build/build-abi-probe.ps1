# Compiles and runs the PKCS#11 ABI oracle (abi-probe.c) with MSVC for the test host's architecture
# and writes its output to <TestOutputDir>\abi-oracle.txt, where AbiOracleTests read it.
#
# Usage: pwsh build-abi-probe.ps1 -TestOutputDir <path> -Rid win-x64|win-x86|win-arm64
#
# -Rid MUST match the architecture the tests run as (the build target passes the SDK's RID): the
# point is to measure the layout the test process itself sees, including the 4-byte pointers and
# 1-byte packing of win-x86.

param(
    [Parameter(Mandatory=$true)]
    [string]$TestOutputDir,
    [Parameter(Mandatory=$true)]
    [ValidateSet('win-x64', 'win-x86', 'win-arm64')]
    [string]$Rid
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Find-VcVarsAll.ps1')

$vcvars = Find-VcVarsAll
if (-not $vcvars) { Write-Error "vcvarsall.bat (VS 2022 with the C++ toolset) not found via vswhere or the standard install paths." }

# vcvarsall host_target argument. The x64 runners build x86 with the amd64-hosted cross compiler
# (as pkcs11-mock does); arm64 runners use the native arm64 toolchain.
$vcArch = switch ($Rid) {
    'win-x86'   { 'amd64_x86' }
    'win-arm64' { 'arm64' }
    default     { 'amd64' }
}

$probe   = Join-Path $PSScriptRoot 'abi-probe.c'
$headers = Join-Path $PSScriptRoot '..\vendor\pkcs11\published\3-02'
if (-not (Test-Path (Join-Path $headers 'pkcs11.h'))) {
    Write-Error "OASIS headers missing at $headers. Run: git submodule update --init vendor/pkcs11"
}
$work    = Join-Path ([System.IO.Path]::GetTempPath()) ("abi-probe-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $work, $TestOutputDir | Out-Null

try {
    $exe = Join-Path $work 'abi-probe.exe'
    $cmd = "call `"$vcvars`" $vcArch >nul && cl /nologo /W3 /I`"$headers`" `"$probe`" /Fo`"$work\\`" /Fe`"$exe`""
    $result = cmd /c $cmd '2>&1'
    if ($LASTEXITCODE -ne 0) { $result | Write-Host; Write-Error "cl ($Rid) failed ($LASTEXITCODE)" }

    $oracle = Join-Path $TestOutputDir 'abi-oracle.txt'
    & $exe | Set-Content -Path $oracle -Encoding ascii
    if ($LASTEXITCODE -ne 0) { Write-Error "abi-probe ($Rid) failed ($LASTEXITCODE)" }
    Write-Host "Wrote $oracle ($((Get-Content $oracle).Count) rows, MSVC $vcArch)"
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
