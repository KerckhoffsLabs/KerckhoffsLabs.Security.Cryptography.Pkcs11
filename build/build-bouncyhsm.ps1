# Builds BouncyHsm from the vendor/bouncyhsm submodule on Windows: the server (portable net10.0) and
# the native PKCS#11 client for the requested RID, staged where BouncyHsmBackendFixture looks.
#
# Usage: build-bouncyhsm.ps1 -TestOutputDir <dir> [-Rid win-x64|win-x86|win-arm64]
#
# Outputs (relative to -TestOutputDir):
#   bouncyhsm\server\BouncyHsm.dll                       (+ the rest of the publish output)
#   bouncyhsm\runtimes\<rid>\native\BouncyHsm.Pkcs11Lib.dll
#
# Upstream ships no ARM64 client, so win-arm64 prints "skipped" and exits 0.
param(
    [Parameter(Mandatory=$true)]
    [string]$TestOutputDir,
    [string]$Rid = ''
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$srcDir   = Join-Path $repoRoot 'vendor\bouncyhsm'
$csproj   = Join-Path $srcDir 'src\Src\BouncyHsm\BouncyHsm.csproj'
$vcxproj  = Join-Path $srcDir 'src\Src\BouncyHsm.Pkcs11Lib\BouncyHsm.Pkcs11Lib.vcxproj'

if (-not (Test-Path $csproj)) {
    Write-Error "bouncyhsm submodule missing at $srcDir. Run: git submodule update --init --recursive"
}

if (-not $Rid) {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    $Rid = if ($arch -eq [System.Runtime.InteropServices.Architecture]::Arm64) { 'win-arm64' } else { 'win-x64' }
}
$platform = switch ($Rid) {
    'win-x64' { 'x64' }
    'win-x86' { 'Win32' }
    default   { Write-Host "build-bouncyhsm.ps1: upstream ships no native client for $Rid; skipped."; return }
}

$bhOut     = Join-Path $TestOutputDir 'bouncyhsm'
$serverDir = Join-Path $bhOut 'server'
$nativeDir = Join-Path $bhOut "runtimes\$Rid\native"
$destLib   = Join-Path $nativeDir 'BouncyHsm.Pkcs11Lib.dll'
$stampFile = Join-Path $bhOut ".built-from-$Rid"

# Same stamp as build/lib/common.sh's build_stamp: the submodule commit plus this script's blob hash.
$stamp = "$((& git -C $srcDir rev-parse HEAD).Trim()) $((& git hash-object $PSCommandPath).Trim())"
if ((Test-Path $stampFile) -and ((Get-Content $stampFile -Raw).Trim() -eq $stamp) `
    -and (Test-Path (Join-Path $serverDir 'BouncyHsm.dll')) -and (Test-Path $destLib)) {
    Write-Host "bouncyhsm up to date at $bhOut"
    return
}
Remove-Item -Force -ErrorAction SilentlyContinue $stampFile
New-Item -ItemType Directory -Force -Path $serverDir, $nativeDir | Out-Null

Write-Host 'Publishing BouncyHsm server...'
# Runs inside the test project's dotnet build; clear the outer MSBuild's variables so the nested
# publish resolves its own SDK (see build-bouncyhsm.sh).
foreach ($v in 'MSBuildExtensionsPath', 'MSBuildSDKsPath', 'MSBUILD_EXE_PATH', 'MSBuildLoadMicrosoftTargetsReadOnly') {
    Remove-Item "Env:$v" -ErrorAction SilentlyContinue
}
& dotnet publish $csproj -c Release -o $serverDir -nologo -v q
if ($LASTEXITCODE -ne 0) { Write-Error "dotnet publish failed ($LASTEXITCODE)" }

. (Join-Path $PSScriptRoot 'Find-VcVarsAll.ps1')
$vcvars = Find-VcVarsAll
if (-not $vcvars) { Write-Error "vcvarsall.bat (VS with the C++ toolset) not found via vswhere or the standard install paths." }

# Upstream's vcxproj pins PlatformToolset v145 (VS 2026). Build with the toolset of the installed VS
# instead (17.x -> v143, 18.x -> v145), so a runner image on VS 2022 still builds it. The toolset is
# chosen here, not inside the cmd line: cmd expands %VAR% when it parses the whole line, before an
# earlier `set` in that same line has run.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vsVersion = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationVersion).Trim()
$toolset = if ($vsVersion -like '17.*') { 'v143' } else { 'v145' }
$objDir = Join-Path $env:TEMP "bouncyhsm-$Rid"
$cmd = "call `"$vcvars`" amd64 >nul && " +
       "msbuild `"$vcxproj`" /nologo /v:minimal /p:Configuration=Release /p:Platform=$platform " +
       "/p:PlatformToolset=$toolset /p:OutDir=`"$objDir\\`" /p:IntDir=`"$objDir\obj\\`" /target:Rebuild"
Write-Host "msbuild ($Rid -> $platform, toolset $toolset)"
& cmd.exe /c $cmd
if ($LASTEXITCODE -ne 0) { Write-Error "msbuild ($Rid) failed ($LASTEXITCODE)" }

Copy-Item -Force (Join-Path $objDir 'BouncyHsm.Pkcs11Lib.dll') $destLib
Set-Content -NoNewline -Path $stampFile -Value $stamp
Write-Host "Installed $serverDir and $destLib"
