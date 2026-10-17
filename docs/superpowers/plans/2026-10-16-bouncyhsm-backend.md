# BouncyHsm Test Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the shared `*TestCases` suite against BouncyHsm, built from a vendored submodule and
started by its own test fixture, on every CI leg that has a BouncyHsm native client.

**Architecture:**
- **Build:** `vendor/bouncyhsm` is built by `build/build-bouncyhsm.{sh,ps1}`, called from an opt-in
  MSBuild target. It produces a portable server and a native client, both under
  `<test-out>/bouncyhsm/`.
- **Server lifecycle:** `BouncyHsmServer` owns the server process: free ports, readiness, `POST /Slot`
  and kill.
- **Fixture:** `BouncyHsmBackendFixture` uses `BouncyHsmServer`, points the native client at it
  through `BOUNCY_HSM_CFG_STRING`, and implements `IPkcs11Backend`.
- **Wrappers and gates:** hand-written `*.BouncyHsm.cs` wrappers delegate to the shared test cases.
  Quirk gates live on the fixture, each with a test that fails once the quirk is gone.

**Tech Stack:** .NET 10 / C# latest, xUnit v3 on Microsoft.Testing.Platform, bash and PowerShell build
scripts, MSBuild `Exec` targets, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-16-bouncyhsm-backend-design.md`

**Precondition: PR 1 (the Encrypt length-retry fix) is merged into `main`.** Rebase this branch onto it
before Task 5. Without it, 7 RSA encrypt wrappers fail on BouncyHsm (#114). Do **not** gate them;
they are this library's bug, not BouncyHsm's.

## Global Constraints

- Submodule `vendor/bouncyhsm`: shallow, pinned to tag `v2.3.3` = `220e5cde645febea5f521c5584dd41dbd9b6b296`.
- Server: `dotnet publish vendor/bouncyhsm/src/Src/BouncyHsm/BouncyHsm.csproj -c Release`, staged at `<test-out>/bouncyhsm/server/`.
- Native client staged at `<test-out>/bouncyhsm/runtimes/<rid>/native/<lib>`, where `<lib>` is:
  - `BouncyHsm.Pkcs11Lib.so` (linux-x64)
  - `libBouncyHsm.Pkcs11Lib.dylib` (osx-x64, osx-arm64)
  - `BouncyHsm.Pkcs11Lib.dll` (win-x64, win-x86)
- linux-arm64 and win-arm64: no native client. The build prints "skipped" and exits 0, and the tests skip.
- The MSBuild target `BuildBouncyHsm` is opt-in (`-p:BuildBouncyHsm=true`). `SkipNativeBuilds=true` and `SkipBouncyHsmBuild=true` disable it.
- Server environment:
  - `PersistenceStorageType=InMemory`
  - `BouncyHsmSetup__TcpEndpoint__Endpoint=127.0.0.1:<tcp>`
  - `Kestrel__Endpoints__Http__Url=http://127.0.0.1:<http>`
  - `BouncyHsmSetup__EnableSwagger=false`
  - `Serilog__MinimumLevel__Default=Warning`
- The server binds to loopback only.
- Client config: `BOUNCY_HSM_CFG_STRING=Server=127.0.0.1; Port=<tcp>; LogTarget=ErrorConsole; LogLevel=Error;`. Set it **before** `Pkcs11Library.Load`; the client reads it at load time.
- Token label: `Settings.BouncyHsmTokenLabel` (`PKCS11_TEST_BOUNCYHSM_TOKEN`, default `kl-bouncyhsm`). PINs: `Settings.UserPin` / `Settings.SoPin`.
- **PINs are never logged and never appear in exception messages.**
- Collection name `BouncyHsm`; class suffix `_BouncyHsm`.
- CI expect variable: `PKCS11_TEST_EXPECT_BOUNCYHSM=1`.
- Test step convention: every BouncyHsm `[Fact]`/`[Theory]` uses
  `SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable)`.
- Upstream issues: harrison314/BouncyHsm#114, #115 and #116.

**Deviation from the spec:** the spec says the libc `setenv` P/Invoke moves from the Kryoptic fixture
into a new `Support/NativeEnvironment.cs`. `SoftHsmBackendFixture.SetNativeEnv(string, string)`
already works on Linux, macOS and Windows (on Windows it relies on `SetEnvironmentVariable`), and three
callers already reuse it (`SoftHsmGateBackendFixture`, `NssBehindP11KitProxyTests`). So the BouncyHsm
fixture calls it directly and nothing is refactored.

**Second deviation:** the spec mentions a NuGet package cache for the vendored restore. The
`bouncyhsm` build cache in Task 6 skips the publish entirely on a hit, so it is left out (YAGNI).

## Review Focus

1. **The server can't start** (no `dotnet` host, missing or corrupt `BouncyHsm.dll`, a port collision
   that survives the retry). The fixture should fail within the 60 s timeout with the server's own
   output in the message, not hang or report "token not found". *Test:* Task 3,
   `Start_WithMissingServerAssembly_FailsFastWithServerOutput`.
2. **The server process outlives the fixture.** After `Dispose`, nothing should still be listening
   on its ports and its process should have exited. *Test:* Task 3,
   `Dispose_StopsTheServerProcess`.
3. **A PIN leaks through an error.** When `POST /Slot` is rejected, the message should give the status
   and the server's reason, but never the PINs it sent. *Test:* Task 3,
   `CreateSlot_Rejected_MessageNeverContainsThePins`.
4. **Two runs on one machine** (a developer running two terminals, or parallel jobs on one self-hosted
   runner). Each should get its own ports and token without interfering. *Test:* Task 3,
   `Start_TwiceConcurrently_GivesIndependentServers`.
5. **A chatty server fills the stdout pipe.** If output isn't drained, the server blocks and the tests
   hang. Output should be drained continuously and the kept tail bounded. *Test:* Task 3,
   `VerboseServer_KeepsRespondingAndOutputTailStaysBounded`.

---

## File Structure

| File | Responsibility |
|---|---|
| `.gitmodules`, `vendor/bouncyhsm` | pinned upstream source |
| `build/build-bouncyhsm.sh` | Linux and macOS: publish the server, build and stage the native client |
| `build/build-bouncyhsm.ps1` | Windows: the same, with MSBuild on the vcxproj |
| `tests/…Tests/…Tests.csproj` | `BuildBouncyHsm` target; `SkipNativeBuilds` wiring |
| `tests/…Tests/Support/Settings.cs` | `BouncyHsmDirectory`, `BouncyHsmTokenLabel` |
| `tests/…Tests/Support/Fixtures/BouncyHsmServer.cs` | the server process: ports, start, readiness, slot creation, output tail, kill |
| `tests/…Tests/Support/Fixtures/BouncyHsmBackendFixture.cs` | `IPkcs11Backend`, availability gate, quirk gates, collection definition |
| `tests/…Tests/Unit/Architecture/TestCollectionConventionTests.cs` | `("_BouncyHsm", "BouncyHsm")` suffix rule |
| `tests/…Tests/Integration/Smoke/BouncyHsmAvailabilityTests.cs` | CI guard on `PKCS11_TEST_EXPECT_BOUNCYHSM` |
| `tests/…Tests/Integration/Smoke/BouncyHsmServerTests.cs` | lifecycle tests for the Review Focus items |
| `tests/…Tests/Integration/Compat/BouncyHsmQuirkTests.cs` | a test per gate asserting its quirk is still there |
| `tests/…Tests/**/*.BouncyHsm.cs` | about 67 wrapper classes |
| `.github/workflows/ci.yml`, `.github/workflows/code-quality.yml` | build, cache and expect wiring |
| `README.md`, `tests/…Tests/README.md`, `BACKLOG.md` | docs and gate-removal entries |

`tests/…Tests` stands for `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests`.

---

### Task 1: Vendor BouncyHsm and build it on Linux and macOS

**Files:**
- Modify: `.gitmodules`
- Create: `vendor/bouncyhsm` (submodule)
- Create: `build/build-bouncyhsm.sh`
- Modify: `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj` (the `SkipNativeBuilds` group at about lines 64–74, and a new target after `BuildKryoptic`)

**Interfaces:**
- Produces: `<test-out>/bouncyhsm/server/BouncyHsm.dll` and `<test-out>/bouncyhsm/runtimes/<rid>/native/<lib>`, the names in Global Constraints. It also produces the `<test-out>/bouncyhsm/.built-from` stamp.

- [ ] **Step 1: Add the submodule, pinned and shallow**

```bash
git submodule add --depth 1 https://github.com/harrison314/BouncyHsm.git vendor/bouncyhsm
git -C vendor/bouncyhsm fetch --depth 1 origin tag v2.3.3
git -C vendor/bouncyhsm checkout v2.3.3
git config -f .gitmodules submodule.vendor/bouncyhsm.shallow true
git -C vendor/bouncyhsm rev-parse HEAD   # must print 220e5cde645febea5f521c5584dd41dbd9b6b296
```

- [ ] **Step 2: Run the not-yet-written build to confirm it is missing**

Run: `bash build/build-bouncyhsm.sh /tmp/bh-out`
Expected: `bash: build/build-bouncyhsm.sh: No such file or directory`

- [ ] **Step 3: Write `build/build-bouncyhsm.sh`**

```bash
#!/usr/bin/env bash
# Builds BouncyHsm from the vendor/bouncyhsm submodule: the server (portable net10.0, the same on
# every OS) and the native PKCS#11 client for this machine, staged where BouncyHsmBackendFixture
# looks for them.
#
# Usage: build-bouncyhsm.sh <test-output-dir>
#
# Outputs (relative to <test-output-dir>):
#   bouncyhsm/server/BouncyHsm.dll                     (+ the rest of the publish output)
#   bouncyhsm/runtimes/<rid>/native/BouncyHsm.Pkcs11Lib.so | libBouncyHsm.Pkcs11Lib.dylib
#
# Idempotent: skips the rebuild when the staged outputs were built from this submodule commit by
# this script (see is_built_from). Upstream ships no Linux arm64 client, so on linux-arm64 this prints
# "skipped" and exits 0; the fixture then reports the backend unavailable and its tests skip.

set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
require_args 1 "<test-output-dir>" "$@"

OUT_BASE="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_ROOT}/vendor/bouncyhsm"

require_submodule "${SRC_DIR}/src/Src/BouncyHsm/BouncyHsm.csproj" bouncyhsm

RID="$(host_rid)"
case "${RID}" in
  linux-x64)            MAKE_DIR="build_linux"; MAKE_TARGET="build64";                        BUILT="BouncyHsm.Pkcs11Lib-x64.so";          STAGED="BouncyHsm.Pkcs11Lib.so" ;;
  osx-x64)              MAKE_DIR="build_macos"; MAKE_TARGET="libBouncyHsm.Pkcs11Lib-x64.dylib";   BUILT="libBouncyHsm.Pkcs11Lib-x64.dylib";   STAGED="libBouncyHsm.Pkcs11Lib.dylib" ;;
  osx-arm64)            MAKE_DIR="build_macos"; MAKE_TARGET="libBouncyHsm.Pkcs11Lib-arm64.dylib"; BUILT="libBouncyHsm.Pkcs11Lib-arm64.dylib"; STAGED="libBouncyHsm.Pkcs11Lib.dylib" ;;
  *) echo "build-bouncyhsm.sh: upstream ships no native client for ${RID}; skipped." >&2; exit 0 ;;
esac

BH_OUT="${OUT_BASE}/bouncyhsm"
SERVER_DIR="${BH_OUT}/server"
NATIVE_DIR="${BH_OUT}/runtimes/${RID}/native"
DEST_LIB="${NATIVE_DIR}/${STAGED}"

STAMP_FILE="${BH_OUT}/.built-from"
STAMP="$(build_stamp "${SRC_DIR}")"
if is_built_from "${STAMP_FILE}" "${STAMP}" "${SERVER_DIR}/BouncyHsm.dll" "${DEST_LIB}"; then
  echo "bouncyhsm up to date at ${BH_OUT}"
  exit 0
fi
rm -f "${STAMP_FILE}"
mkdir -p "${SERVER_DIR}" "${NATIVE_DIR}"

echo "Publishing BouncyHsm server..."
# This runs inside the test project's `dotnet build` (an MSBuild Exec). The outer build's MSBuild
# variables would otherwise steer the nested SDK at the outer MSBuild; clear them so the vendored
# publish resolves its own SDK through the repo's global.json like a fresh shell would.
(
  unset MSBuildExtensionsPath MSBuildSDKsPath MSBUILD_EXE_PATH MSBuildLoadMicrosoftTargetsReadOnly
  dotnet publish "${SRC_DIR}/src/Src/BouncyHsm/BouncyHsm.csproj" -c Release -o "${SERVER_DIR}" -nologo -v q
) 2>&1

echo "Building BouncyHsm native client for ${RID}..."
# Upstream's Makefiles default to clang; `cc` is whatever the runner's toolchain provides
# (gcc on ubuntu-latest's build-essential, Apple clang on macOS).
make -C "${SRC_DIR}/${MAKE_DIR}" CC=cc "${MAKE_TARGET}" 2>&1

SRC_LIB="${SRC_DIR}/${MAKE_DIR}/${BUILT}"
if [[ ! -f "${SRC_LIB}" ]]; then
  echo "build succeeded but ${SRC_LIB} not found" >&2; exit 1
fi
cp "${SRC_LIB}" "${DEST_LIB}"

record_build "${STAMP_FILE}" "${STAMP}"
echo "Installed ${SERVER_DIR} and ${DEST_LIB}"
```

Then run `chmod +x build/build-bouncyhsm.sh`.

- [ ] **Step 4: Run it and verify the outputs**

Run: `bash build/build-bouncyhsm.sh /tmp/bh-out && ls /tmp/bh-out/bouncyhsm/server/BouncyHsm.dll /tmp/bh-out/bouncyhsm/runtimes/linux-x64/native/BouncyHsm.Pkcs11Lib.so`
Expected: both paths are printed. A cold run takes about 3–4 min.

Run it again: `bash build/build-bouncyhsm.sh /tmp/bh-out`
Expected: `bouncyhsm up to date at /tmp/bh-out/bouncyhsm` within a second.

- [ ] **Step 5: Add the MSBuild target**

In the test csproj, add a line to the `SkipNativeBuilds` property group (the one that sets `<BuildKryoptic>false</BuildKryoptic>`):

```xml
    <BuildBouncyHsm>false</BuildBouncyHsm>
```

Add `BouncyHsm` to that group's comment, in the list "(pkcs11-mock, the ABI oracle, the gate shims, SoftHSM and Kryoptic)".

After the `BuildKryoptic` target, add:

```xml
  <!-- Opt-in (-p:BuildBouncyHsm=true), like Kryoptic: a cold build publishes the vendored server
       (about 3 min, mostly restore), which a plain local build should not pay. Stages the server and
       the native client under bin/<cfg>/<tfm>/bouncyhsm, where BouncyHsmBackendFixture looks. -->
  <Target Name="BuildBouncyHsm" BeforeTargets="PrepareForBuild" Condition="'$(BuildBouncyHsm)' == 'true' AND '$(SkipBouncyHsmBuild)' != 'true'">
    <PropertyGroup>
      <_BouncyHsmOutputDir>$(MSBuildProjectDirectory)/bin/$(Configuration)/$(TargetFramework)</_BouncyHsmOutputDir>
      <_BouncyHsmRid Condition="'$(RuntimeIdentifier)' != ''">$(RuntimeIdentifier)</_BouncyHsmRid>
      <_BouncyHsmRid Condition="'$(_BouncyHsmRid)' == ''">$(NETCoreSdkPortableRuntimeIdentifier)</_BouncyHsmRid>
    </PropertyGroup>
    <Exec Condition="!$([MSBuild]::IsOSPlatform('Windows'))" Command="bash &quot;$(MSBuildProjectDirectory)/../../build/build-bouncyhsm.sh&quot; &quot;$(_BouncyHsmOutputDir)&quot;" IgnoreStandardErrorWarningFormat="true" />
    <Exec Condition="$([MSBuild]::IsOSPlatform('Windows'))" Command="pwsh -NoProfile -ExecutionPolicy Bypass -File &quot;$(MSBuildProjectDirectory)\..\..\build\build-bouncyhsm.ps1&quot; -TestOutputDir &quot;$(_BouncyHsmOutputDir)&quot; -Rid &quot;$(_BouncyHsmRid)&quot;" IgnoreStandardErrorWarningFormat="true" />
  </Target>
```

- [ ] **Step 6: Build through MSBuild**

Run: `dotnet build tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests -c Release -p:BuildBouncyHsm=true -p:SkipSoftHsmV2Build=true -p:SkipPkcs11GateBuild=true -v q`
Expected: `0 Warning(s)`, `0 Error(s)`, and `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/bin/Release/net10.0/bouncyhsm/server/BouncyHsm.dll` exists.

Run: `dotnet build tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests -c Release -p:SkipNativeBuilds=true -v q`
Expected: the build does not print "Publishing BouncyHsm server".

- [ ] **Step 7: Commit**

```bash
git add .gitmodules vendor/bouncyhsm build/build-bouncyhsm.sh tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj
git commit -m "build: vendor BouncyHsm v2.3.3 and build it on Linux and macOS"
```

---

### Task 2: Build BouncyHsm on Windows

**Files:**
- Create: `build/build-bouncyhsm.ps1`

**Interfaces:**
- Consumes: `build/Find-VcVarsAll.ps1` (`Find-VcVarsAll` returns the vcvarsall.bat path or `$null`), as `build-pkcs11-mock.ps1` uses it.
- Produces: the same layout as Task 1, with `BouncyHsm.Pkcs11Lib.dll` under `runtimes/win-x64|win-x86/native/`.

- [ ] **Step 1: Write `build/build-bouncyhsm.ps1`**

```powershell
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
Write-Host "msbuild ($Rid -> $platform)"
& cmd.exe /c $cmd
if ($LASTEXITCODE -ne 0) { Write-Error "msbuild ($Rid) failed ($LASTEXITCODE)" }

Copy-Item -Force (Join-Path $objDir 'BouncyHsm.Pkcs11Lib.dll') $destLib
Set-Content -NoNewline -Path $stampFile -Value $stamp
Write-Host "Installed $serverDir and $destLib"
```

The Windows stamp is per RID (`.built-from-<rid>`) because the x64 and x86 legs share a server
publish but not a native client.

- [ ] **Step 2: Check that it parses**

If `pwsh` is installed locally, run:
`pwsh -NoProfile -Command "[System.Management.Automation.Language.Parser]::ParseFile('build/build-bouncyhsm.ps1',[ref]$null,[ref]$e) | Out-Null; if ($e) { $e; exit 1 }"`
Expected: no output, exit 0.

If `pwsh` isn't installed, say so in the task report. The real check is Task 6's windows-latest x64
and x86 legs.

- [ ] **Step 3: Commit**

```bash
git add build/build-bouncyhsm.ps1
git commit -m "build: build BouncyHsm on Windows x64 and x86"
```

---

### Task 3: `BouncyHsmServer`, the fixture, and its guards

**Files:**
- Modify: `tests/…Tests/Support/Settings.cs` (append before the private helpers at the end of the class)
- Create: `tests/…Tests/Support/Fixtures/BouncyHsmServer.cs`
- Create: `tests/…Tests/Support/Fixtures/BouncyHsmBackendFixture.cs`
- Modify: `tests/…Tests/Unit/Architecture/TestCollectionConventionTests.cs:27-34`
- Create: `tests/…Tests/Integration/Smoke/BouncyHsmAvailabilityTests.cs`
- Test: `tests/…Tests/Integration/Smoke/BouncyHsmServerTests.cs`

**Interfaces:**
- Consumes: Task 1's layout, and `SoftHsmBackendFixture.SetNativeEnv(string name, string value)` (internal static).
- Produces:
  - `Settings.BouncyHsmDirectory : string` and `Settings.BouncyHsmTokenLabel : string`
  - `internal sealed class BouncyHsmServer : IDisposable`, with:
    - `static BouncyHsmServer Start(string serverAssemblyPath, IReadOnlyDictionary<string, string>? extraEnvironment = null, TimeSpan? readyTimeout = null)`
    - `int TcpPort`, `int HttpPort`, `int ProcessId`
    - `int CreateSlot(string tokenLabel, string userPin, string soPin)`, which returns the PKCS#11 slot id
    - `IReadOnlyList<string> OutputTail` (at most 200 lines)
    - `Dispose()`
  - `public sealed class BouncyHsmBackendFixture : IPkcs11Backend, IDisposable`, with:
    - `static bool BouncyHsmAvailable`
    - `internal static string? ServerAssemblyPath()` and `internal static string? NativeLibraryPath()`
  - `[CollectionDefinition("BouncyHsm")] BouncyHsmBackendCollection`

- [ ] **Step 1: Write the failing lifecycle tests**

`tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/Smoke/BouncyHsmServerTests.cs`:

```csharp
using System.Diagnostics;
using System.Net.Sockets;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// Lifecycle of the BouncyHsm server process the fixture owns. These start their own servers and
/// never load the PKCS#11 client, so they need no backend collection.
/// </summary>
[NoBackendCollection("Starts private BouncyHsm server processes on their own random ports and never " +
                     "loads the PKCS#11 client, so it shares no native state with the BouncyHsm collection.")]
public sealed class BouncyHsmServerTests
{
    private static string ServerDll => BouncyHsmBackendFixture.ServerAssemblyPath()!;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Start_WithMissingServerAssembly_FailsFastWithServerOutput()
    {
        string missing = Path.Join(Path.GetTempPath(), $"no-such-{Guid.NewGuid():N}", "BouncyHsm.dll");
        var sw = Stopwatch.StartNew();

        var ex = Assert.Throws<InvalidOperationException>(() => BouncyHsmServer.Start(missing));

        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(30), $"took {sw.Elapsed}");
        Assert.Contains("exited", ex.Message, StringComparison.Ordinal);
        Assert.Contains(missing, ex.Message, StringComparison.Ordinal); // the host's own complaint names the path
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Dispose_StopsTheServerProcess()
    {
        var server = BouncyHsmServer.Start(ServerDll);
        int pid = server.ProcessId, tcp = server.TcpPort;

        server.Dispose();

        Assert.Throws<ArgumentException>(() => Process.GetProcessById(pid));
        using var probe = new TcpClient();
        Assert.ThrowsAny<SocketException>(() => probe.Connect("127.0.0.1", tcp));
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void CreateSlot_Rejected_MessageNeverContainsThePins()
    {
        using var server = BouncyHsmServer.Start(ServerDll);
        const string userPin = "user-pin-sentinel-4711";
        const string soPin = "so-pin-sentinel-0815";

        // The server limits Label to 512 characters, so this is a 400 with a validation body.
        var ex = Assert.Throws<InvalidOperationException>(
            () => server.CreateSlot(new string('x', 600), userPin, soPin));

        Assert.Contains("400", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(userPin, ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(soPin, ex.Message, StringComparison.Ordinal);
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public async Task Start_TwiceConcurrently_GivesIndependentServers()
    {
        var starts = await Task.WhenAll(
            Task.Run(() => BouncyHsmServer.Start(ServerDll)),
            Task.Run(() => BouncyHsmServer.Start(ServerDll)));
        using var a = starts[0];
        using var b = starts[1];

        Assert.Equal(4, new HashSet<int> { a.TcpPort, a.HttpPort, b.TcpPort, b.HttpPort }.Count);
        int slotA = a.CreateSlot("kl-a", "11111111", "11111111");
        int slotB = b.CreateSlot("kl-b", "11111111", "11111111");
        Assert.True(slotA > 0 && slotB > 0);
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void VerboseServer_KeepsRespondingAndOutputTailStaysBounded()
    {
        using var server = BouncyHsmServer.Start(ServerDll, new Dictionary<string, string>
        {
            ["Serilog__MinimumLevel__Default"] = "Verbose",
            ["Serilog__WriteTo__0__Args__restrictedToMinimumLevel"] = "Verbose",
        });

        for (int i = 0; i < 100; i++)
            server.CreateSlot($"kl-verbose-{i}", "11111111", "11111111");

        Assert.InRange(server.OutputTail.Count, 1, 200);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `dotnet build tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests -c Release -p:SkipSoftHsmV2Build=true -p:SkipPkcs11GateBuild=true -v q`
Expected: compile errors `CS0103`/`CS0246` for `BouncyHsmServer` and `BouncyHsmBackendFixture`.

- [ ] **Step 3: Add the `Settings` entries**

Append inside `public static class Settings`, after the Kryoptic entries:

```csharp
    /// <summary>
    /// Directory holding a BouncyHsm build (<c>server/BouncyHsm.dll</c> plus
    /// <c>runtimes/&lt;rid&gt;/native/</c>). Falls back to the <c>bouncyhsm</c> directory the
    /// BuildBouncyHsm MSBuild target stages next to the test assembly.
    /// </summary>
    public static string BouncyHsmDirectory =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_BOUNCYHSM_DIR")
        ?? Path.Join(AppContext.BaseDirectory, "bouncyhsm");

    /// <summary>Label of the token the BouncyHsm fixture creates on its private server.</summary>
    public static string BouncyHsmTokenLabel =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_BOUNCYHSM_TOKEN") ?? "kl-bouncyhsm";
```

- [ ] **Step 4: Write `BouncyHsmServer.cs`**

```csharp
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// One BouncyHsm server process, private to its owner: in-memory storage, loopback-only, on two
/// freshly chosen ports. Starting returns only once the REST API answers; disposing kills the
/// process tree. The server's output is drained continuously (so a chatty server never blocks on a
/// full pipe) and its last <see cref="TailLines"/> lines are kept for failure messages.
/// </summary>
internal sealed class BouncyHsmServer : IDisposable
{
    private const int TailLines = 200;
    private static readonly TimeSpan DefaultReadyTimeout = TimeSpan.FromSeconds(60);

    private readonly Process _process;
    private readonly ConcurrentQueue<string> _tail = new();
    private readonly HttpClient _http;
    private readonly EventHandler _onProcessExit;
    private bool _disposed;

    public int TcpPort { get; }
    public int HttpPort { get; }
    public int ProcessId => _process.Id;
    public IReadOnlyList<string> OutputTail => [.. _tail];

    private BouncyHsmServer(Process process, int tcpPort, int httpPort)
    {
        _process = process;
        TcpPort = tcpPort;
        HttpPort = httpPort;
        _http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{httpPort}/"), Timeout = TimeSpan.FromSeconds(30) };
        _onProcessExit = (_, _) => Kill();
        AppDomain.CurrentDomain.ProcessExit += _onProcessExit;
    }

    /// <summary>
    /// Starts a server from <paramref name="serverAssemblyPath"/> and waits until it is ready. A
    /// failed start is retried once on new ports, since a port can be taken between choosing and binding.
    /// </summary>
    public static BouncyHsmServer Start(string serverAssemblyPath,
        IReadOnlyDictionary<string, string>? extraEnvironment = null, TimeSpan? readyTimeout = null)
    {
        try
        {
            return StartOnce(serverAssemblyPath, extraEnvironment, readyTimeout ?? DefaultReadyTimeout);
        }
        catch (InvalidOperationException) when (File.Exists(serverAssemblyPath))
        {
            return StartOnce(serverAssemblyPath, extraEnvironment, readyTimeout ?? DefaultReadyTimeout);
        }
    }

    private static BouncyHsmServer StartOnce(string serverAssemblyPath,
        IReadOnlyDictionary<string, string>? extraEnvironment, TimeSpan readyTimeout)
    {
        int tcpPort = FreeLoopbackPort();
        int httpPort = FreeLoopbackPort();

        var psi = new ProcessStartInfo(DotnetHost())
        {
            ArgumentList = { serverAssemblyPath },
            WorkingDirectory = Path.GetDirectoryName(serverAssemblyPath) is { Length: > 0 } dir && Directory.Exists(dir)
                ? dir : AppContext.BaseDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.Environment["PersistenceStorageType"] = "InMemory";
        psi.Environment["BouncyHsmSetup__TcpEndpoint__Endpoint"] = $"127.0.0.1:{tcpPort}";
        psi.Environment["Kestrel__Endpoints__Http__Url"] = $"http://127.0.0.1:{httpPort}";
        psi.Environment["BouncyHsmSetup__EnableSwagger"] = "false";
        psi.Environment["Serilog__MinimumLevel__Default"] = "Warning";
        foreach (var (name, value) in extraEnvironment ?? new Dictionary<string, string>())
            psi.Environment[name] = value;

        var process = new Process { StartInfo = psi };
        var server = new BouncyHsmServer(process, tcpPort, httpPort);
        process.OutputDataReceived += (_, e) => server.Record(e.Data);
        process.ErrorDataReceived += (_, e) => server.Record(e.Data);
        try
        {
            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            server.WaitUntilReady(readyTimeout);
            return server;
        }
        catch
        {
            server.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Creates a slot holding one token and returns its PKCS#11 slot id. The PINs are sent to the
    /// server and never put into a message: a rejection reports the status and the server's reason only.
    /// </summary>
    public int CreateSlot(string tokenLabel, string userPin, string soPin)
    {
        var body = new
        {
            IsHwDevice = true,
            IsRemovableDevice = false,
            Description = "kl-bouncyhsm",
            Token = new
            {
                Label = tokenLabel,
                SerialNumber = $"kl-{Guid.NewGuid():N}"[..16],
                SimulateHwRng = true,
                SimulateHwMechanism = true,
                SimulateQualifiedArea = false,
                SimulateProtectedAuthPath = false,
                SpeedMode = "WithoutRestriction",
                UserPin = userPin,
                SoPin = soPin,
            },
        };
        using HttpResponseMessage response = _http.PostAsJsonAsync("Slot", body).GetAwaiter().GetResult();
        string text = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        if (!response.IsSuccessStatusCode)
        {
            string reason = text.Replace(userPin, "***", StringComparison.Ordinal).Replace(soPin, "***", StringComparison.Ordinal);
            throw new InvalidOperationException(
                $"BouncyHsm POST /Slot failed: {(int)response.StatusCode} {response.ReasonPhrase}. {reason}");
        }
        using var json = JsonDocument.Parse(text);
        return json.RootElement.GetProperty("SlotId").GetInt32();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        AppDomain.CurrentDomain.ProcessExit -= _onProcessExit;
        Kill();
        _http.Dispose();
        _process.Dispose();
    }

    private void Kill()
    {
        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit(TimeSpan.FromSeconds(10));
            }
        }
        catch (InvalidOperationException) { /* never started */ }
    }

    private void Record(string? line)
    {
        if (line is null) return;
        _tail.Enqueue(line);
        while (_tail.Count > TailLines && _tail.TryDequeue(out _)) { }
    }

    private void WaitUntilReady(TimeSpan timeout)
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < timeout)
        {
            if (_process.HasExited)
            {
                _process.WaitForExit(); // flush the asynchronous output readers
                throw new InvalidOperationException(
                    $"BouncyHsm server exited with code {_process.ExitCode} before it was ready.{Tail()}");
            }
            try
            {
                using HttpResponseMessage r = _http.GetAsync("Slot").GetAwaiter().GetResult();
                if (r.StatusCode == HttpStatusCode.OK) return;
            }
            catch (HttpRequestException) { /* not listening yet */ }
            Thread.Sleep(250);
        }
        throw new InvalidOperationException($"BouncyHsm server was not ready within {timeout}.{Tail()}");
    }

    private string Tail() => _tail.IsEmpty ? "" : Environment.NewLine + string.Join(Environment.NewLine, _tail);

    private static int FreeLoopbackPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    /// <summary>
    /// The dotnet host of this test run, so the server runs on the same .NET install, and arch, as the
    /// test host: DOTNET_HOST_PATH (set by the dotnet CLI), then DOTNET_ROOT, then dotnet on PATH.
    /// </summary>
    private static string DotnetHost()
    {
        if (Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") is { Length: > 0 } host && File.Exists(host))
            return host;
        string exe = OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet";
        if (Environment.GetEnvironmentVariable("DOTNET_ROOT") is { Length: > 0 } root && File.Exists(Path.Join(root, exe)))
            return Path.Join(root, exe);
        return exe;
    }
}
```

- [ ] **Step 5: Write `BouncyHsmBackendFixture.cs`**

```csharp
using System.Runtime.InteropServices;
using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// xUnit collection fixture for BouncyHsm (harrison314/BouncyHsm): a PKCS#11 v3.x soft HSM whose
/// native client forwards every call over TCP to a .NET server built on BouncyCastle. It is a sixth,
/// independent implementation alongside the mock, SoftHSM2, NSS, Kryoptic and opencryptoki, and the
/// only real backend besides SoftHSM2 that runs on Windows and macOS.
///
/// Built from the vendor/bouncyhsm submodule by the opt-in BuildBouncyHsm MSBuild target
/// (<see cref="Settings.BouncyHsmDirectory"/>). The fixture starts a private, in-memory server
/// (<see cref="BouncyHsmServer"/>), creates one token through its REST API, and points the client at
/// it with <c>BOUNCY_HSM_CFG_STRING</c>, which the client reads when the library loads, so it is set
/// before <see cref="Pkcs11Library.Load(string)"/>. Each run starts from a fresh token.
///
/// Known upstream bugs are gated below, one flag each, and
/// <c>Integration/Compat/BouncyHsmQuirkTests</c> fails once a gated bug is fixed.
/// </summary>
public sealed class BouncyHsmBackendFixture : IPkcs11Backend, IDisposable
{
    private readonly BouncyHsmServer? _server;

    public string LibraryPath { get; } = string.Empty;
    public Pkcs11Library Library { get; } = null!;
    public NativeCULong SlotId { get; }
    public ReadOnlyMemory<byte> SoPin { get; } = Encoding.UTF8.GetBytes(Settings.SoPin);
    public ReadOnlyMemory<byte> UserPin { get; } = Encoding.UTF8.GetBytes(Settings.UserPin);
    public string TokenLabel { get; } = Settings.BouncyHsmTokenLabel;

    /// <summary>Mechanisms the token reports via <c>C_GetMechanismList</c>; empty when unavailable.</summary>
    public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();

    /// <summary>True when the token's mechanism list includes <paramref name="mechanism"/>.</summary>
    public bool Supports(CKM mechanism) => SupportedMechanisms.Contains(mechanism);

    /// <summary>True when a BouncyHsm server and a native client for this RID are staged. Never starts a process.</summary>
    public static bool BouncyHsmAvailable => ServerAssemblyPath() is not null && NativeLibraryPath() is not null;

    public BouncyHsmBackendFixture()
    {
        if (!BouncyHsmAvailable) return;

        _server = BouncyHsmServer.Start(ServerAssemblyPath()!);
        try
        {
            _server.CreateSlot(TokenLabel, Settings.UserPin, Settings.SoPin);

            string config = $"Server=127.0.0.1; Port={_server.TcpPort}; LogTarget=ErrorConsole; LogLevel=Error;";
            Environment.SetEnvironmentVariable("BOUNCY_HSM_CFG_STRING", config);
            SoftHsmBackendFixture.SetNativeEnv("BOUNCY_HSM_CFG_STRING", config);

            LibraryPath = NativeLibraryPath()!;
            Library = Pkcs11Library.Load(LibraryPath);
            Pkcs11Slot slot = Library.GetSlotList().FirstOrDefault(s => s.GetTokenInfo().Label == TokenLabel)
                ?? throw new InvalidOperationException($"BouncyHsm token '{TokenLabel}' did not appear in the slot list.");
            SlotId = (NativeCULong)slot.SlotId.Value;
            SupportedMechanisms = new HashSet<CKM>(slot.GetMechanismList());
        }
        catch
        {
            try { Library?.Dispose(); } catch { /* best-effort */ }
            _server.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        try { Library?.Dispose(); } catch { /* best-effort */ }
        _server?.Dispose();
    }

    internal static string? ServerAssemblyPath()
    {
        string path = Path.Join(Settings.BouncyHsmDirectory, "server", "BouncyHsm.dll");
        return File.Exists(path) ? path : null;
    }

    internal static string? NativeLibraryPath()
    {
        string fileName = OperatingSystem.IsWindows() ? "BouncyHsm.Pkcs11Lib.dll"
            : OperatingSystem.IsMacOS() ? "libBouncyHsm.Pkcs11Lib.dylib"
            : "BouncyHsm.Pkcs11Lib.so";
        string path = Path.Join(Settings.BouncyHsmDirectory, "runtimes", RuntimeInformation.RuntimeIdentifier, "native", fileName);
        return File.Exists(path) ? path : null;
    }
}

/// <summary>xUnit collection definition for the BouncyHsm backend.</summary>
[CollectionDefinition("BouncyHsm")]
public sealed class BouncyHsmBackendCollection : ICollectionFixture<BouncyHsmBackendFixture> { }
```

`RuntimeInformation.RuntimeIdentifier` returns the portable RID (`linux-x64`, `osx-arm64`, `win-x86`,
and so on) for a framework-dependent app, which is the same naming the build scripts stage under.

- [ ] **Step 6: Add the convention entry and the availability guard**

In `Unit/Architecture/TestCollectionConventionTests.cs`, add a line to `BackendNameSuffixes` after `("_Kryoptic", "Kryoptic"),`:

```csharp
        ("_BouncyHsm", "BouncyHsm"),
```

Create `Integration/Smoke/BouncyHsmAvailabilityTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// CI-health guard: makes a missing BouncyHsm build fail loudly instead of silently skipping the
/// whole <c>[Fact(SkipUnless = nameof(BouncyHsmAvailable))]</c> suite while CI stays green. BouncyHsm
/// is built only on the legs that declare it with <c>PKCS11_TEST_EXPECT_BOUNCYHSM=1</c> (no arm64
/// client ships upstream), so the guard is keyed on that marker.
/// </summary>
[NoBackendCollection("Reads the fixture's static File.Exists probe only — it never starts the server " +
                     "or loads the module, so serializing it against the BouncyHsm collection would buy nothing.")]
public sealed class BouncyHsmAvailabilityTests
{
    [Fact]
    public void BouncyHsm_IsAvailable_WhereTheCiLegExpectsIt()
    {
        bool expected = string.Equals(
            Environment.GetEnvironmentVariable("PKCS11_TEST_EXPECT_BOUNCYHSM"), "1", StringComparison.Ordinal);

        if (!expected) return;

        Assert.True(BouncyHsmBackendFixture.BouncyHsmAvailable,
            "This CI leg declares PKCS11_TEST_EXPECT_BOUNCYHSM=1 but no BouncyHsm server and native " +
            $"client were found under {Settings.BouncyHsmDirectory}. Refusing to let the BouncyHsm " +
            "integration suite skip silently and report green.");
    }
}
```

- [ ] **Step 7: Run the lifecycle tests and the guards**

Run: `dotnet build tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests -c Release -p:BuildBouncyHsm=true -p:SkipSoftHsmV2Build=true -p:SkipPkcs11GateBuild=true -v q`
Expected: `0 Warning(s)`, `0 Error(s)`.

Run: `dotnet test --project tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests -c Release --no-build -- --filter-class '*BouncyHsmServerTests' --filter-class '*BouncyHsmAvailabilityTests' --filter-class '*TestCollectionConventionTests'`
Expected: all pass, 0 skipped among the `BouncyHsmServerTests`.

Then check the guard really fails:
`PKCS11_TEST_EXPECT_BOUNCYHSM=1 PKCS11_TEST_BOUNCYHSM_DIR=/nonexistent dotnet test --project tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests -c Release --no-build -- --filter-class '*BouncyHsmAvailabilityTests'`
Expected: 1 failed, with the "Refusing to let the BouncyHsm integration suite skip silently" message.

- [ ] **Step 8: Commit**

```bash
git add tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Settings.cs \
        tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/BouncyHsmServer.cs \
        tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/BouncyHsmBackendFixture.cs \
        tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Unit/Architecture/TestCollectionConventionTests.cs \
        tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/Smoke/BouncyHsmAvailabilityTests.cs \
        tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/Smoke/BouncyHsmServerTests.cs
git commit -m "test: BouncyHsm backend fixture that starts its own server"
```

---

### Task 4: Quirk gates and their quirk-still-present tests

**Files:**
- Modify: `tests/…Tests/Support/Fixtures/BouncyHsmBackendFixture.cs` (add the gates after `BouncyHsmAvailable`)
- Test: `tests/…Tests/Integration/Compat/BouncyHsmQuirkTests.cs`

**Interfaces:**
- Consumes: `BouncyHsmBackendFixture` (Task 3); `Pkcs11Session.Digest(Mechanism, ReadOnlySpan<byte>)`, `Pkcs11Key.Sign(Mechanism, ReadOnlySpan<byte>)`, `Pkcs11Key.Verify(Mechanism, ReadOnlySpan<byte>, ReadOnlySpan<byte>)`, `Pkcs11Exception.ReturnValue`.
- Produces, used by the Task 5 wrappers:
  - `public const bool BouncyHsmAcceptsEmptyInput = false;`
  - `public const bool BouncyHsmRejectsOutOfRangeSignatures = false;`
  - `public static bool EmptyDigestAndMacAvailable` (true when the backend is available and `BouncyHsmAcceptsEmptyInput`)
  - `public static bool OutOfRangeSignatureRejectionAvailable` (true when the backend is available and `BouncyHsmRejectsOutOfRangeSignatures`)

- [ ] **Step 1: Write the quirk tests**

`tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/Compat/BouncyHsmQuirkTests.cs`:

```csharp
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Compat;

/// <summary>
/// One test per gate on <see cref="BouncyHsmBackendFixture"/>: each reproduces a known BouncyHsm bug
/// directly and asserts that it is still there. When a submodule bump brings the upstream fix, the
/// matching test fails, telling us to remove the gate so the shared test cases run again.
/// </summary>
[Collection("BouncyHsm")]
public sealed class BouncyHsmQuirkTests(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EmptyDigest_QuirkStillPresent()
    {
        using var session = _backend.OpenSession();

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => session.Digest(new Mechanism(CKM.CKM_SHA256), []));

        Assert.True(ex.ReturnValue == CKR.CKR_ARGUMENTS_BAD,
            $"harrison314/BouncyHsm#115 looks fixed (C_Digest of empty data returned {ex.ReturnValue}): " +
            "set BouncyHsmBackendFixture.BouncyHsmAcceptsEmptyInput to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EmptyHmac_QuirkStillPresent()
    {
        using var session = _backend.OpenSession();
        string label = $"quirk-hmac-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).Value(RandomNumberGenerator.GetBytes(32)).Sign().Verify().Build();
        using var key = session.ImportKey(tpl);
        try
        {
            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), []));

            Assert.True(ex.ReturnValue == CKR.CKR_GENERAL_ERROR,
                $"harrison314/BouncyHsm#115 looks fixed (C_Sign of empty data returned {ex.ReturnValue}): " +
                "set BouncyHsmBackendFixture.BouncyHsmAcceptsEmptyInput to true and delete this test.");
        }
        finally { key.Destroy(); }
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void OutOfRangePssSignature_QuirkStillPresent()
    {
        using var session = _backend.OpenSession();
        string label = $"quirk-pss-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().ModulusBits(2048).PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA).Label(label).Id(id).Sign().Build();
        using var key = session.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), pubTpl, privTpl);
        var pss = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32));

        // 256 bytes of 0xFF is greater than any 2048-bit modulus.
        byte[] outOfRange = Enumerable.Repeat((byte)0xFF, 256).ToArray();
        try
        {
            var ex = Record.Exception(() => key.Verify(pss, "abc"u8, outOfRange));

            Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_GENERAL_ERROR },
                "harrison314/BouncyHsm#116 looks fixed (an out-of-range PSS signature no longer gives " +
                $"CKR_GENERAL_ERROR; got {ex?.GetType().Name ?? "no exception"}): set " +
                "BouncyHsmBackendFixture.BouncyHsmRejectsOutOfRangeSignatures to true and delete this test.");
        }
        finally { key.Destroy(); }
    }
}
```

`Pkcs11Key.Destroy()` on a key pair destroys both the private and the public object.

- [ ] **Step 2: Run them to confirm each quirk reproduces**

These tests assert the *wrong* behaviour, so the step that would normally be "watch it fail" is
"watch it reproduce". They need only Task 3, not the gate constants, so they pass right away:

Run: `dotnet test --project tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests -c Release --no-build -- --filter-class '*BouncyHsmQuirkTests'` (build first with the Task 3 command)
Expected: 3 passed. If one fails, the quirk isn't reproducible as described. Stop and report it
rather than adding a gate.

- [ ] **Step 3: Add the gates to the fixture**

After `BouncyHsmAvailable` in `BouncyHsmBackendFixture.cs`:

```csharp
    /// <summary>
    /// False while harrison314/BouncyHsm#115 is open: the client refuses <c>ulDataLen == 0</c> in
    /// <c>C_Digest</c>/<c>C_DigestUpdate</c>/<c>C_Verify</c> (<c>CKR_ARGUMENTS_BAD</c>) and the server refuses to
    /// sign or verify empty data (<c>CKR_GENERAL_ERROR</c>). BouncyHsmQuirkTests.EmptyDigest_QuirkStillPresent
    /// and EmptyHmac_QuirkStillPresent fail once it is fixed.
    /// </summary>
    public const bool BouncyHsmAcceptsEmptyInput = false;

    /// <summary>
    /// False while harrison314/BouncyHsm#116 is open: an RSA-PSS signature whose value is at least the
    /// modulus gives <c>CKR_GENERAL_ERROR</c> instead of <c>CKR_SIGNATURE_INVALID</c>, so a tamper check
    /// fails for about half of all random tamperings.
    /// BouncyHsmQuirkTests.OutOfRangePssSignature_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRejectsOutOfRangeSignatures = false;

    /// <summary>Gate for empty-input digest and MAC cases: see <see cref="BouncyHsmAcceptsEmptyInput"/>.</summary>
    public static bool EmptyDigestAndMacAvailable => BouncyHsmAvailable && BouncyHsmAcceptsEmptyInput;

    /// <summary>Gate for cases that verify a tampered RSA-PSS signature: see <see cref="BouncyHsmRejectsOutOfRangeSignatures"/>.</summary>
    public static bool OutOfRangeSignatureRejectionAvailable => BouncyHsmAvailable && BouncyHsmRejectsOutOfRangeSignatures;
```

The `&&` with a `const false` gives a CS0429 "unreachable expression" warning, and warnings are errors
here. If the build shows it, change the two `const` fields to `static readonly bool`. Keep the doc
comments.

- [ ] **Step 4: Build and rerun**

Run the Task 3 build command, then:
`dotnet test --project tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests -c Release --no-build -- --filter-class '*BouncyHsmQuirkTests'`
Expected: `0 Warning(s)`, `0 Error(s)`; 3 passed.

- [ ] **Step 5: Commit**

```bash
git add tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/BouncyHsmBackendFixture.cs \
        tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/Compat/BouncyHsmQuirkTests.cs
git commit -m "test: gate the known BouncyHsm bugs, each with a quirk-still-present test"
```

---

### Task 5: The BouncyHsm wrappers

**Precondition:** PR 1 is merged and this branch is rebased onto it (see the header).

**Files:**
- Create: one `*.BouncyHsm.cs` next to each source wrapper listed in Step 1, about 67 files under `tests/…Tests/Algorithms/` and `tests/…Tests/Integration/`

**Interfaces:**
- Consumes: `BouncyHsmBackendFixture`, `BouncyHsmAvailable`, `EmptyDigestAndMacAvailable`, `OutOfRangeSignatureRejectionAvailable` (Tasks 3–4); `Pkcs11BackendExtensions.RequireMechanism`.

- [ ] **Step 1: Generate the wrappers from their sources**

Sources:
- The 55 test cases with both an opencryptoki and a Kryoptic wrapper: use the **opencryptoki** wrapper, whose token is likewise provisioned outside the library under test.
- The opencryptoki-only `SignEdDsaContextTests`, `SignHashMlDsaTests` and `SignMlDsaDeterministicHedgeTests`: use the opencryptoki wrapper. Skip `SignIbmMlDsaContextTests`, which tests an IBM vendor mechanism.
- The 9 Kryoptic-only test cases: use the Kryoptic wrapper. These are `HkdfPkcs11Tests`, `PinManagementTests`, `HkdfTests`, `IkeDeriveTests`, `RawChaCha20Tests`, `OperationStateMixingTests`, `KekTemplateEnforcementTests`, `Pkcs5Pbkd2ReferenceVectorTests` and `InsecureOperationGateTests`.

Run from `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests` (this is a one-off; don't commit the loop):

```bash
gen() { # gen <source-wrapper> <Backend>
  local src="$1" b="$2" dst="${1%.$2.cs}.BouncyHsm.cs"
  sed -e "s/${b}BackendFixture/BouncyHsmBackendFixture/g" \
      -e "s/${b}Available/BouncyHsmAvailable/g" \
      -e "s/_${b}\b/_BouncyHsm/g" \
      -e "s/Collection(\"${b}\")/Collection(\"BouncyHsm\")/g" \
      -e "s/\b${b}\b/BouncyHsm/g" -e "s/opencryptoki/BouncyHsm/g" "$src" > "$dst"
}
o=$(find . -name '*.OpenCryptoki.cs' -not -path './bin/*' -not -path './obj/*' -not -path '*/Smoke/*' -not -name 'SignIbmMlDsaContextTests.OpenCryptoki.cs')
for f in $o; do gen "$f" OpenCryptoki; done
for t in Algorithms/HkdfPkcs11Tests Integration/Auth/PinManagementTests Integration/Derive/HkdfTests \
         Integration/Derive/IkeDeriveTests Integration/Encrypt/RawChaCha20Tests \
         Integration/Interop/OperationStateMixingTests Integration/Keys/KekTemplateEnforcementTests \
         Integration/Keys/Pkcs5Pbkd2ReferenceVectorTests Integration/Security/InsecureOperationGateTests; do
  gen "./$t.Kryoptic.cs" Kryoptic
done
find . -name '*.BouncyHsm.cs' -not -path './bin/*' | wc -l    # expect 67
grep -rn "OpenCryptoki\|Kryoptic" --include='*.BouncyHsm.cs' . # expect no output
```

Read every generated file's doc comment and fix wording that still describes the source backend,
for example "over opencryptoki" becoming "over BouncyHsm".

- [ ] **Step 2: Apply the gates the spike established**

1. `Algorithms/RSAPkcs11Tests.BouncyHsm.cs`, `SignVerifyData_AcrossKeySizes_RoundTrips`: replace the
   `[InlineData]` list with exactly the following, since BouncyHsm generates 2048–6144-bit moduli in
   steps of 1024 only:
   ```csharp
       [InlineData(2048)]
       [InlineData(3072)]
       [InlineData(4096)]
   ```
2. Same file, `SignVerifyData_Pss_RoundTrips`: change its attribute to
   ```csharp
       [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.OutOfRangeSignatureRejectionAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "harrison314/BouncyHsm#116: a tampered PSS signature can give CKR_GENERAL_ERROR")]
   ```
3. `Integration/Keys/Pkcs11KeyMechanismTests.BouncyHsm.cs`, `AesKeyWrap_WrapUnwrap_RoundTrip`: make
   the body's first statement `_backend.RequireMechanism(CKM.CKM_AES_KEY_WRAP);`. If the class reaches
   the module through a helper and has no `_backend` field, add the primary-constructor field the
   other wrappers use: `private readonly BouncyHsmBackendFixture _backend = backend;`.
4. `Integration/Interop/EmptyInputTests.BouncyHsm.cs`: put
   `SkipUnless = nameof(BouncyHsmBackendFixture.EmptyDigestAndMacAvailable)` with
   `Skip = "harrison314/BouncyHsm#115: zero-length data is refused"` on
   `Sha256_EmptyInput_MatchesBcl_SessionReusable` and `Hmac_EmptyInput_MatchesBcl_SessionReusable`.

- [ ] **Step 3: Build**

Run: `dotnet build tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests -c Release -p:BuildBouncyHsm=true -p:SkipSoftHsmV2Build=true -p:SkipPkcs11GateBuild=true -v q`
Expected: `0 Warning(s)`, `0 Error(s)`. If a generated file names a source-backend-only member
(`KryopticSupports…`, `SoftHsmSupports…`), replace it with `_backend.Supports(CKM.…)` or
`_backend.RequireMechanism(CKM.…)` for the mechanism it stood for.

- [ ] **Step 4: Run the whole BouncyHsm set and triage**

Run: `dotnet test --project tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests -c Release --no-build --output Detailed -- --filter-class '*_BouncyHsm' --filter-class '*BouncyHsmQuirkTests' --filter-class '*BouncyHsmServerTests' 2>&1 | tee /tmp/bh-run.log | tail -8`
Expected: `failed: 0`.

For each failure, find its cause before changing anything:
- **Our library's bug** (it marshals wrong, mishandles a spec-compliant reply, or the failure is
  something PR 1 should have fixed): **stop and report it with the test name and the server log
  line.** Do not gate it.
- **BouncyHsm's bug or a documented limitation:** add a gate that follows the Task 4 pattern (a
  fixture flag with an upstream issue link, plus a `*_QuirkStillPresent` test), or use
  `RequireMechanism` when the mechanism isn't advertised. List each new gate in the task report.

To see the server side of a failure, temporarily add
`["Serilog__MinimumLevel__Default"] = "Information"` in the fixture's `BouncyHsmServer.Start` call and
read `OutputTail`. Revert that before committing.

- [ ] **Step 5: Run the full suite with BouncyHsm enabled**

Run: `PKCS11_TEST_EXPECT_BOUNCYHSM=1 dotnet test --project tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests -c Release --no-build 2>&1 | tail -8`
Expected: `failed: 0`, with the convention tests included, which confirms every new class has its collection.

- [ ] **Step 6: Commit**

```bash
git status --short tests/   # expect only new *.BouncyHsm.cs files
git add tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests
git commit -m "test: run the shared test cases against BouncyHsm"
```

---

### Task 6: CI

**Files:**
- Modify: `.github/workflows/ci.yml` (the `build-and-test` matrix at about lines 55–66, the cache steps after "Cache built native libraries", the Build step `env`, and both Test steps)
- Modify: `.github/workflows/code-quality.yml` (the Build `env` and the "Test with coverage" `env`)

- [ ] **Step 1: Matrix flag**

In `build-and-test`'s `matrix.include`, add `bouncyhsm: true` to `ubuntu-latest`, `macos-latest`,
`macos-15-intel`, `windows-latest` (x64) and `windows-latest` with `arch: x86`. Leave it off
`ubuntu-24.04-arm` and `windows-11-arm`. For example:

```yaml
          - os: ubuntu-latest
            bouncyhsm: true
          - os: ubuntu-24.04-arm
            arch: arm64
          - os: macos-latest
            bouncyhsm: true
```

- [ ] **Step 2: Revision output and cache**

In the "Submodule revisions" step's `run`, add:

```bash
          echo "bouncyhsm=$(git -C vendor/bouncyhsm rev-parse HEAD)" >> "$GITHUB_OUTPUT"
```

After "Cache Kryoptic build", add:

```yaml
      # BouncyHsm (every leg with an upstream native client): the published server plus this leg's
      # native client. A hit skips the BuildBouncyHsm target, including its ~3 min cold publish.
      - name: Cache BouncyHsm build
        if: matrix.bouncyhsm
        id: bouncyhsm-cache
        uses: actions/cache@v6.1.0
        with:
          path: tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/bin/Release/net10.0/bouncyhsm
          key: bouncyhsm-${{ runner.os }}-${{ matrix.arch || runner.arch }}-${{ steps.rev.outputs.bouncyhsm }}-${{ hashFiles('build/build-bouncyhsm.sh', 'build/build-bouncyhsm.ps1', 'build/lib/common.sh') }}-v1
```

- [ ] **Step 3: Build env**

Add to the Build step's `env`:

```yaml
          # BouncyHsm's BeforeTarget stages its server and native client under bin/…/bouncyhsm, where
          # BouncyHsmBackendFixture finds them; on a cache hit they are already there.
          BuildBouncyHsm: ${{ matrix.bouncyhsm && steps.bouncyhsm-cache.outputs.cache-hit != 'true' && 'true' || '' }}
```

- [ ] **Step 4: Expect variable on both Test steps**

On the `Test` step (`if: matrix.os != 'ubuntu-latest'`), add:

```yaml
        env:
          PKCS11_TEST_EXPECT_BOUNCYHSM: ${{ matrix.bouncyhsm && '1' || '' }}
```

On "Test (incl. opencryptoki + Kryoptic + NSS)", add `PKCS11_TEST_EXPECT_BOUNCYHSM: '1'` to the
existing `env`. Rename the step to "Test (incl. opencryptoki + Kryoptic + NSS + BouncyHsm)" and add
BouncyHsm to its comment. `sg` only strips `LD_LIBRARY_PATH`, which BouncyHsm doesn't need.

- [ ] **Step 5: code-quality.yml**

Add `BuildBouncyHsm: 'true'` next to `BuildKryoptic: 'true'` in the Build `env`, and
`PKCS11_TEST_EXPECT_BOUNCYHSM: '1'` next to `PKCS11_TEST_EXPECT_KRYOPTIC: '1'` in "Test with coverage".
Update the coverage comment from "Three backends present on Linux" to four, adding BouncyHsm to the
list.

- [ ] **Step 6: Lint the workflows**

Run: `actionlint .github/workflows/ci.yml .github/workflows/code-quality.yml` if it is installed;
otherwise `python3 -c "import sys,yaml; [yaml.safe_load(open(f)) for f in sys.argv[1:]]" .github/workflows/ci.yml .github/workflows/code-quality.yml`.
Expected: no output.

- [ ] **Step 7: Commit, push, and watch CI**

```bash
git add .github/workflows/ci.yml .github/workflows/code-quality.yml
git commit -m "ci: build and run the BouncyHsm backend on every leg with a native client"
git push -u origin feat/bouncyhsm-backend
```

Open the PR as a draft (`gh pr create --draft`) and run `gh pr checks --watch`. Expected:
- every leg is green;
- on the five `bouncyhsm` legs, the test log shows `BouncyHsm_IsAvailable_WhereTheCiLegExpectsIt` passed and `*_BouncyHsm` tests passed, not skipped;
- on the two arm64 legs, the `*_BouncyHsm` tests are skipped.

If a Windows leg fails in `build-bouncyhsm.ps1`, the usual suspects are the toolset mapping and
`OutDir` quoting. Fix them there; don't weaken the leg.

---

### Task 7: Docs and backlog

**Files:**
- Modify: `README.md` (the "Building from source" paragraph, about line 261)
- Modify: `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/README.md` (the collection table at about line 56 and the suffix sentence at about line 62; a new section)
- Modify: `BACKLOG.md` (three entries in `## Low`)

- [ ] **Step 1: README.md**

Replace
`The repository vendors its test backends (\`pkcs11-mock\`, SoftHSMv2, opencryptoki) as git submodules,`
with
`The repository vendors its test backends (\`pkcs11-mock\`, SoftHSMv2, opencryptoki, NSS, Kryoptic, BouncyHsm) as git submodules,`

- [ ] **Step 2: Test README**

In the collection table row, replace `"Mock" \| "SoftHsm" \| "Nss" \| "OpenCryptoki" \| "MemoryLeaks"` with
`"Mock" \| "SoftHsm" \| "Nss" \| "OpenCryptoki" \| "Kryoptic" \| "BouncyHsm" \| "MemoryLeaks"`.
In the suffix sentence, replace `` `*_Mock` / `*_SoftHsm` / `*_Nss` / `*_OpenCryptoki` `` with
`` `*_Mock` / `*_SoftHsm` / `*_Nss` / `*_OpenCryptoki` / `*_Kryoptic` / `*_BouncyHsm` ``.

Append this section:

````markdown
## Running against BouncyHsm locally

BouncyHsm is built from `vendor/bouncyhsm` by an opt-in target (a cold build publishes the server,
about 3 minutes):

```bash
git submodule update --init vendor/bouncyhsm
dotnet test --project tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests -c Release -p:BuildBouncyHsm=true
```

You don't start anything yourself. `BouncyHsmBackendFixture` starts a private, in-memory server on
random loopback ports, creates its token, and kills the server when the run ends. A test host that is
killed hard can leave that server behind. It holds nothing on disk and doesn't affect the next run,
but you may want to end it (`pkill -f BouncyHsm.dll`, or Task Manager on Windows).

Linux and Windows arm64 have no BouncyHsm client upstream, so the BouncyHsm tests skip there.
Known BouncyHsm bugs are gated on `BouncyHsmBackendFixture` (see `BouncyHsmQuirkTests`).
````

- [ ] **Step 3: BACKLOG.md**

Find the highest id: `grep -oE "BL-[0-9]+" BACKLOG.md | sort -t- -k2 -n | tail -1` (it was BL-160 when this plan was written). Append three entries to `## Low`, numbered after it, in the BL-153 format:

```markdown
### [BL-161] Lift the BouncyHsm empty-input gate once harrison314/BouncyHsm#115 ships
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/BouncyHsmBackendFixture.cs` (`BouncyHsmAcceptsEmptyInput`)
- **Problem:** BouncyHsm v2.3.3 refuses zero-length data in `C_Digest`/`C_DigestUpdate`/`C_Verify` (`CKR_ARGUMENTS_BAD`) and `C_Sign` (`CKR_GENERAL_ERROR`), so the EmptyInput SHA-256 and HMAC cases skip on it.
- **Proposed action:** After a `vendor/bouncyhsm` bump that includes the fix, `BouncyHsmQuirkTests.EmptyDigest_QuirkStillPresent`/`EmptyHmac_QuirkStillPresent` fail. Then set the flag to true and delete both tests.
- **Breaks public API?** No
- **Raised by:** BouncyHsm backend

### [BL-162] Lift the BouncyHsm out-of-range-signature gate once harrison314/BouncyHsm#116 ships
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/BouncyHsmBackendFixture.cs` (`BouncyHsmRejectsOutOfRangeSignatures`)
- **Problem:** An RSA-PSS signature at or above the modulus gives `CKR_GENERAL_ERROR` instead of `CKR_SIGNATURE_INVALID`, so `SignVerifyData_Pss_RoundTrips` skips on BouncyHsm.
- **Proposed action:** After the bump, `BouncyHsmQuirkTests.OutOfRangePssSignature_QuirkStillPresent` fails. Then set the flag to true and delete the test.
- **Breaks public API?** No
- **Raised by:** BouncyHsm backend

### [BL-163] Recheck BouncyHsm against harrison314/BouncyHsm#114 after the fix ships
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11SessionCore.Encryption.cs` (the length-query fallback from PR 1)
- **Problem:** BouncyHsm returns `CKR_BUFFER_TOO_SMALL` without the required length. PR 1 made the library tolerate this, so nothing is gated, but the fallback is now the only path BouncyHsm exercises.
- **Proposed action:** Once a bump includes the upstream fix, confirm the RSA encrypt wrappers still pass, then confirm the fallback stays covered by its fake-module unit test.
- **Breaks public API?** No
- **Raised by:** BouncyHsm backend
```

- [ ] **Step 4: Commit and push**

```bash
git add README.md tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/README.md BACKLOG.md
git commit -m "docs: document the BouncyHsm backend and its upstream gates"
git push
```

Wait for green checks, then mark the PR ready (`gh pr ready`).
