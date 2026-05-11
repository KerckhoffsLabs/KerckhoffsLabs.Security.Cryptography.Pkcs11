# PKCS11.NET Phase 0b: Build Scaffolding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Take the post-Phase-0a library (clean build, 118 tests passing, library + Runtime.InteropServices projects only) and add everything needed for distribution and integration testing: MIT LICENSE, README, packaging metadata, `net8.0;net9.0` multi-targeting, a dedicated `Pkcs11.Tests` xUnit project, a `pkcs11-mock` C submodule and its build scripts, an MSBuild target that builds the mock before tests run, one passing end-to-end smoke test against the mock, comprehensive `ObjectAttribute` round-trip tests, a `Pkcs11.Mock` C# wrapper project skeleton, a GitHub Actions CI workflow on Linux + Windows, and a polish pass (XML docs on cast operators, canonicalize three pre-existing `ToCULong` implementations).

**Architecture:** Linear scaffolding pass — each task adds one piece of infrastructure or fills one gap deferred from Phase 0a's final code review. Build stays green throughout (no design-gap red phase like 0a had). Final task verifies `dotnet pack` produces a valid `.nupkg` and runs the full exit checklist.

**Tech Stack:** C# 12 / .NET 8 + .NET 9 (multi-targeted), xUnit 2.9, `Microsoft.DotNet.XUnitExtensions` (`[SkippableFact]`), `Microsoft.SourceLink.GitHub`, `pkcs11-mock` (C, built via `make`+`gcc`), GitHub Actions, MIT license.

**Reference specs:**
- Parent: `docs/superpowers/specs/2026-05-11-pkcs11-completion-design.md`
- Phase 0a sub-spec: `docs/superpowers/specs/2026-05-11-utility-class-redesign-design.md`
- Phase 0a plan (executed): `docs/superpowers/plans/2026-05-11-phase0a-utility-class-redesign.md`

**Pre-flight (read before T1):**
Phase 0a is complete and merged to `main` at `877ca64`, tagged `phase-0a-complete`. You are on branch `phase-0b-build-scaffolding`. The Phase 0a final code review left a small punch list of deferred items; this plan absorbs them as T7 (ObjectAttribute round-trip tests with `InternalsVisibleTo`) and T10 (XML docs on cast operators, canonicalize three `ToCULong` implementations).

---

## File Structure

After this phase, the repo looks like:

```
PKCS11.NET/
├── .github/workflows/ci.yml                                            [CREATE]
├── .gitmodules                                                         [CREATE — via `git submodule add`]
├── LICENSE                                                             [CREATE]
├── README.md                                                           [CREATE]
├── CLAUDE.md                                                           [unchanged]
├── build/
│   ├── build-pkcs11-mock.sh                                            [CREATE]
│   └── build-pkcs11-mock.ps1                                           [CREATE]
├── docs/superpowers/{specs,plans}/                                     [unchanged from 0a]
├── third-party/pkcs11-mock/                                            [CREATE — submodule]
└── src/
    ├── src.sln                                                         [MODIFY — add 2 new projects]
    ├── KerckhoffsLabs.Runtime.InteropServices/                         [unchanged]
    │   └── NativeCULong.cs                                             [MODIFY — XML docs on cast operators]
    ├── KerckhoffsLabs.Runtime.InteropServices.UnitTests/               [unchanged]
    ├── KerckhoffsLabs.Security.Cryptography.Pkcs11/
    │   ├── KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj          [MODIFY — multi-target + packaging metadata]
    │   ├── Common/{CKA,CKC,CKM}.cs                                     [MODIFY — canonicalize ToCULong]
    │   └── (other files unchanged)
    ├── KerckhoffsLabs.Security.Cryptography.Pkcs11.Mock/
    │   ├── KerckhoffsLabs.Security.Cryptography.Pkcs11.Mock.csproj     [CREATE — skeleton]
    │   └── AssemblyInfo.cs                                             [CREATE]
    └── KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/
        ├── KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj    [CREATE]
        ├── Settings.cs                                                 [CREATE]
        ├── HighLevel/SmokeTests.cs                                     [CREATE]
        └── HighLevel/ObjectAttributeTests.cs                           [CREATE]
```

**Deleted in this phase:**
- `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.slnx` — stray solution file that only references the main library.

**Deferred to Phase 1 onward:**
- `IPkcs11Backend`, `MockBackendFixture`, `SoftHsmBackendFixture` — backend abstraction used by Phase 1+'s session-level tests. Phase 0b's smoke test loads the mock directly without a fixture.
- The `Pkcs11.Mock` project's actual content (C# wrappers for pkcs11-mock's diagnostic extension functions). 0b ships the skeleton; Phase 4 populates it.

---

## Task 1: MIT LICENSE + README

Quick wins; no dependencies on any other task.

**Files:**
- Create: `LICENSE`
- Create: `README.md`

- [ ] **Step 1: Create the MIT LICENSE file at repo root**

Create `/home/alexandre/dev/PKCS11.NET/LICENSE`:

```
MIT License

Copyright (c) 2026 Alexandre Laroche

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 2: Create a minimal README**

Create `/home/alexandre/dev/PKCS11.NET/README.md`:

```markdown
# PKCS11.NET

Modern, secure-by-default PKCS#11 v3.1 interop for .NET.

> **Status:** Phase 0b (build scaffolding). API surface and full test
> coverage land in subsequent phases — see `docs/superpowers/specs/` for
> the design and `docs/superpowers/plans/` for the phased plans.

## Building

```bash
git clone --recurse-submodules <repo-url>
cd PKCS11.NET
dotnet build src/src.sln
```

If you already cloned without `--recurse-submodules`:

```bash
git submodule update --init --recursive
```

## Running tests

```bash
dotnet test src/src.sln
```

Tests load `pkcs11-mock` (built from `third-party/pkcs11-mock` as a
submodule). The build is triggered automatically by an MSBuild target
in the test project. On Linux/macOS this requires `make` and `gcc`; on
Windows it requires `pwsh` and MSVC build tools.

## License

MIT — see `LICENSE`.
```

- [ ] **Step 3: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add LICENSE README.md
git -C /home/alexandre/dev/PKCS11.NET commit -m "docs: add MIT LICENSE and minimal README

Phase 0b scaffolding. README documents the build + test flow including
the pkcs11-mock submodule and the MSBuild integration that builds it."
```

---

## Task 2: Multi-target + packaging metadata + delete stray .slnx

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`
- Delete: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.slnx`

- [ ] **Step 1: Replace the main library csproj**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`. The current content multi-targets net9.0 only with `CheckForOverflowUnderflow=true` and a ProjectReference. Replace the entire file with:

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFrameworks>net8.0;net9.0</TargetFrameworks>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
    <EnableNETAnalyzers>true</EnableNETAnalyzers>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <RuntimeIdentifiers>win-x86;win-x64;linux-x64;linux-arm64;osx-x64;osx-arm64</RuntimeIdentifiers>
    <LangVersion>latest</LangVersion>
    <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
  </PropertyGroup>

  <PropertyGroup>
    <PackageId>KerckhoffsLabs.Security.Cryptography.Pkcs11</PackageId>
    <Version>0.1.0</Version>
    <Authors>Alexandre Laroche</Authors>
    <Description>Modern, secure-by-default PKCS#11 v3.1 interop for .NET.</Description>
    <PackageLicenseExpression>MIT</PackageLicenseExpression>
    <PackageReadmeFile>README.md</PackageReadmeFile>
    <RepositoryType>git</RepositoryType>
    <PublishRepositoryUrl>true</PublishRepositoryUrl>
    <EmbedUntrackedSources>true</EmbedUntrackedSources>
    <ContinuousIntegrationBuild Condition="'$(CI)' == 'true'">true</ContinuousIntegrationBuild>
    <Deterministic>true</Deterministic>
    <GenerateDocumentationFile>true</GenerateDocumentationFile>
    <IncludeSymbols>true</IncludeSymbols>
    <SymbolPackageFormat>snupkg</SymbolPackageFormat>
    <!-- Tolerate missing XML docs for now; tightened in T10. -->
    <NoWarn>$(NoWarn);CS1591</NoWarn>
  </PropertyGroup>

  <PropertyGroup Condition="'$(TargetPlatformIdentifier)' == 'windows'">
    <DefineConstants>WINDOWS</DefineConstants>
  </PropertyGroup>

  <ItemGroup>
    <None Include="..\..\README.md" Pack="true" PackagePath="\" />
  </ItemGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.SourceLink.GitHub" Version="8.0.0" PrivateAssets="all" />
  </ItemGroup>

  <ItemGroup>
    <ProjectReference Include="..\KerckhoffsLabs.Runtime.InteropServices\KerckhoffsLabs.Runtime.InteropServices.csproj" />
  </ItemGroup>

</Project>
```

- [ ] **Step 2: Restore and build for both TFMs**

```bash
cd /home/alexandre/dev/PKCS11.NET
dotnet restore src/src.sln
dotnet build src/src.sln -c Release 2>&1 | tail -10
```

Expected: `0 Error(s)`. Both `net8.0` and `net9.0` outputs land in `bin/Release/`. If `net8.0` produces an error (likely a missing API), check the call site:
- If the API is `net9.0`-only, guard with `#if NET9_0_OR_GREATER` or replace with a `net8.0`-compatible equivalent.
- At time of writing the library uses only APIs available in `net8.0` (`ArgumentNullException.ThrowIfNull` since .NET 6, `ObjectDisposedException.ThrowIf` since .NET 7, `Enum.IsDefined<T>(T)` since .NET 5, `BinaryPrimitives.WriteUInt64LittleEndian` since .NET 5). No conditional compilation expected.

- [ ] **Step 3: Run tests to confirm nothing regressed**

```bash
dotnet test src/src.sln 2>&1 | tail -5
```

Expected: 118 passed, 1 skipped, 0 failed.

- [ ] **Step 4: Delete the stray `.slnx` file**

```bash
git -C /home/alexandre/dev/PKCS11.NET rm src/KerckhoffsLabs.Security.Cryptography.Pkcs11.slnx
```

The canonical solution is `src/src.sln`. The `.slnx` only referenced the main library and was confusing tooling.

- [ ] **Step 5: Refresh the lock file**

The new `Microsoft.SourceLink.GitHub` PackageReference changes the dependency tree. Re-restore and confirm the lock file is updated:

```bash
dotnet restore src/src.sln
grep -c "Microsoft.SourceLink.GitHub" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/packages.lock.json
```

Expected: `>= 1`.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj src/KerckhoffsLabs.Security.Cryptography.Pkcs11/packages.lock.json
git -C /home/alexandre/dev/PKCS11.NET commit -m "chore(pack): multi-target net8.0;net9.0 + packaging metadata

Adds:
- TargetFrameworks net8.0;net9.0
- NuGet metadata (PackageId, Version 0.1.0, Authors, Description,
  PackageLicenseExpression MIT, PackageReadmeFile)
- Microsoft.SourceLink.GitHub for source-link symbols
- Deterministic + EmbedUntrackedSources + symbol package (.snupkg)
- RuntimeIdentifiers for the platforms we expect to support

Also deletes the stray .slnx that only referenced the main library;
src/src.sln is the canonical solution."
```

---

## Task 3: Scaffold the Pkcs11.Tests xUnit project

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Settings.cs`
- Modify: `src/src.sln`

- [ ] **Step 1: Create the test project csproj**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>net9.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <IsPackable>false</IsPackable>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
    <EnableNETAnalyzers>true</EnableNETAnalyzers>
    <LangVersion>latest</LangVersion>
  </PropertyGroup>

  <ItemGroup>
    <ProjectReference Include="..\KerckhoffsLabs.Security.Cryptography.Pkcs11\KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj" />
  </ItemGroup>

  <ItemGroup>
    <PackageReference Include="coverlet.collector" Version="6.0.4" />
    <PackageReference Include="Microsoft.DotNet.XUnitExtensions" Version="11.0.0-beta.25605.110" />
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="18.0.1" />
    <PackageReference Include="xunit" Version="2.9.3" />
    <PackageReference Include="xunit.runner.visualstudio" Version="3.1.5" />
  </ItemGroup>

  <ItemGroup>
    <Using Include="Xunit" />
  </ItemGroup>

</Project>
```

(Package versions match the existing `KerckhoffsLabs.Runtime.InteropServices.UnitTests` project so the lock-file solver has nothing new to argue with.)

- [ ] **Step 2: Create Settings.cs**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Settings.cs`:

```csharp
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

/// <summary>
/// Per-test-run configuration. All values are environment-driven so
/// developers can point the suite at any PKCS#11 module.
/// </summary>
public static class Settings
{
    /// <summary>
    /// Path to the pkcs11-mock shared library. Falls back to a path next
    /// to the test assembly when the env var is unset.
    /// </summary>
    public static string MockLibraryPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_MOCK_LIBRARY")
        ?? DefaultMockPath();

    /// <summary>
    /// Optional path to a SoftHSM2 PKCS#11 library. Tests that require it
    /// skip themselves when this resolves to null.
    /// </summary>
    public static string? SoftHsmLibraryPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_SOFTHSM_LIBRARY");

    /// <summary>
    /// Normal-user PIN for fixture tokens. Matches the pkcs11-mock default.
    /// Set PKCS11_TEST_USER_PIN to override (e.g. for SoftHSM2).
    /// </summary>
    public static string UserPin =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_USER_PIN") ?? "11111111";

    /// <summary>
    /// SO PIN for fixture tokens. Matches the pkcs11-mock default.
    /// </summary>
    public static string SoPin =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_SO_PIN") ?? "11111111";

    private static string DefaultMockPath()
    {
        string baseDir = AppContext.BaseDirectory;
        string rid =
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "win-x64" :
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                ? (RuntimeInformation.OSArchitecture == Architecture.Arm64 ? "osx-arm64" : "osx-x64")
            : RuntimeInformation.OSArchitecture == Architecture.Arm64 ? "linux-arm64"
            : "linux-x64";

        string fileName =
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "pkcs11-mock.dll" :
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "pkcs11-mock.dylib"
            : "pkcs11-mock.so";

        return Path.Combine(baseDir, "runtimes", rid, "native", fileName);
    }
}
```

- [ ] **Step 3: Add the test project to the solution**

```bash
cd /home/alexandre/dev/PKCS11.NET/src
dotnet sln src.sln add KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj
```

Expected output: `Project ... added to the solution.`

- [ ] **Step 4: Build the new project**

```bash
cd /home/alexandre/dev/PKCS11.NET
dotnet build src/src.sln 2>&1 | tail -5
```

Expected: `0 Error(s)`. The test project has no tests yet — that's fine; it just needs to compile.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/src.sln src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/
git -C /home/alexandre/dev/PKCS11.NET commit -m "test: scaffold Pkcs11.Tests xUnit project with env-driven Settings

Empty xUnit project wired into src.sln. Settings.cs resolves the
pkcs11-mock library path based on RuntimeInformation, with env-var
overrides for CI and developer environments. No tests yet — added in
T5 and T7."
```

---

## Task 4: Add pkcs11-mock as a git submodule

**Files:**
- Create: `.gitmodules` (auto-generated)
- Create: `third-party/pkcs11-mock/` (submodule)

- [ ] **Step 1: Add the submodule**

```bash
git -C /home/alexandre/dev/PKCS11.NET submodule add https://github.com/Pkcs11Interop/pkcs11-mock.git third-party/pkcs11-mock
```

Expected: `.gitmodules` is created, `third-party/pkcs11-mock/` is populated, both appear in `git status` as staged.

- [ ] **Step 2: Pin to a known release tag**

Pin to a specific release to make the build reproducible. Check the latest tag:

```bash
gh release list -R Pkcs11Interop/pkcs11-mock --limit 1
```

At time of writing the latest release is `v8.0.1`. Pin to it (substitute the actual current latest if different):

```bash
cd /home/alexandre/dev/PKCS11.NET/third-party/pkcs11-mock
git fetch --tags
git checkout v8.0.1
cd /home/alexandre/dev/PKCS11.NET
```

Re-stage the submodule pointer:

```bash
git -C /home/alexandre/dev/PKCS11.NET add third-party/pkcs11-mock
```

- [ ] **Step 3: Verify the submodule layout**

```bash
ls /home/alexandre/dev/PKCS11.NET/third-party/pkcs11-mock/build/
```

Expected: directories like `linux/`, `macosx/`, `windows/` each with a build script. If the directory structure differs:

```bash
ls /home/alexandre/dev/PKCS11.NET/third-party/pkcs11-mock/
```

If anything else looks unexpected, report it before continuing — Task 5's scripts adapt to the discovered layout.

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET commit -m "build: vendor pkcs11-mock as submodule pinned to v8.0.1

The mock PKCS#11 module is used by the test suite to exercise the full
interop stack without requiring a real HSM or SoftHSM2. Pinned to a
release tag for reproducibility."
```

(Substitute the actual tag name in the message if it differs from `v8.0.1`.)

---

## Task 5: Write the mock build scripts

**Files:**
- Create: `build/build-pkcs11-mock.sh`
- Create: `build/build-pkcs11-mock.ps1`

- [ ] **Step 1: Write the Linux/macOS build script**

Create `/home/alexandre/dev/PKCS11.NET/build/build-pkcs11-mock.sh`:

```bash
#!/usr/bin/env bash
# Builds pkcs11-mock and copies the resulting shared library into the
# Pkcs11.Tests output directory under the appropriate runtime identifier.
#
# Usage: build-pkcs11-mock.sh <test-output-dir>
#   <test-output-dir> e.g. src/.../Pkcs11.Tests/bin/Debug/net9.0
#
# Idempotent: if the target binary already exists and is newer than the
# submodule HEAD commit, it is reused.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <test-output-dir>" >&2
  exit 2
fi

OUT_BASE="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOCK_DIR="${REPO_ROOT}/third-party/pkcs11-mock"

if [[ ! -d "${MOCK_DIR}" ]]; then
  echo "pkcs11-mock submodule missing at ${MOCK_DIR}." >&2
  echo "Run: git submodule update --init --recursive" >&2
  exit 1
fi

UNAME_S="$(uname -s)"
case "${UNAME_S}" in
  Linux)
    RID="linux-$(uname -m | sed -e 's/x86_64/x64/' -e 's/aarch64/arm64/')"
    LIB_EXT="so"
    ;;
  Darwin)
    RID="osx-$(uname -m | sed -e 's/x86_64/x64/' -e 's/arm64/arm64/')"
    LIB_EXT="dylib"
    ;;
  *)
    echo "unsupported OS: ${UNAME_S}" >&2
    exit 1
    ;;
esac

DEST_DIR="${OUT_BASE}/runtimes/${RID}/native"
DEST_FILE="${DEST_DIR}/pkcs11-mock.${LIB_EXT}"

mkdir -p "${DEST_DIR}"

# Skip rebuild if dest is newer than the mock submodule HEAD.
MOCK_HEAD_TS="$(git -C "${MOCK_DIR}" log -1 --format=%ct HEAD 2>/dev/null || echo 0)"
DEST_TS=0
if [[ -f "${DEST_FILE}" ]]; then
  DEST_TS=$(stat -c %Y "${DEST_FILE}" 2>/dev/null || stat -f %m "${DEST_FILE}" 2>/dev/null || echo 0)
fi
if (( DEST_TS > MOCK_HEAD_TS )); then
  echo "pkcs11-mock up to date at ${DEST_FILE}"
  exit 0
fi

echo "Building pkcs11-mock for ${RID}..."

BUILD_SUBDIR=""
case "${UNAME_S}" in
  Linux)   BUILD_SUBDIR="build/linux" ;;
  Darwin)  BUILD_SUBDIR="build/macosx" ;;
esac

# Upstream's build.sh tries to build both 32-bit and 64-bit which often
# fails without gcc-multilib. Invoke `make` directly to build only the
# host architecture.
pushd "${MOCK_DIR}/${BUILD_SUBDIR}" >/dev/null
make clean >/dev/null 2>&1 || true
make
popd >/dev/null

# Locate the produced library (may be named pkcs11-mock-x64.so or similar).
SRC_LIB="$(find "${MOCK_DIR}/${BUILD_SUBDIR}" -maxdepth 2 -name "pkcs11-mock*.${LIB_EXT}" -type f | head -n1)"
if [[ -z "${SRC_LIB}" ]]; then
  echo "build succeeded but no .${LIB_EXT} found under ${MOCK_DIR}/${BUILD_SUBDIR}" >&2
  exit 1
fi

cp "${SRC_LIB}" "${DEST_FILE}"
echo "Installed ${DEST_FILE}"
```

Make it executable:

```bash
chmod +x /home/alexandre/dev/PKCS11.NET/build/build-pkcs11-mock.sh
```

- [ ] **Step 2: Write the Windows build script**

Create `/home/alexandre/dev/PKCS11.NET/build/build-pkcs11-mock.ps1`:

```powershell
# Builds pkcs11-mock and copies the resulting DLL into the Pkcs11.Tests
# output directory under runtimes/win-x64/native.
#
# Usage: pwsh build-pkcs11-mock.ps1 -TestOutputDir <path>

param(
    [Parameter(Mandatory=$true)]
    [string]$TestOutputDir
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$mockDir  = Join-Path $repoRoot 'third-party\pkcs11-mock'

if (-not (Test-Path $mockDir)) {
    Write-Error "pkcs11-mock submodule missing at $mockDir. Run: git submodule update --init --recursive"
}

$rid = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'win-arm64' } else { 'win-x64' }
$destDir  = Join-Path $TestOutputDir "runtimes\$rid\native"
$destFile = Join-Path $destDir 'pkcs11-mock.dll'

New-Item -ItemType Directory -Force -Path $destDir | Out-Null

# Skip rebuild if dest is newer than mock submodule HEAD.
$mockHeadTs = (& git -C $mockDir log -1 --format=%ct HEAD).Trim()
if (Test-Path $destFile) {
    $destTs = [int][double]::Parse((Get-Item $destFile).LastWriteTimeUtc.Subtract([datetime]'1970-01-01').TotalSeconds)
    if ($destTs -gt [int]$mockHeadTs) {
        Write-Host "pkcs11-mock up to date at $destFile"
        return
    }
}

Write-Host "Building pkcs11-mock for $rid..."

Push-Location (Join-Path $mockDir 'build\windows')
try {
    cmd /c 'build.bat'
} finally {
    Pop-Location
}

# Upstream produces pkcs11-mock-x64.dll / pkcs11-mock-x86.dll.
$srcLib = Get-ChildItem -Path (Join-Path $mockDir 'build\windows') -Filter 'pkcs11-mock*.dll' -Recurse |
          Where-Object { $_.Name -match 'x64' } |
          Select-Object -First 1

if (-not $srcLib) {
    Write-Error "build succeeded but no x64 .dll found under $mockDir\build\windows"
}

Copy-Item -Path $srcLib.FullName -Destination $destFile -Force
Write-Host "Installed $destFile"
```

- [ ] **Step 3: Smoke-test the Linux script manually**

```bash
build/build-pkcs11-mock.sh /tmp/pkcs11-mock-test
```

Expected:
- Build output from `make`.
- Final line: `Installed /tmp/pkcs11-mock-test/runtimes/linux-x64/native/pkcs11-mock.so` (or `linux-arm64` on ARM hosts).

Verify:

```bash
ls -la /tmp/pkcs11-mock-test/runtimes/linux-x64/native/
file /tmp/pkcs11-mock-test/runtimes/linux-x64/native/pkcs11-mock.so
```

Expected: non-empty `.so` ELF shared library. Clean up: `rm -rf /tmp/pkcs11-mock-test`.

If `make` fails with "command not found", install build deps: `sudo apt-get install build-essential` (Debian/Ubuntu).

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add build/build-pkcs11-mock.sh build/build-pkcs11-mock.ps1
git -C /home/alexandre/dev/PKCS11.NET commit -m "build: add pkcs11-mock build scripts (sh + ps1)

Builds the vendored pkcs11-mock submodule and copies the resulting
shared library into a runtime-identifier-keyed path so the test runner
can NativeLibrary.Load(\"pkcs11-mock\") portably. Idempotent: skips
rebuild when the output is newer than the submodule HEAD."
```

---

## Task 6: TDD the mock smoke test + MSBuild integration

We write the test first, watch it fail (no mock binary in the output dir yet), wire the MSBuild target to invoke the build script, then watch it pass. This is the first end-to-end exercise of the P/Invoke stack on the new test project.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/SmokeTests.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj`

- [ ] **Step 1: Write the failing smoke test**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/SmokeTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

/// <summary>
/// End-to-end smoke check that the library loads pkcs11-mock and
/// completes a minimal Cryptoki lifecycle: C_Initialize → C_GetInfo →
/// C_Finalize.
///
/// This test is the bridge that proves the build, the marshalling,
/// the project reference, and the mock-binary-copy MSBuild target
/// are all wired correctly. Every later phase relies on it.
/// </summary>
public class SmokeTests
{
    [Fact]
    public void LoadInitializeFinalize_OnMock_Succeeds()
    {
        string libPath = Settings.MockLibraryPath;

        Assert.True(
            File.Exists(libPath),
            $"pkcs11-mock library not found at '{libPath}'. " +
            $"Ensure the submodule is initialized and the build script has run. " +
            $"From repo root: build/build-pkcs11-mock.sh <test-output-dir>");

        using var library = new Pkcs11Library(libPath);

        LibraryInfo info = library.GetInfo();

        // pkcs11-mock identifies itself with the string "Pkcs11Interop Project".
        // We assert manufacturer and cryptoki version are non-empty rather than
        // checking exact strings, so a future mock-version bump doesn't break
        // us spuriously.
        Assert.False(string.IsNullOrWhiteSpace(info.ManufacturerId));
        Assert.False(string.IsNullOrWhiteSpace(info.CryptokiVersion));
    }
}
```

- [ ] **Step 2: Run the test, expect failure at the file-existence assertion**

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~SmokeTests" 2>&1 | tail -20
```

Expected: 1 test, 1 failure. Failure message includes `"pkcs11-mock library not found at '...runtimes/linux-x64/native/pkcs11-mock.so'"`.

(If the test passes here, a stale binary was left somewhere — investigate and clean before continuing. The intent is to prove the MSBuild target in Step 3 is what wires this up.)

- [ ] **Step 3: Wire the MSBuild target that builds the mock before tests**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj`. Insert this `<Target>` block directly above the closing `</Project>`:

```xml
  <Target Name="BuildPkcs11Mock" BeforeTargets="PrepareForBuild" Condition="'$(SkipPkcs11MockBuild)' != 'true'">
    <PropertyGroup>
      <_MockOutputDir>$(MSBuildProjectDirectory)\bin\$(Configuration)\$(TargetFramework)</_MockOutputDir>
    </PropertyGroup>
    <Exec
      Condition="!$([MSBuild]::IsOSPlatform('Windows'))"
      Command="bash &quot;$(MSBuildProjectDirectory)/../../build/build-pkcs11-mock.sh&quot; &quot;$(_MockOutputDir)&quot;"
      IgnoreStandardErrorWarningFormat="true" />
    <Exec
      Condition="$([MSBuild]::IsOSPlatform('Windows'))"
      Command="pwsh -NoProfile -ExecutionPolicy Bypass -File &quot;$(MSBuildProjectDirectory)\..\..\build\build-pkcs11-mock.ps1&quot; -TestOutputDir &quot;$(_MockOutputDir)&quot;"
      IgnoreStandardErrorWarningFormat="true" />
  </Target>
```

- [ ] **Step 4: Rebuild and re-run the test**

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~SmokeTests" 2>&1 | tail -10
```

Expected: `Passed: 1, Failed: 0`.

If the test still fails with "library not found":
- Confirm the MSBuild target ran (look for `Building pkcs11-mock...` in the full build output).
- Confirm the binary landed where `Settings.MockLibraryPath` resolves: `ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/bin/Debug/net9.0/runtimes/`.

If the test fails with a marshalling / P-Invoke error (`DllNotFoundException`, `EntryPointNotFoundException`), that's a real interop bug, not a build-wiring issue. Diagnose.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/SmokeTests.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj
git -C /home/alexandre/dev/PKCS11.NET commit -m "test: add pkcs11-mock smoke test + MSBuild wiring

First end-to-end test of the interop stack against the mock. Loads
pkcs11-mock through Pkcs11Library, calls C_Initialize / C_GetInfo /
C_Finalize, asserts basic LibraryInfo content. An MSBuild target
before PrepareForBuild invokes the platform-specific mock build
script so the binary is in place when tests run."
```

---

## Task 7: InternalsVisibleTo + comprehensive ObjectAttribute round-trip tests

This task closes a Phase 0a final-review gap: comprehensive coverage of every typed `ObjectAttribute` constructor + read-back, plus a regression test for the `CannotBeRead` sentinel on Windows.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ObjectAttributeTests.cs`

- [ ] **Step 1: Expose internals to the test project**

The `ObjectAttribute(CK_ATTRIBUTE)` constructor is internal. The test for `CannotBeRead` needs to construct an ObjectAttribute with `valueLen = NativeCULong.MaxValue` directly. Add an `InternalsVisibleTo` entry to the main library csproj.

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`. Add this `<ItemGroup>` above the closing `</Project>`:

```xml
  <ItemGroup>
    <InternalsVisibleTo Include="KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests" />
  </ItemGroup>
```

(SDK-style MSBuild supports `<InternalsVisibleTo>` as an MSBuild item — emits an assembly-level attribute at build time. No separate AssemblyInfo file needed.)

- [ ] **Step 2: Write the comprehensive round-trip tests**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ObjectAttributeTests.cs`:

```csharp
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

/// <summary>
/// Comprehensive round-trip tests for every typed ObjectAttribute
/// constructor + the corresponding GetValueAs* reader. Closes the
/// Phase 0a final-review gap on coverage.
///
/// Lifecycle invariants (Dispose, post-dispose access, CannotBeRead)
/// are also covered.
/// </summary>
public class ObjectAttributeTests
{
    // ---- Round-trip per typed constructor -----------------------------------

    [Fact]
    public void RoundTrip_Bool_True()
    {
        using var attr = new ObjectAttribute(CKA.CKA_TOKEN, true);
        Assert.Equal((ulong)CKA.CKA_TOKEN, attr.Type);
        Assert.Equal(1, attr.ValueLength);
        Assert.True(attr.GetValueAsBool());
    }

    [Fact]
    public void RoundTrip_Bool_False()
    {
        using var attr = new ObjectAttribute(CKA.CKA_TOKEN, false);
        Assert.False(attr.GetValueAsBool());
        Assert.Equal(1, attr.ValueLength);
    }

    [Fact]
    public void RoundTrip_Ulong()
    {
        ulong source = 0x123456789ABCDEF0UL;
        using var attr = new ObjectAttribute(CKA.CKA_VALUE_LEN, source);
        // On Windows, NativeCULong is 32-bit — only the low 32 bits are stored
        // and the test platform is Linux-x64 (64-bit storage). Assert what the
        // platform supports.
        ulong roundtripped = attr.GetValueAsUlong();
        if (UnmanagedMemory.NativeULongSize == 4)
            Assert.Equal(source & 0xFFFFFFFFUL, roundtripped);
        else
            Assert.Equal(source, roundtripped);
    }

    [Fact]
    public void RoundTrip_CKO_Enum() // ObjectAttribute(CKA, CKO) overload
    {
        using var attr = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        Assert.Equal((ulong)CKO.CKO_PRIVATE_KEY, attr.GetValueAsUlong());
    }

    [Fact]
    public void RoundTrip_CKK_Enum()
    {
        using var attr = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        Assert.Equal((ulong)CKK.CKK_AES, attr.GetValueAsUlong());
    }

    [Fact]
    public void RoundTrip_CKC_Enum()
    {
        using var attr = new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509);
        Assert.Equal((ulong)CKC.CKC_X_509, attr.GetValueAsUlong());
    }

    [Fact]
    public void RoundTrip_String_Utf8NoTerminator()
    {
        const string source = "signing-key-α";  // includes non-ASCII to exercise UTF-8
        using var attr = new ObjectAttribute(CKA.CKA_LABEL, source);
        Assert.Equal(source, attr.GetValueAsString());
        // No trailing NUL byte:
        Assert.Equal(System.Text.Encoding.UTF8.GetByteCount(source), attr.ValueLength);
    }

    [Fact]
    public void RoundTrip_String_Empty()
    {
        using var attr = new ObjectAttribute(CKA.CKA_LABEL, string.Empty);
        Assert.Equal(string.Empty, attr.GetValueAsString());
        Assert.Equal(0, attr.ValueLength);
    }

    [Fact]
    public void RoundTrip_ByteArray()
    {
        byte[] source = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
        using var attr = new ObjectAttribute(CKA.CKA_VALUE, source);
        Assert.Equal(source, attr.GetValueAsByteArray());
        Assert.Equal(source.Length, attr.ValueLength);
    }

    [Fact]
    public void RoundTrip_ByteArray_Empty()
    {
        using var attr = new ObjectAttribute(CKA.CKA_VALUE, Array.Empty<byte>());
        Assert.Equal(Array.Empty<byte>(), attr.GetValueAsByteArray());
        Assert.Equal(0, attr.ValueLength);
    }

    [Fact]
    public void RoundTrip_ReadOnlySpan_MatchesByteArray()
    {
        byte[] source = { 1, 2, 3, 4, 5 };
        using var fromArray = new ObjectAttribute(CKA.CKA_VALUE, source);
        using var fromSpan  = new ObjectAttribute(CKA.CKA_VALUE, (ReadOnlySpan<byte>)source);
        Assert.Equal(fromArray.GetValueAsByteArray(), fromSpan.GetValueAsByteArray());
    }

    [Fact]
    public void RoundTrip_DateTime()
    {
        var source = new DateTime(2026, 12, 31, 0, 0, 0, DateTimeKind.Utc);
        using var attr = new ObjectAttribute(CKA.CKA_START_DATE, source);
        DateTime? roundtripped = attr.GetValueAsDateTime();
        Assert.NotNull(roundtripped);
        // CK_DATE encodes date only; time component is dropped.
        Assert.Equal(source.Date, roundtripped.Value.Date);
        Assert.Equal(DateTimeKind.Utc, roundtripped.Value.Kind);
    }

    [Fact]
    public void RoundTrip_ListOfUlong()
    {
        var source = new List<ulong> { 1, 2, 3, 100 };
        using var attr = new ObjectAttribute(CKA.CKA_ALLOWED_MECHANISMS, source);
        ulong[] roundtripped = attr.GetValueAsUlongArray();
        Assert.Equal(source.Count, roundtripped.Length);
        for (int i = 0; i < source.Count; i++)
            Assert.Equal(source[i], roundtripped[i]);
    }

    [Fact]
    public void RoundTrip_ListOfCkm()
    {
        var source = new List<CKM> { CKM.CKM_AES_GCM, CKM.CKM_RSA_PKCS_OAEP };
        using var attr = new ObjectAttribute(CKA.CKA_ALLOWED_MECHANISMS, source);
        CKM[] roundtripped = attr.GetValueAsCkmArray();
        Assert.Equal(source.Count, roundtripped.Length);
        for (int i = 0; i < source.Count; i++)
            Assert.Equal(source[i], roundtripped[i]);
    }

    [Fact]
    public void RoundTrip_NestedAttributeList()
    {
        using var child1 = new ObjectAttribute(CKA.CKA_LABEL, "wrapped");
        using var child2 = new ObjectAttribute(CKA.CKA_TOKEN, true);
        var children = new List<ObjectAttribute> { child1, child2 };

        using var parent = new ObjectAttribute(CKA.CKA_WRAP_TEMPLATE, children);
        ObjectAttribute[] readBack = parent.GetValueAsAttributeArray();
        try
        {
            Assert.Equal(2, readBack.Length);
            // Each readBack[i] wraps a fresh CK_ATTRIBUTE pointing at the
            // SAME unmanaged buffer as parent's child slot — read but don't
            // Dispose them (their `value` pointer aliases the parent's
            // contiguous buffer, and parent owns lifetime).
            Assert.Equal((ulong)CKA.CKA_LABEL, readBack[0].Type);
            Assert.Equal((ulong)CKA.CKA_TOKEN, readBack[1].Type);
        }
        finally
        {
            // Detach without freeing (children alias the parent's buffer).
            // Reading children's own bytes would be unsafe; we only verified
            // the type field, which lives in the inline struct, not the value.
        }
    }

    // ---- CopyValueTo --------------------------------------------------------

    [Fact]
    public void CopyValueTo_WritesExactBytes()
    {
        byte[] source = { 9, 8, 7 };
        using var attr = new ObjectAttribute(CKA.CKA_VALUE, source);
        Span<byte> dest = stackalloc byte[8];
        int written = attr.CopyValueTo(dest);
        Assert.Equal(source.Length, written);
        Assert.Equal(source, dest[..written].ToArray());
    }

    [Fact]
    public void CopyValueTo_ThrowsWhenDestinationTooSmall()
    {
        using var attr = new ObjectAttribute(CKA.CKA_VALUE, new byte[] { 1, 2, 3, 4 });
        byte[] tooSmall = new byte[2];
        Assert.Throws<ArgumentException>(() => attr.CopyValueTo(tooSmall));
    }

    // ---- Lifetime / Dispose -------------------------------------------------

    [Fact]
    public void DoubleDisposeIsSafe()
    {
        var attr = new ObjectAttribute(CKA.CKA_VALUE, new byte[] { 1, 2, 3 });
        attr.Dispose();
        attr.Dispose(); // must not throw
    }

    [Fact]
    public void PostDisposeAccess_Throws()
    {
        var attr = new ObjectAttribute(CKA.CKA_VALUE, new byte[] { 1, 2, 3 });
        attr.Dispose();
        Assert.Throws<ObjectDisposedException>(() => attr.Type);
        Assert.Throws<ObjectDisposedException>(() => attr.ValueLength);
        Assert.Throws<ObjectDisposedException>(() => attr.GetValueAsByteArray());
        Assert.Throws<ObjectDisposedException>(() => attr.CopyValueTo(new byte[16]));
    }

    // ---- CannotBeRead sentinel (regression for the 32-bit/64-bit Windows
    //      bug caught in Phase 0a final review) ---------------------------

    [Fact]
    public void CannotBeRead_DetectsSentinel()
    {
        // Construct a CK_ATTRIBUTE manually with the sentinel valueLen.
        // The PKCS#11 spec sentinel: valueLen = -1 cast to CK_LONG, i.e.
        // the all-bits-set value of CK_ULONG (= NativeCULong.MaxValue).
        var raw = new CK_ATTRIBUTE
        {
            type = (NativeCULong)(ulong)CKA.CKA_VALUE,
            value = IntPtr.Zero,
            valueLen = NativeCULong.MaxValue,
        };
        using var attr = new ObjectAttribute(raw);

        Assert.True(attr.CannotBeRead);
        Assert.Equal(0, attr.ValueLength); // CannotBeRead short-circuits to 0
    }

    [Fact]
    public void CannotBeRead_ReturnsFalseForNormalAttribute()
    {
        using var attr = new ObjectAttribute(CKA.CKA_VALUE, new byte[] { 1 });
        Assert.False(attr.CannotBeRead);
    }

    [Fact]
    public void GetValueAs_ThrowsOnSensitiveAttribute()
    {
        var raw = new CK_ATTRIBUTE
        {
            type = (NativeCULong)(ulong)CKA.CKA_VALUE,
            value = IntPtr.Zero,
            valueLen = NativeCULong.MaxValue,
        };
        using var attr = new ObjectAttribute(raw);

        Assert.Throws<AttributeValueException>(() => attr.GetValueAsBool());
        Assert.Throws<AttributeValueException>(() => attr.GetValueAsUlong());
        Assert.Throws<AttributeValueException>(() => attr.GetValueAsString());
        Assert.Throws<AttributeValueException>(() => attr.GetValueAsByteArray());
        Assert.Throws<AttributeValueException>(() => attr.CopyValueTo(new byte[16]));
        Assert.Throws<AttributeValueException>(() => attr.GetValueAsDateTime());
    }

    // ---- ulong-typed constructor for raw vendor attribute IDs -------------

    [Fact]
    public void RawUlongTypeCtor_PreservesVendorAttributeId()
    {
        const ulong vendorAttrId = 0x80000042; // CKA_VENDOR_DEFINED + 0x42
        using var attr = new ObjectAttribute(vendorAttrId, new byte[] { 0xAA });
        Assert.Equal(vendorAttrId, attr.Type);
        Assert.Single(attr.GetValueAsByteArray(), (byte)0xAA);
    }
}
```

- [ ] **Step 3: Run the new tests**

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~ObjectAttributeTests" 2>&1 | tail -5
```

Expected: all tests pass. If `CannotBeRead_DetectsSentinel` fails, the `CannotBeRead` check has a platform bug — investigate `HighLevel/ObjectAttribute.cs`.

If `RoundTrip_NestedAttributeList` fails, the unmanaged-memory layout for nested attribute arrays has a regression — inspect the `_CreateAttribute` private helper and the `GetValueAsAttributeArray` reader.

- [ ] **Step 4: Run the full test suite**

```bash
dotnet test src/src.sln 2>&1 | tail -5
```

Expected: full count is original 118 + new ObjectAttribute tests + smoke test = ~140 passing.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ObjectAttributeTests.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "test: comprehensive ObjectAttribute round-trip + Dispose + CannotBeRead

Closes the Phase 0a final-review coverage gap. Adds:
- Per-typed-constructor round-trip: bool, ulong, CKO/CKK/CKC enum
  overloads, string (UTF-8 with non-ASCII), byte[] + ReadOnlySpan<byte>,
  DateTime, List<ulong>, List<CKM>, nested List<ObjectAttribute>
- CopyValueTo: exact-byte semantics + too-small-destination throws
- Lifetime: double-dispose safe; post-dispose access throws
  ObjectDisposedException on every public reader
- CannotBeRead sentinel regression test for the Phase 0a 32-bit/64-bit
  Windows bug: constructs an attribute with valueLen=NativeCULong.MaxValue
  via the internal ctor and asserts CannotBeRead=true plus that every
  GetValueAs* throws AttributeValueException
- Vendor-defined raw ulong type passthrough

Adds InternalsVisibleTo for the test project so the internal CK_ATTRIBUTE
ctor is reachable from the sensitive-attribute regression tests."
```

---

## Task 8: Scaffold the Pkcs11.Mock C# wrapper project

Near-empty project; it gets populated in Phase 4 with C# wrappers for `pkcs11-mock`'s diagnostic extension functions. Creating the skeleton now keeps the solution layout matching the parent spec.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Mock/KerckhoffsLabs.Security.Cryptography.Pkcs11.Mock.csproj`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Mock/AssemblyInfo.cs`
- Modify: `src/src.sln`

- [ ] **Step 1: Create the csproj**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Mock/KerckhoffsLabs.Security.Cryptography.Pkcs11.Mock.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFrameworks>net8.0;net9.0</TargetFrameworks>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
    <EnableNETAnalyzers>true</EnableNETAnalyzers>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <IsPackable>false</IsPackable>
    <LangVersion>latest</LangVersion>
  </PropertyGroup>

  <ItemGroup>
    <ProjectReference Include="..\KerckhoffsLabs.Security.Cryptography.Pkcs11\KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj" />
  </ItemGroup>

</Project>
```

- [ ] **Step 2: Create a placeholder AssemblyInfo so the project has at least one C# file**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Mock/AssemblyInfo.cs`:

```csharp
// This assembly will provide C# wrappers for the pkcs11-mock diagnostic
// extension functions (C_GetUnmanagedStructSize*, etc.) used by the test
// suite. Populated in Phase 4.

[assembly: System.Reflection.AssemblyMetadata("Phase", "0b-skeleton")]
```

- [ ] **Step 3: Add to solution and build**

```bash
cd /home/alexandre/dev/PKCS11.NET/src
dotnet sln src.sln add KerckhoffsLabs.Security.Cryptography.Pkcs11.Mock/KerckhoffsLabs.Security.Cryptography.Pkcs11.Mock.csproj
cd /home/alexandre/dev/PKCS11.NET
dotnet build src/src.sln 2>&1 | tail -5
```

Expected: `0 Error(s)`.

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/src.sln src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Mock/
git -C /home/alexandre/dev/PKCS11.NET commit -m "test: scaffold Pkcs11.Mock project skeleton

Empty project that will hold C# wrappers for pkcs11-mock's diagnostic
extension functions (C_GetUnmanagedStructSize*). Populated in Phase 4
when the marshalling-correctness tests need it."
```

---

## Task 9: Add the GitHub Actions CI workflow

A single workflow that builds on Linux + Windows (the matrix exists specifically to catch any future platform-specific bug like the 32-bit/64-bit Windows `CannotBeRead` issue Phase 0a's review caught) and packs the library tag-gated.

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
    tags: ['v*']
  pull_request:
    branches: [main]

jobs:
  build-and-test:
    name: build-and-test (${{ matrix.os }})
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - name: Checkout (with submodules)
        uses: actions/checkout@v4
        with:
          submodules: recursive

      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: |
            8.0.x
            9.0.x

      - name: Install build deps (Linux)
        if: runner.os == 'Linux'
        run: sudo apt-get update && sudo apt-get install -y build-essential

      - name: Restore
        run: dotnet restore src/src.sln

      - name: Build
        run: dotnet build src/src.sln --configuration Release --no-restore

      - name: Test
        run: dotnet test src/src.sln --configuration Release --no-build --logger trx --results-directory TestResults

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: test-results-${{ matrix.os }}
          path: TestResults/

  pack:
    name: pack
    needs: build-and-test
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && (github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v'))
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive

      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: |
            8.0.x
            9.0.x

      - name: Pack
        run: dotnet pack src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj --configuration Release -p:SkipPkcs11MockBuild=true -o artifacts

      - name: Upload nupkg
        uses: actions/upload-artifact@v4
        with:
          name: nupkg
          path: artifacts/
```

- [ ] **Step 2: Lint locally if `actionlint` is available**

Optional:
```bash
actionlint .github/workflows/ci.yml
```

Expected: no output (success). If `actionlint` is not installed, GitHub will validate on push. Skip.

- [ ] **Step 3: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add .github/workflows/ci.yml
git -C /home/alexandre/dev/PKCS11.NET commit -m "ci: add GitHub Actions workflow (build + test + pack)

Matrix builds on ubuntu-latest and windows-latest with both .NET 8 and
.NET 9. The Windows leg specifically guards against future platform
bugs like the 32-bit/64-bit storage discrepancy that Phase 0a's
final review caught in CannotBeRead.

On pushes to main or tag pushes, packs the main library and uploads
the .nupkg as an artifact. NuGet publish is not yet wired up — that
lands when versioning graduates past 0.x."
```

---

## Task 10: Polish — XML docs on cast operators + canonicalize CKA/CKC/CKM `ToCULong`

Two cleanup items from the Phase 0a final review.

**Files:**
- Modify: `src/KerckhoffsLabs.Runtime.InteropServices/NativeCULong.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKA.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKC.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKM.cs`

- [ ] **Step 1: Add XML docs to the NativeCULong cast operators**

Open `src/KerckhoffsLabs.Runtime.InteropServices/NativeCULong.cs`. Find the explicit cast operator block (introduced in Phase 0a, after the existing `public nuint Value => _value;` line). Each operator currently has no `<summary>` doc. Add one per group as follows.

Before the `// ---- Explicit cast operators ...` block (or replace the block comment with structured doc comments), the operators should be wrapped in two summary regions:

For the 5 incoming operators (`primitive → NativeCULong`), add this single `<summary>` above the group:

```csharp
    /// <summary>
    /// Converts a primitive integer value into a <see cref="NativeCULong"/>. With project-wide
    /// <c>CheckForOverflowUnderflow=true</c>, out-of-range values throw
    /// <see cref="System.OverflowException"/>. Wrap the call in <c>unchecked { ... }</c> to opt
    /// out and get wrap semantics. The generic-math equivalent is
    /// <see cref="System.Numerics.INumberBase{T}.CreateChecked{TOther}(TOther)"/>.
    /// </summary>
    public static explicit operator NativeCULong(int   value) => /* existing body */;
    public static explicit operator NativeCULong(uint  value) => /* existing body */;
    public static explicit operator NativeCULong(long  value) => /* existing body */;
    public static explicit operator NativeCULong(ulong value) => /* existing body */;
    public static explicit operator NativeCULong(nuint value) => /* existing body */;
```

Note: C# doesn't allow a single `<summary>` to apply to multiple members. The five-operator group needs five individual one-line docs. Use:

```csharp
    /// <summary>Converts an <see cref="int"/> to a <see cref="NativeCULong"/>. Range-checked under <c>CheckForOverflowUnderflow=true</c>.</summary>
    public static explicit operator NativeCULong(int   value) => /* existing body */;

    /// <summary>Converts a <see cref="uint"/> to a <see cref="NativeCULong"/>. Always exact; widens to <see cref="nuint"/> storage on Unix.</summary>
    public static explicit operator NativeCULong(uint  value) => /* existing body */;

    /// <summary>Converts a <see cref="long"/> to a <see cref="NativeCULong"/>. Range-checked under <c>CheckForOverflowUnderflow=true</c>.</summary>
    public static explicit operator NativeCULong(long  value) => /* existing body */;

    /// <summary>Converts a <see cref="ulong"/> to a <see cref="NativeCULong"/>. Range-checked under <c>CheckForOverflowUnderflow=true</c> on 32-bit storage platforms.</summary>
    public static explicit operator NativeCULong(ulong value) => /* existing body */;

    /// <summary>Converts a <see cref="nuint"/> to a <see cref="NativeCULong"/>. Range-checked under <c>CheckForOverflowUnderflow=true</c> on 32-bit storage platforms.</summary>
    public static explicit operator NativeCULong(nuint value) => /* existing body */;
```

And for the 5 outgoing operators:

```csharp
    /// <summary>Converts a <see cref="NativeCULong"/> to an <see cref="int"/>. Range-checked under <c>CheckForOverflowUnderflow=true</c>.</summary>
    public static explicit operator int   (NativeCULong value) => /* existing body */;

    /// <summary>Converts a <see cref="NativeCULong"/> to a <see cref="uint"/>. Range-checked under <c>CheckForOverflowUnderflow=true</c> on 64-bit storage platforms.</summary>
    public static explicit operator uint  (NativeCULong value) => /* existing body */;

    /// <summary>Converts a <see cref="NativeCULong"/> to a <see cref="long"/>. Always exact.</summary>
    public static explicit operator long  (NativeCULong value) => /* existing body */;

    /// <summary>Converts a <see cref="NativeCULong"/> to a <see cref="ulong"/>. Always exact.</summary>
    public static explicit operator ulong (NativeCULong value) => /* existing body */;

    /// <summary>Converts a <see cref="NativeCULong"/> to a <see cref="nuint"/>. Always exact.</summary>
    public static explicit operator nuint (NativeCULong value) => /* existing body */;
```

Leave the existing implementation bodies unchanged — only add the `///` comments. The same set of `<summary>` lines also applies to the corresponding `operator checked X` variants added in Phase 0a — add an analogous one-liner to each, replacing the "Range-checked..." phrase with "Always throws on overflow."

- [ ] **Step 2: Add XML docs to public ObjectAttribute constructors**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/ObjectAttribute.cs`. Each public constructor and the `internal ObjectAttribute(CK_ATTRIBUTE)` constructor lacks a `<summary>`. Add a one-liner to each. The full set with their summaries:

```csharp
    /// <summary>Wraps an existing low-level CK_ATTRIBUTE struct. The instance takes ownership of any unmanaged buffer the struct points at and frees it on <see cref="Dispose"/>.</summary>
    internal ObjectAttribute(CK_ATTRIBUTE attribute);

    /// <summary>Creates an attribute of the given vendor-defined attribute id with no value.</summary>
    public ObjectAttribute(ulong type);

    /// <summary>Creates an attribute of the given <see cref="CKA"/> type with no value.</summary>
    public ObjectAttribute(CKA   type);

    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a <see cref="ulong"/> value (encoded as CK_ULONG on the wire).</summary>
    public ObjectAttribute(ulong type, ulong value);

    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a <see cref="ulong"/> value (encoded as CK_ULONG on the wire).</summary>
    public ObjectAttribute(CKA type, ulong value);

    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a <see cref="CKC"/> enum value.</summary>
    public ObjectAttribute(CKA type, CKC value);

    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a <see cref="CKK"/> enum value.</summary>
    public ObjectAttribute(CKA type, CKK value);

    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a <see cref="CKO"/> enum value.</summary>
    public ObjectAttribute(CKA type, CKO value);

    /// <summary>Creates a vendor-defined-id attribute holding a bool value (encoded as a single byte: 0x01 or 0x00).</summary>
    public ObjectAttribute(ulong type, bool value);

    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a bool value (encoded as a single byte: 0x01 or 0x00).</summary>
    public ObjectAttribute(CKA type, bool value);

    /// <summary>Creates a vendor-defined-id attribute holding a UTF-8 string with no null terminator.</summary>
    public ObjectAttribute(ulong type, string value);

    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a UTF-8 string with no null terminator.</summary>
    public ObjectAttribute(CKA type, string value);

    /// <summary>Creates a vendor-defined-id attribute holding the bytes of <paramref name="value"/>.</summary>
    public ObjectAttribute(ulong type, byte[] value);

    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding the bytes of <paramref name="value"/>.</summary>
    public ObjectAttribute(CKA type, byte[] value);

    /// <summary>Creates a vendor-defined-id attribute holding the bytes of <paramref name="value"/>. Zero-allocation when the caller already holds a span.</summary>
    public ObjectAttribute(ulong type, ReadOnlySpan<byte> value);

    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding the bytes of <paramref name="value"/>. Zero-allocation when the caller already holds a span.</summary>
    public ObjectAttribute(CKA type, ReadOnlySpan<byte> value);

    /// <summary>Creates a vendor-defined-id attribute holding a date value (encoded as 8-byte ASCII "yyyyMMdd").</summary>
    public ObjectAttribute(ulong type, DateTime value);

    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a date value (encoded as 8-byte ASCII "yyyyMMdd").</summary>
    public ObjectAttribute(CKA type, DateTime value);

    /// <summary>Creates a vendor-defined-id attribute holding a list of nested attributes (encoded as a contiguous CK_ATTRIBUTE[] in unmanaged memory).</summary>
    public ObjectAttribute(ulong type, List<ObjectAttribute> value);

    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a list of nested attributes (encoded as a contiguous CK_ATTRIBUTE[] in unmanaged memory).</summary>
    public ObjectAttribute(CKA type, List<ObjectAttribute> value);

    /// <summary>Creates a vendor-defined-id attribute holding a list of <see cref="ulong"/> values (encoded as a contiguous CK_ULONG[] in unmanaged memory).</summary>
    public ObjectAttribute(ulong type, List<ulong> value);

    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a list of <see cref="ulong"/> values (encoded as a contiguous CK_ULONG[] in unmanaged memory).</summary>
    public ObjectAttribute(CKA type, List<ulong> value);

    /// <summary>Creates a vendor-defined-id attribute holding a list of <see cref="CKM"/> values (encoded as a contiguous CK_ULONG[] in unmanaged memory).</summary>
    public ObjectAttribute(ulong type, List<CKM> value);

    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a list of <see cref="CKM"/> values (encoded as a contiguous CK_ULONG[] in unmanaged memory).</summary>
    public ObjectAttribute(CKA type, List<CKM> value);
```

Apply these as XML doc comments above each existing constructor declaration. Leave the constructor bodies untouched.

The `GetValueAs*` methods, `ValueLength`, `CopyValueTo`, `Type`, `CannotBeRead`, and `Dispose` already have summaries from Phase 0a — no action needed.

- [ ] **Step 3: Canonicalize CKA/CKC/CKM `ToCULong` implementations**

The 10 other `CK*Extensions` classes (CKD, CKG, CKH, CKK, CKN, CKO, CKP, CKR, CKS, CKU) use the pattern:

```csharp
public static NativeCULong ToCULong(this CKR value)
{
    return (NativeCULong)(ulong)value;
}
```

But three pre-existing files use a different (older) pattern:

```csharp
public static NativeCULong ToCULong(this CKA value)
{
    return new NativeCULong(Convert.ToUInt32(value));
}
```

This works but: (a) loses bits on Unix if `value` ever exceeds `uint.MaxValue` (vendor-defined CKA values go above 0x80000000 — fit in uint, but the pattern is fragile), (b) is inconsistent with the other 10 enum extensions. Canonicalize.

For each of `Common/CKA.cs`, `Common/CKC.cs`, `Common/CKM.cs`, find the `ToCULong` method inside the `*Extensions` class and replace its body. The replacement looks the same for each (substitute the enum name):

```csharp
public static NativeCULong ToCULong(this CKA value)
{
    return (NativeCULong)(ulong)value;
}
```

- [ ] **Step 4: Build and test to confirm no regression**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | tail -3
```

Expected: 0 errors. All tests still pass.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Runtime.InteropServices/NativeCULong.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/ObjectAttribute.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKA.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKC.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKM.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "polish: XML docs on cast operators + ObjectAttribute ctors + canonicalize 3 ToCULong impls

Phase 0a final-review follow-ups:
- NativeCULong's 10 plain cast operators + 7 operator checked variants
  each get a one-line <summary>. Closes the CS1591 gap that the csproj
  currently suppresses with NoWarn (for these specific members).
- ObjectAttribute's ~24 public + 1 internal constructors get one-line
  <summary> docs.
- CKA, CKC, CKM ToCULong impls switched from
  'new NativeCULong(Convert.ToUInt32(value))' to '(NativeCULong)(ulong)value'
  to match the 10 newer extension classes and avoid implicit 32-bit
  truncation for vendor values."
```

---

## Task 11: Final cleanup + dotnet pack smoke + exit checklist

**Files:**
- (Verification only; possible csproj tweak to remove the CS1591 suppression now that XML docs exist on the public surface.)

- [ ] **Step 1: Tighten the CS1591 suppression**

Now that the cast operators (Task 10) and ObjectAttribute constructors should have XML docs, the `<NoWarn>$(NoWarn);CS1591</NoWarn>` line in `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` may be no-longer-needed. **But the rest of the library still lacks XML docs on its public surface** (Session.cs, Mechanism.cs, etc., have many public members). Leave the suppression in place for Phase 0b — fully removing it is Phase 1+ work as more of the public API gets stable XML docs.

No action this step except to verify the suppression is intentional and noted. Skip.

- [ ] **Step 2: Final clean build**

```bash
cd /home/alexandre/dev/PKCS11.NET
dotnet clean src/src.sln >/dev/null
dotnet build src/src.sln --configuration Release 2>&1 | tail -5
```

Expected: `0 Error(s)`. Warnings tolerated.

- [ ] **Step 3: Final full test run**

```bash
dotnet test src/src.sln --configuration Release --no-build 2>&1 | tail -10
```

Expected: All tests pass. Final count should be:
- Original 118 `NativeCULongTests` / `NativeCULongCastTests` / `EnumExtensionsTests` / `SpanOverloadSmokeTests` tests
- 1 smoke test from T6
- ~22 `ObjectAttributeTests` from T7

Total: ~141 passing, 1 skipped (pre-existing), 0 failed.

- [ ] **Step 4: Verify `dotnet pack` produces a valid `.nupkg`**

```bash
dotnet pack src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -c Release -p:SkipPkcs11MockBuild=true -o /tmp/pack-test 2>&1 | tail -10
ls /tmp/pack-test/
```

Expected: `KerckhoffsLabs.Security.Cryptography.Pkcs11.0.1.0.nupkg` plus `KerckhoffsLabs.Security.Cryptography.Pkcs11.0.1.0.snupkg`. Both `net8.0` and `net9.0` outputs should be inside the `.nupkg` (verify with `unzip -l /tmp/pack-test/KerckhoffsLabs.Security.Cryptography.Pkcs11.0.1.0.nupkg | grep lib/`).

Clean up: `rm -rf /tmp/pack-test`.

- [ ] **Step 5: Verify the Phase 0b exit-criteria invariants**

```bash
# LICENSE + README at repo root
ls /home/alexandre/dev/PKCS11.NET/LICENSE /home/alexandre/dev/PKCS11.NET/README.md

# Multi-target on the main library:
grep "TargetFrameworks" /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj

# Pkcs11.Tests and Pkcs11.Mock projects exist:
ls /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj
ls /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Mock/KerckhoffsLabs.Security.Cryptography.Pkcs11.Mock.csproj

# pkcs11-mock submodule + build scripts exist:
ls /home/alexandre/dev/PKCS11.NET/third-party/pkcs11-mock/
ls /home/alexandre/dev/PKCS11.NET/build/build-pkcs11-mock.sh /home/alexandre/dev/PKCS11.NET/build/build-pkcs11-mock.ps1

# CI workflow exists:
ls /home/alexandre/dev/PKCS11.NET/.github/workflows/ci.yml

# .slnx is gone:
ls /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11.slnx 2>&1

# CKA/CKC/CKM canonicalized:
grep -E "Convert\.ToUInt32" /home/alexandre/dev/PKCS11.NET/src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CK{A,C,M}.cs ; echo "exit=$?"
```

Expected outputs:
- LICENSE + README + csproj + submodule + scripts + CI workflow + project files all exist.
- `TargetFrameworks` shows `net8.0;net9.0`.
- The `.slnx` file `ls` returns "No such file or directory".
- The `Convert.ToUInt32` grep returns no matches (`exit=1`).

- [ ] **Step 6: Tag the milestone**

```bash
git -C /home/alexandre/dev/PKCS11.NET tag -a phase-0b-complete -m "Phase 0b complete: build scaffolding; smoke test green; pack produces valid nupkg"
```

- [ ] **Step 7: Final commit (if any tracked state changed during verification — typically not needed)**

If the verification steps produced no new modifications, skip this step. Otherwise:

```bash
git -C /home/alexandre/dev/PKCS11.NET commit -m "chore: Phase 0b verification artifacts"
```

---

## Phase 0b Exit Checklist

Confirm each before considering Phase 0b done:

- [ ] `dotnet build src/src.sln -c Debug` and `-c Release` succeed with 0 errors.
- [ ] `dotnet test src/src.sln --no-build` shows ~141 passed, 1 skipped (pre-existing), 0 failed.
- [ ] `LICENSE` and `README.md` exist at repo root.
- [ ] Main library csproj has `<TargetFrameworks>net8.0;net9.0</TargetFrameworks>`.
- [ ] Main library csproj has `Microsoft.SourceLink.GitHub` and packaging metadata (PackageId, Version, Authors, Description, License).
- [ ] `Pkcs11.Tests` and `Pkcs11.Mock` projects exist in `src.sln`.
- [ ] `third-party/pkcs11-mock` is a submodule pinned to a release tag.
- [ ] `build/build-pkcs11-mock.sh` and `build/build-pkcs11-mock.ps1` exist.
- [ ] `Pkcs11.Tests` has an MSBuild target that builds the mock before tests run.
- [ ] `SmokeTests.LoadInitializeFinalize_OnMock_Succeeds` passes against the built mock.
- [ ] `ObjectAttributeTests` (~22 tests) all pass, including the `CannotBeRead_DetectsSentinel` regression test.
- [ ] `InternalsVisibleTo` is set on the main library for the test project.
- [ ] `.github/workflows/ci.yml` runs build+test on `ubuntu-latest` and `windows-latest`, and packs on main/tag pushes.
- [ ] Stray `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.slnx` is deleted.
- [ ] `Common/{CKA,CKC,CKM}.cs` `ToCULong` impls match the canonical `(NativeCULong)(ulong)value` pattern.
- [ ] All 10 plain cast operators and 7 `operator checked` variants on `NativeCULong` have XML doc summaries.
- [ ] All public `ObjectAttribute` constructors (~24) have XML doc summaries.
- [ ] `dotnet pack` produces a valid `.nupkg` + `.snupkg`.
- [ ] Tag `phase-0b-complete` exists.

When all checked, Phase 0b is complete. Phases 1–5 from the parent spec can proceed.
