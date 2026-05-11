# PKCS11.NET Phase 0: Build + Scaffolding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Take the in-progress PKCS11.NET library from 931 build errors to a green-building repo with packaging metadata, a multi-targeted (`net8.0;net9.0`) library, an xUnit test project, a vendored `pkcs11-mock` C submodule + build script, one passing smoke test against the mock, a `Pkcs11.Mock` C# project skeleton, and a CI workflow.

**Architecture:** Mechanical build-fix (project reference + two missing `using` statements clears 931 errors). New `Pkcs11.Tests` xUnit project loads the mock via `NativeLibrary` and runs an end-to-end `C_Initialize → C_GetInfo → C_Finalize` round-trip. Mock binary is built from a submodule by a shell/PowerShell script invoked from MSBuild before tests run.

**Tech Stack:** .NET 8 + .NET 9, C# 12, xUnit 2.9, `Microsoft.DotNet.XUnitExtensions` (for `[SkippableFact]`), `Microsoft.SourceLink.GitHub`, `pkcs11-mock` (C, built via `make`+`gcc`), GitHub Actions.

**Reference spec:** `docs/superpowers/specs/2026-05-11-pkcs11-completion-design.md`

---

## File Structure

After this phase, the repo looks like:

```
PKCS11.NET/
├── .github/workflows/ci.yml                                            [CREATE]
├── .gitmodules                                                         [CREATE — by `git submodule add`]
├── LICENSE                                                             [CREATE]
├── README.md                                                           [CREATE]
├── CLAUDE.md                                                           [exists, unchanged]
├── build/
│   ├── build-pkcs11-mock.sh                                            [CREATE]
│   └── build-pkcs11-mock.ps1                                           [CREATE]
├── docs/superpowers/{specs,plans}/                                     [exists]
├── third-party/pkcs11-mock/                                            [CREATE — submodule]
└── src/
    ├── src.sln                                                         [MODIFY — add 2 new projects]
    ├── KerckhoffsLabs.Runtime.InteropServices/                         [unchanged]
    ├── KerckhoffsLabs.Runtime.InteropServices.UnitTests/               [unchanged]
    ├── KerckhoffsLabs.Security.Cryptography.Pkcs11/
    │   ├── KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj          [MODIFY — project ref + packaging]
    │   ├── Logging/Pkcs11InteropLogUtils.cs                            [MODIFY — add using]
    │   └── Native/PlatormSpecificPackAttribute.cs                      [MODIFY — add using]
    ├── KerckhoffsLabs.Security.Cryptography.Pkcs11.Mock/
    │   └── KerckhoffsLabs.Security.Cryptography.Pkcs11.Mock.csproj     [CREATE — skeleton]
    └── KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/
        ├── KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj    [CREATE]
        ├── Settings.cs                                                 [CREATE — env-driven config]
        └── HighLevel/SmokeTests.cs                                     [CREATE]
```

**Files left to later phases:** `IPkcs11Backend`, `MockBackendFixture`, `SoftHsmBackendFixture`, the `Session.*.cs` partials, secure helpers — all introduced in Phase 1 onward when they're first needed.

**Note on `.slnx`:** the repo contains a stray `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.slnx` that only references the main library. This phase does NOT use or update it. The canonical solution is `src/src.sln`. We delete the stray `.slnx` in Task 9 to avoid confusion.

---

## Task 1: Fix the build (zero errors)

The library currently has **931 build errors** rooted in three trivial omissions: a missing project reference and two missing `using` statements. Fixing them is a one-commit task.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/PlatormSpecificPackAttribute.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Logging/Pkcs11InteropLogUtils.cs`

- [ ] **Step 1: Establish the baseline failure**

Run from repo root: `dotnet build src/src.sln 2>&1 | tail -3`
Expected: `931 Error(s)`. (Lock this in — the next steps drive it to 0.)

- [ ] **Step 2: Add the missing project reference**

Edit `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`. After the existing `<PropertyGroup>` blocks, add this `<ItemGroup>` (above the closing `</Project>`):

```xml
  <ItemGroup>
    <ProjectReference Include="..\KerckhoffsLabs.Runtime.InteropServices\KerckhoffsLabs.Runtime.InteropServices.csproj" />
  </ItemGroup>
```

- [ ] **Step 3: Rebuild and confirm `NativeCULong` errors are gone**

Run: `dotnet build src/src.sln 2>&1 | tail -3`
Expected: ~10 errors remain (5 from `PlatormSpecificPackAttribute.cs`, 5 from `Pkcs11InteropLogUtils.cs`, doubled by net8/net9 multi-target compile if that's been added — but at this point it hasn't, so ~6 errors).

- [ ] **Step 4: Add `using System.Runtime.InteropServices;` to `PlatormSpecificPackAttribute.cs`**

Edit `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/PlatormSpecificPackAttribute.cs`. Add the `using` as the first line of the file. After the edit the file should look like:

```csharp
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

#if WINDOWS
[StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
#else
[StructLayout(LayoutKind.Sequential, Pack = 0, CharSet = CharSet.Unicode)]
#endif
internal sealed class PlatformSpecificPackAttribute : Attribute
{
}
```

- [ ] **Step 5: Add `using` for the `HighLevel` namespace to `Pkcs11InteropLogUtils.cs`**

Edit `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Logging/Pkcs11InteropLogUtils.cs`. Add a second `using` so the top of the file reads:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
```

(Leave the rest of the file unchanged.)

- [ ] **Step 6: Rebuild and confirm zero errors**

Run: `dotnet build src/src.sln 2>&1 | tail -3`
Expected: `0 Error(s)`. Warnings allowed.

- [ ] **Step 7: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/PlatormSpecificPackAttribute.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Logging/Pkcs11InteropLogUtils.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "fix(build): add NativeCULong project reference and missing usings

The main library project did not reference KerckhoffsLabs.Runtime.InteropServices
where NativeCULong is defined, causing 925 errors. PlatormSpecificPackAttribute.cs
was missing 'using System.Runtime.InteropServices;' and Pkcs11InteropLogUtils.cs
was missing the HighLevel namespace using. Build now produces 0 errors."
```

---

## Task 2: Add packaging metadata, multi-target, LICENSE, README

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`
- Create: `LICENSE` (repo root)
- Create: `README.md` (repo root)

- [ ] **Step 1: Create the MIT LICENSE file at repo root**

Create `/home/alexandre/dev/PKCS11.NET/LICENSE` with the standard MIT license body:

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

- [ ] **Step 2: Create a minimal README at repo root**

Create `/home/alexandre/dev/PKCS11.NET/README.md`:

```markdown
# PKCS11.NET

Modern, secure-by-default PKCS#11 v3.1 interop for .NET.

> **Status:** Phase 0 (build + scaffolding). API surface and full test
> coverage land in subsequent phases — see `docs/superpowers/specs/` for
> the design and `docs/superpowers/plans/` for the phased plans.

## Building

```bash
git clone --recurse-submodules <repo-url>
cd PKCS11.NET
dotnet build src/src.sln
```

## Running tests

```bash
dotnet test src/src.sln
```

Tests load `pkcs11-mock` (built from `third-party/pkcs11-mock` as a
submodule). The build is triggered automatically by an MSBuild target
in the test project.

## License

MIT — see `LICENSE`.
```

- [ ] **Step 3: Add packaging metadata + multi-target to the main library csproj**

Replace the entire contents of `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` with:

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
    <!-- Suppress the warning about missing XML docs for public members.
         We will tighten this in the polish phase. -->
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

- [ ] **Step 4: Restore + build to verify the multi-target works on both TFMs**

Run from repo root:

```bash
dotnet restore src/src.sln
dotnet build src/src.sln -c Release 2>&1 | tail -10
```

Expected: `0 Error(s)`. Both `net8.0` and `net9.0` outputs land in `bin/Release/`.

If `net8.0` produces errors due to use of a `net9.0`-only API, locate the call site and either guard it with `#if NET9_0_OR_GREATER` or replace with a `net8.0`-compatible equivalent. (At time of writing, no such call sites are expected — the library uses only `System.Runtime.InteropServices` APIs available in `net8.0`.)

- [ ] **Step 5: Refresh the lock file**

Run: `dotnet restore src/src.sln`
This regenerates `packages.lock.json` to reflect the new SourceLink package. Verify it's been updated:

```bash
grep -c "Microsoft.SourceLink.GitHub" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/packages.lock.json
```

Expected: `>= 1`.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add LICENSE README.md src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj src/KerckhoffsLabs.Security.Cryptography.Pkcs11/packages.lock.json
git -C /home/alexandre/dev/PKCS11.NET commit -m "chore(pack): add MIT license, README, packaging metadata, multi-target

Multi-targets net8.0 + net9.0. Adds SourceLink, deterministic build,
symbol package, and PackageReadmeFile so 'dotnet pack' produces a
publish-ready .nupkg + .snupkg pair."
```

---

## Task 3: Scaffold the `Pkcs11.Tests` xUnit project

We are NOT yet adding the `IPkcs11Backend`/`MockBackendFixture` abstraction — those are introduced in Phase 1 when multiple tests need them. Phase 0 ships one direct smoke test.

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

- [ ] **Step 2: Create `Settings.cs`**

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

Run from `/home/alexandre/dev/PKCS11.NET/src`:

```bash
dotnet sln src.sln add KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj
```

Expected output: `Project ... added to the solution.`

- [ ] **Step 4: Build the new project**

Run from repo root: `dotnet build src/src.sln 2>&1 | tail -5`
Expected: `0 Error(s)`. (The test project has no tests yet — that's fine; it just needs to compile.)

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/src.sln src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/
git -C /home/alexandre/dev/PKCS11.NET commit -m "test: scaffold Pkcs11.Tests xUnit project with env-driven Settings

Empty xUnit project wired into src.sln. Settings.cs resolves the
pkcs11-mock library path based on RuntimeInformation, with env-var
overrides for CI and developer environments. No tests yet — added in
Task 6."
```

---

## Task 4: Add `pkcs11-mock` as a git submodule

**Files:**
- Create: `.gitmodules` (auto-generated by `git submodule add`)
- Create: `third-party/pkcs11-mock/` (submodule)

- [ ] **Step 1: Add the submodule**

Run from repo root:

```bash
git -C /home/alexandre/dev/PKCS11.NET submodule add https://github.com/Pkcs11Interop/pkcs11-mock.git third-party/pkcs11-mock
```

Expected: `.gitmodules` is created, `third-party/pkcs11-mock/` is populated, both files appear in `git status` as staged.

- [ ] **Step 2: Pin the submodule to a known-good SHA**

Pin to a specific release to make the build reproducible. Use the latest tag from the upstream repo (check via `gh release list -R Pkcs11Interop/pkcs11-mock --limit 1`). At time of writing the latest release is `v8.0.1`. Pin to it:

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

Run: `ls /home/alexandre/dev/PKCS11.NET/third-party/pkcs11-mock/build/`
Expected: directories like `linux/`, `macosx/`, `windows/` each with a build script.

If the directory structure does not match, inspect the actual layout:
```bash
ls /home/alexandre/dev/PKCS11.NET/third-party/pkcs11-mock/
```
and adapt the build-script paths in Task 5 accordingly.

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET commit -m "build: vendor pkcs11-mock as submodule pinned to v8.0.1

The mock PKCS#11 module is used by the test suite to exercise the full
interop stack without requiring a real HSM or SoftHSM2. Pinned to a
release tag for reproducibility."
```

---

## Task 5: Write the mock build scripts

These scripts compile `third-party/pkcs11-mock` and copy the result into the test project's output directory under a runtime-identifier-keyed path so `NativeLibrary.Load("pkcs11-mock")` resolves on every platform.

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
# The script is idempotent: if the target binary already exists and is
# newer than the submodule HEAD commit, it is reused.

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

# pkcs11-mock's build scripts produce architecture-suffixed artifacts
# (pkcs11-mock-x64.so etc.). We invoke `make` directly against the
# upstream Makefile to keep control over the output name.
pushd "${MOCK_DIR}/${BUILD_SUBDIR}" >/dev/null
make clean >/dev/null 2>&1 || true
make
popd >/dev/null

# Locate the produced library (upstream names it pkcs11-mock-x64.so or
# pkcs11-mock-arm64.so depending on host arch).
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

Run from repo root:

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

Expected: a non-empty `.so` ELF shared library. Clean up: `rm -rf /tmp/pkcs11-mock-test`.

If `make` fails with "command not found" install build deps: `sudo apt-get install build-essential` on Debian/Ubuntu.

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add build/build-pkcs11-mock.sh build/build-pkcs11-mock.ps1
git -C /home/alexandre/dev/PKCS11.NET commit -m "build: add pkcs11-mock build scripts (sh + ps1)

Builds the vendored pkcs11-mock submodule and copies the resulting
shared library into a runtime-identifier-keyed path so the test runner
can NativeLibrary.Load(\"pkcs11-mock\") portably. Idempotent: skips
rebuild when output is newer than the submodule HEAD."
```

---

## Task 6: TDD the mock smoke test

We write the test first, watch it fail (no mock binary in the output dir yet), wire the MSBuild target to invoke the build script, then watch it pass. This is the first end-to-end exercise of the P/Invoke stack.

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

- [ ] **Step 2: Run the test, expect it to fail at the file-existence assertion**

Run: `dotnet test src/src.sln --filter "FullyQualifiedName~SmokeTests" 2>&1 | tail -20`

Expected: 1 test, 1 failure. Failure message includes `"pkcs11-mock library not found at '...runtimes/linux-x64/native/pkcs11-mock.so'"`.

(If the test passes here it means a stale binary was left somewhere — investigate and clean before continuing. The intent is to prove the MSBuild target in Step 3 is what wires this up.)

- [ ] **Step 3: Wire the MSBuild target that builds the mock before tests**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj`. Insert the following two `<Target>` elements directly above the closing `</Project>`:

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

Run: `dotnet test src/src.sln --filter "FullyQualifiedName~SmokeTests" 2>&1 | tail -10`

Expected: `Passed: 1, Failed: 0`.

If the test still fails with "library not found", check:
- The MSBuild target ran (look for `Building pkcs11-mock...` output above the test summary in the full log).
- The binary landed at the path `Settings.MockLibraryPath` resolves to. Check via `ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/bin/Debug/net9.0/runtimes/`.

If it fails with a marshalling/P-Invoke error (`DllNotFoundException`, `EntryPointNotFoundException`, etc.) — that's a real bug, not a build-wiring issue, and indicates one of:
- `LowLevelPkcs11Library.cs` is not loading the correct path (it should accept the absolute path we pass).
- The mock binary is for the wrong architecture (uname -m vs. dotnet runtime arch mismatch).

Diagnose and fix; this is the "real bug" surface area the smoke test exists to expose.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/SmokeTests.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj
git -C /home/alexandre/dev/PKCS11.NET commit -m "test: add pkcs11-mock smoke test + MSBuild wiring

First end-to-end test of the interop stack. Loads pkcs11-mock through
Pkcs11Library, calls C_Initialize / C_GetInfo / C_Finalize, asserts
basic LibraryInfo content. An MSBuild target before PrepareForBuild
invokes the platform-specific mock build script so the binary is in
place when tests run."
```

---

## Task 7: Scaffold the `Pkcs11.Mock` C# wrapper project

This is a near-empty project for now — it gets populated in Phase 4 with C# wrappers for `pkcs11-mock`'s diagnostic extension functions. We create it now so the solution layout matches the spec and the CI workflow exercises it.

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

[assembly: System.Reflection.AssemblyMetadata("Phase", "0-skeleton")]
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

## Task 8: Add the CI workflow

A single workflow that builds on Linux + Windows, runs the smoke test on both, and (on `main` or tag pushes) packs the library as a `.nupkg` artifact. NuGet publish is intentionally NOT wired up in Phase 0 — that lands when `Version` graduates past 0.x.

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

- [ ] **Step 2: Lint the workflow locally if `actionlint` is available**

Optional but quick. If you have `actionlint` installed:

```bash
actionlint .github/workflows/ci.yml
```

Expected: no output (success). If `actionlint` is not installed, skip — GitHub will validate on push.

- [ ] **Step 3: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add .github/workflows/ci.yml
git -C /home/alexandre/dev/PKCS11.NET commit -m "ci: add GitHub Actions workflow (build + test + pack)

Builds on ubuntu-latest and windows-latest with the matrix using both
.NET 8 and .NET 9. Runs dotnet test on both. On pushes to main or tag
pushes, packs the main library and uploads the .nupkg as an artifact.
NuGet publish is not yet wired up — that lands when versioning
graduates past 0.x."
```

---

## Task 9: Clean up the stray `.slnx` and validate end state

**Files:**
- Delete: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.slnx`

- [ ] **Step 1: Remove the stray solution file**

```bash
git -C /home/alexandre/dev/PKCS11.NET rm src/KerckhoffsLabs.Security.Cryptography.Pkcs11.slnx
```

- [ ] **Step 2: Final full build + test from a clean slate**

```bash
cd /home/alexandre/dev/PKCS11.NET
dotnet clean src/src.sln >/dev/null
dotnet build src/src.sln --configuration Release 2>&1 | tail -5
dotnet test  src/src.sln --configuration Release --no-build 2>&1 | tail -10
```

Expected:
- Build: `0 Error(s)`.
- Test summary: `Passed: <N>, Failed: 0` where N includes the existing `NativeCULong` tests **and** the new `SmokeTests.LoadInitializeFinalize_OnMock_Succeeds`.

- [ ] **Step 3: Verify `dotnet pack` produces a valid `.nupkg`**

```bash
dotnet pack src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -c Release -p:SkipPkcs11MockBuild=true -o /tmp/pack-test 2>&1 | tail -5
ls /tmp/pack-test/
```

Expected: `KerckhoffsLabs.Security.Cryptography.Pkcs11.0.1.0.nupkg` + `.snupkg` in `/tmp/pack-test/`. Clean up: `rm -rf /tmp/pack-test`.

- [ ] **Step 4: Commit the cleanup**

```bash
git -C /home/alexandre/dev/PKCS11.NET commit -m "chore: remove stray .slnx solution file

The canonical solution is src/src.sln. The .slnx only referenced the
main library project and was confusing tooling. Deleted."
```

- [ ] **Step 5: Tag the milestone (optional but recommended)**

```bash
git -C /home/alexandre/dev/PKCS11.NET tag -a phase-0-complete -m "Phase 0 complete: builds, multi-targets, packs, smoke test green"
```

---

## Phase 0 Exit Checklist

Confirm each before considering Phase 0 done:

- [ ] `dotnet build src/src.sln -c Release` succeeds with 0 errors, 0 warnings (warnings are tolerated this phase but should be triaged).
- [ ] `dotnet test src/src.sln -c Release` shows `Passed > 0, Failed: 0`, and the count includes `SmokeTests.LoadInitializeFinalize_OnMock_Succeeds`.
- [ ] `dotnet pack` produces `KerckhoffsLabs.Security.Cryptography.Pkcs11.0.1.0.nupkg` containing both TFM outputs and SourceLink metadata.
- [ ] The `Pkcs11.Mock` and `Pkcs11.Tests` projects appear in `src/src.sln`.
- [ ] `third-party/pkcs11-mock` is a submodule pinned to a release tag.
- [ ] CI workflow file exists and is syntactically valid.

When all are checked, Phase 0 is complete and Phase 1 (Encrypt + Decrypt) can be planned.
