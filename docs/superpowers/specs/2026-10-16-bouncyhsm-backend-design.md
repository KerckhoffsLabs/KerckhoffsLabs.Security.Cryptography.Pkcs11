# BouncyHsm test backend — design

Date: 2026-10-16
Status: approved in conversation, awaiting written-spec review

## Goal

Add [BouncyHsm](https://github.com/harrison314/BouncyHsm) as a supported test backend: the shared
`*TestCases` run against it on every CI leg that has a BouncyHsm native client, exactly like the
SoftHSM2, NSS, Kryoptic and opencryptoki backends.

### Why

A spike (local branch `spike/bouncyhsm`, throwaway) ran the opencryptoki wrapper set against
BouncyHsm v2.3.3: 396 tests, 306 passed, 14 failed, 76 skipped. Two of the failures were in this
library, which no existing backend had caught:

- `Pkcs11SessionCore.Encrypt` retries `CKR_BUFFER_TOO_SMALL` only with the length the module reports,
  and gives up when the module leaves it unchanged (7 RSA encrypt tests).
- Empty input passed as a null pointer (AES-CCM empty plaintext), fixed by #182.

The others are BouncyHsm limitations or bugs, reported upstream as
harrison314/BouncyHsm#114, #115 and #116.

### Success criteria

- The BouncyHsm tests pass, or skip through documented gates, on ubuntu-latest, macos-latest (arm64),
  macos-15-intel (x64), windows-latest (x64) and windows-latest (x86).
- On those legs, CI fails if BouncyHsm is silently unavailable (`PKCS11_TEST_EXPECT_BOUNCYHSM=1`).
- ubuntu-24.04-arm and windows-11-arm skip BouncyHsm cleanly, since upstream ships no arm64 native
  client for them.
- A developer can run it locally with one submodule init and one build flag, without starting a
  server by hand.
- Every quirk gate names its upstream issue and has a test that fails once the quirk is gone.

### Out of scope

- PKCS#11 v2.40 compatibility legs (`pkcs11-v240`): BouncyHsm reports v3.x.
- An "external server" mode (`PKCS11_TEST_BOUNCYHSM_ENDPOINT`). It can be added later if needed.
- Linux/Windows arm64 native client builds.

## Delivery

1. **PR 1: library fix.** `Pkcs11SessionCore.Encrypt` falls back to a `NULL`-buffer length query when a
   `CKR_BUFFER_TOO_SMALL` reports a length no larger than the buffer it was given, matching what
   `CallWithLengthProbe` already does. Audit every other hand-rolled `CKR_BUFFER_TOO_SMALL` retry
   (Decrypt, the dual-function and multi-part paths, wrap) for the same gap. Unit test it with a fake
   module that returns `CKR_BUFFER_TOO_SMALL` and leaves the length unchanged. This PR has its own
   design and plan; it lands first.
2. **PR 2: the BouncyHsm backend.** Everything below. It depends on PR 1, so its RSA encrypt tests run
   ungated. #182 is merged, so the EmptyInput wrappers are included.

## 1. Vendoring and build

- **Submodule** `vendor/bouncyhsm`, shallow, pinned to tag `v2.3.3` (`220e5cde645febea5f521c5584dd41dbd9b6b296`).
  Upgrades are deliberate submodule bumps.
- **`build/build-bouncyhsm.sh`** (Linux, macOS) and **`build/build-bouncyhsm.ps1`** (Windows):
  `build-bouncyhsm.{sh,ps1} <test-output-dir> [rid]`. They are idempotent and skip work when the
  outputs are newer than the submodule HEAD. When the submodule is missing, they exit non-zero with
  "run `git submodule update --init vendor/bouncyhsm`", like `build-abi-probe.sh`.
  1. **Server:** `dotnet publish vendor/bouncyhsm/src/Src/BouncyHsm/BouncyHsm.csproj -c Release -o
     <out>/bouncyhsm/server`. This is portable `net10.0` output and the same on every OS. A cold
     publish took about 3m20s locally, mostly NuGet restore.
     - Upstream's `src/Directory.Build.props` does not import ours, so our `TreatWarningsAsErrors`
       does not reach the vendored build.
     - The NU1903 warnings from upstream's pinned ASP.NET 10.0.12 packages stay in that build.
     - The server binds only to loopback, so those advisories don't affect a test-only server.
  2. **Native client**, staged at `<out>/bouncyhsm/runtimes/<rid>/native/`:
     | RID | Build | Staged name |
     |---|---|---|
     | linux-x64 | `make -C vendor/bouncyhsm/build_linux build64 CC=cc` | `BouncyHsm.Pkcs11Lib.so` |
     | osx-arm64 / osx-x64 | `make -C vendor/bouncyhsm/build_macos` for the runner arch | `libBouncyHsm.Pkcs11Lib.dylib` |
     | win-x64 / win-x86 | MSBuild (`vswhere`) on `BouncyHsm.Pkcs11Lib.vcxproj`, `Platform=x64` / `Win32` | `BouncyHsm.Pkcs11Lib.dll` |
     | linux-arm64, win-arm64 | none: the script prints "skipped" and exits 0 | none |

     The macOS Makefile targets and outputs still need to be confirmed during implementation;
     upstream CI builds them with a plain `make`.
- **csproj target** `BuildBouncyHsm`, `BeforeTargets="PrepareForBuild"`. It is opt-in with
  `-p:BuildBouncyHsm=true`, like `BuildKryoptic`, so a plain local build does not pay for the publish.
  `SkipNativeBuilds=true` and `SkipBouncyHsmBuild=true` turn it off.

## 2. `BouncyHsmBackendFixture`

`tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/BouncyHsmBackendFixture.cs`,
implementing `IPkcs11Backend` and `IDisposable`, with `[CollectionDefinition("BouncyHsm")]`.

### Locating the server

- `Settings.BouncyHsmDirectory` reads `PKCS11_TEST_BOUNCYHSM_DIR` and falls back to
  `<test-assembly-dir>/bouncyhsm`.
- It must contain `server/BouncyHsm.dll` and `runtimes/<rid>/native/<lib>`.
- `static bool BouncyHsmAvailable` only checks that those two files exist. It never starts a process,
  because xUnit evaluates it before any fixture exists.

### Starting the server (constructor)

1. Pick two free loopback ports, one TCP and one HTTP, by binding a socket to port 0 and releasing it.
   If start-up fails, retry once with new ports to cover the small race.
2. Start the server: `<dotnet> <dir>/server/BouncyHsm.dll`, where `<dotnet>` is `DOTNET_HOST_PATH`
   when set and otherwise `dotnet` on `PATH`. That way the server runs on the same .NET install, and
   so the same arch, as the test host. Environment:
   - `PersistenceStorageType=InMemory`
   - `BouncyHsmSetup__TcpEndpoint__Endpoint=127.0.0.1:<tcp>`
   - `Kestrel__Endpoints__Http__Url=http://127.0.0.1:<http>`
   - `BouncyHsmSetup__EnableSwagger=false`
   - `Serilog__MinimumLevel__Default=Warning`

   Stdout and stderr are drained into a bounded ring buffer, about the last 200 lines, which is
   attached to any start-up exception.
3. Readiness: poll `GET /Slot` until it returns 200. Timeout 60 s. If the process exits first, fail
   at once with its output.
4. Create the slot with `POST /Slot`:
   - `IsHwDevice=true`, `Description="kl-bouncyhsm"`
   - token `Label=Settings.BouncyHsmTokenLabel`, which reads `PKCS11_TEST_BOUNCYHSM_TOKEN` and
     defaults to `kl-bouncyhsm`
   - `UserPin=Settings.UserPin`, `SoPin=Settings.SoPin`
   - `SpeedMode=WithoutRestriction`, `SimulateHwRng=true`, `SimulateHwMechanism=true`, other
     simulations off

   PINs are never logged or included in exception messages.
5. Set `BOUNCY_HSM_CFG_STRING=Server=127.0.0.1; Port=<tcp>; LogTarget=ErrorConsole; LogLevel=Error;`
   both through `Environment.SetEnvironmentVariable` and through libc `setenv`. The client reads its
   config from `getenv` in a load-time constructor on Unix, and from `GetEnvironmentVariable` in
   `DllMain` on Windows.
   - It has to be set **before** `Pkcs11Library.Load`, and the address is then fixed for the process.
     That's fine with one collection fixture.
   - The libc `setenv` P/Invoke now in `KryopticBackendFixture` moves to a shared
     `Support/NativeEnvironment.cs`, and both fixtures use it.
6. `Pkcs11Library.Load`, then find the slot whose token label matches, and set `SlotId` and
   `SupportedMechanisms` from `GetMechanismList()`.

### Failure policy

- Backend files absent: the gate is false and every BouncyHsm test skips.
- Files present but start-up fails: the constructor throws and the BouncyHsm tests fail loudly.

### Teardown

- `Dispose` unloads the library first, then calls `Process.Kill(entireProcessTree: true)` and waits
  up to 10 s for exit.
- An `AppDomain.ProcessExit` handler does the same kill.
- A test host that is hard-killed can leave an orphan server behind. It holds nothing on disk and
  listens only on random loopback ports, so the next run is unaffected. This is a documented
  limitation; there is deliberately no Job Object or watchdog.

### Interface members

`SupportsTokenObjects` and `RequiresUserLogin` keep their defaults (true). `Supports(CKM)` uses the
mechanism list. `AeadAuthFailureCode` keeps its default unless the implementation run shows otherwise.

## 3. Test wrappers, quirk gates and conventions

### Wrappers

- One hand-written `*.BouncyHsm.cs` per shared test case, covering the union of the opencryptoki and
  Kryoptic wrapper sets (about 60 files), plus `Integration/Interop/EmptyInputTests.BouncyHsm.cs`.
- Classes are `*_BouncyHsm` with `[Collection("BouncyHsm")]`, and each test carries the standard
  `SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable)` boilerplate.
- Cases the spike did not cover are run during implementation and gated only when there is a cause
  traced to BouncyHsm.

### Quirk gates

Each gate lives once on the fixture, with a doc comment linking the upstream issue:

| Quirk | Gate | Applies to |
|---|---|---|
| Zero-length data refused: `C_Digest`/`C_DigestUpdate`/`C_Verify` → `CKR_ARGUMENTS_BAD`, `C_Sign` → `CKR_GENERAL_ERROR` (#115) | `static bool BouncyHsmAcceptsEmptyInput => false` | the EmptyInput SHA-256 and HMAC wrappers, and any other empty-input case shown to fail for this reason |
| An RSA-PSS signature ≥ the modulus gives `CKR_GENERAL_ERROR`, not `CKR_SIGNATURE_INVALID` (#116); depends on the random data | `static bool BouncyHsmRejectsOutOfRangeSignatures => false` | the `SignVerifyData_Pss_RoundTrips` wrapper |
| RSA modulus limited to 2048–6144 bits in steps of 1024 (by design) | none | the BouncyHsm wrapper's `[InlineData]` lists 2048, 3072 and 4096 only |
| No `CKM_AES_KEY_WRAP` (not advertised) | `_backend.RequireMechanism(CKM.CKM_AES_KEY_WRAP)` in the wrapper | `AesKeyWrap_WrapUnwrap_RoundTrip`; it starts running if upstream adds the mechanism |
| `CKR_BUFFER_TOO_SMALL` without the required length (#114) | none | handled in the library by PR 1 |

**Each gate has a test that confirms the quirk is still there.** Every quirk gate has a
`*_QuirkStillPresent` test in `Integration/Compat/BouncyHsmQuirkTests.cs` that reproduces the quirk
directly and asserts the wrong behaviour. When an upstream fix arrives with a submodule bump, that
test goes red and points at the gate to remove. The #116 test uses an all-`0xFF` signature, which is
always ≥ the modulus, so it doesn't depend on random data.

### Conventions and guard tests

- `Unit/Architecture/TestCollectionConventionTests.cs`: add `("_BouncyHsm", "BouncyHsm")` to `BackendNameSuffixes`.
- `Integration/Smoke/BouncyHsmAvailabilityTests.cs`: fails when `PKCS11_TEST_EXPECT_BOUNCYHSM=1` and
  the backend is unavailable, like the Kryoptic, opencryptoki and NSS guards.
- `Support/Settings.cs`: `BouncyHsmDirectory` and `BouncyHsmTokenLabel`.

## 4. CI, coverage and docs

### `ci.yml` / `build-and-test`

- Matrix field `bouncyhsm: true` on ubuntu-latest, macos-latest, macos-15-intel, windows-latest (x64)
  and windows-latest (x86). It is absent on ubuntu-24.04-arm and windows-11-arm.
- On legs with that field:
  - A cache step for `<test-out>/bouncyhsm`, keyed on the `vendor/bouncyhsm` submodule SHA, the hash
    of `build/build-bouncyhsm.*` and the RID. On a hit, the build passes `-p:SkipBouncyHsmBuild=true`;
    on a miss, it passes `-p:BuildBouncyHsm=true`.
  - The NuGet package cache covers the vendored restore too.
  - The Test step sets `PKCS11_TEST_EXPECT_BOUNCYHSM=1`.
- No new apt or brew packages: `build-essential` and the Xcode toolchain are already there. Windows
  uses the preinstalled VS Build Tools through `vswhere`.

### `code-quality.yml`

Add `BuildBouncyHsm: 'true'` next to Kryoptic, so BouncyHsm runs count toward Sonar coverage.

### Docs

- `README.md`: the vendored-backends sentence becomes "pkcs11-mock, SoftHSMv2, opencryptoki, NSS,
  Kryoptic, BouncyHsm". This also fixes the existing omission of NSS and Kryoptic.
- `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/README.md`: add `BouncyHsm` (and the
  missing `Kryoptic`) to the collection table, plus a "Running against BouncyHsm locally" section:
  `git submodule update --init vendor/bouncyhsm`, then `dotnet test … -p:BuildBouncyHsm=true`. The
  fixture starts and stops the server itself.
- `BACKLOG.md`: one entry each for harrison314/BouncyHsm#114, #115 and #116, naming the gate to remove
  once upstream ships a fix.

## Risks

| Risk | Mitigation |
|---|---|
| Cold `dotnet publish` (about 3m20s) slows CI | cache keyed on the submodule SHA; a warm leg pays only the server start-up of 2–3 s |
| The macOS or Windows native build differs from upstream CI | confirm early in the implementation, starting with the macOS legs; upstream CI builds both |
| Port race between choosing and binding | retry once with new ports |
| A loopback TCP server behaves differently on runners (firewall prompts on Windows) | bind only to `127.0.0.1`; the first Windows CI run confirms nothing blocks it, and the readiness timeout turns a block into a clear failure |
| A server crash in the middle of a run | `OpenSession` failures surface as test failures; the ring buffer captures server output for diagnosis |
| Upstream fixes a quirk | the `*_QuirkStillPresent` tests go red on the submodule bump |
