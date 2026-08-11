# Library Review Backlog

_Generated 2026-07-09, extended 2026-08-11 from a second full multi-specialist deep review (cryptography ×2, PKCS#11 v3.2 conformance ×2, .NET library design + P/Invoke ×2, QA & release engineering ×3). Both rounds deduplicated overlapping findings and re-verified every Critical/High citation against the source; the 2026-08-11 round added BL-063 – BL-156, corrected three coverage-matrix rows, and repaired this file's missing `## Low` heading._

## Summary

- Total items: 156 (36 resolved, 120 open)
- Critical: 0 | High: 32 (22 open, 10 resolved) | Medium: 86 (70 open, 16 resolved) | Low: 38 (28 open, 10 resolved)
- Headline risks:
  - **The advertised streaming surface does not exist, and the previous coverage matrix said it did.** No multi-part or streaming operation is reachable from the public API, and multi-part *sign* is not implemented at any layer — `C_SignUpdate`/`C_SignFinal`/`C_SignRecover` have zero callers outside `Native/` while their encrypt/digest/verify counterparts all have wrappers. A consumer cannot sign or encrypt a payload larger than memory (BL-087, BL-099). Two matrix rows have been corrected below.
  - **Nine public-API decisions are cheap now and SemVer-major later — five of them now settled.** Exceptions did not derive from `CryptographicException`, so `catch (CryptographicException)` around the BCL-shaped façades silently failed; they now do (BL-063, resolved); `ECCurve` collided with `System.Security.Cryptography.ECCurve` and is now `Pkcs11ECCurve`, with a reflection guard against the next such clash (BL-066, resolved); 96 `CKF`/`CK`/`CKZ` constants published the platform-width-dependent third-party `NativeCULong` and are now `ulong`, with that package gone from the public surface entirely (BL-067, resolved); every `CK_VERSION` reached the API as a lossy string in which a v3.1 module rendered as `"3.01"` and is now a comparable `System.Version` (BL-068, resolved); and `LoadStaticallyLinked()` could not work on any shipped RID because `__Internal` is Mono-only, and now resolves against the entry-point module instead (BL-064, resolved). The set is BL-063 – BL-071.
  - **The secure-defaults story has three real holes.** The insecure-mechanism gate omits `CKM_EXTRACT_KEY_FROM_KEY` and the `CKM_CONCATENATE_*` family — Clulow's canonical key-extraction attack — in both the runtime gate and the shipped analyzer; the key generators grant `CKA_WRAP`+`CKA_DECRYPT` and `CKA_ENCRYPT`+`CKA_UNWRAP` on one key, which is the textbook wrap-oracle and unwrap-injection pair; and the ECDH peer public key is never curve-matched or point-validated before reaching the token, which is invalid-curve private-key recovery against a key the library sells as non-extractable (BL-070, BL-074, BL-080).
  - **Session and library lifetime is not safe under concurrency, and only one workspace per slot actually works.** `Pkcs11Library.Dispose()` closes tracked sessions outside the busy lock BL-015 added; `LowLevelPkcs11Library.Dispose` unmaps the module *before* setting a non-`volatile` disposed flag; `C_Finalize` is decided per instance, so one instance tears down global state under another's live sessions; `CloseAllSessions()` strands handles that a later finalizer can use to close an unrelated live session; and the second `OpenWorkspace` on a slot throws `CKR_USER_ALREADY_LOGGED_IN` while disposing either logs the other out (BL-078 – BL-085).
  - **Roughly half the test suite cannot fail.** 1005 of ~2060 test attributes are gated, the `PKCS11_TEST_EXPECT_*` guards check only backend *presence* and never mechanism availability, and no CI step counts skips — so a degraded OpenSSL 3.5 step would skip every ML-DSA/ML-KEM test with CI still green. Eighteen `[ConditionalFact]`s sit behind hard-coded `false` constants and four such gates have no consumer at all (BL-086, BL-129).
- Release-readiness assessment: The core remains unusually strong for a pre-1.0 library, and this second review confirmed that independently: the Windows `Pack=1`/`NativeCULong` scheme is complete and correct on all six RIDs (33 of 33 struct-taking entry points have a `_Windows` sibling and a matching dispatch guard), every PKCS#11 constant value matches the vendored headers exactly with zero mismatches, `CK_FUNCTION_LIST_3_2` field order is exact, no managed↔native parameter-struct layout defect exists, and PIN handling, logging and exception messages leak nothing. **No Critical was confirmed** — no memory-corruption or key-leakage defect is reachable without either a caller error or a deliberately extractable key. What has changed since the first review is the assessment of *completeness*: the gap between what the API promises and what it exposes is larger than the first pass recorded, and it is concentrated in exactly the places SemVer makes permanent. Before a confident 1.0 the 22 open High items must land, led by the four still-open "Breaks public API? Yes" decisions (BL-063 – BL-071, of which BL-063, BL-064, BL-066, BL-067 and BL-068 are resolved) and the four lifetime/concurrency defects (BL-078, BL-082, BL-083, BL-085); the release scaffolding gaps carried over from the first review (BL-001, BL-002, BL-004) remain unaddressed; and the test-gate census (BL-086, BL-129) should land early, because it is what will tell you whether the rest of the suite is really green.

## Critical

_None. No memory-safety, key-leakage, or silent-data-corruption defect was confirmed at the P/Invoke boundary in either review round._

Three findings came closest and were deliberately held at High rather than inflated, because each requires a caller action or a non-default posture to become exploitable: **BL-075** (a caller-supplied bit-length that exceeds its own buffer makes the module read past an allocation — genuine out-of-bounds, but caller-triggered), **BL-080** (invalid-curve ECDH recovers a token-resident private key, but only through the raw-secret read-back path, which is itself `AllowInsecure`-gated), and **BL-070** (the wrap-oracle role conflict exfiltrates only a key the caller deliberately made extractable). All three should be treated as pre-1.0 blockers regardless of the label.

## High

### [BL-001] Publish workflow cannot succeed: no submodules, but solution-wide build/test triggers native vendor builds
- **Area:** Release Eng
- **Severity:** High
- **Effort:** S
- **Location:** `.github/workflows/publish.yml:17-36`
- **Problem:** The publish job checks out without `submodules:` yet runs `dotnet build`/`dotnet test` on the full solution. Building the test project fires the `BuildPkcs11Mock`/`BuildSoftHsmV2` targets (`src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj:36,49`, gated only on unset `Skip*` properties) against uninitialized `vendor/` directories with no native toolchain installed. A `v*` tag push can never reach the pack/push steps. Verified by the coordinator.
- **Proposed action:** Build and pack only the shippable library project in `publish.yml` (release gating stays in `ci.yml`), or add `submodules: recursive` plus the native deps and cache. The dedicated release build of just `KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` is the cleaner fix.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-002] No public-API contract gate: no PublicApiAnalyzers, no API snapshot test, no package validation
- **Area:** Cross-cutting
- **Severity:** High
- **Effort:** S
- **Location:** repo-wide — no `PublicAPI.Shipped.txt`/`Unshipped.txt`, no `EnablePackageValidation`, no PublicApiGenerator/ApiCompat anywhere (verified); `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`, `Directory.Build.props`
- **Problem:** Nothing fails a build or PR when the public surface changes. For a library whose stated #1 concern is that public-surface mistakes are permanent under SemVer, an accidental `public`, a widened signature, or a dropped overload ships silently. This also leaves the `NativeCULong` per-RID asset layout unguarded across releases.
- **Proposed action:** Add `Microsoft.CodeAnalysis.PublicApiAnalyzers` with checked-in `Shipped`/`Unshipped` files (every PR then carries a reviewable surface diff), and/or a PublicApiGenerator golden-file test. Enable `Microsoft.DotNet.PackageValidation` with a baseline once 1.0.0 ships. Must land before 1.0 so the 1.0 surface is the frozen baseline.
- **Breaks public API?** No
- **Raised by:** QA A, QA C, .NET Engineer A, .NET Engineer B

### [BL-003] ✅ RESOLVED — Vendor-defined / unknown return codes throw a bare `InvalidEnumValueException` instead of a typed `Pkcs11Exception`
- **Status:** Resolved 2026-07-10. `ToCKR()` and `ToCKM()` are now non-validating casts (documented as deliberate: return-path values are module-controlled and vendor codes are spec-legal), so unknown codes flow into `ExceptionMapper`'s existing fallback and surface as `Pkcs11UnclassifiedException` with `ReturnValue` preserving the raw code. `Pkcs11Exception` messages render undefined codes as hex ("vendor-defined CKR 0x80000123" / "unrecognized CKR 0x0000FFFF") instead of bare decimal. The other 11 `ToCK*` converters keep validation — they convert caller-supplied values, where fail-fast is the intended design, and have no production read-back call sites. Tests updated/added (vendor pass-through, mapper categorization, ThrowIfError end-to-end); full suite green (1647 passed).
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKR.cs:548-554` (`ToCKR`); consumed on ~130 return paths in `Native/LowLevelPkcs11Library.cs`; parallel issue in `Common/CKM.cs` (`ToCKM`)
- **Problem:** `ToCKR()` validates with `Enum.IsDefined` and throws `InvalidEnumValueException` — which derives from `Exception`, not `Pkcs11Exception` (verified: `Exceptions/InvalidEnumValueException.cs:14`) — for any value not in the enum. PKCS#11 explicitly permits vendor-defined codes ≥ `CKR_VENDOR_DEFINED = 0x80000000` and real HSMs return them; a spec-legal code bypasses the entire typed error model. The Windows struct paths cast directly and pass vendor codes through, so behavior is also platform-inconsistent. Same forward-compat trap for future standard codes.
- **Proposed action:** Make `ToCKR()` a non-validating cast (the mechanism-list path already does this deliberately at `LowLevelPkcs11Library.cs:358-361`) and ensure `Pkcs11Exception` surfaces the raw numeric code for unknown values. `CKR` is ulong-backed so unknown values round-trip losslessly; the fix is non-breaking.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** PKCS#11 v3.2 §3.1; `CKR_VENDOR_DEFINED`

### [BL-004] No SECURITY.md / vulnerability disclosure policy for a cryptography library
- **Area:** Release Eng
- **Severity:** High
- **Effort:** S
- **Location:** MISSING: `SECURITY.md` (verified absent from repo root and `.github/`)
- **Problem:** An HSM/crypto interop library has no documented private disclosure channel, response expectation, or supported-versions statement. Researchers finding a marshalling or key-handling bug have nowhere to report it privately.
- **Proposed action:** Add `SECURITY.md` (enable GitHub Private Vulnerability Reporting, state response SLA and supported versions). Must land before 1.0.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-005] ✅ RESOLVED — The native function-list loader — the code most able to corrupt the process — has no hermetic test
- **Status:** Resolved 2026-07-10. `Delegates` gained an export-resolver seam (`internal Delegates(Func<string, IntPtr>)`; the production `Delegates(IntPtr)` ctor now wraps `NativeLibrary.TryGetExport` in the same resolver — behavior unchanged). New `Unit/Native/DelegatesLoaderTests.cs` drives the REAL loader with no native module: `[UnmanagedCallersOnly]` managed stubs serve `C_GetFunctionList`/`C_GetInterface`, synthetic `CK_FUNCTION_LIST`/`_3_0`/`_3_2` tables live in unmanaged memory with a unique sentinel per slot (written via the same packed-struct dispatch the loader reads with, so valid on Windows too), and a reflection sweep asserts every table slot lands in its same-named `FunctionPointers` field (+`_Windows` sibling). 9 tests cover: exhaustive v2.40 slot binding, per-symbol fallback (also the hermetic half of BL-006), v3.0 interface binding without the v3.2 re-read, v3.2 12-addition binding, sub-3.0 version-header rejection → fallback, C_GetInterface error → fallback, all-null v3.2 table guards, missing bootstrap symbol, and a harness self-check. Full suite green (1656 passed).
- **Area:** QA
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs:1521-1760` (`TryLoadFromGetInterface`, per-symbol fallback), `Native/LowLevelPkcs11Library.cs`
- **Problem:** The loader binds every Cryptoki function pointer by reading raw unmanaged struct offsets and selects v2.40/v3.0/v3.2 from the `CK_VERSION` header. Every test fake implements the managed `ILowLevelPkcs11Library` seam and bypasses this code entirely; a transposed field or mis-sized pointer in `CK_FUNCTION_LIST_3_0`/`_3_2` would surface only if a real CI module happens to exercise the specific mis-bound slot.
- **Proposed action:** Add a hermetic test that constructs synthetic `CK_FUNCTION_LIST_3_0`/`_3_2` tables in unmanaged memory with sentinel pointers, drives the real loader, and asserts each delegate binds to the expected slot. Complements BL-006 and the struct-pin work in BL-024.
- **Breaks public API?** No
- **Raised by:** QA A

### [BL-006] ✅ RESOLVED — The promised v2.40-only fallback path (`C_GetFunctionList`, no `C_GetInterface`) is never exercised
- **Status:** Resolved 2026-07-10 in two halves. Hermetic half (with BL-005): `DelegatesLoaderTests` drives the per-symbol fallback and version-header rejection with synthetic tables. Real-module half: new `build/pkcs11-gate.c` spec-version-gate shims wrap the vendored SoftHSM — `pkcs11-gate240.so` exports only `C_GetFunctionList` (a faithful v2.40-only module), `pkcs11-gate30.so` additionally serves a v3.0-truncated, version-rewritten copy of the interface table (a v3.0-but-not-v3.2 module). Each gate dlopens a private file copy of libsofthsm2 (independent `C_Initialize` state); fixtures (`SoftHsmGate240Fixture`/`SoftHsmGate30Fixture`) live in the "SoftHsm" collection to serialize env-var access. `Integration/Compat/SpecVersionGateTests.cs` (11 tests) validates: v2.40 negotiation (`SupportsMessageApi`/`SupportsV32Api` false), clean `CKR_FUNCTION_NOT_SUPPORTED` from `GetInterfaces`/`LoginUser`/`CancelOperations`, AES-GCM through the v2.40 `ct‖tag` concat fallback against real crypto (previously exercised by no real backend), SHA-256 BCL cross-check, RSA-PSS round-trip; and v3.0 negotiation (message API bound, v3.2 absent), interface enumeration, AEAD round-trip. Built by the `BuildPkcs11Gate` MSBuild target (Linux/macOS; Windows gets the hermetic coverage). Full suite green (1667 passed).
- **Area:** QA
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs:1529-1532` (fallback branch), `:1802-1851` (bootstrap)
- **Problem:** Backward compatibility with v2.40 modules is a non-negotiable goal, but all three CI backends (pkcs11-mock, SoftHSMv2, opencryptoki) export `C_GetInterface`, so the per-symbol legacy fallback binding never runs anywhere. The spec-conformance reviewer confirmed the path is *correct by reading* (nulls leave `IsV32ApiSupported == false`, unsupported calls return `CKR_FUNCTION_NOT_SUPPORTED`), but it has zero executed coverage.
- **Proposed action:** Force the fallback deterministically — a loader shim/test module that hides `C_GetInterface`, or the BL-005 synthetic-loader harness driven through the fallback branch — and assert the resulting library degrades as documented.
- **Breaks public API?** No
- **Raised by:** QA A

### [BL-007] ✅ RESOLVED — ML-DSA / ML-KEM have no independent verification on real backends — flagship PQC ships KAT-free
- **Status:** Resolved 2026-07-09. BCL cross-checks hoisted into the shared backend-agnostic test cases: `MLDsaPkcs11TestCases.Assert_SignData_VerifiesWithBcl` (token signs → BCL `MLDsa` rebuilt from the exported public key verifies, rejects tamper, agrees on context binding; all three parameter sets) and `MLKemPkcs11TestCases.Assert_Decapsulate_BclEncapsulation_MatchesSharedSecret` (BCL encapsulates off-token → token decapsulation must match), both gated on `MLDsa.IsSupported`/`MLKem.IsSupported` and wired into the SoftHSM and opencryptoki wrappers. Fixed ACVP vector files were deliberately deferred (vectors must be sourced from `usnistgov/ACVP-Server`, not fabricated) — track as a follow-up if file-based KATs are still wanted.
- **Area:** QA
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Algorithms/MLDsaPkcs11TestCases.cs:85`, `MLKemPkcs11TestCases.cs:85`; `Integration/Adapters/KnownAnswerTests.SoftHsm2.cs` (no PQC entries — verified)
- **Problem:** Every real-backend PQC test is a self-consistent round-trip (the token both produces and checks), so a wrapper mis-encoding of parameter-set or context that sign and verify share passes silently. The BCL cross-checks exist only in the managed-fake suite, where the "token" is itself BCL-backed. No ACVP/NIST vector for any PQC mechanism exists anywhere — for the library's headline v3.2 differentiator.
- **Proposed action:** Hoist the BCL cross-check (export the token's public/encapsulation key; verify the token's signature / re-encapsulate off-token) into the shared test cases so it runs on SoftHSM and opencryptoki; add NIST ACVP sigVer (ML-DSA) and decapsulation (ML-KEM) vectors where key import is supported. Land pre-1.0.
- **Breaks public API?** No
- **Raised by:** QA B
- **Spec / References:** NIST ACVP; FIPS 203/204

### [BL-063] ✅ RESOLVED — Library exceptions do not derive from `CryptographicException`, so `catch (CryptographicException)` around the BCL-shaped façades does not work
- **Status:** Resolved 2026-08-11. `Pkcs11Exception` (and with it all seven typed subclasses), `InsecureOperationException`, `AttributeValueException` and `InvalidEnumValueException` now derive from `System.Security.Cryptography.CryptographicException`; `ReturnValue`, `Method`, `Mechanism` and `Attribute` are untouched, so narrowing still works and only the base class is added. `InvalidEnumValueException` was reparented too, though the proposed action omitted it (the Location line did list it): it is raised while converting values a module returned mid-operation — its own summary calls that "a protocol violation by the module" — so it escapes a façade call by exactly the same route as the rest. Each type's XML doc now states why it carries the base, since that is the contract consumers rely on, and the README gained a short error-handling section showing the `catch (Pkcs11Exception)` / `catch (CryptographicException)` pair. Three tests in `Unit/Exceptions/CryptographicExceptionContractTests.cs`, written from the caller's side — the façade is held as a BCL `RSA`, not as `RSAPkcs11` — cover a security refusal and a token failure caught as `CryptographicException` with their detail asserted intact, plus a reflection guard that every exported exception type derives from it, verified to fail by reverting one base class. They use `Assert.ThrowsAny` rather than `Assert.Throws`, deliberately: xUnit's `Assert.Throws<T>` demands an exact type match and would reject the very derived types a real `catch` clause accepts, so it would have asserted something other than the contract. Full suite green (2005 passed, 0 failed, 631 gated skips). Does not overlap BL-094, which asks for AEAD tag failures to surface as `AuthenticationTagMismatchException` — that is a narrowing *within* this hierarchy and is still open.
- **Area:** .NET API Design
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Exceptions/Pkcs11Exception.cs:32`, `Exceptions/InsecureOperationException.cs:11`, `Exceptions/AttributeValueException.cs:8`, `Exceptions/InvalidEnumValueException.cs:14`
- **Problem:** Every exception type derives directly from `System.Exception` (verified: `public abstract class Pkcs11Exception(...) : Exception`, `public sealed class InsecureOperationException : Exception`). But `RSAPkcs11 : RSA`, `ECDsaPkcs11 : ECDsa`, `MLDsaPkcs11 : MLDsa` and `HMACPkcs11 : HMAC` are documented as drop-in substitutes — "callers can pass this instance anywhere a BCL `RSA` is accepted" (`Algorithms/RSAPkcs11.cs:12-14`) — and every consumer of those types, plus every generic crypto wrapper in the ecosystem, funnels failures through `catch (CryptographicException)`. A `Pkcs11Exception` escaping `rsa.SignData(...)` therefore bypasses the caller's error handling entirely.
- **Proposed action:** Reparent `Pkcs11Exception`, `InsecureOperationException` and `AttributeValueException` onto `System.Security.Cryptography.CryptographicException`, keeping `ReturnValue`/`Method`.
- **Breaks public API?** Yes — changing an exception base class is SemVer-major; must land before 1.0
- **Raised by:** .NET Engineer A
- **Spec / References:** Framework Design Guidelines §7.3; `System.Security.Cryptography` convention

### [BL-064] ✅ RESOLVED — `LoadStaticallyLinked()` cannot work on any RID the package ships — `__Internal` is a Mono-only convention
- **Status:** Resolved 2026-08-11 by the entry's first option — fixed, not deprecated or deleted. The reviewer's diagnosis reproduced exactly: with the old bootstrap in place the new behavioural test fails with `DllNotFoundException: Unable to load shared library '__Internal'`, CoreCLR having gone looking for a real `__Internal.so`. The static branch of `Delegates(IntPtr)` is now `Load(ResolverFor(NativeLibrary.GetMainProgramHandle()))`, so the static path is the ordinary load sequence over a different handle rather than a separate bootstrap: same `C_GetFunctionList` entry, same best-effort v3.0/v3.2 binding, same graceful degradation for exports a v2.40-only module omits. That collapsed three things — the `NativeMethods` class, the parameterless `InitializeWithGetFunctionList()` overload, and the try/catch that previously swallowed a failure to reach the process symbol table (now load-bearing, because the bootstrap needs the same handle) — and dropped `partial` from `Delegates`, since the `[LibraryImport]` source generator was the only reason for it. Two tests, both verified to fail against the old code by restoring it: `LoadStaticallyLinked` on a host that exports no bootstrap now reaches the intended `EntryPointNotFoundException` naming `C_GetFunctionList` instead of failing earlier for the wrong reason, and a reflection guard asserts the assembly declares **zero** P/Invokes — the right invariant to hold, because everything else dispatches through the `CK_FUNCTION_LIST` pointer table, so any new P/Invoke is the shape this defect would return in whatever library name it named. The public XML doc no longer prescribes `DllImport("__Internal")`; it states the actual requirement (the host must export `C_GetFunctionList` from its entry-point module, via `DirectPInvoke` plus a linker export under Native AOT), documents `EntryPointNotFoundException`, and drops the unreachable iOS claim, since the package ships no `ios`/`maccatalyst`/`android` TFM. The stale internal comment on `LowLevelPkcs11Library`'s parameterless constructor was corrected too. Full suite green (2002 passed, 0 failed, 631 gated skips).
  - **Follow-up 2026-08-11 — the end-to-end AOT case the entry asked for now exists, and it found a second requirement.** The hermetic tests above prove the `__Internal` defect is gone; they cannot prove a real static link *succeeds*, and nothing in the repo had ever loaded a statically-linked module. `build/build-pkcs11-mock-static.sh` now builds pkcs11-mock as a PIC archive, and `tests/AotSmoke` links it into the Native AOT binary behind `-p:StaticMockArchive=<path>`, so one published binary covers both ways in: `AotSmoke <path>` (dlopen) and `AotSmoke static` (`LoadStaticallyLinked`). Both run green in the `aot-smoke` CI job, which also asserts the bootstrap is actually exported (`nm -D`) so a linker regression fails saying so rather than as a bare "entry point not found". Getting there surfaced a requirement no amount of reading would have: **linking the archive in is not sufficient under Native AOT, twice over.** A static archive contributes only members that resolve an undefined reference and nothing in a managed binary names the bootstrap, so the member is dropped silently (`--undefined=C_GetFunctionList` forces it); and ILC generates an exports file reading `global: DotNetRuntimeDebugHeader; local: *;` and hands it to the linker, which hides the symbol regardless of any export flag also passed — including the blanket `--export-dynamic` ILC itself passes. Each failure mode presents identically, as `EntryPointNotFoundException`. Both are now written up on `LoadStaticallyLinked`'s remarks, which is the part a consumer actually needs and which the entry's "add an AOT-smoke case" would not have produced on its own.
- **Area:** P/Invoke
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs:37-39` (`[LibraryImport("__Internal")]`); public entry `Pkcs11Library.cs:77-89`
- **Problem:** The static-link bootstrap is `[LibraryImport("__Internal")] C_GetFunctionList`. `"__Internal"` is a **Mono** runtime special case; CoreCLR and Native AOT do not implement it and instead try to load a native library literally named `__Internal` (the reviewer confirmed `DllNotFoundException` with a minimal net10.0 repro). The package is `net10.0` with RIDs `win-x86;win-x64;linux-x64;linux-arm64;osx-x64;osx-arm64` and no `ios`/`maccatalyst`/`android` TFM, so the Mono path is unreachable from any shipped asset — yet the XML doc advertises this as the entry point for "iOS, Native AOT, single-file embedded builds". Native AOT statically links via `DirectPInvoke`, not `__Internal`. No test references the method. Verified by the coordinator.
- **Proposed action:** Replace the bootstrap with the mechanism this same file already uses for the v3.0 half — `NativeLibrary.GetMainProgramHandle()` + `NativeLibrary.TryGetExport` (`Delegates.cs:1506`, `:1537`) — which works on CoreCLR and Native AOT and removes the only `[LibraryImport]` in the assembly. Add an AOT-smoke case. Otherwise mark it `[Experimental]` or delete it before 1.0.
- **Breaks public API?** Yes — deleting or re-specifying a public static factory is SemVer-major; must land before 1.0
- **Raised by:** .NET Engineer B
- **Spec / References:** .NET `NativeLibrary.GetMainProgramHandle`; Native AOT `DirectPInvoke`

### [BL-065] Verify throws instead of returning `false` for a wrong-length signature, diverging from the BCL contract it mirrors
- **Area:** Cryptography
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs` (`IsVerified`); consumers `Algorithms/ECDsaPkcs11.cs:125-131`, `Pkcs11Key.cs:350-360`
- **Problem:** `IsVerified` maps `CKR_OK` to `true` and `CKR_SIGNATURE_INVALID` to `false`, then throws for everything else — including `CKR_SIGNATURE_LEN_RANGE`, which is exactly what a token returns for a truncated or over-long signature. So `ECDsaPkcs11.VerifyHash`, `RSAPkcs11.VerifyHash` and `DSAPkcs11.VerifySignature` throw on attacker-supplied malformed input where `System.Security.Cryptography` returns `false`. Every signature negative test in the suite flips a byte in a *correctly sized* signature, so nothing catches it. Verified by the coordinator.
- **Proposed action:** Treat `CKR_SIGNATURE_LEN_RANGE` (and arguably `CKR_DATA_LEN_RANGE` on the verify path) as `false` in `IsVerified`, and add length-varying negatives — truncate by one byte, extend by one byte, empty — to every sign/verify test-case class so the divergence cannot return.
- **Breaks public API?** Yes — behavioural: a call that throws today would return `false`; cheap now, needs a compat switch later. Must land before 1.0
- **Raised by:** QA B
- **Spec / References:** PKCS#11 v3.2 `C_Verify` (`CKR_SIGNATURE_LEN_RANGE` = "the signature is of an invalid length"); `ECDsa.VerifyHash`/`RSA.VerifyHash` return `false` for malformed signatures

### [BL-066] ✅ RESOLVED — The public `ECCurve` collides with `System.Security.Cryptography.ECCurve` — the library's own code needs an alias to compile
- **Status:** Resolved 2026-08-11. The struct is now `Pkcs11ECCurve` (`Pkcs11ECCurve.cs` / `Pkcs11ECCurve.NamedCurves.cs`), with the `FromECCurve`/`ToECCurve` bridges and the whole `NamedCurves` catalog unchanged; `Pkcs11Workspace.GenerateEcKeyPair(Pkcs11ECCurve? …)` is the only signature affected. `Pkcs11ECCurve` was chosen over `CkEcCurve` because the type is a managed abstraction over `CKA_EC_PARAMS`, not a `CK_*` struct projection, so the `Ck*` prefix would have misfiled it. All four internal `using BclECCurve = …` aliases are gone — the library now writes bare `ECCurve` where it means the BCL type, which is the proof the collision is closed; the test fakes' fully-qualified `System.Security.Cryptography.ECCurve` was simplified for the same reason. The `BclECCurve` alias survives only in the test files that deliberately juxtapose both types (`(Pkcs11ECCurve token, BclECCurve bcl)`), where it is a readability choice rather than a necessity. New `Unit/PublicTypeNameCollisionTests.cs` guards the whole exported surface by reflection — no non-nested public type may share a simple name with a `System.Security.Cryptography` type — so the next type added cannot reintroduce the clash; it asserts the BCL name set is non-empty first, so it cannot pass vacuously. Full suite green (1983 passed, 0 failed, 631 gated skips).
- **Area:** .NET API Design
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/ECCurve.cs:25` (`public readonly partial struct ECCurve`, namespace `…Pkcs11` at `:5`); the collision is demonstrated by the library's own aliases in `ECCurve.cs`, `Pkcs11PublicKeyView.cs`, `Algorithms/ECDsaPkcs11.cs`, `Algorithms/ECDiffieHellmanPkcs11.cs` (`using BclECCurve = System.Security.Cryptography.ECCurve;`)
- **Problem:** A consumer of a cryptography library will almost always have `using System.Security.Cryptography;` in scope. Adding `using KerckhoffsLabs.Security.Cryptography.Pkcs11;` then makes every bare `ECCurve` reference ambiguous (CS0104) — including the documented `Pkcs11Workspace.GenerateEcKeyPair(ECCurve? …)` call and `ECCurve.NamedCurves.NistP256`. That the library itself needed four internal aliases in four separate files is the tell. Verified by the coordinator.
- **Proposed action:** Rename to a non-colliding, intent-revealing name (`Pkcs11ECCurve`, or `CkEcCurve` to match the `Ck*` family) and keep the `FromECCurve`/`ToECCurve` bridges.
- **Breaks public API?** Yes — renaming a public type is SemVer-major; must land before 1.0
- **Raised by:** .NET Engineer A
- **Spec / References:** Framework Design Guidelines §3.2.3 — avoid names that conflict with types in namespaces likely to be used together

### [BL-067] ✅ RESOLVED — `NativeCULong` — a third-party, platform-width-dependent type — is on the public surface via 96 `CKF`/`CK`/`CKZ` constants
- **Status:** Resolved 2026-08-11. The 96 constants are now `public const ulong` — `const`, not `static readonly`, so they are usable in `case` labels and attribute arguments — and `CK.IsCkInformationUnavailable` takes a `ulong`. `[Flags]` enums were the wrong shape for this class of constant and were rejected: `CKF` is a *mixed* bit space where the same value means different things per context (`CKF_TOKEN_PRESENT`, `CKF_RNG` and `CKF_HW` are all `0x1`), the typed per-context view already exists as the `SlotFlags`/`TokenFlags`/`SessionFlags`/`MechanismFlags`/`InterfaceFlags`/`LibraryFlags` records, and an enum would have *re-added* the cast this entry exists to remove, since those records expose `ulong Flags`. Fixing only the 96 constants would have left the goal unmet, so the 13 `CK*Extensions` classes — 26 public `ToCULong`/`ToCK*` methods, the last public `NativeCULong` signatures, and used by nothing outside `Native/`, `MechanismParams/` and `Internal/` — are now `internal`, and the six flag records' internal constructors take `ulong`. `NativeCULong` is therefore absent from the public surface: a consumer no longer references the interop package at all, and seven test files dropped their `using KerckhoffsLabs.Runtime.InteropServices;` outright. `CK_UNAVAILABLE_INFORMATION` remains `static readonly` rather than `const` and still varies by platform — that is not an accident to fix but the spec's definition (all bits set in a `CK_ULONG`, whose width is 32-bit on Windows and pointer-sized elsewhere), and since token-reported counts widen to `ulong` verbatim the sentinel must match that width to be comparable; it is now derived from the marshalled width (`UnmanagedMemory.NativeULongSize`) rather than an `OperatingSystem.IsWindows()` branch, which is also correct on 32-bit Unix, and the reason is documented on the field. New `Unit/PublicSurfaceDependencyTests.cs` walks every exported type's fields, method/constructor parameters, return types, bases and interfaces — unwrapping by-ref, array and generic decoration — and fails if any names a type from the interop assembly; it was verified to fail by re-publicising `CKRExtensions`, and a companion test asserts the marshalling layer still holds `NativeCULong` fields so an empty offender list cannot mean the package simply left the build. Internal call sites got simpler rather than noisier: the cancel-flag accumulation in `Pkcs11Session` is now plain `ulong cancelFlags |= CKF.CKF_DIGEST` instead of a double cast, and the six flag records lost `.Value` from all 68 predicates. Full suite green (1985 passed, 0 failed, 631 gated skips).
- **Area:** .NET API Design
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKF.cs` (68 members), `Common/CK.cs` (26), `Common/CKZ.cs` (2) — all `public static readonly NativeCULong`; the library's own workaround at `SessionFlags.cs:15,19`, `SlotFlags.cs:15,19,23`, `InterfaceFlags.cs:15`
- **Problem:** All flag and sentinel constants are `NativeCULong` from the separate `KerckhoffsLabs.Runtime.InteropServices` package — a type whose *width differs per RID* (4-byte on Win64, `nuint` elsewhere) and which ships as a per-RID runtime asset. Three consequences: the constants do not compose with the library's own `ulong`-typed flag properties without reaching for `.Value` (the library itself writes `Flags & CKF.CKF_RW_SESSION.Value`); consumers take a hard public-API dependency on an interop package they otherwise never need; and any breaking change in that package becomes a breaking change here. `CK.CK_UNAVAILABLE_INFORMATION` is even branch-computed from `OperatingSystem.IsWindows()`, so its public value differs by platform. Verified by the coordinator (counts exact).
- **Proposed action:** Keep `NativeCULong` strictly inside `Native/`; publish the constants as `ulong` (or `[Flags]` enums) and add `ulong`-typed helpers, since today's `CK.IsCkInformationUnavailable` only accepts `NativeCULong`.
- **Breaks public API?** Yes — constant type changes are SemVer-major; must land before 1.0
- **Raised by:** .NET Engineer A
- **Spec / References:** Extends BL-040, which settled the `CKM`/`ulong` boundary but left the `CKF`/`CK`/`CKZ` constant classes handing `NativeCULong` to consumers

### [BL-068] ✅ RESOLVED — Every `CK_VERSION` reaches the public API only as a lossy, ambiguous string — no programmatic version comparison is possible
- **Status:** Resolved 2026-08-11. All six version-bearing properties (the entry said five; `LibraryInfo` has two, `SlotInfo` two and `TokenInfo` two) are now `System.Version`, built by a new `CK_VERSION.ToVersion()` that carries `Major`/`Minor` verbatim. Verbatim is the correct mapping and not a shortcut: both the spec encoding and `Version` order on the raw minor integer, so a v3.01 module (`Minor = 1`) sorts below a v3.10 one (`Minor = 10`) either way, and `Build`/`Revision` stay unset because `CK_VERSION` has no such fields. The string form was *not* kept as a sibling property, which is a deliberate departure from the entry's "alongside the display string": its ambiguity is the defect, and a property whose only use is display would go on being compared. `CK_VERSION.ToString()` keeps the spec rendering for logs and the debugger, where it is unambiguous because nothing compares it, and each public property documents the hundredths encoding so a consumer wanting the vendor's `"3.01"` can format it in one line. `Pkcs11Library.SupportsCryptokiVersion(int major, int minor)` is the readable form of the comparison and retires the exception-driven `GetInterfaces()` probe; it is named for the *reported spec version* specifically, leaving `Supports…Api` free for the function-table capability probe BL-077 still owns, and its remarks warn that a datasheet's "v3.1" is `(3, 10)`, not `(3, 1)`. New `Unit/CryptokiVersionTests.cs` pins the ordering, the helper (including the v2.40-refuses-v3 case and the disposed guard) and — as the record of *why* this changed — the two concrete traps of the old surface: ordinal text order inverts against real order once a minor passes 99 (NSS softoken reports 3.125, which sorted below a 3.99 module), and `"3.02"` versus `"3.20"` leaves a consumer who means "v3.2" unable to tell which module they are asking for. The rendering theory in `SlotInfoTests` became a raw-field theory over the same values. Full suite green (2000 passed, 0 failed, 631 gated skips).
- **Area:** .NET API Design
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/LibraryInfo.cs:12,24` (assigned `:28,32`), `SlotInfo.cs:24,27`, `TokenInfo.cs:60,63`; formatter `Native/CK_VERSION.cs:19-23`
- **Problem:** All five version-bearing public properties are `string`, produced by `CK_VERSION.ToString()`, which formats minor as `{0:D2}` only when non-zero: `{3,0}` → `"3.0"` but `{3,1}` → `"3.01"`, `{3,2}` → `"3.02"` and `{3,20}` → `"3.20"`. A consumer cannot compare, sort or `Version.Parse` these reliably; `if (info.CryptokiVersion >= "3.1")` is silently wrong, and `"3.02"` vs `"3.2"` is a genuine ordering trap. For a library whose headline promise is one managed surface across v2.40/3.0/3.1/3.2, the module's spec version is the most important datum in `CK_INFO` and it is reachable only by string-parsing — the alternative being exception-driven control flow through `GetInterfaces()` (`Pkcs11Library.cs:244-248`). Verified by the coordinator.
- **Proposed action:** Expose a comparable type — `System.Version` or a `public readonly record struct CkVersion(byte Major, byte Minor) : IComparable<CkVersion>` — alongside the display string, plus a `SupportsVersion(3, 2)`-style helper on `Pkcs11Library`.
- **Breaks public API?** Yes — property-type change; must land before 1.0
- **Raised by:** PKCS#11 Specialist A, .NET Engineer A
- **Spec / References:** PKCS#11 v3.2 §3.1 (`CK_VERSION` minor is the hundredths portion), §5.4.2 `C_GetInfo`. BL-020 covers only the *missing* version on `InterfaceInfo`

### [BL-069] `CkmSp800108KdfParams.AdditionalDerivedKeys` returns raw `ulong` handles that no public API can accept
- **Area:** .NET API Design
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismParams/CkmSp800108KdfParams.cs:89` (`public IReadOnlyList<ulong> AdditionalDerivedKeys`); absorbed at `:152-169`
- **Problem:** `AddDerivedKey` lets a caller request sibling keys in one `C_DeriveKey`, and the handles are correctly read back out of the `CK_DERIVED_KEY` array — but the property returns `IReadOnlyList<ulong>` and nothing on the public surface accepts a raw handle (`ObjectHandle`, `Pkcs11Object` and `Pkcs11Key` all have internal constructors). The consumer therefore cannot use the sibling keys for any operation and cannot destroy them; if the per-key template sets `CKA_TOKEN=true` they persist on the token permanently and unreachably. The feature is wired end-to-end at the interop layer and dead at the API layer. Verified by the coordinator.
- **Proposed action:** Return `IReadOnlyList<Pkcs11Key>` (or a disposable list) constructed by the session that performed the derive, since it holds the workspace needed to build them.
- **Breaks public API?** Yes — property-type change; must land before 1.0
- **Raised by:** Cryptographer A
- **Spec / References:** PKCS#11 v3.0 §2.42 (`ulAdditionalDerivedKeys`/`pAdditionalDerivedKeys`); same shape as resolved BL-008

### [BL-070] The secure-defaults key generators grant conflicting wrap/decrypt roles on one key, enabling the classic wrap-oracle and unwrap-injection attacks
- **Area:** Cryptography
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Workspace.cs:373` (`GenerateAesKey`: `.Encrypt().Decrypt().Wrap().Unwrap()`), `:408` and `:414` (`GenerateRsaKeyPair`: public `.Encrypt().Verify().Wrap()`, private `.Sign().Decrypt().Unwrap()`)
- **Problem:** Both helpers put conflicting roles on a single key. With `CKA_WRAP` + `CKA_DECRYPT`, any key a caller deliberately made extractable — which `BuildSecureKeyDefaults` explicitly permits (`Internal/Pkcs11Session.cs:1586-1598`) — can be exfiltrated by `C_WrapKey` followed by `C_Decrypt` of the blob. With `CKA_ENCRYPT` + `CKA_UNWRAP`, a caller can `C_Encrypt` a chosen plaintext and `C_UnwrapKey` it into a fresh *sensitive* key of known value, defeating the sensitivity guarantee for every key so created. Neither the helpers nor the README's wrap-hardening section (which addresses only the *wrapped* key's attributes) applies role separation or a wrap/unwrap template to the wrapping key these helpers produce. Verified by the coordinator.
- **Proposed action:** Split the roles: default `GenerateAesKey` to `Encrypt().Decrypt()` and add an explicit key-encryption-key helper producing a `Wrap().Unwrap()`-only KEK with `CKA_WRAP_TEMPLATE`/`CKA_UNWRAP_TEMPLATE` pinned to sensitive/non-extractable (the builders gained that support in BL-018); likewise split `GenerateRsaKeyPair` into a signing pair and a key-transport pair. Document the conflict in the security-model section.
- **Breaks public API?** Yes — changes what the helpers emit and adds parameters/overloads; must land before 1.0
- **Raised by:** Cryptographer B
- **Spec / References:** Clulow, *On the Security of PKCS#11* (CHES 2003); Bortolozzo et al., CCS 2010; PKCS#11 v3.2 §5.2 attribute-conflict guidance

### [BL-071] `Pkcs11Slot.CloseAllSessions()` invalidates every tracked session handle with no bookkeeping — a later finalizer can close an unrelated live session
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Slot.cs:221-229`; the handles it strands are at `Internal/SafeHandles/Pkcs11SessionHandle.cs:43-61`
- **Problem:** The method body is only a log, `C_CloseAllSessions(slotId)` and `ThrowIfError` — nothing informs the library's session tracker (`Native/LowLevelPkcs11Library.cs:36`), the `Pkcs11SessionHandle`s, or the `Pkcs11Session` objects. Each stranded handle still reports `IsInvalid == false`, so when it is later disposed or finalized it calls `C_CloseSession(staleId)`. PKCS#11 places no restriction on handle reuse, so a session opened after the mass-close can receive the same numeric handle — at which point the stale finalizer closes a live, unrelated session. The corresponding `Pkcs11Session` objects also keep `_disposed == false` and keep issuing calls on closed handles. Verified by the coordinator.
- **Proposed action:** Have `CloseAllSessions()` mark every tracked handle for that slot invalid (`SetHandleAsInvalid` + untrack) before the native call, or remove it from the public surface in favour of disposing workspaces. Add a test that opens a session, mass-closes, opens a second, then finalizes the first handle and asserts the second is still usable.
- **Breaks public API?** Yes — if the method is removed rather than fixed; decide before 1.0
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** PKCS#11 v3.2 §5.6.8 (`C_CloseAllSessions`), §4.4 (handle validity and reuse)

### [BL-072] Asymmetric BCL façades never set `KeySizeValue`: `KeySize` is 0, `LegalKeySizes` throws, and ECDSA DER-format signing (CSR / certificate signing) is impossible
- **Area:** .NET API Design
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/RSAPkcs11.cs:38-45`, `Algorithms/ECDsaPkcs11.cs:38-45`, `Algorithms/DSAPkcs11.cs:47-53`, `Algorithms/ECDiffieHellmanPkcs11.cs:51-57`; contrast `Algorithms/AesPkcs11.cs:72`, `Algorithms/RC2Pkcs11.cs:73`, `Algorithms/TripleDESPkcs11.cs:79`, which do assign it
- **Problem:** The four asymmetric adapters wrap a `Pkcs11Key` without ever assigning `KeySizeValue` — the coordinator confirmed `KeySizeValue` appears only in the three symmetric adapters. The reviewer verified the consequences with minimal `RSA`/`ECDsa` subclasses on the same net10.0 SDK: `KeySize == 0`; `LegalKeySizes` throws `NullReferenceException`; `RSA.GetMaxOutputSize()` throws `CryptographicException`; and, even with a working `ExportParameters(false)`, `ECDsa.GetMaxSignatureSize(DSASignatureFormat.Rfc3279DerSequence)` and `ECDsa.SignData(data, hash, Rfc3279DerSequence)` both throw `NotSupportedException`. That last format is the one `X509SignatureGenerator.CreateForECDsa` and `CertificateRequest.Create` use, so the headline HSM scenario — token-backed CSR and certificate signing — fails, as does anything reading `KeySize` (Microsoft.IdentityModel `ECDsaSecurityKey`/`RsaSecurityKey`, key-strength policy checks).
- **Proposed action:** In each adapter's constructor read the key size from the token (`CKA_MODULUS_BITS`/`CKA_MODULUS` length for RSA, curve field size from `CKA_EC_PARAMS` for EC, `CKA_PRIME` length for DSA) and assign `KeySizeValue` plus a `LegalKeySizesValue` table. Add adapter tests asserting `KeySize`, `LegalKeySizes`, `GetMaxOutputSize()` and a real-backend CSR round-trip through `ECDsaPkcs11`.
- **Breaks public API?** No — behavioural fix
- **Raised by:** .NET Engineer A
- **Spec / References:** `AsymmetricAlgorithm.KeySize`/`LegalKeySizes` contract; `ECDsa.GetMaxSignatureSize`

### [BL-073] AES-CCM and ChaCha20-Poly1305 cannot fall back to the v2.40 path; their fallback code is unreachable on modules that advertise the message API but reject the mechanism
- **Area:** Cryptography
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/AesCcmPkcs11.cs:89`, `:132` and `Algorithms/ChaCha20Poly1305Pkcs11.cs:93`, `:136`; the pattern they omit is at `Algorithms/AesGcmPkcs11.cs:105` and `:163`
- **Problem:** `AesGcmPkcs11` wraps its message-API branch in `catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_FUNCTION_NOT_SUPPORTED)` and falls through to classic `C_Encrypt`/`C_Decrypt`, with a comment naming opencryptoki as a module that exports the v3.0 message entry points without implementing the mechanism through them. `AesCcmPkcs11` and `ChaCha20Poly1305Pkcs11` branch on the identical `_key.SupportsMessageApi` test but have no such handler anywhere in either file, so against exactly that class of module the call throws and the correct classic-params fallback sitting directly below never executes. The dead code makes both mechanisms read as portable when they are not. Verified by the coordinator: the `catch` clause exists only in `AesGcmPkcs11.cs`.
- **Proposed action:** Lift the `CKR_FUNCTION_NOT_SUPPORTED` handler into a shared helper and apply it at all four CCM/ChaCha message-branch sites. `C_MessageEncryptInit`/`C_MessageDecryptInit` is the first call in each, so nothing has been written when it fails and the retry is side-effect-free — the reasoning the GCM comment already states.
- **Breaks public API?** No
- **Raised by:** Cryptographer A
- **Spec / References:** PKCS#11 v3.0 §5.20. Extends BL-028; BL-053 shows the ChaCha KAT is dormant, so the current suite cannot catch this

### [BL-074] The insecure-mechanism gate omits the key-extraction derive family — the canonical PKCS#11 key-leakage attack is ungated
- **Area:** Cryptography
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:637-799` (`GuardMechanism`) and its transcription `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Generators/InsecureMechanismData.cs:21-136`
- **Problem:** Three internally inconsistent holes; the coordinator confirmed by grep that none of the named mechanisms appears in either file. **(a) Key-extraction derives are ungated:** `CKM_EXTRACT_KEY_FROM_KEY`, `CKM_XOR_BASE_AND_DATA`, `CKM_CONCATENATE_BASE_AND_KEY`/`_BASE_AND_DATA`/`_DATA_AND_BASE`. These are the mechanisms in Clulow's classic attack — derive a short sub-key from a sensitive key, then brute-force it via a legitimate encrypt — and the derived key's own `CKA_SENSITIVE=true` default does not block it. For a library whose flagship security feature is this gate, leaving the canonical key-leakage path unlisted is the most consequential omission. **(b) MD5/SHA-1 asymmetry:** all three `CKM_MD2_*` variants are gated but the more reachable `CKM_MD5_HMAC`, `CKM_MD5_HMAC_GENERAL`, `CKM_MD5_KEY_DERIVATION` and `CKM_SHA1_KEY_DERIVATION` are not, nor `CKM_RSA_9796` (forgeable ISO 9796-2) while `CKM_RSA_X_509` is, nor `CKM_SSL3_MD5_MAC`/`CKM_SSL3_SHA1_MAC`. **(c) ECB/stream asymmetry:** `CKM_AES_ECB`/`CKM_AES_CTR` are gated but `CKM_CAMELLIA_ECB`, `CKM_ARIA_ECB`, `CKM_IDEA_ECB`, `CKM_GOST28147_ECB` and raw `CKM_CHACHA20`/`CKM_SALSA20`/`CKM_AES_XTS` are not. Because the shipped `KLPKCS11009` analyzer is generated from the same list, none carries a compile-time signal either.
- **Proposed action:** Add all three groups to `GuardMechanism` and `InsecureMechanismData.GatedMechanisms` — the existing parity test then keeps them in step. Give the extraction family its own message naming the attack, since unlike the others it is a token-policy bypass rather than a weak algorithm.
- **Breaks public API?** No
- **Raised by:** Cryptographer A
- **Spec / References:** Clulow, CHES 2003 §3; RFC 7568 (SSLv3 prohibited); Coron–Naccache–Stern forgery against ISO 9796-2

### [BL-075] `CkmChaCha20Params` / `CkmSalsa20Params` let the bit-length field exceed the buffer it describes, producing an out-of-bounds read inside the token
- **Area:** P/Invoke
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismParams/CkmChaCha20Params.cs:25-33` (validation) and `:40-43` (marshalling); `MechanismParams/CkmSalsa20Params.cs:22-41`
- **Problem:** Both constructors validate only that the buffers are non-empty, then marshal the caller's `blockCounterBits`/`nonceBits` verbatim alongside pointers to scope blocks sized from the arrays' own lengths. An 8-byte nonce with `nonceBits: 96`, or a 4-byte counter with `blockCounterBits: 64`, hands the native module a pointer with a length that overruns the allocation by 4 bytes — the module reads past the end of an `UnmanagedMemory.Allocate` block. This is the only place in `MechanismParams/` where a length field is not derived from its array; `CkmAesGcmParams`, `CkmAesCcmParams` and `CkmSalsa20ChaCha20Poly1305Params` all compute it. Verified by the coordinator.
- **Proposed action:** In both constructors require `bits > 0`, `bits % 8 == 0` and `bits / 8 <= buffer.Length`; additionally restrict `blockCounterBits` to {32, 64} and `nonceBits` to {64, 96} per the mechanism definition, throwing `ArgumentOutOfRangeException` otherwise.
- **Breaks public API?** No
- **Raised by:** Cryptographer A
- **Spec / References:** `CK_CHACHA20_PARAMS`/`CK_SALSA20_PARAMS` verified field-for-field against `vendor/nss/lib/util/pkcs11t.h:2269-2283`; RFC 8439 §2.3. Distinct from BL-045, which concerns module-reported lengths inbound

### [BL-076] ✅ RESOLVED — `Pkcs11SessionHandle` narrows `CK_ULONG` through `IntPtr` in a checked context — a legal high-bit session handle throws and orphans the session
- **Status:** Resolved 2026-08-11. Reproduced first: the new tests fail against the old code with `System.OverflowException` for every handle at or above `0x8000_0000_0000_0000` on this RID, exactly as reported. Taken the first way the entry offered — the id now lives in its own `NativeCULong` field and the base `SafeHandle.handle` carries an opaque non-zero marker — rather than the `unchecked` reinterpretation, because that option only looks simple: the round trip has to go through `nuint`, not `long`, or it sign-extends and corrupts the handle on win-x86 (`nint` is 32-bit there while `ulong` is not), and the correctness of each cast would then rest on which of the two `NativeCULong` widths the RID resolved. Removing the conversion beats making it clever. `IsInvalid` and `SessionId` read the field; the marker is never dereferenced or sent to the module, and exists so `DangerousGetHandle` and a debugger agree with `IsInvalid` about whether the instance owns anything. `Unit/Internal/Pkcs11SessionHandleRangeTests.cs` covers the round trip across the whole `CK_ULONG` range with the boundaries computed from `NativeULongSize` rather than hardcoded, so the 32-bit RIDs assert their own range; the high-bit case asserts the id actually reached `C_CloseSession` rather than merely that nothing threw, since the reported failure mode was a silently orphaned session, not an exception; and the invalid handle is asserted never to be closed. A sweep for the same shape elsewhere found only `Pkcs11ModuleHandle`, which holds a genuine native pointer and is correct as it stands. Full suite green (2012 passed, 0 failed, 631 gated skips).
- **Area:** P/Invoke
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/SafeHandles/Pkcs11SessionHandle.cs:30` (`SetHandle((IntPtr)(ulong)sessionId)`) and `:37` (`SessionId => (NativeCULong)(ulong)handle`); caller `Internal/Pkcs11Session.cs:270`
- **Problem:** The assembly builds with `CheckForOverflowUnderflow=true` and `IntPtr` is `nint`, so both conversions are *checked*; the reviewer confirmed with a net10.0 repro that `(IntPtr)(ulong)0x8000000000000001` and `(ulong)(IntPtr)(-1)` each throw `OverflowException`. `CK_SESSION_HANDLE` is an opaque `CK_ULONG` whose full unsigned range is legal, and modules deriving handles from pointers or hashes do set the high bit; on **win-x86**, a shipped RID with its own CI leg, the threshold is only `0x8000_0000`. The failure is not graceful: the throw happens in the constructor *before* `RegisterSession(this)`, and `handle` is still `IntPtr.Zero` so `IsInvalid` is true and `ReleaseHandle` no-ops — the session just opened on the token is never registered and never closed, leaking for the process lifetime, while the caller sees `OverflowException` rather than `Pkcs11Exception`. Verified by the coordinator.
- **Proposed action:** Stop routing the handle through `IntPtr` arithmetic — store the id in a separate `NativeCULong` field with an opaque non-zero `SafeHandle` placeholder, or use `unchecked` bit reinterpretation in both directions. Add a unit test constructing the handle from `NativeCULong.MaxValue - 1`.
- **Breaks public API?** No — the type is internal
- **Raised by:** .NET Engineer B
- **Spec / References:** PKCS#11 v3.2 §3.2 (`CK_SESSION_HANDLE` is a `CK_ULONG`, value opaque to the application)

### [BL-077] No public capability probe: a consumer cannot ask whether the module supports the v3.0 message API or the v3.2 surface
- **Area:** .NET API Design
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs:560-582` (`IsMessageApiSupported`, `IsV32ApiSupported`); `Internal/Pkcs11Session.cs:1950` and `:3360` on the **internal** session; the only escape is `Pkcs11Key.cs:431`
- **Problem:** The library computes exactly the right capability facts but every carrier is internal. `Pkcs11Key.SupportsMessageApi` is the only capability property that reaches consumers, and there is no v3.2 equivalent — so a consumer calling the public `Pkcs11Key.EncapsulateKey` against a v3.0 token can only discover the module's limits by catching `Pkcs11Exception` with `CKR_FUNCTION_NOT_SUPPORTED`. Combined with BL-068 there is no non-exceptional way to write version-adaptive code, which is the library's headline promise. Verified by the coordinator.
- **Proposed action:** Surface `SupportsMessageApi`/`SupportsV32Api` — or a single `Pkcs11Capabilities` record carrying them alongside the negotiated interface version — on `Pkcs11Workspace` and/or `Pkcs11Library`. Purely additive.
- **Breaks public API?** No — additive, though the shape of the capability type is a pre-1.0 decision
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** Distinct from BL-019: that covers the v3.2 *methods* being unreachable, this the support *predicate*, which stays unreachable even after BL-019 lands

### [BL-078] `LowLevelPkcs11Library.Dispose` unmaps the native module before setting the disposed flag, and the flag is not `volatile`
- **Area:** P/Invoke
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs:2151-2162`; field declared at `:13`
- **Problem:** `Dispose(bool)` calls `_library.Dispose()` (→ `NativeLibrary.Free`, `Internal/SafeHandles/Pkcs11ModuleHandle.cs:34`) and only then sets `_disposed = true`. Every native entry point guards with `ObjectDisposedException.ThrowIf(_disposed, this)`, so a thread that passes the guard during that window calls a `delegate* unmanaged[Cdecl]` into freshly unmapped memory. `_disposed` is also a plain `bool` written on one thread and read on others — note the deliberate contrast with `Pkcs11Session._disposed`, which is `volatile` for exactly this reason (`Internal/Pkcs11Session.cs:27`). Reachable through the public surface without exotic usage: `Pkcs11Slot` carries no disposal state of its own, so `slot.GetTokenInfo()` racing `library.Dispose()` is this window. Verified by the coordinator: `:13` is non-volatile, `Internal/Pkcs11Session.cs:27` is volatile.
- **Proposed action:** Set `_disposed = true` first, make it `volatile`, and release `_library` only afterwards; better still, gate dispatch on the `SafeHandle` via `DangerousAddRef`/`DangerousRelease` so a call in flight keeps the module mapped.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist B, .NET Engineer B

### [BL-079] The public session-opening surface is too narrow: read-only sessions are unreachable, write-protected tokens unusable, and slots addressable only by a possibly-ambiguous label
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Slot.cs:197` (`internal Pkcs11Session OpenSession(bool readWrite = true)`); `Pkcs11Library.cs:364`, `:395` (both public factories use the default), `:407-411` (`MatchSlotByLabel`)
- **Problem:** Three defects in one surface, all verified by the coordinator. (a) `readWrite` exists and is honoured but `OpenSession` is `internal` and neither public factory exposes it, so consumers always get `CKF_SERIAL_SESSION | CKF_RW_SESSION`; a read-only workload cannot get the token-enforced guarantee that a bug cannot create or destroy token objects. (b) Against a write-protected token — the normal state of read-only signing and certificate tokens — `C_OpenSession` with `CKF_RW_SESSION` returns `CKR_TOKEN_WRITE_PROTECTED`, so the library is wholly unusable there; the fixtures already know write-protected tokens are real (`Support/Fixtures/NssBackendFixture.cs:59`). (c) Both factories take a *token label string*, so a caller who enumerated slots via `GetSlotList()` and holds a `Pkcs11Slot`/`SlotId` must round-trip through a label — and `MatchSlotByLabel` uses `FirstOrDefault` over a case-sensitive `TrimEnd()` comparison, so two tokens sharing a label (permitted, and easy to produce on SoftHSM) silently resolve to whichever enumerates first, an unlabelled token is reachable only via `""`, and the environment condition "no such token" surfaces as `ArgumentException`.
- **Proposed action:** Add `Pkcs11Slot.OpenWorkspace(CKU, SecurePin, bool readWrite = true)` / `OpenWorkspaceWithoutLogin(bool readWrite = true)` (or `Pkcs11Library.OpenWorkspace(SlotId, …)`), surface `readWrite` on the label-based overloads, and throw a typed `Pkcs11TokenException` rather than `ArgumentException` when no token matches.
- **Breaks public API?** No — additive, except the `ArgumentException` → `Pkcs11TokenException` change, which is behavioural and should land before 1.0
- **Raised by:** PKCS#11 Specialist B, .NET Engineer A
- **Spec / References:** PKCS#11 v3.2 §5.6.1 (`C_OpenSession`), §4.4 (read-only session object restrictions); `CKR_TOKEN_WRITE_PROTECTED`

### [BL-080] The ECDH peer public key is never validated or curve-matched before being handed to the token — invalid-curve private-key recovery
- **Area:** Cryptography
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/ECDiffieHellmanPkcs11.cs:179-186` (`DeriveRawSecret`); `Pkcs11Workspace.cs:494-515` (`DeriveSharedSecretEcdh`); `MechanismParams/CkmEcdh1DeriveParams.cs:25-33`
- **Problem:** `DeriveRawSecret` takes `peer.Q.X`/`peer.Q.Y` straight from `ExportParameters()`, concatenates them into an uncompressed point and passes them to `CKM_ECDH1_DERIVE`; `peer.Curve` is never read, so a peer key on a *different, weaker* curve is accepted silently. The span overload accepts the point unvalidated and `CkmEcdh1DeriveParams`'s only check is `IsEmpty`. Nothing verifies the point satisfies the curve equation, lies in the correct subgroup, or is not the identity — and PKCS#11 does not require the token to validate either (SoftHSM 2.x does not). With the raw-secret read-back path enabled, the standard invalid-curve / small-subgroup attack recovers the token-resident private key one residue at a time, from a key the library sells as non-extractable. A second defect in the same lines: `int fieldSize = x.Length` sizes the shared secret from the *peer's* coordinate encoding rather than the local key's field size, and `ECDiffieHellmanPublicKey` is subclassable, so a short `Q.X` silently produces a smaller `CKA_VALUE_LEN` and the token truncates the agreement with no error. Verified by the coordinator.
- **Proposed action:** Require `peer.Curve` to equal the local key's `CKA_EC_PARAMS` curve, and validate the point by round-tripping the peer `ECParameters` through `ECDiffieHellman.Create(peer)` — both the OpenSSL and CNG backends reject off-curve points on import — rejecting with `Pkcs11ArgumentException`. Derive `fieldSize` from the local key and reject peer coordinates whose length differs. Add an `ECParameters` overload for the raw-span entry point and document the span form as caller-validated.
- **Breaks public API?** No — additive validation
- **Raised by:** Cryptographer B
- **Spec / References:** NIST SP 800-56A Rev. 3 §5.6.2.3.2 (full public-key validation before key agreement); Antipa et al., PKC 2003. Distinct from resolved BL-011, which governed *who may extract* Z

### [BL-081] `CKA_ALWAYS_AUTHENTICATE` / `CKU_CONTEXT_SPECIFIC` re-authentication is unimplemented, and the session lock structurally prevents it
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKA.cs:346` (defined, referenced nowhere else); `Common/CKU.cs:23` (used only by `Logging/Pkcs11LogUtils.cs:19`); `Internal/Pkcs11Session.cs:421-422` (`Login` is internal and takes `AcquireExclusive()`); `Pkcs11Library.cs:358-367`
- **Problem:** A private key with `CKA_ALWAYS_AUTHENTICATE = CK_TRUE` requires `C_Login(hSession, CKU_CONTEXT_SPECIFIC, …)` *between* `C_SignInit`/`C_DecryptInit` and `C_Sign`/`C_Decrypt`. `Pkcs11Key.Sign` runs init and operate as one exclusive-locked unit with no seam, and `Pkcs11Session.Login` is internal and itself takes the exclusive lock, so even an internal caller could not re-authenticate mid-operation. Signing or decrypting with such a key — the default posture for signing keys on FIPS-mode HSMs and on PIV/eID cards — therefore fails with `CKR_USER_NOT_LOGGED_IN`. Separately, `OpenWorkspace(slotLabel, CKU.CKU_CONTEXT_SPECIFIC, pin)` is accepted by the public signature although it can never be valid on a freshly opened session. Verified by the coordinator: `CKA.cs:346` is the only occurrence of the attribute in the library.
- **Proposed action:** Add a context-specific re-auth path — an optional `SecurePin contextPin` or `Func<SecurePin>` callback on `Pkcs11Key.Sign`/`Decrypt` issuing `C_Login(CKU_CONTEXT_SPECIFIC)` inside the already-held lock between init and operate. Document `CKA_ALWAYS_AUTHENTICATE` in the private-key template builder, and reject `CKU_CONTEXT_SPECIFIC` in `OpenWorkspace` with `ArgumentException`.
- **Breaks public API?** No — additive overloads
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** PKCS#11 v3.2 §4.9 (`CKA_ALWAYS_AUTHENTICATE`), §5.6.6 `C_Login`

### [BL-082] `Pkcs11Library.Dispose()` closes tracked sessions without taking the per-session busy lock, reintroducing the race BL-015 fixed
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs:91-113` (`CloseAllTrackedSessions`; the justifying comment is at `:86-90`, `handle.Dispose()` at `:108`); called from `Pkcs11Library.cs:435`
- **Problem:** `CloseAllTrackedSessions` issues `C_CloseSession` by disposing each `Pkcs11SessionHandle` directly, entirely outside `Pkcs11Session._busyLock`. So `library.Dispose()` on thread A closes a session out from under an in-flight `C_Sign`/`C_Encrypt` on thread B — precisely the undefined behaviour the BL-015 fix eliminated for `Pkcs11Session.Dispose`. The XML comment asserts this is safe because "`SafeHandle.Dispose()` is reentrant and thread-safe", which is the reasoning BL-015's own fix comment refutes: ref-counting protects the handle object, not the session behind it, because the session id crosses the boundary by value. `Pkcs11Library.cs:15-19` documents disposing the library with sessions open as a *supported* safety net, so this is a documented path rather than caller abuse. Verified by the coordinator.
- **Proposed action:** Have the tracker hold the owning `Pkcs11Session` (or a lock object shared with it) rather than only the bare handle, and route library teardown through the same wait-for-the-lock path `Pkcs11Session.Dispose(bool)` uses. Add a test mirroring `Unit/Internal/Pkcs11SessionDisposeRaceTests.cs` but driving `Pkcs11Library.Dispose()`.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** PKCS#11 v3.2 §5.6.7; the fix rationale already recorded at `Internal/Pkcs11Session.cs:850-863`

### [BL-083] `C_Finalize` is decided per-`Pkcs11Library` instance, so the owning instance tears down global Cryptoki state under another instance's live sessions
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Library.cs:38-46` (`_ownsFinalize`), set at `:177`, teardown `:427-446`
- **Problem:** With two `Pkcs11Library` instances on the same module, instance A owns `C_Finalize` and instance B observed `CKR_CRYPTOKI_ALREADY_INITIALIZED` (the early `return` at `:164` leaves `_ownsFinalize` false). `CloseAllTrackedSessions` walks only *A's own* tracker (`Native/LowLevelPkcs11Library.cs:36`), so disposing A calls `C_Finalize` while B's sessions are still open — and B's `Pkcs11SessionHandle` finalizers then issue `C_CloseSession` after `C_Finalize`, exactly the post-finalize call the tracker was built to prevent. `Integration/Lifecycle/Pkcs11LibraryAlreadyInitializedTests.Pkcs11Mock.cs:17-38` tests only the B-then-A order, so the dangerous direction is untested. Verified by the coordinator.
- **Proposed action:** Replace the per-instance `_ownsFinalize` with a process-wide refcount keyed on the resolved module path or handle, so `C_Finalize` runs only when the last `Pkcs11Library` for that module is disposed and session tracking is shared across instances of the same module. Add the A-disposed-first test.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** PKCS#11 v3.2 §5.5.2 — `C_Finalize` "should be the last Cryptoki call made by an application"

### [BL-084] Only one workspace per slot is usable: the second `OpenWorkspace` throws `CKR_USER_ALREADY_LOGGED_IN`, and disposing either logs the other out
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Library.cs:364-371` (unconditional `session.Login`); `Pkcs11Workspace.cs:96-104` (`Dispose` → `Logout`); the guidance being contradicted is at `Internal/Pkcs11Session.cs:113-118`
- **Problem:** The session busy-guard's own error message instructs callers to "Use a separate Session per thread", but the only public way to obtain a session is `OpenWorkspace`, which always calls `C_Login` and ends in `Pkcs11Exception.ThrowIfError` with no tolerance for an already-logged-in state. PKCS#11 login state is per-application-per-token, so a second `OpenWorkspace` on the same slot returns `CKR_USER_ALREADY_LOGGED_IN`, which `Internal/ExceptionMapper.cs:29` maps to `Pkcs11AuthenticationException`. Symmetrically, `Pkcs11Workspace.Dispose` issues `C_Logout`, de-authenticating *every* other workspace on that slot — the doc comment acknowledges the token-wide effect and calls it intended, which it cannot be once more than one workspace exists. The concurrency model the library documents is therefore unreachable, and there is no session pooling. No test opens two concurrent workspaces, and `Integration/ThreadSafety/SessionParallelTests.Pkcs11Mock.cs:19-21` states outright that real cross-session parallelism is not exercised. Verified by the coordinator.
- **Proposed action:** Tolerate `CKR_USER_ALREADY_LOGGED_IN` in `OpenWorkspace` as success; track a per-slot workspace count and skip `C_Logout` unless this is the last workspace on the slot; add a multi-session test against SoftHSM2 (`ulMaxSessionCount > 1`).
- **Breaks public API?** No — behavioural fix
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** PKCS#11 v3.2 §5.6 (login state shared across an application's sessions with a token), §5.6.9 `C_Logout`

### [BL-085] The `CKR_CANT_LOCK` fallback silently enters single-threaded mode with no compensating serialization and no way for a consumer to detect it
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Library.cs:167-174`; app-supplied mutex callbacks declared unsupported at `Native/CK_C_INITIALIZE_ARGS.cs:17-27`
- **Problem:** On `CKR_CANT_LOCK` the library logs a warning and retries `C_Initialize(NULL)`, which per spec is the application *promising* it will not access the library from multiple threads. The wrapper then does nothing to honour that promise: `Pkcs11Session._busyLock` serializes only within one session, and `Pkcs11Library`/`Pkcs11Slot` methods (`GetSlotList`, `GetTokenInfo`, `GetMechanismList`, `WaitForSlotEvent`) take no lock at all. The only signal is a `LogWarning` telling the caller to serialize at the C# layer — but no public property reports which mode was negotiated, so a consumer cannot know it must. Appendix B currently records this probe-and-fallback as a *positive* finding, which misses the second half of the contract. Verified by the coordinator.
- **Proposed action:** Expose the negotiated mode publicly (e.g. `Pkcs11Library.SupportsConcurrentAccess`, ideally folded into the BL-077 capability type), and when OS locking was refused serialize *all* dispatch through one library-wide lock so the promise made to `C_Initialize` is actually kept. Document the stance on app-supplied mutexes.
- **Breaks public API?** No — additive
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** PKCS#11 v3.2 §5.4 (`C_Initialize` threading modes 1–4), §5.5.1. None of the four CI backends returns `CKR_CANT_LOCK`, so this path has zero real-backend coverage

### [BL-086] Roughly half the suite is behind runtime gates and CI has no guard against a mass silent skip
- **Area:** QA
- **Severity:** High
- **Effort:** M
- **Location:** `.github/workflows/ci.yml:338`, `:360`, `:447` (all three `dotnet test` invocations); gates at `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/SoftHsmBackendFixture.cs:101-138`
- **Problem:** 1005 of ~2060 test attributes are `ConditionalFact`/`ConditionalTheory`, plus 46 in-body `SkipTestException`. The three `PKCS11_TEST_EXPECT_*` guards assert *backend presence* only — never *mechanism* availability. `SoftHsmSupportsMlDsa`/`MlKem`/`SlhDsa` key on marker files written by `build-softhsmv2.sh`, so if the from-source OpenSSL 3.5 step degrades, every ML-DSA/ML-KEM test skips and CI still reports green. All three test steps use `--logger "console;verbosity=normal"` only: no `.trx`, no skipped count, no minimum-executed floor. This is the systemic gap that allowed BL-053 to exist and would hide the next one.
- **Proposed action:** Emit `--logger "trx"` and add a CI step that fails when the skipped count exceeds a checked-in per-leg baseline, or when total executed drops below a floor. Add `PKCS11_TEST_EXPECT_MLDSA`/`_MLKEM`-style declarations mirroring the existing backend-availability guards so a lost PQC capability fails rather than skips.
- **Breaks public API?** No
- **Raised by:** QA B, QA A

### [BL-087] No multi-part or streaming operation is publicly reachable, and multi-part **sign** is not implemented at all — the coverage matrix overstates both
- **Area:** Cross-cutting
- **Severity:** High
- **Effort:** L
- **Location:** Public surface: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs:326`, `:350`, `:389`, `:413` (all one-shot `ReadOnlySpan<byte>`). Bound but uncalled: `Native/ILowLevelPkcs11Library.cs:111-114` (`C_SignUpdate`, `C_SignFinal`, `C_SignRecoverInit`, `C_SignRecover`), `:123` (`C_SignEncryptUpdate`), `:64-73` (message sign/verify families)
- **Problem:** Every `*_Update`/`*_Final` path — `Encrypt(Stream)`, `Decrypt(Stream)`, `Digest(Stream)`, `Verify(Stream)`, `DigestEncrypt`, `DecryptDigest`, `DecryptVerify`, `VerifySignature(Stream)` — lives on the `internal` `Pkcs11Session`, so all of it, including the `TryCancelOperation` unwind logic, is unreachable by consumers. Worse, the sign side is not merely unexposed: **the coordinator verified by grep that `C_SignUpdate`, `C_SignFinal` and `C_SignRecover` have zero callers anywhere in `Internal/`, `Algorithms/`, `Objects/` or the root types, while `C_EncryptUpdate` (×2), `C_DigestUpdate` (×1) and `C_VerifyUpdate` (×1) all do have callers in `Internal/Pkcs11Session.cs`; and `grep Stream` over `Pkcs11Key.cs` and `Pkcs11Workspace.cs` returns nothing at all.** Consequently the coverage-matrix rows for v2.40 multi-part crypto and v3.0 message-based sign/verify were both wrong before this review (corrected below), and BL-019's stated scope understates the gap. Practical consequence: a consumer cannot sign or encrypt a payload larger than memory, and the span overloads copy, so peak footprint is 2× the payload.
- **Proposed action:** Add multi-part sign to `Pkcs11Session` (`C_SignInit`/`C_SignUpdate`/`C_SignFinal` with the same `finalized` + `TryCancelOperation` unwind shape as `Verify(Stream)`), then expose `Stream` overloads for Sign/Verify/Encrypt/Decrypt/Digest on `Pkcs11Key`/`Pkcs11Workspace`. Decide and document explicitly whether `C_SignRecover`, `C_SignEncryptUpdate` and message-based sign/verify are in scope for 1.0.
- **Breaks public API?** No — additive, but the shape of the streaming surface is a pre-1.0 decision
- **Raised by:** PKCS#11 Specialist B, PKCS#11 Specialist A
- **Spec / References:** PKCS#11 v3.2 §5.12 (`C_SignUpdate`/`C_SignFinal`), §5.13.5 (`C_SignRecover`), §5.20 (message-based). Extends BL-019

## Medium

### [BL-008] ✅ RESOLVED — `Pkcs11Key.EncapsulateKey` returns a `ValueTuple` containing a disposable, hiding ownership
- **Status:** Resolved 2026-07-09. `EncapsulateKey` now returns a public `readonly record struct EncapsulationResult` (`EncapsulationResult.cs`) with documented `Ciphertext`/`SharedSecret` properties. The result is `IDisposable` (disposes `SharedSecret`, so `using var result = key.EncapsulateKey(...)` works), documents caller ownership on the type, the properties, and the `<returns>` tag, and keeps an explicit `Deconstruct` so tuple-style call sites still compile. Full test suite green (1637 passed / 0 failed).
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs:519`
- **Problem:** The returned `SharedSecret` is an `IDisposable` `Pkcs11Key`, but the anonymous tuple obscures that the caller owns and must dispose it; the `<returns>` doc says nothing about disposal and `using` cannot destructure a tuple. FDG discourages tuples in public signatures, doubly so when an element owns a resource.
- **Proposed action:** Return a named `readonly struct` (e.g. `EncapsulationResult`) or use an `out` parameter, and document the disposal obligation.
- **Breaks public API?** Yes — must land before 1.0
- **Raised by:** .NET Engineer A

### [BL-009] C-style ALL_CAPS enum members and 2–3 letter type names must be a conscious, documented pre-1.0 decision
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S (decision + docs; L if renamed)
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKM.cs:8`, `Common/CKA.cs:8`, `Common/CKR.cs:8`, `Common/CKO.cs:8`, `Common/CKK.cs:8` and ~15 siblings
- **Problem:** `enum CKM : uint { CKM_RSA_PKCS, ... }` violates Framework Design Guidelines naming and threads through the entire public API, so it is effectively unchangeable after 1.0. It is very likely a deliberate spec-fidelity choice (greppable against the OASIS spec, familiar from Pkcs11Interop) — but that rationale is recorded nowhere.
- **Proposed action:** Do not rename blindly. Make the call explicitly, record the spec-traceability rationale in the docs/README, and lock it. If the project ever wanted idiomatic names, pre-1.0 is the only time.
- **Breaks public API?** Yes if ever changed — decide before 1.0
- **Raised by:** .NET Engineer A

### [BL-010] Strong-naming decision is unmade and undocumented (irreversible after 1.0)
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` (no `SignAssembly`/`PublicSign`)
- **Problem:** Strong-named consumers cannot reference an un-strong-named assembly, and adding a strong name after 1.0 is itself a breaking change — this is a one-way door either way.
- **Proposed action:** Decide (the OSS norm is to strong-name with a checked-in key, treating it as identity not security) and document the decision either way.
- **Breaks public API?** Yes if changed later — decide before 1.0
- **Raised by:** .NET Engineer B

### [BL-062] ✅ RESOLVED — The secure-defaults gate ran on only five of nine object-creating paths, and conflated two different risks
- **Status:** Resolved 2026-07-31, found while auditing BL-011 for other bypasses of the same shape.
- **Problem (a) — coverage.** `DeriveKey`, `UnwrapKey`, `EncapsulateKey`, `DecapsulateKey` and `UnwrapKeyAuthenticated` ran `BuildSecureKeyDefaults`; `GenerateKey`, `GenerateKeyPair`, `CreateObject` and `CopyObject` did not. So a template refused through a derive was accepted through a generate — the more direct route to defeating the non-extractable posture. Confirmed by probe before fixing, not inferred.
- **Problem (b) — the test list mirrored the gap.** `KeyCreationSecureDefaultsTests.Operations` enumerated operations by hand, and the four it omitted were exactly the four that were ungated. The coverage was self-fulfilling: it could only ever assert what someone had remembered to add.
- **Problem (c) — two risks treated as one.** The gate refused `CKA_SENSITIVE=false` *and* `CKA_EXTRACTABLE=true`. These are not equivalent: `CKA_SENSITIVE=false` makes the value readable in plaintext off the token, while `CKA_EXTRACTABLE=true` merely permits wrapping — export encrypted under a KEK, the standard way to back up and transport keys, and required by PKCS#11 for it. The conflation was survivable only while `GenerateKey` was ungated; closing (a) made it bite, turning key wrapping into an operation that demanded an "insecure" opt-in.
- **Fix:** the refusal is split out as `GuardInsecureKeyAttributes` — check-only, so it is safe on public-key and non-key templates where seeding `CKA_SENSITIVE`/`CKA_EXTRACTABLE` defaults would be wrong or rejected — and now runs on all nine paths. `GenerateKey` and the private half of `GenerateKeyPair` additionally get the defaults; `CreateObject`/`CopyObject` get the check only, since any object class may arrive there. Only `CKA_SENSITIVE=false` is refused. Non-extractable remains the default when the caller says nothing: asking for extractable is allowed, getting it by omission is not.
- **Verification:** `KeyCreationSecureDefaultsTests.Operations` extended from four entries to nine, with a comment recording why the short list was itself the bug. `SecureDefaultsGateCoverageTests` adds the two properties that list cannot express — that the gate refuses rather than disables, and that it does not push secret-key defaults onto a public-key template. Mutation-verified: reverting the four newly-gated paths reddens six of eight cases.
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** M
- **Location:** `Internal/Pkcs11Session.cs`
- **Related:** BL-011, whose audit surfaced it.
- **Breaks public API?** Behavioural, both ways — `GenerateKey`/`ImportKey` now refuse `CKA_SENSITIVE=false` without opt-in; every path now permits `CKA_EXTRACTABLE=true` without one. Pre-1.0.
- **Raised by:** BL-011 follow-up audit

### [BL-011] ✅ RESOLVED — ECDH raw shared-secret extraction bypasses the `AllowInsecure` gate that the analogous ML-KEM path enforces
- **Status:** Resolved 2026-07-31 by **removing the bypass**, not by adding a second gate. The first attempt added a guard inside `ECDiffieHellmanPkcs11`; that was the wrong shape — it treated a symptom and left the mechanism that caused it in place.
- **How the bypass worked:** `Pkcs11Key.DeriveExtractable` existed *to* skip the policy, calling `DeriveCore(..., enforceSecureDefaults: false)` so `Pkcs11Session.BuildSecureKeyDefaults` never ran. Its own doc said as much. Exactly two production callers used it — `ECDiffieHellmanPkcs11` and `SP800108HmacCounterKdfPkcs11` — and both did so to avoid requiring `AllowInsecure` for an operation that genuinely extracts key material. `MLKemPkcs11` never used it: it calls the public `EncapsulateKey`/`DecapsulateKey`, which do run the gate, so its own `GuardExtraction` is a friendlier message layered on a policy already enforced beneath it.
- **The fix:** `DeriveExtractable` and the whole `enforceSecureDefaults` parameter are deleted, from `Pkcs11Key` and `Pkcs11Session` alike. The two adapters call the public `Pkcs11Key.Derive`, so their extractable, non-sensitive template meets `BuildSecureKeyDefaults` like any external caller's would. There is now **one** enforcement point and no way around it — no adapter can forget the policy, because there is nothing left to remember.
- **Consequence, stated plainly:** every byte-returning method on `ECDiffieHellmanPkcs11` and `SP800108HmacCounterKdfPkcs11` now requires `AllowInsecure` — including `DeriveKeyFromHash`. That is honest rather than incidental: `ECDiffieHellman`'s contract returns `byte[]` from every derive method, so the adapter cannot be implemented without extraction. Previously `DeriveKeyFromHash` silently created an extractable, non-sensitive copy of Z on the token without the caller consenting, which is precisely what the gate exists to prevent — the bypass concealed a policy violation rather than avoiding one. Both classes now say so in their remarks.
- **Rejected:** gating inside the adapters (the first attempt). It leaves each adapter carrying its own hand-written guard, near-duplicates that a third adapter can simply omit — ownership by convention, the pattern BL-012/BL-056/BL-057/BL-060 removed elsewhere.
- **Verification:** `WithoutAllowInsecure_EveryDerivationIsRefused` (raw / hash / hmac / material) and `WithAllowInsecure_DerivationWorks`. Mutation-verified: disabling **both** secure-default checks in `BuildSecureKeyDefaults` reddens all four refusal cases and leaves the opt-in case green. Disabling only the `CKA_EXTRACTABLE` check changed nothing — the templates set `CKA_SENSITIVE=false` too, and that branch fires first — which is why the mutation had to cover both to prove anything. The 24 tests that broke were converted to opt in, rather than the production gate being softened to suit them.
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** M
- **Location:** `Pkcs11Key.cs`; `Internal/Pkcs11Session.cs`; `Algorithms/ECDiffieHellmanPkcs11.cs`; `Algorithms/SP800108HmacCounterKdfPkcs11.cs`
- **Related:** same "remove the ambiguity rather than police it" resolution as BL-012/BL-056/BL-057/BL-060.
- **Breaks public API?** Behavioural — both adapters now refuse by default. Landed pre-1.0, as the entry required.
- **Raised by:** Cryptographer A
### [BL-012] ✅ RESOLVED — `Mechanism` does not own its `MechanismParameters`; ordered two-object disposal is easy to misuse
- **Status:** Resolved 2026-07-29. `Mechanism` now owns the parameters it is constructed with and disposes them in `Dispose(true)`, after releasing the marshalled `CK_MECHANISM` block so the block never outlives the buffers it points at. The parameter object is left alone on the finalizer path, since it is managed and carries a finalizer of its own. The leak this fixes was the common case rather than the exotic one: roughly twelve call sites construct parameters inline (`new Mechanism(ckm, new CkmAesGcmParams(...))`) and keep no reference, so nothing could dispose them and their unmanaged IV/AAD buffers survived until the GC ran. The two sites that do hold a variable use `using var p = …; using var m = new Mechanism(…, p);`, which disposes in reverse order — mechanism first — and stays correct, because disposal is idempotent. What is no longer supported is sharing one parameter instance across two mechanisms; that is now stated on both constructors and on the `MechanismParameters` class doc. Sharing one parameter instance across two mechanisms is now rejected at the second construction with an `InvalidOperationException` rather than left to documentation: each mechanism marshals its own copy of the parameter struct including the buffer addresses, so disposing either would leave the other pointing at freed memory and hand the token released buffers with no exception anywhere. `MechanismOwnsParametersTests` pinned all of it, and the ownership cases were confirmed to fail with the disposal line removed.
  - **Superseded by BL-057 (2026-07-29):** the mechanism described above no longer exists. Parameter objects hold no unmanaged memory, so there is nothing to own, nothing to order, and nothing to free — the sharing rejection and its `InvalidOperationException` were deleted along with `MechanismOwnsParametersTests`, and sharing one descriptor across two mechanisms is now legal and tested. The defect this item recorded is still fixed; it was fixed by removing the lifetime rather than by assigning its owner.
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Mechanism.cs:107-164`; e.g. `MechanismParams/CkmAesGcmParams.cs:60-71`
- **Problem:** `Mechanism.Dispose` frees only the top-level parameter block, never the `MechanismParameters` that owns nested unmanaged IV/AAD buffers. Disposing only the `Mechanism` (the natural assumption) leaks sensitive buffers until finalization; disposing params first leaves the marshalled block dangling for subsequent calls. The correct order lives only in a per-type doc remark.
- **Proposed action:** Have `Mechanism` take ownership and dispose its params in `Dispose(true)` (or move buffer ownership into `Mechanism`). If caller ownership is kept, promote the ordering contract to a first-class documented invariant.
- **Breaks public API?** Yes (ownership semantics) — land before 1.0
- **Raised by:** .NET Engineer B

### [BL-013] ✅ RESOLVED — `C_GetAttributeValue` read-back trusts the module's post-call `valueLen` without clamping to the allocated buffer
- **Area:** P/Invoke
- **Severity:** Medium
- **Effort:** S
- **Location:** `Internal/Pkcs11Session.cs` (`GetAttributeValue`, `GuardReportedLength`); `Objects/ObjectAttribute.cs` (every `GetValueAs*` / `CopyValueTo`)
- **Problem:** Buffers are sized from the first call's `valueLen`, but after the second call the wrapper reads back using whatever `valueLen` the module last wrote, unchecked. A buggy or hostile module that inflates `valueLen` on the second call causes an out-of-bounds read of adjacent unmanaged heap into the returned array (info disclosure / AV). The overflow-to-write variant is already blocked by `NativeCULong` checked casts; this is the in-range-but-oversized case.
- **Resolution (2026-07-31):** `GetAttributeValue` records the size allocated per attribute and `GuardReportedLength` rejects any post-call length exceeding it, throwing `AttributeValueException` with a message naming both figures — the caller's next step is to identify the offending module, which a bare "could not be read" would not support. Applied after the second call and, for nested array attributes, after the third.
  - **A leak had to be fixed to make the guard safe.** Ownership of the allocated blocks passed to the `ObjectAttribute`s only at the very end of the method, so every earlier exit leaked them — the two fatal-return paths and the malformed-nested-template throw already did, before this change added a fourth. A guard that threw and leaked would have traded an out-of-bounds read for an unbounded leak of buffers that can hold key material. The allocations are now tracked and freed on any failure, with the `ObjectAttribute` construction deliberately outside the `try` so the two owners cannot double-free.
  - **A message-carrying `AttributeValueException(ulong, string)` overload was added.** The existing constructors all produce "could not be read"/"could not be converted", and the `Pkcs11Exception` hierarchy is keyed on CKR codes, which do not apply here: the module returns `CKR_OK` throughout and simply answers inconsistently.
- **Verification:** `AttributeLengthClampTests` drives a fake module that reports one length then a larger one. Three mutations, each killing only what it should — the guard disabled (the pre-fix behaviour), `<=` narrowed to `<` (which would reject the legal exact-length answer), and the free-loop deleted (caught by the allocation-count assertion, not by the refusal assertion). A shrinking second answer is legal and is covered as an accepted case.
- **Breaks public API?** No (additive)
- **Related:** BL-029 proposes fuzzing this same read-back path with adversarial `ulValueLen`; this guard is what such a harness would now be testing against.
- **Raised by:** Cryptographer B

### [BL-014] Fixed-length token strings NUL-padded by real tokens are not trimmed, breaking label matching
- **Area:** P/Invoke
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/TokenInfo.cs:74-91`, `SlotInfo.cs:32-33`, `LibraryInfo.cs:29-31`, `Pkcs11Library.cs:368`
- **Problem:** CK_UTF8CHAR fields are decoded with argless `TrimEnd()`, which strips whitespace but not `'\0'`. The spec mandates space padding but many real tokens NUL-pad; a NUL-padded label decodes to `"mytoken\0\0…"`, the token-by-label lookup silently fails, and every info string carries embedded NULs.
- **Proposed action:** Truncate at the first `'\0'` or use `TrimEnd(' ', '\0')` across all fixed-length string decodes.
- **Breaks public API?** No
- **Raised by:** .NET Engineer B
- **Spec / References:** PKCS#11 v3.1 §3.2 (blank-padded fields)

### [BL-015] ✅ RESOLVED — `Pkcs11Session.Dispose` bypasses the busy-lock every operation acquires — close can race an in-flight native call
- **Status:** Resolved 2026-08-10. `Dispose(bool)` now runs its whole body under `_busyLock`, so the `C_CloseSession` issued by releasing the handle can no longer overlap a native call in flight on another thread. `_disposed` became `volatile` — it is written under the lock but read outside it by the property guards.
  - **It waits for the lock rather than calling `AcquireExclusive()`, which is what this entry proposed.** `AcquireExclusive` throws on cross-thread contention, and disposal usually runs from a `using` that is already unwinding, where that throw would replace the exception that started the unwind — the same objection that moved `ReadOnlyDisposableList.Dispose` off throwing (S3877). So `Dispose` uses a blocking `Monitor.Enter`. Waiting is bounded in practice: the lock is only ever held for the length of one native call, and the sole nesting is `_busyLock` → the library's session tracker, never the reverse, so there is no ordering cycle. `Monitor` is reentrant, so disposing from inside an operation on the same thread still closes.
- **Verification:** `Pkcs11SessionDisposeRaceTests` parks a worker inside `C_GenerateRandom` on a fake module and disposes from a second thread. Three mutations, each killed by a different assertion — the lock removed (the pre-fix behaviour: the fake records a close entered while the call was on the stack), `AcquireExclusive()` substituted for `Monitor.Enter` (throws out of `Dispose`, *and* leaves the session unclosed), and a non-reentrant lock (the same-thread self-disposal test deadlocks). Full suite green: 1947 passed, 0 failed.
- **Area:** P/Invoke
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:796-827` (Dispose) vs `:269-284` (CloseSession)
- **Problem:** Every native operation and `CloseSession` acquire `AcquireExclusive()`, but `Dispose` does not, and P/Invokes pass the raw session id by value so SafeHandle ref-counting cannot protect them. A `Dispose` racing an in-flight `Sign`/`Encrypt` on another thread lets `C_CloseSession` run concurrently with an active call on the same session — UB at the boundary. `_disposed` is also a plain non-volatile bool written outside the lock.
- **Proposed action:** Acquire `AcquireExclusive()` in `Dispose(true)` before releasing the handle (mirroring `CloseSession`); make `_disposed` visibility-safe.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist B

### [BL-016] ✅ RESOLVED — `SupportsMechanism` issues native calls and mutates cached state without the concurrency guard
- **Status:** Resolved 2026-08-10. `SupportsMechanism` now opens with `using var _ = AcquireExclusive()`, so its `C_GetSessionInfo` + `C_GetMechanismList` probe obeys the same single-thread contract as every other native-touching method, and the lazy `_supportedMechanisms` write is no longer an unsynchronized publication.
  - **The lock spans the whole body, not just the lazy population.** Reading the cache reference outside the lock is the unsafe-publication half of the same race — a thread can observe the reference before the `HashSet` it points at is fully constructed — and the cached read is the common path, taken by every call after the first. Bracketing only the population would have left it uncovered.
  - **Every call site was verified to be outside the lock**, so this is a real cross-thread window rather than a theoretical one: `Pkcs11Key.SupportsMechanism` (public), and `ECDsaPkcs11`/`DSAPkcs11` both probe *before* the `Sign`/`Verify` that takes the lock. Same-thread reentrancy still works, so a future caller that probes from inside a locked section is fine.
  - **Minor behaviour change on the public surface:** `Pkcs11Key.SupportsMechanism` now throws `InvalidOperationException` when another thread is mid-operation on the session, where it previously raced silently. That is the contract every other session member already enforces; a caller hitting it was already violating "a separate Session per thread".
- **Verification:** `Pkcs11SessionSupportsMechanismRaceTests` parks a worker inside `C_GenerateRandom` and probes from a second thread. Three mutations, each killed by a different assertion — the lock removed (the fake records a probe issued while the call was on the stack), the lock narrowed to the population block (the warm-cache test, and only that one, fails), and the guard swallowing contention rather than reporting it (the `InvalidOperationException` assertion). A fourth test pins same-thread reentrancy. Full suite green: 1951 passed, 0 failed.
- **Follow-up, now also resolved (2026-08-10):** `SupportsMechanism` had no `_disposed` guard. It now carries `ObjectDisposedException.ThrowIf(_disposed, this)` immediately after acquiring the lock, matching every other member. The guard sits *before* the cache check, not inside the population block: the warm-cache path answers from memory without touching the token, so a guard on the probe alone would have left the common path silently reporting the capabilities of a session that no longer exists — the worst shape of this bug, since nothing downstream fails either. Cold-cache use-after-dispose was less severe (the token rejected the invalid handle and the probe returned `false`, and the adapters' subsequent `Sign`/`Verify` threw `ObjectDisposedException` anyway), but both now fail at the guard. `Pkcs11Key.SupportsMechanism` documents the exception. Verified by adding `SupportsMechanism` to the `Operations_AfterDispose_ThrowObjectDisposed` table plus a dedicated warm-cache test; moving the guard inside the population block kills that test and only that test. Full suite green: 1952 passed, 0 failed.
- **Area:** P/Invoke
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:225-246`; publicly reachable via `Pkcs11Key.cs:93`
- **Problem:** It calls `C_GetSessionInfo` + `C_GetMechanismList` and lazily writes `_supportedMechanisms` with no `AcquireExclusive()` — the only native-touching method outside the single-thread contract, and the unsynchronized `HashSet` write is a managed data race.
- **Proposed action:** Route the lazy population through `AcquireExclusive()` (or a dedicated lock) so it obeys the same contract as the rest of the class.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist B

### [BL-017] ✅ RESOLVED — PIN material is copied into an unpinned managed array on every login/PIN path, defeating `SecurePin`'s pinning
- **Status:** Resolved 2026-07-09. Added internal `SecurePin.ToPinnedArray()`, which copies the PIN into a pinned-object-heap array (`GC.AllocateArray(pinned: true)`) that the GC never relocates, so the existing `finally` zeroing destroys the only transient copy. All six call sites switched (`InitPin`, `SetPin` ×2, `Login`, `LoginUser`, `Pkcs11Slot.InitToken`); the `SecurePin(string)` constructor's UTF-8 transient was pinned the same way. No public-API change. Unit tests added; SoftHSM login paths verified green end-to-end.
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:303` (InitPin), `:334-335` (SetPin), `:426` (Login), `:466` (LoginUser); `Pkcs11Slot.cs:166` (InitToken)
- **Problem:** Each path does `pin.Pin.ToArray()` then zeroes the copy in a `finally` — but the fresh array is unpinned, so a GC compaction between allocation and `ZeroMemory` can leave an unzeroed PIN copy on the heap: exactly the leak `SecurePin`'s pinned buffer (`SecurePin.cs:26-40`) exists to prevent.
- **Proposed action:** Marshal directly from the already-pinned `SecurePin` buffer (span-taking interop overload), or pin the transient with `GCHandleType.Pinned` for its lifetime. Internal plumbing only; public signatures already take `SecurePin`.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist B

### [BL-018] ✅ RESOLVED — Wrap-hardening attributes (`CKA_WRAP_WITH_TRUSTED`, `CKA_TRUSTED`, `CKA_WRAP_TEMPLATE`/`CKA_UNWRAP_TEMPLATE`) have no first-class template-builder support
- **Status:** Resolved 2026-08-10. `SecretKeyTemplateBuilder` gained `WrapWithTrusted()`, `Trusted()`, `WrapTemplate()`, `UnwrapTemplate()`, and `DeriveTemplate()`; `PrivateKeyTemplateBuilder` gained `WrapWithTrusted()`, `UnwrapTemplate()`, and `DeriveTemplate()`; `PublicKeyTemplateBuilder` gained `Trusted()` and `WrapTemplate()`. Nested templates are configured through a new public `NestedKeyTemplateBuilder`, which carries no secure defaults by design — the same nested template means opposite things depending on which attribute carries it (see below), so a silent default would be wrong in one direction. `ObjectTemplate`'s internal constructor now takes an optional `List<ObjectTemplate>` of owned nested children and disposes them; `ObjectTemplateBuilderBase` gained a protected `NestedTemplate(...)` helper shared by every nested-template setter. Documented in the README's new "Wrap hardening" subsection.
  - **`CKA_WRAP_TEMPLATE` was unreachable, not merely awkward.** The entry's own framing said the nested-template form was "awkward and undocumented" — in fact the base builder exposed `Attribute(CKA, …)` overloads only for `ulong`/`bool`/`string`/`ReadOnlySpan<byte>`, and `Set` is `protected`, so there was no way to attach a nested `CK_ATTRIBUTE[]` at all from outside the assembly. The correction belongs in the record: this was a missing capability, not a rough edge.
  - **`CKA_DERIVE_TEMPLATE` was added beyond this entry's stated scope.** The plumbing is identical to `CKA_UNWRAP_TEMPLATE` (both are impositions applied to a token-produced key), and `Pkcs11Session.IsNestedAttributeTemplate` already listed all three attributes for read-back purposes. Shipping `WrapTemplate`/`UnwrapTemplate` while leaving `DeriveTemplate` unreachable would have left exactly one of the three nested-template attributes stuck behind the same escape hatch this entry closes for the other two.
  - **Follow-up 2026-08-10 — whole-branch review findings, all fixed.** The independent branch review found that the ownership invariant was still only half-tested: `Build()` clears `_nested` unconditionally, so dropping the nested list from the `ObjectTemplate` it returns left the whole suite green while leaving the children unreferenced — a later GC would finalize them and free the buffers the parent's flat copy still points at, mid token call. The `NestedTemplateCount` seam proved the builder let go; nothing proved the template caught. Fixed by replacing that seam with `NestedTemplates` on the builder and adding `NestedChildren` on `ObjectTemplate`, asserting both halves in `Build_TransfersOwnershipOfNestedChildren`; the previously-invisible mutation now fails. Also fixed: `GC.KeepAlive` added at all **14** template call sites in `Pkcs11Workspace`/`Pkcs11Key` (the review named seven; the `FindAllObjects([.. filter.Attributes])` sites have the identical shape — after the spread the template is dead to the JIT, so a temporary could be finalized during the in-flight native call); the nested-list constructor now reads children through `CkAttribute` so a disposed child throws instead of marshalling silently as `{type, NULL, 0}`; a test for the displaced-child disposal on repeat `WrapTemplate`; a public `Attribute(CKA, Action<NestedKeyTemplateBuilder>)` overload so `GenericTemplateBuilder`'s vendor-defined classes can reach nested templates too; the `configure` null-check moved ahead of the disposed/built guards to match the `Attribute(...)` overloads; and a correction to `ObjectTemplateBuilderBase.Dispose(bool)`'s XML doc, which justified having no finalizer by claiming `ObjectAttribute` has one — it does not, and the resulting leak-on-misuse is the deliberate trade against freeing memory under a live token.
  - **Follow-up 2026-08-10 — finalizer redesign.** The `GC.KeepAlive` fix above patched call sites; this fixes the shape. `~ObjectTemplate` is gone: a template aggregates `ObjectAttribute` instances but does not own their buffers, so finalizing it freed memory that live attributes still described — reachability of the container says nothing about whether the contents are in use, which is why the hazard existed at all. The safety net moved down to `ObjectAttribute`, which owns the buffer and is the correct reachability to key on. That mattered for security, not just leaks: `UnmanagedMemory.Free` zeroizes before releasing, so the finalizer is what wipes key material (an imported `CKA_VALUE`, say) from unmanaged memory when a caller forgets to dispose — and an `ObjectAttribute` never placed in a template previously had no safety net at all. Two prerequisites had to land with it. (a) **Ownership is now explicit** (`_ownsValue`): `GetValueAsAttributeArray` was using the "takes ownership" constructor for views pointing at buffers the nested children own, so disposing a read-back array freed someone else's memory — a pre-existing landmine that a finalizer would have made fire unprompted at the next GC. Those views are non-owning and suppress their own finalizer. (b) **Release is finalizer-safe**: the claim is an `Interlocked.Exchange`, because `UnmanagedMemory.Free` throws on a second free and that throw on the finalizer thread would take the process down. Finally, the keep-alives moved from the 14 public call sites to the ~13 marshalling methods in `Pkcs11Session` — the actual choke point, where `BuildTemplate` copies raw `pValue` pointers and drops the reference — and `BuildTemplate`'s own docs now state the requirement, since C# cannot enforce it.
  - **Follow-up 2026-08-10 — allocation tracker made lock-free.** Adding `~ObjectAttribute` put `UnmanagedMemory.Free` on the finalizer thread, and that method took a process-global `Lock` around a shared `Dictionary` on every allocate and free (the tracker is populated unconditionally; only its logging is gated by `DebugModeEnabled`). A single application thread holding that lock could therefore stall finalization for the whole process, not just this library — a coupling the finalizer change introduced. Now a `ConcurrentDictionary`: `TryAdd`/`TryRemove` are atomic on their own, which is all the tracker needed, and `TryRemove` doubles as the claim that makes a double-free impossible. It also removes a serialization point that every attribute allocation across every session was passing through.
  - **Lifetime hazard and how the design closes it.** `ObjectAttribute(CKA, List<ObjectAttribute>)` copies each child's `CK_ATTRIBUTE` struct — including its `pValue` pointer — into the parent's flat buffer with no deep copy and no ownership transfer, so a child must outlive and stay reachable from its parent (`ObjectTemplate` carries a finalizer as a backstop). The callback design (`Action<NestedKeyTemplateBuilder>`) never hands the caller a disposable child to mismanage: the nested builder is constructed, configured, and consumed entirely inside `NestedTemplate(...)`, and the resulting `ObjectTemplate` is stored in the parent's owned-children list and disposed alongside it.
  - **A correction worth recording honestly.** The original plan's mutation check for the ownership test did not reproduce: the test could not observe child lifetime at all, because `GetValueAsAttributeArray()` reads only the parent's own flat buffer and never dereferences the child pointers, so a disposed-and-zeroed child was invisible to it. The fix was an `internal NestedTemplateCount` test seam on the builder base (precedent: `LowLevelPkcs11Library.TrackedSessionCount`) plus a `Build_TransfersOwnershipOfNestedChildren` test; the mutation that the test actually catches is deleting `_nested.Clear()` from `Build()`.
  - **`Trusted()` is documented as SO-settable only, not gated.** PKCS#11 restricts setting `CKA_TRUSTED = true` to the security officer; a conformant token rejects it from a normal user session with `CKR_ATTRIBUTE_READ_ONLY`. The builder does not enforce this locally — it has no way to know which user type opened the session, and refusing at build time would break legitimate SO-session use. The XML docs and the README both call this out explicitly.
- **Verification:** Full suite green: 1972 passed, 0 failed, 631 skipped, 2603 total (`dotnet test ... -- xUnit.MaxParallelThreads=2`). `dotnet build -c Release` of the library project: 0 Warning(s).
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Objects/SecretKeyTemplateBuilder.cs:57-64`, `Objects/PrivateKeyTemplateBuilder.cs:22-28`
- **Problem:** Secure defaults close the direct wrap-exfiltration path, but for keys deliberately made wrappable the standard defense-in-depth controls are reachable only through the generic `Attribute(CKA, …)` escape hatch; the nested-template form is awkward and undocumented. A hard-to-misuse library leaves its main wrap-hardening controls off the beaten path.
- **Proposed action:** Add fluent helpers (`WrapWithTrusted()`, `Trusted()`, `WrapTemplate(...)`/`UnwrapTemplate(...)`) and document the wrap/unwrap-template threat in the security-model docs. Additive.
- **Breaks public API?** No
- **Raised by:** Cryptographer B

### [BL-019] v3.2 functions bound at the interop layer but unreachable from the public API (verify-signature, authenticated wrap, async, validation flags)
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/ILowLevelPkcs11Library.cs:76-85`, `Native/FunctionPointers.cs:336-364`; no public callers (verified by the specialist)
- **Problem:** `C_VerifySignature*`, `C_WrapKeyAuthenticated`/`C_UnwrapKeyAuthenticated`, `C_AsyncComplete`/`C_AsyncGetID`/`C_AsyncJoin`, and `C_GetSessionValidationFlags` are fully wired and gated but have no public wrapper, so consumers cannot use them without forking. (KEM and message-AEAD are exposed.)
- **Proposed action:** Add high-level wrappers for verify-signature streaming, authenticated wrap/unwrap, and validation-flags inspection; make an explicit, documented in/out-of-scope call on async for 1.0. Additive post-1.0, so not a release blocker — but decide deliberately.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** PKCS#11 v3.2 §5.16, §5.17, §5.20

### [BL-020] `InterfaceInfo` omits the interface version, defeating the point of interface enumeration
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/InterfaceInfo.cs:8-21`; producers `Pkcs11Library.cs:276-282`, `:308-311`
- **Problem:** `GetInterfaces()` returns only `Name` + flags. The interface's cryptoki version sits in the `CK_VERSION` header of the function list the descriptor points to, but is never surfaced — a consumer cannot tell a token's 2.40 / 3.0 / 3.2 "PKCS 11" interfaces apart.
- **Proposed action:** Read the `CK_VERSION` from `CK_INTERFACE.FunctionList` and add a `Version` property. Additive.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist A

### [BL-021] ✅ RESOLVED — Inconsistent XML-doc `<exception>` coverage on the shipped surface
- **Status:** Resolved 2026-07-09. Systematic `<exception>`-completeness pass across the public surface: `Pkcs11Key` (all operational methods: Sign/Verify/Encrypt/Decrypt/Wrap/Unwrap/Encapsulate/Decapsulate/Derive/Message* now document ObjectDisposed/ArgumentNull/InsecureOperation/Pkcs11Exception incl. the underlying C_ function; Verify's managed-fallback NotSupportedException caught too), `Pkcs11Workspace` (18 members), `Pkcs11Library`/`Pkcs11Slot`/`Pkcs11Object`/`Pkcs11Certificate`/`Mechanism`/`SecurePin`, `Objects/` (ObjectAttribute read-backs with per-condition AttributeValueException tags; builder guards documented at `ObjectTemplateBuilderBase`), `MechanismParams/` validating constructors, and `Algorithms/` (AEAD Encrypt/Decrypt incl. auth-failure CKRs, DSA/ECDH/ECDsa/RSA overrides, SP800-108 KDF, certificate extensions). The two cited terse summaries (`Pkcs11Slot`, `Mechanism`) rewritten as proper sentences. Session-layer `AllowInsecure` guards documented as part of the public contract (consistent convention across files). Verified: docs-only diff (zero non-`///` lines changed), build green with warnings-as-errors (CS1570/CS1574 enforced), 791 unit tests pass.
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** M
- **Location:** e.g. `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs:304,359,379,462,489,566` (throw `ObjectDisposedException`/`ArgumentNullException`, document at most one); contrast `Pkcs11Workspace.cs:120-121`
- **Problem:** Flagship types are documented excellently, but many operational methods omit `<exception>` tags for exceptions they demonstrably throw, so IntelliSense under-reports what callers must catch. Summary style is uneven; these docs ship in the package XML.
- **Proposed action:** A systematic `<exception>`-completeness pass over every public method plus summary-style normalization.
- **Breaks public API?** No
- **Raised by:** .NET Engineer A

### [BL-022] net10.0-only targeting is a major reach cut with no documented rationale
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` (`<TargetFramework>net10.0</TargetFramework>`); `README.md:15`
- **Problem:** net8.0 (LTS through Nov 2026) and netstandard2.0 consumers are excluded entirely. The csproj comment justifies net10 via the `NativeCULong` RID assets, but the real blocker is the net10 BCL PQC types (`MLDsa`, `MLKem`, `SlhDsa`, `SP800108HmacCounterKdf`); neither the trade-off nor the rationale is stated anywhere a consumer sees.
- **Proposed action:** Either multi-target (net8.0 classical surface with `#if`-gated PQC façades) or explicitly document the net10-only decision and its PQC rationale in the README. Adding TFMs later is non-breaking, but the positioning decision belongs pre-1.0.
- **Breaks public API?** No
- **Raised by:** .NET Engineer A

### [BL-023] Windows consumers without a resolved RID asset hit a hard `PlatformNotSupportedException` at first load
- **Area:** P/Invoke
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs:184-196`; csproj (no `net10.0-windows` TFM)
- **Problem:** Windows correctness depends on `NativeCULong` resolving its 4-byte per-RID asset. The width guard fails loudly instead of mis-marshalling (correct), but in AnyCPU/no-RID, single-file, or transitive-reference configurations the library is simply unusable on Windows at first load — a consumer trap with no guidance. (CI validates the packed path itself on win x64/x86/arm64.)
- **Proposed action:** Ship a Windows consumption guide (RID-specific restore/publish) or a `net10.0-windows` TFM hard-referencing the 4-byte build, and add a CI job that consumes the packed .nupkg from a no-RID Windows app to prove asset resolution as shipped.
- **Breaks public API?** No
- **Raised by:** .NET Engineer B

### [BL-024] ✅ RESOLVED — Native struct-layout pin coverage is missing win-x86 absolute size pins (gaps (a) Unix FUNCTION_LIST and (c) pointer-field offsets closed 2026-07-29)
- **Status:** Resolved 2026-07-29. Added `IsWindows32` and a `WindowsSiblingStructSize_OnX86` `ConditionalTheory` pinning all 98 Pack=1 siblings on the ILP32 leg, closing the last gap. The values are derived, not probed — no 32-bit Windows host was available — but the derivation was validated before use: a field-walking model (Pack=1, CK_ULONG=4, pointer=8) reproduced **all 98** existing win-x64 pins exactly, so the same model at pointer=4 rests on something already checked against known-good values. Sanity checks hold: pointer-free structs are byte-identical across the two ABIs (`CK_AES_CTR_PARAMS` 20, `CK_RC2_CBC_PARAMS` 12) and `CK_FUNCTION_LIST_Windows` goes 546 → 274 = 2 + 68×4. Because both Windows theories are skipped on Unix, a further `WindowsX86Pins_AreDerivableFromTheX64Pins` `[Fact]` runs on *every* platform and re-derives each x86 literal from its x64 counterpart minus 4 per recursive pointer field — verified to fail when a single row is corrupted. That guards transcription, not the ABI itself; the win-x86 CI leg remains the confirmation that the model matches real ILP32.
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `Tests/Unit/Native/MarshalSizeOfTests.cs:17-27,182`
- **Problem:** Absolute size pins run only on `IsWindows64`, so the win-x86 ILP32 leg — the ABI most different from LP64, and one CI genuinely runs — has no absolute expectations. (Gaps (a) Unix `CK_FUNCTION_LIST` pins and (c) offset pins for the pointer-bearing structs were closed 2026-07-29.)
- **Proposed action:** Add a `ConditionalTheory(nameof(IsWindows32))` mirroring `WindowsSiblingStructSize`. The expected values are derivable rather than guessable: with `Pack = 1` and `CK_ULONG` = 4 on both Windows ABIs, win-x86 size = win-x64 size − 4 × (recursive count of pointer fields). Values cannot be verified on a Linux host, so the first CI x86 run is the confirmation step.
- **Breaks public API?** No
- **Raised by:** QA A, QA B

### [BL-025] ✅ RESOLVED — "v3.2 methods fail cleanly on sub-v3.2 modules" contract is unverified
- **Status:** Resolved 2026-07-10. Hermetic: new `Unit/Internal/Pkcs11SessionV32NotSupportedTests.cs` drives every v3.2 session method (`EncapsulateKey`, `DecapsulateKey`, `WrapKeyAuthenticated`, `UnwrapKeyAuthenticated`, `VerifySignature` one-shot + streaming, `GetSessionValidationFlags`) against a fake reporting `IsV32ApiSupported == false` whose low-level entries return `CKR_FUNCTION_NOT_SUPPORTED` (mirroring the real dispatch's null-function-pointer guard), asserting each throws the documented typed `Pkcs11Exception` — never an NRE — plus `SupportsV32Api == false`. Real-module: the spec-version-gate suites (v2.40 and v3.0 tiers over real SoftHSM) each gained an `EncapsulateKey_Throws_FunctionNotSupported` case exercising the actual null-fptr dispatch end to end. All 50 related tests green.
- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:3018-3026`; `Tests/Unit/Internal/Pkcs11SessionV32Tests.cs`
- **Problem:** Every hermetic v3.2 test uses a fake reporting `IsV32ApiSupported => true`; nothing drives `EncapsulateKey`/`DecapsulateKey`/`WrapKeyAuthenticated`/`VerifySignature`/`GetSessionValidationFlags` against a backend reporting false to confirm the documented `CKR_FUNCTION_NOT_SUPPORTED` exception rather than a null-delegate NRE.
- **Proposed action:** Add a not-supported-fake test asserting each v3.2 method throws the documented typed exception.
- **Breaks public API?** No
- **Raised by:** QA A

### [BL-026] ✅ RESOLVED — No assembly-level test-parallelization policy around the process-global native module
- **Status:** Resolved 2026-08-10. The policy is now stated in code (`Support/TestParallelization.cs`: `[assembly: CollectionBehavior(CollectionPerClass, DisableTestParallelization = false)]`) with the reasoning for keeping the fast default — an assembly attribute rather than an `xunit.runner.json`, so it can carry that comment and can't be silently left out of the output. The guardrail is `Unit/TestCollectionConventionTests`, four reflection rules: every `Integration/**` test class carries a `[Collection]` or an explicit `[NoBackendCollection("why")]`; any class named `*_Mock`/`*_SoftHsm`/`*_Nss`/`*_OpenCryptoki` anywhere in the assembly (so `Algorithms/**` too) joins the matching collection; an injected collection fixture is supplied by the declared collection; and no `[Collection]` names a non-existent definition. A fifth test guards against the four passing vacuously. Six existing classes took the opt-out (the four `*AvailabilityTests`, which only run static `File.Exists` probes, and the two `*.Managed.cs` classes, which drive per-test in-process `ManagedSoftToken`s). Verified by mutation: dropping a `[Collection]` and typoing another failed 4 of the 5 tests with the right diagnostics.
- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/` (no `xunit.runner.json`; safety rests on per-file `[Collection]` attributes)
- **Problem:** pkcs11-mock is single-session and process-global; a new Integration test class that forgets its backend `[Collection]` attribute runs in parallel with the collection and corrupts shared native state — an intermittent failure with no guardrail against the omission.
- **Proposed action:** Add an explicit parallelization policy (`xunit.runner.json`/assembly attribute) plus a convention test that every `Integration/**` class carries a backend collection.
- **Breaks public API?** No
- **Raised by:** QA A

### [BL-027] ✅ RESOLVED — No CI-health guard for opencryptoki — the second real backend can silently stop running
- **Status:** Resolved 2026-07-10. The ubuntu-latest test step now declares `PKCS11_TEST_EXPECT_OPENCRYPTOKI=1` (set on the step itself, not by the provisioning script, so a provisioning regression that stops exporting the library path is caught rather than masked), and a new `OpenCryptokiAvailabilityTests` guard — mirroring `SoftHsmAvailabilityTests` — fails the job when the marker is set but `OpenCryptokiBackendFixture.OpenCryptokiAvailable` is false. Verified both ways locally: passes with no marker, fails with the marker and no backend.
- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/OpenCryptokiBackendFixture.cs:34`; contrast `Integration/Smoke/SoftHsmAvailabilityTests.cs:14`; provisioning `ci.yml:288-293`
- **Problem:** SoftHSM has an availability guard that fails the job if missing; opencryptoki's availability is a bare `File.Exists` on an env var written by multi-step CI provisioning. If provisioning regresses, every opencryptoki KAT and integration test skips and the second-implementation cross-check vanishes under a green build.
- **Proposed action:** Add an `OpenCryptoki_IsAvailable` guard gated on a CI marker env var (e.g. `EXPECT_OPENCRYPTOKI=1` on the ubuntu-latest leg), mirroring the SoftHSM guard.
- **Breaks public API?** No
- **Raised by:** QA B

### [BL-028] AES-CCM, ChaCha20-Poly1305, SP800-108 KDF, and SLH-DSA have zero real-backend coverage
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/SoftHsmBackendFixture.cs:59-88`; the four `*.Managed.cs` suites under `Tests/Algorithms/`
- **Problem:** Neither CI real backend implements these four mechanism families, so their `CK_*_PARAMS` are validated on the wire only by the in-process `ManagedSoftToken` — a strict real token rejecting a field the fake tolerates would never surface. (Managed KATs and struct-size pins do exist.)
- **Proposed action:** Add a third soft-token backend that implements them (e.g. Kryoptic covers AES-CCM, ChaCha20-Poly1305, ML-KEM, SLH-DSA), at least as a nightly/optional CI leg, and light up the existing capability-gated cases.
- **Breaks public API?** No
- **Raised by:** QA B

### [BL-029] No fuzzing of the inbound marshalling layer
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Unit/Native/` (no SharpFuzz or similar anywhere)
- **Problem:** The highest-risk direction — a buggy/hostile token controlling returned lengths in the two-call probe and attribute read-back — is covered only by example-based tests.
- **Proposed action:** Add a SharpFuzz harness over (1) `CK_ATTRIBUTE[]` template build/read-back and (2) length-probe read-back with adversarial `ulValueLen`. Pairs with BL-013.
- **Breaks public API?** No
- **Raised by:** QA B, Cryptographer B

### [BL-030] Docs site is API-reference-only; README fails the 60-second use-case test
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** M
- **Location:** `docs/toc.yml`, `docs/index.md`, `README.md`
- **Problem:** `toc.yml` has only Home + API; there is no getting-started or end-to-end flow (load → initialize → session → login → operate → dispose) anywhere, and the README contains no usage code at all.
- **Proposed action:** Add a `docs/articles/` getting-started walkthrough wired into `toc.yml`, and a minimal end-to-end snippet at the top of the README.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-031] No migration guide from Pkcs11Interop
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** M
- **Location:** MISSING: `MIGRATION.md` / docs article
- **Problem:** Pkcs11Interop is the incumbent .NET PKCS#11 binding and the most likely source of adopters; no concept/API mapping exists — a real adoption barrier.
- **Proposed action:** Add a migration article mapping common Pkcs11Interop patterns (slots/sessions/attributes/mechanisms) to this library's façades; link from the README.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-032] No dependency-update automation (dependabot/renovate) or dependency-review gate
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** MISSING: `.github/dependabot.yml` (verified)
- **Problem:** Actions are SHA-pinned (good) but nothing keeps the pins current or flags vulnerable NuGet dependencies.
- **Proposed action:** Add `dependabot.yml` for the `nuget` and `github-actions` ecosystems (grouped); optionally `dependency-review-action` on PRs.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-033] No CHANGELOG or GitHub Release / release-notes flow
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** M
- **Location:** MISSING: `CHANGELOG.md` (verified); `.github/workflows/publish.yml` (no release step)
- **Problem:** Publishing pushes to NuGet with no per-version record of changes — especially important for a security library where gate/behavior changes matter.
- **Proposed action:** Adopt Keep-a-Changelog (or Conventional Commits-generated notes) and create a GitHub Release from the tag-triggered publish.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-034] No CONTRIBUTING.md, CODE_OF_CONDUCT.md, or issue/PR templates
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** MISSING: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `.github/ISSUE_TEMPLATE/`, `.github/pull_request_template.md` (all verified absent)
- **Problem:** Contribution prerequisites here are non-trivial (submodules, from-source OpenSSL 3.5, format/warnings gates) and entirely undocumented; no triage structure exists.
- **Proposed action:** Add the standard community-health files, with CONTRIBUTING covering submodule init, native prerequisites, and the formatting/warnings expectations.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-035] No SBOM generated or attached at publish
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `.github/workflows/publish.yml` (provenance attestation present at `:41-43`; no SBOM step)
- **Problem:** Supply-chain-conscious consumers increasingly require a CycloneDX/SPDX SBOM; provenance attestation alone doesn't provide the dependency graph.
- **Proposed action:** Generate a CycloneDX SBOM (dotnet tool or `Microsoft.Sbom.Targets`) during publish and attach it to the release; optionally attest it.
- **Breaks public API?** No
- **Raised by:** QA C, .NET Engineer B

### [BL-036] ✅ RESOLVED — No CodeQL SAST workflow
- **Status:** Resolved 2026-08-10 (configured 2026-07-21). CodeQL runs via GitHub's **default setup**, which is why no `.github/workflows/codeql.yml` exists — the scan is repo-configured rather than checked in. Confirmed against the API (`repos/.../code-scanning/default-setup`): `state: configured`, languages `csharp`, `c-cpp` (the vendored native shims), and `actions`, default query suite, `remote` threat model, weekly schedule on top of the push/PR triggers. Results land in the GitHub security tab and the advisory flow, which was the gap SonarCloud left open. Note the trade-off of default setup: the configuration is not reviewable in-tree, so a change to it leaves no diff — move to an advanced-setup workflow file if that ever needs to be gated by code review.
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** MISSING: `.github/workflows/codeql.yml`
- **Problem:** SonarCloud runs in `code-quality.yml`, but CodeQL is the expected baseline SAST for a security-sensitive library and feeds GitHub's security tab/advisory flow, which Sonar does not.
- **Proposed action:** Add the standard CodeQL `csharp` workflow on push/PR/schedule.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-057] ✅ RESOLVED — Unmanaged parameter memory is scoped to the parameter object rather than to the call that needs it
- **Status:** Resolved 2026-07-29. `Native/MechanismParameterScope.cs` owns every unmanaged byte for one native call and zeroizes then frees all of it on disposal. All 27 `Ckm*Params` are now managed descriptors: they build their `[PackedForPkcs11]` struct in `BuildMarshalable(scope)`, allocate nothing in their constructors, and have no finalizers. `Mechanism` is a stateless pairing of type and descriptor — `Marshal(scope, out object? marshalledParams)` is a pure function, and `AbsorbOutput(object?)` copies token-written output back into managed state before the scope is released. `Pkcs11Session` opens one scope per operation across 32 call sites and 27 scopes. Deleted: `ToMarshalableStructure` (89 call sites), 26 finalizers, `TryClaimOwnership`/`ThrowIfAlreadyOwned` and its `InvalidOperationException`. Sharing one descriptor across two mechanisms is now legal and asserted (`BuildMarshalableTests.cs:661`). The four in/out types stopped being exceptions to the model: `CopyTagTo`/`CopyMacTo`/`AdditionalDerivedKeys` read managed buffers that `AbsorbOutput` fills. Full suite green (1865 passed / 0 failed / 630 skipped).
  - **Deviation from the design:** the spec had `Mechanism` cache the struct it built. That was rejected during implementation — the cache made one instance carry per-operation state, so `DecryptVerify(m, k, m, k, …)` overwrote it and silently discarded the first mechanism's output. Single-threaded and deterministic, not a race. Hence the `out` parameter.
  - **Public behaviour change:** `AdditionalDerivedKeys` returns an empty snapshot before the derive rather than one zero handle per requested key. Pre-seeding zeros was considered and rejected: it makes "the token never wrote this slot" indistinguishable from "not yet absorbed."
  - **Public behaviour fix found in review:** the raw `Mechanism(type, byte[])` constructors now copy the caller's array. Once `Marshal` read it at call time instead of the constructor copying it to unmanaged memory immediately, a caller zeroizing its own IV buffer afterwards — ordinary hygiene — silently produced an all-zero IV the token accepts without error.
  - **`IDisposable` deliberately remains** on `MechanismParameters` and `Mechanism` with a no-op `Dispose`, so this change is source-compatible. Removing it is BL-058.
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** L
- **Location:** `MechanismParams/` (27 types, 23 of which call `UnmanagedMemory.Allocate`); `MechanismParams/MechanismParameters.cs`; `Mechanism.cs`; `Internal/Pkcs11Session.cs` (~8 sites that consume an already-marshalled `CK_MECHANISM`)
- **Problem:** `MechanismParameters` does two jobs: it describes what the caller wants (a nonce, an AAD, a tag length) and it owns unmanaged memory laid out for the native ABI. Every symptom traced so far — the disposal-order contract, ownership transfer to `Mechanism`, the sharing hazard, the `TryClaimOwnership` guard, finalizers on 25 types — follows from the second job. The buffers only need to exist for the duration of the native call; they persist today solely because allocation happens in the parameter constructor. The debate has been about who owns memory across a lifetime that should not exist.
- **Proposed action:** Scope the unmanaged lifetime to the operation. Parameters hold managed data only, validated in the constructor as today. The session allocates the `CK_MECHANISM` block and its side buffers immediately before the native call, marshals, calls, and frees in a `finally`. `Mechanism` becomes a plain pairing of type and descriptor. Sharing is then trivially safe, the ordering contract and the ownership guard disappear, and `MechanismParameters` drops `IDisposable` along with the finalizers.
- **How this handles the in/out parameters:** four types carry memory the token writes and the caller reads back — `CkmGcmMessageParams.CopyTagTo`, `CkmCcmMessageParams.CopyMacTo`, `CkmSalsa20ChaCha20Poly1305MsgParams.CopyTagTo`, and `CkmSp800108KdfParams.AdditionalDerivedKeys` (handles written into a nested `CK_DERIVED_KEY[]`). Because the operation owns the block, it copies the token's output back into the descriptor's managed buffer before freeing; the read-back accessors then read managed memory. They stop being exceptions to the model instead of being carved out of it.
- **Why zeroization is not a blocker:** the unmanaged copy is still zeroized on free, exactly as today. The descriptor's managed array mirrors data the caller already holds in managed memory, since they passed a span from somewhere — copying extends the window rather than creating a new class of exposure, and the BCL's own AEAD APIs do not wipe caller-provided nonces either. Plain `byte[]` is therefore sufficient and descriptors need no `IDisposable`. `Internal/SecureBuffer.cs` remains available if a future parameter type warrants stronger handling.
- **Variants considered and rejected:** (a) *hybrid* — convert only the input-only types and let the four in/out ones keep owning: gives one type family two different lifetime semantics, so a caller must know which of 27 siblings needs `using`; an inconsistent API is worse here than a uniformly imperfect one. (b) *uniform `SecureBuffer` in descriptors* — `SecureBuffer` is itself `IDisposable` and pins, so parameters would keep `IDisposable` and would need finalizers more than before, erasing the benefit that motivates the work.
- **Scheduling note:** larger than it first appears — the marshalling currently happens in the `Mechanism` constructor and the session consumes the finished struct, so the change reaches the session layer rather than staying inside `MechanismParams/`. Not urgent: the current model is safe, since BL-012 fixed the disposal ordering and sharing now fails loudly at construction. Worth its own spec rather than an incremental fix, and worth doing pre-1.0 because lifetime semantics cannot be changed afterwards.
- **Related:** subsumes what remains of BL-012. Shares its theme with BL-056 — ownership expressed in the type system instead of by convention. Mechanisms, parameters and keys are best settled under one convention rather than three.
- **Breaks public API?** No, as landed — `IDisposable` was kept so no caller had to change. The breaking half is BL-058.
- **Raised by:** BL-012 follow-up; design revised 2026-07-29 after the in/out and zeroization analysis

### [BL-037] No automated versioning source — the version exists only as a tag stamp
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` (`<Version>0.0.0</Version>`); `.github/workflows/publish.yml:29-30`
- **Problem:** No MinVer/Nerdbank.GitVersioning; CI and local builds always produce 0.0.0; nothing verifies a publish tag is on `main`, annotated, or intentional before pushing to an immutable package ID.
- **Proposed action:** Adopt MinVer (or NBGV) so every build derives a deterministic version from git, and guard publish on the tag being reachable from `main`.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-088] `EncapsulationResult` is a struct whose non-nullable properties are null on `default`
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/EncapsulationResult.cs:38` (`public byte[] Ciphertext`), `:44` (`public Pkcs11Key SharedSecret`), `:61` (`Dispose() => SharedSecret?.Dispose();`)
- **Problem:** With nullable reference types enabled both properties advertise non-null, yet the type is a `readonly record struct` whose `default` is reachable by any consumer (`EncapsulationResult r = default;`, an array element, an unassigned field). The XML doc at `:18-20` admits it, and the `?.` in `Dispose` is the compiler-visible proof. Consumers get no warning and a `NullReferenceException` at first use.
- **Proposed action:** Make it a `sealed class` — which also removes the "disposable value type" smell — or keep the struct and annotate both properties `byte[]?`/`Pkcs11Key?` so the nullability contract is honest.
- **Breaks public API?** Yes — either change is SemVer-major; must land before 1.0
- **Raised by:** .NET Engineer A
- **Spec / References:** Extends BL-008 — the `default`-struct nullability hole arrived with the `ValueTuple` replacement; CA1815/CA1001 territory

### [BL-089] `TokenInfo` numeric properties hand back the platform-dependent `CK_UNAVAILABLE_INFORMATION` sentinel as a plain `ulong`
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/TokenInfo.cs:29-57` (`MaxSessionCount`, `SessionCount`, `MaxRwSessionCount`, `RwSessionCount`, `MaxPinLen`, `MinPinLen` and the four memory properties); helper `Common/CK.cs:17-26`
- **Problem:** PKCS#11 lets a token return `CK_UNAVAILABLE_INFORMATION` for any of these. The properties pass it through unmodified and are documented as plain counts, so a consumer sees `18446744073709551615` on Linux/macOS and `4294967295` on Windows for the same token. The one helper that recognises the sentinel, `CK.IsCkInformationUnavailable`, takes a `NativeCULong` and so cannot be applied to these `ulong` properties without the consumer constructing an interop type (see BL-067).
- **Proposed action:** Type them `ulong?` (null when unavailable) or add `bool …Available` companions; either way document the sentinel explicitly.
- **Breaks public API?** Yes — property-type change; must land before 1.0
- **Raised by:** .NET Engineer A
- **Spec / References:** PKCS#11 v3.2 §3.2 `CK_TOKEN_INFO` / `CK_UNAVAILABLE_INFORMATION`

### [BL-090] The constants every call site needs (`CKM`, `CKA`, `CKU`, `CKK`, `CKR`) live in a secondary `Common` namespace
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/` — 37 public types, e.g. `Common/CKM.cs:7`, `Common/CKA.cs:8`, `Common/CKU.cs:8`, `Common/CKK.cs:8`, `Common/CKR.cs:8`; consumed by root-namespace signatures at `Pkcs11Library.cs:358`, `Mechanism.cs:39`, `Pkcs11Key.cs:79,121`, `Exceptions/Pkcs11Exception.cs:34`
- **Problem:** No non-trivial program can be written with a single `using KerckhoffsLabs.Security.Cryptography.Pkcs11;` — logging in needs `CKU`, any mechanism needs `CKM`, any template needs `CKA`/`CKK`, and any error handling needs `CKR`, all of which sit under `…Pkcs11.Common`. "Common" is also precisely the non-descriptive grouping the guidelines warn against, and it splits types that are inseparable in use.
- **Proposed action:** Move the constant enums into the root `…Pkcs11` namespace, keeping `Objects`, `Algorithms`, `MechanismParams` and `Exceptions` as they are. If `Common` stays, document the required `using` pair prominently in the README quickstart.
- **Breaks public API?** Yes — namespace moves are SemVer-major; decide before 1.0
- **Raised by:** .NET Engineer A
- **Spec / References:** Framework Design Guidelines §3.2 (namespace naming). BL-009 covers member and type *naming*, not namespace placement

### [BL-091] Vendor and newer-than-enum **attribute** types are second-class: builders and readers take `CKA` only, while `ObjectAttribute` has a `ulong` escape hatch the builders cannot reach
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Objects/ObjectTemplateBuilderBase.cs:41,50,60,69,85` (every `Attribute(...)` overload takes `CKA`); `Objects/ObjectAttribute.cs:115,120,136,146,157,163,171,183,221,244` (parallel `ulong` overloads, unreachable from the builders); `Pkcs11Key.cs:121` (`GetAttributeValue(params CKA[])`); `Common/CKA.cs:8` (`public enum CKA : uint`)
- **Problem:** `GenericTemplateBuilder`'s own doc advertises it for vendor-defined values, but the only way to name a vendor attribute through it is `Attribute((CKA)0x80000042UL, …)` — an unchecked cast into an enum the library elsewhere validates, and one that silently caps the type at 32 bits even though `CK_ATTRIBUTE_TYPE` is a `CK_ULONG` (8 bytes on Unix LP64). Reading has the same shape: `GetAttributeValue` accepts no `ulong`. The `CKM`/`ulong` boundary was deliberated and settled in BL-040; the `CKA` boundary never received the same treatment, and it is the one commercial-HSM consumers hit first.
- **Proposed action:** Add `Attribute(ulong attributeType, …)` overloads on `ObjectTemplateBuilderBase` (keying the internal dictionary on `ulong` rather than `CKA`) and a `GetAttributeValue(params ulong[])` overload; consider `ObjectAttribute.IsVendorDefined`/`TryGetAttributeType(out CKA)` mirroring the `Mechanism` decision.
- **Breaks public API?** No — additive
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** The `CKA` analogue of resolved BL-040; distinct from BL-061, which covers vendor mechanism-*parameter* layouts

### [BL-092] `Pkcs11Key.IsAsymmetricKeyType` omits six asymmetric key types the library's own `CKK` enum declares, so the wrong handle is used
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs:649-654`; missing members at `Common/CKK.cs:23` (`CKK_DH`), `:38` (`CKK_X9_42_DH`), `:296` (`CKK_EC_MONTGOMERY`), `:321` (`CKK_HSS`), `:326` (`CKK_XMSS`), `:331` (`CKK_XMSSMT`)
- **Problem:** The predicate lists only RSA/DSA/EC/EC_EDWARDS/ML_KEM/ML_DSA/SLH_DSA. For an X25519/X448 (`CKK_EC_MONTGOMERY`), DH, or HSS/XMSS/XMSS^MT key pair it returns `false`, so `GetAttributeValue` (`Pkcs11Key.cs:126-128`), `Encrypt` (`:394`), `Wrap` (`:514`) and `MessageEncrypt` (`:464`) pick the **private** handle where they intend the public one. Concretely, a `CKA_EC_POINT` read on an X25519 key pair hits the private object and fails with `CKR_ATTRIBUTE_SENSITIVE` even though a readable public companion is attached — and HSS/XMSS are exactly the v3.1/v3.2 surface this library advertises.
- **Proposed action:** Add the six members, and re-derive the predicate from `CKA_CLASS` where available (the hydrated `objectClass` is already known at `Pkcs11Workspace.cs:638`). Add a unit test per key type asserting handle selection.
- **Breaks public API?** No — behavioural fix
- **Raised by:** .NET Engineer A, Cryptographer A
- **Spec / References:** PKCS#11 v3.0 §2.3.5 (`CKK_EC_MONTGOMERY`)

### [BL-093] `ReadOnlyDisposableList<T>.Empty` is a process-wide singleton that a documented-as-safe `Dispose()` permanently poisons
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/ReadOnlyDisposableList.cs:33` (`public static ReadOnlyDisposableList<T> Empty { get; } = new([]);`); `Dispose` latches `_disposed`, and the indexer, `Count` and `GetEnumerator` all call `ObjectDisposedException.ThrowIf`
- **Problem:** The XML doc states "An empty list. Disposing it does nothing." — but `Dispose()` latches `_disposed` on the shared static instance, after which `Count`, the indexer and `GetEnumerator()` throw `ObjectDisposedException` for every other holder of `Empty` in the process, for the process lifetime. Since this type is the return type of `FindKeys`/`FindObjects`/`FindCertificates`/`GetAttributeValue` and is meant to be consumed with `using`, `using var x = …Empty;` is a live foot-gun. The existing test (`Tests/Unit/ReadOnlyDisposableListTests.cs:135-136`) disposes `Empty` and passes only because its assertion runs first. Verified by the coordinator (the singleton is at `:33`, not `:219` as first cited).
- **Proposed action:** Make `Dispose()` a no-op when the list is empty, or drop `Empty` and return `new([])` from each call site. Add a test asserting `Empty.Count == 0` *after* `Empty.Dispose()`.
- **Breaks public API?** No — behavioural fix
- **Raised by:** .NET Engineer A

### [BL-094] AEAD façades surface tag-authentication failure as `Pkcs11Exception`, not `AuthenticationTagMismatchException`
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/AesGcmPkcs11.cs:130` (documented behaviour) and `:131-189`; same pattern in `Algorithms/AesCcmPkcs11.cs` and `Algorithms/ChaCha20Poly1305Pkcs11.cs`
- **Problem:** These types explicitly mirror `AesGcm`/`AesCcm`/`ChaCha20Poly1305` ("Method shapes mirror the BCL", `AesGcmPkcs11.cs:10`). The one behaviour every AEAD consumer codes against is `catch (AuthenticationTagMismatchException)`; here a forged tag produces an unrelated exception type, so tamper-detection branches silently fall through to a generic error path. Verified by the coordinator: `AuthenticationTagMismatchException` appears nowhere in the library.
- **Proposed action:** In the three `Decrypt` implementations map `CKR_ENCRYPTED_DATA_INVALID`, `CKR_AEAD_DECRYPT_FAILED` and `CKR_SIGNATURE_INVALID` to `AuthenticationTagMismatchException`, and clear the caller's plaintext destination before throwing, as `AesGcm` does.
- **Breaks public API?** Yes — behavioural: the exception type changes. Cheap now; must land before 1.0
- **Raised by:** .NET Engineer A
- **Spec / References:** `System.Security.Cryptography.AesGcm.Decrypt` documented contract

### [BL-095] `GetRSAPrivateKey()`/`GetECDsaPrivateKey()` mint a `Pkcs11Key` the caller can never reach or dispose
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/Pkcs11CertificateExtensions.cs:25-31` and `:41-47`; ownership contract at `Algorithms/RSAPkcs11.cs:31-33`, `Algorithms/ECDsaPkcs11.cs:31-33`
- **Problem:** The extensions call `certificate.TryOpenPrivateKey()` and hand the resulting `Pkcs11Key` to `new RSAPkcs11(key)`/`new ECDsaPkcs11(key)`, which explicitly "does not take ownership". The key is never returned to the caller, so `using var rsa = cert.GetRSAPrivateKey();` disposes the adapter and abandons the wrapper — the opposite of the BCL shape being mirrored, where disposing the returned `RSA` is necessary and sufficient.
- **Proposed action:** Add an internal `ownsKey` flag to the adapters (disposing the wrapped key when set) and use it from these two extension methods so the BCL ownership contract holds; document the borrowed-versus-owned distinction on the public constructors.
- **Breaks public API?** No
- **Raised by:** .NET Engineer A

### [BL-096] `RSAPkcs11` leaves `SignHash`/`VerifyHash` unimplemented, so a documented BCL member throws `NotImplementedException`
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/RSAPkcs11.cs:26-157` (no `SignHash`/`VerifyHash` overrides; the comment at `:80-86` shows the authors know the base defaults throw)
- **Problem:** The reviewer verified on net10.0 with a minimal `RSA` subclass that `SignHash(byte[], HashAlgorithmName, RSASignaturePadding)` and `VerifyHash(...)` throw `NotImplementedException: Method not supported. Derived class must override.` Hash-then-sign is a first-class RSA workflow (`SignedXml`, detached-signature protocols, callers who already hold a digest), and `NotImplementedException` from a public, non-obsolete member of a shipped type is both undocumented here and the wrong exception type.
- **Proposed action:** Implement them over the raw mechanisms — `CKM_RSA_PKCS` with a DigestInfo-wrapped hash for PKCS#1 v1.5, `CKM_RSA_PKCS_PSS` with `CkmRsaPkcsPssParams` for PSS, matching what `ECDsaPkcs11.SignHash` (`Algorithms/ECDsaPkcs11.cs:115-131`) already does — or at minimum override them to throw `NotSupportedException` with an actionable message plus `<exception>` docs.
- **Breaks public API?** No
- **Raised by:** .NET Engineer A

### [BL-097] Logging is a mutable process-global with a documented guarantee the implementation cannot keep
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Logging/Pkcs11Logging.cs:13-20` (the remark) and `:31-38` (`SetLoggerFactory`); captured loggers at `Pkcs11Library.cs:25`, `Pkcs11Slot.cs:22`
- **Problem:** The class remark asserts that replacing the factory "affects every subsequent log call site, including those captured into `static readonly` fields, because the loggers returned by `ILoggerFactory.CreateLogger` are typically thin wrappers that re-dispatch through the factory on every call." That is false for both factories in play: `NullLoggerFactory.CreateLogger` returns `NullLogger.Instance`, and `Microsoft.Extensions.Logging.LoggerFactory` returns a `Logger` bound to *that factory's* provider snapshot. So any type whose `static readonly ILogger` initialised before `SetLoggerFactory` was called — for example a `Pkcs11Library` constructed during host startup, before logging is configured — logs nothing for the rest of the process, silently. It is also DI-hostile: two `Pkcs11Library` instances cannot have different loggers, and the constructor accepts no `ILoggerFactory`.
- **Proposed action:** Accept an optional `ILoggerFactory` on `Pkcs11Library`'s constructors and thread an instance `ILogger` down to `Pkcs11Slot`/`Pkcs11Session`, keeping `Pkcs11Logging` as a fallback. Either resolve the static loggers lazily per call or correct the remark to state the ordering requirement plainly.
- **Breaks public API?** No — additive constructor overloads
- **Raised by:** .NET Engineer A

### [BL-098] There is no mockable seam: every high-level type is sealed with an internal constructor and non-virtual members, contradicting the project's own design rule
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** L
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Workspace.cs:30,35`, `Pkcs11Key.cs:41,52`, `Pkcs11Slot.cs:17,44`, `Pkcs11Library.cs:21`, `Native/ILowLevelPkcs11Library.cs:6-14`, `Internal/Pkcs11Session.cs:20`
- **Problem:** A consumer writing a service that takes a `Pkcs11Key` cannot unit-test it without a real token or software module: the type is sealed, exposes no interface and no virtual members, and cannot be constructed (internal constructor, `InternalsVisibleTo` only for this repo's test assembly). The same holds for `Pkcs11Workspace` and `Pkcs11Slot`. The library gets its own hermetic tests through the `internal` `ILowLevelPkcs11Library`; consumers get nothing equivalent. This directly contradicts the project's stated design rule in `CLAUDE.md` — "Use **interfaces** and **dependency injection** to allow mocking and testing without real hardware."
- **Proposed action:** Extract narrow public interfaces for the consumer-facing operations (e.g. `IPkcs11Workspace`, `ISigningKey`/`IEncryptionKey` over `Pkcs11Key`) implemented by the sealed types, or ship a small `…Pkcs11.Testing` package with an in-memory backend.
- **Breaks public API?** No — additive, but the shape is much easier to get right before the types are locked
- **Raised by:** .NET Engineer A

### [BL-099] The v3.0 half of "bound at interop but publicly unreachable": `C_SessionCancel`, `C_LoginUser`, and the 14 message multi-part / message sign-verify functions
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** L
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:497` (`CancelOperations`, internal), `:456` (`LoginUser`, internal); the message multi-part and message sign/verify functions have no caller outside `Native/` at all (`Native/ILowLevelPkcs11Library.cs:56-57,61-62,64-73`)
- **Problem:** Of the 36 v3.x functions, 10 are reachable publicly and 26 are not; BL-019 enumerates only the v3.2 members of that set, so the v3.0 members are unrecorded. Two are more than completeness items: `C_SessionCancel` is the spec's only way to abort a stuck or partially-fed operation without closing the session — and `Pkcs11Session` already uses it internally for unwind — and `C_LoginUser` is the only login path for HSMs with named user accounts beyond SO/User.
- **Proposed action:** At minimum promote `CancelOperations(...)` and `LoginUser(...)` to `Pkcs11Workspace`; both are already implemented and guarded. Decide explicitly, and document, whether the message multi-part and message sign/verify families ship in 1.0 or are deferred.
- **Breaks public API?** No — additive
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** Extends BL-019 with the v3.0 half and concrete counts

### [BL-100] The v3.2 surface is bound only when the module's *default* interface reports minor ≥ 2, and the per-symbol fallback is then skipped
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs:1554-1558` (early `return` when `TryLoadFromGetInterface` succeeds), `:1675-1704` (`C_GetInterface(null, NULL, …)`), `:1778` (`if (version.Minor >= 2)`), `:1826` (`return true`)
- **Problem:** `TryLoadFromGetInterface` asks for the *default* interface (`pInterfaceName = NULL`, `pVersion = NULL`) and derives the tier from the `CK_VERSION` header of whatever table comes back. The spec does not require the default interface to be the highest version a module implements. If a module defaults to its 3.0 table the method still returns `true`, so `TryLoadV30Symbols` returns early and the per-symbol fallback that would have resolved `C_EncapsulateKey`, `C_VerifySignatureInit`, `C_WrapKeyAuthenticated` and the rest as plain exports never runs — the entire v3.2 surface is silently lost even though the module exports it. `C_GetInterfaceList` is bound but never used by the loader to look for a higher-version `"PKCS 11"` table, and `Minor >= 2` means a future `{4,0}` module would get only the v3.0 bindings. Both vendored real backends happen to list 3.2 first, which is why CI does not catch this.
- **Proposed action:** After the default-interface probe, enumerate `C_GetInterfaceList` for `"PKCS 11"` entries and bind from the highest-version table found; failing that, always run the per-symbol fallback for the tiers the chosen table did not supply. Gate the v3.2 re-read on `Major > 3 || (Major == 3 && Minor >= 2)`.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** PKCS#11 v3.2 §5.4.4–5.4.5 — a NULL name yields the *default*, not necessarily the newest, interface. Extends BL-048; adjacent to BL-047

### [BL-101] The public flag records omit five v3.x bits that `CKF` already defines
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismFlags.cs:117-121` (no `Encapsulate`/`Decapsulate`), `TokenFlags.cs:87` (no `ErrorState`/`AsyncSessionSupported`), `SessionFlags.cs:19` (no `AsyncSession`); the unused constants are at `Common/CKF.cs:116`, `:290`, `:295`, `:300`, `:305`
- **Problem:** `MechanismFlags` exposes every v2.40 and v3.0 mechanism flag but neither v3.2 addition, so a consumer of the public `Pkcs11Key.EncapsulateKey`/`DecapsulateKey` has no typed way to ask `C_GetMechanismInfo` whether the token supports encapsulation with a given mechanism. `TokenFlags` picked up `CKF_SEED_RANDOM_REQUIRED` but not `CKF_ERROR_STATE` (token in an error state — operationally important) or `CKF_ASYNC_SESSION_SUPPORTED`, and `SessionFlags` omits `CKF_ASYNC_SESSION`. The raw `Flags` value is public on each record, so this is discoverability rather than a hard block.
- **Proposed action:** Add `MechanismFlags.Encapsulate`/`Decapsulate`, `TokenFlags.ErrorState`/`AsyncSessionSupported` and `SessionFlags.AsyncSession`. Add a test asserting every `CKF_*` constant in the relevant category has a corresponding property, so the next spec revision cannot drift.
- **Breaks public API?** No — additive
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** `CKF_ENCAPSULATE` 0x10000000, `CKF_DECAPSULATE` 0x20000000, `CKF_ERROR_STATE` 0x01000000, `CKF_ASYNC_SESSION_SUPPORTED` 0x04000000, `CKF_ASYNC_SESSION` 0x00000008 — cross-checked against `vendor/nss/lib/util/pkcs11t.h:258-265,313`

### [BL-102] Token-side IV/nonce generation in the v3.0 message-AEAD params is hardcoded off, and the `CK_GENERATOR_FUNCTION` values do not exist in the library
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismParams/CkmGcmMessageParams.cs:61-70` (`IvFixedBits = 0`, `IvGenerator = 0 // CKG_NO_GENERATE`); `MechanismParams/CkmCcmMessageParams.cs:65-66`; `Common/CKG.cs` contains only the nine `CKG_MGF1_*` values
- **Problem:** The message-based AEAD API's `ivGenerator`/`nonceGenerator` field exists precisely so the *token* can produce non-repeating GCM/CCM IVs, removing the application's ability to reuse a nonce — the one catastrophic misuse of AES-GCM. Both public params types pin it to `CKG_NO_GENERATE` with no way to change it and never read the IV back, so `AesGcmPkcs11.Encrypt` always requires a caller-supplied nonce. `CKG_NO_GENERATE`/`CKG_GENERATE`/`CKG_GENERATE_COUNTER`/`CKG_GENERATE_RANDOM`/`CKG_GENERATE_COUNTER_XOR` are absent from the whole library, so even the raw escape hatch requires a magic number.
- **Proposed action:** Add a `CK_GENERATOR_FUNCTION` enum — named distinctly from `CKG`, since the spec reuses that prefix for two unrelated types — plus optional `ivGenerator`/`ivFixedBits` (resp. nonce) arguments on `CkmGcmMessageParams.ForEncrypt`/`CkmCcmMessageParams`, reading the token-generated IV back through the existing `AbsorbOutput` path and exposing it via a `CopyIvTo`.
- **Breaks public API?** No — additive
- **Raised by:** PKCS#11 Specialist A, Cryptographer A
- **Spec / References:** PKCS#11 v3.2 §2.13 / §2.14; values at `vendor/nss/lib/util/pkcs11t.h:2123-2128`; NIST SP 800-38D §8.2. BL-043 concerns 32-bit GCM tags, a different field

### [BL-103] The recommended hybrid and v3.2 authenticated key-wrap mechanisms have native param structs but no managed parameter type
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/RawMechanismParams/CK_RSA_AES_KEY_WRAP_PARAMS.cs:10-21`, `CK_ECDH_AES_KEY_WRAP_PARAMS.cs`, `CK_GCM_WRAP_PARAMS.cs:32-54`, `CK_CCM_WRAP_PARAMS.cs`, `CK_PKCS5_PBKD2_PARAMS2.cs`, `CK_AES_CBC_ENCRYPT_DATA_PARAMS.cs`, `CK_MAC_GENERAL_PARAMS.cs:64-70` — none referenced from `MechanismParams/`
- **Problem:** 53 of the 85 native param structs have no managed counterpart. Most are genuinely legacy (SSL3/WTLS/SKIPJACK/GOST/OTP) and their absence is defensible, but seven are not. `CKM_RSA_AES_KEY_WRAP` is the standard, non-Bleichenbacher way to wrap a symmetric key under an RSA public key — the very thing a consumer reaches for once `GuardMechanism` refuses `CKM_RSA_PKCS` — and it is unreachable because its parameter is *nested* (`OAEPParams` is a pointer to a `CK_RSA_PKCS_OAEP_PARAMS`), which `Pkcs11ParameterWriter` cannot express. `CK_GCM_WRAP_PARAMS`/`CK_CCM_WRAP_PARAMS` are the v3.2 authenticated-wrap parameters and additionally carry token-written output fields, so the writer cannot serve them either. `CKM_PKCS5_PBKD2` and `CKM_AES_CBC_ENCRYPT_DATA` — the latter explicitly *recommended* by the library's own guard message at `Internal/Pkcs11Session.cs:679` — are also unreachable as typed parameters.
- **Proposed action:** Add `Ckm*` types for at least those seven structs. Separately, document that the remaining native structs are deliberately not surfaced, so the asymmetry reads as a decision rather than an oversight.
- **Breaks public API?** No — additive
- **Raised by:** Cryptographer A
- **Spec / References:** PKCS#11 v3.2 §2.1.24, §2.15; v3.0 §2.28. Extends BL-019 with the parameter-type half and BL-061 by naming the concrete stranded mechanisms

### [BL-104] `Pkcs11MechanismMap` has no SHA-3 or SHA-224 arms for RSA/ECDSA/HMAC, and documents an HMAC-truncation overload that does not exist
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/Pkcs11MechanismMap.cs:30-38`, `:49-61`, `:68-80`, `:87-95`, `:176-192`
- **Problem:** `RsaPkcs1Sign`, `RsaPssSign`, `RsaOaep`, `EcdsaSign` and `Hmac` accept only SHA-1/256/384/512 and throw `NotSupportedException` otherwise, yet the `CKM` enum declares every combined mechanism they would need (`CKM_SHA3_256_RSA_PKCS_PSS`, `CKM_ECDSA_SHA3_256`, `CKM_SHA3_256_HMAC`, `CKM_SHA224_RSA_PKCS_PSS`, `CKM_ECDSA_SHA224`) — and the same file already maps SHA-224 and all four SHA-3 sizes for DSA (`:115-124`) and HashML-DSA (`:159-171`). Since .NET 8 exposes `HashAlgorithmName.SHA3_256/384/512`, `RSAPkcs11.SignData(data, SHA3_256, Pss)` fails on a token that fully supports it. Separately, the `Hmac` remark at `:178-181` promises "a different overload that accepts a truncation length" — no such overload exists, and `CK_MAC_GENERAL_PARAMS` has no managed type (BL-103), so truncated HMAC is unreachable.
- **Proposed action:** Add the SHA-224 and SHA3-224/256/384/512 arms to the four RSA/ECDSA/HMAC mappers, and either add the promised `Hmac(HashAlgorithmName, int macLength)` overload or delete the remark.
- **Breaks public API?** No — additive
- **Raised by:** Cryptographer A

### [BL-105] `CkmRsaPkcsOaepParams` hardcodes `Source = CKZ_DATA_SPECIFIED`, blocking tokens that require `source = 0` for an absent label
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismParams/CkmRsaPkcsOaepParams.cs:34-41`
- **Problem:** `Source` is set unconditionally to `CKZ_DATA_SPECIFIED` with `SourceData = IntPtr.Zero`/`SourceDataLen = 0` when no label is supplied — the default — and no constructor or property lets a caller change it. SoftHSM, NSS and opencryptoki accept that combination, but several commercial HSMs reject `CKZ_DATA_SPECIFIED` with a NULL `pSourceData` and require `source = 0`, a long-standing PKCS#11 interop wart. As shipped, RSA-OAEP is unusable end-to-end against those modules, including through `Pkcs11MechanismMap.RsaOaep` and therefore `RSAPkcs11.Encrypt`/`Decrypt`.
- **Proposed action:** Add a constructor overload taking the source value (defaulting to today's behaviour) and consider defaulting to `0` when the label is empty. Additive and cheap now; after 1.0 the behaviour change would need a compat switch.
- **Breaks public API?** No — additive
- **Raised by:** Cryptographer A
- **Spec / References:** PKCS#11 v3.2 §2.1.8 (`CK_RSA_PKCS_OAEP_PARAMS.source`/`pSourceData`); RFC 8017 §7.1 (empty label)

### [BL-106] `CkmAesCcmParams` does not validate the nonce length that its own message-mode sibling enforces
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismParams/CkmAesCcmParams.cs:27-39` (documented range at `:22`, only `IsEmpty` checked at `:30`); compare `MechanismParams/CkmCcmMessageParams.cs:35-36`
- **Problem:** The classic-params CCM type documents "Nonce (BCL: 7-13 bytes)" but checks only that the nonce is non-empty, while `CkmCcmMessageParams` correctly rejects anything outside 7..13 with an explicit RFC 3610 message. It also does not cross-check `dataLen` against the implied length-field width (`L = 15 − nonceLen`, so `dataLen < 2^(8L)`). A 6- or 14-byte nonce therefore reaches the token as a malformed CCM parameter block, surfacing as an opaque vendor error rather than an `ArgumentException`.
- **Proposed action:** Copy the 7..13 check from `CkmCcmMessageParams` into `CkmAesCcmParams`, and add the `dataLen < 2^(8·(15−nonceLen))` bound to both.
- **Breaks public API?** No
- **Raised by:** Cryptographer A
- **Spec / References:** RFC 3610 §2.1; PKCS#11 v3.2 `CK_CCM_PARAMS` (`ulNonceLen` must be 7..13)

### [BL-107] EdDSA and X25519/X448 have no supported path, and the secure-default generator family stops at RSA/EC/AES
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKM.cs:1373` (`CKM_EDDSA`, no `Pkcs11MechanismMap` entry and no façade); `Pkcs11ECCurve.cs:17-19` (Edwards/Montgomery deliberately excluded); `Pkcs11Workspace.cs:366-476` (the complete generator set); `Pkcs11Key.cs:363-374` (managed verify fallback covers only `CKK_RSA` and `CKK_EC`)
- **Problem:** `CKM_EDDSA` has a full, correctly laid-out parameter type (`MechanismParams/CkmEddsaParams.cs`) but no mechanism-map entry and no façade, while ML-DSA and SLH-DSA both get one. `Pkcs11ECCurve.NamedCurves` intentionally omits Ed25519/Ed448 and nothing replaces it, so generating an Ed25519 key requires hand-DER-encoding `CKA_EC_PARAMS` through the generic attribute escape with an OID the docs never name. There is also no `GenerateEd25519KeyPair`/`GenerateMlDsaKeyPair`/`GenerateMlKemKeyPair`/`GenerateSlhDsaKeyPair`, so an agility migration drops off the hardened paved path and must reconstruct the `Sensitive().NonExtractable()` posture by hand. Finally, `Pkcs11Key.Verify`'s no-public-handle fallback handles only RSA and EC while `IsAsymmetricKeyType` lists four more types, so those reach `CKR_OBJECT_HANDLE_INVALID` rather than a typed "not supported". EdDSA is supported by all three real CI backends but is exercised only through the *internal* session (`Tests/Integration/Sign/SignEdDsaTests.SoftHsm2.cs:14-40`), so the public surface has no EdDSA coverage at all.
- **Proposed action:** Add named-curve constants and `CKA_EC_PARAMS` support for Ed25519/Ed448/X25519/X448 (Ed25519 needs only the well-known OID `1.3.101.112`) plus `Pkcs11MechanismMap.EdDsaSign(bool prehash, ReadOnlySpan<byte> context)`; add the four missing generator helpers with the same posture; make the `Verify` fallback throw `NotSupportedException` naming the key type. If EdDSA is intentionally out of scope for 1.0, say so in the `CkmEddsaParams` doc so the mechanism does not look half-wired.
- **Breaks public API?** No — additive
- **Raised by:** Cryptographer A, Cryptographer B
- **Spec / References:** PKCS#11 v3.0 §2.3.5–2.3.6; RFC 8032

### [BL-108] `DeriveSharedSecretEcdh` accepts `CKD_NULL` with no gate, silently making the raw ECDH x-coordinate the AES key — and its own doc describes the opposite behaviour
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Workspace.cs:486-488` (doc) and `:494-515` (implementation)
- **Problem:** The `kdf` parameter doc says "pass `CKD.CKD_NULL` to take the raw shared secret as the key material (do your own KDF off-token)", but the method does not return the secret — it derives an on-token AES key from it — so there is no off-token KDF step for the caller to perform. With `CKD_NULL` the resulting AES key *is* the raw x-coordinate, or a token-chosen truncation of it when the field is larger than the requested key length, which SP 800-56A forbids. `GuardMechanism` has no case for `CKM_ECDH1_DERIVE`, so nothing warns or refuses.
- **Proposed action:** Correct the doc to state what `CKD_NULL` actually produces here, and either refuse `CKD_NULL` on this helper unless `AllowInsecure` is set — consistent with the project's established gate pattern — or drop `CKD_NULL` from this convenience overload and point those callers at the lower-level derive.
- **Breaks public API?** No — the gate is a behavioural addition, cheap pre-1.0
- **Raised by:** Cryptographer B
- **Spec / References:** NIST SP 800-56A Rev. 3 §5.8 (a KDF is mandatory on Z); PKCS#11 v3.2 §2.3.3

### [BL-109] Decrypted plaintext and outbound managed copies are duplicated onto the GC heap and never zeroized
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** M
- **Location:** Decrypt side: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:2096-2097`, `:2274-2275`, `:2163-2196`, `:2545`, `:3070`. Encrypt/sign side: `:1756`, `:2000`, `:2254`, `:2308`, `:2339`, `:3543`
- **Problem:** Two halves of one inconsistency. On the decrypt side `Array.Resize(ref decryptedData, …)` allocates a new array and abandons the original, which still holds the full plaintext and is never wiped; the streaming path's `part`/`lastPart` buffers are left populated after the loop; and `DecryptVerify`/`DecryptDigest` accumulate into a growable `MemoryStream` (leaving stale copies as it doubles) and then `.ToArray()` it. On the encrypt/sign side, copies made purely to satisfy the `byte[]`-based P/Invoke signature (`plaintext.ToArray()`) are left for the GC. In a PKCS#11 wrapper the decrypt output is frequently key material — a decrypted key blob is the whole point of the unwrap flow — and the session layer already zeroizes PIN buffers and RNG output, and the façades already zeroize decrypt outputs, so this is an inconsistency rather than a policy.
- **Proposed action:** Replace `Array.Resize` on decrypt outputs with copy-then-`CryptographicOperations.ZeroMemory(old)`; zeroize `part`/`lastPart` in a `finally`; use a pre-sized array or a caller-supplied `Stream` for the dual-function paths; and wrap the outbound copies in `try/finally { ZeroMemory(buf); }` — or replace the `byte[]` P/Invoke overloads with pinned-span ones so the copies disappear, which the comment at `:1531-1532` already anticipates.
- **Breaks public API?** No
- **Raised by:** Cryptographer B, Cryptographer A
- **Spec / References:** Extends BL-046 (RNG/seed copies only) and BL-017 (PIN copies)

### [BL-110] Post-call counts from the module are trusted to grow buffers and to index arrays; four call sites disagree on how to handle it
- **Area:** P/Invoke
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:248-250` (`SupportsMechanism`, no trim at all), `Pkcs11Slot.cs:115-116` (`Array.Resize` up), `Pkcs11Library.cs:228-229` (`Array.Resize` up), `Internal/Pkcs11Session.cs:1287` (loop bound with no clamp); contrast the correct clamp at `Pkcs11Library.cs:267` (`Math.Min`)
- **Problem:** `SupportsMechanism` allocates from the *first* call's count and then materialises the whole array, ignoring what the module wrote on the second call — so if the module reports fewer (legitimate when the token's mechanism set changed between calls) the untouched tail stays `default(CKM)`, which is `0x00000000` = `CKM_RSA_PKCS_KEY_PAIR_GEN`. The cached set then spuriously contains it, and `Pkcs11Key.SupportsMechanism` — whose documented purpose is choosing between a combined-hash mechanism and a hash-then-sign fallback — returns the wrong answer for the rest of the session. Conversely `GetMechanismList` and `GetSlotList` use `Array.Resize` to *grow* on an inflated count, fabricating zero-valued mechanisms and slot ids that flow to callers as real values, and the `C_FindObjects` loop indexes to the reported count with no clamp, yielding `IndexOutOfRangeException` rather than a typed exception. Only `GetInterfaces` clamps. No memory-safety consequence — the managed array bound holds — but the fabricated entries are silent.
- **Proposed action:** Clamp with `Math.Min(reported, array.Length)` at all four sites, or reject a grown count with a typed `Pkcs11Exception` naming both figures, matching the `GuardReportedLength` precedent (`Internal/Pkcs11Session.cs:1203-1217`). Add a fake-module unit test for the shrinking second call.
- **Breaks public API?** No
- **Raised by:** Cryptographer B, .NET Engineer B
- **Spec / References:** PKCS#11 v3.2 §5.2 (two-call convention; `CKR_BUFFER_TOO_SMALL` is the required response to an undersized buffer). Distinct from BL-045, which concerns a ceiling on the first call's magnitude

### [BL-111] Forgotten-dispose safety depends on `~LowLevelPkcs11Library` looking like dead code, and `Pkcs11SessionHandle`'s doc asserts a finalization guarantee that does not exist
- **Area:** P/Invoke
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs:2151-2171`; the claim at `Internal/SafeHandles/Pkcs11SessionHandle.cs:13-18`, release path `:43-61`; `Internal/SafeHandles/Pkcs11ModuleHandle.cs:29-41`
- **Problem:** `Pkcs11SessionHandle` and `Pkcs11ModuleHandle` are both `SafeHandle` (hence `CriticalFinalizerObject`), and the CLR gives **no ordering guarantee among critical finalizers**. The session handle's class remark states the opposite — that the strong `_library` reference "guarantees that `C_CloseSession` can still be called when this handle is finally released" — but reachability prevents *collection*, not *finalization*, so on the path where a consumer drops the library and an open session together, `Pkcs11ModuleHandle.ReleaseHandle` (`NativeLibrary.Free`) may run before the session handle calls `C_CloseSession` through the unmapped module. What actually prevents that today is incidental: `~LowLevelPkcs11Library() => Dispose(false)` runs in the *non-critical* phase and sets `_disposed = true`, so the later `C_CloseSession` hits the `ObjectDisposedException` guard and is swallowed by `ReleaseHandle`'s `catch`. Because `Dispose(false)` releases nothing, that finalizer reads as dead code — deleting it, or "fixing" it to release `_library`, reintroduces a call through a dangling function pointer. Two secondary consequences of the same path: `C_Finalize` is never issued before the module is unloaded (a spec violation; some vendor modules hang or fault at process exit with live worker threads), and no stray session actually receives `C_CloseSession`.
- **Proposed action:** Make the dependency explicit rather than incidental: have `Pkcs11SessionHandle` take a `DangerousAddRef` on the `Pkcs11ModuleHandle` for its lifetime and release it in `ReleaseHandle` — which is exactly what SafeHandle ref-counting is for and makes the ordering real. Correct the remark, and mark `~LowLevelPkcs11Library` as load-bearing until then.
- **Breaks public API?** No
- **Raised by:** .NET Engineer B
- **Spec / References:** `CriticalFinalizerObject` — critical finalizers run after non-critical ones, with no relative order among themselves. Related to BL-078 (the `volatile` half) and BL-083

### [BL-112] No protected-authentication-path login: `pPin = NULL_PTR` is unreachable even though `TokenFlags.ProtectedAuthenticationPath` is surfaced
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/SecurePin.cs:26-28` and `:52-56` (both constructors reject empty); `Internal/Pkcs11Session.cs:421-436` (`Login`), `:301` (`InitPin`), `:331` (`SetPin`), `:456` (`LoginUser`); `Pkcs11Slot.cs:155` (`InitToken`); the flag is exposed at `TokenFlags.cs:38-39`
- **Problem:** PKCS#11 signals "collect the PIN on the token's own pinpad" by passing `pPin = NULL_PTR, ulPinLen = 0`, and this repo's own interop docs say exactly that (`Native/LowLevelPkcs11Library.cs:396`, `:412`). But every public PIN-taking entry point requires a non-null `SecurePin`, and `SecurePin` throws on an empty PIN, so the managed surface can never produce the NULL pointer. The plumbing is already correct — `Delegates.C_Login` maps a zero-length array to `NULL` via `fixed` — only the entry points block it. So the library tells consumers their token has `CKF_PROTECTED_AUTHENTICATION_PATH` and then gives them no way to use it: a pinpad reader or an HSM configured for on-device PIN entry cannot be logged into at all.
- **Proposed action:** Add `Login(CKU userType)`/`InitPin()`/`SetPin()`/`InitToken(string label)` overloads (or accept `SecurePin?`) that pass `null` through to the native call, documented as requiring `TokenFlags.ProtectedAuthenticationPath`.
- **Breaks public API?** No — additive, but a day-one blocker for pinpad users
- **Raised by:** .NET Engineer B
- **Spec / References:** PKCS#11 v3.2 §5.6.8 `C_Login`; `CKF_PROTECTED_AUTHENTICATION_PATH`

### [BL-113] `Type.IsDefined` runs on every marshal call — ~1.07 µs each, twice per call on Windows — where the generator could emit a folded predicate
- **Area:** P/Invoke
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Pkcs11Marshal.cs:63-64` (used at `:28`, `:37`, `:54`); `Native/UnmanagedMemory.cs:343-344` (used at `:159`, `:171`, `:217`, `:235`, `:309`, `:327`)
- **Problem:** Both hot-path classes decide the packed-versus-unified layout with `t.IsDefined(typeof(PackedForPkcs11Attribute), inherit: false)`, an uncached custom-attribute metadata lookup. The reviewer measured **1070 ns per call versus 1.6 ns for a static generic cache — roughly 670×** — on net10.0 Release. It is not one call per operation: `UnmanagedMemory.SizeOf<T>` and `Write<T>`/`Read<T>` each perform a lookup and then delegate to `Pkcs11Marshal`, which performs a second on Windows, and `GetAttributeValue` runs `SizeOf`/`Write`/`Read` per attribute across up to three `C_GetAttributeValue` passes — tens of microseconds of pure reflection per call. The comments justify `Type.IsDefined` as "AOT-safe, no dynamic code", which is true but orthogonal to the cost.
- **Proposed action:** Have `PackedStructsGenerator` emit `PackedDispatch.IsPacked<T>()`/`IsPacked(Type)` as the same `typeof(T) == typeof(...)` chains it already emits for `SizeOfWindows`/`WriteWindows` — JIT- and AOT-folded per instantiation — and route both classes through it; or minimally a `static class Packed<T> { public static readonly bool Value = …; }` cache. Collapse the duplicated predicate so a call costs one decision rather than two.
- **Breaks public API?** No
- **Raised by:** .NET Engineer B

### [BL-114] The multi-part unwind-cancel is applied inconsistently — `VerifySignature(Stream)` and `DigestKey` have none
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:3671-3713` (`VerifySignature` streaming) and `:2686-2721` (`DigestKey`); the pattern they omit is at `:1936-1940`, `:2200-2204`, `:2461-2465`, `:2855-2859`, `:3030-3039`
- **Problem:** `VerifySignature(Stream)` runs `C_VerifySignatureInit` and then loops `C_VerifySignatureUpdate` with no `try`/`finally`, so a mid-stream throw — from `inputStream.Read` or an `Update` error — leaves the verify-signature operation active, wedging the next unrelated operation on the session with `CKR_OPERATION_ACTIVE`. `DigestKey` has the same shape across `C_DigestInit` → `C_DigestKey` → `C_DigestFinal`. Every sibling multi-part method carries a `finalized` flag plus `TryCancelOperation`, so this is a gap in an otherwise uniform pattern, and one of the two is on the new v3.2 path.
- **Proposed action:** Wrap both bodies in the same `bool finalized` + `finally { if (!finalized) TryCancelOperation(...); }` shape, using `CKF_VERIFY` and `CKF_DIGEST` respectively.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** PKCS#11 v3.2 §5.6.11 (`C_SessionCancel`), §5.16.10–11. Extends BL-049, which names only streaming `DecryptVerify`

### [BL-115] `SetPin` leaks the old PIN unzeroized if the second `ToPinnedArray()` throws
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:341-355`
- **Problem:** `oldTmp = oldPin.ToPinnedArray()` runs, then `newTmp = newPin.ToPinnedArray()` runs — both *outside* the `try`. If the second call throws (for example `ObjectDisposedException` from `SecurePin.ToPinnedArray`), the `finally` never executes and `oldTmp` — a pinned-object-heap array holding the PIN in cleartext, which by construction never moves and is never overwritten — survives until GC with the PIN intact. `Login`, `LoginUser` and `InitPin` are unaffected because each allocates a single transient.
- **Proposed action:** Declare both arrays as null, then acquire and use them inside one `try`, zeroizing whichever are non-null in the `finally`.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** Extends BL-017, which made the copies pinned but did not cover this error-path escape

### [BL-116] `Destroy()` leaves the wrapper fully usable with stale handles
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs:191-196`; `Pkcs11Object.cs:83-87`
- **Problem:** After a successful `Destroy()`, `_disposed` stays false, so every subsequent member — `Sign`, `Encrypt`, `GetValue`, and `Destroy()` itself — still passes its guard and re-sends the now-stale handle. Because PKCS#11 permits handle reuse, a second `Destroy()` after another object has taken the recycled handle destroys an unrelated object: irreversible key loss with no error. The doc comment at `Pkcs11Key.cs:186-187` recognises the handles become stale but nothing enforces it. `Pkcs11Key.Destroy` additionally has no partial-failure story: if the private destroy succeeds and the public one throws, the caller cannot tell which half survived.
- **Proposed action:** Add a `_destroyed` flag set on success and have every member throw once it is set; clear each handle to `ObjectHandle.Invalid` as it is destroyed so a partial failure is self-describing.
- **Breaks public API?** Yes — behavioural: calls that silently succeed today would throw. Must land before 1.0
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** PKCS#11 v3.2 §4.4 — object handles are valid only until the object is destroyed, and may be reused

### [BL-117] `Pkcs11Key.Wrap` accepts a target key from a different workspace without checking provenance
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs:508-527` (handle chosen at `:519-521`, used at `:526`)
- **Problem:** `Wrap` null-checks `targetKey` and validates that its handle is non-invalid, but never verifies the target belongs to the same workspace — so a handle obtained from a *different* session is passed to this session's `C_WrapKey`. Session-object handles are session-scoped, so the best case is `CKR_OBJECT_HANDLE_INVALID`; the bad case is a numeric collision with a different object in the receiving session, wrapping the wrong key material with no error anywhere. Reachable today: two `OpenWorkspaceWithoutLogin` calls, or two slots, produce two independent sessions.
- **Proposed action:** Add a `ReferenceEquals(targetKey.Workspace, _workspace)` check at the top of `Wrap`, throwing `ArgumentException`, and audit any future cross-key method for the same check.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** PKCS#11 v3.2 §4.4 — object handles are valid only in the session (or, for token objects, the application's sessions with that token) that returned them

### [BL-118] No typed exception for operation-state or not-supported return codes
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/ExceptionMapper.cs:19-80` (default arm at `:79`); codes at `Common/CKR.cs:203`, `:208`, `:493`, `:133`, `:423`
- **Problem:** `CKR_OPERATION_ACTIVE`, `CKR_OPERATION_NOT_INITIALIZED`, `CKR_OPERATION_CANCEL_FAILED`, `CKR_FUNCTION_NOT_SUPPORTED`, `CKR_FUNCTION_CANCELED` and `CKR_CRYPTOKI_NOT_INITIALIZED` all fall through to `Pkcs11UnclassifiedException` — the same bucket as vendor-defined codes. A consumer who hits a wedged session (BL-114, BL-049) cannot distinguish it from an unknown vendor code without inspecting `ReturnValue`. This also weakens the "v3.2 methods fail cleanly on sub-v3.2 modules" contract: the XML docs repeatedly promise `CKR_FUNCTION_NOT_SUPPORTED` as the signal, but it arrives as an unclassified exception.
- **Proposed action:** Add `Pkcs11OperationStateException` (the three `CKR_OPERATION_*` plus `CKR_FUNCTION_CANCELED`) and `Pkcs11NotSupportedException` (`CKR_FUNCTION_NOT_SUPPORTED`), and route the two `CKR_CRYPTOKI_*_INITIALIZED` codes to a lifecycle category.
- **Breaks public API?** Yes — adding these narrows what `Pkcs11UnclassifiedException` catches, which is a behavioural break for anyone catching it. Must land before 1.0
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** PKCS#11 v3.2 §5.3 return-value groupings. BL-003 covered the unknown-value enum cast, not the categorization

### [BL-119] `Pkcs11Session.CloseSession()` leaves `_disposed == false`, and the whole test suite uses it instead of `Dispose`
- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:276-291`; the id shim at `:47-52`
- **Problem:** `CloseSession()` disposes the handle and nulls `_sessionHandle` but never sets `_disposed`. The object therefore stays "live": `_sessionId` degrades to `CK_INVALID_HANDLE` and every operation passes its `ObjectDisposedException` guard and issues native calls with session handle `0`, yielding `CKR_SESSION_HANDLE_INVALID` instead of the `ObjectDisposedException` the type's contract promises, while `SessionId` returns `0` rather than throwing. It has zero production callers and 62 test call sites, so the suite routinely tears sessions down through this half-closed path rather than through the production `Dispose` path that BL-015 hardened.
- **Proposed action:** Either set `_disposed = true` in `CloseSession` (making it a synonym for `Dispose`) or delete it and migrate the tests to `Dispose()`. The latter also raises test fidelity for the disposal-ordering work.
- **Breaks public API?** No — the type is internal
- **Raised by:** PKCS#11 Specialist B

### [BL-120] Digest and HMAC façades buffer the entire input while the multi-part digest path sits unused in the same assembly, and the class comment states the opposite
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/SHA256Pkcs11.cs:13-22` (the claim) and `:47-61` (the buffering); same shape in `SHA1Pkcs11.cs:39`, `SHA384Pkcs11.cs:15`, `SHA512Pkcs11.cs:15`, `SHA3_256/384/512Pkcs11.cs:27`, `MD5Pkcs11.cs:39`, `HMACPkcs11.cs:32`; the unused path is `Internal/Pkcs11Session.cs:2805-2860`
- **Problem:** The remark says "there is no portable streaming digest in the BCL-mappable surface here", but `Pkcs11Session.Digest(Mechanism, Stream, int)` drives `C_DigestInit`/`C_DigestUpdate`/`C_DigestFinal` correctly — including unwind-cancel — in the same assembly, and is exactly what `HashCore`/`HashFinal` map onto. So the stated justification for buffering is inaccurate, and `HashAlgorithm.ComputeHash(Stream)` over these types accumulates the whole payload in a `MemoryStream`. Secondary: `_buffer.SetLength(0)` and `_buffer.Dispose()` never overwrite the accumulated bytes, and `_buffer.ToArray()` makes a second copy that is also never zeroized, so message plaintext lingers on the managed heap.
- **Proposed action:** Refactor the digest core into an incremental helper (`DigestInit`/`DigestUpdate`/`DigestFinal` on the session) that `HashCore`/`HashFinal` drive directly, replacing the buffer. If buffering must stay for some mechanism, correct the comment and zeroize both the buffer and the `ToArray()` copy on reset and dispose.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** Supersedes the untracked design note previously recorded in Appendix B, which accepted the buffering without noting that the multi-part path already exists

### [BL-121] Multi-part and streaming paths have zero real-backend coverage, and the fake is an identity transform where output length always equals input length
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Unit/Internal/Pkcs11SessionStreamTests.cs:41-54` (the fake's `Update`); the code under test at `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:1898-1934`
- **Problem:** `C_EncryptUpdate`/`C_DecryptUpdate`/`C_DigestUpdate`/`C_VerifyUpdate` and the combined `DigestEncrypt`/`DecryptDigest`/`DecryptVerify` operations are exercised only against `StreamFake`, whose `Update` copies exactly `inLen` bytes out. A real CBC or block-mode token buffers partial blocks and returns *fewer* bytes than it was fed — often zero — flushing the remainder in `C_EncryptFinal`, which is precisely the case where the loop's length bookkeeping and the `CKR_BUFFER_TOO_SMALL` regrow at `:1910-1916` actually matter. There is no empty-input-stream case either.
- **Proposed action:** Add a SoftHSM/opencryptoki integration class driving the stream overloads with AES-CBC — a mechanism whose update output length differs from its input length — at buffer lengths 1, 15, 16, 17 and 4096±1, plus a zero-byte input, comparing against the one-shot result.
- **Breaks public API?** No
- **Raised by:** QA B

### [BL-122] Every real-backend crypto payload is ≤ 256 bytes; boundary and bulk sizes are untested, and the empty-input digest runs only against the in-process fake
- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Algorithms/SHA256Pkcs11TestCases.cs:31-65`, `Algorithms/SHA256Pkcs11Tests.Managed.cs:68`, `Algorithms/AesGcmPkcs11TestCases.cs:205-224`
- **Problem:** Across every `new byte[N]` literal in `Algorithms/` and `Integration/`, the largest buffer is 256 bytes and digest inputs are 3–54 bytes. Nothing crosses the 4096-byte internal stream buffer, and no digest exercises the SHA padding boundaries (55/56/64/119/120 bytes). `ComputeHash([])` — the case where a module receives `pData == NULL, ulDataLen == 0` and real tokens diverge — exists only in the eight `*Tests.Managed.cs` files, i.e. against `ManagedSoftToken`, which accepts it by construction.
- **Proposed action:** Add a shared size-matrix theory (0, 1, 15, 16, 17, 55, 56, 64, 4095, 4096, 4097, 1 MiB) to the digest and AES/GCM test-case classes, run on at least SoftHSM across all six legs and asserted against the BCL; promote the empty-input digest to the real backends.
- **Breaks public API?** No
- **Raised by:** QA B

### [BL-123] Wrap/unwrap has no asymmetric key transport, no RFC 5649 vector for the padded mechanism the round-trips actually use, and no tampered-blob negative
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/Adapters/KnownAnswerTests.SoftHsm2.cs:171-192`; `Integration/Keys/WrapUnwrapKeyTests.SoftHsm2.cs:45-46` and `:108-109`
- **Problem:** The only wrap KAT is RFC 3394 `CKM_AES_KEY_WRAP`. Every functional wrap/unwrap round-trip uses `CKM_AES_KEY_WRAP_PAD`, which has no published-vector check even though RFC 5649 §6 supplies two. `CKM_RSA_PKCS_OAEP` never appears as a wrap mechanism and `CKM_RSA_AES_KEY_WRAP` appears nowhere, so wrapping a symmetric key under an RSA public key — the most common HSM key-transport pattern — is untested on all four backends. There is also no negative asserting that flipping a byte in the wrapped blob makes `UnwrapKey` fail, even though RFC 3394's integrity check is the whole point of AES-KW.
- **Proposed action:** Add the RFC 5649 KWP vectors to the known-answer set; add an RSA-OAEP wrap/unwrap round-trip that proves the material survived by cross-decrypting; and add a tampered-blob negative asserting `CKR_WRAPPED_KEY_INVALID`/`CKR_ENCRYPTED_DATA_INVALID`.
- **Breaks public API?** No
- **Raised by:** QA B
- **Spec / References:** RFC 5649 §6; RFC 3394 §2.2.2

### [BL-124] ECDH derive is only ever run with `CKD_NULL` and no shared data, so the KDF and `pSharedData` fields never reach a real module
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/Keys/DeriveSharedSecretEcdhTests.SoftHsm2.cs:39-40` and its `.Nss.cs`/`.OpenCryptoki.cs` siblings; the only `CKD_SHA*_KDF` uses are `Unit/Native/MechanismParamsMarshalTests.cs:133-137`, `Unit/MechanismParams/BuildMarshalableTests.cs:298-303` and `Integration/MemoryLeaks/MechanismParamsLeakTests.cs:127,146`; the gate that would track it is `Support/Fixtures/SoftHsmBackendFixture.cs:94`
- **Problem:** All four backends' derive tests pass `kdf: CKD_NULL` with no shared data. `CKD_SHA*_KDF` and a non-empty `pSharedData`/`ulSharedDataLen` appear only in a leak test that asserts no cryptographic output and in unit-level struct-offset assertions. That leaves the two-pointer-plus-two-length tail of `CK_ECDH1_DERIVE_PARAMS` — where a swapped pointer/length pair is easy to get wrong and invisible on 64-bit Linux — without a single end-to-end execution. `SoftHsmSupportsEcdh1WithKdf => false` was written to gate exactly this case but has zero consumers repo-wide, so the gap is invisible rather than tracked.
- **Proposed action:** Add a `CKD_SHA256_KDF` derive with non-empty shared data against whichever backend advertises it, cross-checked against an SP 800-56A concatenation KDF computed in managed code, with a hard-fail guard rather than a silent skip if no backend supports it.
- **Breaks public API?** No
- **Raised by:** QA B, QA A
- **Spec / References:** Extends BL-028 with a mechanism its list omits

### [BL-125] No real-token negatives for the two states consumers hit most: not-logged-in, and session reuse after a failed operation
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:516-534` (`TryCancelOperation`); test-side `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Unit/Exceptions/ExceptionMapperTests.cs:17`, `Support/TestKeys.cs:158`
- **Problem:** `CKR_USER_NOT_LOGGED_IN` appears in the test tree only in the mapping table and in fakes — no real-backend test performs a private-key operation or a `FindObjects` for `CKA_PRIVATE=true` objects on an un-logged-in session, so the token's actual access-control behaviour (throw versus silently return nothing) is undocumented and unpinned. Separately, `TryCancelOperation` treats `CKR_FUNCTION_NOT_SUPPORTED` as success and logs nothing, so on a v2.40 module — SoftHSM 2.5 via the `softhsm-v240` job, NSS, opencryptoki — a failed operation stays *active*, and no test verifies the session is still usable afterwards; the next call would fail with `CKR_OPERATION_ACTIVE`.
- **Proposed action:** Add a real-backend test that a private-key sign on an un-logged-in session surfaces `Pkcs11AuthenticationException` and that private objects are invisible to `FindObjects`; add an "operation failure leaves the session usable" test (force a failure with a bad mechanism parameter, then run a successful operation on the same session) and run it on both a v3.x and the gated v2.40 module.
- **Breaks public API?** No
- **Raised by:** QA B
- **Spec / References:** BL-049 is the missing cancel call on one method and BL-052 is token removal; neither covers session recoverability on modules where `C_SessionCancel` does not exist

### [BL-126] 24 of 32 public mechanism-parameter types, and the public HashML-DSA / HashSLH-DSA / hedge surface, never reach a real module
- **Area:** QA
- **Severity:** Medium
- **Effort:** L
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/Pkcs11MechanismMap.cs:104-107`, `:133-136`, `:154-173`; `MechanismParams/CkmEddsaParams.cs`; tested only at `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Unit/Internal/Pkcs11MechanismMapTests.cs:120-150`
- **Problem:** Cross-referencing `MechanismParams/*.cs` against everything under `Integration/` and `Algorithms/`, only `CkmAesGcmParams`, `CkmAesCcmParams`, `CkmEcdh1DeriveParams`, `CkmRsaPkcsOaepParams`, `CkmRsaPkcsPssParams`, `CkmSalsa20ChaCha20Poly1305Params`, `CkmSp800108KdfParams` and the PQC sign params are ever used in a real call. `CkmEddsaParams` (Ed25519ph and context signing), `CkmHkdfParams`, `CkmChaCha20Params`, the IKE-derive family, X3DH/X2Ratchet and XEdDSA are unit-marshalling-only. Notably `Pkcs11MechanismMap.MlDsaHashSign` and `SlhDsaHashSign` — public v3.2 entry points that build `CK_HASH_SIGN_ADDITIONAL_CONTEXT` — and every non-default `CkhHedge` value are tested only by asserting the returned `Mechanism`'s fields, never by a token that would reject a malformed block. RSA-OAEP with a label (`CKZ_DATA_SPECIFIED` + `pSourceData`) is likewise verified only structurally.
- **Proposed action:** Rank the untouched param types by likelihood of consumer use and add one real-module acceptance test each, following the pattern already established by `Integration/Sign/SignIbmMlDsaContextTests.OpenCryptoki.cs` — a token that returns `CKR_MECHANISM_PARAM_INVALID` for a wrong-sized block is a genuine oracle. Prioritise `MlDsaHashSign`/`SlhDsaHashSign`, the deterministic hedge variant, OAEP-with-label and `CkmEddsaParams`. Record anything no available backend implements in a coverage matrix rather than leaving it silently untested.
- **Breaks public API?** No
- **Raised by:** QA B
- **Spec / References:** BL-028 names four specific mechanism families and BL-061 covers the vendor writer's capabilities; neither covers this surface or the inventory as a whole

### [BL-127] SP800-108 correctness verification is gated off on the one backend that implements it, and the workaround does not require extraction
- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/NssBackendFixture.cs:88-97`; `Algorithms/SP800108HmacCounterKdfPkcs11Tests.Nss.cs:13-14` and `:30+`
- **Problem:** NSS is the only backend with the SP800-108 KDF, and `SupportsExtractableDerive => false` disables exactly the cases that compare the derived bytes to the BCL, leaving only argument-validation tests running. The gate itself is justified — NSS refuses extractable derives — but the conclusion "therefore unverifiable" does not follow: the derived key can be *used* on-token and the result compared against the same operation keyed with managed `SP800108HmacCounterKdf.DeriveBytes` output.
- **Proposed action:** Add an extraction-free correctness case — derive a non-extractable generic-secret or AES key via the façade, compute `CKM_SHA256_HMAC` over a fixed message on-token, and assert equality against the BCL `SP800108HmacCounterKdf` + `HMACSHA256` result. The same technique applies to any future KDF on a no-extract token.
- **Breaks public API?** No
- **Raised by:** QA B
- **Spec / References:** Extends BL-028 — the new aspect is that the blocker is removable, not that coverage is missing

### [BL-128] The v3.0 message-based AEAD path reaches a real module on exactly one CI leg, and no test asserts which branch ran
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:1987-2016`; `Algorithms/AesGcmPkcs11.cs:90-111` and `:143-169`; `vendor/softhsmv2/src/lib/main.cpp:1440-1448`; `.github/workflows/ci.yml:301`
- **Problem:** The per-message parameter block is marshalled to the module only inside `C_EncryptMessage`, which is reached only after `C_MessageEncryptInit` succeeds. SoftHSMv2 exports non-NULL message entry points that unconditionally return `CKR_FUNCTION_NOT_SUPPORTED`, so `IsMessageApiSupported` is *true* on all six platform legs but the params block never reaches a module there — the façade always falls through to the v2.40 branch. NSS, the only backend that actually implements the message API, is built only on the ubuntu-latest leg. So `CK_GCM_MESSAGE_PARAMS_Windows`, `CK_CCM_MESSAGE_PARAMS_Windows` and `CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS_Windows` are covered on Windows and arm64 only by static layout pins, never by a real call, and no test asserts *which* branch executed — so a regression making `SupportsMessageApi` return false would silently erase the message-path coverage entirely (and would also mask BL-073).
- **Proposed action:** Assert the taken branch — expose an internal counter or test hook — so each backend's expected path is pinned, and extend `build/pkcs11-gate.c` with a mode that forces `SupportsMessageApi` on and off over real SoftHSM crypto so both branches are exercised on every platform leg.
- **Breaks public API?** No
- **Raised by:** QA B

### [BL-129] Eighteen permanently-dormant `[ConditionalFact]`s sit behind hard-coded `false` capability constants, and four gates have no consumer at all
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** Gates at `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/NssBackendFixture.cs:69,76,80,93,103,115` and `Support/Fixtures/SoftHsmBackendFixture.cs:77,81,85,90,94`; representative dormant tests at `Integration/Keys/Pkcs11WorkspaceGenerateKeyTests.Nss.cs:21,40`, `Integration/Keys/DeleteKeyTests.Nss.cs:17`, `Integration/Sign/SignEdDsaTests.Nss.cs:28`, `Integration/Verify/VerifyEdDsaTests.Nss.cs:21`, `Algorithms/RSAPkcs11Tests.Nss.cs:67` and eleven more
- **Problem:** Ten fixture capability gates are compile-time constants that can never become true (`SupportsClassicAesGcm`, `SupportsEdDsa`, `TokenObjectsAvailable`, `SupportsExtractableDerive`, `SupportsRc2Ecb`, `SupportsRsaPkcs1Encrypt`, `SoftHsmSupportsChaCha20Poly1305`/`ChaCha20KeyType`/`AesCcm`/`Ecdh1WithKdf`). Seventeen `[ConditionalFact]`s besides BL-053's ChaCha20 KAT are therefore unreachable on every CI leg — three whole test classes contain nothing but dormant tests, and `SignEdDsaTests.Nss.cs:11` documents itself as "Gated on the live mechanism list" while the actual gate is `=> false`. Separately, four SoftHSM gates have **zero** consumers anywhere in the repo, so the "when we move to a newer SoftHSM, flip the relevant flag" instruction is inert for four of five flags.
- **Proposed action:** Add one reflection meta-test — sibling to the exemplary `Unit/TestCollectionConventionTests.cs` — that enumerates every static `bool` gate referenced by a `[Conditional*]` attribute, fails when it is a constant `false` unless the member carries an explicit `[DormantGate("reason")]` marker, and separately fails on a gate with no `[Conditional*]` consumer. Then either delete the unreachable NSS test wrappers or convert the constants into runtime probes, as `SoftHsmSupportsMlDsa` already does via a marker file.
- **Breaks public API?** No
- **Raised by:** QA A
- **Spec / References:** Extends BL-053, which covers one instance; this is the census plus the systemic guard

### [BL-130] No v3.1 module is exercised anywhere in the suite, despite v3.1 being a declared compatibility target
- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Unit/Native/DelegatesLoaderTests.cs:198,213,237-238,267-268,288-289,309,327`; the branch under test at `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs:1704,1778`; `build/build-pkcs11-gate.sh:76,78`
- **Problem:** The hermetic loader tests build interface tables at exactly `(2,40)`, `(3,0)` and `(3,2)` — never `(3,1)`. The gate shims are `pkcs11-gate240.so` and `pkcs11-gate30.so` only, and no real backend reports 3.1. Since `Delegates.cs:1778` dispatches on `version.Minor >= 2`, a module reporting 3.1 is a distinct input class — it must take the v3.0 bindings and leave the twelve v3.2 slots unbound — with no coverage at all. A grep for `Minor = 1` / `(3, 1)` across the 386 test files returns only an unrelated `TokenInfo` hardware-version case.
- **Proposed action:** Add `V31Interface_BindsV30Additions_AndLeavesV32SlotsNull` to `DelegatesLoaderTests` using `BuildTable<CK_FUNCTION_LIST_3_0>(3, 1, …)` — a copy of the existing v3.0 case with the minor bumped, asserting the v3.2 sentinels stay unbound. That closes the declared v2.40/v3.0/v3.1/v3.2 matrix for the cost of one test.
- **Breaks public API?** No
- **Raised by:** QA A
- **Spec / References:** BL-006 covers the v2.40 fallback and BL-025 the v3.2-on-sub-v3.2 contract; neither touches 3.1

### [BL-131] The 100-cycle allocation stress test passes having executed zero cycles, and its second assertion is tautological
- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/MemoryLeaks/EncryptDecryptStressTests.Pkcs11Mock.cs:82-89,108-109,125-127`
- **Problem:** `TestKeys.CreateAes256Key` is wrapped in `catch (Pkcs11Exception) { continue; }`. pkcs11-mock's `C_CreateObject` (`vendor/pkcs11-mock/src/pkcs11-mock.c:776-782`) returns `CKR_ATTRIBUTE_VALUE_INVALID` for any attribute with a NULL `pValue` or `ulValueLen <= 0`, so a marshalling regression in `ObjectAttribute` makes all 100 iterations `continue`; `baseline == OutstandingAllocationCount` and `created == destroyed` both hold at zero and the test reports green having exercised nothing. `Assert.Equal(created, destroyed)` can never fail on its own terms either: `destroyed++` sits in the `finally` immediately after `session.DestroyObject(key)`, so a destroy failure already propagates and the counters can only diverge via an exception that fails the test anyway.
- **Proposed action:** Assert `Assert.Equal(100, created)` — the mock accepts this template today, so it is a true invariant — and drop or replace the `created == destroyed` assertion with something the `finally` does not already guarantee.
- **Breaks public API?** No
- **Raised by:** QA A

### [BL-132] Fourteen `AllowInsecure`-bypass tests pass on *any* exception, so a broken gate that throws the wrong type stays green
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/Sign/SignRsaPkcsTests.cs:64-68`, `Integration/Digest/DigestMd5Sha1Tests.cs:67-70`, `Integration/Encrypt/EncryptAesTests.cs:137-143`, `Integration/Decrypt/DecryptAesTests.cs:79`, `Integration/Security/InsecureOperationGateTests.cs:64,118,203,226`, `Integration/Keys/UnwrapSecureDefaultsTests.Pkcs11Mock.cs:45,77`, `Integration/Keys/KeyCreationSecureDefaultsTests.Pkcs11Mock.cs:124,154`, `Integration/Security/AllowInsecureScopeTests.Pkcs11Mock.cs:102`, `Algorithms/AesPkcs11TestCases.cs:131`
- **Problem:** The negative half of the secure-defaults suite is strongly asserted (`Assert.Throws<InsecureOperationException>` plus an assertion on `ex.Mechanism`). The positive half only asserts `!(ex is InsecureOperationException)` or swallows everything via a bare `catch`. Every one of these sites would pass if the operation threw `ArgumentException` from a broken parameter builder, `NotSupportedException`, or `ObjectDisposedException` — that is, if the call never reached the token at all. Mutating the gate to throw `InvalidOperationException` leaves all fourteen green.
- **Proposed action:** Narrow the acceptance set: assert the recorded exception is `null` or a `Pkcs11Exception`, which proves the call reached `C_*`; and where the fixture advertises the mechanism (SoftHSM supports `CKM_MD5`, `CKM_SHA_1`, `CKM_AES_ECB`, `CKM_AES_CFB128`) assert the operation actually succeeds rather than merely "did not throw the gate".
- **Breaks public API?** No
- **Raised by:** QA A

### [BL-133] Pull requests get no coverage signal at all — the Codecov upload is push-only and there is no threshold or quality gate
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `.github/workflows/code-quality.yml:139-147` (`if: github.event_name == 'push'`), `:109-118` (no `sonar.qualitygate.wait`); no `codecov.yml` at the repository root
- **Problem:** Coverage *is* collected (`--collect:"XPlat Code Coverage;Format=opencover,cobertura"` at `:132`) and imported into Sonar, but the Codecov upload is gated to `push`, so a pull request never receives a coverage delta or a Codecov status check. With no `codecov.yml` there are no `project`/`patch` targets either, and the Sonar scan does not wait on its quality gate — so a PR that adds an untested public method, or deletes a test file, is blocked by nothing. For a library whose safety case rests on test rigour, that removes the enforcement half of the coverage strategy.
- **Proposed action:** Change the condition to `github.event_name == 'push' || github.event.pull_request.head.repo.full_name == github.repository`, which keeps fork PRs excluded (the stated reason for the current gate); add a `codecov.yml` with a `patch` target so new code carries tests; and pass `/d:sonar.qualitygate.wait=true` so the Sonar verdict is a blocking check.
- **Breaks public API?** No
- **Raised by:** QA A

### [BL-134] No compile gate on the README and docs code snippets
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** M
- **Location:** `README.md:50-73,85-88,111-124`, `docs/diagnostics.md:11`; no samples project in `src/KerckhoffsLabs.sln:6-11` and none under `tests/`
- **Problem:** The quickstart snippet is the flagship API demonstration (`Pkcs11Library` → `OpenWorkspace(slotLabel:, CKU, SecurePin)` → `GenerateRsaKeyPair(modulusBits:, label:)` → `RSAPkcs11.SignData`) and the wrap-hardening snippet chains eight template-builder methods. The reviewer verified all of them resolve against the current surface today, but nothing compiles them — so the first pre-1.0 rename silently ships a broken quickstart, and the API is explicitly still moving (BL-008, BL-038, BL-039 were all signature changes; BL-063 through BL-071 add more).
- **Proposed action:** Add a small `tests/Samples` project (or a `Samples` folder in the test project) holding each snippet as a real compiled method, and reference them from the docs via docfx `[!code-csharp[](…#region)]` so the markdown and the compiled source cannot diverge. The `AllowInsecureScope` snippet uses `…` as a body placeholder, so extract it as a region rather than fencing raw markdown.
- **Breaks public API?** No
- **Raised by:** QA A
- **Spec / References:** BL-030 covers README *content*; this is snippet verification

### [BL-135] The release build depends on an ephemeral prerelease dev-build from a secondary feed
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj:37` (`Microsoft.DotNet.XUnitExtensions 11.0.0-beta.26357.109`), `NuGet.config:7-8,17-20`, `.github/workflows/publish.yml:32-36`
- **Problem:** The test project's `[ConditionalFact]` support comes from an unstable Microsoft dev-build hosted on the `dnceng/public/dotnet-eng` Azure DevOps feed, not nuget.org. `publish.yml` restores, builds and tests the whole solution before packing, so the release path hard-depends on that feed serving that exact dev build; `dotnet-eng` prunes old dev builds, and there is no fallback or vendored copy. A pruned package or a feed outage makes it impossible to cut a release from an existing tag.
- **Proposed action:** Either restrict the publish job to the library project — keeping the full-suite gate in `ci.yml` as the release precondition, which is also the cleaner fix for BL-001 — or drop the dependency, since `ConditionalFact`/`ConditionalTheory` is roughly 50 lines of xUnit trait code that can live in `Support/`. The latter also removes the only reason the `dotnet-eng` source exists.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-136] No NuGet lockfile and no locked-mode restore, so the shipped package's dependency graph is not pinned
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `Directory.Build.props:3-28` (no `RestorePackagesWithLockFile`); no `packages.lock.json` anywhere in the repository; `.github/workflows/publish.yml:32`
- **Problem:** Every `PackageReference` carries an exact-looking version, but NuGet resolves those as *minimum* versions: if a direct or transitive package is unlisted, or a transitive edge's floor moves, the restore that produces the released `.nupkg` silently resolves a different graph than the one CI validated. Nothing in any workflow uses `--locked-mode`, so an unexpected graph change is undetectable, and there is no committed record of what the shipped build actually consumed.
- **Proposed action:** Set `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` in `Directory.Build.props`, commit the resulting `packages.lock.json` files, and add `--locked-mode` to the `dotnet restore` in `ci.yml`, `code-quality.yml` and `publish.yml` so a graph change becomes a reviewable diff rather than a silent substitution.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-137] The SDK and compiler version used to produce the released package is not pinned
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `global.json:2-5` (`"version": "10.0.100"`, `"rollForward": "latestFeature"`); `.github/workflows/publish.yml:22-24` (`dotnet-version: '10.0.x'`)
- **Problem:** `setup-dotnet` installs whatever the newest `10.0.x` is at run time, and `rollForward: latestFeature` accepts any feature band at or above 10.0.100, so the Roslyn version, the analyzer set and the emitted IL for a release build all depend on the day the tag is pushed. Re-running the publish workflow for the same tag can therefore produce a different binary — which defeats the `Deterministic` + `ContinuousIntegrationBuild` + SourceLink investment already made in the csproj, since determinism only guarantees byte-identical output *for the same toolchain*.
- **Proposed action:** Pin an exact SDK patch in `global.json` with `"rollForward": "disable"` (or `latestPatch` at most), have every workflow use `setup-dotnet` with `global-json-file: global.json` instead of `dotnet-version: '10.0.x'`, and let dependency automation bump the pin as a reviewable PR.
- **Breaks public API?** No
- **Raised by:** QA C
- **Spec / References:** The upstream cause of BL-054's observation that determinism is never *verified*

### [BL-138] Only the default CA rule subset is active, so API-design and correctness rules are invisible despite the warnings-as-errors posture
- **Area:** Cross-cutting
- **Severity:** Medium
- **Effort:** M
- **Location:** `Directory.Build.props:18-19` (`EnableNETAnalyzers`/`EnforceCodeStyleInBuild` with no `AnalysisMode`/`AnalysisLevel`, verified absent from every `.props` and `.csproj`); `.editorconfig:37-129` (no `dotnet_diagnostic.CAxxxx` entries; all naming rules are `suggestion`)
- **Problem:** With `AnalysisMode` unset the SDK uses `Default`, which leaves roughly half the CA catalogue disabled — including rules that map directly onto findings this review process discovered by hand. CA1045 (avoid `out` parameters) is exactly BL-038; CA1707 (identifiers should not contain underscores) is exactly BL-009; CA1002 (`List<T>` in public signatures) is BL-142; and CA1062, CA2000, CA1014 (`[CLSCompliant]`, never declared although `uint`-backed enums and `ulong` parameters make the surface non-CLS-compliant), CA1815, CA1032, CA1064 and CA2225 all bear on the public surface this project calls its #1 risk. The naming section of `.editorconfig` is documentation only, so nothing in it fails a build. `TreatWarningsAsErrors` gives the repo the machinery to enforce all of this; it simply is not pointed at it.
- **Proposed action:** Set `<AnalysisMode>All</AnalysisMode>` (or at minimum `Recommended`, or `AnalysisModeApiDesign=All`) on the library project, then triage the resulting diagnostics into either fixes or explicit `.editorconfig` `dotnet_diagnostic.CAxxxx.severity = none` entries with a stated reason — a documented opt-out per rule is auditable, whereas today's silence is not. This also converts BL-009's naming decision from tribal knowledge into a checked-in, reviewable statement.
- **Breaks public API?** No
- **Raised by:** QA C, .NET Engineer A

### [BL-139] `code-quality.yml` cannot succeed on a fork pull request, so every external contribution shows a red check after roughly an hour of runner time
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `.github/workflows/code-quality.yml:14-19` (`pull_request` trigger), `:37-38` (`SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}`), `:109-119` (`sonarscanner begin`), `:144` (`fail_ci_if_error: true`)
- **Problem:** GitHub does not inject secrets into `pull_request` runs from forks, so `SONAR_TOKEN` is empty and `dotnet sonarscanner begin` cannot authenticate — but only *after* the job has installed Java, built OpenSSL 3.5.7 from source and compiled SoftHSM. Every first-time outside contributor therefore sees a failing check they cannot fix, and the project burns most of an hour of runner time per fork push. Separately, `fail_ci_if_error: true` on the Codecov upload means a Codecov outage fails the quality gate for reasons unrelated to the code. (The `pull_request` versus `pull_request_target` choice is correct everywhere — no workflow uses `pull_request_target`, which is the right call.)
- **Proposed action:** Guard the Sonar steps with `if: github.event.pull_request.head.repo.full_name == github.repository || github.event_name != 'pull_request'`, or move the scan to `push` plus a `workflow_run`-triggered companion. Drop `fail_ci_if_error: true` or scope it to `push`. While there, pin `dotnet tool install --global dotnet-sonarscanner` (`:93`) with `--version` for consistency with the docfx pin, since it runs unpinned in a job holding `SONAR_TOKEN`.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-140] `CONTRIBUTING.md` documents none of the build, and the build is unusually demanding
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `CONTRIBUTING.md:33-35` (the entire "Contributing code and content" section), versus `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj:48-83` (three `BeforeTargets="PrepareForBuild"` native build targets) and `.github/workflows/ci.yml:26-28,95-97`
- **Problem:** A plain `dotnet build` of this solution compiles pkcs11-mock, SoftHSMv2 and a C gate shim from four git submodules and needs `build-essential`/`cmake`/autotools present, or MSVC plus vcpkg on Windows. `CONTRIBUTING.md` says nothing about `git clone --recursive`, the required native toolchain, the `SkipPkcs11MockBuild`/`SkipSoftHsmV2Build`/`SkipPkcs11GateBuild` escape hatches, `dotnet format` being a CI gate, or how to run the suite against a specific backend — so the first thing a new contributor sees is an opaque `Exec` failure inside an MSBuild target.
- **Proposed action:** Add a "Building and testing" section covering the recursive clone (and `git submodule update --init`), per-OS prerequisites, the three `Skip*` properties for a managed-only build, `dotnet format src/KerckhoffsLabs.sln` before pushing, and the `PKCS11_TEST_*` environment variables that select or require a backend.
- **Breaks public API?** No
- **Raised by:** QA C
- **Spec / References:** Extends BL-034 — the file now exists but omits everything a contributor needs in order to build

### [BL-141] The shipped analyzer is packed through a private NuGet target and its packaged form is never verified
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj:74-83` (`<Target Name="PackAnalyzer" BeforeTargets="_GetPackageFiles">`)
- **Problem:** Three analyzers plus the `PackedStructsGenerator` reach consumers only because this target hooks `_GetPackageFiles`, an undocumented NuGet-internal target; if it is renamed or reordered in a future SDK the analyzer silently vanishes from the package and the build still succeeds. Nothing asserts that the produced `.nupkg` contains `analyzers/dotnet/cs/…Generators.dll` (nor `README.md`/`icon.png`). The analyzers *are* dogfooded via `ProjectReference` in the test project, which is genuinely good, but that path exercises them as a project reference rather than as a package-delivered analyzer, so a wrong pack path or a Roslyn-version mismatch is invisible.
- **Proposed action:** Switch to a supported hook (`TargetsForTfmSpecificContentInPackage` or `TargetsForTfmSpecificBuildOutput`) and add a CI step that runs `dotnet pack` and asserts the expected entries exist in the archive. A small consumer smoke project referencing the packed `.nupkg` from a local feed would also prove `KLPKCS11008` fires as delivered.
- **Breaks public API?** No
- **Raised by:** QA C
- **Spec / References:** Extends BL-002. `Generators/PackedStructsGenerator.cs:36-42` correctly no-ops when a compilation declares no `[PackedForPkcs11]` structs, so shipping the generator to consumers is itself safe

## Low

### [BL-058] ✅ RESOLVED — `MechanismParameters` and `Mechanism` still advertise `IDisposable` with nothing left to release
- **Status:** Resolved 2026-07-30. `IDisposable` removed from both types, along with `Dispose()`, the `protected abstract Dispose(bool)` contract, all 27 `Dispose(bool)` overrides, the 28 `_disposed` fields, and the 38 now-unreachable `ObjectDisposedException.ThrowIf` guards. Neither type has any lifecycle left: they are values.
  - **Actual scope was larger than the estimate.** 339 `using var` conversions plus 6 block-form `using` statements plus 12 explicit `.Dispose()` calls, across 95 files — not the 265 sites this entry predicted. The compiler enumerated every one (CS1674 / CS1061), so none could be missed silently; three passes were needed because the test project only compiles once the library does.
  - **Consequence the entry did not state:** with nothing able to set `_disposed`, every disposal guard became dead code and the 10 tests asserting `ObjectDisposedException` after disposal were asserting a contract that no longer exists. They were deleted, not weakened. The properties worth keeping survive elsewhere — sharing one descriptor across two mechanisms is still pinned by `BuildMarshalableTests.OneDescriptor_CanBackTwoMechanisms`.
  - **Verified no leak was introduced.** `CkmSp800108KdfParams` retains `IReadOnlyList<ObjectAttribute>` templates, and `ObjectAttribute` does own unmanaged memory — but the params object never disposed them: `Sp800108KdfBuilder.AddDerivedKey` documents that the caller retains ownership and must keep them undisposed until after the derive. All 27 `Dispose(bool)` bodies were confirmed to flip a flag and nothing more before removal.
  - Four `RunBlock` methods in the AES/DES/3DES/RC2 façades wrapped their whole body in `using (mechanism)`; those are unwrapped and dedented rather than left as bare block scopes.
  - Full suite: 0 failed, 1860 passed, 630 skipped (1870 minus the 10 deleted disposal tests).
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** M (mechanical, but wide)
- **Location:** `MechanismParams/MechanismParameters.cs`; `Mechanism.cs`; 265 `using` call sites across production and tests
- **Problem:** BL-057 moved every unmanaged byte into the per-call scope, so `Dispose` on both types is now a no-op. A type that implements `IDisposable` without owning a resource is misleading in the direction that matters: it teaches callers that the object holds something, which is precisely the mental model BL-057 removed. `MechanismParamsFinalizerTests` already asserts no parameter type declares a finalizer, so nothing depends on the disposal machinery.
- **Proposed action:** Remove `IDisposable` from both types and rewrite the call sites. Measured cost: **265** — 178 `using var … = new Mechanism(…)`, 82 `using var … = new Ckm*Params(…)`, 5 block-form `using (…)`. The compiler flags every one (CS1674), so none can be missed silently.
- **Why it was split out:** bundling 265 uniform edits with the marshalling rewrite would have buried the risky change in churn and made the diff effectively unreviewable. On its own the diff is mechanical and a reviewer can confirm it by inspection.
- **Also in scope:** the `GC.SuppressFinalize` calls at `Mechanism.cs:219` and `MechanismParams/MechanismParameters.cs:52` are dead — neither type has a finalizer any more.
- **Related:** completes BL-057.
- **Breaks public API?** Yes (`using` on either type stops compiling) — land before 1.0
- **Raised by:** BL-057 implementation, deliberately deferred

### [BL-061] Vendor parameter writer covers input-only, flat structs — not read-back or nested layouts
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** M
- **Location:** `MechanismParams/Pkcs11ParameterWriter.cs`; `MechanismParams/VendorMechanismParameters.cs`
- **Problem:** `VendorMechanismParameters` lets a caller use a `CKM_VENDOR_DEFINED` mechanism without hand-serializing a struct, but it models only the field kinds the built-in types needed: `CK_ULONG`, pointer, `CK_BBOOL`, raw byte, and inline fixed arrays. Two shapes are unsupported. (a) **Read-back**: a vendor parameter the token writes into — the equivalent of `CopyTagTo` — has no route home, because `AbsorbOutput` is `internal` and the writer hands back no field handles. A caller needing an output field must fall back to the raw `byte[]` constructor and lose the layout help exactly where it is hardest to get right. (b) **Nested structs and arrays of structs**, as in `CK_SSL3_KEY_MAT_PARAMS` (`CK_SSL3_RANDOM_DATA`) or the `CK_DERIVED_KEY[]` of SP800-108: the writer can only append scalars, so a nested layout has to be flattened by hand, reintroducing the alignment reasoning the type exists to remove.
- **Proposed action:** For (a), return a field handle from the writer that the caller can read after the call while the scope is alive — `var tag = writer.OutBuffer(16);` plus a protected `Absorb(handle, span)` hook. For (b), a nested scope: `writer.Struct(inner => inner.CkULong(...)...)` applying the same alignment rules recursively, with the struct's own alignment being that of its widest member.
- **Verification:** the existing oracle extends directly — assert the writer reproduces `CK_SSL3_KEY_MAT_PARAMS` and `CK_DERIVED_KEY` byte for byte, as `VendorParameterWriterTests` already does for the flat cases.
- **Related:** completes the extension point opened for BL-057's successor work; the raw `Mechanism(type, byte[])` constructor remains the escape hatch meanwhile.
- **Breaks public API?** No (additive)
- **Raised by:** vendor-parameter-writer implementation

### [BL-059] ✅ RESOLVED — `CK_MECHANISM.CreateMechanism` is dead production code kept alive only by its own tests
- **Status:** Resolved 2026-07-30. All 8 overloads deleted (the count was 8, not 6 — each of the four parameter shapes had a `CKM` and a `NativeCULong` form), together with `Unit/Native/CkMechanismTests.cs`, whose single test existed only to compare two of them. `CK_MECHANISM` is now a plain three-field interop struct with no behaviour. The build is the proof of completeness: 0 warnings with `TreatWarningsAsErrors` and `EnforceCodeStyleInBuild`, so no caller and no stranded `using` remained.
  - **The invariant this unblocks is now checkable by grep.** Every `UnmanagedMemory.Allocate` / `AllocHGlobal` in the library is one of: `Native/MechanismParameterScope.cs:25` (the scope itself), `Native/UnmanagedMemory.cs:89` (the allocator), `Native/LowLevelPkcs11Library.cs:219` (`C_Initialize` args), `Objects/ObjectAttribute.cs:160,405` and `Internal/Pkcs11Session.cs:989,1033` (CKA attribute values, explicitly outside BL-057's scope). Zero in `MechanismParams/`, zero in `Mechanism.cs` — no unmanaged parameter memory is owned by anything but the per-call scope.
  - **Coverage:** the deleted test asserted that the span and `byte[]` overloads produce identical buffers. The surviving equivalent of that property is `Mechanism.Marshal` writing a raw parameter into the scope, covered by `MechanismTests.Marshal_ByteArrayParameter_CopiesTheBytesIntoTheScope` and `…_IgnoresLaterChangesToTheCallersArray`.
- **Area:** P/Invoke
- **Severity:** Low
- **Effort:** S
- **Location:** `Native/CK_MECHANISM.cs` (6 overloads); sole caller `Unit/Native/CkMechanismTests.cs`
- **Problem:** These overloads were the legacy path's allocation primitive — they allocated the parameter block inside the `Mechanism` constructor. BL-057 replaced that with `Mechanism.Marshal(scope, …)`, leaving them unreferenced by any production code path. Their tests still pass, which is what keeps them from showing up as unused. Dead allocation helpers on an interop struct are a trap: the next person needing a `CK_MECHANISM` may reach for one and reintroduce an allocation with no scope to own it.
- **Proposed action:** Delete the 6 overloads and their tests, or keep one and document it as test-only. Verify nothing outside `Native/` references them first.
- **Why it is worth more than its size:** these two `UnmanagedMemory.Allocate` calls (`Native/CK_MECHANISM.cs:80,119`) are the only place in the parameter or mechanism layer where unmanaged memory is owned by nothing at all, so they are the sole reason BL-057's central claim — that only the per-call scope owns parameter memory — is not literally true. Deleting them makes the invariant checkable by grep.
- **Breaks public API?** No (`internal`)
- **Raised by:** BL-057 implementation (Task 8)

### [BL-060] ✅ RESOLVED — One parameter descriptor with output fields, used for both halves of a dual-mechanism operation, silently keeps only the last result
- **Status:** Resolved 2026-07-31 by rejecting the pairing rather than documenting it. `MechanismParameters.AbsorbsTokenOutput` (false by default, overridden by the four types the token writes into) lets the session recognise the case; `Pkcs11Session.ThrowIfOneDescriptorDrivesBothHalves` throws `ArgumentException` naming the second mechanism's parameter. Wired into the three inner methods that own the call scope — `DecryptVerify`, `DigestEncrypt`, `DecryptDigest` — which every one of the eight public overloads funnels through, so the byte[] forms are covered by the same check.
  - **The guard is deliberately narrow.** Sharing a descriptor stays legal, because each mechanism marshals into its own block; only an output-bearing descriptor driving *both halves of one call* is refused. Tests pin both directions — the rejection, and that an input-only descriptor shared across both halves still runs.
  - Mutation-verified: commenting out the three guard calls (against a clean build) reddens the four rejection tests and leaves the three permissive ones green.
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** S
- **Location:** `Internal/Pkcs11Session.cs` `DecryptVerify` / `DigestEncrypt` / `DecryptDigest`; `MechanismParams/MechanismParameters.cs`
- **Problem:** Those three operations run two mechanisms in one scope. Each now marshals into its own block, so the blocks no longer collide — but if the *same descriptor instance* is passed for both halves and it has output fields (a tag, a MAC, derived handles), both `AbsorbOutput` calls write the same managed buffer and the first result is lost with no error. BL-057 made sharing a descriptor across mechanisms legal, which is correct for the common input-only case and makes this narrow case reachable. The old `TryClaimOwnership` guard never covered it either: it rejected two *mechanisms* sharing one descriptor, not one descriptor used for two operations.
- **Proposed action:** Cheapest honest option is to document it on the three methods. A stronger option is to reject it — for the four descriptor types that have output fields, throw if the same instance is supplied for both halves of one call. Decide with BL-056, which is settling ownership conventions across mechanisms, parameters and keys.
- **Related:** the residual of BL-057's sharing relaxation; same theme as BL-056.
- **Breaks public API?** No (documentation), or yes if the guard is added — settle before 1.0
- **Raised by:** BL-057 implementation (Task 7), found while verifying the `_lastMarshalled` finding

### [BL-056] ✅ RESOLVED — Ephemeral vs. persistent keys are indistinguishable: destroying a token object is a separate call callers must remember, in the right order
- **Status:** Resolved 2026-07-31, after the original framing was found to be wrong. See "Correction" below — the entry claimed a risk the code does not have, and missed two real defects that were sitting in the same methods.
- **Correction to the original problem statement:** it asserted that forgetting `Delete()` leaves "an extractable copy of a shared secret on the token". All three ephemeral paths create **session objects**, not token objects: `MLKemPkcs11` sets `.OnToken(false)` explicitly, and `ECDiffieHellmanPkcs11`/`SP800108HmacCounterKdfPkcs11` omit `CKA_TOKEN` entirely, whose PKCS#11 default is `CK_FALSE`. PKCS#11 destroys session objects at `C_CloseSession`, which this library wires to `SafeHandle.ReleaseHandle`. So the exposure is bounded by the session's lifetime, not permanent — real, but a different and smaller risk than stated.
- **Why the proposed fix was rejected:** the entry proposed an `ownsTokenObject` flag (or a distinct type) so `Dispose` could destroy. Both are unworkable, because ownership here is **runtime data, not static structure**: `CKA_TOKEN` is set from a caller-supplied template, or from the `persistOnToken` argument of `Pkcs11Workspace.GenerateAesKey`/`GenerateRsaKeyPair`. A flag would make `Dispose` destroy or not according to an argument invisible at the call site — the very "ownership by convention" complaint this entry opens with, moved one layer down. A distinct return type cannot be chosen at all when the deciding attribute is inside a runtime template.
- **The decision, and the asymmetry behind it:** destroying wrongly is irreversible loss of key material; failing to destroy a session object costs nothing, because the token collects it at session close. Given that, **disposal is inert and destruction is explicit**, permanently and on every wrapper type:
  - `Dispose()` releases the managed wrapper (and, on `Pkcs11Key`, any workspace/library it owns). It never calls `C_DestroyObject`.
  - `Destroy()` is the only member that destroys. Renamed from `Delete()` on `Pkcs11Key`, `Pkcs11Object` and `Pkcs11Certificate` — `Delete` read as "release the wrapper" and invited exactly this confusion. No forwarder: pre-1.0, no released consumers.
  - The invariant is stated in the class remarks of all three types, with the reasoning, so the next contributor does not re-litigate it.
- **Two real defects found in the same methods, both fixed:**
  1. **Cleanup masked real failures.** `ECDiffieHellmanPkcs11` and `SP800108HmacCounterKdfPkcs11` destroyed the derived key inside `finally`. A throw from `finally` *replaces* an exception already in flight, so a failed `C_DestroyObject` reached the caller instead of the actual error — and both methods have a throw right above it. Now routed through `DestroyEphemeral(derived, operationFailed)`, which suppresses the destroy failure only when something else already went wrong, and lets it surface when it is the only news. `MLKemPkcs11` already had this shape; the other two had diverged from it.
  2. **Derived key material leaked in cleartext.** `SP800108HmacCounterKdfPkcs11` never disposed the `ObjectAttribute` list returned by `GetAttributeValue`. Those own unmanaged buffers holding the derived secret, and disposing them is what zeroizes them (`UnmanagedMemory.Free` wipes before releasing), so every `DeriveKey` call left the secret in unmanaged memory for the life of the process. Its `ECDiffieHellmanPkcs11` sibling disposed them correctly, which is how the divergence was spotted.
- **Verification:** `DisposeDoesNotDestroyTests` asserts the observable outcome — the object is still on the token after `Dispose`, gone after `Destroy` — including the persistent-key case an auto-destroying `Dispose` would ruin. Mutation-verified: making `Dispose` destroy reddens both inertness tests and leaves the `Destroy` tests green. `DerivedKeyMaterialLeakTests` pins both derive paths against the allocation counter; restoring the missing `attrs` disposal reddens the SP800-108 case and leaves ECDH green.
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** M
- **Location:** `Pkcs11Object.cs`; `Pkcs11Key.cs`; `Pkcs11Certificate.cs`; `Algorithms/ECDiffieHellmanPkcs11.cs`; `Algorithms/SP800108HmacCounterKdfPkcs11.cs`; `Algorithms/MLKemPkcs11.cs`
- **Related:** completes the ownership family with BL-012/BL-057/BL-060. The pattern is the same one those settled: remove the ambiguity rather than document it — here by making disposal mean one thing everywhere, instead of adding a mode that decides what it means.
- **Breaks public API?** Yes (`Delete()` renamed to `Destroy()` on three types) — pre-1.0, no released consumers
- **Raised by:** CodeQL `cs/missed-using-statement` triage; rewritten 2026-07-31 after analysis showed the original premise was incorrect
### [BL-038] `WaitForSlotEvent` uses `void` + two `out` params instead of a Try/result shape, with a raw `ulong` slot id
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Library.cs:324`
- **Problem:** Classic Try-pattern case shipped as `void WaitForSlotEvent(bool, out bool, out ulong)`; the returned slot id has no path back to a `Pkcs11Slot`.
- **Proposed action:** Reshape as `bool TryWaitForSlotEvent(bool nonBlocking, out Pkcs11Slot? slot)` (or a result struct) before the signature is permanent.
- **Breaks public API?** Yes — land before 1.0
- **Raised by:** .NET Engineer A

### [BL-039] ✅ RESOLVED — Slot/session identifiers surface as raw `ulong`, contrary to the project's own handle-wrapping rule
- **Status:** Resolved 2026-07-10 by introducing the dedicated types (the pre-1.0 window made the breaking change free). New public `readonly record struct SlotId` (public ctor — slot numbers are config-driven, externally meaningful values) and `SessionId` (internal ctor — session handles are library-produced, surfaced for diagnostics only), both following the `ObjectHandle` idiom with a `Value` accessor and purposeful `ToString` (decimal for slots matching vendor tooling, hex for opaque session handles). Adopted on `Pkcs11Slot.SlotId`, `SlotInfo.SlotId`, `TokenInfo.SlotId`, `SessionInfo.SessionId`/`SlotId`. `WaitForSlotEvent`'s `out ulong` was deliberately left for BL-038, which replaces that signature wholesale. Full suite green (1679 passed).
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Slot.cs:35`, `SessionInfo.cs:14`, `SlotInfo.cs:12`, `TokenInfo.cs:12`
- **Problem:** `ObjectHandle` is wrapped internally, but slot/session ids leak as bare `ulong` — defensible, yet inconsistent with CLAUDE.md's dedicated-handle-type rule, and changing the type later is breaking.
- **Proposed action:** Introduce `readonly struct SlotId` (and optionally `SessionId`) or consciously accept and document the raw `ulong` — decide before 1.0.
- **Breaks public API?** Yes if changed — decide before 1.0
- **Raised by:** .NET Engineer A

### [BL-040] ✅ RESOLVED — The `CKM`/`ulong` boundary is unsettled: no typed accessor on `Mechanism`, and `GetMechanismList` silently drops vendor mechanisms
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** S
- **Location:** `Mechanism.cs` (`Type`); `Pkcs11Slot.cs:97` (`GetMechanismList`); remaining cast sites `Pkcs11Key.cs:671,679,699`, `Algorithms/ECDsaPkcs11.cs:93,136`, `Algorithms/DSAPkcs11.cs:108,119`, `Internal/Pkcs11Session.cs:1319`
- **Problem:** `Mechanism.Type` is a raw `ulong`, so callers write `(CKM)mechanism.Type`. The original entry counted three cast sites; the real count was 57, of which 49 were `GuardMechanism((CKM)mechanism.Type)` inside `Pkcs11Session`.
  - **The internal half is resolved (2026-07-31).** `GuardMechanism` now takes the `Mechanism` and converts once, so those 49 casts became one. That was never an argument for a public accessor: a guard should take the object, not a projection of it, and `GuardMechanism(mechanism.MechanismType)` would still have been 49 call sites performing a conversion the callee should own. Eight casts remain, spread over four files, which is ordinary.
  - **What is left is a design decision, not a missing convenience.** A bare `public CKM MechanismType` would be lossy in the direction the library has been widening: there are now four `ulong` constructors for vendor mechanisms, and a value such as `0x80070002` has no `CKM` member, so the property would hand back an enum value that names nothing while looking authoritative. `NativeCULongExtensions.ToCKM` already documents this as a deliberate choice — it is non-validating "unlike most `ToCK*` converters" precisely because mechanism values may be vendor-defined or newer than the enum. A typed property is that same unchecked cast with the warning label removed.
  - **~~The same boundary is broken in the other direction, and worse.~~ Wrong — corrected 2026-07-31.** This entry previously claimed `Pkcs11Slot.GetMechanismList()` drops vendor-defined mechanisms. It does not, and never did. The claim was taken from the method's own XML remarks without reading the implementation: `LowLevelPkcs11Library.C_GetMechanismList` marshals through `NativeCULong[]` and then casts each value to `CKM` **without validating it**, with a comment stating that this is deliberate so vendor mechanisms are not lost. Nothing filters. The defect was the documentation, which told callers a mechanism was unreachable while it sat in the list they had just been handed.
- **Resolution (2026-07-31):**
  - `Mechanism.IsVendorDefined` — `Type >= (ulong)CKM.CKM_VENDOR_DEFINED`. The question that decides whether a `CKM` view means anything.
  - `Mechanism.TryGetMechanism(out CKM)` — reports whether the enum names the value. **Not** a bare `CKM` property, for the lossiness reason above. It departs from the `Try` convention by assigning the out parameter even on failure: `default(CKM)` is `CKM_RSA_PKCS_KEY_PAIR_GEN`, a real and entirely different mechanism, so defaulting would hand a caller who ignored the result something plausible and wrong, where the true value is merely unnamed.
  - `GetMechanismList`'s remarks corrected to say what it does, with a test (`GetMechanismList_VendorDefinedMechanisms_SurviveUnnamed`) pinning it — documentation being the one kind of claim no compiler disagrees with.
  - The `GuardMechanism(Mechanism)` refactor landed earlier the same day took the library from 57 of these casts to 9.
  - No raw `ulong` overload of `GetMechanismList` was added: the values are already all there, so it would return the same list in a different type.
- **Verification:** four mutations, each killing only the test that guards it — `>=` weakened to `>`; `TryGetMechanism` always reporting success; the out parameter defaulted on failure (the rejected convention); and `GetMechanismList` filtering to defined values, which is precisely the behaviour the old doc described.
- **Breaks public API?** No (additive)
- **Related:** BL-002 — this landed before that gate exists, so the surface change was reviewed by hand rather than against a baseline.
- **Raised by:** .NET Engineer A; scope corrected 2026-07-31 after measuring the cast sites and reading the interop layer

### [BL-041] ✅ RESOLVED — Legacy-crypto `[Obsolete]` attributes lack `DiagnosticId`, forcing blanket CS0618 suppression
- **Status:** Resolved 2026-07-14. Every obsoletion now carries a stable `DiagnosticId` + `UrlFormat` (ids centralized in `DiagnosticIds.cs`): KLPKCS11001 MD5, …002 SHA-1, …003 DES, …004 Triple-DES, …005 RC2, …006 DSA, …007 weak EC curves (the 10 sub-128-bit named curves — beyond the finding's 6 façades, same class of problem). New `docs/diagnostics.md` (wired into the TOC) documents each id, shows precise `#pragma`/`NoWarn` suppression, and states that suppressing the compiler diagnostic does *not* disable the runtime `AllowInsecure` gate; the `UrlFormat` resolves to its anchor. All 22 in-repo suppressions migrated from blanket `CS0618` to the specific id. New `ObsoleteDiagnosticIdTests` pins every id to its type (they are a public contract consumers write into their builds) and sweeps the exported surface so a future bare `[Obsolete]` fails the build. Full suite green (1696 passed).
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/SHA1Pkcs11.cs:27`, `MD5Pkcs11.cs:27`, `DESPkcs11.cs:42`, `TripleDESPkcs11.cs:47`, `RC2Pkcs11.cs:43`, `DSAPkcs11.cs:26`
- **Problem:** Deliberate legacy use under `AllowInsecure` can only be suppressed globally, hiding every other obsoletion in the consumer's code.
- **Proposed action:** Give each a stable `DiagnosticId` (e.g. `KLPKCS11001`) + `UrlFormat`, BCL `SYSLIB*`-style.
- **Breaks public API?** No
- **Raised by:** .NET Engineer A

### [BL-042] No documented SemVer/stability policy; own v3.2-only surface carries no `[Experimental]`
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** M
- **Location:** `README.md` (no stability section); `Pkcs11Key.cs:415,438,519,543`
- **Problem:** `SlhDsaPkcs11` correctly propagates `[Experimental("SYSLIB5006")]`, but the library's own newest v3.2 surface (encapsulation, message-AEAD) has no stability signal, and nothing states what consumers may rely on across versions.
- **Proposed action:** Add a README stability/SemVer section; consider a project-specific `[Experimental]` diagnostic for the v3.2-only surface so 1.0 can ship a stable classical core.
- **Breaks public API?** No (attribute is breaking to *add* post-1.0 — another reason to do it now)
- **Raised by:** .NET Engineer A

### [BL-043] `CkmAesGcmParams` accepts 32-bit GCM tags with no gate or warning
- **Area:** Cryptography
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismParams/CkmAesGcmParams.cs:24-28`
- **Problem:** The public low-level params type validates `tagBits` to any multiple of 8 in [32, 128]; short tags materially raise forgery probability and are restricted by SP 800-38D. (The high-level `AesGcmPkcs11` already enforces 12–16 bytes.)
- **Proposed action:** Floor at 96 bits unless `AllowInsecure`, or at minimum document the SP 800-38D constraint on the parameter.
- **Breaks public API?** Behavioral if gated — decide before 1.0
- **Raised by:** Cryptographer A
- **Spec / References:** NIST SP 800-38D §5.2.1.2, Appendix C

### [BL-044] `CkmHashPqcSignParams` doc suggests `CKM_SHAKE_*` hashes the library deliberately does not map
- **Area:** Cryptography
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismParams/CkmHashPqcSignParams.cs:19` (contrast `Algorithms/Pkcs11MechanismMap.cs:140-147`)
- **Problem:** The param doc's example list includes `CKM_SHAKE_*`, which the mechanism map documents as intentionally unmapped (no standalone SHAKE hash mechanism in OASIS v3.2).
- **Proposed action:** Drop `CKM_SHAKE_*` from the example or add the map's rationale so low- and high-level docs agree.
- **Breaks public API?** No
- **Raised by:** Cryptographer A

### [BL-045] No sanity ceiling on module-reported lengths before allocation (length-probe DoS)
- **Area:** P/Invoke
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:1487-1499` (`CallWithLengthProbe`), `:986-987`; `Native/UnmanagedMemory.cs:75-101`
- **Problem:** Every two-call probe allocates exactly the module-reported length; a buggy token claiming 2 GB for a label forces a giant allocation (checked casts prevent corruption, not OOM).
- **Proposed action:** Add a configurable conservative ceiling with a typed exception in the probe and attribute-allocation loops.
- **Breaks public API?** No
- **Raised by:** Cryptographer B

### [BL-046] ✅ RESOLVED — Intermediate RNG/seed copies are not zeroized
- **Status:** Resolved 2026-07-14. The interop signatures take `byte[]`, so the span overloads must copy through a transient — `GenerateRandom(Span<byte>)` now zeroes the token's output array after filling the caller's span, and `SeedRandom(ReadOnlySpan<byte>)` zeroes its copy of the caller's entropy, both in a `finally`. (The `Pkcs11Workspace` wrappers pass straight through, so no second leak.) New `Pkcs11SessionRandomZeroizationTests` keeps the transient reachable through the fake to inspect it after the call; both tests were mutation-verified to fail with their respective `ZeroMemory` removed. Full suite green (1701 passed).
- **Area:** Cryptography
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:2988-2995` (`GenerateRandom(Span<byte>)`), `:2958-2962` (`SeedRandom(ReadOnlySpan<byte>)`)
- **Problem:** The span overloads copy through un-zeroized temporaries — potential key material lingering on the GC heap, inconsistent with the codebase's otherwise-strict zeroization discipline.
- **Proposed action:** Zero the intermediates in a `finally` (or fill the destination directly).
- **Breaks public API?** No
- **Raised by:** Cryptographer B

### [BL-047] Base v2.40 function pointers are never re-sourced from the negotiated v3.x interface table
- **Area:** PKCS#11 Conformance
- **Severity:** Low
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs:1487-1516`, `:1647-1799`
- **Problem:** After `TryLoadFromGetInterface` succeeds, only v3.x additions are bound from the interface table; the ~68 base pointers stay bound from legacy `C_GetFunctionList`, mixing two tables the spec allows to differ. Theoretical with real modules.
- **Proposed action:** Rebind the full base surface from the returned v3.x function list when the interface path succeeds.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** PKCS#11 v3.0 §5.4.5

### [BL-048] No consumer control over which interface/version is dispatched
- **Area:** PKCS#11 Conformance
- **Severity:** Low
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs:1653-1658`; `Pkcs11Library.cs:297-312`
- **Problem:** The library always negotiates the module's default (highest) interface; there is no way to pin dispatch to a named/lower-version interface — a common interop workaround for buggy v3.x implementations.
- **Proposed action:** Consider an opt-in on load (interface name / max version); at minimum document the default-interface behavior.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist A

### [BL-049] Streaming `DecryptVerify` lacks the unwind-cancel its sibling multi-part methods have
- **Area:** P/Invoke
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:2302-2374` (contrast `:1921-1925`, `:2714-2723`, `:2886-2893`)
- **Problem:** A mid-stream exception leaves both `C_VerifyInit` and `C_DecryptInit` operations active on the shared per-workspace session, wedging the next unrelated operation with `CKR_OPERATION_ACTIVE`. Latent today (not publicly surfaced) but inconsistent with the otherwise-uniform pattern.
- **Proposed action:** Add the same `finalized`-flag `try/finally` + `TryCancelOperation` unwind before this is ever exposed publicly.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist B

### [BL-050] ✅ RESOLVED — `CloseWhenDisposed = false` does not actually keep the session open
- **Status:** Resolved 2026-08-10. The flag is removed. It could not deliver what its name promised: `Pkcs11SessionHandle` is a `SafeHandle` with a critical finalizer, so a session held back from closing still received `C_CloseSession` once the handle became unreachable — just nondeterministically, and in principle after `C_Finalize`. Honouring it properly would have meant detaching the handle (`SetHandleAsInvalid` plus removing it from the library's tracker), which deliberately leaks a live session on the token; nobody asked for that. A grep across `src/` (library and tests) found no reader or writer other than the property's own definition and its trace log, so there was no behaviour to preserve — only a misleading contract to delete. `Dispose` now always releases the handle. Internal type, so no public-API change. A `NOTE` comment at the former site records why the flag is not coming back.
- **Area:** P/Invoke
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:808-827`
- **Problem:** The retained `Pkcs11SessionHandle`'s critical finalizer still calls `C_CloseSession` once the disposed session becomes unreachable — the session closes anyway, just nondeterministically, and could in principle finalize after `C_Finalize`. The flag's contract is misleading (internal type, limited blast radius).
- **Proposed action:** Remove the flag, or implement a real detach that suppresses/transfers the SafeHandle release.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist B

### [BL-051] `NativeLibrary.Load` resolves bare names via the OS search path, undocumented
- **Area:** P/Invoke
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs:127`; public entry `Pkcs11Library.cs:80`
- **Problem:** A non-absolute module name triggers platform search heuristics (cwd/PATH/LD_LIBRARY_PATH) — a DLL-planting vector inherent to consumer-chosen modules, but unmentioned in the docs.
- **Proposed action:** Document that an absolute, trusted path should be passed; consider warning on (or rejecting) non-rooted paths.
- **Breaks public API?** No
- **Raised by:** .NET Engineer B

### [BL-052] Token-removed / device-error mid-operation is only tested at the CKR-mapping level
- **Area:** QA
- **Severity:** Low
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Unit/Exceptions/ExceptionMapperTests.cs:49-61`
- **Problem:** No test injects `CKR_DEVICE_REMOVED` between Init and Final to prove the session is left usable (busy-guard released, no unmanaged leak); the `ManagedSoftToken` fault-injection hooks already exist.
- **Proposed action:** Add a fake-injected device-removed mid-digest/mid-sign case asserting clean teardown.
- **Breaks public API?** No
- **Raised by:** QA B

### [BL-053] Adapter-level ChaCha20-Poly1305 KAT is dormant — reads as covered but never executes
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/Adapters/KnownAnswerTests.SoftHsm2.cs:350`; gate hardcoded false at `Support/Fixtures/SoftHsmBackendFixture.cs:71`
- **Problem:** The KAT is gated on a capability flag that is hardcoded `false` and wired to no other backend. Coverage exists via the managed RFC 8439 KAT, but the dormant adapter code gives a false impression of real-backend coverage.
- **Proposed action:** Wire it to a backend that can run it (see BL-028) or delete it.
- **Breaks public API?** No
- **Raised by:** QA B

### [BL-054] Publish-trigger and artifact hardening gaps (no environment gate, no concurrency guard, snupkg unattested)
- **Area:** Release Eng
- **Severity:** Low
- **Effort:** S
- **Location:** `.github/workflows/publish.yml:4-5,41-55`
- **Problem:** Any `v*` tag triggers a push to an immutable package ID with no protected-environment approval or `concurrency` group; the symbol package is not attested; determinism is configured but never verified post-build.
- **Proposed action:** Gate publish behind a protected GitHub Environment, add a `concurrency` group, and consider attesting the snupkg. The OIDC + provenance flow itself is already strong.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-055] ✅ RESOLVED — Eight param structs use `[MarshalAs(ByValArray)] byte[]` where the rest of the codebase uses `[InlineArray]`, leaving a latent under-allocation trap
- **Status:** Resolved 2026-07-29. The eight `byte[]` fields became `[InlineArray]` buffers (`CkChar16`, and a new `CkChar8`), matching the `CkChar32` pattern `CK_INFO` already used. The change is layout-neutral on the unmanaged side — all ~194 absolute size pins passed unchanged — so only the managed layout moved, and managed now equals marshalled for all 198 native types. `Pkcs11Marshal.SizeOf` and the generator's `SizeOfWindows`/`SizeOfUnified` emissions switched to `Unsafe.SizeOf` and the CA1421 suppression was deleted. `NativeStructLayoutTests.EveryCkStruct_ManagedSizeMatchesMarshalledSize` now enforces the invariant on every platform leg, superseding the divergence pin it replaced. The suppression removal is scoped to `Pkcs11Marshal.cs`: `Native/UnmanagedMemory.cs:163`'s non-packed branch (`Marshal.SizeOf<T>()` for types without `[PackedForPkcs11]`) still uses `Marshal.SizeOf` and will still trip CA1421 under `AnalysisMode=All`/SonarCloud. That is deliberate, not a regression — both halves of that code path (the `SizeOf` call and the `Marshal.PtrToStructure`/`StructureToPtr` calls elsewhere in the same file) go through the CLR's runtime marshaller for those types, so they cannot disagree with each other the way a hand-rolled `Unsafe.SizeOf` would.
- **Area:** Interop
- **Severity:** Low
- **Effort:** M
- **Location:** `Native/RawMechanismParams/CK_AES_CTR_PARAMS.cs:20-21`, `CK_CAMELLIA_CTR_PARAMS.cs:20-21`, `CK_AES_CBC_ENCRYPT_DATA_PARAMS.cs:15-16`, `CK_ARIA_CBC_ENCRYPT_DATA_PARAMS.cs:15-16`, `CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS.cs:15-16`, `CK_SEED_CBC_ENCRYPT_DATA_PARAMS.cs:15-16`, `CK_DES_CBC_ENCRYPT_DATA_PARAMS.cs:15-16`, `CK_RC2_CBC_PARAMS.cs:20-21`; `Native/Pkcs11Marshal.cs:20`
- **Problem:** These eight carry a managed `byte[]` field marshalled `ByValArray`, so the managed layout stores an 8-byte reference where the unmanaged layout stores the array inline. Six diverge in total size (`CK_AES_CTR_PARAMS` is 24 marshalled vs 16 managed; the `*_CBC_ENCRYPT_DATA_PARAMS` family 32 vs 24); `CK_DES_CBC_ENCRYPT_DATA_PARAMS` and `CK_RC2_CBC_PARAMS` agree only because an 8-byte IV happens to match the reference width it displaces. Nothing is wrong today — allocation and `StructureToPtr` both go through `Marshal.SizeOf` consistently — but it makes the CA1421 suggestion (`sizeof`/`Unsafe.SizeOf`) an under-allocation bug rather than a cleanup, which is why `Pkcs11Marshal.SizeOf` carries a suppression instead of a fix. Every other inline buffer in the codebase (`CkChar16/32/64`, `CK_DATE`'s `Char4`/`Char2`) already uses `[InlineArray]`, which marshals to an identical managed and unmanaged layout (see Appendix B).
- **Proposed action:** Convert the eight `byte[]` fields to `[InlineArray]` buffers matching the existing `CkChar*` pattern, making managed and marshalled layouts identical. That removes the divergence class entirely, lets the `Pkcs11Marshal.SizeOf` suppression be replaced by a real fix, and keeps these structs blittable. Guarded meanwhile by `MarshalSizeOfTests.ByValArrayStruct_MarshalledSizeExceedsManagedSize`, which pins the current divergence; the per-platform size census pins the target sizes across the change.
- **Breaks public API?** No — all types are `internal`.
- **Raised by:** SonarCloud CA1421 triage

### [BL-142] `ObjectAttribute` takes `List<T>` in public constructors
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Objects/ObjectAttribute.cs:183`, `:217`, `:221`, `:240`, `:244`, `:266`
- **Problem:** Six public constructors accept `List<ObjectAttribute>`, `List<ulong>` and `List<CKM>`. The guidelines call for `IEnumerable<T>`/`IReadOnlyList<T>`/`ReadOnlySpan<T>` on input parameters; `List<T>` forces callers to materialise a specific concrete type, and hands them a mutable collection whose ownership is unclear — the array-valued attribute cases do copy, but the signature does not say so.
- **Proposed action:** Change the parameters to `IReadOnlyList<T>`, or add `ReadOnlySpan<T>` overloads for the scalar-array cases. Source-compatible for callers already passing `List<T>`.
- **Breaks public API?** Yes — binary-breaking after 1.0, source-compatible now; land before 1.0
- **Raised by:** .NET Engineer A
- **Spec / References:** CA1002; Framework Design Guidelines §8.3

### [BL-143] `EncapsulateKey`'s `expectedCiphertextLen` puts a token quirk in the public signature
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs:576-592` (`int expectedCiphertextLen = 0`, documented at `:562-566` as a workaround for tokens that ignore the NULL-buffer length probe)
- **Problem:** A magic-zero `int` whose only purpose is to work around SoftHSM's non-conforming `C_EncapsulateKey` sits in the signature of the flagship v3.2 KEM entry point. Every consumer now has to understand a module bug in order to call it, and the parameter can never be removed once shipped. The library already has the right home for this: the per-token quirk cache on `Pkcs11Library` (`Pkcs11Library.cs:54-61`, `MlKemDecapsulateOmitsValueLen`).
- **Proposed action:** Derive the length internally from the key's `CKA_PARAMETER_SET` — ML-KEM ciphertext sizes are fixed per parameter set — and fall back to probe-then-retry, learning the quirk the way `MlKemDecapsulateOmitsValueLen` already does. Then drop the parameter, or mark it `[EditorBrowsable(Never)]` if it must remain as an escape hatch.
- **Breaks public API?** Yes — removing a parameter is SemVer-major; land before 1.0
- **Raised by:** .NET Engineer A

### [BL-144] Four v3.x `CKF` constants are absent, leaving one documented by name only and one publicly documented as magic numbers
- **Area:** PKCS#11 Conformance
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKF.cs` (no `CKF_END_OF_MESSAGE`, no `CKF_HKDF_SALT_NULL`/`_DATA`/`_KEY`); `Native/LowLevelPkcs11Library.cs:726` and `:806` reference `CKF_END_OF_MESSAGE` by name in XML docs; `MechanismParams/CkmHkdfParams.cs:26,30` (`ulong saltType` documented in prose as "1 = SALT_NULL, 2 = SALT_DATA, 4 = SALT_KEY")
- **Problem:** These are the only four v3.x `CKF_*` constants missing from `CKF`, verified by diffing all 69 `CKF_*` defines in `vendor/nss/lib/util/pkcs11t.h` against `Common/CKF.cs` — every other name and value matches exactly. The public `CkmHkdfParams` constructor therefore asks callers for a bare `ulong` and spells the legal values out in prose, which is the opposite of the project's strongly-typed-constants rule. `CkmXeddsaParams` has the same shape for `CK_XEDDSA_HASH_TYPE`.
- **Proposed action:** Add `CKF_END_OF_MESSAGE = 0x00000001` and `CKF_HKDF_SALT_NULL`/`_DATA`/`_KEY` = 0x01/0x02/0x04 to `CKF`, and add a typed salt-type enum overload on `CkmHkdfParams` (keeping the `ulong` form for vendor salt types) plus an `XEdDsaHashType` enum on `CkmXeddsaParams`.
- **Breaks public API?** No — additive
- **Raised by:** PKCS#11 Specialist A, Cryptographer A
- **Spec / References:** `vendor/nss/lib/util/pkcs11t.h:1708`, `:2423-2425`

### [BL-145] No template-builder support for `CKA_PARAMETER_SET`, so PQC key generation needs an untyped escape hatch
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Objects/PublicKeyTemplateBuilder.cs`; `Objects/ObjectAttribute.cs:129-133` (which has `(CKA, CKK)`, `(CKA, CKO)` and `(CKA, CKC)` overloads but none for the PQC parameter-set enums)
- **Problem:** ML-KEM, ML-DSA and SLH-DSA key generation — the headline v3.2 capability — requires `CKA_PARAMETER_SET`, but no builder method exposes it, so a consumer must use the untyped `Attribute(CKA, ulong)` escape with a manual `(ulong)CkpMlKem.CKP_ML_KEM_768` cast. The library defines `CkpMlKem`, `CkpMlDsa` and `CkpSlhDsa` as strong enums and then gives them no first-class way into a template.
- **Proposed action:** Add `ParameterSet(CkpMlKem)`/`(CkpMlDsa)`/`(CkpSlhDsa)` overloads to the public- and private-key template builders, plus matching `ObjectAttribute` constructors.
- **Breaks public API?** No — additive
- **Raised by:** Cryptographer A

### [BL-146] `CKM_AES_KEY_WRAP_PAD` is not documented as deprecated in favour of `CKM_AES_KEY_WRAP_KWP`
- **Area:** Cryptography
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKM.cs:1670-1673`; compare `:1957-1960`
- **Problem:** `CKM_AES_KEY_WRAP_PAD` carries the bare summary "AES key wrapping mechanism with padding", while its replacement `CKM_AES_KEY_WRAP_KWP` — two thousand lines away — is properly annotated "AES Key Wrap with Padding (KWP) per RFC 5649 / NIST SP 800-38F (PKCS#11 v3.0)". The v3.0 spec deprecates `_PAD` precisely because its padding scheme was under-specified and implementations diverged; a consumer reading the enum has no way to know which of the two adjacent-looking members to pick. This matters more given BL-123: the functional wrap round-trips all use `_PAD`.
- **Proposed action:** Extend the `CKM_AES_KEY_WRAP_PAD` doc comment to state that it is deprecated as of PKCS#11 v3.0 and to point at `CKM_AES_KEY_WRAP_KWP`. This is the pattern the project already uses for weak mechanisms, minus the runtime gate — which is not warranted here, since `_PAD` is ambiguous rather than insecure.
- **Breaks public API?** No — documentation only
- **Raised by:** Cryptographer A
- **Spec / References:** PKCS#11 v3.0 §2.15; RFC 5649

### [BL-147] `CK_ULONG` scalars are written and read with hard-coded little-endian primitives, and one overload truncates silently on Windows where its sibling throws
- **Area:** P/Invoke
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Objects/ObjectAttribute.cs:120-125` (silent truncation) versus `:232` and `:258` (`checked((uint)…)`); reads at `:296-297`, `:409-411`; `MechanismParams/CkmSp800108KdfParams.cs:267-275` and `:277-283`; contrast `MechanismParams/Pkcs11ParameterWriter.cs:172-187`, which branches on `BitConverter.IsLittleEndian`
- **Problem:** Two inconsistencies in one family of code. `ObjectAttribute(ulong type, ulong value)` writes the value with `WriteUInt64LittleEndian` and then slices to the native `CK_ULONG` width, so on Windows the high 32 bits are **discarded silently** — while `ObjectAttribute(ulong, List<ulong>)` twenty lines later uses `checked((uint)…)` and throws for the same input. A consumer passing a vendor attribute value above `uint.MaxValue` therefore gets a wrong attribute on Windows and an exception on Linux. Separately, all of these paths hard-code little-endian for bytes the *local* module reads in native byte order; `Pkcs11ParameterWriter` gets this right, so the codebase disagrees with itself. Inert on the six shipped RIDs, all of which are little-endian, but the divergence is the kind of thing that outlives a RID list.
- **Proposed action:** Route every `CK_ULONG` scalar through one helper — reuse `Pkcs11ParameterWriter`'s endianness branch, or `BinaryPrimitives.Write{U}IntNativeEndian` — and make the narrowing `checked` everywhere, so all overloads fail the same way on Windows instead of one truncating.
- **Breaks public API?** No
- **Raised by:** .NET Engineer B

### [BL-148] The `(array, count)` pairs crossing the P/Invoke boundary are never checked against each other
- **Area:** P/Invoke
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs:1305-1325` (`C_GetAttributeValue`), `:1335-1346`, `:1355-1366`, `:1233-1243`, `:1376-1382` (`C_FindObjects`), and the template/count pairs at `:1008-1030`, `:1954-1982`, `:2033-2058`
- **Problem:** Every array-taking interop method takes a separate `NativeCULong count`, pins the array with `fixed`, and hands both to the module without asserting `count <= array.Length`. Callers inside `Pkcs11Session` always pass `template.Length`, so nothing is broken today — but `ILowLevelPkcs11Library` is the seam the test fakes implement, and the only place where a mismatch turns into the module writing past a pinned managed array: real heap corruption, not a bounds check. The whole point of this layer is that a mistake above it cannot corrupt memory.
- **Proposed action:** Add `ArgumentOutOfRangeException.ThrowIfGreaterThan((ulong)count, (ulong)(template?.Length ?? 0))` at the top of each array-taking wrapper, or drop the redundant `count` parameter and derive it from the array length.
- **Breaks public API?** No
- **Raised by:** .NET Engineer B

### [BL-149] Generated Windows siblings carry `CharSet = CharSet.Unicode` on structs whose PKCS#11 fields are single-byte
- **Area:** P/Invoke
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Generators/PackedStructsGenerator.cs:66`; visible in every emitted file
- **Problem:** The generator hard-codes `[StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]`. It is inert today because no `CK_*` struct declares a `char` or `string` field — fixed-length fields are `[InlineArray]` byte buffers (`Native/CkCharBuffer.cs`) — so `Marshal.SizeOf` and the pinned layouts are unaffected. But PKCS#11 fixed-length fields are blank-padded, non-NUL-terminated **single-byte** arrays; the day someone adds a `char` or `ByValTStr` field to a marked struct, `CharSet.Unicode` doubles its marshalled width on Windows only, and the existing managed-versus-marshalled size guard would be the only thing standing between that and a wrong-layout call.
- **Proposed action:** Emit `CharSet = CharSet.Ansi`, or omit `CharSet` entirely — which is what the hand-written unified structs do (`Native/CK_TOKEN_INFO.cs:8`) — so a generated sibling cannot diverge from its source struct's layout rules.
- **Breaks public API?** No — all affected types are internal
- **Raised by:** .NET Engineer B

### [BL-150] `Internal/SecureBuffer.cs` is dead production code presented as evidence of a live discipline
- **Area:** Cross-cutting
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/SecureBuffer.cs:1-92`; the only references are doc comments at `Logging/Pkcs11Logging.cs:25`, `Native/UnmanagedMemory.cs:14` and `:107`, plus its own unit test
- **Problem:** No production code references the type. Appendix B cites it as part of the evidence that "zeroization and SafeHandle discipline are consistent", and BL-057's resolution note says it "remains available if a future parameter type warrants stronger handling" — so it reads as load-bearing infrastructure that nothing actually uses, and its tests read as coverage of a live path. Two specialists found it independently; one deliberately did not raise it on the strength of that recorded decision, which is itself the problem: the decision is not visible at the code.
- **Proposed action:** Either delete it with its test and drop the doc references, or add a comment stating plainly that it is a reserved utility with no current caller, so neither a future reviewer nor the backlog mistakes its test for coverage of a production path.
- **Breaks public API?** No — the type is internal
- **Raised by:** PKCS#11 Specialist B, Cryptographer B
- **Spec / References:** Same category as resolved BL-059 (dead `CK_MECHANISM.CreateMechanism`), a different instance

### [BL-151] `C_OpenSession`'s `pApplication`/`Notify` are hardcoded NULL with no documented decision
- **Area:** PKCS#11 Conformance
- **Severity:** Low
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Slot.cs:206`; the dispatch is at `Native/Delegates.cs:187-193`
- **Problem:** Every session is opened with both `pApplication` and `Notify` as `IntPtr.Zero`, so `CK_NOTIFY` callbacks — `CKN_SURRENDER` (progress and cancellation, the mechanism `CKR_FUNCTION_CANCELED` exists for) and `CKN_OTP_CHANGED` — can never be delivered. Under `[assembly: DisableRuntimeMarshalling]` a callback would need `[UnmanagedCallersOnly]`, so this looks deliberate and is a defensible choice for an AOT-friendly wrapper. But it is nowhere stated, and it leaves `WaitForSlotEvent` as the only token-presence signal.
- **Proposed action:** Document the decision on `Pkcs11Slot.OpenSession` and in the threading/notification documentation. If it is intended to be permanent, say so — adding a notification surface later is additive but changes the session-lifetime contract.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist B, .NET Engineer B
- **Spec / References:** PKCS#11 v3.2 §5.21 (`CK_NOTIFY`, `CKN_SURRENDER`)

### [BL-152] `Pkcs11ECCurve` lacks `[MemberNotNullWhen]`, forcing consumers to null-forgive `Oid`
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11ECCurve.cs:38` (`public string? Oid`), `:51` (`IsNamed`), `:54` (`IsDefault => Oid is null`)
- **Problem:** `IsDefault` and `IsNamed` are exactly the guards that establish `Oid`'s nullability, but neither is annotated, so a consumer who checks `if (!curve.IsDefault)` still receives a nullable `Oid` and must write `!`. For a library that enables nullable reference types and cares about accuracy on the public surface, this is a cheap gap.
- **Proposed action:** Add `[MemberNotNullWhen(false, nameof(Oid))]` on `IsDefault` and `[MemberNotNullWhen(true, nameof(Oid))]` on `IsNamed`.
- **Breaks public API?** No — additive annotation
- **Raised by:** .NET Engineer A

### [BL-153] `NssBackendFixture` documents a `BuildNss` MSBuild target that does not exist, and its built-path probe can never succeed in CI
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/NssBackendFixture.cs:14-16` and `:152-160`; the test project's targets are `BuildPkcs11Mock`, `BuildPkcs11Gate` and `BuildSoftHsmV2` only
- **Problem:** The type doc says the library "is built from the `vendor/nss` submodule and staged next to the test assembly by the `BuildNss` MSBuild target"; no such target exists anywhere in the repository. NSS is staged by `.github/workflows/ci.yml` into `$RUNNER_TEMP/nss/...` and located purely via `PKCS11_TEST_NSS_LIBRARY`, so `BuiltLibraryPath()` — which probes `<asmdir>/runtimes/<rid>/native/nss/libsoftokn3.so` — never resolves, and the environment variable is the sole real path, the inverse of the documented precedence. A contributor trying to run the NSS suite locally will look for a target that is not there.
- **Proposed action:** Either add the `BuildNss` target for parity with the other three backends, or correct the doc to say NSS is provisioned out of band via `PKCS11_TEST_NSS_LIBRARY` — as `OpenCryptokiBackendFixture` honestly states — and drop the unreachable `BuiltLibraryPath()` probe.
- **Breaks public API?** No
- **Raised by:** QA A

### [BL-154] The docs build is never validated on a pull request, so `docfx --warningsAsErrors` breaks only after merge
- **Area:** Release Eng
- **Severity:** Low
- **Effort:** S
- **Location:** `.github/workflows/docs.yml:4-13` (`push: branches: [main]` plus `workflow_dispatch` only) and `:50` (`dotnet docfx docs/docfx.json --warningsAsErrors`)
- **Problem:** The docs job triggers on `src/**` as well as `docs/**` and runs docfx with warnings as errors, so an unresolved `<see cref>` or a malformed XML doc comment in a library PR passes CI and then breaks the Pages deployment on `main`. For a library whose public docs site is the primary reference, the break lands on the published artifact rather than on the contributor.
- **Proposed action:** Add a `pull_request` trigger that runs the `build` job only, leaving `deploy` gated on `push` to `main`. Nothing else needs to change — the workflow's per-job permission split is already least-privilege.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-155] Vendored submodules are pinned to untagged upstream commits, with no in-tree record of why and no review gate on bumps
- **Area:** Release Eng
- **Severity:** Low
- **Effort:** S
- **Location:** `.gitmodules:1-16`; the actual pins are `vendor/softhsmv2` = `c26ef0a` (239 commits past the `2.6.1` tag), `vendor/opencryptoki` = `627d2751` (10 commits past `v3.27.0`), `vendor/nss` = `NSS_3_126_RTM`, `vendor/pkcs11-mock` = `v2.0.0`; the misstatement is at `.github/workflows/ci.yml:225`
- **Problem:** Two of the four backends are pinned to mid-development upstream commits rather than releases, so the "three independent real backends" evidence rests partly on unreleased upstream code — and the `ci.yml` comment misstates the opencryptoki pin as the v3.27.0 release. Submodule SHAs also feed the native-artifact cache key (`ci.yml:170`), so a bump silently changes what the whole matrix tests. There is no `CODEOWNERS` and no `gitsubmodule` entry for dependency automation, so a submodule bump arrives as an opaque one-line SHA diff.
- **Proposed action:** Move each submodule to a tagged release where possible, or add a short `vendor/README.md` recording why each non-tag pin was chosen and what it fixes; correct the `ci.yml:225` comment; and add `.github/CODEOWNERS` covering `vendor/`, `.github/workflows/`, `build/` and `Directory.Build.props` so infrastructure and pin changes always require an owner's review.
- **Breaks public API?** No
- **Raised by:** QA C
- **Spec / References:** Extends BL-032, which covers the `nuget`/`github-actions` ecosystems but not `gitsubmodule`, the untagged pins, or `CODEOWNERS`

### [BL-156] Two remaining unverified third-party build inputs, and `NuGet.config` does not clear inherited sources
- **Area:** Release Eng
- **Severity:** Low
- **Effort:** S
- **Location:** `.github/workflows/ci.yml:325` (`python3 -m pip install --user 'gyp-next==0.22.2'`); `build/build-softhsmv2.ps1:75-77` (`vcpkg install openssl:$triplet` against the runner image's baseline); `NuGet.config:3-9` (no `<clear />`)
- **Problem:** Source integrity is otherwise handled well — the OpenSSL 3.5.7 tarball is SHA-256 verified in both workflows, and all three SoftHSM 2.5 `.deb`s are fetched from content-addressed Debian snapshot URLs with pinned digests and a post-extract version assertion (`build/setup-softhsm25.sh:30-65`). Three gaps remain: `gyp-next` is installed by version only, with no `--require-hashes`; the Windows SoftHSM's OpenSSL floats with whatever baseline the runner image's vcpkg carries — the script's own comment only guesses "3.6+" — and that version is neither pinned nor reflected in the vcpkg cache key, so the cache can serve a different OpenSSL than the one a later run would build; and `packageSources` has no `<clear />`, so machine- and user-level feeds merge in, largely but not entirely neutered by the `packageSourceMapping` block, which is otherwise exactly right.
- **Proposed action:** Pin `gyp-next` with a hash-locked requirements file; pin the vcpkg tree (a checked-out SHA, or manifest mode with a `builtin-baseline`) and fold the resolved OpenSSL version into the cache key; and add `<clear />` as the first child of `<packageSources>`.
- **Breaks public API?** No
- **Raised by:** QA C

## PKCS#11 v3.2 Coverage Matrix

**Corrected 2026-08-11:** the three public-façade rows below marked ❌ were previously recorded as ✅. A grep over `Internal/`, `Algorithms/`, `Objects/` and the root types finds no caller for `C_SignUpdate`, `C_SignFinal` or `C_SignRecover`, while `C_EncryptUpdate`/`C_DigestUpdate`/`C_VerifyUpdate` all have callers — and `Pkcs11Key`/`Pkcs11Workspace` expose no `Stream` overload at all. See BL-087 and BL-099.

Condensed from PKCS#11 Specialist A, who cross-checked `CK_FUNCTION_LIST_3_0`/`_3_2`, `CK_INTERFACE`, and `CK_ASYNC_DATA` field-by-field against the vendored v3.2 header (`vendor/opencryptoki/usr/include/pkcs11types.h`) — exact match, including the 12 v3.2 additions in declaration order. **No v3.2 `C_*` function is missing at the interop layer.** Re-confirmed 2026-08-11: all 104 function-list entries are bound; **78 of 104 are reachable from the public API** (v2.40 68/68 in substance, v3.0 8 of 24, v3.2 2 of 12).

| Function group | Low-level (P/Invoke) | High-level (public façade) |
|---|---|---|
| v2.40 general / slot / token (`C_Initialize` … `C_WaitForSlotEvent`) | ✅ | ✅ |
| v2.40 session / PIN / login (`C_OpenSession` … `C_Logout`) | ✅ | ✅ |
| v2.40 object / attribute (`C_CreateObject` … `C_FindObjectsFinal`) | ✅ | ✅ |
| v2.40 crypto — single-part (`C_Encrypt`, `C_Decrypt`, `C_Sign`, `C_Verify`, `C_Digest`) | ✅ | ✅ |
| v2.40 crypto — multi-part (`*_Update`/`*_Final`) | ✅ | ❌ — internal only; **multi-part sign is not implemented at all** (`C_SignUpdate`/`C_SignFinal` have no caller outside `Native/`) — BL-087 |
| v2.40 crypto — SignRecover/VerifyRecover, dual-function combos | ✅ | ❌ — low-level only — BL-087 |
| v2.40 key management / RNG | ✅ | ✅ |
| v2.40 legacy (`C_GetFunctionStatus`, `C_CancelFunction`) | ✅ | low-level only (legacy no-ops) |
| v3.0 interfaces (`C_GetInterfaceList`, `C_GetInterface`) | ✅ | ✅ |
| v3.0 `C_LoginUser`, `C_SessionCancel` | ✅ | ❌ — implemented but `internal` — BL-099 |
| v3.0 message-based AEAD — encrypt/decrypt single-shot triples | ✅ | ✅ |
| v3.0 message-based — `Begin`/`Next` multi-part, message Sign/Verify (14 functions) | ✅ | ❌ — no caller outside `Native/` — BL-099 |
| v3.2 KEM (`C_EncapsulateKey`, `C_DecapsulateKey`) | ✅ | ✅ |
| v3.2 verify-signature streaming (`C_VerifySignature*`) | ✅ | ❌ — BL-019 |
| v3.2 authenticated wrap (`C_WrapKeyAuthenticated`, `C_UnwrapKeyAuthenticated`) | ✅ | ❌ — BL-019 |
| v3.2 async (`C_AsyncComplete`, `C_AsyncGetID`, `C_AsyncJoin`) | ✅ | ❌ — BL-019 |
| v3.2 validation (`C_GetSessionValidationFlags`) | ✅ | ❌ — BL-019 |

Mechanisms (`CKM`, 480 members): RSA (PSS/OAEP), EC/EdDSA/Montgomery, AES (GCM/CCM/CTR/KW/message), ChaCha20/Salsa20/Poly1305, ML-DSA/ML-KEM/SLH-DSA, HSS/LMS, SHA-2/-3/SHAKE, HMAC, KDFs, legacy `[Obsolete]`-gated — comprehensive, spot-checked constant values correct, raw-`ulong` vendor escape hatch present. Attributes (`CKA`, 160 members): all v3.2 additions present (trust, validation, profile, HSS, parameter-set, encapsulate/decapsulate templates); `CKO_PROFILE`/`VALIDATION`/`TRUST` defined but have no dedicated template builders (GenericTemplateBuilder suffices). Return codes (`CKR`, 105 members): all v3.2 additions present; vendor-code handling gap is BL-003.


Constant coverage was re-verified 2026-08-11 by diffing the enums against three independent vendored headers (`vendor/opencryptoki/usr/include/pkcs11types.h`, `vendor/nss/lib/util/pkcs11t.h`, `vendor/pkcs11-mock/src/cryptoki/pkcs11t.h`): **zero value mismatches** across `CKM` (480), `CKA` (155), `CKR` (105), `CKK` (69), `CKD` (26), `CKO`, `CKC`, `CKS`, `CKU`, `CKN`, `CKH`, `CKT`, `CKG`, `CKP`. Residual gaps: `CKF` is 65 of 69 (BL-144), `CK_GENERATOR_FUNCTION` is entirely absent (BL-102), `CKK_INVALID_KEY_TYPE` is absent (trivial), and five defined `CKF` bits have no property on the public flag records (BL-101). `CK_FUNCTION_LIST_3_2` declaration order matches `pkcs11f.h` exactly — a transposition there would have been Critical, and there is none.
## Appendix A — Unverified / Speculative

- **KEM/authenticated-unwrap secure-defaults application** (Cryptographer B, round 1): whether `EncapsulateKey`/`DecapsulateKey` and `UnwrapKeyAuthenticated` call `BuildSecureKeyDefaults` like `UnwrapKey`/`DeriveKey` do — a shared comment claims so, but the reviewer read only the latter two call sites in full. Confirm before 1.0.
- **GitHub repository settings** (QA C, both rounds): branch protections, required status checks, tag protection, Environment approvals, and Private Vulnerability Reporting enablement are not verifiable from the repo — confirm in Settings. Specifically confirm that `lint`, all six `build-and-test` legs, `aot-smoke` and `softhsm-v240` are *required* checks; BL-139 changes character depending on whether `code-quality` is required.
- **`CK_CCM_WRAP_PARAMS` field order and the `CK_XEDDSA_HASH_TYPE` value set** (Cryptographer A): `CK_GCM_WRAP_PARAMS` and both PQC context structs were confirmed against `vendor/opencryptoki/usr/include/pkcs11types.h:1890-1901`, but `CK_CCM_WRAP_PARAMS` appears in no vendored header. Someone with the OASIS v3.2 PDF should confirm that one before BL-103 is implemented.
- **Real-HSM handle recycling frequency** (PKCS#11 Specialist B): whether shipping HSMs recycle session and object handles aggressively enough for BL-071 and BL-116 to fire in practice. The spec permits it and nothing defends against it, which is why both were raised; the actual frequency is vendor-dependent and would need a real-device experiment.
- **`CKR_CANT_LOCK` prevalence** (PKCS#11 Specialist B): BL-085's practical severity depends on how many shipping modules refuse `CKF_OS_LOCKING_OK`. None of the four CI backends does, so that path has zero real-backend coverage today.
- **Backend mechanism advertisement** (QA B): whether opencryptoki's software token advertises `CKD_SHA256_KDF` or `CKM_RSA_AES_KEY_WRAP` in this build is not determinable from source. BL-123 and BL-124 assume a capable backend can be found and should be implemented with a hard-fail guard so the assumption is checked rather than silently skipped.
- **`ManagedSoftToken` Windows-packed dispatch** (QA A): whether `UnmanagedMemory.Read<CK_CCM_PARAMS>` in the fake resolves to the Windows-packed sibling layout on the Windows legs. The tests pass there, presumably via the `IsPackedForPkcs11` dispatch, but confirming it was outside that reviewer's lane.
- **`CertificateRequest.Create` with `ECDsaPkcs11`** (.NET Engineer A): the claim follows from a verified `SignData(…, Rfc3279DerSequence)` failure on a shim subclass plus .NET's ECDSA `X509SignatureGenerator` using that format, rather than from a live token. A real-backend CSR round-trip test would confirm it directly and is worth adding regardless (BL-072).

## Appendix B — Out of Scope Observations

Positive findings worth preserving. Items marked **(re-verified 2026-08-11)** were independently reconfirmed by the second review round.

- **The Windows packing scheme is complete and coherent (re-verified 2026-08-11).** `CK_FUNCTION_LIST` — whose natural alignment would shift every pointer by 6 bytes on Win64 — is `[PackedForPkcs11]`; a full enumeration found **33 of 33** struct-taking function pointers have a `_Windows` sibling *and* a matching `HasC_*_Windows` dispatch guard, with no entry point bypassing the packed path. `C_GetInterface` correctly needs none (it returns `CK_INTERFACE**`, read through the dispatching `UnmanagedMemory.Read<CK_INTERFACE>`). 98 marked structs, 99 generated files, all 85 raw param structs attributed; nested by-value packed structs substitute correctly. `EnsureCkUlongWidthMatchesPlatform` fails loud on a mis-resolved `NativeCULong` asset.
- **The `NativeCULong` guard is correct on every shipped RID, with one nuance worth recording.** `KerckhoffsLabs.Runtime.InteropServices 1.3.1` ships runtime assets for `win-x64` and `win-arm64` **only**; `win-x86` resolves the neutral `nuint` build and is still correct because `nuint` is 4 bytes in an ILP32 Windows process — which is why that CI leg is green. Relevant when reading BL-023: on win-x86 correctness rests on `nuint == 4`, not on an asset, and the guard cannot distinguish the two.
- **`[InlineArray]` marshals correctly (re-verified 2026-08-11, empirically).** For a `CK_SLOT_INFO`-shaped struct, `Unsafe.SizeOf == Marshal.SizeOf == 112` (unified LP64) and `== 104` (Pack=1, matching native Win64 `pragma pack(1)`), and a round-trip preserved byte 63 of the inline array and the flags at offset 96.
- **Calling convention and packing match the real headers (re-verified 2026-08-11).** `vendor/pkcs11-mock/src/pkcs11-mock.h:35-51` confirms `#pragma pack(push, cryptoki, 1)` + `__cdecl` on Windows and default alignment elsewhere; every function pointer is `delegate* unmanaged[Cdecl]`.
- **Every PKCS#11 constant value checks out (re-verified 2026-08-11).** See the note under the coverage matrix: zero value mismatches across fourteen enums against three independent vendored headers, including the v3.2-only PQC parameter-set values.
- **No managed↔native parameter-struct layout defect exists (re-verified 2026-08-11).** A field-sequence comparison of every native param struct against its C counterpart produced no genuine mismatch, and the highest-risk pairs were hand-checked against spec text — including `CK_EDDSA_PARAMS`, whose counter-intuitive `phFlag, ulContextDataLen, pContextData` order the library has right, and the whole SP800-108 graph. The generator forwards `[MarshalAs]` verbatim to `_Windows` siblings, so `CK_BBOOL` fields keep `UnmanagedType.U1`.
- **Integer overflow at the length boundary is handled by design:** `CheckForOverflowUnderflow` plus `NativeCULong`'s checked conversions route every length cast through a throwing conversion. (Note the flip side: BL-076 is a case where that checked conversion is applied to a value whose full range is legal.)
- **The native interop layer is fully quarantined** — every type under `Native/` is `internal`; no raw `IntPtr`, `delegate*`, or `CK_*` type appears on the public surface (re-verified 2026-08-11).
- **AOT/trim posture is sound:** `[assembly: DisableRuntimeMarshalling]`, `delegate* unmanaged[Cdecl]` dispatch, generator-emitted `typeof` chains with no reflection, `IsAotCompatible` plus analyzers, and a CI AOT smoke job. The one reflection cost found is a performance issue, not an AOT blocker (BL-113).
- **Zeroization, PIN handling and secret hygiene are consistent (re-verified 2026-08-11).** `SecurePin` pins via `GCHandle`, hands out pinned-object-heap transients so the zeroizing `finally` destroys the only copy, redacts `ToString()`, and documents the `string` overload's interning caveat; every consumer zeroizes in a `finally`. **No managed-side secret comparison exists anywhere** (no `FixedTimeEquals`/`SequenceEqual`) — verification goes to the token or to BCL `VerifyData`/`VerifyHash`, both constant-time — so there is no timing surface to harden. No log statement formats key, PIN or plaintext material, and `Pkcs11Exception` interpolates only the method name and CKR; the only user data interpolated anywhere is a label, and `OpenKey(id)` deliberately logs `len=` rather than the id bytes. The residual gaps are narrow and tracked as BL-109 and BL-115.
- **Secure-by-default is consistently enforced** in key-producing operations via `BuildSecureKeyDefaults`; template builders default correctly; verification is delegated to the token with `CKR_SIGNATURE_INVALID → false` mapping. The gaps are the gate's *membership* (BL-074), the generators' *role assignment* (BL-070), and one verify return code (BL-065) — not the mechanism.
- **PQC handling is unusually careful.** ML-DSA pre-hash/SHAKE arms are refused with accurate FIPS 204 domain-separation reasoning rather than emitting non-interoperable signatures; `MLKemPkcs11` length-checks the token's `CKA_VALUE` before copying, zeroizes the intermediate in a `finally`, zeroizes the caller's secret on every failure path, surfaces rather than swallows a `C_DestroyObject` failure, caches the `CKA_VALUE_LEN` token quirk, and refuses private-key export on all four BCL paths. Two independent reviewers named it the strongest file in the repository.
- **`MechanismParameterScope` is a sound design:** call-scoped allocation, `Write` returning `IntPtr.Zero` for an empty span (the correct PKCS#11 absent-buffer encoding), zeroize-on-free, and a deliberately stateless `Mechanism.Marshal` together eliminate the aliasing and lifetime bugs this layer usually has. `ThrowIfOneDescriptorDrivesBothHalves` is a thoughtful guard.
- **The test suite is mature where it covers.** ~90 struct sizes pinned per platform via a reflection census; genuine KATs from NIST/RFC sources (AES-GCM McGrew & Viega, HMAC RFC 4231, Ed25519 RFC 8032, AES-KW RFC 3394, RSA-OAEP/PSS, ECDSA P-256, ECDH P-256) re-run against three real backends with the deterministic direction correctly chosen for randomized schemes; independent BCL cross-verification for RSA, ECDSA (correctly asserting `IeeeP1363FixedFieldConcatenation`), DSA and ML-DSA; thorough AEAD negatives (tampered tag, tampered ciphertext, wrong AAD, wrong nonce). **No timing-dependent test exists anywhere** — zero hits for `Thread.Sleep`/`Task.Delay`/`Stopwatch`/`SpinWait` across the suite; concurrency tests use barriers and latches. Assertion mix is healthy (1493 `Assert.Equal` versus 50 `Assert.NotNull`). `Unit/TestCollectionConventionTests.cs` is exemplary, including an explicit anti-vacuity guard — and is the pattern BL-129 should be built on.
- **The fakes do not bypass parameter marshalling**, contrary to the usual concern: `ManagedSoftToken` reads the mechanism parameter block back out of unmanaged memory, so the GCM/CCM/ChaCha/RC2 param writers are genuinely exercised, and `FakeLowLevelPkcs11Library` throws on all ~110 members by default so a test cannot pass via an unimplemented call. What they do bypass is `LowLevelPkcs11Library`'s own struct-array marshalling and `_Windows` sibling dispatch — covered instead by the `*.Managed.cs` suites running on all six legs plus direct marshalling tests.
- **CI/publish hygiene is modern (re-verified 2026-08-11).** Every `uses:` in all four workflows is SHA-pinned with a version comment; `GITHUB_TOKEN` is least-privilege per job; `persist-credentials: false` everywhere; no `pull_request_target` anywhere; concurrency groups correctly asymmetric (cancel PRs, never cancel `main`); OIDC trusted publishing with build-provenance attestation; package source mapping; enforced `.editorconfig` + `dotnet format` gate; docfx pinned in `dotnet-tools.json`; analyzer release tracking (`AnalyzerReleases.Shipped/Unshipped.md`) correctly staged for all three diagnostic ids. Source integrity is good where it exists — the OpenSSL tarball is SHA-256 verified and the SoftHSM 2.5 `.deb`s come from content-addressed snapshot URLs with pinned digests and a post-extract version assertion.
- **Deliberately evaluated and not raised:** cache poisoning via the native/OpenSSL caches (GitHub cache scoping makes it require push access to `main`, at which point the workflow is writable); NuGet author signing (nuget.org repository-signs, and OIDC + provenance attestation is stronger); the unversioned `analyzers/dotnet/cs` folder (a `net10.0`-only package can only be consumed by Roslyn ≥ 4.14, so the 4.11-built analyzer cannot bite); `tests/AotSmoke` being outside the solution (cosmetic — the job still builds it); and the pack(1)-on-Unix ambiguity, which is inherent to PKCS#11 rather than a defect here (NSS applies `pragma pack(1)` unconditionally, so its view of `CK_TLS12_KEY_MAT_PARAMS` differs from the standard OASIS convention this library correctly follows; affects only SSL3/TLS12 key-material mechanisms, unreachable from any public API — worth a documented vendor-quirk note).
- **Deliberate design notes:** no async surface anywhere, which is the correct default for a synchronous P/Invoke wrapper — the real cancellation primitive is `C_SessionCancel` (BL-099), and a `Task`-returning façade would be worse; `CK_NOTIFY` is unsupported (BL-151); `[Experimental]` propagation is handled correctly where it applies (`SlhDsaPkcs11` re-declares `SYSLIB5006`); vendor extensibility is genuinely available via `VendorMechanismParameters` + `Mechanism`'s `ulong` constructors; XML-doc completeness is structurally enforced by `GenerateDocumentationFile` + `TreatWarningsAsErrors`, so CS1591 is a build error and no undocumented public member exists; and `LangVersion` is pinned to 13.0 while `CLAUDE.md` says `latest`.
