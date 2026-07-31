# Library Review Backlog

_Generated 2026-07-09 from a multi-specialist deep review (cryptography, PKCS#11 v3.2 conformance, .NET library design, P/Invoke, QA & release engineering). Nine specialists reviewed in parallel; findings were deduplicated, and every Critical/High citation was re-verified against the source by the coordinator._

## Summary

- Total items: 62 (23 resolved)
- Critical: 0 | High: 7 (3 open, 4 resolved) | Medium: 32 (22 open, 10 resolved) | Low: 23 (14 open, 9 resolved)
- Headline risks:
  - **The release pipeline cannot ship and the public surface is unguarded.** `publish.yml` fails by construction (no submodule checkout but solution-wide build/test), and there is no public-API snapshot, package validation, or API-diff gate — the #1-concern surface can drift silently.
  - **Real-HSM robustness gaps.** Vendor-defined return codes (spec-legal, common on real HSMs) escape the typed exception hierarchy as a bare `InvalidEnumValueException`; NUL-padded token labels (a ubiquitous vendor quirk) break label matching; a lying module's post-call `valueLen` is trusted, allowing an out-of-bounds unmanaged read.
  - **The highest-risk native code has no hermetic tests.** The function-list loader (version dispatch, pointer binding) is bypassed by every test fake, and the promised v2.40-only fallback path is never exercised by any CI backend.
  - **Flagship PQC mechanisms are verified only by self-round-trips on real backends** — no ACVP vectors, no independent cross-check, so a shared mis-encoding in sign+verify would pass green. _(Resolved 2026-07-09 — see BL-007.)_
- Release-readiness assessment: The foundations are unusually strong for a pre-1.0 library — the Windows Pack=1/`NativeCULong` marshalling scheme is complete, coherent, and CI-validated across six platforms; the native layer is fully quarantined behind an idiomatic, secure-by-default public API; zeroization and SafeHandle discipline are consistent; and v3.2 coverage at the interop layer is complete. No memory-corruption or key-leak defect was confirmed. What stands between this codebase and a confident 1.0 is not the crypto core but the release scaffolding (broken publish flow, no API-contract gate, no SECURITY.md, no versioning automation), a handful of real-token robustness fixes (vendor CKR, NUL padding, `valueLen` clamping), hermetic loader/back-compat test coverage, independent PQC verification, and a short list of public-API decisions (tuple return, enum naming, mechanism ownership, TFM strategy, strong naming, ECDH extraction gating) that are cheap now and breaking later. With the High items and the "Breaks public API? Yes" Mediums landed, this is a credible 1.0.

## Critical

_None. No memory-safety, key-leakage, or silent-data-corruption defect was confirmed at the P/Invoke boundary._

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

### [BL-013] `C_GetAttributeValue` read-back trusts the module's post-call `valueLen` without clamping to the allocated buffer
- **Area:** P/Invoke
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:986-1052`; `Objects/ObjectAttribute.cs:257-282`
- **Problem:** Buffers are sized from the first call's `valueLen`, but after the second call the wrapper reads back using whatever `valueLen` the module last wrote, unchecked. A buggy or hostile module that inflates `valueLen` on the second call causes an out-of-bounds read of adjacent unmanaged heap into the returned array (info disclosure / AV). The overflow-to-write variant is already blocked by `NativeCULong` checked casts; this is the in-range-but-oversized case.
- **Proposed action:** Record the allocated size per attribute and reject `valueLen > allocated` on read-back with a typed exception. Cheap defense-in-depth squarely within the "expect vendor quirks" mandate.
- **Breaks public API?** No
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

### [BL-015] `Pkcs11Session.Dispose` bypasses the busy-lock every operation acquires — close can race an in-flight native call
- **Area:** P/Invoke
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:796-827` (Dispose) vs `:269-284` (CloseSession)
- **Problem:** Every native operation and `CloseSession` acquire `AcquireExclusive()`, but `Dispose` does not, and P/Invokes pass the raw session id by value so SafeHandle ref-counting cannot protect them. A `Dispose` racing an in-flight `Sign`/`Encrypt` on another thread lets `C_CloseSession` run concurrently with an active call on the same session — UB at the boundary. `_disposed` is also a plain non-volatile bool written outside the lock.
- **Proposed action:** Acquire `AcquireExclusive()` in `Dispose(true)` before releasing the handle (mirroring `CloseSession`); make `_disposed` visibility-safe.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist B

### [BL-016] `SupportsMechanism` issues native calls and mutates cached state without the concurrency guard
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

### [BL-018] Wrap-hardening attributes (`CKA_WRAP_WITH_TRUSTED`, `CKA_TRUSTED`, `CKA_WRAP_TEMPLATE`/`CKA_UNWRAP_TEMPLATE`) have no first-class template-builder support
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

### [BL-026] No assembly-level test-parallelization policy around the process-global native module
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

### [BL-036] No CodeQL SAST workflow
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

### [BL-037] No automated versioning source — the version exists only as a tag stamp
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` (`<Version>0.0.0</Version>`); `.github/workflows/publish.yml:29-30`
- **Problem:** No MinVer/Nerdbank.GitVersioning; CI and local builds always produce 0.0.0; nothing verifies a publish tag is on `main`, annotated, or intentional before pushing to an immutable package ID.
- **Proposed action:** Adopt MinVer (or NBGV) so every build derives a deterministic version from git, and guard publish on the tag being reachable from `main`.
- **Breaks public API?** No
- **Raised by:** QA C

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

### [BL-050] `CloseWhenDisposed = false` does not actually keep the session open
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

## PKCS#11 v3.2 Coverage Matrix

Condensed from PKCS#11 Specialist A, who cross-checked `CK_FUNCTION_LIST_3_0`/`_3_2`, `CK_INTERFACE`, and `CK_ASYNC_DATA` field-by-field against the vendored v3.2 header (`vendor/opencryptoki/usr/include/pkcs11types.h`) — exact match, including the 12 v3.2 additions in declaration order. **No v3.2 `C_*` function is missing at the interop layer.**

| Function group | Low-level (P/Invoke) | High-level (public façade) |
|---|---|---|
| v2.40 general / slot / token (`C_Initialize` … `C_WaitForSlotEvent`) | ✅ | ✅ |
| v2.40 session / PIN / login (`C_OpenSession` … `C_Logout`) | ✅ | ✅ |
| v2.40 object / attribute (`C_CreateObject` … `C_FindObjectsFinal`) | ✅ | ✅ |
| v2.40 crypto (single/multi-part, SignRecover/VerifyRecover, dual-function) | ✅ | ✅ (dual-function combos low-level only) |
| v2.40 key management / RNG | ✅ | ✅ |
| v2.40 legacy (`C_GetFunctionStatus`, `C_CancelFunction`) | ✅ | low-level only (legacy no-ops) |
| v3.0 interfaces / login / cancel (`C_GetInterfaceList`, `C_GetInterface`, `C_LoginUser`, `C_SessionCancel`) | ✅ | ✅ |
| v3.0 message-based AEAD (`C_MessageEncryptInit` family + Decrypt/Sign/Verify) | ✅ | ✅ |
| v3.2 KEM (`C_EncapsulateKey`, `C_DecapsulateKey`) | ✅ | ✅ |
| v3.2 verify-signature streaming (`C_VerifySignature*`) | ✅ | ❌ — BL-019 |
| v3.2 authenticated wrap (`C_WrapKeyAuthenticated`, `C_UnwrapKeyAuthenticated`) | ✅ | ❌ — BL-019 |
| v3.2 async (`C_AsyncComplete`, `C_AsyncGetID`, `C_AsyncJoin`) | ✅ | ❌ — BL-019 |
| v3.2 validation (`C_GetSessionValidationFlags`) | ✅ | ❌ — BL-019 |

Mechanisms (`CKM`, 480 members): RSA (PSS/OAEP), EC/EdDSA/Montgomery, AES (GCM/CCM/CTR/KW/message), ChaCha20/Salsa20/Poly1305, ML-DSA/ML-KEM/SLH-DSA, HSS/LMS, SHA-2/-3/SHAKE, HMAC, KDFs, legacy `[Obsolete]`-gated — comprehensive, spot-checked constant values correct, raw-`ulong` vendor escape hatch present. Attributes (`CKA`, 160 members): all v3.2 additions present (trust, validation, profile, HSS, parameter-set, encapsulate/decapsulate templates); `CKO_PROFILE`/`VALIDATION`/`TRUST` defined but have no dedicated template builders (GenericTemplateBuilder suffices). Return codes (`CKR`, 105 members): all v3.2 additions present; vendor-code handling gap is BL-003.

## Appendix A — Unverified / Speculative

- **KEM/authenticated-unwrap secure-defaults application** (Cryptographer B): whether `EncapsulateKey`/`DecapsulateKey` and `UnwrapKeyAuthenticated` call `BuildSecureKeyDefaults` like `UnwrapKey`/`DeriveKey` do — a shared comment claims so, but the reviewer read only the latter two call sites in full. Confirm before 1.0.
- **GitHub repository settings** (QA C): branch protections, required status checks, tag protection, Environment approvals, and Private Vulnerability Reporting enablement are not verifiable from the repo — confirm in Settings.

## Appendix B — Out of Scope Observations

Positive findings worth preserving (multiple specialists, independently):

- **The Windows packing scheme is complete and coherent.** `CK_FUNCTION_LIST` (whose natural alignment would shift every pointer by 6 bytes on Win64) is `[PackedForPkcs11]`; every mechanism/attribute-bearing entry point has unified + `_Windows` function pointers bound from the same slot with matching dispatch branches; every raw param struct carries the attribute; `EnsureCkUlongWidthMatchesPlatform` fails loud on a mis-resolved `NativeCULong` asset instead of corrupting memory. Parameter struct layouts and CKM constants were verified against the vendored v3.2 headers.
- **`[InlineArray]` structs marshal correctly** (verified 2026-07-29, was Appendix A). Runtime marshalling expands `CkChar16/32/64` and `CK_DATE`'s `Char4`/`Char2` rather than seeing a single field: `Marshal.SizeOf<CK_INFO>()` is 88 on LP64 — matching both the C ABI and `Unsafe.SizeOf` — which is what `MarshalSizeOfTests` already pins (88 / 112 / 208 for `CK_INFO` / `CK_SLOT_INFO` / `CK_TOKEN_INFO`). Production reads still pass these by direct blittable pointer (`C_GetInfo` takes `ref CK_INFO`), but the `Marshal` path is covered too: `Pkcs11MarshalTests` round-trips `CK_INFO` through `WriteStructure`/`ReadStructure`, asserting `ManufacturerId[0]` **and** `[31]` — the latter is what proves all 32 bytes survive rather than just the first element. The remaining risk is durability, not correctness (InlineArray marshalling may be implementation detail rather than contract); the per-platform size census is the standing guard if runtime behavior ever shifts.
- **Integer overflow at the length boundary is handled by design:** `CheckForOverflowUnderflow` + `NativeCULong`'s `operator checked int` route every length cast through a throwing conversion.
- **The native interop layer is fully quarantined** — every type under `Native/` is `internal`; no raw `IntPtr`, `delegate*`, or `CK_*` type appears on the public surface.
- **AOT/trim posture is sound:** `[assembly: DisableRuntimeMarshalling]`, `delegate* unmanaged[Cdecl]` dispatch, generator-emitted `typeof` chains with no reflection, `IsAotCompatible` + analyzers, CI AOT smoke job.
- **Zeroization and SafeHandle discipline are consistent:** unmanaged buffers zeroized on free; `SecurePin`/`SecureBuffer` pinned, zeroed, and `ToString()`-redacted; no log statement formats key/PIN/plaintext material (verified by grep); sessions closed before `C_Finalize`; `Pkcs11SessionHandle` keeps the module reachable; `C_Initialize` probes `CKF_OS_LOCKING_OK` with `CKR_CANT_LOCK` fallback.
- **Secure-by-default is consistently enforced** in key-producing operations via `BuildSecureKeyDefaults` (sensitive/non-extractable appended, explicit insecure values refused without `AllowInsecure`); template builders default correctly; verification is delegated to the token with `CKR_SIGNATURE_INVALID → false` mapping and no managed-side secret comparisons.
- **PQC handling is unusually careful:** ML-DSA pre-hash/SHAKE arms refused with accurate FIPS 204 domain-separation reasoning rather than emitting non-interoperable signatures; ML-KEM probes and caches the `CKA_VALUE_LEN` token quirk.
- **The test suite is mature where it covers:** ~90 struct sizes pinned per-platform with a reflection census over the packed siblings; strong classical KATs (NIST/RFC vectors) on two real backends, capability-gated; AEAD negative tests assert exact CKRs; thread-safety tests are gate-based, not sleep-based; assertions check exact bytes/handles.
- **CI/publish hygiene is modern:** OIDC trusted publishing (no long-lived NuGet key), build-provenance attestation, SHA-pinned actions with least-privilege permissions, `persist-credentials: false`, commit-pinned submodules, enforced `.editorconfig` + `dotnet format` gate, package source mapping.
- **Deliberate design notes:** no async surface anywhere (defensible for a blocking C API — document the stance); digest/HMAC façades buffer entire inputs in unzeroized `MemoryStream`s (memory growth + lingering message bytes; no public incremental multi-part sign/digest API); `WaitForSlotEvent` should document the spec's single-caller-thread expectation; `LangVersion` is pinned to 13.0 while CLAUDE.md says `latest`.
