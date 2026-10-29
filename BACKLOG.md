# Library Review Backlog

_Generated 2026-07-09 and extended 2026-08-11 by two multi-specialist reviews (cryptography, PKCS#11 v3.2 conformance, .NET library design and P/Invoke, QA and release engineering), then re-verified against `main` by staleness passes on 2026-09-15 and 2026-10-27. This file lists open items only: on 2026-10-27 the 88 resolved items were removed to keep it readable. Their records, and any reference below to an ID no longer listed here, are in the git history; commit 6ecb5d70 is the last to hold them all. A partly resolved item stays, with a `Remaining scope` line for what is left._

## Summary

- Open items: 93, 23 of them partly resolved. Item IDs keep their numbering, so gaps are resolved items.
- Critical: 0 | High: 8 (1 partly resolved) | Medium: 47 (14 partly resolved) | Low: 38 (8 partly resolved; includes the Info entry BL-158)
- Headline risks:
  - **The advertised streaming surface does not exist.** No multi-part or streaming operation is reachable from the public API, and multi-part *sign* is not implemented at any layer: `C_SignUpdate`/`C_SignFinal`/`C_SignRecover` have zero callers outside `Native/` while their encrypt/digest/verify counterparts all have wrappers. A consumer cannot sign or encrypt a payload larger than memory (BL-087, BL-099).
  - **Only one session per slot is usable.** The second `OpenSession` on a slot throws `CKR_USER_ALREADY_LOGGED_IN`, and disposing either session logs the other out (BL-084).
  - **The public surface is narrower than the module's.** There is no capability probe for the v3.0 message API or the v3.2 functions (BL-077), read-only sessions and write-protected tokens are unreachable (BL-079), `CKA_ALWAYS_AUTHENTICATE` re-authentication is unimplemented (BL-081), and the v3.0 and v3.2 functions bound at the interop layer have no public caller (BL-019, BL-099).
  - **Roughly half the test suite cannot fail.** About half the test attributes are gated, the `PKCS11_TEST_EXPECT_*` guards check only backend *presence* and never mechanism availability, and no CI step counts skips, so a degraded OpenSSL 3.5 step would skip every ML-DSA/ML-KEM test with CI still green (BL-086, BL-129).
- Release-readiness assessment: The core is unusually strong for a pre-1.0 library: the Windows `Pack=1`/`NativeCULong` scheme is complete and correct on all six RIDs, every PKCS#11 constant value matches the vendored headers, `CK_FUNCTION_LIST_3_2` field order is exact, no managed↔native parameter-struct layout defect exists, and PIN handling, logging and exception messages leak nothing (Appendix B). **No Critical was confirmed.** What stands between the library and a confident 1.0 is *completeness*, concentrated where SemVer makes the surface permanent: the 8 open High items, which are the one-session-per-slot limit (BL-084), the narrow session-opening and capability surface (BL-077, BL-079, BL-081), the missing streaming surface (BL-087), the publish workflow (BL-001), package validation (BL-002, waiting for 1.0.0), and the test-gate census (BL-086). The census should land early, because it is what will tell you whether the rest of the suite is really green.

## Critical

_None. No memory-safety, key-leakage, or silent-data-corruption defect was confirmed at the P/Invoke boundary in either review round. The three findings that came closest (BL-070, BL-075, BL-080) are resolved._

## High

### [BL-001] Publish workflow cannot succeed: no submodules, but solution-wide build/test triggers native vendor builds
- **Area:** Release Eng
- **Severity:** High
- **Effort:** S
- **Location:** `.github/workflows/publish.yml:25-44` (checkout without `submodules:` at `:25-28`, `dotnet build KerckhoffsLabs.sln` at `:42`, `dotnet test --solution` at `:44`); the native targets in `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj:81` (`BuildPkcs11Mock`), `:98` (`BuildAbiOracle`), `:111` (`BuildPkcs11Gate`) and `:118` (`BuildSoftHsmV2`) run unless a `Skip*` switch, or the `SkipNativeBuilds=true` master switch at `:66-79`, is set
- **Problem:** The publish job checks out without `submodules:` yet runs `dotnet build`/`dotnet test` on the full solution. Building the test project fires the `BuildPkcs11Mock`/`BuildSoftHsmV2` targets (`src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj:36,49`, gated only on unset `Skip*` properties) against uninitialized `vendor/` directories with no native toolchain installed. A `v*` tag push can never reach the pack/push steps. Verified by the coordinator.
- **Proposed action:** Build and pack only the shippable library project in `publish.yml` (release gating stays in `ci.yml`), or add `submodules: recursive` plus the native deps and cache. The dedicated release build of just `KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` is the cleaner fix.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-002] ⚠️ PARTIALLY RESOLVED — No public-API contract gate: no PublicApiAnalyzers, no API snapshot test, no package validation
- **Status:** Partially resolved 2026-10-07 (#37). `Microsoft.CodeAnalysis.PublicApiAnalyzers` is referenced as a private asset, and every public member is declared in a checked-in `PublicAPI.Unshipped.txt`, generated by the analyzer's own code fix. `PublicAPI.Shipped.txt` stays empty until 1.0.0. An undeclared new member (RS0016) or a declared member that disappears (RS0017) fails the build, so every surface change shows up as a text diff in the PR. `PublicSurfaceDependencyTests.NoPublicApiMember_ExposesAMarshallingLayerType` additionally refuses any public signature that exposes a pointer, `IntPtr`, `SafeHandle` or a `Native`/`Internal`/interop-package type.
- **Area:** Cross-cutting
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj:67` (`Microsoft.CodeAnalysis.PublicApiAnalyzers`), with `PublicAPI.Shipped.txt`/`PublicAPI.Unshipped.txt` beside it; no `EnablePackageValidation` anywhere
- **Problem:** Nothing fails a build or PR when the public surface changes. For a library whose stated #1 concern is that public-surface mistakes are permanent under SemVer, an accidental `public`, a widened signature, or a dropped overload ships silently. This also leaves the `NativeCULong` per-RID asset layout unguarded across releases.
- **Remaining scope:** `EnablePackageValidation` with a 1.0.0 baseline, which is also what would guard the packaged asset layout (including `NativeCULong`'s per-RID assets) across releases. Per the proposed action, this lands once 1.0.0 ships.
- **Proposed action:** Add `Microsoft.CodeAnalysis.PublicApiAnalyzers` with checked-in `Shipped`/`Unshipped` files (every PR then carries a reviewable surface diff), and/or a PublicApiGenerator golden-file test. Enable `Microsoft.DotNet.PackageValidation` with a baseline once 1.0.0 ships. Must land before 1.0 so the 1.0 surface is the frozen baseline.
- **Breaks public API?** No
- **Raised by:** QA A, QA C, .NET Engineer A, .NET Engineer B

### [BL-077] No public capability probe: a consumer cannot ask whether the module supports the v3.0 message API or the v3.2 surface
- **Area:** .NET API Design
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs:128` (`IsMessageApiSupported`), `:164` (`IsV32ApiSupported`); carried by the **internal** session at `Internal/Pkcs11SessionCore.Encryption.cs:189` (`SupportsMessageApi`) and `Internal/Pkcs11SessionCore.Pkcs11V32.cs:18-19` (`SupportsV32Api`); the only public carrier is `Pkcs11Key.cs:624` (`SupportsMessageApi`). The module's claimed version is answered by `Pkcs11Library.SupportsCryptokiVersion(Version)` (`Pkcs11Library.cs:359`, BL-068), which is explicitly not a bound-function probe
- **Problem:** The library computes exactly the right capability facts but every carrier is internal. `Pkcs11Key.SupportsMessageApi` is the only capability property that reaches consumers, and there is no v3.2 equivalent — so a consumer calling the public `Pkcs11Key.EncapsulateKey` against a v3.0 token can only discover the module's limits by catching `Pkcs11Exception` with `CKR_FUNCTION_NOT_SUPPORTED`. Combined with BL-068 there is no non-exceptional way to write version-adaptive code, which is the library's headline promise. Verified by the coordinator.
- **Proposed action:** Surface `SupportsMessageApi`/`SupportsV32Api` — or a single `Pkcs11Capabilities` record carrying them alongside the negotiated interface version — on `Pkcs11Session` and/or `Pkcs11Library`. Purely additive.
- **Breaks public API?** No — additive, though the shape of the capability type is a pre-1.0 decision
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** Distinct from BL-019: that covers the v3.2 *methods* being unreachable, this the support *predicate*, which stays unreachable even after BL-019 lands

### [BL-079] The public session-opening surface is too narrow: read-only sessions are unreachable, write-protected tokens unusable, and slots addressable only by a possibly-ambiguous label
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Slot.cs:230` (`internal Pkcs11SessionCore OpenSessionCore(bool readWrite = true, ICryptoPolicy? policy = null)`); the three public factories, all label-only and all read-write, at `Pkcs11Library.cs:558` (`OpenSessionWithPin`), `:594` (`OpenSessionWithPinpad`), `:627` (`OpenSessionWithoutLogin`); `MatchSlotByLabel` at `:644-648`
- **Problem:** Three defects in one surface, all verified by the coordinator. (a) `readWrite` exists and is honoured but `OpenSessionCore` is `internal` and neither public factory exposes it, so consumers always get `CKF_SERIAL_SESSION | CKF_RW_SESSION`; a read-only workload cannot get the token-enforced guarantee that a bug cannot create or destroy token objects. (b) Against a write-protected token — the normal state of read-only signing and certificate tokens — `C_OpenSession` with `CKF_RW_SESSION` returns `CKR_TOKEN_WRITE_PROTECTED`, so the library is wholly unusable there; the fixtures already know write-protected tokens are real (`Support/Fixtures/NssBackendFixture.cs:59`). (c) Both factories take a *token label string*, so a caller who enumerated slots via `GetSlotList()` and holds a `Pkcs11Slot`/`SlotId` must round-trip through a label — and `MatchSlotByLabel` uses `FirstOrDefault` over a case-sensitive `TrimEnd()` comparison, so two tokens sharing a label (permitted, and easy to produce on SoftHSM) silently resolve to whichever enumerates first, an unlabelled token is reachable only via `""`, and the environment condition "no such token" surfaces as `ArgumentException`.
- **Proposed action:** Add `Pkcs11Slot.OpenSession(CKU, SecurePin, bool readWrite = true)` / `OpenSessionWithoutLogin(bool readWrite = true)` (or `Pkcs11Library.OpenSession(SlotId, …)`), surface `readWrite` on the label-based overloads, and throw a typed `Pkcs11TokenException` rather than `ArgumentException` when no token matches.
- **Breaks public API?** No — additive, except the `ArgumentException` → `Pkcs11TokenException` change, which is behavioural and should land before 1.0
- **Raised by:** PKCS#11 Specialist B, .NET Engineer A
- **Spec / References:** PKCS#11 v3.2 §5.6.1 (`C_OpenSession`), §4.4 (read-only session object restrictions); `CKR_TOKEN_WRITE_PROTECTED`

### [BL-081] `CKA_ALWAYS_AUTHENTICATE` / `CKU_CONTEXT_SPECIFIC` re-authentication is unimplemented, and the session lock structurally prevents it
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKA.cs:344` (referenced elsewhere only by the log-printing flag set at `Objects/ObjectAttribute.cs:424`); `Common/CKU.cs:21` (used only by `Internal/Log.cs:107`); `Internal/Pkcs11SessionCore.Session.cs:147` (`Login` is internal and takes `AcquireExclusive()`); `Pkcs11Library.cs:558-573` (`OpenSessionWithPin` accepts `CKU_CONTEXT_SPECIFIC` unchecked)
- **Problem:** A private key with `CKA_ALWAYS_AUTHENTICATE = CK_TRUE` requires `C_Login(hSession, CKU_CONTEXT_SPECIFIC, …)` *between* `C_SignInit`/`C_DecryptInit` and `C_Sign`/`C_Decrypt`. `Pkcs11Key.Sign` runs init and operate as one exclusive-locked unit with no seam, and `Pkcs11SessionCore.Login` is internal and itself takes the exclusive lock, so even an internal caller could not re-authenticate mid-operation. Signing or decrypting with such a key — the default posture for signing keys on FIPS-mode HSMs and on PIV/eID cards — therefore fails with `CKR_USER_NOT_LOGGED_IN`. Separately, `OpenSession(slotLabel, CKU.CKU_CONTEXT_SPECIFIC, pin)` is accepted by the public signature although it can never be valid on a freshly opened session. Verified by the coordinator: `CKA.cs:346` is the only occurrence of the attribute in the library.
- **Proposed action:** Add a context-specific re-auth path — an optional `SecurePin contextPin` or `Func<SecurePin>` callback on `Pkcs11Key.Sign`/`Decrypt` issuing `C_Login(CKU_CONTEXT_SPECIFIC)` inside the already-held lock between init and operate. Document `CKA_ALWAYS_AUTHENTICATE` in the private-key template builder, and reject `CKU_CONTEXT_SPECIFIC` in `OpenSession` with `ArgumentException`.
- **Breaks public API?** No — additive overloads
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** PKCS#11 v3.2 §4.9 (`CKA_ALWAYS_AUTHENTICATE`), §5.6.6 `C_Login`

### [BL-084] Only one session per slot is usable: the second `OpenSession` throws `CKR_USER_ALREADY_LOGGED_IN`, and disposing either logs the other out
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Library.cs:558-573` (unconditional `session.Login` at `:567`; likewise `:594-602` for the pinpad); `Pkcs11Session.cs:112-133` (`Dispose` → `_core.LogoutForDispose()` at `:125`); the guidance being contradicted is at `Internal/Pkcs11SessionCore.cs:137-140`; mapping at `Internal/ExceptionMapper.cs:29`
- **Problem:** The session busy-guard's own error message instructs callers to "Use a separate Session per thread", but the only public way to obtain a session is `OpenSession`, which always calls `C_Login` and ends in `Pkcs11Exception.ThrowIfError` with no tolerance for an already-logged-in state. PKCS#11 login state is per-application-per-token, so a second `OpenSession` on the same slot returns `CKR_USER_ALREADY_LOGGED_IN`, which `Internal/ExceptionMapper.cs:29` maps to `Pkcs11AuthenticationException`. Symmetrically, `Pkcs11Session.Dispose` issues `C_Logout`, de-authenticating *every* other session on that slot — the doc comment acknowledges the token-wide effect and calls it intended, which it cannot be once more than one session exists. The concurrency model the library documents is therefore unreachable, and there is no session pooling. No test opens two concurrent sessions, and `Integration/ThreadSafety/SessionParallelTests.Pkcs11Mock.cs:19-21` states outright that real cross-session parallelism is not exercised. Verified by the coordinator.
- **Proposed action:** Tolerate `CKR_USER_ALREADY_LOGGED_IN` in `OpenSession` as success; track a per-slot session count and skip `C_Logout` unless this is the last session on the slot; add a multi-session test against SoftHSM2 (`ulMaxSessionCount > 1`).
- **Breaks public API?** No — behavioural fix
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** PKCS#11 v3.2 §5.6 (login state shared across an application's sessions with a token), §5.6.9 `C_Logout`

### [BL-086] Roughly half the suite is behind runtime gates and CI has no guard against a mass silent skip
- **Area:** QA
- **Severity:** High
- **Effort:** M
- **Location:** `.github/workflows/ci.yml:307`, `:335`, `:546` (all three `dotnet test` invocations; console output only, no `.trx`, no skip baseline); gates at `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/IPkcs11Backend.cs:63-71`; the `PKCS11_TEST_EXPECT_*` checks (`Integration/Smoke/*AvailabilityTests.cs`) still assert backend presence only
- **Problem:** 1005 of ~2060 test attributes are `[Fact]`/`[Theory]` with `SkipUnless`/`SkipWhen` (`ConditionalFact`/`ConditionalTheory` before the xUnit v3 migration — see BL-135), plus 46 in-body `Assert.Skip` calls (`SkipTestException` before that same migration). The three `PKCS11_TEST_EXPECT_*` guards assert *backend presence* only — never *mechanism* availability. `SupportsMlDsa`/`MlKem`/`SlhDsa` key on the advertised `C_GetMechanismList` (SoftHSM's `WITH_ML_DSA`/`WITH_ML_KEM` build flags gate the mechanism's entry into its own mechanism list, so this is accurate today), but nothing stops the *entire* mechanism list from coming back empty or truncated if the from-source OpenSSL 3.5 step degrades or the token init silently fails — every ML-DSA/ML-KEM test would skip and CI would still report green. All three test steps use plain console output only: no `.trx`, no skipped count, no minimum-executed floor. This is the systemic gap that allowed BL-053 to exist and would hide the next one.
- **Proposed action:** Emit a `.trx` report (e.g. `Microsoft.Testing.Extensions.TrxReport` + `dotnet test --report-trx`) and add a CI step that fails when the skipped count exceeds a checked-in per-leg baseline, or when total executed drops below a floor — MTP's own `--minimum-expected-tests`/`--zero-tests-policy strict` cover part of this natively. Add `PKCS11_TEST_EXPECT_MLDSA`/`_MLKEM`-style declarations mirroring the existing backend-availability guards so a lost PQC capability fails rather than skips.
- **Breaks public API?** No
- **Raised by:** QA B, QA A

### [BL-087] No multi-part or streaming operation is publicly reachable, and multi-part **sign** is not implemented at all — the coverage matrix overstates both
- **Area:** Cross-cutting
- **Severity:** High
- **Effort:** L
- **Location:** Public surface: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs:466` (`Sign`), `:490` (`Verify`), `:576` (`Encrypt`), `:606` (`Decrypt`), all one-shot, plus `Pkcs11Session.Digest`. Internal stream paths with no public route in `Internal/Pkcs11SessionCore.Encryption.cs`, `.Digesting.cs` and `.Signing.cs`. Bound but uncalled: `C_SignUpdate`, `C_SignFinal`, `C_SignRecover` (`Native/LowLevelPkcs11Library.SigningAndMacing.cs`), `C_SignEncryptUpdate` (`.DualFunction.cs`), and the message sign/verify families (`.MessageSigning.cs`, `.MessageVerifying.cs`)
- **Problem:** Every `*_Update`/`*_Final` path — `Encrypt(Stream)`, `Decrypt(Stream)`, `Digest(Stream)`, `Verify(Stream)`, `DigestEncrypt`, `DecryptDigest`, `DecryptVerify`, `VerifySignature(Stream)` — lives on the `internal` `Pkcs11SessionCore`, so all of it, including the `TryCancelOperation` unwind logic, is unreachable by consumers. Worse, the sign side is not merely unexposed: **the coordinator verified by grep that `C_SignUpdate`, `C_SignFinal` and `C_SignRecover` have zero callers anywhere in `Internal/`, `Algorithms/`, `Objects/` or the root types, while `C_EncryptUpdate` (×2), `C_DigestUpdate` (×1) and `C_VerifyUpdate` (×1) all do have callers in `Internal/Pkcs11SessionCore.cs`; and `grep Stream` over `Pkcs11Key.cs` and `Pkcs11Session.cs` returns nothing at all.** Consequently the coverage-matrix rows for v2.40 multi-part crypto and v3.0 message-based sign/verify were both wrong before this review (corrected below), and BL-019's stated scope understates the gap. Practical consequence: a consumer cannot sign or encrypt a payload larger than memory, and the span overloads copy, so peak footprint is 2× the payload.
- **Proposed action:** Add multi-part sign to `Pkcs11SessionCore` (`C_SignInit`/`C_SignUpdate`/`C_SignFinal` with the same `finalized` + `TryCancelOperation` unwind shape as `Verify(Stream)`), then expose `Stream` overloads for Sign/Verify/Encrypt/Decrypt/Digest on `Pkcs11Key`/`Pkcs11Session`. Decide and document explicitly whether `C_SignRecover`, `C_SignEncryptUpdate` and message-based sign/verify are in scope for 1.0.
- **Breaks public API?** No — additive, but the shape of the streaming surface is a pre-1.0 decision
- **Raised by:** PKCS#11 Specialist B, PKCS#11 Specialist A
- **Spec / References:** PKCS#11 v3.2 §5.12 (`C_SignUpdate`/`C_SignFinal`), §5.13.5 (`C_SignRecover`), §5.20 (message-based). Extends BL-019

## Medium

### [BL-009] C-style ALL_CAPS enum members and 2–3 letter type names must be a conscious, documented pre-1.0 decision
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S (decision + docs; L if renamed)
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKM.cs:7`, `Common/CKA.cs:6`, `Common/CKR.cs:6`, `Common/CKO.cs:6`, `Common/CKK.cs:6` and their siblings (24 public types in `Common/`)
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

### [BL-014] Fixed-length token strings NUL-padded by real tokens are not trimmed, breaking label matching
- **Area:** P/Invoke
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/TokenInfo.cs:76-79` and `:95` (`UtcTime`), `SlotInfo.cs:34-35`, `LibraryInfo.cs:37,39` (argless `TrimEnd()`, so NULs survive), `Pkcs11Library.cs:646` (label match); attribute strings already use `TrimEnd('\0')` (`Objects/ObjectAttribute.cs:294`, `Native/ObjectIdentityReader.cs:89`)
- **Problem:** CK_UTF8CHAR fields are decoded with argless `TrimEnd()`, which strips whitespace but not `'\0'`. The spec mandates space padding but many real tokens NUL-pad; a NUL-padded label decodes to `"mytoken\0\0…"`, the token-by-label lookup silently fails, and every info string carries embedded NULs.
- **Proposed action:** Truncate at the first `'\0'` or use `TrimEnd(' ', '\0')` across all fixed-length string decodes.
- **Breaks public API?** No
- **Raised by:** .NET Engineer B
- **Spec / References:** PKCS#11 v3.1 §3.2 (blank-padded fields)

### [BL-019] v3.2 functions bound at the interop layer but unreachable from the public API (verify-signature, authenticated wrap, async, validation flags)
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CryptokiTable.cs:356-377` (bound); internal-only wrappers with no public caller at `Internal/Pkcs11SessionCore.Pkcs11V32.cs:191` (`WrapKeyAuthenticated`), `:232` (`UnwrapKeyAuthenticated`), `:286` and `:324` (`VerifySignature`), `:377` (`GetSessionValidationFlags`); no wrapper at all for the async functions
- **Problem:** `C_VerifySignature*`, `C_WrapKeyAuthenticated`/`C_UnwrapKeyAuthenticated`, `C_AsyncComplete`/`C_AsyncGetID`/`C_AsyncJoin`, and `C_GetSessionValidationFlags` are fully wired and gated but have no public wrapper, so consumers cannot use them without forking. (KEM and message-AEAD are exposed.)
- **Proposed action:** Add high-level wrappers for verify-signature streaming, authenticated wrap/unwrap, and validation-flags inspection; make an explicit, documented in/out-of-scope call on async for 1.0. Additive post-1.0, so not a release blocker — but decide deliberately.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** PKCS#11 v3.2 §5.16, §5.17, §5.20

### [BL-020] `InterfaceInfo` omits the interface version, defeating the point of interface enumeration
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/InterfaceInfo.cs:8-14` (`Name` and `InterfaceFlags` only); producers `Pkcs11Library.cs:417-441` (`GetInterfaces`) and `:458-472` (`GetInterface`)
- **Problem:** `GetInterfaces()` returns only `Name` + flags. The interface's cryptoki version sits in the `CK_VERSION` header of the function list the descriptor points to, but is never surfaced — a consumer cannot tell a token's 2.40 / 3.0 / 3.2 "PKCS 11" interfaces apart.
- **Proposed action:** Read the `CK_VERSION` from `CK_INTERFACE.FunctionList` and add a `Version` property. Additive.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist A

### [BL-022] net10.0-only targeting is a major reach cut with no documented rationale
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj:3-12` (the comment justifies `net10.0` only by `NativeCULong`; `<TargetFramework>` at `:12`); `README.md:44` ("Requires .NET 10.0 or later", no rationale)
- **Problem:** net8.0 (LTS through Nov 2026) and netstandard2.0 consumers are excluded entirely. The csproj comment justifies net10 via the `NativeCULong` RID assets, but the real blocker is the net10 BCL PQC types (`MLDsa`, `MLKem`, `SlhDsa`, `SP800108HmacCounterKdf`); neither the trade-off nor the rationale is stated anywhere a consumer sees.
- **Proposed action:** Either multi-target (net8.0 classical surface with `#if`-gated PQC façades) or explicitly document the net10-only decision and its PQC rationale in the README. Adding TFMs later is non-breaking, but the positioning decision belongs pre-1.0.
- **Breaks public API?** No
- **Raised by:** .NET Engineer A

### [BL-023] ⚠️ PARTIALLY RESOLVED — Windows consumers without a resolved RID asset hit a hard `PlatformNotSupportedException` at first load
- **Status:** Partially resolved 2026-10-06 (#52). The width guard's `PlatformNotSupportedException` no longer prescribes the removed `net10.0-windows` target framework. It says the runtime-specific KerckhoffsLabs.Runtime.InteropServices assembly was not loaded, and lists the causes a consumer can act on: the `.deps.json` not deployed, restore or publish without a `RuntimeIdentifier`, or a pre-1.2.0 or overriding package version. Pinned by a `LowLevelPkcs11LibraryCoreTests` case.
- **Area:** P/Invoke
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs:84-120` (`EnsureCkUlongWidthMatchesPlatform`, `ThrowIfWidthMismatch`); csproj comment `:3-11`. There is no `net10.0-windows` TFM since the InteropServices 1.2.0 bump, which ships the 4-byte build as `runtimes/win-x64` and `runtimes/win-arm64` assets
- **Problem:** Windows correctness depends on `NativeCULong` resolving its 4-byte per-RID asset. The width guard fails loudly instead of mis-marshalling (correct), but in AnyCPU/no-RID, single-file, or transitive-reference configurations the library is simply unusable on Windows at first load — a consumer trap with no guidance. (CI validates the packed path itself on win x64/x86/arm64.)
- **Remaining scope:** a Windows consumption guide in the README or docs (RID-specific restore and publish, single-file, transitive references), and a CI job that consumes the packed `.nupkg` from an app with no RuntimeIdentifier to prove the asset resolves as shipped.
- **Proposed action:** Ship a Windows consumption guide (RID-specific restore/publish) or a `net10.0-windows` TFM hard-referencing the 4-byte build, and add a CI job that consumes the packed .nupkg from a no-RID Windows app to prove asset resolution as shipped.
- **Breaks public API?** No
- **Raised by:** .NET Engineer B

### [BL-029] No fuzzing of the inbound marshalling layer
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Unit/Native/` (no SharpFuzz harness; CsCheck drives the BCL differential tests and FsCheck the algorithm laws of the `Algorithms` adapters, not this layer, whose coverage is example-based, e.g. `ReportedLengthTests`, `AttributeLengthClampTests`)
- **Problem:** The highest-risk direction — a buggy/hostile token controlling returned lengths in the two-call probe and attribute read-back — is covered only by example-based tests.
- **Proposed action:** Add a SharpFuzz harness over (1) `CK_ATTRIBUTE[]` template build/read-back and (2) length-probe read-back with adversarial `ulValueLen`. Pairs with BL-013.
- **Breaks public API?** No
- **Raised by:** QA B, Cryptographer B

### [BL-030] ⚠️ PARTIALLY RESOLVED — Docs site has no getting-started article; README now has a quickstart
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** M
- **Location:** `docs/toc.yml`, `docs/index.md`, `README.md`
- **Problem:** `toc.yml` has only Home + API; there is no getting-started or end-to-end flow (load → initialize → session → login → operate → dispose) anywhere, and the README contains no usage code at all.
- **Remaining scope:** The README now has a full end-to-end quickstart snippet (load → session → generate → sign → verify), so that half is resolved. `docs/toc.yml` still lists only Home/Diagnostics/API — there is still no getting-started walkthrough article on the docs site itself.
- **Proposed action:** Add a `docs/articles/` getting-started walkthrough wired into `toc.yml` (the README snippet can be reused as its basis).
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

### [BL-033] ⚠️ PARTIALLY RESOLVED — No CHANGELOG or GitHub Release / release-notes flow
- **Status:** Partially resolved 2026-10-19 (#215). A tag-triggered `release` job, separate from `publish` so `contents: write` is never held by the job that builds and tests, runs after the NuGet push succeeds. It creates the GitHub Release with GitHub-generated notes and attaches the attested `.nupkg`/`.snupkg`.
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** M
- **Location:** MISSING: `CHANGELOG.md`; `.github/workflows/publish.yml:84-110` (the `release` job, with GitHub-generated notes)
- **Problem:** Publishing pushes to NuGet with no per-version record of changes — especially important for a security library where gate/behavior changes matter.
- **Remaining scope:** a curated `CHANGELOG.md` (Keep a Changelog), or notes that call out behaviour and policy changes. The generated notes are a list of PR titles, which does not single out the security-relevant gate changes this entry is about.
- **Proposed action:** Adopt Keep-a-Changelog (or Conventional Commits-generated notes) and create a GitHub Release from the tag-triggered publish.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-034] ⚠️ PARTIALLY RESOLVED — `CONTRIBUTING.md` now exists but is content-free; CODE_OF_CONDUCT.md and issue/PR templates still missing
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `CONTRIBUTING.md` (exists, but documents none of the build — see BL-140); MISSING: `CODE_OF_CONDUCT.md`, `.github/ISSUE_TEMPLATE/`, `.github/pull_request_template.md` (still all verified absent)
- **Problem:** Contribution prerequisites here are non-trivial (submodules, from-source OpenSSL 3.5, format/warnings gates) and entirely undocumented; no triage structure exists.
- **Remaining scope:** `CONTRIBUTING.md` was added, closing the "doesn't exist at all" gap, but it covers none of the submodule/native-toolchain/formatting prerequisites (tracked in full under BL-140). `CODE_OF_CONDUCT.md` and the `.github/` issue/PR templates are still absent.
- **Proposed action:** Add `CODE_OF_CONDUCT.md` and issue/PR templates; fill in `CONTRIBUTING.md`'s build instructions per BL-140.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-035] No SBOM generated or attached at publish
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `.github/workflows/publish.yml:61-65` (provenance attestation over the `.nupkg`, `.snupkg` and packaged DLLs; no SBOM step, and the `release` job at `:84-110` attaches none)
- **Problem:** Supply-chain-conscious consumers increasingly require a CycloneDX/SPDX SBOM; provenance attestation alone doesn't provide the dependency graph.
- **Proposed action:** Generate a CycloneDX SBOM (dotnet tool or `Microsoft.Sbom.Targets`) during publish and attach it to the release; optionally attest it.
- **Breaks public API?** No
- **Raised by:** QA C, .NET Engineer B

### [BL-037] No automated versioning source — the version exists only as a tag stamp
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj:35` (`<Version>0.0.0</Version>`); `.github/workflows/publish.yml:37-38` (version derived from the tag); `--verify-tag` at `:110` checks only that the tag exists, not that it is reachable from `main`
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

### [BL-089] ⚠️ PARTIALLY RESOLVED — `TokenInfo` numeric properties hand back the platform-dependent `CK_UNAVAILABLE_INFORMATION` sentinel as a plain `ulong`
- **Status:** Partially resolved 2026-08-11 (b9e0f165, BL-067). `CK.IsCkInformationUnavailable` now takes a `ulong`, so it applies directly to these properties, and `CK.CK_UNAVAILABLE_INFORMATION` documents why it is `0xFFFFFFFF` on Windows and `0xFFFFFFFFFFFFFFFF` on 64-bit Unix.
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/TokenInfo.cs:30-57` (`MaxSessionCount`, `SessionCount`, `MaxRwSessionCount`, `RwSessionCount`, `MaxPinLen`, `MinPinLen` and the four memory properties); helper `Common/CK.cs:33` (`IsCkInformationUnavailable(ulong)`)
- **Problem:** PKCS#11 lets a token return `CK_UNAVAILABLE_INFORMATION` for any of these. The properties pass it through unmodified and are documented as plain counts, so a consumer sees `18446744073709551615` on Linux/macOS and `4294967295` on Windows for the same token. The one helper that recognises the sentinel, `CK.IsCkInformationUnavailable`, takes a `NativeCULong` and so cannot be applied to these `ulong` properties without the consumer constructing an interop type (see BL-067).
- **Remaining scope:** the ten `TokenInfo` counts (`TokenInfo.cs:30-57`) are still plain `ulong` documented as counts. Make them `ulong?`, or add `…Available` companions, and document the sentinel on each property. This is a property-type change and must land before 1.0.
- **Proposed action:** Type them `ulong?` (null when unavailable) or add `bool …Available` companions; either way document the sentinel explicitly.
- **Breaks public API?** Yes — property-type change; must land before 1.0
- **Raised by:** .NET Engineer A
- **Spec / References:** PKCS#11 v3.2 §3.2 `CK_TOKEN_INFO` / `CK_UNAVAILABLE_INFORMATION`

### [BL-090] The constants every call site needs (`CKM`, `CKA`, `CKU`, `CKK`, `CKR`) live in a secondary `Common` namespace
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/` — 24 public types, e.g. `Common/CKM.cs:7`, `Common/CKA.cs:6`, `Common/CKU.cs:6`, `Common/CKK.cs:6`, `Common/CKR.cs:6`; consumed by root-namespace signatures such as `Pkcs11Library.OpenSessionWithPin(…, CKU, …)` (`Pkcs11Library.cs:558`), the `Mechanism(CKM, …)` constructors and `Pkcs11Key.GetAttributeValue(params ReadOnlySpan<CKA>)`. The README quickstart shows the `…Pkcs11.Common` using (`README.md:56`), but the move-or-keep decision is still unrecorded
- **Problem:** No non-trivial program can be written with a single `using KerckhoffsLabs.Security.Cryptography.Pkcs11;` — logging in needs `CKU`, any mechanism needs `CKM`, any template needs `CKA`/`CKK`, and any error handling needs `CKR`, all of which sit under `…Pkcs11.Common`. "Common" is also precisely the non-descriptive grouping the guidelines warn against, and it splits types that are inseparable in use.
- **Proposed action:** Move the constant enums into the root `…Pkcs11` namespace, keeping `Objects`, `Algorithms`, `MechanismParams` and `Exceptions` as they are. If `Common` stays, document the required `using` pair prominently in the README quickstart.
- **Breaks public API?** Yes — namespace moves are SemVer-major; decide before 1.0
- **Raised by:** .NET Engineer A
- **Spec / References:** Framework Design Guidelines §3.2 (namespace naming). BL-009 covers member and type *naming*, not namespace placement

### [BL-092] `Pkcs11Key.IsAsymmetricKeyType` omits six asymmetric key types the library's own `CKK` enum declares, so the wrong handle is used
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs:919-924` (the predicate; call sites `:122`, `:241`, `:496`, `:581`, `:657`, `:707`); missing members at `Common/CKK.cs:21` (`CKK_DH`), `:36` (`CKK_X9_42_DH`), `:294` (`CKK_EC_MONTGOMERY`), `:319` (`CKK_HSS`), `:324` (`CKK_XMSS`), `:329` (`CKK_XMSSMT`)
- **Problem:** The predicate lists only RSA/DSA/EC/EC_EDWARDS/ML_KEM/ML_DSA/SLH_DSA. For an X25519/X448 (`CKK_EC_MONTGOMERY`), DH, or HSS/XMSS/XMSS^MT key pair it returns `false`, so `GetAttributeValue` (`Pkcs11Key.cs:126-128`), `Encrypt` (`:394`), `Wrap` (`:514`) and `MessageEncrypt` (`:464`) pick the **private** handle where they intend the public one. Concretely, a `CKA_EC_POINT` read on an X25519 key pair hits the private object and fails with `CKR_ATTRIBUTE_SENSITIVE` even though a readable public companion is attached — and HSS/XMSS are exactly the v3.1/v3.2 surface this library advertises.
- **Proposed action:** Add the six members, and re-derive the predicate from `CKA_CLASS` where available (the hydrated `objectClass` is already known at `Pkcs11Session.cs:638`). Add a unit test per key type asserting handle selection.
- **Breaks public API?** No — behavioural fix
- **Raised by:** .NET Engineer A, Cryptographer A
- **Spec / References:** PKCS#11 v3.0 §2.3.5 (`CKK_EC_MONTGOMERY`)

### [BL-095] `GetRSAPrivateKey()`/`GetECDsaPrivateKey()` mint a `Pkcs11Key` the caller can never reach or dispose
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/Pkcs11CertificateExtensions.cs:35-117` (seven getters since #240: `GetRSA`/`GetECDsa`/`GetDSA`/`GetECDiffieHellman`/`GetMLDsa`/`GetMLKem`/`GetSlhDsaPrivateKey`), all through `GetPrivateKey` (`:120-138`); ownership contract at `Algorithms/RSAPkcs11.cs:9`, `:33`, and the same in the other adapters
- **Problem:** The extensions call `certificate.TryOpenPrivateKey()` and hand the resulting `Pkcs11Key` to `new RSAPkcs11(key)`/`new ECDsaPkcs11(key)`, which explicitly "does not take ownership". The key is never returned to the caller, so `using var rsa = cert.GetRSAPrivateKey();` disposes the adapter and abandons the wrapper — the opposite of the BCL shape being mirrored, where disposing the returned `RSA` is necessary and sufficient.
- **Proposed action:** Add an internal `ownsKey` flag to the adapters (disposing the wrapped key when set) and use it from these two extension methods so the BCL ownership contract holds; document the borrowed-versus-owned distinction on the public constructors.
- **Breaks public API?** No
- **Raised by:** .NET Engineer A

### [BL-098] There is no mockable seam: every high-level type is sealed with an internal constructor and non-virtual members, contradicting the project's own design rule
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** L
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Session.cs:35,40`, `Pkcs11Key.cs:42,54`, `Pkcs11Slot.cs:16,54`, `Pkcs11Library.cs:23`, `Internal/Pkcs11SessionCore.cs:16` (`Native/ILowLevelPkcs11Library.cs` was deleted by #109; the library's own hermetic tests load fake modules through the real loader, `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fakes/Modules/`)
- **Problem:** A consumer writing a service that takes a `Pkcs11Key` cannot unit-test it without a real token or software module: the type is sealed, exposes no interface and no virtual members, and cannot be constructed (internal constructor, `InternalsVisibleTo` only for this repo's test assembly). The same holds for `Pkcs11Session` and `Pkcs11Slot`. The library gets its own hermetic tests through the `internal` `ILowLevelPkcs11Library`; consumers get nothing equivalent. This directly contradicts the project's stated design rule in `CLAUDE.md` — "Use **interfaces** and **dependency injection** to allow mocking and testing without real hardware."
- **Proposed action:** Extract narrow public interfaces for the consumer-facing operations (e.g. `IPkcs11Session`, `ISigningKey`/`IEncryptionKey` over `Pkcs11Key`) implemented by the sealed types, or ship a small `…Pkcs11.Testing` package with an in-memory backend.
- **Breaks public API?** No — additive, but the shape is much easier to get right before the types are locked
- **Raised by:** .NET Engineer A

### [BL-099] The v3.0 half of "bound at interop but publicly unreachable": `C_SessionCancel`, `C_LoginUser`, and the 14 message multi-part / message sign-verify functions
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** L
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11SessionCore.cs:522` (`CancelOperations`, internal), `Internal/Pkcs11SessionCore.Session.cs:191` (`LoginUser`, internal); the message multi-part and message sign/verify functions are bound in `Native/LowLevelPkcs11Library.MessageSigning.cs`, `.MessageVerifying.cs`, `.MessageEncryption.cs` and `.MessageDecryption.cs`, with no caller outside `Native/`
- **Problem:** Of the 36 v3.x functions, 10 are reachable publicly and 26 are not; BL-019 enumerates only the v3.2 members of that set, so the v3.0 members are unrecorded. Two are more than completeness items: `C_SessionCancel` is the spec's only way to abort a stuck or partially-fed operation without closing the session — and `Pkcs11SessionCore` already uses it internally for unwind — and `C_LoginUser` is the only login path for HSMs with named user accounts beyond SO/User.
- **Proposed action:** At minimum promote `CancelOperations(...)` and `LoginUser(...)` to `Pkcs11Session`; both are already implemented and guarded. Decide explicitly, and document, whether the message multi-part and message sign/verify families ship in 1.0 or are deferred.
- **Breaks public API?** No — additive
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** Extends BL-019 with the v3.0 half and concrete counts

### [BL-101] The public flag records omit five v3.x bits that `CKF` already defines
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismFlags.cs:118-121` (no `Encapsulate`/`Decapsulate`), `TokenFlags.cs:86-87` (no `ErrorState`/`AsyncSessionSupported`), `SessionFlags.cs:18-19` (no `AsyncSession`); the unused constants are at `Common/CKF.cs:116`, `:290`, `:295`, `:300`, `:305`
- **Problem:** `MechanismFlags` exposes every v2.40 and v3.0 mechanism flag but neither v3.2 addition, so a consumer of the public `Pkcs11Key.EncapsulateKey`/`DecapsulateKey` has no typed way to ask `C_GetMechanismInfo` whether the token supports encapsulation with a given mechanism. `TokenFlags` picked up `CKF_SEED_RANDOM_REQUIRED` but not `CKF_ERROR_STATE` (token in an error state — operationally important) or `CKF_ASYNC_SESSION_SUPPORTED`, and `SessionFlags` omits `CKF_ASYNC_SESSION`. The raw `Flags` value is public on each record, so this is discoverability rather than a hard block.
- **Proposed action:** Add `MechanismFlags.Encapsulate`/`Decapsulate`, `TokenFlags.ErrorState`/`AsyncSessionSupported` and `SessionFlags.AsyncSession`. Add a test asserting every `CKF_*` constant in the relevant category has a corresponding property, so the next spec revision cannot drift.
- **Breaks public API?** No — additive
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** `CKF_ENCAPSULATE` 0x10000000, `CKF_DECAPSULATE` 0x20000000, `CKF_ERROR_STATE` 0x01000000, `CKF_ASYNC_SESSION_SUPPORTED` 0x04000000, `CKF_ASYNC_SESSION` 0x00000008 — cross-checked against `vendor/nss/lib/util/pkcs11t.h:258-265,313`

### [BL-102] Token-side IV/nonce generation in the v3.0 message-AEAD params is hardcoded off, and the `CK_GENERATOR_FUNCTION` values do not exist in the library
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismParams/CkmGcmMessageParams.cs:64-65`; `MechanismParams/CkmCcmMessageParams.cs:74-75`; `Common/CKG.cs` contains only the nine `CKG_MGF1_*` values
- **Problem:** The message-based AEAD API's `ivGenerator`/`nonceGenerator` field exists precisely so the *token* can produce non-repeating GCM/CCM IVs, removing the application's ability to reuse a nonce — the one catastrophic misuse of AES-GCM. Both public params types pin it to `CKG_NO_GENERATE` with no way to change it and never read the IV back, so `AesGcmPkcs11.Encrypt` always requires a caller-supplied nonce. `CKG_NO_GENERATE`/`CKG_GENERATE`/`CKG_GENERATE_COUNTER`/`CKG_GENERATE_RANDOM`/`CKG_GENERATE_COUNTER_XOR` are absent from the whole library, so even the raw escape hatch requires a magic number.
- **Proposed action:** Add a `CK_GENERATOR_FUNCTION` enum — named distinctly from `CKG`, since the spec reuses that prefix for two unrelated types — plus optional `ivGenerator`/`ivFixedBits` (resp. nonce) arguments on `CkmGcmMessageParams.ForEncrypt`/`CkmCcmMessageParams`, reading the token-generated IV back through the existing `AbsorbOutput` path and exposing it via a `CopyIvTo`.
- **Breaks public API?** No — additive
- **Raised by:** PKCS#11 Specialist A, Cryptographer A
- **Spec / References:** PKCS#11 v3.2 §2.13 / §2.14; values at `vendor/nss/lib/util/pkcs11t.h:2123-2128`; NIST SP 800-38D §8.2. BL-043 concerns 32-bit GCM tags, a different field

### [BL-103] ⚠️ PARTIALLY RESOLVED — The recommended hybrid and v3.2 authenticated key-wrap mechanisms have native param structs but no managed parameter type
- **Status:** Partially resolved 2026-09-12. `CkmPkcs5Pbkd2Params` now gives `CKM_PKCS5_PBKD2` a typed parameter. It marshals as `CK_PKCS5_PBKD2_PARAMS2`, and `Rfc2898DeriveBytesPkcs11` builds on it.
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/RawMechanismParams/CK_RSA_AES_KEY_WRAP_PARAMS.cs:10-21`, `CK_ECDH_AES_KEY_WRAP_PARAMS.cs`, `CK_GCM_WRAP_PARAMS.cs:32-54`, `CK_CCM_WRAP_PARAMS.cs`, `CK_PKCS5_PBKD2_PARAMS2.cs`, `CK_AES_CBC_ENCRYPT_DATA_PARAMS.cs`, `CK_MAC_GENERAL_PARAMS.cs:64-70` — none referenced from `MechanismParams/`
- **Problem:** 53 of the 85 native param structs have no managed counterpart. Most are genuinely legacy (SSL3/WTLS/SKIPJACK/GOST/OTP) and their absence is defensible, but seven are not. `CKM_RSA_AES_KEY_WRAP` is the standard, non-Bleichenbacher way to wrap a symmetric key under an RSA public key — the very thing a consumer reaches for once `GuardMechanism` refuses `CKM_RSA_PKCS` — and it is unreachable because its parameter is *nested* (`OAEPParams` is a pointer to a `CK_RSA_PKCS_OAEP_PARAMS`), which `Pkcs11ParameterWriter` cannot express. `CK_GCM_WRAP_PARAMS`/`CK_CCM_WRAP_PARAMS` are the v3.2 authenticated-wrap parameters and additionally carry token-written output fields, so the writer cannot serve them either. `CKM_PKCS5_PBKD2` and `CKM_AES_CBC_ENCRYPT_DATA` — the latter explicitly *recommended* by the library's own guard message at `Internal/Pkcs11SessionCore.cs:679` — are also unreachable as typed parameters.
- **Remaining scope:** `CK_RSA_AES_KEY_WRAP_PARAMS`, `CK_ECDH_AES_KEY_WRAP_PARAMS`, `CK_GCM_WRAP_PARAMS`, `CK_CCM_WRAP_PARAMS`, `CK_AES_CBC_ENCRYPT_DATA_PARAMS` and `CK_MAC_GENERAL_PARAMS` still have no managed type. The note that the remaining native structs are deliberately not surfaced has not been written.
- **Proposed action:** Add `Ckm*` types for at least those seven structs. Separately, document that the remaining native structs are deliberately not surfaced, so the asymmetry reads as a decision rather than an oversight.
- **Breaks public API?** No — additive
- **Raised by:** Cryptographer A
- **Spec / References:** PKCS#11 v3.2 §2.1.24, §2.15; v3.0 §2.28. Extends BL-019 with the parameter-type half and BL-061 by naming the concrete stranded mechanisms

### [BL-104] ⚠️ PARTIALLY RESOLVED — `Pkcs11MechanismMap` has no SHA-3 or SHA-224 arms for RSA/ECDSA/HMAC, and documents an HMAC-truncation overload that does not exist
- **Status:** Partially resolved 2026-10-26 (#250, #251, #255; SHA-224 in e88cd41e, 2026-09-19). `RsaPkcs1Sign`, `RsaPssSign`, `RsaOaep`, `EcdsaSign` and `Hmac` now map SHA-224, gated behind the session policy, and SHA3-256/384/512. SHA3-224 is deliberately not mapped, because the BCL has no `HashAlgorithmName` for it (`Pkcs11MechanismMapTests.Rsa_Sha3_224_IsNotMapped`). Covered by `RsaPkcs1_HashToCkm_ReturnsExpected`, `RsaPss_HashToCkm_ReturnsExpectedWithParams`, `RsaOaep_HashToCkm_ReturnsExpectedWithParams`, `EcdsaSign_HashToCkm_ReturnsExpected` and `HmacHash_HashToCkm_ReturnsExpected`.
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/Pkcs11MechanismMap.cs:40-49`, `:69-80`, `:97-108`, `:125-134`, `:237-246`; the truncation remark at `:226-228`
- **Problem:** `RsaPkcs1Sign`, `RsaPssSign`, `RsaOaep`, `EcdsaSign` and `Hmac` accept only SHA-1/256/384/512 and throw `NotSupportedException` otherwise, yet the `CKM` enum declares every combined mechanism they would need (`CKM_SHA3_256_RSA_PKCS_PSS`, `CKM_ECDSA_SHA3_256`, `CKM_SHA3_256_HMAC`, `CKM_SHA224_RSA_PKCS_PSS`, `CKM_ECDSA_SHA224`) — and the same file already maps SHA-224 and all four SHA-3 sizes for DSA (`:115-124`) and HashML-DSA (`:159-171`). Since .NET 8 exposes `HashAlgorithmName.SHA3_256/384/512`, `RSAPkcs11.SignData(data, SHA3_256, Pss)` fails on a token that fully supports it. Separately, the `Hmac` remark at `:178-181` promises "a different overload that accepts a truncation length" — no such overload exists, and `CK_MAC_GENERAL_PARAMS` has no managed type (BL-103), so truncated HMAC is unreachable.
- **Remaining scope:** the `Hmac` remark (`Pkcs11MechanismMap.cs:226-228`) still promises "a different overload that accepts a truncation length". No such overload exists, and `CK_MAC_GENERAL_PARAMS` has no managed type (BL-103). Add the overload or delete the remark.
- **Proposed action:** Add the SHA-224 and SHA3-224/256/384/512 arms to the four RSA/ECDSA/HMAC mappers, and either add the promised `Hmac(HashAlgorithmName, int macLength)` overload or delete the remark.
- **Breaks public API?** No — additive
- **Raised by:** Cryptographer A

### [BL-105] `CkmRsaPkcsOaepParams` hardcodes `Source = CKZ_DATA_SPECIFIED`, blocking tokens that require `source = 0` for an absent label
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismParams/CkmRsaPkcsOaepParams.cs:24` (the only constructor), `:38-40` (`Source` hardcoded)
- **Problem:** `Source` is set unconditionally to `CKZ_DATA_SPECIFIED` with `SourceData = IntPtr.Zero`/`SourceDataLen = 0` when no label is supplied — the default — and no constructor or property lets a caller change it. SoftHSM, NSS and opencryptoki accept that combination, but several commercial HSMs reject `CKZ_DATA_SPECIFIED` with a NULL `pSourceData` and require `source = 0`, a long-standing PKCS#11 interop wart. As shipped, RSA-OAEP is unusable end-to-end against those modules, including through `Pkcs11MechanismMap.RsaOaep` and therefore `RSAPkcs11.Encrypt`/`Decrypt`.
- **Proposed action:** Add a constructor overload taking the source value (defaulting to today's behaviour) and consider defaulting to `0` when the label is empty. Additive and cheap now; after 1.0 the behaviour change would need a compat switch.
- **Breaks public API?** No — additive
- **Raised by:** Cryptographer A
- **Spec / References:** PKCS#11 v3.2 §2.1.8 (`CK_RSA_PKCS_OAEP_PARAMS.source`/`pSourceData`); RFC 8017 §7.1 (empty label)

### [BL-107] EdDSA and X25519/X448 have no supported path, and the secure-default generator family stops at RSA/EC/AES
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKM.cs:1373` (`CKM_EDDSA`, no `Pkcs11MechanismMap` entry and no façade); `Pkcs11ECCurve.cs:19-21` (Edwards/Montgomery deliberately excluded); `Pkcs11Session.KeyGeneration.cs:109,160,205` (the complete generator set); `Pkcs11Key.cs:508-522` (managed verify fallback covers only `CKK_RSA` and `CKK_EC`)
- **Problem:** `CKM_EDDSA` has a full, correctly laid-out parameter type (`MechanismParams/CkmEddsaParams.cs`) but no mechanism-map entry and no façade, while ML-DSA and SLH-DSA both get one. `Pkcs11ECCurve.NamedCurves` intentionally omits Ed25519/Ed448 and nothing replaces it, so generating an Ed25519 key requires hand-DER-encoding `CKA_EC_PARAMS` through the generic attribute escape with an OID the docs never name. There is also no `GenerateEd25519KeyPair`/`GenerateMlDsaKeyPair`/`GenerateMlKemKeyPair`/`GenerateSlhDsaKeyPair`, so an agility migration drops off the hardened paved path and must reconstruct the `Sensitive().NonExtractable()` posture by hand. Finally, `Pkcs11Key.Verify`'s no-public-handle fallback handles only RSA and EC while `IsAsymmetricKeyType` lists four more types, so those reach `CKR_OBJECT_HANDLE_INVALID` rather than a typed "not supported". EdDSA is supported by all three real CI backends but is exercised only through the *internal* session (`Tests/Integration/Sign/SignEdDsaTests.SoftHsm2.cs:14-40`), so the public surface has no EdDSA coverage at all.
- **Proposed action:** Add named-curve constants and `CKA_EC_PARAMS` support for Ed25519/Ed448/X25519/X448 (Ed25519 needs only the well-known OID `1.3.101.112`) plus `Pkcs11MechanismMap.EdDsaSign(bool prehash, ReadOnlySpan<byte> context)`; add the four missing generator helpers with the same posture; make the `Verify` fallback throw `NotSupportedException` naming the key type. If EdDSA is intentionally out of scope for 1.0, say so in the `CkmEddsaParams` doc so the mechanism does not look half-wired.
- **Breaks public API?** No — additive
- **Raised by:** Cryptographer A, Cryptographer B
- **Spec / References:** PKCS#11 v3.0 §2.3.5–2.3.6; RFC 8032

### [BL-116] `Destroy()` leaves the wrapper fully usable with stale handles
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs:440-445` (doc remark at `:435-436`); `Pkcs11Object.cs:83-87`; `Pkcs11Certificate.cs:78-82` has the same shape
- **Problem:** After a successful `Destroy()`, `_disposed` stays false, so every subsequent member — `Sign`, `Encrypt`, `GetValue`, and `Destroy()` itself — still passes its guard and re-sends the now-stale handle. Because PKCS#11 permits handle reuse, a second `Destroy()` after another object has taken the recycled handle destroys an unrelated object: irreversible key loss with no error. The doc comment at `Pkcs11Key.cs:186-187` recognises the handles become stale but nothing enforces it. `Pkcs11Key.Destroy` additionally has no partial-failure story: if the private destroy succeeds and the public one throws, the caller cannot tell which half survived.
- **Proposed action:** Add a `_destroyed` flag set on success and have every member throw once it is set; clear each handle to `ObjectHandle.Invalid` as it is destroyed so a partial failure is self-describing.
- **Breaks public API?** Yes — behavioural: calls that silently succeed today would throw. Must land before 1.0
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** PKCS#11 v3.2 §4.4 — object handles are valid only until the object is destroyed, and may be reused

### [BL-117] `Pkcs11Key.Wrap` accepts a target key from a different session without checking provenance
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs:701-720` (handle chosen at `:712-714`, used at `:719`)
- **Problem:** `Wrap` null-checks `targetKey` and validates that its handle is non-invalid, but never verifies the target belongs to the same session — so a handle obtained from a *different* session is passed to this session's `C_WrapKey`. Session-object handles are session-scoped, so the best case is `CKR_OBJECT_HANDLE_INVALID`; the bad case is a numeric collision with a different object in the receiving session, wrapping the wrong key material with no error anywhere. Reachable today: two `OpenSessionWithoutLogin` calls, or two slots, produce two independent sessions.
- **Proposed action:** Add a `ReferenceEquals(targetKey.Session, _session)` check at the top of `Wrap`, throwing `ArgumentException`, and audit any future cross-key method for the same check.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** PKCS#11 v3.2 §4.4 — object handles are valid only in the session (or, for token objects, the application's sessions with that token) that returned them

### [BL-118] No typed exception for operation-state or not-supported return codes
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/ExceptionMapper.cs:79` (the default arm); codes at `Common/CKR.cs:121`, `:131`, `:201`, `:206`, `:421`, `:491`
- **Problem:** `CKR_OPERATION_ACTIVE`, `CKR_OPERATION_NOT_INITIALIZED`, `CKR_OPERATION_CANCEL_FAILED`, `CKR_FUNCTION_NOT_SUPPORTED`, `CKR_FUNCTION_CANCELED` and `CKR_CRYPTOKI_NOT_INITIALIZED` all fall through to `Pkcs11UnclassifiedException` — the same bucket as vendor-defined codes. A consumer who hits a wedged session (BL-114, BL-049) cannot distinguish it from an unknown vendor code without inspecting `ReturnValue`. This also weakens the "v3.2 methods fail cleanly on sub-v3.2 modules" contract: the XML docs repeatedly promise `CKR_FUNCTION_NOT_SUPPORTED` as the signal, but it arrives as an unclassified exception.
- **Proposed action:** Add `Pkcs11OperationStateException` (the three `CKR_OPERATION_*` plus `CKR_FUNCTION_CANCELED`) and `Pkcs11NotSupportedException` (`CKR_FUNCTION_NOT_SUPPORTED`), and route the two `CKR_CRYPTOKI_*_INITIALIZED` codes to a lifecycle category.
- **Breaks public API?** Yes — adding these narrows what `Pkcs11UnclassifiedException` catches, which is a behavioural break for anyone catching it. Must land before 1.0
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** PKCS#11 v3.2 §5.3 return-value groupings. BL-003 covered the unknown-value enum cast, not the categorization

### [BL-120] Digest and HMAC façades buffer the entire input while the multi-part digest path sits unused in the same assembly, and the class comment states the opposite
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/SHA256Pkcs11.cs:13-22` (the claim) and `:46-61` (the buffering); same shape in `SHA1Pkcs11.cs:39`, `SHA384Pkcs11.cs:15`, `SHA512Pkcs11.cs:15`, `SHA3_256/384/512Pkcs11.cs:27`, `MD5Pkcs11.cs:39`, `HMACPkcs11.cs:32`; the unused multi-part path is `Internal/Pkcs11SessionCore.Digesting.cs:106,128`
- **Problem:** The remark says "there is no portable streaming digest in the BCL-mappable surface here", but `Pkcs11SessionCore.Digest(Mechanism, Stream, int)` drives `C_DigestInit`/`C_DigestUpdate`/`C_DigestFinal` correctly — including unwind-cancel — in the same assembly, and is exactly what `HashCore`/`HashFinal` map onto. So the stated justification for buffering is inaccurate, and `HashAlgorithm.ComputeHash(Stream)` over these types accumulates the whole payload in a `MemoryStream`. Secondary: `_buffer.SetLength(0)` and `_buffer.Dispose()` never overwrite the accumulated bytes, and `_buffer.ToArray()` makes a second copy that is also never zeroized, so message plaintext lingers on the managed heap.
- **Proposed action:** Refactor the digest core into an incremental helper (`DigestInit`/`DigestUpdate`/`DigestFinal` on the session) that `HashCore`/`HashFinal` drive directly, replacing the buffer. If buffering must stay for some mechanism, correct the comment and zeroize both the buffer and the `ToArray()` copy on reset and dispose.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** Supersedes the untracked design note previously recorded in Appendix B, which accepted the buffering without noting that the multi-part path already exists

### [BL-121] ⚠️ PARTIALLY RESOLVED — Multi-part and streaming paths have zero real-backend coverage, and the fake is an identity transform where output length always equals input length
- **Status:** Partially resolved 2026-10-26 (#129, #259, #260). The stream overloads now reach real modules with mechanisms whose update output differs from their input. `KnownAnswerTestCases.Assert_AesGcm_Multipart_Kat` (#129) encrypts and decrypts the McGrew–Viega vector through the stream overloads in 16-, 17-, 32- and 64-byte pieces, on every backend that does multi-part GCM. `OperationContractTestCases.Assert_CbcPad_MultipartDecrypt_MatchesBcl` (#259) decrypts BCL `CKM_AES_CBC_PAD` ciphertexts of 1, 15, 16, 17, 31 and 33 bytes in 16- to 64-byte pieces. `DecryptAesTestCases.Assert_AesCbcPad_StreamDecrypt_LastBlockComesFromFinal` (#260) checks that the held-back last block comes from `C_DecryptFinal`, on SoftHSM, Kryoptic, NSS, opencryptoki, BouncyHsm, Craton and FreeHSM. `Assert_Digest_Multipart_MatchesSinglePart` and `Assert_Hmac_Multipart_MatchesBcl` (#259) drive the stream digest and verify in 7-byte pieces. #260's `CallFinal` and `StreamFinalLengthTests` cover a final whose length query answers 0.
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Unit/Internal/Pkcs11SessionCoreStreamTests.cs:41-54` (the fake's `Update`); the code under test in `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11SessionCore.Encryption.cs`; dual-function streams only in `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/Interop/DualFunctionCryptoTests.Pkcs11Mock.cs`
- **Problem:** `C_EncryptUpdate`/`C_DecryptUpdate`/`C_DigestUpdate`/`C_VerifyUpdate` and the combined `DigestEncrypt`/`DecryptDigest`/`DecryptVerify` operations are exercised only against `StreamFake`, whose `Update` copies exactly `inLen` bytes out. A real CBC or block-mode token buffers partial blocks and returns *fewer* bytes than it was fed — often zero — flushing the remainder in `C_EncryptFinal`, which is precisely the case where the loop's length bookkeeping and the `CKR_BUFFER_TOO_SMALL` regrow at `:1910-1916` actually matter. There is no empty-input-stream case either.
- **Remaining scope:** no real-backend stream *encrypt* with a block-buffering mode such as CBC (encrypt is covered only through GCM). The dual-function `DigestEncrypt`/`DecryptDigest`/`DecryptVerify` streams run only against pkcs11-mock (`DualFunctionCryptoTests.Pkcs11Mock.cs`). There is no zero-byte input stream and no 4096±1 buffer length. `Pkcs11SessionCoreStreamTests`' `StreamFake.Update` is still an identity transform.
- **Proposed action:** Add a SoftHSM/opencryptoki integration class driving the stream overloads with AES-CBC — a mechanism whose update output length differs from its input length — at buffer lengths 1, 15, 16, 17 and 4096±1, plus a zero-byte input, comparing against the one-shot result.
- **Breaks public API?** No
- **Raised by:** QA B

### [BL-122] ⚠️ PARTIALLY RESOLVED — Every real-backend crypto payload is ≤ 256 bytes; boundary and bulk sizes are untested, and the empty-input digest runs only against the in-process fake
- **Status:** Partially resolved 2026-10-17 (#182). Empty input is now exercised on every real backend through `EmptyInputTestCases` (SoftHSM, Kryoptic, NSS, opencryptoki, BouncyHsm, Craton, FreeHSM): `Sha256_EmptyInput_MatchesBcl_SessionReusable`, `Hmac_EmptyInput_MatchesBcl_SessionReusable`, `EcDsa_EmptyData_SignVerify_MatchesBcl_SessionReusable` and `AesGcm_EmptyPlaintext_WithAad_MatchesBcl_SessionReusable`. Each runs an empty input and then a non-empty one on the same session, so a module that leaves the operation active is caught. `Cbc_EmptyInput_MatchesBcl` covers AES, DES and 3DES.
- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/Interop/EmptyInputTestCases.cs`; `Algorithms/SHA256Pkcs11TestCases.cs`, `Algorithms/SHA256Pkcs11Tests.Managed.cs`, `Algorithms/AesGcmPkcs11TestCases.cs`
- **Problem:** Across every `new byte[N]` literal in `Algorithms/` and `Integration/`, the largest buffer is 256 bytes and digest inputs are 3–54 bytes. Nothing crosses the 4096-byte internal stream buffer, and no digest exercises the SHA padding boundaries (55/56/64/119/120 bytes). `ComputeHash([])` — the case where a module receives `pData == NULL, ulDataLen == 0` and real tokens diverge — exists only in the eight `*Tests.Managed.cs` files, i.e. against `ManagedSoftToken`, which accepts it by construction.
- **Remaining scope:** the size matrix. No digest input crosses the SHA padding boundaries (55/56/64/119/120 bytes). No payload crosses the 4096-byte stream buffer or reaches 1 MiB; the only large inputs are `AesCcmPkcs11TestCases.Assert_EncryptDecrypt_LargeAad_MatchesBcl`'s 8192- and 0xFF00-byte AAD over a 40-byte plaintext.
- **Proposed action:** Add a shared size-matrix theory (0, 1, 15, 16, 17, 55, 56, 64, 4095, 4096, 4097, 1 MiB) to the digest and AES/GCM test-case classes, run on at least SoftHSM across all six legs and asserted against the BCL; promote the empty-input digest to the real backends.
- **Breaks public API?** No
- **Raised by:** QA B

### [BL-123] ⚠️ PARTIALLY RESOLVED — Wrap/unwrap has no asymmetric key transport, no RFC 5649 vector for the padded mechanism the round-trips actually use, and no tampered-blob negative
- **Status:** Partially resolved 2026-10-29 (#229, #254, and the algorithm-conformance tests). `AesPkcs11TestCases.Assert_KeyWrapPadded_UsesTheTokensKwp_AndMatchesBcl` (#229) wraps with the token's `CKM_AES_KEY_WRAP_KWP` and asserts byte equality with the BCL's RFC 5649 `EncryptKeyWrapPadded`, with each side unwrapping the other's output, on every real backend that advertises KWP. The BCL serves as the independent reference instead of the RFC 5649 §6 vectors. `Assert_DecryptKeyWrapPadded_InvalidWrap_Throws` (#254) feeds three invalid KWP wraps (modified IV, modified padding, an encoded length of 2^32−1) to `DecryptKeyWrapPadded` on SoftHSM, Kryoptic, NSS and BouncyHsm and asserts a `CryptographicException`; `AesPkcs11Tests.Managed` adds `DecryptKeyWrapPadded_Tampered_Throws`. `AlgorithmConformanceTestCases.Assert_RsaOaep_TransportsAnAesKey` wraps an AES-256 key under RSA-OAEP with SHA-256 and unwraps it to a key that encrypts as the original does, on SoftHSM, Kryoptic, NSS, opencryptoki, BouncyHsm and FreeHSM; Craton HSM's wrapper pins its `CKR_MECHANISM_INVALID`. `Assert_AesKeyWrap_TamperedBlob_IsRefused` flips the first, ninth and last byte of a `C_WrapKey` blob under `CKM_AES_KEY_WRAP`, truncates it and replaces it with `0xFF`s, and asserts that `C_UnwrapKey` refuses each one and still unwraps the untouched blob.
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/Keys/WrapUnwrapKeyTests.cs` and its per-backend wrappers; `Algorithms/AesPkcs11TestCases.cs` (`Assert_KeyWrapPadded_UsesTheTokensKwp_AndMatchesBcl`, `Assert_DecryptKeyWrapPadded_InvalidWrap_Throws`)
- **Problem:** The only wrap KAT is RFC 3394 `CKM_AES_KEY_WRAP`. Every functional wrap/unwrap round-trip uses `CKM_AES_KEY_WRAP_PAD`, which has no published-vector check even though RFC 5649 §6 supplies two. `CKM_RSA_PKCS_OAEP` never appears as a wrap mechanism and `CKM_RSA_AES_KEY_WRAP` appears nowhere, so wrapping a symmetric key under an RSA public key — the most common HSM key-transport pattern — is untested on all four backends. There is also no negative asserting that flipping a byte in the wrapped blob makes `UnwrapKey` fail, even though RFC 3394's integrity check is the whole point of AES-KW.
- **Remaining scope:** `CKM_RSA_AES_KEY_WRAP` appears nowhere.
- **Proposed action:** Add the RFC 5649 KWP vectors to the known-answer set; add an RSA-OAEP wrap/unwrap round-trip that proves the material survived by cross-decrypting; and add a tampered-blob negative asserting `CKR_WRAPPED_KEY_INVALID`/`CKR_ENCRYPTED_DATA_INVALID`.
- **Breaks public API?** No
- **Raised by:** QA B
- **Spec / References:** RFC 5649 §6; RFC 3394 §2.2.2

### [BL-124] ⚠️ PARTIALLY RESOLVED — ECDH derive is only ever run with `CKD_NULL` and no shared data, so the KDF and `pSharedData` fields never reach a real module
- **Status:** Partially resolved 2026-10-29 by the algorithm-conformance tests. `AlgorithmConformanceTestCases.Assert_Ecdh_Sha256Kdf_IsX963OverZAndTheSharedData` derives with `CKD_SHA256_KDF`, without and with shared data, and checks the key against the ANSI X9.63 KDF computed in managed code, which is what PKCS#11 specifies for `CKD_SHA*_KDF` (not SP 800-56A's concatenation KDF). It passes on Kryoptic, NSS and opencryptoki. BouncyHsm's wrapper pins a KDF whose counter starts at 0, and FreeHSM's pins `CKR_ARGUMENTS_BAD`; SoftHSM refuses the KDF, so the case skips there. **Remaining scope:** `SoftHsmSupportsEcdh1WithKdf` still has no consumer, and the other `CKD_SHA*_KDF` hashes do not run.
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/Keys/DeriveSharedSecretEcdhTests.SoftHsm2.cs:42-43,88` and its siblings (all `kdf: CKD.CKD_NULL`); the gate that would track it, `SoftHsmSupportsEcdh1WithKdf`, is at `Support/Fixtures/SoftHsmBackendFixture.cs:98` and has no consumer
- **Problem:** All four backends' derive tests pass `kdf: CKD_NULL` with no shared data. `CKD_SHA*_KDF` and a non-empty `pSharedData`/`ulSharedDataLen` appear only in a leak test that asserts no cryptographic output and in unit-level struct-offset assertions. That leaves the two-pointer-plus-two-length tail of `CK_ECDH1_DERIVE_PARAMS` — where a swapped pointer/length pair is easy to get wrong and invisible on 64-bit Linux — without a single end-to-end execution. `SoftHsmSupportsEcdh1WithKdf => false` was written to gate exactly this case but has zero consumers repo-wide, so the gap is invisible rather than tracked.
- **Proposed action:** Add a `CKD_SHA256_KDF` derive with non-empty shared data against whichever backend advertises it, cross-checked against an SP 800-56A concatenation KDF computed in managed code, with a hard-fail guard rather than a silent skip if no backend supports it.
- **Breaks public API?** No
- **Raised by:** QA B, QA A
- **Spec / References:** Extends BL-028 with a mechanism its list omits

### [BL-125] ⚠️ PARTIALLY RESOLVED — No real-token negatives for the two states consumers hit most: not-logged-in, and session reuse after a failed operation
- **Status:** Partially resolved 2026-10-26 (#259; library side in #63, 2026-10-07). #63 tracks an operation that a module without `C_SessionCancel` could not cancel (`CancelAbandoned`); the next init of that kind then fails with a message saying the operation is still active and the session should be replaced, instead of a bare `CKR_OPERATION_ACTIVE`. `OperationContractTestCases.Assert_Operation_AfterAnError_TheSessionStaysUsable` (#259) forces a mid-operation failure — an AES-CBC partial block through the stream decrypt, a wrong HMAC through the stream verify, a tampered RSA-OAEP ciphertext — and then runs a successful operation of the same kind on the same session, on SoftHSM, Kryoptic, NSS, opencryptoki, BouncyHsm, Craton and FreeHSM. The `pkcs11-v240` CI legs run the SoftHSM and NSS suites against SoftHSM 2.5 and NSS 3.51, so the case also runs on v2.40 modules.
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11SessionCore.cs:620`, `:646` (`CancelAbandoned`); `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/Interop/OperationContractTestCases.cs`
- **Problem:** `CKR_USER_NOT_LOGGED_IN` appears in the test tree only in the mapping table and in fakes — no real-backend test performs a private-key operation or a `FindObjects` for `CKA_PRIVATE=true` objects on an un-logged-in session, so the token's actual access-control behaviour (throw versus silently return nothing) is undocumented and unpinned. Separately, `TryCancelOperation` treats `CKR_FUNCTION_NOT_SUPPORTED` as success and logs nothing, so on a v2.40 module — SoftHSM 2.5 via the `softhsm-v240` job, NSS, opencryptoki — a failed operation stays *active*, and no test verifies the session is still usable afterwards; the next call would fail with `CKR_OPERATION_ACTIVE`.
- **Remaining scope:** no real-backend not-logged-in negative. No test signs with a private key on an un-logged-in session or checks that `CKA_PRIVATE` objects are invisible to `FindObjects` there.
- **Proposed action:** Add a real-backend test that a private-key sign on an un-logged-in session surfaces `Pkcs11AuthenticationException` and that private objects are invisible to `FindObjects`; add an "operation failure leaves the session usable" test (force a failure with a bad mechanism parameter, then run a successful operation on the same session) and run it on both a v3.x and the gated v2.40 module.
- **Breaks public API?** No
- **Raised by:** QA B
- **Spec / References:** BL-049 is the missing cancel call on one method and BL-052 is token removal; neither covers session recoverability on modules where `C_SessionCancel` does not exist

### [BL-126] ⚠️ PARTIALLY RESOLVED — All four named priorities, HKDF, ChaCha20 and IKE-derive landed; X3DH/X2Ratchet and XEdDSA still never reach a real module (and never can — no vendored backend implements them)
- **Area:** QA
- **Severity:** Medium
- **Effort:** L
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/Pkcs11MechanismMap.cs:104-107`, `:133-136`, `:154-173`; `MechanismParams/CkmEddsaParams.cs`; tested only at `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Unit/Internal/Pkcs11MechanismMapTests.cs:120-150`
- **Problem:** Cross-referencing `MechanismParams/*.cs` against everything under `Integration/` and `Algorithms/`, only `CkmAesGcmParams`, `CkmAesCcmParams`, `CkmEcdh1DeriveParams`, `CkmRsaPkcsOaepParams`, `CkmRsaPkcsPssParams`, `CkmSalsa20ChaCha20Poly1305Params`, `CkmSp800108KdfParams` and the PQC sign params are ever used in a real call. `CkmEddsaParams` (Ed25519ph and context signing), `CkmHkdfParams`, `CkmChaCha20Params`, the IKE-derive family, X3DH/X2Ratchet and XEdDSA are unit-marshalling-only. Notably `Pkcs11MechanismMap.MlDsaHashSign` — a public v3.2 entry point that builds `CK_HASH_SIGN_ADDITIONAL_CONTEXT` — and every non-default `CkhHedge` value were tested only by asserting the returned `Mechanism`'s fields, never by a token that would reject a malformed block. RSA-OAEP with a label (`CKZ_DATA_SPECIFIED` + `pSourceData`) was likewise verified only structurally. (`SlhDsaHashSign`, named in the original proposed action alongside `MlDsaHashSign`, does not exist as a method in this codebase — there is no combined-hash SLH-DSA mapping to test.)
- **Remaining scope:** X3DH/X2Ratchet and XEdDSA are still unit-marshalling-only, and a source audit of all five vendored backends (SoftHSM2, opencryptoki, Kryoptic, NSS, pkcs11-mock) found none of them implement Signal's X3DH/X2Ratchet/XEdDSA — no real mechanism registration exists for any of them anywhere. No real-backend test is possible for these until a vendored backend actually implements one — this is a hard floor on this item's remaining scope, not an effort gap. (Raw `CKM_CHACHA20` and the IKE-derive family were in this same "no backend implements it" state when this item was last written; Kryoptic gained a real ChaCha20 implementation on 2026-09-12, and NSS's `sftkike.c` turned out to be a genuine, dispatched IKE-derive implementation — see Resolution below — so both findings are now stale for those two families specifically.)
- **Resolution:** Added one real-module acceptance test per named priority, following the established `SignIbmMlDsaContextTests.OpenCryptoki.cs` pattern (a token that rejects a malformed parameter block is the oracle):
  - `SignHashMlDsaTests.OpenCryptoki.cs` — `Pkcs11MechanismMap.MlDsaHashSign(SHA256)` round-trips against opencryptoki's `CKM_HASH_ML_DSA_SHA256`, feeding the raw message (confirmed against `mech_pqc.c` that the token hashes it internally for every combined mechanism except the bare `CKM_HASH_ML_DSA`).
  - `SignMlDsaDeterministicHedgeTests.OpenCryptoki.cs` — `CkhHedge.CKH_DETERMINISTIC_REQUIRED` against `CKM_ML_DSA`; opencryptoki maps this straight to OpenSSL's `OSSL_SIGNATURE_PARAM_DETERMINISTIC` (confirmed in `mech_openssl.c`), so the test asserts the actual observable effect — two signs of the same message produce byte-identical signatures — not just "didn't throw".
  - `EncryptRsaOaepLabelTests.SoftHsm2.cs` — `CkmRsaPkcsOaepParams` with a non-empty label, round-tripping and asserting a mismatched label fails to decrypt; SoftHSM2 genuinely feeds the label into `EVP_PKEY_CTX_set0_rsa_oaep_label` for both directions (confirmed in `OSSLRSA.cpp`), so this is real encoding behaviour, not a validated-and-discarded field.
  - `SignEdDsaContextTests.OpenCryptoki.cs` — `CkmEddsaParams` for both Ed25519ctx (non-empty context, asserting a signature verifies only under the same context) and Ed25519ph (prehash, asserting the same signature does not also verify as plain Ed25519); opencryptoki's `build_edwards_params` selects between all three OpenSSL "instances" based on exactly these fields (confirmed in `mech_openssl.c`).
  - `HkdfTestCases.cs` (`HkdfTests.Nss.cs` / `.Kryoptic.cs`) — `CkmHkdfParams` in all three modes (Extract-and-Expand, Expand-only, Extract-only), cross-checked byte-for-byte against the independent BCL `System.Security.Cryptography.HKDF` implementation rather than just round-tripping. NSS and Kryoptic are the only two vendored backends with a real HKDF implementation (SoftHSM2, opencryptoki and pkcs11-mock have none). The read-back cases are gated on the already-established, permanently-`false` `NssBackendFixture.ExtractableDeriveAvailable` (NSS refuses to derive a readable key at all — the same documented limitation `SP800108HmacCounterKdfPkcs11Tests.Nss.cs` already works around); Kryoptic runs normally. A second set of cases (`*_MatchesBclViaSignProbe`, same technique introduced for `IkeDeriveTestCases`) closes the NSS gap for real instead of leaving it dormant: derive the key non-extractable (`CKA_SIGN` instead of `CKA_EXTRACTABLE`), HMAC-sign a fixed probe message with it on the token, and compare against the MAC the independent BCL-derived bytes would produce for that message. Gated on plain `NssBackendFixture.NssAvailable`; verified locally against a real Kryoptic build (all 6 HKDF cases pass together).
  - `RawChaCha20TestCases.cs` (`RawChaCha20Tests.Kryoptic.cs` / `.Nss.cs`) — `CkmChaCha20Params` (`CKM_CHACHA20`), gated on the live mechanism list rather than a hard skip: Kryoptic gained a real implementation upstream on 2026-09-12 (`latchset/kryoptic#504`, now vendored here), and NSS's `sftk_Init`/`pkcs11c.c` already had one (`CKM_CHACHA20` alongside the legacy `CKM_NSS_CHACHA20_CTR`). RFC 8439 defines ChaCha20-Poly1305's ciphertext as the raw ChaCha20 keystream (starting at block counter 1) XORed with the plaintext, so the BCL's `ChaCha20Poly1305` doubles as an independent reference implementation for the raw cipher — a genuine known-answer cross-check, not just a round trip. A second test demonstrates the mechanism's lack of authentication directly: decrypting with the wrong block counter silently returns garbage instead of throwing, which is the documented reason `CKM_CHACHA20` is gated by default (see BL-074's resolution). SoftHSM2, opencryptoki and pkcs11-mock still implement neither, so those backends have no corresponding test file.
  - `IkeDeriveTestCases.cs` (`IkeDeriveTests.Nss.cs`, `IkeDeriveTests.Kryoptic.cs`) — all four IKE-derive mechanisms (`CkmIkePrfDeriveParams`, `CkmIke1PrfDeriveParams`, `CkmIke1ExtendedDeriveParams`, `CkmIke2PrfPlusDeriveParams`). NSS's `sftkike.c` has real dispatch (confirmed genuine registration with `CKF_DERIVE` in `pkcs11.c:675-678`); Kryoptic's vendored submodule pin has only the debug-name-table-only match (`const_to_elem!` in `src/pkcs11/mod.rs`), but a real implementation is now up for review upstream (`latchset/kryoptic#512`) — `IkeDeriveTests.Kryoptic.cs` is gated on the live mechanism list (`backend.Supports(CKM.CKM_IKE_PRF_DERIVE)`, same as `RawChaCha20TestCases`'s pattern before `#504` merged), so it skips cleanly today and starts running for real automatically once that PR merges and the submodule pin is bumped — verified locally by building the `#512` branch's `libkryoptic_pkcs11.so` directly and pointing `PKCS11_TEST_KRYOPTIC_LIBRARY` at it: all 4 cases pass. Every one of the four constructions is documented plain HMAC (RFC 2409 §5/Appendix B, RFC 7296 §2.13), so each case reproduces it with the BCL's `HMACSHA256` as an independent reference and cross-checks byte-for-byte: `CKM_IKE_PRF_DERIVE` as `HMAC(inKey, Ni‖Nr)`, `CKM_IKE1_PRF_DERIVE` as `HMAC(inKey, gxy‖CKY_I‖CKY_R‖keyNumber)` (needs a second imported key for the `gxy` handle), `CKM_IKE1_EXTENDED_DERIVE` as the `K1=HMAC(K,extra)`, `K2=HMAC(K,K1‖extra)` chain (forced past the single-block subset shortcut via non-empty extra data, requesting two PRF blocks), and `CKM_IKE2_PRF_PLUS_DERIVE` as the RFC 7296 `T1=HMAC(K,S‖0x01)`, `T2=HMAC(K,T1‖S‖0x02)` construction truncated to a non-block-aligned length. NSS's read-back cases are gated on `ExtractableDeriveAvailable` (NSS's non-extractable-derive policy is general, not HKDF-specific) — permanently dormant, which is why `IkeDeriveTestCases`'s missing `session.AllowInsecure = true` (needed to read the derived key back for the comparison, same as `HkdfTestCases`) went unnoticed until the Kryoptic run above actually executed the code and hit `InsecureOperationException`; fixed in all four cases. A second set of cases (`*_MatchesBclViaSignProbe`) closes the NSS gap for real instead of leaving it dormant: derive the key non-extractable (`CKA_SIGN` instead of `CKA_EXTRACTABLE`, default `CKA_SENSITIVE` — never triggers the `AllowInsecure` gate at all), HMAC-sign a fixed probe message with it on the token, and compare against the MAC the independent BCL reference bytes would produce for that same message — a mismatch in even one derived bit changes the MAC with overwhelming probability, so this is a genuine cross-check without ever reading `CKA_VALUE`. Mirrors how `DeriveSharedSecretEcdhTests` already proves ECDH-derived AES keys match via a cross-party AES-GCM round trip instead of reading the raw key. Gated on plain `NssBackendFixture.NssAvailable`, so these run for real wherever NSS is actually available (verified locally against the `#512` Kryoptic build too: all 4 pass there alongside the existing read-back cases).

  None of these run in this project's sandbox (opencryptoki/SoftHSM2/Kryoptic don't load there, and NSS is unavailable), but all compile and are wired into the same skip/skip-unless machinery as every other real-backend test in the suite.
- **Breaks public API?** No
- **Raised by:** QA B
- **Spec / References:** BL-028 names four specific mechanism families and BL-061 covers the vendor writer's capabilities; neither covers this surface or the inventory as a whole

### [BL-128] The v3.0 message-based AEAD path reaches a real module on exactly one CI leg, and no test asserts which branch ran
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11SessionCore.Encryption.cs:189`, `:277-310`; `Algorithms/AesGcmPkcs11.cs:93`, `:147`
- **Problem:** The per-message parameter block is marshalled to the module only inside `C_EncryptMessage`, which is reached only after `C_MessageEncryptInit` succeeds. SoftHSMv2 exports non-NULL message entry points that unconditionally return `CKR_FUNCTION_NOT_SUPPORTED`, so `IsMessageApiSupported` is *true* on all six platform legs but the params block never reaches a module there — the façade always falls through to the v2.40 branch. NSS, the only backend that actually implements the message API, is built only on the ubuntu-latest leg. So `CK_GCM_MESSAGE_PARAMS_Windows`, `CK_CCM_MESSAGE_PARAMS_Windows` and `CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS_Windows` are covered on Windows and arm64 only by static layout pins, never by a real call, and no test asserts *which* branch executed — so a regression making `SupportsMessageApi` return false would silently erase the message-path coverage entirely (and would also mask BL-073).
- **Proposed action:** Assert the taken branch — expose an internal counter or test hook — so each backend's expected path is pinned, and extend `build/pkcs11-gate.c` with a mode that forces `SupportsMessageApi` on and off over real SoftHSM crypto so both branches are exercised on every platform leg.
- **Breaks public API?** No
- **Raised by:** QA B

### [BL-129] ⚠️ PARTIALLY RESOLVED — Eighteen permanently-dormant `[Fact(SkipUnless = ...)]`s sit behind hard-coded `false` capability constants, and four gates have no consumer at all
- **Status:** Partially resolved 2026-10-15 (#126, #150). The NSS EdDSA gate went in #126, so those tests now run on the live mechanism list; the classic AES-GCM gate went in #150; the other dormant wrappers named here no longer reference their constants.
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/NssBackendFixture.cs:70` (`TokenObjectsAvailable => false`) and the dormant `[Fact]`s behind it (`Integration/Keys/DeleteKeyTests.Nss.cs:15`, `Pkcs11KeyMechanismTests.Nss.cs:23,30`, `Pkcs11SessionFindKeysTests.Nss.cs:23`, `Pkcs11SessionGenerateKeyTests.Nss.cs:16,23`, `Integration/Objects/FindObjectsTests.Nss.cs:25,62`); the consumer-less constant-`false` gates in `NssBackendFixture.cs` and `SoftHsmBackendFixture.cs`
- **Problem:** Ten fixture capability gates are compile-time constants that can never become true (`SupportsClassicAesGcm`, `SupportsEdDsa`, `TokenObjectsAvailable`, `SupportsExtractableDerive`, `SupportsRc2Ecb`, `SupportsRsaPkcs1Encrypt`, `SoftHsmSupportsChaCha20Poly1305`/`ChaCha20KeyType`/`AesCcm`/`Ecdh1WithKdf`). Seventeen `[Fact(SkipUnless = ...)]`s besides BL-053's ChaCha20 KAT are therefore unreachable on every CI leg — three whole test classes contain nothing but dormant tests, and `SignEdDsaTests.Nss.cs:11` documents itself as "Gated on the live mechanism list" while the actual gate is `=> false`. Separately, four SoftHSM gates have **zero** consumers anywhere in the repo, so the "when we move to a newer SoftHSM, flip the relevant flag" instruction is inert for four of five flags.
- **Remaining scope:** eight `[Fact]`s are still unreachable behind `NssBackendFixture.TokenObjectsAvailable => false` (`DeleteKeyTests.Nss.cs:15`, `Pkcs11KeyMechanismTests.Nss.cs:23,30`, `Pkcs11SessionFindKeysTests.Nss.cs:23`, `Pkcs11SessionGenerateKeyTests.Nss.cs:16,23`, `FindObjectsTests.Nss.cs:25,62`). Eight constant-`false` gates have no `SkipUnless` consumer at all: `NssBackendFixture.SupportsMultipartClassicAesGcm`, `SupportsExtractableDerive`, `SupportsRc2Ecb`, `SupportsRsaPkcs1Encrypt`, and `SoftHsmBackendFixture.SoftHsmSupportsChaCha20Poly1305`, `ChaCha20KeyType`, `AesCcm`, `Ecdh1WithKdf`. The reflection meta-test (constant-`false` gates without a `[DormantGate]` marker, and gates without consumers) has not been written.
- **Proposed action:** Add one reflection meta-test — sibling to the exemplary `Unit/TestCollectionConventionTests.cs` — that enumerates every static `bool` gate referenced by a `SkipUnless`/`SkipWhen` on a `[Fact]`/`[Theory]`, fails when it is a constant `false` unless the member carries an explicit `[DormantGate("reason")]` marker, and separately fails on a gate with no such consumer. Then either delete the unreachable NSS test wrappers or convert the constants into runtime probes, as `IPkcs11Backend.SupportsMlDsa`/`MlKem`/`SlhDsa` already do off the advertised mechanism list.
- **Breaks public API?** No
- **Raised by:** QA A
- **Spec / References:** Extends BL-053, which covers one instance; this is the census plus the systemic guard

### [BL-131] The 100-cycle allocation stress test passes having executed zero cycles, and its second assertion is tautological
- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/MemoryLeaks/EncryptDecryptStressTests.Pkcs11Mock.cs:72-84` (`catch (Pkcs11Exception) { continue; }` at `:79-81`), `:102`, `:119-120`
- **Problem:** `TestKeys.CreateAes256Key` is wrapped in `catch (Pkcs11Exception) { continue; }`. pkcs11-mock's `C_CreateObject` (`vendor/pkcs11-mock/src/pkcs11-mock.c:776-782`) returns `CKR_ATTRIBUTE_VALUE_INVALID` for any attribute with a NULL `pValue` or `ulValueLen <= 0`, so a marshalling regression in `ObjectAttribute` makes all 100 iterations `continue`; `baseline == OutstandingAllocationCount` and `created == destroyed` both hold at zero and the test reports green having exercised nothing. `Assert.Equal(created, destroyed)` can never fail on its own terms either: `destroyed++` sits in the `finally` immediately after `session.DestroyObject(key)`, so a destroy failure already propagates and the counters can only diverge via an exception that fails the test anyway.
- **Proposed action:** Assert `Assert.Equal(100, created)` — the mock accepts this template today, so it is a true invariant — and drop or replace the `created == destroyed` assertion with something the `finally` does not already guarantee.
- **Breaks public API?** No
- **Raised by:** QA A

### [BL-132] Fourteen `AllowInsecure`-bypass tests pass on *any* exception, so a broken gate that throws the wrong type stays green
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/Sign/SignRsaPkcsTests.cs:60-67`, `Integration/Digest/DigestMd5Sha1Tests.cs:63-70`, `Integration/Encrypt/EncryptAesTests.cs:142`, `Integration/Decrypt/DecryptAesTests.cs:80`, `Integration/Security/InsecureOperationGateTests.cs:64,118,203,226`, `Integration/Keys/UnwrapSecureDefaultsTests.Pkcs11Mock.cs:45,77`, `Integration/Keys/KeyCreationSecureDefaultsTests.Pkcs11Mock.cs:122,152`, `Integration/Keys/DeriveSharedSecretEcdhTests.Pkcs11Mock.cs:52,64`, `Algorithms/AesPkcs11TestCases.cs:137`
- **Problem:** The negative half of the secure-defaults suite is strongly asserted (`Assert.Throws<InsecureOperationException>` plus an assertion on `ex.Mechanism`). The positive half only asserts `!(ex is InsecureOperationException)` or swallows everything via a bare `catch`. Every one of these sites would pass if the operation threw `ArgumentException` from a broken parameter builder, `NotSupportedException`, or `ObjectDisposedException` — that is, if the call never reached the token at all. Mutating the gate to throw `InvalidOperationException` leaves all fourteen green.
- **Proposed action:** Narrow the acceptance set: assert the recorded exception is `null` or a `Pkcs11Exception`, which proves the call reached `C_*`; and where the fixture advertises the mechanism (SoftHSM supports `CKM_MD5`, `CKM_SHA_1`, `CKM_AES_ECB`, `CKM_AES_CFB128`) assert the operation actually succeeds rather than merely "did not throw the gate".
- **Breaks public API?** No
- **Raised by:** QA A

### [BL-133] Pull requests get no coverage signal at all — the Codecov upload is push-only and there is no threshold or quality gate
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `.github/workflows/code-quality.yml:194` (`if: github.event_name == 'push'` on the Codecov step), `:149` (`sonarscanner begin`, no `sonar.qualitygate.wait`); no `codecov.yml` at the repository root
- **Problem:** Coverage *is* collected (`--collect:"XPlat Code Coverage;Format=opencover,cobertura"` at `:132`) and imported into Sonar, but the Codecov upload is gated to `push`, so a pull request never receives a coverage delta or a Codecov status check. With no `codecov.yml` there are no `project`/`patch` targets either, and the Sonar scan does not wait on its quality gate — so a PR that adds an untested public method, or deletes a test file, is blocked by nothing. For a library whose safety case rests on test rigour, that removes the enforcement half of the coverage strategy.
- **Proposed action:** Change the condition to `github.event_name == 'push' || github.event.pull_request.head.repo.full_name == github.repository`, which keeps fork PRs excluded (the stated reason for the current gate); add a `codecov.yml` with a `patch` target so new code carries tests; and pass `/d:sonar.qualitygate.wait=true` so the Sonar verdict is a blocking check.
- **Breaks public API?** No
- **Raised by:** QA A

### [BL-134] No compile gate on the README and docs code snippets
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** M
- **Location:** `README.md:51-75,87-91,104-113,157-168,220-233`, `docs/diagnostics.md:11-16`; no samples project in `KerckhoffsLabs.sln` (now at the repository root) and none under `tests/`; `tests/AotSmoke` compiles none of the snippets
- **Problem:** The quickstart snippet is the flagship API demonstration (`Pkcs11Library` → `OpenSession(slotLabel:, CKU, SecurePin)` → `GenerateRsaKeyPair(modulusBits:, label:)` → `RSAPkcs11.SignData`) and the wrap-hardening snippet chains eight template-builder methods. The reviewer verified all of them resolve against the current surface today, but nothing compiles them — so the first pre-1.0 rename silently ships a broken quickstart, and the API is explicitly still moving (BL-008, BL-038, BL-039 were all signature changes; BL-063 through BL-071 add more). **This already happened**: BL-070's fix removed `GenerateRsaKeyPair` and the quickstart snippet above kept calling it, uncaught until a manual review noticed — exactly the silent-break scenario this entry predicted.
- **Follow-up note 2026-09-07:** the README snippet was manually patched to `GenerateRsaSigningKeyPair` after the fact; this entry's proposed action (a compiled samples project) is what would have caught it automatically.
- **Proposed action:** Add a small `tests/Samples` project (or a `Samples` folder in the test project) holding each snippet as a real compiled method, and reference them from the docs via docfx `[!code-csharp[](…#region)]` so the markdown and the compiled source cannot diverge. The `AllowInsecureScope` snippet uses `…` as a body placeholder, so extract it as a region rather than fencing raw markdown.
- **Breaks public API?** No
- **Raised by:** QA A
- **Spec / References:** BL-030 covers README *content*; this is snippet verification

### [BL-138] Only the default CA rule subset is active, so API-design and correctness rules are invisible despite the warnings-as-errors posture
- **Area:** Cross-cutting
- **Severity:** Medium
- **Effort:** M
- **Location:** `Directory.Build.props:9` (`EnableNETAnalyzers`, with no `AnalysisMode`/`AnalysisLevel` in any `.props` or `.csproj`); `.editorconfig` (no `dotnet_diagnostic.CAxxxx` entries)
- **Problem:** With `AnalysisMode` unset the SDK uses `Default`, which leaves roughly half the CA catalogue disabled — including rules that map directly onto findings this review process discovered by hand. CA1045 (avoid `out` parameters) is exactly BL-038; CA1707 (identifiers should not contain underscores) is exactly BL-009; CA1002 (`List<T>` in public signatures) is BL-142; and CA1062, CA2000, CA1014 (`[CLSCompliant]`, never declared although `uint`-backed enums and `ulong` parameters make the surface non-CLS-compliant), CA1815, CA1032, CA1064 and CA2225 all bear on the public surface this project calls its #1 risk. The naming section of `.editorconfig` is documentation only, so nothing in it fails a build. `TreatWarningsAsErrors` gives the repo the machinery to enforce all of this; it simply is not pointed at it.
- **Proposed action:** Set `<AnalysisMode>All</AnalysisMode>` (or at minimum `Recommended`, or `AnalysisModeApiDesign=All`) on the library project, then triage the resulting diagnostics into either fixes or explicit `.editorconfig` `dotnet_diagnostic.CAxxxx.severity = none` entries with a stated reason — a documented opt-out per rule is auditable, whereas today's silence is not. This also converts BL-009's naming decision from tribal knowledge into a checked-in, reviewable statement.
- **Breaks public API?** No
- **Raised by:** QA C, .NET Engineer A

### [BL-139] ⚠️ PARTIALLY RESOLVED — `code-quality.yml` cannot succeed on a fork pull request, so every external contribution shows a red check after roughly an hour of runner time
- **Status:** Partially resolved 2026-10-19. `dotnet-sonarscanner` is pinned to 12.0.0 (#213), and the job is skipped on runs Dependabot triggers, which get no `SONAR_TOKEN` (#209). The Codecov upload is push-only, so `fail_ci_if_error: true` can no longer fail a pull request.
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `.github/workflows/code-quality.yml:19-20` (`pull_request`), `:39` (job `if`), `:44-45` (`SONAR_TOKEN`), `:147-160` (`sonarscanner begin`), `:193-198` (Codecov)
- **Problem:** GitHub does not inject secrets into `pull_request` runs from forks, so `SONAR_TOKEN` is empty and `dotnet sonarscanner begin` cannot authenticate — but only *after* the job has installed Java, built OpenSSL 3.5.7 from source and compiled SoftHSM. Every first-time outside contributor therefore sees a failing check they cannot fix, and the project burns most of an hour of runner time per fork push. Separately, `fail_ci_if_error: true` on the Codecov upload means a Codecov outage fails the quality gate for reasons unrelated to the code. (The `pull_request` versus `pull_request_target` choice is correct everywhere — no workflow uses `pull_request_target`, which is the right call.)
- **Remaining scope:** A pull request from a fork still runs the whole job with an empty `SONAR_TOKEN` and fails at `dotnet sonarscanner begin` (`code-quality.yml:147-160`) after the native builds. The `if:` at `:39` keys on the actor, not on the head repository. A Codecov outage still fails the push run on `main` (`:198`).
- **Proposed action:** Guard the Sonar steps with `if: github.event.pull_request.head.repo.full_name == github.repository || github.event_name != 'pull_request'`, or move the scan to `push` plus a `workflow_run`-triggered companion. Drop `fail_ci_if_error: true` or scope it to `push`. While there, pin `dotnet tool install --global dotnet-sonarscanner` (`:93`) with `--version` for consistency with the docfx pin, since it runs unpinned in a job holding `SONAR_TOKEN`.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-140] `CONTRIBUTING.md` documents none of the build, and the build is unusually demanding
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `CONTRIBUTING.md:33-35` (the entire "Contributing code and content" section), versus `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj:66-173` (the `SkipNativeBuilds` master switch at `:66-79`; always-on `BuildPkcs11Mock`/`BuildAbiOracle`/`BuildPkcs11Gate`/`BuildSoftHsmV2`; opt-in `BuildKryoptic`/`BuildBouncyHsm`/`BuildCratonHsm`/`BuildFreeHsm`); `README.md:260-278` covers only the recursive clone
- **Problem:** A plain `dotnet build` of this solution compiles pkcs11-mock, SoftHSMv2 and a C gate shim from four git submodules and needs `build-essential`/`cmake`/autotools present, or MSVC plus vcpkg on Windows. `CONTRIBUTING.md` says nothing about `git clone --recursive`, the required native toolchain, the `SkipPkcs11MockBuild`/`SkipSoftHsmV2Build`/`SkipPkcs11GateBuild` escape hatches, `dotnet format` being a CI gate, or how to run the suite against a specific backend — so the first thing a new contributor sees is an opaque `Exec` failure inside an MSBuild target.
- **Proposed action:** Add a "Building and testing" section covering the recursive clone (and `git submodule update --init`), per-OS prerequisites, the three `Skip*` properties for a managed-only build, `dotnet format src/KerckhoffsLabs.sln` before pushing, and the `PKCS11_TEST_*` environment variables that select or require a backend.
- **Breaks public API?** No
- **Raised by:** QA C
- **Spec / References:** Extends BL-034 — the file now exists but omits everything a contributor needs in order to build

### [BL-141] The shipped analyzer is packed through a private NuGet target and its packaged form is never verified
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj:97-106` (`<Target Name="PackAnalyzer" BeforeTargets="_GetPackageFiles">`)
- **Problem:** Three analyzers plus the `PackedStructsGenerator` reach consumers only because this target hooks `_GetPackageFiles`, an undocumented NuGet-internal target; if it is renamed or reordered in a future SDK the analyzer silently vanishes from the package and the build still succeeds. Nothing asserts that the produced `.nupkg` contains `analyzers/dotnet/cs/…Generators.dll` (nor `README.md`/`icon.png`). The analyzers *are* dogfooded via `ProjectReference` in the test project, which is genuinely good, but that path exercises them as a project reference rather than as a package-delivered analyzer, so a wrong pack path or a Roslyn-version mismatch is invisible.
- **Proposed action:** Switch to a supported hook (`TargetsForTfmSpecificContentInPackage` or `TargetsForTfmSpecificBuildOutput`) and add a CI step that runs `dotnet pack` and asserts the expected entries exist in the archive. A small consumer smoke project referencing the packed `.nupkg` from a local feed would also prove `KLPKCS11008` fires as delivered.
- **Breaks public API?** No
- **Raised by:** QA C
- **Spec / References:** Extends BL-002. `Generators/PackedStructsGenerator.cs:36-42` correctly no-ops when a compilation declares no `[PackedForPkcs11]` structs, so shipping the generator to consumers is itself safe

## Low

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

### [BL-038] ⚠️ PARTIALLY RESOLVED — `WaitForSlotEvent` uses `void` + two `out` params instead of a Try/result shape, with a raw `ulong` slot id
- **Status:** Partially resolved 2026-09-18. `WaitForSlotEvent` returns `ulong?` (null when a non-blocking poll finds no event) instead of `void` with two `out` parameters (commit 0c41ecee).
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Library.cs:523`
- **Problem:** Classic Try-pattern case shipped as `void WaitForSlotEvent(bool, out bool, out ulong)`; the returned slot id has no path back to a `Pkcs11Slot`.
- **Remaining scope:** The slot comes back as a raw `ulong` rather than `SlotId?` or a `Pkcs11Slot`, so the BL-039 handle-wrapping rule still stops one call short, and an event still has no path back to a `Pkcs11Slot`. Location: `Pkcs11Library.cs:523`.
- **Proposed action:** Reshape as `bool TryWaitForSlotEvent(bool nonBlocking, out Pkcs11Slot? slot)` (or a result struct) before the signature is permanent.
- **Breaks public API?** Yes — land before 1.0
- **Raised by:** .NET Engineer A

### [BL-042] No documented SemVer/stability policy; own v3.2-only surface carries no `[Experimental]`
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** M
- **Location:** `README.md` (no stability section); `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs:647,673` (`MessageEncrypt`/`MessageDecrypt`), `:839,866` (`EncapsulateKey`/`DecapsulateKey`)
- **Problem:** `SlhDsaPkcs11` correctly propagates `[Experimental("SYSLIB5006")]`, but the library's own newest v3.2 surface (encapsulation, message-AEAD) has no stability signal, and nothing states what consumers may rely on across versions.
- **Proposed action:** Add a README stability/SemVer section; consider a project-specific `[Experimental]` diagnostic for the v3.2-only surface so 1.0 can ship a stable classical core.
- **Breaks public API?** No (attribute is breaking to *add* post-1.0 — another reason to do it now)
- **Raised by:** .NET Engineer A

### [BL-044] `CkmHashPqcSignParams` doc suggests `CKM_SHAKE_*` hashes the library deliberately does not map
- **Area:** Cryptography
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismParams/CkmHashPqcSignParams.cs:19` (contrast `Algorithms/Pkcs11MechanismMap.cs:195-199`)
- **Problem:** The param doc's example list includes `CKM_SHAKE_*`, which the mechanism map documents as intentionally unmapped (no standalone SHAKE hash mechanism in OASIS v3.2).
- **Proposed action:** Drop `CKM_SHAKE_*` from the example or add the map's rationale so low- and high-level docs agree.
- **Breaks public API?** No
- **Raised by:** Cryptographer A

### [BL-045] ⚠️ PARTIALLY RESOLVED — No sanity ceiling on module-reported lengths before allocation (length-probe DoS)
- **Status:** Partially resolved 2026-10-06 by #46. Every length a module reports before an allocation now goes through `ReportedLength.ForAllocation`. That refuses `CK_UNAVAILABLE_INFORMATION` and any length above `Array.MaxLength` with a `Pkcs11Exception` rather than an `OverflowException` (`LengthQuery_ReportingUnavailableInformation_IsRefused` in each `*DispatchTests` class).
- **Area:** P/Invoke
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11SessionCore.Marshalling.cs:142-180` (`CallWithLengthProbe`), `Native/ReportedLength.cs:17-22`, `Internal/Pkcs11SessionCore.Objects.cs:248-265`, `Native/UnmanagedMemory.cs:76`
- **Problem:** Every two-call probe allocates exactly the module-reported length; a buggy token claiming 2 GB for a label forces a giant allocation (checked casts prevent corruption, not OOM).
- **Remaining scope:** No ceiling below `Array.MaxLength` exists, so a module reporting about 2 GB for a label or signature still gets that allocation. The attribute read path (`Pkcs11SessionCore.Objects.cs:248-265`, `AllocateValueBuffers`) sizes from `valueLen` without going through `ForAllocation`.
- **Proposed action:** Add a configurable conservative ceiling with a typed exception in the probe and attribute-allocation loops.
- **Breaks public API?** No
- **Raised by:** Cryptographer B

### [BL-048] No consumer control over which interface/version is dispatched
- **Area:** PKCS#11 Conformance
- **Severity:** Low
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.Loader.cs:53-102`; `Pkcs11Library.cs:106,174`
- **Problem:** The library always negotiates the module's default (highest) interface; there is no way to pin dispatch to a named/lower-version interface — a common interop workaround for buggy v3.x implementations.
- **Proposed action:** Consider an opt-in on load (interface name / max version); at minimum document the default-interface behavior.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist A

### [BL-052] Token-removed / device-error mid-operation is only tested at the CKR-mapping level
- **Area:** QA
- **Severity:** Low
- **Effort:** M
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Unit/Exceptions/ExceptionMapperTests.cs:49-56`
- **Problem:** No test injects `CKR_DEVICE_REMOVED` between Init and Final to prove the session is left usable (busy-guard released, no unmanaged leak); the `ManagedSoftToken` fault-injection hooks already exist.
- **Proposed action:** Add a fake-injected device-removed mid-digest/mid-sign case asserting clean teardown.
- **Breaks public API?** No
- **Raised by:** QA B

### [BL-054] ⚠️ PARTIALLY RESOLVED — Publish-trigger and artifact hardening gaps (no environment gate, no concurrency guard, snupkg unattested)
- **Status:** Partially resolved 2026-10-19 by #215. The symbol package is attested alongside the `.nupkg` and the assemblies extracted from it, and the attested packages are attached to the GitHub release by a separate `contents: write` job.
- **Area:** Release Eng
- **Severity:** Low
- **Effort:** S
- **Location:** `.github/workflows/publish.yml:3-5`, `:16-21` (no `environment:`, no `concurrency:`), `:61-66` (attestation)
- **Problem:** Any `v*` tag triggers a push to an immutable package ID with no protected-environment approval or `concurrency` group; the symbol package is not attested; determinism is configured but never verified post-build.
- **Remaining scope:** Any `v*` tag still publishes with no protected-Environment approval and no `concurrency` group (`publish.yml:3-5`, `:16-21`), and nothing verifies after the build that it is deterministic.
- **Proposed action:** Gate publish behind a protected GitHub Environment, add a `concurrency` group, and consider attesting the snupkg. The OIDC + provenance flow itself is already strong.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-143] `EncapsulateKey`'s `expectedCiphertextLen` puts a token quirk in the public signature
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs:825-842` (the `int expectedCiphertextLen = 0` parameter and its doc); quirk cache at `Pkcs11Library.cs:64` (`MlKemDecapsulateOmitsValueLen`)
- **Problem:** A magic-zero `int` whose only purpose is to work around SoftHSM's non-conforming `C_EncapsulateKey` sits in the signature of the flagship v3.2 KEM entry point. Every consumer now has to understand a module bug in order to call it, and the parameter can never be removed once shipped. The library already has the right home for this: the per-token quirk cache on `Pkcs11Library` (`Pkcs11Library.cs:54-61`, `MlKemDecapsulateOmitsValueLen`).
- **Proposed action:** Derive the length internally from the key's `CKA_PARAMETER_SET` — ML-KEM ciphertext sizes are fixed per parameter set — and fall back to probe-then-retry, learning the quirk the way `MlKemDecapsulateOmitsValueLen` already does. Then drop the parameter, or mark it `[EditorBrowsable(Never)]` if it must remain as an escape hatch.
- **Breaks public API?** Yes — removing a parameter is SemVer-major; land before 1.0
- **Raised by:** .NET Engineer A

### [BL-144] ⚠️ PARTIALLY RESOLVED — Four v3.x `CKF` constants are absent, leaving one documented by name only and one publicly documented as magic numbers
- **Status:** Partially resolved 2026-09-18 (commit ae172401). `CkmHkdfParams` takes a typed `HkdfSaltType` (`Null`/`Data`/`Key`, the `CKF_HKDF_SALT_*` values) through one factory per salt source, and `CkmXeddsaParams` takes a `CKM` hash type, so neither public constructor asks for a bare `ulong` any more.
- **Area:** PKCS#11 Conformance
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKF.cs` (no `CKF_END_OF_MESSAGE`, no `CKF_HKDF_SALT_NULL`/`_DATA`/`_KEY`); `Native/LowLevelPkcs11Library.MessageEncryption.cs:64` and `.MessageDecryption.cs:64` reference `CKF_END_OF_MESSAGE` by name in XML docs
- **Problem:** These are the only four v3.x `CKF_*` constants missing from `CKF`, verified by diffing all 69 `CKF_*` defines in `vendor/nss/lib/util/pkcs11t.h` against `Common/CKF.cs` — every other name and value matches exactly. The public `CkmHkdfParams` constructor therefore asks callers for a bare `ulong` and spells the legal values out in prose, which is the opposite of the project's strongly-typed-constants rule. `CkmXeddsaParams` has the same shape for `CK_XEDDSA_HASH_TYPE`.
- **Remaining scope:** `Common/CKF.cs` still has no `CKF_END_OF_MESSAGE` or `CKF_HKDF_SALT_NULL`/`_DATA`/`_KEY`. These are the only 4 of the 72 `CKF_*` defines in the vendored NSS 3.132 `pkcs11t.h` that it lacks. `CKF_END_OF_MESSAGE` is still named only in the XML docs of `LowLevelPkcs11Library.MessageEncryption.cs:64` and `MessageDecryption.cs:64`.
- **Proposed action:** Add `CKF_END_OF_MESSAGE = 0x00000001` and `CKF_HKDF_SALT_NULL`/`_DATA`/`_KEY` = 0x01/0x02/0x04 to `CKF`, and add a typed salt-type enum overload on `CkmHkdfParams` (keeping the `ulong` form for vendor salt types) plus an `XEdDsaHashType` enum on `CkmXeddsaParams`.
- **Breaks public API?** No — additive
- **Raised by:** PKCS#11 Specialist A, Cryptographer A
- **Spec / References:** `vendor/nss/lib/util/pkcs11t.h:1708`, `:2423-2425`

### [BL-145] No template-builder support for `CKA_PARAMETER_SET`, so PQC key generation needs an untyped escape hatch
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Objects/PublicKeyTemplateBuilder.cs`, `Objects/PrivateKeyTemplateBuilder.cs`; `Objects/ObjectAttribute.cs:136-142` (which has `(CKA, CKC)`, `(CKA, CKK)` and `(CKA, CKO)` overloads but none for the PQC parameter-set enums)
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

### [BL-147] ⚠️ PARTIALLY RESOLVED — `CK_ULONG` scalars are written and read with hard-coded little-endian primitives, and one overload truncates silently on Windows where its sibling throws
- **Status:** Partially resolved 2026-09-30 by #26. Every `ObjectAttribute` constructor writes `CK_ULONG` values through one helper that refuses a value wider than the platform's `CK_ULONG` with `ArgumentOutOfRangeException`, so a vendor value above `uint.MaxValue` now throws on Windows from every overload instead of being truncated by one (`ObjectAttributeTests.Ulong_WiderThan32Bits_IsRefused_WhereCkUlongIs32Bits`).
- **Area:** P/Invoke
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Objects/ObjectAttribute.cs:240-249` (`WriteCULong`), little-endian primitives at `:246-248`, `:279-280`, `:393-394`; `MechanismParams/CkmSp800108KdfParams.cs:316-327`; contrast `MechanismParams/Pkcs11ParameterWriter.cs:193`, which branches on `BitConverter.IsLittleEndian`
- **Problem:** Two inconsistencies in one family of code. `ObjectAttribute(ulong type, ulong value)` writes the value with `WriteUInt64LittleEndian` and then slices to the native `CK_ULONG` width, so on Windows the high 32 bits are **discarded silently** — while `ObjectAttribute(ulong, List<ulong>)` twenty lines later uses `checked((uint)…)` and throws for the same input. A consumer passing a vendor attribute value above `uint.MaxValue` therefore gets a wrong attribute on Windows and an exception on Linux. Separately, all of these paths hard-code little-endian for bytes the *local* module reads in native byte order; `Pkcs11ParameterWriter` gets this right, so the codebase disagrees with itself. Inert on the six shipped RIDs, all of which are little-endian, but the divergence is the kind of thing that outlives a RID list.
- **Remaining scope:** `CK_ULONG` scalars are still written and read with hard-coded little-endian primitives (`ObjectAttribute.cs:246-248`, `:279-280`, `:393-394`; `CkmSp800108KdfParams.cs:316-327`), while `Pkcs11ParameterWriter.cs:193` uses native byte order. This has no effect on the shipped little-endian RIDs.
- **Proposed action:** Route every `CK_ULONG` scalar through one helper — reuse `Pkcs11ParameterWriter`'s endianness branch, or `BinaryPrimitives.Write{U}IntNativeEndian` — and make the narrowing `checked` everywhere, so all overloads fail the same way on Windows instead of one truncating.
- **Breaks public API?** No
- **Raised by:** .NET Engineer B

### [BL-148] ⚠️ PARTIALLY RESOLVED — The `(array, count)` pairs crossing the P/Invoke boundary are never checked against each other
- **Status:** Partially resolved 2026-08-11 (commit 737a762f, which took spans across the interop surface). Every attribute-template and handle-array wrapper takes a span and derives the count it passes from the span's length, so the two can no longer disagree.
- **Area:** P/Invoke
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.General.cs:89` (`C_GetInterfaceList`, the one array/count pair left); the span-taking wrappers, e.g. `Native/LowLevelPkcs11Library.Object.cs:92` (`C_GetAttributeValue`), `:153` (`C_FindObjects`)
- **Problem:** Every array-taking interop method takes a separate `NativeCULong count`, pins the array with `fixed`, and hands both to the module without asserting `count <= array.Length`. Callers inside `Pkcs11SessionCore` always pass `template.Length`, so nothing is broken today — but `ILowLevelPkcs11Library` is the seam the test fakes implement, and the only place where a mismatch turns into the module writing past a pinned managed array: real heap corruption, not a bounds check. The whole point of this layer is that a mistake above it cannot corrupt memory.
- **Remaining scope:** `C_GetInterfaceList` (`Native/LowLevelPkcs11Library.General.cs:89`) still takes `CK_INTERFACE[]?` with a separate in/out `ref NativeCULong count`. The caller's count goes to the module as the buffer capacity without a check against `interfaces.Length`; the post-call `CheckedOutput` check runs only after the module has written.
- **Proposed action:** Add `ArgumentOutOfRangeException.ThrowIfGreaterThan((ulong)count, (ulong)(template?.Length ?? 0))` at the top of each array-taking wrapper, or drop the redundant `count` parameter and derive it from the array length.
- **Breaks public API?** No
- **Raised by:** .NET Engineer B

### [BL-149] Generated Windows siblings carry `CharSet = CharSet.Unicode` on structs whose PKCS#11 fields are single-byte
- **Area:** P/Invoke
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.SourceGenerators/PackedStructsGenerator.cs:66`; visible in every emitted file
- **Problem:** The generator hard-codes `[StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]`. It is inert today because no `CK_*` struct declares a `char` or `string` field — fixed-length fields are `[InlineArray]` byte buffers (`Native/CkCharBuffer.cs`) — so `Marshal.SizeOf` and the pinned layouts are unaffected. But PKCS#11 fixed-length fields are blank-padded, non-NUL-terminated **single-byte** arrays; the day someone adds a `char` or `ByValTStr` field to a marked struct, `CharSet.Unicode` doubles its marshalled width on Windows only, and the existing managed-versus-marshalled size guard would be the only thing standing between that and a wrong-layout call.
- **Proposed action:** Emit `CharSet = CharSet.Ansi`, or omit `CharSet` entirely — which is what the hand-written unified structs do (`Native/CK_TOKEN_INFO.cs:8`) — so a generated sibling cannot diverge from its source struct's layout rules.
- **Breaks public API?** No — all affected types are internal
- **Raised by:** .NET Engineer B

### [BL-151] `C_OpenSession`'s `pApplication`/`Notify` are hardcoded NULL with no documented decision
- **Area:** PKCS#11 Conformance
- **Severity:** Low
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Slot.cs:231-238` (`OpenSessionCore`); `Native/LowLevelPkcs11Library.Session.cs:48-51` (the remark states that `pApplication` and `Notify` are NULL, not why)
- **Problem:** Every session is opened with both `pApplication` and `Notify` as `IntPtr.Zero`, so `CK_NOTIFY` callbacks — `CKN_SURRENDER` (progress and cancellation, the mechanism `CKR_FUNCTION_CANCELED` exists for) and `CKN_OTP_CHANGED` — can never be delivered. Under `[assembly: DisableRuntimeMarshalling]` a callback would need `[UnmanagedCallersOnly]`, so this looks deliberate and is a defensible choice for an AOT-friendly wrapper. But it is nowhere stated, and it leaves `WaitForSlotEvent` as the only token-presence signal.
- **Proposed action:** Document the decision on `Pkcs11Slot.OpenSessionCore` and in the threading/notification documentation. If it is intended to be permanent, say so — adding a notification surface later is additive but changes the session-lifetime contract.
- **Breaks public API?** No
- **Raised by:** PKCS#11 Specialist B, .NET Engineer B
- **Spec / References:** PKCS#11 v3.2 §5.21 (`CK_NOTIFY`, `CKN_SURRENDER`)

### [BL-152] `Pkcs11ECCurve` lacks `[MemberNotNullWhen]`, forcing consumers to null-forgive `Oid`
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11ECCurve.cs:42` (`public string? Oid`), `:55` (`IsNamed`), `:58` (`IsDefault => Oid is null`)
- **Problem:** `IsDefault` and `IsNamed` are exactly the guards that establish `Oid`'s nullability, but neither is annotated, so a consumer who checks `if (!curve.IsDefault)` still receives a nullable `Oid` and must write `!`. For a library that enables nullable reference types and cares about accuracy on the public surface, this is a cheap gap.
- **Proposed action:** Add `[MemberNotNullWhen(false, nameof(Oid))]` on `IsDefault` and `[MemberNotNullWhen(true, nameof(Oid))]` on `IsNamed`.
- **Breaks public API?** No — additive annotation
- **Raised by:** .NET Engineer A

### [BL-153] `NssBackendFixture` documents a `BuildNss` MSBuild target that does not exist, and its built-path probe can never succeed in CI
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/NssBackendFixture.cs:14-16` and `:199-206`; CI builds NSS with `build/build-nss.sh` and sets `PKCS11_TEST_NSS_LIBRARY` (`.github/workflows/ci.yml:291-298`, `asan.yml:110-112`); the test project has no `BuildNss` target
- **Problem:** The type doc says the library "is built from the `vendor/nss` submodule and staged next to the test assembly by the `BuildNss` MSBuild target"; no such target exists anywhere in the repository. NSS is staged by `.github/workflows/ci.yml` into `$RUNNER_TEMP/nss/...` and located purely via `PKCS11_TEST_NSS_LIBRARY`, so `BuiltLibraryPath()` — which probes `<asmdir>/runtimes/<rid>/native/nss/libsoftokn3.so` — never resolves, and the environment variable is the sole real path, the inverse of the documented precedence. A contributor trying to run the NSS suite locally will look for a target that is not there.
- **Proposed action:** Either add the `BuildNss` target for parity with the other three backends, or correct the doc to say NSS is provisioned out of band via `PKCS11_TEST_NSS_LIBRARY` — as `OpenCryptokiBackendFixture` honestly states — and drop the unreachable `BuiltLibraryPath()` probe.
- **Breaks public API?** No
- **Raised by:** QA A

### [BL-154] The docs build is never validated on a pull request, so `docfx --warningsAsErrors` breaks only after merge
- **Area:** Release Eng
- **Severity:** Low
- **Effort:** S
- **Location:** `.github/workflows/docs.yml:4-13` (`push: branches: [main]` plus `workflow_dispatch` only) and `:52` (`dotnet docfx docs/docfx.json --warningsAsErrors`)
- **Problem:** The docs job triggers on `src/**` as well as `docs/**` and runs docfx with warnings as errors, so an unresolved `<see cref>` or a malformed XML doc comment in a library PR passes CI and then breaks the Pages deployment on `main`. For a library whose public docs site is the primary reference, the break lands on the published artifact rather than on the contributor.
- **Proposed action:** Add a `pull_request` trigger that runs the `build` job only, leaving `deploy` gated on `push` to `main`. Nothing else needs to change — the workflow's per-job permission split is already least-privilege.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-155] ⚠️ PARTIALLY RESOLVED — Vendored submodules are pinned to untagged upstream commits, with no in-tree record of why and no review gate on bumps
- **Status:** Partially resolved 2026-10-29 (#211, #128, #242, #243, #261, and the FreeHSM v2.5.1 bump). `.github/CODEOWNERS` assigns every path to the maintainer, and the main ruleset requires a code owner's review (#211, 2026-10-19). The `ci.yml` comment now describes the opencryptoki pin correctly as master after v3.27.0 (#128). NSS, Kryoptic, BouncyHsm, pkcs11-mock and FreeHSM are pinned to release tags (`NSS_3_132_RTM`, `v1.5.4`, `v2.3.4`, `v2.0.0`, `v2.5.1`; #242, #243, #261 and the FreeHSM bump).
- **Area:** Release Eng
- **Severity:** Low
- **Effort:** S
- **Location:** `.gitmodules`; untagged pins `vendor/softhsmv2` = `884cb38f` (28 commits past `2.7.0`), `vendor/opencryptoki` = `1cf36153` (390 past `v3.27.0`), `vendor/craton-hsm-core` = `89c6daf8` (v0.10.6 by its version bump; no upstream tags); `.github/dependabot.yml` (no `gitsubmodule` ecosystem)
- **Problem:** Two of the four backends are pinned to mid-development upstream commits rather than releases, so the "three independent real backends" evidence rests partly on unreleased upstream code — and the `ci.yml` comment misstates the opencryptoki pin as the v3.27.0 release. Submodule SHAs also feed the native-artifact cache key (`ci.yml:170`), so a bump silently changes what the whole matrix tests. There is no `CODEOWNERS` and no `gitsubmodule` entry for dependency automation, so a submodule bump arrives as an opaque one-line SHA diff.
- **Remaining scope:** SoftHSMv2 (`884cb38f`, 28 commits past 2.7.0), opencryptoki (`1cf36153`, 390 past v3.27.0) and craton-hsm-core (`89c6daf8`, the v0.10.6 version bump; no upstream tags) are still untagged pins, with no in-tree record of why. `dependabot.yml` covers `nuget`, `pip` and `github-actions` but not `gitsubmodule`.
- **Proposed action:** Move each submodule to a tagged release where possible, or add a short `vendor/README.md` recording why each non-tag pin was chosen and what it fixes; correct the `ci.yml:225` comment; and add `.github/CODEOWNERS` covering `vendor/`, `.github/workflows/`, `build/` and `Directory.Build.props` so infrastructure and pin changes always require an owner's review.
- **Breaks public API?** No
- **Raised by:** QA C
- **Spec / References:** Extends BL-032, which covers the `nuget`/`github-actions` ecosystems but not `gitsubmodule`, the untagged pins, or `CODEOWNERS`

### [BL-156] ⚠️ PARTIALLY RESOLVED — Two remaining unverified third-party build inputs, and `NuGet.config` does not clear inherited sources
- **Status:** Partially resolved 2026-10-19 by #212. NSS's build tools (`gyp-next` and its dependencies) install from the hash-locked `build/requirements-nss.txt` with `--require-hashes`.
- **Area:** Release Eng
- **Severity:** Low
- **Effort:** S
- **Location:** `build/build-softhsmv2.ps1:75-77` (`vcpkg install openssl:$triplet` against the runner image's baseline); `.github/workflows/ci.yml:132`, `:233` (cache key `vcpkg-openssl-<arch>-windows-v1`); `NuGet.config:3-6` (no `<clear />`)
- **Problem:** Source integrity is otherwise handled well — the OpenSSL 3.5.7 tarball is SHA-256 verified in both workflows, and all three SoftHSM 2.5 `.deb`s are fetched from content-addressed Debian snapshot URLs with pinned digests and a post-extract version assertion (`build/setup-softhsm25.sh:30-65`). Three gaps remain: `gyp-next` is installed by version only, with no `--require-hashes`; the Windows SoftHSM's OpenSSL floats with whatever baseline the runner image's vcpkg carries — the script's own comment only guesses "3.6+" — and that version is neither pinned nor reflected in the vcpkg cache key, so the cache can serve a different OpenSSL than the one a later run would build; and `packageSources` has no `<clear />`, so machine- and user-level feeds merge in, largely but not entirely neutered by the `packageSourceMapping` block, which is otherwise exactly right.
- **Remaining scope:** The Windows SoftHSM's OpenSSL still floats with the runner image's vcpkg baseline (`build/build-softhsmv2.ps1:75-77`), and its cache key (`vcpkg-openssl-<arch>-windows-v1`) does not record the version. `NuGet.config`'s `<packageSources>` still has no `<clear />`, and it no longer has a `packageSourceMapping` block, so inherited machine and user feeds now merge in unrestricted.
- **Proposed action:** Pin `gyp-next` with a hash-locked requirements file; pin the vcpkg tree (a checked-out SHA, or manifest mode with a `builtin-baseline`) and fold the resolved OpenSSL version into the cache key; and add `<clear />` as the first child of `<packageSources>`.
- **Breaks public API?** No
- **Raised by:** QA C

### [BL-158] `CKM_PKCS5_PBKD2` only exercised against Kryoptic and NSS — SoftHSM2/opencryptoki never register it
- **Area:** Interop / Test coverage
- **Severity:** Info
- **Effort:** — (documented, no fix possible on either side)
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/Rfc2898DeriveBytesPkcs11.cs`, `MechanismParams/CkmPkcs5Pbkd2Params.cs`; `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Algorithms/Rfc2898DeriveBytesPkcs11Tests*.cs`, `Rfc2898DeriveBytesPkcs11TestCases.cs`
- **Problem:** Prompted by [latchset/kryoptic#277](https://github.com/latchset/kryoptic/issues/277) (which asks Kryoptic's own suite to extend its PBKDF2 tests beyond the HMAC-SHA1 PRF), a source audit of all four vendored backends found `CKM_PKCS5_PBKD2` had zero coverage here at all — there wasn't even a high-level wrapper to call it with. Backend audit: Kryoptic implements it fully (`src/pbkdf2.rs`, all 7 `CKP_PKCS5_PBKD2_HMAC_*` PRFs except GOST). NSS implements it too (registered in `pkcs11.c`'s mechanism table, dispatched from `NSC_GenerateKey`, SHA1/224/256/384/512). SoftHSM2 only defines the `CKM_PKCS5_PBKD2` constant in its vendored `pkcs11.h` header — no dispatch anywhere in its crypto backend. opencryptoki's soft token has `compute_PKCS5_PBKDF2_HMAC`, but only as an internal helper deriving its own master key from the SO/user PIN — it is never registered in `mech_list.c` or reachable from `C_GenerateKey`/`C_DeriveKey`.
- **Proposed action:** None — this is a real capability gap in SoftHSM2 and opencryptoki, not a wrapper bug. `Rfc2898DeriveBytesPkcs11` (BCL-`Rfc2898DeriveBytes`-shaped, over `CkmPkcs5Pbkd2Params`) is the exposed API; its `PrfForHash` switch supports exactly SHA-1/256/384/512 — not SHA-224, even though Kryoptic and NSS both implement `CKP_PKCS5_PBKD2_HMAC_SHA224` — because `System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2` has no SHA-224 support either (confirmed: `HashAlgorithmName` has no `SHA224` field, and passing a manually-constructed `HashAlgorithmName("SHA224")` throws `CryptographicException: 'SHA224' is not a known hash algorithm`). With no independent reference to cross-check against, excluding it is a deliberate scope match to the BCL type this wrapper mirrors, not a test gap. The test suite cross-checks Kryoptic and NSS output against `Rfc2898DeriveBytes.Pbkdf2` for all four PRFs it does support, and also exercises `GetBytes`'s stream-continuation semantics against the BCL. SoftHSM2/opencryptoki's test files exist for symmetry; only the cases that actually invoke `CKM_PKCS5_PBKD2` skip via `RequireMechanism` — the constructor/argument-validation cases never touch the token and genuinely pass on both (empirically confirmed: 12 of 24 pass, 12 skip on SoftHSM2). Revisit only if either project adds the mechanism upstream.
- **Breaks public API?** No (adds `Rfc2898DeriveBytesPkcs11` and `CkmPkcs5Pbkd2Params`, purely additive)
- **Raised by:** Cross-referencing kryoptic#277 against this wrapper's own test coverage
- **Corrected 2026-09-19:** the original wording overclaimed "every PRF both support" (SHA-224 is supported by Kryoptic/NSS but has no BCL reference to test against, so it's out of scope by design, not an oversight) and "skip everything via RequireMechanism" (only the cases that touch the token do); both re-verified against source and an actual test run.
- **Corrected 2026-10-26:** FreeHSM, added as a backend by #259, is a third implementation. Its `CKM_PKCS5_PBKD2` cases cross-check against `Rfc2898DeriveBytes.Pbkdf2` in CI as Kryoptic's and NSS's do. SoftHSM2, opencryptoki, BouncyHsm and Craton HSM do not advertise the mechanism, so their copies skip the cases that reach the token. The `Rfc2898DeriveBytesPkcs11TestCases` class doc still names only Kryoptic and NSS.

### [BL-161] Lift the BouncyHsm empty-digest gate once BouncyHsm digests empty data
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/BouncyHsmBackendFixture.cs` (`BouncyHsmAcceptsEmptyDigest`)
- **Problem:** BouncyHsm v2.3.3 refused zero-length data in `C_Digest`/`C_DigestUpdate`/`C_Verify` (`CKR_ARGUMENTS_BAD`) and `C_Sign` (`CKR_GENERAL_ERROR`). The fix for harrison314/BouncyHsm#115, in the 8a5584ab bump, lets empty data through the client and signs and verifies it, so the EmptyInput HMAC case runs again. A digest of empty data is still refused, and still is at v2.3.4 (#261): `DigestSessionState.Final` answers it with `CKR_DATA_LEN_RANGE`, so the EmptyInput SHA-256 case still skips.
- **Proposed action:** After a `vendor/bouncyhsm` bump that digests empty data, `BouncyHsmQuirkTests.EmptyDigest_QuirkStillPresent` fails. Then set the flag to true and delete the test.
- **Breaks public API?** No
- **Raised by:** BouncyHsm backend

### [BL-167] Lift the BouncyHsm empty-signature gate once BouncyHsm verifies an empty signature
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/BouncyHsmBackendFixture.cs` (`BouncyHsmAcceptsEmptySignature`, `WrongLengthRsaSignatureRejectionAvailable`); `Integration/Verify/SignatureLengthTests.BouncyHsm.cs` (`Rsa_WrongLengthSignature_ReturnsFalse`)
- **Problem:** BouncyHsm's native client refuses `ulSignatureLen == 0` in `C_Verify` and `C_VerifyFinal` with `CKR_ARGUMENTS_BAD` (`bouncy-pkcs11.c`), where an empty signature is simply invalid and should get `CKR_SIGNATURE_INVALID` or `CKR_SIGNATURE_LEN_RANGE`. `SignatureLengthTestCases.Assert_Rsa_WrongLengthSignature_ReturnsFalse` includes an empty signature, so `Rsa_WrongLengthSignature_ReturnsFalse` skips on BouncyHsm; the ECDSA and HMAC wrong-length cases still run there. Not yet reported upstream.
- **Proposed action:** Report it upstream. After a `vendor/bouncyhsm` bump that verifies an empty signature, `BouncyHsmQuirkTests.EmptySignature_QuirkStillPresent` fails. Then set the flag to true and delete the test.
- **Breaks public API?** No
- **Raised by:** BouncyHsm backend

### [BL-168] Lift the BouncyHsm SP 800-108 double-pipeline gate once its A chain matches SP 800-108
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/BouncyHsmBackendFixture.cs` (`BouncyHsmDoublePipelineMatchesSp800108`, `Sp800108DoublePipelineAvailable`); `Integration/Derive/Sp800108ChainedKdfTests.BouncyHsm.cs` (`DoublePipeline_HmacSha256_MatchesReference`)
- **Problem:** BouncyHsm's `Sp800_108DoublePipelineKdf` computes A(1) = PRF(fixed input), as SP 800-108 §5.3 does, then applies the PRF again before the first block, so block i is keyed on A(i+1) and the output is not SP 800-108's. NSS agrees with the managed reference in `Sp800108ChainedKdfTestCases`; BouncyHsm's output equals that reference with one extra PRF on the A chain. Feedback mode matches the reference. Not yet reported upstream.
- **Proposed action:** Report it upstream. After a `vendor/bouncyhsm` bump with the fix, `BouncyHsmQuirkTests.Sp800108DoublePipeline_QuirkStillPresent` fails. Then set the flag to true and delete the test.
- **Breaks public API?** No
- **Raised by:** BouncyHsm backend

### [BL-169] Lift the wolfPKCS11 derived-key sensitivity gate once C_DeriveKey takes the template's CKA_SENSITIVE and CKA_EXTRACTABLE
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/WolfPkcs11BackendFixture.cs` (`WolfPkcs11DerivedKeysTakeTheTemplatesSensitivity`, `DerivedKeyReadbackAvailable`)
- **Problem:** wolfPKCS11 v2.2.0's `C_DeriveKey` makes a key derived from a sensitive base sensitive, and one from a non-extractable base non-extractable, whatever the template asks, so the ECDH secret and the HKDF output cannot be read back and `ECDiffieHellmanPkcs11`'s raw-secret and KDF methods and `HkdfPkcs11` fail on it. PKCS#11 v3.2 §6.3.17 and §6.62.3 let the template set either value; the base key decides only `CKA_ALWAYS_SENSITIVE` and `CKA_NEVER_EXTRACTABLE`. Not yet reported upstream; the draft is with the maintainer.
- **Proposed action:** Report it upstream. After a `vendor/wolfpkcs11` bump with the fix, `WolfPkcs11QuirkTests.DerivedKeySensitivity_QuirkStillPresent` fails. Then set the flag to true and delete the test.
- **Breaks public API?** No
- **Raised by:** wolfPKCS11 backend

### [BL-170] Lift the wolfPKCS11 empty-OAEP-message gate once RSA-OAEP takes an empty message
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/WolfPkcs11BackendFixture.cs` (`WolfPkcs11AcceptsEmptyOaepMessage`)
- **Problem:** RSA-OAEP `C_Encrypt` of zero bytes gives `CKR_FUNCTION_FAILED`, and `C_Decrypt` of another implementation's ciphertext of it `CKR_ENCRYPTED_DATA_INVALID`; RFC 8017 §7.1 allows any length up to k - 2hLen - 2. The OAEP cases leave the empty message out on wolfPKCS11 (`emptyData`). Not yet reported upstream; the draft is with the maintainer.
- **Proposed action:** Report it upstream. After a `vendor/wolfpkcs11` bump with the fix, `WolfPkcs11QuirkTests.EmptyOaepMessage_QuirkStillPresent` fails. Then set the flag to true and delete the test.
- **Breaks public API?** No
- **Raised by:** wolfPKCS11 backend

### [BL-171] Lift the wolfPKCS11 malformed-signature gate once C_Verify answers it with CKR_SIGNATURE_INVALID
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/WolfPkcs11BackendFixture.cs` (`WolfPkcs11RejectsMalformedSignatures`, `MalformedSignatureRejectionAvailable`)
- **Problem:** `C_Verify` answers a malformed or out-of-range signature with `CKR_FUNCTION_FAILED` instead of `CKR_SIGNATURE_INVALID`: every altered RSA PKCS#1 v1.5 signature, RSA-PSS at or above the modulus, ECDSA P-521 with r or s above 2^521, ML-DSA with a malformed hint. The signature laws and the PSS round trips that alter a signature skip on wolfPKCS11. Not yet reported upstream; the draft is with the maintainer.
- **Proposed action:** Report it upstream. After a `vendor/wolfpkcs11` bump with the fix, `WolfPkcs11QuirkTests.MalformedSignature_QuirkStillPresent` fails. Then set the flag to true and delete the test.
- **Breaks public API?** No
- **Raised by:** wolfPKCS11 backend

### [BL-172] Lift the wolfPKCS11 wrong-length-RSA-signature gate once C_Verify answers it with CKR_SIGNATURE_LEN_RANGE
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/WolfPkcs11BackendFixture.cs` (`WolfPkcs11RejectsWrongLengthRsaSignatures`, `WrongLengthRsaSignatureRejectionAvailable`)
- **Problem:** `C_Verify` of an RSA signature of the wrong length (empty, short or padded; PSS and PKCS#1 v1.5) gives `CKR_FUNCTION_FAILED` instead of `CKR_SIGNATURE_LEN_RANGE`, so `SignatureLengthTests_WolfPkcs11.Rsa_WrongLengthSignature_ReturnsFalse` skips. Not yet reported upstream; the draft is with the maintainer.
- **Proposed action:** Report it upstream. After a `vendor/wolfpkcs11` bump with the fix, `WolfPkcs11QuirkTests.WrongLengthRsaSignature_QuirkStillPresent` fails. Then set the flag to true and delete the test.
- **Breaks public API?** No
- **Raised by:** wolfPKCS11 backend

### [BL-173] Lift the wolfPKCS11 RSA-1024 gate once CKM_RSA_PKCS_KEY_PAIR_GEN generates the minimum it advertises
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/WolfPkcs11BackendFixture.cs` (`WolfPkcs11GeneratesItsMinimumRsaKeySize`)
- **Problem:** `CKM_RSA_PKCS_KEY_PAIR_GEN` advertises 1024 bits as its minimum (a constant in `src/slot.c`) but fails to make a 1024-bit key with `CKR_FUNCTION_FAILED`, because wolfSSL's default `RSA_MIN_SIZE` is 2048. The 1024 row of the RSA key-size sweep skips. Not yet reported upstream; the draft is with the maintainer.
- **Proposed action:** Report it upstream. After a `vendor/wolfpkcs11` bump with the fix, `WolfPkcs11QuirkTests.MinimumRsaKeySize_QuirkStillPresent` fails. Then set the flag to true and delete the test.
- **Breaks public API?** No
- **Raised by:** wolfPKCS11 backend

### [BL-174] Lift the wolfPKCS11 wrap-template gate once C_GenerateKey takes CKA_WRAP_TEMPLATE and CKA_UNWRAP_TEMPLATE
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/WolfPkcs11BackendFixture.cs` (`WolfPkcs11AcceptsWrapTemplates`, `WrapTemplateAvailable`)
- **Problem:** `CKA_WRAP_TEMPLATE` or `CKA_UNWRAP_TEMPLATE` makes `C_GenerateKey` fail with `CKR_ATTRIBUTE_VALUE_INVALID`: wolfPKCS11 lists them as byte arrays (`src/crypto.c`) rather than the attribute arrays PKCS#11 v3.2 §4.10 defines, so `Pkcs11Session.GenerateAesKeyEncryptionKey` cannot work on it and the KEK cases skip. Not yet reported upstream; the draft is with the maintainer.
- **Proposed action:** Report it upstream. After a `vendor/wolfpkcs11` bump with the fix, `WolfPkcs11QuirkTests.WrapTemplate_QuirkStillPresent` fails. Then set the flag to true and delete the test.
- **Breaks public API?** No
- **Raised by:** wolfPKCS11 backend

### [BL-175] Lift the wolfPKCS11 EC-unwrap gate once wolfPKCS11 unwraps EC private keys
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/WolfPkcs11BackendFixture.cs` (`WolfPkcs11UnwrapsEcPrivateKeys`, `EcPrivateKeyUnwrapAvailable`)
- **Problem:** A capability rather than a departure: wolfPKCS11 wraps and unwraps only RSA private keys and AES, generic-secret and HKDF keys (`CHECK_WRAPPABLE` in `src/crypto.c`), so `C_UnwrapKey` of an EC private key gives `CKR_KEY_NOT_WRAPPABLE`, and no mechanism flag says so.
- **Proposed action:** After a `vendor/wolfpkcs11` bump with the fix, `WolfPkcs11QuirkTests.EcPrivateKeyUnwrap_StillMissing` fails. Then set the flag to true and delete the test.
- **Breaks public API?** No
- **Raised by:** wolfPKCS11 backend

### [BL-176] Lift the wolfPKCS11 session-object gate once session objects are visible to every session of the application
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/WolfPkcs11BackendFixture.cs` (`WolfPkcs11SharesSessionObjectsAcrossSessions`, `SharedSessionObjectsAvailable`)
- **Problem:** wolfPKCS11 keeps session objects per session: another session of the application does not find one and cannot use its handle. PKCS#11 v3.2 §4.4.1 makes a session object the application's, seen by every session until the one that made it closes. Not yet reported upstream; the draft is with the maintainer.
- **Proposed action:** Report it upstream. After a `vendor/wolfpkcs11` bump with the fix, `WolfPkcs11QuirkTests.SessionObjectVisibility_QuirkStillPresent` fails. Then set the flag to true and delete the test.
- **Breaks public API?** No
- **Raised by:** wolfPKCS11 backend

### [BL-177] Lift the wolfPKCS11 multi-part gate once the hash-and-sign mechanisms and AES-ECB work multi-part
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/WolfPkcs11BackendFixture.cs` (`WolfPkcs11DoesMultipartSignAndEcb`)
- **Problem:** `C_SignUpdate`, `C_VerifyUpdate` and `C_EncryptUpdate` return `CKR_MECHANISM_INVALID` for every `CKM_SHA*_RSA_PKCS`, `CKM_SHA*_RSA_PKCS_PSS` and `CKM_ECDSA_SHA*` and for `CKM_AES_ECB`, though PKCS#11 v3.2 defines them multi-part and the token advertises them. The multi-part rows of the buffer, operation-state and stream cases skip. Not yet reported upstream; the draft is with the maintainer.
- **Proposed action:** Report it upstream. After a `vendor/wolfpkcs11` bump with the fix, `WolfPkcs11QuirkTests.MultipartSignAndEcb_QuirkStillPresent` fails. Then set the flag to true and delete the test.
- **Breaks public API?** No
- **Raised by:** wolfPKCS11 backend

### [BL-178] Lift the wolfPKCS11 short-buffer gate once C_GetAttributeValue marks a short attribute CK_UNAVAILABLE_INFORMATION
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Support/Fixtures/WolfPkcs11BackendFixture.cs` (`WolfPkcs11MarksAShortBufferUnavailable`, `ShortBufferMarkingAvailable`)
- **Problem:** `C_GetAttributeValue` into a buffer too small returns `CKR_BUFFER_TOO_SMALL` but leaves the attribute's `ulValueLen` as given, where PKCS#11 v3.2 §5.7.5 sets `CK_UNAVAILABLE_INFORMATION`. Not yet reported upstream; the draft is with the maintainer.
- **Proposed action:** Report it upstream. After a `vendor/wolfpkcs11` bump with the fix, `WolfPkcs11QuirkTests.ShortBufferLength_QuirkStillPresent` fails. Then set the flag to true and delete the test.
- **Breaks public API?** No
- **Raised by:** wolfPKCS11 backend

### [BL-179] Support stateful hash-based signatures (LMS/HSS, XMSS/XMSS^MT)
- **Area:** Feature
- **Severity:** Low
- **Effort:** L
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11` (`CKM.CKM_HSS`, `CKM.CKM_HSS_KEY_PAIR_GEN`, `CKM.CKM_XMSS`, `CKM.CKM_XMSSMT` are named only)
- **Problem:** The library has no API for PKCS#11 v3.1's stateful hash-based signatures. wolfPKCS11 implements them (`--enable-lms --enable-xmss`), so it would be the backend to test them on; the wolfPKCS11 test build leaves them off.
- **Proposed action:** Design the key-state handling (each signature consumes state), then add the API and enable LMS/XMSS in `build/build-wolfpkcs11.sh`.
- **Breaks public API?** No (additive)
- **Raised by:** wolfPKCS11 backend

### [BL-180] Lift the inline per-backend signing tests into shared test cases
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Integration/Sign/` (`SignEdDsaContextTests`, `SignHashMlDsaTests`, `SignMlDsaDeterministicHedgeTests`)
- **Problem:** BouncyHsm's and opencryptoki's wrappers each carry their own copy of these test bodies, with no `*TestCases` class, so no other backend runs them (wolfPKCS11's ML-DSA hedge variant goes unchecked).
- **Proposed action:** Move the bodies into shared `*TestCases` and wrap them on every backend.
- **Breaks public API?** No
- **Raised by:** wolfPKCS11 backend

### [BL-181] Restore the hand-trimmed RSA-size and small-curve rows in the backend wrappers
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** the `*.FreeHsm.cs`, `*.CratonHsm.cs` and other wrappers of `RSAPkcs11TestCases.Assert_SignVerifyData_AcrossKeySizes_RoundTrips` and the `ECDsaPkcs11TestCases` secp160r1/secp224k1 cases
- **Problem:** Backends without every RSA modulus or curve left those rows out of their wrappers by hand. `Pkcs11BackendExtensions.SkipIfRefusedOutsideKeySize` now skips a size a token refuses outside its advertised range, so the rows can go back and run wherever the token does more than it claims.
- **Proposed action:** Restore the rows on every backend; triage any refusal inside an advertised range.
- **Breaks public API?** No
- **Raised by:** wolfPKCS11 backend

## PKCS#11 v3.2 Coverage Matrix

**Corrected 2026-08-11:** the three public-façade rows below marked ❌ were previously recorded as ✅. A grep over `Internal/`, `Algorithms/`, `Objects/` and the root types finds no caller for `C_SignUpdate`, `C_SignFinal` or `C_SignRecover`, while `C_EncryptUpdate`/`C_DigestUpdate`/`C_VerifyUpdate` all have callers — and `Pkcs11Key`/`Pkcs11Session` expose no `Stream` overload at all. See BL-087 and BL-099.

Condensed from PKCS#11 Specialist A, who cross-checked `CK_FUNCTION_LIST_3_0`/`_3_2`, `CK_INTERFACE`, and `CK_ASYNC_DATA` field-by-field against the vendored v3.2 header (`vendor/opencryptoki/usr/include/pkcs11types.h`) — exact match, including the 12 v3.2 additions in declaration order. **No v3.2 `C_*` function is missing at the interop layer.** Re-confirmed 2026-08-11: all 104 function-list entries are bound; **78 of 104 are reachable from the public API** (v2.40 68/68 in substance, v3.0 8 of 24, v3.2 2 of 12).

| Function group | Low-level (P/Invoke) | High-level (public façade) |
|---|---|---|
| v2.40 general / slot / token (`C_Initialize` … `C_WaitForSlotEvent`) | ✅ | ✅ |
| v2.40 session / PIN / login (`C_OpenSession` … `C_Logout`) | ✅ | ✅ |
| v2.40 object / attribute (`C_CreateObject` … `C_FindObjectsFinal`) | ✅ | ✅ |
| v2.40 crypto — single-part (`C_Encrypt`, `C_Decrypt`, `C_Sign`, `C_Verify`, `C_Digest`) | ✅ | ✅ |
| v2.40 crypto — multi-part (`*_Update`/`*_Final`) | ✅ | ❌ — internal only; **multi-part sign is not implemented at all** (`C_SignUpdate`/`C_SignFinal` have no caller outside `Native/`) — BL-087 |
| v2.40 crypto — SignRecover/VerifyRecover, dual-function combos | ✅ | ❌ — internal only: `Pkcs11SessionCore` wraps `C_VerifyRecover`, `C_DigestEncryptUpdate`, `C_DecryptDigestUpdate` and `C_DecryptVerifyUpdate`, none of them public; `C_SignRecover` and `C_SignEncryptUpdate` have no caller outside `Native/` — BL-087 |
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

Mechanisms (`CKM`, 480 members): RSA (PSS/OAEP), EC/EdDSA/Montgomery, AES (GCM/CCM/CTR/KW/message), ChaCha20/Salsa20/Poly1305, ML-DSA/ML-KEM/SLH-DSA, HSS/LMS, SHA-2/-3/SHAKE, HMAC, KDFs, legacy `[Obsolete]`-gated — comprehensive, spot-checked constant values correct, raw-`ulong` vendor escape hatch present. Attributes (`CKA`, 160 members): all v3.2 additions present (trust, validation, profile, HSS, parameter-set, encapsulate/decapsulate templates); `CKO_PROFILE`/`VALIDATION`/`TRUST` defined but have no dedicated template builders (GenericTemplateBuilder suffices). Return codes (`CKR`, 105 members): all v3.2 additions present; vendor and unknown codes surface as `Pkcs11UnclassifiedException` (BL-003, resolved).


Constant coverage was re-verified 2026-08-11 by diffing the enums against three independent vendored headers (`vendor/opencryptoki/usr/include/pkcs11types.h`, `vendor/nss/lib/util/pkcs11t.h`, `vendor/pkcs11-mock/src/cryptoki/pkcs11t.h`): **zero value mismatches** across `CKM` (480), `CKA` (160), `CKR` (105), `CKK` (69), `CKD` (26), `CKO`, `CKC`, `CKS`, `CKU`, `CKN`, `CKH`, `CKT`, `CKG`, `CKP`. Residual gaps: `CKF` is 68 of 72 (BL-144: `CKF_END_OF_MESSAGE` and `CKF_HKDF_SALT_NULL`/`_DATA`/`_KEY`; re-counted 2026-10-27 against NSS 3.132's `pkcs11t.h`), `CK_GENERATOR_FUNCTION` is entirely absent (BL-102), `CKK_INVALID_KEY_TYPE` is absent (trivial), and five defined `CKF` bits have no property on the public flag records (BL-101). `CK_FUNCTION_LIST_3_2` declaration order matches `pkcs11f.h` exactly — a transposition there would have been Critical, and there is none.
## Appendix A — Unverified / Speculative

- **KEM/authenticated-unwrap secure-defaults application** (Cryptographer B, round 1): whether `EncapsulateKey`/`DecapsulateKey` and `UnwrapKeyAuthenticated` call `BuildSecureKeyDefaults` like `UnwrapKey`/`DeriveKey` do — a shared comment claims so, but the reviewer read only the latter two call sites in full. Confirm before 1.0.
- **GitHub repository settings** (QA C, both rounds): branch protections, required status checks, tag protection, Environment approvals, and Private Vulnerability Reporting enablement are not verifiable from the repo — confirm in Settings. Specifically confirm that `lint`, all six `build-and-test` legs, `aot-smoke` and `softhsm-v240` are *required* checks; BL-139 changes character depending on whether `code-quality` is required.
- **`CK_CCM_WRAP_PARAMS` field order and the `CK_XEDDSA_HASH_TYPE` value set** (Cryptographer A): `CK_GCM_WRAP_PARAMS` and both PQC context structs were confirmed against `vendor/opencryptoki/usr/include/pkcs11types.h:1890-1901`, but `CK_CCM_WRAP_PARAMS` appears in no vendored header. Someone with the OASIS v3.2 PDF should confirm that one before BL-103 is implemented.
- **Real-HSM handle recycling frequency** (PKCS#11 Specialist B): whether shipping HSMs recycle session and object handles aggressively enough for BL-116 to fire in practice. The spec permits it and nothing defends against it, which is why it was raised; the actual frequency is vendor-dependent and would need a real-device experiment. (BL-071's half of this question is moot now that `CloseAllSessions()` is resolved by removal — there is no bookkeeping gap left to fire.)
- **`CKR_CANT_LOCK` prevalence** (PKCS#11 Specialist B): BL-085's practical severity depends on how many shipping modules refuse `CKF_OS_LOCKING_OK`. None of the four CI backends does, so that path has zero real-backend coverage today.
- **Backend mechanism advertisement** (QA B): whether opencryptoki's software token advertises `CKD_SHA256_KDF` or `CKM_RSA_AES_KEY_WRAP` in this build is not determinable from source. BL-123 and BL-124 assume a capable backend can be found and should be implemented with a hard-fail guard so the assumption is checked rather than silently skipped.
- **`ManagedSoftToken` Windows-packed dispatch** (QA A): whether `UnmanagedMemory.Read<CK_CCM_PARAMS>` in the fake resolves to the Windows-packed sibling layout on the Windows legs. The tests pass there, presumably via the `IsPackedForPkcs11` dispatch, but confirming it was outside that reviewer's lane.
- ~~**`CertificateRequest.Create` with `ECDsaPkcs11`** (.NET Engineer A): the claim follows from a verified `SignData(…, Rfc3279DerSequence)` failure on a shim subclass plus .NET's ECDSA `X509SignatureGenerator` using that format, rather than from a live token.~~ Confirmed and closed by BL-072's fix: `ECDsaPkcs11Tests_Managed.CertificateRequest_Create_SigningRequest_Succeeds` is exactly this round-trip, run against the in-process managed token.

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
- **Secure-by-default is consistently enforced** in key-producing operations via `BuildSecureKeyDefaults`; template builders default correctly; verification is delegated to the token with `CKR_SIGNATURE_INVALID → false` mapping. The remaining gaps are the gate's *membership* (BL-074) and one verify return code (BL-065) — not the mechanism. (The generators' *role assignment* gap, BL-070, is resolved.)
- **PQC handling is unusually careful.** ML-DSA pre-hash/SHAKE arms are refused with accurate FIPS 204 domain-separation reasoning rather than emitting non-interoperable signatures; `MLKemPkcs11` length-checks the token's `CKA_VALUE` before copying, zeroizes the intermediate in a `finally`, zeroizes the caller's secret on every failure path, surfaces rather than swallows a `C_DestroyObject` failure, caches the `CKA_VALUE_LEN` token quirk, and refuses private-key export on all four BCL paths. Two independent reviewers named it the strongest file in the repository.
- **`MechanismParameterScope` is a sound design:** call-scoped allocation, `Write` returning `IntPtr.Zero` for an empty span (the correct PKCS#11 absent-buffer encoding), zeroize-on-free, and a deliberately stateless `Mechanism.Marshal` together eliminate the aliasing and lifetime bugs this layer usually has. `ThrowIfOneDescriptorDrivesBothHalves` is a thoughtful guard.
- **The test suite is mature where it covers.** ~90 struct sizes pinned per platform via a reflection census; genuine KATs from NIST/RFC sources (AES-GCM McGrew & Viega, HMAC RFC 4231, Ed25519 RFC 8032, AES-KW RFC 3394, RSA-OAEP/PSS, ECDSA P-256, ECDH P-256) re-run against three real backends with the deterministic direction correctly chosen for randomized schemes; independent BCL cross-verification for RSA, ECDSA (correctly asserting `IeeeP1363FixedFieldConcatenation`), DSA and ML-DSA; thorough AEAD negatives (tampered tag, tampered ciphertext, wrong AAD, wrong nonce). **No timing-dependent test exists anywhere** — zero hits for `Thread.Sleep`/`Task.Delay`/`Stopwatch`/`SpinWait` across the suite; concurrency tests use barriers and latches. Assertion mix is healthy (1493 `Assert.Equal` versus 50 `Assert.NotNull`). `Unit/TestCollectionConventionTests.cs` is exemplary, including an explicit anti-vacuity guard — and is the pattern BL-129 should be built on.
- **The fakes do not bypass parameter marshalling**, contrary to the usual concern: `ManagedSoftToken` reads the mechanism parameter block back out of unmanaged memory, so the GCM/CCM/ChaCha/RC2 param writers are genuinely exercised, and `FakeLowLevelPkcs11Library` throws on all ~110 members by default so a test cannot pass via an unimplemented call. What they do bypass is `LowLevelPkcs11Library`'s own struct-array marshalling and `_Windows` sibling dispatch — covered instead by the `*.Managed.cs` suites running on all six legs plus direct marshalling tests.
- **CI/publish hygiene is modern (re-verified 2026-08-11).** Every `uses:` in all four workflows is SHA-pinned with a version comment; `GITHUB_TOKEN` is least-privilege per job; `persist-credentials: false` everywhere; no `pull_request_target` anywhere; concurrency groups correctly asymmetric (cancel PRs, never cancel `main`); OIDC trusted publishing with build-provenance attestation; package source mapping; enforced `.editorconfig` + `dotnet format` gate; docfx pinned in `dotnet-tools.json`; analyzer release tracking (`AnalyzerReleases.Shipped/Unshipped.md`) correctly staged for all three diagnostic ids. Source integrity is good where it exists — the OpenSSL tarball is SHA-256 verified and the SoftHSM 2.5 `.deb`s come from content-addressed snapshot URLs with pinned digests and a post-extract version assertion.
- **Deliberately evaluated and not raised:** cache poisoning via the native/OpenSSL caches (GitHub cache scoping makes it require push access to `main`, at which point the workflow is writable); NuGet author signing (nuget.org repository-signs, and OIDC + provenance attestation is stronger); the unversioned `analyzers/dotnet/cs` folder (a `net10.0`-only package can only be consumed by Roslyn ≥ 4.14, so the 4.11-built analyzer cannot bite); `tests/AotSmoke` being outside the solution (cosmetic — the job still builds it); and the pack(1)-on-Unix ambiguity, which is inherent to PKCS#11 rather than a defect here (NSS applies `pragma pack(1)` unconditionally, so its view of `CK_TLS12_KEY_MAT_PARAMS` differs from the standard OASIS convention this library correctly follows; affects only SSL3/TLS12 key-material mechanisms, unreachable from any public API — worth a documented vendor-quirk note).
- **Deliberate design notes:** no async surface anywhere, which is the correct default for a synchronous P/Invoke wrapper — the real cancellation primitive is `C_SessionCancel` (BL-099), and a `Task`-returning façade would be worse; `CK_NOTIFY` is unsupported (BL-151); `[Experimental]` propagation is handled correctly where it applies (`SlhDsaPkcs11` re-declares `SYSLIB5006`); vendor extensibility is genuinely available via `VendorMechanismParameters` + `Mechanism`'s `ulong` constructors; XML-doc completeness is structurally enforced by `GenerateDocumentationFile` + `TreatWarningsAsErrors`, so CS1591 is a build error and no undocumented public member exists; and `LangVersion` is pinned to 13.0 while `CLAUDE.md` says `latest`.
