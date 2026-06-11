# Library Review Backlog

_Generated 2026-06-08 from a multi-specialist deep review (cryptography ×2, PKCS#11 v3.2 conformance ×2, .NET library design + P/Invoke ×2, QA & release engineering ×3)._

## Summary

- Total items: 62
- Critical: 1 | High: 13 | Medium: 33 | Low: 15
- Resolved so far: BL-001, BL-002, BL-003, BL-011, BL-044, BL-045, BL-046, BL-047 — see each item's **Status** line.
- Headline risks:
  - **Secure-by-default is not uniform.** The `UnwrapKey` path enforces `CKA_SENSITIVE=true` / `CKA_EXTRACTABLE=false` via `BuildSecureUnwrapDefaults`, but the sibling key-creating paths (`DeriveKey`, `EncapsulateKey`, `DecapsulateKey`, `UnwrapKeyAuthenticated`) forward the caller template verbatim — a consumer can silently land an extractable ML-KEM shared secret. This is the one defect that touches key material directly (BL-001).
  - **Backward-compat & v3.x surface gaps that ship permanently.** `ToCKR()`/`ToCKM()` throw on every vendor-defined code (BL-005), `CKF_END_OF_MESSAGE` is undefined so the streaming AEAD API is unusable (BL-006), and the v3.2 async-session surface is unreachable.
  - **No public-API stability gate before 1.0.** No `PublicApiAnalyzers`, no `PackageValidation` baseline, no API snapshot test (BL-004) — and two genuinely-public-but-shouldn't-be types (BL-002, BL-003) will become SemVer commitments the moment 1.0 ships.
  - **Test coverage has real-token blind spots.** The v3.0 message-API branch, the pure-v2.40 fallback path, and several shipped mechanisms (AES-CCM, ChaCha20-Poly1305, SP800-108, SLH-DSA) are exercised only by the managed fake or skipped entirely (BL-009, BL-010, BL-011).
  - **Release plumbing is not 1.0-ready.** `publish.yml` is broken (BL-014), version is hardcoded `0.0.0` (BL-013), and there is no `SECURITY.md` for a cryptography library (BL-012).
- Release-readiness assessment: **Not yet 1.0.** The interop core is in strong shape — the v2.40/v3.0/v3.2 function tables are complete and in spec order, the `NativeCULong` width guard is sound, Windows (incl. ARM64) and x86 are in the CI test matrix, and `[Obsolete]`/`AllowInsecure` gating of weak crypto is comprehensive. No memory-corruption or unconditional key-leak defect was confirmed in normal use. But a public-library 1.0 is a permanent contract: the API-stability gate (BL-004), the two leaked public types (BL-002/003), the secure-default asymmetry (BL-001), the vendor-code crash (BL-005), and the broken release pipeline (BL-012/013/014) should all land before the first tag. Estimate the High tier is roughly 2–3 focused weeks; the Critical item is an afternoon.

---

## Critical

### [BL-001] Secure-default extractability gate is missing on DeriveKey / EncapsulateKey / DecapsulateKey / UnwrapKeyAuthenticated
- **Status:** ✅ Resolved 2026-06-09 — `BuildSecureKeyDefaults` is now applied in all four paths (`Pkcs11Session.Derive.cs`, `Pkcs11Session.V32.cs` encap/decap/auth-unwrap).
- **Area:** Cryptography
- **Severity:** Critical
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.Derive.cs:18-47`; `Internal/Pkcs11Session.V32.cs:37-119` (encap/decap), `:173-206` (auth-unwrap); contrast the correct pattern at `Internal/Pkcs11Session.Keys.cs:185-256` (`BuildSecureUnwrapDefaults`).
- **Problem:** `UnwrapKey` injects `CKA_SENSITIVE=true` / `CKA_EXTRACTABLE=false` for any attribute the caller omitted, and throws `InsecureOperationException` on an explicit insecure value unless `AllowInsecure` is set. The four sibling key-producing paths forward `attributes` / `sharedKeyTemplate` / `unwrappedKeyTemplate` straight to the native call with no equivalent guard. A caller who derives or decapsulates a key (e.g. an ML-KEM shared secret — the most security-critical output of those calls) without specifying the security attributes gets whatever the token defaults to, which on many tokens is extractable/non-sensitive — silently, despite the library's "secure by default" promise.
- **Proposed action:** Apply `BuildSecureUnwrapDefaults()` (or an extracted shared helper) inside all four methods before the native call, identical to `UnwrapKey`. Verified: `BuildSecureUnwrapDefaults` already exists and is the only thing standing between these paths and a secure default.
- **Breaks public API?** No — additive runtime guard; an explicit `CKA_EXTRACTABLE=true` caller would newly need `AllowInsecure`, which is the intended contract.
- **Raised by:** Cryptographer B
- **Spec / References:** PKCS#11 v3.2 §5.18.10–12; design intent documented at `Pkcs11Session.Keys.cs:181-186`.

---

## High

### [BL-002] `Pkcs11PublicKeyView` is `public static` but documented as an internal helper
- **Status:** ✅ Resolved 2026-06-10 — `Pkcs11PublicKeyView` and `TryParseEcPublicKey` are now `internal` (only consumers are `ECDsaPkcs11`/`ECDiffieHellmanPkcs11`; the unit test reaches it via `InternalsVisibleTo`). The "Internal helper" doc is now accurate.
- **Area:** .NET API Design
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11PublicKeyView.cs:14,55`
- **Problem:** The class XML doc opens "Internal helper that synthesizes a managed public-key view…", yet the class is `public static class` and exposes `public static ECParameters? TryParseEcPublicKey(byte[], byte[])`. The two synthesis methods are correctly `internal`; only this one method leaks. It commits the library to a `byte[]`-based EC-point parser as a SemVer surface and invites callers to parse token EC data without the library's validation context.
- **Proposed action:** Make the class and method `internal` (its only consumer is `ECDsaPkcs11.ExportParameters`). If a public EC-point parser is genuinely wanted, expose it deliberately on a well-named public utility type with full docs. Fix the doc comment to match the chosen visibility.
- **Breaks public API?** Yes — must land before 1.0.
- **Raised by:** .NET Engineer A, Cryptographer B

### [BL-003] `SessionInfo` is a public type no public member can produce
- **Status:** ✅ Resolved 2026-06-10 — `SessionInfo` is now reachable: added the public `Pkcs11Workspace.GetSessionInfo()` (disposed-guarded, delegates to the session). The type stays a public record with an internal constructor (library-produced, not consumer-constructed). Covered by `WorkspaceSessionInfoTests`.
- **Area:** .NET API Design
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/SessionInfo.cs:9`; producer `Internal/Pkcs11Session.cs:356` (`internal`)
- **Problem:** `public sealed record SessionInfo` has only an `internal` constructor and its sole producer (`Pkcs11Session.GetSessionInfo()`) is `internal`. No public method on `Pkcs11Workspace`/`Pkcs11Slot`/`Pkcs11Library` returns one. It appears in IntelliSense but is unobtainable — dead public surface that becomes a binary-compat commitment at 1.0.
- **Proposed action:** Either expose `GetSessionInfo()` on `Pkcs11Workspace` (the natural owner) so the type is reachable, or make `SessionInfo` `internal` until it is ready.
- **Breaks public API?** Yes — must land before 1.0.
- **Raised by:** .NET Engineer A

### [BL-004] No public-API stability gate (analyzer, snapshot test, or package-validation baseline)
- **Area:** Cross-cutting
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` (no `Microsoft.CodeAnalysis.PublicApiAnalyzers`, no `PublicAPI.*.txt`, no `PackageValidationBaselineVersion`); no `PublicApiGenerator`/`Verify` test anywhere.
- **Problem:** With `TreatWarningsAsErrors=true` but no API gate, any accidental public-surface add/remove/signature-change passes CI silently. Pre-1.0 is the only free moment to capture the intended contract. (A prior cleanup of accidentally-public native types confirms the surface drifts unnoticed.)
- **Proposed action:** Add `Microsoft.CodeAnalysis.PublicApiAnalyzers` + commit `PublicAPI.Shipped.txt`/`PublicAPI.Unshipped.txt` as the explicit contract; add a `PublicApiGenerator`+`Verify` snapshot test; once 1.0.0 ships, set `PackageValidationBaselineVersion`.
- **Breaks public API?** No (but is the mechanism that protects the API — land before 1.0).
- **Raised by:** .NET Engineer A, .NET Engineer B, QA A, QA C

### [BL-005] `ToCKR()` / `ToCKM()` throw `InvalidEnumValueException` on every vendor-defined value
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKR.cs:551-557`; `Common/CKM.cs:2393-2399`. `ToCKR()` is on the return path of **every** native call (100+ sites in `Native/LowLevelPkcs11Library.cs`).
- **Problem:** `ToCKR()` does `Enum.IsDefined` and throws for any undefined value, including the entire spec-permitted vendor range (`>= 0x80000000`). A token returning a vendor error code makes the wrapper throw a confusing `InvalidEnumValueException` instead of surfacing the failure. `ToCKM()` has the same issue and is reached from `CkmRsaPkcsPssParams.HashAlg`/`CkmRsaPkcsOaepParams.HashAlg`. `C_GetMechanismList` already works around this with an unvalidated cast (`LowLevelPkcs11Library.cs:340`); the rest does not.
- **Proposed action:** For undefined values `>= CKR_VENDOR_DEFINED`, return `CKR_VENDOR_DEFINED` (and expose the raw numeric code on the exception); apply the same to `ToCKM()`.
- **Breaks public API?** No (behavior fix).
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** PKCS#11 v3.2 §3.1, §8.1.

### [BL-006] `CKF_END_OF_MESSAGE` is undefined — streaming AEAD message API is unusable
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** S
- **Location:** referenced only in doc comments at `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs:684,764`; absent from `Common/CKF.cs`.
- **Problem:** `C_EncryptMessageNext`/`C_DecryptMessageNext` require `CKF_END_OF_MESSAGE` (0x1) in `ulFlags` on the final chunk, and the wrappers' own docs say so, but the constant exists nowhere in the source. Callers must hard-code a magic literal.
- **Proposed action:** Add `CKF_END_OF_MESSAGE` to `CKF.cs` and reference it from the streaming wrappers.
- **Breaks public API?** No (additive).
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** PKCS#11 v3.0 §5.9.7, §5.10.7.

### [BL-007] `SupportsMechanism` runs native calls outside the session lock
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:226-247`
- **Problem:** `SupportsMechanism` (reached from the public `Pkcs11Key.SupportsMechanism`) issues `C_GetSessionInfo`/`C_GetMechanismList` without `AcquireExclusive()`, and lazily writes `_supportedMechanisms` unsynchronized. If a crypto op runs on the session from another thread, two native calls hit the same session concurrently — undefined behavior under the null-args (non-OS-locking) init path — and the check-then-write races.
- **Proposed action:** Take `AcquireExclusive()` (or a dedicated lock around the lazy init) at the top of `SupportsMechanism`.
- **Breaks public API?** No.
- **Raised by:** PKCS#11 Specialist B

### [BL-008] Raw mechanism-param structs hold managed `byte[]` via `[MarshalAs(ByValArray)]`
- **Area:** P/Invoke
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/RawMechanismParams/CK_AES_CTR_PARAMS.cs:20` and the same pattern in `CK_AES_CBC_ENCRYPT_DATA_PARAMS.cs`, `CK_CAMELLIA_CTR_PARAMS.cs`, `CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS.cs`, `CK_RC2_CBC_PARAMS.cs`, `CK_ARIA_CBC_ENCRYPT_DATA_PARAMS.cs`, `CK_DES_CBC_ENCRYPT_DATA_PARAMS.cs`, `CK_SEED_CBC_ENCRYPT_DATA_PARAMS.cs`.
- **Problem:** Eight `[PackedForPkcs11]` structs declare fixed buffers as `[MarshalAs(UnmanagedType.ByValArray, SizeConst=N)] public byte[]`. The generator's Windows-sibling copy is a reference copy with no null/length check; `Marshal.StructureToPtr` then throws an opaque `MarshalDirectiveException` on a null array and may leave uninitialized bytes for an under-length one. Relying on marshalling stubs for structs containing managed references is also fragile under future AOT hardening.
- **Proposed action:** Replace each `byte[]` field with an `[InlineArray(N)]` value type (as already done for the `CkChar*` char buffers) so the structs are fully blittable; validate span length in the high-level `MechanismParameters` constructors.
- **Breaks public API?** No (internal types).
- **Raised by:** .NET Engineer B
- **Spec / References:** PKCS#11 v3.2 §6.3; `Marshal.StructureToPtr` ByValArray remarks.

### [BL-009] The v3.0 message-API code path is shipped but never executed by any test
- **Area:** QA
- **Severity:** High
- **Effort:** M
- **Location:** production branch `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/AesGcmPkcs11.cs:86-109` (gated on `_key.SupportsMessageApi`); every backend reports the API unavailable (`tests/.../Support/Pkcs11Fakes/NotSupportedPkcs11Library.cs:16`; SoftHSM lacks the symbols; `vendor/pkcs11-mock` returns `CKR_FUNCTION_NOT_SUPPORTED`); the only candidate mock AES tests are `[Fact(Skip)]` at `tests/.../Integration/Encrypt/EncryptAesTests.Pkcs11Mock.cs:18,22`.
- **Problem:** The `true`-branch of the AEAD dual-dispatch (message-based encrypt/decrypt for AES-GCM, AES-CCM, ChaCha20-Poly1305) is dead from a test perspective — it compiles and ships but no automated test ever calls it, so its parameter marshalling (`CkmGcmMessageParams`, etc.) is unverified end-to-end.
- **Proposed action:** Add a `ManagedSoftToken` variant with `IsMessageApiSupported=true` implementing the message functions over BCL primitives, and run the existing adapter suites against it; longer term, upgrade/patch `pkcs11-mock` to implement the message API.
- **Breaks public API?** No.
- **Raised by:** QA A (note: demoted from the specialist's "Critical" — no corruption is demonstrated, only absence of coverage).
- **Spec / References:** PKCS#11 v3.0 §5.9–5.10.

### [BL-010] The pure-v2.40 fallback (no `C_GetInterface`, no v3.x symbols) is never tested
- **Area:** QA
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs:1456-1607` (`TryLoadFromGetInterface` / `TryLoadV30Symbols`); only version-negotiation test is `tests/.../Integration/Discovery/GetInterfacesTests.Pkcs11Mock.cs`.
- **Problem:** Backward compatibility with v2.40 modules is a stated non-negotiable goal, but no backend exercises a library that exports only the v2.40 function list — `pkcs11-mock` presents as v3.1 and SoftHSM exposes enough v3.0 symbols to bind. The fallback detection path that leaves `IsMessageApiSupported=false` is unexercised.
- **Proposed action:** Add a `FakeLowLevelPkcs11Library` unit test that nulls the v3.x delegates and asserts detection; optionally vendor a minimal synthetic v2.40 `.so`/`.dll` for an integration test.
- **Breaks public API?** No.
- **Raised by:** QA A
- **Spec / References:** PKCS#11 v2.40 §2.2; v3.0 §3.4.

### [BL-011] Several shipped mechanisms have no real-token test execution
- **Status:** ✅ Resolved 2026-06-10 — AES-CCM, ChaCha20-Poly1305, SP800-108 counter KDF and SLH-DSA are implemented in `ManagedSoftToken` over the BCL primitive, so their parameter-marshalling path runs in CI via the `*.Managed.cs` tests. KATs now pin a published vector where one is compact (AES-CCM: RFC 3610 #1 — was BCL-derived; ChaCha20-Poly1305: RFC 8439 §2.8.2) and otherwise cross-check the BCL computed outside the marshalling path (SP800-108: CAVP vectors are variable-format ACVP JSON; SLH-DSA: FIPS 205 signatures are ~17 KB+). The real-token gap (no CI backend — neither SoftHSM nor opencryptoki — implements these four) is documented in `SoftHsmBackendFixture`.
- **Area:** QA
- **Severity:** High
- **Effort:** L
- **Location:** `tests/.../Support/Fixtures/SoftHsmBackendFixture.cs:47-107` hardcodes capability flags `false`, permanently skipping: AES-CCM (`AesCcmPkcs11Tests.SoftHsm2.cs:176-323`), ChaCha20-Poly1305 (`ChaCha20Poly1305Pkcs11Tests.SoftHsm2.cs:179-297` + KAT at `Integration/Adapters/KnownAnswerTests.SoftHsm2.cs:100-127`), SP800-108 KDF (`SP800108HmacCounterKdfPkcs11Tests.SoftHsm2.cs:59-162`), SLH-DSA (`SlhDsaPkcs11Tests.SoftHsm2.cs:91-147`).
- **Problem:** These mechanisms are exposed in the public API and have prepared KAT vectors, but no CI backend implements them, so their parameter marshalling is validated (if at all) only by the in-process managed fake. A consistent mis-encoding shared by fake and adapter would pass.
- **Proposed action:** Implement each mechanism in `ManagedSoftToken` over the BCL primitive (AesCcm, ChaCha20Poly1305, SP800-108, SlhDsa are all available on .NET 10) so the marshalling path runs in CI; pin a NIST/RFC fixed vector rather than re-deriving from the BCL; track the real-token gap explicitly.
- **Breaks public API?** No.
- **Raised by:** QA B, QA A
- **Spec / References:** NIST SP 800-38C; RFC 8439; NIST SP 800-108r1; FIPS 205.

### [BL-012] No `SECURITY.md` / vulnerability-disclosure policy
- **Area:** Release Eng
- **Severity:** High
- **Effort:** S
- **Location:** MISSING — repo root and `.github/` have no `SECURITY.md`.
- **Problem:** A library that wraps HSMs and enforces a security gate has no disclosure channel, embargo terms, or response SLA. A researcher finding a flaw in the gating or marshalling has nowhere to report it.
- **Proposed action:** Add `SECURITY.md` (contact or GitHub Private Vulnerability Reporting, response-time commitment, optional PGP key) and enable GitHub Security Advisories.
- **Breaks public API?** No.
- **Raised by:** QA C

### [BL-013] No versioning automation — `Version` hardcoded `0.0.0`
- **Area:** Release Eng
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj:27`; tag-strip workaround in `.github/workflows/publish.yml:28`.
- **Problem:** Every local build produces `0.0.0` packages; the publish flow derives a version only from `${GITHUB_REF_NAME#v}` with no SemVer validation and no changelog gate.
- **Proposed action:** Adopt MinVer or Nerdbank.GitVersioning (`PrivateAssets=all`) to derive version from annotated git tags everywhere, eliminating the placeholder and the manual `/p:Version=` injection.
- **Breaks public API?** No.
- **Raised by:** QA C

### [BL-014] `publish.yml` is broken — checkout omits submodules, so the release build fails before pack
- **Area:** Release Eng
- **Severity:** High
- **Effort:** S
- **Location:** `.github/workflows/publish.yml:16-34`
- **Problem:** Checkout has `fetch-depth: 0` but no `submodules: recursive`. `dotnet build src/KerckhoffsLabs.sln` includes the Tests project, whose `BeforeTargets="PrepareForBuild"` targets shell out to build `vendor/pkcs11-mock` and `vendor/softhsmv2` (`*.Tests.csproj:36,49`); with the submodules absent the `set -euo pipefail` scripts exit 1 and the `<Exec>` (no `ContinueOnError`) fails the build, so `pack`/`push` never run. The job also installs no native toolchain.
- **Proposed action:** Either add `submodules: recursive` + the native toolchain (mirror `ci.yml`), or set `SkipPkcs11MockBuild=true`/`SkipSoftHsmV2Build=true` for the release build and gate publish on a successful CI run via `needs:`.
- **Breaks public API?** No.
- **Raised by:** QA C
- **Spec / References:** actions/checkout submodules; MSBuild `Exec` `ContinueOnError`.

---

## Medium

### [BL-015] `GenerateKey` overloads have the same name but invoke different PKCS#11 operations
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Workspace.cs:271,288`
- **Problem:** `GenerateKey(mechanism, template)` calls `C_GenerateKey` (symmetric) while `GenerateKey(mechanism, privTemplate, pubTemplate)` calls `C_GenerateKeyPair` — entirely different operations distinguished only by arity.
- **Proposed action:** Rename to `GenerateSymmetricKey` and `GenerateKeyPair`; promote the existing `GenerateAesKey`/`GenerateRsaKeyPair`/`GenerateEcKeyPair` as the primary API.
- **Breaks public API?** Yes — must land before 1.0.
- **Raised by:** .NET Engineer A

### [BL-016] `WaitForSlotEvent` uses dual `out` parameters
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Library.cs:287`
- **Problem:** `void WaitForSlotEvent(bool, out bool eventOccurred, out ulong slotId)` couples two outputs (slotId meaningless when no event); FDG prefers a single return value.
- **Proposed action:** Return `SlotEvent?` (null = no event) or a tuple.
- **Breaks public API?** Yes — must land before 1.0.
- **Raised by:** .NET Engineer A

### [BL-017] PKCS#11 v3.2 surface (ML-KEM/ML-DSA, encaps/decaps) is not `[Experimental]`
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs:514,537`; `Algorithms/MLKemPkcs11.cs:40`; `Algorithms/MLDsaPkcs11.cs:36`
- **Problem:** `SlhDsaPkcs11` is `[Experimental("SYSLIB5006")]`, but the rest of the recently-published v3.2 surface (encaps/decaps, ML-KEM, ML-DSA) carries no instability marker even though constants/conventions may shift before wide HSM adoption.
- **Proposed action:** Mark v3.2-exclusive surface with a library diagnostic id (e.g. `[Experimental("KLAB0001")]`); removing it later is non-breaking.
- **Breaks public API?** Yes (adding `[Experimental]` is source-breaking for opted-out consumers) — land before 1.0.
- **Raised by:** .NET Engineer A

### [BL-018] `Mechanism.Type` returns raw `ulong` instead of `CKM`
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Mechanism.cs:25-33`
- **Problem:** Even when built from a `CKM`, `Type` returns `ulong`, forcing `(CKM)mechanism.Type` casts throughout and losing IntelliSense enum discovery.
- **Proposed action:** Add `public CKM MechanismType => (CKM)_ckMechanism.Mechanism;`, keeping `Type`/`RawType` for vendor-defined values.
- **Breaks public API?** No (additive).
- **Raised by:** .NET Engineer A

### [BL-019] `Mechanism.Dispose()` does not dispose its `MechanismParameters`
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Mechanism.cs:149-163`
- **Problem:** `Dispose` frees the marshalled param copy but never calls `_mechanismParams.Dispose()`, so `using var m = new Mechanism(CKM_AES_GCM, new CkmAesGcmParams(...))` leaks the params' unmanaged buffer. Library call sites avoid this with a separate `using`, but nothing enforces or documents it.
- **Proposed action:** Have `Mechanism` take ownership and dispose the params, or document/guard the ownership contract explicitly.
- **Breaks public API?** No.
- **Raised by:** .NET Engineer A

### [BL-020] `Pkcs11Key.GetAttributeValue` doc omits the caller-disposes-each contract
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs:107-121`
- **Problem:** Returns `IReadOnlyList<ObjectAttribute>` whose elements own unmanaged buffers, but unlike `FindKeys`/`FindObjects` the `<returns>` doc never says they must be disposed — a silent native leak for tooltip-only readers.
- **Proposed action:** Document the disposal requirement; consider a disposable `AttributeValues` wrapper that disposes all members.
- **Breaks public API?** No.
- **Raised by:** .NET Engineer A

### [BL-021] `GetRSAPrivateKey` / `GetECDsaPrivateKey` open a `Pkcs11Key` with no reachable disposal path
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/Pkcs11CertificateExtensions.cs:23-43`
- **Problem:** These factory extensions allocate a `Pkcs11Key`, wrap it in an adapter that "does NOT take ownership", and return only the adapter — the caller can never dispose the underlying key.
- **Proposed action:** Have adapters constructed via these factories take ownership and dispose the key; keep "no ownership" only for the public `new RSAPkcs11(key)` constructor.
- **Breaks public API?** No.
- **Raised by:** .NET Engineer A

### [BL-022] Missing `<exception>` tags on public crypto methods
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Workspace.cs:270-416` (GenerateKey/AesKey/RsaKeyPair/EcKeyPair); `Pkcs11Key.cs:359,374` (Encrypt/Decrypt) and across the 26 algorithm adapters.
- **Problem:** Many public throwing members lack `<exception>` (and some `<param>`/`<returns>`) tags, so callers can't see what to catch from IntelliSense.
- **Proposed action:** Add `<exception cref="Pkcs11Exception">`, `ObjectDisposedException`, and `InsecureOperationException` tags consistently.
- **Breaks public API?** No.
- **Raised by:** .NET Engineer A

### [BL-023] Single-target `net10.0` excludes .NET 8 LTS / .NET 9 consumers
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj:12`
- **Problem:** Only the PQC adapters (`MLKem`/`MLDsa`/`SlhDsa`) actually require .NET 10; the core HSM workflow (RSA/EC/AES-GCM, P/Invoke, `SafeHandle`) runs on .NET 6+. net10-only locks out the bulk of enterprise consumers on .NET 8 LTS.
- **Proposed action:** Multi-target `net8.0;net10.0`, `#if NET10_0_OR_GREATER` the PQC adapters.
- **Breaks public API?** No (widens reach).
- **Raised by:** .NET Engineer A

### [BL-024] No async surface / no `CancellationToken`; `WaitForSlotEvent` blocks forever
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Library.cs:287`
- **Problem:** No public API accepts a `CancellationToken`, and blocking `WaitForSlotEvent` has no cancellation. Designing the blocking shape now (with v3.2 async functions already bound) makes a later `*Async` story awkward.
- **Proposed action:** Reserve `WaitForSlotEventAsync(CancellationToken)` now; adopt `CancellationToken`-last convention; evaluate exposing `C_Async*` as Task-based.
- **Breaks public API?** No (additive if reserved now).
- **Raised by:** .NET Engineer A

### [BL-025] Global lock serializes every unmanaged alloc/free in production
- **Area:** P/Invoke
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/UnmanagedMemory.cs:103-115`
- **Problem:** A single `Lock` guards a `Dictionary<IntPtr,int>` tracker on every `Allocate`/`Free`, including release builds — a contention bottleneck that grows with session count.
- **Proposed action:** Gate tracking behind a debug/diagnostic flag (direct `AllocHGlobal`/`FreeHGlobal` in production), or shard/lock-free the tracker.
- **Breaks public API?** No.
- **Raised by:** .NET Engineer B

### [BL-026] `win-arm64` absent from `RuntimeIdentifiers`
- **Area:** P/Invoke
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj:19`
- **Problem:** RIDs omit `win-arm64` (LLP64, CK_ULONG=4 bytes like win-x64). Publishing for that RID risks resolving the 8-byte `NativeCULong` asset and doubling every CK_ULONG width. CI *does* test `windows-11-arm` and the runtime width guard catches a mismatch loudly, which is why this is Medium not High — but the RID should be present so the correct asset resolves without a runtime abort.
- **Proposed action:** Add `win-arm64`; confirm the `KerckhoffsLabs.Runtime.InteropServices` package ships/falls back correctly for it.
- **Breaks public API?** No.
- **Raised by:** .NET Engineer B, QA C

### [BL-027] `C_GetInterface` is missing from `ILowLevelPkcs11Library`
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/ILowLevelPkcs11Library.cs` (absent); impl in `Native/LowLevelPkcs11Library.cs`; `Native/FunctionPointers.cs:260-261`.
- **Problem:** `C_GetInterfaceList` is on the interface but `C_GetInterface` is not, so named/versioned-interface selection can't be mocked or reached without downcasting. The raw pointer also types `pVersion` as `IntPtr`.
- **Proposed action:** Add `C_GetInterface` to the interface; type `pVersion` as `CK_VERSION*` (see BL-053).
- **Breaks public API?** No (internal interface).
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** PKCS#11 v3.0 §5.4.

### [BL-028] v3.2 async-session API is unreachable from the high-level surface
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Slot.cs:194-204` (no async-capable `OpenSession`); no wrappers in `Internal/Pkcs11Session.V32.cs`; `Common/CKF.cs:290` defines `CKF_ASYNC_SESSION`.
- **Problem:** `C_AsyncComplete`/`C_AsyncGetID`/`C_AsyncJoin` are bound at the low level but no `OpenSession` overload sets `CKF_ASYNC_SESSION` and no high-level wrappers exist, so the whole async feature is unreachable.
- **Proposed action:** Add an async-capable `OpenSession` overload and `AsyncComplete/GetId/Join` wrappers gated on capability detection (see BL-052).
- **Breaks public API?** No (additive).
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** PKCS#11 v3.2 §5.6.9-5.6.11.

### [BL-029] `VerifySignature(Stream)` (v3.2) has no try/finally cancel guard
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.V32.cs:252-290`
- **Problem:** The streaming verify-signature loop has no `try/finally`; a thrown `C_VerifySignatureUpdate` or stream read leaves an active operation on the session, unlike every other multi-part method.
- **Proposed action:** Wrap in `try/finally` and best-effort `TryCancelOperation` when not finalized (needs the verify cancel flag — see BL-051).
- **Breaks public API?** No.
- **Raised by:** PKCS#11 Specialist B

### [BL-030] `CloseSession()` leaves `_disposed=false`, producing confusing post-close errors
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:270-285`
- **Problem:** After `CloseSession()`, `_disposed` stays false; later calls pass the dispose guard and issue native calls with `CK_INVALID_HANDLE`, surfacing `Pkcs11Exception` instead of a predictable `ObjectDisposedException`.
- **Proposed action:** Set `_disposed=true` (or a `_sessionClosed` flag) at the end of `CloseSession()`.
- **Breaks public API?** No.
- **Raised by:** PKCS#11 Specialist B

### [BL-031] `CKR_CANT_LOCK` fallback silently degrades the thread-safety model with no API signal
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Library.cs:152-176`
- **Problem:** On `CKR_CANT_LOCK` the library retries `C_Initialize(null)` (app must serialize all access) and only logs a warning. Library-level calls (`GetSlotList`, `WaitForSlotEvent`) are unguarded and callers can't detect that single-threaded use is now required.
- **Proposed action:** Expose `bool IsOsLockingActive { get; }` and document the constraint on library-level methods.
- **Breaks public API?** No (additive).
- **Raised by:** PKCS#11 Specialist B

### [BL-032] `Pkcs11Workspace.Dispose()` catches only `Pkcs11Exception`, can leak the session
- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Workspace.cs:75-97`
- **Problem:** If `Logout()` throws `ObjectDisposedException`/`InvalidOperationException` (e.g. library disposed first), it escapes before `_session.Dispose()`, `_disposed=true`, and `GC.SuppressFinalize` run.
- **Proposed action:** Catch all exceptions from `Logout()`, and move `_session.Dispose()` + `_disposed=true` into a `finally`.
- **Breaks public API?** No.
- **Raised by:** PKCS#11 Specialist B

### [BL-033] `SecurePin(string)` builds an unpinned intermediate UTF-8 buffer
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/SecurePin.cs:57-76`
- **Problem:** The `tmp` byte array holding the encoded PIN is not pinned; a GC compaction between encode and `ZeroMemory(tmp)` can leave PIN bytes at the original (now-freed) address until overwritten. The final `_buffer` is correctly pinned.
- **Proposed action:** Use a `stackalloc` span (PINs are short) or a second pinned `GCHandle` for the intermediate.
- **Breaks public API?** No.
- **Raised by:** Cryptographer B

### [BL-034] Harden `DecryptVerify`: no cancel guard + plaintext released before authentication
- **Area:** Cryptography / PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.Verify.cs:287-363`
- **Problem:** Two issues on the same method. (1) No `try/finally` — a thrown `outputStream.Write` or failing `C_DecryptFinal`/`C_VerifyFinal` leaves both DECRYPT and VERIFY operations active, wedging the session (inconsistent with `DigestEncrypt`/`DecryptDigest` which guard with `TryCancelOperation`). (2) Decrypted plaintext is written to `outputStream` (lines 342, 355) before `C_VerifyFinal` (line 357), so a caller that consumes output before checking `isValid` operates on unauthenticated data — spec-mandated for `C_DecryptVerify` but undocumented here.
- **Proposed action:** Add a `try/finally` that cancels both ops on failure; add a prominent `<remarks>` warning that plaintext precedes the signature check and advise buffering until `isValid=true`.
- **Breaks public API?** No.
- **Raised by:** PKCS#11 Specialist B, Cryptographer B

### [BL-035] MD5-HMAC / MD5-KDF (and `CKM_SHA_1_KEY_GEN`) bypass the insecure-mechanism gate
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:608-761`
- **Problem:** `GuardMechanism` gates `CKM_MD5` and `CKM_MD5_RSA_PKCS` but not `CKM_MD5_HMAC`/`CKM_MD5_HMAC_GENERAL`/`CKM_MD5_KEY_DERIVATION` (the MD2 cluster covers all four of its variants). A caller building those mechanisms directly gets no gate. `CKM_SHA_1_KEY_GEN` is likewise absent from the SHA-1 arm.
- **Proposed action:** Add the three MD5 variants and `CKM_SHA_1_KEY_GEN` to their respective gate arms.
- **Breaks public API?** No.
- **Raised by:** Cryptographer A

### [BL-036] ECDH `DeriveRawSecret` template omits `CKA_TOKEN=false`
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/ECDiffieHellmanPkcs11.cs:162-166`
- **Problem:** The ephemeral derived-Z template is `Extractable().Sensitive(false)` without `OnToken(false)`. On tokens defaulting derived objects to `CKA_TOKEN=true`, a crash between `Derive` and `Delete` leaves a sensitive, extractable key persisted on the token. The ML-KEM template correctly sets `.OnToken(false)` (`MLKemPkcs11.cs:200`).
- **Proposed action:** Add `.OnToken(false)` to the chain.
- **Breaks public API?** No.
- **Raised by:** Cryptographer A

### [BL-037] `GenerateKey`/`ImportKey` template builders set `CKA_EXTRACTABLE=true` with no `AllowInsecure` check
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Objects/PrivateKeyTemplateBuilder.cs:28`, `Objects/SecretKeyTemplateBuilder.cs:32`; consumed at `Pkcs11Workspace.cs:271-278`.
- **Problem:** `.Extractable()`/`.Sensitive(false)` set the insecure posture without consulting `AllowInsecure`, inconsistent with `UnwrapKey` (which throws). A caller can generate/import an extractable key while the gate stays silent. (Distinct from BL-001, which is about omitted attributes; this is about an explicit opt-in not being gated.)
- **Proposed action:** Scan the outgoing template in `GenerateKey`/`CreateObject` for `CKA_EXTRACTABLE=true`/`CKA_SENSITIVE=false` and throw `InsecureOperationException` unless `AllowInsecure`; or document the deliberate asymmetry.
- **Breaks public API?** No (behavior; gated by `AllowInsecure`).
- **Raised by:** Cryptographer B

### [BL-038] AOT smoke test is not run in CI
- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `tests/AotSmoke/AotSmoke.csproj` exists but is not in `src/KerckhoffsLabs.sln` and no workflow publishes it.
- **Problem:** The library declares `IsAotCompatible`, but no CI step AOT-publishes, so a reintroduced `[RequiresDynamicCode]`/reflection path won't be caught until a consumer's AOT publish fails.
- **Proposed action:** Add a `dotnet publish tests/AotSmoke -r linux-x64 -c Release` step on the existing ubuntu runner, failing on IL2026/IL3050.
- **Breaks public API?** No.
- **Raised by:** QA C

### [BL-039] No SBOM, dependency vulnerability scan, or Dependabot
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** M
- **Location:** MISSING — no `.github/dependabot.yml`, no `dotnet list package --vulnerable` step, no SBOM artifact.
- **Problem:** A crypto library with runtime dependencies generates no component inventory and runs no transitive vuln scan; known-vulnerable versions go undetected.
- **Proposed action:** Add `dependabot.yml` (NuGet + Actions), a `dotnet list package --vulnerable --include-transitive` CI gate, and a CycloneDX SBOM publish artifact.
- **Breaks public API?** No.
- **Raised by:** QA C

### [BL-040] Community-health files absent (CONTRIBUTING, CODE_OF_CONDUCT, CHANGELOG, issue/PR templates)
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** M
- **Location:** MISSING — repo root and `.github/`.
- **Problem:** None of the standard OSS files exist; contributors have no guidance and there is no changelog to communicate releases.
- **Proposed action:** Add `CONTRIBUTING.md` (incl. how to run native tests), `CODE_OF_CONDUCT.md` (Contributor Covenant), seed `CHANGELOG.md`, and issue/PR templates.
- **Breaks public API?** No.
- **Raised by:** QA C

### [BL-041] README has no quick-start code sample
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `README.md:1-81`
- **Problem:** The only code is a 2-line `AllowInsecure` snippet; there is no end-to-end example (open workspace → session → sign/verify), so the 80% use case isn't demonstrable in <60s.
- **Proposed action:** Add a "Quick start" section with a self-contained ~30-line example drawn from the test fixtures.
- **Breaks public API?** No.
- **Raised by:** QA C

### [BL-042] No GitHub Environment protection on the publish job
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `.github/workflows/publish.yml:8-10` (no `environment:` key).
- **Problem:** Any `v*` tag push publishes to NuGet with no required-reviewer gate or wait timer; a compromised token or stray `git push --tags` ships a release.
- **Proposed action:** Add an `environment: nuget-publish` with required reviewers and scope `NUGET_USER` to it.
- **Breaks public API?** No.
- **Raised by:** QA C

### [BL-043] Codecov upload is `push`-only — PRs get no coverage feedback
- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `.github/workflows/code-quality.yml:117` (`if: github.event_name == 'push'`).
- **Problem:** PRs never send coverage, so reviewers see no diff-coverage or "coverage decreased" signal before merge.
- **Proposed action:** Remove the push-only guard (or use Codecov tokenless for fork PRs).
- **Breaks public API?** No.
- **Raised by:** QA C

### [BL-044] AEAD authenticity-negative tests on SoftHSM accept any `Exception`
- **Status:** ✅ Resolved 2026-06-09 — the four GCM authenticity-negative tests now assert `Pkcs11Exception` + `CKR_ENCRYPTED_DATA_INVALID` via a shared `AssertAuthFailure` helper.
- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `tests/.../Algorithms/AesGcmPkcs11Tests.SoftHsm2.cs:243,258,272-273,289`
- **Problem:** The four tamper/wrong-AAD/wrong-nonce tests use `Assert.ThrowsAny<Exception>()`, so a `NullReferenceException`/`AccessViolationException` would pass as "authentication correctly rejected", masking crashes. The managed sibling correctly asserts `Pkcs11Exception` + `CKR_ENCRYPTED_DATA_INVALID`.
- **Proposed action:** Tighten to `Pkcs11Exception` and assert the return code where predictable.
- **Breaks public API?** No.
- **Raised by:** QA A

### [BL-045] KAT coverage is thin — most mechanisms have only round-trip / cross-BCL tests
- **Status:** ✅ Resolved 2026-06-09 — added fixed-vector KATs for RSA-OAEP (decrypt), RSA-PSS (verify), ECDSA P-256 (verify, raw r‖s), ECDH P-256 (CKD_NULL Z), AES-KW (RFC 3394 §4.6) and HMAC-SHA384/512 (RFC 4231 TC6/7) in `KnownAnswerTests.SoftHsm2.cs`.
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `tests/.../Integration/Adapters/KnownAnswerTests.SoftHsm2.cs:19-147` (only AES-GCM, HMAC-SHA256, Ed25519, gated ChaCha20); RSA-OAEP/PSS, ECDSA, ECDH, AES-KW, HMAC-SHA384/512 lack fixed vectors.
- **Problem:** Round-trip tests can't catch a wrapper that mis-encodes a parameter symmetrically (e.g. wrong PSS salt length, transposed GCM IV/AAD, AES-KW padding byte). Fixed published vectors can.
- **Proposed action:** Add at least one NIST/RFC vector per family touching parameter marshalling: RSA-OAEP, RSA-PSS, ECDSA P-256, ECDH (SP 800-56A), AES-KW (RFC 3394 B.3), HMAC-SHA384/512 (RFC 4231 TC6/7).
- **Breaks public API?** No.
- **Raised by:** QA B, QA A
- **Spec / References:** RFC 3394; NIST SP 800-56A; PKCS#1 v2.2; RFC 4231.

### [BL-046] No negative/tamper tests for RSA-OAEP decryption
- **Status:** ✅ Resolved 2026-06-09 — `RSAPkcs11Tests.SoftHsm2.cs` now has tampered-ciphertext and wrong-key OAEP decrypt tests asserting `Pkcs11Exception`.
- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `tests/.../Algorithms/RSAPkcs11Tests.SoftHsm2.cs:188-230`
- **Problem:** All RSA-OAEP tests are happy-path round-trips — no corrupted-ciphertext, wrong-key, or all-zero-buffer case, unlike the GCM adapter's five authenticity tests.
- **Proposed action:** Add tampered-ciphertext and wrong-key decryption tests asserting a `Pkcs11Exception` (not a garbage success).
- **Breaks public API?** No.
- **Raised by:** QA B

### [BL-047] Only one real PKCS#11 backend (SoftHSM2) in CI
- **Status:** ✅ Resolved 2026-06-09 — opencryptoki (built from the vendored v3.27.0 source) runs as a second real backend on the CI `build-and-test` ubuntu-latest leg, covering AES-GCM/CBC, RSA, ECDSA, ECDH, HMAC, SHA-2/3, DES/3DES, ML-KEM and ML-DSA.
- **Area:** QA
- **Severity:** Medium
- **Effort:** L
- **Location:** `.github/workflows/ci.yml` (`build-and-test`); `tests/.../Support/Fixtures/SoftHsmBackendFixture.cs`.
- **Problem:** With only SoftHSM2 doing real crypto, a bug both it and the wrapper implement identically wrong passes every round-trip. SoftHSM's documented quirks (OAEP SHA-1 only, ECDH `CKD_NULL` only, no AES-CCM/ChaCha20) further narrow real coverage.
- **Proposed action:** Add opencryptoki (apt-installable on the existing Ubuntu runner) as a second backend for at least AES-GCM, HMAC, ECDSA.
- **Breaks public API?** No.
- **Raised by:** QA B

### [BL-048] No fuzzing of the marshalling layer
- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `tests/.../Unit/Native/MechanismParamsMarshalTests.cs` (+`.Extended.cs`) — deterministic inputs only.
- **Problem:** The most fragile paths (length-prefixed IV/AAD in `CkmAesGcmParams`/`CkmSalsa20ChaCha20Poly1305Params`, `ObjectAttribute` byte arrays) are tested with fixed inputs; a truncation/misalignment causing an unmanaged OOB read wouldn't surface.
- **Proposed action:** Add a `SharpFuzz` harness over the param/attribute constructors with a short CI time budget.
- **Breaks public API?** No.
- **Raised by:** QA B

### [BL-049] ML-DSA / ML-KEM real-token tests run only on the Linux CI leg
- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `tests/.../Support/Fixtures/SoftHsmBackendFixture.cs:70-92`; `.github/workflows/ci.yml:113-120` (macOS), `:129-173` (Windows).
- **Problem:** PQC tests require SoftHSM built against OpenSSL ≥3.5; only the Linux leg builds it, so macOS/Windows (incl. the marshalling-fragile win-x86) skip ML-DSA/ML-KEM. `CKA_PARAMETER_SET` width on win-x86 is exactly the kind of bug this would catch.
- **Proposed action:** Pin `openssl@3.5` on macOS and check the vcpkg OpenSSL version on Windows; emit a CI warning (not silent skip) where PQC should be enabled but isn't.
- **Breaks public API?** No.
- **Raised by:** QA B

### [BL-050] `FakeLowLevelPkcs11Library` reports `IsV32ApiSupported=true` but all v3.2 methods throw
- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `tests/.../Support/Fakes/FakeLowLevelPkcs11Library.cs:17,66-77`
- **Problem:** The unit-test fake advertises v3.2 support but every v3.2 entry point throws `NotSupportedException`, so any test branching on the flag explodes — and it falsely implies v3.2 paths are reachable in unit tests.
- **Proposed action:** Either set the flag `false`, or implement the v3.2 methods (as `ManagedSoftToken.Pqc.cs` does for encaps/decaps).
- **Breaks public API?** No.
- **Raised by:** QA A

---

## Low

### [BL-051] `IsMessageApiSupported` only checks the encrypt/decrypt half of the message API
- **Area:** PKCS#11 Conformance
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs:539-546`
- **Problem:** The property checks six encrypt/decrypt message pointers but not the sign/verify message functions, so the name overstates coverage.
- **Proposed action:** Rename to `IsMessageEncryptDecryptApiSupported` and add a sign/verify companion, or expand to all twelve.
- **Breaks public API?** No.
- **Raised by:** PKCS#11 Specialist A

### [BL-052] `IsV32ApiSupported` omits the async trio
- **Area:** PKCS#11 Conformance
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs:553-561`
- **Problem:** The v3.2 capability gate checks KEM/auth-wrap/verify-signature/validation but not `C_AsyncComplete/GetID/Join`, so callers can't detect async availability (feeds BL-028).
- **Proposed action:** Add an `IsV32AsyncApiSupported` property, or document the property's scope.
- **Breaks public API?** No.
- **Raised by:** PKCS#11 Specialist A

### [BL-053] `C_GetInterface` `pVersion` typed as `IntPtr`
- **Area:** P/Invoke
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/FunctionPointers.cs:261`
- **Problem:** `pVersion` is `IntPtr` rather than `CK_VERSION*`, so a version-constrained interface request is impossible without unsafe casts (all callers pass `IntPtr.Zero`).
- **Proposed action:** Change to `CK_VERSION*`; update `TryLoadFromGetInterface` to pass `(CK_VERSION*)null`.
- **Breaks public API?** No.
- **Raised by:** PKCS#11 Specialist A

### [BL-054] `_supportedMechanisms` cache is never invalidated
- **Area:** PKCS#11 Conformance
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:219-247`
- **Problem:** The per-session mechanism set is cached for the session lifetime and goes stale after a token remove/reinsert cycle.
- **Proposed action:** Document it as a session-open snapshot and/or add `InvalidateMechanismCache()`.
- **Breaks public API?** No.
- **Raised by:** PKCS#11 Specialist B

### [BL-055] `SecurePin(string)` constructor has no `[Obsolete]` nudge toward the span overload
- **Area:** Cryptography
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/SecurePin.cs:50-77`
- **Problem:** The source `string` is immutable/GC-moveable/internable and can't be zeroed; the type name implies full protection. A `ReadOnlySpan<byte>` overload is the secure path.
- **Proposed action:** Mark the `string` overload `[Obsolete(error:false)]` steering callers to the span overload.
- **Breaks public API?** No (warning only).
- **Raised by:** PKCS#11 Specialist B

### [BL-056] `Login`/`SetPin`/`InitPin` pass an unpinned PIN copy to P/Invoke
- **Area:** Cryptography
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:304,335,433`
- **Problem:** `pin.Pin.ToArray()` creates an unpinned `byte[]`; the GC-compaction window before/after the native call is tiny but nonzero (zeroization in `finally` is otherwise correct).
- **Proposed action:** Allocate via `SecureBuffer`/pinned `GCHandle` to close the window.
- **Breaks public API?** No.
- **Raised by:** Cryptographer B

### [BL-057] `CKM_AES_GCM_WRAP` / `CKM_AES_CCM_WRAP` constants missing despite raw structs existing
- **Area:** Cryptography
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKM.cs:1484-1489` (gap at 0x108F); structs `Native/RawMechanismParams/CK_GCM_WRAP_PARAMS.cs`, `CK_CCM_WRAP_PARAMS.cs`.
- **Problem:** The v3.2 wrap mechanisms have raw param structs but no `CKM` constants, so callers can't reference them type-safely.
- **Proposed action:** Add the `CKM` constants and matching high-level param wrappers.
- **Breaks public API?** No (additive).
- **Raised by:** Cryptographer A
- **Spec / References:** PKCS#11 v3.2 §2.5.

### [BL-058] `CkmXeddsaParams` takes a raw `ulong hashType` with no enum
- **Area:** Cryptography
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismParams/CkmXeddsaParams.cs:17-18`
- **Problem:** The constructor doc references `CK_XEDDSA_HASH_TYPE` but no such enum exists; callers pass a magic number while every other param wrapper takes a typed enum.
- **Proposed action:** Define `CkXeddsaHashType` and use it.
- **Breaks public API?** Yes (constructor signature) — land before 1.0.
- **Raised by:** Cryptographer A
- **Spec / References:** PKCS#11 v3.0 §2.3.14.

### [BL-059] `ECDsaPkcs11` leaks the combined `Mechanism` on the happy path
- **Area:** Cryptography
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/ECDsaPkcs11.cs:86-94,120-128`
- **Problem:** `VerifyData`/`SignDataInternal` dispose the combined mechanism only on the fallback path; on the supported path it's left undisposed. No unmanaged leak today (ECDSA combined mechs carry no param buffer) but it violates the `IDisposable` contract and would become a real leak if params were added.
- **Proposed action:** Wrap `combined` in `using` at both sites.
- **Breaks public API?** No.
- **Raised by:** Cryptographer A

### [BL-060] No `SlhDsaHashSign` map helper despite ML-DSA having one
- **Area:** Cryptography
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/Pkcs11MechanismMap.cs` (absent); constants at `Common/CKM.cs:2278-2323`.
- **Problem:** `CKM_HASH_SLH_DSA_*` constants and `CkmHashPqcSignParams` exist but there's no `SlhDsaHashSign` factory, asymmetric with `MlDsaHashSign`, leaving raw-mechanism callers without a typed helper.
- **Proposed action:** Add `SlhDsaHashSign` mirroring `MlDsaHashSign`.
- **Breaks public API?** No (additive).
- **Raised by:** Cryptographer A

### [BL-061] Generator emits `CharSet.Unicode` on every Windows sibling struct
- **Area:** P/Invoke
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Generators/PackedStructsGenerator.cs:51`
- **Problem:** `CharSet.Unicode` is emitted unconditionally though almost no PKCS#11 struct has `char`/`string` fields (they use `CK_UTF8CHAR` byte buffers); it's misleading noise.
- **Proposed action:** Emit `CharSet` only when string fields are present, and prefer `Ansi` if ever needed.
- **Breaks public API?** No.
- **Raised by:** .NET Engineer B

### [BL-062] No recorded strong-name signing decision
- **Area:** Release Eng
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` (no `SignAssembly`/key, no comment).
- **Problem:** No deliberate stance on strong-naming for a security library distributed on NuGet (absence ≠ decision).
- **Proposed action:** Record the decision in the csproj (a comment if intentionally unsigned, or add a key if desired).
- **Breaks public API?** No.
- **Raised by:** .NET Engineer B

### [BL-063] `ECCurve.IsBelowSecurityBaseline` is `internal`
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/ECCurve.cs:64`
- **Problem:** The weak-curve predicate that gates `GenerateEcKeyPair` isn't accessible to callers building their own policy.
- **Proposed action:** Make it `public`.
- **Breaks public API?** No (additive).
- **Raised by:** .NET Engineer A

### [BL-064] Raw `ulong Flags` exposed on every flags record
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/TokenFlags.cs:11` (and `SlotFlags`/`SessionFlags`/`MechanismFlags`/`InterfaceFlags`).
- **Problem:** `public ulong Flags` invites magic-number bit tests alongside the typed booleans and commits the library to a valid raw value.
- **Proposed action:** `[EditorBrowsable(Never)]` or rename to `RawFlags`.
- **Breaks public API?** No.
- **Raised by:** .NET Engineer A

### [BL-065] No third-party analyzers (Meziantou / Roslynator)
- **Area:** Release Eng
- **Severity:** Low
- **Effort:** S
- **Location:** `Directory.Build.props:18` (only `EnableNETAnalyzers`).
- **Problem:** Only first-party NetAnalyzers run; Meziantou's crypto/`IDisposable`/`CancellationToken` rules are directly relevant.
- **Proposed action:** Add `Meziantou.Analyzer` (`PrivateAssets=all`); Roslynator optional.
- **Breaks public API?** No.
- **Raised by:** QA C

### [BL-066] Minor test-quality nits: hardcoded SoftHSM flags, untested `CKR_CANT_LOCK`, skipped CBC-PAD, KAT provenance/label
- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `tests/.../Support/Fixtures/SoftHsmBackendFixture.cs:47-59` (flags hardcoded `false` instead of driven by the live `SupportedMechanisms` set); `Pkcs11Library.cs:165-172` `CKR_CANT_LOCK` retry untested; `tests/.../Integration/Encrypt/EncryptAesTests.Pkcs11Mock.cs:18,22` CBC-PAD permanently skipped with no managed-backend substitute; `tests/.../Integration/Discovery/GetInterfacesTests.Pkcs11Mock.cs:20-24` doesn't assert per-interface versions; `tests/.../Algorithms/AesCcmPkcs11Tests.SoftHsm2.cs:300-302` KAT provenance not cited; `tests/.../Integration/Adapters/KnownAnswerTests.SoftHsm2.cs:88` Ed25519 vector mislabeled "test 1" (it's RFC 8032 §6.1 vector 3).
- **Problem:** A cluster of small fidelity issues: capability gates can't self-update, a retry branch and a mechanism path have no coverage, and two KAT comments are inaccurate.
- **Proposed action:** Drive the SoftHSM flags from `SupportedMechanisms`; add a `FakeLowLevelPkcs11Library` `CKR_CANT_LOCK` retry test; implement CBC-PAD in `ManagedSoftToken` or remove the skipped tests; assert interface versions; cite NIST/RFC sources and fix the Ed25519 label.
- **Breaks public API?** No.
- **Raised by:** QA A, QA B

---

## PKCS#11 v3.2 Coverage Matrix

Condensed from PKCS#11 Specialist A. Overall conformance is **strong** — the gaps are mostly reachability/ergonomics, not missing bindings.

| Area | Status | Note |
|---|---|---|
| v2.40 / v3.0 / v3.2 function tables | ✅ Covered | All entries present and in spec order. |
| Interface dispatch (`C_GetInterface`/`List`) | ⚠️ Partial | Works; `pVersion` typed `IntPtr` (BL-053), `C_GetInterface` not on the interface (BL-027). |
| v2.40 per-symbol fallback | ✅ Covered | `TryLoadV30Symbols` falls back correctly (untested — BL-010). |
| Version negotiation (`C_GetInfo`/`CK_VERSION`) | ✅ Covered | Version header read before binding. |
| Windows Pack=1 ABI + `NativeCULong` width guard | ✅ Covered | Source-generated siblings; startup width guard. |
| Message-based AEAD (v3.0) | ⚠️ Partial | Bindings + wrappers present; `CKF_END_OF_MESSAGE` missing (BL-006); gate covers only encrypt/decrypt (BL-051); branch untested (BL-009). |
| KEM encaps/decaps | ✅ Covered | Two-call probe; wrappers present (secure-default gap — BL-001). |
| Authenticated wrap/unwrap (v3.2) | ✅ Covered | Present (secure-default gap on unwrap — BL-001). |
| Verify-signature-only (v3.2) | ✅ Covered | One-shot + streaming (streaming cancel-guard — BL-029). |
| Async session API (v3.2) | ⚠️ Partial | Bindings only; unreachable from high level (BL-028); not in capability gate (BL-052). |
| PQC: ML-KEM / ML-DSA / SLH-DSA | ✅ Covered | Mechanisms, key types, param sets all mapped. |
| EdDSA / XEdDSA | ✅ Covered | XEdDSA hash type not typed (BL-058). |
| v3.0/3.1/3.2 return codes | ✅ Covered | All present; vendor-code pass-through broken (BL-005). |
| Object classes: PROFILE / VALIDATION / TRUST | ✅ Covered | All defined. |
| v3.2 attributes (validation/trust/encap/decap) | ✅ Covered | Full range defined. |
| `CKU_CONTEXT_SPECIFIC`, session validation flags | ✅ Covered | Present with wrapper. |
| Vendor-extension story | ⚠️ Partial | Vendor `*_DEFINED` constants present; `ToCKR`/`ToCKM` throw on vendor values outside the mechanism-list path (BL-005). |

---

## Appendix A — Unverified / Speculative

- **Malicious-module heap corruption (Cryptographer B, Out-of-Scope note):** A buggy/hostile native module can overwrite managed output buffers beyond the reported length. This is inherent to `SafeHandle`-less P/Invoke against a trusted module and is accepted when the PKCS#11 module is in the TCB. Not a backlog item; recorded for awareness.
- **Branch-protection / required-checks settings (QA C):** Not verifiable from repository contents — must be confirmed in GitHub repo settings.
- **`KerckhoffsLabs.Runtime.InteropServices` internals (.NET Engineer B):** The `NativeCULong` per-RID width behavior is taken as documented; the package source was not reviewable. The startup width guard in `LowLevelPkcs11Library` is the safety net and was verified to exist.
- **LLP64 field-offset drift (QA A, Out-of-Scope note):** `NativeStructLayoutTests` pin field offsets only on Unix (LP64); no Windows LLP64 offset-pin tests exist for the `_Windows` siblings. The source generator enforces field identity, so this is lower-risk; raised for completeness rather than as a confirmed defect.

---

## Appendix B — Out of Scope Observations

Positive findings worth recording (these are *not* backlog items):

- **Mechanism correctness is high.** AES-GCM tag/IV (bits, [32,128]), AES-CCM L/M (RFC 3610 mac lengths), RSA-OAEP/PSS params (incl. PSS default salt = hash length), ECDSA combined-mechanism fallback, ML-DSA/SLH-DSA `CK_SIGN_ADDITIONAL_CONTEXT` (255-byte context enforced), ML-KEM extract-and-destroy, EdDSA param order, and ChaCha20-Poly1305 (12-byte nonce / 16-byte tag) were all reviewed as correct (Cryptographer A).
- **Secure defaults & gating.** `GuardMechanism` (`Pkcs11Session.cs:608-761`) comprehensively covers weak families; the deliberate allowance of strong-hash RSASSA-PKCS1-v1_5 *signatures* is well-reasoned. `[Obsolete]` markers on broken-crypto adapters are correct and reference the `AllowInsecure` gate.
- **No managed-side secret comparison.** All signature/MAC verification routes through `C_Verify`; the only `FixedTimeEquals` use is in the test fake. No non-constant-time secret comparison in production (Cryptographer B).
- **`SecureBuffer`/`SecurePin` zeroization.** Uses `CryptographicOperations.ZeroMemory` + pinned `GCHandle`; finalizer re-entry is guarded. PIN bytes are zeroed in `finally` across Login/InitPin/SetPin (residual unpinned-window nits captured in BL-033/BL-056).
- **Lifecycle correctness.** `CloseAllTrackedSessions` runs before `C_Finalize`; `Pkcs11SessionHandle` keeps the module reachable so it can't unload under a live handle; reentrant `AcquireExclusive` and the throw-on-concurrent-use `_busyLock` are sound design (PKCS#11 Specialist B).
- **Interop hygiene.** All `Native.*` types are `internal` (no raw `IntPtr`/interop leakage to consumers); the exception hierarchy is well-structured; `AllowInsecureScope()` returns a proper `IDisposable`.
- **CI strengths.** Windows x64, Windows ARM64, and win-x86 are in the test matrix (the `CK_ULONG`-width-fragile platforms are exercised); actions are SHA-pinned; `permissions: read-all`; OIDC trusted publishing + SLSA provenance; deterministic builds + SourceLink + snupkg symbols (QA B, QA C).
