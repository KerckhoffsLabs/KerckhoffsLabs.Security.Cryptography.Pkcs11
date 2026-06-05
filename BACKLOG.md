# Library Review Backlog

_Generated 2026-05-15 from a multi-specialist deep review (cryptography, PKCS#11 v3.2 conformance, .NET library design, P/Invoke, QA & release engineering)._

_Resolved and won't-fix items have been moved to [BACKLOG.closed.md](BACKLOG.closed.md)._

## Summary


- **Total items raised:** 63 _(since 2026-05-15)_
- **Open by severity:** Critical 0 | High 7 | Medium 14 | Low 5 — 26 open; the remainder Resolved or Won't-Fix. _(Counts last refreshed 2026-06-04.)_
- **Headline risks:**
  - **Public API has no shape guard.** No `PublicApiAnalyzer`, no `PackageValidation`, no API-diff job — breaking surface changes ship silently (BL-027, open).
  - _Resolved:_ the public API had exposed the entire native interop layer (~85 `CK_*` structs, `IMechanismParams`, the `CreateMechanism` factory). Closed by BL-022 / BL-023 / BL-024 — those types are now `internal`.

- **Release-readiness assessment:** Not yet 1.0-ready, but materially improved since the 2026-05-15 review. **All four Critical items are resolved** — Windows struct packing (BL-001), ML-DSA pre-hash semantics (BL-002), and multi-part / find-object state cleanup (BL-003/004) — as are most Highs (P/Invoke layout & AOT, secure-defaults gating, heap zeroing, the release pipeline). The remaining pre-1.0 work is predominantly **public-API scoping** — vendor-mechanism overloads (BL-014) — and **release-engineering / QA breadth** — a public-API shape guard (BL-027), `SECURITY.md` (BL-028), and macOS/ARM64 CI (BL-036). (`[Experimental]` scoping (BL-005), the secure key-gen forwarders (BL-021), and the OAEP / ECDH-KDF coverage (BL-035) were resolved in 2026-06-05.) These are SemVer-sensitive shape decisions that must land before 1.0, not correctness fixes. The library has excellent bones: clean exception hierarchy, well-designed `SecurePin`/`SecureBuffer`, sound secure-by-default mechanism gating, comprehensive v3.2 enum coverage, and a healthy test suite.

---

## High

### [BL-014] `GetMechanismInfo` accepts only `CKM` enum — vendor mechanisms unreachable

- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Slot.cs:118`; `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs:217`
- **Problem:** Vendor mechanisms with values ≥ `CKM_VENDOR_DEFINED = 0x80000000` cannot be cast to `CKM`. `GetMechanismList` returns `List<CKM>` (truncating vendor mechs). Consumers needing to query vendor capability info are blocked. `ObjectAttribute(ulong)` precedent exists for raw-value access.
- **Proposed action:** Add `GetMechanismList()` overload returning `IReadOnlyList<ulong>` and `GetMechanismInfo(ulong)` overload. Keep typed `CKM` overloads as the discoverable default.
- **Breaks public API?** Yes (return-type relaxation from `List<CKM>` to `IReadOnlyList<CKM>` is a binary-compat change — fold into BL-019). Must land before 1.0.
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** PKCS#11 v3.2 §3.4.

### [BL-027] No `PublicAPI.Shipped.txt` / `PackageValidation` — public surface unguarded

- **Area:** QA / Release Eng
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`
- **Problem:** No `Microsoft.CodeAnalysis.PublicApiAnalyzers`, no `Microsoft.DotNet.PackageValidation`, no API-diff CI step, no `PublicAPI.Shipped.txt`. Given BL-022's revelation that ~85 types are accidentally public, surface changes between releases will not be caught.
- **Proposed action:** Add `Microsoft.CodeAnalysis.PublicApiAnalyzers` and `Microsoft.DotNet.PackageValidation` to the csproj. Generate the baseline at 0.1.0. Add a CI step `dotnet build` that fails on unapproved public surface changes.
- **Breaks public API?** No.
- **Raised by:** .NET Engineer A, QA A, QA C
- **Spec / References:** [PackageValidation docs](https://learn.microsoft.com/dotnet/fundamentals/package-validation/overview).

### [BL-028] No SECURITY.md / vulnerability disclosure policy

- **Area:** Release Eng
- **Severity:** High
- **Effort:** S
- **Location:** `absent: SECURITY.md`
- **Problem:** A library wrapping cryptographic hardware has no disclosure policy, no contact, no embargo terms. Responsible reporters have nowhere to go.
- **Proposed action:** Add `SECURITY.md` with disclosure email or GitHub private vulnerability reporting, response-time SLA, PGP key. Enable "Report a vulnerability" in repo Settings → Security.
- **Breaks public API?** No.
- **Raised by:** QA C
- **Spec / References:** [GitHub Security Advisories](https://docs.github.com/en/code-security/security-advisories/).

---

## Medium

### [BL-037] No backward-compat test matrix — only one Cryptoki version exercised

- **Area:** QA
- **Severity:** Medium
- **Effort:** L
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Fixtures/SoftHsmBackendFixture.cs` (single fixture)
- **Problem:** Library claims v2.40–v3.2 back-compat. Test suite runs against one SoftHSM (≈v3.0). No path exercises v2.40-only or v3.1-only modules.
- **Proposed action:** Add a `PKCS11_EXTRA_MODULE_PATH` env-var override that runs a subset of the smoke and round-trip tests against an arbitrary caller-supplied module. Document the matrix in a `TESTING.md`.
- **Raised by:** QA A

### [BL-041] `CK_GCM_PARAMS.IvBits` carries a stale TODO and an undefined value

- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/RawMechanismParams/CK_GCM_PARAMS.cs:24`; `MechanismParams/CkmAesGcmParams.cs:43`
- **Problem:** `IvBits` is set to `iv.Length * 8` with a TODO comment. SoftHSM and many vendors ignore or reject non-zero values; PKCS#11 v3.2 retains the field as legacy ("may be 0").
- **Proposed action:** Set `IvBits = 0`, update comment to cite v3.2 §2.5.13.
- **Raised by:** Cryptographer A, PKCS#11 Specialist A

### [BL-042] `Pkcs11Workspace.Dispose` docstring claims it logs the user out — it doesn't

- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Workspace.cs:18-19,49-55`
- **Problem:** The XML doc states "the session's own Dispose logs the user out before closing." `Pkcs11Session.Dispose` never calls `C_Logout`. The HSM audit log will show only close, not logout.
- **Proposed action:** Either correct the doc, or add an explicit `Logout()` call before close (swallow `CKR_USER_NOT_LOGGED_IN`).
- **Raised by:** PKCS#11 Specialist B

### [BL-043] `LoginUser`, ML-KEM extract-and-destroy paths don't zero transient buffers / swallow destroy errors

- **Update (2026-06-04):** still open; the ML-KEM adapter was renamed/moved (`Pkcs11MlKem`→`Algorithms/MLKemPkcs11.cs`). Verified both sub-issues remain: `LoginUser` does not zero `usernameBytes` (`Pkcs11Session.cs` ~474), and `MLKemPkcs11.TryDestroy` still swallows `Pkcs11Exception` (~219). The recent ML-KEM shared-secret length-check fix is unrelated to this.
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs` (`LoginUser`); `Algorithms/MLKemPkcs11.cs` (`TryDestroy`)
- **Problem:** `LoginUser` zeroes `pinTmp` but not `usernameBytes` — inconsistent with the project's documented hygiene. `MLKemPkcs11.TryDestroy` silently swallows `Pkcs11Exception`; if `C_DestroyObject` fails the extractable shared-secret object lingers on-token.
- **Proposed action:** Zero `usernameBytes` in the `LoginUser` finally. Log the `TryDestroy` failure at warning and consider surfacing it to the caller after the copy completes.
- **Raised by:** Cryptographer A, Cryptographer B, PKCS#11 Specialist B

### [BL-044] `CKS_LAST_VALIDATION_OK`, `CKP_PKCS11_V3_2_*` profile constants are missing

- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CK.cs`; `Common/CKP.cs`; `Internal/Pkcs11Session.V32.cs:291` (broken `<see cref>`)
- **Problem:** XML doc on `GetSessionValidationFlags` tells callers to use `CKS_LAST_VALIDATION_OK`, which is undefined. Profile-ID constants (`CKP_PKCS11_V3_2_BASELINE` etc.) are not defined, so callers reading `CKA_PROFILE_ID` have no named constants.
- **Proposed action:** Add `CKS_LAST_VALIDATION_OK = 1` to `CK.cs`. Add a `CkpProfile` enum (or extend `CKP`) with the four v3.2 baseline/extended/complete/HSM profile IDs.
- **Raised by:** PKCS#11 Specialist A

### [BL-045] Async API (`C_AsyncComplete`/`GetID`/`Join`) has no high-level wrapper

- **Area:** PKCS#11 Conformance
- **Severity:** Medium
- **Effort:** L
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs:859-896`
- **Problem:** Bound at the low level but unreachable from `Pkcs11Session.V32.cs` / `Pkcs11Workspace`. `CK_ASYNC_DATA` is `internal`. No way to open an async session.
- **Proposed action:** Expose `OpenAsyncSession` on `Pkcs11Slot`, add a `Task`-returning wrapper on `Pkcs11Session`. Mark with `[Experimental]` per BL-005.
- **Raised by:** PKCS#11 Specialist A

### [BL-046] `Pkcs11Key.Wrap` selects public handle for asymmetric types that have no wrap mechanism

- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs:406`
- **Problem:** `Wrap` picks `_publicHandle` for any asymmetric key type. RSA-OAEP key wrap is correct; EC / EdDSA / ML-KEM keys produce a token-side `CKR_KEY_TYPE_INCONSISTENT` rather than a clear `ArgumentException`.
- **Proposed action:** Validate that the asymmetric key type is wrap-capable; throw `ArgumentException` for unsupported types.
- **Raised by:** Cryptographer B

### [BL-047] `RSAPkcs11.SignMechanismFor` inconsistently gates PKCS#1 v1.5

- **Update (2026-06-04):** still open; `RSAPkcs11` moved to `Algorithms/RSAPkcs11.cs` (`SignMechanismFor` now ~219-227). The gating split is unchanged. Related: BL-069 and the recent managed-verify additions (RSA-PSS / raw-ECDSA) touch the RSA verify path, but the all-gated-vs-all-allowed *policy* decision for `CKM_SHA*_RSA_PKCS` is still pending.
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Algorithms/RSAPkcs11.cs` (`SignMechanismFor`, ~219-227); `Internal/Pkcs11Session.cs` (`GuardMechanism`)
- **Problem:** `GuardMechanism` blocks `CKM_SHA1_RSA_PKCS` but allows `CKM_SHA256_RSA_PKCS` / `_SHA384_` / `_SHA512_`. The inline comment claims the SHA-N variants are "intentionally not gated." The split is inconsistent and creates false confidence.
- **Proposed action:** Decide either all-gated or all-allowed for `CKM_SHA*_RSA_PKCS`. Document the policy explicitly in code and the security model doc.
- **Raised by:** Cryptographer B

### [BL-048] No `.editorconfig`, `dotnet format` not in CI, README references stale `third-party/` path

- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `absent: .editorconfig`; `.github/workflows/ci.yml`; `README.md:26`
- **Problem:** No root `.editorconfig`. No `dotnet format --verify-no-changes` CI step. Formatting regressions are caught only by manual commits. README still mentions `third-party/pkcs11-mock` though the submodule was renamed to `vendor/pkcs11-mock` in commit 6c5014e.
- **Proposed action:** Add a root `.editorconfig`, add the verify step to CI, update README.
- **Raised by:** QA C

### [BL-050] No SBOM / dependency-vulnerability scan

- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** M
- **Location:** `.github/workflows/ci.yml` (absent)
- **Problem:** No `CycloneDX` SBOM, no `dotnet list package --vulnerable`, no Dependabot config. A crypto library should be transparent about its supply chain.
- **Proposed action:** Add `dotnet list package --vulnerable --include-transitive` (fail on findings). Generate `CycloneDX` SBOM as a build artifact. Enable Dependabot.
- **Raised by:** QA C

### [BL-051] No docs site, missing community-health files

- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** L
- **Location:** `absent: CONTRIBUTING.md, CODE_OF_CONDUCT.md, CHANGELOG.md, docfx.json, .github/PULL_REQUEST_TEMPLATE.md, .github/ISSUE_TEMPLATE/`
- **Problem:** Library generates XML documentation but ships it nowhere. README is build/test only — no usage example. No CONTRIBUTING / CoC / CHANGELOG / PR + issue templates.
- **Proposed action:** Add the missing files (CoC from the Contributor Covenant template is a 2-minute copy). Set up DocFX with a GitHub Pages deploy. Seed CHANGELOG with `## 0.1.0 (unreleased)`.
- **Raised by:** QA C

### [BL-053] Enum naming convention (`CKA_FOO`) deliberately deviates from .NET style — undocumented

- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** L (if PascalCase aliasing chosen)
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKA.cs`; `CKM.cs`; `CKR.cs`; …
- **Problem:** All-caps enum names + all-caps members violate .NET Framework Design Guidelines. Likely a deliberate choice for spec correspondence but undocumented; appears in every IntelliSense pop-up.
- **Proposed action:** Document the deliberate deviation in a project-style note. Optionally add PascalCase aliases marked `[EditorBrowsable(EditorBrowsableState.Advanced)]`. Decide before 1.0 — switching after is a SemVer-major change.
- **Raised by:** .NET Engineer A

### [BL-063] No public generic attribute read/write

- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs`; `Objects/ObjectAttribute.cs` (internal); internal `Pkcs11Session.Objects.cs` has `GetAttributeValue`/`SetAttributeValue`.
- **Problem:** Public API surface review (2026-05-20). No public way to read object attributes (`CKA_MODULUS`, `CKA_EC_POINT`, `CKA_VALUE`, `CKA_ID`, custom/vendor attributes) or modify mutable ones (`CKA_LABEL`, `CKA_ID`). The library synthesizes RSA/EC public params internally for the BCL adapters (`Pkcs11PublicKeyView`) but exposes no general "read attribute X" door. `Pkcs11Key` surfaces only `KeyType`/`Label`/`Id`.
- **Proposed action:** Add a public read API (e.g., `Pkcs11Key.GetAttribute(CKA)` returning a typed value, or a small attribute accessor) and a guarded write for mutable attributes. Keep the secure-by-default posture: attribute *read* must honour the token's sensitivity flags (return "unavailable" rather than throwing on `CKA_SENSITIVE`/non-readable), and must not become a side-channel to extract material the token marks non-extractable.
- **Breaks public API?** No (additive).
- **Raised by:** Public-surface review.
- **Spec / References:** PKCS#11 v3.2 `C_GetAttributeValue` / `C_SetAttributeValue`; relates to BL-014 (vendor values).

## Low

### [BL-059] `EncryptDecryptStressTests` swallows `Pkcs11Exception` — could mask handle leaks

- **Area:** QA
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/MemoryLeaks/EncryptDecryptStressTests.cs:58-77`
- **Problem:** Both `Encrypt` and `DestroyObject` are wrapped in `catch (Pkcs11Exception) {}`. The baseline-count comparison only tracks `UnmanagedMemory` blocks, not PKCS#11 object handles, so a `CreateObject` success + `DestroyObject` failure pattern would not be flagged.
- **Proposed action:** Track whether `CreateObject` succeeded; ensure `DestroyObject` runs for any successfully-created key regardless of encrypt outcome.
- **Raised by:** QA A

### [BL-061] `CancelOperations(ulong flags)` takes raw flags — no typed `[Flags]` surface

- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:495`
- **Problem:** Split out from BL-055. `CancelOperations(ulong flags)` (and the broader CKF surface) is passed as raw `ulong` / `NativeCULong`; the CKF constants live in a static `CKF` class as `NativeCULong` fields, not a `[Flags]` enum, so callers have no discoverable, type-safe way to compose `CKF_ENCRYPT | CKF_SIGN | …`.
- **Proposed action:** Decide whether to model CKF as a `[Flags]` enum (and similar bitmask domains) for discoverability + type safety, or leave the `NativeCULong`-constant model. If adopting an enum, do it consistently across the CKF surface, not just `CancelOperations`. Pre-1.0 (signature change to `CancelOperations`).
- **Raised by:** Derived from BL-055.
- **Spec / References:** —

### [BL-066] No public multi-part / streaming crypto (one-shot only)

- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** L
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs`; internal `Pkcs11Session.{Encrypt,Decrypt,Sign,Verify,Digest}.cs` have the multi-part `*Update`/`*Final` wrappers.
- **Problem:** Public API surface review (2026-05-20). All public crypto is one-shot (`Encrypt`/`Decrypt`/`Sign`/`Verify`/`Digest` over a single buffer), so data that does not fit in memory cannot be processed. The internal session already implements the multi-part `Init`/`Update`/`Final` sequences (with BL-003 self-healing cleanup); they are not exposed.
- **Proposed action:** Design a public streaming surface (e.g., `Stream`-based or incremental `Update`/`Final` objects) over the existing internal multi-part wrappers. This is the surface that would also justify making `CancelOperations` public (see BL-061) so a consumer can abort a partial operation. Significant API-design work — sequence-state management, disposal semantics, and thread-affinity all need care.
- **Breaks public API?** No (additive).
- **Raised by:** Public-surface review.
- **Spec / References:** PKCS#11 v3.2 §5.9–5.12 (multi-part operations).

### [BL-069] Managed verify fallback rejects raw `CKM_RSA_PKCS` / `CKM_RSA_X_509` for private-only keys

- **Area:** Cryptography
- **Severity:** Low
- **Effort:** S (Option B — `CKM_RSA_PKCS` only) / M (Option C — adds `CKM_RSA_X_509`)
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Key.cs` (`VerifyRsaInManaged` / `MapRsaSignMechanism`, ~581-616)
- **Problem:** When a key has no `CKO_PUBLIC_KEY` companion, `Pkcs11Key.Verify` falls back to managed verification using public params synthesized from the private object. The mechanism map now covers PKCS#1 v1.5 and RSA-PSS (combined `CKM_SHA*_RSA_PKCS[_PSS]`) and raw `CKM_ECDSA`, but still throws `NotSupportedException` for raw `CKM_RSA_PKCS` and `CKM_RSA_X_509`. This is **not reachable through any BCL adapter** — `RSAPkcs11` only ever produces combined `CKM_SHA*_RSA_PKCS[_PSS]` for verify and does not implement hash-level `VerifyHash` — so it affects only direct low-level `Pkcs11Key.Verify` callers with a private-only key. It is an availability gap (throws), never a wrong result, hence Low.
- **Proposed action:** Three options, in increasing effort/risk:
  - **A (recommended):** leave unsupported. The current explicit `NotSupportedException` ("provide a `CKO_PUBLIC_KEY` companion") already guides callers; no adapter exercises this path.
  - **B:** support `CKM_RSA_PKCS` — parse the input DER `DigestInfo` (via `System.Formats.Asn1`, already used in this file) to recover `(hashAlgorithm, digest)`, then `rsa.VerifyHash(digest, sig, hashName, RSASignaturePadding.Pkcs1)`. Caveat: `VerifyHash` reconstructs the *canonical* DigestInfo, so a signature over a non-canonically-encoded DigestInfo would be rejected even though the token's byte-exact `C_Verify` accepts it. Covers v1.5 only.
  - **C:** add `CKM_RSA_X_509` via a hand-rolled RSA public op (`BigInteger` `sᵉ mod n`) + `CryptographicOperations.FixedTimeEquals` block compare — low-risk (no padding parser). Achieving *byte-exact* `CKM_RSA_PKCS` would additionally require a strict EMSA-PKCS1-v1_5 unpad, which is a signature-forgery footgun (Bleichenbacher'06 / "BERserk" leniency class) and is **not** recommended for a non-adapter path.
- **Breaks public API?** No (additive behavior on an internal verify path).
- **Raised by:** Algorithms-review follow-up (2026-06-04); split from the managed-verify fix that closed RSA-PSS + raw-ECDSA.
- **Spec / References:** PKCS#11 v3.2 (`CKM_RSA_PKCS` DigestInfo input; `CKM_RSA_X_509` raw); Bleichenbacher RSA signature-forgery / "BERserk" (padding-leniency class); relates to BL-018 (raw `CKM_RSA_X_509` gating), BL-047 (v1.5 gating split).

---

## PKCS#11 v3.2 Coverage Matrix

Condensed from PKCS#11 Specialist A's full matrix.

### Functions

| Status | Count | Notes |
|---|---|---|
| Covered (v2.40 / v3.0 / v3.2) | ~85 | Including all message-AEAD, `C_LoginUser`, `C_SessionCancel`, `C_VerifySignature*`, `C_DecapsulateKey`, `C_UnwrapKeyAuthenticated` |
| Partial | 6 | `C_EncapsulateKey` and `C_WrapKeyAuthenticated` (BL-011); `C_GetSessionValidationFlags` (BL-044); `C_AsyncComplete`/`GetID`/`Join` (BL-045) |
| Missing | 1 | `C_GetInterfaceList` (BL-013) |

Notable gap not on the backlog because the function is technically covered: `C_GetMechanismInfo` is implemented but only accepts `CKM` enum values (BL-014).

### Mechanisms

| Status | Coverage |
|---|---|
| Covered with high-level wrapper | RSA (PKCS#1 / OAEP / PSS), ECDSA, ECDH1, EdDSA, AES (GCM / CCM / CBC / CTR / KEY_WRAP / KEY_WRAP_PAD), ChaCha20-Poly1305, HMAC (SHA-2 family), ML-DSA, ML-KEM, SHA-2/SHA-3 digests, HKDF (raw struct only) |
| Covered (enum + raw struct only — no high-level helper) | XEDDSA, SLH-DSA, HSS, SP800-108 KDF (counter + feedback), IKE family, X3DH, X2-Ratchet, Salsa20, PBKDF2, RSA-AES-KEY-WRAP |
| Hash-ML-DSA variants | Mapped for SHA-224/256/384/512 and SHA3 variants. SHAKE128/SHAKE256 listed in doc but **not implemented** (BL-010). Note BL-002: the entire `SignPreHash` path is semantically wrong. |

### Attributes (v3.2 additions)

All claimed v3.2 attribute additions present: `CKA_PROFILE_ID`, `CKA_PARAMETER_SET`, `CKA_VALIDATION_STATE` + the 11-attribute validation block, `CKA_ENCAPSULATE_TEMPLATE` / `CKA_DECAPSULATE_TEMPLATE`, trust attributes, `CKA_ENCAPSULATE` / `CKA_DECAPSULATE` usage flags, HSS attrs, ratchet attrs, wrap/unwrap/derive template attrs, `CKA_ALLOWED_MECHANISMS`. No findings.

### Return Codes (v3.2 additions)

All present: `CKR_AEAD_DECRYPT_FAILED`, `CKR_PENDING`, `CKR_ASYNC_NOT_SUPPORTED`, `CKR_SEED_RANDOM_REQUIRED`, `CKR_OPERATION_NOT_PERMITTED`, `CKR_TOKEN_NOT_INITIALIZED`, `CKR_PARAMETER_SET_NOT_SUPPORTED`. No findings.

### Flags (v3.2 additions)

All present: `CKF_ASYNC_SESSION`, `CKF_ASYNC_SESSION_SUPPORTED`, `CKF_ENCAPSULATE`, `CKF_DECAPSULATE`. No findings.

### Profile / Validation Constants

Missing: `CKP_PKCS11_V3_2_BASELINE/EXTENDED_PROVIDER/COMPLETE_PROVIDER/HSM_PROVIDER`, `CKS_LAST_VALIDATION_OK` (BL-044).

---

## Appendix A — Unverified / Speculative

Items raised by specialists that could not be substantiated from code, or that require runtime evidence to confirm:

- **PIN-handling races on GC promotion (CRYPTO-B-3 follow-up).** `Pkcs11MlKem.ReadAndCopySecret` correctly zeroes the local managed `byte[]`, but the .NET GC may have promoted a copy in between allocation and the `finally` block. This is structurally hard to eliminate without changing the `ObjectAttribute.GetValueAsByteArray()` API to return into a caller-supplied `Span<byte>`. Filed as an observation, not a backlog item.
- **`AcquireExclusive` reentrancy in `SupportsMechanism` (P11-B-4).** Currently safe because `Monitor` is reentrant on the same thread, but fragile if `SupportsMechanism` is ever called from a thread that doesn't hold the lock. Worth documenting as an internal-only contract.
- **Branch protection rules.** Unverifiable from source — needs confirmation in GitHub Settings → Branches.
- **NuGet package signing (Authenticode-signed nupkg).** Out of scope for repo review; needs a certificate and Trusted Signing setup.

---

## Appendix B — Out of Scope Observations (positive findings & context)

### Strong areas (no findings)

- **`SecurePin` / `SecureBuffer`.** Pinned allocation + `CryptographicOperations.ZeroMemory` + finalizer safety net + `ToString()` redaction throughout. No leakage path found.
- **Exception hierarchy.** Abstract `Pkcs11Exception` + typed subclasses + `ExceptionMapper` is clean. `Throw` / `ThrowIfError` / `Create` triad documented with the CS0177 rationale. The `InsecureOperationException` two-ctor design (mechanism-typed vs message-only) is well-considered.
- **Insecure-mechanism gate architecture.** The per-session `AllowInsecure` flag wired through a centralized `GuardMechanism` switch in `Pkcs11Session.cs` is the right shape. The remaining issues are coverage (BL-018) and scoping (BL-008), not architecture.
- **`InsecureOperationGateTests`.** Coverage matrix over Encrypt / Decrypt / Sign / Verify / Digest / GenerateKey / DeriveKey with both gate and bypass directions is one of the strongest test areas in the suite.
- **`Pkcs11MechanismMap` centralization.** All BCL adapters route through it; fixing a mapping there propagates globally. No mechanism is hardcoded in more than one place.
- **`SafeHandle` discipline.** `Pkcs11ModuleHandle` correctly extends `SafeHandle` / `CriticalFinalizerObject` and calls `NativeLibrary.Free` in `ReleaseHandle`. Library loading via `NativeLibrary.Load` is correct (no consumer-controlled-path `DllImport`).
- **`NativeCULong` packaging.** Correctly uses `'$(OS)' == 'Windows_NT'` to pick 32-bit vs 64-bit `CK_ULONG`. This handles the classic Cryptoki footgun correctly — the Pack=1 issue (BL-001) is orthogonal to CK_ULONG sizing.
- **All 70+ delegates consistently `[UnmanagedFunctionPointer(CallingConvention.Cdecl)]`.** No `stdcall` slip on Windows.
- **`Marshal.AllocHGlobal` accounting.** `UnmanagedMemory` always populates the tracker dictionary (per the recent fix), and `Free` zeroes the `ref IntPtr` after free. The strict "untracked memory" check catches double-frees immediately.
- **`Mechanism` (high-level wrapper) ownership.** Owns the `CK_MECHANISM.Parameter` pointer lifetime, frees in `Dispose(bool)`, finalizer backstop — sound dispose pattern.
- **`TryLoadFromGetInterface` version negotiation.** Correctly reads `CK_FUNCTION_LIST_3_0` only when `Major >= 3`, `CK_FUNCTION_LIST_3_2` only when `Minor >= 2`, with a safe fallback. The static-link gap (BL-012) is in a different code path.
- **PQC parameter-set values.** `CKP_ML_DSA_44/65/87`, `CKP_ML_KEM_512/768/1024`, `CKP_SLH_DSA_*`, hedge-variant defaults (`CKH_HEDGE_PREFERRED = 0`) match PKCS#11 v3.2 Annex A and FIPS 204/203.
- **Template-builder defaults.** `PrivateKeyTemplateBuilder` and `SecretKeyTemplateBuilder` default to `CKA_SENSITIVE=true, CKA_EXTRACTABLE=false`. `PublicKeyTemplateBuilder` omits sensitivity (correct for public material).
- **Memory-leak harness.** `OutstandingAllocationCount` baseline/delta pattern with `GC.Collect() + WaitForPendingFinalizers()` double-fence is the correct approach for deterministic unmanaged accounting. Recently hardened against cross-test finalizer drift.
- **SourceLink, deterministic build, snupkg symbols, README in package** all wired in the csproj.

### Threat-model summary (for context)

| Direction | Surface | Findings |
|---|---|---|
| Module → host (memory safety) | P/Invoke layer | BL-001 packing on Windows is the primary risk; BL-026 SSL3 IsExport; rest is sound |
| Module → host (state corruption) | Session lifecycle | BL-003, BL-004 (op state); BL-015, BL-016 (init/finalize pairing) |
| Caller → key material (extraction) | Wrap/unwrap, ML-KEM extract-and-destroy | BL-017 (unwrap defaults); BL-008 (AllowInsecure scope); BL-009 (heap residue) |
| Caller → mechanism choice (cryptographic agility) | `GuardMechanism`, `Pkcs11MechanismMap` | BL-018 missing entries; BL-047 PKCS#1 v1.5 split inconsistency |
| Logging side channel | `Logging/`, exception messages | No PIN leakage found; BL-007 references internal type name; BL-055 logs pointer addresses in debug mode |
