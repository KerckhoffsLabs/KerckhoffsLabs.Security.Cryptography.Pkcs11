# Library Review Backlog

_Generated 2026-05-15 from a multi-specialist deep review (cryptography, PKCS#11 v3.2 conformance, .NET library design, P/Invoke, QA & release engineering)._

## Summary


- **Total items:** 62
- **Critical:** 0 | **High:** 8 | **Medium:** 15 | **Low:** 4
- **Headline risks:**
  - **Public API exposes the entire native interop layer.** ~85 `CK_*` structs, `IMechanismParams` returning `object`, and the `CK_MECHANISM.CreateMechanism` allocation factory are all `public`. This freezes marshalling internals into SemVer commitments and is AOT-hostile.
  - **Public API has no shape guard.** No `PublicApiAnalyzer`, no `PackageValidation`, no API-diff job — breaking changes ship silently.

- **Release-readiness assessment:** The library is **not ready for a 1.0 release.** The four Critical items are silent failures that would damage trust on first contact (Windows users see crashes / wrong attributes; pre-hash ML-DSA users produce signatures no other implementation can verify; any exception inside a multi-part operation leaves the session permanently broken). Past those, the public API surface itself needs scoping before 1.0 — exposing the raw P/Invoke types and a single-target net10.0 are SemVer-major changes after 1.0, so they have to land beforehand. The cryptographic correctness work, public-API redesign, P/Invoke layout fixes, and release-pipeline gaps together represent roughly 4-8 weeks of focused work before a defensible 1.0. The library has excellent bones: clean exception hierarchy, well-designed `SecurePin`/`SecureBuffer`, sound secure-by-default mechanism gating architecture, comprehensive enum coverage of v3.2, and a healthy test suite — but the pre-1.0 polish layer is missing.

---

## Critical

### [BL-001] `[PlatformSpecificPack]` is functionally dead; Windows OASIS-compliant modules will marshal at wrong offsets

- **Status: Resolved (2026-05-15)** via Option B — source generator emits `T_Windows` siblings with `Pack=1` for every `[PackedForPkcs11]`-marked struct; `Pkcs11Marshal` + `UnmanagedMemory` + `LowLevelPkcs11Library` runtime-dispatch on Windows via parallel `_Windows` delegates that target the same native function pointers. `MarshalSizeOfTests` pins both unified (Linux/macOS) and `_Windows` sibling sizes; Windows CI now hard-fails if SoftHSM isn't installed (closes BL-049 in the same branch). See `docs/superpowers/plans/2026-05-15-pkcs11-struct-packing-source-gen.md` for the full implementation.
- **Area:** P/Invoke
- **Severity:** Critical (for Windows OASIS-compliant modules); currently latent because Linux is the only platform actually exercised
- **Effort:** M (Option A) — L (Option B, Pkcs11Interop-style)
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/PlatformSpecificPackAttribute.cs:5-10`; applied to 99 structs across `Native/` and `Native/RawMechanismParams/`; `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj:34-36`
- **Problem:** Three independent defects compound:
  1. `[StructLayout(LayoutKind.Sequential, Pack = ?)]` is written on the *`PlatformSpecificPackAttribute` class itself* (an `Attribute` subclass — a reference type), not on the consuming structs. The CLR does not propagate `[StructLayout]` from a custom-attribute class onto types that *use* the attribute. Empirical proof on Linux x64: every CK struct reports `Marshal.SizeOf` consistent with `Pack=0` (CLR default for structs without explicit `[StructLayout]`). Introspecting the attribute class itself raises `TypeLoadException: format is invalid` because `[StructLayout(Pack=…)]` on a reference type is itself ill-formed.
  2. The `#if WINDOWS` symbol is set by `<DefineConstants Condition="'$(TargetPlatformIdentifier)' == 'windows'">WINDOWS</DefineConstants>` in the csproj. The TFM is `net10.0` (no `-windows` OS suffix), so the condition is always false. Even if defect 1 were fixed, the conditional would always pick the non-Windows branch on every build.
  3. `[StructLayout(Pack=N)]` is a compile-time IL attribute baked into the shipped assembly. A single cross-platform NuGet `.dll` carries one set of IL and runs on every platform — there is no compile-time switch that can vary `Pack` by the *consumer's* runtime OS. The design intent ("Pack=1 on Windows, default elsewhere via a single attribute") cannot be realized with one struct set.
- **Verified ABI reality:**
  - **Linux/macOS x64 native ABI = `Pack=0` (natural alignment).** OASIS `pkcs11.h` only emits `#pragma pack(push, cryptoki, 1)` under `#if defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)` — confirmed in `vendor/softhsmv2/src/lib/pkcs11/pkcs11.h:82-86`. The CLR default Pack=0 coincidentally matches SoftHSM and every other typical Linux/macOS PKCS#11 module. Tests pass *because* this is the correct ABI, not despite the bug.
  - **Windows OASIS-compliant native ABI = `Pack=1`.** The CLR default Pack=0 will misalign `CK_ATTRIBUTE` (24 vs 16 bytes), `CK_MECHANISM` (24 vs 16), `CK_FUNCTION_LIST` (6-byte pad before the first function pointer), `CK_C_INITIALIZE_ARGS` (48 vs 44), `CK_INFO` (74 vs 72), and most param structs containing both `NativeCULong` and `IntPtr`/`NativeCULong` adjacencies. Every `C_*` call against such a module reads/writes at wrong offsets — function pointers resolve to arbitrary memory or the wrong function.
  - **Windows non-OASIS-conformant modules** (some older vendor SDKs that historically omit the pragma — e.g., the same family Pkcs11Interop addresses with its API40 variant) use natural alignment and would coincidentally work with the current CLR default.
- **Why this is currently invisible:** the Windows CI step `choco install -y softhsm` has `continue-on-error: true` (see BL-049), so Windows runners report green even when SoftHSM never installs and zero SoftHSM-backed tests run. The Linux runner is the only path actually exercising native interop; Linux Pack=0 happens to be correct.
- **Reference design (Pkcs11Interop):** ships four parallel struct trees — `LowLevelAPI40` (Pack=0, 32-bit `CK_ULONG`), `LowLevelAPI41` (Pack=1, 32-bit), `LowLevelAPI80` (Pack=0, 64-bit), `LowLevelAPI81` (Pack=1, 64-bit) — and dispatches at runtime via a factory. Their canonical Linux/macOS x64 set is `API80 (Pack=0)`, matching SoftHSM's natural-alignment ABI exactly. Windows 64-bit modules use `API40` (4-byte `CK_ULONG`); whether the Pack=0 or Pack=1 variant fits depends on how the vendor compiled their headers — hence both ship in parallel. This author chose to simplify by collapsing the (`CK_ULONG` size × Pack) matrix using `NativeCULong` plus `[PlatformSpecificPack]`. `NativeCULong` collapses the first axis correctly because it does runtime dispatch (`uint` on Windows via `'$(OS)' == 'Windows_NT'`, `ulong` elsewhere). Collapsing the Pack axis cannot be done the same way because Pack is compile-time IL only.
- **Proposed action — choose one before 1.0:**
  - **Option A — narrow the supported platforms (pre-1.0 minimum, ~M effort).** Delete `[PlatformSpecificPack]`. Decorate every CK struct with bare `[StructLayout(LayoutKind.Sequential)]` (the default Pack value resolves to the consumer's platform-natural at runtime). Update the README/csproj to declare "Linux x64, macOS x64/arm64 supported; Windows support deferred." Drop `win-x86;win-x64` from `<RuntimeIdentifiers>` for the 0.x line. Linux/macOS continue to work as today.
  - **Option B — full correctness via source generation (~L effort).** Mark each CK struct `partial`. Implement a source generator that, on a `[PackedForPkcs11]`-style marker, emits two type definitions per struct (one with `[StructLayout(Sequential, Pack=1)]` named e.g. `CK_INFO_Windows`, one with `[StructLayout(Sequential)]` named `CK_INFO`) plus a thin runtime dispatcher in `Marshal*` helpers that picks based on `OperatingSystem.IsWindows()`. The public type the rest of the library uses can be the existing one for Linux/macOS and the suffixed one on Windows. Consumer code is unchanged. This preserves the user's "simplification" intent — one source definition per struct, one tag attribute — but moves the platform pivot from a (broken) compile-time `[StructLayout]` to a (correct) build-time generation step.
  - **Option C — Pkcs11Interop-style runtime dispatch (~XL).** Maintain four parallel struct sets. Highest compatibility, highest maintenance.
- **Regression test (apply with either option):** add `MarshalSizeOfTests` asserting `Marshal.SizeOf<CK_INFO>()`, `<CK_ATTRIBUTE>`, `<CK_MECHANISM>`, `<CK_C_INITIALIZE_ARGS>`, `<CK_FUNCTION_LIST>` against the expected ABI for the current OS. This catches *any* future struct layout drift, regardless of which option is chosen.
- **Breaks public API?** Yes — `[PlatformSpecificPack]` (currently `internal` so technically fine), the public `CK_*` structs (these need to become `internal` anyway per BL-022), and the supported-RID list. Must land before 1.0.
- **Raised by:** .NET Engineer B, PKCS#11 Specialist A; revised after empirical verification + comparison against Pkcs11Interop's `LowLevelAPI40/41/80/81` design.
- **Spec / References:** OASIS PKCS#11 `pkcs11.h` `#if _WIN32 → #pragma pack(push, cryptoki, 1)` (confirmed in `vendor/softhsmv2/src/lib/pkcs11/pkcs11.h:82-86`); .NET `StructLayoutAttribute` docs; [Pkcs11Interop source — `LowLevelAPI80/CK_INFO.cs`](https://github.com/Pkcs11Interop/Pkcs11Interop/blob/master/src/Pkcs11Interop/Pkcs11Interop/LowLevelAPI80/CK_INFO.cs) demonstrating Pack=0 for Linux/macOS x64.

### [BL-002] `Pkcs11MlDsa.SignPreHashCore` / `VerifyPreHashCore` double-hash via `CKM_HASH_ML_DSA_*`

- **Status: Resolved (2026-05-15)** — `SignPreHashCore` / `VerifyPreHashCore` now throw `NotSupportedException` with a precise rationale. PKCS#11 v3.2 offers no mechanism that accepts a caller-supplied pre-hash: `CKM_ML_DSA` is structurally pure ML-DSA (domain prefix 0x00, never 0x01), and `CKM_HASH_ML_DSA_<H>` hashes its own input — there is no way to produce a spec-compliant HashML-DSA signature from a digest. Removed the dead `HashSignMechanismFor` helper. `Pkcs11MechanismMap.MlDsaHashSign` is retained because it remains valid for message-based HashML-DSA workflows added later (out of scope here).
- **Area:** Cryptography
- **Severity:** Critical
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11MlDsa.cs:82-102`
- **Problem:** The BCL `MLDsa.SignPreHash(hash, …)` contract states `hash` is the pre-computed message digest. The override hands `hash` to `CKM_HASH_ML_DSA_SHA256` (and siblings), a combined mechanism that hashes its input before signing. The token therefore signs `H(H(message))` instead of the FIPS 204 §5.4 HashML-DSA value over the message. The signature is well-formed but interoperable with nothing — any external verifier produces "signature invalid". The internal round-trip via the same wrapper succeeds, so existing tests would not catch this even if PQC adapters were tested (see BL-040).
- **Proposed action:** Either route pre-hash via the plain `CKM_ML_DSA` mechanism with the OID embedded in the context per FIPS 204 §5.4, or throw `NotSupportedException` from `SignPreHashCore`/`VerifyPreHashCore` with a clear message that PKCS#11 v3.2's `CKM_HASH_ML_DSA_*` expects the message, not the digest. Add a known-answer test against a NIST ML-DSA vector if available.
- **Breaks public API?** No (semantics fix; signature shape unchanged for callers using `SignData`).
- **Raised by:** Cryptographer A
- **Spec / References:** FIPS 204 §5.4 (HashML-DSA); PKCS#11 v3.2 §2.46.

### [BL-003] Multi-part stream operations leave session in active-operation state on exception

- **Status: Resolved (2026-05-15)** — wrapped each stream-based `*_Init → loop → *_Final` in `try/finally` with a `finalized` flag that is set only after `ThrowIfError` returns. On the exception path the new `Pkcs11Session.TryCancelOperation` helper invokes `C_SessionCancel` with the appropriate `CKF_*` flag(s) and swallows errors (including `CKR_FUNCTION_NOT_SUPPORTED` from v2.40 libraries) so the original exception is never masked. Applied to stream-based `Encrypt`, `Decrypt`, `Verify`, `Digest`, `DigestEncrypt`, and `DecryptDigest`. Combined-op methods compose the cancel flags from independent `*Inited`/`*Finalized` markers so only the still-live sub-operations are cancelled.
- **Area:** PKCS#11 Conformance
- **Severity:** Critical
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.Encrypt.cs:113-171`; same anti-pattern in `Pkcs11Session.Decrypt.cs`, `.Verify.cs`, `.Digest.cs`
- **Problem:** Stream-based `Encrypt`/`Decrypt`/`Verify`/`Digest*` methods do `C_*Init → loop(C_*Update) → C_*Final` with **no `try/finally`**. If `inputStream.Read`, `outputStream.Write`, or any `C_*Update` throws, `C_*Final` never runs and the session is permanently wedged in active-operation state. The next call (including `C_CloseSession`) fails with `CKR_OPERATION_ACTIVE` on spec-compliant tokens.
- **Proposed action:** Wrap the update loop and final call in `try/finally`. On the exception path, invoke `C_SessionCancel` (v3.0+) — already wrapped as `Pkcs11Session.CancelOperations` — or fall back to a best-effort `C_*Final(null, 0)` to clear the operation before re-throwing.
- **Breaks public API?** No.
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** PKCS#11 v3.1 §5.6.8 (`C_SessionCancel`); §11.8–11.13.

### [BL-004] `FindAllObjects` leaves search active on `C_FindObjects` exception

- **Status: Resolved (2026-05-15)** — wrapped the `C_FindObjects` loop in `try/finally` so `C_FindObjectsFinal` always runs (`Pkcs11Session.Objects.cs:341-391`). The cleanup tolerates the rv and logs a warning rather than throwing so a mid-search exception is not masked on the unwind path.
- **Area:** PKCS#11 Conformance
- **Severity:** Critical
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.Objects.cs:361-379`
- **Problem:** `C_FindObjectsInit` → loop `C_FindObjects` → `C_FindObjectsFinal` runs without `try/finally`. If `C_FindObjects` throws mid-loop, `C_FindObjectsFinal` never executes. The session enters "find active" state and the next `C_FindObjectsInit` returns `CKR_OPERATION_ACTIVE`. `FindKeys` / `OpenKey` calls thereafter fail.
- **Proposed action:** Wrap the loop and finalize call in `try/finally`. The `finally` calls `C_FindObjectsFinal` and tolerates the rv (the session may have been finalized).
- **Breaks public API?** No.
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** PKCS#11 v3.1 §11.14.

---

## High

### [BL-005] `[Experimental]` not applied — v3.2 surface locked in pre-1.0

- **Area:** .NET API Design
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11MlDsa.cs:29`; `Pkcs11MlKem.cs`; `Pkcs11Key.cs:452,475` (EncapsulateKey/DecapsulateKey)
- **Problem:** PQC adapters and v3.2 KEM/auth-wrap methods are shipped without `[Experimental("PKCS11NET001")]`. Once 1.0 ships, any change to those signatures is a SemVer-major.
- **Proposed action:** Apply `[Experimental("PKCS11NET001")]` to every v3.2-only public type/method now. Document the policy in a `STABILITY.md`.
- **Breaks public API?** Yes (consumers get a compile-time warning). Must land before 1.0.
- **Raised by:** .NET Engineer A
- **Spec / References:** `System.Diagnostics.CodeAnalysis.ExperimentalAttribute` (.NET 8+).

### [BL-006] Single `net10.0` target locks out .NET 8 LTS consumers

- **Status: Won't Fix (2026-05-15)** — .NET 8 LTS ends November 2026 (~6 months away). The support window doesn't justify the multi-target maintenance burden (extra TFM in CI, `#if NET10_0_OR_GREATER` guards around every BCL ML-DSA/ML-KEM/SLH-DSA adapter, two NuGet builds to validate). New consumers should be on .NET 10 by the time we reach 1.0.
- **Area:** .NET API Design
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj:4`
- **Problem:** `<TargetFramework>net10.0</TargetFramework>` excludes every consumer on .NET 8 LTS (supported until November 2026) and .NET 9. Most of the codebase compiles fine on .NET 8 — only `MLDsa` / `MLKem` / `SlhDsa` BCL types require .NET 10.
- **Proposed action:** Add `net8.0` to `<TargetFrameworks>` and `#if NET10_0_OR_GREATER`-gate the BCL adapters (`Pkcs11MlDsa`, `Pkcs11MlKem`). Verify with `dotnet build` against both TFMs.
- **Breaks public API?** No (additive).
- **Raised by:** .NET Engineer A
- **Spec / References:** [.NET Library Guidance — Cross-platform targeting](https://learn.microsoft.com/dotnet/standard/library-guidance/cross-platform-targeting).

### [BL-007] `AllowInsecure` is unreachable from consumer code; exception messages reference an internal type

- **Status: Resolved (2026-05-20)** — Surfaced `AllowInsecure` (get/set) and `AllowInsecureScope()` as public members on `Pkcs11Workspace`, delegating to the internal session. Updated every consumer-facing message to reference the public name: `InsecureOperationException`'s base message + doc now say `Pkcs11Workspace.AllowInsecure` (and mention `AllowInsecureScope()`), and `MLKemPkcs11`'s extract-and-destroy guard + docs likewise. Also swept the internal `[Obsolete]` compile-time messages across the `Pkcs11Session` partials from `Session.AllowInsecure` to `Pkcs11Workspace.AllowInsecure` for consistency. `AllowInsecureScopeTests` confirms the flag is reachable and toggles via the public workspace surface.
- **Area:** .NET API Design
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:15,161`; `Pkcs11Workspace.cs:46`; `Exceptions/InsecureOperationException.cs:22`; `Pkcs11MlKem.cs:175`
- **Problem:** `AllowInsecure` is `public bool` on the `internal sealed` class `Pkcs11Session`. `Pkcs11Workspace.Session` is `internal`. Consumers cannot reach the flag at all — yet runtime exception messages tell them to set "`Pkcs11Session.AllowInsecure = true`". The library shipped a recovery instruction that points at a type the consumer has never seen.
- **Proposed action:** Surface `AllowInsecure` (and a scoped `WithInsecure(Action)` helper — see BL-008) on `Pkcs11Workspace`. Update every exception message to reference the public name.
- **Breaks public API?** No (additive).
- **Raised by:** .NET Engineer A, Cryptographer B
- **Spec / References:** —

### [BL-008] `AllowInsecure` once set stays on for the session lifetime — no scoped opt-in

- **Status: Resolved (2026-05-20)** — Added `AllowInsecureScope()` on `Pkcs11Session` (and surfaced on `Pkcs11Workspace`) returning an `IDisposable` lease that captures the prior flag value, sets it true through the setter, and restores the captured value on dispose — restoring directly so unwinding never re-logs. Nested scopes restore in LIFO order. The raw setter is retained for long-running cases and now logs a warning on every transition into the insecure state, so the relaxation is auditable. `AllowInsecureScopeTests` covers scope enable/restore, restoring a previously-true value, nested LIFO, and that the gate is bypassed for exactly one operation then re-armed.
- **Area:** Cryptography
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:161-173`
- **Problem:** `AllowInsecure` is a plain setter. Enabling it for one ML-KEM extraction or one RSA-PKCS1 verify leaves every gated mechanism unlocked until the session is closed. There is no way to opt in just for the next call.
- **Proposed action:** Add a disposable lease (`using var _ = session.AllowInsecureScope()`) that resets the flag on dispose. Keep the raw setter for the long-running cases but encourage the scope in docs. Log a warning on every transition to `true`.
- **Breaks public API?** No (additive once BL-007 lands).
- **Raised by:** Cryptographer B
- **Spec / References:** —

### [BL-009] `UnmanagedMemory.Free` does not zero before `Marshal.FreeHGlobal` — IVs/AAD/key material leak in unmanaged heap

- **Status: Resolved (2026-05-19)** — `UnmanagedMemory.Free` now zeroes the buffer (using the tracked size and `CryptographicOperations.ZeroMemory` over a `Span<byte>` constructed from the pointer — guaranteed not to be elided by the JIT) before calling `Marshal.FreeHGlobal`. Extracted as an internal `Zeroize(IntPtr, int)` seam for direct regression testing. Two new tests in `UnmanagedMemoryHarnessTests` pin the behavior: `Zeroize_ClearsSentinelBytes` and `Zeroize_IsNoopOnZeroPointerOrZeroSize`. Mirrors the established `SecureBuffer` / `SecurePin` zeroize pattern.
- **Area:** Cryptography
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/UnmanagedMemory.cs:123-142`
- **Problem:** `Free` removes the tracker entry and calls `Marshal.FreeHGlobal` directly. Every mechanism-param wrapper (`CkmAesGcmParams`, `CkmAesCcmParams`, `CkmRsaPkcsOaepParams`, `CkmEcdh1DeriveParams`, etc.) stores IVs, nonces, AAD, and context bytes in this heap. Same for `ObjectAttribute` value buffers — including `CKA_VALUE` results read back from the token (the ML-KEM extract-and-destroy path at `Pkcs11MlKem.cs:231`). Bytes remain readable until the allocator reuses them.
- **Proposed action:** Inside `Free`, zero the buffer using its tracked size (`unsafe { NativeMemory.Clear((void*)memory, (nuint)size); }`) before calling `FreeHGlobal`. The `_allocations` dictionary already holds the size — change is a few lines.
- **Breaks public API?** No.
- **Raised by:** Cryptographer A, Cryptographer B
- **Spec / References:** Mirrors the established `SecureBuffer` / `SecurePin` zeroize pattern; `CryptographicOperations.ZeroMemory`.

### [BL-010] `Pkcs11MlDsa.MlDsaHashSign` docstring promises SHAKE128/SHAKE256; switch arm is missing

- **Status: Resolved (2026-05-19)** — Docstring now lists exactly the eight hashes the switch implements (SHA224, SHA256, SHA384, SHA512, SHA3-224/256/384/512). Added remarks block explaining why SHAKE128/SHAKE256 are deferred: OASIS PKCS#11 v3.2 defines `CKM_HASH_ML_DSA_SHAKE128/256` as the combined mechanism but does not define a standalone `CKM_SHAKE_128/256` hash CKM (only `_KEY_DERIVATION` variants), so the `hash` field of `CK_HASH_SIGN_ADDITIONAL_CONTEXT` has no spec-defined value for the SHAKE-prehash case. Adding arms would require a token-by-token compat test we don't yet have — track as a follow-up. Regression tests in `Pkcs11MechanismMapTests` pin the 8-hash mapping and assert `NotSupportedException` for SHAKE128 / SHAKE256 / MD5.
- **Area:** Cryptography
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11MechanismMap.cs:102-124`
- **Problem:** XML doc lists SHAKE128/SHAKE256; the `switch` has no arms for them. CKM enum has `CKM_HASH_ML_DSA_SHAKE128/256`. Caller hits `NotSupportedException`.
- **Proposed action:** Either add the two arms (mapping to the SHAKE CKM values) or remove them from the doc. Add arms if intent is to support them per FIPS 204 §5.4.
- **Breaks public API?** No.
- **Raised by:** Cryptographer A
- **Spec / References:** FIPS 204 §5.4; PKCS#11 v3.2 Table 6-35.

### [BL-011] `EncapsulateKey` / `WrapKeyAuthenticated` size-probe throws on `CKR_BUFFER_TOO_SMALL`

- **Status: Resolved (2026-05-20)** — Both length-probe calls in `Pkcs11Session.V32.cs` now treat `CKR_OK` and `CKR_BUFFER_TOO_SMALL` as successful probe outcomes (the token has populated the length output either way per PKCS#11 v3.2 §5.2); only a genuine error code aborts the probe. The real (second) call still goes through `ThrowIfError` unchanged. `DecapsulateKey` is unaffected — its output is an object handle, not a sized buffer, so it makes a single call with no probe. Regression test added (`EncapsulateKeyBufferProbeTests`) once the `ILowLevelPkcs11Library` seam landed: a fake whose probe returns `CKR_BUFFER_TOO_SMALL` drives `EncapsulateKey` and asserts it allocates + makes the real call rather than throwing (verified to fail against the pre-fix code).
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.V32.cs:66,148`
- **Problem:** The two-call buffer-size probe passes the result directly to `ThrowIfError`, treating `CKR_BUFFER_TOO_SMALL` as an error. Spec-compliant tokens are allowed (and many use) `CKR_BUFFER_TOO_SMALL` to signal "I have populated the length output". `Pkcs11Session.Encrypt.cs:60-65` already handles this correctly — this path doesn't.
- **Proposed action:** Mirror the Encrypt pattern: treat `CKR_OK` and `CKR_BUFFER_TOO_SMALL` as successful probe outcomes. Apply to both functions.
- **Breaks public API?** No.
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** PKCS#11 v3.2 §5.2 (buffer-size protocol), §5.18.10.

### [BL-012] Static-link path skips v3.0/v3.2 surface entirely

- **Status: Resolved (2026-05-20)** — The static-link constructor branch (`Delegates(IntPtr.Zero)`) now runs the same v3.0/v3.2 binding logic as the dynamic path. After the `__Internal` `C_GetFunctionList` v2.40 bootstrap, it calls `TryLoadV30Symbols(NativeLibrary.GetMainProgramHandle())`. `GetMainProgramHandle()` (.NET 8+) resolves statically-linked / process-global exports, and the `NativeLibrary.TryGetExport` calls inside `TryLoadV30Symbols` / `TryLoadFromGetInterface` return `false` (no throw, no link-time symbol requirement) for functions a v2.40-only module doesn't provide — so v3.2 modules now bind `EncapsulateKey` / `SessionCancel` / message-AEAD, while v2.40-only modules degrade gracefully. The call is wrapped in try/catch so a platform without process-global symbol resolution stays v2.40-only rather than failing construction. This is cleaner than the originally-proposed `[DllImport("__Internal")] C_GetInterface`, which would impose an AOT link-time unresolved-symbol requirement on v2.40-only static modules. **Not exercised by the test suite** — the suite (and AOT smoke) use the dynamic-load path; the static-link branch needs an actual statically-linked PKCS#11 module to validate end-to-end. Build stays AOT-clean and the AOT smoke binary still runs.
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs:817-830`
- **Problem:** `LoadStaticallyLinked` (iOS / Native AOT) only calls `InitializeWithGetFunctionList()`. The v3.0/v3.2 binding path `TryLoadV30Symbols` requires a non-zero library handle. So a statically-linked v3.2 module silently degrades to v2.40: `IsV32ApiSupported` returns false, `EncapsulateKey`/`SessionCancel`/message-AEAD are all unreachable.
- **Proposed action:** Add a parallel `NativeMethods.C_GetInterface` `[DllImport("__Internal")]` and invoke it on the zero-handle path; if not available, fall back to per-symbol lookup using the static-link mechanism.
- **Breaks public API?** No.
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** PKCS#11 v3.0 §5.4.5.

### [BL-013] `C_GetInterfaceList` unreachable from managed code

- **Status: Resolved (2026-05-21)** — Added `C_GetInterfaceList` + `_Windows` function pointers (`FunctionPointers.cs`), bound them in both loader paths (`TryLoadV30Symbols` raw export and the v3.0 function-list read in `TryLoadFromGetInterface`, which also covers v3.2 tokens since the entry sits at the same offset), and added `Delegates` wrappers + a `LowLevelPkcs11Library.C_GetInterfaceList` two-call wrapper with the Windows `CK_INTERFACE_Windows`→`ToUnified` readback. Surfaced as `Pkcs11Library.GetInterfaces()` returning a new public `Pkcs11Interface` (`Name`, `Flags`, `IsForkSafe`). Returns `CKR_FUNCTION_NOT_SUPPORTED` on v2.40 modules. Test `GetInterfacesTests_Mock` asserts pkcs11-mock's two "PKCS 11" interfaces; full suite 509 pass.
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_FUNCTION_LIST_3_0.cs:87`; no delegate or wrapper exists
- **Problem:** `C_GetInterfaceList` is declared in v3.0/v3.2 function-list structs but has no delegate, no binding, no public wrapper. Consumers cannot enumerate interfaces a token exposes (the only way to discover vendor-specific interface tables).
- **Proposed action:** Add `C_GetInterfaceListDelegate`, bind it in `TryLoadFromGetInterface`, and expose a `LowLevelPkcs11Library.C_GetInterfaceList` wrapper using the standard two-call idiom.
- **Breaks public API?** No (additive on `Pkcs11Library`).
- **Raised by:** PKCS#11 Specialist A
- **Spec / References:** PKCS#11 v3.0 §5.4.4.

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

### [BL-015] `Pkcs11Library.Dispose` calls `C_Finalize` unconditionally even when it didn't initialize

- **Status: Resolved (2026-05-19)** — Added `_weInitialized` field, set only when `C_Initialize` returns `CKR_OK` (left false on `CKR_CRYPTOKI_ALREADY_INITIALIZED`). `Dispose` now gates `C_Finalize` on the flag. Behavioral regression test in `Pkcs11LibraryAlreadyInitializedTests` opens a second `Pkcs11Library` against the same path (the OS loader refcounts the same image so pkcs11-mock returns `CKR_CRYPTOKI_ALREADY_INITIALIZED`), disposes it, and verifies the first instance is still usable. Test fails without the fix (`Pkcs11Exception: CKR_CRYPTOKI_NOT_INITIALIZED`), passes with it.
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Library.cs:107,288`
- **Problem:** `Initialize()` returns early when `CKR_CRYPTOKI_ALREADY_INITIALIZED` is returned (this instance didn't init); `Dispose()` still calls `C_Finalize`. In multi-instance scenarios the second instance tears down the first instance's library state.
- **Proposed action:** Track `_weInitialized` set only when `C_Initialize` returned `CKR_OK`. Gate the `C_Finalize` call on it.
- **Breaks public API?** No.
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** PKCS#11 v3.1 §11.4.

### [BL-016] `Pkcs11Library.Dispose` does not invalidate open sessions before `C_Finalize`

- **Status: Resolved (2026-05-19)** — `LowLevelPkcs11Library` now tracks every `Pkcs11SessionHandle` via a `List<WeakReference<Pkcs11SessionHandle>>` (the weak reference avoids preventing GC of normally-disposed sessions). `Pkcs11SessionHandle` registers itself in its constructor and unregisters in `ReleaseHandle`. `Pkcs11Library.Dispose` now calls `LowLevelPkcs11Library.CloseAllTrackedSessions()` before `C_Finalize`, which iterates the live tracked handles and disposes each (closing them gracefully while the function table is still valid). The class doc spells out the ownership contract: library must outlive every session it produced — disposal-with-open-sessions is a safety net, not the intended flow. Regression tests in `Pkcs11LibrarySessionTrackingTests` cover four cases: opening a session adds to the tracker, disposing the session removes it, disposing the library with an open session drains the tracker and closes the session without throwing, and disposing the library with no live sessions no-ops.
- **Area:** PKCS#11 Conformance
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Library.cs:285-295`; `Internal/SafeHandles/Pkcs11SessionHandle.cs:40-52`
- **Problem:** Disposing the library while sessions are open leaves `Pkcs11SessionHandle` SafeHandles pointing at a library that's about to unload. The SafeHandle finalizer will call `C_CloseSession` on the dead function table.
- **Proposed action:** Track open sessions inside `Pkcs11Library`. In `Dispose`, close (or at least `SetHandleAsInvalid`) every outstanding session before `C_Finalize`. Document the ownership contract: library must outlive every session.
- **Breaks public API?** No.
- **Raised by:** PKCS#11 Specialist B
- **Spec / References:** —

### [BL-017] `UnwrapKey` doesn't enforce `CKA_SENSITIVE=true` / `CKA_EXTRACTABLE=false` on the result

- **Area:** Cryptography
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.Keys.cs:148-199`; `Pkcs11Key.cs:427-442`
- **Problem:** Both unwrap surfaces accept a caller-supplied template with no library-side merging of secure defaults. A caller can unwrap an encrypted key blob into an extractable, non-sensitive object on the token — silently downgrading the security posture established by `PrivateKeyTemplateBuilder` / `SecretKeyTemplateBuilder`.
- **Proposed action:** When the unwrap target template lacks `CKA_SENSITIVE` / `CKA_EXTRACTABLE`, default them to `true`/`false` respectively. To opt out, the caller can pass them explicitly with `AllowInsecure = true`.
- **Breaks public API?** Behaviour change but not signature change — defensible pre-1.0.
- **Raised by:** Cryptographer B
- **Spec / References:** PKCS#11 v3.1 §11.14.

### [BL-018] `CKM_AES_CBC`, `CKM_AES_CTR`, `CKM_RC4`, `CKM_RC2_*` not in `GuardMechanism`

- **Status: Resolved (2026-05-20)** — Added `GuardMechanism` arms grouped by class: unauthenticated AES modes (`CKM_AES_CBC` raw, `CKM_AES_CTR`, `CKM_AES_CTS`, `CKM_AES_OFB`, `CKM_AES_CFB{1,8,64,128}` — `CKM_AES_CBC_PAD` stays permitted as the documented legacy fallback); broken/legacy ciphers (`CKM_RC4*`, `CKM_RC2_*`, `CKM_SEED_*`); broken/deprecated hashes (`CKM_MD2*`, `CKM_RIPEMD128*`/`CKM_RIPEMD160*`); SHA-1 in signature/MAC contexts (`CKM_SHA_1_HMAC*`, `CKM_ECDSA_SHA1`); and raw `CKM_RSA_X_509`. Each throws `InsecureOperationException` with a specific remediation; all are opt-out via `AllowInsecure`. Two tests that deliberately round-trip raw AES-CBC now use `AllowInsecureScope()`/`AllowInsecure=true`. Added 13 gate-coverage `[InlineData]` cases. 582 tests pass. Out of scope (not named in this item, left ungated): the other 64-bit-block legacy ciphers `CKM_CAST*`, `CKM_RC5_*`, `CKM_BLOWFISH_*`, `CKM_SKIPJACK_*` — file a follow-up if a wider sweep is wanted.
- **Area:** Cryptography
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:516-563`
- **Problem:** `GuardMechanism` blocks `CKM_AES_ECB` but silently allows raw `CKM_AES_CBC` (vulnerable to padding-oracle), `CKM_AES_CTR` (unauthenticated), `CKM_RC4`, `CKM_RC2_*`, `CKM_SEED_*`, `CKM_MD2*`, `CKM_RIPEMD*`, `CKM_SHA_1_HMAC`, `CKM_ECDSA_SHA1`, `CKM_RSA_X_509`. A caller writing legacy interop sees no warning.
- **Proposed action:** Add the missing arms grouped by class (unauthenticated-modes, broken-ciphers, broken-hashes). Priority order: RC4 / MD2 (critical), AES-CBC (padding-oracle), ECDSA-SHA1 / SHA1-HMAC (deprecated), RSA-X_509 / RC2 / SEED / RIPEMD.
- **Breaks public API?** No (additive gate; consumers opt in via `AllowInsecure`).
- **Raised by:** Cryptographer A, Cryptographer B
- **Spec / References:** NIST SP 800-131A Rev. 2; project CLAUDE.md "Avoid insecure defaults".

### [BL-019] `GetSlotList`/`GetMechanismList` return concrete `List<T>` — exposes implementation

- **Status: Resolved (2026-05-19)** — Both methods now return `IReadOnlyList<T>`. `GetMechanismList` returns the underlying `CKM[]` directly (arrays satisfy `IReadOnlyList<T>`, no allocator churn from a wrapper). `GetSlotList` keeps its `List<Pkcs11Slot>` accumulator but exposes it via the read-only interface. The binary-compat change must land before 1.0; this is that landing. Internal callers (the `MockBackendFixture`, `SoftHsmBackendFixture`, several tests) all use indexing, foreach, or `new HashSet<CKM>(...)` patterns — none rely on the `List<T>` API surface, so no consumer churn.
- **Area:** .NET API Design
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Library.cs:149`; `Pkcs11Slot.cs:92`
- **Problem:** Returning mutable `List<T>` is a binary-compat commitment to that type and lets callers mutate library-owned data. `Pkcs11Workspace.FindKeys` already returns `IReadOnlyList<T>`.
- **Proposed action:** Change both return types to `IReadOnlyList<T>` before 1.0.
- **Breaks public API?** Yes. Must land before 1.0.
- **Raised by:** .NET Engineer A
- **Spec / References:** [Framework Design Guidelines — Collection types](https://learn.microsoft.com/dotnet/standard/design-guidelines/guidelines-for-collections).

### [BL-020] `WaitForSlotEvent` parameter name typo: `eventOccured`

- **Status: Resolved (2026-05-19)** — Parameter renamed to `eventOccurred` along with the XML doc references. No external callers existed (only the declaration, the two assignments inside the method body, and the `<param>` / `<paramref>` doc tags), so no consumer churn.
- **Area:** .NET API Design
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Library.cs:190`
- **Problem:** `out bool eventOccured` is misspelled. Parameter names are public API (named arguments, generated docs). Fixing after 1.0 is source-breaking for any caller using named arguments.
- **Proposed action:** Rename to `eventOccurred`.
- **Breaks public API?** Yes (parameter-name rename is source-breaking for named arguments). Must land before 1.0.
- **Raised by:** .NET Engineer A
- **Spec / References:** —

### [BL-021] High-level secure key-generation helpers exist only on `internal Pkcs11Session`

- **Area:** .NET API Design
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.Keys.cs:211,252,307`
- **Problem:** `GenerateAesKey`, `GenerateRsaKeyPair`, `GenerateEcKeyPair` are `public` on the `internal` `Pkcs11Session`. From a consumer's standpoint, the `Pkcs11Workspace` façade exposes only the generic `GenerateKey(Mechanism, ObjectTemplate)` overloads — defeating the "secure-by-default" intent of the helpers. The `EcCurve` enum is even cross-referenced in XML doc to a non-existent `Pkcs11Workspace.GenerateEcKeyPair`.
- **Proposed action:** Add forwarding methods on `Pkcs11Workspace`. Match the helper signatures exactly so the XML doc cref resolves.
- **Breaks public API?** No (additive). Land before 1.0 to set the API shape.
- **Raised by:** .NET Engineer A
- **Spec / References:** —

### [BL-022] ~85 raw `CK_*` structs in `Native/` and `Native/RawMechanismParams/` are `public`

- **Status: Resolved (2026-05-19)** — All 94 `public partial struct CK_*` declarations under `Native/` and `Native/RawMechanismParams/` demoted to `internal partial struct`. No public API surface referenced these types (verified by grep): every cross-namespace consumer was either an `internal` constructor (`LibraryInfo`, `MechanismInfo`, `SlotInfo`, `TokenInfo`, `SessionInfo`, `ObjectAttribute`), an `internal` field (`Mechanism._ckMechanism`, `ObjectAttribute._ckAttribute`), or a local variable inside a method. `CK_VERSION` was demoted alongside the rest — `LibraryInfo` already exposes the version as a string property, so the raw struct doesn't need to be public. Source generator already emitted siblings as `internal partial struct CK_X_Windows`, so the access modifiers are now consistent across the unified and Windows pairs. All 565 tests still pass (the test assembly reaches `Native/` via `[InternalsVisibleTo]`).
- **Area:** .NET API Design
- **Severity:** High
- **Effort:** L
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_MECHANISM.cs:10`; `Native/CK_ATTRIBUTE.cs:6`; 80+ similar
- **Problem:** Every native interop struct (`CK_MECHANISM`, `CK_GCM_PARAMS`, `CK_RSA_PKCS_OAEP_PARAMS`, …) is `public`. These are unmanaged-layout types with raw `IntPtr` and `NativeCULong` fields. Marking them public commits the library to their current layout and marshalling strategy forever. The high-level `Ckm*Params` wrappers in `MechanismParams/` are the intended public surface.
- **Proposed action:** Mark every type under `Native/` and `Native/RawMechanismParams/` as `internal`. Spot-keep `CK_VERSION` as `public` only if version-comparison is a documented consumer use case (and prefer a string property on `LibraryInfo` instead).
- **Breaks public API?** Yes. Must land before 1.0.
- **Raised by:** .NET Engineer A, .NET Engineer B
- **Spec / References:** —

### [BL-023] `IMechanismParams.ToMarshalableStructure()` returns `object` — AOT/trim hostile and breaks abstraction

- **Status: Resolved (2026-05-20)** — Replaced the public `IMechanismParams` interface with a public abstract base class `MechanismParameters` (named to avoid colliding with the `MechanismParams` namespace) whose marshalling method `internal abstract object ToMarshalableStructure()` is no longer on the public surface. The 26 `Ckm*Params` wrappers now derive from it (`internal override` the marshalling method, `public override void Dispose()`); the public `Mechanism(type, MechanismParameters)` constructors and `Pkcs11Key.MessageEncrypt/MessageDecrypt` take the base class, so `new Mechanism(CKM.X, new CkmYParams(...))` is unchanged. Because the abstract marshalling member is `internal`, consumers in other assemblies cannot subclass `MechanismParameters` — custom/vendor parameters go through the existing `Mechanism(type, byte[])` ctor, which closes the "no type-system constraint enforces the blittable contract" hole. `Mechanism.ToMarshalableStructure()` (same `object`-returning leak, internal-only callers) was also demoted to `internal`. The AOT/trim concern was already mitigated by the packed-struct source generator: mechanism params marshal through `UnmanagedMemory.SizeOf`/`Write` → `PackedDispatch` (JIT-folded `typeof` chain), never `Marshal.StructureToPtr` reflection, so no `[RequiresDynamicCode]` annotation is needed and the assembly stays AOT-clean. 590 tests pass.
- **Area:** .NET API Design
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/MechanismParams/IMechanismParams.cs:11`
- **Problem:** The interface is `public` and its only method returns a boxed `object` that internally feeds `Marshal.StructureToPtr(object, …)` (reflection-based, `[RequiresDynamicCode]` in .NET 8+). No type-system constraint enforces the "must be a blittable struct" contract. Plus the leaks of `Native/` types into the contract.
- **Proposed action:** Mark `IMechanismParams` `internal`. If consumer-defined mechanisms are a real use case, design a separate `byte[]`-based extension point on `Mechanism`. Annotate the affected call sites with `[RequiresDynamicCode]`/`[RequiresUnreferencedCode]` until a trimming-safe path exists.
- **Breaks public API?** Yes. Must land before 1.0.
- **Raised by:** .NET Engineer A, .NET Engineer B
- **Spec / References:** [.NET AOT compatibility](https://learn.microsoft.com/dotnet/core/deploying/native-aot/).

### [BL-024] `CK_MECHANISM.CreateMechanism` is `public static` and allocates unmanaged memory invisibly

- **Status: Resolved (2026-05-20)** — The `CK_MECHANISM` struct itself was already demoted to `internal` by BL-022; the remaining gap was the eight `CreateMechanism` factories still declared `public static` (misleading — they were already unreachable externally through the internal struct). Demoted all eight to `internal static`, so no public escape hatch advertises an allocate-without-dispose path. All mechanism construction goes through the `IDisposable` `Mechanism` class. The lone external caller is a test, which reaches the internal members via `[InternalsVisibleTo]`. Struct fields stay `public` — the same harmless public-fields-on-internal-struct pattern BL-022 left across the other `CK_*` types. 590 tests pass.
- **Area:** .NET API Design / P/Invoke
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/CK_MECHANISM.cs:32-127`
- **Problem:** Eight `CreateMechanism` factories allocate via `UnmanagedMemory.Allocate` and store the pointer in the struct's `Parameter` field. Nothing in the signatures communicates that `Parameter` must be freed. Callers using `CK_MECHANISM` directly leak. The `Mechanism` class wraps this correctly, but the public escape hatch defeats it.
- **Proposed action:** Make `CK_MECHANISM` and all factory methods `internal`. All consumer-facing mechanism construction goes through `Mechanism` (already `IDisposable`).
- **Breaks public API?** Yes (subset of BL-022). Must land before 1.0.
- **Raised by:** .NET Engineer B
- **Spec / References:** —

### [BL-025] Function dispatch via `Marshal.GetDelegateForFunctionPointer<T>` blocks Native AOT

- **Status: Resolved (2026-05-19)** — Empirical baseline (captured before any change at `docs/superpowers/notes/2026-05-19-bl025-aot-baseline.txt`) showed the AOT analyzer does NOT flag `Marshal.GetDelegateForFunctionPointer<TDelegate>` when `TDelegate` carries `[UnmanagedFunctionPointer]` in .NET 10 — the runtime can pre-generate the marshalling thunk when the delegate signature is statically known. The premise of this BL was partly incorrect on that point. All 21 actual analyzer warnings came from reflection-based packed-struct dispatch in `Pkcs11Marshal.cs` / `UnmanagedMemory.cs` (`SiblingCache<T>` lookup, `Marshal.PtrToStructure(IntPtr, Type)`, `Marshal.SizeOf(Type)`, `Assembly.GetType(string)`, unannotated `T` on generic Marshal calls). Fix: extended `PackedStructsGenerator` to emit a `PackedDispatch.g.cs` with a `typeof(T) == typeof(...)` chain (one branch per `[PackedForPkcs11]` type — 99 branches) plus per-type `_WindowsSiblings` helpers, all using `Marshal.SizeOf<T>` / `Marshal.PtrToStructure<T>` / `Marshal.StructureToPtr<T>` with concrete sibling types. The JIT/AOT compiler folds the typeof comparisons per generic instantiation, so callers pay one direct call — no reflection. Deleted `Pkcs11Marshal.SiblingCache<T>` and the `Type`-accepting `UnmanagedMemory` overloads. Migrated all callsites to generic forms. Enabled `<IsAotCompatible>true</IsAotCompatible>` + `<EnableAotAnalyzer>` + `<EnableTrimAnalyzer>` permanently; build is now zero-warning. Added `tests/AotSmoke/` project that publishes with `PublishAot=true` and prints the cryptoki manufacturer when run against pkcs11-mock (verified end-to-end). Delegate→fptr migration is filed separately as BL-051 (the empirical evidence says it isn't AOT-mandatory; it's a future runtime-cost improvement). See `docs/superpowers/plans/2026-05-19-pkcs11-function-pointer-dispatch-aot.md` for the design preserved for that follow-up.
- **Area:** P/Invoke
- **Severity:** High
- **Effort:** L
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs:884-888,1061-1110,932-1010`; `Native/UnmanagedMemory.cs:196` (`Marshal.PtrToStructure(IntPtr, Type)`)
- **Problem:** The entire dispatch table is built with generic and non-generic `Marshal.GetDelegateForFunctionPointer` and `Marshal.PtrToStructure(IntPtr, Type)` — both are `[RequiresDynamicCode]` in .NET 7+. No `[RequiresDynamicCode]` annotation is present on the assembly or any callsite; AOT consumers get no warning.
- **Proposed action:** Short-term: annotate the public surface (or at least `Pkcs11Library` and `LowLevelPkcs11Library`) with `[RequiresDynamicCode("Uses runtime delegate creation for PKCS#11 dispatch")]`. Long-term: replace delegates with `delegate* unmanaged[Cdecl]<…>` function pointers and `[LibraryImport]` source generation, which are fully AOT-compatible. Replace every `Marshal.PtrToStructure(ptr, Type)` with the generic `Marshal.PtrToStructure<T>(ptr)`.
- **Breaks public API?** No (annotations); long-term refactor is internal-only.
- **Raised by:** .NET Engineer B
- **Spec / References:** [Native AOT warnings](https://learn.microsoft.com/dotnet/core/deploying/native-aot/warnings/il2026).

### [BL-026] `CK_SSL3_KEY_MAT_PARAMS.IsExport` missing `[MarshalAs(UnmanagedType.U1)]`

- **Area:** P/Invoke
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/RawMechanismParams/CK_SSL3_KEY_MAT_PARAMS.cs:30`
- **Problem:** Default `bool` marshalling on a `[StructLayout(Sequential)]` struct is 4-byte `BOOL`, not 1-byte `CK_BBOOL`. Every other `bool` in the codebase carries `[MarshalAs(UnmanagedType.U1)]`. This struct alone has the wrong size on every platform.
- **Proposed action:** Add `[MarshalAs(UnmanagedType.U1)]` to `IsExport`. Add a unit test that asserts `Marshal.SizeOf<CK_SSL3_KEY_MAT_PARAMS>()` against the expected size on each platform.
- **Breaks public API?** No (subsumed by BL-022 making the type internal).
- **Raised by:** .NET Engineer B
- **Spec / References:** PKCS#11 `CK_BBOOL = CK_BYTE`.

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

### [BL-029] No automated versioning — `<Version>0.1.0</Version>` is a literal

- **Status: Resolved (2026-05-20)** — Done differently from the proposed MinVer approach: `.github/workflows/publish.yml` triggers on `v*` tags, checks out with `fetch-depth: 0`, derives `VERSION=${GITHUB_REF_NAME#v}` from the tag, and packs with `/p:Version=$VERSION`. Tagged releases now pack the tag's version instead of a hardcoded literal. The csproj keeps `<Version>0.0.0</Version>` as the local/untagged-build default (overridden on release). MinVer was not adopted — the CI-injected version is sufficient and avoids the extra build-time dependency; revisit MinVer only if meaningful versions for local/dev builds become a requirement.
- **Area:** Release Eng
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj:17`
- **Problem:** CI pack triggers on `v*` tags but does not derive the version from the tag. Every tagged release packs `0.1.0` unless the file is hand-edited first.
- **Proposed action:** Add `<PackageReference Include="MinVer" PrivateAssets="all" />`, remove `<Version>`, add `<MinVerTagPrefix>v</MinVerTagPrefix>`.
- **Breaks public API?** No.
- **Raised by:** QA C
- **Spec / References:** [MinVer](https://github.com/adamralph/minver).

### [BL-030] CI `pack` job uploads artifacts but never publishes to NuGet.org

- **Status: Resolved (2026-05-20)** — A dedicated `.github/workflows/publish.yml` (triggered on `v*` tags) now builds, tests, packs the tag-derived version, and runs `dotnet nuget push ./artifacts/*.nupkg --source https://api.nuget.org/v3/index.json`. Goes beyond the proposed action: uses NuGet **OIDC trusted publishing** (`nuget/login` + `id-token: write`) instead of a long-lived `NUGET_API_KEY` secret, and attaches build provenance via `actions/attest-build-provenance`. `dotnet nuget push *.nupkg` auto-detects and pushes the adjacent `.snupkg` symbol package when symbol generation is enabled.
- **Area:** Release Eng
- **Severity:** High
- **Effort:** S
- **Location:** `.github/workflows/ci.yml:60-83`
- **Problem:** The `pack` job uploads to GitHub Actions artifacts only. There is no `dotnet nuget push` step. Tag pushes do not actually release.
- **Proposed action:** Add a publish step guarded by `startsWith(github.ref, 'refs/tags/v')` using a `NUGET_API_KEY` repository secret. Push both `.nupkg` and `.snupkg`.
- **Breaks public API?** No.
- **Raised by:** QA C
- **Spec / References:** —

### [BL-031] `TreatWarningsAsErrors` absent — analyzer warnings are advisory

- **Status: Resolved (2026-05-20)** — Added repo-root `Directory.Build.props` with `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>` (applies to the library, test, and generator projects). Dropped the project-wide `<NoWarn>$(NoWarn);CS1591</NoWarn>` suppression and addressed the 22 undocumented public members per-callsite with `<summary>` doc comments (the three AEAD adapters' `NonceByteSizes`/`TagByteSizes`/`Encrypt`/`Decrypt`, `CKMExtensions`, and `ObjectAttribute`'s `GetValueAs*` + `Dispose`). The whole solution builds clean with warnings-as-errors; 590 tests pass. The lone remaining build warning is the local-only SourceLink "repository has no remote" message — an MSBuild *task* warning (no warning code), which `TreatWarningsAsErrors` (a C# compiler property) does not elevate, and which never fires in CI where a remote exists. `Meziantou.Analyzer` was considered but not added (it would surface a fresh wave of diagnostics that would immediately become errors — out of scope here).
- **Area:** Release Eng
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj`
- **Problem:** Net analyzers are on but warnings don't fail the build. `<NoWarn>CS1591</NoWarn>` blankets missing-doc warnings instead of `#pragma`-suppressing them at the source.
- **Proposed action:** Add `Directory.Build.props` at repo root with `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`. Drop the project-wide CS1591 suppression and address per-callsite (paired with BL-051). Consider `Meziantou.Analyzer`.
- **Breaks public API?** No.
- **Raised by:** QA C
- **Spec / References:** —

### [BL-032] PQC adapters (`Pkcs11MlDsa`, `Pkcs11MlKem`) have zero tests

- **Area:** QA
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11MlDsa.cs`; `Pkcs11MlKem.cs`; no test files
- **Problem:** Public v3.2 BCL adapters ship with no tests — not even null-guard ctor tests, let alone the round-trip that would have caught BL-002.
- **Proposed action:** Add `MlDsaPkcs11Tests.cs` and `MlKemPkcs11Tests.cs` in `Algorithms/`. Mock-only ctor null tests run today; round-trip tests gate on a future `SoftHsmSupportsMlDsa` capability flag.
- **Breaks public API?** No.
- **Raised by:** QA A
- **Spec / References:** —

### [BL-033] No KATs for any AEAD / asymmetric mechanism

- **Area:** QA
- **Severity:** High
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Digest/DigestSha2Tests.cs:15-26` is the only KAT in the suite
- **Problem:** Every AEAD/asymmetric test uses random session keys and round-trip equality. A bug that mishandles IVs, swaps AAD, or selects the wrong parameter set would pass all existing tests.
- **Proposed action:** Add at least one NIST CAVP or RFC vector per primary mechanism: AES-GCM (SP 800-38D), AES-CCM (RFC 3610), ChaCha20-Poly1305 (RFC 8439), HMAC (FIPS 198-1), Ed25519 (RFC 8032 §5.1).
- **Breaks public API?** No.
- **Raised by:** QA B
- **Spec / References:** Spec citations above.

### [BL-034] No wrong-AAD negative test for any AEAD

- **Area:** QA
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Decrypt/DecryptAesGcmTests.cs:95,128`; `Algorithms/AesCcmPkcs11Tests.cs`; `Algorithms/ChaCha20Poly1305Pkcs11Tests.cs`
- **Problem:** Tampered-tag and wrong-IV are tested; mismatched-AAD is not. A bug that ignores AAD in `CK_GCM_PARAMS` would silently pass.
- **Proposed action:** Add one `Decrypt_WrongAad_Throws` test per AEAD: encrypt with AAD, decrypt with different AAD, assert failure.
- **Breaks public API?** No.
- **Raised by:** QA B
- **Spec / References:** NIST SP 800-38D §7.

### [BL-035] RSA-OAEP and ECDH-with-KDF are gated off — never run in CI

- **Area:** QA
- **Severity:** High
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Encrypt/EncryptRsaTests.cs:111`; `HighLevel/Decrypt/DecryptRsaTests.cs:124`; `HighLevel/Derive/DeriveSharedSecretEcdhTests.cs:81`
- **Problem:** Both primary recommended paths are skipped by `SoftHsmSupportsOaepSha256 = false` and `SoftHsmSupportsEcdh1WithKdf = false`. SoftHSM 2.7 does support OAEP-SHA1 and ECDH with `CKD_NULL`; tests using those variants would exercise the marshalling paths in CI.
- **Proposed action:** Add `EncryptDecrypt_OaepSha1_RoundTrips` (gated on `SoftHsmAvailable` only) and `Ecdh_NullKdf_BothPartiesDeriveSameSecret`. Keep the SHA-256 / SHA-256-KDF tests flagged for when SoftHSM is upgraded.
- **Breaks public API?** No.
- **Raised by:** QA B
- **Spec / References:** —

### [BL-036] macOS and ARM64 absent from CI — `CK_ULONG` / packing regressions invisible

- **Area:** QA / Release Eng
- **Severity:** High
- **Effort:** M
- **Location:** `.github/workflows/ci.yml:16` (matrix: `[ubuntu-latest, windows-latest]` only)
- **Problem:** CI runs only Linux x64 and Windows x64. The csproj declares `osx-x64;osx-arm64;linux-arm64` as RIDs and the fixture has macOS-specific code. None of it is exercised. Apple Silicon is a common developer workstation. ARM64 Linux runners are now available. The `[PlatformSpecificPack]` bug (BL-001) is currently masked partly because Windows tests don't actually run due to a `continue-on-error` choco install (BL-049).
- **Proposed action:** Add `macos-latest` and `ubuntu-24.04-arm` (or `macos-13-arm64` and `ubuntu-22.04-arm`) to the matrix.
- **Breaks public API?** No.
- **Raised by:** QA A, QA B, QA C
- **Spec / References:** —

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

### [BL-038] No cross-library signature-verification test

- **Area:** QA
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Algorithms/RSAPkcs11Tests.cs:42-45`; `ECDsaPkcs11Tests.cs:35-38`
- **Problem:** All signing tests verify with the same `*Pkcs11` instance. A DER-encoding bug in `ExportParameters` or wrong PSS salt would pass.
- **Proposed action:** Export public key via `ExportParameters`, import into BCL `RSA.Create()` / `ECDsa.Create()`, cross-verify the PKCS#11-produced signature.
- **Raised by:** QA A

### [BL-039] EC curves beyond P-256 are untested; HMAC-SHA-384/512 likewise

- **Status: Resolved (2026-05-20)** — Promoted the three test classes to `[ConditionalTheory]` over the curve / hash set: `SignEcdsaTests` (P-256/384/521 with expected r||s lengths 64/96/132), `ECDsaPkcs11Tests` (SignVerify with the curve-matched hash, and ExportParameters asserting the right named-curve OID per curve), and `HMACPkcs11Tests` (SHA-256/384/512 with 32/48/64-byte MACs). Added a shared `TestKeys.GenerateEcKeyPair(session, ecParams)` + `EcParams(curve)` helper; `GenerateEcP256KeyPair` now delegates to it. The new SHA-384/512 HMAC cases surfaced that SoftHSM enforces a per-mechanism minimum key size (`CKR_KEY_SIZE_RANGE`), so the test now sizes the generic-secret key to the digest length. All curves/hashes verified against the live SoftHSM backend (`ECDsaPkcs11.ExportParameters` resolves P-384/521 via `Pkcs11PublicKeyView.ResolveNamedCurve`). 598 tests pass (+8).
- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `Algorithms/ECDsaPkcs11Tests.cs:74`; `HighLevel/Sign/SignEcdsaTests.cs:19`; `Algorithms/HMACPkcs11Tests.cs:39`
- **Problem:** P-384 / P-521 EC and SHA-384/SHA-512 HMAC differ only in the CKM/curve selection and exercise different code paths in `ExportParameters` and the mechanism map. SoftHSM 2.7 supports all.
- **Proposed action:** Promote both test classes to `[ConditionalTheory]` over the curve / hash set.
- **Raised by:** QA A, QA B

### [BL-040] Smoke test assertions are weak (non-empty string only)

- **Area:** QA
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/SmokeTests.cs:14-16`
- **Problem:** `GetInfo()` only checks non-empty strings. Version-parsing regressions would not be caught.
- **Proposed action:** Assert `CryptokiVersion` matches `\d+\.\d+`, major ≥ 2; assert `SlotCount > 0`.
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

### [BL-043] `LoginUser`, `Pkcs11MlKem` extract-and-destroy paths don't zero transient buffers / swallow destroy errors

- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs:434-446`; `Pkcs11MlKem.cs:241-246`
- **Problem:** `LoginUser` zeroes `pinTmp` but not `usernameBytes` — inconsistent with the project's documented hygiene. `Pkcs11MlKem.TryDestroy` silently swallows `Pkcs11Exception`; if `C_DestroyObject` fails the extractable shared-secret object lingers on-token.
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

- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/RSAPkcs11.cs:238-241`; `Internal/Pkcs11Session.cs:516-563`
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

### [BL-049] Windows SoftHSM install masked by `continue-on-error: true` — Windows integration tests silently skip

- **Status: Resolved (2026-05-20)** — The literal cause is already gone: `ci.yml` was refactored and no longer runs `choco install softhsm` (with or without `continue-on-error`). Two of the proposed actions conflict with deliberate design and were *not* taken: the `SoftHsmBackendFixture` intentionally refuses to auto-discover a system-installed SoftHSM (distro/choco versions are unpredictable; prior bugs traced to mismatched installs), and the vendored `BuildSoftHsmV2` target is Linux/macOS-only. On Windows the marshalling / Windows struct-packing path (the BL-001 concern) is exercised by the **pkcs11-mock** backend, which *does* build and run on Windows; the real-crypto SoftHSM suite is Linux/macOS-only by design and skips on Windows intentionally. The surviving masking risk is platform-flipped — if the **Linux** vendored build silently fails to place `libsofthsm2.so`, every `[ConditionalFact(SoftHsmAvailable)]` skips and CI stays green. Closed that with a guard test `SoftHsmAvailabilityTests.SoftHsm_IsAvailable_OnCiBuildPlatforms` that **fails** (not skips) in CI on Linux/macOS when SoftHSM is unavailable (verified non-vacuous: it fails when the built lib is removed), plus a `ci.yml` "Report SoftHSM build (Linux)" step that prints `softhsm2-util --version` for an auditable log. 599 tests pass.
- **Follow-up (2026-05-20):** the "larger separate effort" of building SoftHSM2 on Windows (so the real-crypto suite runs on the Windows leg too) was started — added `build/build-softhsmv2.ps1` (CMake + vcpkg OpenSSL, per `vendor/softhsmv2/CMAKE-WIN-NOTES.md`), wired the `BuildSoftHsmV2` target to run on Windows (mirroring `BuildPkcs11Mock`), and taught `SoftHsmBackendFixture` to discover the Windows `libsofthsm2.dll` / `softhsm2-util.exe`. **Unvalidated** — the Windows native build can't be tested in the Linux dev environment; it needs a Windows CI run to confirm (generator/vcpkg-triplet/DLL-name/OpenSSL-runtime-DLL details may need iteration). Until confirmed, the guard test still exempts Windows; once green, drop that exemption so a silent Windows skip also fails.
- **Area:** Release Eng
- **Severity:** Medium
- **Effort:** S
- **Location:** `.github/workflows/ci.yml:42`
- **Problem:** `choco install -y softhsm` has `continue-on-error: true`. If choco fails, every `[ConditionalFact(SoftHsmAvailable)]` test silently skips on Windows and CI reports green. This is what masks BL-001 (Windows struct-packing bug) today.
- **Proposed action:** Remove the `continue-on-error`. Either fix the choco install or build SoftHSM from the vendored submodule on Windows. Print the SoftHSM version after install for an auditable log.
- **Raised by:** QA A, QA C

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

### [BL-052] `AttributeValueException` is `[Serializable]` (obsolete) and unsealed

- **Status: Resolved (2026-05-20)** — Removed `[Serializable]`, the `protected SerializationInfo` constructor, `GetObjectData`, and the now-unused `using System.Runtime.Serialization;` (these had been stop-gap `[Obsolete(SYSLIB0051)]`-marked in an earlier pass; full removal supersedes that). Marked the class `sealed`, matching every other concrete exception in the hierarchy. No subclasses and no callers of the serialization members existed (verified by grep), so no consumer churn. 599 tests pass.
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Exceptions/AttributeValueException.cs:9,96`
- **Problem:** Implements obsolete `ISerializable` pattern (BinaryFormatter removed). Unsealed unlike every other concrete exception in the hierarchy. Both inconsistencies invite confusion.
- **Proposed action:** Remove `[Serializable]`, the `SerializationInfo` ctor, `GetObjectData`. Mark `sealed`.
- **Raised by:** .NET Engineer A

### [BL-053] Enum naming convention (`CKA_FOO`) deliberately deviates from .NET style — undocumented

- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** L (if PascalCase aliasing chosen)
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKA.cs`; `CKM.cs`; `CKR.cs`; …
- **Problem:** All-caps enum names + all-caps members violate .NET Framework Design Guidelines. Likely a deliberate choice for spec correspondence but undocumented; appears in every IntelliSense pop-up.
- **Proposed action:** Document the deliberate deviation in a project-style note. Optionally add PascalCase aliases marked `[EditorBrowsable(EditorBrowsableState.Advanced)]`. Decide before 1.0 — switching after is a SemVer-major change.
- **Raised by:** .NET Engineer A

### [BL-060] Migrate cryptoki dispatch from `[UnmanagedFunctionPointer]` delegates to `delegate* unmanaged[Cdecl]` function pointers

- **Status: Resolved (2026-05-19) — completed in full** — All cryptoki functions are now fptr-dispatched. The `*_INFO` structs (`CK_INFO`, `CK_SLOT_INFO`, `CK_TOKEN_INFO`) were made blittable via `[InlineArray]` (`CkChar16`/`CkChar32`/`CkChar64` buffer types) and `CK_VERSION` was converted to two plain `byte` fields; the `PackedStructsGenerator` then regenerated fully-blittable `_Windows` siblings with no `[MarshalAs]`. With blittable layouts confirmed, `C_GetInfo`, `C_GetSlotInfo`, and `C_GetTokenInfo` (unified + `_Windows` variants) migrated to `delegate* unmanaged[Cdecl]<CK_X*, NativeCULong>` fptrs using the same `fixed (CK_X* p = &info)` pattern as the other ~129 functions. Zero `[UnmanagedFunctionPointer]` delegates remain. Design: `docs/superpowers/plans/2026-05-19-pkcs11-info-structs-blittable.md`. All 564 tests pass; build stays zero-AOT-warning; AOT smoke binary confirmed (manufacturer/cryptoki round-trips through native dispatch). Landed in commits `0c9565f` → `837bd7c` (phases 1–8) + subsequent blittable-`*_INFO` phases.
- **Area:** P/Invoke
- **Severity:** Medium
- **Effort:** L
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/Delegates.cs` (~135 delegate types + matching fields + populators)
- **Problem:** The PKCS#11 dispatch table is currently built from ~135 `[UnmanagedFunctionPointer(CallingConvention.Cdecl)]` delegate types bound via `Marshal.GetDelegateForFunctionPointer<T>(IntPtr)`. **This is NOT an AOT-correctness issue in .NET 10** (confirmed by analyzer baseline at `docs/superpowers/notes/2026-05-19-bl025-aot-baseline.txt` — zero IL3050/IL2026 from this path). However, function pointers would still deliver: (1) smaller AOT binary (no per-delegate marshalling-stub IL emission), (2) zero per-call delegate-thunk synthesis cost at first call, (3) no `Delegate.Invoke` indirection on the hot path, (4) eliminated `[UnmanagedFunctionPointer]` boilerplate, (5) uniform dispatch style — the codebase already uses `delegate*` elsewhere.
- **Proposed action:** Migrate per `docs/superpowers/plans/2026-05-19-pkcs11-function-pointer-dispatch-aot.md` (Tasks 2–10 of the original BL-025 plan, now preserved here as the design for this follow-up). The plan covers introducing a `FunctionPointers` class with `delegate* unmanaged[Cdecl]<...>` fields, migrating function groups in coherent waves with per-call marshalling shims (`fixed` for arrays/ref structs, bool↔byte conversions), and deleting the legacy `delegate` types. Each task ends with `dotnet test` green — cryptographic correctness must not regress.
- **Breaks public API?** No (internal-only refactor — `LowLevelPkcs11Library` public method signatures unchanged by design).
- **Raised by:** Derived from BL-025 closure.
- **Spec / References:** [Function pointers (C# language spec)](https://learn.microsoft.com/dotnet/csharp/language-reference/proposals/csharp-9.0/function-pointers); the existing `docs/superpowers/plans/2026-05-19-pkcs11-function-pointer-dispatch-aot.md` (13-task plan, Tasks 2–10 apply here).

### [BL-062] No public way to delete a token object (create-without-delete)

- **Status: Resolved (2026-05-20)** — Added public `Pkcs11Key.Delete()`, which calls the internal `Pkcs11Session.DestroyObject` (`C_DestroyObject`) on each valid handle — both halves of a key pair. Doc is explicit about the distinction from `Dispose` (release the wrapper, leave the token object) vs `Delete` (erase the key material), and notes the token enforces `CKA_DESTROYABLE`/read-only permissions (`CKR_ACTION_PROHIBITED`). Chose the single OO entry point over a redundant `Pkcs11Workspace.DeleteKey`. New SoftHSM test `DeleteKeyTests.Delete_RemovesKeyFromToken` generates an on-token AES key, deletes it via `Pkcs11Key.Delete()`, and asserts `FindKeys` is empty afterward (verified it runs, not skips). 600 tests pass.
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Workspace.cs`; `Pkcs11Key.cs:122` (`Dispose` only closes the handle); internal `Pkcs11Session.Objects.cs` has `DestroyObject`.
- **Problem:** Public API surface review (2026-05-20). Consumers can `GenerateKey` / `ImportKey` but there is no public way to remove a token object — `Pkcs11Key.Dispose` closes the handle without calling `C_DestroyObject`, so the object persists on the token. A consumer can fill a token with no API to clean up. The internal `Pkcs11Session.DestroyObject` already exists; it's simply not surfaced.
- **Proposed action:** Surface deletion — e.g., `Pkcs11Key.Delete()` (and/or `Pkcs11Workspace.DeleteKey`) that calls the internal `DestroyObject`. Be explicit in docs about the distinction from `Dispose` (close handle vs destroy on token). Respect token permissions (deletion of a read-only/CKA_DESTROYABLE=false object fails at the token).
- **Breaks public API?** No (additive).
- **Raised by:** Public-surface review.
- **Spec / References:** PKCS#11 v3.2 `C_DestroyObject`.

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

### [BL-064] Object find/read is key-only — certificates and data objects unreachable

- **Status: Resolved (2026-05-20).** Three finders, each returning the right typed result:
  - `FindObjects(ObjectTemplate filter)` → generic `Pkcs11Object` (object class, label, id, `GetValue()` reading `CKA_VALUE`, `Delete()`). Unlike `FindKeys`/`HydrateKeyFromHandle` — which read `CKA_KEY_TYPE` and so genuinely throw on non-key objects — this reads only `CKA_CLASS`/`CKA_LABEL`/`CKA_ID`, so certificates and data objects are enumerable/readable.
  - `FindCertificates()` → typed `Pkcs11Certificate`: exposes the parsed `X509Certificate2`, retains the token handle (`Delete()`), and bridges to the on-token private key by `CKA_ID` via `GetRSAPrivateKey()`/`GetECDsaPrivateKey()` returning token-backed `RSAPkcs11`/`ECDsaPkcs11` (BCL-shaped, null when absent/wrong type, mirroring `X509Certificate2`).
  - `FindKeys` → `Pkcs11Key` (retained — operation-capable, companion pairing).
  - **Design history (kept for the record):** an earlier pass put `AsX509Certificate()`/`AsX509CertificateWithPrivateKey()` on the *generic* `Pkcs11Object`; reverted because (1) typed conversions don't belong on the generic view (symmetry would force key-typed ones too) and (2) `CopyWithPrivateKey` can't bind a non-extractable HSM key on the OpenSSL backend (it exports — Windows/CNG-only). The shipped design keeps cert and key as separate token objects (the platform reality) and bridges them by `CKA_ID`, with no `CopyWithPrivateKey`. The cert→key lookup filters on `CKA_CLASS = CKO_PRIVATE_KEY` (the cert shares the id, so a bare id filter would mis-match the cert). SoftHSM tests cover both generic read/delete and minting a token-signed cert (via `X509SignatureGenerator`, no export) → `FindCertificates` → `GetRSAPrivateKey` → sign-on-token → verify. 602 tests pass. Generic per-attribute read/write remains BL-063; clean public non-key *import* (`ImportKey` throws on a cert template) remains a separate follow-up.
- **Area:** .NET API Design
- **Severity:** Medium
- **Effort:** M
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Workspace.cs:118` (`FindKeys`); `CertificateTemplateBuilder.cs`, `DataTemplateBuilder.cs` (import-only).
- **Problem:** Public API surface review (2026-05-20). `FindKeys` enumerates keys only. There is no public way to find or read certificates or data objects, even though `CertificateTemplateBuilder` / `DataTemplateBuilder` exist for *importing* them — so a consumer can write a certificate to the token but cannot enumerate or read it back.
- **Proposed action:** Generalize the find/read surface beyond keys — e.g., a `FindObjects(ObjectTemplate filter)` returning object handles/views, plus typed certificate/data accessors (read `CKA_VALUE` for a cert). Pairs naturally with BL-063 (attribute read).
- **Breaks public API?** No (additive).
- **Raised by:** Public-surface review.
- **Spec / References:** PKCS#11 v3.2 `C_FindObjects*`.

---

## Low

### [BL-054] `Pkcs11Library` finalizer body is empty — comment promises cleanup that doesn't happen

- **Status: Resolved (2026-05-20)** — Removed the `~Pkcs11Library()` finalizer. Native release was never done there anyway — it's handled by `Pkcs11ModuleHandle`'s critical-finalizer `SafeHandle` (reached via `_pkcs11Library.Dispose()`). With no finalizer the `Dispose(bool disposing)` split and `GC.SuppressFinalize` became dead finalizer-pattern scaffolding (the same misleading-cleanup smell the item flags), so collapsed them into a single idempotent `Dispose()`. Updated the `<see cref="Dispose(bool)"/>` doc reference to `Dispose()`. Behavior is unchanged (managed dispose always ran the cleanup; the finalizer path did nothing). 600 tests pass.
- **Area:** P/Invoke
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Library.cs:300-310` (finalizer + `Dispose(false)`)
- **Problem:** Finalizer says "disposes object if caller forgot" but `Dispose(false)` does nothing — the `SafeHandle` does the real native release. Sound but misleading.
- **Proposed action:** Remove the finalizer; rely on `Pkcs11ModuleHandle`'s critical finalizer.
- **Raised by:** PKCS#11 Specialist B, .NET Engineer B

### [BL-055] Minor polish: `eventOccurred` doc-class items

- **Status: Resolved (2026-05-20)** — Dispositions per sub-item: (1) `Mechanism._mechanismParams` now `IMechanismParams?` (matches the `Parameters` property which is already nullable). (2) `UnmanagedMemory.Allocate` zeroes via `NativeMemory.Clear` instead of allocating a throwaway managed `byte[]` each call. (4) `Pkcs11PublicKeyView.TrySynthesizeRsa/Ec` changed `public static` → `internal static` to match the internal class. (5) `LowLevelPkcs11Library.Dispose` no longer re-assigns `_library = new Pkcs11ModuleHandle()` after disposing it (dead churn; nothing reads the field post-dispose, which is gated by `_disposed`). (7) `Pkcs11Library.GetSlotList` slot-count check simplified to `slotList.Length != (int)slotCount`, dropping the `NativeCULong((uint)…)` round-trip. (8) The `C_GetInterface` version `Minor` guard is moot — `CK_VERSION` became two `byte` fields when made blittable, so the reads are now `version.Major < 3` / `version.Minor >= 2` with no `[0]`/null/length concern. **Deliberately kept:** (3) `DebugModeEnabled` logging the allocation address — it's opt-in debug-only, a pointer is not secret material (and ASLR randomizes it per run), and the address is the correlation key the tracker exists to provide. **Deferred:** (6) a `[Flags]` enum for `CancelOperations(ulong flags)` — the library models *all* CKF flags as `NativeCULong` constants (`CKF.CKF_*`), so a one-off cancel-only enum would be inconsistent; surfacing CKF as a typed flags enum is a broader API decision worth its own item.
- **Area:** Cross-cutting
- **Severity:** Low
- **Effort:** S
- **Location:** Various
- **Problem:** Aggregated lower-impact items: `Mechanism._mechanismParams = null` lacks `?` annotation (`Mechanism.cs:62`); `UnmanagedMemory.Allocate` allocates a managed `byte[]` to zero a buffer (`UnmanagedMemory.cs:99-100`, prefer `NativeMemory.Clear`); `DebugModeEnabled` logs raw pointer addresses (`UnmanagedMemory.cs:113,137`); `Pkcs11PublicKeyView` methods are `public static` on an `internal` class — should be `internal static` to match (`Pkcs11PublicKeyView.cs:21,52`); `LowLevelPkcs11Library.Dispose(true)` re-assigns `_library = new Pkcs11ModuleHandle()` (unnecessary churn); `CancelOperations(ulong flags)` lacks a `[Flags]` enum for discoverability (`Pkcs11Session.cs:456-465`); `Pkcs11Library.GetSlotList` slot-count comparison uses a 32-bit-truncating cast (`Pkcs11Library.cs:166-169`); `C_GetInterface` version-comparison reads `Major[0]` after a null/length check but doesn't guard `Minor[0]` (`Delegates.cs:982`).
- **Proposed action:** Address as part of pre-1.0 cleanup pass. None are individually urgent.
- **Raised by:** Multiple (Cryptographer A, .NET Engineer A, .NET Engineer B, PKCS#11 Specialist B)

### [BL-056] NuGet `<Description>` says v3.1 — codebase is v3.2

- **Status: Resolved (2026-05-20)** — `<Description>` corrected to "PKCS#11 v3.2" and the README headline updated to match (both landed in the metadata-tidy / README commits). Added `<PackageTags>pkcs11;hsm;cryptography;pkcs11v3;pqc;ml-dsa;ml-kem</PackageTags>` for discoverability. The remaining `v3.1` mentions in source are accurate spec citations (HSS/LMS, `C_GetTokenInfo` locking, optional `CKA_EC_POINT`) — features genuinely introduced in PKCS#11 v3.1 — not version claims, so they stay.
- **Area:** Release Eng
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj:19`; `README.md:3`
- **Problem:** Package metadata still says v3.1; library implements v3.2.
- **Proposed action:** Update `<Description>` and README headline. Add `<PackageTags>pkcs11;hsm;cryptography;pkcs11v3;pqc;ml-dsa;ml-kem</PackageTags>` for discoverability.
- **Raised by:** .NET Engineer A, .NET Engineer B, PKCS#11 Specialist A, QA C

### [BL-057] Missing `global.json`, `--locked-mode` restore, `coverlet` collection

- **Status: Resolved (2026-05-20); locked-mode reverted (2026-05-21).** (1) Added `global.json` pinning the SDK to the .NET 10 band (`version: 10.0.100`, `rollForward: latestFeature`). (3) `coverlet.collector` is exercised: `coverage.yml` runs `dotnet test --collect:"XPlat Code Coverage"` + Codecov upload. **(2) `--locked-mode` and `packages.lock.json` were removed** after they broke CI: this project sets `<IsAotCompatible>`, which pulls the SDK-implicit package `Microsoft.NET.ILLink.Tasks`, and that package is *not portable* in a lock file — its version tracks the SDK patch (NU1004: lock pinned 10.0.7, the runner's newer SDK resolved 10.0.8) and, even with the SDK pinned to the same version, its content hash differs by SDK *provenance* (NU1403: the lock was generated with the distro-packaged SDK; CI uses the official Microsoft download). Locked-mode is therefore unworkable here. Dropped `--locked-mode` from all four restores, removed `<RestorePackagesWithLockFile>` from the three projects, deleted the three `packages.lock.json`, and reverted the temporary exact-SDK pin. Determinism still comes from the pinned `global.json` band + explicit `PackageReference` versions. To re-enable enforced lock reproducibility later, regenerate the lock with the *official* SDK build that CI uses (not the distro package) and pin the SDK in lockstep.
- **Area:** Release Eng
- **Severity:** Low
- **Effort:** S
- **Location:** `absent: global.json`; `.github/workflows/ci.yml:45,66-83`; `KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj:19`
- **Problem:** SDK version not pinned (`<LangVersion>latest</LangVersion>` floats). `dotnet restore` doesn't use `--locked-mode` even though `packages.lock.json` is checked in. `coverlet.collector` is referenced but `dotnet test` never collects coverage.
- **Proposed action:** Add `global.json` pinning the SDK band. Add `--locked-mode` to all `dotnet restore` invocations (or pass `RestoreLockedMode` MSBuild property). Either wire coverlet up (`--collect:"XPlat Code Coverage"` + Codecov upload) or remove the reference.
- **Raised by:** QA C

### [BL-058] Pre-release `Microsoft.DotNet.XUnitExtensions` test dependency fragility

- **Status: Won't Fix (2026-05-20)** — Test-only dependency; it never ships in the package, so feed fragility can at most break a local/CI test restore, not consumers. No stable `Microsoft.DotNet.XUnitExtensions` release exists to pin to, and the `[ConditionalFact]`/`[ConditionalTheory]` support it provides (used for the SoftHSM-gated tests) has no drop-in replacement worth a rewrite. `packages.lock.json` + `--locked-mode` already pin the exact resolved version, so the build is reproducible despite the pre-release source. Revisit only if the feed actually breaks or a stable release ships.
- **Area:** Release Eng
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj:20`
- **Problem:** Uses `11.0.0-beta.25605.110` from an Azure DevOps feed. Test-only, so not a shipping concern, but fragile if the feed URL changes.
- **Proposed action:** Pin a stable release if/when one is published; otherwise document the override feed in CONTRIBUTING.
- **Raised by:** QA C

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

### [BL-065] No public PIN management (SetPin / InitPin)

- **Status: Resolved (2026-05-20)** — Surfaced `Pkcs11Workspace.SetPin(SecurePin oldPin, SecurePin newPin)` (`C_SetPIN`) and `InitPin(SecurePin userPin)` (`C_InitPIN`), delegating to the existing internal `Pkcs11Session` methods after a disposed-guard + null-guard (matching the established workspace delegation style; `SecurePin` zeroize handling is unchanged). Tests: mock-backend guard tests (null args → `ArgumentNullException`, after-dispose → `ObjectDisposedException`) that run cross-platform and never touch a real PIN, plus a SoftHSM `SetPin` round-trip that performs a real `C_SetPIN` change and restores the shared token's user PIN (self-restoring, with a finally fallback; SoftHSM tests run serially so the change is contained). InitPin's SoftHSM integration was intentionally not added — exercising it resets the user PIN via an SO session, a high-blast-radius change to the shared token, and it's the same thin delegation pattern that the SetPin round-trip already proves end-to-end. 606 tests pass.
- **Area:** .NET API Design
- **Severity:** Low
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Pkcs11Workspace.cs`; internal `Pkcs11Session.cs` has `SetPin`/`InitPin`.
- **Problem:** Public API surface review (2026-05-20). Token administration beyond `Pkcs11Slot.InitToken` is unreachable: there is no public way to change the logged-in user's PIN (`C_SetPIN`) or for the SO to initialize the user PIN (`C_InitPIN`). Both already exist on the internal `Pkcs11Session` (taking `SecurePin`); they are simply not surfaced on `Pkcs11Workspace`.
- **Proposed action:** Surface `SetPin(SecurePin oldPin, SecurePin newPin)` and `InitPin(SecurePin userPin)` on `Pkcs11Workspace`, delegating to the session. Mirror the `SecurePin`/zeroize handling already used internally.
- **Breaks public API?** No (additive).
- **Raised by:** Public-surface review.
- **Spec / References:** PKCS#11 v3.2 `C_SetPIN` / `C_InitPIN`.

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

### [BL-067] Other legacy 64-bit-block ciphers not in `GuardMechanism`

- **Status: Resolved (2026-05-20)** — Added `GuardMechanism` arms for the CAST (`CKM_CAST_*`, `CKM_CAST3_*`, `CKM_CAST5_*`), RC5 (`CKM_RC5_*`), Blowfish (`CKM_BLOWFISH_*`), and SKIPJACK (`CKM_SKIPJACK_*`, including the `*64`/`CFB*` modes and the `WRAP`/`PRIVATE_WRAP`/`RELAYX` key-wrap mechanisms) families, each throwing `InsecureOperationException` recommending `CKM_AES_GCM`. `CKM_CAST5_*` are the old names for `CKM_CAST128_*` (identical enum values), so only the CAST128 labels are listed — they match CAST5 calls too. Added 8 gate-coverage `[InlineData]` cases. 590 tests pass.
- **Area:** Cryptography
- **Severity:** Medium
- **Effort:** S
- **Location:** `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Internal/Pkcs11Session.cs` (`GuardMechanism`)
- **Problem:** BL-018 gated the insecure mechanisms it enumerated (DES/3DES, RC4, RC2, SEED, MD2, RIPEMD, SHA-1 sig/MAC, unauthenticated AES modes, raw RSA). It did not gate the remaining legacy ciphers that are present in the `CKM` enum: `CKM_CAST*` / `CKM_CAST3_*` / `CKM_CAST5_*` / `CKM_CAST128_*`, `CKM_RC5_*`, `CKM_BLOWFISH_*`, and `CKM_SKIPJACK_*`. These are 64-bit-block ciphers (vulnerable to Sweet32-class birthday attacks) or, for SKIPJACK, an 80-bit-key cipher with known weaknesses — all unauthenticated and effectively unused outside legacy interop. A caller can use them today with no warning.
- **Proposed action:** Add `GuardMechanism` arms for the CAST/RC5/Blowfish/SKIPJACK families (key-gen, ECB/CBC/CBC_PAD, MAC variants), each throwing `InsecureOperationException` recommending `CKM_AES_GCM`. Mirror the BL-018 grouping and add gate-coverage `[InlineData]` cases.
- **Breaks public API?** No (additive gate; opt-out via `AllowInsecure`).
- **Raised by:** BL-018 follow-up (2026-05-20).
- **Spec / References:** NIST SP 800-131A Rev. 2; Sweet32 (CVE-2016-2183) for 64-bit-block ciphers.

### [BL-068] Windows SoftHSM2 CI build is unusable (token init fails + ~27 min build)

- **Area:** Release Eng
- **Severity:** Low
- **Effort:** M
- **Location:** `build/build-softhsmv2.ps1`; `.github/workflows/ci.yml` (Windows legs, currently `SkipSoftHsmV2Build=true`).
- **Problem:** The Windows SoftHSM2 build (`build-softhsmv2.ps1`) compiles successfully, but the first CI run surfaced two blockers, so it's gated off on the Windows legs (Windows runs pkcs11-mock only; SoftHSM tests self-skip there). (1) **Token init fails:** `softhsm2-util --init-token` errors with `Could not load the PKCS#11 library/module: LoadLibraryA failed: 0x0000007E` (ERROR_MOD_NOT_FOUND). Likely causes: the Windows build omits the `-DDEFAULT_PKCS11_LIB` / `-DDEFAULT_SOFTHSM2_CONF` / `-DDEFAULT_TOKENDIR` defaults the Linux script bakes in, and/or the vcpkg OpenSSL runtime DLLs (`libcrypto-3-x64.dll`) aren't resolvable next to `softhsm2-util.exe` / `libsofthsm2.dll` at load time. (2) **~27 min build:** vcpkg compiles OpenSSL from source on every run with no caching — impractical for routine CI.
- **Proposed action:** (a) Pass the `-DDEFAULT_*` paths in `build-softhsmv2.ps1` to match `build-softhsmv2.sh`; verify the OpenSSL runtime DLLs land next to the module + util (and confirm with a dependency walk). (b) Make OpenSSL fast: cache the vcpkg build (`actions/cache` on the vcpkg binary cache) or use a prebuilt OpenSSL instead of from-source. (c) Once green and fast, re-enable the Windows leg (drop `SkipSoftHsmV2Build` there) and remove the Windows exemption in `SoftHsmAvailabilityTests`.
- **Breaks public API?** No (CI/test infra only).
- **Raised by:** First Windows CI run of the SoftHSM build (2026-05-21).

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
