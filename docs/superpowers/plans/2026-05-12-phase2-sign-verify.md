# PKCS11.NET Phase 2: Sign + Verify Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Carve `Sign`, `Verify`, `SignRecover`, `VerifyRecover` (and the `SignEncrypt` / `DecryptVerify` combined ops) out of `Session.cs` into `Session.Sign.cs` + `Session.Verify.cs` partials; extend `GuardMechanism` to cover signing-side insecure mechanisms (RSA PKCS#1 v1.5 sign, MD5/SHA-1 RSA combos, DES/3DES MAC); add `CkmRsaPkcsPssParams` wrapper; ship secure-default helpers `SignRsaPss`, `SignEcdsa`, `SignEd25519`, `SignEd448` (and Verify counterparts); add `[Obsolete]` shortcuts `SignRsaPkcs1V15` / `VerifyRsaPkcs1V15`; cover all of it with functional + argument-validation + gate tests against pkcs11-mock and SoftHSM2.

**Architecture:** Mechanical extension of the Phase 1 pattern. Reuse the `IMechanismParams` interface, the unmanaged-memory ownership idiom from `CkmAesGcmParams`, the static-helper + per-backend concrete test-class layout from `EncryptAesTests`, and the established `Settings`/`IPkcs11Backend` plumbing. The behavior surface is additive — pre-Phase-2 method signatures are preserved verbatim when moved into partials, with only the GuardMechanism wiring added.

**Tech Stack:** C# 12 / .NET 8 + .NET 9, xUnit 2.9, `Microsoft.DotNet.XUnitExtensions` (`[ConditionalFact]`, `[ConditionalTheory]`), pkcs11-mock v2.0.0, SoftHSM2 (apt on Linux, choco on Windows).

**Reference specs:**
- Parent: `docs/superpowers/specs/2026-05-11-pkcs11-completion-design.md`
- Phase 1: `docs/superpowers/plans/2026-05-11-phase1-encrypt-decrypt.md` (the pattern this plan inherits)

**Out of scope (deferred to later phases):**
- PKCS#11 v3.1 message-based APIs (`C_SignMessageInit`, `C_SignMessage`, `C_VerifyMessageInit`, etc.) — pkcs11-mock v2.0.0 predates v3.1. Revisit when a backend supports them.
- `Session.cs` still holds `DigestEncrypt` + `DecryptDigest` after Phase 2; they move when the `Session.Digest.cs` partial lands in Phase 3.

---

## File Structure

```
src/
├── KerckhoffsLabs.Security.Cryptography.Pkcs11/
│   ├── HighLevel/
│   │   ├── Session.cs                                        [MODIFY — strip Sign/Verify/SignRecover/VerifyRecover/SignEncrypt/DecryptVerify out; extend GuardMechanism]
│   │   ├── Session.Sign.cs                                   [CREATE — partial: Sign + SignRecover + SignEncrypt + Span overloads + secure helpers]
│   │   ├── Session.Verify.cs                                 [CREATE — partial: Verify + VerifyRecover + DecryptVerify + Span overloads + secure helpers]
│   │   └── MechanismParams/
│   │       └── CkmRsaPkcsPssParams.cs                        [CREATE — high-level wrapper for CK_RSA_PKCS_PSS_PARAMS]
│   ├── Common/
│   │   ├── CKM.cs                                            [MODIFY — add CKM_EDDSA, CKM_EC_EDWARDS_KEY_PAIR_GEN]
│   │   └── CKK.cs                                            [MODIFY — add CKK_EC_EDWARDS]
│   └── (Native/MechanismParams/CK_RSA_PKCS_PSS_PARAMS.cs already exists from Phase 0)
│
└── KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/
    └── HighLevel/
        ├── Sign/
        │   ├── SignRsaPssTests.cs                            [CREATE]
        │   ├── SignEcdsaTests.cs                             [CREATE]
        │   ├── SignEdDsaTests.cs                             [CREATE — covers Ed25519 + Ed448]
        │   └── SignRsaPkcsTests.cs                           [CREATE — covers [Obsolete] PKCS#1 v1.5 + gate]
        ├── Verify/
        │   ├── VerifyRsaPssTests.cs                          [CREATE]
        │   ├── VerifyEcdsaTests.cs                           [CREATE]
        │   ├── VerifyEdDsaTests.cs                           [CREATE]
        │   └── VerifyRsaPkcsTests.cs                         [CREATE]
        └── Security/
            └── InsecureOperationGateTests.cs                 [MODIFY — extend Theory data to include signing mechanisms]
```

Each test file follows the Phase 1 pattern: **internal static helper class with assertion methods** + two concrete test classes (`*_Mock` with `[Fact]` / `[Theory]`, `*_SoftHsm` with `[ConditionalFact(nameof(SoftHsmAvailable))]` / `[ConditionalTheory(...)]`). No abstract base classes — `ConditionalFact` resolves the gate-member name on the declaring type.

The `TestKeys` helper (created in Phase 1 T9) already has `OpenLoggedInSession`, `GenerateRsa2048KeyPair`. Phase 2 extends it with EC and EdDSA key generators.

---

## Task 1: Extend `GuardMechanism` to cover signing-side insecure mechanisms

Adds the additional CKM values to the runtime gate. After this task lands, calling `Sign(new Mechanism(CKM.CKM_MD5_RSA_PKCS), ...)` against any backend will throw `InsecureOperationException` unless `AllowInsecure = true`. Nothing else changes yet.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/InsecureOperationException.cs`

- [ ] **Step 1: Update `GuardMechanism` switch in Session.cs**

Locate `private void GuardMechanism(CKM mechanism)` (just above `#region IDisposable`). Replace the body with this expanded version that adds signing-side mechanisms:

```csharp
    private void GuardMechanism(CKM mechanism)
    {
        if (AllowInsecure) return;

        switch (mechanism)
        {
            case CKM.CKM_RSA_PKCS:
                throw new InsecureOperationException(mechanism,
                    "RSA PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks and fault attacks; use CKM_RSA_PKCS_OAEP for encryption or CKM_RSA_PKCS_PSS for signing.");
            case CKM.CKM_MD5_RSA_PKCS:
            case CKM.CKM_SHA1_RSA_PKCS:
                throw new InsecureOperationException(mechanism,
                    "MD5/SHA-1 in RSA signature contexts is broken; use CKM_SHA256_RSA_PKCS_PSS or CKM_ECDSA_SHA256 instead.");
            case CKM.CKM_MD5:
            case CKM.CKM_SHA_1:
                throw new InsecureOperationException(mechanism,
                    "MD5 and SHA-1 are broken hash functions; use CKM_SHA256 or stronger.");
            case CKM.CKM_DES_ECB:
            case CKM.CKM_DES_CBC:
            case CKM.CKM_DES_CBC_PAD:
            case CKM.CKM_DES3_ECB:
            case CKM.CKM_DES3_CBC:
            case CKM.CKM_DES3_CBC_PAD:
                throw new InsecureOperationException(mechanism,
                    "DES and 3DES are deprecated; use AES (CKM_AES_GCM or CKM_AES_CBC_PAD) instead.");
            case CKM.CKM_DES_MAC:
            case CKM.CKM_DES3_MAC:
                throw new InsecureOperationException(mechanism,
                    "DES/3DES MAC is weak; use CKM_AES_CMAC or CKM_SHA256_HMAC instead.");
            case CKM.CKM_AES_ECB:
                throw new InsecureOperationException(mechanism,
                    "ECB mode leaks structural information from the plaintext; use CKM_AES_GCM or CKM_AES_CBC_PAD instead.");
            default:
                return;
        }
    }
```

- [ ] **Step 2: Update XML doc on `InsecureOperationException`**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/InsecureOperationException.cs`. Replace the existing class-level summary with one that reflects the now-complete mechanism set:

```csharp
/// <summary>
/// Thrown when an operation uses a mechanism the library considers insecure by default,
/// unless the caller has opted in via <c>Session.AllowInsecure = true</c>. Covers RSA
/// PKCS#1 v1.5 padding (for both encryption and signature), MD5 and SHA-1 (raw and in RSA
/// signature contexts), DES/3DES (encryption and MAC), and AES-ECB.
/// </summary>
```

(The previous "Phase 2 — these are added later" forward-reference becomes a fulfilled promise.)

- [ ] **Step 3: Build to confirm**

```bash
dotnet build src/src.sln 2>&1 | tail -3
```

Expected: `0 Error(s)`. Nothing calls the new gate branches yet — Sign/Verify don't pass through `GuardMechanism` until T5.

- [ ] **Step 4: Run the test suite**

```bash
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 164 passed, 38 skipped, 0 failed (identical to phase-1-complete). No test currently relies on those mechanisms not being gated.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/InsecureOperationException.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session): extend GuardMechanism with signing-side insecure mechanisms

Adds MD5_RSA_PKCS, SHA1_RSA_PKCS, raw MD5, raw SHA_1, DES_MAC, DES3_MAC
to the runtime gate. Refreshes the InsecureOperationException XML doc
to match: the 'added in Phase 2' forward-reference is now fulfilled.

Nothing calls these branches until T5 wires GuardMechanism into the
Sign/Verify entry points."
```

---

## Task 2: Add `CKM_EDDSA` + `CKK_EC_EDWARDS` enum values

Required by the EdDSA helpers (T8). Both are PKCS#11 v3.0 additions that the upstream import missed (matching the pattern we saw with CKM_CHACHA20_POLY1305 in Phase 1).

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKM.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKK.cs`

- [ ] **Step 1: Add `CKM_EDDSA` to the CKM enum**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKM.cs`. Search for the surrounding ECDSA entries (`CKM_ECDSA_SHA512 = 0x00001046`). After the ECDSA block, add:

```csharp
    /// <summary>EdDSA (Ed25519/Ed448) signing mechanism. PKCS#11 v3.0 §2.3.</summary>
    CKM_EDDSA = 0x00001057,

    /// <summary>EC Edwards key pair generation (for Ed25519/Ed448 keys). PKCS#11 v3.0 §2.3.</summary>
    CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x00001055,
```

Place them in numerical order in the file — find the closest existing values (`0x00001050`-`0x00001060` range) and insert these between them.

- [ ] **Step 2: Add `CKK_EC_EDWARDS` to the CKK enum**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKK.cs`. After `CKK_EC = 0x00000003`, find the right numerical slot and add:

```csharp
    /// <summary>Edwards-curve key (Ed25519, Ed448). PKCS#11 v3.0 §10.7.</summary>
    CKK_EC_EDWARDS = 0x00000040,
```

- [ ] **Step 3: Build**

```bash
dotnet build src/src.sln 2>&1 | tail -3
```

Expected: 0 errors.

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKM.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKK.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(enums): add CKM_EDDSA / CKM_EC_EDWARDS_KEY_PAIR_GEN / CKK_EC_EDWARDS

PKCS#11 v3.0 additions (§2.3, §10.7) that the original Pkcs11Interop
import predated. Required by the SignEd25519 / SignEd448 helpers
landing in T8."
```

---

## Task 3: Add `CkmRsaPkcsPssParams` high-level wrapper

Phase 1 added similar wrappers for AES-GCM / ChaCha20-Poly1305 / RSA-OAEP. PSS needs one too — the secure `SignRsaPss` helper (T8) constructs `CkmRsaPkcsPssParams` and passes it into `new Mechanism(CKM.CKM_RSA_PKCS_PSS, params)`.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/MechanismParams/CkmRsaPkcsPssParams.cs`

- [ ] **Step 1: Write the wrapper class**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/MechanismParams/CkmRsaPkcsPssParams.cs`:

```csharp
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_RSA_PKCS_PSS_PARAMS"/>. Owns no unmanaged
/// buffers — PSS params are three integers — but follows the IMechanismParams
/// contract so the secure helpers can construct a Mechanism uniformly.
/// </summary>
public sealed class CkmRsaPkcsPssParams : IMechanismParams
{
    private CK_RSA_PKCS_PSS_PARAMS _lowLevelParams;
    private bool _disposed;

    /// <summary>
    /// Initializes RSA-PSS parameters.
    /// </summary>
    /// <param name="hashAlg">Hash mechanism (typically <see cref="CKM.CKM_SHA256"/>).</param>
    /// <param name="mgf">Mask generation function (typically <see cref="CKG.CKG_MGF1_SHA256"/>).</param>
    /// <param name="saltLength">Salt length in bytes. RFC 8017 recommends matching the hash output length (32 for SHA-256).</param>
    public CkmRsaPkcsPssParams(CKM hashAlg, CKG mgf, int saltLength)
    {
        if (saltLength < 0)
            throw new ArgumentOutOfRangeException(nameof(saltLength), "Salt length must be non-negative.");

        _lowLevelParams = new CK_RSA_PKCS_PSS_PARAMS
        {
            HashAlg = hashAlg.ToCULong(),
            Mgf = mgf.ToCULong(),
            Len = (NativeCULong)saltLength,
        };
    }

    /// <inheritdoc/>
    public object ToMarshalableStructure()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _lowLevelParams;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>No-op finalizer for symmetry with the other params wrappers; this type owns no unmanaged memory.</summary>
    ~CkmRsaPkcsPssParams() => Dispose();
}
```

- [ ] **Step 2: Build**

```bash
dotnet build src/src.sln 2>&1 | tail -3
```

Expected: 0 errors.

- [ ] **Step 3: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/MechanismParams/CkmRsaPkcsPssParams.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(MechanismParams): add CkmRsaPkcsPssParams high-level wrapper

Typed builder for CK_RSA_PKCS_PSS_PARAMS, matching the pattern of
CkmAesGcmParams / CkmRsaPkcsOaepParams added in Phase 1. PSS params
are pure integers (hash + MGF + salt length); no unmanaged buffers,
so the Dispose path is trivial."
```

---

## Task 4: Carve `Session.Sign.cs` out of `Session.cs`

Pure mechanical refactor: move all Sign + SignRecover methods (plus the SignEncrypt combined op) into a new partial. No behavior change in this task.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Sign.cs`

- [ ] **Step 1: Locate the Sign-side methods**

```bash
grep -n "public.* Sign(\|public.* SignRecover\|public.* SignEncrypt" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs | head -25
```

Expected (per phase-1-complete state):
- 9 `Sign` methods (3 shapes × 3 keyPin variants — no-pin / string-pin / byte[]-pin)
- 3 `SignRecover` methods
- 9 `SignEncrypt` methods (combined op, byte[]/Stream/Stream-with-buffer × no-pin/string-pin/byte[]-pin)

If counts differ, surface that before moving anything.

- [ ] **Step 2: Create Session.Sign.cs with the scaffold**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Sign.cs`:

```csharp
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
{
    // Paste the Sign + SignRecover + SignEncrypt methods + their XML doc comments here.
}
```

- [ ] **Step 3: Move each method group verbatim**

For each method (and its preceding XML doc block), cut from `Session.cs` and paste inside the `public partial class Session { ... }` body in `Session.Sign.cs`. Process in this order to keep line numbers stable while editing:

1. All 9 `Sign` methods (top-down by line number).
2. All 3 `SignRecover` methods.
3. All 9 `SignEncrypt` methods.

Match the strip pattern from Phase 1 T5: only move the methods, no usings/namespace changes; do not modify any bodies (T5 will add GuardMechanism). Preserve trailing blank lines / comment blocks.

- [ ] **Step 4: Build**

```bash
dotnet build src/src.sln 2>&1 | tail -3
```

Expected: 0 errors.

- [ ] **Step 5: Run the full test suite**

```bash
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 164 passed, 38 skipped, 0 failed.

- [ ] **Step 6: Verify the carve scope**

```bash
echo "=== Session.cs no longer has Sign-side methods ==="
grep -cE "public.* Sign\(|public.* SignRecover\(|public.* SignEncrypt\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
echo "=== Session.Sign.cs has them all ==="
grep -cE "public.* Sign\(|public.* SignRecover\(|public.* SignEncrypt\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Sign.cs
```

Expected: `0` for Session.cs, `21` for Session.Sign.cs (9 Sign + 3 SignRecover + 9 SignEncrypt).

- [ ] **Step 7: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Sign.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "refactor(Session): carve Sign / SignRecover / SignEncrypt into Session.Sign.cs

Pure relocation, no behavior change. Combined-op SignEncrypt moves
here per the Phase 2 design (each combined op lives in the partial
of its 'primary' operation; SignEncrypt is fundamentally a Sign with
encryption tacked on, so it lives next to Sign).

Sets up T6 (Span overloads + GuardMechanism wire-up) and T8 (secure
helpers + [Obsolete] shortcuts)."
```

---

## Task 5: Carve `Session.Verify.cs` out of `Session.cs`

Same mechanical refactor for the Verify side.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Verify.cs`

- [ ] **Step 1: Locate the Verify-side methods**

```bash
grep -n "public.* Verify(\|public.* VerifyRecover\|public.* DecryptVerify" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs | head -15
```

Expected:
- 3 `Verify` methods (byte[], Stream, Stream-with-buffer)
- 1 `VerifyRecover` method
- 3 `DecryptVerify` methods (combined op)

If counts differ, surface that before moving anything.

- [ ] **Step 2: Create Session.Verify.cs**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Verify.cs`:

```csharp
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
{
    // Paste Verify + VerifyRecover + DecryptVerify methods + their XML doc comments here.
}
```

- [ ] **Step 3: Move each method group verbatim**

In order: 3 `Verify` → 1 `VerifyRecover` → 3 `DecryptVerify`. No edits to bodies.

- [ ] **Step 4: Build + test**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. 164 passed, 38 skipped, 0 failed.

- [ ] **Step 5: Verify the carve scope**

```bash
echo "=== Session.cs no longer has Verify-side methods ==="
grep -cE "public.* Verify\(|public.* VerifyRecover\(|public.* DecryptVerify\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
echo "=== Session.Verify.cs has them all ==="
grep -cE "public.* Verify\(|public.* VerifyRecover\(|public.* DecryptVerify\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Verify.cs
```

Expected: `0` for Session.cs, `7` for Session.Verify.cs.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Verify.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "refactor(Session): carve Verify / VerifyRecover / DecryptVerify into Session.Verify.cs

Pure relocation. DecryptVerify (the combined op) lives next to Verify
per the same rule SignEncrypt followed in T4: combined ops live with
their 'primary' operation. Session.cs now retains only DigestEncrypt
and DecryptDigest among combined ops — they move when Session.Digest.cs
lands in Phase 3."
```

---

## Task 6: Add Span overloads + wire `GuardMechanism` into Sign/Verify entry points

Adds `ReadOnlySpan<byte>` overloads on the byte[] entry points and threads `GuardMechanism((CKM)mechanism.Type)` through every existing Sign/Verify method body. Mirrors Phase 1 T7 exactly.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Sign.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Verify.cs`

- [ ] **Step 1: Add a `ReadOnlySpan<byte>` overload above each byte[] `Sign(...)`**

In `Session.Sign.cs`, above the existing `public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, byte[] data)`, add:

```csharp
    /// <summary>
    /// Signs <paramref name="data"/> using the given mechanism and key. Throws
    /// <see cref="InsecureOperationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">Signing mechanism.</param>
    /// <param name="keyHandle">Handle of the private/MAC key.</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>Signature bytes (size depends on key + mechanism).</returns>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(keyHandle);
        // Temporary array for the byte[]-based P/Invoke path. Replace with pinned-Span
        // P/Invoke when perf profiling proves it matters.
        byte[] buffer = data.ToArray();
        return Sign(mechanism, keyHandle, buffer);
    }
```

The 2 keyPin variants of `Sign(Mechanism, ObjectHandle, ..., byte[])` each get their own Span overload — same shape, just with the keyPin parameter passed through:

```csharp
    /// <summary>String-keyPin variant — see <see cref="Sign(Mechanism, ObjectHandle, ReadOnlySpan{byte})"/>.</summary>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, string keyPin, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(keyHandle);
        byte[] buffer = data.ToArray();
        return Sign(mechanism, keyHandle, keyPin, buffer);
    }

    /// <summary>byte[]-keyPin variant — see <see cref="Sign(Mechanism, ObjectHandle, ReadOnlySpan{byte})"/>.</summary>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, byte[] keyPin, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(keyHandle);
        byte[] buffer = data.ToArray();
        return Sign(mechanism, keyHandle, keyPin, buffer);
    }
```

(Three Span overloads total — one per keyPin variant — all delegate to the existing byte[] paths.)

- [ ] **Step 2: Insert `GuardMechanism` into each existing Sign / SignRecover method**

For each of the existing methods (9 Sign, 3 SignRecover, 9 SignEncrypt), find the entry-check block at the top — typically `if (_disposed) throw new ObjectDisposedException(...)` followed by `_logger.Debug(...)` followed by argument null checks. Use the Phase 1 T7 ordering:

1. `if (_disposed) throw new ObjectDisposedException(...)` (existing)
2. Move (or add) `if (mechanism == null) throw new ArgumentNullException("mechanism");` BEFORE the logger
3. Move (or add) `if (keyHandle == null) throw new ArgumentNullException("keyHandle");` BEFORE the logger
4. Add `GuardMechanism((CKM)mechanism.Type);` BEFORE the logger
5. Existing logger / remaining body unchanged

For `SignEncrypt`, there are TWO mechanisms (`signingMechanism` and `encryptionMechanism`). Guard both:

```csharp
        GuardMechanism((CKM)signingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);
```

- [ ] **Step 3: Add a `ReadOnlySpan<byte>` overload to `Verify`**

In `Session.Verify.cs`, above the existing `public void Verify(Mechanism mechanism, ObjectHandle keyHandle, byte[] data, byte[] signature, out bool isValid)`, add:

```csharp
    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="data"/> using the given
    /// mechanism and key. Throws <see cref="InsecureOperationException"/> if
    /// <paramref name="mechanism"/> is insecure-by-default and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">Verification mechanism.</param>
    /// <param name="keyHandle">Handle of the public/MAC key.</param>
    /// <param name="data">Data the signature was computed over.</param>
    /// <param name="signature">Signature bytes to verify.</param>
    /// <param name="isValid">Set to true if the signature verifies; false otherwise.</param>
    public void Verify(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, out bool isValid)
    {
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(keyHandle);
        byte[] dataBuf = data.ToArray();
        byte[] sigBuf = signature.ToArray();
        Verify(mechanism, keyHandle, dataBuf, sigBuf, out isValid);
    }
```

- [ ] **Step 4: Insert `GuardMechanism` into each existing Verify / VerifyRecover / DecryptVerify method**

Same pattern as Step 2. `DecryptVerify` has two mechanisms — guard both.

- [ ] **Step 5: Build**

```bash
dotnet build src/src.sln 2>&1 | tail -3
```

Expected: 0 errors.

- [ ] **Step 6: Run tests**

```bash
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 164 passed, 38 skipped, 0 failed. No existing test uses a now-gated mechanism on the Sign/Verify path, so wiring `GuardMechanism` doesn't break anything.

- [ ] **Step 7: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Sign.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Verify.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session): add ReadOnlySpan<byte> Sign/Verify + wire GuardMechanism

Span overloads delegate to the existing byte[] path via .ToArray() —
zero-copy via pinning is a future optimization. GuardMechanism is now
called from every Sign / Verify / SignRecover / VerifyRecover /
SignEncrypt / DecryptVerify entry point; insecure mechanisms (RSA
PKCS#1 v1.5 signing, MD5/SHA-1 RSA combos, DES/3DES MAC) throw
InsecureOperationException unless Session.AllowInsecure = true.

Combined-op methods guard BOTH of their mechanisms."
```

---

## Task 7: Extend `TestKeys` helper with EC + EdDSA key generators

Phase 1's `TestKeys` exposes RSA key-pair generation and an AES key constructor. T9 (round-trip tests) needs EC P-256 and Ed25519/Ed448 keys too.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/TestKeys.cs`

- [ ] **Step 1: Add `GenerateEcP256KeyPair`**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/TestKeys.cs`. Below the existing `GenerateRsa2048KeyPair`, add:

```csharp
    /// <summary>
    /// Generates an EC key pair on the P-256 (secp256r1) curve as session objects.
    /// Returns (publicHandle, privateHandle).
    /// </summary>
    public static (ObjectHandle pub, ObjectHandle priv) GenerateEcP256KeyPair(Session session)
    {
        using var mechanism = new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN);

        // DER-encoded ASN.1 OID for prime256v1 (1.2.840.10045.3.1.7):
        // 06 08 2A 86 48 CE 3D 03 01 07
        byte[] p256Params = new byte[] { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

        using var pubClass    = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubKeyType  = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
        using var pubToken    = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var pubVerify   = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var pubParams   = new ObjectAttribute(CKA.CKA_EC_PARAMS, p256Params);

        using var privClass    = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privKeyType  = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
        using var privToken    = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var privSensitive= new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privSign     = new ObjectAttribute(CKA.CKA_SIGN, true);

        var pubTemplate  = new List<ObjectAttribute> { pubClass, pubKeyType, pubToken, pubVerify, pubParams };
        var privTemplate = new List<ObjectAttribute> { privClass, privKeyType, privToken, privSensitive, privSign };

        session.GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub, out var priv);
        return (pub, priv);
    }
```

- [ ] **Step 2: Add `GenerateEd25519KeyPair`**

Below `GenerateEcP256KeyPair`:

```csharp
    /// <summary>
    /// Generates an Ed25519 key pair as session objects.
    /// Returns (publicHandle, privateHandle). Requires SoftHSM2 2.6+; not supported by pkcs11-mock.
    /// </summary>
    public static (ObjectHandle pub, ObjectHandle priv) GenerateEd25519KeyPair(Session session)
    {
        using var mechanism = new Mechanism(CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN);

        // DER-encoded ASN.1 OID for id-Ed25519 (1.3.101.112):
        // 06 03 2B 65 70
        byte[] ed25519Params = new byte[] { 0x06, 0x03, 0x2B, 0x65, 0x70 };

        using var pubClass    = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubKeyType  = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC_EDWARDS);
        using var pubToken    = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var pubVerify   = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var pubParams   = new ObjectAttribute(CKA.CKA_EC_PARAMS, ed25519Params);

        using var privClass    = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privKeyType  = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC_EDWARDS);
        using var privToken    = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var privSensitive= new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privSign     = new ObjectAttribute(CKA.CKA_SIGN, true);

        var pubTemplate  = new List<ObjectAttribute> { pubClass, pubKeyType, pubToken, pubVerify, pubParams };
        var privTemplate = new List<ObjectAttribute> { privClass, privKeyType, privToken, privSensitive, privSign };

        session.GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub, out var priv);
        return (pub, priv);
    }
```

- [ ] **Step 3: Add `GenerateEd448KeyPair`**

```csharp
    /// <summary>
    /// Generates an Ed448 key pair as session objects.
    /// Returns (publicHandle, privateHandle). Requires SoftHSM2 2.6+; not supported by pkcs11-mock.
    /// </summary>
    public static (ObjectHandle pub, ObjectHandle priv) GenerateEd448KeyPair(Session session)
    {
        using var mechanism = new Mechanism(CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN);

        // DER-encoded ASN.1 OID for id-Ed448 (1.3.101.113):
        // 06 03 2B 65 71
        byte[] ed448Params = new byte[] { 0x06, 0x03, 0x2B, 0x65, 0x71 };

        using var pubClass    = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubKeyType  = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC_EDWARDS);
        using var pubToken    = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var pubVerify   = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var pubParams   = new ObjectAttribute(CKA.CKA_EC_PARAMS, ed448Params);

        using var privClass    = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privKeyType  = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC_EDWARDS);
        using var privToken    = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var privSensitive= new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privSign     = new ObjectAttribute(CKA.CKA_SIGN, true);

        var pubTemplate  = new List<ObjectAttribute> { pubClass, pubKeyType, pubToken, pubVerify, pubParams };
        var privTemplate = new List<ObjectAttribute> { privClass, privKeyType, privToken, privSensitive, privSign };

        session.GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub, out var priv);
        return (pub, priv);
    }
```

- [ ] **Step 4: Build**

```bash
dotnet build src/src.sln 2>&1 | tail -3
```

Expected: 0 errors. If `CKA_EC_PARAMS` doesn't exist on `CKA`, find the canonical name (might be `CKA_ECDSA_PARAMS` in some imports) and adjust.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/TestKeys.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "test(TestKeys): add EC P-256 + Ed25519 + Ed448 key-pair generators

Generates session-only signing key pairs for use by Phase 2 Sign/Verify
round-trip tests. Each helper picks the canonical DER-encoded curve
OID. EdDSA variants require SoftHSM2 2.6+ and are not supported by
pkcs11-mock; tests gate them via SoftHsmAvailable."
```

---

## Task 8: Add secure-default Sign/Verify helpers + `[Obsolete]` PKCS#1 v1.5 shortcuts

Adds the named convenience methods on `Session`. Mirrors Phase 1 T8 exactly — each helper builds the right mechanism via the high-level params wrapper, calls the generic Sign/Verify, returns the result.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Sign.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Verify.cs`

- [ ] **Step 1: Add `SignRsaPss` to Session.Sign.cs**

Append (above the closing `}` of the partial):

```csharp
    // === Secure-default signing helpers ====================================

    /// <summary>
    /// Signs <paramref name="data"/> using RSA-PSS with SHA-256, MGF1+SHA-256, and a 32-byte salt
    /// (matching the hash output length per RFC 8017).
    /// </summary>
    /// <param name="privateKeyHandle">Handle of an RSA private key (CKA_SIGN=true).</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>Signature bytes (length = RSA modulus / 8).</returns>
    public byte[] SignRsaPss(ObjectHandle privateKeyHandle, ReadOnlySpan<byte> data)
    {
        using var p = new MechanismParams.CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, saltLength: 32);
        using var mechanism = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, p);
        return Sign(mechanism, privateKeyHandle, data);
    }
```

- [ ] **Step 2: Add `SignEcdsa` to Session.Sign.cs**

```csharp
    /// <summary>
    /// Signs <paramref name="data"/> using ECDSA with SHA-256 — the standard modern ECDSA mode.
    /// Output is the raw concatenated (r || s) form per PKCS#11 §2.3.6.
    /// </summary>
    /// <param name="privateKeyHandle">Handle of an EC private key on a strong curve (P-256+, secp256k1, P-384, P-521).</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>Signature bytes (2 × curve coordinate length; 64 bytes for P-256).</returns>
    public byte[] SignEcdsa(ObjectHandle privateKeyHandle, ReadOnlySpan<byte> data)
    {
        using var mechanism = new Mechanism(CKM.CKM_ECDSA_SHA256);
        return Sign(mechanism, privateKeyHandle, data);
    }
```

- [ ] **Step 3: Add `SignEd25519` to Session.Sign.cs**

```csharp
    /// <summary>
    /// Signs <paramref name="data"/> using Ed25519 (EdDSA over Curve25519).
    /// Output is a fixed 64-byte signature.
    /// </summary>
    /// <param name="privateKeyHandle">Handle of an Ed25519 private key (CKK_EC_EDWARDS, CKA_EC_PARAMS=Ed25519 OID).</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>64-byte Ed25519 signature.</returns>
    public byte[] SignEd25519(ObjectHandle privateKeyHandle, ReadOnlySpan<byte> data)
    {
        using var mechanism = new Mechanism(CKM.CKM_EDDSA);
        return Sign(mechanism, privateKeyHandle, data);
    }
```

- [ ] **Step 4: Add `SignEd448` to Session.Sign.cs**

```csharp
    /// <summary>
    /// Signs <paramref name="data"/> using Ed448 (EdDSA over Curve448).
    /// Output is a fixed 114-byte signature.
    /// </summary>
    /// <param name="privateKeyHandle">Handle of an Ed448 private key (CKK_EC_EDWARDS, CKA_EC_PARAMS=Ed448 OID).</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>114-byte Ed448 signature.</returns>
    public byte[] SignEd448(ObjectHandle privateKeyHandle, ReadOnlySpan<byte> data)
    {
        using var mechanism = new Mechanism(CKM.CKM_EDDSA);
        return Sign(mechanism, privateKeyHandle, data);
    }
```

(Same mechanism as Ed25519 — the key tells the backend which curve to use. The two helpers exist for API clarity / symmetry.)

- [ ] **Step 5: Add `[Obsolete] SignRsaPkcs1V15` to Session.Sign.cs**

```csharp
    // === Legacy named shortcut (gated, compile-time warning) ===============

    /// <summary>
    /// Signs using RSA PKCS#1 v1.5 padding. **Use <see cref="SignRsaPss"/> instead.**
    /// This method exists for compatibility; it throws <see cref="InsecureOperationException"/>
    /// at runtime unless <see cref="AllowInsecure"/> is set on the session.
    /// </summary>
    [Obsolete("RSA PKCS#1 v1.5 signing is vulnerable to fault attacks and is not recommended for new code. " +
              "Use SignRsaPss instead. If you must use it, set Session.AllowInsecure = true.")]
    public byte[] SignRsaPkcs1V15(ObjectHandle privateKeyHandle, ReadOnlySpan<byte> data)
    {
        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS);
        return Sign(mechanism, privateKeyHandle, data);
    }
```

- [ ] **Step 6: Add Verify counterparts to Session.Verify.cs**

Append (above the closing `}` of the partial):

```csharp
    // === Secure-default verification helpers ===============================

    /// <summary>Verifies <paramref name="signature"/> over <paramref name="data"/> using RSA-PSS / SHA-256 / MGF1+SHA-256 / 32-byte salt.</summary>
    public void VerifyRsaPss(ObjectHandle publicKeyHandle, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, out bool isValid)
    {
        using var p = new MechanismParams.CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, saltLength: 32);
        using var mechanism = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, p);
        Verify(mechanism, publicKeyHandle, data, signature, out isValid);
    }

    /// <summary>Verifies an ECDSA-SHA256 signature.</summary>
    public void VerifyEcdsa(ObjectHandle publicKeyHandle, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, out bool isValid)
    {
        using var mechanism = new Mechanism(CKM.CKM_ECDSA_SHA256);
        Verify(mechanism, publicKeyHandle, data, signature, out isValid);
    }

    /// <summary>Verifies an Ed25519 signature.</summary>
    public void VerifyEd25519(ObjectHandle publicKeyHandle, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, out bool isValid)
    {
        using var mechanism = new Mechanism(CKM.CKM_EDDSA);
        Verify(mechanism, publicKeyHandle, data, signature, out isValid);
    }

    /// <summary>Verifies an Ed448 signature.</summary>
    public void VerifyEd448(ObjectHandle publicKeyHandle, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, out bool isValid)
    {
        using var mechanism = new Mechanism(CKM.CKM_EDDSA);
        Verify(mechanism, publicKeyHandle, data, signature, out isValid);
    }

    // === Legacy named shortcut (gated, compile-time warning) ===============

    /// <summary>
    /// Verifies a signature produced with RSA PKCS#1 v1.5 padding.
    /// **Use <see cref="VerifyRsaPss"/> instead.** Throws <see cref="InsecureOperationException"/>
    /// at runtime unless <see cref="AllowInsecure"/> is set on the session.
    /// </summary>
    [Obsolete("RSA PKCS#1 v1.5 signing is vulnerable to fault attacks and is not recommended for new code. " +
              "Use VerifyRsaPss instead. If you must use it, set Session.AllowInsecure = true.")]
    public void VerifyRsaPkcs1V15(ObjectHandle publicKeyHandle, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, out bool isValid)
    {
        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS);
        Verify(mechanism, publicKeyHandle, data, signature, out isValid);
    }
```

- [ ] **Step 7: Build**

```bash
dotnet build src/src.sln 2>&1 | tail -3
```

Expected: 0 errors.

- [ ] **Step 8: Run tests**

```bash
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 164 passed, 38 skipped, 0 failed. No new tests yet — T9/T10 add them.

- [ ] **Step 9: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Sign.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Verify.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session): secure-default sign/verify helpers + [Obsolete] PKCS#1 v1.5

Secure helpers (recommended public surface):
- Sign/VerifyRsaPss (SHA-256 + MGF1+SHA-256 + 32-byte salt)
- Sign/VerifyEcdsa (SHA-256 over the key's curve)
- Sign/VerifyEd25519 (Ed25519 fixed-output EdDSA)
- Sign/VerifyEd448 (Ed448 fixed-output EdDSA)

Each builds the appropriate mechanism (with high-level params wrapper
for PSS) and delegates to the generic Sign/Verify path, which already
guards against insecure mechanisms via GuardMechanism.

Legacy named shortcuts with [Obsolete]:
- SignRsaPkcs1V15 / VerifyRsaPkcs1V15 — point at the PSS alternative;
  throw via the runtime gate unless AllowInsecure = true.

The generic Sign(Mechanism, ObjectHandle, ...) and overloads remain
for vendor/advanced mechanisms that don't have a named helper."
```

---

## Task 9: Sign round-trip tests (RSA-PSS, ECDSA, EdDSA, PKCS#1 v1.5 gate)

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Sign/SignRsaPssTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Sign/SignEcdsaTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Sign/SignEdDsaTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Sign/SignRsaPkcsTests.cs`

- [ ] **Step 1: Write `SignRsaPssTests.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Sign;

internal static class SignRsaPssTestCases
{
    /// <summary>SoftHSM-only round trip: generate key, sign, verify, assert valid.</summary>
    internal static void Assert_RsaPss_RoundTrip(IPkcs11Backend backend)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
        try
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes("phase-2 PSS round-trip");
            byte[] sig = session.SignRsaPss(priv, data);
            Assert.Equal(256, sig.Length); // 2048 bits / 8

            session.VerifyRsaPss(pub, data, sig, out bool isValid);
            Assert.True(isValid, "RSA-PSS round-trip should verify.");
        }
        finally
        {
            session.DestroyObject(priv);
            session.DestroyObject(pub);
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("SoftHsm")]
public sealed class SignRsaPssTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public SignRsaPssTests_SoftHsm(SoftHsmBackendFixture f) { _backend = f; }
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RsaPss_RoundTrip() => SignRsaPssTestCases.Assert_RsaPss_RoundTrip(_backend);
}
```

(No Mock-side test class — pkcs11-mock doesn't actually verify signatures, so a round-trip on the mock is meaningless. The gate behavior of the helper is covered indirectly by `InsecureOperationGateTests` since PSS is the secure path that's NOT gated.)

- [ ] **Step 2: Write `SignEcdsaTests.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Sign;

internal static class SignEcdsaTestCases
{
    internal static void Assert_Ecdsa_RoundTrip(IPkcs11Backend backend)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        var (pub, priv) = TestKeys.GenerateEcP256KeyPair(session);
        try
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes("phase-2 ECDSA round-trip");
            byte[] sig = session.SignEcdsa(priv, data);
            Assert.Equal(64, sig.Length); // 2 × 32-byte P-256 coordinates

            session.VerifyEcdsa(pub, data, sig, out bool isValid);
            Assert.True(isValid, "ECDSA round-trip should verify.");
        }
        finally
        {
            session.DestroyObject(priv);
            session.DestroyObject(pub);
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("SoftHsm")]
public sealed class SignEcdsaTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public SignEcdsaTests_SoftHsm(SoftHsmBackendFixture f) { _backend = f; }
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ecdsa_RoundTrip() => SignEcdsaTestCases.Assert_Ecdsa_RoundTrip(_backend);
}
```

- [ ] **Step 3: Write `SignEdDsaTests.cs` (covers Ed25519 + Ed448)**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Sign;

internal static class SignEdDsaTestCases
{
    internal static void Assert_Ed25519_RoundTrip(IPkcs11Backend backend)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        var (pub, priv) = TestKeys.GenerateEd25519KeyPair(session);
        try
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes("phase-2 Ed25519 round-trip");
            byte[] sig = session.SignEd25519(priv, data);
            Assert.Equal(64, sig.Length); // Ed25519 fixed signature size

            session.VerifyEd25519(pub, data, sig, out bool isValid);
            Assert.True(isValid, "Ed25519 round-trip should verify.");
        }
        finally
        {
            session.DestroyObject(priv);
            session.DestroyObject(pub);
            session.Logout();
            session.CloseSession();
        }
    }

    internal static void Assert_Ed448_RoundTrip(IPkcs11Backend backend)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        var (pub, priv) = TestKeys.GenerateEd448KeyPair(session);
        try
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes("phase-2 Ed448 round-trip");
            byte[] sig = session.SignEd448(priv, data);
            Assert.Equal(114, sig.Length); // Ed448 fixed signature size

            session.VerifyEd448(pub, data, sig, out bool isValid);
            Assert.True(isValid, "Ed448 round-trip should verify.");
        }
        finally
        {
            session.DestroyObject(priv);
            session.DestroyObject(pub);
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("SoftHsm")]
public sealed class SignEdDsaTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public SignEdDsaTests_SoftHsm(SoftHsmBackendFixture f) { _backend = f; }
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ed25519_RoundTrip() => SignEdDsaTestCases.Assert_Ed25519_RoundTrip(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ed448_RoundTrip() => SignEdDsaTestCases.Assert_Ed448_RoundTrip(_backend);
}
```

- [ ] **Step 4: Write `SignRsaPkcsTests.cs` (gate + AllowInsecure bypass)**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Sign;

internal static class SignRsaPkcsTestCases
{
    /// <summary>The [Obsolete] shortcut throws InsecureOperationException by default.</summary>
    internal static void Assert_SignRsaPkcs1V15_GatedByDefault(IPkcs11Backend backend)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var fakeKey = new ObjectHandle(0);
#pragma warning disable CS0618 // intentionally testing the obsolete API
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.SignRsaPkcs1V15(fakeKey, Array.Empty<byte>()));
#pragma warning restore CS0618
            Assert.Equal(CKM.CKM_RSA_PKCS, ex.Mechanism);
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }

    /// <summary>With AllowInsecure=true the gate is bypassed (call may fail for other reasons).</summary>
    internal static void Assert_SignRsaPkcs1V15_AllowInsecureBypassesGate(IPkcs11Backend backend)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        session.AllowInsecure = true;
        try
        {
            var fakeKey = new ObjectHandle(0);
            try
            {
#pragma warning disable CS0618
                session.SignRsaPkcs1V15(fakeKey, Array.Empty<byte>());
#pragma warning restore CS0618
            }
            catch (InsecureOperationException)
            {
                Assert.Fail("AllowInsecure=true should have suppressed the gate.");
            }
            catch
            {
                // Any other exception (Pkcs11Exception for bad key handle, etc.) is acceptable —
                // we're only asserting the gate didn't fire.
            }
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("Mock")]
public sealed class SignRsaPkcsTests_Mock
{
    private readonly MockBackendFixture _backend;
    public SignRsaPkcsTests_Mock(MockBackendFixture f) { _backend = f; }

    [Fact]
    public void SignRsaPkcs1V15_GatedByDefault() => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_GatedByDefault(_backend);

    [Fact]
    public void SignRsaPkcs1V15_AllowInsecureBypassesGate() => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_AllowInsecureBypassesGate(_backend);
}

[Collection("SoftHsm")]
public sealed class SignRsaPkcsTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public SignRsaPkcsTests_SoftHsm(SoftHsmBackendFixture f) { _backend = f; }
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignRsaPkcs1V15_GatedByDefault() => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_GatedByDefault(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignRsaPkcs1V15_AllowInsecureBypassesGate() => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_AllowInsecureBypassesGate(_backend);
}
```

- [ ] **Step 5: Build + run**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Goal: 0 errors. Mock-side tests in `SignRsaPkcsTests_Mock` (2 tests) pass. The 5 SoftHSM-only round-trip tests skip locally. No regressions in the existing 46 + 118 = 164 passing.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Sign/
git -C /home/alexandre/dev/PKCS11.NET commit -m "test(Sign): round-trip tests for RSA-PSS, ECDSA, EdDSA + PKCS#1 v1.5 gate

Round-trip tests are SoftHsm-only since pkcs11-mock doesn't implement
actual signature verification. PKCS#1 v1.5 gate-by-default and
AllowInsecure-bypass tests run on both backends (the gate fires
before any P/Invoke)."
```

---

## Task 10: Verify edge cases + tampered-signature tests + extend `InsecureOperationGateTests`

The Verify side gets dedicated edge-case tests (tampered signature, wrong key) and the cross-cutting gate-tests file gets new theory data for the signing-side mechanisms.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Verify/VerifyRsaPssTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Verify/VerifyEcdsaTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Verify/VerifyEdDsaTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Verify/VerifyRsaPkcsTests.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Security/InsecureOperationGateTests.cs`

- [ ] **Step 1: Write `VerifyRsaPssTests.cs`**

Focus: tampered-data and tampered-signature rejection. Both require SoftHSM (mock doesn't actually verify).

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Verify;

internal static class VerifyRsaPssTestCases
{
    internal static void Assert_RejectsTamperedData(IPkcs11Backend backend)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
        try
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes("original");
            byte[] sig = session.SignRsaPss(priv, data);

            byte[] tamperedData = (byte[])data.Clone();
            tamperedData[0] ^= 0xFF;

            session.VerifyRsaPss(pub, tamperedData, sig, out bool isValid);
            Assert.False(isValid, "Tampered data must not verify.");
        }
        finally
        {
            session.DestroyObject(priv);
            session.DestroyObject(pub);
            session.Logout();
            session.CloseSession();
        }
    }

    internal static void Assert_RejectsTamperedSignature(IPkcs11Backend backend)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
        try
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes("phase-2 tamper test");
            byte[] sig = session.SignRsaPss(priv, data);

            byte[] tamperedSig = (byte[])sig.Clone();
            tamperedSig[^1] ^= 0xFF;

            session.VerifyRsaPss(pub, data, tamperedSig, out bool isValid);
            Assert.False(isValid, "Tampered signature must not verify.");
        }
        finally
        {
            session.DestroyObject(priv);
            session.DestroyObject(pub);
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("SoftHsm")]
public sealed class VerifyRsaPssTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public VerifyRsaPssTests_SoftHsm(SoftHsmBackendFixture f) { _backend = f; }
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RejectsTamperedData() => VerifyRsaPssTestCases.Assert_RejectsTamperedData(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RejectsTamperedSignature() => VerifyRsaPssTestCases.Assert_RejectsTamperedSignature(_backend);
}
```

- [ ] **Step 2: Write `VerifyEcdsaTests.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Verify;

internal static class VerifyEcdsaTestCases
{
    internal static void Assert_RejectsTamperedData(IPkcs11Backend backend)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        var (pub, priv) = TestKeys.GenerateEcP256KeyPair(session);
        try
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes("phase-2 ECDSA tamper");
            byte[] sig = session.SignEcdsa(priv, data);

            byte[] tampered = (byte[])data.Clone();
            tampered[0] ^= 0xFF;

            session.VerifyEcdsa(pub, tampered, sig, out bool isValid);
            Assert.False(isValid, "Tampered data must not verify.");
        }
        finally
        {
            session.DestroyObject(priv);
            session.DestroyObject(pub);
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("SoftHsm")]
public sealed class VerifyEcdsaTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public VerifyEcdsaTests_SoftHsm(SoftHsmBackendFixture f) { _backend = f; }
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RejectsTamperedData() => VerifyEcdsaTestCases.Assert_RejectsTamperedData(_backend);
}
```

- [ ] **Step 3: Write `VerifyEdDsaTests.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Verify;

internal static class VerifyEdDsaTestCases
{
    internal static void Assert_Ed25519_RejectsTamperedData(IPkcs11Backend backend)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        var (pub, priv) = TestKeys.GenerateEd25519KeyPair(session);
        try
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes("Ed25519 tamper");
            byte[] sig = session.SignEd25519(priv, data);
            byte[] tampered = (byte[])data.Clone();
            tampered[0] ^= 0xFF;

            session.VerifyEd25519(pub, tampered, sig, out bool isValid);
            Assert.False(isValid, "Tampered data must not verify.");
        }
        finally
        {
            session.DestroyObject(priv);
            session.DestroyObject(pub);
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("SoftHsm")]
public sealed class VerifyEdDsaTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public VerifyEdDsaTests_SoftHsm(SoftHsmBackendFixture f) { _backend = f; }
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ed25519_RejectsTamperedData() => VerifyEdDsaTestCases.Assert_Ed25519_RejectsTamperedData(_backend);
}
```

- [ ] **Step 4: Write `VerifyRsaPkcsTests.cs`**

Mirror of `SignRsaPkcsTests.cs` for the Verify side:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Verify;

internal static class VerifyRsaPkcsTestCases
{
    internal static void Assert_VerifyRsaPkcs1V15_GatedByDefault(IPkcs11Backend backend)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var fakeKey = new ObjectHandle(0);
#pragma warning disable CS0618
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.VerifyRsaPkcs1V15(fakeKey, Array.Empty<byte>(), Array.Empty<byte>(), out _));
#pragma warning restore CS0618
            Assert.Equal(CKM.CKM_RSA_PKCS, ex.Mechanism);
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("Mock")]
public sealed class VerifyRsaPkcsTests_Mock
{
    private readonly MockBackendFixture _backend;
    public VerifyRsaPkcsTests_Mock(MockBackendFixture f) { _backend = f; }

    [Fact]
    public void VerifyRsaPkcs1V15_GatedByDefault() => VerifyRsaPkcsTestCases.Assert_VerifyRsaPkcs1V15_GatedByDefault(_backend);
}

[Collection("SoftHsm")]
public sealed class VerifyRsaPkcsTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public VerifyRsaPkcsTests_SoftHsm(SoftHsmBackendFixture f) { _backend = f; }
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void VerifyRsaPkcs1V15_GatedByDefault() => VerifyRsaPkcsTestCases.Assert_VerifyRsaPkcs1V15_GatedByDefault(_backend);
}
```

- [ ] **Step 5: Extend `InsecureOperationGateTests.cs` with signing-side theory data**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Security/InsecureOperationGateTests.cs`.

Find the static helper method `Assert_Encrypt_InsecureMechanismThrows` (the gate-coverage method used by the Encrypt `[Theory]`). Add a parallel `Assert_Sign_InsecureMechanismThrows`:

```csharp
    internal static void Assert_Sign_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var mech = new Mechanism((CKM)mechanismId);
            var fakeHandle = new ObjectHandle(0);
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.Sign(mech, fakeHandle, Array.Empty<byte>()));
            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            try { session.Logout(); } catch { }
            try { session.CloseSession(); } catch { }
        }
    }

    internal static void Assert_Verify_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var mech = new Mechanism((CKM)mechanismId);
            var fakeHandle = new ObjectHandle(0);
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.Verify(mech, fakeHandle, Array.Empty<byte>(), Array.Empty<byte>(), out _));
            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            try { session.Logout(); } catch { }
            try { session.CloseSession(); } catch { }
        }
    }
```

Then in the `InsecureOperationGateTests_Mock` class, add two new `[Theory]` methods:

```csharp
    [Theory]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_MD5_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_SHA1_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_DES_MAC)]
    [InlineData((ulong)CKM.CKM_DES3_MAC)]
    public void Sign_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_Sign_InsecureMechanismThrows(_backend, mech);

    [Theory]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_MD5_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_SHA1_RSA_PKCS)]
    public void Verify_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_Verify_InsecureMechanismThrows(_backend, mech);
```

And the matching `[ConditionalTheory(nameof(SoftHsmAvailable))]` blocks in `InsecureOperationGateTests_SoftHsm`.

- [ ] **Step 6: Build + run**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. The Mock-side gate tests added in this task (8 new mock-runnable assertions across the new files) all pass. SoftHsm tests skip locally. Total: ~54 passed in the Pkcs11 suite (46 from before + ~8 new gate tests), ~45+ skipped (including all the SoftHsm round-trip + tampered-data tests).

- [ ] **Step 7: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Verify/ src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Security/InsecureOperationGateTests.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "test(Verify+Security): tampered-data tests + signing-side gate coverage

Verify-side edge-case tests (tampered-data, tampered-signature) are
SoftHsm-only since pkcs11-mock doesn't authenticate. PKCS#1 v1.5
gate-by-default test runs on both backends.

InsecureOperationGateTests gets [Theory]-parameterized coverage of
the new signing-side gates: CKM_RSA_PKCS, CKM_MD5_RSA_PKCS,
CKM_SHA1_RSA_PKCS, CKM_DES_MAC, CKM_DES3_MAC for Sign; the same set
minus MAC for Verify (MAC verification uses C_VerifyInit, not a
separate gate path)."
```

---

## Task 11: Final verification + tag

**Files:** (verification only)

- [ ] **Step 1: Clean release build**

```bash
cd /home/alexandre/dev/PKCS11.NET
dotnet clean src/src.sln >/dev/null
dotnet build src/src.sln --configuration Release 2>&1 | tail -5
```

Expected: `0 Error(s)`.

- [ ] **Step 2: Final full test run**

```bash
dotnet test src/src.sln --configuration Release --no-build 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected counts (locally, with SoftHSM2 unavailable):
- `Runtime.InteropServices.Tests`: 118 passed, 1 skipped, 0 failed (unchanged)
- `Pkcs11.Tests`: ~54-56 passed (46 from phase-1-complete + 8-10 new Mock-runnable signing-gate/AllowInsecure tests), ~45+ skipped (existing SoftHsm-gated + new SoftHsm-gated round-trip + tampered-data tests), 0 failed

If failed > 0, STOP and investigate.

- [ ] **Step 3: Verify pack still works**

```bash
dotnet pack src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -c Release -p:SkipPkcs11MockBuild=true -o /tmp/pack-test 2>&1 | tail -3
ls /tmp/pack-test/
rm -rf /tmp/pack-test
```

Expected: nupkg + snupkg produced.

- [ ] **Step 4: Verify the Phase 2 exit-criteria invariants**

```bash
echo "=== Session.Sign.cs exists with all expected methods ==="
ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Sign.cs
grep -cE "public (byte\[\]|void) (Sign|SignRecover|SignEncrypt|SignRsaPss|SignEcdsa|SignEd25519|SignEd448|SignRsaPkcs1V15)\b" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Sign.cs

echo "=== Session.Verify.cs exists with all expected methods ==="
ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Verify.cs
grep -cE "public (byte\[\]|void) (Verify|VerifyRecover|DecryptVerify|VerifyRsaPss|VerifyEcdsa|VerifyEd25519|VerifyEd448|VerifyRsaPkcs1V15)\b" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Verify.cs

echo "=== Session.cs no longer has Sign/Verify methods ==="
grep -cE "public (byte\[\]|void) (Sign|SignRecover|SignEncrypt|Verify|VerifyRecover|DecryptVerify)\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs

echo "=== CkmRsaPkcsPssParams exists ==="
ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/MechanismParams/CkmRsaPkcsPssParams.cs

echo "=== New enum values present ==="
grep -cE "CKM_EDDSA\b|CKM_EC_EDWARDS_KEY_PAIR_GEN\b" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKM.cs
grep -cE "CKK_EC_EDWARDS\b" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKK.cs

echo "=== GuardMechanism extended ==="
grep -cE "CKM_MD5_RSA_PKCS|CKM_SHA1_RSA_PKCS|CKM_MD5\b|CKM_SHA_1\b|CKM_DES_MAC|CKM_DES3_MAC" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs

echo "=== Phase 2 test directories ==="
ls -d src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Sign/ src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Verify/
```

Expected outputs (all on success path):
- `Session.Sign.cs`: ≥ 17 method matches (9 Sign + 3 SignRecover + 9 SignEncrypt is 21, plus 4 secure helpers = 25; the regex matches public byte[]/void only, so SignEncrypt-returning-byte and SignEncrypt-returning-void all count).
- `Session.Verify.cs`: ≥ 8 matches.
- `Session.cs`: 0 matches for the Sign/Verify methods.
- All other ls/grep results show the expected files/values.

- [ ] **Step 5: Tag the milestone**

```bash
git -C /home/alexandre/dev/PKCS11.NET tag -a phase-2-complete -m "Phase 2 complete: Sign+Verify partial split + secure helpers + dual-backend tests

Delivered:
- Session.Sign.cs + Session.Verify.cs partials (Sign, Verify, SignRecover,
  VerifyRecover, plus combined ops SignEncrypt + DecryptVerify)
- Secure helpers: SignRsaPss, SignEcdsa, SignEd25519, SignEd448 + Verify
  counterparts (RSA-PSS/SHA-256/MGF1/32-byte-salt; ECDSA/SHA-256;
  Ed25519/Ed448 fixed-output)
- [Obsolete] SignRsaPkcs1V15 / VerifyRsaPkcs1V15 — runtime-gated
- ReadOnlySpan<byte> overloads on the generic Sign/Verify entry points
- GuardMechanism extended for signing-side insecure mechanisms:
  CKM_RSA_PKCS (sign context), CKM_MD5_RSA_PKCS, CKM_SHA1_RSA_PKCS,
  raw MD5, raw SHA_1, CKM_DES_MAC, CKM_DES3_MAC
- CkmRsaPkcsPssParams high-level wrapper class
- CKM_EDDSA, CKM_EC_EDWARDS_KEY_PAIR_GEN, CKK_EC_EDWARDS enum values
  (PKCS#11 v3.0 additions)
- TestKeys helpers for EC P-256, Ed25519, Ed448 key generation
- Tests for round-trip, tampered-data/signature, gate enforcement,
  AllowInsecure bypass — dual-backend (Mock + SoftHSM2)"
```

---

## Phase 2 Exit Checklist

- [ ] `dotnet build src/src.sln -c Release` succeeds with 0 errors.
- [ ] `dotnet test src/src.sln` shows all tests passing; new Phase 2 Mock-runnable tests are green; SoftHsm-only tests skip on dev hosts without SoftHSM2.
- [ ] `Session.Sign.cs` exists with Sign + SignRecover + SignEncrypt + Span overloads + 4 secure helpers + `[Obsolete] SignRsaPkcs1V15`.
- [ ] `Session.Verify.cs` exists with Verify + VerifyRecover + DecryptVerify + Span overloads + 4 secure helpers + `[Obsolete] VerifyRsaPkcs1V15`.
- [ ] `Session.cs` no longer contains any Sign/Verify/SignRecover/VerifyRecover/SignEncrypt/DecryptVerify method definitions.
- [ ] `GuardMechanism` covers CKM_MD5_RSA_PKCS, CKM_SHA1_RSA_PKCS, CKM_MD5, CKM_SHA_1, CKM_DES_MAC, CKM_DES3_MAC.
- [ ] `CkmRsaPkcsPssParams` wrapper exists.
- [ ] `CKM_EDDSA`, `CKM_EC_EDWARDS_KEY_PAIR_GEN`, `CKK_EC_EDWARDS` enum values present.
- [ ] `TestKeys` has GenerateEcP256KeyPair, GenerateEd25519KeyPair, GenerateEd448KeyPair.
- [ ] Test files exist under `Tests/HighLevel/Sign/` and `Tests/HighLevel/Verify/` for each helper.
- [ ] `InsecureOperationGateTests` has signing-side `[Theory]` data for both Mock and SoftHsm classes.
- [ ] Tag `phase-2-complete` exists.

When all checked, Phase 2 is complete. Phase 3 (Digest + Random) can be planned next.
