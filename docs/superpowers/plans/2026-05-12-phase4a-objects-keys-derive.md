# PKCS11.NET Phase 4a: Objects + Keys + Derive Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Carve the object-management methods (CreateObject, CopyObject, DestroyObject, GetObjectSize, GetAttributeValue ×2, SetAttributeValue, FindObjectsInit, FindObjects, FindObjectsFinal, FindAllObjects) into `Session.Objects.cs`; carve key management (GenerateKey, GenerateKeyPair, WrapKey, UnwrapKey) into `Session.Keys.cs`; carve `DeriveKey` into `Session.Derive.cs`. Add `ReadOnlySpan<byte>` overloads on the buffer-bearing methods (`WrapKey` output remains byte[], `UnwrapKey` gains Span input). Wire `GuardMechanism` into every mechanism-bearing entry point. Add secure-default key-generation helpers: `GenerateAesKey`, `GenerateRsaKeyPair`, `GenerateEcKeyPair`. Add `DeriveSharedSecretEcdh` helper. Cover with backend-parameterized tests including a parameterized mechanism matrix for `GenerateKey`.

**Architecture:** Mechanical extension of Phases 1–3. Reuse `IMechanismParams`, the `IPkcs11Backend` test plumbing, the established static-helper + per-backend-concrete test layout. New high-level wrapper `CkmEcdh1DeriveParams` for `CK_ECDH1_DERIVE_PARAMS`. No other new architectural pieces.

**Tech Stack:** C# 12 / .NET 8 + .NET 9, xUnit 2.9, `Microsoft.DotNet.XUnitExtensions` (`[ConditionalFact]`, `[ConditionalTheory]`), pkcs11-mock v2.0.0, SoftHSM2.

**Reference specs:**
- Parent: `docs/superpowers/specs/2026-05-11-pkcs11-completion-design.md`
- Phase 2: `docs/superpowers/plans/2026-05-12-phase2-sign-verify.md` (closest pattern reference for both carve + secure helpers)

**Out of scope (deferred to later phases):**
- `SecurePin` / `SecureBuffer` / `SafeHandle` adoption → Phase 4b.
- Memory-leak + thread-safety test suites → Phase 4c.
- PKCS#11 v3.1 message-based APIs (`C_*Message*`) — pkcs11-mock v2.0.0 doesn't support v3.1.
- SP800-108 KDF mechanisms (`CKM_SP800_108_COUNTER_KDF` etc.) — not in the imported `CKM` enum; specialized; will be added when a concrete use case demands them.

---

## File Structure

```
src/
├── KerckhoffsLabs.Security.Cryptography.Pkcs11/
│   └── HighLevel/
│       ├── Session.cs                                        [MODIFY — strip Objects/Keys/Derive methods]
│       ├── Session.Objects.cs                                [CREATE — partial: 10 object-management methods]
│       ├── Session.Keys.cs                                   [CREATE — partial: GenerateKey/Pair, WrapKey/UnwrapKey, Span overloads, secure key-gen helpers]
│       ├── Session.Derive.cs                                 [CREATE — partial: DeriveKey + DeriveSharedSecretEcdh helper]
│       └── MechanismParams/
│           └── CkmEcdh1DeriveParams.cs                       [CREATE — high-level wrapper for CK_ECDH1_DERIVE_PARAMS]
│
└── KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/
    └── HighLevel/
        ├── Objects/
        │   └── ObjectLifecycleTests.cs                       [CREATE — CreateObject + FindObjects + DestroyObject + GetAttributeValue round-trip]
        ├── Keys/
        │   ├── GenerateAesKeyTests.cs                        [CREATE — Mock + SoftHsm]
        │   ├── GenerateRsaKeyPairTests.cs                    [CREATE — SoftHsm only]
        │   ├── GenerateEcKeyPairTests.cs                     [CREATE — SoftHsm only]
        │   ├── WrapUnwrapKeyTests.cs                         [CREATE — AES-KEY-WRAP round-trip, SoftHsm only]
        │   └── KeyGenMechanismMatrixTests.cs                 [CREATE — [Theory] over CKM_AES_KEY_GEN, CKM_GENERIC_SECRET_KEY_GEN, etc.]
        └── Derive/
            └── DeriveSharedSecretEcdhTests.cs                [CREATE — SoftHsm only]
```

After Phase 4a, `Session.cs` retains only lifecycle + auth methods (Open/Close/Login/Logout, GetSessionInfo, GetOperationState/SetOperationState, InitPin/SetPin, CancelFunction/GetFunctionStatus, Dispose).

---

## Task 1: Carve `Session.Objects.cs` out of `Session.cs`

Pure mechanical refactor: move the 10 object-management methods into a new partial. No behavior change.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Objects.cs`

- [ ] **Step 1: Locate the methods**

```bash
grep -n "public .* (CreateObject|CopyObject|DestroyObject|GetObjectSize|GetAttributeValue|SetAttributeValue|FindObjectsInit|FindObjects|FindObjectsFinal|FindAllObjects)\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs | head -15
```

Expected (verified prior):
- `CreateObject(List<ObjectAttribute>)` → `ObjectHandle`
- `CopyObject(ObjectHandle, List<ObjectAttribute>)` → `ObjectHandle`
- `DestroyObject(ObjectHandle)` → void
- `GetObjectSize(ObjectHandle)` → `ulong`
- `GetAttributeValue(ObjectHandle, List<CKA>)` → `List<ObjectAttribute>`
- `GetAttributeValue(ObjectHandle, List<ulong>)` → `List<ObjectAttribute>`
- `SetAttributeValue(ObjectHandle, List<ObjectAttribute>)` → void
- `FindObjectsInit(List<ObjectAttribute>)` → void
- `FindObjects(int objectCount)` → `List<ObjectHandle>`
- `FindObjectsFinal()` → void
- `FindAllObjects(List<ObjectAttribute>)` → `List<ObjectHandle>`

Total: 11 public methods. If counts differ, STOP and report. Bring along any `protected` helpers.

- [ ] **Step 2: Create Session.Objects.cs scaffold**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
{
    // Object-management methods inserted here
}
```

Add `using KerckhoffsLabs.Runtime.InteropServices;` if any moved method directly references `NativeCULong`.

- [ ] **Step 3: Move methods verbatim, top-down**

Cut each method's full XML doc block + body from `Session.cs`, paste into `Session.Objects.cs` inside the partial body. No modifications.

- [ ] **Step 4: Build**

```bash
dotnet build src/src.sln 2>&1 | tail -3
```

Expected: 0 errors.

- [ ] **Step 5: Tests**

```bash
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 181 passed (118 + 63), 61 skipped, 0 failed — unchanged from phase-3-complete.

- [ ] **Step 6: Verify carve scope**

```bash
echo "=== Session.cs no longer has Object methods ==="
grep -cE "public .* (CreateObject|CopyObject|DestroyObject|GetObjectSize|GetAttributeValue|SetAttributeValue|FindObjectsInit|FindObjects|FindObjectsFinal|FindAllObjects)\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
echo "=== Session.Objects.cs has them all ==="
grep -cE "public .* (CreateObject|CopyObject|DestroyObject|GetObjectSize|GetAttributeValue|SetAttributeValue|FindObjectsInit|FindObjects|FindObjectsFinal|FindAllObjects)\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Objects.cs
```

Expected: 0 in Session.cs, 11 in Session.Objects.cs.

- [ ] **Step 7: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Objects.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "refactor(Session): carve object-management methods into Session.Objects.cs

Pure relocation: CreateObject, CopyObject, DestroyObject, GetObjectSize,
GetAttributeValue (2 overloads), SetAttributeValue, FindObjectsInit,
FindObjects, FindObjectsFinal, FindAllObjects. No behavior change."
```

---

## Task 2: Carve `Session.Keys.cs` out of `Session.cs`

Same mechanical refactor for the key-management methods.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Keys.cs`

- [ ] **Step 1: Locate the methods**

```bash
grep -n "public .* (GenerateKey|GenerateKeyPair|WrapKey|UnwrapKey)\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs | head
```

Expected:
- `GenerateKey(Mechanism, List<ObjectAttribute>)` → `ObjectHandle`
- `GenerateKeyPair(Mechanism, List<ObjectAttribute>, List<ObjectAttribute>, out ObjectHandle, out ObjectHandle)` → void
- `WrapKey(Mechanism, ObjectHandle, ObjectHandle)` → `byte[]`
- `UnwrapKey(Mechanism, ObjectHandle, byte[], List<ObjectAttribute>)` → `ObjectHandle`

Total: 4 public methods.

- [ ] **Step 2: Create Session.Keys.cs scaffold**

```csharp
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
{
    // Key-management methods inserted here
}
```

- [ ] **Step 3: Move methods verbatim**

- [ ] **Step 4: Build + test**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. 181 / 61 / 0 unchanged.

- [ ] **Step 5: Verify carve scope**

```bash
grep -cE "public .* (GenerateKey|GenerateKeyPair|WrapKey|UnwrapKey)\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
grep -cE "public .* (GenerateKey|GenerateKeyPair|WrapKey|UnwrapKey)\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Keys.cs
```

Expected: 0 in Session.cs, 4 in Session.Keys.cs.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Keys.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "refactor(Session): carve key-management methods into Session.Keys.cs

Pure relocation: GenerateKey, GenerateKeyPair, WrapKey, UnwrapKey.
Sets up T4 (GuardMechanism wiring), T5 (Span overloads), and T6
(secure-default key-gen helpers)."
```

---

## Task 3: Carve `Session.Derive.cs` out of `Session.cs`

Single-method carve for `DeriveKey`.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Derive.cs`

- [ ] **Step 1: Locate the method**

```bash
grep -n "public .* DeriveKey\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
```

Expected: 1 `DeriveKey(Mechanism, ObjectHandle, List<ObjectAttribute>)` → `ObjectHandle`.

- [ ] **Step 2: Create Session.Derive.cs scaffold**

```csharp
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
{
    // DeriveKey moved here
}
```

- [ ] **Step 3: Move verbatim**

- [ ] **Step 4: Build + test**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. 181 / 61 / 0.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Derive.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "refactor(Session): carve DeriveKey into Session.Derive.cs

Pure relocation. Sets up T7 (DeriveSharedSecretEcdh helper)."
```

---

## Task 4: Wire `GuardMechanism` into Keys + Derive entry points + add `ReadOnlySpan<byte>` UnwrapKey overload

The newly carved Session.Keys.cs has 4 methods, all mechanism-bearing. Session.Derive.cs has 1 method (DeriveKey), mechanism-bearing. Wire `GuardMechanism((CKM)mechanism.Type)` into each.

Also add a `ReadOnlySpan<byte>` overload of `UnwrapKey` that takes the wrapped-key bytes as Span.

CreateObject does NOT take a mechanism, so no gating there. (Per-attribute gating, e.g., rejecting CKK_DES in CKA_KEY_TYPE, is a different design problem and is deferred — the user can pass through any attribute set via the explicit-template API.)

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Keys.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Derive.cs`

- [ ] **Step 1: Add `ReadOnlySpan<byte>` overload of UnwrapKey above the existing byte[] overload**

```csharp
    /// <summary>
    /// Unwraps a wrapped key using the given unwrapping key and mechanism. Throws
    /// <see cref="InsecureOperationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">Key-unwrap mechanism.</param>
    /// <param name="unwrappingKeyHandle">Handle of the unwrapping key (private RSA, AES-WRAP key, etc.).</param>
    /// <param name="wrappedKey">Wrapped key bytes to unwrap.</param>
    /// <param name="attributes">Template for the resulting unwrapped key.</param>
    /// <returns>Handle of the newly unwrapped key.</returns>
    public ObjectHandle UnwrapKey(Mechanism mechanism, ObjectHandle unwrappingKeyHandle, ReadOnlySpan<byte> wrappedKey, List<ObjectAttribute> attributes)
    {
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(unwrappingKeyHandle);
        ArgumentNullException.ThrowIfNull(attributes);
        // Temporary array for the byte[]-based P/Invoke path. Replace with pinned-Span
        // P/Invoke when perf profiling proves it matters.
        byte[] buffer = wrappedKey.ToArray();
        return UnwrapKey(mechanism, unwrappingKeyHandle, buffer, attributes);
    }
```

- [ ] **Step 2: Insert GuardMechanism into Session.Keys.cs methods**

For each of `GenerateKey`, `GenerateKeyPair`, `WrapKey`, `UnwrapKey(byte[])` (NOT the Span overload — it delegates):

Ordering pattern from Phase 2 T6:
1. Disposed check (existing)
2. Mechanism null-check (move above logger if needed)
3. Other null-checks (key handle, attributes, etc.)
4. **`GuardMechanism((CKM)mechanism.Type);`** — NEW
5. Logger
6. Rest of body

If a method already uses `if (mechanism == null) throw new ArgumentNullException("mechanism");` style, preserve it; just move it above the logger and add the GuardMechanism call.

- [ ] **Step 3: Insert GuardMechanism into Session.Derive.cs**

Same pattern for `DeriveKey`:
1. Disposed check
2. `mechanism` null-check
3. `baseKeyHandle` null-check
4. `attributes` null-check
5. **`GuardMechanism((CKM)mechanism.Type);`**
6. Logger
7. Rest of body

- [ ] **Step 4: Build**

```bash
dotnet build src/src.sln 2>&1 | tail -3
```

Expected: 0 errors.

- [ ] **Step 5: Tests**

```bash
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 181 / 61 / 0 — no test currently uses an insecure key-gen / wrap / derive mechanism.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Keys.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Derive.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session.Keys+Derive): wire GuardMechanism + add ReadOnlySpan<byte> UnwrapKey

GuardMechanism now fires from GenerateKey, GenerateKeyPair, WrapKey,
UnwrapKey, and DeriveKey before any P/Invoke. Insecure key-gen
mechanisms (e.g. CKM_DES_KEY_GEN, CKM_DES3_KEY_GEN if a test added
them) and insecure key-wrap mechanisms (e.g. CKM_DES3_ECB_ENCRYPT_DATA)
throw InsecureOperationException unless AllowInsecure = true.

UnwrapKey gains a ReadOnlySpan<byte> wrapped-key overload that
delegates to the byte[] path via .ToArray(); the byte[] path remains
for callers who already have a heap-allocated buffer."
```

---

## Task 5: Extend `GuardMechanism` with key-gen and key-wrap insecure mechanisms

Adds DES/3DES key-generation + key-wrap variants to the runtime gate so the new Keys/Derive wiring actually has insecure targets to reject.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`

- [ ] **Step 1: Verify the relevant CKM values exist**

```bash
grep -nE "CKM_DES_KEY_GEN\b|CKM_DES2_KEY_GEN\b|CKM_DES3_KEY_GEN\b|CKM_DES3_ECB_ENCRYPT_DATA\b|CKM_DES3_CBC_ENCRYPT_DATA\b" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/CKM.cs | head
```

All should exist. If any are missing, surface that — add them only if absolutely needed by the secure helpers (T6 — we don't add DES/3DES helpers, so this is purely about rejecting the values if a caller passes them).

- [ ] **Step 2: Extend `GuardMechanism`**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`. Locate `private void GuardMechanism(CKM mechanism)`. Add a new case group BEFORE the `case CKM.CKM_AES_ECB:` line:

```csharp
            case CKM.CKM_DES_KEY_GEN:
            case CKM.CKM_DES2_KEY_GEN:
            case CKM.CKM_DES3_KEY_GEN:
                throw new InsecureOperationException(mechanism,
                    "DES and 3DES key generation produces deprecated keys; use CKM_AES_KEY_GEN instead.");
            case CKM.CKM_DES3_ECB_ENCRYPT_DATA:
            case CKM.CKM_DES3_CBC_ENCRYPT_DATA:
                throw new InsecureOperationException(mechanism,
                    "DES3 key-derive mechanisms are weak; use CKM_SP800_108-family KDFs or CKM_AES_CBC_ENCRYPT_DATA on a strong base key instead.");
```

If any referenced CKM value doesn't exist, drop that specific case label rather than fabricating values. Note the actual omission in the commit message.

- [ ] **Step 3: Build + test**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. 181 / 61 / 0.

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session.GuardMechanism): add DES/3DES key-gen + key-derive mechanisms

Closes the gap for CKM_DES_KEY_GEN, CKM_DES2_KEY_GEN, CKM_DES3_KEY_GEN
(key-pair generation paths) and CKM_DES3_ECB_ENCRYPT_DATA /
CKM_DES3_CBC_ENCRYPT_DATA (key-derive paths). Now that Phase 4a wires
GuardMechanism through GenerateKey / GenerateKeyPair / WrapKey /
UnwrapKey / DeriveKey, these mechanisms are rejected at the entry."
```

---

## Task 6: Secure-default key-generation helpers

Adds `GenerateAesKey`, `GenerateRsaKeyPair`, `GenerateEcKeyPair` on `Session`. Each applies the secure-defaults policy from CLAUDE.md: `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`, `CKA_TOKEN` defaulting to `false` (session-only) unless explicitly overridden.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Keys.cs`

- [ ] **Step 1: Append `GenerateAesKey` to Session.Keys.cs**

Above the closing `}` of the partial:

```csharp
    // === Secure-default key-generation helpers =============================

    /// <summary>
    /// Generates an AES key of the specified bit length as a session-only, non-extractable,
    /// sensitive secret key. Defaults to 256-bit AES.
    /// </summary>
    /// <param name="bitLength">Key length in bits — 128, 192, or 256. Default 256.</param>
    /// <param name="label">Optional CKA_LABEL value. Defaults to none.</param>
    /// <param name="persistOnToken">If true, the key is created with CKA_TOKEN=true (persistent). Default false (session-only).</param>
    /// <returns>Handle of the new AES key.</returns>
    public ObjectHandle GenerateAesKey(int bitLength = 256, string? label = null, bool persistOnToken = false)
    {
        if (bitLength != 128 && bitLength != 192 && bitLength != 256)
            throw new ArgumentOutOfRangeException(nameof(bitLength), "AES key length must be 128, 192, or 256 bits.");

        using var mechanism = new Mechanism(CKM.CKM_AES_KEY_GEN);

        using var attrClass     = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrKeyType   = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var attrValueLen  = new ObjectAttribute(CKA.CKA_VALUE_LEN, (ulong)(bitLength / 8));
        using var attrToken     = new ObjectAttribute(CKA.CKA_TOKEN, persistOnToken);
        using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var attrExtract   = new ObjectAttribute(CKA.CKA_EXTRACTABLE, false);
        using var attrEncrypt   = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var attrDecrypt   = new ObjectAttribute(CKA.CKA_DECRYPT, true);
        using var attrWrap      = new ObjectAttribute(CKA.CKA_WRAP, true);
        using var attrUnwrap    = new ObjectAttribute(CKA.CKA_UNWRAP, true);

        var template = new List<ObjectAttribute> { attrClass, attrKeyType, attrValueLen, attrToken, attrSensitive, attrExtract, attrEncrypt, attrDecrypt, attrWrap, attrUnwrap };
        if (label is not null)
        {
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            template.Add(attrLabel);
            return GenerateKey(mechanism, template);
        }

        return GenerateKey(mechanism, template);
    }
```

Note the awkward branching on `label is not null` — the `attrLabel` must stay alive (via `using var`) until after the `GenerateKey` call. The simpler version (always create `attrLabel`, but with an empty string when null) is less correct because some backends reject empty labels. The double `return` pattern keeps the using scope tight.

- [ ] **Step 2: Append `GenerateRsaKeyPair`**

```csharp
    /// <summary>
    /// Generates an RSA key pair as session objects (private key non-extractable + sensitive,
    /// CKA_TOKEN=false). Defaults to RSA-2048 with the standard exponent 65537.
    /// </summary>
    /// <param name="modulusBits">Modulus length in bits — must be ≥ 2048 (PKCS#11 recommends ≥ 2048 since the 2014 update). Default 2048.</param>
    /// <param name="label">Optional CKA_LABEL value applied to BOTH public and private key. Defaults to none.</param>
    /// <param name="persistOnToken">If true, both keys created with CKA_TOKEN=true. Default false.</param>
    /// <returns>(publicKeyHandle, privateKeyHandle) tuple.</returns>
    public (ObjectHandle pub, ObjectHandle priv) GenerateRsaKeyPair(int modulusBits = 2048, string? label = null, bool persistOnToken = false)
    {
        if (modulusBits < 2048)
            throw new ArgumentOutOfRangeException(nameof(modulusBits), "RSA modulus must be ≥ 2048 bits (NIST SP 800-131A).");

        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

        using var pubClass    = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubKeyType  = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var pubToken    = new ObjectAttribute(CKA.CKA_TOKEN, persistOnToken);
        using var pubEncrypt  = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var pubVerify   = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var pubWrap     = new ObjectAttribute(CKA.CKA_WRAP, true);
        using var pubModBits  = new ObjectAttribute(CKA.CKA_MODULUS_BITS, (ulong)modulusBits);
        using var pubExp      = new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 });

        using var privClass     = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privKeyType   = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var privToken     = new ObjectAttribute(CKA.CKA_TOKEN, persistOnToken);
        using var privSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privExtract   = new ObjectAttribute(CKA.CKA_EXTRACTABLE, false);
        using var privDecrypt   = new ObjectAttribute(CKA.CKA_DECRYPT, true);
        using var privSign      = new ObjectAttribute(CKA.CKA_SIGN, true);
        using var privUnwrap    = new ObjectAttribute(CKA.CKA_UNWRAP, true);

        var pubTemplate  = new List<ObjectAttribute> { pubClass, pubKeyType, pubToken, pubEncrypt, pubVerify, pubWrap, pubModBits, pubExp };
        var privTemplate = new List<ObjectAttribute> { privClass, privKeyType, privToken, privSensitive, privExtract, privDecrypt, privSign, privUnwrap };

        if (label is not null)
        {
            using var pubLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            using var privLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            pubTemplate.Add(pubLabel);
            privTemplate.Add(privLabel);
            GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub, out var priv);
            return (pub, priv);
        }

        GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub2, out var priv2);
        return (pub2, priv2);
    }
```

- [ ] **Step 3: Append `GenerateEcKeyPair`**

```csharp
    /// <summary>
    /// Generates an EC key pair on the named curve as session objects (private key
    /// non-extractable + sensitive, CKA_TOKEN=false).
    /// </summary>
    /// <param name="curve">Named curve — currently supports <see cref="EcCurve.P256"/>, <see cref="EcCurve.P384"/>, <see cref="EcCurve.P521"/>. Default P-256.</param>
    /// <param name="label">Optional CKA_LABEL applied to both keys.</param>
    /// <param name="persistOnToken">If true, both keys created with CKA_TOKEN=true. Default false.</param>
    /// <returns>(publicKeyHandle, privateKeyHandle) tuple.</returns>
    public (ObjectHandle pub, ObjectHandle priv) GenerateEcKeyPair(EcCurve curve = EcCurve.P256, string? label = null, bool persistOnToken = false)
    {
        byte[] ecParams = curve switch
        {
            // prime256v1 (P-256): 1.2.840.10045.3.1.7
            EcCurve.P256 => new byte[] { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 },
            // secp384r1 (P-384): 1.3.132.0.34
            EcCurve.P384 => new byte[] { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 },
            // secp521r1 (P-521): 1.3.132.0.35
            EcCurve.P521 => new byte[] { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 },
            _ => throw new ArgumentOutOfRangeException(nameof(curve), $"Unsupported curve: {curve}."),
        };

        using var mechanism = new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN);

        using var pubClass    = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubKeyType  = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
        using var pubToken    = new ObjectAttribute(CKA.CKA_TOKEN, persistOnToken);
        using var pubVerify   = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var pubParams   = new ObjectAttribute(CKA.CKA_EC_PARAMS, ecParams);

        using var privClass     = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privKeyType   = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
        using var privToken     = new ObjectAttribute(CKA.CKA_TOKEN, persistOnToken);
        using var privSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privExtract   = new ObjectAttribute(CKA.CKA_EXTRACTABLE, false);
        using var privSign      = new ObjectAttribute(CKA.CKA_SIGN, true);
        using var privDerive    = new ObjectAttribute(CKA.CKA_DERIVE, true);

        var pubTemplate  = new List<ObjectAttribute> { pubClass, pubKeyType, pubToken, pubVerify, pubParams };
        var privTemplate = new List<ObjectAttribute> { privClass, privKeyType, privToken, privSensitive, privExtract, privSign, privDerive };

        if (label is not null)
        {
            using var pubLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            using var privLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            pubTemplate.Add(pubLabel);
            privTemplate.Add(privLabel);
            GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub, out var priv);
            return (pub, priv);
        }

        GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub2, out var priv2);
        return (pub2, priv2);
    }
```

- [ ] **Step 4: Add `EcCurve` enum (new file, since it's a public type)**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/EcCurve.cs`:

```csharp
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Named curves supported by the <see cref="Session.GenerateEcKeyPair"/> secure helper.
/// Vendor-specific or less common curves can still be generated via <see cref="Session.GenerateKeyPair"/>
/// with an explicit <c>CKA_EC_PARAMS</c> attribute.
/// </summary>
public enum EcCurve
{
    /// <summary>secp256r1 / prime256v1 / P-256 (FIPS 186-4). Recommended for most use cases.</summary>
    P256,
    /// <summary>secp384r1 / P-384 (FIPS 186-4).</summary>
    P384,
    /// <summary>secp521r1 / P-521 (FIPS 186-4).</summary>
    P521,
}
```

- [ ] **Step 5: Build + test**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. 181 / 61 / 0.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Keys.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/EcCurve.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session.Keys): secure-default key-generation helpers + EcCurve enum

Secure-default helpers (recommended public surface):
- GenerateAesKey(bitLength = 256) — CKA_SENSITIVE=true, CKA_EXTRACTABLE=false,
  CKA_TOKEN=false by default. Rejects key lengths other than 128/192/256.
- GenerateRsaKeyPair(modulusBits = 2048) — rejects < 2048. Public exponent
  fixed at 65537. CKA_SENSITIVE/CKA_EXTRACTABLE on the private key.
- GenerateEcKeyPair(curve = P256) — accepts a P-256/P-384/P-521 enum;
  vendor curves still require the explicit GenerateKeyPair API.

Each helper delegates to the generic GenerateKey/Pair path which fires
GuardMechanism. Each accepts an optional CKA_LABEL and a persistOnToken
escape hatch."
```

---

## Task 7: `CkmEcdh1DeriveParams` wrapper + `DeriveSharedSecretEcdh` helper

ECDH key derivation uses `CK_ECDH1_DERIVE_PARAMS`. Phase 1 / 2 established the IMechanismParams wrapper pattern; apply it here.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/MechanismParams/CkmEcdh1DeriveParams.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Derive.cs`

- [ ] **Step 1: Inspect `CK_ECDH1_DERIVE_PARAMS` field names**

```bash
cat src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/MechanismParams/CK_ECDH1_DERIVE_PARAMS.cs
```

Expected fields (typical): `Kdf` (NativeCULong), `SharedDataLen`, `SharedData` (IntPtr), `PublicDataLen`, `PublicData` (IntPtr). Confirm naming; the wrapper must use the exact field names of the actual struct.

- [ ] **Step 2: Create `CkmEcdh1DeriveParams.cs`**

```csharp
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_ECDH1_DERIVE_PARAMS"/>. Owns the unmanaged
/// buffers for the peer's public point and the optional shared data.
/// Dispose this instance AFTER the <see cref="Mechanism"/> that holds a reference
/// to it has been disposed.
/// </summary>
public sealed class CkmEcdh1DeriveParams : IMechanismParams
{
    private CK_ECDH1_DERIVE_PARAMS _lowLevelParams;
    private IntPtr _publicData;
    private IntPtr _sharedData;
    private bool _disposed;

    /// <summary>
    /// Initializes ECDH1-derive parameters.
    /// </summary>
    /// <param name="kdf">Key derivation function (typically <see cref="CKD.CKD_SHA256_KDF"/> or stronger). Use <see cref="CKD.CKD_NULL"/> only if the caller will derive separately.</param>
    /// <param name="peerPublicPoint">DER-encoded OCTET STRING of the peer's public EC point (the full <c>CKA_EC_POINT</c> value).</param>
    /// <param name="sharedData">Optional shared data to mix into the KDF; pass <c>default</c> for none.</param>
    public CkmEcdh1DeriveParams(CKD kdf, ReadOnlySpan<byte> peerPublicPoint, ReadOnlySpan<byte> sharedData = default)
    {
        if (peerPublicPoint.IsEmpty)
            throw new ArgumentException("Peer public point must not be empty.", nameof(peerPublicPoint));

        _publicData = UnmanagedMemory.Allocate(peerPublicPoint.Length);
        UnmanagedMemory.Write(_publicData, peerPublicPoint);

        if (!sharedData.IsEmpty)
        {
            _sharedData = UnmanagedMemory.Allocate(sharedData.Length);
            UnmanagedMemory.Write(_sharedData, sharedData);
        }

        _lowLevelParams = new CK_ECDH1_DERIVE_PARAMS
        {
            Kdf = kdf.ToCULong(),
            SharedData = _sharedData,
            SharedDataLen = (NativeCULong)sharedData.Length,
            PublicData = _publicData,
            PublicDataLen = (NativeCULong)peerPublicPoint.Length,
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
        UnmanagedMemory.Free(ref _publicData);
        UnmanagedMemory.Free(ref _sharedData);
        _lowLevelParams.PublicData = IntPtr.Zero;
        _lowLevelParams.SharedData = IntPtr.Zero;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmEcdh1DeriveParams() => Dispose();
}
```

**If** the actual `CK_ECDH1_DERIVE_PARAMS` struct uses different field names (e.g., `pPublicData` instead of `PublicData`), adjust the assignments to match. Surface the discrepancy in the commit message.

- [ ] **Step 3: Add `DeriveSharedSecretEcdh` helper to Session.Derive.cs**

Above the closing `}` of the partial:

```csharp
    // === Secure-default derive helpers =====================================

    /// <summary>
    /// Performs ECDH1 key derivation using the caller's EC private key and the peer's public
    /// point. The derived key is a session-only sensitive secret key suitable for use with
    /// AES-GCM / ChaCha20-Poly1305 (default 32 bytes, KDF=SHA-256 — pass <paramref name="aesBitLength"/>
    /// to change the output length).
    /// </summary>
    /// <param name="myPrivateKeyHandle">Handle of the caller's EC private key (CKA_DERIVE=true).</param>
    /// <param name="peerPublicPoint">DER-encoded OCTET STRING of the peer's public EC point.</param>
    /// <param name="aesBitLength">Derived AES key length in bits — 128, 192, or 256. Default 256.</param>
    /// <returns>Handle of the derived AES key.</returns>
    public ObjectHandle DeriveSharedSecretEcdh(ObjectHandle myPrivateKeyHandle, ReadOnlySpan<byte> peerPublicPoint, int aesBitLength = 256)
    {
        if (aesBitLength != 128 && aesBitLength != 192 && aesBitLength != 256)
            throw new ArgumentOutOfRangeException(nameof(aesBitLength), "AES key length must be 128, 192, or 256 bits.");

        using var p = new MechanismParams.CkmEcdh1DeriveParams(CKD.CKD_SHA256_KDF, peerPublicPoint);
        using var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, p);

        using var attrClass     = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrKeyType   = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var attrValueLen  = new ObjectAttribute(CKA.CKA_VALUE_LEN, (ulong)(aesBitLength / 8));
        using var attrToken     = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var attrExtract   = new ObjectAttribute(CKA.CKA_EXTRACTABLE, false);
        using var attrEncrypt   = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var attrDecrypt   = new ObjectAttribute(CKA.CKA_DECRYPT, true);

        var template = new List<ObjectAttribute> { attrClass, attrKeyType, attrValueLen, attrToken, attrSensitive, attrExtract, attrEncrypt, attrDecrypt };
        return DeriveKey(mechanism, myPrivateKeyHandle, template);
    }
```

- [ ] **Step 4: Build + test**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. 181 / 61 / 0.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/MechanismParams/CkmEcdh1DeriveParams.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Derive.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session.Derive): CkmEcdh1DeriveParams wrapper + DeriveSharedSecretEcdh

CkmEcdh1DeriveParams: typed builder for CK_ECDH1_DERIVE_PARAMS, owns
the unmanaged buffers for peer-public-point and optional shared data.
Same Dispose lifecycle as the other Phase 1+2 MechanismParams wrappers.

DeriveSharedSecretEcdh: secure ECDH1 helper. Defaults to AES-256 with
SHA-256 KDF; the derived key is session-only, sensitive, non-extractable.
Callers who want raw shared-secret bytes (no built-in KDF) use the
generic DeriveKey API with CKD.CKD_NULL."
```

---

## Task 8: Object lifecycle tests

End-to-end CreateObject → SetAttributeValue → GetAttributeValue → FindObjects → DestroyObject coverage.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Objects/ObjectLifecycleTests.cs`

- [ ] **Step 1: Write the file**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Objects;

internal static class ObjectLifecycleTestCases
{
    /// <summary>SoftHSM-only: create a data object, find it by label, destroy it.</summary>
    internal static void Assert_CreateFindDestroy_DataObject(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            string label = "phase-4a-test-" + Guid.NewGuid().ToString("N");
            byte[] value = System.Text.Encoding.UTF8.GetBytes("phase-4a object lifecycle");

            using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
            using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, value);
            var template = new List<ObjectAttribute> { attrClass, attrToken, attrLabel, attrValue };

            ObjectHandle created = session.CreateObject(template);
            try
            {
                // Find it back by label.
                using var findClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
                using var findLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
                var found = session.FindAllObjects(new List<ObjectAttribute> { findClass, findLabel });
                Assert.Single(found);

                // GetAttributeValue retrieves the value.
                var attrs = session.GetAttributeValue(found[0], new List<CKA> { CKA.CKA_VALUE });
                Assert.Single(attrs);
                Assert.Equal(value, attrs[0].GetValueAsByteArray());
            }
            finally
            {
                session.DestroyObject(created);
            }

            // After destroy, the same Find returns empty.
            using var verifyClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
            using var verifyLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            var afterDestroy = session.FindAllObjects(new List<ObjectAttribute> { verifyClass, verifyLabel });
            Assert.Empty(afterDestroy);
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("SoftHsm")]
public sealed class ObjectLifecycleTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void CreateFindDestroy_DataObject() => ObjectLifecycleTestCases.Assert_CreateFindDestroy_DataObject(_backend);
}
```

No Mock concrete class — pkcs11-mock's CreateObject returns a fixed handle and FindObjects has limited fidelity; the round-trip semantics here need SoftHSM.

If `ObjectAttribute.GetValueAsByteArray()` doesn't exist with that exact name (might be `GetValueAsByteArray` vs `ValueAsByteArray` or a different accessor), find the right method by reading `src/.../HighLevel/ObjectAttribute.cs`.

- [ ] **Step 2: Build + run**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. New SoftHsm test (1) skips locally. Mock counts unchanged.

- [ ] **Step 3: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Objects/
git -C /home/alexandre/dev/PKCS11.NET commit -m "test(Objects): CreateObject + FindObjects + GetAttributeValue + DestroyObject round-trip

End-to-end object lifecycle test, SoftHsm-only because pkcs11-mock's
object store is too minimal to verify the find-after-create semantics."
```

---

## Task 9: Key-generation helper tests

Covers GenerateAesKey, GenerateRsaKeyPair, GenerateEcKeyPair, plus argument-validation paths that run on both backends.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Keys/GenerateAesKeyTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Keys/GenerateRsaKeyPairTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Keys/GenerateEcKeyPairTests.cs`

- [ ] **Step 1: Write `GenerateAesKeyTests.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Keys;

internal static class GenerateAesKeyTestCases
{
    internal static void Assert_RejectsWrongBitLength(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => session.GenerateAesKey(bitLength: 64));
            Assert.Throws<ArgumentOutOfRangeException>(() => session.GenerateAesKey(bitLength: 100));
            Assert.Throws<ArgumentOutOfRangeException>(() => session.GenerateAesKey(bitLength: 512));
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }

    internal static void Assert_GeneratesAes256Key(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle key = session.GenerateAesKey(bitLength: 256);
            try
            {
                Assert.NotNull(key);
                // Verify the generated key reports CKA_VALUE_LEN = 32 bytes.
                var attrs = session.GetAttributeValue(key, new List<CKA> { CKA.CKA_VALUE_LEN });
                Assert.Single(attrs);
                Assert.Equal(32UL, attrs[0].GetValueAsUlong());
            }
            finally
            {
                session.DestroyObject(key);
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
public sealed class GenerateAesKeyTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void RejectsWrongBitLength() => GenerateAesKeyTestCases.Assert_RejectsWrongBitLength(_backend);
}

[Collection("SoftHsm")]
public sealed class GenerateAesKeyTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RejectsWrongBitLength() => GenerateAesKeyTestCases.Assert_RejectsWrongBitLength(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GeneratesAes256Key() => GenerateAesKeyTestCases.Assert_GeneratesAes256Key(_backend);
}
```

If `ObjectAttribute.GetValueAsUlong()` doesn't exist with that exact name, find the canonical accessor in `ObjectAttribute.cs` and use it.

- [ ] **Step 2: Write `GenerateRsaKeyPairTests.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Keys;

internal static class GenerateRsaKeyPairTestCases
{
    internal static void Assert_RejectsTooSmallModulus(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => session.GenerateRsaKeyPair(modulusBits: 1024));
            Assert.Throws<ArgumentOutOfRangeException>(() => session.GenerateRsaKeyPair(modulusBits: 0));
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }

    internal static void Assert_GeneratesRsa2048KeyPair(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = session.GenerateRsaKeyPair(modulusBits: 2048);
            try
            {
                Assert.NotNull(pub);
                Assert.NotNull(priv);
            }
            finally
            {
                session.DestroyObject(priv);
                session.DestroyObject(pub);
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
public sealed class GenerateRsaKeyPairTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void RejectsTooSmallModulus() => GenerateRsaKeyPairTestCases.Assert_RejectsTooSmallModulus(_backend);
}

[Collection("SoftHsm")]
public sealed class GenerateRsaKeyPairTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RejectsTooSmallModulus() => GenerateRsaKeyPairTestCases.Assert_RejectsTooSmallModulus(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GeneratesRsa2048KeyPair() => GenerateRsaKeyPairTestCases.Assert_GeneratesRsa2048KeyPair(_backend);
}
```

- [ ] **Step 3: Write `GenerateEcKeyPairTests.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Keys;

internal static class GenerateEcKeyPairTestCases
{
    internal static void Assert_GeneratesP256KeyPair(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = session.GenerateEcKeyPair(curve: EcCurve.P256);
            try
            {
                Assert.NotNull(pub);
                Assert.NotNull(priv);
            }
            finally
            {
                session.DestroyObject(priv);
                session.DestroyObject(pub);
            }
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("SoftHsm")]
public sealed class GenerateEcKeyPairTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GeneratesP256KeyPair() => GenerateEcKeyPairTestCases.Assert_GeneratesP256KeyPair(_backend);
}
```

- [ ] **Step 4: Build + run**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. 2 new Mock-runnable tests pass (RejectsWrongBitLength + RejectsTooSmallModulus). SoftHsm tests skip.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Keys/
git -C /home/alexandre/dev/PKCS11.NET commit -m "test(Keys): argument-validation + round-trip tests for secure key-gen helpers

Mock-runnable: argument-validation tests (wrong bit length, wrong
modulus size). SoftHsm-only: actual key-pair generation against the
backend."
```

---

## Task 10: Wrap/Unwrap + Derive tests

End-to-end key-wrap (AES-KEY-WRAP-PAD) round-trip and ECDH shared-secret derivation.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Keys/WrapUnwrapKeyTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Derive/DeriveSharedSecretEcdhTests.cs`

- [ ] **Step 1: Write `WrapUnwrapKeyTests.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Keys;

internal static class WrapUnwrapKeyTestCases
{
    internal static void Assert_AesKeyWrapPad_RoundTrip(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle kek = session.GenerateAesKey(bitLength: 256);
            ObjectHandle dataKey = session.GenerateAesKey(bitLength: 256);
            try
            {
                using var wrapMech = new Mechanism(CKM.CKM_AES_KEY_WRAP_PAD);
                byte[] wrapped = session.WrapKey(wrapMech, kek, dataKey);
                Assert.NotEmpty(wrapped);

                // Unwrap into a fresh handle.
                using var attrClass     = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                using var attrKeyType   = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
                using var attrToken     = new ObjectAttribute(CKA.CKA_TOKEN, false);
                using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
                using var attrExtract   = new ObjectAttribute(CKA.CKA_EXTRACTABLE, false);
                using var attrEncrypt   = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
                using var attrDecrypt   = new ObjectAttribute(CKA.CKA_DECRYPT, true);
                var template = new List<ObjectAttribute> { attrClass, attrKeyType, attrToken, attrSensitive, attrExtract, attrEncrypt, attrDecrypt };

                ObjectHandle unwrapped = session.UnwrapKey(wrapMech, kek, wrapped, template);
                try
                {
                    Assert.NotNull(unwrapped);
                }
                finally
                {
                    session.DestroyObject(unwrapped);
                }
            }
            finally
            {
                session.DestroyObject(dataKey);
                session.DestroyObject(kek);
            }
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("SoftHsm")]
public sealed class WrapUnwrapKeyTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesKeyWrapPad_RoundTrip() => WrapUnwrapKeyTestCases.Assert_AesKeyWrapPad_RoundTrip(_backend);
}
```

- [ ] **Step 2: Write `DeriveSharedSecretEcdhTests.cs`**

ECDH between two ephemeral P-256 key pairs in the same session — both parties derive the same shared secret (Alice has her private key + Bob's public point; Bob has his private key + Alice's public point).

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Derive;

internal static class DeriveSharedSecretEcdhTestCases
{
    internal static void Assert_Ecdh_BothPartiesDeriveSameSecret(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            // Alice and Bob each generate a P-256 key pair.
            var (alicePub, alicePriv) = session.GenerateEcKeyPair(curve: EcCurve.P256);
            var (bobPub, bobPriv) = session.GenerateEcKeyPair(curve: EcCurve.P256);
            try
            {
                // Extract each peer's public point (CKA_EC_POINT is a DER-encoded OCTET STRING).
                var aliceAttrs = session.GetAttributeValue(alicePub, new List<CKA> { CKA.CKA_EC_POINT });
                var bobAttrs   = session.GetAttributeValue(bobPub,   new List<CKA> { CKA.CKA_EC_POINT });
                byte[] alicePoint = aliceAttrs[0].GetValueAsByteArray();
                byte[] bobPoint   = bobAttrs[0].GetValueAsByteArray();

                // Both parties derive AES-256 keys from the shared secret.
                ObjectHandle aliceKey = session.DeriveSharedSecretEcdh(alicePriv, bobPoint);
                ObjectHandle bobKey   = session.DeriveSharedSecretEcdh(bobPriv,   alicePoint);
                try
                {
                    // Encrypt the same plaintext with both derived keys and check the ciphertext+tag matches.
                    // Use AES-GCM with a fixed IV so the encryption is deterministic per key.
                    byte[] iv = new byte[12];
                    byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("phase-4a ECDH sanity check");
                    byte[] ctA = session.EncryptAesGcm(aliceKey, iv, plaintext);
                    byte[] ctB = session.EncryptAesGcm(bobKey,   iv, plaintext);
                    Assert.Equal(ctA, ctB);
                }
                finally
                {
                    session.DestroyObject(bobKey);
                    session.DestroyObject(aliceKey);
                }
            }
            finally
            {
                session.DestroyObject(alicePriv);
                session.DestroyObject(alicePub);
                session.DestroyObject(bobPriv);
                session.DestroyObject(bobPub);
            }
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("SoftHsm")]
public sealed class DeriveSharedSecretEcdhTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ecdh_BothPartiesDeriveSameSecret() => DeriveSharedSecretEcdhTestCases.Assert_Ecdh_BothPartiesDeriveSameSecret(_backend);
}
```

- [ ] **Step 3: Build + run**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. Both new tests SoftHsm-only — skip locally.

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Keys/WrapUnwrapKeyTests.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Derive/
git -C /home/alexandre/dev/PKCS11.NET commit -m "test(Keys+Derive): AES-KEY-WRAP-PAD round-trip + ECDH shared-secret derivation

WrapUnwrapKeyTests: generate two AES keys, wrap one with the other
using CKM_AES_KEY_WRAP_PAD, unwrap into a fresh handle.

DeriveSharedSecretEcdhTests: classic ECDH sanity check — Alice and
Bob each derive a key from (their private, peer's public), then
encrypt the same plaintext with the same IV and confirm identical
ciphertext + tag, proving both arrived at the same shared secret."
```

---

## Task 11: Key-gen mechanism matrix `[Theory]`

Parameterized coverage that the gate fires for the full set of insecure key-gen and key-derive mechanisms.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Security/InsecureOperationGateTests.cs`

- [ ] **Step 1: Add helpers**

In the static `InsecureOperationGateTestCases` class:

```csharp
    internal static void Assert_GenerateKey_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var mech = new Mechanism((CKM)mechanismId);
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.GenerateKey(mech, new List<ObjectAttribute>()));
            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            try { session.Logout(); } catch { }
            try { session.CloseSession(); } catch { }
        }
    }

    internal static void Assert_DeriveKey_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var mech = new Mechanism((CKM)mechanismId);
            var fakeBase = new ObjectHandle(0);
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.DeriveKey(mech, fakeBase, new List<ObjectAttribute>()));
            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            try { session.Logout(); } catch { }
            try { session.CloseSession(); } catch { }
        }
    }
```

- [ ] **Step 2: Add `[Theory]` blocks in Mock test class**

```csharp
    [Theory]
    [InlineData((ulong)CKM.CKM_DES_KEY_GEN)]
    [InlineData((ulong)CKM.CKM_DES2_KEY_GEN)]
    [InlineData((ulong)CKM.CKM_DES3_KEY_GEN)]
    public void GenerateKey_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_GenerateKey_InsecureMechanismThrows(_backend, mech);

    [Theory]
    [InlineData((ulong)CKM.CKM_DES3_ECB_ENCRYPT_DATA)]
    [InlineData((ulong)CKM.CKM_DES3_CBC_ENCRYPT_DATA)]
    public void DeriveKey_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_DeriveKey_InsecureMechanismThrows(_backend, mech);
```

If any of the listed CKM values doesn't exist in `Common/CKM.cs` (T5 verified, but adjust here if T5 dropped any), remove the matching `[InlineData]` line.

- [ ] **Step 3: Matching `[ConditionalTheory(nameof(SoftHsmAvailable))]` in the SoftHsm class with the same InlineData entries.**

- [ ] **Step 4: Build + run**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. 5 new Mock-runnable tests pass (3 GenerateKey + 2 DeriveKey theory entries). 5 SoftHsm-gated tests skip locally.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Security/InsecureOperationGateTests.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "test(Security): extend gate Theory data with key-gen and key-derive mechanisms

GenerateKey: CKM_DES_KEY_GEN, CKM_DES2_KEY_GEN, CKM_DES3_KEY_GEN.
DeriveKey: CKM_DES3_ECB_ENCRYPT_DATA, CKM_DES3_CBC_ENCRYPT_DATA.

Both Mock and SoftHsm classes get matching Theory blocks. The gate
fires in managed code before any P/Invoke, so all five InlineData
entries pass on the mock backend."
```

---

## Task 12: Final verification + tag

- [ ] **Step 1: Clean Release build**

```bash
cd /home/alexandre/dev/PKCS11.NET
dotnet clean src/src.sln >/dev/null
dotnet build src/src.sln --configuration Release 2>&1 | tail -5
```

Expected: 0 errors.

- [ ] **Step 2: Final test run**

```bash
dotnet test src/src.sln --configuration Release --no-build 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected counts (locally, SoftHSM2 unavailable):
- `Runtime.InteropServices.Tests`: 118 / 1 / 0 (unchanged).
- `Pkcs11.Tests`: ~63 + ~7 new Mock-runnable = ~70 passed (2 GenerateAes/Rsa rejection tests + 5 gate theory entries); ~60 + ~9 new SoftHsm-gated = ~69 skipped; 0 failed.

If failed > 0, STOP and investigate.

- [ ] **Step 3: Verify pack still works**

```bash
dotnet pack src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -c Release -p:SkipPkcs11MockBuild=true -o /tmp/pack-test 2>&1 | tail -3
ls /tmp/pack-test/
rm -rf /tmp/pack-test
```

- [ ] **Step 4: Verify Phase 4a exit-criteria invariants**

```bash
echo "=== Session.Objects.cs ==="
ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Objects.cs
echo "=== Session.Keys.cs ==="
ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Keys.cs
echo "=== Session.Derive.cs ==="
ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Derive.cs
echo "=== EcCurve.cs ==="
ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/EcCurve.cs
echo "=== CkmEcdh1DeriveParams ==="
ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/MechanismParams/CkmEcdh1DeriveParams.cs
echo "=== Session.cs has no Object/Key/Derive method definitions ==="
grep -cE "public .* (CreateObject|CopyObject|DestroyObject|GetObjectSize|GetAttributeValue|SetAttributeValue|FindObjectsInit|FindObjects|FindObjectsFinal|FindAllObjects|GenerateKey|GenerateKeyPair|WrapKey|UnwrapKey|DeriveKey)\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
echo "=== Secure helpers exist ==="
grep -cE "public .* (GenerateAesKey|GenerateRsaKeyPair|GenerateEcKeyPair|DeriveSharedSecretEcdh)\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Keys.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Derive.cs
echo "=== Phase 4a test dirs ==="
ls -d src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/{Objects,Keys,Derive}/
```

Expected: all files exist; 0 Object/Key/Derive method matches in Session.cs; 4 secure-helper matches across the two files; 3 test directories exist.

- [ ] **Step 5: Tag the milestone**

```bash
git -C /home/alexandre/dev/PKCS11.NET tag -a phase-4a-complete -m "Phase 4a complete: Objects+Keys+Derive partial split + secure helpers + tests

Delivered:
- Session.Objects.cs (CreateObject, CopyObject, DestroyObject, GetObjectSize,
  GetAttributeValue x2, SetAttributeValue, FindObjectsInit, FindObjects,
  FindObjectsFinal, FindAllObjects).
- Session.Keys.cs (GenerateKey, GenerateKeyPair, WrapKey, UnwrapKey +
  ReadOnlySpan<byte> UnwrapKey overload).
- Session.Derive.cs (DeriveKey).
- GuardMechanism wired into key-gen/wrap/derive entry points + extended
  with CKM_DES*_KEY_GEN and CKM_DES3_*_ENCRYPT_DATA cases.
- Secure helpers: GenerateAesKey (CKA_SENSITIVE/EXTRACTABLE defaults),
  GenerateRsaKeyPair (modulus >= 2048), GenerateEcKeyPair (P-256/384/521
  via EcCurve enum), DeriveSharedSecretEcdh (CKM_ECDH1_DERIVE + CKD_SHA256_KDF
  to a sensitive AES key).
- CkmEcdh1DeriveParams high-level wrapper.
- Tests: object lifecycle round-trip, AES/RSA/EC key-gen helpers (arg
  validation on Mock; round-trip on SoftHsm), AES-KEY-WRAP-PAD round-trip,
  ECDH same-secret derivation, [Theory]-parameterized gate coverage for
  DES/3DES key-gen + key-derive mechanisms.

Out of scope (deferred to subsequent phases):
- Phase 4b: SecurePin / SecureBuffer / SafeHandle adoption.
- Phase 4c: Memory-leak + thread-safety test suites.
- v3.1 message-based APIs: still backend-blocked."
```

---

## Phase 4a Exit Checklist

- [ ] `dotnet build src/src.sln -c Release` succeeds with 0 errors.
- [ ] All tests pass; SoftHsm-gated tests skip on dev hosts without SoftHSM2.
- [ ] `Session.Objects.cs` exists with 11 object-management methods.
- [ ] `Session.Keys.cs` exists with GenerateKey, GenerateKeyPair, WrapKey, UnwrapKey + ReadOnlySpan UnwrapKey + 3 secure-default key-gen helpers.
- [ ] `Session.Derive.cs` exists with DeriveKey + DeriveSharedSecretEcdh.
- [ ] `Session.cs` no longer contains any of the carved methods.
- [ ] `GuardMechanism` covers CKM_DES_KEY_GEN, CKM_DES2_KEY_GEN, CKM_DES3_KEY_GEN, CKM_DES3_ECB_ENCRYPT_DATA, CKM_DES3_CBC_ENCRYPT_DATA.
- [ ] `EcCurve` enum exists with P256/P384/P521 values.
- [ ] `CkmEcdh1DeriveParams` wrapper exists.
- [ ] Test directories `HighLevel/Objects/`, `HighLevel/Keys/`, `HighLevel/Derive/` exist with the specified test files.
- [ ] `InsecureOperationGateTests` has key-gen + derive `[Theory]` data.
- [ ] Tag `phase-4a-complete` exists.

When all checked, Phase 4a is complete. Phase 4b (SecurePin/SecureBuffer/SafeHandle adoption) can be planned next.
