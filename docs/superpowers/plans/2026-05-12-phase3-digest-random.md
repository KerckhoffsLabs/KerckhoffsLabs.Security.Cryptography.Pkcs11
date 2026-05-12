# PKCS11.NET Phase 3: Digest + Random Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Carve `DigestKey`, `Digest`, `DigestEncrypt`, `DecryptDigest` out of `Session.cs` into a `Session.Digest.cs` partial and `SeedRandom` + `GenerateRandom` into `Session.Random.cs`; add `ReadOnlySpan<byte>` overloads on the buffer entry points; wire `GuardMechanism` into Digest entry points (the gate already rejects raw MD5/SHA-1 from Phase 2 T1); add secure-default helpers `DigestSha256` / `DigestSha384` / `DigestSha512` and `[Obsolete]` shortcuts `DigestMd5` / `DigestSha1`; cover with backend-parameterized functional tests.

**Architecture:** Mechanical extension of the Phase 1 + 2 pattern. Reuse `IMechanismParams`, the established static-helper + per-backend-concrete test layout, `TestKeys.OpenLoggedInSession`, and the `IPkcs11Backend` plumbing. No new architectural pieces.

**Tech Stack:** C# 12 / .NET 8 + .NET 9, xUnit 2.9, `Microsoft.DotNet.XUnitExtensions` (`[ConditionalFact]`), pkcs11-mock v2.0.0, SoftHSM2.

**Reference specs:**
- Parent: `docs/superpowers/specs/2026-05-11-pkcs11-completion-design.md`
- Phase 1: `docs/superpowers/plans/2026-05-11-phase1-encrypt-decrypt.md`
- Phase 2: `docs/superpowers/plans/2026-05-12-phase2-sign-verify.md` (closest pattern reference)

**Out of scope (deferred to later phases):**
- PKCS#11 v3.1 `C_DigestMessage*` message-based APIs — pkcs11-mock v2.0.0 predates v3.1.
- SHA-3 family helpers — `CKM_SHA3_256` etc. not currently in the imported `CKM` enum; SHA-3 backend support is still spotty. Defer until a real use case demands them.

---

## File Structure

```
src/
├── KerckhoffsLabs.Security.Cryptography.Pkcs11/
│   └── HighLevel/
│       ├── Session.cs                                        [MODIFY — strip Digest/Random methods]
│       ├── Session.Digest.cs                                 [CREATE — partial: Digest + DigestKey + DigestEncrypt + DecryptDigest + Span overloads + secure helpers]
│       └── Session.Random.cs                                 [CREATE — partial: SeedRandom + GenerateRandom + Span overloads]
│
└── KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/
    └── HighLevel/
        ├── Digest/
        │   ├── DigestSha2Tests.cs                            [CREATE — covers SHA-256/384/512 helpers]
        │   └── DigestMd5Sha1Tests.cs                         [CREATE — covers [Obsolete] DigestMd5/DigestSha1 gate + bypass]
        ├── Random/
        │   └── RandomTests.cs                                [CREATE — GenerateRandom basic properties]
        └── Security/
            └── InsecureOperationGateTests.cs                 [MODIFY — extend Theory data with Digest mechanisms]
```

Same static-helper + per-backend-concrete pattern as Phase 1/2. No abstract base classes.

After Phase 3, `Session.cs` retains only lifecycle methods (Open/Close/Login/Logout, attribute reads, object find, key wrap/unwrap, key generation, key derivation, CancelFunction, etc.). The combined ops are all relocated.

---

## Task 1: Carve `Session.Digest.cs` out of `Session.cs`

Pure mechanical refactor: move the 10 Digest-side methods (1 DigestKey + 3 Digest + 3 DigestEncrypt + 3 DecryptDigest) into a new partial. No behavior change.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Digest.cs`

- [ ] **Step 1: Locate the methods**

```bash
grep -n "public.* Digest(\|public.* DigestKey\|public.* DigestEncrypt\|public.* DecryptDigest" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs | head -15
```

Expected (verified prior to plan):
- 1 `DigestKey(Mechanism, ObjectHandle)`
- 3 `Digest(Mechanism, ...)` overloads (byte[], Stream, Stream-with-bufferLength)
- 3 `DigestEncrypt(...)` overloads (combined op, byte[]/Stream/Stream-with-bufferLength)
- 3 `DecryptDigest(...)` overloads (combined op, byte[]/Stream/Stream-with-bufferLength)

Total: 10 public methods. If counts differ, STOP and report.

- [ ] **Step 2: Create Session.Digest.cs with scaffold**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
{
    // Methods inserted here
}
```

- [ ] **Step 3: Move methods verbatim, top-down**

Move in source order:
1. `DigestKey` (and any protected helper if present)
2. The 3 `Digest` overloads (and any protected helper)
3. The 3 `DigestEncrypt` overloads
4. The 3 `DecryptDigest` overloads

Cut from `Session.cs` (XML doc block start through closing `}` of each method), paste into `Session.Digest.cs` inside `public partial class Session { ... }`. Do not modify any body content.

Bring any `protected` helpers along with their public siblings.

- [ ] **Step 4: Build**

```bash
dotnet build src/src.sln 2>&1 | tail -3
```

Expected: 0 errors. If a referenced type is missing from the usings, extend the scaffold (e.g., add `using KerckhoffsLabs.Runtime.InteropServices;` if `NativeCULong` is referenced).

- [ ] **Step 5: Tests**

```bash
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 175 passed (118 + 57), 51 skipped, 0 failed.

- [ ] **Step 6: Verify carve scope**

```bash
echo "=== Session.cs no longer has Digest-side methods ==="
grep -cE "public (byte\[\]|void) (Digest|DigestKey|DigestEncrypt|DecryptDigest)\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
echo "=== Session.Digest.cs has them all ==="
grep -cE "public (byte\[\]|void) (Digest|DigestKey|DigestEncrypt|DecryptDigest)\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Digest.cs
```

Expected: `0` in Session.cs, `10` in Session.Digest.cs.

- [ ] **Step 7: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Digest.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "refactor(Session): carve Digest / DigestKey / DigestEncrypt / DecryptDigest into Session.Digest.cs

Pure relocation, no behavior change. The two remaining combined ops
(DigestEncrypt and DecryptDigest) move here per the Phase 2 promise.
Session.cs now retains only object/lifecycle/key-management methods;
the operational partials are complete."
```

---

## Task 2: Carve `Session.Random.cs` out of `Session.cs`

Same mechanical refactor for the Random methods.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Random.cs`

- [ ] **Step 1: Locate the methods**

```bash
grep -n "public.* SeedRandom\|public.* GenerateRandom" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs | head
```

Expected: 1 `SeedRandom(byte[] seed)` and 1 `GenerateRandom(int length)` — 2 public methods total. No protected helpers expected. If counts differ, STOP and report.

- [ ] **Step 2: Create Session.Random.cs with scaffold**

```csharp
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
{
    // Methods inserted here
}
```

- [ ] **Step 3: Move methods verbatim**

Cut `SeedRandom` (with its XML doc) and `GenerateRandom` (with its XML doc) from `Session.cs`, paste into `Session.Random.cs` inside the partial body. Do not modify bodies.

- [ ] **Step 4: Build + test**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. 175 passed, 51 skipped, 0 failed.

- [ ] **Step 5: Verify carve scope**

```bash
echo "=== Session.cs no longer has Random methods ==="
grep -cE "public (byte\[\]|void) (SeedRandom|GenerateRandom)\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
echo "=== Session.Random.cs has them ==="
grep -cE "public (byte\[\]|void) (SeedRandom|GenerateRandom)\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Random.cs
```

Expected: `0` in Session.cs, `2` in Session.Random.cs.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Random.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "refactor(Session): carve SeedRandom / GenerateRandom into Session.Random.cs

Pure relocation. Random ops don't take a Mechanism, so there's no
gate wiring to do — they're just isolated by responsibility."
```

---

## Task 3: Add `ReadOnlySpan<byte>` overload + wire `GuardMechanism` into Digest entry points

Adds a Span overload to `Digest(byte[])` and threads `GuardMechanism((CKM)mechanism.Type)` through every existing Digest / DigestKey / DigestEncrypt / DecryptDigest method. Mirrors Phase 1 T7 / Phase 2 T6.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Digest.cs`

- [ ] **Step 1: Add `ReadOnlySpan<byte>` overload above the existing `Digest(Mechanism, byte[])` method**

```csharp
    /// <summary>
    /// Computes a digest over <paramref name="data"/> using the given mechanism. Throws
    /// <see cref="InsecureOperationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list (raw MD5 / SHA-1) and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">The digest mechanism (typically <see cref="CKM.CKM_SHA256"/> or stronger).</param>
    /// <param name="data">Data to digest.</param>
    /// <returns>Digest bytes (length depends on the mechanism — 32 for SHA-256, 48 for SHA-384, 64 for SHA-512).</returns>
    public byte[] Digest(Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(mechanism);
        // Temporary array for the byte[]-based P/Invoke path. Replace with pinned-Span
        // P/Invoke when perf profiling proves it matters.
        byte[] buffer = data.ToArray();
        return Digest(mechanism, buffer);
    }
```

The Span overload doesn't call `GuardMechanism` directly — it delegates to the byte[] path which will (after Step 2).

- [ ] **Step 2: Insert `GuardMechanism` into every existing Digest-side entry point**

For each public method (and any protected helper) in `Session.Digest.cs`:

- `DigestKey(Mechanism, ObjectHandle)` — guards `(CKM)mechanism.Type`.
- All 3 `Digest(Mechanism, ...)` overloads — guard `(CKM)mechanism.Type`.
- All 3 `DigestEncrypt(...)` overloads — guard BOTH `(CKM)digestingMechanism.Type` AND `(CKM)encryptionMechanism.Type`.
- All 3 `DecryptDigest(...)` overloads — guard BOTH `(CKM)digestingMechanism.Type` AND `(CKM)decryptionMechanism.Type`.

For each method, the ordering is:
1. `if (_disposed) throw new ObjectDisposedException(...)` or `ObjectDisposedException.ThrowIf(_disposed, this)` — keep existing
2. `mechanism` null-check(s) (move above logger if needed; for combined ops, null-check BOTH mechanisms)
3. `keyHandle` null-check (if the method has one)
4. **`GuardMechanism((CKM)mechanism.Type);`** (and second guard for combined ops)
5. `_logger.Debug(...)` — existing
6. Rest of body unchanged

If the method has a `protected` helper that the public method delegates to (e.g., Phase 2's Sign pattern), follow the same single-source rule: guard at the protected layer only, remove guards from the public methods that delegate. **Inspect the file to determine call-graph before duplicating guards.**

- [ ] **Step 3: Build**

```bash
dotnet build src/src.sln 2>&1 | tail -3
```

Expected: 0 errors.

- [ ] **Step 4: Tests**

```bash
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 175 passed, 51 skipped, 0 failed. No existing test uses raw MD5 / SHA-1 on the Digest path, so wiring the gate doesn't break anything.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Digest.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session.Digest): add ReadOnlySpan<byte> Digest + wire GuardMechanism

Span overload on Digest delegates to the byte[] path via .ToArray().
GuardMechanism is now called from every Digest / DigestKey /
DigestEncrypt / DecryptDigest entry point; raw MD5 (CKM_MD5) and
raw SHA-1 (CKM_SHA_1) throw InsecureOperationException unless
Session.AllowInsecure = true (gated since Phase 2 T1).

Combined-op methods guard BOTH of their mechanisms."
```

---

## Task 4: Add `ReadOnlySpan<byte>` / `Span<byte>` overloads on Random methods

Adds Span input variant for `SeedRandom` and Span output variant for `GenerateRandom`. No mechanism gating (Random doesn't take a CKM).

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Random.cs`

- [ ] **Step 1: Add `ReadOnlySpan<byte>` overload of `SeedRandom`**

Above the existing `public void SeedRandom(byte[] seed)`:

```csharp
    /// <summary>
    /// Seeds the token's random number generator with caller-supplied entropy. Useful when
    /// the host has access to high-quality entropy (e.g., another RNG) that the caller wants
    /// to mix into the token's internal state. Most callers should rely solely on the token's
    /// internal RNG and call <see cref="GenerateRandom(int)"/> directly.
    /// </summary>
    /// <param name="seed">Entropy bytes to mix into the token RNG.</param>
    public void SeedRandom(ReadOnlySpan<byte> seed)
    {
        byte[] buffer = seed.ToArray();
        SeedRandom(buffer);
    }
```

- [ ] **Step 2: Add a `Span<byte>` output overload of `GenerateRandom`**

Above the existing `public byte[] GenerateRandom(int length)`:

```csharp
    /// <summary>
    /// Fills <paramref name="destination"/> with random bytes from the token's RNG and
    /// returns the number of bytes written.
    /// </summary>
    /// <param name="destination">Buffer to fill. The full length of <paramref name="destination"/> is filled.</param>
    /// <returns>Number of bytes written (equal to <paramref name="destination"/>.Length).</returns>
    public int GenerateRandom(Span<byte> destination)
    {
        if (destination.IsEmpty) return 0;
        byte[] random = GenerateRandom(destination.Length);
        random.CopyTo(destination);
        return destination.Length;
    }
```

- [ ] **Step 3: Build + test**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. 175 passed, 51 skipped, 0 failed.

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Random.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session.Random): add ReadOnlySpan<byte> SeedRandom + Span<byte> GenerateRandom

Span input on SeedRandom delegates to the existing byte[] path.
Span output on GenerateRandom returns the byte count written, so
callers using stackalloc'd buffers can size precisely. The byte[]
variant remains for the common case where the caller wants a fresh
heap allocation."
```

---

## Task 5: Secure-default Digest helpers + `[Obsolete]` shortcuts

Adds named helpers for SHA-256, SHA-384, SHA-512 and gated shortcuts for MD5 and SHA-1.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Digest.cs`

- [ ] **Step 1: Append the secure helpers above the closing `}` of the partial**

```csharp
    // === Secure-default digest helpers =====================================

    /// <summary>Computes a SHA-256 digest over <paramref name="data"/>. Output is 32 bytes.</summary>
    /// <param name="data">Data to digest.</param>
    /// <returns>32-byte SHA-256 digest.</returns>
    public byte[] DigestSha256(ReadOnlySpan<byte> data)
    {
        using var mechanism = new Mechanism(CKM.CKM_SHA256);
        return Digest(mechanism, data);
    }

    /// <summary>Computes a SHA-384 digest over <paramref name="data"/>. Output is 48 bytes.</summary>
    /// <param name="data">Data to digest.</param>
    /// <returns>48-byte SHA-384 digest.</returns>
    public byte[] DigestSha384(ReadOnlySpan<byte> data)
    {
        using var mechanism = new Mechanism(CKM.CKM_SHA384);
        return Digest(mechanism, data);
    }

    /// <summary>Computes a SHA-512 digest over <paramref name="data"/>. Output is 64 bytes.</summary>
    /// <param name="data">Data to digest.</param>
    /// <returns>64-byte SHA-512 digest.</returns>
    public byte[] DigestSha512(ReadOnlySpan<byte> data)
    {
        using var mechanism = new Mechanism(CKM.CKM_SHA512);
        return Digest(mechanism, data);
    }

    // === Legacy named shortcuts (gated, compile-time warning) ==============

    /// <summary>
    /// Computes an MD5 digest. **Use <see cref="DigestSha256"/> instead.** Throws
    /// <see cref="InsecureOperationException"/> at runtime unless
    /// <see cref="AllowInsecure"/> is set on the session.
    /// </summary>
    [Obsolete("MD5 is a broken hash function with practical collisions. " +
              "Use DigestSha256 (or stronger) instead. " +
              "If you must use it, set Session.AllowInsecure = true.")]
    public byte[] DigestMd5(ReadOnlySpan<byte> data)
    {
        using var mechanism = new Mechanism(CKM.CKM_MD5);
        return Digest(mechanism, data);
    }

    /// <summary>
    /// Computes a SHA-1 digest. **Use <see cref="DigestSha256"/> instead.** Throws
    /// <see cref="InsecureOperationException"/> at runtime unless
    /// <see cref="AllowInsecure"/> is set on the session.
    /// </summary>
    [Obsolete("SHA-1 is broken (SHAttered demonstrated practical collisions). " +
              "Use DigestSha256 (or stronger) instead. " +
              "If you must use it, set Session.AllowInsecure = true.")]
    public byte[] DigestSha1(ReadOnlySpan<byte> data)
    {
        using var mechanism = new Mechanism(CKM.CKM_SHA_1);
        return Digest(mechanism, data);
    }
```

- [ ] **Step 2: Build**

```bash
dotnet build src/src.sln 2>&1 | tail -3
```

Expected: 0 errors. The `[Obsolete]` helpers will not generate any warnings until a caller compiles against them.

- [ ] **Step 3: Tests**

```bash
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 175 passed, 51 skipped, 0 failed.

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Digest.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session.Digest): secure-default digest helpers + [Obsolete] MD5/SHA-1

Secure helpers (recommended public surface):
- DigestSha256 (32-byte output)
- DigestSha384 (48-byte output)
- DigestSha512 (64-byte output)

Each builds the appropriate Mechanism and delegates to the generic
Digest(Mechanism, ReadOnlySpan<byte>) path, which already guards
against insecure mechanisms via GuardMechanism.

Legacy named shortcuts with [Obsolete]:
- DigestMd5 / DigestSha1 — point at the SHA-256 alternative;
  throw via the runtime gate unless AllowInsecure = true."
```

---

## Task 6: Digest tests — SHA-2 family + MD5/SHA-1 gate

Tests the new secure helpers against both backends (Mock should produce a canned digest the same way Phase 1 Encrypt tests do for argument-validation paths) and verifies the `[Obsolete]` gate.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Digest/DigestSha2Tests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Digest/DigestMd5Sha1Tests.cs`

- [ ] **Step 1: Write `DigestSha2Tests.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Digest;

internal static class DigestSha2TestCases
{
    /// <summary>SoftHSM-only: real SHA-256 over "abc" matches the published test vector.</summary>
    internal static void Assert_Sha256_KnownAnswer(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes("abc");
            byte[] digest = session.DigestSha256(data);
            Assert.Equal(32, digest.Length);

            // NIST FIPS 180-4 published vector for SHA-256("abc"):
            // BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
            byte[] expected = Convert.FromHexString("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
            Assert.Equal(expected, digest);
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }

    internal static void Assert_Sha384_OutputLength(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            byte[] digest = session.DigestSha384(System.Text.Encoding.UTF8.GetBytes("phase-3"));
            Assert.Equal(48, digest.Length);
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }

    internal static void Assert_Sha512_OutputLength(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            byte[] digest = session.DigestSha512(System.Text.Encoding.UTF8.GetBytes("phase-3"));
            Assert.Equal(64, digest.Length);
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("SoftHsm")]
public sealed class DigestSha2Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Sha256_KnownAnswer() => DigestSha2TestCases.Assert_Sha256_KnownAnswer(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Sha384_OutputLength() => DigestSha2TestCases.Assert_Sha384_OutputLength(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Sha512_OutputLength() => DigestSha2TestCases.Assert_Sha512_OutputLength(_backend);
}
```

Note: known-answer test (`Assert_Sha256_KnownAnswer`) is SoftHSM-only because pkcs11-mock returns a canned response, not real SHA-256. The output-length tests are also SoftHSM-only (mock might return a wrong-length placeholder).

- [ ] **Step 2: Write `DigestMd5Sha1Tests.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Digest;

internal static class DigestMd5Sha1TestCases
{
    internal static void Assert_Md5_GatedByDefault(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
#pragma warning disable CS0618
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.DigestMd5(Array.Empty<byte>()));
#pragma warning restore CS0618
            Assert.Equal(CKM.CKM_MD5, ex.Mechanism);
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }

    internal static void Assert_Sha1_GatedByDefault(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
#pragma warning disable CS0618
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.DigestSha1(Array.Empty<byte>()));
#pragma warning restore CS0618
            Assert.Equal(CKM.CKM_SHA_1, ex.Mechanism);
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }

    internal static void Assert_Md5_AllowInsecureBypassesGate(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        session.AllowInsecure = true;
        try
        {
            try
            {
#pragma warning disable CS0618
                session.DigestMd5(Array.Empty<byte>());
#pragma warning restore CS0618
            }
            catch (InsecureOperationException)
            {
                Assert.Fail("AllowInsecure=true should have suppressed the gate.");
            }
            catch
            {
                // Any other exception is acceptable — we only assert the gate didn't fire.
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
public sealed class DigestMd5Sha1Tests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void Md5_GatedByDefault() => DigestMd5Sha1TestCases.Assert_Md5_GatedByDefault(_backend);

    [Fact]
    public void Sha1_GatedByDefault() => DigestMd5Sha1TestCases.Assert_Sha1_GatedByDefault(_backend);

    [Fact]
    public void Md5_AllowInsecureBypassesGate() => DigestMd5Sha1TestCases.Assert_Md5_AllowInsecureBypassesGate(_backend);
}

[Collection("SoftHsm")]
public sealed class DigestMd5Sha1Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Md5_GatedByDefault() => DigestMd5Sha1TestCases.Assert_Md5_GatedByDefault(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Sha1_GatedByDefault() => DigestMd5Sha1TestCases.Assert_Sha1_GatedByDefault(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Md5_AllowInsecureBypassesGate() => DigestMd5Sha1TestCases.Assert_Md5_AllowInsecureBypassesGate(_backend);
}
```

- [ ] **Step 3: Build + run**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. Mock gate tests (3 tests) pass; SoftHsm tests (6) skip locally.
Total counts: ~178 passed (175 + 3 new Mock-runnable), ~57 skipped (51 + 6 new SoftHsm).

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Digest/
git -C /home/alexandre/dev/PKCS11.NET commit -m "test(Digest): SHA-2 known-answer + [Obsolete] MD5/SHA-1 gate

SHA-256/384/512 round-trip / output-length tests are SoftHsm-only
(pkcs11-mock returns a canned digest, not real SHA-x).

[Obsolete] DigestMd5 / DigestSha1 gate-by-default and
AllowInsecure-bypass tests run on both backends — the gate fires in
managed code before any P/Invoke."
```

---

## Task 7: Random tests

Verifies that `GenerateRandom` produces output of the requested length and that consecutive calls produce different results.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Random/RandomTests.cs`

- [ ] **Step 1: Write `RandomTests.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Random;

internal static class RandomTestCases
{
    internal static void Assert_GenerateRandom_ProducesRequestedLength(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            byte[] r = session.GenerateRandom(32);
            Assert.Equal(32, r.Length);
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }

    internal static void Assert_GenerateRandom_ConsecutiveCallsDiffer(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            byte[] a = session.GenerateRandom(32);
            byte[] b = session.GenerateRandom(32);
            Assert.NotEqual(a, b);
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }

    internal static void Assert_GenerateRandom_SpanOverload_FillsBuffer(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            Span<byte> buffer = stackalloc byte[16];
            int written = session.GenerateRandom(buffer);
            Assert.Equal(16, written);
            // At least one byte should be non-zero with overwhelming probability.
            bool anyNonZero = false;
            for (int i = 0; i < buffer.Length; i++) if (buffer[i] != 0) { anyNonZero = true; break; }
            Assert.True(anyNonZero, "GenerateRandom produced all-zero output (probability ~2^-128).");
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("Mock")]
public sealed class RandomTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void GenerateRandom_ProducesRequestedLength() => RandomTestCases.Assert_GenerateRandom_ProducesRequestedLength(_backend);

    // ConsecutiveCallsDiffer is SoftHsm-only — pkcs11-mock returns the same canned bytes.
    // SpanOverload_FillsBuffer is SoftHsm-only for the same reason.
}

[Collection("SoftHsm")]
public sealed class RandomTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateRandom_ProducesRequestedLength() => RandomTestCases.Assert_GenerateRandom_ProducesRequestedLength(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateRandom_ConsecutiveCallsDiffer() => RandomTestCases.Assert_GenerateRandom_ConsecutiveCallsDiffer(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateRandom_SpanOverload_FillsBuffer() => RandomTestCases.Assert_GenerateRandom_SpanOverload_FillsBuffer(_backend);
}
```

- [ ] **Step 2: Build + run**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Goal: 0 errors. The Mock-runnable test (1) passes; the SoftHsm-only tests (3) skip locally.
Total: ~179 passed (178 + 1), ~60 skipped (57 + 3).

If `GenerateRandom_ProducesRequestedLength` fails on Mock because the mock returns a wrong-length response, move it to SoftHsm-only and leave no Mock-runnable Random tests.

- [ ] **Step 3: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Random/
git -C /home/alexandre/dev/PKCS11.NET commit -m "test(Random): GenerateRandom basic properties + Span<byte> overload coverage

Mock-runnable: length assertion (mock returns a canned buffer of the
requested size). SoftHsm-only: consecutive-calls-differ (mock is
deterministic) + Span<byte> overload fill check."
```

---

## Task 8: Extend `InsecureOperationGateTests` with digest mechanisms

Adds `[Theory]` data covering Digest-side insecure mechanisms (raw MD5, raw SHA-1) to the cross-cutting gate tests file.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Security/InsecureOperationGateTests.cs`

- [ ] **Step 1: Add a helper for the Digest entry-point gate**

In the static `InsecureOperationGateTestCases` class:

```csharp
    internal static void Assert_Digest_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var mech = new Mechanism((CKM)mechanismId);
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.Digest(mech, Array.Empty<byte>()));
            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            try { session.Logout(); } catch { }
            try { session.CloseSession(); } catch { }
        }
    }
```

- [ ] **Step 2: Add `[Theory]` in the Mock test class**

```csharp
    [Theory]
    [InlineData((ulong)CKM.CKM_MD5)]
    [InlineData((ulong)CKM.CKM_SHA_1)]
    public void Digest_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_Digest_InsecureMechanismThrows(_backend, mech);
```

- [ ] **Step 3: Add the matching `[ConditionalTheory(nameof(SoftHsmAvailable))]` in the SoftHsm class**

```csharp
    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData((ulong)CKM.CKM_MD5)]
    [InlineData((ulong)CKM.CKM_SHA_1)]
    public void Digest_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_Digest_InsecureMechanismThrows(_backend, mech);
```

- [ ] **Step 4: Build + run**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. 2 new Mock-runnable tests pass; 2 new SoftHsm-gated tests skip locally.
Total: ~181 passed (179 + 2), ~62 skipped (60 + 2).

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Security/InsecureOperationGateTests.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "test(Security): extend InsecureOperationGateTests with raw MD5/SHA-1 digest

The Digest entry point is the third place raw MD5 / SHA-1 can be
called (alongside Sign and Verify in Phase 2). Add [Theory] coverage
so the gate's behavior on the Digest path is verified directly."
```

---

## Task 9: Final verification + tag

**Files:** (verification only)

- [ ] **Step 1: Clean Release build**

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
- `Runtime.InteropServices.Tests`: 118 passed, 1 skipped, 0 failed (unchanged).
- `Pkcs11.Tests`: ~63 passed (57 from phase-2-complete + 6 new Mock-runnable: 3 digest gate + 1 random length + 2 digest theory), ~62 skipped (50 from phase-2 + 12 new SoftHsm: 3 SHA-2 + 3 MD5/SHA-1 gate + 3 random + 2 digest theory + extra Span tests), 0 failed.

If failed > 0, STOP and investigate.

- [ ] **Step 3: Verify pack still works**

```bash
dotnet pack src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -c Release -p:SkipPkcs11MockBuild=true -o /tmp/pack-test 2>&1 | tail -3
ls /tmp/pack-test/
rm -rf /tmp/pack-test
```

Expected: nupkg + snupkg produced.

- [ ] **Step 4: Verify the Phase 3 exit-criteria invariants**

```bash
echo "=== Session.Digest.cs exists ==="
ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Digest.cs
grep -cE "public (byte\[\]|void|int) (Digest|DigestKey|DigestEncrypt|DecryptDigest|DigestSha256|DigestSha384|DigestSha512|DigestMd5|DigestSha1)\b" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Digest.cs

echo "=== Session.Random.cs exists ==="
ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Random.cs
grep -cE "public (byte\[\]|void|int) (SeedRandom|GenerateRandom)\b" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Random.cs

echo "=== Session.cs no longer has Digest/Random methods ==="
grep -cE "public (byte\[\]|void) (Digest|DigestKey|DigestEncrypt|DecryptDigest|SeedRandom|GenerateRandom)\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs

echo "=== Phase 3 test directories ==="
ls -d src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Digest/ src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Random/
```

Expected outputs:
- `Session.Digest.cs` exists with ≥ 13 method matches (10 carved + 3 secure helpers + 2 obsolete = 15; the regex catches all).
- `Session.Random.cs` exists with 4 method matches (2 carved + 2 Span overloads).
- `Session.cs` has 0 Digest/Random matches.
- Both test directories exist.

- [ ] **Step 5: Tag the milestone**

```bash
git -C /home/alexandre/dev/PKCS11.NET tag -a phase-3-complete -m "Phase 3 complete: Digest+Random partial split + secure helpers + dual-backend tests

Delivered:
- Session.Digest.cs partial (DigestKey, Digest, DigestEncrypt, DecryptDigest)
  + ReadOnlySpan<byte> overload + GuardMechanism wired
- Session.Random.cs partial (SeedRandom, GenerateRandom)
  + ReadOnlySpan<byte> seed overload + Span<byte> output overload
- Secure helpers: DigestSha256, DigestSha384, DigestSha512
- [Obsolete] shortcuts: DigestMd5, DigestSha1 (runtime-gated)
- Tests for SHA-2 known-answer (SoftHsm), MD5/SHA-1 gate (both backends),
  GenerateRandom length + distinct + Span overload, plus digest entries
  in the InsecureOperationGateTests [Theory] coverage."
```

---

## Phase 3 Exit Checklist

- [ ] `dotnet build src/src.sln -c Release` succeeds with 0 errors.
- [ ] `dotnet test src/src.sln` — all tests pass; SoftHsm-gated tests skip on hosts without SoftHSM2.
- [ ] `Session.Digest.cs` exists with DigestKey + 3 Digest + 3 DigestEncrypt + 3 DecryptDigest + Span overload + 3 secure helpers + 2 [Obsolete] shortcuts.
- [ ] `Session.Random.cs` exists with SeedRandom + GenerateRandom + Span overloads.
- [ ] `Session.cs` no longer contains Digest/DigestKey/DigestEncrypt/DecryptDigest/SeedRandom/GenerateRandom definitions.
- [ ] `GuardMechanism` is called from every Digest entry point (single-source at protected helper level if helpers exist; otherwise at each public method).
- [ ] Tests exist under `Tests/HighLevel/Digest/` and `Tests/HighLevel/Random/`.
- [ ] `InsecureOperationGateTests` has Digest `[Theory]` data for both Mock and SoftHsm classes.
- [ ] Tag `phase-3-complete` exists.

When all checked, Phase 3 is complete. Phase 4 (Objects + Keys + KDF + MessageBased) can be planned next.
