# PKCS11.NET Phase 4c: Memory-Leak + Thread-Safety Suites Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the two test suites called out by the parent spec — a memory-leak suite verifying that disposable types (Mechanism, ObjectAttribute, all `IMechanismParams` wrappers) leave `UnmanagedMemory.OutstandingAllocationCount` at baseline after dispose, and a thread-safety suite enforcing the documented contract that **concurrent use of a single session throws a deterministic exception** while **different sessions on different threads work in parallel**. Adds the production-code change required by the contract: a `Monitor.TryEnter`-based busy-flag on `Session` applied to every public mechanism-bearing method.

**Architecture:**

1. **Memory-leak suite** — expose a public `UnmanagedMemory.OutstandingAllocationCount` property so tests can baseline + verify. `UnmanagedMemory.DebugModeEnabled` already tracks every Allocate/Free into a private dictionary; the new property exposes the count. Tests live under `Tests/HighLevel/MemoryLeaks/`. Mock-only — we don't want to hit a real HSM in a 100-cycle stress loop.

2. **Thread-safety suite** — production change: add a `_busyLock` object + `AcquireExclusive()` helper to `Session.cs` that uses `Monitor.TryEnter` (NOT `Interlocked.CompareExchange`). The `Monitor` choice is deliberate: `Monitor` is reentrant from the same thread, which matters because secure helpers like `GenerateAesKey` internally call the public `GenerateKey`. With `Interlocked` that would self-deadlock; with `Monitor` the inner call sees the lock is owned by the same thread and proceeds. A *different* thread calling `TryEnter` while the lock is held fails immediately, and the helper throws `InvalidOperationException` — the deterministic exception the spec requires. Apply the guard to every public method that performs a native call. Tests live under `Tests/HighLevel/ThreadSafety/`. Mock-only.

**Tech Stack:** C# 12 / .NET 8 + .NET 9, xUnit 2.9, `System.Threading.Monitor`, `System.Runtime.CompilerServices.CallerMemberNameAttribute` for diagnostic messages.

**Reference specs:**
- Parent: `docs/superpowers/specs/2026-05-11-pkcs11-completion-design.md` (lines 167-168 for the suite contracts; line 265-266 for exit-criteria language)
- Phase 4b: `docs/superpowers/plans/2026-05-12-phase4b-secure-memory.md` (pattern reference for SafeHandle adoption and the existing partial-class hygiene)

**Out of scope (deferred to later work):**
- Async dispose / `IAsyncDisposable`.
- A full thread-safe Session (concurrent reads + serialized writes). The contract here is "one operation at a time"; users who need parallelism use multiple sessions.
- Tools to enforce the contract at compile time (e.g., Roslyn analyzers). Runtime detection is sufficient.
- Stress tests against SoftHsm — the Mock-only matrix is what the spec calls for, and SoftHsm-against-shared-token concurrency would be testing SoftHsm's behavior, not ours.

---

## File Structure

```
src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
├── Native/
│   └── UnmanagedMemory.cs                                  [MODIFY — add public OutstandingAllocationCount property]
└── HighLevel/
    ├── Session.cs                                          [MODIFY — add _busyLock + AcquireExclusive + ExclusiveLease helper; apply guard to PIN/lifecycle methods]
    ├── Session.Encrypt.cs                                  [MODIFY — apply busy-guard]
    ├── Session.Decrypt.cs                                  [MODIFY — apply busy-guard]
    ├── Session.Sign.cs                                     [MODIFY — apply busy-guard]
    ├── Session.Verify.cs                                   [MODIFY — apply busy-guard]
    ├── Session.Digest.cs                                   [MODIFY — apply busy-guard]
    ├── Session.Random.cs                                   [MODIFY — apply busy-guard]
    ├── Session.Objects.cs                                  [MODIFY — apply busy-guard]
    ├── Session.Keys.cs                                     [MODIFY — apply busy-guard]
    └── Session.Derive.cs                                   [MODIFY — apply busy-guard]

src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/
└── HighLevel/
    ├── MemoryLeaks/                                        [CREATE DIR]
    │   ├── UnmanagedMemoryHarnessTests.cs                  [CREATE — sanity test for OutstandingAllocationCount + DebugModeEnabled invariants]
    │   ├── MechanismParamsLeakTests.cs                     [CREATE — one test per IMechanismParams wrapper × 5]
    │   ├── MechanismAndObjectAttributeLeakTests.cs         [CREATE — Mechanism + ObjectAttribute leak tests]
    │   └── EncryptDecryptStressTests.cs                    [CREATE — omnibus N-cycle stress test]
    └── ThreadSafety/                                       [CREATE DIR]
        ├── SessionBusyGuardTests.cs                        [CREATE — single-session concurrent throws InvalidOperationException]
        └── SessionParallelTests.cs                         [CREATE — different sessions on different threads succeed]
```

After Phase 4c: 12 production files modified (10 Session partials + UnmanagedMemory + Session.cs busy-guard infrastructure); 6 new test files added under 2 new directories.

---

## Task 1: Expose `UnmanagedMemory.OutstandingAllocationCount`

The private `_allocations` dictionary already tracks every Allocate/Free when `DebugModeEnabled` is true. Expose its count as a read-only public property.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/UnmanagedMemory.cs`

- [ ] **Step 1: Add the property**

After the existing `DebugModeEnabled` property (around line 51), add:

```csharp
    /// <summary>
    /// Number of unmanaged allocations currently outstanding (allocated but not yet freed).
    /// Only meaningful while <see cref="DebugModeEnabled"/> is <c>true</c>; returns <c>0</c>
    /// otherwise because the allocation dictionary is only populated in debug mode.
    /// </summary>
    /// <remarks>
    /// Intended for diagnostic and leak-detection tests. Production code must not depend on
    /// this property's behavior outside of debug mode.
    /// </remarks>
    public static int OutstandingAllocationCount
    {
        get
        {
            lock (_allocationsLock)
            {
                return _allocations.Count;
            }
        }
    }
```

Note: take the existing `_allocationsLock` for thread safety; the underlying dictionary is not concurrent.

- [ ] **Step 2: Write a sanity test**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/MemoryLeaks/UnmanagedMemoryHarnessTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.MemoryLeaks;

/// <summary>
/// Sanity tests for the UnmanagedMemory leak-detection harness. If these fail, every other
/// test in MemoryLeaks/ is meaningless.
/// </summary>
public sealed class UnmanagedMemoryHarnessTests : IDisposable
{
    private readonly bool _wasDebug;

    public UnmanagedMemoryHarnessTests()
    {
        _wasDebug = UnmanagedMemory.DebugModeEnabled;
        UnmanagedMemory.DebugModeEnabled = true;
    }

    public void Dispose()
    {
        UnmanagedMemory.DebugModeEnabled = _wasDebug;
    }

    [Fact]
    public void OutstandingAllocationCount_IsAccessible()
    {
        int count = UnmanagedMemory.OutstandingAllocationCount;
        Assert.True(count >= 0);
    }

    [Fact]
    public void OutstandingAllocationCount_TracksAllocateAndFree()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        IntPtr ptr = UnmanagedMemory.Allocate(16);
        try
        {
            Assert.Equal(baseline + 1, UnmanagedMemory.OutstandingAllocationCount);
        }
        finally
        {
            UnmanagedMemory.Free(ref ptr);
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }
}
```

The fixture's constructor enables debug mode for the lifetime of each test; `Dispose` restores the original state. Tests run in parallel by default in xUnit, but the `DebugModeEnabled` toggle is process-wide. To avoid flakes when MemoryLeaks tests run alongside other tests (which might toggle debug mode), wrap each MemoryLeaks test file in `[Collection("MemoryLeaks")]` so they all serialize together. Add the collection definition to the project:

```csharp
[CollectionDefinition("MemoryLeaks", DisableParallelization = true)]
public class MemoryLeaksCollection { }
```

(Place this in a new file `Tests/HighLevel/MemoryLeaks/MemoryLeaksCollection.cs` or in the existing collections file.)

- [ ] **Step 3: Run + commit**

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~UnmanagedMemoryHarnessTests" 2>&1 | grep -E "Passed!|Failed!"
```

Expected: 2 passed.

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/UnmanagedMemory.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/MemoryLeaks/
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(UnmanagedMemory): expose OutstandingAllocationCount for leak-detection tests

Read-only public property over the existing _allocations dictionary,
guarded by the same _allocationsLock the rest of the class uses. Only
meaningful while DebugModeEnabled is true; returns 0 otherwise.

Harness sanity tests under Tests/HighLevel/MemoryLeaks/. The whole
directory uses [Collection(\"MemoryLeaks\")] with DisableParallelization
so the process-wide DebugModeEnabled toggle doesn't race with other tests."
```

---

## Task 2: Memory-leak tests — `IMechanismParams` wrappers

One test per wrapper. Each test toggles debug mode (via the collection fixture), baselines the allocation count, exercises the wrapper through construct → use → dispose, and asserts the count is back to baseline.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/MemoryLeaks/MechanismParamsLeakTests.cs`

- [ ] **Step 1: Write the test file**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.MemoryLeaks;

[Collection("MemoryLeaks")]
public sealed class MechanismParamsLeakTests : IDisposable
{
    private readonly bool _wasDebug;

    public MechanismParamsLeakTests()
    {
        _wasDebug = UnmanagedMemory.DebugModeEnabled;
        UnmanagedMemory.DebugModeEnabled = true;
    }

    public void Dispose() => UnmanagedMemory.DebugModeEnabled = _wasDebug;

    [Fact]
    public void CkmAesGcmParams_NoLeak()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 10; i++)
        {
            using var p = new CkmAesGcmParams(
                iv: new byte[12],
                aad: new byte[16],
                tagBits: 128);
            // touching ToMarshalableStructure is part of the realistic lifecycle
            _ = p.ToMarshalableStructure();
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void CkmRsaPkcsOaepParams_NoLeak()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 10; i++)
        {
            using var p = new CkmRsaPkcsOaepParams(
                hashAlg: CKM.CKM_SHA256,
                mgf: CKG.CKG_MGF1_SHA256,
                source: CKZ.CKZ_DATA_SPECIFIED,
                sourceData: new byte[16]);
            _ = p.ToMarshalableStructure();
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void CkmRsaPkcsPssParams_NoLeak()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 10; i++)
        {
            using var p = new CkmRsaPkcsPssParams(
                hashAlg: CKM.CKM_SHA256,
                mgf: CKG.CKG_MGF1_SHA256,
                saltLen: 32);
            _ = p.ToMarshalableStructure();
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void CkmSalsa20ChaCha20Poly1305Params_NoLeak()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 10; i++)
        {
            using var p = new CkmSalsa20ChaCha20Poly1305Params(
                nonce: new byte[12],
                aad: new byte[16]);
            _ = p.ToMarshalableStructure();
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void CkmEcdh1DeriveParams_NoLeak()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 10; i++)
        {
            // P-256 uncompressed public point: DER-encoded OCTET STRING of 0x04||X||Y (66 bytes total).
            byte[] peerPublicPoint = new byte[66];
            peerPublicPoint[0] = 0x04;
            peerPublicPoint[1] = 0x41;
            peerPublicPoint[2] = 0x04;
            using var p = new CkmEcdh1DeriveParams(
                kdf: CKD.CKD_SHA256_KDF,
                peerPublicPoint: peerPublicPoint,
                sharedData: new byte[16]);
            _ = p.ToMarshalableStructure();
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }
}
```

**Important:** the constructor parameter names above (`iv`, `aad`, `tagBits`, `hashAlg`, `mgf`, `source`, `sourceData`, `saltLen`, `nonce`, `peerPublicPoint`, `sharedData`, `kdf`) are best-guesses — verify each against the actual constructor signatures by reading the wrapper files under `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/MechanismParams/`. Adapt as needed.

`CKG` and `CKZ` enums may live in `Common/`. Verify and adjust the `using`s.

- [ ] **Step 2: Run + commit**

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~MechanismParamsLeakTests" 2>&1 | grep -E "Passed!|Failed!"
```

Expected: 5 passed. If any wrapper leaks, the test fails — that's a real bug to investigate, not a flaky test.

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/MemoryLeaks/MechanismParamsLeakTests.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "test(MemoryLeaks): IMechanismParams wrappers leak suite

One test per wrapper × 10-cycle construct/use/dispose loop. Asserts
OutstandingAllocationCount is back to baseline after each test.

If a wrapper's Dispose path is broken (forgot to Free an IntPtr,
finalizer not chained, etc.), this is the test that catches it."
```

---

## Task 3: Memory-leak tests — `Mechanism` + `ObjectAttribute` + omnibus stress

`Mechanism` and `ObjectAttribute` are their own `IDisposable` classes that hold unmanaged buffers. Plus one omnibus N-cycle test that runs realistic encrypt/decrypt operations against the Mock.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/MemoryLeaks/MechanismAndObjectAttributeLeakTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/MemoryLeaks/EncryptDecryptStressTests.cs`

- [ ] **Step 1: Write `MechanismAndObjectAttributeLeakTests.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.MemoryLeaks;

[Collection("MemoryLeaks")]
public sealed class MechanismAndObjectAttributeLeakTests : IDisposable
{
    private readonly bool _wasDebug;

    public MechanismAndObjectAttributeLeakTests()
    {
        _wasDebug = UnmanagedMemory.DebugModeEnabled;
        UnmanagedMemory.DebugModeEnabled = true;
    }

    public void Dispose() => UnmanagedMemory.DebugModeEnabled = _wasDebug;

    [Fact]
    public void Mechanism_NoLeak_PlainMechanism()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 20; i++)
        {
            using var m = new Mechanism(CKM.CKM_AES_KEY_GEN);
            _ = m.ToCkMechanism();
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void Mechanism_NoLeak_WithIMechanismParams()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 20; i++)
        {
            using var p = new CkmAesGcmParams(iv: new byte[12], aad: null!, tagBits: 128);
            using var m = new Mechanism(CKM.CKM_AES_GCM, p);
            _ = m.ToCkMechanism();
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void ObjectAttribute_NoLeak_BoolValue()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 20; i++)
        {
            using var a = new ObjectAttribute(CKA.CKA_TOKEN, false);
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void ObjectAttribute_NoLeak_ByteArrayValue()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 20; i++)
        {
            using var a = new ObjectAttribute(CKA.CKA_VALUE, new byte[32]);
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void ObjectAttribute_NoLeak_UlongValue()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 20; i++)
        {
            using var a = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }
}
```

Note: `Mechanism.ToCkMechanism()` may be named differently — read `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Mechanism.cs` and use the actual accessor name (likely `ToCK_MECHANISM` or just `ToMarshalableStructure`).

- [ ] **Step 2: Write `EncryptDecryptStressTests.cs`**

End-to-end realistic workload: N cycles of encrypt + decrypt against Mock.

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.MemoryLeaks;

[Collection("MemoryLeaks")]
public sealed class EncryptDecryptStressTests : IDisposable
{
    private readonly MockBackendFixture _backend;
    private readonly bool _wasDebug;

    public EncryptDecryptStressTests(MockBackendFixture f)
    {
        _backend = f;
        _wasDebug = UnmanagedMemory.DebugModeEnabled;
        UnmanagedMemory.DebugModeEnabled = true;
    }

    public void Dispose() => UnmanagedMemory.DebugModeEnabled = _wasDebug;

    [Fact]
    public void EncryptDecrypt_100Cycles_NoLeak()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;

        for (int i = 0; i < 100; i++)
        {
            var session = TestKeys.OpenLoggedInSession(_backend);
            try
            {
                // pkcs11-mock returns canned data for encrypt/decrypt; we're testing our
                // managed-side allocation discipline, not the crypto.
                using var mech = new Mechanism(CKM.CKM_AES_ECB);
                // Mock returns CK_INVALID_HANDLE for everything but accepts our calls without
                // throwing on the protected helpers; the real assertion is allocations, not
                // any specific output.
                try
                {
                    using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                    using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
                    using var attrValueLen = new ObjectAttribute(CKA.CKA_VALUE_LEN, 16UL);
                    var template = new List<ObjectAttribute> { attrClass, attrKeyType, attrValueLen };
                    var key = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template);
                    try
                    {
                        // The mock returns canned bytes; we just need to know our Mechanism
                        // and buffer allocations don't leak.
                        byte[] data = new byte[16];
                        _ = session.Encrypt(mech, key, data);
                    }
                    finally
                    {
                        session.DestroyObject(key);
                    }
                }
                catch (Pkcs11Exception)
                {
                    // Mock's specific CKR codes are not the point of this test; only the leak
                    // accounting is. Swallow.
                }
            }
            finally
            {
                session.Logout();
                session.CloseSession();
            }
        }

        // Force a full GC cycle to flush any deferred finalizers — anything still outstanding
        // at this point is a real leak.
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }
}
```

**Important caveats inline:**
- The mock returns canned data; the test isn't asserting crypto correctness, only allocation discipline.
- The `try/catch (Pkcs11Exception)` is deliberate — Mock may reject specific operations (e.g., `Encrypt` against an invalid key handle), but our wrappers must still clean up their unmanaged allocations regardless. That's what the test verifies.
- The `GC.Collect → WaitForPendingFinalizers → GC.Collect` triple is the canonical .NET pattern to ensure deferred-finalizer cleanup runs before we check the count. Otherwise, an instance whose `Dispose` wasn't called and whose finalizer hasn't run yet would inflate the count and fail the test for the wrong reason.

If `session.Encrypt(mech, key, data)` doesn't exist with that signature on Mock backend, simplify the inner workload to just a handful of allocations the test can guarantee will leak-test cleanly (e.g., just construct/dispose 100 Mechanism instances). The goal is to exercise the integrated allocation path; the specific operations are illustrative.

- [ ] **Step 3: Run + commit**

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~MechanismAndObjectAttributeLeakTests|FullyQualifiedName~EncryptDecryptStressTests" 2>&1 | grep -E "Passed!|Failed!"
```

Expected: 6 passed (5 leak + 1 stress).

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/MemoryLeaks/
git -C /home/alexandre/dev/PKCS11.NET commit -m "test(MemoryLeaks): Mechanism + ObjectAttribute coverage + 100-cycle stress

Per-type leak tests for Mechanism (plain + with-params) and
ObjectAttribute (bool / byte[] / ulong variants). Plus an omnibus
100-cycle stress test exercising GenerateKey/Encrypt/DestroyObject
against pkcs11-mock with a forced GC + finalizer flush before the
final assertion."
```

---

## Task 4: Add busy-flag infrastructure to `Session.cs`

Add the `_busyLock`, `AcquireExclusive()` helper, and a `ref struct ExclusiveLease : IDisposable` so `using var _ = AcquireExclusive();` is the idiom for guarded methods.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`

- [ ] **Step 1: Add the helper near the top of the class (after fields, before public methods)**

```csharp
    /// <summary>
    /// Lock object guarding concurrent native-call access to this <see cref="Session"/>.
    /// PKCS#11 sessions are not safe for concurrent use; this lock detects cross-thread
    /// attempts and throws <see cref="InvalidOperationException"/>.
    /// </summary>
    /// <remarks>
    /// <see cref="Monitor"/> (used via <see cref="Monitor.TryEnter(object)"/>) is reentrant on
    /// the same thread, which is required because secure helpers like
    /// <c>GenerateAesKey</c> internally call the public <c>GenerateKey</c>. Re-entry from the
    /// same thread succeeds; a different thread calling while the lock is held fails
    /// immediately, and <see cref="AcquireExclusive"/> throws.
    /// </remarks>
    private readonly object _busyLock = new();

    /// <summary>Disposable token returned by <see cref="AcquireExclusive"/>. Releases the busy lock on dispose.</summary>
    /// <remarks>
    /// Implemented as <c>internal sealed class</c> (not <c>ref struct</c>) so the test suite can
    /// invoke <see cref="AcquireExclusive"/> via <c>[InternalsVisibleTo]</c> and hold the lease
    /// across a thread boundary. A ref struct would be unboxable and unusable for that test.
    /// The one extra heap allocation per public method call is negligible against the cost of
    /// crossing the P/Invoke boundary that follows.
    /// </remarks>
    internal sealed class ExclusiveLease : IDisposable
    {
        private readonly object _lock;
        private bool _released;

        internal ExclusiveLease(object lockObj)
        {
            _lock = lockObj;
            _released = false;
        }

        public void Dispose()
        {
            if (_released) return;
            _released = true;
            Monitor.Exit(_lock);
        }
    }

    /// <summary>
    /// Acquires exclusive access to this session for the duration of the returned
    /// <see cref="ExclusiveLease"/>. Throws <see cref="InvalidOperationException"/> if another
    /// thread is already inside an exclusive section.
    /// </summary>
    /// <remarks>
    /// Usage: <c>using var _ = AcquireExclusive(); ... // protected body</c>
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// Thrown if a different thread currently holds the lock. The message identifies the
    /// caller via <see cref="System.Runtime.CompilerServices.CallerMemberNameAttribute"/>.
    /// </exception>
    internal ExclusiveLease AcquireExclusive([System.Runtime.CompilerServices.CallerMemberName] string? caller = null)
    {
        if (!Monitor.TryEnter(_busyLock))
        {
            throw new InvalidOperationException(
                $"Concurrent access to a PKCS#11 Session is not supported. " +
                $"Method '{caller ?? "<unknown>"}' was invoked while another operation is in progress " +
                $"on a different thread. Use a separate Session per thread.");
        }
        return new ExclusiveLease(_busyLock);
    }
```

The `Monitor.TryEnter` immediate-fail-on-different-thread semantics is what guarantees the deterministic-exception contract. The lease is held until `Dispose` runs (typically via the `using` pattern, freeing the lock at the end of the method body).

- [ ] **Step 2: Apply the guard to `Session.cs`'s own PIN methods + CloseSession + GetSessionInfo + GetOperationState/SetOperationState + CancelFunction + GetFunctionStatus**

Wrap each public method body with `using var _ = AcquireExclusive();` as the first line (before any `_disposed` check, since the guard itself doesn't need the session to be in a particular state):

```csharp
public void Login(CKU userType, SecurePin pin)
{
    using var _ = AcquireExclusive();
    // existing body
}
```

Apply to all of:
- `Login` (3 overloads)
- `InitPin` (3 overloads)
- `SetPin` (3 overloads)
- `Logout` (if exists; verify by grep)
- `CloseSession`
- `GetSessionInfo`
- `GetOperationState` / `SetOperationState`
- `CancelFunction` / `GetFunctionStatus`

DO NOT apply to private helpers (`LoginCore`, `InitPinCore`, `SetPinCore`) — they're internal and called only from the public wrappers that already hold the lock.

- [ ] **Step 3: Build + run all tests**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. All existing tests pass — the guard is a no-op for single-threaded tests.

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session): AcquireExclusive busy-flag infrastructure + Session.cs guard

Adds Session._busyLock + AcquireExclusive() helper returning an
ExclusiveLease ref struct. Monitor.TryEnter underlies the lock — same
thread can re-enter (matters for secure helpers like GenerateAesKey that
call public GenerateKey internally); a different thread calling while
the lock is held fails immediately and AcquireExclusive throws
InvalidOperationException with the caller method name.

Applied to Session.cs's own public methods: Login/InitPin/SetPin
overloads, CloseSession, GetSessionInfo, Logout, GetOperationState,
SetOperationState, CancelFunction, GetFunctionStatus. The internal
Core helpers are not guarded; they're only reachable from the public
wrappers that already hold the lock.

Cross-partial guard application follows in Tasks 5-7."
```

---

## Task 5: Apply busy-guard to `Encrypt` + `Decrypt` partials

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Encrypt.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Decrypt.cs`

- [ ] **Step 1: Locate public methods**

```bash
grep -nE "^\s*public " src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Encrypt.cs
grep -nE "^\s*public " src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Decrypt.cs
```

- [ ] **Step 2: Add `using var _ = AcquireExclusive();` as the first line of each public method body**

Pattern:

```csharp
public byte[] Encrypt(Mechanism mechanism, ObjectHandle keyHandle, byte[] data)
{
    using var _ = AcquireExclusive();
    // existing body
}
```

If a public method delegates to another public method on this Session (e.g., `EncryptAesGcm` delegates to a protected helper that calls `Encrypt`), only the outer entry point needs the explicit guard — Monitor is reentrant. But the inner call WILL re-acquire from the same thread; the cost is negligible and correctness is preserved.

If `protected` methods exist that are NOT called publicly but only from inside the partials, they don't need the guard. Use grep to check.

- [ ] **Step 3: Build + run all tests**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. Existing tests unchanged.

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Encrypt.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Decrypt.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session.{Encrypt,Decrypt}): apply busy-guard to public methods"
```

---

## Task 6: Apply busy-guard to `Sign` + `Verify` + `Digest` + `Random` partials

Same mechanical pattern. Wrap every public method body with `using var _ = AcquireExclusive();` as the first line.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Sign.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Verify.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Digest.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Random.cs`

- [ ] **Step 1: Locate + wrap (per partial)**

For each of the four files:

```bash
grep -nE "^\s*public " src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.<Group>.cs
```

For each public method, add `using var _ = AcquireExclusive();` as the first line.

- [ ] **Step 2: Build + run all tests**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. Existing tests unchanged.

- [ ] **Step 3: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Sign.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Verify.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Digest.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Random.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session.{Sign,Verify,Digest,Random}): apply busy-guard to public methods"
```

---

## Task 7: Apply busy-guard to `Objects` + `Keys` + `Derive` partials

Same mechanical pattern. **Important:** `Session.Keys.cs` has secure helpers (`GenerateAesKey`, `GenerateRsaKeyPair`, `GenerateEcKeyPair`) that call public `GenerateKey`/`GenerateKeyPair` internally. Both layers get the guard; Monitor's reentrancy keeps the inner call legal from the same thread. `DeriveSharedSecretEcdh` similarly calls public `DeriveKey`.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Objects.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Keys.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Derive.cs`

- [ ] **Step 1: Locate + wrap**

```bash
grep -nE "^\s*public " src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Objects.cs
grep -nE "^\s*public " src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Keys.cs
grep -nE "^\s*public " src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Derive.cs
```

Add `using var _ = AcquireExclusive();` as the first line of every public method.

- [ ] **Step 2: Verify reentrancy works**

The secure helpers (`GenerateAesKey`, etc.) need to keep working — they take the lock, then call `GenerateKey` which takes the lock again on the same thread (Monitor.TryEnter succeeds), then the inner method releases (decrement count), then the outer releases. Run the T6 GenerateAesKeyTests to confirm:

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~GenerateAesKeyTests" 2>&1 | grep -E "Passed!|Failed!"
```

Expected: same counts as before (no regressions).

- [ ] **Step 3: Build + run all tests**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. All existing tests pass — guard is a no-op for single-threaded tests.

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Objects.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Keys.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Derive.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session.{Objects,Keys,Derive}): apply busy-guard to public methods

Secure helpers (GenerateAesKey/RsaKeyPair/EcKeyPair/DeriveSharedSecretEcdh)
that call public GenerateKey/Pair/DeriveKey internally rely on Monitor
reentrancy — Acquire from the same thread succeeds; the lock is owned
for the duration of the outermost call."
```

---

## Task 8: Thread-safety tests

Tests for both invariants: (a) concurrent use of a single session throws `InvalidOperationException`, (b) different sessions on different threads work in parallel.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ThreadSafety/SessionBusyGuardTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ThreadSafety/SessionParallelTests.cs`

- [ ] **Step 1: Write `SessionBusyGuardTests.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.ThreadSafety;

[Collection("Mock")]
public sealed class SessionBusyGuardTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void ConcurrentCall_FromDifferentThread_Throws_InvalidOperationException()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var startGate = new System.Threading.ManualResetEventSlim(false);
            using var holdGate = new System.Threading.ManualResetEventSlim(false);

            Exception? capturedB = null;

            // Thread A: take the busy lock via the internal AcquireExclusive helper
            // (accessible via [InternalsVisibleTo]), hold it open via a gate, then release.
            var threadA = new System.Threading.Thread(() =>
            {
                using var lease = session.AcquireExclusive(nameof(ConcurrentCall_FromDifferentThread_Throws_InvalidOperationException));
                startGate.Set();
                holdGate.Wait();
            });

            // Thread B: wait until A holds the lock, then call any public method.
            // The guard on the public method should detect cross-thread contention and throw.
            var threadB = new System.Threading.Thread(() =>
            {
                startGate.Wait();
                try
                {
                    session.GetSessionInfo();
                }
                catch (Exception ex)
                {
                    capturedB = ex;
                }
                finally
                {
                    holdGate.Set();
                }
            });

            threadA.Start();
            threadB.Start();
            threadA.Join();
            threadB.Join();

            Assert.NotNull(capturedB);
            Assert.IsType<InvalidOperationException>(capturedB);
            Assert.Contains("Concurrent access", capturedB!.Message);
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }

    [Fact]
    public void ReentrantCall_FromSameThread_Succeeds()
    {
        // Same-thread reentrancy is required by secure helpers (e.g., GenerateAesKey calls
        // public GenerateKey internally). If the lock weren't reentrant, those helpers would
        // self-deadlock or throw on every call. This test directly exercises the reentrant
        // path: hold the lease, then call a public method on the same thread.
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var outerLease = session.AcquireExclusive(nameof(ReentrantCall_FromSameThread_Succeeds));
            // From the SAME thread, calling a public method that internally re-acquires
            // must succeed (Monitor is reentrant on the same thread).
            _ = session.GetSessionInfo();
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}
```

- [ ] **Step 2: Write `SessionParallelTests.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.ThreadSafety;

[Collection("Mock")]
public sealed class SessionParallelTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void DifferentSessions_OnDifferentThreads_BothSucceed()
    {
        const int threadCount = 8;
        const int opsPerThread = 50;

        Exception?[] failures = new Exception?[threadCount];
        var threads = new System.Threading.Thread[threadCount];

        for (int t = 0; t < threadCount; t++)
        {
            int threadIndex = t;
            threads[t] = new System.Threading.Thread(() =>
            {
                try
                {
                    var session = TestKeys.OpenLoggedInSession(_backend);
                    try
                    {
                        for (int i = 0; i < opsPerThread; i++)
                        {
                            // GetSessionInfo is the simplest cross-cutting op available against
                            // pkcs11-mock — it just reads canned state, so we're testing that
                            // the busy-guard doesn't artificially serialize across DIFFERENT
                            // sessions.
                            _ = session.GetSessionInfo();
                        }
                    }
                    finally
                    {
                        session.Logout();
                        session.CloseSession();
                    }
                }
                catch (Exception ex)
                {
                    failures[threadIndex] = ex;
                }
            });
        }

        foreach (var th in threads) th.Start();
        foreach (var th in threads) th.Join();

        for (int t = 0; t < threadCount; t++)
        {
            Assert.Null(failures[t]);
        }
    }
}
```

- [ ] **Step 3: Build + run**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln --filter "FullyQualifiedName~ThreadSafety" 2>&1 | grep -E "Passed!|Failed!"
```

Expected: 3 passed (1 concurrent-throws + 1 reentrant + 1 parallel).

- [ ] **Step 4: Full suite + commit**

```bash
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Confirm full suite still green.

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ThreadSafety/
git -C /home/alexandre/dev/PKCS11.NET commit -m "test(ThreadSafety): single-session busy-guard + cross-session parallelism

SessionBusyGuardTests: exercises the busy-guard contract via reflection
on AcquireExclusive — Thread A holds the lease, Thread B's call throws
InvalidOperationException with 'Concurrent access' in the message.
A separate test confirms same-thread reentrancy works (required by
secure helpers like GenerateAesKey).

SessionParallelTests: 8 threads × 50 ops each, each thread on its own
Session — all complete without exceptions, proving the guard scopes
to a single Session and doesn't cross-serialize."
```

---

## Task 9: Final verification + tag

- [ ] **Step 1: Clean Release build**

```bash
dotnet clean src/src.sln >/dev/null
dotnet build src/src.sln --configuration Release 2>&1 | tail -3
```

Expected: 0 errors.

- [ ] **Step 2: Full test run**

```bash
dotnet test src/src.sln --configuration Release --no-build 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected counts:
- `Runtime.InteropServices.Tests`: 118 / 1 / 0 (unchanged).
- `Pkcs11.Tests`: ~95 + 14 new = ~109 passed (5 + 5 + 1 + 3 + harness 2 = 14 ≈ 16 if cycle stress test counts separately).
  Specifically new: 2 harness + 5 IMechanismParams + 5 Mechanism/ObjectAttribute + 1 stress + 1 concurrent-throws + 1 reentrant + 1 parallel = 16.
- Skipped count unchanged.
- 0 failed.

- [ ] **Step 3: Pack verification**

```bash
dotnet pack src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -c Release -p:SkipPkcs11MockBuild=true -o /tmp/pack-test 2>&1 | tail -3
ls /tmp/pack-test/
rm -rf /tmp/pack-test
```

- [ ] **Step 4: Phase 4c exit-criteria invariants**

```bash
echo "=== UnmanagedMemory.OutstandingAllocationCount exists ==="
grep -c "public static int OutstandingAllocationCount" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/UnmanagedMemory.cs
echo "=== AcquireExclusive in Session.cs ==="
grep -c "AcquireExclusive" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
echo "=== AcquireExclusive applied to all 10 partials ==="
for f in src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session*.cs; do
  c=$(grep -c "AcquireExclusive" "$f")
  echo "$f: $c"
done
echo "=== MemoryLeaks dir ==="
ls -d src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/MemoryLeaks/
echo "=== ThreadSafety dir ==="
ls -d src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ThreadSafety/
```

Expected:
- `OutstandingAllocationCount` exists → 1.
- `AcquireExclusive` in Session.cs → ≥3 (definition + at least one usage on Session.cs's own methods).
- Every Session.<Group>.cs contains ≥1 `AcquireExclusive` reference.
- Both test directories exist.

- [ ] **Step 5: Tag**

```bash
git -C /home/alexandre/dev/PKCS11.NET tag -a phase-4c-complete -m "Phase 4c complete: memory-leak + thread-safety suites + Session busy-guard

Delivered:
- UnmanagedMemory.OutstandingAllocationCount public property exposing
  the existing _allocations dictionary's count. Used by the leak suite
  to baseline + verify zero-leak invariants.
- Memory-leak suite (Mock-only, [Collection(\"MemoryLeaks\")]):
  - UnmanagedMemoryHarnessTests: harness sanity (2 tests).
  - MechanismParamsLeakTests: 1 test per IMechanismParams wrapper (5).
  - MechanismAndObjectAttributeLeakTests: Mechanism (plain + with-params),
    ObjectAttribute (bool/byte[]/ulong) (5 tests).
  - EncryptDecryptStressTests: 100-cycle omnibus stress test against the
    Mock with forced GC + WaitForPendingFinalizers (1 test).
- Session._busyLock + AcquireExclusive() + ExclusiveLease ref struct:
  Monitor.TryEnter-based, reentrant on the same thread (required by the
  secure helpers GenerateAesKey/RsaKeyPair/EcKeyPair/DeriveSharedSecretEcdh
  that internally call public GenerateKey/Pair/DeriveKey). A different
  thread calling while the lock is held fails immediately and
  AcquireExclusive throws InvalidOperationException with the caller name.
- Busy-guard applied to every public method across all 10 Session partials.
- Thread-safety suite (Mock-only):
  - SessionBusyGuardTests: single-session concurrent access from a
    different thread throws InvalidOperationException with 'Concurrent
    access' in the message. Reentrant call from the same thread succeeds.
  - SessionParallelTests: 8 threads × 50 ops each on independent Sessions
    all succeed — the guard scopes to a single Session.

Out of scope (deferred):
- Async dispose / IAsyncDisposable.
- A full thread-safe Session (concurrent reads + serialized writes).
- Roslyn analyzer for compile-time enforcement.
- Stress tests against SoftHsm."
```

---

## Phase 4c Exit Checklist

- [ ] `dotnet build src/src.sln -c Release` succeeds with 0 errors.
- [ ] All tests pass; SoftHsm-gated tests skip on dev hosts without SoftHSM2; new memory-leak and thread-safety tests pass on Mock.
- [ ] `UnmanagedMemory.OutstandingAllocationCount` is a public static property.
- [ ] `Session.AcquireExclusive` exists and is applied to every public method across all 10 Session partials.
- [ ] `Tests/HighLevel/MemoryLeaks/` exists with the four test files specified.
- [ ] `Tests/HighLevel/ThreadSafety/` exists with two test files specified.
- [ ] Tag `phase-4c-complete` exists.

When all checked, Phase 4c is complete. With Phase 4a + 4b + 4c done, the spec's "Phase 4" entry (lines 184) is delivered. Phase 5 (packaging + docs) can be planned next.
