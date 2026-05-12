# PKCS11.NET Phase 4b: Secure Memory + SafeHandle Adoption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce `SecurePin` (public) and `SecureBuffer` (internal) for zero-on-dispose PIN/key-material handling, adopt them in the `Login`/`InitPin`/`SetPin` paths with `[Obsolete]` markers on the `byte[]` and `string` overloads, and switch the native library + session handles to `SafeHandle`-derived types (`Pkcs11ModuleHandle` and `Pkcs11SessionHandle`) so cleanup survives abnormal teardown.

**Architecture:** Two new namespaces — `Security/` for `SecurePin` + `SecureBuffer` (zero-on-dispose pinned-byte[] wrappers via `GCHandle.Alloc(..., Pinned)` and `CryptographicOperations.ZeroMemory`), and `LowLevel/SafeHandles/` for the two `SafeHandle` subclasses. `Session._sessionId` becomes a property delegating to `_sessionHandle.SessionId`, preserving call-site compatibility across the 12 partials. `Session`'s explicit finalizer is removed (SafeHandle's critical finalizer takes over). The byte[]/string PIN overloads stay marked `[Obsolete(error: false)]` — soft migration per parent spec line 109.

**Tech Stack:** C# 12 / .NET 8 + .NET 9, `System.Security.Cryptography.CryptographicOperations.ZeroMemory`, `System.Runtime.InteropServices.SafeHandle`, `GCHandle` for pinning. xUnit 2.9, `Microsoft.DotNet.XUnitExtensions`, pkcs11-mock v2.0.0, SoftHSM2.

**Reference specs:**
- Parent: `docs/superpowers/specs/2026-05-11-pkcs11-completion-design.md` (§ Secure memory handling, § Handle types)
- Phase 4a: `docs/superpowers/plans/2026-05-12-phase4a-objects-keys-derive.md` (pattern reference for partial-class hygiene and test layout)

**Out of scope (deferred):**
- Phase 4c: memory-leak + thread-safety test suites.
- Public `SecureBuffer`-returning overloads of `Decrypt`/`WrapKey`/`GenerateRandom`. The user chose internal-only scope; key-material returned to callers stays `byte[]` and callers own disposal.
- PKCS#11 v3.1 message-based APIs — still backend-blocked.
- `SafeHandle` adoption on `ObjectHandle`. Per parent spec line 116, object handles are not disposable (objects outlive sessions); the value lives in token state, not native memory.
- Unmanaged-buffer SafeHandles inside `IMechanismParams` / `ObjectAttribute`. Pattern works there too but each is a finalizer-backed `IDisposable` already; lift to SafeHandle is a separate refactor and not on the spec's deferred list.

---

## File Structure

```
src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
├── Security/                                              [CREATE DIR]
│   ├── SecurePin.cs                                       [CREATE — public sealed IDisposable, pinned byte[], ZeroMemory on Dispose]
│   └── SecureBuffer.cs                                    [CREATE — internal sealed IDisposable, same pattern]
├── LowLevel/SafeHandles/                                  [CREATE DIR]
│   ├── Pkcs11ModuleHandle.cs                              [CREATE — internal sealed SafeHandle for NativeLibrary IntPtr]
│   └── Pkcs11SessionHandle.cs                             [CREATE — internal sealed SafeHandle for session NativeCULong]
├── Native/
│   └── LowLevelPkcs11Library.cs                           [MODIFY — IntPtr _library → Pkcs11ModuleHandle]
└── HighLevel/
    └── Session.cs                                         [MODIFY — NativeCULong _sessionId → Pkcs11SessionHandle _sessionHandle + shim property; Login/InitPin/SetPin gain SecurePin overloads, byte[]/string variants become Obsolete; remove ~Session finalizer]

src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/
├── Security/                                              [CREATE DIR]
│   ├── SecurePinTests.cs                                  [CREATE — construction/zero-on-dispose/double-dispose/string-ctor-temp-zeroed]
│   └── SecureBufferTests.cs                               [CREATE — same shape, internal-visible-to via [InternalsVisibleTo]]
└── LowLevel/SafeHandles/                                  [CREATE DIR]
    ├── Pkcs11ModuleHandleTests.cs                         [CREATE — Mock-runnable IsInvalid + release-on-dispose]
    └── Pkcs11SessionHandleTests.cs                        [CREATE — Mock-runnable IsInvalid + closes session on dispose]
```

After Phase 4b: `Session.cs` no longer has its own finalizer; `LowLevelPkcs11Library._library` is `Pkcs11ModuleHandle`; PIN paths have `SecurePin` as the preferred surface with soft-obsolete `byte[]`/`string` overloads.

---

## Task 1: `SecurePin` — public secure PIN wrapper

`SecurePin` is the recommended public type for passing PINs to login/init/set. Owns a pinned `byte[]` (so the GC can't move it and leave copies of the PIN scattered in memory), zeroes via `CryptographicOperations.ZeroMemory` on Dispose, has a finalizer safety net.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Security/SecurePin.cs`

- [ ] **Step 1: Write the test file first**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Security/SecurePinTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
using System.Text;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Security;

public sealed class SecurePinTests
{
    [Fact]
    public void Constructor_FromSpan_CopiesBytes()
    {
        byte[] source = Encoding.UTF8.GetBytes("hunter2");
        using var pin = new SecurePin(source);
        Assert.Equal(source.Length, pin.Length);
        Assert.True(pin.Pin.SequenceEqual(source));
    }

    [Fact]
    public void Constructor_FromString_EncodesUtf8()
    {
        using var pin = new SecurePin("hunter2");
        byte[] expected = Encoding.UTF8.GetBytes("hunter2");
        Assert.True(pin.Pin.SequenceEqual(expected));
    }

    [Fact]
    public void Constructor_RejectsNullString()
        => Assert.Throws<ArgumentNullException>(() => new SecurePin((string)null!));

    [Fact]
    public void Pin_AfterDispose_ThrowsObjectDisposed()
    {
        var pin = new SecurePin("hunter2");
        pin.Dispose();
        Assert.Throws<ObjectDisposedException>(() => _ = pin.Pin);
    }

    [Fact]
    public void Length_AfterDispose_ThrowsObjectDisposed()
    {
        var pin = new SecurePin("hunter2");
        pin.Dispose();
        Assert.Throws<ObjectDisposedException>(() => _ = pin.Length);
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var pin = new SecurePin("hunter2");
        pin.Dispose();
        pin.Dispose(); // must not throw
    }

    [Fact]
    public void Dispose_ZeroesUnderlyingBuffer()
    {
        // Capture the underlying buffer via reflection to verify zeroing.
        var pin = new SecurePin("hunter2");
        var field = typeof(SecurePin).GetField("_buffer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(field);
        byte[] buffer = (byte[])field!.GetValue(pin)!;
        Assert.NotEqual(0, buffer[0]); // pre-condition: buffer holds PIN bytes
        pin.Dispose();
        Assert.All(buffer, b => Assert.Equal(0, b));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~SecurePinTests" 2>&1 | tail -5
```

Expected: compile failure or "type SecurePin not found" — confirms tests aren't passing accidentally.

- [ ] **Step 3: Implement `SecurePin.cs`**

```csharp
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;

/// <summary>
/// Holds a PIN value in a pinned byte buffer that is zeroed on disposal.
/// Prefer this over raw <c>byte[]</c> or <c>string</c> when passing PINs to PKCS#11.
/// </summary>
/// <remarks>
/// The buffer is pinned via <see cref="GCHandle.Alloc(object, GCHandleType)"/> so the
/// garbage collector cannot move it and leave stale copies of the PIN scattered in memory.
/// Always dispose this instance as soon as the PIN is no longer needed; the finalizer is a
/// safety net, not a substitute for deterministic disposal.
/// </remarks>
public sealed class SecurePin : IDisposable
{
    private byte[] _buffer;
    private GCHandle _pin;
    private bool _disposed;

    /// <summary>Initializes a new <see cref="SecurePin"/> from a span of bytes. The bytes are copied.</summary>
    /// <param name="pin">The PIN bytes. Must not be empty.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="pin"/> is empty.</exception>
    public SecurePin(ReadOnlySpan<byte> pin)
    {
        if (pin.IsEmpty) throw new ArgumentException("PIN must not be empty.", nameof(pin));
        _buffer = new byte[pin.Length];
        _pin = GCHandle.Alloc(_buffer, GCHandleType.Pinned);
        pin.CopyTo(_buffer);
    }

    /// <summary>Initializes a new <see cref="SecurePin"/> from a string using UTF-8 encoding.</summary>
    /// <remarks>
    /// The transient byte[] used to encode the string is zeroed before this constructor returns.
    /// The string itself remains in managed memory and cannot be reliably zeroed — strings are
    /// immutable and may be interned. Prefer the <see cref="ReadOnlySpan{T}"/> overload if you
    /// can avoid putting the PIN in a string at all.
    /// </remarks>
    /// <param name="pin">The PIN string. Must not be null.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="pin"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if the encoded PIN is empty.</exception>
    public SecurePin(string pin)
    {
        ArgumentNullException.ThrowIfNull(pin);
        int byteCount = Encoding.UTF8.GetByteCount(pin);
        if (byteCount == 0) throw new ArgumentException("PIN must not be empty.", nameof(pin));
        byte[] tmp = new byte[byteCount];
        try
        {
            Encoding.UTF8.GetBytes(pin, tmp);
            _buffer = new byte[byteCount];
            _pin = GCHandle.Alloc(_buffer, GCHandleType.Pinned);
            Array.Copy(tmp, _buffer, byteCount);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tmp);
        }
    }

    /// <summary>Returns a read-only span over the PIN bytes. Valid until <see cref="Dispose"/> is called.</summary>
    public ReadOnlySpan<byte> Pin
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer;
        }
    }

    /// <summary>The length of the PIN in bytes.</summary>
    public int Length
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer.Length;
        }
    }

    /// <summary>Zeroes the underlying buffer and releases the GC pin.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_buffer);
        if (_pin.IsAllocated) _pin.Free();
        _buffer = Array.Empty<byte>();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer safety net — release pin even if Dispose was not called.</summary>
    ~SecurePin() => Dispose();
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~SecurePinTests" 2>&1 | grep -E "Passed!|Failed!"
```

Expected: 7 passed, 0 failed.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Security/SecurePin.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Security/SecurePinTests.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Security): SecurePin public type for zero-on-dispose PIN handling

Pinned byte buffer (GCHandleType.Pinned) so the GC can't relocate the
PIN and leave copies in memory. CryptographicOperations.ZeroMemory on
Dispose. Two ctors: ReadOnlySpan<byte> (preferred) and string (UTF-8
with transient buffer also zeroed). Finalizer safety net."
```

---

## Task 2: `SecureBuffer` — internal zero-on-dispose buffer

Same pattern as `SecurePin` but `internal` and intended for transient buffers inside the library. No public surface.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Security/SecureBuffer.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj` (add `[InternalsVisibleTo]` for the Tests assembly if not present)

- [ ] **Step 1: Verify `InternalsVisibleTo` for Tests**

```bash
grep -n "InternalsVisibleTo" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj
```

If absent, add inside the `<Project>`:

```xml
  <ItemGroup>
    <InternalsVisibleTo Include="KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests" />
  </ItemGroup>
```

If already present, skip this sub-step.

- [ ] **Step 2: Write the test file first**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Security/SecureBufferTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Security;

public sealed class SecureBufferTests
{
    [Fact]
    public void Constructor_AllocatesRequestedLength()
    {
        using var buf = new SecureBuffer(16);
        Assert.Equal(16, buf.Length);
        Assert.All(buf.Span.ToArray(), b => Assert.Equal(0, b));
    }

    [Fact]
    public void Constructor_RejectsNonPositiveLength()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new SecureBuffer(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new SecureBuffer(-1));
    }

    [Fact]
    public void Span_AllowsReadWrite()
    {
        using var buf = new SecureBuffer(4);
        buf.Span[0] = 0xAA;
        buf.Span[3] = 0xBB;
        Assert.Equal(0xAA, buf.Span[0]);
        Assert.Equal(0xBB, buf.Span[3]);
    }

    [Fact]
    public void Span_AfterDispose_ThrowsObjectDisposed()
    {
        var buf = new SecureBuffer(4);
        buf.Dispose();
        Assert.Throws<ObjectDisposedException>(() => _ = buf.Span);
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var buf = new SecureBuffer(4);
        buf.Dispose();
        buf.Dispose();
    }

    [Fact]
    public void Dispose_ZeroesBuffer()
    {
        var buf = new SecureBuffer(4);
        buf.Span.Fill(0xCC);
        var field = typeof(SecureBuffer).GetField("_buffer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        byte[] inner = (byte[])field!.GetValue(buf)!;
        Assert.Equal(0xCC, inner[0]);
        buf.Dispose();
        Assert.All(inner, b => Assert.Equal(0, b));
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~SecureBufferTests" 2>&1 | tail -5
```

Expected: compile failure — `SecureBuffer` undefined.

- [ ] **Step 4: Implement `SecureBuffer.cs`**

```csharp
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;

/// <summary>
/// Internal transient buffer for sensitive bytes (PINs, key material).
/// Pinned via <see cref="GCHandle"/> and zeroed on <see cref="Dispose"/>.
/// </summary>
internal sealed class SecureBuffer : IDisposable
{
    private byte[] _buffer;
    private GCHandle _pin;
    private bool _disposed;

    /// <summary>Allocates a zero-filled buffer of the given length and pins it.</summary>
    /// <param name="length">The buffer length in bytes. Must be > 0.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="length"/> is &lt;= 0.</exception>
    public SecureBuffer(int length)
    {
        if (length <= 0) throw new ArgumentOutOfRangeException(nameof(length), "Length must be > 0.");
        _buffer = new byte[length];
        _pin = GCHandle.Alloc(_buffer, GCHandleType.Pinned);
    }

    /// <summary>Read/write span over the buffer. Valid until <see cref="Dispose"/>.</summary>
    public Span<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer;
        }
    }

    /// <summary>The buffer length in bytes.</summary>
    public int Length
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer.Length;
        }
    }

    /// <summary>Zeroes the buffer and releases the GC pin.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_buffer);
        if (_pin.IsAllocated) _pin.Free();
        _buffer = Array.Empty<byte>();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~SecureBuffer() => Dispose();
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~SecureBufferTests" 2>&1 | grep -E "Passed!|Failed!"
```

Expected: 6 passed, 0 failed.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Security/SecureBuffer.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Security/SecureBufferTests.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Security): SecureBuffer internal zero-on-dispose buffer

Internal-only counterpart to SecurePin. Used inside the library for
transient PIN-encoding and other sensitive intermediates. Same pattern:
pinned byte[], CryptographicOperations.ZeroMemory on Dispose,
finalizer safety net."
```

---

## Task 3: Adopt `SecurePin` in `Session.Login`/`InitPin`/`SetPin`

Add new `SecurePin` overloads that are the recommended public path. Mark existing `byte[]` and `string` overloads `[Obsolete(error: false)]` per spec line 109 — soft migration, no `AllowInsecure` gate. The internal flow stays the same: extract a span from the SecurePin, pass length + bytes to the existing protected delegate.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`

- [ ] **Step 1: Locate existing overloads**

```bash
grep -nE "public void (Login|InitPin|SetPin)\(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
```

Expected (verified earlier):
- `Login(CKU userType, string pin)` (line 337)
- `Login(CKU userType, byte[] pin)` (line 365)
- `InitPin(string userPin)` (line 149)
- `InitPin(byte[] userPin)` (line 173)
- `SetPin(string oldPin, string newPin)` (line 198 area)
- `SetPin(byte[] oldPin, byte[] newPin)` (line 231 area)

Six overloads total. If counts differ, STOP and report.

- [ ] **Step 2: Add `SecurePin`-bearing overloads (preferred public path)**

Inside `Session.cs`, alongside the existing overloads, add:

```csharp
    /// <summary>Logs a user into the token using a <see cref="SecurePin"/>.</summary>
    /// <remarks>Preferred over the <c>byte[]</c> and <c>string</c> overloads — the PIN bytes are
    /// pinned and zeroed on dispose, reducing the window where PIN material lives in managed memory.</remarks>
    /// <param name="userType">User to log in as.</param>
    /// <param name="pin">The PIN. Caller retains ownership and is responsible for disposing it.</param>
    public void Login(CKU userType, SecurePin pin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(pin);
        // SecurePin guarantees a pinned, non-empty buffer; delegate to the existing byte[] path
        // via a copy. We can't pass the pinned span directly because the existing protected
        // helper takes byte[]; for now, accept the small extra copy. A future refactor could
        // make the protected path take ReadOnlySpan<byte>.
        byte[] copy = pin.Pin.ToArray();
        try
        {
            LoginCore(userType, copy);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(copy);
        }
    }

    /// <summary>Initializes the normal user's PIN using a <see cref="SecurePin"/>.</summary>
    public void InitPin(SecurePin userPin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(userPin);
        byte[] copy = userPin.Pin.ToArray();
        try
        {
            InitPinCore(copy);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(copy);
        }
    }

    /// <summary>Changes the current user's PIN using <see cref="SecurePin"/> values.</summary>
    public void SetPin(SecurePin oldPin, SecurePin newPin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(oldPin);
        ArgumentNullException.ThrowIfNull(newPin);
        byte[] oldCopy = oldPin.Pin.ToArray();
        byte[] newCopy = newPin.Pin.ToArray();
        try
        {
            SetPinCore(oldCopy, newCopy);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(oldCopy);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(newCopy);
        }
    }
```

Note: the helper names `LoginCore`, `InitPinCore`, `SetPinCore` may not exist yet. If the existing public methods do the native call directly, refactor first: extract the body of the existing `byte[]` overload into a private/protected helper named `LoginCore(CKU, byte[])` / `InitPinCore(byte[])` / `SetPinCore(byte[], byte[])`. Then have all three flavors (SecurePin, byte[], string) delegate to it. This keeps the native call site single-sourced.

Alternative if extraction adds churn: instead of a `…Core` helper, call the existing `Login(userType, byte[] pin)` overload directly from the SecurePin overload (suppress the obsolete warning with `#pragma warning disable CS0618` around the call). Pick whichever produces a cleaner diff.

- [ ] **Step 3: Mark `byte[]` and `string` overloads `[Obsolete]`**

```csharp
    [Obsolete("Use the SecurePin overload — byte[] PIN buffers cannot be reliably zeroed. " +
              "byte[] is allowed for backward compatibility but does not pin or zero the PIN.",
              error: false)]
    public void Login(CKU userType, byte[] pin) { /* existing body */ }

    [Obsolete("Use the SecurePin overload — string PINs cannot be zeroed (strings are immutable and may be interned). " +
              "string is allowed for backward compatibility.",
              error: false)]
    public void Login(CKU userType, string pin) { /* existing body */ }
```

Same `[Obsolete]` attributes on the two `InitPin` and two `SetPin` byte[]/string overloads.

If the body of the `string` overload allocates a temp `byte[]` via `Encoding.UTF8.GetBytes`, wrap that temp in `SecureBuffer` and dispose it in a `finally`. This zeroes the PIN-bearing intermediate even on the obsolete path:

```csharp
    public void Login(CKU userType, string pin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(pin);
        int byteCount = Encoding.UTF8.GetByteCount(pin);
        using var tmp = new SecureBuffer(byteCount);
        Encoding.UTF8.GetBytes(pin, tmp.Span);
        byte[] copy = tmp.Span.ToArray();
        try
        {
            LoginCore(userType, copy);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(copy);
        }
    }
```

- [ ] **Step 4: Add tests for the new SecurePin overloads (Mock-runnable, login flow)**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Auth/SecurePinLoginTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Auth;

internal static class SecurePinLoginTestCases
{
    internal static void Assert_Login_AcceptsSecurePin(IPkcs11Backend backend)
    {
        var session = backend.Library.OpenSession(backend.SlotId, SessionType.ReadWrite);
        try
        {
            using var pin = new SecurePin(backend.UserPin);
            session.Login(CKU.CKU_USER, pin);
            session.Logout();
        }
        finally
        {
            session.CloseSession();
        }
    }

    internal static void Assert_Login_RejectsNullSecurePin(IPkcs11Backend backend)
    {
        var session = backend.Library.OpenSession(backend.SlotId, SessionType.ReadWrite);
        try
        {
            Assert.Throws<ArgumentNullException>(() => session.Login(CKU.CKU_USER, (SecurePin)null!));
        }
        finally
        {
            session.CloseSession();
        }
    }
}

[Collection("Mock")]
public sealed class SecurePinLoginTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;
    [Fact] public void Login_AcceptsSecurePin() => SecurePinLoginTestCases.Assert_Login_AcceptsSecurePin(_backend);
    [Fact] public void Login_RejectsNullSecurePin() => SecurePinLoginTestCases.Assert_Login_RejectsNullSecurePin(_backend);
}
```

- [ ] **Step 5: Build + run**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln --filter "FullyQualifiedName~SecurePinLoginTests" 2>&1 | grep -E "Passed!|Failed!"
```

Expected: 0 errors (some new `[Obsolete]` warnings on internal call sites that still use the legacy `byte[]`/`string` overloads — those are deliberate; suppress with `#pragma warning disable CS0618` inside the affected file only). 2 passed.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Auth/
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session): SecurePin overloads for Login/InitPin/SetPin + obsolete legacy

SecurePin overloads are the new recommended public path. byte[] and
string variants stay for backward compatibility but are marked
[Obsolete(error: false)] with a clear migration message.

Internal: the obsolete string overload encodes via SecureBuffer so the
transient PIN bytes are zeroed before the method returns, even on the
legacy code path. The SecurePin overload still has to copy out of the
pinned buffer into a byte[] for the existing protected helper; the
copy is zeroed in a finally."
```

---

## Task 4: `Pkcs11ModuleHandle` — `SafeHandle` for the native library

Wraps the `IntPtr` from `NativeLibrary.Load`. `ReleaseHandle()` calls `NativeLibrary.Free`. CriticalFinalizerObject means cleanup runs even on `Environment.FailFast`.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/LowLevel/SafeHandles/Pkcs11ModuleHandle.cs`

- [ ] **Step 1: Write the test file**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/LowLevel/SafeHandles/Pkcs11ModuleHandleTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.LowLevel.SafeHandles;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.LowLevel.SafeHandles;

[Collection("Mock")]
public sealed class Pkcs11ModuleHandleTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void InvalidHandle_IsInvalid_Returns_True()
    {
        using var handle = new Pkcs11ModuleHandle();
        Assert.True(handle.IsInvalid);
    }

    [Fact]
    public void LoadedHandle_IsInvalid_Returns_False()
    {
        IntPtr raw = NativeLibrary.Load(_backend.LibraryPath);
        using var handle = new Pkcs11ModuleHandle(raw);
        Assert.False(handle.IsInvalid);
    }

    [Fact]
    public void Dispose_FreesUnderlyingHandle_AndMarksInvalid()
    {
        IntPtr raw = NativeLibrary.Load(_backend.LibraryPath);
        var handle = new Pkcs11ModuleHandle(raw);
        Assert.False(handle.IsInvalid);
        handle.Dispose();
        Assert.True(handle.IsClosed);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~Pkcs11ModuleHandleTests" 2>&1 | tail -5
```

Expected: type not found.

- [ ] **Step 3: Implement `Pkcs11ModuleHandle.cs`**

```csharp
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.LowLevel.SafeHandles;

/// <summary>
/// <see cref="SafeHandle"/> wrapper for a PKCS#11 native module loaded via
/// <see cref="NativeLibrary.Load(string)"/>. Releases via <see cref="NativeLibrary.Free(IntPtr)"/>.
/// </summary>
/// <remarks>
/// SafeHandle inherits from <c>CriticalFinalizerObject</c>, so release runs even on
/// <c>Environment.FailFast</c> and during AppDomain unload — better protection against
/// native-handle leaks than a regular finalizer.
/// </remarks>
internal sealed class Pkcs11ModuleHandle : SafeHandle
{
    /// <summary>Creates an invalid handle. Used as a sentinel before <see cref="NativeLibrary.Load"/>.</summary>
    public Pkcs11ModuleHandle() : base(IntPtr.Zero, ownsHandle: true) { }

    /// <summary>Creates a handle that owns <paramref name="moduleHandle"/>.</summary>
    public Pkcs11ModuleHandle(IntPtr moduleHandle) : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(moduleHandle);
    }

    /// <inheritdoc/>
    public override bool IsInvalid => handle == IntPtr.Zero;

    /// <inheritdoc/>
    protected override bool ReleaseHandle()
    {
        if (handle == IntPtr.Zero) return true;
        try
        {
            NativeLibrary.Free(handle);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~Pkcs11ModuleHandleTests" 2>&1 | grep -E "Passed!|Failed!"
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/LowLevel/SafeHandles/Pkcs11ModuleHandle.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/LowLevel/SafeHandles/Pkcs11ModuleHandleTests.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(LowLevel): Pkcs11ModuleHandle SafeHandle for native library

Wraps the IntPtr returned by NativeLibrary.Load. ReleaseHandle calls
NativeLibrary.Free. As SafeHandle (a CriticalFinalizerObject), release
runs even on Environment.FailFast — better than a regular finalizer
for guarding against native-handle leaks."
```

---

## Task 5: Adopt `Pkcs11ModuleHandle` in `LowLevelPkcs11Library`

Switch the `IntPtr _library` field to `Pkcs11ModuleHandle _library`. Five touch sites in this file.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs`

- [ ] **Step 1: Read the current field declaration and usages**

```bash
grep -n "_library\b\|NativeLibrary\." src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs
```

Expected hits (~5): declaration (line 16), Load assignment (line 34), Delegates constructor call (line 35), Free call (line 1206), zero-out (line 1207).

- [ ] **Step 2: Apply the migration**

Add `using KerckhoffsLabs.Security.Cryptography.Pkcs11.LowLevel.SafeHandles;` at the top.

Change line 16 from:
```csharp
protected IntPtr _library = IntPtr.Zero;
```
to:
```csharp
protected Pkcs11ModuleHandle _library = new Pkcs11ModuleHandle();
```

Change lines 34-35:
```csharp
_library = NativeLibrary.Load(libraryPath);
_delegates = new Delegates(_library, useGetFunctionList);
```
to:
```csharp
_library = new Pkcs11ModuleHandle(NativeLibrary.Load(libraryPath));
_delegates = new Delegates(_library.DangerousGetHandle(), useGetFunctionList);
```

Change lines 1206-1207:
```csharp
NativeLibrary.Free(_library);
_library = IntPtr.Zero;
```
to:
```csharp
_library.Dispose();
_library = new Pkcs11ModuleHandle();
```

Check whether `Delegates` constructor takes `IntPtr` — it should, based on previous grep. If it takes `IntPtr`, no further changes needed in `Delegates.cs` (the .DangerousGetHandle() call gives the IntPtr it expects).

- [ ] **Step 3: Build + run all tests**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. Existing tests pass (the SafeHandle wrapper is functionally equivalent to the raw IntPtr from the caller's point of view).

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "refactor(LowLevel): adopt Pkcs11ModuleHandle for the native library handle

Five touch sites in LowLevelPkcs11Library.cs swap IntPtr _library for
Pkcs11ModuleHandle _library. Delegates constructor still takes IntPtr;
DangerousGetHandle() provides it. The SafeHandle ensures the library
is freed even on abnormal teardown."
```

---

## Task 6: `Pkcs11SessionHandle` — `SafeHandle` for the session

Wraps a session ID. `ReleaseHandle()` calls `_library.C_CloseSession(SessionId)`. Holds a reference to `LowLevelPkcs11Library` so the library's SafeHandle can't be released until all session SafeHandles are released.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/LowLevel/SafeHandles/Pkcs11SessionHandle.cs`

- [ ] **Step 1: Write the test file**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/LowLevel/SafeHandles/Pkcs11SessionHandleTests.cs`:

```csharp
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.LowLevel.SafeHandles;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.LowLevel.SafeHandles;

[Collection("Mock")]
public sealed class Pkcs11SessionHandleTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void InvalidHandle_IsInvalid_Returns_True()
    {
        using var lib = (LowLevelPkcs11Library)_backend.Library;
        using var handle = new Pkcs11SessionHandle(lib, CK.CK_INVALID_HANDLE);
        Assert.True(handle.IsInvalid);
    }

    [Fact]
    public void ValidHandle_SessionId_RoundTrips()
    {
        var sid = new NativeCULong(42);
        using var lib = (LowLevelPkcs11Library)_backend.Library;
        using var handle = new Pkcs11SessionHandle(lib, sid);
        Assert.Equal(sid, handle.SessionId);
        Assert.False(handle.IsInvalid);
    }
}
```

Note: this test treats `_backend.Library` as castable to `LowLevelPkcs11Library`. If `IPkcs11Backend.Library` returns `Pkcs11Library` (the high-level class), the test needs to reach the inner low-level via an accessor. Adapt to whatever the existing test plumbing exposes — read `MockBackendFixture.cs` first.

If the test setup makes constructing a bare `Pkcs11SessionHandle` against a real library impractical, simplify the test to a minimal invariants check (IsInvalid for default, SessionId round-trip via a fake/mocked library) and defer end-to-end ReleaseHandle coverage to the integrated tests in Task 8.

- [ ] **Step 2: Run tests to verify they fail**

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~Pkcs11SessionHandleTests" 2>&1 | tail -5
```

- [ ] **Step 3: Implement `Pkcs11SessionHandle.cs`**

```csharp
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.LowLevel.SafeHandles;

/// <summary>
/// <see cref="SafeHandle"/> wrapper around a PKCS#11 session handle. Calls
/// <c>C_CloseSession</c> on release. Holds a reference to the owning
/// <see cref="LowLevelPkcs11Library"/> so the library SafeHandle cannot be released
/// while any session is still open.
/// </summary>
internal sealed class Pkcs11SessionHandle : SafeHandle
{
    private readonly LowLevelPkcs11Library _library;

    public Pkcs11SessionHandle(LowLevelPkcs11Library library, NativeCULong sessionId)
        : base(IntPtr.Zero, ownsHandle: true)
    {
        _library = library ?? throw new ArgumentNullException(nameof(library));
        SetHandle((IntPtr)(ulong)sessionId);
    }

    /// <summary>The underlying PKCS#11 session handle.</summary>
    public NativeCULong SessionId => (NativeCULong)(ulong)handle;

    /// <inheritdoc/>
    public override bool IsInvalid =>
        SessionId == CK.CK_INVALID_HANDLE;

    /// <inheritdoc/>
    protected override bool ReleaseHandle()
    {
        if (IsInvalid) return true;
        try
        {
            CKR rv = _library.C_CloseSession(SessionId);
            return rv == CKR.CKR_OK;
        }
        catch
        {
            return false;
        }
    }
}
```

Note on `(IntPtr)(ulong)sessionId`: `NativeCULong` is `uint` on Windows and `nuint` on Unix-LP64. Casting through `ulong` then `IntPtr` is portable. The reverse cast in `SessionId` uses the same two-step.

- [ ] **Step 4: Run tests to verify they pass**

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~Pkcs11SessionHandleTests" 2>&1 | grep -E "Passed!|Failed!"
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/LowLevel/SafeHandles/Pkcs11SessionHandle.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/LowLevel/SafeHandles/Pkcs11SessionHandleTests.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(LowLevel): Pkcs11SessionHandle SafeHandle for session lifecycle

Wraps a session ID and a reference to the owning LowLevelPkcs11Library.
ReleaseHandle calls C_CloseSession. The library reference prevents the
library SafeHandle from being released while sessions are still open
(GC reachability invariant)."
```

---

## Task 7: Adopt `Pkcs11SessionHandle` in `Session.cs`

Replace `protected NativeCULong _sessionId` with a `Pkcs11SessionHandle _sessionHandle` field plus a shim property `protected NativeCULong _sessionId => _sessionHandle.SessionId;` so the 12 partials don't need to change. Remove the `~Session()` finalizer — SafeHandle takes over critical cleanup.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`

- [ ] **Step 1: Read the current field, constructor, and Dispose pattern**

```bash
grep -n "_sessionId\|~Session\|protected virtual void Dispose\|_pkcs11Library" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs | head -25
```

Confirm: field at line 31, constructor stores the session ID around line 112, finalizer around line 513, Dispose pattern nearby, and `_pkcs11Library` is the `LowLevelPkcs11Library` reference.

- [ ] **Step 2: Add `_sessionHandle` field; convert `_sessionId` to a shim**

Replace:
```csharp
protected NativeCULong _sessionId = CK.CK_INVALID_HANDLE;
```
with:
```csharp
protected Pkcs11SessionHandle _sessionHandle = null!;

/// <summary>Compatibility shim — returns the underlying session ID. Read-only.</summary>
protected NativeCULong _sessionId
{
    get => _sessionHandle is null ? CK.CK_INVALID_HANDLE : _sessionHandle.SessionId;
}
```

Add `using KerckhoffsLabs.Security.Cryptography.Pkcs11.LowLevel.SafeHandles;`.

- [ ] **Step 3: Initialize `_sessionHandle` in the constructor**

Replace:
```csharp
_sessionId = (NativeCULong)(sessionId);
```
with:
```csharp
_sessionHandle = new Pkcs11SessionHandle(_pkcs11Library, (NativeCULong)sessionId);
```

- [ ] **Step 4: Rewrite `CloseSession`**

Find the existing `CloseSession` method (around line 120). Replace its body so the close goes through `_sessionHandle.Dispose()` instead of directly calling `C_CloseSession`:

```csharp
    public void CloseSession()
    {
        if (_disposed) return;
        if (_sessionHandle is null || _sessionHandle.IsInvalid) return;

        _logger.Debug("Session({0})::CloseSession", _sessionId);
        _logger.Info("Closing session {0}", _sessionId);

        // SafeHandle.Dispose triggers ReleaseHandle, which calls C_CloseSession on the library.
        _sessionHandle.Dispose();
        _sessionHandle = null!;
    }
```

- [ ] **Step 5: Update Dispose(bool) / remove the finalizer**

Find the `~Session()` finalizer and the `Dispose(bool)` method. Remove the finalizer entirely. Inside `Dispose(bool)` change the cleanup to:

```csharp
    protected virtual void Dispose(bool disposing)
    {
        if (_disposed) return;
        if (disposing)
        {
            // Managed cleanup — release the session handle, which closes the session via SafeHandle.
            _sessionHandle?.Dispose();
            _sessionHandle = null!;
        }
        // No unmanaged resources owned by Session directly anymore — Pkcs11SessionHandle owns the
        // session ID, Pkcs11ModuleHandle owns the library module. Both are SafeHandles and run their
        // own critical finalizers.
        _disposed = true;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
```

Remove the `~Session()` finalizer block entirely.

- [ ] **Step 6: Suppress obsolete-warning churn**

If the file references its own `[Obsolete]` overloads internally (from Task 3), wrap those call sites with `#pragma warning disable CS0618 // obsolete` … `#pragma warning restore CS0618` to keep the build clean.

- [ ] **Step 7: Build + run all tests**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. All existing tests still pass — the shim property keeps the partials working unchanged.

If a partial does anything that writes to `_sessionId` (rather than reading), the build will fail with "property is read-only." That's intentional — find the offender and change it to `_sessionHandle = new Pkcs11SessionHandle(_pkcs11Library, newSid);` or similar. Likely no such site outside the constructor and CloseSession.

- [ ] **Step 8: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "refactor(Session): Pkcs11SessionHandle backing + remove Session finalizer

Session._sessionId becomes a read-only shim over Pkcs11SessionHandle.SessionId,
so the 12 partials don't change. CloseSession + Dispose route through the
SafeHandle.

The explicit ~Session finalizer is removed: SafeHandle is a
CriticalFinalizerObject and runs its release after regular finalizers,
which is exactly what we want for native-handle cleanup."
```

---

## Task 8: Full integration test pass

Run the entire suite to confirm Phase 4b changes haven't broken anything.

- [ ] **Step 1: Clean Release build + full test run**

```bash
dotnet clean src/src.sln >/dev/null
dotnet build src/src.sln -c Release 2>&1 | tail -3
dotnet test src/src.sln -c Release --no-build 2>&1 | grep -E "Passed!|Failed!" | tail -3
```

Expected: 0 errors. Test counts go up by approximately:
- +7 SecurePinTests
- +6 SecureBufferTests
- +3 Pkcs11ModuleHandleTests
- +2 Pkcs11SessionHandleTests
- +2 SecurePinLoginTests_Mock
- Total new: ~20 Mock-runnable tests, all passing
- Pre-existing pass count unchanged
- Skipped count unchanged

If any pre-existing test regresses, STOP and investigate before continuing.

- [ ] **Step 2: Verify pack still works**

```bash
dotnet pack src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -c Release -p:SkipPkcs11MockBuild=true -o /tmp/pack-test 2>&1 | tail -3
ls /tmp/pack-test/
rm -rf /tmp/pack-test
```

Expected: nupkg + snupkg generated.

- [ ] **Step 3: Verify Phase 4b exit-criteria invariants**

```bash
echo "=== SecurePin + SecureBuffer ===" ; ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Security/SecurePin.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Security/SecureBuffer.cs
echo "=== SafeHandles ===" ; ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11/LowLevel/SafeHandles/Pkcs11ModuleHandle.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/LowLevel/SafeHandles/Pkcs11SessionHandle.cs
echo "=== _library is Pkcs11ModuleHandle ===" ; grep -c "Pkcs11ModuleHandle _library" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/LowLevelPkcs11Library.cs
echo "=== _sessionHandle is Pkcs11SessionHandle ===" ; grep -c "Pkcs11SessionHandle _sessionHandle" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
echo "=== Session has no finalizer ===" ; grep -c "~Session" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
echo "=== SecurePin overload on Login ===" ; grep -c "Login(CKU userType, SecurePin" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
echo "=== byte[]/string overloads are [Obsolete] ===" ; grep -cE "\[Obsolete.*SecurePin" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
```

Expected:
- All 4 file listings show the files exist.
- `_library is Pkcs11ModuleHandle` → 1.
- `_sessionHandle is Pkcs11SessionHandle` → 1.
- `Session has no finalizer` → 0.
- `SecurePin overload on Login` → 1.
- `byte[]/string overloads are [Obsolete]` → 6 (Login string + byte[]; InitPin string + byte[]; SetPin string + byte[]).

- [ ] **Step 4: Tag the milestone**

```bash
git -C /home/alexandre/dev/PKCS11.NET tag -a phase-4b-complete -m "Phase 4b complete: SecurePin + SecureBuffer + SafeHandle adoption

Delivered:
- SecurePin (public, IDisposable): pinned byte[], ZeroMemory on Dispose,
  finalizer safety net. Two ctors: ReadOnlySpan<byte> (preferred) and
  string (UTF-8 with transient buffer zeroed).
- SecureBuffer (internal, IDisposable): same pattern, used inside the
  library for transient PIN/key material.
- Pkcs11ModuleHandle: SafeHandle for the NativeLibrary module IntPtr.
- Pkcs11SessionHandle: SafeHandle for the session ID; ReleaseHandle
  calls C_CloseSession. Holds a reference to LowLevelPkcs11Library to
  keep the module SafeHandle alive while sessions remain open.
- Session.Login/InitPin/SetPin: SecurePin overloads are the new preferred
  surface; byte[]/string overloads are [Obsolete(error: false)] for soft
  migration per spec line 109.
- LowLevelPkcs11Library: IntPtr _library replaced with Pkcs11ModuleHandle.
- Session: _sessionId becomes a shim over Pkcs11SessionHandle.SessionId;
  ~Session finalizer removed (SafeHandle takes over critical cleanup).

Out of scope (deferred):
- Phase 4c: Memory-leak + thread-safety test suites.
- Public SecureBuffer-returning overloads of Decrypt/WrapKey/GenerateRandom.
- SafeHandle adoption on IMechanismParams/ObjectAttribute unmanaged buffers."
```

---

## Phase 4b Exit Checklist

- [ ] `dotnet build src/src.sln -c Release` succeeds with 0 errors.
- [ ] All tests pass; SoftHsm-gated tests skip on dev hosts without SoftHSM2.
- [ ] `Security/SecurePin.cs` and `Security/SecureBuffer.cs` exist.
- [ ] `LowLevel/SafeHandles/Pkcs11ModuleHandle.cs` and `Pkcs11SessionHandle.cs` exist.
- [ ] `LowLevelPkcs11Library._library` is `Pkcs11ModuleHandle`.
- [ ] `Session._sessionHandle` is `Pkcs11SessionHandle`; `_sessionId` is a shim property; `~Session()` finalizer removed.
- [ ] `Session.Login`/`InitPin`/`SetPin` have `SecurePin` overloads and `[Obsolete]` `byte[]`/`string` overloads.
- [ ] Tag `phase-4b-complete` exists.

When all checked, Phase 4b is complete. Phase 4c (memory-leak + thread-safety test suites) can be planned next.
