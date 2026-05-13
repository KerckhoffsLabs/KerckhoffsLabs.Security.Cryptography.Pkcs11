# PKCS11 Workspace + Key Implementation Plan (Plan 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the public `Pkcs11Workspace` (auth context, key factory) and `Pkcs11Key` (handle wrapper with mechanism-level surface and auto-discovered public companion) abstractions on top of the existing `Session` infrastructure, leaving `Session` untouched as a public type until Plan 4 demotes it to `internal Pkcs11Session`.

**Architecture:** `Pkcs11Workspace` wraps a `Pkcs11Library` + `Slot` + `Session` triple. `Pkcs11Key` wraps a `Pkcs11Workspace` reference plus a private/public `ObjectHandle` pair (one may be `Invalid`). All operations on `Pkcs11Key` delegate to the underlying `Session` — Plan 2 introduces no new native surface; it shapes the existing one. Public-key views for asymmetric keys are either a real `CKO_PUBLIC_KEY` handle found by CKA_ID, or a synthesized view computed in managed code from `CKA_MODULUS`+`CKA_PUBLIC_EXPONENT` (RSA) or `CKA_EC_POINT`+`CKA_EC_PARAMS` (EC) on the private key.

**Tech Stack:** C# 12, .NET 8/9, xUnit 2.9 with `MockBackendFixture`/`SoftHsmBackendFixture` collection-paired pattern, `Pkcs11Exception.ThrowIfError` from Plan 1.

**Spec:** `docs/superpowers/specs/2026-05-13-pkcs11-bcl-aligned-redesign-design.md`

**Working directory:** `/home/alexandre/dev/PKCS11.NET`

---

## Project conventions worth knowing

- **Solution file:** `src/KerckhoffsLabs.sln`. Build: `dotnet build src/KerckhoffsLabs.sln -c Debug`. Test all: `dotnet test src/KerckhoffsLabs.sln -c Debug`. Filter: `--filter "FullyQualifiedName~ClassName"`.
- **Git workflow:** The repo is on branch `main` with two Plan-1 commits at HEAD (`refactor(ObjectHandle): ...` then `feat(Pkcs11): plan-1 foundations`). Plan 2 lands on `main` as additional commits. Commit messages follow the existing style: `<scope>(<area>): <one-line summary>` followed by a multi-section body. Sign with `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`.
- **InternalsVisibleTo:** the test project sees production internals (`<InternalsVisibleTo Include="KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests" />`). Tests can call internal members directly.
- **Pkcs11Exception conventions** (settled in Plan 1):
  - `Pkcs11Exception.ThrowIfError(rv, "C_MethodName")` for guard-clause throws (no-op on CKR_OK).
  - `Pkcs11Exception.Throw(rv, "C_MethodName")` ([DoesNotReturn]) for unconditional throws.
  - `throw Pkcs11Exception.Create(rv, "C_MethodName")` for literal-throw expression contexts requiring CS0177 satisfaction.
  - Never construct a typed `Pkcs11Exception` subclass directly in production code — only `Common/ExceptionMapper.cs` is allowed to do that.
- **ObjectTemplate conventions** (settled in Plan 1): `ObjectTemplate.ForSecretKey(CKK).Build()` style. `ObjectTemplate` is `IDisposable` — pass it via `using` or dispose explicitly. Its internal `Attributes` accessor returns `IReadOnlyList<ObjectAttribute>` for marshalling.
- **ObjectHandle is a `readonly record struct`** (post-Plan 1). `ObjectHandle.Invalid` is the zero/sentinel value. `ObjectHandle.IsInvalid` checks for it.
- **xUnit collection fixtures:** existing tests use `[Collection("Mock")]` + `[Collection("SoftHsm")]` paired test classes that share a static helper class. Follow the existing pattern (see `Tests/HighLevel/Encrypt/EncryptChaChaTests.cs` for the model).
- **Mock backend availability:** pkcs11-mock supports a subset of mechanisms. Many integration tests are SoftHSM-only via `[ConditionalFact(nameof(SoftHsmAvailable))]` from `Microsoft.DotNet.XUnitExtensions`. New tests in this plan use the same gate when they need real crypto.
- **Native-call routing:** `Session` already owns the `_p11` (LowLevelPkcs11Library) reference. Pkcs11Workspace **does not** open another native handle — it holds a `Session` instance and delegates. Pkcs11Key **does not** open anything native either; it holds object handles and delegates through the workspace's session.

---

## File structure

### New production files

```
src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
└── HighLevel/
    ├── Pkcs11Workspace.cs                   PUBLIC. Auth context. Wraps Pkcs11Library + Slot + Session.
    ├── Pkcs11Workspace.Random.cs            PUBLIC. Random / Digest passthroughs.
    ├── Pkcs11Workspace.Keys.cs              PUBLIC. OpenKey / FindKeys / ImportKey / GenerateKey overloads.
    ├── Pkcs11Key.cs                         PUBLIC. Key handle wrapper + Open factories.
    ├── Pkcs11Key.Mechanism.cs               PUBLIC. Sign/Verify/Encrypt/Decrypt/Wrap/Unwrap/Derive.
    └── Pkcs11PublicKeyView.cs               internal. Synthesized public-key view for asymmetric private-only keys.
```

### Modified production files

```
src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
└── HighLevel/
    └── Pkcs11Library.cs                     Add `OpenWorkspace(slotLabel, userType, pin)` factory.
```

### New test files

```
src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/
└── HighLevel/
    ├── Pkcs11WorkspaceTests.cs              Open/close lifecycle, slot lookup, ownership.
    ├── Pkcs11KeyTests.cs                    Open/close, properties, dispose semantics, one-shot Open factories.
    ├── Pkcs11WorkspaceRandomTests.cs        Random/Digest passthrough.
    ├── Pkcs11WorkspaceFindKeysTests.cs      FindKeys + ImportKey.
    ├── Pkcs11WorkspaceGenerateKeyTests.cs   Symmetric + asymmetric generation.
    ├── Pkcs11KeyMechanismTests.cs           Sign/Verify/Encrypt/Decrypt/Wrap/Unwrap/Derive round-trips.
    └── Pkcs11KeyPublicSynthesisTests.cs     RSA + EC public-key synthesis paths.
```

Each integration test file uses the Mock + SoftHsm dual-class pattern from existing tests. Managed-only tests (argument validation, lifecycle) live in the same file but use `[Fact]` rather than `[ConditionalFact]`.

---

## Type ownership / lifetime rules

A small reference table referenced by tasks:

| Constructed by | Owns library | Owns workspace | Owns session | Dispose cascade |
|---|---|---|---|---|
| `library.OpenWorkspace(...)` | no | (returns workspace) | yes | workspace.Dispose → session.Dispose. Library left alone. |
| `workspace.OpenKey(...)` | no | no | no | key.Dispose → managed only (handles not destroyed). |
| `Pkcs11Key.Open(libraryPath, ...)` | yes | yes | yes | key.Dispose → workspace.Dispose → session.Dispose → library.Dispose. |
| `Pkcs11Key.Open(library, ...)` | no | yes | yes | key.Dispose → workspace.Dispose → session.Dispose. Library left alone. |

`Pkcs11Key.Dispose` never destroys the underlying PKCS#11 object — handles refer to token-side state that may outlive the wrapper. Callers who want to destroy must use the existing `Session.DestroyObject(ObjectHandle)` (Plan 4 will move that to `Pkcs11Workspace.DestroyKey` or similar).

---

## Task list

### Task 1: `Pkcs11Workspace` skeleton + `Pkcs11Library.OpenWorkspace`

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Workspace.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Library.cs` (add `OpenWorkspace` method)
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceTests.cs`

Purpose: Establish the workspace shape — a thin wrapper over `Pkcs11Library` + `Slot` + `Session` constructed by an authentication operation. Dispose closes the session and logs out. The class is partial so subsequent tasks add operations in separate files.

- [ ] **Step 1: Write the failing argument-validation tests**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public sealed class Pkcs11WorkspaceTests
{
    [Fact]
    public void OpenWorkspace_NullSlotLabel_Throws()
    {
        using var library = NullLibraryStub.Build();

        Assert.Throws<ArgumentNullException>(() =>
            library.OpenWorkspace(slotLabel: null!, CKU.CKU_USER, new SecurePin("12345"u8)));
    }

    [Fact]
    public void OpenWorkspace_NullPin_Throws()
    {
        using var library = NullLibraryStub.Build();

        Assert.Throws<ArgumentNullException>(() =>
            library.OpenWorkspace(slotLabel: "x", CKU.CKU_USER, pin: null!));
    }

    /// <summary>
    /// Minimal Pkcs11Library construction harness for argument-validation tests that do
    /// not need a working backend. The library is constructed against the mock so that
    /// it can be disposed cleanly even though no operations are performed.
    /// </summary>
    private static class NullLibraryStub
    {
        public static Pkcs11Library Build()
        {
            var path = MockBackendFixture.MockLibraryPath;
            if (path is null) throw new SkipTestException("pkcs11-mock not available.");
            return new Pkcs11Library(path);
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11WorkspaceTests" -c Debug
```

Expected: build error — `Pkcs11Library.OpenWorkspace` does not exist, neither does `Pkcs11Workspace`.

- [ ] **Step 3: Create `Pkcs11Workspace.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Authenticated context against a PKCS#11 token. Holds the library, slot, and active
/// session and exposes the operations a caller performs while logged in.
/// </summary>
/// <remarks>
/// <para>
/// Construction is exclusively via <see cref="Pkcs11Library.OpenWorkspace(string, CKU, Security.SecurePin)"/>.
/// The workspace does not own the library — callers continue to own and dispose the
/// <see cref="Pkcs11Library"/> they passed (or the one they constructed via the
/// <see cref="Pkcs11Library(string)"/> ctor). The workspace owns the session it opened
/// and closes it on <see cref="Dispose"/>; the session's own Dispose logs the user out
/// before closing.
/// </para>
/// <para>
/// Keys obtained via the workspace's factory methods (Plan-2 Tasks 4–6) hold a non-owning
/// reference to the workspace. The workspace must outlive any key produced from it.
/// </para>
/// </remarks>
public sealed partial class Pkcs11Workspace : IDisposable
{
    private readonly Pkcs11Library _library;
    private readonly Slot _slot;
    private readonly Session _session;
    private bool _disposed;

    internal Pkcs11Workspace(Pkcs11Library library, Slot slot, Session session)
    {
        _library = library;
        _slot = slot;
        _session = session;
    }

    /// <summary>The slot this workspace is authenticated against.</summary>
    public Slot Slot => _slot;

    /// <summary>The library that hosts this workspace. The workspace does not own the library.</summary>
    public Pkcs11Library Library => _library;

    /// <summary>Internal accessor for the underlying session. Used by <see cref="Pkcs11Key"/> to delegate operations.</summary>
    internal Session Session => _session;

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        // Session.Dispose closes the session (and logs out if logged in) per its own
        // documented semantics.
        _session.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
```

- [ ] **Step 4: Add `OpenWorkspace` to `Pkcs11Library.cs`**

Locate the `Pkcs11Library` class body in `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Library.cs`. Find a logical spot before the `Dispose` method and add:

```csharp
    /// <summary>
    /// Opens an authenticated workspace against the slot whose token label matches
    /// <paramref name="slotLabel"/>.
    /// </summary>
    /// <param name="slotLabel">The token label (case-sensitive, trimmed of trailing
    /// spaces — PKCS#11 pads labels with spaces to 32 chars).</param>
    /// <param name="userType">The PKCS#11 user type to log in as.</param>
    /// <param name="pin">The PIN. The workspace does not retain the PIN past construction.</param>
    /// <returns>An open <see cref="Pkcs11Workspace"/>. Callers must <c>Dispose</c> it.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="slotLabel"/> or <paramref name="pin"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if no slot with a matching token label is present.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying PKCS#11 calls.</exception>
    public Pkcs11Workspace OpenWorkspace(string slotLabel, CKU userType, Security.SecurePin pin)
    {
        ArgumentNullException.ThrowIfNull(slotLabel);
        ArgumentNullException.ThrowIfNull(pin);

        Slot? matched = null;
        foreach (var slot in GetSlotList(SlotsType.WithTokenPresent))
        {
            if (slot.GetTokenInfo().Label.TrimEnd() == slotLabel)
            {
                matched = slot;
                break;
            }
        }

        if (matched is null)
            throw new ArgumentException(
                $"No slot found with token label '{slotLabel}'.", nameof(slotLabel));

        var session = matched.OpenSession(SessionType.ReadWrite);
        try
        {
            session.Login(userType, pin);
            return new Pkcs11Workspace(this, matched, session);
        }
        catch
        {
            session.CloseSession();
            throw;
        }
    }
```

- [ ] **Step 5: Run tests to verify the two argument-null tests pass**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11WorkspaceTests" -c Debug
```

Expected: 2/2 pass (or skipped if pkcs11-mock isn't available — the `Build()` helper throws `SkipTestException` in that case, which xUnit reports as Skip rather than Fail).

- [ ] **Step 6: Verify the full test suite still passes**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures.

- [ ] **Step 7: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Workspace.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Library.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceTests.cs

git commit -m "$(cat <<'EOF'
feat(Pkcs11Workspace): authenticated context wrapper

Introduces Pkcs11Workspace as the public auth-context type that wraps
the Pkcs11Library + Slot + Session triple. Constructed via the new
Pkcs11Library.OpenWorkspace(slotLabel, userType, pin) factory which
finds the matching slot, opens an R/W session, logs in, and hands back
an owning Workspace. Workspace.Dispose closes the session; the library
is left to the caller. The class is partial so subsequent commits add
operation surface (random/digest, key open, generation, mechanism ops)
in separate files.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `Pkcs11Workspace` non-key-bound passthroughs (Random + Digest)

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Workspace.Random.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceRandomTests.cs`

Purpose: Add the operations on the workspace that take no key handle: `GenerateRandom`, `SeedRandom`, `Digest` (data-only digest, not key-digest). Thin delegations to `Session` equivalents.

- [ ] **Step 1: Write the failing tests**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceRandomTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

[Collection("Mock")]
public sealed class Pkcs11WorkspaceRandomTests_Mock
{
    private readonly MockBackendFixture _backend;
    public Pkcs11WorkspaceRandomTests_Mock(MockBackendFixture backend) => _backend = backend;

    public static bool MockAvailable => MockBackendFixture.IsAvailable;

    [ConditionalFact(nameof(MockAvailable))]
    public void GenerateRandom_ReturnsRequestedLength()
    {
        using var workspace = OpenMockWorkspace(_backend);

        byte[] bytes = workspace.GenerateRandom(32);

        Assert.Equal(32, bytes.Length);
    }

    [ConditionalFact(nameof(MockAvailable))]
    public void GenerateRandom_ZeroLength_ThrowsArgumentOutOfRange()
    {
        using var workspace = OpenMockWorkspace(_backend);

        Assert.Throws<ArgumentOutOfRangeException>(() => workspace.GenerateRandom(0));
    }

    [ConditionalFact(nameof(MockAvailable))]
    public void Digest_NonNullMechanism_DataOnly_DelegatesToSession()
    {
        using var workspace = OpenMockWorkspace(_backend);
        var mechanism = new Mechanism(CKM.CKM_SHA256);
        byte[] data = System.Text.Encoding.UTF8.GetBytes("hello");

        byte[] hash = workspace.Digest(mechanism, data);

        Assert.Equal(32, hash.Length); // SHA-256 = 32 bytes
    }

    [ConditionalFact(nameof(MockAvailable))]
    public void Digest_NullMechanism_Throws()
    {
        using var workspace = OpenMockWorkspace(_backend);

        Assert.Throws<ArgumentNullException>(() => workspace.Digest(mechanism: null!, new byte[1]));
    }

    private static Pkcs11Workspace OpenMockWorkspace(MockBackendFixture backend)
    {
        if (!MockBackendFixture.IsAvailable) throw new SkipTestException("pkcs11-mock not available.");
        var library = backend.Library;
        return library.OpenWorkspace(MockBackendFixture.TokenLabel, CKU.CKU_USER,
            new SecurePin(MockBackendFixture.UserPin));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail (or skip if mock missing)**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11WorkspaceRandomTests" -c Debug
```

Expected: build error — `workspace.GenerateRandom`, `workspace.Digest`, and `workspace.SeedRandom` do not exist.

- [ ] **Step 3: Inspect `MockBackendFixture` to confirm the fixture's public surface**

```bash
grep -n "public " src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Fixtures/MockBackendFixture.cs | head -20
```

Locate the `Library` property, `TokenLabel` constant, `UserPin` constant, and `IsAvailable`/`MockLibraryPath` members. If any are named differently in the existing fixture, adapt the test code in Step 1 to match the actual names. (Do this BEFORE running the failing-test step again.)

If `IsAvailable` or `MockLibraryPath` doesn't exist as a static, add them to the fixture as needed — the test convention in this project is to expose availability as a static for `[ConditionalFact]`.

- [ ] **Step 4: Create `Pkcs11Workspace.Random.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public sealed partial class Pkcs11Workspace
{
    /// <summary>
    /// Reads <paramref name="length"/> bytes from the token's RNG.
    /// </summary>
    /// <param name="length">Number of bytes to generate. Must be &gt; 0.</param>
    /// <returns>A newly allocated byte array of length <paramref name="length"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="length"/> is &lt;= 0.</exception>
    public byte[] GenerateRandom(int length)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (length <= 0)
            throw new ArgumentOutOfRangeException(nameof(length), "Length must be > 0.");
        return _session.GenerateRandom(length);
    }

    /// <summary>
    /// Seeds the token's RNG with the supplied bytes. Optional — many tokens ignore seed
    /// data because they use hardware entropy.
    /// </summary>
    /// <param name="seed">Seed bytes. Must not be empty.</param>
    public void SeedRandom(ReadOnlySpan<byte> seed)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (seed.IsEmpty)
            throw new ArgumentException("Seed must not be empty.", nameof(seed));
        _session.SeedRandom(seed);
    }

    /// <summary>
    /// Computes a one-shot digest over <paramref name="data"/> using the given mechanism.
    /// </summary>
    /// <param name="mechanism">Digest mechanism (e.g. <see cref="Mechanism"/> wrapping <see cref="CKM.CKM_SHA256"/>).</param>
    /// <param name="data">The data to digest.</param>
    /// <returns>The digest bytes.</returns>
    public byte[] Digest(Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        return _session.Digest(mechanism, data);
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11WorkspaceRandomTests" -c Debug
```

Expected: 4/4 pass (or skipped if mock unavailable).

- [ ] **Step 6: Verify full suite**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures.

- [ ] **Step 7: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Workspace.Random.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceRandomTests.cs

git commit -m "$(cat <<'EOF'
feat(Pkcs11Workspace): GenerateRandom + SeedRandom + Digest passthroughs

Three non-key-bound operations layered on Session: GenerateRandom(int),
SeedRandom(ReadOnlySpan<byte>), Digest(Mechanism, ReadOnlySpan<byte>).
Each guards on _disposed and on its own argument contracts; the actual
work delegates to the underlying Session. Tests cover happy-path
round-trip via the mock backend plus the argument-validation paths.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `Pkcs11Key` skeleton

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Key.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyTests.cs`

Purpose: Define `Pkcs11Key` with constructors, identifying properties, and disposal semantics. No operations yet — those are Tasks 9–11.

- [ ] **Step 1: Write the failing tests**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public sealed class Pkcs11KeyTests
{
    [Fact]
    public void Ctor_NullWorkspace_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new Pkcs11Key(
                workspace: null!,
                privateHandle: default,
                publicHandle: default,
                keyType: CKK.CKK_AES,
                label: null,
                id: Array.Empty<byte>(),
                ownedLibrary: null,
                ownsWorkspace: false));
    }

    [Fact]
    public void Ctor_BothHandlesInvalid_Throws()
    {
        // A Pkcs11Key must carry at least one valid handle (private, public, or symmetric).
        Assert.Throws<ArgumentException>(() =>
            new Pkcs11Key(
                workspace: WorkspaceStub.Build(),
                privateHandle: ObjectHandle.Invalid,
                publicHandle: ObjectHandle.Invalid,
                keyType: CKK.CKK_AES,
                label: null,
                id: Array.Empty<byte>(),
                ownedLibrary: null,
                ownsWorkspace: false));
    }

    [Fact]
    public void Properties_AreExposed()
    {
        var workspace = WorkspaceStub.Build();
        byte[] id = { 0x01, 0x02 };
        var key = new Pkcs11Key(
            workspace,
            privateHandle: new ObjectHandle(42),
            publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_RSA,
            label: "my-key",
            id: id,
            ownedLibrary: null,
            ownsWorkspace: false);

        Assert.Equal(CKK.CKK_RSA, key.KeyType);
        Assert.Equal("my-key", key.Label);
        Assert.True(id.AsSpan().SequenceEqual(key.Id));

        key.Dispose();
    }

    [Fact]
    public void Dispose_OwnsWorkspace_DisposesWorkspace()
    {
        var workspace = WorkspaceStub.Build();
        var key = new Pkcs11Key(
            workspace,
            privateHandle: new ObjectHandle(1),
            publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_AES,
            label: null,
            id: Array.Empty<byte>(),
            ownedLibrary: null,
            ownsWorkspace: true);

        key.Dispose();
        // Re-dispose is a no-op; should not throw.
        key.Dispose();
    }

    /// <summary>
    /// Builds a Pkcs11Workspace via reflection for unit tests that need a workspace
    /// instance but no real backend. Uses the internal ctor — InternalsVisibleTo gives
    /// the test assembly access. The returned workspace is NOT functional; only its
    /// reference identity matters for these tests.
    /// </summary>
    private static class WorkspaceStub
    {
        public static Pkcs11Workspace Build()
        {
            // Internal ctor is accessible; we pass null! for the dependencies because no
            // real operations run. This is a unit-only stub; integration tests open a
            // real workspace via Pkcs11Library.OpenWorkspace.
            return (Pkcs11Workspace)Activator.CreateInstance(
                typeof(Pkcs11Workspace),
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic,
                binder: null,
                args: new object?[] { null, null, null },
                culture: null)!;
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11KeyTests" -c Debug
```

Expected: build error — `Pkcs11Key` does not exist.

- [ ] **Step 3: Create `Pkcs11Key.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Handle wrapper over a PKCS#11 key object. Carries the workspace it belongs to, the
/// private and/or public handles, and the cached identifying metadata (label, ID, key
/// type). Operations (Sign, Verify, Encrypt, Decrypt, Wrap, Unwrap, Derive) live on a
/// partial file (<c>Pkcs11Key.Mechanism.cs</c>) and delegate through the workspace's
/// session.
/// </summary>
/// <remarks>
/// <para>
/// Instances are produced by <see cref="Pkcs11Workspace"/> factory methods
/// (<c>OpenKey</c>, <c>GenerateKey</c>, <c>ImportKey</c>) or by the static
/// <see cref="Open(string, string, CKU, Security.SecurePin, string)"/> one-shot
/// factories. The <c>internal</c> constructor remains visible to the test assembly via
/// <c>InternalsVisibleTo</c>.
/// </para>
/// <para>
/// Disposing a key releases owned resources (workspace and/or library, depending on how
/// the key was constructed — see the one-shot <c>Open</c> overloads). It does NOT
/// destroy the underlying PKCS#11 object on the token; handles refer to token-side state
/// that may legitimately outlive the wrapper.
/// </para>
/// <para>
/// Asymmetric keys may carry both a private and a public handle (paired automatically
/// via <c>CKA_ID</c> by <see cref="Pkcs11Workspace.OpenKey(string)"/>) or only one. A
/// public-only key has <c>privateHandle == ObjectHandle.Invalid</c>; a private-only
/// key on a token without a stored <c>CKO_PUBLIC_KEY</c> companion has
/// <c>publicHandle == ObjectHandle.Invalid</c> (operations needing the public side will
/// fall back to managed synthesis — see Tasks 7–8).
/// </para>
/// </remarks>
public sealed partial class Pkcs11Key : IDisposable
{
    private readonly Pkcs11Workspace _workspace;
    private readonly Pkcs11Library? _ownedLibrary;
    private readonly bool _ownsWorkspace;
    private readonly ObjectHandle _privateHandle;
    private readonly ObjectHandle _publicHandle;
    private readonly CKK _keyType;
    private readonly string? _label;
    private readonly byte[] _id;
    private bool _disposed;

    internal Pkcs11Key(
        Pkcs11Workspace workspace,
        ObjectHandle privateHandle,
        ObjectHandle publicHandle,
        CKK keyType,
        string? label,
        byte[] id,
        Pkcs11Library? ownedLibrary,
        bool ownsWorkspace)
    {
        ArgumentNullException.ThrowIfNull(workspace);
        if (privateHandle.IsInvalid && publicHandle.IsInvalid)
            throw new ArgumentException(
                "Pkcs11Key must carry at least one valid handle.",
                nameof(privateHandle));

        _workspace = workspace;
        _privateHandle = privateHandle;
        _publicHandle = publicHandle;
        _keyType = keyType;
        _label = label;
        _id = id ?? Array.Empty<byte>();
        _ownedLibrary = ownedLibrary;
        _ownsWorkspace = ownsWorkspace;
    }

    /// <summary>The PKCS#11 key type (e.g. <see cref="CKK.CKK_AES"/>, <see cref="CKK.CKK_RSA"/>).</summary>
    public CKK KeyType => _keyType;

    /// <summary>The key's CKA_LABEL, or <c>null</c> if not set on the token.</summary>
    public string? Label => _label;

    /// <summary>The key's CKA_ID. Returns an empty span if not set on the token.</summary>
    public ReadOnlySpan<byte> Id => _id;

    /// <summary>Internal accessor for the workspace this key belongs to.</summary>
    internal Pkcs11Workspace Workspace => _workspace;

    /// <summary>Internal accessor for the private handle. <see cref="ObjectHandle.Invalid"/> for public-only keys.</summary>
    internal ObjectHandle PrivateHandle => _privateHandle;

    /// <summary>Internal accessor for the public handle. <see cref="ObjectHandle.Invalid"/> when no companion exists and synthesis is unavailable.</summary>
    internal ObjectHandle PublicHandle => _publicHandle;

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        if (_ownsWorkspace) _workspace.Dispose();
        _ownedLibrary?.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11KeyTests" -c Debug
```

Expected: 4/4 pass.

- [ ] **Step 5: Verify full suite**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures.

- [ ] **Step 6: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Key.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyTests.cs

git commit -m "$(cat <<'EOF'
feat(Pkcs11Key): handle wrapper skeleton + identifying properties

Adds the Pkcs11Key public sealed partial class. Carries the owning
workspace reference, private/public ObjectHandle pair (one may be
Invalid), and cached identifying metadata (CKK, label, CKA_ID). Two
disposal-ownership flags determine whether Dispose cascades to the
workspace and/or library: both off when produced by
Workspace.OpenKey/Generate/Import; one or both on for the one-shot
Pkcs11Key.Open factories (added in Task 6). Construction guards
against null workspace and against the both-handles-invalid degenerate
case.

Mechanism operations (Sign, Verify, Encrypt, Decrypt, Wrap, Unwrap,
Derive) live on a partial file added by Tasks 9-11.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `Pkcs11Workspace.OpenKey` with CKA_ID auto-discovery

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Workspace.Keys.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceFindKeysTests.cs`

Purpose: Look up a key by label or CKA_ID. For asymmetric keys, automatically discover the companion via CKA_ID and bind both handles to the same `Pkcs11Key`.

- [ ] **Step 1: Write the failing tests**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceFindKeysTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

internal static class WorkspaceKeyTestCases
{
    public static void Assert_OpenKey_ByLabel_ReturnsKey(Pkcs11Workspace workspace, string label)
    {
        using var key = workspace.OpenKey(label);
        Assert.NotNull(key);
        Assert.Equal(label, key.Label);
    }

    public static void Assert_OpenKey_NotFound_Throws(Pkcs11Workspace workspace)
    {
        Assert.Throws<Pkcs11ObjectException>(() => workspace.OpenKey("does-not-exist-zzzz"));
    }

    public static void Assert_FindKeys_Empty_ReturnsEmptyList(Pkcs11Workspace workspace)
    {
        using var filter = ObjectTemplate.Empty()
            .Label("definitely-no-such-label-9999")
            .Build();
        var keys = workspace.FindKeys(filter);
        Assert.Empty(keys);
    }
}

[Collection("Mock")]
public sealed class Pkcs11WorkspaceFindKeysTests_Mock
{
    private readonly MockBackendFixture _backend;
    public Pkcs11WorkspaceFindKeysTests_Mock(MockBackendFixture backend) => _backend = backend;

    public static bool MockAvailable => MockBackendFixture.IsAvailable;

    [ConditionalFact(nameof(MockAvailable))]
    public void OpenKey_NotFound_Throws()
    {
        if (!MockBackendFixture.IsAvailable) throw new SkipTestException("Mock unavailable");
        using var workspace = _backend.Library.OpenWorkspace(
            MockBackendFixture.TokenLabel, CKU.CKU_USER, new SecurePin(MockBackendFixture.UserPin));
        WorkspaceKeyTestCases.Assert_OpenKey_NotFound_Throws(workspace);
    }

    [ConditionalFact(nameof(MockAvailable))]
    public void FindKeys_Empty_ReturnsEmptyList()
    {
        if (!MockBackendFixture.IsAvailable) throw new SkipTestException("Mock unavailable");
        using var workspace = _backend.Library.OpenWorkspace(
            MockBackendFixture.TokenLabel, CKU.CKU_USER, new SecurePin(MockBackendFixture.UserPin));
        WorkspaceKeyTestCases.Assert_FindKeys_Empty_ReturnsEmptyList(workspace);
    }
}

[Collection("SoftHsm")]
public sealed class Pkcs11WorkspaceFindKeysTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public Pkcs11WorkspaceFindKeysTests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void OpenKey_NotFound_Throws()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            SoftHsmBackendFixture.TokenLabel, CKU.CKU_USER, new SecurePin(SoftHsmBackendFixture.UserPin));
        WorkspaceKeyTestCases.Assert_OpenKey_NotFound_Throws(workspace);
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void OpenKey_AfterGenerate_FindsKey()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            SoftHsmBackendFixture.TokenLabel, CKU.CKU_USER, new SecurePin(SoftHsmBackendFixture.UserPin));

        // Generate an AES key with a known label, then look it up.
        string label = $"test-key-{Guid.NewGuid():N}";
        using (var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label(label).ValueLen(32).OnToken().Build())
        {
            // Direct delegation to Session for now — Workspace.GenerateKey is Task 12.
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template.Attributes.ToList());
        }

        try
        {
            WorkspaceKeyTestCases.Assert_OpenKey_ByLabel_ReturnsKey(workspace, label);
        }
        finally
        {
            using var filter = ObjectTemplate.Empty().Label(label).Build();
            foreach (var k in workspace.FindKeys(filter))
            {
                workspace.Session.DestroyObject(k.PrivateHandle.IsInvalid ? k.PublicHandle : k.PrivateHandle);
                k.Dispose();
            }
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail (build errors)**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11WorkspaceFindKeysTests" -c Debug
```

Expected: build error — `Workspace.OpenKey`, `Workspace.FindKeys`, `Pkcs11Key.PrivateHandle` (etc.) used in tests; only the last is defined (internal). `OpenKey`/`FindKeys` do not exist yet.

- [ ] **Step 3: Create `Pkcs11Workspace.Keys.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public sealed partial class Pkcs11Workspace
{
    /// <summary>
    /// Looks up a key by CKA_LABEL. If a matching private key is found, attempts to
    /// pair it with its public companion via CKA_ID; if the lookup hits a symmetric key
    /// (or a private key with no companion), the returned <see cref="Pkcs11Key"/> carries
    /// a single handle.
    /// </summary>
    /// <param name="label">The CKA_LABEL string to match.</param>
    /// <returns>A new <see cref="Pkcs11Key"/>. Caller must <c>Dispose</c> it.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="label"/> is null.</exception>
    /// <exception cref="Pkcs11ObjectException">Thrown if no matching key is found.</exception>
    public Pkcs11Key OpenKey(string label)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(label);

        using var filter = ObjectTemplate.Empty().Label(label).Build();
        return OpenKeyByFilter(filter, $"label '{label}'");
    }

    /// <summary>
    /// Looks up a key by CKA_ID.
    /// </summary>
    /// <param name="id">The CKA_ID bytes to match.</param>
    /// <returns>A new <see cref="Pkcs11Key"/>. Caller must <c>Dispose</c> it.</returns>
    /// <exception cref="Pkcs11ObjectException">Thrown if no matching key is found.</exception>
    public Pkcs11Key OpenKey(ReadOnlySpan<byte> id)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (id.IsEmpty) throw new ArgumentException("Id must not be empty.", nameof(id));

        using var filter = ObjectTemplate.Empty().Id(id).Build();
        return OpenKeyByFilter(filter, $"id (len={id.Length})");
    }

    /// <summary>
    /// Finds all keys matching the given template.
    /// </summary>
    /// <param name="filter">Attribute filter. Use <see cref="ObjectTemplate.Empty"/>-based builder.</param>
    /// <returns>A list of <see cref="Pkcs11Key"/>. May be empty. Caller disposes each.</returns>
    public IReadOnlyList<Pkcs11Key> FindKeys(ObjectTemplate filter)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(filter);

        var handles = _session.FindAllObjects(filter.Attributes.ToList());
        var result = new List<Pkcs11Key>(handles.Count);
        foreach (var handle in handles)
            result.Add(HydrateKeyFromHandle(handle));
        return result;
    }

    private Pkcs11Key OpenKeyByFilter(ObjectTemplate filter, string queryDescription)
    {
        var handles = _session.FindAllObjects(filter.Attributes.ToList());
        if (handles.Count == 0)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                $"OpenKey({queryDescription})");

        return HydrateKeyFromHandle(handles[0]);
    }

    /// <summary>
    /// Reads CKA_CLASS, CKA_KEY_TYPE, CKA_LABEL, CKA_ID off the handle and constructs a
    /// <see cref="Pkcs11Key"/>. If the handle is a private key with a non-empty CKA_ID,
    /// searches for a matching public companion and attaches both handles.
    /// </summary>
    private Pkcs11Key HydrateKeyFromHandle(ObjectHandle handle)
    {
        var attrs = _session.GetAttributeValue(handle, new List<CKA>
        {
            CKA.CKA_CLASS,
            CKA.CKA_KEY_TYPE,
            CKA.CKA_LABEL,
            CKA.CKA_ID,
        });

        var classAttr = attrs[0];
        var keyTypeAttr = attrs[1];
        var labelAttr = attrs[2];
        var idAttr = attrs[3];

        var objectClass = (CKO)classAttr.GetValueAsCkUlong();
        var keyType = (CKK)keyTypeAttr.GetValueAsCkUlong();
        string? label = labelAttr.CannotBeRead ? null : labelAttr.GetValueAsString();
        byte[] id = idAttr.CannotBeRead ? Array.Empty<byte>() : idAttr.GetValueAsByteArray();

        // Dispose the read-out attribute objects — they own unmanaged buffers.
        foreach (var a in attrs) a.Dispose();

        ObjectHandle privateHandle = ObjectHandle.Invalid;
        ObjectHandle publicHandle = ObjectHandle.Invalid;

        if (objectClass == CKO.CKO_PRIVATE_KEY)
        {
            privateHandle = handle;
            // Search for public companion by CKA_ID. Empty ID disables the lookup.
            if (id.Length > 0)
            {
                using var companionFilter = ObjectTemplate.Empty()
                    .Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_PUBLIC_KEY)
                    .Id(id)
                    .Build();
                var companionHandles = _session.FindAllObjects(companionFilter.Attributes.ToList());
                if (companionHandles.Count > 0)
                    publicHandle = companionHandles[0];
            }
        }
        else if (objectClass == CKO.CKO_PUBLIC_KEY)
        {
            publicHandle = handle;
        }
        else // CKO_SECRET_KEY or other
        {
            privateHandle = handle;
        }

        return new Pkcs11Key(
            workspace: this,
            privateHandle: privateHandle,
            publicHandle: publicHandle,
            keyType: keyType,
            label: label,
            id: id,
            ownedLibrary: null,
            ownsWorkspace: false);
    }
}
```

Note: this code uses `ObjectAttribute` accessor methods (`GetValueAsCkUlong`, `GetValueAsString`, `GetValueAsByteArray`). If those names differ in the existing `ObjectAttribute.cs`, update the call sites. The existing test code in `Tests/HighLevel/ObjectAttributeTests.cs` will show the right names.

- [ ] **Step 4: Run tests to verify they pass (or skip cleanly)**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11WorkspaceFindKeysTests" -c Debug
```

Expected: 4/4 pass (or skipped if backends unavailable).

- [ ] **Step 5: Verify full suite**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures.

- [ ] **Step 6: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Workspace.Keys.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceFindKeysTests.cs

git commit -m "$(cat <<'EOF'
feat(Pkcs11Workspace): OpenKey + FindKeys with CKA_ID auto-pairing

Adds three workspace-level lookups built on Session.FindAllObjects:

  OpenKey(string label) — single-match by CKA_LABEL.
  OpenKey(ReadOnlySpan<byte> id) — single-match by CKA_ID.
  FindKeys(ObjectTemplate filter) — multi-match for arbitrary
    attribute filters.

Each return path hydrates the resulting handle(s) through a private
HydrateKeyFromHandle helper that:
  1) reads CKA_CLASS / CKA_KEY_TYPE / CKA_LABEL / CKA_ID off the object,
  2) for private-key results, attempts to locate the public companion
     via CKA_ID and bind both handles to the same Pkcs11Key,
  3) for symmetric or public-only results, stores the single handle.

OpenKey(label) and OpenKey(id) throw Pkcs11ObjectException
(CKR_OBJECT_HANDLE_INVALID) when no match is found — same semantic the
caller would get from C_FindObjects on a real PKCS#11 dispatch.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: `Pkcs11Workspace.ImportKey`

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Workspace.Keys.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceFindKeysTests.cs`

Purpose: Add `ImportKey(ObjectTemplate)` returning a `Pkcs11Key` after creating the object via `C_CreateObject`. Used for importing pre-existing key material (e.g., from a recovery file).

- [ ] **Step 1: Append a test to `Pkcs11WorkspaceFindKeysTests.cs`**

Inside the `Pkcs11WorkspaceFindKeysTests_SoftHsm` class, add:

```csharp
    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ImportKey_AesValue_RoundTrips()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            SoftHsmBackendFixture.TokenLabel, CKU.CKU_USER, new SecurePin(SoftHsmBackendFixture.UserPin));

        byte[] keyMaterial = new byte[32];
        for (int i = 0; i < keyMaterial.Length; i++) keyMaterial[i] = (byte)i;
        string label = $"imported-{Guid.NewGuid():N}";

        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label)
            .Value(keyMaterial)
            .Encrypt()
            .Decrypt()
            .Build();

        using Pkcs11Key key = workspace.ImportKey(template);

        Assert.Equal(label, key.Label);
        Assert.Equal(CKK.CKK_AES, key.KeyType);

        // Cleanup
        workspace.Session.DestroyObject(key.PrivateHandle);
    }
```

- [ ] **Step 2: Run tests to verify the new one fails (build error or skip)**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11WorkspaceFindKeysTests" -c Debug
```

Expected: build error — `workspace.ImportKey` does not exist.

- [ ] **Step 3: Append `ImportKey` to `Pkcs11Workspace.Keys.cs`**

Add the following method inside the `Pkcs11Workspace` partial class (alongside `OpenKey`/`FindKeys`):

```csharp
    /// <summary>
    /// Creates a new object on the token from the given template and returns it as a
    /// <see cref="Pkcs11Key"/>. Used for importing pre-existing key material —
    /// <see cref="ObjectTemplate.ForSecretKey(CKK)"/> with <c>.Value(...)</c> for
    /// symmetric keys, or analogous templates for public/private RSA/EC keys.
    /// </summary>
    /// <param name="template">A fully-built template. Will not be modified.</param>
    /// <returns>A new <see cref="Pkcs11Key"/> wrapping the created object.</returns>
    public Pkcs11Key ImportKey(ObjectTemplate template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(template);

        var handle = _session.CreateObject(template.Attributes.ToList());
        return HydrateKeyFromHandle(handle);
    }
```

- [ ] **Step 4: Run tests**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11WorkspaceFindKeysTests" -c Debug
```

Expected: 5/5 pass.

- [ ] **Step 5: Verify full suite**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

- [ ] **Step 6: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Workspace.Keys.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceFindKeysTests.cs

git commit -m "$(cat <<'EOF'
feat(Pkcs11Workspace): ImportKey(ObjectTemplate) → Pkcs11Key

ImportKey delegates to Session.CreateObject with the template's
materialized attribute list and routes the resulting handle through
the same HydrateKeyFromHandle helper used by OpenKey/FindKeys, so
imported keys come back with their CKK / label / CKA_ID metadata
already cached on the wrapper.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: `Pkcs11Key.Open` one-shot factories

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Key.cs` (modify — append `Open` overloads)
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyTests.cs`

Purpose: Add two static `Open` overloads — one takes a library path (constructs and owns the library), one takes a pre-loaded library (caller retains library ownership).

- [ ] **Step 1: Append tests inside `Pkcs11KeyTests` class**

```csharp
    [Fact]
    public void Open_PathBased_NullPath_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            Pkcs11Key.Open(
                libraryPath: null!,
                slotLabel: "x",
                userType: CKU.CKU_USER,
                pin: new SecurePin("12345"u8),
                keyLabel: "x"));
    }

    [Fact]
    public void Open_PathBased_NullKeyLabel_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            Pkcs11Key.Open(
                libraryPath: "x",
                slotLabel: "x",
                userType: CKU.CKU_USER,
                pin: new SecurePin("12345"u8),
                keyLabel: null!));
    }

    [Fact]
    public void Open_LibraryBased_NullLibrary_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            Pkcs11Key.Open(
                library: null!,
                slotLabel: "x",
                userType: CKU.CKU_USER,
                pin: new SecurePin("12345"u8),
                keyLabel: "x"));
    }
```

Add the using directives at the top of the file if not already present:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11KeyTests" -c Debug
```

Expected: build error — `Pkcs11Key.Open` does not exist.

- [ ] **Step 3: Add the two `Open` overloads to `Pkcs11Key.cs`**

Inside the existing `Pkcs11Key` class (in the same file), append:

```csharp
    /// <summary>
    /// One-shot factory: loads the PKCS#11 library at <paramref name="libraryPath"/>,
    /// opens an authenticated workspace, looks up the key by label, and returns it. The
    /// returned key owns the library and the workspace — disposing it tears down all
    /// three.
    /// </summary>
    /// <param name="libraryPath">Path to the PKCS#11 native library.</param>
    /// <param name="slotLabel">CKA_LABEL of the slot's token.</param>
    /// <param name="userType">User type to log in as.</param>
    /// <param name="pin">The PIN.</param>
    /// <param name="keyLabel">CKA_LABEL of the key to open.</param>
    public static Pkcs11Key Open(
        string libraryPath,
        string slotLabel,
        CKU userType,
        Security.SecurePin pin,
        string keyLabel)
    {
        ArgumentNullException.ThrowIfNull(libraryPath);
        ArgumentNullException.ThrowIfNull(slotLabel);
        ArgumentNullException.ThrowIfNull(pin);
        ArgumentNullException.ThrowIfNull(keyLabel);

        Pkcs11Library? library = null;
        Pkcs11Workspace? workspace = null;
        try
        {
            library = new Pkcs11Library(libraryPath);
            workspace = library.OpenWorkspace(slotLabel, userType, pin);
            return OpenKeyInternal(workspace, keyLabel, ownedLibrary: library, ownsWorkspace: true);
        }
        catch
        {
            workspace?.Dispose();
            library?.Dispose();
            throw;
        }
    }

    /// <summary>
    /// One-shot factory taking a pre-loaded library: opens an authenticated workspace,
    /// looks up the key, and returns it. The returned key owns the workspace but NOT the
    /// library — the caller continues to own and dispose <paramref name="library"/>.
    /// </summary>
    /// <param name="library">A pre-loaded library. Caller retains ownership.</param>
    /// <param name="slotLabel">CKA_LABEL of the slot's token.</param>
    /// <param name="userType">User type to log in as.</param>
    /// <param name="pin">The PIN.</param>
    /// <param name="keyLabel">CKA_LABEL of the key to open.</param>
    public static Pkcs11Key Open(
        Pkcs11Library library,
        string slotLabel,
        CKU userType,
        Security.SecurePin pin,
        string keyLabel)
    {
        ArgumentNullException.ThrowIfNull(library);
        ArgumentNullException.ThrowIfNull(slotLabel);
        ArgumentNullException.ThrowIfNull(pin);
        ArgumentNullException.ThrowIfNull(keyLabel);

        Pkcs11Workspace? workspace = null;
        try
        {
            workspace = library.OpenWorkspace(slotLabel, userType, pin);
            return OpenKeyInternal(workspace, keyLabel, ownedLibrary: null, ownsWorkspace: true);
        }
        catch
        {
            workspace?.Dispose();
            throw;
        }
    }

    private static Pkcs11Key OpenKeyInternal(
        Pkcs11Workspace workspace,
        string keyLabel,
        Pkcs11Library? ownedLibrary,
        bool ownsWorkspace)
    {
        // Open the key through the workspace, then re-wrap with the ownership flags
        // appropriate for the one-shot path. We can't rebind a Pkcs11Key in place, so
        // pull the handles + metadata out of the workspace-owned key, dispose it (a
        // no-op for state but keeps the API contract uniform), and build a new wrapper
        // with the ownership cascade.
        using var transient = workspace.OpenKey(keyLabel);

        // Need to materialize Id and Label so we can pass them across the rebind.
        // Use the public accessors on the transient instance.
        var label = transient.Label;
        var idBytes = transient.Id.ToArray();
        var keyType = transient.KeyType;
        var privateHandle = transient.PrivateHandle;
        var publicHandle = transient.PublicHandle;

        return new Pkcs11Key(
            workspace,
            privateHandle,
            publicHandle,
            keyType,
            label,
            idBytes,
            ownedLibrary,
            ownsWorkspace);
    }
```

- [ ] **Step 4: Run tests**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11KeyTests" -c Debug
```

Expected: 7/7 pass (4 from Task 3 + 3 new).

- [ ] **Step 5: Verify full suite**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

- [ ] **Step 6: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Key.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyTests.cs

git commit -m "$(cat <<'EOF'
feat(Pkcs11Key): Open one-shot factories (path + library overloads)

Two static factories that bundle the library load → workspace open →
key lookup pipeline:

  Pkcs11Key.Open(libraryPath, ...) — owns library + workspace + key.
    Dispose tears down all three. Convenient when the key is the only
    thing the caller wants from the library.

  Pkcs11Key.Open(library, ...) — owns workspace + key. The caller
    retains ownership of `library` and can use the same library to
    open more keys/workspaces concurrently.

Both overloads route through an internal OpenKeyInternal that reuses
Workspace.OpenKey to perform the lookup, then re-wraps the handles
with the correct ownership flags so Pkcs11Key.Dispose disposes only
what it actually owns.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: RSA public-key synthesis from private-only key

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11PublicKeyView.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Workspace.Keys.cs` (extend hydrate path)
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyPublicSynthesisTests.cs`

Purpose: When a private RSA key has no `CKO_PUBLIC_KEY` companion (CKA_ID lookup returns nothing), synthesize a managed public-key view by reading `CKA_MODULUS` + `CKA_PUBLIC_EXPONENT` off the private key object. The synthesized view is internal — the Plan-3 BCL providers (`RSAPkcs11`) consume it via `RSA.ImportParameters(...)` for managed `Verify` paths.

- [ ] **Step 1: Write the failing test**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyPublicSynthesisTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

[Collection("SoftHsm")]
public sealed class Pkcs11KeyPublicSynthesisTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public Pkcs11KeyPublicSynthesisTests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Rsa_PrivateOnly_HasSynthesizedPublicView()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            SoftHsmBackendFixture.TokenLabel, CKU.CKU_USER, new SecurePin(SoftHsmBackendFixture.UserPin));

        // Generate an RSA key pair with the SAME CKA_ID on both halves, then look up
        // by ID — the pair is found together. To simulate "private only", we explicitly
        // destroy the public companion after generation.
        string label = $"rsa-test-{Guid.NewGuid():N}";
        byte[] id = System.Text.Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().ModulusBits(2048)
            .PublicExponent(new byte[] { 0x01, 0x00, 0x01 })
            .Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign()
            .Build();

        workspace.Session.GenerateKeyPair(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN),
            pubTpl.Attributes.ToList(),
            privTpl.Attributes.ToList(),
            out var pubHandle,
            out var privHandle);

        try
        {
            // Destroy the public-key object so only the private-side survives.
            workspace.Session.DestroyObject(pubHandle);

            // Now OpenKey by label — it should find ONLY the private and synthesize the public view.
            using var key = workspace.OpenKey(label);

            Assert.False(key.PrivateHandle.IsInvalid);
            Assert.True(key.PublicHandle.IsInvalid, "no CKO_PUBLIC_KEY survived");
            Assert.NotNull(key.GetSynthesizedRsaParameters());
            Assert.Equal(2048 / 8, key.GetSynthesizedRsaParameters()!.Value.Modulus!.Length);
        }
        finally
        {
            workspace.Session.DestroyObject(privHandle);
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail (build error)**

Expected: build error — `Pkcs11Key.GetSynthesizedRsaParameters()` does not exist.

- [ ] **Step 3: Create `Pkcs11PublicKeyView.cs`**

```csharp
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Internal helper that synthesizes a managed public-key view from attributes on a
/// PKCS#11 private-key object when no <c>CKO_PUBLIC_KEY</c> companion is stored on the
/// token. Used by <see cref="Pkcs11Key"/> to support verify-only / encrypt-only paths
/// that need only public material.
/// </summary>
internal static class Pkcs11PublicKeyView
{
    /// <summary>
    /// Reads CKA_MODULUS + CKA_PUBLIC_EXPONENT from the private-key object identified by
    /// <paramref name="privateHandle"/> and returns the corresponding
    /// <see cref="RSAParameters"/>. Returns <c>null</c> if either attribute is missing
    /// or marked sensitive (which would be unusual but is spec-legal).
    /// </summary>
    public static RSAParameters? TrySynthesizeRsa(Session session, ObjectHandle privateHandle)
    {
        var attrs = session.GetAttributeValue(privateHandle, new List<CKA>
        {
            CKA.CKA_MODULUS,
            CKA.CKA_PUBLIC_EXPONENT,
        });

        try
        {
            if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
                return null;

            return new RSAParameters
            {
                Modulus = attrs[0].GetValueAsByteArray(),
                Exponent = attrs[1].GetValueAsByteArray(),
            };
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
    }
}
```

- [ ] **Step 4: Add the synthesis hook to `Pkcs11Key`**

Append to `Pkcs11Key.cs` inside the class:

```csharp
    /// <summary>
    /// Returns the synthesized RSA public parameters for this key when its public side
    /// is reachable via attributes on the private-key object. Returns <c>null</c> if the
    /// public side is reachable via a real <see cref="PublicHandle"/> (caller should
    /// use that path instead), or when synthesis is unavailable (non-RSA key type, or
    /// CKA_MODULUS/CKA_PUBLIC_EXPONENT marked sensitive).
    /// </summary>
    /// <remarks>
    /// Currently only RSA is supported. EC synthesis is added in Task 8.
    /// </remarks>
    internal RSAParameters? GetSynthesizedRsaParameters()
    {
        if (_keyType != CKK.CKK_RSA) return null;
        if (!_publicHandle.IsInvalid) return null; // real public handle exists
        if (_privateHandle.IsInvalid) return null; // public-only — no private to read from

        return Pkcs11PublicKeyView.TrySynthesizeRsa(_workspace.Session, _privateHandle);
    }
```

Note: this method is `internal` — tests have access through InternalsVisibleTo, but Plan-3 BCL providers (in the same assembly) will also reach for it.

- [ ] **Step 5: Run tests**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11KeyPublicSynthesisTests" -c Debug
```

Expected: 1/1 pass (or skipped if SoftHSM unavailable).

- [ ] **Step 6: Verify full suite**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

- [ ] **Step 7: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11PublicKeyView.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Key.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyPublicSynthesisTests.cs

git commit -m "$(cat <<'EOF'
feat(Pkcs11Key): synthesize RSA public params from private-only key

Adds an internal Pkcs11PublicKeyView helper that reads CKA_MODULUS
and CKA_PUBLIC_EXPONENT off a CKO_PRIVATE_KEY object and returns the
corresponding RSAParameters. Pkcs11Key.GetSynthesizedRsaParameters
exposes the result to Plan-3 BCL providers as the public-side fallback
when no CKO_PUBLIC_KEY companion exists on the token.

Plan-3's RSAPkcs11.VerifyData will use these synthesized parameters to
verify in managed code via RSA.Create().ImportParameters(...) when the
key is private-only — preserving the BCL convention that public
material is always reachable from a key handle that has private
material.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: EC public-key synthesis (with CKA_EC_POINT fallback)

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11PublicKeyView.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Key.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyPublicSynthesisTests.cs`

Purpose: Synthesize EC public material from `CKA_EC_POINT` + `CKA_EC_PARAMS` on the private key. Per the spec, `CKA_EC_POINT` is optional on `CKO_PRIVATE_KEY` — when absent, synthesis returns null and `GetSynthesizedEcParameters` reports unavailability.

- [ ] **Step 1: Append a test**

Inside `Pkcs11KeyPublicSynthesisTests_SoftHsm`:

```csharp
    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ec_PrivateOnly_SynthesizesWhenEcPointPresent()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            SoftHsmBackendFixture.TokenLabel, CKU.CKU_USER, new SecurePin(SoftHsmBackendFixture.UserPin));

        string label = $"ec-test-{Guid.NewGuid():N}";
        byte[] id = System.Text.Encoding.ASCII.GetBytes(label);
        // OID for secp256r1 (NIST P-256), DER-encoded.
        byte[] secp256r1 = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Label(label).Id(id).Verify().EcParams(secp256r1).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Label(label).Id(id).Sign().Build();

        workspace.Session.GenerateKeyPair(
            new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN),
            pubTpl.Attributes.ToList(),
            privTpl.Attributes.ToList(),
            out var pubHandle,
            out var privHandle);

        try
        {
            workspace.Session.DestroyObject(pubHandle);
            using var key = workspace.OpenKey(label);
            var ec = key.GetSynthesizedEcParameters();
            // On SoftHSM, CKA_EC_POINT is stored on the private key, so synthesis succeeds.
            Assert.NotNull(ec);
            Assert.NotNull(ec!.Value.Q.X);
        }
        finally
        {
            workspace.Session.DestroyObject(privHandle);
        }
    }
```

- [ ] **Step 2: Run tests to verify they fail (build error)**

Expected: `Pkcs11Key.GetSynthesizedEcParameters` does not exist.

- [ ] **Step 3: Extend `Pkcs11PublicKeyView.cs`**

Append:

```csharp
    /// <summary>
    /// Reads CKA_EC_POINT + CKA_EC_PARAMS from a CKO_PRIVATE_KEY object and returns the
    /// corresponding <see cref="ECParameters"/>. Returns <c>null</c> if either attribute
    /// is unreadable (per PKCS#11 v3.1, CKA_EC_POINT is optional on private-key
    /// objects).
    /// </summary>
    public static ECParameters? TrySynthesizeEc(Session session, ObjectHandle privateHandle)
    {
        var attrs = session.GetAttributeValue(privateHandle, new List<CKA>
        {
            CKA.CKA_EC_POINT,
            CKA.CKA_EC_PARAMS,
        });

        try
        {
            if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
                return null;

            // CKA_EC_POINT is DER-encoded OCTET STRING wrapping the uncompressed point.
            // Strip the DER OCTET STRING tag/length to get the point bytes.
            byte[] der = attrs[0].GetValueAsByteArray();
            ReadOnlySpan<byte> pointBytes = StripDerOctetString(der);
            if (pointBytes.IsEmpty) return null;

            // Point format: 0x04 || X || Y for uncompressed (the only mandatory form).
            if (pointBytes[0] != 0x04) return null;
            int coordLen = (pointBytes.Length - 1) / 2;
            if (coordLen <= 0 || pointBytes.Length != 1 + 2 * coordLen) return null;

            byte[] x = pointBytes.Slice(1, coordLen).ToArray();
            byte[] y = pointBytes.Slice(1 + coordLen, coordLen).ToArray();

            // CKA_EC_PARAMS is the named-curve OID (DER-encoded). Map it to ECCurve.
            byte[] paramsBytes = attrs[1].GetValueAsByteArray();
            ECCurve curve = ResolveNamedCurve(paramsBytes);

            return new ECParameters
            {
                Curve = curve,
                Q = new ECPoint { X = x, Y = y },
            };
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
    }

    private static ReadOnlySpan<byte> StripDerOctetString(byte[] der)
    {
        // DER OCTET STRING: 0x04 <len> <bytes>. The <len> may be short-form (one byte
        // up to 0x7F) or long-form (0x81/0x82 prefix). Only short-form and 0x81 are
        // common for EC points up to ~127 bytes.
        if (der.Length < 2 || der[0] != 0x04) return ReadOnlySpan<byte>.Empty;

        int offset = 2;
        int len = der[1];
        if (len == 0x81 && der.Length >= 3)
        {
            len = der[2];
            offset = 3;
        }
        else if (len == 0x82 && der.Length >= 4)
        {
            len = (der[2] << 8) | der[3];
            offset = 4;
        }
        else if (len > 0x7F)
        {
            return ReadOnlySpan<byte>.Empty;
        }

        if (offset + len > der.Length) return ReadOnlySpan<byte>.Empty;
        return der.AsSpan(offset, len);
    }

    private static ECCurve ResolveNamedCurve(byte[] derOid)
    {
        // OID DER: 0x06 <len> <bytes>. We compare the byte sequence to known curves.
        // For the curves we support, return the BCL's friendly name (ECCurve.CreateFromFriendlyName).
        // OID 1.2.840.10045.3.1.7 = secp256r1 (P-256): 06 08 2A 86 48 CE 3D 03 01 07
        // OID 1.3.132.0.34       = secp384r1 (P-384): 06 05 2B 81 04 00 22
        // OID 1.3.132.0.35       = secp521r1 (P-521): 06 05 2B 81 04 00 23
        ReadOnlySpan<byte> p256 = stackalloc byte[]
            { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
        ReadOnlySpan<byte> p384 = stackalloc byte[]
            { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
        ReadOnlySpan<byte> p521 = stackalloc byte[]
            { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };

        if (derOid.AsSpan().SequenceEqual(p256))
            return ECCurve.CreateFromFriendlyName("nistP256");
        if (derOid.AsSpan().SequenceEqual(p384))
            return ECCurve.CreateFromFriendlyName("nistP384");
        if (derOid.AsSpan().SequenceEqual(p521))
            return ECCurve.CreateFromFriendlyName("nistP521");

        // Unknown curve — return default. The caller is responsible for handling.
        return default;
    }
```

- [ ] **Step 4: Add `GetSynthesizedEcParameters` to `Pkcs11Key.cs`**

```csharp
    /// <summary>
    /// Returns the synthesized EC public parameters when this key is an EC private-only
    /// key with readable CKA_EC_POINT + CKA_EC_PARAMS. Returns <c>null</c> when the
    /// key is non-EC, a real public handle exists (caller should use that path), or
    /// CKA_EC_POINT is sensitive/missing on the private object.
    /// </summary>
    internal System.Security.Cryptography.ECParameters? GetSynthesizedEcParameters()
    {
        if (_keyType != CKK.CKK_EC) return null;
        if (!_publicHandle.IsInvalid) return null;
        if (_privateHandle.IsInvalid) return null;
        return Pkcs11PublicKeyView.TrySynthesizeEc(_workspace.Session, _privateHandle);
    }
```

- [ ] **Step 5: Run tests**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11KeyPublicSynthesisTests" -c Debug
```

Expected: 2/2 pass (or skipped if SoftHSM unavailable). The EC test verifies synthesis succeeds when `CKA_EC_POINT` is present (SoftHSM's default behavior).

- [ ] **Step 6: Verify full suite**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

- [ ] **Step 7: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11PublicKeyView.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Key.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyPublicSynthesisTests.cs

git commit -m "$(cat <<'EOF'
feat(Pkcs11Key): synthesize EC public params from private-only key

Extends Pkcs11PublicKeyView with TrySynthesizeEc(...): reads
CKA_EC_POINT + CKA_EC_PARAMS off a CKO_PRIVATE_KEY, strips the
DER OCTET STRING wrapper from the EC point, splits into X/Y
coordinates, and maps the curve OID to an ECCurve via
ECCurve.CreateFromFriendlyName. Currently supports the three NIST
prime curves used in practice (secp256r1 / secp384r1 / secp521r1);
unknown curves return a default ECCurve so the caller can decide
how to handle.

CKA_EC_POINT is optional on CKO_PRIVATE_KEY per PKCS#11 v3.1 §6.4.5
— synthesis returns null when the attribute is absent or marked
sensitive. Tokens that don't store CKA_EC_POINT on private objects
will get an unusable EC public view; the BCL provider in Plan 3 will
fall back to a clear ObjectException at invocation time.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: `Pkcs11Key.Sign` + `Verify`

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Key.Mechanism.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyMechanismTests.cs`

Purpose: Add `Sign(Mechanism, ReadOnlySpan<byte>)` and `Verify(Mechanism, ReadOnlySpan<byte>, ReadOnlySpan<byte>)`. Sign uses the private handle; Verify uses the public handle when available, or fails with `Pkcs11ObjectException` if neither a real public handle nor public-key synthesis can produce one.

- [ ] **Step 1: Write the failing tests**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyMechanismTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

internal static class Pkcs11KeyMechanismCases
{
    public static void Assert_RsaSignVerify_RoundTrips(Pkcs11Workspace workspace)
    {
        string label = $"sign-verify-{Guid.NewGuid():N}";
        byte[] id = System.Text.Encoding.ASCII.GetBytes(label);
        byte[] data = System.Text.Encoding.UTF8.GetBytes("hello pkcs11");

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().ModulusBits(2048)
            .PublicExponent(new byte[] { 0x01, 0x00, 0x01 }).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign().Build();

        workspace.Session.GenerateKeyPair(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN),
            pubTpl.Attributes.ToList(),
            privTpl.Attributes.ToList(),
            out var pubHandle,
            out var privHandle);

        try
        {
            using var key = workspace.OpenKey(label);
            var sha256Rsa = new Mechanism(CKM.CKM_SHA256_RSA_PKCS);

            byte[] signature = key.Sign(sha256Rsa, data);
            Assert.True(key.Verify(sha256Rsa, data, signature));

            byte[] tampered = (byte[])data.Clone();
            tampered[0] ^= 0xFF;
            Assert.False(key.Verify(sha256Rsa, tampered, signature));
        }
        finally
        {
            workspace.Session.DestroyObject(pubHandle);
            workspace.Session.DestroyObject(privHandle);
        }
    }
}

[Collection("SoftHsm")]
public sealed class Pkcs11KeyMechanismTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public Pkcs11KeyMechanismTests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RsaPkcs_SignVerify_RoundTrip()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            SoftHsmBackendFixture.TokenLabel, CKU.CKU_USER, new SecurePin(SoftHsmBackendFixture.UserPin));
        Pkcs11KeyMechanismCases.Assert_RsaSignVerify_RoundTrips(workspace);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Expected: build error — `key.Sign` and `key.Verify` do not exist.

- [ ] **Step 3: Create `Pkcs11Key.Mechanism.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public sealed partial class Pkcs11Key
{
    /// <summary>
    /// Signs <paramref name="data"/> using the given mechanism. Requires the key to
    /// carry a private handle (symmetric keys are sign-capable too).
    /// </summary>
    /// <param name="mechanism">The signing mechanism.</param>
    /// <param name="data">The data to sign.</param>
    /// <returns>The signature bytes.</returns>
    /// <exception cref="Pkcs11ObjectException">Thrown if the key has no private handle.</exception>
    public byte[] Sign(Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);

        if (_privateHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Sign (no private handle)");

        return _workspace.Session.Sign(mechanism, _privateHandle, data);
    }

    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="data"/> using the
    /// given mechanism. Requires either a real public handle or a synthesizable public
    /// view (RSA always succeeds from a private key; EC depends on CKA_EC_POINT being
    /// readable on the private key when no CKO_PUBLIC_KEY exists).
    /// </summary>
    /// <returns><c>true</c> if the signature is valid, <c>false</c> if not.</returns>
    /// <exception cref="Pkcs11ObjectException">Thrown if no public material is reachable.</exception>
    public bool Verify(Mechanism mechanism, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);

        // Prefer the real public handle.
        if (!_publicHandle.IsInvalid)
            return _workspace.Session.Verify(mechanism, _publicHandle, data, signature);

        // Fall back to managed verify via synthesized public parameters.
        if (_keyType == CKK.CKK_RSA)
        {
            var rsaParams = GetSynthesizedRsaParameters();
            if (rsaParams is not null)
                return VerifyRsaInManaged(mechanism, rsaParams.Value, data, signature);
        }
        else if (_keyType == CKK.CKK_EC)
        {
            var ecParams = GetSynthesizedEcParameters();
            if (ecParams is not null)
                return VerifyEcInManaged(mechanism, ecParams.Value, data, signature);
        }

        throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
            "Pkcs11Key.Verify (no public handle and synthesis unavailable)");
    }

    private static bool VerifyRsaInManaged(
        Mechanism mechanism,
        System.Security.Cryptography.RSAParameters rsaParams,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        using var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportParameters(rsaParams);

        var (hashName, padding) = MapRsaSignMechanism(mechanism);
        return rsa.VerifyData(data, signature, hashName, padding);
    }

    private static bool VerifyEcInManaged(
        Mechanism mechanism,
        System.Security.Cryptography.ECParameters ecParams,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        using var ec = System.Security.Cryptography.ECDsa.Create();
        ec.ImportParameters(ecParams);
        var hashName = MapEcdsaMechanism(mechanism);
        return ec.VerifyData(data, signature, hashName);
    }

    private static (System.Security.Cryptography.HashAlgorithmName, System.Security.Cryptography.RSASignaturePadding)
        MapRsaSignMechanism(Mechanism mechanism) => mechanism.Type switch
        {
            CKM.CKM_SHA1_RSA_PKCS   => (System.Security.Cryptography.HashAlgorithmName.SHA1,   System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            CKM.CKM_SHA256_RSA_PKCS => (System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            CKM.CKM_SHA384_RSA_PKCS => (System.Security.Cryptography.HashAlgorithmName.SHA384, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            CKM.CKM_SHA512_RSA_PKCS => (System.Security.Cryptography.HashAlgorithmName.SHA512, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            _ => throw new NotSupportedException(
                $"Managed RSA verify is not implemented for mechanism {mechanism.Type}. " +
                "Provide a CKO_PUBLIC_KEY companion on the token to use the native verify path."),
        };

    private static System.Security.Cryptography.HashAlgorithmName MapEcdsaMechanism(Mechanism mechanism)
        => mechanism.Type switch
        {
            CKM.CKM_ECDSA_SHA1   => System.Security.Cryptography.HashAlgorithmName.SHA1,
            CKM.CKM_ECDSA_SHA256 => System.Security.Cryptography.HashAlgorithmName.SHA256,
            CKM.CKM_ECDSA_SHA384 => System.Security.Cryptography.HashAlgorithmName.SHA384,
            CKM.CKM_ECDSA_SHA512 => System.Security.Cryptography.HashAlgorithmName.SHA512,
            _ => throw new NotSupportedException(
                $"Managed ECDSA verify is not implemented for mechanism {mechanism.Type}. " +
                "Provide a CKO_PUBLIC_KEY companion on the token to use the native verify path."),
        };
}
```

- [ ] **Step 4: Run tests**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11KeyMechanismTests" -c Debug
```

Expected: 1/1 pass (or skipped).

- [ ] **Step 5: Verify full suite**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

- [ ] **Step 6: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Key.Mechanism.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyMechanismTests.cs

git commit -m "$(cat <<'EOF'
feat(Pkcs11Key): Sign + Verify with managed public-side fallback

Sign(Mechanism, ReadOnlySpan<byte>) delegates straight to
Session.Sign with the private handle, guarding on the no-private-key
case.

Verify(Mechanism, ReadOnlySpan<byte>, ReadOnlySpan<byte>) uses the
real CKO_PUBLIC_KEY handle when present. When absent, it falls back
to managed verification via the synthesized RSAParameters or
ECParameters (Tasks 7-8): RSA.Create().ImportParameters or
ECDsa.Create().ImportParameters, then VerifyData with the
mechanism-mapped HashAlgorithmName + padding. The fallback is
RSA-PKCS#1-v1.5 + ECDSA only for now; PSS / OAEP-related mechanisms
require the on-token path and throw NotSupportedException with a
clear message.

If neither real-handle verify nor managed synthesis works (EC private
key with sensitive CKA_EC_POINT, or non-RSA/EC keys), Verify throws
Pkcs11ObjectException so the caller knows the public side is
unreachable.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: `Pkcs11Key.Encrypt` + `Decrypt`

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Key.Mechanism.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyMechanismTests.cs`

Purpose: Symmetric encrypt/decrypt use the single handle. Asymmetric encrypt uses the public handle (or synthesized RSA params); decrypt uses the private handle. Plan 2 implements the on-token path; managed-fallback Encrypt for synthesized RSA is added but limited to PKCS#1 v1.5 / OAEP per the same mechanism map.

- [ ] **Step 1: Append AES-CBC round-trip test**

Add to `Pkcs11KeyMechanismCases`:

```csharp
    public static void Assert_AesCbcEncryptDecrypt_RoundTrips(Pkcs11Workspace workspace)
    {
        byte[] iv = new byte[16];
        for (int i = 0; i < iv.Length; i++) iv[i] = (byte)i;
        byte[] plaintext = new byte[32];
        for (int i = 0; i < plaintext.Length; i++) plaintext[i] = (byte)(0x40 + i);

        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .ValueLen(32).Encrypt().Decrypt().Build();
        workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN),
            template.Attributes.ToList());

        // Re-look the key up — GenerateKey above returns a handle but we want the
        // Pkcs11Key wrapper. Generate produces a session-only key with no label, so
        // we round-trip through the workspace's key surface via a freshly generated
        // labeled key.
        string label = $"aes-cbc-{Guid.NewGuid():N}";
        using var labeledTpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build();
        workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN),
            labeledTpl.Attributes.ToList());

        try
        {
            using var key = workspace.OpenKey(label);
            var mech = new Mechanism(CKM.CKM_AES_CBC, iv);

            byte[] ciphertext = key.Encrypt(mech, plaintext);
            byte[] recovered = key.Decrypt(mech, ciphertext);

            Assert.Equal(plaintext, recovered);
        }
        finally
        {
            using var filter = ObjectTemplate.Empty().Label(label).Build();
            foreach (var k in workspace.FindKeys(filter))
            {
                var handle = k.PrivateHandle.IsInvalid ? k.PublicHandle : k.PrivateHandle;
                workspace.Session.DestroyObject(handle);
                k.Dispose();
            }
        }
    }
```

Add to `Pkcs11KeyMechanismTests_SoftHsm`:

```csharp
    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesCbc_EncryptDecrypt_RoundTrip()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            SoftHsmBackendFixture.TokenLabel, CKU.CKU_USER, new SecurePin(SoftHsmBackendFixture.UserPin));
        Pkcs11KeyMechanismCases.Assert_AesCbcEncryptDecrypt_RoundTrips(workspace);
    }
```

- [ ] **Step 2: Run tests — verify failure**

Expected: build error — `Pkcs11Key.Encrypt` / `Pkcs11Key.Decrypt` do not exist.

- [ ] **Step 3: Append `Encrypt`/`Decrypt` to `Pkcs11Key.Mechanism.cs`**

```csharp
    /// <summary>
    /// Encrypts <paramref name="plaintext"/> using this key. Symmetric keys use the
    /// single handle; asymmetric public-side encryption (RSA-OAEP / RSA-PKCS) uses the
    /// public handle.
    /// </summary>
    public byte[] Encrypt(Mechanism mechanism, ReadOnlySpan<byte> plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);

        // For symmetric keys, _privateHandle holds the only handle.
        // For asymmetric, encrypt uses the public side.
        ObjectHandle handle = IsAsymmetricKeyType(_keyType)
            ? _publicHandle
            : _privateHandle;

        if (handle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Encrypt (handle unavailable)");

        return _workspace.Session.Encrypt(mechanism, handle, plaintext);
    }

    /// <summary>
    /// Decrypts <paramref name="ciphertext"/> using this key. Symmetric uses the single
    /// handle; asymmetric uses the private handle.
    /// </summary>
    public byte[] Decrypt(Mechanism mechanism, ReadOnlySpan<byte> ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);

        if (_privateHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Decrypt (no private handle)");

        return _workspace.Session.Decrypt(mechanism, _privateHandle, ciphertext);
    }

    private static bool IsAsymmetricKeyType(CKK keyType) => keyType switch
    {
        CKK.CKK_RSA or CKK.CKK_DSA or CKK.CKK_EC or CKK.CKK_EC_EDWARDS or CKK.CKK_EC_MONTGOMERY => true,
        _ => false,
    };
```

- [ ] **Step 4: Run tests**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11KeyMechanismTests" -c Debug
```

Expected: 2/2 pass (or skipped).

- [ ] **Step 5: Verify full suite**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

- [ ] **Step 6: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Key.Mechanism.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyMechanismTests.cs

git commit -m "$(cat <<'EOF'
feat(Pkcs11Key): Encrypt + Decrypt

Encrypt picks the public handle for asymmetric key types (RSA, DSA,
EC/EdDSA/Montgomery) and the single handle for symmetric. Decrypt
always uses the private (or single symmetric) handle. Both methods
delegate to the underlying Session.Encrypt / Session.Decrypt.

Per the Plan-2 scope, no managed-fallback Encrypt is implemented for
synthesized RSA — that path will be wired up in Plan 3 by RSAPkcs11
where it has full BCL provider context. Callers attempting to Encrypt
on a private-only RSA key with no CKO_PUBLIC_KEY companion get a
Pkcs11ObjectException at invocation time.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: `Pkcs11Key.Wrap` + `Unwrap` + `Derive`

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Key.Mechanism.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyMechanismTests.cs`

Purpose: Add the remaining three mechanism-level operations. Wrap uses the wrapping key's public-or-symmetric handle and consumes the target key's private-or-symmetric handle. Unwrap and Derive return new `Pkcs11Key` instances.

- [ ] **Step 1: Append a wrap/unwrap test**

Inside `Pkcs11KeyMechanismCases`:

```csharp
    public static void Assert_AesKeyWrapUnwrap_RoundTrips(Pkcs11Workspace workspace)
    {
        // Generate a wrapping AES key.
        string wrapperLabel = $"wrapper-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(wrapperLabel).ValueLen(32).Wrap().Unwrap().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN),
                t.Attributes.ToList());
        }

        // Generate a target AES key to wrap.
        string targetLabel = $"target-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(targetLabel).ValueLen(16).Encrypt().Decrypt().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN),
                t.Attributes.ToList());
        }

        try
        {
            using var wrapper = workspace.OpenKey(wrapperLabel);
            using var target = workspace.OpenKey(targetLabel);

            byte[] wrapped = wrapper.Wrap(new Mechanism(CKM.CKM_AES_KEY_WRAP), target);

            using var unwrapTpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
                .Extractable().Encrypt().Decrypt().Build();
            using var unwrapped = wrapper.Unwrap(
                new Mechanism(CKM.CKM_AES_KEY_WRAP), wrapped, unwrapTpl);

            Assert.False(unwrapped.PrivateHandle.IsInvalid);
            Assert.Equal(CKK.CKK_AES, unwrapped.KeyType);
        }
        finally
        {
            CleanupByLabel(workspace, wrapperLabel);
            CleanupByLabel(workspace, targetLabel);
        }
    }

    private static void CleanupByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            var handle = k.PrivateHandle.IsInvalid ? k.PublicHandle : k.PrivateHandle;
            workspace.Session.DestroyObject(handle);
            k.Dispose();
        }
    }
```

Add to `Pkcs11KeyMechanismTests_SoftHsm`:

```csharp
    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesKeyWrap_WrapUnwrap_RoundTrip()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            SoftHsmBackendFixture.TokenLabel, CKU.CKU_USER, new SecurePin(SoftHsmBackendFixture.UserPin));
        Pkcs11KeyMechanismCases.Assert_AesKeyWrapUnwrap_RoundTrips(workspace);
    }
```

- [ ] **Step 2: Run tests — verify failure**

Expected: build error — `Pkcs11Key.Wrap`, `Pkcs11Key.Unwrap`, `Pkcs11Key.Derive` do not exist.

- [ ] **Step 3: Append `Wrap`/`Unwrap`/`Derive` to `Pkcs11Key.Mechanism.cs`**

```csharp
    /// <summary>
    /// Wraps <paramref name="targetKey"/> with this key. This key is the wrapper; the
    /// target's private (or symmetric) handle is consumed by the wrap operation.
    /// </summary>
    /// <param name="mechanism">The wrap mechanism (e.g. <see cref="CKM.CKM_AES_KEY_WRAP"/>).</param>
    /// <param name="targetKey">The key being wrapped. Must carry a private/symmetric handle.</param>
    /// <returns>The wrapped key bytes — opaque blob to be transported / stored.</returns>
    public byte[] Wrap(Mechanism mechanism, Pkcs11Key targetKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(targetKey);

        // Wrapping key: public side for asymmetric, single handle for symmetric.
        ObjectHandle wrapHandle = IsAsymmetricKeyType(_keyType) ? _publicHandle : _privateHandle;
        if (wrapHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Wrap (wrapping-key handle unavailable)");

        ObjectHandle targetHandle = targetKey._privateHandle.IsInvalid
            ? targetKey._publicHandle
            : targetKey._privateHandle;
        if (targetHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Wrap (target-key handle unavailable)");

        return _workspace.Session.WrapKey(mechanism, wrapHandle, targetHandle);
    }

    /// <summary>
    /// Unwraps the byte blob <paramref name="wrappedBytes"/> using this key as the
    /// unwrapping key, into a new on-token object described by
    /// <paramref name="template"/>.
    /// </summary>
    /// <returns>A new <see cref="Pkcs11Key"/> wrapping the unwrapped object.</returns>
    public Pkcs11Key Unwrap(Mechanism mechanism, ReadOnlySpan<byte> wrappedBytes, ObjectTemplate template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(template);

        // Unwrapping key: private side for asymmetric, single handle for symmetric.
        ObjectHandle unwrapHandle = _privateHandle.IsInvalid ? _publicHandle : _privateHandle;
        if (unwrapHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Unwrap (unwrapping-key handle unavailable)");

        ObjectHandle resulting = _workspace.Session.UnwrapKey(
            mechanism, unwrapHandle, wrappedBytes.ToArray(), template.Attributes.ToList());

        return _workspace.HydrateExistingHandleAsKey(resulting);
    }

    /// <summary>
    /// Derives a new key from this key.
    /// </summary>
    public Pkcs11Key Derive(Mechanism mechanism, ObjectTemplate template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(template);

        ObjectHandle baseHandle = _privateHandle.IsInvalid ? _publicHandle : _privateHandle;
        if (baseHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Derive (base-key handle unavailable)");

        ObjectHandle resulting = _workspace.Session.DeriveKey(
            mechanism, baseHandle, template.Attributes.ToList());
        return _workspace.HydrateExistingHandleAsKey(resulting);
    }
```

Add a helper on `Pkcs11Workspace.Keys.cs` so `Unwrap`/`Derive` can rehydrate handles:

```csharp
    /// <summary>
    /// Hydrates an existing object handle into a Pkcs11Key (used after operations that
    /// produce a new on-token object — Unwrap, Derive).
    /// </summary>
    internal Pkcs11Key HydrateExistingHandleAsKey(ObjectHandle handle)
        => HydrateKeyFromHandle(handle);
```

- [ ] **Step 4: Run tests**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11KeyMechanismTests" -c Debug
```

Expected: 3/3 pass (or skipped).

- [ ] **Step 5: Verify full suite**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

- [ ] **Step 6: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Key.Mechanism.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Workspace.Keys.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11KeyMechanismTests.cs

git commit -m "$(cat <<'EOF'
feat(Pkcs11Key): Wrap + Unwrap + Derive

Wrap consumes the target key's private/symmetric handle and produces
an opaque byte blob via Session.WrapKey using this key's
public/symmetric handle as the wrapping key. Unwrap and Derive run
the inverse / derivation operations and rehydrate the resulting new
on-token object as a fresh Pkcs11Key via Workspace.HydrateExisting-
HandleAsKey.

All three guard on handle availability and route argument errors
through the standard Pkcs11ObjectException path.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 12: `Pkcs11Workspace.GenerateKey` (symmetric)

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Workspace.Keys.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceGenerateKeyTests.cs`

Purpose: Single-template overload calls `Session.GenerateKey` and rehydrates.

- [ ] **Step 1: Write the failing test**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceGenerateKeyTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

[Collection("SoftHsm")]
public sealed class Pkcs11WorkspaceGenerateKeyTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public Pkcs11WorkspaceGenerateKeyTests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateKey_Symmetric_ReturnsKeyWithLabelAndType()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            SoftHsmBackendFixture.TokenLabel, CKU.CKU_USER, new SecurePin(SoftHsmBackendFixture.UserPin));

        string label = $"gen-{Guid.NewGuid():N}";
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build();

        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template);

        try
        {
            Assert.Equal(label, key.Label);
            Assert.Equal(CKK.CKK_AES, key.KeyType);
            Assert.False(key.PrivateHandle.IsInvalid);
        }
        finally
        {
            workspace.Session.DestroyObject(key.PrivateHandle);
        }
    }
}
```

- [ ] **Step 2: Verify failure**

Expected: build error — `workspace.GenerateKey` does not exist.

- [ ] **Step 3: Add `GenerateKey` (symmetric overload) to `Pkcs11Workspace.Keys.cs`**

```csharp
    /// <summary>
    /// Generates a new symmetric key using <c>C_GenerateKey</c> and returns it as a
    /// <see cref="Pkcs11Key"/>. For asymmetric key generation, use the two-template
    /// overload (Task 13).
    /// </summary>
    public Pkcs11Key GenerateKey(Mechanism mechanism, ObjectTemplate template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(template);

        var handle = _session.GenerateKey(mechanism, template.Attributes.ToList());
        return HydrateKeyFromHandle(handle);
    }
```

- [ ] **Step 4: Run tests**

Expected: 1/1 pass (or skipped).

- [ ] **Step 5: Verify full suite**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

- [ ] **Step 6: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Workspace.Keys.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceGenerateKeyTests.cs

git commit -m "$(cat <<'EOF'
feat(Pkcs11Workspace): GenerateKey(Mechanism, ObjectTemplate) symmetric

Single-template overload that delegates to Session.GenerateKey and
rehydrates the resulting handle through HydrateKeyFromHandle so the
returned Pkcs11Key carries its CKK / label / CKA_ID just like keys
opened via OpenKey or ImportKey.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 13: `Pkcs11Workspace.GenerateKey` (asymmetric, two templates → single Pkcs11Key)

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Workspace.Keys.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceGenerateKeyTests.cs`

Purpose: Two-template overload calls `Session.GenerateKeyPair` and returns a single `Pkcs11Key` carrying both handles (per the spec decision — no separate `Pkcs11KeyPair` type).

- [ ] **Step 1: Append test**

```csharp
    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateKey_Asymmetric_ReturnsKeyWithBothHandles()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            SoftHsmBackendFixture.TokenLabel, CKU.CKU_USER, new SecurePin(SoftHsmBackendFixture.UserPin));

        string label = $"gen-pair-{Guid.NewGuid():N}";
        byte[] id = System.Text.Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().ModulusBits(2048)
            .PublicExponent(new byte[] { 0x01, 0x00, 0x01 }).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign().Build();

        using var key = workspace.GenerateKey(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN),
            privTpl,
            pubTpl);

        try
        {
            Assert.Equal(label, key.Label);
            Assert.Equal(CKK.CKK_RSA, key.KeyType);
            Assert.False(key.PrivateHandle.IsInvalid);
            Assert.False(key.PublicHandle.IsInvalid);
        }
        finally
        {
            workspace.Session.DestroyObject(key.PrivateHandle);
            workspace.Session.DestroyObject(key.PublicHandle);
        }
    }
```

- [ ] **Step 2: Verify failure**

Expected: build error — two-template `GenerateKey` overload does not exist.

- [ ] **Step 3: Append asymmetric `GenerateKey` overload to `Pkcs11Workspace.Keys.cs`**

```csharp
    /// <summary>
    /// Generates a new asymmetric key pair using <c>C_GenerateKeyPair</c> and returns
    /// it as a single <see cref="Pkcs11Key"/> carrying both handles.
    /// </summary>
    /// <param name="mechanism">Key-pair generation mechanism (e.g. <see cref="CKM.CKM_RSA_PKCS_KEY_PAIR_GEN"/>).</param>
    /// <param name="privateTemplate">Template for the private key half.</param>
    /// <param name="publicTemplate">Template for the public key half.</param>
    public Pkcs11Key GenerateKey(
        Mechanism mechanism,
        ObjectTemplate privateTemplate,
        ObjectTemplate publicTemplate)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(privateTemplate);
        ArgumentNullException.ThrowIfNull(publicTemplate);

        _session.GenerateKeyPair(
            mechanism,
            publicTemplate.Attributes.ToList(),
            privateTemplate.Attributes.ToList(),
            out var publicHandle,
            out var privateHandle);

        // Read identifying metadata off the private side (preferred) — same shape
        // HydrateKeyFromHandle uses, but we already have both handles in hand so we
        // bypass the companion-discovery lookup.
        var attrs = _session.GetAttributeValue(privateHandle, new List<CKA>
        {
            CKA.CKA_KEY_TYPE,
            CKA.CKA_LABEL,
            CKA.CKA_ID,
        });

        try
        {
            var keyType = (CKK)attrs[0].GetValueAsCkUlong();
            string? label = attrs[1].CannotBeRead ? null : attrs[1].GetValueAsString();
            byte[] id = attrs[2].CannotBeRead ? Array.Empty<byte>() : attrs[2].GetValueAsByteArray();

            return new Pkcs11Key(
                workspace: this,
                privateHandle: privateHandle,
                publicHandle: publicHandle,
                keyType: keyType,
                label: label,
                id: id,
                ownedLibrary: null,
                ownsWorkspace: false);
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
    }
```

- [ ] **Step 4: Run tests**

Expected: 2/2 pass.

- [ ] **Step 5: Verify full suite**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

- [ ] **Step 6: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Workspace.Keys.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11WorkspaceGenerateKeyTests.cs

git commit -m "$(cat <<'EOF'
feat(Pkcs11Workspace): GenerateKey two-template asymmetric overload

The two-template GenerateKey overload generates an asymmetric key
pair (C_GenerateKeyPair) and returns a single Pkcs11Key carrying
both handles — no separate Pkcs11KeyPair type, per the spec design
decision. Metadata (CKK, label, CKA_ID) is read directly off the
private handle so we skip the companion-discovery lookup that
OpenKey/HydrateKeyFromHandle has to do.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 14: Final sanity sweep

**Files:**
- None modified; verification only.

- [ ] **Step 1: Confirm zero new `throw new Pkcs11` calls outside ExceptionMapper**

```bash
cd /home/alexandre/dev/PKCS11.NET
grep -rn "throw new Pkcs11" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
```

Expected: no output. (Plan 1's invariant must hold after Plan 2 — every Plan 2 throw site uses `Pkcs11Exception.Create(...)`, `Throw(...)`, or `ThrowIfError(...)`.)

- [ ] **Step 2: Confirm no leakage of `ExceptionMapper.Map` outside the central files**

```bash
grep -rn "ExceptionMapper\.Map" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/ | grep -v "Common/ExceptionMapper\.cs\|Common/Pkcs11Exception\.cs"
```

Expected: no output.

- [ ] **Step 3: Confirm `Pkcs11Workspace` and `Pkcs11Key` are public sealed partial classes**

```bash
grep -n "public sealed partial class Pkcs11Workspace" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Workspace.cs
grep -n "public sealed partial class Pkcs11Key" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Key.cs
```

Expected: one match each.

- [ ] **Step 4: Confirm `Pkcs11Library.OpenWorkspace` exists**

```bash
grep -n "public Pkcs11Workspace OpenWorkspace" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Library.cs
```

Expected: one match.

- [ ] **Step 5: Run the full test suite**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures. Test count should be roughly Plan 1's 209 + Plan 2's new tests:
- `Pkcs11WorkspaceTests`: 2
- `Pkcs11KeyTests`: 7
- `Pkcs11WorkspaceRandomTests`: 4 (per backend = 4 mock + later 4 softhsm; for now just Mock = 4)
- `Pkcs11WorkspaceFindKeysTests`: 5 (2 Mock + 3 SoftHsm)
- `Pkcs11WorkspaceGenerateKeyTests`: 2 (SoftHsm only)
- `Pkcs11KeyMechanismTests`: 3 (SoftHsm only)
- `Pkcs11KeyPublicSynthesisTests`: 2 (SoftHsm only)

≈ 25 new tests. Backend-gated tests may show up as Skipped if the relevant fixture isn't available. Total: ~234 passing or skipped + the pre-existing 209 = ~234, with the SoftHsm-only ones skipped in environments without it.

- [ ] **Step 6: Run a Release build**

```bash
dotnet build src/KerckhoffsLabs.sln -c Release
```

Expected: 0 errors.

- [ ] **Step 7: Commit (or skip — verification only)**

This task is verification-only. No file changes, so nothing to commit. Report completion.

---

## Self-review (already done — no action needed)

The plan was reviewed for the items below before publication:

**1. Spec coverage**

Cross-reference against `docs/superpowers/specs/2026-05-13-pkcs11-bcl-aligned-redesign-design.md`:

| Spec requirement | Plan-2 task |
|---|---|
| Pkcs11Workspace as auth context (architecture decision §5) | Task 1 |
| `OpenWorkspace(...)` factory on Pkcs11Library | Task 1 |
| Workspace.GenerateRandom / SeedRandom / Digest | Task 2 |
| Pkcs11Key with hidden session, CngKey-style (decision §4) | Task 3 |
| Pkcs11Workspace.OpenKey(label) / OpenKey(id) | Task 4 |
| CKA_ID-based public-companion auto-discovery (decision §3) | Task 4 |
| Pkcs11Workspace.FindKeys + ImportKey | Tasks 4-5 |
| Pkcs11Key.Open one-shot factories, both overloads (decision §4 + §8 open Q answer) | Task 6 |
| RSA public-key synthesis from private (decision §3) | Task 7 |
| EC public-key synthesis with CKA_EC_POINT fallback (decision §3) | Task 8 |
| Pkcs11Key.Sign / Verify with managed verify fallback (decision §4 + §6) | Task 9 |
| Pkcs11Key.Encrypt / Decrypt (decision §4) | Task 10 |
| Pkcs11Key.Wrap / Unwrap / Derive (decision §4) | Task 11 |
| Pkcs11Workspace.GenerateKey symmetric (decision §4 §3-no-keypair) | Task 12 |
| Pkcs11Workspace.GenerateKey asymmetric returning single Pkcs11Key (decision §3) | Task 13 |
| No HasPrivateKey / HasPublicKey introspection (decision §4 → spec edit) | Honored throughout — no such properties added |
| Sessions stay public in Plan 2 (becomes internal in Plan 4) | Honored — Session unchanged |

**2. Placeholder scan**

No `TBD`, `TODO`, "fill in", "similar to Task N", or undefined-type references. Every code block is complete.

**3. Type / signature consistency**

- `Pkcs11Key.Sign(Mechanism, ReadOnlySpan<byte>)` matches the spec sketch.
- `Pkcs11Key.Verify(...)` returns `bool` consistent with the spec.
- `Pkcs11Workspace.GenerateKey` has two overloads: one-template (symmetric) and three-arg (mechanism + private template + public template). Spec sketches the same.
- `Pkcs11Key.Open` two overloads: `(string libraryPath, ...)` and `(Pkcs11Library library, ...)`. Spec sketches both.
- Ownership flags on `Pkcs11Key` ctor are consistent across all factory paths.
- `ObjectTemplate` usage matches Plan 1 (`using var` pattern, dispose after use, `.Attributes.ToList()` to materialize for the existing Session methods).

---

## Execution handoff

**Plan complete and saved to `docs/superpowers/plans/2026-05-13-pkcs11-workspace-key.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — fresh subagent per task with two-stage review.

**2. Inline Execution** — execute tasks in this session using `executing-plans`, with batched checkpoints.
