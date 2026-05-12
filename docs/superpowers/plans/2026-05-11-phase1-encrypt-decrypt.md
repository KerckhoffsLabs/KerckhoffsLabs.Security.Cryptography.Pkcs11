# PKCS11.NET Phase 1: Encrypt + Decrypt Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Carve Encrypt and Decrypt operations out of the monolithic `Session.cs` into two partial-class files, add `ReadOnlySpan<byte>`/`Span<byte>` overloads alongside the existing `byte[]` and `Stream` variants, introduce secure-default convenience helpers (`EncryptAesGcm`, `EncryptChaCha20Poly1305`, `EncryptRsaOaep` + Decrypt counterparts), establish the per-session `AllowInsecure` runtime gate with `InsecureOperationException` for deprecated mechanisms (RSA PKCS#1 v1.5, DES/3DES, AES-ECB), and ship comprehensive functional + lifecycle + security-policy tests running against both `pkcs11-mock` and a new `SoftHSM2` backend fixture.

**Architecture:** TDD-driven per group. Test infrastructure first (`IPkcs11Backend` + both fixtures), then Encrypt/Decrypt refactor + new APIs in TDD order. Build stays green throughout. Pre-Phase-1 method signatures are preserved (the partial-class move is mechanical; behavior unchanged). New APIs are additive.

**Tech Stack:** C# 12 / .NET 8 + .NET 9, xUnit 2.9, `Microsoft.DotNet.XUnitExtensions` (`[SkippableFact]`, `[ConditionalFact]`), `pkcs11-mock` v2.0.0, SoftHSM2 (apt on Linux, chocolatey on Windows).

**Reference specs:**
- Parent: `docs/superpowers/specs/2026-05-11-pkcs11-completion-design.md`
- Phase 0a: `docs/superpowers/specs/2026-05-11-utility-class-redesign-design.md`

**Out of scope (deferred to later phases):**
- PKCS#11 v3.1 message-based APIs (`C_MessageEncryptInit`, `C_EncryptMessage`, etc.) — pkcs11-mock v2.0.0 predates v3.1, no backend supports them yet. Revisit when a backend does.
- Combined operations (`DigestEncrypt`, `SignEncrypt`, `DecryptDigest`) — these stay in `Session.cs` for Phase 1; they get their own home when Sign+Verify partial lands in Phase 2.

---

## File Structure

After this phase the relevant files are:

```
src/
├── KerckhoffsLabs.Security.Cryptography.Pkcs11/
│   ├── HighLevel/
│   │   ├── Session.cs                                        [MODIFY — strip Encrypt/Decrypt out; `partial`]
│   │   ├── Session.Encrypt.cs                                [CREATE — partial: existing + Span overloads + secure helpers]
│   │   ├── Session.Decrypt.cs                                [CREATE — partial: existing + Span overloads + secure helpers]
│   │   └── (other files unchanged)
│   └── Common/
│       └── InsecureOperationException.cs                     [CREATE]
│
└── KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/
    ├── Fixtures/
    │   ├── IPkcs11Backend.cs                                 [CREATE]
    │   ├── MockBackendFixture.cs                             [CREATE]
    │   └── SoftHsmBackendFixture.cs                          [CREATE]
    ├── HighLevel/
    │   ├── SmokeTests.cs                                     [MODIFY — refactor to use IPkcs11Backend]
    │   ├── Encrypt/
    │   │   ├── EncryptAesTests.cs                            [CREATE]
    │   │   ├── EncryptAesGcmTests.cs                         [CREATE]
    │   │   ├── EncryptChaChaTests.cs                         [CREATE]
    │   │   └── EncryptRsaTests.cs                            [CREATE]
    │   ├── Decrypt/
    │   │   ├── DecryptAesTests.cs                            [CREATE]
    │   │   ├── DecryptAesGcmTests.cs                         [CREATE]
    │   │   ├── DecryptChaChaTests.cs                         [CREATE]
    │   │   └── DecryptRsaTests.cs                            [CREATE]
    │   └── Security/
    │       └── InsecureOperationGateTests.cs                 [CREATE]
    └── (other files unchanged)
```

Each test file has TWO concrete classes (one per backend) that inherit from a shared abstract base. Pattern from the parent spec:

```csharp
public abstract class EncryptAesTests
{
    protected readonly IPkcs11Backend Backend;
    protected EncryptAesTests(IPkcs11Backend b) { Backend = b; }

    [SkippableFact]
    public void Encrypt_AesCbc_RoundTripsKnownPlaintext() { /* ... */ }
}

[Collection("Mock")]
public class EncryptAesTests_Mock    : EncryptAesTests { public EncryptAesTests_Mock(MockBackendFixture f)    : base(f) { } }

[Collection("SoftHsm")]
public class EncryptAesTests_SoftHsm : EncryptAesTests { public EncryptAesTests_SoftHsm(SoftHsmBackendFixture f) : base(f) { } }
```

xUnit collection fixtures ensure library `C_Initialize`/`C_Finalize` happens once per backend, not per test class.

---

## Task 1: Add `InsecureOperationException` + `AllowInsecure` property on Session

Foundation for the security-policy work. Adding it first lets the secure helpers + `[Obsolete]` methods in T7–T8 reference it cleanly.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/InsecureOperationException.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`

- [ ] **Step 1: Write the exception class**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/InsecureOperationException.cs`:

```csharp
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Thrown when an operation uses a mechanism the library considers insecure by default,
/// unless the caller has opted in via <c>Session.AllowInsecure = true</c>. Covers RSA
/// PKCS#1 v1.5 padding, DES/3DES, AES-ECB, MD5/SHA-1 in signature contexts, and other
/// mechanisms flagged in the parent design spec.
/// </summary>
public sealed class InsecureOperationException : Exception
{
    /// <summary>The mechanism that triggered the gate.</summary>
    public CKM Mechanism { get; }

    /// <summary>
    /// Initializes a new <see cref="InsecureOperationException"/>.
    /// </summary>
    /// <param name="mechanism">The mechanism that was rejected.</param>
    /// <param name="suggestion">A short pointer to the modern alternative, included in the message.</param>
    public InsecureOperationException(CKM mechanism, string suggestion)
        : base($"Mechanism {mechanism} is disallowed by default. {suggestion} " +
               $"To bypass, set Session.AllowInsecure = true before invoking the operation.")
    {
        Mechanism = mechanism;
    }
}
```

- [ ] **Step 2: Add the `AllowInsecure` property to Session.cs**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`. Find the class declaration `public class Session` (near the top of the file). Change it to `public partial class Session` (the `partial` keyword is required for the splits in T3 + T4).

Then, near the existing `_disposed` / `_pkcs11Library` field declarations, add:

```csharp
    /// <summary>
    /// When <c>true</c>, this session does not reject operations that use mechanisms flagged as
    /// insecure by default (RSA PKCS#1 v1.5, DES/3DES, AES-ECB, etc.). Default is <c>false</c>.
    /// Set explicitly per session; never set this globally.
    /// </summary>
    public bool AllowInsecure { get; set; } = false;
```

Also add a private helper method near the bottom of the class:

```csharp
    /// <summary>
    /// Checks the given mechanism against the insecure-mechanism set and throws
    /// <see cref="InsecureOperationException"/> if it is insecure and <see cref="AllowInsecure"/>
    /// is false.
    /// </summary>
    private void GuardMechanism(CKM mechanism)
    {
        if (AllowInsecure) return;

        switch (mechanism)
        {
            case CKM.CKM_RSA_PKCS:
                throw new InsecureOperationException(mechanism,
                    "RSA PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks; use CKM_RSA_PKCS_OAEP instead.");
            case CKM.CKM_DES_ECB:
            case CKM.CKM_DES_CBC:
            case CKM.CKM_DES_CBC_PAD:
            case CKM.CKM_DES3_ECB:
            case CKM.CKM_DES3_CBC:
            case CKM.CKM_DES3_CBC_PAD:
                throw new InsecureOperationException(mechanism,
                    "DES and 3DES are deprecated; use AES (CKM_AES_GCM or CKM_AES_CBC_PAD) instead.");
            case CKM.CKM_AES_ECB:
                throw new InsecureOperationException(mechanism,
                    "ECB mode leaks structural information from the plaintext; use CKM_AES_GCM or CKM_AES_CBC_PAD instead.");
            default:
                return;
        }
    }
```

- [ ] **Step 3: Build to confirm nothing breaks**

```bash
dotnet build src/src.sln 2>&1 | tail -3
```

Expected: `0 Error(s)`. The new exception class compiles; Session.cs becomes partial; AllowInsecure property + GuardMechanism are added but not yet called from anywhere — that wiring happens in T6.

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/InsecureOperationException.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session): add AllowInsecure property + InsecureOperationException

Foundation for the insecure-op runtime gate. Session is declared
partial (preparing for Encrypt/Decrypt split in subsequent commits).
GuardMechanism is private and currently unused; T7 wires it into
the Encrypt/Decrypt entry points to enforce the gate."
```

---

## Task 2: Add `IPkcs11Backend` abstraction

Lets test classes parameterize over the loaded mock vs SoftHSM2 without hard-coding the library path or PIN.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Fixtures/IPkcs11Backend.cs`

- [ ] **Step 1: Write the interface**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Fixtures/IPkcs11Backend.cs`:

```csharp
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

/// <summary>
/// Abstraction over a backing PKCS#11 module (pkcs11-mock or SoftHSM2). Tests
/// depend on this rather than on a concrete fixture, so the same test runs
/// against either backend via the xUnit `[Collection]` mechanism.
/// </summary>
public interface IPkcs11Backend
{
    /// <summary>Absolute path to the loaded shared library.</summary>
    string LibraryPath { get; }

    /// <summary>The shared <see cref="Pkcs11Library"/> instance for the backend.</summary>
    Pkcs11Library Library { get; }

    /// <summary>Slot id of a slot containing an initialized token.</summary>
    NativeCULong SlotId { get; }

    /// <summary>SO PIN for the fixture's token (raw bytes).</summary>
    byte[] SoPin { get; }

    /// <summary>Normal-user PIN for the fixture's token (raw bytes).</summary>
    byte[] UserPin { get; }

    /// <summary>Label of the fixture's token.</summary>
    string TokenLabel { get; }
}
```

- [ ] **Step 2: Build to confirm**

```bash
dotnet build src/src.sln 2>&1 | tail -3
```

Expected: `0 Error(s)`. The interface is in the test project; nothing references it yet.

- [ ] **Step 3: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Fixtures/IPkcs11Backend.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "test(Fixtures): add IPkcs11Backend abstraction

Test interface that the mock + SoftHSM2 fixtures implement. Lets a single
test class run against both backends via xUnit [Collection]."
```

---

## Task 3: Implement `MockBackendFixture` and refactor `SmokeTests`

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Fixtures/MockBackendFixture.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/SmokeTests.cs`

- [ ] **Step 1: Write the MockBackendFixture**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Fixtures/MockBackendFixture.cs`:

```csharp
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

/// <summary>
/// xUnit collection fixture wrapping pkcs11-mock. Loads the mock library
/// once per collection, picks the first slot with a token present, and
/// disposes on collection teardown.
/// </summary>
public sealed class MockBackendFixture : IPkcs11Backend, IDisposable
{
    public string LibraryPath { get; }
    public Pkcs11Library Library { get; }
    public NativeCULong SlotId { get; }
    public byte[] SoPin { get; } = System.Text.Encoding.UTF8.GetBytes("11111111");
    public byte[] UserPin { get; } = System.Text.Encoding.UTF8.GetBytes("11111111");
    public string TokenLabel { get; } = "Pkcs11Interop Mock Token";

    public MockBackendFixture()
    {
        LibraryPath = Settings.MockLibraryPath;
        if (!File.Exists(LibraryPath))
            throw new InvalidOperationException(
                $"pkcs11-mock not found at '{LibraryPath}'. " +
                $"Run build/build-pkcs11-mock.sh to produce it.");

        Library = new Pkcs11Library(LibraryPath);
        var slots = Library.GetSlotList(SlotsType.WithTokenPresent);
        if (slots.Count == 0)
            throw new InvalidOperationException("pkcs11-mock reported no slots with token present.");
        SlotId = (NativeCULong)slots[0].SlotId;
    }

    public void Dispose() => Library?.Dispose();
}

/// <summary>xUnit collection definition that binds <see cref="MockBackendFixture"/> as a singleton across a collection.</summary>
[CollectionDefinition("Mock")]
public sealed class MockBackendCollection : ICollectionFixture<MockBackendFixture> { }
```

(`Slot.SlotId` should already be a public property on `Slot`. If the property name differs, adjust the cast — the goal is to grab the slot's numeric id.)

- [ ] **Step 2: Refactor SmokeTests to use the fixture**

The existing `SmokeTests.LoadInitializeFinalize_OnMock_Succeeds` loads the library directly. Replace its content with a fixture-backed version. Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/SmokeTests.cs` and replace its entire content with:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

/// <summary>
/// End-to-end smoke check that the library loads a backend and completes a
/// minimal Cryptoki lifecycle. Runs against pkcs11-mock; SoftHSM2 gets its
/// own smoke variant in T4.
/// </summary>
public abstract class SmokeTests
{
    private readonly IPkcs11Backend _backend;
    protected SmokeTests(IPkcs11Backend backend) { _backend = backend; }

    [Fact]
    public void GetInfo_ReturnsNonEmptyManufacturerAndVersion()
    {
        LibraryInfo info = _backend.Library.GetInfo();
        Assert.False(string.IsNullOrWhiteSpace(info.ManufacturerId));
        Assert.False(string.IsNullOrWhiteSpace(info.CryptokiVersion));
    }
}

[Collection("Mock")]
public sealed class SmokeTests_Mock : SmokeTests { public SmokeTests_Mock(MockBackendFixture f) : base(f) { } }
```

- [ ] **Step 3: Run the smoke test**

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~SmokeTests_Mock" 2>&1 | tail -5
```

Expected: 1 passed, 0 failed.

- [ ] **Step 4: Full test suite check**

```bash
dotnet test src/src.sln 2>&1 | tail -5
```

Expected: 142 passed (or current count). The refactor preserves coverage.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Fixtures/MockBackendFixture.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/SmokeTests.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "test(Fixtures): add MockBackendFixture; refactor SmokeTests to use it

Refactors SmokeTests to use the collection fixture pattern with
[CollectionDefinition(\"Mock\")] so subsequent Encrypt/Decrypt tests can
share the loaded mock library across their test classes."
```

---

## Task 4: Implement `SoftHsmBackendFixture`

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Fixtures/SoftHsmBackendFixture.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/SmokeTests.cs` (add `SmokeTests_SoftHsm` concrete class)
- Modify: `.github/workflows/ci.yml` (install softhsm2)

- [ ] **Step 1: Install softhsm2 on the dev machine for local testing**

```bash
sudo apt-get install -y softhsm2
which softhsm2-util && softhsm2-util --version
```

Expected: `softhsm2-util` is on `PATH` and prints a version. If the dev machine is non-Linux, the fixture will skip via `[ConditionalFact]` and the SoftHSM tests will be no-op locally — CI on Linux handles the real coverage.

- [ ] **Step 2: Write the SoftHsmBackendFixture**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Fixtures/SoftHsmBackendFixture.cs`:

```csharp
using System.Diagnostics;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

/// <summary>
/// xUnit collection fixture wrapping SoftHSM2. Creates a fresh token directory
/// per test run, initializes a token with a deterministic SO/USER PIN, loads
/// libsofthsm2.so, and exposes the resulting slot through <see cref="IPkcs11Backend"/>.
/// Tests using this fixture must use <see cref="SoftHsmAvailable"/> as a [ConditionalFact]
/// member name to skip when SoftHSM2 isn't installed.
/// </summary>
public sealed class SoftHsmBackendFixture : IPkcs11Backend, IDisposable
{
    public string LibraryPath { get; }
    public Pkcs11Library Library { get; } = null!;
    public NativeCULong SlotId { get; }
    public byte[] SoPin   { get; } = System.Text.Encoding.UTF8.GetBytes("12345678");
    public byte[] UserPin { get; } = System.Text.Encoding.UTF8.GetBytes("87654321");
    public string TokenLabel { get; } = "phase1-test-token";

    private readonly string _tokenDir;
    private readonly string _configPath;
    private readonly bool _available;

    /// <summary>True when SoftHSM2 was detected and the fixture is fully initialized.</summary>
    public static bool SoftHsmAvailable => SoftHsmDiscover() is not null;

    public SoftHsmBackendFixture()
    {
        string? libPath = Settings.SoftHsmLibraryPath ?? SoftHsmDiscover();
        if (libPath is null)
        {
            _available = false;
            LibraryPath = string.Empty;
            _tokenDir = _configPath = string.Empty;
            return;
        }

        LibraryPath = libPath;

        _tokenDir = Path.Combine(Path.GetTempPath(), "pkcs11net-softhsm-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tokenDir);

        _configPath = Path.Combine(_tokenDir, "softhsm2.conf");
        File.WriteAllText(_configPath,
            $"directories.tokendir = {_tokenDir}\n" +
            "objectstore.backend = file\n" +
            "log.level = ERROR\n");
        Environment.SetEnvironmentVariable("SOFTHSM2_CONF", _configPath);

        // Initialize a token via softhsm2-util.
        RunUtil($"--init-token --free " +
                $"--label \"{TokenLabel}\" " +
                $"--so-pin \"{System.Text.Encoding.UTF8.GetString(SoPin)}\" " +
                $"--pin \"{System.Text.Encoding.UTF8.GetString(UserPin)}\"");

        Library = new Pkcs11Library(LibraryPath);
        var slots = Library.GetSlotList(SlotsType.WithTokenPresent);
        Slot? found = slots.FirstOrDefault(s => s.GetTokenInfo().Label.Trim() == TokenLabel);
        if (found is null)
            throw new InvalidOperationException($"SoftHSM2 token '{TokenLabel}' did not appear in slot list.");
        SlotId = (NativeCULong)found.SlotId;
        _available = true;
    }

    public void Dispose()
    {
        try { Library?.Dispose(); } catch { /* ignore teardown errors */ }
        try { if (Directory.Exists(_tokenDir)) Directory.Delete(_tokenDir, recursive: true); } catch { }
    }

    private static string? SoftHsmDiscover()
    {
        // Standard install locations across Linux distributions and macOS.
        string[] candidates =
        {
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/local/lib/softhsm/libsofthsm2.so",
            "/opt/homebrew/lib/softhsm/libsofthsm2.so",
            "/usr/local/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so",
            // Windows (when softhsm2 has been installed via chocolatey).
            @"C:\SoftHSM2\lib\softhsm2-x64.dll",
        };
        return candidates.FirstOrDefault(File.Exists);
    }

    private void RunUtil(string args)
    {
        var psi = new ProcessStartInfo("softhsm2-util", args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.Environment["SOFTHSM2_CONF"] = _configPath;
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Could not start softhsm2-util.");
        p.WaitForExit();
        if (p.ExitCode != 0)
        {
            string err = p.StandardError.ReadToEnd();
            throw new InvalidOperationException($"softhsm2-util failed (exit {p.ExitCode}): {err}");
        }
    }
}

/// <summary>xUnit collection definition for the SoftHSM2 backend.</summary>
[CollectionDefinition("SoftHsm")]
public sealed class SoftHsmBackendCollection : ICollectionFixture<SoftHsmBackendFixture> { }
```

(If `Slot.GetTokenInfo()` is named differently in the current codebase, substitute. The pattern is: find the slot whose token has the expected label.)

- [ ] **Step 3: Add the SoftHSM smoke test variant**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/SmokeTests.cs`. Replace the bottom (where the `SmokeTests_Mock` class is) with:

```csharp
[Collection("Mock")]
public sealed class SmokeTests_Mock : SmokeTests { public SmokeTests_Mock(MockBackendFixture f) : base(f) { } }

[Collection("SoftHsm")]
public sealed class SmokeTests_SoftHsm : SmokeTests
{
    public SmokeTests_SoftHsm(SoftHsmBackendFixture f) : base(f)
    {
        Skip.If(!SoftHsmBackendFixture.SoftHsmAvailable, "SoftHSM2 not installed on this host.");
    }
}
```

Also change `[Fact]` in the base class to `[SkippableFact]` so the `Skip.If` machinery is available, and add `using Xunit;` (which the project already implies via the global Using).

The full updated `SmokeTests.cs` becomes:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public abstract class SmokeTests
{
    private readonly IPkcs11Backend _backend;
    protected SmokeTests(IPkcs11Backend backend) { _backend = backend; }

    [SkippableFact]
    public void GetInfo_ReturnsNonEmptyManufacturerAndVersion()
    {
        LibraryInfo info = _backend.Library.GetInfo();
        Assert.False(string.IsNullOrWhiteSpace(info.ManufacturerId));
        Assert.False(string.IsNullOrWhiteSpace(info.CryptokiVersion));
    }
}

[Collection("Mock")]
public sealed class SmokeTests_Mock : SmokeTests { public SmokeTests_Mock(MockBackendFixture f) : base(f) { } }

[Collection("SoftHsm")]
public sealed class SmokeTests_SoftHsm : SmokeTests
{
    public SmokeTests_SoftHsm(SoftHsmBackendFixture f) : base(f)
    {
        Skip.If(!SoftHsmBackendFixture.SoftHsmAvailable, "SoftHSM2 not installed on this host.");
    }
}
```

- [ ] **Step 4: Add softhsm2 install to CI**

Open `.github/workflows/ci.yml`. Find the `Install build deps (Linux)` step and add a separate step before `Restore`:

```yaml
      - name: Install SoftHSM2 (Linux)
        if: runner.os == 'Linux'
        run: sudo apt-get install -y softhsm2

      - name: Install SoftHSM2 (Windows)
        if: runner.os == 'Windows'
        run: choco install -y softhsm
        shell: pwsh
        continue-on-error: true
```

(Windows install is `continue-on-error: true` because chocolatey's softhsm package is occasionally flaky; tests will skip gracefully if it didn't install.)

- [ ] **Step 5: Run tests locally**

```bash
dotnet test src/src.sln 2>&1 | tail -10
```

Expected: full suite passes. SoftHSM smoke test runs on Linux with softhsm2 installed; otherwise it shows as Skipped.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Fixtures/SoftHsmBackendFixture.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/SmokeTests.cs .github/workflows/ci.yml
git -C /home/alexandre/dev/PKCS11.NET commit -m "test(Fixtures): add SoftHsmBackendFixture + CI softhsm2 install

SoftHsmBackendFixture initializes a fresh token in a temp directory per
test run via softhsm2-util. Auto-discovers libsofthsm2 across common
install locations; honors PKCS11_TEST_SOFTHSM_LIBRARY env var override.

CI installs softhsm2 via apt on Linux and chocolatey on Windows. The
Windows install is best-effort (continue-on-error) because the choco
package is occasionally unavailable; SoftHsm tests skip gracefully then.

SmokeTests gains a SmokeTests_SoftHsm parameterization that runs the
same lifecycle assertion against SoftHSM2 when available."
```

---

## Task 5: Carve `Session.Encrypt.cs` out of `Session.cs`

Pure mechanical refactor: move the three existing Encrypt method bodies out of Session.cs into a partial. No behavior change; no new APIs in this task.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Encrypt.cs`

- [ ] **Step 1: Locate the Encrypt methods in Session.cs**

The existing methods are at approximately:
- `public byte[] Encrypt(Mechanism mechanism, ObjectHandle keyHandle, byte[] data)` — around line 772
- `public void Encrypt(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream)` — around line 817
- `public void Encrypt(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream, int bufferLength)` — around line 847

Locate them exactly:

```bash
grep -n "public.* Encrypt(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs | head -5
```

Find any XML doc comment(s) immediately above each method (look back ~15 lines for `///` lines) and include them in the move.

- [ ] **Step 2: Create Session.Encrypt.cs with the moved methods**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Encrypt.cs` with this skeleton:

```csharp
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
{
    // === existing Encrypt methods moved from Session.cs ===
    // (Paste the three Encrypt method bodies + their XML doc comments here.)
}
```

Move the three method bodies (and their XML doc comments) verbatim from `Session.cs` into the placeholder above the `===` comment. Remove the placeholder comment. Then delete the methods from `Session.cs`.

The partial class shares all of `Session.cs`'s usings + namespace, so the moved code requires no using changes other than the ones in the new file's header (already shown above).

- [ ] **Step 3: Build to confirm**

```bash
dotnet build src/src.sln 2>&1 | tail -5
```

Expected: `0 Error(s)`. The Encrypt methods now live in `Session.Encrypt.cs` but are still members of `Session` via the `partial` keyword.

- [ ] **Step 4: Run tests to confirm no regression**

```bash
dotnet test src/src.sln 2>&1 | tail -5
```

Expected: all previously-passing tests still pass.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Encrypt.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "refactor(Session): carve Encrypt methods into Session.Encrypt.cs partial

Pure relocation, no behavior change. The three existing Encrypt
methods (byte[], Stream, Stream-with-buffer-size) move into a new
partial-class file. Sets up for Span overloads + secure helpers in
subsequent tasks."
```

---

## Task 6: Carve `Session.Decrypt.cs` out of `Session.cs`

Same mechanical refactor for Decrypt.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Decrypt.cs`

- [ ] **Step 1: Locate the Decrypt methods in Session.cs**

```bash
grep -n "public.* Decrypt(" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs | head -5
```

Expected: three lines, approximately at 921, 966, 996. (Ignore `DecryptDigest` matches; those stay in Session.cs.)

- [ ] **Step 2: Create Session.Decrypt.cs**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Decrypt.cs`:

```csharp
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
{
    // === existing Decrypt methods moved from Session.cs ===
}
```

Move the three Decrypt method bodies (+ their XML doc comments) verbatim from `Session.cs`. Do NOT move `DecryptDigest` — that's a combined operation and stays in `Session.cs` until Phase 2's Sign+Verify split lands.

- [ ] **Step 3: Build and test**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | tail -5
```

Expected: 0 errors, all tests pass.

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Decrypt.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "refactor(Session): carve Decrypt methods into Session.Decrypt.cs partial

Pure relocation. DecryptDigest stays in Session.cs since it's a
combined operation that will move when Sign+Verify lands (Phase 2)."
```

---

## Task 7: Add `Span<byte>`/`ReadOnlySpan<byte>` overloads to Encrypt + Decrypt

Adds new overloads alongside the existing `byte[]` and `Stream` variants. Span overloads delegate to the existing `byte[]` paths via temporary array conversion — zero-copy refinement is a future-perf concern, not a correctness one. Wires the `GuardMechanism` call from T1.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Encrypt.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Decrypt.cs`

- [ ] **Step 1: Add Span overload to Encrypt**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Encrypt.cs`. Add this method **above** the existing `public byte[] Encrypt(Mechanism mechanism, ObjectHandle keyHandle, byte[] data)`:

```csharp
    /// <summary>
    /// Encrypts <paramref name="data"/> using the given mechanism and key. Throws
    /// <see cref="InsecureOperationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">The encryption mechanism to use.</param>
    /// <param name="keyHandle">Handle of the key to encrypt with.</param>
    /// <param name="data">Plaintext to encrypt.</param>
    /// <returns>A freshly-allocated byte array containing the ciphertext.</returns>
    public byte[] Encrypt(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(keyHandle);
        GuardMechanism(mechanism.Type);
        // Temporary array for the byte[]-based P/Invoke path. Replace with pinned-Span
        // P/Invoke when perf profiling proves it matters.
        byte[] buffer = data.ToArray();
        return Encrypt(mechanism, keyHandle, buffer);
    }
```

The existing `Encrypt(..., byte[] data)` method ALSO needs `GuardMechanism(mechanism.Type);` added at the top of its body (it's the primary entry point that takes `byte[]`, so all the other entries should flow through the gate). Find the existing method body and add the `ArgumentNullChecks` + `GuardMechanism` call at the top (just after the `ObjectDisposedException.ThrowIf` check that should already be there).

Same for the two `Stream`-based `Encrypt` overloads — add `GuardMechanism(mechanism.Type);` after the existing entry checks.

- [ ] **Step 2: Add Span overload to Decrypt**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Decrypt.cs`. Add above the existing `public byte[] Decrypt(Mechanism mechanism, ObjectHandle keyHandle, byte[] encryptedData)`:

```csharp
    /// <summary>
    /// Decrypts <paramref name="encryptedData"/> using the given mechanism and key. Throws
    /// <see cref="InsecureOperationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and <see cref="AllowInsecure"/> is false.
    /// </summary>
    public byte[] Decrypt(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> encryptedData)
    {
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(keyHandle);
        GuardMechanism(mechanism.Type);
        byte[] buffer = encryptedData.ToArray();
        return Decrypt(mechanism, keyHandle, buffer);
    }
```

Add `GuardMechanism(mechanism.Type);` to the existing `Decrypt(..., byte[])` and both `Stream` overloads at the top of each body.

- [ ] **Step 3: Build**

```bash
dotnet build src/src.sln 2>&1 | tail -3
```

Expected: `0 Error(s)`. If a build error says `mechanism.Type` doesn't exist, check the property name — `Mechanism.Type` is the canonical accessor; if the local class uses `Mechanism.Mechanism` or `Mechanism.Ckm`, adapt.

- [ ] **Step 4: Run tests**

```bash
dotnet test src/src.sln 2>&1 | tail -5
```

Expected: all tests still pass. **However**, if any existing test invokes `Encrypt`/`Decrypt` with an insecure mechanism (e.g., `CKM_DES_CBC`) without setting `AllowInsecure=true`, it will now throw `InsecureOperationException`. Inspect the failure if so — it's catching a real test that needs the `AllowInsecure` opt-in.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Encrypt.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Decrypt.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session): add ReadOnlySpan<byte> Encrypt/Decrypt + wire GuardMechanism

Span overloads delegate to the existing byte[] path via .ToArray() —
zero-copy via pinning is a future optimization. GuardMechanism is now
called from every Encrypt/Decrypt entry point; insecure mechanisms
(RSA PKCS#1 v1.5, DES/3DES, AES-ECB) throw InsecureOperationException
unless Session.AllowInsecure=true."
```

---

## Task 8: Add secure-default encryption helpers

Named methods that build the right `Mechanism` and call `Encrypt`/`Decrypt`. These are pure convenience over the generic API.

**Files:**
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Encrypt.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Decrypt.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/MechanismParams/CK_GCM_PARAMS.cs` (only if missing or incomplete; check first)

- [ ] **Step 1: Verify `CK_GCM_PARAMS` exists**

```bash
grep -l "CK_GCM_PARAMS" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/MechanismParams/ 2>/dev/null
```

Expected: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Native/MechanismParams/CK_GCM_PARAMS.cs` exists. (Phase 0 imported all upstream MechanismParams files.) If it does not exist, STOP and report — the helpers can't be built without it.

Inspect it to confirm field names — typically `pIv`, `ulIvLen`, `pAAD`, `ulAADLen`, `ulTagBits`. The helper below references `pIv`, `ulIvLen`, `ulIvBits`, `pAAD`, `ulAADLen`, `ulTagBits`. Adjust the helper to match the actual field names.

- [ ] **Step 2: Add `EncryptAesGcm` and `EncryptChaCha20Poly1305` and `EncryptRsaOaep` to `Session.Encrypt.cs`**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Encrypt.cs`. Append (above the closing `}` of the partial class):

```csharp
    // === Secure-default encryption helpers =================================

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> using AES-GCM with a 96-bit IV and a 128-bit
    /// authentication tag. Produces ciphertext concatenated with the tag (PKCS#11 standard
    /// output format for AEAD).
    /// </summary>
    /// <param name="keyHandle">An AES key handle (must allow encryption).</param>
    /// <param name="iv">12-byte (96-bit) nonce, MUST be unique per key.</param>
    /// <param name="plaintext">Data to encrypt.</param>
    /// <param name="aad">Additional Authenticated Data; default is empty.</param>
    /// <returns>Ciphertext + 16-byte tag.</returns>
    public byte[] EncryptAesGcm(
        ObjectHandle keyHandle,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> aad = default)
    {
        if (iv.Length != 12)
            throw new ArgumentException("AES-GCM IV must be exactly 12 bytes (96 bits).", nameof(iv));

        var ckParams = new CK_GCM_PARAMS
        {
            pIv = UnmanagedMemory.Allocate(iv.Length),
            ulIvLen = (NativeCULong)iv.Length,
            ulIvBits = (NativeCULong)(iv.Length * 8),
            pAAD = aad.Length > 0 ? UnmanagedMemory.Allocate(aad.Length) : IntPtr.Zero,
            ulAADLen = (NativeCULong)aad.Length,
            ulTagBits = (NativeCULong)128,
        };
        try
        {
            UnmanagedMemory.Write(ckParams.pIv, iv);
            if (aad.Length > 0)
                UnmanagedMemory.Write(ckParams.pAAD, aad);

            using var mechanism = new Mechanism(CKM.CKM_AES_GCM, ckParams);
            return Encrypt(mechanism, keyHandle, plaintext);
        }
        finally
        {
            if (ckParams.pIv != IntPtr.Zero) UnmanagedMemory.Free(ref ckParams.pIv);
            if (ckParams.pAAD != IntPtr.Zero) UnmanagedMemory.Free(ref ckParams.pAAD);
        }
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> using ChaCha20-Poly1305 with a 96-bit nonce.
    /// Produces ciphertext concatenated with a 128-bit tag.
    /// </summary>
    public byte[] EncryptChaCha20Poly1305(
        ObjectHandle keyHandle,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> aad = default)
    {
        if (nonce.Length != 12)
            throw new ArgumentException("ChaCha20-Poly1305 nonce must be exactly 12 bytes (96 bits).", nameof(nonce));

        // PKCS#11 v3.0 uses CK_SALSA20_CHACHA20_POLY1305_PARAMS for this mechanism.
        // If the local codebase has a different params struct name, adapt.
        var ckParams = new CK_SALSA20_CHACHA20_POLY1305_PARAMS
        {
            pNonce = UnmanagedMemory.Allocate(nonce.Length),
            ulNonceLen = (NativeCULong)nonce.Length,
            pAAD = aad.Length > 0 ? UnmanagedMemory.Allocate(aad.Length) : IntPtr.Zero,
            ulAADLen = (NativeCULong)aad.Length,
        };
        try
        {
            UnmanagedMemory.Write(ckParams.pNonce, nonce);
            if (aad.Length > 0)
                UnmanagedMemory.Write(ckParams.pAAD, aad);

            using var mechanism = new Mechanism(CKM.CKM_CHACHA20_POLY1305, ckParams);
            return Encrypt(mechanism, keyHandle, plaintext);
        }
        finally
        {
            if (ckParams.pNonce != IntPtr.Zero) UnmanagedMemory.Free(ref ckParams.pNonce);
            if (ckParams.pAAD != IntPtr.Zero) UnmanagedMemory.Free(ref ckParams.pAAD);
        }
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> using RSA-OAEP with SHA-256 and MGF1+SHA-256.
    /// Suitable for wrapping symmetric keys; not for bulk data (plaintext must be smaller
    /// than the RSA modulus minus 2*hashSize+2).
    /// </summary>
    public byte[] EncryptRsaOaep(ObjectHandle keyHandle, ReadOnlySpan<byte> plaintext)
    {
        var ckParams = new CK_RSA_PKCS_OAEP_PARAMS
        {
            hashAlg = CKM.CKM_SHA256.ToCULong(),
            mgf = CKG.CKG_MGF1_SHA256.ToCULong(),
            source = (NativeCULong)1, // CKZ_DATA_SPECIFIED
            pSourceData = IntPtr.Zero,
            ulSourceDataLen = (NativeCULong)0,
        };

        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_OAEP, ckParams);
        return Encrypt(mechanism, keyHandle, plaintext);
    }
```

Two of the structs (`CK_GCM_PARAMS`, `CK_RSA_PKCS_OAEP_PARAMS`, `CK_SALSA20_CHACHA20_POLY1305_PARAMS`) live in `Native/MechanismParams/`. If field names differ from the helper above:
- `CK_GCM_PARAMS` may use `pIv`, `ulIvLen`, `ulIvBits`, `pAAD`, `ulAADLen`, `ulTagBits`. If yours uses different names, adjust the assignments.
- `CK_RSA_PKCS_OAEP_PARAMS` may use `hashAlg`, `mgf`, `source`, `pSourceData`, `ulSourceDataLen` — or those names with `_` separators. Adjust.
- `CK_SALSA20_CHACHA20_POLY1305_PARAMS` may not exist in the imported set (PKCS#11 v3.0). If it's missing, **add it** under `Native/MechanismParams/` with the fields: `IntPtr pNonce; NativeCULong ulNonceLen; IntPtr pAAD; NativeCULong ulAADLen;`. Mark it `[StructLayout(LayoutKind.Sequential)] [PlatformSpecificPack]`.

Report any deviation; don't silently guess struct shapes.

- [ ] **Step 2b: Add `[Obsolete]` named shortcuts for RSA PKCS#1 v1.5 in `Session.Encrypt.cs`**

The parent spec calls for `[Obsolete]`-marked named methods that give callers a compile-time warning pointing at the modern alternative. The runtime gate (via `GuardMechanism`) ensures these methods throw at runtime regardless of whether the caller heeds the warning, so they're double protection.

Append to `Session.Encrypt.cs` (above the closing `}` of the partial):

```csharp
    // === Legacy named shortcuts (gated, compile-time warning) ==============

    /// <summary>
    /// Encrypts using RSA PKCS#1 v1.5 padding. **Use <see cref="EncryptRsaOaep"/> instead.**
    /// This method exists for compatibility; it throws <see cref="InsecureOperationException"/>
    /// at runtime unless <see cref="AllowInsecure"/> is set on the session.
    /// </summary>
    [Obsolete("RSA PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks. Use EncryptRsaOaep instead. " +
              "If you must use it, set Session.AllowInsecure = true.")]
    public byte[] EncryptRsaPkcs1V15(ObjectHandle keyHandle, ReadOnlySpan<byte> plaintext)
    {
        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS);
        return Encrypt(mechanism, keyHandle, plaintext);
    }
```

- [ ] **Step 3: Add Decrypt counterparts to `Session.Decrypt.cs`**

Open `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Decrypt.cs`. Append (above the closing `}`):

```csharp
    // === Secure-default decryption helpers =================================

    /// <summary>
    /// Decrypts ciphertext+tag produced by <see cref="EncryptAesGcm"/>. The tag is the last
    /// 16 bytes of <paramref name="ciphertextAndTag"/>.
    /// </summary>
    public byte[] DecryptAesGcm(
        ObjectHandle keyHandle,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> ciphertextAndTag,
        ReadOnlySpan<byte> aad = default)
    {
        if (iv.Length != 12)
            throw new ArgumentException("AES-GCM IV must be exactly 12 bytes (96 bits).", nameof(iv));
        if (ciphertextAndTag.Length < 16)
            throw new ArgumentException("AES-GCM ciphertext must include a 16-byte tag.", nameof(ciphertextAndTag));

        var ckParams = new CK_GCM_PARAMS
        {
            pIv = UnmanagedMemory.Allocate(iv.Length),
            ulIvLen = (NativeCULong)iv.Length,
            ulIvBits = (NativeCULong)(iv.Length * 8),
            pAAD = aad.Length > 0 ? UnmanagedMemory.Allocate(aad.Length) : IntPtr.Zero,
            ulAADLen = (NativeCULong)aad.Length,
            ulTagBits = (NativeCULong)128,
        };
        try
        {
            UnmanagedMemory.Write(ckParams.pIv, iv);
            if (aad.Length > 0)
                UnmanagedMemory.Write(ckParams.pAAD, aad);

            using var mechanism = new Mechanism(CKM.CKM_AES_GCM, ckParams);
            return Decrypt(mechanism, keyHandle, ciphertextAndTag);
        }
        finally
        {
            if (ckParams.pIv != IntPtr.Zero) UnmanagedMemory.Free(ref ckParams.pIv);
            if (ckParams.pAAD != IntPtr.Zero) UnmanagedMemory.Free(ref ckParams.pAAD);
        }
    }

    /// <summary>
    /// Decrypts ciphertext+tag produced by <see cref="EncryptChaCha20Poly1305"/>.
    /// </summary>
    public byte[] DecryptChaCha20Poly1305(
        ObjectHandle keyHandle,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertextAndTag,
        ReadOnlySpan<byte> aad = default)
    {
        if (nonce.Length != 12)
            throw new ArgumentException("ChaCha20-Poly1305 nonce must be exactly 12 bytes (96 bits).", nameof(nonce));

        var ckParams = new CK_SALSA20_CHACHA20_POLY1305_PARAMS
        {
            pNonce = UnmanagedMemory.Allocate(nonce.Length),
            ulNonceLen = (NativeCULong)nonce.Length,
            pAAD = aad.Length > 0 ? UnmanagedMemory.Allocate(aad.Length) : IntPtr.Zero,
            ulAADLen = (NativeCULong)aad.Length,
        };
        try
        {
            UnmanagedMemory.Write(ckParams.pNonce, nonce);
            if (aad.Length > 0)
                UnmanagedMemory.Write(ckParams.pAAD, aad);

            using var mechanism = new Mechanism(CKM.CKM_CHACHA20_POLY1305, ckParams);
            return Decrypt(mechanism, keyHandle, ciphertextAndTag);
        }
        finally
        {
            if (ckParams.pNonce != IntPtr.Zero) UnmanagedMemory.Free(ref ckParams.pNonce);
            if (ckParams.pAAD != IntPtr.Zero) UnmanagedMemory.Free(ref ckParams.pAAD);
        }
    }

    /// <summary>
    /// Decrypts ciphertext produced by <see cref="EncryptRsaOaep"/> using RSA-OAEP with
    /// SHA-256 and MGF1+SHA-256.
    /// </summary>
    public byte[] DecryptRsaOaep(ObjectHandle keyHandle, ReadOnlySpan<byte> ciphertext)
    {
        var ckParams = new CK_RSA_PKCS_OAEP_PARAMS
        {
            hashAlg = CKM.CKM_SHA256.ToCULong(),
            mgf = CKG.CKG_MGF1_SHA256.ToCULong(),
            source = (NativeCULong)1,
            pSourceData = IntPtr.Zero,
            ulSourceDataLen = (NativeCULong)0,
        };
        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_OAEP, ckParams);
        return Decrypt(mechanism, keyHandle, ciphertext);
    }

    // === Legacy named shortcuts (gated, compile-time warning) ==============

    /// <summary>
    /// Decrypts ciphertext that was encrypted with RSA PKCS#1 v1.5 padding.
    /// **Use <see cref="DecryptRsaOaep"/> instead.** This method exists for compatibility;
    /// it throws <see cref="InsecureOperationException"/> at runtime unless
    /// <see cref="AllowInsecure"/> is set on the session.
    /// </summary>
    [Obsolete("RSA PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks. Use DecryptRsaOaep instead. " +
              "If you must use it, set Session.AllowInsecure = true.")]
    public byte[] DecryptRsaPkcs1V15(ObjectHandle keyHandle, ReadOnlySpan<byte> ciphertext)
    {
        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS);
        return Decrypt(mechanism, keyHandle, ciphertext);
    }
```

- [ ] **Step 4: Build and test**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln 2>&1 | tail -5
```

Expected: 0 errors, all tests still pass. No new tests yet — the secure helpers are just additions.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Encrypt.cs src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Decrypt.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "feat(Session): secure-default encrypt/decrypt helpers + [Obsolete] PKCS#1 v1.5

Secure helpers (recommended public surface):
- Encrypt/DecryptAesGcm (96-bit IV, 128-bit tag, optional AAD)
- Encrypt/DecryptChaCha20Poly1305 (96-bit nonce, optional AAD)
- Encrypt/DecryptRsaOaep (SHA-256 + MGF1+SHA-256)

Each builds the appropriate mechanism params struct on the unmanaged
heap, delegates to the generic Encrypt/Decrypt path (which already
guards against insecure mechanisms via GuardMechanism), and cleans
up unmanaged buffers in a finally block.

Legacy named shortcuts with [Obsolete]:
- EncryptRsaPkcs1V15 / DecryptRsaPkcs1V15 — point at the OAEP
  alternative; throw via the runtime gate unless AllowInsecure=true.

The generic Encrypt(Mechanism, ObjectHandle, ...) remains for vendor /
advanced mechanisms that don't have a named helper."
```

---

## Task 9: Encrypt round-trip tests

TDD-style: write tests first, watch them fail or pass, fix as needed. Tests are backend-parameterized — each test class has Mock and SoftHsm concrete variants.

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Encrypt/EncryptAesGcmTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Encrypt/EncryptAesTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Encrypt/EncryptChaChaTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Encrypt/EncryptRsaTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/TestKeys.cs` (helper for generating ephemeral session keys)

- [ ] **Step 1: Write `TestKeys.cs` helper**

Each test needs an ephemeral AES, ChaCha20, or RSA key. Creating these via `Session.GenerateKey` is a Phase 4 concern; for Phase 1 we use `Session.CreateObject` with raw key material as session objects (CKA_TOKEN=false).

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/TestKeys.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

/// <summary>
/// Helpers for creating ephemeral session-only test keys without depending on
/// Session.GenerateKey* (Phase 4 territory). Each helper returns an
/// ObjectHandle; the caller is responsible for destroying it when done.
/// </summary>
internal static class TestKeys
{
    /// <summary>Creates a session-only AES-256 secret key from <paramref name="rawKey"/> (32 bytes).</summary>
    public static ObjectHandle CreateAes256Key(Session session, byte[] rawKey)
    {
        if (rawKey.Length != 32) throw new ArgumentException("AES-256 key must be 32 bytes.", nameof(rawKey));

        using var attrClass        = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrKeyType      = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var attrToken        = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrEncrypt      = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var attrDecrypt      = new ObjectAttribute(CKA.CKA_DECRYPT, true);
        using var attrValue        = new ObjectAttribute(CKA.CKA_VALUE, rawKey);

        var template = new List<ObjectAttribute> { attrClass, attrKeyType, attrToken, attrEncrypt, attrDecrypt, attrValue };
        return session.CreateObject(template);
    }

    /// <summary>Creates a session-only ChaCha20 secret key from <paramref name="rawKey"/> (32 bytes).</summary>
    public static ObjectHandle CreateChaCha20Key(Session session, byte[] rawKey)
    {
        if (rawKey.Length != 32) throw new ArgumentException("ChaCha20 key must be 32 bytes.", nameof(rawKey));

        using var attrClass        = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrKeyType      = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_CHACHA20);
        using var attrToken        = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrEncrypt      = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var attrDecrypt      = new ObjectAttribute(CKA.CKA_DECRYPT, true);
        using var attrValue        = new ObjectAttribute(CKA.CKA_VALUE, rawKey);

        var template = new List<ObjectAttribute> { attrClass, attrKeyType, attrToken, attrEncrypt, attrDecrypt, attrValue };
        return session.CreateObject(template);
    }
}
```

(`Session.CreateObject(List<ObjectAttribute>)` should already exist as part of the upstream-ported object-management surface. If its signature differs — e.g., takes `ObjectAttribute[]` — adapt.)

- [ ] **Step 2: Write the EncryptAesGcmTests**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Encrypt/EncryptAesGcmTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Encrypt;

public abstract class EncryptAesGcmTests
{
    private readonly IPkcs11Backend _backend;
    protected EncryptAesGcmTests(IPkcs11Backend backend) { _backend = backend; }

    [SkippableFact]
    public void EncryptAesGcm_RoundTripsKnownPlaintext()
    {
        byte[] rawKey = new byte[32]; for (int i = 0; i < 32; i++) rawKey[i] = (byte)i;
        byte[] iv = new byte[12];     for (int i = 0; i < 12; i++) iv[i] = (byte)(0xA0 + i);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("hello, AEAD world");

        using var session = _backend.Library.GetSlotList(SlotsType.WithTokenPresent)
            .First(s => (KerckhoffsLabs.Runtime.InteropServices.NativeCULong)s.SlotId == _backend.SlotId)
            .OpenSession(SessionType.ReadWrite);
        session.Login(CKU.CKU_USER, _backend.UserPin);

        var keyHandle = TestKeys.CreateAes256Key(session, rawKey);
        try
        {
            byte[] ciphertext = session.EncryptAesGcm(keyHandle, iv, plaintext, aad: ReadOnlySpan<byte>.Empty);
            Assert.Equal(plaintext.Length + 16, ciphertext.Length); // includes 16-byte tag

            byte[] roundtrip = session.DecryptAesGcm(keyHandle, iv, ciphertext, aad: ReadOnlySpan<byte>.Empty);
            Assert.Equal(plaintext, roundtrip);
        }
        finally
        {
            session.DestroyObject(keyHandle);
            session.Logout();
        }
    }

    [SkippableFact]
    public void EncryptAesGcm_WithAad_RoundTrips()
    {
        byte[] rawKey = new byte[32]; for (int i = 0; i < 32; i++) rawKey[i] = (byte)i;
        byte[] iv = new byte[12];
        byte[] plaintext = new byte[100];
        byte[] aad = System.Text.Encoding.UTF8.GetBytes("v1-public-header");

        using var session = OpenLoggedInSession();
        var keyHandle = TestKeys.CreateAes256Key(session, rawKey);
        try
        {
            byte[] ciphertext = session.EncryptAesGcm(keyHandle, iv, plaintext, aad);
            byte[] roundtrip = session.DecryptAesGcm(keyHandle, iv, ciphertext, aad);
            Assert.Equal(plaintext, roundtrip);
        }
        finally
        {
            session.DestroyObject(keyHandle);
            session.Logout();
        }
    }

    [SkippableFact]
    public void EncryptAesGcm_RejectsWrongIvLength()
    {
        using var session = OpenLoggedInSession();
        var keyHandle = TestKeys.CreateAes256Key(session, new byte[32]);
        try
        {
            Assert.Throws<ArgumentException>(() =>
                session.EncryptAesGcm(keyHandle, new byte[8], new byte[16]));
        }
        finally
        {
            session.DestroyObject(keyHandle);
            session.Logout();
        }
    }

    private Session OpenLoggedInSession()
    {
        var slot = _backend.Library.GetSlotList(SlotsType.WithTokenPresent)
            .First(s => (KerckhoffsLabs.Runtime.InteropServices.NativeCULong)s.SlotId == _backend.SlotId);
        var session = slot.OpenSession(SessionType.ReadWrite);
        session.Login(CKU.CKU_USER, _backend.UserPin);
        return session;
    }
}

[Collection("Mock")]
public sealed class EncryptAesGcmTests_Mock : EncryptAesGcmTests
{
    public EncryptAesGcmTests_Mock(MockBackendFixture f) : base(f) { }
}

[Collection("SoftHsm")]
public sealed class EncryptAesGcmTests_SoftHsm : EncryptAesGcmTests
{
    public EncryptAesGcmTests_SoftHsm(SoftHsmBackendFixture f) : base(f)
    {
        Skip.If(!SoftHsmBackendFixture.SoftHsmAvailable, "SoftHSM2 not installed.");
    }
}
```

(Many API specifics — `slot.OpenSession(SessionType.ReadWrite)`, `session.Login(CKU userType, byte[] pin)`, `session.DestroyObject(handle)` — should already exist; if they don't or have different signatures, surface that.)

- [ ] **Step 3: Run the AES-GCM tests**

```bash
dotnet test src/src.sln --filter "FullyQualifiedName~EncryptAesGcm" 2>&1 | tail -10
```

Expected: 3 tests × 2 backends = 6 results. On Mock, all pass. On SoftHsm: passes if SoftHSM2 is installed locally, skipped otherwise. If a test fails:
- The `pkcs11-mock` v2.0.0 may report success without actually encrypting (it's a mock — verify by asserting against ciphertext length only, not content). If the mock returns the plaintext unchanged, that's a known mock limitation; the round-trip property still holds.
- If SoftHSM2 fails, the mechanism may not be enabled in your SoftHSM build. Inspect `softhsm2-util --show-slots` output; CKM_AES_GCM should be in the supported list.

If a test fails for a non-environmental reason, that's a real bug in the helper or its mechanism-params plumbing — investigate.

- [ ] **Step 4: Add the remaining Encrypt test files**

Create three more test files following the same template:

`EncryptAesTests.cs` — AES-CBC and AES-CBC-PAD round-trips (the generic `Encrypt(mechanism, ...)` path, no helper). Demonstrates the legacy API still works and that AES-CBC isn't gated as insecure.

`EncryptChaChaTests.cs` — ChaCha20-Poly1305 round-trip via `EncryptChaCha20Poly1305`. Same shape as the AES-GCM test class.

`EncryptRsaTests.cs` — RSA-OAEP round-trip via `EncryptRsaOaep`. Needs an RSA key — generate one via `Session.GenerateKeyPair` if available, else import a 2048-bit RSA test key from a hardcoded PKCS#8 DER blob.

Use the same `[Collection("Mock")]` / `[Collection("SoftHsm")]` parameterization for each. If RSA key generation isn't available (Phase 4 work), use `Skip.If(!HasRsaSupport, "Phase 4 territory")` and document the dependency.

- [ ] **Step 5: Build and run**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln --filter "FullyQualifiedName~Encrypt" 2>&1 | tail -10
```

Expected: tests pass on Mock; SoftHsm tests pass when SoftHSM2 is installed.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Encrypt/ src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/TestKeys.cs
git -C /home/alexandre/dev/PKCS11.NET commit -m "test: Encrypt round-trip tests for AES-CBC, AES-GCM, ChaCha20-Poly1305, RSA-OAEP

Backend-parameterized via [Collection(\"Mock\")] / [Collection(\"SoftHsm\")];
each test class has two concrete subclasses. SoftHsm tests skip when
SoftHSM2 isn't installed locally; CI installs it.

TestKeys.cs is a helper for creating ephemeral session-only keys via
Session.CreateObject; replaces the Phase 4 GenerateKey path for now."
```

---

## Task 10: Decrypt round-trip + security-policy tests

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Decrypt/DecryptAesGcmTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Decrypt/DecryptAesTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Decrypt/DecryptChaChaTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Decrypt/DecryptRsaTests.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Security/InsecureOperationGateTests.cs`

- [ ] **Step 1: Write the Decrypt test files**

The Decrypt tests are dual of the Encrypt tests — Encrypt with one helper, Decrypt with the matching one, assert plaintext recovered. Most of the round-trip coverage is already in Task 9's Encrypt tests (each test there decrypts to verify). The dedicated Decrypt tests add:

- **Tag-tampering rejection** for AES-GCM: flip one byte in the tag, expect `Pkcs11Exception` with CKR_GENERAL_ERROR or CKR_FUNCTION_FAILED on Decrypt. On the mock this may pass silently; the SoftHSM variant catches real cryptographic failure.
- **Wrong-IV rejection** for AES-GCM: encrypt with one IV, decrypt with another → exception.
- **Truncated-ciphertext rejection**: pass a buffer < 16 bytes (no tag room) → `ArgumentException`.

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Decrypt/DecryptAesGcmTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Decrypt;

public abstract class DecryptAesGcmTests
{
    private readonly IPkcs11Backend _backend;
    protected DecryptAesGcmTests(IPkcs11Backend backend) { _backend = backend; }

    [SkippableFact]
    public void DecryptAesGcm_RejectsTooShortCiphertext()
    {
        using var session = OpenLoggedInSession();
        var keyHandle = TestKeys.CreateAes256Key(session, new byte[32]);
        try
        {
            Assert.Throws<ArgumentException>(() =>
                session.DecryptAesGcm(keyHandle, new byte[12], new byte[8]));
        }
        finally
        {
            session.DestroyObject(keyHandle);
            session.Logout();
        }
    }

    [SkippableFact(typeof(SoftHsmBackendFixture), nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void DecryptAesGcm_TamperedTag_OnSoftHsm_Throws()
    {
        // Skip on mock — pkcs11-mock doesn't actually verify the tag.
        Skip.If(_backend is MockBackendFixture, "pkcs11-mock does not authenticate AEAD tags.");

        byte[] rawKey = new byte[32]; for (int i = 0; i < 32; i++) rawKey[i] = (byte)i;
        byte[] iv = new byte[12];
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("must be authenticated");

        using var session = OpenLoggedInSession();
        var keyHandle = TestKeys.CreateAes256Key(session, rawKey);
        try
        {
            byte[] ciphertext = session.EncryptAesGcm(keyHandle, iv, plaintext);
            // Flip the last byte (part of the tag).
            ciphertext[^1] ^= 0xFF;

            Assert.Throws<Pkcs11Exception>(() => session.DecryptAesGcm(keyHandle, iv, ciphertext));
        }
        finally
        {
            session.DestroyObject(keyHandle);
            session.Logout();
        }
    }

    private Session OpenLoggedInSession()
    {
        var slot = _backend.Library.GetSlotList(SlotsType.WithTokenPresent)
            .First(s => (KerckhoffsLabs.Runtime.InteropServices.NativeCULong)s.SlotId == _backend.SlotId);
        var session = slot.OpenSession(SessionType.ReadWrite);
        session.Login(CKU.CKU_USER, _backend.UserPin);
        return session;
    }
}

[Collection("Mock")]
public sealed class DecryptAesGcmTests_Mock : DecryptAesGcmTests
{
    public DecryptAesGcmTests_Mock(MockBackendFixture f) : base(f) { }
}

[Collection("SoftHsm")]
public sealed class DecryptAesGcmTests_SoftHsm : DecryptAesGcmTests
{
    public DecryptAesGcmTests_SoftHsm(SoftHsmBackendFixture f) : base(f)
    {
        Skip.If(!SoftHsmBackendFixture.SoftHsmAvailable, "SoftHSM2 not installed.");
    }
}
```

(Replace `Pkcs11Exception` with whatever the library's CKR-mapping exception type is — likely `Pkcs11Exception` from `Common/`.)

Repeat the pattern for `DecryptAesTests.cs`, `DecryptChaChaTests.cs`, `DecryptRsaTests.cs` — focus on edge cases / failure modes rather than re-testing the happy path which Encrypt tests already cover.

- [ ] **Step 2: Write `InsecureOperationGateTests.cs`**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Security/InsecureOperationGateTests.cs`:

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Security;

public abstract class InsecureOperationGateTests
{
    private readonly IPkcs11Backend _backend;
    protected InsecureOperationGateTests(IPkcs11Backend backend) { _backend = backend; }

    [SkippableTheory]
    [InlineData((ulong)CKM.CKM_AES_ECB)]
    [InlineData((ulong)CKM.CKM_DES_CBC)]
    [InlineData((ulong)CKM.CKM_DES3_CBC)]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    public void Encrypt_WithInsecureMechanism_DefaultsToThrow(ulong mechanismId)
    {
        using var session = OpenLoggedInSession();
        try
        {
            // AllowInsecure left at default (false). Don't even need a real key —
            // the gate fires before the operation starts.
            using var mechanism = new Mechanism((CKM)mechanismId);
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.Encrypt(mechanism, new ObjectHandle(0), new byte[0]));
            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            session.Logout();
        }
    }

    [SkippableFact]
    public void Encrypt_WithInsecureMechanism_AllowInsecureBypassesGate()
    {
        using var session = OpenLoggedInSession();
        session.AllowInsecure = true;
        try
        {
            // With AllowInsecure=true the gate is bypassed. The call may still fail for a different
            // reason (no key, mechanism unsupported by backend, etc.) — but it must NOT throw
            // InsecureOperationException.
            using var mechanism = new Mechanism(CKM.CKM_AES_ECB);
            try
            {
                session.Encrypt(mechanism, new ObjectHandle(0), new byte[16]);
            }
            catch (InsecureOperationException)
            {
                Assert.Fail("AllowInsecure=true should have suppressed the gate.");
            }
            catch
            {
                // Any other exception is acceptable — we're only asserting the gate didn't fire.
            }
        }
        finally
        {
            session.Logout();
        }
    }

    private Session OpenLoggedInSession()
    {
        var slot = _backend.Library.GetSlotList(SlotsType.WithTokenPresent)
            .First(s => (KerckhoffsLabs.Runtime.InteropServices.NativeCULong)s.SlotId == _backend.SlotId);
        var session = slot.OpenSession(SessionType.ReadWrite);
        session.Login(CKU.CKU_USER, _backend.UserPin);
        return session;
    }
}

[Collection("Mock")]
public sealed class InsecureOperationGateTests_Mock : InsecureOperationGateTests
{
    public InsecureOperationGateTests_Mock(MockBackendFixture f) : base(f) { }
}

[Collection("SoftHsm")]
public sealed class InsecureOperationGateTests_SoftHsm : InsecureOperationGateTests
{
    public InsecureOperationGateTests_SoftHsm(SoftHsmBackendFixture f) : base(f)
    {
        Skip.If(!SoftHsmBackendFixture.SoftHsmAvailable, "SoftHSM2 not installed.");
    }
}
```

- [ ] **Step 3: Build and run**

```bash
dotnet build src/src.sln 2>&1 | tail -3
dotnet test src/src.sln --filter "FullyQualifiedName~Decrypt|FullyQualifiedName~Security" 2>&1 | tail -10
```

Expected: tests pass on Mock; tag-tampering test passes on SoftHsm only (mock-skipped); gate tests pass on both.

- [ ] **Step 4: Commit**

```bash
git -C /home/alexandre/dev/PKCS11.NET add src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Decrypt/ src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Security/
git -C /home/alexandre/dev/PKCS11.NET commit -m "test: Decrypt edge cases + InsecureOperationException gate tests

Decrypt tests focus on failure modes (tampered tag, too-short ciphertext)
that Encrypt's round-trip path doesn't cover. AES-GCM tag-tampering test
skips on pkcs11-mock since the mock doesn't authenticate.

Security gate tests verify that CKM_AES_ECB, CKM_DES_CBC, CKM_DES3_CBC,
and CKM_RSA_PKCS throw InsecureOperationException by default, and that
session.AllowInsecure=true suppresses the gate."
```

---

## Task 11: Final verification + tag

**Files:**
- (Verification only.)

- [ ] **Step 1: Final clean build**

```bash
cd /home/alexandre/dev/PKCS11.NET
dotnet clean src/src.sln >/dev/null
dotnet build src/src.sln --configuration Release 2>&1 | tail -5
```

Expected: `0 Error(s)`.

- [ ] **Step 2: Final full test run**

```bash
dotnet test src/src.sln --configuration Release --no-build 2>&1 | tail -15
```

Expected: All tests pass. Counts:
- 118 from `Runtime.InteropServices.Tests`
- 1 smoke test × 2 backends = 2 (or 1 on SoftHsm-unavailable hosts) from existing
- ~24 ObjectAttribute tests
- ~10 new Encrypt tests × 2 backends (some skip)
- ~6 new Decrypt tests × 2 backends (some skip)
- ~5 new security tests × 2 backends

Total expected: ~165–190 passing depending on backend availability.

- [ ] **Step 3: Verify pack still works**

```bash
dotnet pack src/KerckhoffsLabs.Security.Cryptography.Pkcs11/KerckhoffsLabs.Security.Cryptography.Pkcs11.csproj -c Release -p:SkipPkcs11MockBuild=true -o /tmp/pack-test 2>&1 | tail -5
ls /tmp/pack-test/
rm -rf /tmp/pack-test
```

Expected: nupkg + snupkg produced.

- [ ] **Step 4: Verify the exit-criteria invariants**

```bash
echo "=== Session is partial ==="
grep -c "public partial class Session" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs

echo "=== Session.Encrypt.cs exists ==="
ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Encrypt.cs

echo "=== Session.Decrypt.cs exists ==="
ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Decrypt.cs

echo "=== InsecureOperationException exists ==="
ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11/Common/InsecureOperationException.cs

echo "=== AllowInsecure property ==="
grep "public bool AllowInsecure" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.cs

echo "=== Secure helpers ==="
grep -cE "EncryptAesGcm|EncryptChaCha20Poly1305|EncryptRsaOaep" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Encrypt.cs
grep -cE "DecryptAesGcm|DecryptChaCha20Poly1305|DecryptRsaOaep" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Session.Decrypt.cs

echo "=== Test fixtures ==="
ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Fixtures/{IPkcs11Backend,MockBackendFixture,SoftHsmBackendFixture}.cs
```

Expected outputs (all on success path):
- `public partial class Session` count = 1.
- Both partial files exist.
- `InsecureOperationException.cs` exists.
- `public bool AllowInsecure` appears once.
- Secure helper greps return `>= 3` (each helper at least once).
- All three fixture files exist.

- [ ] **Step 5: Tag the milestone**

```bash
git -C /home/alexandre/dev/PKCS11.NET tag -a phase-1-complete -m "Phase 1 complete: Encrypt/Decrypt partial split + secure helpers + dual-backend tests"
```

---

## Phase 1 Exit Checklist

- [ ] `dotnet build src/src.sln -c Release` succeeds with 0 errors.
- [ ] `dotnet test src/src.sln` shows all tests passing (counts above).
- [ ] `Session.cs` is declared `public partial class Session`.
- [ ] `Session.Encrypt.cs` exists with the three existing Encrypt methods + Span overload + 3 secure helpers + `[Obsolete] EncryptRsaPkcs1V15`.
- [ ] `Session.Decrypt.cs` exists with the three existing Decrypt methods + Span overload + 3 secure helpers + `[Obsolete] DecryptRsaPkcs1V15`.
- [ ] `Common/InsecureOperationException.cs` exists.
- [ ] `Session.AllowInsecure { get; set; }` exists and defaults to false.
- [ ] `GuardMechanism(CKM)` is called from every Encrypt/Decrypt entry point.
- [ ] `IPkcs11Backend`, `MockBackendFixture`, `SoftHsmBackendFixture` all exist in `Fixtures/`.
- [ ] `SmokeTests` has both `_Mock` and `_SoftHsm` concrete parameterizations.
- [ ] CI workflow installs softhsm2 on Linux and (best-effort) Windows.
- [ ] Tag `phase-1-complete` exists.

When all checked, Phase 1 is complete. Phase 2 (Sign + Verify) can be planned next.
