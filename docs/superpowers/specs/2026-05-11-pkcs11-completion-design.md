# PKCS11.NET — Completion + Tests Design

**Date:** 2026-05-11
**Status:** Approved
**Scope:** Build + full polish pass (largest of the three scopes considered)

## Goal

Take the in-progress `KerckhoffsLabs.Security.Cryptography.Pkcs11` library — currently 128 C# files, ~10,700 lines, **931 build errors** — to a green-building, well-tested, NuGet-shippable PKCS#11 v3.1 interop library for .NET. Target: secure-by-default, modern .NET idioms, dual-backend test suite (pkcs11-mock + SoftHSM2).

## Non-goals

- Drop-in source compatibility with `Pkcs11Interop/Pkcs11Interop`. We are a rebrand; we may take breaking changes (e.g., insecure-op gating).
- Supporting PKCS#11 v2.20 or earlier ABIs. Single unified v3.1-aligned surface.
- Async I/O. PKCS#11 is synchronous; the library is sync-only. Callers may wrap themselves.
- Vendor-specific extensions (Luna, nCipher, etc.) beyond what the v3.1 spec covers.

## Solution layout

```
src/
├── src.sln
├── KerckhoffsLabs.Runtime.InteropServices/            # unchanged; defines NativeCULong
├── KerckhoffsLabs.Runtime.InteropServices.UnitTests/  # unchanged
│
├── KerckhoffsLabs.Security.Cryptography.Pkcs11/       # main library
│   ├── Common/                                        # CKA/CKM/CKR enums + exceptions
│   ├── Native/
│   │   ├── (CK_* structs, LowLevelPkcs11Library, Delegates)
│   │   └── MechanismParams/
│   ├── HighLevel/
│   │   ├── Session.cs                                 # facade + ctor/dispose
│   │   ├── Session.Encrypt.cs    Session.Decrypt.cs
│   │   ├── Session.Sign.cs       Session.Verify.cs
│   │   ├── Session.Digest.cs     Session.Random.cs
│   │   ├── Session.Objects.cs    Session.Keys.cs
│   │   ├── Session.Derive.cs     Session.MessageBased.cs
│   │   └── (Slot, Pkcs11Library, Mechanism, ObjectHandle, ObjectAttribute, *Info, *Flags)
│   ├── Security/                                      # SecurePin, SecureBuffer (zero-on-dispose)
│   └── Logging/                                       # unchanged
│
├── KerckhoffsLabs.Security.Cryptography.Pkcs11.Mock/  # NEW
│   └── C# wrappers for pkcs11-mock's diagnostic extension functions
│
└── KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/ # NEW (xUnit)
    ├── Native/
    ├── HighLevel/
    │   ├── Encrypt/  Decrypt/  Sign/  Verify/  Digest/  Random/
    │   ├── Objects/  Keys/  Derive/  MessageBased/
    │   ├── Lifecycle/  Errors/  Security/  Mechanisms/
    │   └── ThreadSafety/  MemoryLeaks/
    ├── Fixtures/                                      # IPkcs11Backend, MockBackendFixture, SoftHsmBackendFixture
    ├── Settings.cs                                    # env-driven config (PKCS11_TEST_*)
    └── runtimes/                                      # built pkcs11-mock binaries land here

third-party/
└── pkcs11-mock/                                       # git submodule (Apache 2.0)

build/
├── build-pkcs11-mock.sh
└── build-pkcs11-mock.ps1
```

## Public API policies

### Sync-only
No `*Async` overloads. PKCS#11 is inherently synchronous. Documented in README; consumers wrap with `Task.Run` if they need it.

### Buffer ergonomics — Span first

Public methods that accept a buffer take `ReadOnlySpan<byte>`. The corresponding `byte[]` overloads remain (a `byte[]` argument implicitly converts to `ReadOnlySpan<byte>`, so the additional overload is non-breaking and lets callers pass either). Methods that produce a buffer offer a `Span<byte>`-writing variant returning `int` (bytes written) alongside the convenience `byte[]`-returning form. The specific name varies by context — e.g., `ObjectAttribute.CopyValueTo(Span<byte>)` for typed reads; `Session.Encrypt(ReadOnlySpan<byte> input, Span<byte> output)` for in-place operations.

**`Span<byte>` is never exposed over unmanaged memory the library owns.** Outputs are either freshly allocated `byte[]` or copied into a caller-provided `Span<byte>`. This prevents the "span dangles after `Dispose`" footgun in classes like `ObjectAttribute` that own native buffers.

Applies to: `ObjectAttribute` constructors (Phase 0a), `CK_MECHANISM.CreateMechanism` (Phase 0a), `Session.Encrypt` / `Decrypt` / `Sign` / `Verify` / `Digest` / `GenerateRandom` / `GetOperationState` / `SetOperationState` (Phases 1–4).

### Secure defaults

Convenience helpers default to secure behavior:

- `GenerateAesKey`, `GenerateRsaKeyPair`, `GenerateEcKeyPair` set `CKA_SENSITIVE=true` and `CKA_EXTRACTABLE=false`.
- `EncryptAesGcm`, `EncryptChaCha20Poly1305`, `EncryptRsaOaep`, `SignRsaPss`, `SignEcdsa`, `SignEd25519`, `SignEd448` exist as named helpers; under the hood they construct the appropriate `Mechanism`.
- A generic `Digest(HashAlgorithmName)` rejects MD5/SHA-1 in signature contexts.

### Insecure-op gating

Insecure operations stay in the main namespace (no breaking namespace move), are marked `[Obsolete(IsError = false)]` with a message pointing to the modern alternative, and **throw `InsecureOperationException` at runtime unless the caller has set `session.AllowInsecure = true`** (per-session, default `false`).

Applies to:

- RSA PKCS#1 v1.5 encryption and signature
- DES, 3DES (except CKM_3DES_KEY_GEN when explicitly requested)
- MD5 and SHA-1 in signing/MAC contexts
- ECB modes for symmetric ciphers
- `GenerateKey*` overrides where `CKA_EXTRACTABLE=true` is explicitly requested

Example:

```csharp
[Obsolete("RSA PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks. " +
          "Use EncryptRsaOaep or set Session.AllowInsecure = true to bypass.")]
public byte[] EncryptRsaPkcs1V15(ObjectHandle key, byte[] data) { /* ... */ }
```

### Secure memory handling

- `SecurePin` — wraps PIN bytes, pins memory while in use, zeroes on `Dispose`, never logs.
- `SecureBuffer` — used internally for transient buffers holding key material; zeroed on `Dispose`.
- Login methods accept either `SecurePin` (preferred) or `byte[]`. The `byte[]` overload is marked `[Obsolete(IsError = false)]` with a message recommending `SecurePin`. No runtime block — this is a soft migration, not an insecure-op gate.

### Handle types

- `Pkcs11Library` (top-level) → `IDisposable`; owns `LowLevelPkcs11Library` and `C_Initialize` lifecycle.
- `Slot` → value type / lightweight wrapper.
- `Session` → `IDisposable`; owns the session handle.
- `ObjectHandle` → strong type wrapping the raw `NativeCULong`; not disposable (objects outlive sessions).

`SafeHandle`-derived implementations adopted where missing — guards against native leaks on abnormal teardown.

## Test architecture

### Backend abstraction

```csharp
public interface IPkcs11Backend {
    string LibraryPath { get; }
    byte[] SoUserPin { get; }
    byte[] UserPin   { get; }
    NativeCULong SlotId { get; }
    string TokenLabel { get; }
    Pkcs11Library Library { get; }
}
```

Two fixtures:

| Fixture | Source | Availability |
|---|---|---|
| `MockBackendFixture` | `pkcs11-mock.{so,dll,dylib}` built from the vendored submodule. | Always — built in CI and locally via MSBuild target. |
| `SoftHsmBackendFixture` | `libsofthsm2` from system path or `PKCS11_SOFTHSM_LIBRARY` env var. Token initialized into a per-fixture temp directory via `softhsm2-util --init-token`. | Skipped with `[SkippableFact]` when SoftHSM2 isn't installed. |

Tests inherit from a backend-parameterized base class:

```csharp
public abstract class EncryptTests {
    protected readonly IPkcs11Backend Backend;
    protected EncryptTests(IPkcs11Backend b) { Backend = b; }

    [SkippableFact]
    public void Encrypt_AesGcm_RoundTripsKnownPlaintext() { /* ... */ }
}

[Collection("Mock")]    public class EncryptTests_Mock    : EncryptTests { public EncryptTests_Mock(MockBackendFixture f) : base(f) { } }
[Collection("SoftHsm")] public class EncryptTests_SoftHsm : EncryptTests { public EncryptTests_SoftHsm(SoftHsmBackendFixture f) : base(f) { } }
```

### Test categories

| Category | Path | Backend(s) | Asserts |
|---|---|---|---|
| Native marshalling | `Pkcs11.Tests/Native/` | Mock only | Managed `sizeof(T)` vs native `sizeof(CK_T)` via mock's diagnostic helpers. Attribute-array layout. |
| High-level functional | `Pkcs11.Tests/HighLevel/<Group>/` | Both | Per-partial round-trip semantics. One file per `Session.<Group>.cs`. |
| Error mapping | `Pkcs11.Tests/HighLevel/Errors/` | Mock only | Mock injects `CKR_*` codes; assertions map them to specific exceptions. |
| Lifecycle | `Pkcs11.Tests/HighLevel/Lifecycle/` | Both | Double-`Dispose`, post-dispose `ObjectDisposedException`, finalizer safety, PIN zeroing, session-pool reuse if implemented. |
| Security policy | `Pkcs11.Tests/HighLevel/Security/` | Mock | `[Obsolete]` insecure ops throw `InsecureOperationException` unless `AllowInsecure=true`. Secure helpers passed a deprecated mechanism throw the same `InsecureOperationException` (consistent gate). |
| Mechanism matrix | `Pkcs11.Tests/HighLevel/Mechanisms/` | Both | `[Theory]` over (mechanism × key type × key size). |
| Memory leaks | `Pkcs11.Tests/HighLevel/MemoryLeaks/` | Mock | After N operations + `Dispose`, mock's allocation counter is back to baseline. |
| Thread safety | `Pkcs11.Tests/HighLevel/ThreadSafety/` | Mock | Concurrent use of a *single* session surfaces a deterministic exception. *Different* sessions on different threads work in parallel. |

### Isolation

Library-level `C_Initialize` is per-collection (xUnit `IClassFixture` on the fixture, `[Collection]` on each test class). The mock and SoftHSM collections run independently — different DLLs, different state — and can parallelize.

## Phasing

Each phase ends with a green build + green tests + a reviewable PR.

| Phase | Lands | Tests added |
|---|---|---|
| **0. Build + scaffolding** | Project reference, missing `using`s, `Pkcs11.Tests` + `Pkcs11.Mock` projects, `pkcs11-mock` submodule, `build/build-pkcs11-mock.{sh,ps1}`, `.github/workflows/ci.yml`, packaging metadata, `net8.0;net9.0` multi-target, MIT `LICENSE`. | One smoke test: load mock, `C_Initialize`, `C_GetInfo`, `C_Finalize`. |
| **1. Encrypt + Decrypt** | `Session.Encrypt.cs`, `Session.Decrypt.cs` partials. v3.1 message-based: `C_EncryptMessage*`, `C_DecryptMessage*`. Secure helpers: `EncryptAesGcm`, `DecryptAesGcm`, `EncryptChaCha20Poly1305`, `EncryptRsaOaep`. `[Obsolete]` on `EncryptRsaPkcs1V15`. | Functional + lifecycle + security policy + parameterized matrix for Encrypt/Decrypt. Both backends. |
| **2. Sign + Verify** | `Session.Sign.cs`, `Session.Verify.cs`. `C_SignMessage*`, `C_VerifyMessage*`. Secure helpers: `SignRsaPss`, `SignEcdsa`, `SignEd25519`, `SignEd448`. `[Obsolete]` on `SignRsaPkcs1V15`, MD5/SHA-1 signing. | Same shape as Phase 1. |
| **3. Digest + Random** | `Session.Digest.cs`, `Session.Random.cs`. Hash helper that rejects MD5/SHA-1 in signature contexts. | Functional + hash-matrix tests. |
| **4. Objects + Keys + KDF + MessageBased** | `Session.Objects.cs`, `Session.Keys.cs`, `Session.Derive.cs`, `Session.MessageBased.cs`. `C_SessionCancel`. SP800-108 KDF mechanisms. Secure helpers: `GenerateAesKey`, `GenerateRsaKeyPair`, `GenerateEcKeyPair`, `DeriveSharedSecretEcdh`. `SecurePin` + `SecureBuffer` adopted on login + key-material paths. `SafeHandle` adopted where missing. | Memory-leak suite, thread-safety suite, parameterized mechanism matrix. |
| **5. Packaging + docs** | README.md, CHANGELOG.md, `examples/`, NuGet publish job (tag-gated). | Pack succeeds; `.nupkg` smoke-test consumer project in CI. |

Phases 1–4 are independent enough to be reordered if needed, but recommended order is listed — Phase 1 establishes the partial-split, parameterized-test, and secure-helper patterns that 2–4 copy.

## CI

`.github/workflows/ci.yml`:

```yaml
jobs:
  build-and-test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    steps:
      - actions/checkout@v4 (with submodules: recursive)
      - actions/setup-dotnet@v4 (9.0.x)
      - run: bash build/build-pkcs11-mock.sh         # or .ps1 on Windows
      - run: install SoftHSM2 (apt on Linux, choco on Windows; non-fatal)
      - run: dotnet build src/src.sln -c Release
      - run: dotnet test  src/src.sln -c Release --logger trx --collect:"XPlat Code Coverage"
      - codecov upload (gated on token)

  pack:
    needs: build-and-test
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && (github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v'))
    steps:
      - dotnet pack KerckhoffsLabs.Security.Cryptography.Pkcs11
      - publish to NuGet on tag (requires NUGET_API_KEY secret)
      - upload .nupkg as artifact on main pushes
```

The mock build script lands the binary at
`src/.../Pkcs11.Tests/bin/$(Configuration)/$(TargetFramework)/runtimes/$(Rid)/native/pkcs11-mock.{so,dll,dylib}`
so the test runner can load it via `NativeLibrary.Load("pkcs11-mock")`.

## Packaging

`<Authors>` and `<RepositoryUrl>` below are placeholders filled in during Phase 0 once the GitHub repo URL and author/org identity are decided.

```xml
<PropertyGroup>
  <PackageId>KerckhoffsLabs.Security.Cryptography.Pkcs11</PackageId>
  <Version>0.1.0</Version>
  <Description>Modern, secure-by-default PKCS#11 v3.1 interop for .NET.</Description>
  <PackageLicenseExpression>MIT</PackageLicenseExpression>
  <PackageReadmeFile>README.md</PackageReadmeFile>
  <RepositoryUrl>...</RepositoryUrl>
  <PublishRepositoryUrl>true</PublishRepositoryUrl>
  <EmbedUntrackedSources>true</EmbedUntrackedSources>
  <ContinuousIntegrationBuild Condition="'$(CI)' == 'true'">true</ContinuousIntegrationBuild>
  <Deterministic>true</Deterministic>
  <GenerateDocumentationFile>true</GenerateDocumentationFile>
  <IncludeSymbols>true</IncludeSymbols>
  <SymbolPackageFormat>snupkg</SymbolPackageFormat>
  <TargetFrameworks>net8.0;net9.0</TargetFrameworks>
</PropertyGroup>
<ItemGroup>
  <PackageReference Include="Microsoft.SourceLink.GitHub" Version="*" PrivateAssets="all" />
</ItemGroup>
```

License: MIT (root `LICENSE` file).
Versioning: semver from `0.1.0`. Pre-1.0 means we reserve the right to break the API between minors.

## Risks and mitigations

1. **SoftHSM2 install flakiness (Windows chocolatey).** Per-test `[SkippableFact]`. Suite still passes on mock-only. Separate CI warning (non-fatal) when SoftHSM tests were skipped.
2. **pkcs11-mock ABI drift.** Submodule pinned to a specific SHA. Bumps are deliberate PRs.
3. **`Session.cs` partial-class split.** Mitigation: one group at a time, full suite green between groups.
4. **`[Obsolete]` + runtime-gate is a behavior change vs. Pkcs11Interop.** Clear message, `AllowInsecure` escape hatch, CHANGELOG entry.
5. **`net8.0` multi-target.** Accidental `net9.0`-only API use. Mitigation: CI builds both TFMs.
6. **Native-memory leaks.** Phase 4 memory-leak suite + `SafeHandle` adoption.

## Exit criteria

- `dotnet build` clean on Linux + Windows, both TFMs (`net8.0` + `net9.0`), 0 errors, 0 warnings.
- All tests pass under both mock and SoftHSM2 fixtures on Linux; Windows runs at minimum the mock collection.
- ≥80% line coverage on `HighLevel/`.
- Memory-leak suite: zero unfreed native allocations after each workload + `Dispose`.
- Thread-safety suite: documented invariants hold.
- `dotnet pack` produces a valid `.nupkg` with SourceLink + symbols. CI smoke-test project consumes the package and passes.
- README has a "Getting started" sample that compiles against the produced package.
