# PKCS11.NET BCL-Aligned Redesign

**Status:** Design — pending implementation plan
**Date:** 2026-05-13
**Supersedes / extends:** `2026-05-11-utility-class-redesign-design.md`

---

## Goal

Restructure `src/KerckhoffsLabs.Security.Cryptography.Pkcs11` so that:

1. The C1 layering violation is removed: high-level types no longer depend transitively on raw P/Invoke surface, and the public API can be reasoned about without reading `Native/`.
2. The public surface follows `System.Security.Cryptography` BCL conventions, so a .NET developer familiar with `RSACng` / `ECDsaCng` / `AesGcm` can use PKCS#11-backed equivalents with minimal mental remapping.
3. Power users retain full PKCS#11 mechanism-level access for mechanisms with no BCL counterpart (CKM_TLS12_KDF, BLAKE2, GOST, vendor-defined).
4. Internals are testable without a native PKCS#11 library through an in-process fake.
5. Error reporting maps PKCS#11 return codes to typed, catchable exception subclasses by category, not a single stringly-typed `Pkcs11Exception`.
6. Object-template construction is fluent and discoverable, not a verbose `List<ObjectAttribute>`.

## Non-goals

- This is **not** a rewrite of `Native/` or `Common/`. Marshalling and enum surface are mature and stay as-is structurally; only the `Native/MechanismParams/` folder is renamed.
- Async APIs are out of scope. PKCS#11 is synchronous; we mirror that.
- Multi-target changes are out of scope — `net8.0;net9.0` stays.
- This spec does not enumerate every BCL provider method; per-algorithm method coverage is scoped in the implementation plan.

---

## Background

Today's high-level surface lives in `HighLevel/Session.*.cs` — a partial class with one file per operation category (`Session.Sign.cs`, `Session.Encrypt.cs`, etc.) that grew algorithm-specific helpers (`SignRsaPss`, `EncryptAesGcm`, `EncryptRsaOaep`, `DecryptChaCha20Poly1305`, …) alongside mechanism-generic ones (`Sign(Mechanism, ...)`, `Encrypt(Mechanism, ...)`). Three problems:

- **C1 layering:** `Session` is the public entry point but its file fan-out and the operations it hosts pull in `Native/` types directly (handles, raw mechanism params), making the boundary between safe wrapper and unmanaged plumbing porous.
- **Discoverability:** A developer who knows `RSACng.SignData` has no way to discover that the PKCS#11 equivalent is `session.SignRsaPss(handle, ...)`. The API requires reading the library, not pattern-matching from BCL knowledge.
- **Mock seam:** Tests today need either pkcs11-mock or SoftHSM to exercise any meaningful surface. Managed-only logic (template construction, error mapping, argument validation) can't be unit-tested without a native library.

The redesign keeps the parts that work (mechanism-generic `Sign`/`Encrypt`/etc., the strongly-typed enum surface, `SecurePin`) and reshapes the rest.

---

## Architecture decisions

### 1. Coexist: BCL provider types + mechanism-level surface

The public surface presents two complementary entry points:

- **BCL-aligned providers** (`RSAPkcs11`, `ECDsaPkcs11`, `AesGcmPkcs11`, …) — subclass or wrap their `System.Security.Cryptography` counterpart and present the BCL API shape. Internally they translate calls to PKCS#11 mechanisms.
- **Mechanism-level escape hatch** on `Pkcs11Key` and `Pkcs11Workspace` — `Sign(Mechanism, data)`, `Encrypt(Mechanism, data)`, etc. Used when the operation is a PKCS#11 mechanism with no BCL counterpart, or when the caller wants explicit control of mechanism params.

Algorithm-specific helpers on the session (`SignRsaPss`, `EncryptAesGcm`, etc.) are removed. Their behaviour is reachable two ways:

- Through the BCL provider (`new RSAPkcs11(key).SignData(...)`).
- Through the mechanism-level surface (`key.Sign(Mechanism.RsaPkcsPss(...), data)`).

### 2. Naming convention: `AlgorithmPkcs11`

Public BCL-aligned types use the suffix `Pkcs11`, matching the BCL pattern (`RSACng`, `RSACryptoServiceProvider`, `ECDsaOpenSsl`).

Concrete names:

| BCL base | PKCS#11 provider | Subclass / wrapper |
|---|---|---|
| `RSA` | `RSAPkcs11` | subclass |
| `ECDsa` | `ECDsaPkcs11` | subclass |
| `ECDiffieHellman` | `ECDiffieHellmanPkcs11` | subclass |
| `Aes` | `AesPkcs11` | subclass (CBC/CTR/ECB) |
| `AesGcm` | `AesGcmPkcs11` | wrapper (`AesGcm` is sealed) |
| `AesCcm` | `AesCcmPkcs11` | wrapper (`AesCcm` is sealed) |
| `ChaCha20Poly1305` | `ChaCha20Poly1305Pkcs11` | wrapper (sealed) |
| `HMAC` | `HMACPkcs11` | subclass |

Wrappers expose the same method shapes as the sealed BCL base type but do not inherit. This is the same compromise the BCL itself uses when wrapping platform-specific primitives.

### 3. Asymmetric keys: one `Pkcs11Key` covers both halves

PKCS#11 stores asymmetric private and public keys as two separate objects. We do **not** model this as a separate `Pkcs11KeyPair` type. A single `Pkcs11Key` covers all cases:

| What the lookup finds | What `Pkcs11Key` carries |
|---|---|
| Symmetric / secret key | one handle |
| Asymmetric private + public both stored | both handles |
| Asymmetric private only (no `CKO_PUBLIC_KEY`) | private handle + synthesized public view |
| Asymmetric public only | one (public) handle |

**Public-key synthesis.** When `OpenKey` finds an asymmetric private key but no matching `CKO_PUBLIC_KEY` object via `CKA_ID`, the library synthesizes the public-key view from attributes on the private key object:

- **RSA:** read `CKA_MODULUS` + `CKA_PUBLIC_EXPONENT` from the private key. PKCS#11 v3.1 requires these on `CKO_PRIVATE_KEY` for RSA, so synthesis always succeeds.
- **EC / EdDSA:** read `CKA_EC_POINT` + `CKA_EC_PARAMS` from the private key. `CKA_EC_POINT` is optional on `CKO_PRIVATE_KEY` per the spec; when absent, public-key operations on this `Pkcs11Key` throw `Pkcs11ObjectException` at invocation time.

The synthesized public view is **not** backed by a `CK_OBJECT_HANDLE` — public-key operations on it cannot delegate to PKCS#11 mechanisms on the token (no `C_Verify` against a non-existent handle). Operations that conceptually need only public material (`Verify`, `RSAParameters` export of public components) are computed in managed code via `RSA.Create().ImportParameters(...)` / `ECDsa.Create().ImportParameters(...)`. This is consistent with how `RSACng` exposes the public surface on a private-key-only Cng key.

Lookup behavior in `Pkcs11Workspace.OpenKey(label)` / `.OpenKey(id)`:

1. Search for any object matching the label/id.
2. If a private key is found, search on the same `CKA_ID` for a public companion. If found, both handles are attached. If not, attempt public-key synthesis from the private key's attributes; on success, attach the synthesized public view. On synthesis failure (EC private key without `CKA_EC_POINT`), the `Pkcs11Key` carries only the private handle.
3. If only a public key is found, return a `Pkcs11Key` carrying just the public handle. Sign / decrypt operations throw `Pkcs11ObjectException` when invoked.
4. If nothing is found, throw `Pkcs11ObjectException` (`CKR_OBJECT_HANDLE_INVALID`).

`Pkcs11Key` does not expose `HasPrivateKey` / `HasPublicKey` introspection properties. BCL convention is to call the operation and let it throw if the required key material is not available — `Sign` / `Decrypt` on a public-only key throws `Pkcs11ObjectException`, `Verify` on an EC private key without `CKA_EC_POINT` (and no `CKO_PUBLIC_KEY` companion) throws `Pkcs11ObjectException`. Callers that genuinely need to inspect the key's class can do so via the underlying PKCS#11 attributes through the mechanism-level surface, but the common path is "call it and catch."

There is no separate `GenerateKeyPair` method. `GenerateKey` is overloaded by template arity: one template dispatches to `C_GenerateKey` (symmetric), two templates dispatch to `C_GenerateKeyPair` (asymmetric). The asymmetric overload returns a single `Pkcs11Key` with both handles attached — no tuple return, no out-param, no `Pkcs11KeyPair` value type.

### 4. `Pkcs11Key` — CngKey-inspired key wrapper, hides session

The public abstraction for a key handle is `Pkcs11Key`, modeled on `System.Security.Cryptography.CngKey`:

- Carries hidden `Pkcs11Session` + `ObjectHandle` + cached metadata (algorithm, key type, usage flags).
- Public surface: identifying properties (`Algorithm`, `KeyType`, `Label`, `Id`), mechanism-level ops (`Sign`/`Verify`/`Encrypt`/`Decrypt`/`Wrap`/`Unwrap`/`Derive`), `Dispose()`.
- Factory entry points: `Pkcs11Key.Open(...)` (one-shot — opens a workspace internally, owns its lifetime) and `Pkcs11Workspace.OpenKey(...)` (caller owns the workspace).
- Disposing a `Pkcs11Key` releases its session reference; if the key owns the workspace, it disposes the workspace too.

`CngKey` is private in its construction (no public ctor — factory methods only). `Pkcs11Key` follows the same pattern.

### 5. Session management is internal

Today's `HighLevel/Session.cs` becomes `Internal/Pkcs11Session.cs`. It is no longer a public type. The public auth context is `Pkcs11Workspace`:

- Constructed via `Pkcs11Library.OpenWorkspace(slot, userType, pin)` — login happens at construction.
- `IDisposable` — disposal closes the session and logs out.
- Hosts:
  - **Key factory:** `OpenKey(...)`, `GenerateKey(...)` (both symmetric one-template and asymmetric two-template overloads), `ImportKey(...)`, `FindKeys(...)`.
  - **Non-key-bound ops:** `GenerateRandom`, `SeedRandom`, `DigestInit`/`Digest` (digest takes data, not a key).
  - **Multi-key ops:** `Pkcs11Key.WrapWith(otherKey)` / `Workspace.Wrap(wrappingKey, targetKey, mechanism)` — exposed at the workspace level when an operation involves more than one key and neither is the obvious "owner".

This mirrors `CngKey` (key wrapper, hides handle) vs. `CngProvider` (auth/provider context). `Pkcs11Workspace` plays the `CngProvider`-equivalent role.

### 6. Direct mechanism access is preserved

Not every PKCS#11 mechanism has a BCL counterpart (CKM_TLS12_KDF, CKM_BLAKE2*, GOST mechanisms, vendor-defined mechanisms with custom params). For these, the user reaches for the mechanism-level API directly:

```csharp
using var key = workspace.OpenKey(label: "kdf-secret");
byte[] derived = key.Derive(Mechanism.Tls12KdfMaster(...), keyTemplate);
```

Mechanism construction has two flavors:

- **Factory methods** for well-known mechanisms with typed params (`Mechanism.RsaOaep(...)`, `Mechanism.AesGcm(iv, aad, tagBits)`, `Mechanism.EcdhDerive(...)`).
- **Raw constructor** for vendor or rare mechanisms — takes a `CKM` value and an optional `ReadOnlySpan<byte>` of marshalled params. Power-user surface.

### 7. `ObjectHandle` becomes internal

Once `Pkcs11Key` is the public abstraction for an object handle, callers no longer construct or carry `ObjectHandle` values. It becomes an internal implementation detail in `Internal/`. The `readonly record struct` shape stays.

### 8. Mock seam: `IPkcs11Library`

A new internal interface `IPkcs11Library` exposes the surface that high-level types call (slot enumeration, session open/close, mechanism dispatch, attribute get/set, object lifecycle). `Native.LowLevelPkcs11Library` implements it. Tests can substitute `FakePkcs11Library` — an in-process implementation with no native dependency — for managed-only paths (template construction, exception mapping, argument validation, key metadata caching).

This **does not** replace the existing pkcs11-mock / SoftHSM integration tests. It complements them: fakes for fast managed-code coverage, real backends for marshalling and crypto correctness.

### 9. Fluent object template builder

Today's templates are constructed as `List<ObjectAttribute>` or `ObjectAttribute[]` literals. The redesign introduces a fluent builder:

```csharp
// Today
var template = new List<ObjectAttribute>
{
    new(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
    new(CKA.CKA_KEY_TYPE, CKK.CKK_AES),
    new(CKA.CKA_TOKEN, true),
    new(CKA.CKA_SENSITIVE, true),
    new(CKA.CKA_EXTRACTABLE, false),
    new(CKA.CKA_LABEL, "my-key"),
};

// After
var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
    .OnToken()
    .Sensitive()
    .NonExtractable()
    .Label("my-key")
    .Build();
```

Builder factories:

- `ObjectTemplate.ForSecretKey(CKK)`
- `ObjectTemplate.ForPrivateKey(CKK)`
- `ObjectTemplate.ForPublicKey(CKK)`
- `ObjectTemplate.ForCertificate(CKC)`
- `ObjectTemplate.ForData()`
- `ObjectTemplate.Empty()` — raw escape hatch, no class set

Fluent methods are typed per object class where it matters (a `ForCertificate` builder does not expose `.Sensitive()`). The terminal `.Build()` returns a frozen `ObjectTemplate` value that the library can pass into low-level calls.

### 10. Centralized exception mapping with typed hierarchy

Today `Pkcs11Exception` is a single type carrying a CKR. The redesign:

- Keeps `Pkcs11Exception` as the abstract base (CKR + method name + message).
- Introduces typed subclasses by CKR category — catchable by category without string-matching on `Exception.Message`.
- Centralizes the `CKR → exception` mapping in `Internal/ExceptionMapper.cs`, called from one place: `Pkcs11Exception.ThrowIfError(CKR rv, string method)`.

Category mapping:

| Subclass | CKR values |
|---|---|
| `Pkcs11AuthenticationException` | `CKR_PIN_*`, `CKR_USER_*` |
| `Pkcs11SessionException` | `CKR_SESSION_*` |
| `Pkcs11TokenException` | `CKR_TOKEN_*`, `CKR_DEVICE_*` |
| `Pkcs11MechanismException` | `CKR_MECHANISM_*`, `CKR_KEY_FUNCTION_NOT_PERMITTED` |
| `Pkcs11ObjectException` | `CKR_OBJECT_*`, `CKR_ATTRIBUTE_*` |
| `Pkcs11ArgumentException` | `CKR_ARGUMENTS_BAD`, `CKR_DATA_INVALID`, `CKR_BUFFER_TOO_SMALL` |
| `Pkcs11Exception` (default) | anything not covered above |

Existing typed exceptions (`InsecureOperationException`, `InvalidEnumValueException`, `AttributeValueException`) remain unchanged — they're managed-validation exceptions, not CKR mappings.

Every native call site routes through `Pkcs11Exception.ThrowIfError(rv, methodName)`. No ad-hoc `throw new Pkcs11Exception(...)` outside the mapper.

---

## Folder layout — production code

```
src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
│
├── Pkcs11Library.cs                    PUBLIC. Loaded library, slot enumeration, IDisposable.
├── Pkcs11Slot.cs                       PUBLIC. Slot/token metadata, mechanism list.
├── Pkcs11Workspace.cs                  PUBLIC. Auth context, key factory, host for
│                                       non-key-bound + multi-key ops. IDisposable.
├── Pkcs11Key.cs                        PUBLIC. CngKey-style key wrapper. Mechanism
│                                       escape hatch (Sign/Verify/Encrypt/Decrypt/
│                                       Wrap/Unwrap/Derive) lives here.
├── Mechanism.cs                        PUBLIC. CKM + params, raw + factory ctors.
├── SecurePin.cs                        PUBLIC. Caller-facing PIN primitive.
│
├── RSAPkcs11.cs                        PUBLIC. : RSA, override on Pkcs11Key.
├── ECDsaPkcs11.cs                      PUBLIC. : ECDsa
├── ECDiffieHellmanPkcs11.cs            PUBLIC. : ECDiffieHellman
├── AesPkcs11.cs                        PUBLIC. : Aes (CBC/CTR/ECB)
├── AesGcmPkcs11.cs                     PUBLIC. AesGcm-shaped wrapper.
├── AesCcmPkcs11.cs                     PUBLIC. AesCcm-shaped wrapper.
├── ChaCha20Poly1305Pkcs11.cs           PUBLIC. ChaCha20Poly1305-shaped wrapper.
├── HMACPkcs11.cs                       PUBLIC. : HMAC
│
├── Objects/                            PUBLIC.
│   ├── ObjectTemplate.cs               Fluent entry: ObjectTemplate.For*().
│   ├── ObjectTemplateBuilder.cs        Builder returned by For*() factories.
│   └── ObjectAttribute.cs              Single attribute (existing).
│
├── Exceptions/                         PUBLIC.
│   ├── Pkcs11Exception.cs              Base. ThrowIfError(CKR, string method).
│   ├── Pkcs11AuthenticationException.cs
│   ├── Pkcs11SessionException.cs
│   ├── Pkcs11TokenException.cs
│   ├── Pkcs11MechanismException.cs
│   ├── Pkcs11ObjectException.cs
│   ├── Pkcs11ArgumentException.cs
│   ├── InsecureOperationException.cs   (existing)
│   ├── InvalidEnumValueException.cs    (existing)
│   └── AttributeValueException.cs      (existing)
│
├── MechanismParams/                    PUBLIC. High-level typed param shapes.
│   ├── RsaOaepParams.cs
│   ├── RsaPssParams.cs
│   ├── AesGcmParams.cs
│   ├── AesCcmParams.cs
│   ├── ChaCha20Poly1305Params.cs
│   ├── EcdhParams.cs
│   └── ...
│
├── Common/                             PUBLIC. Spec enums (unchanged).
│   └── CKM/CKA/CKR/CKK/CKO/CKF/CKS/CKU/CKD/CKG/CKH/CKN/CKP/CKC/CKZ.cs
│
├── Logging/
│   ├── Pkcs11Logging.cs                PUBLIC. SetLoggerFactory entry.
│   └── Pkcs11LogUtils.cs               internal.
│
├── Internal/                           internal. Managed plumbing.
│   ├── IPkcs11Library.cs               Mock seam.
│   ├── Pkcs11Session.cs                Renamed from today's `Session`.
│   ├── ObjectHandle.cs                 readonly record struct.
│   ├── Pkcs11ModuleHandle.cs           SafeHandle.
│   ├── Pkcs11SessionHandle.cs          SafeHandle.
│   ├── ExceptionMapper.cs              CKR → typed subclass.
│   └── SecureBuffer.cs                 Internal-only sensitive buffer.
│
└── Native/                             internal. P/Invoke + marshalling only.
    ├── LowLevelPkcs11Library.cs        Implements IPkcs11Library.
    ├── Delegates.cs
    ├── UnmanagedMemory.cs
    ├── Bindings/                       CK_MECHANISM, CK_ATTRIBUTE, etc.
    └── RawMechanismParams/             Unmanaged-layout param structs (renamed from
                                        Native/MechanismParams/).
```

## Folder layout — test code

```
src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/
│
├── Pkcs11LibraryTests.cs               Library load/finalize, slot enumeration.
├── Pkcs11SlotTests.cs                  Slot/token info, mechanism list.
├── Pkcs11WorkspaceTests.cs             Login/Logout, lifecycle, factory, multi-key ops.
├── Pkcs11KeyTests.cs                   Open/dispose, metadata, mechanism escape hatch.
├── MechanismTests.cs                   Construction, raw vs. factory, param round-trip.
├── SecurePinTests.cs                   (existing, moved to root)
│
├── Algorithms/                         BCL providers — one file per type.
│   ├── RSAPkcs11Tests.cs               Sign/verify, encrypt/decrypt, ImportParameters,
│   │                                   private+public companion discovery via CKA_ID,
│   │                                   public-key synthesis from private-only RSA key,
│   │                                   public-only key behavior (sign throws).
│   ├── ECDsaPkcs11Tests.cs
│   ├── ECDiffieHellmanPkcs11Tests.cs
│   ├── AesPkcs11Tests.cs
│   ├── AesGcmPkcs11Tests.cs
│   ├── AesCcmPkcs11Tests.cs
│   ├── ChaCha20Poly1305Pkcs11Tests.cs
│   └── HMACPkcs11Tests.cs
│
├── Objects/
│   ├── ObjectTemplateTests.cs          Builder fluency, secure defaults, invalid combos.
│   └── ObjectAttributeTests.cs         (existing)
│
├── Exceptions/
│   ├── Pkcs11ExceptionTests.cs         ThrowIfError dispatch, CKR coverage.
│   ├── ExceptionMappingTests.cs        Every CKR category → expected subclass.
│   └── (existing exception tests folded in)
│
├── MechanismParams/                    Per-param round-trip and validation tests.
│
├── Common/                             Enum tests (existing, kept).
│
├── Internal/                           InternalsVisibleTo-only.
│   ├── Pkcs11SessionTests.cs           Renamed Session tests.
│   ├── ObjectHandleTests.cs            Struct equality, Invalid, IsInvalid, ToString.
│   ├── ExceptionMapperTests.cs         Direct mapper tests (no throw path).
│   ├── FakePkcs11LibraryTests.cs       Sanity tests for the fake itself.
│   └── SecureBufferTests.cs            (existing, moved here)
│
├── Fakes/                              IPkcs11Library implementations for tests.
│   ├── FakePkcs11Library.cs            In-memory implementation.
│   ├── FakeSlot.cs   FakeToken.cs   FakeSession.cs    State containers.
│   └── FakeBuilder.cs                  Fluent fixture setup.
│
└── Fixtures/                           Real-backend fixtures (kept).
    ├── MockBackendFixture.cs           pkcs11-mock (when present).
    ├── SoftHsmBackendFixture.cs        SoftHSM v2/v3.
    └── TestKeys.cs                     Shared key-material helpers.
```

Today's `HighLevel/{Encrypt,Decrypt,Sign,Verify}` test folders are deleted; their content is re-homed under `Algorithms/` per-algorithm. The dual `_Mock` + `_SoftHsm` collection-paired test class pattern is preserved across the move.

---

## Public API sketches

These are illustrative shapes, not exhaustive signatures. Per-method coverage is settled in the implementation plan.

### `Pkcs11Library`

```csharp
public sealed class Pkcs11Library : IDisposable
{
    public static Pkcs11Library Load(string libraryPath);
    public IReadOnlyList<Pkcs11Slot> GetSlots(bool tokenPresentOnly = true);
    public Pkcs11Workspace OpenWorkspace(Pkcs11Slot slot, CKU userType, SecurePin pin);
    public void Dispose();
}
```

### `Pkcs11Workspace`

```csharp
public sealed class Pkcs11Workspace : IDisposable
{
    public Pkcs11Slot Slot { get; }

    public Pkcs11Key OpenKey(string label);
    public Pkcs11Key OpenKey(ReadOnlySpan<byte> id);
        // Auto-discovers private+public companion via CKA_ID when both exist.

    public Pkcs11Key GenerateKey(Mechanism mechanism, ObjectTemplate template);
        // Symmetric: dispatches to C_GenerateKey.
    public Pkcs11Key GenerateKey(
        Mechanism mechanism,
        ObjectTemplate privateTemplate,
        ObjectTemplate publicTemplate);
        // Asymmetric: dispatches to C_GenerateKeyPair. Returns a single Pkcs11Key
        // carrying both handles.

    public Pkcs11Key ImportKey(ObjectTemplate template);
    public IReadOnlyList<Pkcs11Key> FindKeys(ObjectTemplate filter);

    public byte[] GenerateRandom(int length);
    public void   SeedRandom(ReadOnlySpan<byte> seed);
    public byte[] Digest(Mechanism mechanism, ReadOnlySpan<byte> data);

    public void Dispose();
}
```

### `Pkcs11Key`

```csharp
public sealed class Pkcs11Key : IDisposable
{
    public static Pkcs11Key Open(
        string libraryPath,
        string slotLabel,
        CKU userType,
        SecurePin pin,
        string keyLabel);                               // one-shot: loads + owns the library
                                                        // and workspace; Dispose tears
                                                        // them all down.

    public static Pkcs11Key Open(
        Pkcs11Library library,
        string slotLabel,
        CKU userType,
        SecurePin pin,
        string keyLabel);                               // shared library: caller retains
                                                        // ownership of `library`. Pkcs11Key
                                                        // owns the workspace it opens, and
                                                        // disposes it on Dispose. The
                                                        // library is left alone.

    public CKK    KeyType       { get; }
    public string? Label         { get; }
    public ReadOnlySpan<byte> Id { get; }

    // Mechanism-level surface (the escape hatch).
    public byte[] Sign(Mechanism mechanism, ReadOnlySpan<byte> data);
    public bool   Verify(Mechanism mechanism, ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig);
    public byte[] Encrypt(Mechanism mechanism, ReadOnlySpan<byte> plaintext);
    public byte[] Decrypt(Mechanism mechanism, ReadOnlySpan<byte> ciphertext);
    public byte[] Wrap(Mechanism mechanism, Pkcs11Key targetKey);
    public Pkcs11Key Unwrap(Mechanism mechanism, ReadOnlySpan<byte> wrapped, ObjectTemplate template);
    public Pkcs11Key Derive(Mechanism mechanism, ObjectTemplate template);

    public void Dispose();
}
```

### `RSAPkcs11` (representative BCL provider)

```csharp
public sealed class RSAPkcs11 : RSA
{
    public RSAPkcs11(Pkcs11Key key);                    // does not take ownership of the key

    public override byte[] SignData(byte[] data, HashAlgorithmName hash, RSASignaturePadding padding);
    public override bool   VerifyData(byte[] data, byte[] sig, HashAlgorithmName hash, RSASignaturePadding padding);
    public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding);
    public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding);
    public override RSAParameters ExportParameters(bool includePrivateParameters);
    // Throws InsecureOperationException when includePrivateParameters is true and
    // the key is non-extractable.
}
```

The constructor does not take ownership: disposing `RSAPkcs11` does not dispose the underlying `Pkcs11Key`. Lifetime ownership is explicit and one-way (caller owns the key, the provider is a view).

### `Mechanism`

```csharp
public readonly struct Mechanism
{
    public CKM Type { get; }
    public ReadOnlyMemory<byte> Params { get; }

    public Mechanism(CKM type);
    public Mechanism(CKM type, ReadOnlyMemory<byte> rawParams);   // power-user

    // Factory methods (one per well-known mechanism family).
    public static Mechanism RsaOaep(RsaOaepParams p);
    public static Mechanism RsaPkcsPss(RsaPssParams p);
    public static Mechanism AesGcm(AesGcmParams p);
    public static Mechanism AesCcm(AesCcmParams p);
    public static Mechanism ChaCha20Poly1305(ChaCha20Poly1305Params p);
    public static Mechanism EcdhDerive(EcdhParams p);
    // ... one per supported well-known mechanism
}
```

### `ObjectTemplate`

```csharp
public static class ObjectTemplate
{
    public static SecretKeyTemplateBuilder ForSecretKey(CKK keyType);
    public static PrivateKeyTemplateBuilder ForPrivateKey(CKK keyType);
    public static PublicKeyTemplateBuilder ForPublicKey(CKK keyType);
    public static CertificateTemplateBuilder ForCertificate(CKC certType);
    public static DataTemplateBuilder ForData();
    public static GenericTemplateBuilder Empty();
}

// Per-class builder shape (illustrated for SecretKey):
public sealed class SecretKeyTemplateBuilder
{
    public SecretKeyTemplateBuilder OnToken(bool value = true);
    public SecretKeyTemplateBuilder Sensitive(bool value = true);
    public SecretKeyTemplateBuilder NonExtractable();
    public SecretKeyTemplateBuilder Label(string label);
    public SecretKeyTemplateBuilder Id(ReadOnlySpan<byte> id);
    public SecretKeyTemplateBuilder Value(ReadOnlySpan<byte> value);   // for ImportKey
    public SecretKeyTemplateBuilder ValueLen(int bits);                // for GenerateKey
    public SecretKeyTemplateBuilder Encrypt(bool value = true);
    public SecretKeyTemplateBuilder Decrypt(bool value = true);
    public SecretKeyTemplateBuilder Sign(bool value = true);
    public SecretKeyTemplateBuilder Verify(bool value = true);
    public SecretKeyTemplateBuilder Wrap(bool value = true);
    public SecretKeyTemplateBuilder Unwrap(bool value = true);
    public SecretKeyTemplateBuilder Derive(bool value = true);
    public SecretKeyTemplateBuilder Attribute(CKA attribute, object value);  // escape hatch
    public ObjectTemplate Build();
}
```

Per-class builders exclude attributes that don't apply to that class. `Attribute(CKA, object)` is the raw escape hatch for vendor or rare attributes.

`ObjectTemplate.Build()` produces an immutable value that's safe to pass into low-level calls.

### `Pkcs11Exception`

```csharp
public abstract class Pkcs11Exception : Exception
{
    public CKR    ReturnValue { get; }
    public string Method      { get; }

    protected Pkcs11Exception(CKR rv, string method, string? message);

    public static void ThrowIfError(CKR rv, string method);   // central mapping point
}

public sealed class Pkcs11AuthenticationException : Pkcs11Exception { /* ... */ }
public sealed class Pkcs11SessionException        : Pkcs11Exception { /* ... */ }
public sealed class Pkcs11TokenException          : Pkcs11Exception { /* ... */ }
public sealed class Pkcs11MechanismException      : Pkcs11Exception { /* ... */ }
public sealed class Pkcs11ObjectException         : Pkcs11Exception { /* ... */ }
public sealed class Pkcs11ArgumentException       : Pkcs11Exception { /* ... */ }
```

### `IPkcs11Library` (internal mock seam)

```csharp
internal interface IPkcs11Library : IDisposable
{
    // Slot / token
    IReadOnlyList<ulong> GetSlotList(bool tokenPresent);
    SlotInfo  GetSlotInfo(ulong slotId);
    TokenInfo GetTokenInfo(ulong slotId);
    IReadOnlyList<CKM> GetMechanismList(ulong slotId);
    MechanismInfo GetMechanismInfo(ulong slotId, CKM mechanism);

    // Session
    ulong OpenSession(ulong slotId, CKF flags);
    void  CloseSession(ulong sessionHandle);
    void  Login(ulong sessionHandle, CKU userType, ReadOnlySpan<byte> pin);
    void  Logout(ulong sessionHandle);

    // Objects
    ulong CreateObject(ulong sessionHandle, ObjectTemplate template);
    void  DestroyObject(ulong sessionHandle, ulong objectHandle);
    IReadOnlyList<ulong> FindObjects(ulong sessionHandle, ObjectTemplate filter);
    void  GetAttributeValue(ulong sessionHandle, ulong objectHandle, Span<ObjectAttribute> attrs);

    // Crypto
    byte[] Sign(ulong sessionHandle, ulong keyHandle, Mechanism mechanism, ReadOnlySpan<byte> data);
    bool   Verify(ulong sessionHandle, ulong keyHandle, Mechanism mechanism, ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig);
    byte[] Encrypt(ulong sessionHandle, ulong keyHandle, Mechanism mechanism, ReadOnlySpan<byte> data);
    byte[] Decrypt(ulong sessionHandle, ulong keyHandle, Mechanism mechanism, ReadOnlySpan<byte> data);
    // ... wrap, unwrap, derive, digest, random
}
```

The interface deliberately uses `ulong` for handles and value types for templates/mechanisms so the fake can implement it without referencing `Native/` types. `Native.LowLevelPkcs11Library` adapts these calls to the underlying P/Invoke surface.

---

## Migration plan

This is a breaking change. The package has not yet shipped a 1.0; no public consumers exist outside this repository. Migration runs in-tree with no shim layer.

Implementation order (refined in the implementation plan, sketched here):

1. **Add new without removing old:** `Internal/IPkcs11Library.cs`, `Internal/ExceptionMapper.cs`, typed exception subclasses, `Objects/ObjectTemplateBuilder.cs` and per-class builders. Native library implements `IPkcs11Library` alongside its existing public surface.
2. **Introduce `Pkcs11Key` and `Pkcs11Workspace`** as the public abstractions; today's `Session` stays available temporarily so internal code can be migrated callsite by callsite.
3. **Introduce BCL providers** (`RSAPkcs11`, `ECDsaPkcs11`, …), each backed by a `Pkcs11Key`.
4. **Migrate tests:** create new test folders, port test logic algorithm-by-algorithm. Keep `_Mock` + `_SoftHsm` pairing.
5. **Demote internals:** rename `Session` → `Pkcs11Session`, make internal; make `ObjectHandle` internal; delete `Session.*.cs` algorithm-specific helpers; delete `Security/` folder (move `SecurePin` to root, `SecureBuffer` to `Internal/`); rename `Native/MechanismParams/` → `Native/RawMechanismParams/`.
6. **Remove dead `Session` partial fragments** and the `HighLevel/` test folder shells.

The library is in pre-1.0 active development; the changelog records the breaking change but no compatibility shims are written.

---

## Testing strategy

Three tiers, all kept:

1. **Managed-only unit tests, fakes-backed** — `FakePkcs11Library` exercises template construction, exception mapping, argument validation, key metadata caching, builder fluency. Fast, no native dependency.
2. **pkcs11-mock backend tests** — marshalling correctness, error code → exception mapping at the P/Invoke boundary, argument-validation that fires before any native call. Today's `_Mock` test classes carry over.
3. **SoftHSM v2/v3 backend tests** — real crypto correctness, end-to-end roundtrips, mechanism-specific behavior. Today's `_SoftHsm` test classes carry over.

The `_Mock` + `_SoftHsm` collection-paired class pattern (e.g. `EncryptChaChaTests_Mock` + `EncryptChaChaTests_SoftHsm` sharing a `EncryptChaChaTestCases` static helper) is preserved verbatim across the test reorganization.

Per-algorithm test files in `Algorithms/` cover both the BCL provider surface and the underlying mechanism-level surface on `Pkcs11Key`, so callers using either entry point have parity coverage.

---

## Security properties preserved

These constraints from `CLAUDE.md` carry over unchanged:

- **PINs never logged.** `SecurePin` is the only PIN carrier; its `ToString()` returns `"SecurePin{redacted}"`. The mock seam takes `ReadOnlySpan<byte>` for the PIN parameter; the value never lives in a `string`.
- **Non-extractable keys are the default in template builders.** `Sensitive()` and `NonExtractable()` are explicit when needed, but the builders default to safe values (sensitive=true, extractable=false) when calling secret/private-key factories without overrides.
- **Insecure operations throw `InsecureOperationException`.** Calling `ExportParameters(includePrivateParameters: true)` on a non-extractable key throws before any P/Invoke.
- **Constant-time comparison.** Any byte-comparison touching key material (e.g. comparing two `CKA_ID` values, or future tag-validation paths) uses `CryptographicOperations.FixedTimeEquals`.
- **No PIN/key/plaintext in log messages.** `Pkcs11LogUtils` policy unchanged.
- **Library path is configurable, not hardcoded.** `Pkcs11Library.Load(libraryPath)` requires the caller to specify it. No default search.

---

## Open questions (deferred to implementation plan)

- Exact attribute lists per `ObjectTemplate.ForX(...)` builder — what's exposed vs. hidden behind `Attribute(CKA, object)`.
- BCL provider parity scope per type — which `RSA` / `ECDsa` / etc. methods are implemented in v1 vs. deferred. Settled in the implementation plan, not here.
