# PKCS11 BCL Providers Implementation Plan (Plan 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the BCL-aligned provider types — public sealed classes following `System.Security.Cryptography` shapes — built on top of Plan 2's `Pkcs11Key`. A .NET developer familiar with `RSACng` / `AesGcm` can use PKCS#11-backed equivalents with minimal mental remapping.

**Architecture:** Each provider holds a non-owning `Pkcs11Key` reference and delegates operations to it. Asymmetric subclasses inherit from the BCL base (`RSA`, `ECDsa`) and override the relevant virtual methods. AEAD wrappers (`AesGcmPkcs11`, `AesCcmPkcs11`, `ChaCha20Poly1305Pkcs11`) mirror the sealed BCL shape without inheriting. A shared `Pkcs11MechanismMap` static class centralizes the `HashAlgorithmName` + padding → `Mechanism` translation that all providers need.

**Tech Stack:** C# 12, .NET 8/9, xUnit 2.9. Builds on Plan 2's `Pkcs11Workspace` + `Pkcs11Key`.

**Spec:** `docs/superpowers/specs/2026-05-13-pkcs11-bcl-aligned-redesign-design.md`

**Working directory:** `/home/alexandre/dev/PKCS11.NET` (git repo, branch `main`).

---

## Scope

Plan 3 v1 lands six providers:

| BCL base | Provider | Inheritance |
|---|---|---|
| `RSA` | `RSAPkcs11` | subclass |
| `ECDsa` | `ECDsaPkcs11` | subclass |
| `AesGcm` (sealed) | `AesGcmPkcs11` | wrapper |
| `AesCcm` (sealed) | `AesCcmPkcs11` | wrapper |
| `ChaCha20Poly1305` (sealed) | `ChaCha20Poly1305Pkcs11` | wrapper |
| `HMAC` | `HMACPkcs11` | subclass |

**Deferred to a follow-up plan:**
- `AesPkcs11` (subclass of `Aes`) — requires implementing `ICryptoTransform` on top of an on-token key, which is structurally complex enough to deserve its own plan.
- `ECDiffieHellmanPkcs11` — `DeriveKeyMaterial` involves a key-derivation mechanism family (`CKM_ECDH1_DERIVE` and variants) and produces a new on-token key, not a managed byte array; mapping to the BCL's `DeriveBytes` / `DeriveKeyMaterial` flows benefits from its own design pass.

Per-method parity for the six v1 providers is scoped per task below.

---

## Project conventions

- **Build:** `dotnet build src/KerckhoffsLabs.sln -c Debug`.
- **Test:** `dotnet test src/KerckhoffsLabs.sln -c Debug` (full) or `--filter "FullyQualifiedName~ClassName"` (targeted).
- **Git:** each task ends with a `git commit` step. Commit-message style: `feat(ProviderName): one-line summary` followed by multi-paragraph body, signed with `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`.
- **InternalsVisibleTo:** test assembly has access to internal members.
- **Existing types to lean on (all from Plan 2):**
  - `Pkcs11Key.Sign(Mechanism, ReadOnlySpan<byte>) → byte[]`
  - `Pkcs11Key.Verify(Mechanism, ReadOnlySpan<byte>, ReadOnlySpan<byte>) → bool` (with managed verify fallback for synthesized public-key views)
  - `Pkcs11Key.Encrypt(Mechanism, ReadOnlySpan<byte>) → byte[]`
  - `Pkcs11Key.Decrypt(Mechanism, ReadOnlySpan<byte>) → byte[]`
  - `Pkcs11Key.KeyType`, `Pkcs11Key.Label`, `Pkcs11Key.Id`
  - `Pkcs11Key.GetSynthesizedRsaParameters()` (internal)
  - `Pkcs11Key.GetSynthesizedEcParameters()` (internal)
  - Internal `Pkcs11Key.PublicHandle` / `PrivateHandle` accessors.
- **Mechanism param types already in the codebase** (under `HighLevel/MechanismParams/`):
  - `CkmRsaPkcsOaepParams(CKM hashAlg, CKG mgf, ReadOnlySpan<byte> sourceData = default)` — for RSA-OAEP.
  - `CkmRsaPkcsPssParams(CKM hashAlg, CKG mgf, int saltLength)` — for RSA-PSS.
  - `CkmAesGcmParams(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> aad, int tagBits)` — for AES-GCM.
  - `CkmSalsa20ChaCha20Poly1305Params(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad)` — for ChaCha20-Poly1305.

---

## File structure

### New production files

```
src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
└── HighLevel/
    ├── Pkcs11MechanismMap.cs                  internal. Centralized HashAlgorithmName/padding → Mechanism translation.
    ├── RSAPkcs11.cs                           public sealed : RSA.
    ├── ECDsaPkcs11.cs                         public sealed : ECDsa.
    ├── AesGcmPkcs11.cs                        public sealed wrapper.
    ├── AesCcmPkcs11.cs                        public sealed wrapper.
    ├── ChaCha20Poly1305Pkcs11.cs              public sealed wrapper.
    └── HMACPkcs11.cs                          public sealed : HMAC.
```

### New test files

```
src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/
└── HighLevel/
    ├── Pkcs11MechanismMapTests.cs
    ├── RSAPkcs11Tests.cs
    ├── ECDsaPkcs11Tests.cs
    ├── AesGcmPkcs11Tests.cs
    ├── AesCcmPkcs11Tests.cs
    ├── ChaCha20Poly1305Pkcs11Tests.cs
    └── HMACPkcs11Tests.cs
```

### Modified production files

```
src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/
└── Pkcs11Key.Mechanism.cs                     Remove the now-duplicated private MapRsaSignMechanism /
                                               MapEcdsaMechanism helpers; route through
                                               Pkcs11MechanismMap instead.
```

---

## Ownership rule (applies to every provider)

Every provider constructor takes a `Pkcs11Key` and does **not** take ownership of it:

- The caller continues to own and dispose the `Pkcs11Key`.
- Disposing the provider does **not** dispose the key.
- The provider stores the key reference and forwards every operation to it.

This matches how `RSACng(CngKey)` and `ECDsaCng(CngKey)` work in the BCL: the key is the heavyweight resource, the provider is a thin view.

---

## Task list

### Task 1: `Pkcs11MechanismMap` shared translation helpers

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11MechanismMap.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11MechanismMapTests.cs`
- Modify: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Key.Mechanism.cs` (remove inline maps, delegate to Pkcs11MechanismMap)

Centralize the mechanism-name translation logic. Plan 2's `Pkcs11Key.Verify` defined private inline maps; lifting them into a shared internal class makes them reusable by every provider.

- [ ] **Step 1: Write the failing tests**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11MechanismMapTests.cs`:

```csharp
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public sealed class Pkcs11MechanismMapTests
{
    [Theory]
    [InlineData("SHA1",   (ulong)CKM.CKM_SHA1_RSA_PKCS)]
    [InlineData("SHA256", (ulong)CKM.CKM_SHA256_RSA_PKCS)]
    [InlineData("SHA384", (ulong)CKM.CKM_SHA384_RSA_PKCS)]
    [InlineData("SHA512", (ulong)CKM.CKM_SHA512_RSA_PKCS)]
    public void RsaPkcs1_HashToCkm_ReturnsExpected(string hashName, ulong expectedCkm)
    {
        using var mech = Pkcs11MechanismMap.RsaPkcs1Sign(new HashAlgorithmName(hashName));
        Assert.Equal(expectedCkm, mech.Type);
    }

    [Theory]
    [InlineData("SHA1",   (ulong)CKM.CKM_SHA1_RSA_PKCS_PSS)]
    [InlineData("SHA256", (ulong)CKM.CKM_SHA256_RSA_PKCS_PSS)]
    [InlineData("SHA384", (ulong)CKM.CKM_SHA384_RSA_PKCS_PSS)]
    [InlineData("SHA512", (ulong)CKM.CKM_SHA512_RSA_PKCS_PSS)]
    public void RsaPss_HashToCkm_ReturnsExpectedWithParams(string hashName, ulong expectedCkm)
    {
        using var mech = Pkcs11MechanismMap.RsaPssSign(new HashAlgorithmName(hashName), saltLength: -1);
        Assert.Equal(expectedCkm, mech.Type);
    }

    [Theory]
    [InlineData("SHA1",   (ulong)CKM.CKM_ECDSA_SHA1)]
    [InlineData("SHA256", (ulong)CKM.CKM_ECDSA_SHA256)]
    [InlineData("SHA384", (ulong)CKM.CKM_ECDSA_SHA384)]
    [InlineData("SHA512", (ulong)CKM.CKM_ECDSA_SHA512)]
    public void EcdsaSign_HashToCkm_ReturnsExpected(string hashName, ulong expectedCkm)
    {
        using var mech = Pkcs11MechanismMap.EcdsaSign(new HashAlgorithmName(hashName));
        Assert.Equal(expectedCkm, mech.Type);
    }

    [Fact]
    public void RsaPkcs1Sign_UnsupportedHash_Throws()
    {
        Assert.Throws<NotSupportedException>(() =>
            Pkcs11MechanismMap.RsaPkcs1Sign(HashAlgorithmName.MD5));
    }

    [Fact]
    public void RsaOaep_BuildsMechanismWithParams()
    {
        using var mech = Pkcs11MechanismMap.RsaOaep(HashAlgorithmName.SHA256);
        Assert.Equal((ulong)CKM.CKM_RSA_PKCS_OAEP, mech.Type);
    }

    [Fact]
    public void HmacHash_HashToCkm_ReturnsExpected()
    {
        using var mech = Pkcs11MechanismMap.HmacGeneral(HashAlgorithmName.SHA256);
        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, mech.Type);
    }
}
```

- [ ] **Step 2: Run tests to confirm failure**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11MechanismMapTests" -c Debug
```

Expected: build error — `Pkcs11MechanismMap` doesn't exist.

- [ ] **Step 3: Create `Pkcs11MechanismMap.cs`**

```csharp
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Central translation from BCL hash / padding choices to PKCS#11 <see cref="Mechanism"/>
/// instances. Used by every BCL-aligned provider (<see cref="RSAPkcs11"/>,
/// <see cref="ECDsaPkcs11"/>, etc.) to avoid duplicated mapping logic.
/// </summary>
internal static class Pkcs11MechanismMap
{
    /// <summary>RSA PKCS#1 v1.5 sign mechanism for the given hash.</summary>
    public static Mechanism RsaPkcs1Sign(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA1"   => new Mechanism(CKM.CKM_SHA1_RSA_PKCS),
        "SHA256" => new Mechanism(CKM.CKM_SHA256_RSA_PKCS),
        "SHA384" => new Mechanism(CKM.CKM_SHA384_RSA_PKCS),
        "SHA512" => new Mechanism(CKM.CKM_SHA512_RSA_PKCS),
        _ => throw new NotSupportedException(
            $"RSA PKCS#1 sign does not support hash {hash.Name}."),
    };

    /// <summary>RSA PSS sign mechanism for the given hash + salt length. <c>saltLength = -1</c> uses the hash length.</summary>
    public static Mechanism RsaPssSign(HashAlgorithmName hash, int saltLength)
    {
        var (ckm, innerHash, mgf, effectiveSalt) = hash.Name switch
        {
            "SHA1"   => (CKM.CKM_SHA1_RSA_PKCS_PSS,   CKM.CKM_SHA_1,  CKG.CKG_MGF1_SHA1,   saltLength < 0 ? 20 : saltLength),
            "SHA256" => (CKM.CKM_SHA256_RSA_PKCS_PSS, CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, saltLength < 0 ? 32 : saltLength),
            "SHA384" => (CKM.CKM_SHA384_RSA_PKCS_PSS, CKM.CKM_SHA384, CKG.CKG_MGF1_SHA384, saltLength < 0 ? 48 : saltLength),
            "SHA512" => (CKM.CKM_SHA512_RSA_PKCS_PSS, CKM.CKM_SHA512, CKG.CKG_MGF1_SHA512, saltLength < 0 ? 64 : saltLength),
            _ => throw new NotSupportedException(
                $"RSA-PSS does not support hash {hash.Name}."),
        };
        return new Mechanism(ckm, new CkmRsaPkcsPssParams(innerHash, mgf, effectiveSalt));
    }

    /// <summary>RSA OAEP encrypt/decrypt mechanism for the given hash.</summary>
    public static Mechanism RsaOaep(HashAlgorithmName hash)
    {
        var (innerHash, mgf) = hash.Name switch
        {
            "SHA1"   => (CKM.CKM_SHA_1,  CKG.CKG_MGF1_SHA1),
            "SHA256" => (CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256),
            "SHA384" => (CKM.CKM_SHA384, CKG.CKG_MGF1_SHA384),
            "SHA512" => (CKM.CKM_SHA512, CKG.CKG_MGF1_SHA512),
            _ => throw new NotSupportedException(
                $"RSA-OAEP does not support hash {hash.Name}."),
        };
        return new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(innerHash, mgf));
    }

    /// <summary>ECDSA sign mechanism for the given hash.</summary>
    public static Mechanism EcdsaSign(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA1"   => new Mechanism(CKM.CKM_ECDSA_SHA1),
        "SHA256" => new Mechanism(CKM.CKM_ECDSA_SHA256),
        "SHA384" => new Mechanism(CKM.CKM_ECDSA_SHA384),
        "SHA512" => new Mechanism(CKM.CKM_ECDSA_SHA512),
        _ => throw new NotSupportedException(
            $"ECDSA does not support hash {hash.Name}."),
    };

    /// <summary>HMAC mechanism for the given hash.</summary>
    public static Mechanism HmacGeneral(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA1"   => new Mechanism(CKM.CKM_SHA_1_HMAC),
        "SHA256" => new Mechanism(CKM.CKM_SHA256_HMAC),
        "SHA384" => new Mechanism(CKM.CKM_SHA384_HMAC),
        "SHA512" => new Mechanism(CKM.CKM_SHA512_HMAC),
        _ => throw new NotSupportedException(
            $"HMAC does not support hash {hash.Name}."),
    };
}
```

If `CKM.CKM_SHA_1_HMAC` doesn't exist under that name, try `CKM.CKM_SHA1_HMAC` or `CKM.CKM_SHA_1_HMAC_GENERAL`. Adapt to the actual enum-member name.

- [ ] **Step 4: Refactor `Pkcs11Key.Mechanism.cs`**

In `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Key.Mechanism.cs`:
- Delete the existing private `MapRsaSignMechanism` and `MapEcdsaMechanism` helpers at the bottom of the file.
- Update the call sites in `VerifyRsaInManaged` and `VerifyEcInManaged` to use `Pkcs11MechanismMap.RsaPkcs1Sign(...)` and `Pkcs11MechanismMap.EcdsaSign(...)`.
- For verify, you read back `(hashName, padding)` from `MapRsaSignMechanism` — that helper returned a tuple. The mapping is now embedded in `Pkcs11MechanismMap.RsaPkcs1Sign` (it returns a Mechanism, not a tuple). For the managed-verify case in `VerifyRsaInManaged`, you need both the `HashAlgorithmName` and the `RSASignaturePadding` to feed to `rsa.VerifyData`. Since the input was a `Mechanism`, reverse-map it:

```csharp
private static bool VerifyRsaInManaged(
    Mechanism mechanism,
    System.Security.Cryptography.RSAParameters rsaParams,
    ReadOnlySpan<byte> data,
    ReadOnlySpan<byte> signature)
{
    using var rsa = System.Security.Cryptography.RSA.Create();
    rsa.ImportParameters(rsaParams);

    var (hashName, padding) = MechanismToRsaSignParams(mechanism);
    return rsa.VerifyData(data, signature, hashName, padding);
}

private static (HashAlgorithmName, RSASignaturePadding) MechanismToRsaSignParams(Mechanism mechanism)
    => mechanism.Type switch
    {
        (ulong)CKM.CKM_SHA1_RSA_PKCS   => (HashAlgorithmName.SHA1,   RSASignaturePadding.Pkcs1),
        (ulong)CKM.CKM_SHA256_RSA_PKCS => (HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
        (ulong)CKM.CKM_SHA384_RSA_PKCS => (HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
        (ulong)CKM.CKM_SHA512_RSA_PKCS => (HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
        (ulong)CKM.CKM_SHA1_RSA_PKCS_PSS   => (HashAlgorithmName.SHA1,   RSASignaturePadding.Pss),
        (ulong)CKM.CKM_SHA256_RSA_PKCS_PSS => (HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
        (ulong)CKM.CKM_SHA384_RSA_PKCS_PSS => (HashAlgorithmName.SHA384, RSASignaturePadding.Pss),
        (ulong)CKM.CKM_SHA512_RSA_PKCS_PSS => (HashAlgorithmName.SHA512, RSASignaturePadding.Pss),
        _ => throw new NotSupportedException(
            $"Managed RSA verify is not implemented for mechanism {(CKM)mechanism.Type}. " +
            "Provide a CKO_PUBLIC_KEY companion on the token to use the native verify path."),
    };
```

Similarly for ECDSA:

```csharp
private static bool VerifyEcInManaged(...)
{
    using var ec = System.Security.Cryptography.ECDsa.Create();
    ec.ImportParameters(ecParams);
    var hashName = MechanismToEcdsaHash(mechanism);
    return ec.VerifyData(data, signature, hashName);
}

private static HashAlgorithmName MechanismToEcdsaHash(Mechanism mechanism)
    => mechanism.Type switch
    {
        (ulong)CKM.CKM_ECDSA_SHA1   => HashAlgorithmName.SHA1,
        (ulong)CKM.CKM_ECDSA_SHA256 => HashAlgorithmName.SHA256,
        (ulong)CKM.CKM_ECDSA_SHA384 => HashAlgorithmName.SHA384,
        (ulong)CKM.CKM_ECDSA_SHA512 => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException(
            $"Managed ECDSA verify is not implemented for mechanism {(CKM)mechanism.Type}."),
    };
```

- [ ] **Step 5: Run tests + Step 6: Full suite**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~Pkcs11MechanismMapTests" -c Debug
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 14 mapper tests pass + full suite 0 failures.

- [ ] **Step 7: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11MechanismMap.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/Pkcs11Key.Mechanism.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/Pkcs11MechanismMapTests.cs

git commit -m "$(cat <<'EOF'
feat(Pkcs11MechanismMap): shared HashAlgorithmName → Mechanism translation

Lifts the private Map helpers that Plan 2 inlined into
Pkcs11Key.Mechanism.cs into a shared internal static class. The map
now covers the four mechanism families that the BCL providers need:

  RsaPkcs1Sign(HashAlgorithmName)            → CKM_<hash>_RSA_PKCS
  RsaPssSign(HashAlgorithmName, saltLength)  → CKM_<hash>_RSA_PKCS_PSS + CkmRsaPkcsPssParams
  RsaOaep(HashAlgorithmName)                 → CKM_RSA_PKCS_OAEP + CkmRsaPkcsOaepParams
  EcdsaSign(HashAlgorithmName)               → CKM_ECDSA_<hash>
  HmacGeneral(HashAlgorithmName)             → CKM_<hash>_HMAC

Pkcs11Key's managed-verify fallback path is updated to go through this
shared map (forward direction) and through a small reverse-mapping
helper kept inline in Pkcs11Key.Mechanism.cs (Mechanism → (Hash, Padding)).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `RSAPkcs11`

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/RSAPkcs11.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/RSAPkcs11Tests.cs`

Implements: `SignData(byte[], HashAlgorithmName, RSASignaturePadding)`, `VerifyData(...)`, `Encrypt(byte[], RSAEncryptionPadding)`, `Decrypt(...)`, `ExportParameters(bool)`.

- [ ] **Step 1: Write the failing tests**

Create `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/RSAPkcs11Tests.cs`:

```csharp
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public sealed class RSAPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new RSAPkcs11(key: null!));
    }
}

[Collection("SoftHsm")]
public sealed class RSAPkcs11Tests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public RSAPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignVerify_Sha256_Pkcs1_RoundTrips()
    {
        using var workspace = OpenWorkspace();
        using var key = GenerateRsaKey(workspace, out var pubH, out var privH);
        try
        {
            using var rsa = new RSAPkcs11(key);
            byte[] data = System.Text.Encoding.UTF8.GetBytes("test");

            byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

            data[0] ^= 0xFF;
            Assert.False(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }
        finally { Cleanup(workspace, pubH, privH); }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignVerify_Sha256_Pss_RoundTrips()
    {
        using var workspace = OpenWorkspace();
        using var key = GenerateRsaKey(workspace, out var pubH, out var privH);
        try
        {
            using var rsa = new RSAPkcs11(key);
            byte[] data = System.Text.Encoding.UTF8.GetBytes("test");

            byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        }
        finally { Cleanup(workspace, pubH, privH); }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptDecrypt_OaepSha256_RoundTrips()
    {
        using var workspace = OpenWorkspace();
        using var key = GenerateRsaKey(workspace, out var pubH, out var privH);
        try
        {
            using var rsa = new RSAPkcs11(key);
            byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("secret payload");

            byte[] ct = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
            byte[] recovered = rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA256);

            Assert.Equal(plaintext, recovered);
        }
        finally { Cleanup(workspace, pubH, privH); }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ExportParameters_PublicOnly_ReturnsModulusAndExponent()
    {
        using var workspace = OpenWorkspace();
        using var key = GenerateRsaKey(workspace, out var pubH, out var privH);
        try
        {
            using var rsa = new RSAPkcs11(key);
            var p = rsa.ExportParameters(includePrivateParameters: false);

            Assert.NotNull(p.Modulus);
            Assert.NotNull(p.Exponent);
            Assert.Equal(2048 / 8, p.Modulus!.Length);
            Assert.Null(p.D); // private parts must not be set
        }
        finally { Cleanup(workspace, pubH, privH); }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ExportParameters_Private_ThrowsInsecureOperation()
    {
        using var workspace = OpenWorkspace();
        using var key = GenerateRsaKey(workspace, out var pubH, out var privH);
        try
        {
            using var rsa = new RSAPkcs11(key);
            Assert.Throws<InsecureOperationException>(() => rsa.ExportParameters(includePrivateParameters: true));
        }
        finally { Cleanup(workspace, pubH, privH); }
    }

    private static Pkcs11Key GenerateRsaKey(Pkcs11Workspace workspace,
        out KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.ObjectHandle pubH,
        out KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.ObjectHandle privH)
    {
        string label = $"rsa-prov-{Guid.NewGuid():N}";
        byte[] id = System.Text.Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().Encrypt().ModulusBits(2048)
            .PublicExponent(new byte[] { 0x01, 0x00, 0x01 }).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign().Decrypt().Build();

        var key = workspace.GenerateKey(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), privTpl, pubTpl);
        pubH = key.PublicHandle;
        privH = key.PrivateHandle;
        return key;
    }

    private static void Cleanup(Pkcs11Workspace workspace,
        KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.ObjectHandle pubH,
        KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.ObjectHandle privH)
    {
        if (!pubH.IsInvalid)  workspace.Session.DestroyObject(pubH);
        if (!privH.IsInvalid) workspace.Session.DestroyObject(privH);
    }
}
```

- [ ] **Step 2: Verify failure**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~RSAPkcs11" -c Debug
```

Expected: build error.

- [ ] **Step 3: Create `RSAPkcs11.cs`**

```csharp
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// BCL-aligned <see cref="RSA"/> provider backed by a PKCS#11 <see cref="Pkcs11Key"/>.
/// Does not take ownership of the underlying key — disposing the provider does NOT
/// dispose the key.
/// </summary>
public sealed class RSAPkcs11 : RSA
{
    private readonly Pkcs11Key _key;

    /// <summary>
    /// Wraps the given key. The key must be an RSA key (<see cref="CKK.CKK_RSA"/>).
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="key"/> is not RSA.</exception>
    public RSAPkcs11(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_RSA)
            throw new ArgumentException(
                $"Expected an RSA key, got {key.KeyType}.", nameof(key));

        _key = key;
        // BCL property — picks up the modulus size from the key once we read it.
        // We defer the read to first use to avoid forcing a synthesis on construction
        // for keys that may never call ExportParameters.
    }

    /// <inheritdoc/>
    public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(padding);
        using var mech = SignMechanismFor(hashAlgorithm, padding);
        return _key.Sign(mech, data);
    }

    /// <inheritdoc/>
    public override bool VerifyData(byte[] data, byte[] signature,
        HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(padding);
        using var mech = SignMechanismFor(hashAlgorithm, padding);
        return _key.Verify(mech, data, signature);
    }

    /// <inheritdoc/>
    public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(padding);
        using var mech = EncryptMechanismFor(padding);
        return _key.Encrypt(mech, data);
    }

    /// <inheritdoc/>
    public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(padding);
        using var mech = EncryptMechanismFor(padding);
        return _key.Decrypt(mech, data);
    }

    /// <inheritdoc/>
    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
            throw new InsecureOperationException(
                "Refusing to export RSA private parameters. PKCS#11 keys are non-extractable " +
                "by design; export only public material via ExportParameters(false).");

        var synth = _key.GetSynthesizedRsaParameters();
        if (synth is not null) return synth.Value;

        // No synthesized view available — fall back to reading CKA_MODULUS + CKA_PUBLIC_EXPONENT
        // off the real public handle if one exists. The Pkcs11Key API doesn't expose this directly,
        // so we go via the internal session/handle.
        if (!_key.PublicHandle.IsInvalid)
        {
            var session = _key.Workspace.Session;
            var attrs = session.GetAttributeValue(_key.PublicHandle, new List<CKA>
            {
                CKA.CKA_MODULUS,
                CKA.CKA_PUBLIC_EXPONENT,
            });
            try
            {
                if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
                    throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                        "RSAPkcs11.ExportParameters (CKA_MODULUS / CKA_PUBLIC_EXPONENT)");

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

        throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
            "RSAPkcs11.ExportParameters (no public material reachable)");
    }

    /// <summary>Unsupported — keys are immutable on the token.</summary>
    public override void ImportParameters(RSAParameters parameters)
        => throw new NotSupportedException(
            "RSAPkcs11 wraps a PKCS#11 key handle; importing managed parameters is not supported. " +
            "Use Pkcs11Workspace.ImportKey or GenerateKey instead.");

    private static Mechanism SignMechanismFor(HashAlgorithmName hash, RSASignaturePadding padding)
    {
        if (padding == RSASignaturePadding.Pkcs1)
            return Pkcs11MechanismMap.RsaPkcs1Sign(hash);
        if (padding.Mode == RSASignaturePaddingMode.Pss)
            // Use saltLength = -1 (hash length) — matches BCL default.
            return Pkcs11MechanismMap.RsaPssSign(hash, saltLength: -1);
        throw new NotSupportedException($"Unsupported RSA signature padding: {padding}.");
    }

    private static Mechanism EncryptMechanismFor(RSAEncryptionPadding padding)
    {
        if (padding == RSAEncryptionPadding.Pkcs1)
            return new Mechanism(CKM.CKM_RSA_PKCS);
        if (padding.Mode == RSAEncryptionPaddingMode.Oaep)
            return Pkcs11MechanismMap.RsaOaep(padding.OaepHashAlgorithm);
        throw new NotSupportedException($"Unsupported RSA encryption padding: {padding}.");
    }
}
```

- [ ] **Step 4 + Step 5: Run tests + full suite**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~RSAPkcs11" -c Debug
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: argument test passes; SoftHSM tests pass (or skip cleanly).

- [ ] **Step 6: Commit**

```bash
git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/RSAPkcs11.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/RSAPkcs11Tests.cs

git commit -m "$(cat <<'EOF'
feat(RSAPkcs11): BCL-aligned RSA provider backed by Pkcs11Key

Subclasses System.Security.Cryptography.RSA. Constructor takes a
Pkcs11Key (does NOT take ownership). Overrides:

  SignData(byte[], HashAlgorithmName, RSASignaturePadding)
    PKCS#1 v1.5 → CKM_<hash>_RSA_PKCS
    PSS → CKM_<hash>_RSA_PKCS_PSS with CkmRsaPkcsPssParams

  VerifyData(...) — symmetric to Sign; uses Pkcs11Key.Verify which
  has the managed-fallback path for private-only keys via synthesized
  RSAParameters.

  Encrypt(byte[], RSAEncryptionPadding) / Decrypt(...)
    PKCS#1 → CKM_RSA_PKCS
    OAEP → CKM_RSA_PKCS_OAEP with CkmRsaPkcsOaepParams

  ExportParameters(bool includePrivateParameters)
    false → returns Modulus + Exponent from synthesized view or from
            the real public handle's attributes.
    true  → throws InsecureOperationException (PKCS#11 keys are
            non-extractable by design).

  ImportParameters — NotSupportedException with a redirect to
  Pkcs11Workspace.ImportKey.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `ECDsaPkcs11`

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/ECDsaPkcs11.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ECDsaPkcs11Tests.cs`

- [ ] **Step 1: Write the failing tests**

```csharp
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public sealed class ECDsaPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new ECDsaPkcs11(key: null!));
}

[Collection("SoftHsm")]
public sealed class ECDsaPkcs11Tests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public ECDsaPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignVerify_Sha256_RoundTrips()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));
        using var key = GenerateP256Key(workspace, out var pubH, out var privH);
        try
        {
            using var ec = new ECDsaPkcs11(key);
            byte[] data = System.Text.Encoding.UTF8.GetBytes("ecdsa test");

            byte[] sig = ec.SignData(data, HashAlgorithmName.SHA256);
            Assert.True(ec.VerifyData(data, sig, HashAlgorithmName.SHA256));

            data[0] ^= 0xFF;
            Assert.False(ec.VerifyData(data, sig, HashAlgorithmName.SHA256));
        }
        finally
        {
            if (!pubH.IsInvalid)  workspace.Session.DestroyObject(pubH);
            if (!privH.IsInvalid) workspace.Session.DestroyObject(privH);
        }
    }

    private static Pkcs11Key GenerateP256Key(Pkcs11Workspace workspace,
        out ObjectHandle pubH, out ObjectHandle privH)
    {
        string label = $"ec-prov-{Guid.NewGuid():N}";
        byte[] id = System.Text.Encoding.ASCII.GetBytes(label);
        byte[] p256Oid = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Label(label).Id(id).Verify().EcParams(p256Oid).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Label(label).Id(id).Sign().Build();

        var key = workspace.GenerateKey(
            new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), privTpl, pubTpl);
        pubH = key.PublicHandle;
        privH = key.PrivateHandle;
        return key;
    }
}
```

- [ ] **Step 2: Verify failure**

Expected: `ECDsaPkcs11` doesn't exist.

- [ ] **Step 3: Create `ECDsaPkcs11.cs`**

```csharp
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// BCL-aligned <see cref="ECDsa"/> provider backed by a PKCS#11 <see cref="Pkcs11Key"/>.
/// Does not take ownership of the underlying key.
/// </summary>
public sealed class ECDsaPkcs11 : ECDsa
{
    private readonly Pkcs11Key _key;

    /// <summary>Wraps the given key. The key must be an EC key.</summary>
    public ECDsaPkcs11(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_EC)
            throw new ArgumentException(
                $"Expected an EC key, got {key.KeyType}.", nameof(key));
        _key = key;
    }

    /// <inheritdoc/>
    public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(data);
        using var mech = Pkcs11MechanismMap.EcdsaSign(hashAlgorithm);
        return _key.Sign(mech, data);
    }

    /// <inheritdoc/>
    public override byte[] SignHash(byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(hash);
        using var mech = new Mechanism(CKM.CKM_ECDSA);
        return _key.Sign(mech, hash);
    }

    /// <inheritdoc/>
    public override bool VerifyData(byte[] data, byte[] signature, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        using var mech = Pkcs11MechanismMap.EcdsaSign(hashAlgorithm);
        return _key.Verify(mech, data, signature);
    }

    /// <inheritdoc/>
    public override bool VerifyHash(byte[] hash, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(signature);
        using var mech = new Mechanism(CKM.CKM_ECDSA);
        return _key.Verify(mech, hash, signature);
    }

    /// <inheritdoc/>
    public override ECParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
            throw new InsecureOperationException(
                "Refusing to export EC private parameters. PKCS#11 keys are non-extractable.");

        var synth = _key.GetSynthesizedEcParameters();
        if (synth is not null) return synth.Value;

        throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
            "ECDsaPkcs11.ExportParameters (synthesis unavailable; no public companion stored)");
    }

    /// <inheritdoc/>
    public override ECParameters ExportExplicitParameters(bool includePrivateParameters)
        => throw new NotSupportedException("Explicit (non-named-curve) parameter export is not supported.");

    /// <inheritdoc/>
    public override void ImportParameters(ECParameters parameters)
        => throw new NotSupportedException(
            "ECDsaPkcs11 wraps a PKCS#11 key handle; importing managed parameters is not supported.");

    /// <inheritdoc/>
    public override void GenerateKey(ECCurve curve)
        => throw new NotSupportedException(
            "Use Pkcs11Workspace.GenerateKey to generate keys on the token.");
}
```

- [ ] **Step 4–6: Run tests, full suite, commit**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~ECDsaPkcs11" -c Debug
dotnet test src/KerckhoffsLabs.sln -c Debug

git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/ECDsaPkcs11.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ECDsaPkcs11Tests.cs

git commit -m "$(cat <<'EOF'
feat(ECDsaPkcs11): BCL-aligned ECDsa provider backed by Pkcs11Key

Subclass of System.Security.Cryptography.ECDsa with the same
ownership model as RSAPkcs11. Overrides SignData / VerifyData (with
HashAlgorithmName), SignHash / VerifyHash (raw CKM_ECDSA), and
ExportParameters(false) which returns the synthesized ECParameters
view. ExportParameters(true) throws InsecureOperationException.
ImportParameters / GenerateKey / ExportExplicitParameters throw
NotSupportedException with redirects to the workspace API.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `AesGcmPkcs11`

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/AesGcmPkcs11.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/AesGcmPkcs11Tests.cs`

`AesGcm` is sealed; wrap it without inheriting. Method shape mirrors `AesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad)` / `Decrypt(...)`.

- [ ] **Step 1: Write the failing tests**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public sealed class AesGcmPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new AesGcmPkcs11(key: null!));
}

[Collection("SoftHsm")]
public sealed class AesGcmPkcs11Tests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public AesGcmPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptDecrypt_RoundTrips_WithAad()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = $"gcm-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t.Attributes.ToList());
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var gcm = new AesGcmPkcs11(key);

            byte[] nonce = new byte[12];
            for (int i = 0; i < nonce.Length; i++) nonce[i] = (byte)i;
            byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("AES-GCM round trip");
            byte[] aad = System.Text.Encoding.UTF8.GetBytes("associated-data");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

            byte[] decrypted = new byte[plaintext.Length];
            gcm.Decrypt(nonce, ciphertext, tag, decrypted, aad);

            Assert.Equal(plaintext, decrypted);
        }
        finally
        {
            using var f = ObjectTemplate.Empty().Label(label).Build();
            foreach (var k in workspace.FindKeys(f))
            {
                workspace.Session.DestroyObject(k.PrivateHandle);
                k.Dispose();
            }
        }
    }
}
```

- [ ] **Step 2: Verify failure**

Expected: `AesGcmPkcs11` doesn't exist.

- [ ] **Step 3: Create `AesGcmPkcs11.cs`**

```csharp
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// BCL-aligned <see cref="System.Security.Cryptography.AesGcm"/>-shaped wrapper over a
/// PKCS#11 AES key. <c>AesGcm</c> is sealed in the BCL so this is a wrapper, not a
/// subclass. Method shapes mirror the BCL.
/// </summary>
public sealed class AesGcmPkcs11
{
    /// <summary>BCL-equivalent supported tag-length range in bytes.</summary>
    public static System.Security.Cryptography.AesGcm.TagByteSizes TagByteSizes
        => System.Security.Cryptography.AesGcm.TagByteSizes;

    /// <summary>BCL-equivalent supported nonce-length range in bytes.</summary>
    public static System.Security.Cryptography.AesGcm.NonceByteSizes NonceByteSizes
        => System.Security.Cryptography.AesGcm.NonceByteSizes;

    private readonly Pkcs11Key _key;

    /// <summary>Wraps the given key. Must be a symmetric AES key (CKK_AES).</summary>
    public AesGcmPkcs11(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_AES)
            throw new ArgumentException(
                $"Expected an AES key, got {key.KeyType}.", nameof(key));
        _key = key;
    }

    /// <summary>Encrypts <paramref name="plaintext"/> into <paramref name="ciphertext"/> with the GCM tag in <paramref name="tag"/>.</summary>
    public void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (ciphertext.Length != plaintext.Length)
            throw new ArgumentException("ciphertext length must equal plaintext length.", nameof(ciphertext));

        using var mech = new Mechanism(CKM.CKM_AES_GCM,
            new CkmAesGcmParams(nonce, associatedData, tagBits: tag.Length * 8));

        // Session.Encrypt returns ciphertext || tag concatenated.
        byte[] result = _key.Encrypt(mech, plaintext);
        if (result.Length != plaintext.Length + tag.Length)
            throw new InvalidOperationException(
                $"AES-GCM encrypt returned {result.Length} bytes; expected {plaintext.Length + tag.Length}.");

        result.AsSpan(0, plaintext.Length).CopyTo(ciphertext);
        result.AsSpan(plaintext.Length, tag.Length).CopyTo(tag);
    }

    /// <summary>Decrypts <paramref name="ciphertext"/> with <paramref name="tag"/> into <paramref name="plaintext"/>.</summary>
    public void Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (plaintext.Length != ciphertext.Length)
            throw new ArgumentException("plaintext length must equal ciphertext length.", nameof(plaintext));

        using var mech = new Mechanism(CKM.CKM_AES_GCM,
            new CkmAesGcmParams(nonce, associatedData, tagBits: tag.Length * 8));

        // PKCS#11 expects ciphertext || tag concatenated.
        byte[] combined = new byte[ciphertext.Length + tag.Length];
        ciphertext.CopyTo(combined);
        tag.CopyTo(combined.AsSpan(ciphertext.Length));

        byte[] result = _key.Decrypt(mech, combined);
        if (result.Length != plaintext.Length)
            throw new InvalidOperationException(
                $"AES-GCM decrypt returned {result.Length} bytes; expected {plaintext.Length}.");
        result.CopyTo(plaintext);
    }
}
```

If `CkmAesGcmParams` ctor has a different parameter order or different param names, adapt to the actual signature from the inspection at the top of the plan.

- [ ] **Step 4–6: Run tests + suite + commit**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~AesGcmPkcs11" -c Debug
dotnet test src/KerckhoffsLabs.sln -c Debug

git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/AesGcmPkcs11.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/AesGcmPkcs11Tests.cs

git commit -m "$(cat <<'EOF'
feat(AesGcmPkcs11): AesGcm-shaped wrapper backed by Pkcs11Key

System.Security.Cryptography.AesGcm is sealed, so this is a wrapper
that mirrors its shape (Encrypt / Decrypt taking nonce, plaintext,
ciphertext, tag, aad as separate spans) rather than a subclass.
Internally translates to CKM_AES_GCM with CkmAesGcmParams; splits the
PKCS#11 ciphertext||tag concatenation back into separate spans for the
BCL-shaped output.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: `AesCcmPkcs11`

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/AesCcmPkcs11.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/AesCcmPkcs11Tests.cs`

Structurally identical to `AesGcmPkcs11`. Differences:
- Mechanism: `CKM.CKM_AES_CCM`.
- Params type: `CkmAesCcmParams` (verify existence in `HighLevel/MechanismParams/` first; if absent, build the params via raw byte array per the PKCS#11 spec layout).
- BCL static accessors come from `System.Security.Cryptography.AesCcm`.

Apply the same structure as Task 4 but substitute `Aes`→`Aes`, `Gcm`→`Ccm`, `AesGcm`→`AesCcm`, `CKM_AES_GCM`→`CKM_AES_CCM`, `CkmAesGcmParams`→`CkmAesCcmParams`.

**If `CkmAesCcmParams` does NOT exist in `HighLevel/MechanismParams/`,** report it as a `BLOCKED` status to the orchestrator — that param type needs to be authored separately before this task can proceed. Don't invent a partial implementation.

Commit message template:

```
feat(AesCcmPkcs11): AesCcm-shaped wrapper backed by Pkcs11Key

Mirrors the BCL AesCcm sealed shape over a CKM_AES_CCM mechanism
with CkmAesCcmParams. Structurally identical to AesGcmPkcs11
modulo the mechanism + params.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

---

### Task 6: `ChaCha20Poly1305Pkcs11`

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/ChaCha20Poly1305Pkcs11.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/ChaCha20Poly1305Pkcs11Tests.cs`

Structurally identical to `AesGcmPkcs11`. Differences:
- Key type guard: `CKK.CKK_CHACHA20` (verify enum-member name; some codebases call it `CKK_CHACHA20_POLY1305`).
- Mechanism: `CKM.CKM_CHACHA20_POLY1305`.
- Params type: `CkmSalsa20ChaCha20Poly1305Params` (exists per the file listing).
- Tag length is fixed at 16 bytes (128 bits).
- BCL static accessors come from `System.Security.Cryptography.ChaCha20Poly1305`.

Commit message:

```
feat(ChaCha20Poly1305Pkcs11): ChaCha20Poly1305-shaped wrapper

Mirrors the BCL ChaCha20Poly1305 sealed shape over CKM_CHACHA20_POLY1305
with CkmSalsa20ChaCha20Poly1305Params. Structurally identical to
AesGcmPkcs11 modulo the mechanism + params.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

---

### Task 7: `HMACPkcs11`

**Files:**
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/HMACPkcs11.cs`
- Create: `src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/HMACPkcs11Tests.cs`

Subclass of `HMAC`. Override `HashSize`, `HashCore`, `HashFinal`, `Initialize` (or use a simpler `ComputeHash` approach).

Strategy: since `HMAC` is designed around streaming HashCore/HashFinal, but the PKCS#11 surface is one-shot via `Pkcs11Key.Sign(Mechanism, data)`, buffer incoming HashCore calls into a `MemoryStream` and produce the HMAC on `HashFinal`. This is the same compromise the BCL Pkcs11 wrappers in other projects use.

- [ ] **Step 1: Write the failing tests**

```csharp
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public sealed class HMACPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new HMACPkcs11(key: null!, HashAlgorithmName.SHA256));
}

[Collection("SoftHsm")]
public sealed class HMACPkcs11Tests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public HMACPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_Sha256_DeterministicForSameKeyAndInput()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = $"hmac-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).ValueLen(32).Sign().Verify().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), t.Attributes.ToList());
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA256);

            byte[] data = System.Text.Encoding.UTF8.GetBytes("hmac test data");
            byte[] mac1 = hmac.ComputeHash(data);
            byte[] mac2 = hmac.ComputeHash(data);

            Assert.Equal(32, mac1.Length);
            Assert.Equal(mac1, mac2);
        }
        finally
        {
            using var f = ObjectTemplate.Empty().Label(label).Build();
            foreach (var k in workspace.FindKeys(f))
            {
                workspace.Session.DestroyObject(k.PrivateHandle);
                k.Dispose();
            }
        }
    }
}
```

- [ ] **Step 2: Verify failure + Step 3: Create `HMACPkcs11.cs`**

```csharp
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// BCL-aligned <see cref="HMAC"/> provider backed by a PKCS#11 secret key (typically
/// <see cref="CKK.CKK_GENERIC_SECRET"/>). Does not take ownership of the underlying key.
/// </summary>
public sealed class HMACPkcs11 : HMAC
{
    private readonly Pkcs11Key _key;
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly System.IO.MemoryStream _buffer = new();

    /// <summary>Wraps the given key and binds it to a hash algorithm.</summary>
    public HMACPkcs11(Pkcs11Key key, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(key);
        _key = key;
        _hashAlgorithm = hashAlgorithm;
        HashName = hashAlgorithm.Name;
        HashSizeValue = HashSizeFromName(hashAlgorithm) * 8;
    }

    /// <inheritdoc/>
    public override void Initialize() => _buffer.SetLength(0);

    /// <inheritdoc/>
    protected override void HashCore(byte[] array, int ibStart, int cbSize)
        => _buffer.Write(array, ibStart, cbSize);

    /// <inheritdoc/>
    protected override void HashCore(ReadOnlySpan<byte> source)
        => _buffer.Write(source);

    /// <inheritdoc/>
    protected override byte[] HashFinal()
    {
        using var mech = Pkcs11MechanismMap.HmacGeneral(_hashAlgorithm);
        byte[] data = _buffer.ToArray();
        _buffer.SetLength(0);
        return _key.Sign(mech, data);
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing) _buffer.Dispose();
        base.Dispose(disposing);
    }

    private static int HashSizeFromName(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA1"   => 20,
        "SHA256" => 32,
        "SHA384" => 48,
        "SHA512" => 64,
        _ => throw new NotSupportedException($"Unsupported hash: {hash.Name}."),
    };
}
```

- [ ] **Step 4–6: Run tests + suite + commit**

```bash
dotnet test src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.csproj \
  --filter "FullyQualifiedName~HMACPkcs11" -c Debug
dotnet test src/KerckhoffsLabs.sln -c Debug

git add src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/HMACPkcs11.cs \
        src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/HighLevel/HMACPkcs11Tests.cs

git commit -m "$(cat <<'EOF'
feat(HMACPkcs11): HMAC provider backed by Pkcs11Key

Subclass of System.Security.Cryptography.HMAC bound to a PKCS#11 secret
key (typically CKK_GENERIC_SECRET) and a HashAlgorithmName. Buffers
HashCore writes into a MemoryStream, then drives the one-shot
Pkcs11Key.Sign(CKM_<hash>_HMAC, data) on HashFinal. The buffer is
reused on Initialize.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Final sanity sweep

- [ ] **Step 1: Confirm all 6 providers exist**

```bash
cd /home/alexandre/dev/PKCS11.NET
ls src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/{RSAPkcs11,ECDsaPkcs11,AesGcmPkcs11,AesCcmPkcs11,ChaCha20Poly1305Pkcs11,HMACPkcs11}.cs
```

Expected: 6 files listed, no errors.

- [ ] **Step 2: Confirm no `throw new Pkcs11` regressions**

```bash
grep -rn "throw new Pkcs11" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/
```

Expected: no output.

- [ ] **Step 3: Confirm no `ExceptionMapper.Map` leaks**

```bash
grep -rn "ExceptionMapper\.Map" src/KerckhoffsLabs.Security.Cryptography.Pkcs11/ \
  | grep -v "Common/ExceptionMapper\.cs\|Common/Pkcs11Exception\.cs"
```

Expected: no output.

- [ ] **Step 4: Confirm provider class declarations**

```bash
grep -nE "public sealed class (RSAPkcs11|ECDsaPkcs11|AesGcmPkcs11|AesCcmPkcs11|ChaCha20Poly1305Pkcs11|HMACPkcs11)" \
  src/KerckhoffsLabs.Security.Cryptography.Pkcs11/HighLevel/
```

Expected: 6 matches, one per provider.

- [ ] **Step 5: Full test suite**

```bash
dotnet test src/KerckhoffsLabs.sln -c Debug
```

Expected: 0 failures. Test count grows by:
- `Pkcs11MechanismMapTests`: ~14
- `RSAPkcs11Tests`: 6 (1 arg + 5 SoftHsm)
- `ECDsaPkcs11Tests`: 2 (1 arg + 1 SoftHsm)
- `AesGcmPkcs11Tests`: 2
- `AesCcmPkcs11Tests`: 2
- `ChaCha20Poly1305Pkcs11Tests`: 2
- `HMACPkcs11Tests`: 2

≈ 30 new tests. SoftHSM-only ones skip cleanly without the backend.

- [ ] **Step 6: Release build**

```bash
dotnet build src/KerckhoffsLabs.sln -c Release
```

Expected: 0 errors.

- [ ] **Step 7: Report completion**

No commit for the sanity sweep — verification only.

---

## Self-review

**Spec coverage:**
- ✅ `RSAPkcs11` (decision §2) — Task 2.
- ✅ `ECDsaPkcs11` (decision §2) — Task 3.
- ⏳ `ECDiffieHellmanPkcs11` (decision §2) — **deferred to a follow-up plan** (DeriveKeyMaterial complexity).
- ⏳ `AesPkcs11` (decision §2, "CBC/CTR/ECB") — **deferred** (ICryptoTransform complexity).
- ✅ `AesGcmPkcs11` (decision §2) — Task 4.
- ✅ `AesCcmPkcs11` (decision §2) — Task 5.
- ✅ `ChaCha20Poly1305Pkcs11` (decision §2) — Task 6.
- ✅ `HMACPkcs11` (decision §2) — Task 7.
- ✅ Ownership rule (provider does NOT own the key) — applied in every provider ctor.
- ✅ Synthesized-public fallback via `Pkcs11Key.Get*Parameters` — used by `RSAPkcs11.ExportParameters(false)` and inherited by `Verify` paths from Plan 2.
- ✅ Refusal to export private parameters — `InsecureOperationException` on `ExportParameters(true)`.

**Placeholder scan:** none.

**Type / signature consistency:**
- All providers take `Pkcs11Key` (not `ObjectHandle` directly).
- All providers are `public sealed class`.
- All ctor null guards via `ArgumentNullException.ThrowIfNull`.
- All providers use `Pkcs11MechanismMap` (not their own private maps) for translation.

---

## Execution handoff

Plan complete. Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task with two-stage review (used for Plans 1 & 2).
2. **Inline execution** via `executing-plans`.
