# Using crypto policies

Every `Pkcs11Workspace` enforces a **crypto policy**. Before an operation reaches the token, the workspace
asks its policy whether the mechanism, its parameters, the key being generated or the secret being read
back is acceptable, and throws `CryptoPolicyViolationException` when it is not. This page shows how to
choose a policy, react to a refusal, and widen or tighten a policy for exactly what your application
needs.

What each built-in policy allows, for which operations and why, is listed on its reference page:
[Recommended](policies/recommended.md) and [NistApproved](policies/nist-approved.md).

The examples use the namespaces `KerckhoffsLabs.Security.Cryptography.Pkcs11` and its `.Common`,
`.MechanismParams`, `.Policy` and `.Exceptions` sub-namespaces.

## Choosing a policy

| Policy | Use it when | Overrides (`UsePolicy`) |
|---|---|---|
| `CryptoPolicy.Recommended` (default) | You want the library's reviewed, modern allow-list. | Allowed |
| `CryptoPolicy.NistApproved` | Only NIST-approved security functions may be used. | Refused |
| `CryptoPolicy.AllowInsecure` | One scoped legacy operation, as a last resort. | — |
| A policy you derive or build | You need exactly one more thing, or less than a built-in allows. | You choose |

`Recommended` and `NistApproved` can be revised between releases as guidance changes, usually by tightening;
each release's verdicts are pinned by a committed snapshot in the repository. A policy derived with `ToBuilder`
copies the built-in's rules from the library version it runs with, so it follows those revisions too. Check the
release notes and test the operations your application depends on when you upgrade.

The policy is chosen when the workspace is opened:

```csharp
using var library = Pkcs11Library.Load(modulePath);
using var pin = new SecurePin(pinFromYourSecretStore);

// Default: Recommended.
using var workspace = library.OpenWorkspaceWithPin(tokenLabel, CKU.CKU_USER, pin);

// NistApproved: overrides are refused for the workspace's lifetime.
using var fips = library.OpenWorkspaceWithPin(tokenLabel, CKU.CKU_USER, pin, CryptoPolicy.NistApproved);
```

> `NistApproved` restricts what this library sends to the token; it is not a FIPS 140-3 certification, which
> also requires a validated module operating in its approved mode.

## Handling a refusal

A refusal is a `CryptoPolicyViolationException`, a `CryptographicException`. It names the policy, the
request and the reason, and the reason says how to proceed:

```csharp
try
{
    using var aes = new AesPkcs11(key);
    aes.DecryptCbc(ciphertext, iv);
}
catch (CryptoPolicyViolationException ex)
{
    logger.LogWarning("{Policy} refused {Request}: {Reason}", ex.PolicyName, ex.Request, ex.Reason);
    throw;
}
```

The workspace logs every refusal at `Warning` too. To choose between alternatives without throwing — for
example the first cipher mode the policy accepts — ask first:

```csharp
var gcm = new MechanismUseRequest(new Mechanism(CKM.CKM_AES_GCM), CryptoOperation.Encrypt);
if (key.IsPermitted(gcm)) { /* use AES-GCM */ }

// For a choice the token never sees, such as the hash of a managed pre-hashing step:
key.EnsurePermitted(new HashUseRequest(HashAlgorithmName.SHA256, CryptoOperation.Sign));
```

## Allowing one more thing

When `Recommended` refuses something you have reviewed and need, derive your own policy from it. The copy
keeps every rule, adds only the exceptions you name, each with its reason, and carries your name in logs
and refusals. `ToBuilder` never modifies `CryptoPolicy.Recommended` itself.

```csharp
ComposedCryptoPolicy policy = CryptoPolicy.Recommended.ToBuilder("MyApp")
    .AllowMechanism(
        (CKM)0x8000_1001UL,                                   // your vendor's CK_MECHANISM_TYPE
        [CryptoOperation.Sign, CryptoOperation.Verify],
        "Vendor HSM signature scheme, reviewed for our release signing.")
    .Build();

using var workspace = library.OpenWorkspaceWithPin(tokenLabel, CKU.CKU_USER, pin, policy);
```

| Refused | Narrow opt-in on `CryptoPolicyBuilder` |
|---|---|
| A mechanism (legacy, vendor-defined, or an operation it is not allowed for) | `AllowMechanism(mechanism, operations, reason)` |
| A mechanism, for decrypting or verifying old data only | `AllowMechanismForLegacyUse(mechanism, operations, reason)` |
| A hash used on the managed side (a pre-hash, an HMAC) | `AllowHash(hash, operations, reason)` |
| An EC curve below the 128-bit baseline | `AllowCurve(curve, reason)` |
| A key-agreement KDF (e.g. `CKD_NULL` for an on-token key) | `AllowKeyAgreementKdf(kdf, reason)` |
| Key agreement with an existing key of a type | `AllowKeyAgreementKeyType(keyType, reason)` |
| Reading one kind of secret off the token | `AllowSecretExport(kind, reason)` |

Allowing a mechanism that is already allowed adds operations and keeps its existing parameter check (see
[Building a policy from scratch](#building-a-policy-from-scratch)); a different check is refused, so remove
the mechanism first to replace it. ECDH mechanisms require
`MechanismChecks.Ecdh1DeriveParams()`, so the policy's key-agreement KDF list cannot be bypassed.

Prefer allowing the one mechanism you need, for legacy use only (`AllowMechanismForLegacyUse`). For one legacy
operation with no reviewed alternative, lift the policy for a single scoped block. The lease applies to the
whole workspace — every thread using it — and for its duration allows everything, including every secret
export and non-sensitive key templates. It is refused on a `NistApproved` workspace:

```csharp
using (workspace.UsePolicy(CryptoPolicy.AllowInsecure))
{
    // decrypt one legacy archive
}
```

Enabling a specific legacy algorithm is described in [Legacy algorithms](legacy-algorithms.md).

## Allowing less

Tighten a copy the same way: remove what you do not use, or replace a rule.

```csharp
ComposedCryptoPolicy strict = CryptoPolicy.Recommended.ToBuilder("SigningService")
    .RemoveMechanism(CKM.CKM_AES_KEY_WRAP_PAD)                          // vendor-defined padding
    .WithRsaKeyGenerationRule(RsaKeyGenerationRule.Minimum(3072))
    .Build();
```

A mechanism a policy removed is refused as "removed from its allow-list", not as unreviewed.

## Building a policy from scratch

`new CryptoPolicyBuilder(name)` starts empty: it denies every mechanism, requires a 2048-bit RSA
minimum, refuses non-sensitive key templates and refuses every secret export. Allow only what the
application uses:

```csharp
ComposedCryptoPolicy minimal = new CryptoPolicyBuilder("TokenSigner")
    .AllowMechanism(CKM.CKM_EC_KEY_PAIR_GEN, [CryptoOperation.GenerateKeyPair], "Key generation.")
    .AllowMechanism(CKM.CKM_ECDSA_SHA256, [CryptoOperation.Sign, CryptoOperation.Verify], "ES256 signatures.")
    // ECDsaPkcs11 falls back to raw CKM_ECDSA over a managed SHA-256 digest on tokens without CKM_ECDSA_SHA256.
    .AllowMechanism(CKM.CKM_ECDSA, [CryptoOperation.Sign, CryptoOperation.Verify], "ES256 on tokens without the combined mechanism.")
    .AllowHash(HashAlgorithmName.SHA256, [CryptoOperation.Sign, CryptoOperation.Verify], "ES256 digest.")
    .AllowCurve(Pkcs11ECCurve.NamedCurves.NistP256, "ES256 curve.")
    .AllowsOverride(false)
    .Build();
```

A mechanism whose parameters matter can carry a check from `MechanismChecks`, so the token never receives
weak parameters through it — here, nothing shorter than a 128-bit tag:

```csharp
ComposedCryptoPolicy records = new CryptoPolicyBuilder("RecordStore")
    .AllowMechanism(CKM.CKM_AES_KEY_GEN, [CryptoOperation.GenerateKey], "Record keys.")
    .AllowMechanism(CKM.CKM_AES_GCM, [CryptoOperation.Encrypt, CryptoOperation.Decrypt],
        "AES-GCM for record encryption.", MechanismChecks.GcmTagLength(128))
    .Build();
```

The checks available are `OaepHash`, `RsaPss`, `PqcPreHash`, `GcmTagLength`, `CcmMacLength`,
`Pbkdf2Prf`, `Sp800108Prf`, `HkdfPrf` and `Ecdh1DeriveParams`.

`ToBuilder(name)` works on any `ComposedCryptoPolicy`, so a policy you built can be copied and adjusted in
turn. The names `Recommended` and `NistApproved` are reserved for the built-ins. A copy of `NistApproved` keeps
refusing overrides unless you call `AllowsOverride(true)`.

## Reading a secret back

Derived and shared secrets stay on the token by default: `Pkcs11Key.Derive`, `EncapsulateKey`,
`DecapsulateKey` and `Pkcs11Workspace.DeriveSharedSecretEcdh` return sensitive keys. When a protocol needs
the bytes in managed code — a BCL-shaped KDF, a TLS or Noise key schedule — use a read-back operation, and
allow that one kind of secret:

```csharp
ComposedCryptoPolicy policy = CryptoPolicy.Recommended.ToBuilder("MyApp")
    .AllowSecretExport(SecretExportKind.EcdhSharedSecret, "Z feeds our protocol's key schedule; reviewed.")
    .Build();
using var workspace = library.OpenWorkspaceWithPin(tokenLabel, CKU.CKU_USER, pin, policy);
using var key = workspace.OpenKey("ecdh-key");

Span<byte> z = stackalloc byte[32];                           // P-256: one 32-byte field element
try
{
    key.DeriveAndExportSecret(
        new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForPeer(CKD.CKD_NULL, peerPublicKey)), z);
    // Z is raw keying material: feed it to your protocol's KDF, never use it as a key directly.
}
finally
{
    CryptographicOperations.ZeroMemory(z);
}
```

For an X25519 or X448 key, the peer is its public u-coordinate (32 or 56 bytes, as RFC 7748 encodes it), passed
to the constructor; the destination is 32 or 56 bytes:

```csharp
key.DeriveAndExportSecret(
    new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, peerU)), sharedSecret);
```

| Operation | Mechanisms | Export kind |
|---|---|---|
| `Pkcs11Key.DeriveAndExportSecret` | `CKM_ECDH1_DERIVE` / `CKM_ECDH1_COFACTOR_DERIVE` from a `CKK_EC` key (peer point checked against its curve) or an X25519 / X448 key (peer size and low-order points checked) | `EcdhSharedSecret` |
| | `CKM_HKDF_DERIVE` (no salt key), SP 800-108 counter / feedback / double-pipeline (no additional keys, no key segments) | `KdfOutput` |
| `Pkcs11Workspace.DeriveAndExportSecret` | `CKM_PKCS5_PBKD2` | `PasswordKdfOutput` |
| `Pkcs11Key.EncapsulateAndExportSecret` / `DecapsulateAndExportSecret` (experimental, [`KLPKCS11501`](diagnostics.md#KLPKCS11501)) | `CKM_ML_KEM` | `KemSharedSecret` |

Any other mechanism or parameter shape is refused whatever the policy: several derivation mechanisms would
return the base key itself, an encryption of it, or a function of a second key the export decision never
saw. The secret passes through an ephemeral session key that the library creates, reads and destroys while
holding the session, so no other caller of that session can reach it; another session of the same application
could still find it while it exists, as PKCS#11 makes session objects visible to all of an application's
sessions. An allowed export is logged at `Information` once the secret has left the token.
The BCL adapters that return bytes (`ECDiffieHellmanPkcs11`, `MLKemPkcs11`, `HkdfPkcs11`,
`SP800108HmacCounterKdfPkcs11`, `Rfc2898DeriveBytesPkcs11`) are built on these operations and need the
same opt-in.

## Writing your own policy

`ICryptoPolicy` is a single method over a closed set of request types. Delegate to a built-in for what you
do not decide, and deny what you do not recognise, so request kinds added in later versions fail closed:

```csharp
sealed class NoExportAfterHours(ICryptoPolicy inner, TimeProvider clock) : ICryptoPolicy
{
    public string Name => $"{inner.Name}+NoExportAfterHours";
    public bool AllowsOverride => false;

    public PolicyDecision Evaluate(PolicyRequest request) => request switch
    {
        SecretExportRequest when clock.GetLocalNow().Hour is < 8 or >= 18 =>
            PolicyDecision.Deny("Secret export is allowed during business hours only."),
        _ => inner.Evaluate(request),
    };
}
```

Prefer deriving a `ComposedCryptoPolicy` when an allow-list change is all you need: it keeps the
built-in's parameter checks and refusal wording, and its catalogue can be documented.
