# Using crypto policies

Every `Pkcs11Session` enforces a **crypto policy**. Before an operation reaches the token, the session
asks its policy whether the mechanism, its parameters, the key being generated or the secret being read
back is acceptable, and throws `CryptoPolicyViolationException` when it is not. This page shows how to
choose a policy, react to a refusal, and widen or tighten a policy for exactly what your application
needs.

What each built-in policy allows, for which operations and why, is listed on its reference page:
[Recommended](policies/recommended.md), [NistApproved](policies/nist-approved.md) and
[Cnsa20](policies/cnsa-2.0.md).
Why the policies exist, what they protect against and where their protection ends is explained in the
[security model](security-model.md#crypto-policies).

The examples use the namespaces `KerckhoffsLabs.Security.Cryptography.Pkcs11` and its `.Common`,
`.MechanismParams`, `.Policy` and `.Exceptions` sub-namespaces.

## Choosing a policy

| Policy | Use it when | Overrides (`UsePolicy`) |
|---|---|---|
| `CryptoPolicy.Recommended` (default) | You want the library's reviewed, modern allow-list. | Allowed |
| `CryptoPolicy.NistApproved` | Only NIST-approved security functions may be used. | Refused |
| `CryptoPolicy.Cnsa20` | Only CNSA 2.0 algorithms and sizes may be used. | Refused |
| `CryptoPolicy.AllowInsecure` | One scoped legacy operation, as a last resort. | — |
| A policy you derive or build | You need exactly one more thing, or less than a built-in allows. | You choose |

`Recommended`, `NistApproved` and `Cnsa20` can be revised between releases as guidance changes, usually by
tightening; each release's verdicts are pinned by a committed snapshot in the repository. A policy derived with `ToBuilder`
copies the built-in's rules from the library version it runs with, so it follows those revisions too. Check the
release notes and test the operations your application depends on when you upgrade.

The policy is chosen when the session is opened:

```csharp
using var library = Pkcs11Library.Load(modulePath);
using var pin = new SecurePin(pinFromYourSecretStore);

// Default: Recommended.
using var session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

// NistApproved: overrides are refused for the session's lifetime.
using var fips = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin, CryptoPolicy.NistApproved);
```

> `NistApproved` restricts what this library sends to the token; it is not a FIPS 140-3 certification, which
> also requires a validated module operating in its approved mode.

### CNSA 2.0

`CryptoPolicy.Cnsa20` allows only the NSA CNSA 2.0 suite: AES-256 in GCM (128-bit tag only) and KW/KWP,
SHA-384/512 and HMAC over them, SP 800-108 and HKDF over SHA-384/512, ML-KEM-1024, ML-DSA-87, single-level
LMS (HSS) and XMSS. RSA, elliptic curves, SLH-DSA, HashML-DSA, the other AES modes, SHA-256 and PBKDF2 are
refused; the [catalogue](policies/cnsa-2.0.md) gives the CNSA 2.0 alternative for each.

It is the only built-in that **inspects keys**. The session reads each key's `CKA_KEY_TYPE` and its
`CKA_VALUE_LEN`, `CKA_PARAMETER_SET` or `CKA_HSS_LEVELS`: in the template before the token creates a key, from
the key the token created (destroying it if it fails), and from an existing key each time it is used. A key
generated as AES-128 or ML-DSA-65 under `Recommended` is refused when used under `Cnsa20`.

```csharp
using var cnsa = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin, CryptoPolicy.Cnsa20);
```

- **It fails closed.** A key whose type, length, parameter set or HSS levels the token does not report (absent,
  sensitive or unavailable) is refused: the reason says the token did not report it, so CNSA 2.0 compliance
  can't be verified. On a token that hides these attributes, compliant keys cannot be used.
- **LMS and XMSS are allowed for any signing.** CNSA 2.0 intends them for software and firmware signing; the
  policy cannot see what is being signed, so restricting them to that use is the application's job. XMSS
  parameter sets are not checked.
- **It is not a certification.** It restricts what this library sends to the token; it does not certify or
  validate the application or the token. Its CNSA 2.0 citations come from secondary sources and are pending
  verification against the NSA documents.
- **Each keyed operation costs one or two extra attribute reads** (`C_GetAttributeValue`); keys are read again on
  every use, never cached.
- `C_SetOperationState` restores a saved operation whose own mechanism and key are not inspected; only the key
  handles passed to it are.
- Keys returned through TLS/SSL3 key-and-MAC parameters are not judged after creation. `Cnsa20` refuses those
  mechanisms, but a policy derived from it that allows them again would not judge those keys.
- Some tokens (SoftHSM2) do not report `CKA_VALUE_LEN` on unwrapped secret keys; under `Cnsa20` those unwraps
  are refused.
- A custom policy that wraps `Cnsa20` must forward `InspectsKeys`, or key sizes are no longer checked (see
  [Writing your own policy](#writing-your-own-policy)).

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

using var session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin, policy);
```

| Refused | Narrow opt-in on `CryptoPolicyBuilder` |
|---|---|
| A mechanism (legacy, vendor-defined, or an operation it is not allowed for) | `AllowMechanism(mechanism, operations, reason)` |
| A mechanism, for decrypting or verifying old data only | `AllowMechanismForLegacyUse(mechanism, operations, reason)` |
| A hash used on the managed side (a pre-hash, an HMAC) | `AllowHash(hash, operations, reason)` |
| An EC curve below the 128-bit baseline | `AllowCurve(curve, reason)` |
| A key-agreement KDF | `AllowKeyAgreementKdf(kdf, reason)` |
| Key agreement with an existing key of a type | `AllowKeyAgreementKeyType(keyType, reason)` |

Allowing a mechanism that is already allowed adds operations and keeps its existing parameter check (see
[Building a policy from scratch](#building-a-policy-from-scratch)); a different check is refused, so remove
the mechanism first to replace it. ECDH mechanisms require
`MechanismChecks.Ecdh1DeriveParams()`, so the policy's key-agreement KDF list cannot be bypassed.

Prefer allowing the one mechanism you need, for legacy use only (`AllowMechanismForLegacyUse`). For one legacy
operation with no reviewed alternative, lift the policy for a single scoped block. The lease applies to the
whole session — every thread using it — and for its duration allows everything, including reading secrets
off the token and non-sensitive key templates. It is refused on a `NistApproved` session:

```csharp
using (session.UsePolicy(CryptoPolicy.AllowInsecure))
{
    // decrypt one legacy archive
}
```

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
minimum, refuses non-sensitive key templates and refuses reading secrets off the token. Allow only what the
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
turn. The names `Recommended`, `NistApproved` and `Cnsa20` are reserved for the built-ins. A copy of `NistApproved`
or `Cnsa20` keeps refusing overrides unless you call `AllowsOverride(true)`, and a copy of `Cnsa20` keeps
inspecting keys.

## Writing your own policy

`ICryptoPolicy` is essentially a single method over a closed set of request types. Delegate to a built-in for what you
do not decide, and deny what you do not recognise, so request kinds added in later versions fail closed:

```csharp
sealed class NoExportAfterHours(ICryptoPolicy inner, TimeProvider clock) : ICryptoPolicy
{
    public string Name => $"{inner.Name}+NoExportAfterHours";
    public bool AllowsOverride => false;
    public bool InspectsKeys => inner.InspectsKeys;

    public PolicyDecision Evaluate(PolicyRequest request) => request switch
    {
        KeyMaterialExportRequest when clock.GetLocalNow().Hour is < 8 or >= 18 =>
            PolicyDecision.Deny("Reading secrets off the token is allowed during business hours only."),
        _ => inner.Evaluate(request),
    };
}
```

Forward `InspectsKeys` as well: it defaults to `false`, and a session only reads a key's type and size from the
token when its policy says it inspects keys, so a wrapper that leaves it out silently turns off `Cnsa20`'s
key-size checks.

Prefer deriving a `ComposedCryptoPolicy` when an allow-list change is all you need: it keeps the
built-in's parameter checks and refusal wording, and its catalogue can be documented.
