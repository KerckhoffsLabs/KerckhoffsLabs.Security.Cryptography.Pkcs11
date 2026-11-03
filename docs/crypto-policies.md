# Using crypto policies

Every `Pkcs11Session` enforces a **crypto policy**. Before an operation reaches the token, the session
asks its policy whether the mechanism, its parameters, the key being generated or the secret being read
back is acceptable, and throws `CryptoPolicyViolationException` when it is not. This page shows how to
choose a policy, react to a refusal, and widen or tighten a policy for exactly what your application
needs.

What each built-in policy allows, for which operations and why, is listed on its reference page:
[Recommended](policies/recommended.md) and [NistApproved](policies/nist-approved.md).
Why the policies exist, what they protect against and where their protection ends is explained in the
[security model](security-model.md#crypto-policies).

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
| Reading secret key material off the token | `WithKeyMaterialExportRule(KeyMaterialExportRule.Allow(kinds, reason, kdfBaseKeys, privateKeys))`, see [below](#reading-secret-key-material-off-the-token) |

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

## Reading secret key material off the token

Every built-in policy refuses to read secret key material off the token in the clear. Keep secrets on the
token where you can: `Pkcs11Key.DeriveSecretAgreement` (EC, X25519 and X448) then `Pkcs11Key.Derive` to a
sensitive key, `EncapsulateKey` / `DecapsulateKey`. Where an
application genuinely needs the bytes (a drop-in class whose contract returns a shared secret, a value a
protocol sends or compares), opt in for exactly the kinds it needs, over exactly the keys it needs them for, with
a reason:

```csharp
#pragma warning disable KLPKCS11012 // the X25519 secret feeds <protocol>'s managed key schedule, see <ticket>
ComposedCryptoPolicy exportPolicy = CryptoPolicy.Recommended.ToBuilder("MyApp X25519 export")
    .WithKeyMaterialExportRule(KeyMaterialExportRule.Allow(
        [KeyMaterialExportKind.EcdhSharedSecret],
        "X25519 shared secret of an ephemeral key, for <protocol>'s managed key schedule.",
        privateKeys: PrivateKeyScope.SessionObjects))
    .Build();
#pragma warning restore KLPKCS11012
```

| Kind | What it lets the session return | Scope it needs |
|---|---|---|
| `EcdhSharedSecret` | The raw shared secret Z of an ECDH agreement: `Pkcs11Key.DeriveRawSecret` for EC (`CKK_EC`) and X25519 / X448 (`CKK_EC_MONTGOMERY`) keys, and `ECDiffieHellmanPkcs11`'s derive methods | `privateKeys`, see [the private-key scope](#private-key-scope) |
| `KemSharedSecret` | An ML-KEM shared secret: `MLKemPkcs11` encapsulate / decapsulate | `privateKeys` (judged on decapsulation only) |
| `KdfOutput` | KDF output: `Pkcs11Key.DeriveBytes`, `HkdfPkcs11`, `SP800108HmacCounterKdfPkcs11`, `Rfc2898DeriveBytesPkcs11` | `kdfBaseKeys`, see [the base-key scope](#kdfoutput-base-key-scope) |

Every kind is scoped by the on-token key the secret comes from, and **there is no default scope**: `Allow` throws
when a kind it names has no scope, and when a scope is given for a kind it does not name. Each scope's presets
rely on something the token or the deployment has to get right (described below), so the choice is the caller's
to make and to justify.

`Allow` also copies the kinds and throws on an empty list, an undefined kind or a blank reason. It refuses every
kind it does not name exactly as `KeyMaterialExportRule.Refuse()` does. Its reason and scopes are shown in the
policy catalogue. An export is logged once the secret has actually been read and checked (a read-back the token or
a later policy check stops logs nothing): the first export of a kind a policy allows on a session logs a
`KeyMaterialExportAllowed` warning naming the kind and the policy, never the secret, and every later one of
that kind under that policy logs the same at Debug, so a hot KDF path does not flood the log. Every `Allow`
call site (and method-group reference) is reported at build time as
[KLPKCS11012](diagnostics.md#KLPKCS11012), so the opt-in is visible in review; suppress it with a
justification.

<a id="where-to-apply-an-export-opt-in"></a>
#### Where to apply the opt-in

An export rule allows the read to every caller of every session whose policy carries it. So keep it off the
policy your sessions are opened with, and apply it only where the bytes are needed:

- **A scoped lease around the code that needs the bytes**, when nothing else uses the session meanwhile. The
  lease applies to the whole session (every thread using it, not just the caller's) until it is disposed:

  ```csharp
  using (session.UsePolicy(exportPolicy))
  {
      byte[] z = ephemeral.DeriveRawSecret(peerSpki);
      // ... feed z to the managed key schedule, then zero it
  }
  ```

- **A session of its own**, opened with the export policy, for code that runs the export on its own threads (a
  drop-in layer whose agreement, KEM or KDF interface returns bytes) or for a session opened under a policy that
  refuses leases (`AllowsOverride` false, such as `NistApproved`). Keep long-lived keys the scopes do not admit
  out of it.

Build the export policy from the session's own (`ToBuilder`), so the lease or session loosens nothing but the
export.

<a id="private-key-scope"></a>
#### The `EcdhSharedSecret` / `KemSharedSecret` private-key scope

The secret an agreement or a decapsulation reads depends only on the private key and public inputs: the peer's
public key, or the KEM ciphertext. So over a long-lived private key, the read turns the key into an oracle for
everything it has protected. `DeriveRawSecret` with a recorded peer public key returns the same Z that an earlier
`DeriveSecretAgreement` kept on the token, and so every key derived from Z. An ML-KEM decapsulation of a recorded
ciphertext returns the shared secret that `DecapsulateKey` kept on the token. Before it asks the policy, the
library reads the private key (`KeyMaterialExportRequest.PrivateKey`: its type, `CKA_ID`, `CKA_LABEL`,
`CKA_TOKEN`, `CKA_ALWAYS_SENSITIVE` and `CKA_NEVER_EXTRACTABLE`, off the private object), and the rule checks it
against a `PrivateKeyScope`:

| Scope | Private keys it admits |
|---|---|
| `PrivateKeyScope.SessionObjects` | Keys that are session objects (`CKA_TOKEN` false): ephemeral keys, such as the key pair of an ephemeral-static agreement or one generated for a single KEM exchange. A persistent token key is refused |
| `PrivateKeyScope.None` | No key: only a KEM encapsulation, which uses no private key and returns a fresh secret. Every agreement and decapsulation is refused |
| `PrivateKeyScope.Where(predicate, description)` | What the predicate decides from `ExportKeyInfo`; it decides alone |
| `PrivateKeyScope.Any` | Every private key the session can use, long-lived token keys included. Name it only when reproducing what earlier agreements or decapsulations kept on the token is acceptable |

A KEM encapsulation is in every scope. An attribute the token does not report reads as a token object, so an
unknown key is never taken for an ephemeral one.

`SessionObjects` relies on `CKA_TOKEN`, which cannot change on an existing object. A session copy of a token key
(`C_CopyObject`, which the library does not expose) would pass it, so keep a vendor tool or another library from
copying long-lived private keys into sessions whose policy allows these kinds, or create those keys
`CKA_COPYABLE=false`.

<a id="kdfoutput-base-key-scope"></a>
#### The `KdfOutput` base-key scope

KDF output is the value of a key the token could derive from the same base with the same mechanism:
`z.DeriveBytes(hkdf, 32)` over the agreed secret Z of `DeriveSecretAgreement` *is* the AES key
`z.Derive(hkdf, aes256Template)` makes on the token. So a `KdfOutput` opt-in is scoped by base key: before it asks
the policy, the library reads the KDF's base key (`KeyMaterialExportRequest.KdfBaseKey`: the same
`ExportKeyInfo`), and the rule checks it against a `KdfBaseKeyScope`:

| Scope | Base keys it admits |
|---|---|
| `KdfBaseKeyScope.NeverProtected` | Keys that are not `CKA_ALWAYS_SENSITIVE`: key material the application imported (`C_CreateObject`), and keys the token derived from it, such as the PRK of `HkdfPkcs11.ExtractKey`. A generated sensitive key, and anything derived from one as sensitive (Z, a master key's children), is refused, subject to the limits below |
| `KdfBaseKeyScope.Where(predicate, description)` | What the predicate decides from `ExportKeyInfo`; it decides alone, so check `AlwaysSensitive` in it to keep `NeverProtected`'s protection |
| `KdfBaseKeyScope.Any` | Every base key the session can use. Name it only when reproducing derived keys is the point |

```csharp
#pragma warning disable KLPKCS11012 // HKDF over the session's own derive keys only, see <ticket>
KeyMaterialExportRule rule = KeyMaterialExportRule.Allow(
    [KeyMaterialExportKind.KdfOutput],
    "HKDF output for <protocol>, over its own derive keys.",
    kdfBaseKeys: KdfBaseKeyScope.Where(k => !k.AlwaysSensitive && k.Label == "<protocol>-ikm", "<protocol>'s IKM"));
#pragma warning restore KLPKCS11012
```

An attribute the token does not report reads as protected, so an unknown key is never taken for an imported one.
PBKDF2 has no base key (its input is a password the caller holds) and is in every scope.

`NeverProtected` relies on the token keeping `CKA_ALWAYS_SENSITIVE` as PKCS#11 specifies, and it has two limits:

- **Unwrapped keys.** PKCS#11 makes every unwrapped key not `CKA_ALWAYS_SENSITIVE`, whatever its history, and no
  attribute tells a key provisioned under a KEK from one imported in the clear. `NeverProtected` admits both.
- **Tokens that reset the attribute on derive.** Some tokens report every derived key as not
  `CKA_ALWAYS_SENSITIVE`, Z included, and `NeverProtected` then admits it.

On such tokens, or wherever on-token key schedules start from unwrapped keys, narrow the scope with
`Where` (by `CKA_ID` or `CKA_LABEL`, on objects that are `CKA_MODIFIABLE=false`: anyone with a read/write
session can change those attributes otherwise), or keep those base keys in sessions whose policy does not allow
`KdfOutput`.

`Pkcs11Key.DeriveBytes(mechanism, length)` returns the output of an on-token KDF and accepts only KDFs
with their own parameters: `CKM_HKDF_DERIVE` with `CkmHkdfParams`, and `CKM_SP800_108_COUNTER_KDF`,
`CKM_SP800_108_FEEDBACK_KDF` and `CKM_SP800_108_DOUBLE_PIPELINE_KDF` with `CkmSp800108KdfParams` of the
same mode and no additional derived keys. Anything else is refused before the policy or the token is
consulted, a key-agreement mechanism above all, so a `KdfOutput` opt-in can never return an ECDH secret.
`CKM_HKDF_DATA` is refused too (PKCS#11 has it make a data object); `CKM_HKDF_DERIVE` with the same
parameters gives the same bytes. The mechanism and its PRF must still be allowed by the policy.

To read a secret, the library has the token produce it as a short-lived extractable, non-sensitive session object,
reads it and destroys it. The session tags the templates it judges for that object with the kind being read, and
only while that read-back, which the policy allowed, is in progress. A `ComposedCryptoPolicy` (every built-in,
and every policy from `ToBuilder` or `CryptoPolicyBuilder`) judges a tagged template by the export rule for the
kind, **and then** by the template rule without `CKA_SENSITIVE` and `CKA_EXTRACTABLE`: an opt-in exempts its own
read-back object from exactly those two attributes, and a custom `WithKeyTemplateRule` still judges everything
else about it (`CKA_TOKEN`, `CKA_VALUE_LEN`, …), as it judges every template you pass yourself. The CKD_NULL
key-agreement KDF of a raw ECDH read-back is judged by the export rule (private-key scope included), and only for `EcdhSharedSecret`: a
`KdfOutput` or `KemSharedSecret` opt-in never approves a derivation that would return Z. A custom
`ICryptoPolicy` sees these requests tagged with the kind (`KeyTemplateRequest.ReadBackFor`,
`KeyAgreementKdfRequest.ReadBackFor`), after the matching `KeyMaterialExportRequest`, whose `KdfBaseKey` it
should judge too when it allows `KdfOutput`, and whose `PrivateKey` it should judge when it allows
`EcdhSharedSecret` or `KemSharedSecret`.

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
turn. The names `Recommended` and `NistApproved` are reserved for the built-ins. A copy of `NistApproved` keeps
refusing overrides unless you call `AllowsOverride(true)`.

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
        KeyMaterialExportRequest when clock.GetLocalNow().Hour is < 8 or >= 18 =>
            PolicyDecision.Deny("Reading secrets off the token is allowed during business hours only."),
        _ => inner.Evaluate(request),
    };
}
```

Prefer deriving a `ComposedCryptoPolicy` when an allow-list change is all you need: it keeps the
built-in's parameter checks and refusal wording, and its catalogue can be documented.
