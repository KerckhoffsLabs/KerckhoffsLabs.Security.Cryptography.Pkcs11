# Security model

This page explains what the library protects, from whom, how, and where its protection ends. For how to
choose, adjust or write a crypto policy, see [Using crypto policies](crypto-policies.md); for the
diagnostics the analyzers raise, see [Diagnostics](diagnostics.md).

## Overview

The high-level API is **secure by default**:

- Every session enforces a **crypto policy**. A request the policy refuses — a mechanism, a hash, a curve,
  a key size, a parameter, a key template — throws `CryptoPolicyViolationException` (a
  `CryptographicException`) **before any call reaches the token**.
- Keys the library generates are **sensitive and non-extractable**, and each is granted **one role**.
- Insecure choices visible at compile time are reported by `[Obsolete]` attributes and analyzers
  (`KLPKCS11001`–`KLPKCS11011`), so most mistakes surface in the build, not in production.
- Secrets that pass through the library — PINs, passwords, key bytes, plaintext — are held in buffers
  that are zeroed when released.

<a id="threat-model"></a>
## Threat model

### Assets

- **Key material on the token**: private keys and secret keys. The library's purpose is that these stay
  on the token, are used only for the role they were created for, and never leave in the clear unless the
  caller chose that explicitly.
- **The integrity of the policy decision**: what the caller asked for is what the policy judged, and
  nothing reaches the token that the policy did not allow.
- **Secrets in process memory**: PINs, passwords, imported key bytes, plaintext and derived secrets that
  transit the library on their way to or from the token.
- **The correctness of results**: a signature, a decryption or a derived value returned to the caller is
  what the token produced, of the length it reported, and never silently padded or truncated.

### Actors

| Actor | What they can do | How the library responds |
|---|---|---|
| **The application developer** (the main audience of the defaults) | Choose a weak mechanism, a short tag, a small key, a key template that grants too much, or forget to dispose a secret. | Policy refusals before the token is called; `[Obsolete]` and analyzer diagnostics at build time; single-role key helpers; capability attributes that default to `false`; secret buffers zeroed on release, with finalizers as a safety net. |
| **A remote party supplying inputs** | Submit chosen ciphertexts, forged tags or signatures, malformed public keys, or wrapped-key blobs, and observe the outcome. | Inputs are length- and range-checked before they reach the token (an RSA ciphertext must be the modulus's length and below the modulus); AEAD adapters fix the tag size at construction so a short forged tag is refused; tag mismatches surface as `AuthenticationTagMismatchException`. Padding-oracle exposure depends on the caller: see [PKCS#1 v1.5 decryption](diagnostics.md#pkcs1-implicit-rejection). |
| **A PKCS#11 module that deviates from the specification** | Report a length larger than the buffer it was given, return an unexpected code, or implement a mechanism differently from another vendor. | Lengths and counts the module reports are checked against what was allocated before anything is sized, sliced or read; a wrong answer is a `Pkcs11Exception`, not memory corruption or silently zero-padded output. Return codes map to typed exceptions that keep the raw `CKR`. |

### Trust boundaries

1. **Application → library** (the public API). The library assumes the caller is the party authorised to
   use the session it opened, and protects the caller from *mistakes*, not from itself: a caller can
   always lift the policy with `UsePolicy(CryptoPolicy.AllowInsecure)` unless the session was opened under
   a policy that forbids overrides (`CryptoPolicy.NistApproved`).
2. **Library → PKCS#11 module** (P/Invoke and native memory). Everything the module writes or reports is
   validated before use; everything the library hands it is marshalled with the layouts and `CK_ULONG`
   width of the platform, and released deterministically.
3. **Module → token**. Opaque to the library: whatever the module does with the token, the library sees
   only the PKCS#11 interface.

**The library relies on the token to enforce `CKA_SENSITIVE`, `CKA_EXTRACTABLE` and `CKA_PRIVATE`, and the
wrap and unwrap templates.** The library sets these attributes securely when it creates keys and builds
templates, but enforcing them — refusing to reveal a sensitive key's value, to wrap a non-extractable key,
or to show a private object without login — is the token's job, and the library cannot verify after the
fact that the token did so. Choose a token whose enforcement you trust for the keys you protect.

### Controls

| Control | Where it is enforced |
|---|---|
| Crypto policy check before every operation | `Pkcs11Session` (the policy chosen at open, or a scoped `Pkcs11Session.UsePolicy` lease); `CryptoPolicy.Recommended`, `CryptoPolicy.NistApproved` |
| Build-time warnings for insecure choices | `[Obsolete]` on legacy adapters, weak curves and the PBKDF2 constructors with weak defaults (`KLPKCS11001`–`KLPKCS11007`, `KLPKCS11011`); analyzers for insecure values (`KLPKCS11008`–`KLPKCS11010`) |
| Sensitive, non-extractable keys by default | `Pkcs11Session.GenerateAesKey`, `GenerateRsaSigningKeyPair`, … ; `SecretKeyTemplateBuilder` and `PrivateKeyTemplateBuilder` defaults |
| One role per generated key | the `Pkcs11Session` key-generation helpers ([Key role separation](#key-role-separation)) |
| Capability attributes default to `false` | `SecretKeyTemplateBuilder`, `PublicKeyTemplateBuilder`, `PrivateKeyTemplateBuilder` |
| Wrap and unwrap hardening | `WrapWithTrusted`, `WrapTemplate`, `UnwrapTemplate`, `DeriveTemplate` on the template builders ([Wrap hardening](#wrap-hardening)) |
| Ciphertext length and range checks | `Pkcs11Key.Decrypt` and `Pkcs11Key.Unwrap` with RSA PKCS#1 v1.5 or OAEP |
| Fixed AEAD tag size | `AesGcmPkcs11`, `AesCcmPkcs11` constructors |
| Module-reported lengths validated | every call site that sizes or reads a buffer from a length the module reports |
| Secrets zeroed on release | `SecurePin`, `SecurePassword`, attribute and parameter buffers ([Secrets in memory](#secrets-in-memory)) |

### Out of scope

These are outside what the library can defend against, and outside the scope of
[security reports](https://github.com/KerckhoffsLabs/KerckhoffsLabs.Security.Cryptography.Pkcs11/blob/main/SECURITY.md):

- a **malicious PKCS#11 module** chosen by the application: the module runs in the process and can do
  anything the process can;
- a **compromised host or process**: an attacker who can read process memory can read secrets while they
  are in use, whatever the library zeroes afterwards;
- **physical access** to the token, and side channels in the token or module itself;
- vulnerabilities in a PKCS#11 module, HSM or token: report those to their vendor.

<a id="known-limits"></a>
### Known limits

- **Policies judge requests, not what is already on the token.** They check mechanisms, parameters and
  *requested* key sizes and curves; they do not inspect the size or curve of an existing key (for ECDH,
  the existing key's *type* is checked).
- **Raw-digest mechanisms** (`CKM_ECDSA`, `CKM_RSA_PKCS`, `CKM_RSA_PKCS_PSS`) sign a caller-computed
  digest; the policy cannot see which hash produced it.
- **`CKM_AES_KEY_WRAP_PAD` is vendor-dependent**: wrapped keys may not move between tokens.
- **PKCS#1 v1.5 decryption may not fail on bad padding**: some tokens return a synthetic plaintext
  instead ([details](diagnostics.md#pkcs1-implicit-rejection)).
- **`CKA_TRUSTED` is not gated locally**: only the security officer may set it, and the token, not the
  library, enforces that.
- **`NistApproved` is not FIPS certification**: it restricts what this library sends; FIPS 140-3 also
  requires a validated module operating in its approved mode.

<a id="crypto-policies"></a>
## Crypto policies

Every session enforces a **crypto policy**, chosen when it is opened:

```csharp
// Default: Recommended — refuses broken algorithms, weak keys, and plaintext key export.
using var session = library.OpenSessionWithPin(slotLabel, CKU.CKU_USER, pin);

// FIPS: only NIST-approved functions; overrides are refused for the session's lifetime.
using var fips = library.OpenSessionWithPin(slotLabel, CKU.CKU_USER, pin, CryptoPolicy.NistApproved);

// Legacy interop for one operation (not available on a NistApproved session):
using (session.UsePolicy(CryptoPolicy.AllowInsecure)) { /* one legacy operation */ }
```

Refusals throw `CryptoPolicyViolationException` (a `CryptographicException`) naming the policy and the
reason. You can supply your own `ICryptoPolicy`; end any `switch` over `PolicyRequest` with a deny arm so
request kinds added in later versions fail closed.

Both restrictive policies are **allow-lists that deny by default**: every mechanism, hash, curve,
key-agreement KDF and KDF PRF they permit — with its rationale — plus the documented, non-enforcing deny
list (reason and alternative), is generated straight from the policy source into
[Recommended](policies/recommended.md) and [NistApproved](policies/nist-approved.md). Anything not listed
on those pages is refused.

> **`NistApproved` is not FIPS certification.** It restricts what this library sends to the token. FIPS 140-3
> compliance also requires a validated cryptographic module operating in its approved mode. Under
> `NistApproved`, AES key wrapping is approved only via KW/KWP (`CKM_AES_KEY_WRAP`, `CKM_AES_KEY_WRAP_KWP`)
> or the GCM/CCM modes; other AES modes encrypt and decrypt data but may not wrap or unwrap keys.
> AES-GCM tags must be 96 to 128 bits (SP 800-38D §5.2.1.2) and AES-CCM MACs at least 64 bits
> (SP 800-38C Appendix B.2).
> `CKM_AES_KEY_WRAP_PAD` is refused: its padding is vendor-defined (RFC 5649 on some tokens, KW over
> PKCS#7 — not an SP 800-38F method — on others), so its approval cannot be established.

**Known limits.** Both restrictive policies judge requests, not what is already on the token:

- They check mechanisms, parameters and *requested* key sizes/curves. They do not inspect the size or curve
  of existing keys — using an RSA-1024 or Brainpool key already on the token is not refused. (For ECDH, the
  existing key's *type* is checked: `NistApproved` refuses an X25519/X448 key.)
- Raw `CKM_ECDSA`, `CKM_RSA_PKCS` and `CKM_RSA_PKCS_PSS` sign a caller-computed digest; the policy cannot
  see which hash produced it.
- `Recommended` allows `CKM_AES_KEY_WRAP_PAD`, but its meaning is vendor-dependent: RFC 5649 (KWP) on some
  tokens, KW over PKCS#7-padded input on others, so wrapped keys may not move between tokens. Prefer
  `CKM_AES_KEY_WRAP_KWP` where the token supports it.

The default `Recommended` policy allows each mechanism only for the operations it is meant for —
`CKM_AES_GCM` encrypts, decrypts, wraps and unwraps but does not sign; `CKM_SHA256` digests but does not
sign — and **denies every vendor-defined or unreviewed mechanism by default**, including ones it has no
specific objection to. Refusals it documents include unauthenticated symmetric modes (ECB, CBC, CTR, …),
broken/legacy ciphers (DES/3DES, RC2, RC4, SEED, CAST, Blowfish, SKIPJACK), broken hashes
(MD2/MD5/SHA-1/RIPEMD), PKCS#1 v1.5 *encryption* and raw RSA (`CKM_RSA_PKCS`, `CKM_RSA_X_509`),
sub-128-bit EC curves, SHA-1 KDF PRFs, and AES-GCM tags under 96 bits or AES-CCM MACs under 64 bits. Where
the insecure choice is visible at compile time, [diagnostics](diagnostics.md) (`KLPKCS11001`–`KLPKCS11011`)
surface it as a build warning too.

When `Recommended` refuses something you need, there are two remedies:

```csharp
// A mechanism you have reviewed (here a vendor-defined one): your own policy, derived from
// Recommended and named "MyApp". It copies every rule; CryptoPolicy.Recommended itself is unchanged.
ComposedCryptoPolicy reviewed = CryptoPolicy.Recommended.ToBuilder("MyApp")
    .AllowMechanism(
        (CKM)0x8000_1001UL,                           // your vendor's CK_MECHANISM_TYPE
        [CryptoOperation.Sign, CryptoOperation.Verify],
        "Vendor HSM signature scheme, reviewed for our release signing.")
    .Build();
using var session = library.OpenSessionWithPin(slotLabel, CKU.CKU_USER, pin, reviewed);

// One-off legacy interop: lift the policy for a single, scoped operation.
using (session.UsePolicy(CryptoPolicy.AllowInsecure)) { /* decrypt one legacy archive */ }
```

The same builder allows a hash, curve or key-agreement KDF (`AllowHash`, `AllowCurve`,
`AllowKeyAgreementKdf`), tightens a copy (`RemoveMechanism`, `WithRsaKeyGenerationRule`), or starts a policy
from scratch (`new CryptoPolicyBuilder(name)`); see [Using crypto policies](crypto-policies.md). The
generated [Recommended](policies/recommended.md) and [NistApproved](policies/nist-approved.md) pages list
exactly what each policy allows, for which operations, and why.

<a id="key-role-separation"></a>
## Key role separation

`Pkcs11Session`'s key-generation helpers each grant exactly one role, deliberately. Mixing
data-processing roles (encrypt/decrypt, sign/verify) with key-management roles (wrap/unwrap) on the
same key turns the key into a self-service oracle: wrap an extractable key, then decrypt the
resulting blob with the same key to read it in the clear; or encrypt a chosen plaintext, then unwrap
it as if it were a wrapped key, injecting a "sensitive" key of known value (Clulow, *On the Security
of PKCS#11*, CHES 2003).

- `GenerateAesKey` → encrypt/decrypt only. `GenerateAesKeyEncryptionKey` → a dedicated wrap/unwrap-only
  KEK, with `CKA_UNWRAP_TEMPLATE` forcing every key it unwraps to be sensitive and non-extractable.
- `GenerateRsaSigningKeyPair` → sign/verify only. `GenerateRsaKeyTransportKeyPair` → encrypt/decrypt
  only (RSA-OAEP key transport). Neither grants `CKA_WRAP`/`CKA_UNWRAP`; a caller who specifically
  needs RSA `C_WrapKey`/`C_UnwrapKey` should build that template explicitly.

There is no single "do everything" key-generation helper — pick the one that names the role the key
will actually play.

**Every capability attribute defaults to `false`, deliberately.** PKCS#11's own spec default for an
*omitted* `CKA_ENCRYPT`/`CKA_DECRYPT`/`CKA_SIGN`/`CKA_VERIFY`/`CKA_WRAP`/`CKA_UNWRAP`/`CKA_DERIVE` is
`CK_TRUE`, not `CK_FALSE` (confirmed against real NSS and SoftHSM tokens) — leaving a role out of a
template does not refuse it, it grants it. `SecretKeyTemplateBuilder`, `PublicKeyTemplateBuilder`,
and `PrivateKeyTemplateBuilder` all set every applicable capability attribute to `false` at
construction, the same fail-safe-default pattern used for `CKA_SENSITIVE`/`CKA_EXTRACTABLE`; a
caller opts in to each role explicitly via `.Encrypt()`, `.Sign()`, `.Wrap()`, and so on.

<a id="wrap-hardening"></a>
## Wrap hardening

Keys are non-extractable by default, which closes the direct exfiltration path. For a key
deliberately made wrappable, PKCS#11 offers four defence-in-depth controls, all available as
builder helpers:

```csharp
using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
    .ValueLen(32)
    .Wrap()
    .WrapWithTrusted()                      // only a CKA_TRUSTED key may wrap this one
    .WrapTemplate(t => t                    // ...and only keys matching this may be wrapped
        .Class(CKO.CKO_SECRET_KEY)
        .Sensitive()
        .NonExtractable())
    .UnwrapTemplate(t => t                  // keys arriving through this one are born hardened
        .Sensitive()
        .NonExtractable())
    .Build();
```

The two nested templates look alike and mean opposite things — this is the part worth reading
twice:

- **`WrapTemplate` is a filter.** Keys that do not match it *cannot be wrapped* by this key. It
  narrows what this key can be used to exfiltrate.
- **`UnwrapTemplate` is an imposition.** Its attributes are applied to every key unwrapped with
  this key, as if the object already carried them, before any caller-supplied template. It
  constrains what can be smuggled *in* — for example, forcing an arriving key to be
  non-extractable so it cannot be immediately re-exported in the clear.

`DeriveTemplate` works like `UnwrapTemplate`, for keys produced by derivation.

Nested templates carry no secure defaults, deliberately: an attribute you did not write must never
silently change which keys a wrapping key will accept.

**`Trusted()` is SO-only.** PKCS#11 allows `CKA_TRUSTED` to be set to true only by the security
officer. Setting it from a normal user session is rejected by a conformant token with
`CKR_ATTRIBUTE_READ_ONLY`. The library does not gate this locally — it cannot know which user type
opened the session, and refusing at build time would be wrong for SO sessions.

As with every attribute, these controls are enforced by the token ([Trust boundaries](#trust-boundaries)).

<a id="algorithm-notes"></a>
## Algorithm notes

**SHA-224 is refused for a different reason than the broken hashes: it isn't cryptographically
weak.** It's FIPS 180-4-approved — just a truncated SHA-256 with no `HashAlgorithmName` constant in
the BCL and no practical benefit over SHA-256 on equal-cost hardware. RSA PKCS#1/PSS signing,
RSA-OAEP, ECDSA signing, and HMAC all accept it behind a policy that permits it (e.g.
`UsePolicy(CryptoPolicy.AllowInsecure)`), for interop with a token or protocol that specifically
requires it.

**RSA PKCS#1 v1.5 signatures are a deliberate exception.** Strong-hash v1.5 *signatures*
(`CKM_SHA256_RSA_PKCS` and up) are allowed by default: RSASSA-PKCS1-v1_5 with a strong hash is
FIPS 186-5-approved and mandated by ubiquitous interop — JWT `RS256`, TLS 1.2 `CertificateVerify`,
X.509 chains, code signing — and because the gate also governs verification, blocking them would
break verifying third-party signatures. Only v1.5 over a *broken hash*, and v1.5 *encryption* / raw
RSA (Bleichenbacher / ROBOT territory), are gated. Prefer RSA-PSS for new code all the same.

**PKCS#1 v1.5 decryption may succeed on invalid padding.** Tokens that implement implicit rejection
return a synthetic plaintext instead of failing; never treat the outcome of PKCS#1 v1.5 decryption as a
signal. See [PKCS#1 v1.5 decryption and implicit rejection](diagnostics.md#pkcs1-implicit-rejection).

**AES-GCM and AES-CCM fix the tag size at construction.** `AesGcmPkcs11(key, tagSizeInBytes)` and
`AesCcmPkcs11(key, tagSizeInBytes)` refuse a tag of any other length on `Decrypt`. Taking the size from
each call, as `AesGcm(key)` did before it was made obsolete (SYSLIB0053) and as `AesCcm(key)` still does,
would let an attacker who controls the ciphertext submit a forged tag of the shortest legal length.

<a id="secrets-in-memory"></a>
## Secrets in memory

- **PINs: `SecurePin`.** Holds the PIN in a buffer on the pinned object heap, so the garbage collector
  never moves it and cannot leave stale copies, and zeroes it on disposal (a finalizer is the safety net,
  not a substitute). Prefer the `SecurePin(ReadOnlySpan<char>)` constructor: the characters are encoded
  straight into the pinned buffer, so no string or intermediate array holds the PIN; zero your own buffer
  afterwards. The `SecurePin(string)` constructor works, but the string itself cannot be reliably zeroed.
  No Unicode normalization is applied: tokens compare PIN bytes exactly.
- **Passwords for key derivation: `SecurePassword`.** The same design, for the input of PBKDF2
  (`Rfc2898DeriveBytesPkcs11`).
- **Unmanaged buffers.** The unmanaged buffers the library allocates for attribute values (such as an
  imported key's `CKA_VALUE`), mechanism parameters (IVs, nonces, AAD, contexts) and values read back from
  the token are released through one routine that zeroes them with `CryptographicOperations.ZeroMemory`
  first. Attribute buffers
  are owned by `ObjectTemplate` and `ObjectAttribute`: dispose them; their finalizers zero what a caller
  forgets.
- **Intermediate managed buffers.** Where an adapter receives a plaintext or a secret into a temporary
  array before copying it into your destination (AES-GCM, AES-CCM and ChaCha20-Poly1305 decryption, the
  ECDH shared secret before its KDF, ML-KEM, HKDF, PBKDF2), it zeroes that array afterwards.
- **What the library cannot zero.** Arrays it returns to you are yours: methods that return a secret as a
  `byte[]` (a derived key, a shared secret, a decrypted plaintext) leave it to you to call
  `CryptographicOperations.ZeroMemory` when done. Prefer the overloads that write into a `Span<byte>` you
  own, or that keep the derived key on the token.
