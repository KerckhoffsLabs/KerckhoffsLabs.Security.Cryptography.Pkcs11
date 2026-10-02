# Security model

The library is **secure by default**: the safe choice is the one you get without asking, and every
weaker choice is explicit, visible in review, and scoped.

- **Insecure operations are refused before they reach the token.** Every workspace enforces a
  [crypto policy](crypto-policies.md); a mechanism, parameter set, key size or curve it does not allow
  throws `CryptoPolicyViolationException` without any call to the token.
- **Insecure choices are visible at compile time** where they can be: legacy algorithms are `[Obsolete]`,
  and analyzers report insecure mechanisms and hashes written as values ([diagnostics](diagnostics.md)).
- **Keys stay on the token.** Generated private and secret keys are sensitive and non-extractable, and
  derived and shared secrets come back as sensitive on-token keys. Reading a secret into managed memory is
  a separate, narrow operation the policy decides ([reading a secret back](crypto-policies.md#reading-a-secret-back)).
- **Keys get one role each.** The key-generation helpers never mix data-processing and key-management roles,
  and every capability attribute defaults to `false` ([below](#key-role-separation)).

## Crypto policies

Both built-in restrictive policies are **allow-lists that deny by default**: anything they do not list —
including every vendor-defined mechanism — is refused. Their full contents, with the rationale for each
entry and the documented reasons for refusals, are generated from the policy source:
[Recommended](policies/recommended.md) and [NistApproved](policies/nist-approved.md). How to choose, widen or
tighten a policy is described in [Using crypto policies](crypto-policies.md).

The default `Recommended` policy allows each mechanism only for the operations it is meant for —
`CKM_AES_GCM` encrypts, decrypts, wraps and unwraps but does not sign; `CKM_SHA256` digests but does not
sign — and **denies every vendor-defined or unreviewed mechanism by default**, including ones it has no
specific objection to. Refusals it documents include unauthenticated symmetric modes (ECB, CBC, CTR, …),
broken/legacy ciphers (DES/3DES, RC2, RC4, SEED, CAST, Blowfish, SKIPJACK), broken hashes
(MD2/MD5/SHA-1/RIPEMD), PKCS#1 v1.5 *encryption* and raw RSA (`CKM_RSA_PKCS`, `CKM_RSA_X_509`),
sub-128-bit EC curves, SHA-1 KDF PRFs, and AES-GCM tags under 96 bits or AES-CCM MACs under 64 bits.
Where the insecure choice is visible at compile time, [analyzers](diagnostics.md) (`KLPKCS11001`–`KLPKCS11010`)
surface it as a build warning too.

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

**SHA-224 is refused for a different reason than the broken hashes above: it isn't cryptographically
weak.** It's FIPS 180-4-approved — just a truncated SHA-256 with no `HashAlgorithmName` constant in
the BCL and no practical benefit over SHA-256 on equal-cost hardware. RSA PKCS#1/PSS signing,
RSA-OAEP, ECDSA signing, and HMAC all accept it behind a policy that permits it (see
[Using crypto policies](crypto-policies.md)), for interop with a token or protocol that specifically
requires it.

**RSA PKCS#1 v1.5 signatures are a deliberate exception.** Strong-hash v1.5 *signatures*
(`CKM_SHA256_RSA_PKCS` and up) are allowed by default: RSASSA-PKCS1-v1_5 with a strong hash is
FIPS 186-5-approved and mandated by ubiquitous interop — JWT `RS256`, TLS 1.2 `CertificateVerify`,
X.509 chains, code signing — and because the gate also governs verification, blocking them would
break verifying third-party signatures. Only v1.5 over a *broken hash*, and v1.5 *encryption* / raw
RSA (Bleichenbacher / ROBOT territory), are gated. Prefer RSA-PSS for new code all the same.

## Key role separation

`Pkcs11Workspace`'s key-generation helpers each grant exactly one role, deliberately. Mixing
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
