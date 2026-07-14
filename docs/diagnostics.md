# Obsoletion diagnostics

Weak and legacy cryptography stays available for interoperability, but it is never silent: each
such API is `[Obsolete]` with its own **diagnostic id**, and is additionally gated at runtime by
`Pkcs11Workspace.AllowInsecure` (which throws `InsecureOperationException` unless you opt in).

The per-API ids exist so that a deliberate, documented use of one legacy primitive does not blind
you to every other obsoletion in your codebase. Suppress the specific id — never the blanket
`CS0618`:

```csharp
// Interop with a legacy system that only accepts 3DES-wrapped keys.
#pragma warning disable KLPKCS11004 // Triple-DES: required by <system>, tracked in <ticket>
using var des = new TripleDESPkcs11(key);
#pragma warning restore KLPKCS11004
```

or, project-wide when an entire component is a legacy bridge, in the `.csproj`:

```xml
<NoWarn>$(NoWarn);KLPKCS11004</NoWarn>
```

Suppressing the compiler diagnostic does **not** disable the runtime gate: the operation still
requires `AllowInsecure`. The two are independent on purpose — one is a review signal, the other
is an explicit runtime acknowledgement.

## Diagnostics

<a id="KLPKCS11001"></a>
### KLPKCS11001 — MD5

MD5 is a broken hash function with practical collisions. Use `SHA256Pkcs11` or stronger.

<a id="KLPKCS11002"></a>
### KLPKCS11002 — SHA-1

SHA-1 is broken (SHAttered demonstrated practical collisions). Use `SHA256Pkcs11` or stronger.

<a id="KLPKCS11003"></a>
### KLPKCS11003 — DES

Single DES has a 56-bit key and is exhaustively breakable. Use `AesGcmPkcs11` or `AesCcmPkcs11`.

<a id="KLPKCS11004"></a>
### KLPKCS11004 — Triple-DES

Triple-DES has a 64-bit block (Sweet32) and is NIST-deprecated. Use `AesGcmPkcs11` or
`AesCcmPkcs11`.

<a id="KLPKCS11005"></a>
### KLPKCS11005 — RC2

RC2 (RFC 2268) is a weak legacy cipher with a reduced effective key length. Use `AesGcmPkcs11` or
`AesCcmPkcs11`.

<a id="KLPKCS11006"></a>
### KLPKCS11006 — DSA

DSA is disallowed for signature generation by NIST FIPS 186-5 (2023) and is removed from modern
protocol suites. Use `ECDsaPkcs11`, or `MLDsaPkcs11` for post-quantum signatures.

<a id="KLPKCS11007"></a>
### KLPKCS11007 — Weak elliptic curve

The named curve provides less than the 128-bit security baseline (NIST SP 800-57) — this covers
P-192, P-224, secp192k1, secp224k1, and the Brainpool 160/192/224-bit curves. Use `NistP256`,
`BrainpoolP256r1`, or stronger.

<a id="KLPKCS11008"></a>
### KLPKCS11008 — RSA encryption without OAEP

Reported by an analyzer rather than `[Obsolete]`, because the insecure choice here is a *value*, not
a symbol: there is nothing to mark obsolete when a consumer writes
`rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1)` (a BCL padding singleton passed to a BCL override) or
`new Mechanism(CKM.CKM_RSA_PKCS)`. Both routes select RSAES-PKCS#1 v1.5 or raw RSA, where the
Bleichenbacher / ROBOT padding-oracle attacks live, and both end at the same runtime `AllowInsecure`
gate. Use `RSAEncryptionPadding.OaepSHA256` (`CKM_RSA_PKCS_OAEP`).

> **RSA *signatures* are a different story.** RSASSA-PKCS#1 v1.5 with a strong hash
> (`CKM_SHA256_RSA_PKCS` and friends) is **allowed by default** and is *not* reported: it is
> FIPS 186-5-approved and required by JWT RS256, TLS 1.2 CertificateVerify, X.509, and code signing.
> Only *encryption* and the raw `CKM_RSA_PKCS` / `CKM_RSA_X_509` mechanisms carry the padding-oracle
> exposure. The mechanism guard is direction-agnostic, so gating v1.5 signatures would also break
> *verifying* third-party signatures.

<a id="KLPKCS11009"></a>
### KLPKCS11009 — Broken, deprecated, or unauthenticated mechanism

Also an analyzer, for the same reason as KLPKCS11008: the legacy primitives have `[Obsolete]` façade
types, but the *mechanisms* underneath are reachable as values — `new Mechanism(CKM.CKM_DES3_CBC)`,
or `aes.Mode = CipherMode.CBC` — where there is no symbol to mark. Covers everything the runtime gate
rejects apart from the RSA pair above:

- **Unauthenticated AES modes** — ECB, CBC, CBC-PAD, CTR, CTS, OFB, CFB. The common case, and the one
  with no obsolete type to warn you: AES itself is fine, so `AesPkcs11` is *not* obsolete. These modes
  provide no integrity protection and are malleable; raw/padded CBC also enables padding oracles.
  Use `CKM_AES_GCM` or `CKM_AES_CCM`.
- **Broken hashes** — MD2, MD5, SHA-1, RIPEMD-128/160 (and their HMAC / RSA-signature variants).
- **Broken or legacy ciphers** — RC2, RC4, DES, 3DES, SEED, CAST/CAST5/CAST128, RC5, Blowfish, Skipjack.
- **DSA** — every `CKM_DSA*` mechanism (FIPS 186-5 disallows DSA signature generation).

<a id="KLPKCS11010"></a>
### KLPKCS11010 — Broken hash in a signature or MAC

The standalone digest façades are obsolete (KLPKCS11001/002), but a broken hash also reaches the
token as a *value*: `rsa.SignData(data, HashAlgorithmName.SHA1, …)`,
`new HMACPkcs11(key, HashAlgorithmName.MD5)`, `new SP800108HmacCounterKdfPkcs11(key, HashAlgorithmName.SHA1)`.
`HashAlgorithmName.SHA1` is a BCL value this library cannot obsolete, so an analyzer reports it. Use
SHA-256 or stronger.

Note that **verifying** an existing SHA-1 signature is gated too — the mechanism guard is
direction-agnostic, so legacy verification needs `AllowInsecure` as well.

## Runtime-only gates

Not every insecure operation has a compile-time signal, and the analyzers are a best-effort early
warning layered on top of the gate — **the gate, not the diagnostic, is the enforcement point.**

The analyzers see only what is written literally in the source. A mechanism chosen dynamically — from
configuration, a `CKM` variable, or a hash name computed at run time — cannot be traced, and is
rejected only when the operation executes, with an `InsecureOperationException` naming the mechanism.

These policies are inherently runtime-only, because they depend on values rather than symbols:

| Gate | Rejects |
|------|---------|
| RSA key strength | Generating an RSA key pair below 2048 bits |
| EC curve baseline | Generating an EC key on a curve below the 128-bit baseline — including one passed as a value, which the `[Obsolete]` on the named-curve properties cannot catch |
| Secure key defaults | Creating, deriving, or unwrapping a key explicitly marked extractable or non-sensitive |
| Key-material extraction | Reading a shared secret or private key off the token (ML-KEM encapsulate/decapsulate, ML-DSA / SLH-DSA private export) |
