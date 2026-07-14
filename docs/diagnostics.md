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
