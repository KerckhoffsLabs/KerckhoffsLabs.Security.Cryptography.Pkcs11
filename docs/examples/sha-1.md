# SHA-1 — `SHA1Pkcs11`

It is a legacy algorithm: read [Legacy algorithms](legacy.md) for the two steps every use takes.

## SHA-1 for a legacy protocol

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/Sha1Examples.cs#Sha1ForLegacyProtocol)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/Sha1Examples.cs#BclSha1)]

---

This is for protocols that still name or index data by SHA-1, where the hash is an identifier, not a
security guarantee. An attacker can produce two inputs with the same SHA-1, so never rely on it for
integrity or signatures; use [SHA-256](sha-2.md) for anything new.

**What differs from `SHA1`:**

- The adapter is a `HashAlgorithm` over a session, and gives the BCL's digest. Hashing public data on a
  token gains nothing in secrecy: where the token is not required, the BCL is simpler.
- The default policy refuses it: each use takes a scoped `UsePolicy(CryptoPolicy.AllowInsecure)` lease,
  and the adapter is `[Obsolete]` (`KLPKCS11002`), suppressed at the line that needs it. The BCL needs neither.
- Like the [SHA-2 adapters](sha-2.md), it buffers the input and digests it on the token in one call.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.SHA1Pkcs11>.
