# SHA-3 — `SHA3_256Pkcs11`, `SHA3_384Pkcs11`, `SHA3_512Pkcs11`

A hash takes no key, so hashing public data on a token gains nothing in secrecy, and the BCL is faster
where the platform has SHA-3. Use the token's hash when the token must do it (see
[Hashes and HMAC](hashes.md)).

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Hashes/Sha3Examples.cs#Sha3OnToken)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Hashes/Sha3Examples.cs#BclSha3)]

---

**What differs from `SHA3_256` and friends:**

- Each adapter is a `HashAlgorithm` over a session; its constructor takes the `Pkcs11Session` that runs
  the digest. The session is borrowed, not disposed. There is no static `HashData`.
- The digests are the BCL's, byte for byte.
- There is no `IsSupported`: the adapters need a token that implements `CKM_SHA3_256` and its siblings,
  which fewer tokens do than SHA-2: check the token's mechanism list. The BCL's `SHA3_256` needs platform
  support instead.
- PKCS#11 digests in one call, so the adapter **buffers everything written to it** (`TransformBlock`,
  `CryptoStream`, `ComputeHash(Stream)`) and sends it to the token when the hash is finalized. Memory grows
  with the input; for multi-gigabyte streams, hash in software.
- The default `Recommended` policy allows SHA-256, SHA-384, SHA-512 and SHA3-256/384/512. [MD5](md5.md)
  and [SHA-1](sha-1.md) are broken and refused; their adapters exist for legacy interop only and are
  marked `[Obsolete]`.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.SHA3_256Pkcs11>,
<xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.SHA3_384Pkcs11>,
<xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.SHA3_512Pkcs11>.
