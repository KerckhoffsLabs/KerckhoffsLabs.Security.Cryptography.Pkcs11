# SHA-3 — `SHA3_256Pkcs11`, `SHA3_384Pkcs11`, `SHA3_512Pkcs11`

A hash takes no key, so hashing public data on a token gains nothing in secrecy, and the BCL is faster
where the platform has SHA-3:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Hashes/Sha3Examples.cs#BclSha3_256)]

Use the token's hash when the token must do it (see [Hashes and HMAC](hashes.md)). Each adapter is a
`HashAlgorithm` over a session, and its digests are the BCL's (`SHA3_256.HashData` and its siblings):

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Hashes/Sha3Examples.cs#Sha3OnToken)]

**What differs from `SHA3_256` and friends:**

- The constructor takes the `Pkcs11Session` that runs the digest. The session is borrowed, not disposed.
- PKCS#11 digests in one call, so the adapter **buffers everything written to it** (`TransformBlock`,
  `CryptoStream`, `ComputeHash(Stream)`) and sends it to the token when the hash is finalized. Memory grows
  with the input; for multi-gigabyte streams, hash in software.
- The default `Recommended` policy allows SHA-256, SHA-384, SHA-512 and SHA3-256/384/512. [MD5](md5.md)
  and [SHA-1](sha-1.md) are broken and refused; their adapters exist for legacy interop only and are
  marked `[Obsolete]`.
- Fewer tokens implement SHA-3 than SHA-2, and the BCL's `SHA3_256` needs platform support
  (`SHA3_256.IsSupported`).

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.SHA3_256Pkcs11>,
<xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.SHA3_384Pkcs11>,
<xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.SHA3_512Pkcs11>.
