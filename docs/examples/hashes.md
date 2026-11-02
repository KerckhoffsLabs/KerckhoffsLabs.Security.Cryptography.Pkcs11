# Hashes and HMAC

## Hashing on the token — `SHA256Pkcs11`, `SHA384Pkcs11`, `SHA512Pkcs11`, `SHA3_256Pkcs11`, `SHA3_384Pkcs11`, `SHA3_512Pkcs11`

A hash takes no key, so hashing public data on a token gains nothing in secrecy, and the BCL is faster:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/HashExamples.cs#BclSha256)]

Use the token's hash when the token must do it: an environment where every cryptographic function has to
run inside a validated module, or a digest that feeds an operation the token performs next. Each adapter
is a `HashAlgorithm` over a session:

# [SHA-2](#tab/sha2)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/HashExamples.cs#Sha2OnToken)]

# [SHA-3](#tab/sha3)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/HashExamples.cs#Sha3OnToken)]

---

**What differs from `SHA256` and friends:**

- The constructor takes the `Pkcs11Session` that runs the digest. The session is borrowed, not disposed.
- PKCS#11 digests in one call, so the adapter **buffers everything written to it** (`TransformBlock`,
  `CryptoStream`, `ComputeHash(Stream)`) and sends it to the token when the hash is finalized. Memory grows
  with the input; for multi-gigabyte streams, hash in software.
- The default `Recommended` policy allows SHA-256, SHA-384, SHA-512 and SHA3-256/384/512. MD5 and SHA-1
  are broken and refused; their adapters exist for legacy interop only and are marked `[Obsolete]`.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.SHA256Pkcs11>,
<xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.SHA3_256Pkcs11> (the others are alike).

## HMAC with a token key — `HMACPkcs11`

An HMAC key is a secret, and that is where a token helps: the key never enters your process. Generate a
generic-secret key that may only compute and verify MACs:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/HashExamples.cs#GenerateHmacKey)]

Then use it as the BCL's `HMAC`:

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/HashExamples.cs#HmacSha256)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/HashExamples.cs#BclHmacSha256)]

---

**What differs from `HMACSHA256`:**

- The constructor takes a token key and the hash (`HashAlgorithmName.SHA256`, `SHA384`, `SHA512`, or a
  SHA-3 name); one `HMACPkcs11` type covers them all. `Key` cannot be read or set.
- Like the hash adapters, it buffers the input and computes the MAC on the token in one call.
- The default `Recommended` policy allows HMAC with SHA-256 or stronger; HMAC-SHA-1 and HMAC-MD5 are
  refused, and reported at build time as `KLPKCS11010`.
- To check a MAC you received, compute it and compare with `CryptographicOperations.FixedTimeEquals`,
  never with `SequenceEqual`, which leaks through timing how many leading bytes matched.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.HMACPkcs11>.
