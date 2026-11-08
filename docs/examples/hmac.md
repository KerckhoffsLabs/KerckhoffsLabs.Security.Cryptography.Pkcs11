# HMAC — `HMACPkcs11`

An HMAC key is a secret, and that is where a token helps: the key never enters your process.

## Generating a key

Once, when you provision the token, generate a generic-secret key on it that may only compute and verify
MACs, as a token object under a label. It stays on the token after the session closes, sensitive and
non-extractable:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Hashes/HmacExamples.cs#GenerateHmacKey)]

The BCL has nothing like this to store: its key is random bytes in your process
(`RandomNumberGenerator.GetBytes(32)`), and keeping them is up to you.

## Computing a MAC with the key

In the application, open the key by its label and use it as the BCL's `HMAC`:

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Hashes/HmacExamples.cs#HmacSha256)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Hashes/HmacExamples.cs#BclHmacSha256)]

---

**What differs from `HMACSHA256`:**

- The constructor takes a token key and the hash (`HashAlgorithmName.SHA256`, `SHA384`, `SHA512`, or a
  SHA-3 name); one `HMACPkcs11` type covers them all. `Key` cannot be read or set.
- Like the [hash adapters](sha-2.md), it buffers the input and computes the MAC on the token in one call.
- The default `Recommended` policy allows HMAC with SHA-256 or stronger; HMAC-SHA-1 and HMAC-MD5 are
  refused, and reported at build time as `KLPKCS11010`.
- To check a MAC you received, compute it and compare with `CryptographicOperations.FixedTimeEquals`,
  never with `SequenceEqual`, which leaks through timing how many leading bytes matched.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.HMACPkcs11>.
