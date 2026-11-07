# HKDF — `HkdfPkcs11`

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/KeyDerivation/HkdfExamples.cs#HkdfDeriveAesKey)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/KeyDerivation/HkdfExamples.cs#BclHkdf)]

---

**What differs from `HKDF`:**

- The input key material is a token key that may derive (`CKA_DERIVE`): for example the shared secret of
  an [ECDH agreement](ecdh.md), which is how that example uses HKDF. The BCL takes it as bytes.
- `DeriveKey` with a template creates the output key on the token, instead of returning bytes; the key
  never enters your process. `Extract`/`ExtractKey` and `Expand`/`ExpandKey` run the two steps
  separately.
- The default policy accepts SHA-256, SHA-384, SHA-512 and SHA3-256/384/512 as the hash, and refuses
  the byte-returning overloads (see [Key derivation](key-derivation.md)).

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.HkdfPkcs11>.
