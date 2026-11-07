# HKDF — `HkdfPkcs11`

## Generating a key

Once, when you provision the token, generate the input key material (a generic secret that may only derive) on it, as a token object under a label. It stays on
the token after the session closes, sensitive and non-extractable, allowed only what the page needs:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/KeyDerivation/HkdfExamples.cs#GenerateHkdfInputKey)]

The BCL has nothing like this to store: its key is random bytes in your process (`RandomNumberGenerator.GetBytes(32)`), as on the BCL tab below, and keeping them is up to you.

## Deriving a key

In the application, open the input key material by its label, derive an AES key from it on the token, and use that:

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
