# AES-GCM — `AesGcmPkcs11`

AES-GCM is the default choice for [authenticated encryption](aead.md).

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Aead/AesGcmExamples.cs#AesGcmEncryptDecrypt)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Aead/AesGcmExamples.cs#BclAesGcmEncryptDecrypt)]

---

**What differs from `AesGcm`:**

- The constructor takes a `Pkcs11Key` (an AES key on the token) instead of key bytes. The key never
  enters your process.
- Generate nonces with `session.GenerateRandom` (the token's generator) or `RandomNumberGenerator`; both
  are fine. What matters is that a nonce is **never reused** with the same key: AES-GCM's
  confidentiality and authenticity both fail on a repeated nonce.
- `tagSizeInBytes` is fixed for the instance, as for `AesGcm(key, tagSizeInBytes)` (the constructor
  without it is obsolete, SYSLIB0053, and has no counterpart here), and `Decrypt` refuses a tag of any
  other length. The default `Recommended` policy requires at least 12 bytes
  (96 bits), `NistApproved` 12 to 16 bytes. Use 16.
- The nonce is 12 bytes, as for `AesGcm`.

## Detecting tampering

A failed authentication usually throws `AuthenticationTagMismatchException`, as the BCL does. Some tokens
report a bad tag with a generic error code, which the library cannot tell apart from a real fault, so it
surfaces as a `Pkcs11Exception`. Both are `CryptographicException`s; catch that. Here `aesGcm`, `nonce`,
`ciphertext` and `tag` come from an encryption as in the example above:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Aead/AesGcmExamples.cs#AesGcmDetectsTampering)]

Treat every exception from `Decrypt` the same way: reject the message, without telling the sender which
check failed.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.AesGcmPkcs11>.
