# ChaCha20-Poly1305 — `ChaCha20Poly1305Pkcs11`

## Generating a key

Once, when you provision the token, generate a ChaCha20 key on it, as a token object under a label. It stays on
the token after the session closes, sensitive and non-extractable, allowed only what the page needs:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Aead/ChaCha20Poly1305Examples.cs#GenerateChaCha20Key)]

The BCL has nothing like this to store: its key is random bytes in your process (`RandomNumberGenerator.GetBytes(32)`), as on the BCL tab below, and keeping them is up to you.

## Encrypting with the key

In the application, open the key by its label and encrypt and decrypt with it:

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Aead/ChaCha20Poly1305Examples.cs#ChaCha20Poly1305EncryptDecrypt)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Aead/ChaCha20Poly1305Examples.cs#BclChaCha20Poly1305EncryptDecrypt)]

---

**What differs from `ChaCha20Poly1305`:**

- The key is a token ChaCha20 key. The library has no helper that generates one, so the example builds
  the template; `ObjectTemplate.ForSecretKey` starts sensitive and non-extractable with every role off,
  and the example grants only encrypt and decrypt.
- The nonce is 12 bytes and the tag 16, fixed by RFC 8439, as for the BCL.
- Fewer tokens implement `CKM_CHACHA20_POLY1305` than AES-GCM; check with
  `key.SupportsMechanism(CKM.CKM_CHACHA20_POLY1305)` or the token's mechanism list.
- The default `Recommended` policy allows it. `NistApproved` refuses it: ChaCha20-Poly1305 is not a
  NIST-approved algorithm.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.ChaCha20Poly1305Pkcs11>.
