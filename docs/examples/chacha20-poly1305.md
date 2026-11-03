# ChaCha20-Poly1305 — `ChaCha20Poly1305Pkcs11`

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
