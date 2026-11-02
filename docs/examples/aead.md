# Authenticated encryption

AES-GCM, AES-CCM and ChaCha20-Poly1305 encrypt **and** authenticate: a ciphertext, tag or associated
data that was changed in transit fails to decrypt, instead of decrypting to something else. Use one of
them for any new encryption. The adapters have the same `Encrypt` and `Decrypt` as their
`System.Security.Cryptography` counterparts; the differences are that the key is a token key, not bytes,
and that the AES adapters fix the tag size when they are created.

Each example below shows the PKCS#11 code and the BCL code for the same task. Both are compiled and run
in CI.

## AES-GCM — `AesGcmPkcs11`

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/AeadExamples.cs#AesGcmEncryptDecrypt)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/AeadExamples.cs#BclAesGcmEncryptDecrypt)]

---

**What differs from `AesGcm`:**

- The constructor takes a `Pkcs11Key` (an AES key on the token) instead of key bytes. The key never
  enters your process.
- Generate nonces with `session.GenerateRandom` (the token's generator) or `RandomNumberGenerator`; both
  are fine. What matters is that a nonce is **never reused** with the same key: AES-GCM's
  confidentiality and authenticity both fail on a repeated nonce.
- `tagSizeInBytes` is fixed for the instance, as `AesGcm` requires since SYSLIB0053, and `Decrypt`
  refuses a tag of any other length. The default `Recommended` policy requires at least 12 bytes
  (96 bits), `NistApproved` 12 to 16 bytes. Use 16.
- The nonce is 12 bytes, as for `AesGcm`.

### Detecting tampering

A failed authentication throws `AuthenticationTagMismatchException`, as the BCL does:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/AeadExamples.cs#AesGcmDetectsTampering)]

Treat every exception from `Decrypt` the same way: reject the message, without telling the sender which
check failed.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.AesGcmPkcs11>.

## AES-CCM — `AesCcmPkcs11`

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/AeadExamples.cs#AesCcmEncryptDecrypt)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/AeadExamples.cs#BclAesCcmEncryptDecrypt)]

---

**What differs from `AesCcm`:**

- The key is a token key.
- **The tag size is fixed at construction.** `AesCcm(key)` takes the tag size from each call's tag, so
  its `Decrypt` would verify a forged tag of the shortest legal length; `AesCcmPkcs11` takes the size
  once and refuses any other, the same reasoning as SYSLIB0053 for `AesGcm`. The default `Recommended`
  policy and `NistApproved` refuse MACs under 8 bytes (64 bits, SP 800-38C Appendix B.2). Use 16.
- Nonces are 7 to 13 bytes, as for `AesCcm`; 12 is the common choice.
- AES-CCM needs the whole message to start: it does not stream. Prefer AES-GCM unless a protocol
  (IEEE 802.15.4, Bluetooth LE, some IoT stacks) requires CCM.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.AesCcmPkcs11>. See also
[Algorithm notes](../security-model.md#algorithm-notes).

## ChaCha20-Poly1305 — `ChaCha20Poly1305Pkcs11`

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/AeadExamples.cs#ChaCha20Poly1305EncryptDecrypt)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/AeadExamples.cs#BclChaCha20Poly1305EncryptDecrypt)]

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
