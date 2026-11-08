# AES-CCM — `AesCcmPkcs11`

## Generating a key

Once, when you provision the token, generate an AES-256 key on it, as a token object under a label. It stays on
the token after the session closes, sensitive and non-extractable, allowed only what the page needs:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Aead/AesCcmExamples.cs#GenerateAesCcmKey)]

The BCL has nothing like this to store: its key is random bytes in your process (`RandomNumberGenerator.GetBytes(32)`), as on the BCL tab below, and keeping them is up to you.

## Encrypting with the key

In the application, open the key by its label and encrypt and decrypt with it:

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Aead/AesCcmExamples.cs#AesCcmEncryptDecrypt)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Aead/AesCcmExamples.cs#BclAesCcmEncryptDecrypt)]

---

**What differs from `AesCcm`:**

- The key is a token key.
- **The tag size is fixed at construction.** `AesCcm(key)` takes the tag size from each call's tag, so
  its `Decrypt` would verify a forged tag of the shortest legal length; `AesCcmPkcs11` takes the size
  once and refuses any other, the same reasoning as SYSLIB0053 for `AesGcm`. The default `Recommended`
  policy and `NistApproved` refuse MACs under 8 bytes (64 bits, SP 800-38C Appendix B.2). Use 16.
- Nonces are 7 to 13 bytes, as for `AesCcm`; 12 is the common choice.
- AES-CCM needs the whole message to start: it does not stream. Prefer [AES-GCM](aes-gcm.md) unless a
  protocol (IEEE 802.15.4, Bluetooth LE, some IoT stacks) requires CCM.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.AesCcmPkcs11>. See also
[Algorithm notes](../guide/security-model.md#algorithm-notes).
