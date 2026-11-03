# AES-CCM — `AesCcmPkcs11`

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
