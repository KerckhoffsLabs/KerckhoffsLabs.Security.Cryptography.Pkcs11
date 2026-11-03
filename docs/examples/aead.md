# Authenticated encryption

AES-GCM, AES-CCM and ChaCha20-Poly1305 encrypt **and** authenticate: a ciphertext, tag or associated
data that was changed in transit fails to decrypt, instead of decrypting to something else. Use one of
them for any new encryption. The adapters have the same `Encrypt` and `Decrypt` as their
`System.Security.Cryptography` counterparts; the main difference is that the key is a token key, not
bytes. `AesCcmPkcs11` also fixes the tag size when it is created, where `AesCcm` takes it from each call.

| Algorithm | Adapter | BCL type | Use it |
|---|---|---|---|
| [AES-GCM](aes-gcm.md) | `AesGcmPkcs11` | `AesGcm` | by default |
| [AES-CCM](aes-ccm.md) | `AesCcmPkcs11` | `AesCcm` | where a protocol requires CCM |
| [ChaCha20-Poly1305](chacha20-poly1305.md) | `ChaCha20Poly1305Pkcs11` | `ChaCha20Poly1305` | where the token has it and NIST approval is not required |

Each page shows the PKCS#11 code and the BCL code for the same task. Both are compiled and run in CI.
