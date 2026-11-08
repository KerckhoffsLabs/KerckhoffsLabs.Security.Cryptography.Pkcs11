# DES — `DESPkcs11`

It is a legacy algorithm: read [Legacy algorithms](legacy.md) for the two steps every use takes.

The example opens a key that is already on the token. These docs do not show creating new keys for this
algorithm, and the default policy refuses it: to replace the key, generate one as on the [AES-GCM](aes-gcm.md#generating-a-key) page.

## Decrypting a single-DES record

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/DesExamples.cs#DesDecryptLegacyRecord)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/DesExamples.cs#BclDesDecryptLegacyRecord)]

---

**What differs from `DES`:**

- The constructor takes the token key that holds the legacy key; `Key` cannot be read or set. The BCL's
  `DES` needs the key bytes in your process, which is what keeping the key on the token avoids.
- The default policy refuses single DES: each use takes a scoped `UsePolicy(CryptoPolicy.AllowInsecure)`
  lease, and the adapter is `[Obsolete]` (`KLPKCS11003`), suppressed at the line that needs it.
- It decrypts exactly what the BCL's `DES` does with the same key bytes, through the one-shot methods
  (`DecryptCbc`, `DecryptEcb`); there is no `ICryptoTransform`.
- Many tokens no longer implement single DES at all.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.DESPkcs11>.
