# Triple-DES — `TripleDESPkcs11`

It is a legacy algorithm: read [Legacy algorithms](legacy.md) for the two steps every use takes.

## Decrypting a Triple-DES archive

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/TripleDesExamples.cs#TripleDesDecryptLegacyArchive)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/TripleDesExamples.cs#BclTripleDesDecryptLegacyArchive)]

---

Migrate as you read: decrypt the archive, then encrypt what you keep with [AES-GCM](aes-gcm.md) under a
new key, and retire the 3DES key.

**What differs from `TripleDES`:**

- The constructor takes the token key that holds the legacy key; `Key` cannot be read or set. The BCL's
  `TripleDES` needs the key bytes in your process, which is what keeping the key on the token avoids.
- The default policy refuses 3DES: each use takes a scoped `UsePolicy(CryptoPolicy.AllowInsecure)` lease,
  and the adapter is `[Obsolete]` (`KLPKCS11004`), suppressed at the line that needs it.
- It decrypts exactly what the BCL's `TripleDES` does with the same key bytes, through the one-shot
  methods (`DecryptCbc`, `DecryptEcb`); there is no `ICryptoTransform`.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.TripleDESPkcs11>.
