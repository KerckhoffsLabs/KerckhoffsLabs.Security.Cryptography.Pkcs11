# RC2 — `RC2Pkcs11`

It is a legacy algorithm: read [Legacy algorithms](legacy.md) for the two steps every use takes.

The example opens a key that is already on the token. These docs do not show creating new keys for this
algorithm, and the default policy refuses it: to replace the key, generate one as on the [AES-GCM](aes-gcm.md#generating-a-key) page.

## Decrypting an RC2 record

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/Rc2Examples.cs#Rc2DecryptLegacyRecord)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/Rc2Examples.cs#BclRc2DecryptLegacyRecord)]

---

**RC2 has an effective key length** (RFC 2268) separate from the key size, and old data often used
40 bits. Set `rc2.EffectiveKeySize` to the value the data was encrypted with before decrypting, on either
tab: it defaults to the key size, and a wrong value decrypts to garbage, or to a padding error, without
saying why.

**What differs from `RC2`:**

- The constructor takes the token key that holds the legacy key; `Key` cannot be read or set. The BCL's
  `RC2` needs the key bytes in your process, which is what keeping the key on the token avoids.
- The default policy refuses RC2: each use takes a scoped `UsePolicy(CryptoPolicy.AllowInsecure)` lease,
  and the adapter is `[Obsolete]` (`KLPKCS11005`), suppressed at the line that needs it.
- It decrypts exactly what the BCL's `RC2` does with the same key bytes and effective key size, through
  the one-shot methods (`DecryptCbc`, `DecryptEcb`); there is no `ICryptoTransform`.
- Many tokens no longer implement RC2 at all.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.RC2Pkcs11>.
