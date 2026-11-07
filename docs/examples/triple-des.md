# Triple-DES — `TripleDESPkcs11`

It is a legacy algorithm: read [Legacy algorithms](legacy.md) for the two steps every use takes.

## Decrypting a Triple-DES archive

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/TripleDesExamples.cs#TripleDesDecryptLegacyArchive)]

Migrate as you read: decrypt the archive, then encrypt what you keep with [AES-GCM](aes-gcm.md) under a
new key, and retire the 3DES key.

The adapter is a `TripleDES` over the token key, so it decrypts exactly what the BCL's `TripleDES` does with the same key
bytes. In software the key has to be in your process, which is what keeping it on the token avoids; use
this only for data whose key already lives in software:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/TripleDesExamples.cs#BclTripleDesDecryptLegacyArchive)]

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.TripleDESPkcs11>.
