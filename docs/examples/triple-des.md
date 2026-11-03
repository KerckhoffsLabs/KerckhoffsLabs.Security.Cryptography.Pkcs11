# Triple-DES — `TripleDESPkcs11`

It is a legacy algorithm: read [Legacy algorithms](legacy.md) for the two steps every use takes.

## Decrypting a Triple-DES archive

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/TripleDesExamples.cs#TripleDesDecryptLegacyArchive)]

Migrate as you read: decrypt the archive, then encrypt what you keep with [AES-GCM](aes-gcm.md) under a
new key, and retire the 3DES key.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.TripleDESPkcs11>.
