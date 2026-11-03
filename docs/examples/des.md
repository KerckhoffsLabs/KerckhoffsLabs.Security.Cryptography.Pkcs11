# DES — `DESPkcs11`

It is a legacy algorithm: read [Legacy algorithms](legacy.md) for the two steps every use takes.

## Decrypting a single-DES record

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/DesExamples.cs#DesDecryptLegacyRecord)]

Many tokens no longer implement single DES at all.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.DESPkcs11>.
