# MD5 — `MD5Pkcs11`

It is a legacy algorithm: read [Legacy algorithms](legacy.md) for the two steps every use takes.

## MD5 for a legacy protocol

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/Md5Examples.cs#Md5ChecksumForLegacyProtocol)]

This is for protocols that still name or index data by MD5, where the hash is an identifier, not a
security guarantee. An attacker can produce two inputs with the same MD5, so never rely on it for
integrity or signatures; use [SHA-256](sha-2.md) for anything new. Hashing on a token gains nothing in
secrecy, and the BCL's `MD5` gives the same bytes off the token, without the policy lease:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/Md5Examples.cs#BclMd5)]

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.MD5Pkcs11>.
