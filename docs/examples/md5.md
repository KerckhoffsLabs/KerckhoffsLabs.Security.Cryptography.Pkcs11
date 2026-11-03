# MD5 — `MD5Pkcs11`

It is a legacy algorithm: read [Legacy algorithms](legacy.md) for the two steps every use takes.

## MD5 for a legacy protocol

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/Md5Examples.cs#Md5ChecksumForLegacyProtocol)]

This is for protocols that still name or index data by MD5, where the hash is an identifier, not a
security guarantee. An attacker can produce two inputs with the same MD5, so never rely on it for
integrity or signatures; use [SHA-256](sha-2.md) for anything new. Hashing on a token gains nothing in
secrecy; the BCL's `MD5` does the same off the token.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.MD5Pkcs11>.
