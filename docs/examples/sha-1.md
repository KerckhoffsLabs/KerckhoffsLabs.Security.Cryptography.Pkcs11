# SHA-1 — `SHA1Pkcs11`

It is a legacy algorithm: read [Legacy algorithms](legacy.md) for the two steps every use takes.

## SHA-1 for a legacy protocol

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/Sha1Examples.cs#Sha1ForLegacyProtocol)]

This is for protocols that still name or index data by SHA-1, where the hash is an identifier, not a
security guarantee. An attacker can produce two inputs with the same SHA-1, so never rely on it for
integrity or signatures; use [SHA-256](sha-2.md) for anything new. Hashing on a token gains nothing in
secrecy; the BCL's `SHA1` does the same off the token.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.SHA1Pkcs11>.
