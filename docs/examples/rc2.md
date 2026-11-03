# RC2 — `RC2Pkcs11`

It is a legacy algorithm: read [Legacy algorithms](legacy.md) for the two steps every use takes.

## Decrypting an RC2 record

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/Rc2Examples.cs#Rc2DecryptLegacyRecord)]

**RC2 has an effective key length** (RFC 2268) separate from the key size, and old data often used
40 bits. Set `rc2.EffectiveKeySize` to the value the data was encrypted with before decrypting: it
defaults to the key size, and a wrong value decrypts to garbage, or to a padding error, without saying
why. Many tokens no longer implement RC2 at all.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.RC2Pkcs11>.
