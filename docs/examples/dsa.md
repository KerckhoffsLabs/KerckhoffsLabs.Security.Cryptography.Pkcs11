# DSA — `DSAPkcs11`

It is a legacy algorithm: read [Legacy algorithms](legacy.md) for the two steps every use takes.

## Verifying an old DSA signature

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/DsaExamples.cs#DsaVerifyLegacySignature)]

Verifying a DSA signature needs only the public key, so the BCL's `DSA`, built from the token key's
`ExportParameters(false)`, verifies the same signature off the token:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/DsaExamples.cs#DsaVerifyWithBcl)]

Sign anything new with [ECDSA](ecdsa.md), [ML-DSA](ml-dsa.md) or [RSA-PSS](rsa.md).

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.DSAPkcs11>.
