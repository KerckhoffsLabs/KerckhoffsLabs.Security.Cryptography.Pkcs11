# ML-DSA — `MLDsaPkcs11`

FIPS 204 signatures; see [Post-quantum cryptography](post-quantum.md) for what the token and the
platform need.

Sign on the token:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PostQuantum/MlDsaExamples.cs#MlDsaSign)]

Verify anywhere, with the public key and the BCL:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PostQuantum/MlDsaExamples.cs#MlDsaVerifyWithBcl)]

`SignData` and `VerifyData` take an optional context (up to 255 bytes) to bind a signature to its use,
as the BCL does. `SignPreHash` and `VerifyPreHash` (HashML-DSA over a hash you computed) throw
`NotSupportedException`: PKCS#11 v3.2 has no mechanism that signs a caller-supplied pre-hash, so the
token must hash the message itself. ML-DSA-65 is the general-purpose choice.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.MLDsaPkcs11>.
