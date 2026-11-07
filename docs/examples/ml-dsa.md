# ML-DSA — `MLDsaPkcs11`

FIPS 204 signatures; see [Post-quantum cryptography](post-quantum.md) for what the token and the
platform need.

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PostQuantum/MlDsaExamples.cs#MlDsaSign)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PostQuantum/MlDsaExamples.cs#BclMlDsaSign)]

---

Verify anywhere, with the public key and the BCL:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PostQuantum/MlDsaExamples.cs#MlDsaVerifyWithBcl)]

ML-DSA-65 is the general-purpose choice.

**What differs from `MLDsa`:**

- The key pair is generated on the token from templates that name the parameter set
  (`CKA_PARAMETER_SET`) and the two roles; there is no `MLDsaPkcs11.GenerateKey`. The private key never
  leaves the token: export the public key with `ExportMLDsaPublicKey`.
- `SignData` and `VerifyData` take an optional context (up to 255 bytes) to bind a signature to its use,
  as the BCL does.
- `SignPreHash` and `VerifyPreHash` (HashML-DSA over a hash you computed) throw
  `NotSupportedException`: PKCS#11 v3.2 has no mechanism that signs a caller-supplied pre-hash, so the
  token must hash the message itself.
- The BCL needs `MLDsa.IsSupported`; the adapter needs a token with `CKM_ML_DSA`.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.MLDsaPkcs11>.
