# ML-DSA — `MLDsaPkcs11`

FIPS 204 signatures; see [Post-quantum cryptography](post-quantum.md) for what the token and the
platform need.

## Generating a key pair

Once, when you provision the token, generate an ML-DSA-65 key pair on it, as token objects under a label. Both halves
stay on the token after the session closes; the private key is sensitive and non-extractable, and each
half may do only its one job. The example exports the public key, for verifiers.

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PostQuantum/MlDsaExamples.cs#GenerateMlDsaKey)]

The BCL has nothing like this to store: `MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65)` makes the key pair in your process, as on the BCL tab below, and keeping the private key is up to you.

## Signing with the key pair

In the application, open the pair by its label and sign:

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
