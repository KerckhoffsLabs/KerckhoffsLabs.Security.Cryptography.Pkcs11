# SLH-DSA — `SlhDsaPkcs11`

FIPS 205 hash-based signatures; see [Post-quantum cryptography](post-quantum.md) for what the token and
the platform need.

## Generating a key pair

Once, when you provision the token, generate an SLH-DSA-SHA2-128s key pair on it, as token objects under a label. Both halves
stay on the token after the session closes; the private key is sensitive and non-extractable, and each
half may do only its one job. The example exports the public key, for verifiers.

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PostQuantum/SlhDsaExamples.cs#GenerateSlhDsaKey)]

The BCL has nothing like this to store: `SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s)` makes the key pair in your process, as on the BCL tab below, and keeping the private key is up to you.

## Signing with the key pair

In the application, open the pair by its label and sign:

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PostQuantum/SlhDsaExamples.cs#SlhDsaSign)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PostQuantum/SlhDsaExamples.cs#BclSlhDsaSign)]

---

SLH-DSA's security rests only on its hash function, which makes it the conservative choice for
long-lived signatures (firmware, roots of trust). Its signatures are large and slow to make: the "s"
(small) parameter sets give smaller signatures and slower signing than the "f" (fast) ones.

**What differs from `SlhDsa`:**

- The key pair is generated on the token from templates that name the parameter set
  (`CKA_PARAMETER_SET`) and the two roles; there is no `SlhDsaPkcs11.GenerateKey`. The private key never
  leaves the token: export the public key with `ExportSlhDsaPublicKey`.
- The signature is a standard FIPS 205 signature: the BCL's `SlhDsa` verifies it from the exported
  public key, no token needed.
- Both `SlhDsa` and `SlhDsaPkcs11` are `[Experimental]` in .NET 10, so their use is wrapped in
  `#pragma warning disable SYSLIB5006`; expect the API to change. The BCL needs `SlhDsa.IsSupported`;
  the adapter needs a token with `CKM_SLH_DSA`.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.SlhDsaPkcs11>.
