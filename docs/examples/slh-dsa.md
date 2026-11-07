# SLH-DSA — `SlhDsaPkcs11`

FIPS 205 hash-based signatures; see [Post-quantum cryptography](post-quantum.md) for what the token and
the platform need.

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
