# Post-quantum cryptography

The library supports the three NIST post-quantum standards, each as an adapter over the BCL type of the
same name:

| Standard | Purpose | Adapter | BCL type |
|---|---|---|---|
| FIPS 203 ML-KEM | Key establishment | `MLKemPkcs11` | `MLKem` |
| FIPS 204 ML-DSA | Signatures | `MLDsaPkcs11` | `MLDsa` |
| FIPS 205 SLH-DSA | Signatures (hash-based) | `SlhDsaPkcs11` | `SlhDsa` (`[Experimental]`, SYSLIB5006) |

They need a token that implements the PKCS#11 v3.2 mechanisms (`CKM_ML_KEM`, `CKM_ML_DSA`,
`CKM_SLH_DSA`). The BCL counterparts need a platform that supports them (`MLKem.IsSupported` and so on):
OpenSSL 3.5 or later on Linux, a recent Windows. No `Pkcs11Session` helper generates these keys yet, so
the examples build the templates; each names the parameter set and grants each half one role.

## Receiving a key with ML-KEM — `MLKemPkcs11`

The receiver publishes an encapsulation key; a sender uses it to produce a shared secret and a
ciphertext; the receiver recovers the same secret from the ciphertext. Here the receiver is the token and
the secret becomes an AES key on it:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PqcExamples.cs#MlKemReceiveAesKey)]

**Why `DecapsulateKey` and not `MLKemPkcs11.Decapsulate`?** The BCL-shaped `Encapsulate` and
`Decapsulate` return the shared secret to your process, so the default `Recommended` policy refuses them,
as it refuses reading an ECDH secret. `Pkcs11Key.DecapsulateKey` (`C_DecapsulateKey`) creates the secret
as a token key from your template, here an AES key for [AES-GCM](aead.md). Use `MLKemPkcs11` for
`ExportEncapsulationKey` and the other public-key members.

ML-KEM-768 is the general-purpose choice; ML-KEM-1024 for the highest security category; ML-KEM-512
where size matters most.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.MLKemPkcs11>,
<xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Pkcs11Key.DecapsulateKey*>.

## Signing with ML-DSA — `MLDsaPkcs11`

Sign on the token:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PqcExamples.cs#MlDsaSign)]

Verify anywhere, with the public key and the BCL:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PqcExamples.cs#MlDsaVerifyWithBcl)]

`SignData` and `VerifyData` take an optional context (up to 255 bytes) to bind a signature to its use,
as the BCL does. `SignPreHash` and `VerifyPreHash` (HashML-DSA over a hash you computed) throw
`NotSupportedException`: PKCS#11 v3.2 has no mechanism that signs a caller-supplied pre-hash, so the
token must hash the message itself. ML-DSA-65 is the general-purpose choice.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.MLDsaPkcs11>.

## Signing with SLH-DSA — `SlhDsaPkcs11`

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PqcExamples.cs#SlhDsaSign)]

SLH-DSA's security rests only on its hash function, which makes it the conservative choice for
long-lived signatures (firmware, roots of trust). Its signatures are large and slow to make: the "s"
(small) parameter sets give smaller signatures and slower signing than the "f" (fast) ones. Both
`SlhDsa` and `SlhDsaPkcs11` are `[Experimental]` in .NET 10, so their use is wrapped in
`#pragma warning disable SYSLIB5006`; expect the API to change.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.SlhDsaPkcs11>.
