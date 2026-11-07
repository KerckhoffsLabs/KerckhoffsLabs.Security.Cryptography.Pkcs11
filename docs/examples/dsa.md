# DSA — `DSAPkcs11`

It is a legacy algorithm: read [Legacy algorithms](legacy.md) for the two steps every use takes.

The example opens a key that is already on the token. These docs do not show creating new keys for this
algorithm, and the default policy refuses it: to replace the key, generate one as on the [ECDSA](ecdsa.md#generating-a-key-pair) or [ML-DSA](ml-dsa.md#generating-a-key-pair) page.

## Verifying an old DSA signature

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/DsaExamples.cs#DsaVerifyLegacySignature)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Legacy/DsaExamples.cs#BclDsaVerifyLegacySignature)]

---

Sign anything new with [ECDSA](ecdsa.md), [ML-DSA](ml-dsa.md) or [RSA-PSS](rsa.md).

**What differs from `DSA`:**

- The constructor takes a token key. Verifying needs only the public key, so the BCL verifies the same
  signature from the token key's `ExportParameters(false)`; `ExportParameters(true)` throws.
- The default policy refuses DSA: each use takes a scoped `UsePolicy(CryptoPolicy.AllowInsecure)` lease,
  and the adapter is `[Obsolete]` (`KLPKCS11006`), suppressed at the line that needs it. FIPS 186-5
  disallows DSA for new signatures.
- Signatures use the BCL's formats: IEEE P1363 (`r || s`) by default, DER with
  `DSASignatureFormat.Rfc3279DerSequence`.
- macOS's `DSA` takes only 1024-bit keys, so the BCL tab does not run there for a 2048-bit key.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.DSAPkcs11>.
