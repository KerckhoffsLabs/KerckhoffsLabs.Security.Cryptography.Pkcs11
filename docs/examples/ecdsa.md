# ECDSA — `ECDsaPkcs11`

Sign on the token, with a key pair from `GenerateEcSigningKeyPair` (see [Elliptic curves](elliptic-curves.md)):

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/EllipticCurves/EcdsaExamples.cs#SignP256)]

Verify anywhere, with the public key and the plain BCL:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/EllipticCurves/EcdsaExamples.cs#VerifyWithBcl)]

**What differs from `ECDsa`:**

- `ExportParameters(includePrivateParameters: true)` and the private-key export methods throw; export the
  public half with `ExportParameters(false)` or `ExportSubjectPublicKeyInfo()`.
- Signatures use the same formats as the BCL: IEEE P1363 (`r || s`) by default, DER with
  `DSASignatureFormat.Rfc3279DerSequence`.
- The default `Recommended` policy refuses curves below 128-bit security (P-192, P-224, the 160- to
  224-bit Brainpool and SEC curves) when you generate a key, and reports them at build time as
  `KLPKCS11007`. It does not inspect the curve of a key already on the token.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.ECDsaPkcs11>.
