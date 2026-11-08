# ECDSA — `ECDsaPkcs11`

Sign on the token, with a key pair that lives there (see [Elliptic curves](elliptic-curves.md) for the curves).

## Generating a key pair

Once, when you provision the token, generate a P-256 signing key pair on it, as token objects under a label. Both halves
stay on the token after the session closes; the private key is sensitive and non-extractable, and each
half may do only its one job. The example exports the public key (SubjectPublicKeyInfo), for verifiers.

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/EllipticCurves/EcdsaExamples.cs#GenerateEcdsaKey)]

The BCL has nothing like this to store: `ECDsa.Create(ECCurve.NamedCurves.nistP256)` makes the key pair in your process, as on the BCL tab below, and keeping the private key is up to you.

## Signing with the key pair

In the application, open the pair by its label and sign:

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/EllipticCurves/EcdsaExamples.cs#SignP256)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/EllipticCurves/EcdsaExamples.cs#BclSignP256)]

---

Verify anywhere, with the public key and the plain BCL:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/EllipticCurves/EcdsaExamples.cs#VerifyWithBcl)]

**What differs from `ECDsa`:**

- The key pair is generated on the token (`session.GenerateEcSigningKeyPair`, a pair that can only sign
  and verify) instead of by `ECDsa.Create`, and opened from there by label (`session.OpenKey`).
- `ExportParameters(includePrivateParameters: true)` and the private-key export methods throw; export the
  public half with `ExportParameters(false)` or `ExportSubjectPublicKeyInfo()`.
- Signatures use the same formats as the BCL: IEEE P1363 (`r || s`) by default, DER with
  `DSASignatureFormat.Rfc3279DerSequence`.
- The default `Recommended` policy refuses curves below 128-bit security (P-192, P-224, the 160- to
  224-bit Brainpool and SEC curves) when you generate a key, and reports them at build time as
  `KLPKCS11007`. It does not inspect the curve of a key already on the token.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.ECDsaPkcs11>.
