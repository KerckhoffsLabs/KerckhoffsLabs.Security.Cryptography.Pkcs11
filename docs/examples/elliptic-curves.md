# Elliptic curves

`ECDsaPkcs11` is an `ECDsa` and `ECDiffieHellmanPkcs11` an `ECDiffieHellman`, both over a token key pair.
Each role has its own key pair: `Pkcs11Session.GenerateEcSigningKeyPair` creates one that can only sign
and verify (ECDSA), and `GenerateEcKeyAgreementKeyPair` one that can only derive (ECDH). Both default to
P-256, and their private keys are sensitive and non-extractable.

## Signing with ECDSA — `ECDsaPkcs11`

Sign on the token:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/EcExamples.cs#SignP256)]

Verify anywhere, with the public key and the plain BCL:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/EcExamples.cs#VerifyWithBcl)]

**What differs from `ECDsa`:**

- `ExportParameters(includePrivateParameters: true)` and the private-key export methods throw; export the
  public half with `ExportParameters(false)` or `ExportSubjectPublicKeyInfo()`.
- Signatures use the same formats as the BCL: IEEE P1363 (`r || s`) by default, DER with
  `DSASignatureFormat.Rfc3279DerSequence`.
- The default `Recommended` policy refuses curves below 128-bit security (P-192, P-224, the 160- to
  224-bit Brainpool and SEC curves) when you generate a key, and reports them at build time as
  `KLPKCS11007`. It does not inspect the curve of a key already on the token.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.ECDsaPkcs11>.

## Key agreement with ECDH — `ECDiffieHellmanPkcs11`

Two parties agree on an AES key by exchanging public keys. On our side, everything stays on the token:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/EcExamples.cs#AgreeAesKeyWithBclPeer)]

What happens on the token:

1. `DeriveSecretAgreement` runs `CKM_ECDH1_DERIVE` with the peer's public key and keeps the shared
   secret Z as a token object. Z can feed a key-derivation function and nothing else: it cannot encrypt,
   sign or wrap, as SP 800-56A requires. The peer's public key is checked first: same curve, a point on
   the curve.
2. `HkdfPkcs11.DeriveKey` runs HKDF on Z and creates the AES key from the template, on the token. Use a
   salt and an `info` string that names your protocol, so the key cannot be confused with another one.

The peer does the same with `DeriveRawSecretAgreement` and `HKDF.DeriveKey`, and ends with the same 32
bytes as key material.

**Why not `DeriveKeyFromHash` or `DeriveKeyMaterial`?** `ECDiffieHellmanPkcs11` implements them, as the
`ECDiffieHellman` contract requires, but they return the derived secret to your process, which defeats
the point of a token. The default `Recommended` policy therefore refuses them with
`CryptoPolicyViolationException`. Use `ECDiffieHellmanPkcs11` for its `PublicKey` (what you send to the
other party) and the on-token path above for the secret. Reading the secret anyway takes a policy whose
key-material export rule allows it (`CryptoPolicyBuilder.WithKeyMaterialExportRule`, see
<xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.KeyMaterialExportRule>).

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.ECDiffieHellmanPkcs11>,
<xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Pkcs11Key.DeriveSecretAgreement*>.
