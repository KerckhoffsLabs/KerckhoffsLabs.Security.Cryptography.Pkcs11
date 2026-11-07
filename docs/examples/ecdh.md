# ECDH — `ECDiffieHellmanPkcs11`

Two parties agree on an AES key by exchanging public keys. On our side, everything stays on the token,
with a key pair from `GenerateEcKeyAgreementKeyPair` (see [Elliptic curves](elliptic-curves.md)); the
other party is any ECDH implementation, here the BCL's:

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/EllipticCurves/EcdhExamples.cs#AgreeAesKeyWithBclPeer)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/EllipticCurves/EcdhExamples.cs#BclAgreeAesKey)]

---

What happens on the token:

1. `DeriveSecretAgreement` runs `CKM_ECDH1_DERIVE` with the peer's public key and keeps the shared
   secret Z as a token object. Z can feed a key-derivation function and nothing else: it cannot encrypt,
   sign or wrap, as SP 800-56A requires. The peer's public key is checked first: same curve, a point on
   the curve.
2. [`HkdfPkcs11.DeriveKey`](hkdf.md) runs HKDF on Z and creates the AES key from the template, on the
   token. Use a salt and an `info` string that names your protocol, so the key cannot be confused with
   another one.

The peer does the same with `DeriveRawSecretAgreement` and `HKDF.DeriveKey`, and ends with the same 32
bytes as key material.

**What differs from `ECDiffieHellman`:**

- The key pair is generated on the token (`session.GenerateEcKeyAgreementKeyPair`, a pair that can only
  agree on keys). Send the other party `PublicKey`, as with the BCL.
- **The shared secret stays on the token.** `Pkcs11Key.DeriveSecretAgreement` and `HkdfPkcs11.DeriveKey`
  replace `DeriveRawSecretAgreement` and `HKDF.DeriveKey`; the BCL tab has Z and the AES key in your
  process.
- **Why not `DeriveKeyFromHash` or `DeriveKeyMaterial`?** `ECDiffieHellmanPkcs11` implements them, as the
  `ECDiffieHellman` contract requires, but they return the derived secret to your process, which defeats
  the point of a token. The default `Recommended` policy therefore refuses them with
  `CryptoPolicyViolationException`. Reading the secret anyway takes a policy whose key-material export
  rule allows it (`CryptoPolicyBuilder.WithKeyMaterialExportRule`, see
  <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.KeyMaterialExportRule>).

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.ECDiffieHellmanPkcs11>,
<xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Pkcs11Key.DeriveSecretAgreement*>.
