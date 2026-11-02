# Certificates

A certificate on a token is a `Pkcs11Certificate`: the `X509Certificate2` (`Certificate`) plus its label
and `CKA_ID`. Its private key is a separate object with the same `CKA_ID`. The extension methods in
`Pkcs11CertificateExtensions` find that key and return it as the BCL type, the way
`X509Certificate2.GetRSAPrivateKey()` and its siblings do for a software key.

## Issuing a certificate for a token key

The BCL's `CertificateRequest` builds the certificate; the token key signs it:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/CertificateExamples.cs#IssueSelfSignedCertificate)]

Two details matter:

- **The key pair and the certificate share a `CKA_ID`.** That is how PKCS#11 links them, and how
  `GetECDsaPrivateKey` finds the key. The `Pkcs11Session` key-generation helpers do not set an id, so the
  example builds the templates.
- **Use `X509SignatureGenerator`, not `CreateSelfSigned`.** `CertificateRequest.CreateSelfSigned` returns
  a certificate with the private key attached, which means exporting it, and a token key cannot be
  exported. `request.Create(...)` with `X509SignatureGenerator.CreateForECDsa` (or `CreateForRSA`) only
  asks the key to sign. To have a certificate authority issue the certificate instead,
  `request.CreateSigningRequest()` works as it is: it only asks the key to sign the request.

## Signing with a certificate's key — `Pkcs11CertificateExtensions`

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/CertificateExamples.cs#SignWithCertificateKey)]

**What differs from `X509Certificate2.GetECDsaPrivateKey()`:**

- The extensions are on `Pkcs11Certificate`, not `X509Certificate2`, and the returned `ECDsa` is an
  `ECDsaPkcs11` over the token key. Dispose it.
- They return `null` in the same cases as the BCL: the certificate holds a different key type, its key
  usage rules the purpose out (an EC certificate for key agreement only has no ECDSA key), or no private
  key with its `CKA_ID` exists on the token.
- There is one for each key type: `GetRSAPrivateKey`, `GetECDsaPrivateKey`,
  `GetECDiffieHellmanPrivateKey`, `GetDSAPrivateKey`, and the post-quantum `GetMLDsaPrivateKey`,
  `GetMLKemPrivateKey`, `GetSlhDsaPrivateKey` (`[Experimental]`, SYSLIB5006).
- `Pkcs11Certificate.GetPrivateKey()` returns the raw `Pkcs11Key` instead, for use with any adapter.

To find certificates, use `session.OpenCertificate(label)` or `OpenCertificate(id)` for one, and
`session.FindCertificates()` for all of them.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.Pkcs11CertificateExtensions>,
<xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Pkcs11Certificate>.
