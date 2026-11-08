# Certificates

A certificate on a token is a `Pkcs11Certificate`: the `X509Certificate2` (`Certificate`) plus its label
and `CKA_ID`. Its private key is a separate object with the same `CKA_ID`. The extension methods in
`Pkcs11CertificateExtensions` find that key and return it as the BCL type, the way
`X509Certificate2.GetRSAPrivateKey()` and its siblings do for a software key.

## Issuing a certificate for a token key

This is where the key pair is generated: once, at provisioning, as token objects that carry the
certificate's label and `CKA_ID`, sensitive and non-extractable, the private key allowed only to sign.
The BCL's `CertificateRequest` builds the certificate; the token key signs it, and the certificate is
stored next to it. The signing example further down opens both again by the label:

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Certificates/CertificateExamples.cs#IssueSelfSignedCertificate)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Certificates/CertificateExamples.cs#BclIssueSelfSignedCertificate)]

---

**What differs from `CertificateRequest.CreateSelfSigned`:**

- **The key pair and the certificate share a `CKA_ID`.** That is how PKCS#11 links them, and how
  `GetECDsaPrivateKey` finds the key. The `Pkcs11Session` key-generation helpers do not set an id, so the
  example builds the templates.
- **Use `X509SignatureGenerator`, not `CreateSelfSigned`.** `CertificateRequest.CreateSelfSigned` returns
  a certificate with the private key attached, which means exporting it, and a token key cannot be
  exported. `request.Create(...)` with `X509SignatureGenerator.CreateForECDsa` (or the generator for another key
  type, below) only asks the key to sign. To have a certificate authority issue the certificate instead,
  `request.CreateSigningRequest()` works as it is: it only asks the key to sign the request.

## Other key types: RSA, ML-DSA and SLH-DSA

The steps are the same for every signing key: a key pair and a certificate sharing a `CKA_ID`, the
adapter passed to `CertificateRequest`, and the matching `X509SignatureGenerator`. The snippets below
start from the logged-in session of the example above, and leave the key pair and the certificate as
session objects; to keep them, add `.OnToken()` to both templates and pass `persistOnToken: true`, as it does.

| Key | Adapter | `CertificateRequest` | Signature generator |
|---|---|---|---|
| EC (above) | `ECDsaPkcs11` | `(subject, ecdsa, hash)` | `X509SignatureGenerator.CreateForECDsa` |
| RSA | `RSAPkcs11` | `(subject, rsa, hash, padding)` | `X509SignatureGenerator.CreateForRSA(rsa, padding)` |
| ML-DSA | `MLDsaPkcs11` | `(subject, mlDsa)` | `X509SignatureGenerator.CreateForMLDsa` |
| SLH-DSA | `SlhDsaPkcs11` | `(subject, slhDsa)` | `X509SignatureGenerator.CreateForSlhDsa` |

**RSA.** Sign with RSASSA-PSS. Use PKCS#1 v1.5 (`RSASignaturePadding.Pkcs1`, in both calls) only for a
relying party that does not accept PSS certificates; the default policy allows both for signatures.

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Certificates/CertificateExamples.cs#IssueRsaPssCertificate)]

**ML-DSA** (FIPS 204). The parameter set fixes the signature algorithm, so there is no hash to choose.
`MLDsa` is stable in .NET 10, but its `CertificateRequest` constructor and
`X509SignatureGenerator.CreateForMLDsa` are `[Experimental]` (SYSLIB5006). It needs a token with ML-DSA
(Kryoptic, for one), and the BCL needs OpenSSL 3.5 or later on Linux to verify the certificate.

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Certificates/CertificateExamples.cs#IssueMlDsaCertificate)]

**SLH-DSA** (FIPS 205). `SlhDsa` is `[Experimental]` in .NET 10 (SYSLIB5006). The small "s" parameter
sets are slow to sign and give a certificate with an 8 KB signature.

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Certificates/CertificateExamples.cs#IssueSlhDsaCertificate)]

## Checking a certificate's signature with the BCL

A certificate the token signed is an ordinary certificate. Its signature covers the DER of
`tbsCertificate`, and a self-signed certificate's own public key verifies it:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Certificates/CertificateExamples.cs#VerifySelfSignatureWithBcl)]

The tests check every certificate on this page this way. `X509Chain` is not a substitute here: with a
self-signed certificate added as its own `CustomTrustStore` root, `Build` succeeds even for a certificate
signed by another key, because a chain does not check its trust anchor's signature. It is the right tool
once the token key is a CA that issues other certificates: the chain checks those.

## Signing with a certificate's key — `Pkcs11CertificateExtensions`

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Certificates/CertificateExamples.cs#SignWithCertificateKey)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Certificates/CertificateExamples.cs#BclSignWithCertificateKey)]

---

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
