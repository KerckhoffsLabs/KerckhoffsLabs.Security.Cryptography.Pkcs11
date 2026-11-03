# RSA

`RSAPkcs11` is an `RSA` over a token key pair. Code written against `System.Security.Cryptography.RSA` —
`SignData`, `VerifyData`, `Encrypt`, `Decrypt`, `ExportParameters(false)` — works unchanged; the private
key operations run on the token, and the private key never leaves it.

Each RSA key pair has one role. `GenerateRsaSigningKeyPair` creates a pair that can only sign and verify;
`GenerateRsaKeyTransportKeyPair` one that can only encrypt and decrypt. See
[Key role separation](../security-model.md#key-role-separation).

## Signing with RSA-PSS

Sign on the token:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Rsa/RsaExamples.cs#SignPss)]

Verify anywhere, with the public key and the plain BCL:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Rsa/RsaExamples.cs#VerifyPssWithBcl)]

The signature is a standard RSASSA-PSS signature: the verifier does not need a token, PKCS#11 or this
library. `RSAPkcs11.VerifyData` also works, and runs on the token.

## Signing with RSASSA-PKCS1-v1_5

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Rsa/RsaExamples.cs#SignPkcs1v15)]

PKCS#1 v1.5 *signatures* with a SHA-2 or SHA-3 hash are allowed by the default policy: they are
FIPS 186-5-approved and required by JWT `RS256`, TLS 1.2, X.509 and code signing. Prefer PSS for new
formats. PKCS#1 v1.5 *encryption* is a different matter; see below.

## Encrypting with RSA-OAEP

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Rsa/RsaExamples.cs#OaepEncryptDecrypt)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Rsa/RsaExamples.cs#BclOaepEncryptDecrypt)]

---

RSA encrypts only a short message (with a 3072-bit key and OAEP-SHA-256, at most 318 bytes). To encrypt
data, encrypt a random AES key with RSA-OAEP and the data with [AES-GCM](aes-gcm.md) under that key, or
use [ML-KEM](ml-kem.md) as the key-establishment step.

## What differs from `RSA`

- **The key is on the token.** `ExportParameters(includePrivateParameters: true)` always throws
  `CryptoPolicyViolationException`, whatever the policy: the adapter never exports a private key. Export
  the public half with `ExportParameters(false)` or `ExportSubjectPublicKeyInfo()`.
- **Policy limits** under the default `Recommended` policy:
  - generated keys must have a modulus of at least 2048 bits; use 3072 or more for new keys;
  - PSS and OAEP must use SHA-256 or stronger; OAEP with SHA-1 is refused;
  - **PKCS#1 v1.5 encryption** (`RSAEncryptionPadding.Pkcs1`) is refused, and reported at build time as
    `KLPKCS11008`: it is exposed to Bleichenbacher padding-oracle attacks, and on some tokens a bad
    padding does not even fail. See
    [PKCS#1 v1.5 decryption and implicit rejection](../diagnostics.md#pkcs1-implicit-rejection).
- **Ciphertexts are checked before they reach the token:** a ciphertext must be exactly the modulus's
  length, and its value below the modulus, as the BCL requires.
- **Keys already on the token are not inspected.** A 1024-bit key imported long ago still works; the
  policy judges requests, not existing keys. See [Known limits](../security-model.md#known-limits).

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.RSAPkcs11>.
