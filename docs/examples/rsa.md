# RSA

`RSAPkcs11` is an `RSA` over a token key pair. Code written against `System.Security.Cryptography.RSA` —
`SignData`, `VerifyData`, `Encrypt`, `Decrypt`, `ExportParameters(false)` — works unchanged; the private
key operations run on the token, and the private key never leaves it.

Each RSA key pair has one role. `GenerateRsaSigningKeyPair` creates a pair that can only sign and verify;
`GenerateRsaKeyTransportKeyPair` one that can only encrypt and decrypt. See
[Key role separation](../guide/security-model.md#key-role-separation).

## Generating a signing key pair

Once, when you provision the token, generate the key pair on it, as token objects under a label. Both
halves stay on the token after the session closes; the private key is sensitive and non-extractable, and
the pair may only sign and verify. The example exports the public key (SubjectPublicKeyInfo), for
verifiers.

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Rsa/RsaExamples.cs#GenerateRsaSigningKey)]

The BCL has nothing like this to store: `RSA.Create(3072)` makes the key pair in your process, as on the
BCL tab below, and keeping the private key is up to you.

## Signing with RSA-PSS

In the application, open the pair by its label and sign on the token:

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Rsa/RsaExamples.cs#SignPss)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Rsa/RsaExamples.cs#BclSignPss)]

---

Verify anywhere, with the public key and the plain BCL:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Rsa/RsaExamples.cs#VerifyPssWithBcl)]

The signature is a standard RSASSA-PSS signature: the verifier does not need a token, PKCS#11 or this
library. `RSAPkcs11.VerifyData` also works, and runs on the token.

## Signing with RSASSA-PKCS1-v1_5

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Rsa/RsaExamples.cs#SignPkcs1v15)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Rsa/RsaExamples.cs#BclSignPkcs1v15)]

---

PKCS#1 v1.5 *signatures* with a SHA-2 or SHA-3 hash are allowed by the default policy: they are
FIPS 186-5-approved and required by JWT `RS256`, TLS 1.2, X.509 and code signing. Prefer PSS for new
formats. PKCS#1 v1.5 *encryption* is a different matter; see below.

## Encrypting with RSA-OAEP

A key-transport key pair has a different role, so it is a different pair. Generate it once, as above:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/Rsa/RsaExamples.cs#GenerateRsaKeyTransportKey)]

Then, in the application, open it by its label; anyone with the public key encrypts, and the token
decrypts:

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
  policy judges requests, not existing keys. See [Known limits](../guide/security-model.md#known-limits).

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.RSAPkcs11>.
