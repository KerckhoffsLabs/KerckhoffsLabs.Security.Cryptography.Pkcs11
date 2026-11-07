# Examples

Every algorithm the library offers, each shown next to its `System.Security.Cryptography` equivalent.
Every snippet on these pages is compiled and run against real PKCS#11 tokens in CI, so what you read is
what works.

Each page's first PKCS#11 example is a complete flow: it loads the module, opens a session and logs in
with a PIN read from your secret store, opens the key that is already on the token by its label (or
generates one, where generating it is the point), uses it, and disposes everything. Later snippets on a
page start from that session or key. The module path, the token label and the key labels are parameters,
to come from your configuration; see [Getting started](../guide/getting-started.md) for each step.

The examples keep keys on the token: keys are generated or derived there, sensitive and non-extractable,
with only the roles they need.

## Encryption

| Algorithm | Adapter | Use it |
|---|---|---|
| [AES-GCM](aes-gcm.md) | `AesGcmPkcs11` | for new encryption, by default |
| [AES-CCM](aes-ccm.md) | `AesCcmPkcs11` | where a protocol requires CCM |
| [ChaCha20-Poly1305](chacha20-poly1305.md) | `ChaCha20Poly1305Pkcs11` | where the token has it and NIST approval is not required |
| [AES block modes](aes.md) | `AesPkcs11` | CBC, ECB or CFB, for interop only, under a reviewed policy |

## Signatures and key agreement

| Algorithm | Adapter | Use it |
|---|---|---|
| [RSA](rsa.md) | `RSAPkcs11` | RSA-PSS signatures, RSA-OAEP key transport |
| [ECDSA](ecdsa.md) | `ECDsaPkcs11` | elliptic-curve signatures |
| [ECDH](ecdh.md) | `ECDiffieHellmanPkcs11` | key agreement, with the shared secret kept on the token |

## Post-quantum

| Algorithm | Adapter | Use it |
|---|---|---|
| [ML-KEM](ml-kem.md) | `MLKemPkcs11` | key establishment (FIPS 203) |
| [ML-DSA](ml-dsa.md) | `MLDsaPkcs11` | signatures (FIPS 204) |
| [SLH-DSA](slh-dsa.md) | `SlhDsaPkcs11` | hash-based signatures for long-lived keys (FIPS 205) |

## Hashing and MACs

| Algorithm | Adapter | Use it |
|---|---|---|
| [SHA-2](sha-2.md) | `SHA256Pkcs11`, `SHA384Pkcs11`, `SHA512Pkcs11` | when the token must compute the digest |
| [SHA-3](sha-3.md) | `SHA3_256Pkcs11`, `SHA3_384Pkcs11`, `SHA3_512Pkcs11` | when the token must compute the digest |
| [HMAC](hmac.md) | `HMACPkcs11` | message authentication with a token key |

## Key derivation

| Function | Adapter | Derives a key from |
|---|---|---|
| [HKDF](hkdf.md) | `HkdfPkcs11` | key material: a shared secret, a master key |
| [PBKDF2](pbkdf2.md) | `Rfc2898DeriveBytesPkcs11` | a password |
| [SP 800-108](sp800-108.md) | `SP800108HmacCounterKdfPkcs11` | a key-derivation key, a label and a context |

## Certificates and legacy algorithms

- [Certificates](certificates.md): issue a certificate for a token key, and sign with a certificate's key
  through `Pkcs11CertificateExtensions`.
- [Legacy algorithms](legacy.md): Triple-DES, DES, RC2, DSA, MD5 and SHA-1, for reading, verifying or
  migrating data that already exists, never for new data.
