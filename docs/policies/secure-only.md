# SecureOnly policy catalogue

*Generated from the `SecureOnly` policy catalogue by `PolicyCatalogueMarkdown`; do not edit by hand.*

An allow-list of reviewed, modern mechanisms, hashes, curves, key-agreement KDFs and KDF PRFs. Anything not on the list below — including every vendor-defined mechanism — is denied by default, whether or not it also appears in the documented deny list further down this page.

## Allowed mechanisms

### AES

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_AES_CCM` | Encrypt, Decrypt, Wrap, Unwrap | — | — | Authenticated encryption (AES-GCM / AES-CCM). |
| `CKM_AES_CMAC` | Sign, Verify | — | — | AES-based MACs secure for variable-length messages (CMAC, GMAC). |
| `CKM_AES_CMAC_GENERAL` | Sign, Verify | — | — | AES-based MACs secure for variable-length messages (CMAC, GMAC). |
| `CKM_AES_GCM` | Encrypt, Decrypt, Wrap, Unwrap | — | — | Authenticated encryption (AES-GCM / AES-CCM). |
| `CKM_AES_GMAC` | Sign, Verify | — | — | AES-based MACs secure for variable-length messages (CMAC, GMAC). |
| `CKM_AES_KEY_GEN` | GenerateKey | — | — | AES key generation. |
| `CKM_AES_KEY_WRAP` | Encrypt, Decrypt, Wrap, Unwrap | — | — | Standard AES key wrapping (RFC 3394 / RFC 5649, SP 800-38F). |
| `CKM_AES_KEY_WRAP_KWP` | Encrypt, Decrypt, Wrap, Unwrap | — | — | Standard AES key wrapping (RFC 3394 / RFC 5649, SP 800-38F). |
| `CKM_AES_KEY_WRAP_PAD` | Encrypt, Decrypt, Wrap, Unwrap | — | — | AES key wrap with vendor-defined padding (RFC 5649 on some tokens, KW over PKCS#7 on others), kept for interop with tokens that lack CKM_AES_KEY_WRAP_KWP; see the known limits. |

### ChaCha20 / Salsa20

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_CHACHA20_KEY_GEN` | GenerateKey | — | — | ChaCha20 key generation. |
| `CKM_CHACHA20_POLY1305` | Encrypt, Decrypt, Wrap, Unwrap | — | — | Authenticated encryption (RFC 8439 ChaCha20-Poly1305). |

### Digest / HMAC

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_GENERIC_SECRET_KEY_GEN` | GenerateKey | — | — | Generic-secret / HMAC key generation. |
| `CKM_SHA256` | Digest | — | — | SHA-2 / SHA-3 digest with at least 128-bit collision resistance. |
| `CKM_SHA256_HMAC` | Sign, Verify | — | — | HMAC over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKM_SHA256_HMAC_GENERAL` | Sign, Verify | — | — | HMAC over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKM_SHA256_KEY_GEN` | GenerateKey | — | — | Generic-secret / HMAC key generation. |
| `CKM_SHA384` | Digest | — | — | SHA-2 / SHA-3 digest with at least 128-bit collision resistance. |
| `CKM_SHA384_HMAC` | Sign, Verify | — | — | HMAC over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKM_SHA384_HMAC_GENERAL` | Sign, Verify | — | — | HMAC over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKM_SHA384_KEY_GEN` | GenerateKey | — | — | Generic-secret / HMAC key generation. |
| `CKM_SHA3_256` | Digest | — | — | SHA-2 / SHA-3 digest with at least 128-bit collision resistance. |
| `CKM_SHA3_256_HMAC` | Sign, Verify | — | — | HMAC over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKM_SHA3_256_HMAC_GENERAL` | Sign, Verify | — | — | HMAC over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKM_SHA3_256_KEY_GEN` | GenerateKey | — | — | Generic-secret / HMAC key generation. |
| `CKM_SHA3_384` | Digest | — | — | SHA-2 / SHA-3 digest with at least 128-bit collision resistance. |
| `CKM_SHA3_384_HMAC` | Sign, Verify | — | — | HMAC over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKM_SHA3_384_HMAC_GENERAL` | Sign, Verify | — | — | HMAC over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKM_SHA3_384_KEY_GEN` | GenerateKey | — | — | Generic-secret / HMAC key generation. |
| `CKM_SHA3_512` | Digest | — | — | SHA-2 / SHA-3 digest with at least 128-bit collision resistance. |
| `CKM_SHA3_512_HMAC` | Sign, Verify | — | — | HMAC over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKM_SHA3_512_HMAC_GENERAL` | Sign, Verify | — | — | HMAC over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKM_SHA3_512_KEY_GEN` | GenerateKey | — | — | Generic-secret / HMAC key generation. |
| `CKM_SHA512` | Digest | — | — | SHA-2 / SHA-3 digest with at least 128-bit collision resistance. |
| `CKM_SHA512_256` | Digest | — | — | SHA-2 / SHA-3 digest with at least 128-bit collision resistance. |
| `CKM_SHA512_HMAC` | Sign, Verify | — | — | HMAC over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKM_SHA512_HMAC_GENERAL` | Sign, Verify | — | — | HMAC over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKM_SHA512_KEY_GEN` | GenerateKey | — | — | Generic-secret / HMAC key generation. |

### EC

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_ECDH1_COFACTOR_DERIVE` | Derive, Encapsulate, Decapsulate | — | requires CkmEcdh1DeriveParams whose KDF is on the key-agreement KDF allow-list | ECDH key agreement (the key-agreement KDF allow-list applies), also as a PKCS#11 v3.2 KEM. |
| `CKM_ECDH1_DERIVE` | Derive, Encapsulate, Decapsulate | — | requires CkmEcdh1DeriveParams whose KDF is on the key-agreement KDF allow-list | ECDH key agreement (the key-agreement KDF allow-list applies), also as a PKCS#11 v3.2 KEM. |
| `CKM_ECDSA` | Sign, Verify | — | — | ECDSA with a SHA-2 / SHA-3 hash (raw CKM_ECDSA signs a caller-computed digest). |
| `CKM_ECDSA_SHA256` | Sign, Verify | — | — | ECDSA with a SHA-2 / SHA-3 hash (raw CKM_ECDSA signs a caller-computed digest). |
| `CKM_ECDSA_SHA384` | Sign, Verify | — | — | ECDSA with a SHA-2 / SHA-3 hash (raw CKM_ECDSA signs a caller-computed digest). |
| `CKM_ECDSA_SHA3_256` | Sign, Verify | — | — | ECDSA with a SHA-2 / SHA-3 hash (raw CKM_ECDSA signs a caller-computed digest). |
| `CKM_ECDSA_SHA3_384` | Sign, Verify | — | — | ECDSA with a SHA-2 / SHA-3 hash (raw CKM_ECDSA signs a caller-computed digest). |
| `CKM_ECDSA_SHA3_512` | Sign, Verify | — | — | ECDSA with a SHA-2 / SHA-3 hash (raw CKM_ECDSA signs a caller-computed digest). |
| `CKM_ECDSA_SHA512` | Sign, Verify | — | — | ECDSA with a SHA-2 / SHA-3 hash (raw CKM_ECDSA signs a caller-computed digest). |
| `CKM_EC_EDWARDS_KEY_PAIR_GEN` | GenerateKeyPair | — | — | Edwards (Ed25519 / Ed448) and Montgomery (X25519 / X448) key generation. |
| `CKM_EC_KEY_PAIR_GEN` | GenerateKeyPair | — | — | EC key generation (the curve allow-list applies). |
| `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` | GenerateKeyPair | — | — | Edwards (Ed25519 / Ed448) and Montgomery (X25519 / X448) key generation. |
| `CKM_EDDSA` | Sign, Verify | — | — | EdDSA (Ed25519 / Ed448, RFC 8032). |

### KDF

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_HKDF_DATA` | Derive | — | requires CkmHkdfParams naming an allowed PRF (CKM_SHA256/384/512 or CKM_SHA3_256/384/512, hash or _HMAC form) | HKDF (RFC 5869 / SP 800-56C). |
| `CKM_HKDF_DERIVE` | Derive | — | requires CkmHkdfParams naming an allowed PRF (CKM_SHA256/384/512 or CKM_SHA3_256/384/512, hash or _HMAC form) | HKDF (RFC 5869 / SP 800-56C). |
| `CKM_HKDF_KEY_GEN` | GenerateKey | — | — | HKDF salt / key generation. |
| `CKM_PKCS5_PBKD2` | Derive, GenerateKey | — | requires CkmPkcs5Pbkd2Params naming an allowed PRF (CKP_PKCS5_PBKD2_HMAC_SHA256, _SHA384, _SHA512, or _SHA512_256) | PBKDF2 (RFC 8018 / SP 800-132) password-based key derivation. |
| `CKM_SP800_108_COUNTER_KDF` | Derive | — | requires CkmSp800108KdfParams naming an allowed PRF (CKM_SHA256/384/512_HMAC, CKM_SHA3_256/384/512_HMAC, or CKM_AES_CMAC) | SP 800-108 key derivation. |
| `CKM_SP800_108_DOUBLE_PIPELINE_KDF` | Derive | — | requires CkmSp800108KdfParams naming an allowed PRF (CKM_SHA256/384/512_HMAC, CKM_SHA3_256/384/512_HMAC, or CKM_AES_CMAC) | SP 800-108 key derivation. |
| `CKM_SP800_108_FEEDBACK_KDF` | Derive | — | requires CkmSp800108KdfParams naming an allowed PRF (CKM_SHA256/384/512_HMAC, CKM_SHA3_256/384/512_HMAC, or CKM_AES_CMAC) | SP 800-108 key derivation. |

### Post-quantum

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_HASH_ML_DSA` | Sign, Verify | — | requires CkmHashPqcSignParams naming a pre-hash of at least 256 bits | HashML-DSA (FIPS 204) / HashSLH-DSA (FIPS 205) with a caller-chosen pre-hash. |
| `CKM_HASH_ML_DSA_SHA256` | Sign, Verify | — | — | HashML-DSA (FIPS 204) with a pre-hash of at least 256 bits. |
| `CKM_HASH_ML_DSA_SHA384` | Sign, Verify | — | — | HashML-DSA (FIPS 204) with a pre-hash of at least 256 bits. |
| `CKM_HASH_ML_DSA_SHA3_256` | Sign, Verify | — | — | HashML-DSA (FIPS 204) with a pre-hash of at least 256 bits. |
| `CKM_HASH_ML_DSA_SHA3_384` | Sign, Verify | — | — | HashML-DSA (FIPS 204) with a pre-hash of at least 256 bits. |
| `CKM_HASH_ML_DSA_SHA3_512` | Sign, Verify | — | — | HashML-DSA (FIPS 204) with a pre-hash of at least 256 bits. |
| `CKM_HASH_ML_DSA_SHA512` | Sign, Verify | — | — | HashML-DSA (FIPS 204) with a pre-hash of at least 256 bits. |
| `CKM_HASH_ML_DSA_SHAKE128` | Sign, Verify | — | — | HashML-DSA (FIPS 204) with a pre-hash of at least 256 bits. |
| `CKM_HASH_ML_DSA_SHAKE256` | Sign, Verify | — | — | HashML-DSA (FIPS 204) with a pre-hash of at least 256 bits. |
| `CKM_HASH_SLH_DSA` | Sign, Verify | — | requires CkmHashPqcSignParams naming a pre-hash of at least 256 bits | HashML-DSA (FIPS 204) / HashSLH-DSA (FIPS 205) with a caller-chosen pre-hash. |
| `CKM_HASH_SLH_DSA_SHA256` | Sign, Verify | — | — | HashSLH-DSA (FIPS 205) with a pre-hash of at least 256 bits. |
| `CKM_HASH_SLH_DSA_SHA384` | Sign, Verify | — | — | HashSLH-DSA (FIPS 205) with a pre-hash of at least 256 bits. |
| `CKM_HASH_SLH_DSA_SHA3_256` | Sign, Verify | — | — | HashSLH-DSA (FIPS 205) with a pre-hash of at least 256 bits. |
| `CKM_HASH_SLH_DSA_SHA3_384` | Sign, Verify | — | — | HashSLH-DSA (FIPS 205) with a pre-hash of at least 256 bits. |
| `CKM_HASH_SLH_DSA_SHA3_512` | Sign, Verify | — | — | HashSLH-DSA (FIPS 205) with a pre-hash of at least 256 bits. |
| `CKM_HASH_SLH_DSA_SHA512` | Sign, Verify | — | — | HashSLH-DSA (FIPS 205) with a pre-hash of at least 256 bits. |
| `CKM_HASH_SLH_DSA_SHAKE128` | Sign, Verify | — | — | HashSLH-DSA (FIPS 205) with a pre-hash of at least 256 bits. |
| `CKM_HASH_SLH_DSA_SHAKE256` | Sign, Verify | — | — | HashSLH-DSA (FIPS 205) with a pre-hash of at least 256 bits. |
| `CKM_ML_DSA` | Sign, Verify | — | — | ML-DSA (FIPS 204) / SLH-DSA (FIPS 205). |
| `CKM_ML_DSA_KEY_PAIR_GEN` | GenerateKeyPair | — | — | ML-KEM / ML-DSA / SLH-DSA key generation (FIPS 203 / 204 / 205). |
| `CKM_ML_KEM` | Encapsulate, Decapsulate | — | — | ML-KEM (FIPS 203). |
| `CKM_ML_KEM_KEY_PAIR_GEN` | GenerateKeyPair | — | — | ML-KEM / ML-DSA / SLH-DSA key generation (FIPS 203 / 204 / 205). |
| `CKM_SLH_DSA` | Sign, Verify | — | — | ML-DSA (FIPS 204) / SLH-DSA (FIPS 205). |
| `CKM_SLH_DSA_KEY_PAIR_GEN` | GenerateKeyPair | — | — | ML-KEM / ML-DSA / SLH-DSA key generation (FIPS 203 / 204 / 205). |

### RSA encryption

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_RSA_PKCS_OAEP` | Encrypt, Decrypt, Wrap, Unwrap, Encapsulate, Decapsulate | — | requires CkmRsaPkcsOaepParams naming SHA-256 or stronger | RSAES-OAEP key transport (also as a PKCS#11 v3.2 KEM). |

### RSA key generation

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_RSA_PKCS_KEY_PAIR_GEN` | GenerateKeyPair | — | — | RSA key generation (modulus of at least 2048 bits, see the rules). |

### RSA signature

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_RSA_PKCS_PSS` | Sign, Verify | — | requires CkmRsaPkcsPssParams naming SHA-256 or stronger, with a salt no longer than that hash | RSASSA-PSS over a caller-computed digest. |
| `CKM_SHA256_RSA_PKCS` | Sign, Verify | — | — | RSASSA-PKCS1-v1_5 signatures with a SHA-2 / SHA-3 hash: FIPS 186-5-approved and required for JWT RS256, TLS 1.2, X.509 and code-signing interop. |
| `CKM_SHA256_RSA_PKCS_PSS` | Sign, Verify | — | parameters, when given, must be CkmRsaPkcsPssParams naming SHA-256 or stronger, with a salt no longer than that hash | RSASSA-PSS with a SHA-2 / SHA-3 hash. |
| `CKM_SHA384_RSA_PKCS` | Sign, Verify | — | — | RSASSA-PKCS1-v1_5 signatures with a SHA-2 / SHA-3 hash: FIPS 186-5-approved and required for JWT RS256, TLS 1.2, X.509 and code-signing interop. |
| `CKM_SHA384_RSA_PKCS_PSS` | Sign, Verify | — | parameters, when given, must be CkmRsaPkcsPssParams naming SHA-256 or stronger, with a salt no longer than that hash | RSASSA-PSS with a SHA-2 / SHA-3 hash. |
| `CKM_SHA3_256_RSA_PKCS` | Sign, Verify | — | — | RSASSA-PKCS1-v1_5 signatures with a SHA-2 / SHA-3 hash: FIPS 186-5-approved and required for JWT RS256, TLS 1.2, X.509 and code-signing interop. |
| `CKM_SHA3_256_RSA_PKCS_PSS` | Sign, Verify | — | parameters, when given, must be CkmRsaPkcsPssParams naming SHA-256 or stronger, with a salt no longer than that hash | RSASSA-PSS with a SHA-2 / SHA-3 hash. |
| `CKM_SHA3_384_RSA_PKCS` | Sign, Verify | — | — | RSASSA-PKCS1-v1_5 signatures with a SHA-2 / SHA-3 hash: FIPS 186-5-approved and required for JWT RS256, TLS 1.2, X.509 and code-signing interop. |
| `CKM_SHA3_384_RSA_PKCS_PSS` | Sign, Verify | — | parameters, when given, must be CkmRsaPkcsPssParams naming SHA-256 or stronger, with a salt no longer than that hash | RSASSA-PSS with a SHA-2 / SHA-3 hash. |
| `CKM_SHA3_512_RSA_PKCS` | Sign, Verify | — | — | RSASSA-PKCS1-v1_5 signatures with a SHA-2 / SHA-3 hash: FIPS 186-5-approved and required for JWT RS256, TLS 1.2, X.509 and code-signing interop. |
| `CKM_SHA3_512_RSA_PKCS_PSS` | Sign, Verify | — | parameters, when given, must be CkmRsaPkcsPssParams naming SHA-256 or stronger, with a salt no longer than that hash | RSASSA-PSS with a SHA-2 / SHA-3 hash. |
| `CKM_SHA512_RSA_PKCS` | Sign, Verify | — | — | RSASSA-PKCS1-v1_5 signatures with a SHA-2 / SHA-3 hash: FIPS 186-5-approved and required for JWT RS256, TLS 1.2, X.509 and code-signing interop. |
| `CKM_SHA512_RSA_PKCS_PSS` | Sign, Verify | — | parameters, when given, must be CkmRsaPkcsPssParams naming SHA-256 or stronger, with a salt no longer than that hash | RSASSA-PSS with a SHA-2 / SHA-3 hash. |

## Allowed hashes

| Hash | Operations | Rationale |
|---|---|---|
| `SHA256` | Encrypt, Decrypt, Sign, Verify, Wrap, Unwrap, Derive, Digest, GenerateKey, GenerateKeyPair, Encapsulate, Decapsulate | SHA-2 / SHA-3 with at least 128-bit collision resistance. |
| `SHA3-256` | Encrypt, Decrypt, Sign, Verify, Wrap, Unwrap, Derive, Digest, GenerateKey, GenerateKeyPair, Encapsulate, Decapsulate | SHA-2 / SHA-3 with at least 128-bit collision resistance. |
| `SHA3-384` | Encrypt, Decrypt, Sign, Verify, Wrap, Unwrap, Derive, Digest, GenerateKey, GenerateKeyPair, Encapsulate, Decapsulate | SHA-2 / SHA-3 with at least 128-bit collision resistance. |
| `SHA3-512` | Encrypt, Decrypt, Sign, Verify, Wrap, Unwrap, Derive, Digest, GenerateKey, GenerateKeyPair, Encapsulate, Decapsulate | SHA-2 / SHA-3 with at least 128-bit collision resistance. |
| `SHA384` | Encrypt, Decrypt, Sign, Verify, Wrap, Unwrap, Derive, Digest, GenerateKey, GenerateKeyPair, Encapsulate, Decapsulate | SHA-2 / SHA-3 with at least 128-bit collision resistance. |
| `SHA512` | Encrypt, Decrypt, Sign, Verify, Wrap, Unwrap, Derive, Digest, GenerateKey, GenerateKeyPair, Encapsulate, Decapsulate | SHA-2 / SHA-3 with at least 128-bit collision resistance. |

## Allowed EC curves

| Curve | OID | Rationale |
|---|---|---|
| `nistP256` | `1.2.840.10045.3.1.7` | NIST prime curve with at least 128-bit security (FIPS 186-5 / SP 800-186). |
| `secp256k1` | `1.3.132.0.10` | SEC 2 Koblitz curve with 128-bit security (Bitcoin / Ethereum interop). |
| `nistP384` | `1.3.132.0.34` | NIST prime curve with at least 128-bit security (FIPS 186-5 / SP 800-186). |
| `nistP521` | `1.3.132.0.35` | NIST prime curve with at least 128-bit security (FIPS 186-5 / SP 800-186). |
| `brainpoolP320t1` | `1.3.36.3.3.2.8.1.1.10` | RFC 5639 Brainpool curve with at least 128-bit security. |
| `brainpoolP384r1` | `1.3.36.3.3.2.8.1.1.11` | RFC 5639 Brainpool curve with at least 128-bit security. |
| `brainpoolP384t1` | `1.3.36.3.3.2.8.1.1.12` | RFC 5639 Brainpool curve with at least 128-bit security. |
| `brainpoolP512r1` | `1.3.36.3.3.2.8.1.1.13` | RFC 5639 Brainpool curve with at least 128-bit security. |
| `brainpoolP512t1` | `1.3.36.3.3.2.8.1.1.14` | RFC 5639 Brainpool curve with at least 128-bit security. |
| `brainpoolP256r1` | `1.3.36.3.3.2.8.1.1.7` | RFC 5639 Brainpool curve with at least 128-bit security. |
| `brainpoolP256t1` | `1.3.36.3.3.2.8.1.1.8` | RFC 5639 Brainpool curve with at least 128-bit security. |
| `brainpoolP320r1` | `1.3.36.3.3.2.8.1.1.9` | RFC 5639 Brainpool curve with at least 128-bit security. |

## Allowed key-agreement KDFs

| KDF | Rationale |
|---|---|
| `CKD_SHA256_KDF` | ANSI X9.63 KDF over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKD_SHA256_KDF_SP800` | SP 800-56C one-step KDF over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKD_SHA384_KDF` | ANSI X9.63 KDF over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKD_SHA384_KDF_SP800` | SP 800-56C one-step KDF over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKD_SHA3_256_KDF` | ANSI X9.63 KDF over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKD_SHA3_256_KDF_SP800` | SP 800-56C one-step KDF over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKD_SHA3_384_KDF` | ANSI X9.63 KDF over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKD_SHA3_384_KDF_SP800` | SP 800-56C one-step KDF over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKD_SHA3_512_KDF` | ANSI X9.63 KDF over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKD_SHA3_512_KDF_SP800` | SP 800-56C one-step KDF over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKD_SHA512_KDF` | ANSI X9.63 KDF over SHA-2 / SHA-3 with at least 256-bit output. |
| `CKD_SHA512_KDF_SP800` | SP 800-56C one-step KDF over SHA-2 / SHA-3 with at least 256-bit output. |

## Allowed key-agreement key types

The `CKA_KEY_TYPE` of the existing key an ECDH derivation or KEM uses (`CKM_ECDH1_DERIVE` serves both kinds).

| Key type | Rationale |
|---|---|
| `CKK_EC` | ECDH over a Weierstrass curve (SP 800-56A Rev.3); the curve allow-list applies when the key is generated. |
| `CKK_EC_MONTGOMERY` | X25519 / X448 (RFC 7748). |

## Allowed KDF PRFs

Per-family allow-list for the PRF named inside PBKDF2 / SP 800-108 / HKDF mechanism parameters.

| KDF family | Allowed PRFs |
|---|---|
| HKDF (CKM_HKDF_DERIVE / CKM_HKDF_DATA) | `CKM_SHA256`, `CKM_SHA256_HMAC`, `CKM_SHA384`, `CKM_SHA384_HMAC`, `CKM_SHA3_256`, `CKM_SHA3_256_HMAC`, `CKM_SHA3_384`, `CKM_SHA3_384_HMAC`, `CKM_SHA3_512`, `CKM_SHA3_512_HMAC`, `CKM_SHA512`, `CKM_SHA512_HMAC` |
| PBKDF2 (CKM_PKCS5_PBKD2) | `CKP_PKCS5_PBKD2_HMAC_SHA256`, `CKP_PKCS5_PBKD2_HMAC_SHA384`, `CKP_PKCS5_PBKD2_HMAC_SHA512`, `CKP_PKCS5_PBKD2_HMAC_SHA512_256` |
| SP 800-108 (CKM_SP800_108_*_KDF) | `CKM_AES_CMAC`, `CKM_SHA256_HMAC`, `CKM_SHA384_HMAC`, `CKM_SHA3_256_HMAC`, `CKM_SHA3_384_HMAC`, `CKM_SHA3_512_HMAC`, `CKM_SHA512_HMAC` |

## Rules

Beyond the allow-lists above, three rules apply: the modulus rule to RSA key-pair generation requests, the template rule to key templates the library creates keys from, and the export rule to every read of secret key material off the token.

| Rule | Rationale |
|---|---|
| RSA key-pair generation modulus | RSA key generation requires a modulus of at least 2048 bits (NIST SP 800-131A Rev.2). |
| Key template (`CKA_SENSITIVE`) | A key template with CKA_SENSITIVE=false is refused; non-extractable (CKA_EXTRACTABLE=false) stays the default. |
| Key-material export | Reading secret key material off the token in the clear is refused; wrap it under a KEK instead. |

## Documented refusals

Documentation only: every item below is refused because it is absent from the allow-lists above. This table only explains *why* it was considered and refused, rather than simply never reviewed; removing an entry here never allows the item.

### Mechanisms

#### AES

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_AES_CBC` | Unauthenticated AES modes (CBC, CBC-PAD, CTR, CTS, OFB, CFB) provide no integrity protection and are malleable; raw/padded CBC also enables padding-oracle attacks. | CKM_AES_GCM or CKM_AES_CCM |
| `CKM_AES_CBC_PAD` | Unauthenticated AES modes (CBC, CBC-PAD, CTR, CTS, OFB, CFB) provide no integrity protection and are malleable; raw/padded CBC also enables padding-oracle attacks. | CKM_AES_GCM or CKM_AES_CCM |
| `CKM_AES_CFB1` | Unauthenticated AES modes (CBC, CBC-PAD, CTR, CTS, OFB, CFB) provide no integrity protection and are malleable; raw/padded CBC also enables padding-oracle attacks. | CKM_AES_GCM or CKM_AES_CCM |
| `CKM_AES_CFB128` | Unauthenticated AES modes (CBC, CBC-PAD, CTR, CTS, OFB, CFB) provide no integrity protection and are malleable; raw/padded CBC also enables padding-oracle attacks. | CKM_AES_GCM or CKM_AES_CCM |
| `CKM_AES_CFB64` | Unauthenticated AES modes (CBC, CBC-PAD, CTR, CTS, OFB, CFB) provide no integrity protection and are malleable; raw/padded CBC also enables padding-oracle attacks. | CKM_AES_GCM or CKM_AES_CCM |
| `CKM_AES_CFB8` | Unauthenticated AES modes (CBC, CBC-PAD, CTR, CTS, OFB, CFB) provide no integrity protection and are malleable; raw/padded CBC also enables padding-oracle attacks. | CKM_AES_GCM or CKM_AES_CCM |
| `CKM_AES_CTR` | Unauthenticated AES modes (CBC, CBC-PAD, CTR, CTS, OFB, CFB) provide no integrity protection and are malleable; raw/padded CBC also enables padding-oracle attacks. | CKM_AES_GCM or CKM_AES_CCM |
| `CKM_AES_CTS` | Unauthenticated AES modes (CBC, CBC-PAD, CTR, CTS, OFB, CFB) provide no integrity protection and are malleable; raw/padded CBC also enables padding-oracle attacks. | CKM_AES_GCM or CKM_AES_CCM |
| `CKM_AES_ECB` | ECB mode leaks structural information from the plaintext. | CKM_AES_GCM or CKM_AES_CCM |
| `CKM_AES_KEY_WRAP_PKCS7` | Non-standard padding, not RFC 5649. | CKM_AES_KEY_WRAP_KWP |
| `CKM_AES_MAC` | CBC-MAC is unsafe for variable-length messages; TDEA is deprecated. | CKM_AES_CMAC |
| `CKM_AES_MAC_GENERAL` | CBC-MAC is unsafe for variable-length messages; TDEA is deprecated. | CKM_AES_CMAC |
| `CKM_AES_OFB` | Unauthenticated AES modes (CBC, CBC-PAD, CTR, CTS, OFB, CFB) provide no integrity protection and are malleable; raw/padded CBC also enables padding-oracle attacks. | CKM_AES_GCM or CKM_AES_CCM |
| `CKM_AES_XTS` | AES-XTS provides no integrity protection and is designed for disk-sector encryption, not general-purpose use. | CKM_AES_GCM or CKM_AES_CCM |

#### ChaCha20 / Salsa20

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_CHACHA20` | Raw ChaCha20/Salsa20 provide no integrity protection and are malleable. | CKM_CHACHA20_POLY1305 or CKM_AES_GCM |
| `CKM_SALSA20` | Raw ChaCha20/Salsa20 provide no integrity protection and are malleable. | CKM_CHACHA20_POLY1305 or CKM_AES_GCM |

#### DES / TDEA

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_DES2_KEY_GEN` | DES and 3DES key generation produces deprecated keys. | CKM_AES_KEY_GEN |
| `CKM_DES3_CBC` | DES and 3DES are deprecated. | AES (CKM_AES_GCM or CKM_AES_CCM) |
| `CKM_DES3_CBC_ENCRYPT_DATA` | DES3 key-derive mechanisms are weak. | an SP 800-108 KDF (CKM_SP800_108_COUNTER_KDF) or CKM_HKDF_DERIVE on a strong base key |
| `CKM_DES3_CBC_PAD` | DES and 3DES are deprecated. | AES (CKM_AES_GCM or CKM_AES_CCM) |
| `CKM_DES3_CMAC` | CBC-MAC is unsafe for variable-length messages; TDEA is deprecated. | CKM_AES_CMAC |
| `CKM_DES3_CMAC_GENERAL` | CBC-MAC is unsafe for variable-length messages; TDEA is deprecated. | CKM_AES_CMAC |
| `CKM_DES3_ECB` | DES and 3DES are deprecated. | AES (CKM_AES_GCM or CKM_AES_CCM) |
| `CKM_DES3_ECB_ENCRYPT_DATA` | DES3 key-derive mechanisms are weak. | an SP 800-108 KDF (CKM_SP800_108_COUNTER_KDF) or CKM_HKDF_DERIVE on a strong base key |
| `CKM_DES3_KEY_GEN` | DES and 3DES key generation produces deprecated keys. | CKM_AES_KEY_GEN |
| `CKM_DES3_MAC` | DES/3DES MAC is weak. | CKM_AES_CMAC or CKM_SHA256_HMAC |
| `CKM_DES3_MAC_GENERAL` | DES/3DES MAC is weak. | CKM_AES_CMAC or CKM_SHA256_HMAC |
| `CKM_DES_CBC` | DES and 3DES are deprecated. | AES (CKM_AES_GCM or CKM_AES_CCM) |
| `CKM_DES_CBC_PAD` | DES and 3DES are deprecated. | AES (CKM_AES_GCM or CKM_AES_CCM) |
| `CKM_DES_ECB` | DES and 3DES are deprecated. | AES (CKM_AES_GCM or CKM_AES_CCM) |
| `CKM_DES_KEY_GEN` | DES and 3DES key generation produces deprecated keys. | CKM_AES_KEY_GEN |
| `CKM_DES_MAC` | DES/3DES MAC is weak. | CKM_AES_CMAC or CKM_SHA256_HMAC |
| `CKM_DES_MAC_GENERAL` | DES/3DES MAC is weak. | CKM_AES_CMAC or CKM_SHA256_HMAC |

#### DSA

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_DSA` | DSA (FIPS 186) is disallowed for signature generation by NIST FIPS 186-5 and is retained only for interop with existing keys. | CKM_ECDSA_SHA256 or CKM_ML_DSA |
| `CKM_DSA_KEY_PAIR_GEN` | DSA signing is refused; its keys have no secure use. | CKM_EC_KEY_PAIR_GEN or CKM_ML_DSA_KEY_PAIR_GEN |
| `CKM_DSA_SHA1` | DSA (FIPS 186) is disallowed for signature generation by NIST FIPS 186-5 and is retained only for interop with existing keys. | CKM_ECDSA_SHA256 or CKM_ML_DSA |
| `CKM_DSA_SHA224` | DSA (FIPS 186) is disallowed for signature generation by NIST FIPS 186-5 and is retained only for interop with existing keys. | CKM_ECDSA_SHA256 or CKM_ML_DSA |
| `CKM_DSA_SHA256` | DSA (FIPS 186) is disallowed for signature generation by NIST FIPS 186-5 and is retained only for interop with existing keys. | CKM_ECDSA_SHA256 or CKM_ML_DSA |
| `CKM_DSA_SHA384` | DSA (FIPS 186) is disallowed for signature generation by NIST FIPS 186-5 and is retained only for interop with existing keys. | CKM_ECDSA_SHA256 or CKM_ML_DSA |
| `CKM_DSA_SHA512` | DSA (FIPS 186) is disallowed for signature generation by NIST FIPS 186-5 and is retained only for interop with existing keys. | CKM_ECDSA_SHA256 or CKM_ML_DSA |

#### Digest / HMAC

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_MD2` | MD2 is a broken hash function. | CKM_SHA256 or stronger |
| `CKM_MD2_HMAC` | MD2 is a broken hash function. | CKM_SHA256 or stronger |
| `CKM_MD2_HMAC_GENERAL` | MD2 is a broken hash function. | CKM_SHA256 or stronger |
| `CKM_MD5` | MD5 and SHA-1 are broken hash functions. | CKM_SHA256 or stronger |
| `CKM_MD5_HMAC` | MD5/SHA-1-based HMAC and key derivation rely on broken hash functions. | CKM_SHA256_HMAC or an SP800-108 KDF with SHA-256 or stronger |
| `CKM_MD5_HMAC_GENERAL` | MD5/SHA-1-based HMAC and key derivation rely on broken hash functions. | CKM_SHA256_HMAC or an SP800-108 KDF with SHA-256 or stronger |
| `CKM_RIPEMD128` | RIPEMD-128/160 are deprecated hash functions. | CKM_SHA256 or stronger |
| `CKM_RIPEMD128_HMAC` | RIPEMD-128/160 are deprecated hash functions. | CKM_SHA256 or stronger |
| `CKM_RIPEMD128_HMAC_GENERAL` | RIPEMD-128/160 are deprecated hash functions. | CKM_SHA256 or stronger |
| `CKM_RIPEMD160` | RIPEMD-128/160 are deprecated hash functions. | CKM_SHA256 or stronger |
| `CKM_RIPEMD160_HMAC` | RIPEMD-128/160 are deprecated hash functions. | CKM_SHA256 or stronger |
| `CKM_RIPEMD160_HMAC_GENERAL` | RIPEMD-128/160 are deprecated hash functions. | CKM_SHA256 or stronger |
| `CKM_SHA224` | No practical benefit over SHA-256; SHA512_T has a caller-chosen truncation. | CKM_SHA256 or stronger |
| `CKM_SHA224_HMAC` | SHA-224 has no HashAlgorithmName constant in the BCL and offers no practical benefit over SHA-256 on equal-cost hardware. | CKM_SHA256 or stronger |
| `CKM_SHA3_224` | No practical benefit over SHA-256; SHA512_T has a caller-chosen truncation. | CKM_SHA256 or stronger |
| `CKM_SHA512_224` | No practical benefit over SHA-256; SHA512_T has a caller-chosen truncation. | CKM_SHA256 or stronger |
| `CKM_SHA512_T` | No practical benefit over SHA-256; SHA512_T has a caller-chosen truncation. | CKM_SHA256 or stronger |
| `CKM_SHA_1` | MD5 and SHA-1 are broken hash functions. | CKM_SHA256 or stronger |
| `CKM_SHA_1_HMAC` | SHA-1 is collision-broken and deprecated in signature/MAC contexts. | CKM_SHA256_HMAC or CKM_ECDSA_SHA256 |
| `CKM_SHA_1_HMAC_GENERAL` | SHA-1 is collision-broken and deprecated in signature/MAC contexts. | CKM_SHA256_HMAC or CKM_ECDSA_SHA256 |
| `CKM_SSL3_MD5_MAC` | SSLv3 MAC mechanisms are tied to a protocol version prohibited by RFC 7568. | TLS 1.2+ with CKM_SHA256_HMAC |
| `CKM_SSL3_SHA1_MAC` | SSLv3 MAC mechanisms are tied to a protocol version prohibited by RFC 7568. | TLS 1.2+ with CKM_SHA256_HMAC |

#### EC

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_ECDSA_SHA1` | SHA-1 is collision-broken and deprecated in signature/MAC contexts. | CKM_SHA256_HMAC or CKM_ECDSA_SHA256 |
| `CKM_ECDSA_SHA224` | SHA-224 has no HashAlgorithmName constant in the BCL and offers no practical benefit over SHA-256 on equal-cost hardware. | CKM_SHA256 or stronger |

#### Key derivation

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_CONCATENATE_BASE_AND_DATA` | This is Clulow's classic PKCS#11 key-extraction attack: it derives a short, attacker-chosen sub-key from a sensitive base key, which can then be brute-forced via a legitimate encrypt/decrypt call — the derived key's own CKA_SENSITIVE=true default does not block this, since the attack works entirely through mechanisms the token permits. Restrict CKA_DERIVE on sensitive keys via token policy rather than relying on application-level checks. | — |
| `CKM_CONCATENATE_BASE_AND_KEY` | This is Clulow's classic PKCS#11 key-extraction attack: it derives a short, attacker-chosen sub-key from a sensitive base key, which can then be brute-forced via a legitimate encrypt/decrypt call — the derived key's own CKA_SENSITIVE=true default does not block this, since the attack works entirely through mechanisms the token permits. Restrict CKA_DERIVE on sensitive keys via token policy rather than relying on application-level checks. | — |
| `CKM_CONCATENATE_DATA_AND_BASE` | This is Clulow's classic PKCS#11 key-extraction attack: it derives a short, attacker-chosen sub-key from a sensitive base key, which can then be brute-forced via a legitimate encrypt/decrypt call — the derived key's own CKA_SENSITIVE=true default does not block this, since the attack works entirely through mechanisms the token permits. Restrict CKA_DERIVE on sensitive keys via token policy rather than relying on application-level checks. | — |
| `CKM_EXTRACT_KEY_FROM_KEY` | This is Clulow's classic PKCS#11 key-extraction attack: it derives a short, attacker-chosen sub-key from a sensitive base key, which can then be brute-forced via a legitimate encrypt/decrypt call — the derived key's own CKA_SENSITIVE=true default does not block this, since the attack works entirely through mechanisms the token permits. Restrict CKA_DERIVE on sensitive keys via token policy rather than relying on application-level checks. | — |
| `CKM_IKE1_EXTENDED_DERIVE` | Protocol-specific; IPsec stacks should opt in explicitly. | CryptoPolicy.SecureOnly.WithAllowedMechanism(...) after review |
| `CKM_IKE1_PRF_DERIVE` | Protocol-specific; IPsec stacks should opt in explicitly. | CryptoPolicy.SecureOnly.WithAllowedMechanism(...) after review |
| `CKM_IKE2_PRF_PLUS_DERIVE` | Protocol-specific; IPsec stacks should opt in explicitly. | CryptoPolicy.SecureOnly.WithAllowedMechanism(...) after review |
| `CKM_IKE_PRF_DERIVE` | Protocol-specific; IPsec stacks should opt in explicitly. | CryptoPolicy.SecureOnly.WithAllowedMechanism(...) after review |
| `CKM_MD2_KEY_DERIVATION` | MD2 is a broken hash function. | CKM_SHA256 or stronger |
| `CKM_MD5_KEY_DERIVATION` | MD5/SHA-1-based HMAC and key derivation rely on broken hash functions. | CKM_SHA256_HMAC or an SP800-108 KDF with SHA-256 or stronger |
| `CKM_SHA1_KEY_DERIVATION` | MD5/SHA-1-based HMAC and key derivation rely on broken hash functions. | CKM_SHA256_HMAC or an SP800-108 KDF with SHA-256 or stronger |
| `CKM_SHA224_KEY_DERIVATION` | Hash-of-key derivation with no salt or label. | CKM_HKDF_DERIVE or an SP 800-108 KDF (CKM_SP800_108_*_KDF) |
| `CKM_SHA256_KEY_DERIVATION` | Hash-of-key derivation with no salt or label. | CKM_HKDF_DERIVE or an SP 800-108 KDF (CKM_SP800_108_*_KDF) |
| `CKM_SHA384_KEY_DERIVATION` | Hash-of-key derivation with no salt or label. | CKM_HKDF_DERIVE or an SP 800-108 KDF (CKM_SP800_108_*_KDF) |
| `CKM_SHA3_224_KEY_DERIVE` | Hash-of-key derivation with no salt or label. | CKM_HKDF_DERIVE or an SP 800-108 KDF (CKM_SP800_108_*_KDF) |
| `CKM_SHA3_256_KEY_DERIVE` | Hash-of-key derivation with no salt or label. | CKM_HKDF_DERIVE or an SP 800-108 KDF (CKM_SP800_108_*_KDF) |
| `CKM_SHA3_384_KEY_DERIVE` | Hash-of-key derivation with no salt or label. | CKM_HKDF_DERIVE or an SP 800-108 KDF (CKM_SP800_108_*_KDF) |
| `CKM_SHA3_512_KEY_DERIVE` | Hash-of-key derivation with no salt or label. | CKM_HKDF_DERIVE or an SP 800-108 KDF (CKM_SP800_108_*_KDF) |
| `CKM_SHA512_224_KEY_DERIVATION` | Hash-of-key derivation with no salt or label. | CKM_HKDF_DERIVE or an SP 800-108 KDF (CKM_SP800_108_*_KDF) |
| `CKM_SHA512_256_KEY_DERIVATION` | Hash-of-key derivation with no salt or label. | CKM_HKDF_DERIVE or an SP 800-108 KDF (CKM_SP800_108_*_KDF) |
| `CKM_SHA512_KEY_DERIVATION` | Hash-of-key derivation with no salt or label. | CKM_HKDF_DERIVE or an SP 800-108 KDF (CKM_SP800_108_*_KDF) |
| `CKM_SHA512_T_KEY_DERIVATION` | Hash-of-key derivation with no salt or label. | CKM_HKDF_DERIVE or an SP 800-108 KDF (CKM_SP800_108_*_KDF) |
| `CKM_SHAKE_128_KEY_DERIVE` | Hash-of-key derivation with no salt or label. | CKM_HKDF_DERIVE or an SP 800-108 KDF (CKM_SP800_108_*_KDF) |
| `CKM_SHAKE_256_KEY_DERIVE` | Hash-of-key derivation with no salt or label. | CKM_HKDF_DERIVE or an SP 800-108 KDF (CKM_SP800_108_*_KDF) |
| `CKM_XOR_BASE_AND_DATA` | This is Clulow's classic PKCS#11 key-extraction attack: it derives a short, attacker-chosen sub-key from a sensitive base key, which can then be brute-forced via a legitimate encrypt/decrypt call — the derived key's own CKA_SENSITIVE=true default does not block this, since the attack works entirely through mechanisms the token permits. Restrict CKA_DERIVE on sensitive keys via token policy rather than relying on application-level checks. | — |

#### Legacy ciphers

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_BLOWFISH_CBC` | Blowfish is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_BLOWFISH_CBC_PAD` | Blowfish is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_BLOWFISH_KEY_GEN` | Blowfish is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST128_CBC` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST128_CBC_PAD` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST128_ECB` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST128_KEY_GEN` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST128_MAC` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST128_MAC_GENERAL` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST3_CBC` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST3_CBC_PAD` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST3_ECB` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST3_KEY_GEN` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST3_MAC` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST3_MAC_GENERAL` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST_CBC` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST_CBC_PAD` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST_ECB` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST_KEY_GEN` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST_MAC` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_CAST_MAC_GENERAL` | CAST is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_GOST28147_ECB` | This is a legacy 64-bit-block cipher in ECB mode, both leaking structural information from the plaintext and vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_IDEA_ECB` | This is a legacy 64-bit-block cipher in ECB mode, both leaking structural information from the plaintext and vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_RC2_CBC` | RC2 is a deprecated 40/64-bit-key cipher with known weaknesses. | CKM_AES_GCM |
| `CKM_RC2_CBC_PAD` | RC2 is a deprecated 40/64-bit-key cipher with known weaknesses. | CKM_AES_GCM |
| `CKM_RC2_ECB` | RC2 is a deprecated 40/64-bit-key cipher with known weaknesses. | CKM_AES_GCM |
| `CKM_RC2_KEY_GEN` | RC2 is a deprecated 40/64-bit-key cipher with known weaknesses. | CKM_AES_GCM |
| `CKM_RC2_MAC` | RC2 is a deprecated 40/64-bit-key cipher with known weaknesses. | CKM_AES_GCM |
| `CKM_RC2_MAC_GENERAL` | RC2 is a deprecated 40/64-bit-key cipher with known weaknesses. | CKM_AES_GCM |
| `CKM_RC4` | RC4 is a broken stream cipher with a biased keystream (prohibited in TLS by RFC 7465). | CKM_AES_GCM |
| `CKM_RC4_KEY_GEN` | RC4 is a broken stream cipher with a biased keystream (prohibited in TLS by RFC 7465). | CKM_AES_GCM |
| `CKM_RC5_CBC` | RC5 is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_RC5_CBC_PAD` | RC5 is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_RC5_ECB` | RC5 is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_RC5_KEY_GEN` | RC5 is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_RC5_MAC` | RC5 is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_RC5_MAC_GENERAL` | RC5 is a legacy 64-bit-block cipher vulnerable to birthday (Sweet32) attacks. | CKM_AES_GCM |
| `CKM_SEED_CBC` | SEED is a legacy regional cipher retained only for Korean-standard interop. | CKM_AES_GCM |
| `CKM_SEED_CBC_ENCRYPT_DATA` | SEED is a legacy regional cipher retained only for Korean-standard interop. | CKM_AES_GCM |
| `CKM_SEED_CBC_PAD` | SEED is a legacy regional cipher retained only for Korean-standard interop. | CKM_AES_GCM |
| `CKM_SEED_ECB` | SEED is a legacy regional cipher retained only for Korean-standard interop. | CKM_AES_GCM |
| `CKM_SEED_ECB_ENCRYPT_DATA` | SEED is a legacy regional cipher retained only for Korean-standard interop. | CKM_AES_GCM |
| `CKM_SEED_KEY_GEN` | SEED is a legacy regional cipher retained only for Korean-standard interop. | CKM_AES_GCM |
| `CKM_SEED_MAC` | SEED is a legacy regional cipher retained only for Korean-standard interop. | CKM_AES_GCM |
| `CKM_SEED_MAC_GENERAL` | SEED is a legacy regional cipher retained only for Korean-standard interop. | CKM_AES_GCM |
| `CKM_SKIPJACK_CBC64` | SKIPJACK is a withdrawn 80-bit-key, 64-bit-block cipher with known weaknesses. | CKM_AES_GCM (or CKM_AES_KEY_WRAP for key wrapping) |
| `CKM_SKIPJACK_CFB16` | SKIPJACK is a withdrawn 80-bit-key, 64-bit-block cipher with known weaknesses. | CKM_AES_GCM (or CKM_AES_KEY_WRAP for key wrapping) |
| `CKM_SKIPJACK_CFB32` | SKIPJACK is a withdrawn 80-bit-key, 64-bit-block cipher with known weaknesses. | CKM_AES_GCM (or CKM_AES_KEY_WRAP for key wrapping) |
| `CKM_SKIPJACK_CFB64` | SKIPJACK is a withdrawn 80-bit-key, 64-bit-block cipher with known weaknesses. | CKM_AES_GCM (or CKM_AES_KEY_WRAP for key wrapping) |
| `CKM_SKIPJACK_CFB8` | SKIPJACK is a withdrawn 80-bit-key, 64-bit-block cipher with known weaknesses. | CKM_AES_GCM (or CKM_AES_KEY_WRAP for key wrapping) |
| `CKM_SKIPJACK_ECB64` | SKIPJACK is a withdrawn 80-bit-key, 64-bit-block cipher with known weaknesses. | CKM_AES_GCM (or CKM_AES_KEY_WRAP for key wrapping) |
| `CKM_SKIPJACK_KEY_GEN` | SKIPJACK is a withdrawn 80-bit-key, 64-bit-block cipher with known weaknesses. | CKM_AES_GCM (or CKM_AES_KEY_WRAP for key wrapping) |
| `CKM_SKIPJACK_OFB64` | SKIPJACK is a withdrawn 80-bit-key, 64-bit-block cipher with known weaknesses. | CKM_AES_GCM (or CKM_AES_KEY_WRAP for key wrapping) |
| `CKM_SKIPJACK_PRIVATE_WRAP` | SKIPJACK is a withdrawn 80-bit-key, 64-bit-block cipher with known weaknesses. | CKM_AES_GCM (or CKM_AES_KEY_WRAP for key wrapping) |
| `CKM_SKIPJACK_RELAYX` | SKIPJACK is a withdrawn 80-bit-key, 64-bit-block cipher with known weaknesses. | CKM_AES_GCM (or CKM_AES_KEY_WRAP for key wrapping) |
| `CKM_SKIPJACK_WRAP` | SKIPJACK is a withdrawn 80-bit-key, 64-bit-block cipher with known weaknesses. | CKM_AES_GCM (or CKM_AES_KEY_WRAP for key wrapping) |

#### Other

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_ARIA_ECB` | ECB mode leaks structural information from the plaintext. | CKM_AES_GCM or CKM_AES_CCM |
| `CKM_CAMELLIA_ECB` | ECB mode leaks structural information from the plaintext. | CKM_AES_GCM or CKM_AES_CCM |

#### RSA key generation

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_RSA_X9_31_KEY_PAIR_GEN` | RSA key generation via ANSI X9.31 was removed from FIPS 186-5. | CKM_RSA_PKCS_KEY_PAIR_GEN |

#### RSA signature

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_MD2_RSA_PKCS` | MD2 is a broken hash function. | CKM_SHA256 or stronger |
| `CKM_MD5_RSA_PKCS` | MD5/SHA-1 in RSA signature contexts is broken (SHAttered breaks PSS-SHA-1 too). | CKM_SHA256_RSA_PKCS_PSS or CKM_ECDSA_SHA256 |
| `CKM_RIPEMD128_RSA_PKCS` | RIPEMD-128/160 are deprecated hash functions. | CKM_SHA256 or stronger |
| `CKM_RIPEMD160_RSA_PKCS` | RIPEMD-128/160 are deprecated hash functions. | CKM_SHA256 or stronger |
| `CKM_RSA_9796` | ISO 9796-2 RSA signing is forgeable (Coron-Naccache-Stern). | CKM_RSA_PKCS_PSS |
| `CKM_RSA_PKCS` | RSA PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks and fault attacks. | CKM_RSA_PKCS_OAEP for encryption or CKM_RSA_PKCS_PSS for signing |
| `CKM_RSA_X_509` | Raw RSA (X.509, no padding) is malleable and forgeable. | CKM_RSA_PKCS_OAEP for encryption or CKM_RSA_PKCS_PSS for signing |
| `CKM_SHA1_RSA_PKCS` | MD5/SHA-1 in RSA signature contexts is broken (SHAttered breaks PSS-SHA-1 too). | CKM_SHA256_RSA_PKCS_PSS or CKM_ECDSA_SHA256 |
| `CKM_SHA1_RSA_PKCS_PSS` | MD5/SHA-1 in RSA signature contexts is broken (SHAttered breaks PSS-SHA-1 too). | CKM_SHA256_RSA_PKCS_PSS or CKM_ECDSA_SHA256 |
| `CKM_SHA224_RSA_PKCS` | SHA-224 has no HashAlgorithmName constant in the BCL and offers no practical benefit over SHA-256 on equal-cost hardware. | CKM_SHA256 or stronger |
| `CKM_SHA224_RSA_PKCS_PSS` | SHA-224 has no HashAlgorithmName constant in the BCL and offers no practical benefit over SHA-256 on equal-cost hardware. | CKM_SHA256 or stronger |

### Hashes

| Hash | Reason | Alternative |
|---|---|---|
| `MD5` | MD5 is a broken hash function. | SHA256 or stronger |
| `SHA1` | SHA-1 is collision-broken and deprecated in signature contexts. | SHA256 or stronger |
| `SHA224` | SHA-224 has no HashAlgorithmName constant in the BCL and offers no practical benefit over SHA-256 on equal-cost hardware. | SHA256 or stronger |

### EC curves

| Curve | OID | Reason | Alternative |
|---|---|---|---|
| `sm2` | `1.2.156.10197.1.301` | SM2 is a regional (Chinese national standard) curve that has not been reviewed for this policy. | NistP256 or stronger |
| `nistP192` | `1.2.840.10045.3.1.1` | The curve provides less than 128-bit security. | NistP256 or stronger |
| `secp192k1` | `1.3.132.0.31` | The curve provides less than 128-bit security. | NistP256 or stronger |
| `secp224k1` | `1.3.132.0.32` | The curve provides less than 128-bit security. | NistP256 or stronger |
| `nistP224` | `1.3.132.0.33` | The curve provides less than 128-bit security. | NistP256 or stronger |
| `brainpoolP160r1` | `1.3.36.3.3.2.8.1.1.1` | The curve provides less than 128-bit security. | NistP256 or stronger |
| `brainpoolP160t1` | `1.3.36.3.3.2.8.1.1.2` | The curve provides less than 128-bit security. | NistP256 or stronger |
| `brainpoolP192r1` | `1.3.36.3.3.2.8.1.1.3` | The curve provides less than 128-bit security. | NistP256 or stronger |
| `brainpoolP192t1` | `1.3.36.3.3.2.8.1.1.4` | The curve provides less than 128-bit security. | NistP256 or stronger |
| `brainpoolP224r1` | `1.3.36.3.3.2.8.1.1.5` | The curve provides less than 128-bit security. | NistP256 or stronger |
| `brainpoolP224t1` | `1.3.36.3.3.2.8.1.1.6` | The curve provides less than 128-bit security. | NistP256 or stronger |

### Key-agreement KDFs

| KDF | Reason | Alternative |
|---|---|---|
| `CKD_BLAKE2B_160_KDF` | BLAKE2b-based key-agreement KDFs are not NIST SP 800-56C KDFs and have not been reviewed for this policy; BLAKE2b-160 is also below 128-bit collision resistance. | the default CKD_SHA256_KDF or stronger |
| `CKD_BLAKE2B_256_KDF` | BLAKE2b-based key-agreement KDFs are not NIST SP 800-56C KDFs and have not been reviewed for this policy; BLAKE2b-160 is also below 128-bit collision resistance. | the default CKD_SHA256_KDF or stronger |
| `CKD_BLAKE2B_384_KDF` | BLAKE2b-based key-agreement KDFs are not NIST SP 800-56C KDFs and have not been reviewed for this policy; BLAKE2b-160 is also below 128-bit collision resistance. | the default CKD_SHA256_KDF or stronger |
| `CKD_BLAKE2B_512_KDF` | BLAKE2b-based key-agreement KDFs are not NIST SP 800-56C KDFs and have not been reviewed for this policy; BLAKE2b-160 is also below 128-bit collision resistance. | the default CKD_SHA256_KDF or stronger |
| `CKD_CPDIVERSIFY_KDF` | CKD_CPDIVERSIFY_KDF is a CryptoPro (GOST) key-diversification function, not a general-purpose key-agreement KDF. | the default CKD_SHA256_KDF or stronger |
| `CKD_NULL` | CKD_NULL applies no KDF to the ECDH shared secret: the derived AES key becomes the raw x-coordinate (or a token-chosen truncation of it), which NIST SP 800-56A Rev. 3 §5.8 forbids. | the default CKD_SHA256_KDF or stronger |
| `CKD_SHA1_KDF` | SHA-1 is collision-broken and deprecated. | the default CKD_SHA256_KDF or stronger |
| `CKD_SHA1_KDF_ASN1` | SHA-1 is collision-broken and deprecated. | the default CKD_SHA256_KDF or stronger |
| `CKD_SHA1_KDF_CONCATENATE` | SHA-1 is collision-broken and deprecated. | the default CKD_SHA256_KDF or stronger |
| `CKD_SHA1_KDF_SP800` | SHA-1 is collision-broken and deprecated. | the default CKD_SHA256_KDF or stronger |
| `CKD_SHA224_KDF` | SHA-224 / SHA3-224 offer no practical benefit over SHA-256 on equal-cost hardware. | the default CKD_SHA256_KDF or stronger |
| `CKD_SHA224_KDF_SP800` | SHA-224 / SHA3-224 offer no practical benefit over SHA-256 on equal-cost hardware. | the default CKD_SHA256_KDF or stronger |
| `CKD_SHA3_224_KDF` | SHA-224 / SHA3-224 offer no practical benefit over SHA-256 on equal-cost hardware. | the default CKD_SHA256_KDF or stronger |
| `CKD_SHA3_224_KDF_SP800` | SHA-224 / SHA3-224 offer no practical benefit over SHA-256 on equal-cost hardware. | the default CKD_SHA256_KDF or stronger |

### KDF PRFs

| PRF | Reason | Alternative |
|---|---|---|
| `CKM_GOSTR3411_HMAC` | GOST R 34.11-94 is a regional (Russian national standard) hash that has not been reviewed for this policy. | a SHA-256-or-stronger PRF |
| `CKM_SHA224_HMAC` | SHA-224 offers no practical benefit over SHA-256 on equal-cost hardware. | a SHA-256-or-stronger PRF |
| `CKM_SHA512_224_HMAC` | SHA-512/224's truncated output offers no practical benefit over SHA-256. | a SHA-256-or-stronger PRF |
| `CKM_SHA_1_HMAC` | SHA-1 is collision-broken and deprecated. | a SHA-256-or-stronger PRF |
| `CKP_PKCS5_PBKD2_HMAC_GOSTR3411` | GOST R 34.11-94 is a regional (Russian national standard) hash that has not been reviewed for this policy. | a SHA-256-or-stronger PRF |
| `CKP_PKCS5_PBKD2_HMAC_SHA1` | SHA-1 is collision-broken and deprecated. | a SHA-256-or-stronger PRF |
| `CKP_PKCS5_PBKD2_HMAC_SHA224` | SHA-224 offers no practical benefit over SHA-256 on equal-cost hardware. | a SHA-256-or-stronger PRF |
| `CKP_PKCS5_PBKD2_HMAC_SHA512_224` | SHA-512/224's truncated output offers no practical benefit over SHA-256. | a SHA-256-or-stronger PRF |

## Extension point

`CryptoPolicy.SecureOnly.WithAllowedMechanism(...)` returns a new, wider `SecureOnlyPolicy` (named `SecureOnly+custom`) that also allows one more mechanism, for the operations and reason you supply — including a mechanism listed under Documented refusals above, and any vendor-defined mechanism. It only adds: an already-allowed mechanism keeps its operations and parameter check. It never modifies `CryptoPolicy.SecureOnly` itself or any other instance; call it on the returned policy to add more.

## Known limits

- The size and curve of keys already on the token are not inspected: using an existing key that would not pass generation (a short RSA modulus, a weak curve, …) is not refused. Only an ECDH key's type is checked.
- Raw `CKM_ECDSA`, `CKM_RSA_PKCS` and `CKM_RSA_PKCS_PSS` sign a caller-computed digest; the hash that produced it is not visible to the policy.
- `CKM_AES_KEY_WRAP_PAD` is allowed, but its padding is vendor-defined: some tokens implement RFC 5649 (KWP), others KW over PKCS#7-padded input, so a key wrapped on one token may not unwrap on another. Prefer `CKM_AES_KEY_WRAP_KWP` where the token supports it.

---

Anything not listed above is denied by default.
