# Cnsa20 policy catalogue

*Generated from the `Cnsa20` policy catalogue by `PolicyCatalogueMarkdown`; do not edit by hand.*

An allow-list of the NSA CNSA 2.0 algorithms at their CNSA 2.0 sizes (see the baseline below), with the size of every key checked when it is created and each time it is used. Anything not on the list below — including every vendor-defined mechanism — is denied by default, whether or not it also appears in the documented deny list further down this page.

> **`Cnsa20` is not a certification.** It restricts what this library sends to the token; it does not certify or validate the application or the token for CNSA 2.0.
>
> Baseline: NSA CNSA 2.0 (CSA Sept 2022; FAQ v2.2) — cited from secondary sources pending verification against the NSA documents; FIPS 197, FIPS 180-4, FIPS 203, FIPS 204, SP 800-208, SP 800-38D, SP 800-38F, SP 800-108r1, SP 800-56C Rev.2

## Allowed mechanisms

### AES

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_AES_GCM` | Encrypt, Decrypt, Wrap, Unwrap | — | tag, when parameters are given, of 128 bits | CNSA 2.0 AES-256 (FIPS 197) in GCM (SP 800-38D), 128-bit tag |
| `CKM_AES_KEY_GEN` | GenerateKey | — | — | CNSA 2.0 AES-256 (FIPS 197); CKA_VALUE_LEN must be 32 |
| `CKM_AES_KEY_WRAP` | Encrypt, Decrypt, Wrap, Unwrap | — | — | CNSA 2.0 AES-256 (FIPS 197) key wrap (SP 800-38F) |
| `CKM_AES_KEY_WRAP_KWP` | Encrypt, Decrypt, Wrap, Unwrap | — | — | CNSA 2.0 AES-256 (FIPS 197) key wrap (SP 800-38F) |

### Digest / HMAC

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_GENERIC_SECRET_KEY_GEN` | GenerateKey | — | — | Secret / HMAC key generation, at least 256 bits |
| `CKM_SHA384` | Digest | — | — | CNSA 2.0 SHA-384 / SHA-512 (FIPS 180-4) |
| `CKM_SHA384_HMAC` | Sign, Verify | — | — | HMAC over CNSA 2.0 SHA-384 / SHA-512 (FIPS 198-1), key of at least 256 bits |
| `CKM_SHA384_HMAC_GENERAL` | Sign, Verify | — | — | HMAC over CNSA 2.0 SHA-384 / SHA-512 (FIPS 198-1), key of at least 256 bits |
| `CKM_SHA384_KEY_GEN` | GenerateKey | — | — | Secret / HMAC key generation, at least 256 bits |
| `CKM_SHA512` | Digest | — | — | CNSA 2.0 SHA-384 / SHA-512 (FIPS 180-4) |
| `CKM_SHA512_HMAC` | Sign, Verify | — | — | HMAC over CNSA 2.0 SHA-384 / SHA-512 (FIPS 198-1), key of at least 256 bits |
| `CKM_SHA512_HMAC_GENERAL` | Sign, Verify | — | — | HMAC over CNSA 2.0 SHA-384 / SHA-512 (FIPS 198-1), key of at least 256 bits |
| `CKM_SHA512_KEY_GEN` | GenerateKey | — | — | Secret / HMAC key generation, at least 256 bits |

### KDF

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_HKDF_DATA` | Derive | — | requires CkmHkdfParams naming SHA-384 or SHA-512 (hash or _HMAC form) | SP 800-56C Rev.2 HKDF over SHA-384 / SHA-512 |
| `CKM_HKDF_DERIVE` | Derive | — | requires CkmHkdfParams naming SHA-384 or SHA-512 (hash or _HMAC form) | SP 800-56C Rev.2 HKDF over SHA-384 / SHA-512 |
| `CKM_HKDF_KEY_GEN` | GenerateKey | — | — | Secret / HMAC key generation, at least 256 bits |
| `CKM_SP800_108_COUNTER_KDF` | Derive | — | requires CkmSp800108KdfParams naming HMAC-SHA-384 or HMAC-SHA-512 | SP 800-108r1 over HMAC-SHA-384 / HMAC-SHA-512 |
| `CKM_SP800_108_DOUBLE_PIPELINE_KDF` | Derive | — | requires CkmSp800108KdfParams naming HMAC-SHA-384 or HMAC-SHA-512 | SP 800-108r1 over HMAC-SHA-384 / HMAC-SHA-512 |
| `CKM_SP800_108_FEEDBACK_KDF` | Derive | — | requires CkmSp800108KdfParams naming HMAC-SHA-384 or HMAC-SHA-512 | SP 800-108r1 over HMAC-SHA-384 / HMAC-SHA-512 |

### Post-quantum

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_HSS` | Sign, Verify | — | — | CNSA 2.0 LMS (single-level HSS) / XMSS (SP 800-208) |
| `CKM_HSS_KEY_PAIR_GEN` | GenerateKeyPair | — | — | CNSA 2.0 ML-KEM-1024 / ML-DSA-87 (FIPS 203 / 204), LMS / XMSS (SP 800-208) |
| `CKM_ML_DSA` | Sign, Verify | — | — | CNSA 2.0 ML-DSA-87 (FIPS 204) |
| `CKM_ML_DSA_KEY_PAIR_GEN` | GenerateKeyPair | — | — | CNSA 2.0 ML-KEM-1024 / ML-DSA-87 (FIPS 203 / 204), LMS / XMSS (SP 800-208) |
| `CKM_ML_KEM` | Encapsulate, Decapsulate | — | — | CNSA 2.0 ML-KEM-1024 (FIPS 203) |
| `CKM_ML_KEM_KEY_PAIR_GEN` | GenerateKeyPair | — | — | CNSA 2.0 ML-KEM-1024 / ML-DSA-87 (FIPS 203 / 204), LMS / XMSS (SP 800-208) |
| `CKM_XMSS` | Sign, Verify | — | — | CNSA 2.0 LMS (single-level HSS) / XMSS (SP 800-208) |
| `CKM_XMSS_KEY_PAIR_GEN` | GenerateKeyPair | — | — | CNSA 2.0 ML-KEM-1024 / ML-DSA-87 (FIPS 203 / 204), LMS / XMSS (SP 800-208) |

## Allowed hashes

| Hash | Operations | Rationale |
|---|---|---|
| `SHA384` | Encrypt, Decrypt, Sign, Verify, Wrap, Unwrap, Derive, Digest, GenerateKey, GenerateKeyPair, Encapsulate, Decapsulate | CNSA 2.0 SHA-384 (FIPS 180-4) |
| `SHA512` | Encrypt, Decrypt, Sign, Verify, Wrap, Unwrap, Derive, Digest, GenerateKey, GenerateKeyPair, Encapsulate, Decapsulate | CNSA 2.0 SHA-512 (FIPS 180-4) |

## Allowed EC curves

| Curve | OID | Rationale |
|---|---|---|

## Allowed key-agreement KDFs

| KDF | Rationale |
|---|---|

## Allowed key-agreement key types

The `CKA_KEY_TYPE` of the existing key an ECDH derivation or KEM uses (`CKM_ECDH1_DERIVE` serves both kinds).

| Key type | Rationale |
|---|---|

## Allowed KDF PRFs

Per-family allow-list for the PRF named inside PBKDF2 / SP 800-108 / HKDF mechanism parameters.

| KDF family | Allowed PRFs |
|---|---|
| HKDF (CKM_HKDF_DERIVE / CKM_HKDF_DATA) | `CKM_SHA384`, `CKM_SHA384_HMAC`, `CKM_SHA512`, `CKM_SHA512_HMAC` |
| SP 800-108 (CKM_SP800_108_*_KDF) | `CKM_SHA384_HMAC`, `CKM_SHA512_HMAC` |

## Rules

Beyond the allow-lists above, four rules apply: the modulus rule to RSA key-pair generation requests, the template rule to key templates the library creates keys from, the export rule to every read of secret key material off the token, and the key-strength rule to every key template, every key the token creates (a key that fails is destroyed) and every use of an existing key.

| Rule | Rationale |
|---|---|
| RSA key-pair generation modulus | RSA key generation requires a modulus of at least 2048 bits. |
| Key template (`CKA_SENSITIVE`) | Keys stay on the token: a key template with CKA_SENSITIVE=false is refused (CNSA 2.0 policy). |
| Key-material export | Reading key material off the token in plaintext is refused (CNSA 2.0 policy); wrap it with AES-256 KW/KWP or GCM instead. |
| Key strength | Every key is inspected when it is created and each time it is used: AES keys must be AES-256 (CKA_VALUE_LEN = 32); generic-secret, HKDF and HMAC-SHA-384/512 keys must hold a secret of at least 256 bits; ML-KEM keys must be ML-KEM-1024 and ML-DSA keys ML-DSA-87 (CKA_PARAMETER_SET); HSS keys must be single-level LMS (CKA_HSS_LEVELS = 1); XMSS keys are allowed. Every other key type is refused, and so is a key whose type, length, parameter set or HSS levels the token does not report. |

## Documented refusals

Documentation only: every item below is refused because it is absent from the allow-lists above. This table only explains *why* it was considered and refused, rather than simply never reviewed; removing an entry here never allows the item.

### Mechanisms

#### AES

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_AES_CBC` | CNSA 2.0 names AES-256 but no mode; this policy allows only the authenticated GCM mode and the KW/KWP key wraps. | CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys |
| `CKM_AES_CBC_PAD` | CNSA 2.0 names AES-256 but no mode; this policy allows only the authenticated GCM mode and the KW/KWP key wraps. | CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys |
| `CKM_AES_CCM` | CNSA 2.0 names AES-256 but no mode; this policy allows only the authenticated GCM mode and the KW/KWP key wraps. | CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys |
| `CKM_AES_CFB1` | CNSA 2.0 names AES-256 but no mode; this policy allows only the authenticated GCM mode and the KW/KWP key wraps. | CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys |
| `CKM_AES_CFB128` | CNSA 2.0 names AES-256 but no mode; this policy allows only the authenticated GCM mode and the KW/KWP key wraps. | CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys |
| `CKM_AES_CFB64` | CNSA 2.0 names AES-256 but no mode; this policy allows only the authenticated GCM mode and the KW/KWP key wraps. | CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys |
| `CKM_AES_CFB8` | CNSA 2.0 names AES-256 but no mode; this policy allows only the authenticated GCM mode and the KW/KWP key wraps. | CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys |
| `CKM_AES_CMAC` | CNSA 2.0 names AES-256 but no mode; this policy allows only the authenticated GCM mode and the KW/KWP key wraps. | CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys |
| `CKM_AES_CMAC_GENERAL` | CNSA 2.0 names AES-256 but no mode; this policy allows only the authenticated GCM mode and the KW/KWP key wraps. | CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys |
| `CKM_AES_CTR` | CNSA 2.0 names AES-256 but no mode; this policy allows only the authenticated GCM mode and the KW/KWP key wraps. | CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys |
| `CKM_AES_CTS` | CNSA 2.0 names AES-256 but no mode; this policy allows only the authenticated GCM mode and the KW/KWP key wraps. | CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys |
| `CKM_AES_ECB` | CNSA 2.0 names AES-256 but no mode; this policy allows only the authenticated GCM mode and the KW/KWP key wraps. | CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys |
| `CKM_AES_GMAC` | CNSA 2.0 names AES-256 but no mode; this policy allows only the authenticated GCM mode and the KW/KWP key wraps. | CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys |
| `CKM_AES_KEY_WRAP_PAD` | Its padding is vendor-defined (RFC 5649 on some tokens, KW over PKCS#7 on others), so it is not a known SP 800-38F method. | CKM_AES_KEY_WRAP_KWP or CKM_AES_KEY_WRAP |
| `CKM_AES_OFB` | CNSA 2.0 names AES-256 but no mode; this policy allows only the authenticated GCM mode and the KW/KWP key wraps. | CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys |
| `CKM_AES_XTS` | CNSA 2.0 names AES-256 but no mode; this policy allows only the authenticated GCM mode and the KW/KWP key wraps. | CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys |
| `CKM_AES_XTS_KEY_GEN` | CNSA 2.0 names AES-256 but no mode; this policy allows only the authenticated GCM mode and the KW/KWP key wraps. | CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys |

#### ChaCha20 / Salsa20

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_CHACHA20` | ChaCha20 is not part of CNSA 2.0. | CKM_AES_GCM with an AES-256 key |
| `CKM_CHACHA20_KEY_GEN` | ChaCha20 is not part of CNSA 2.0. | CKM_AES_GCM with an AES-256 key |
| `CKM_CHACHA20_POLY1305` | ChaCha20 is not part of CNSA 2.0. | CKM_AES_GCM with an AES-256 key |

#### DES / TDEA

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_DES2_KEY_GEN` | DES and TDEA are not part of CNSA 2.0. | AES-256 (CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys) |
| `CKM_DES3_CBC` | DES and TDEA are not part of CNSA 2.0. | AES-256 (CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys) |
| `CKM_DES3_CBC_PAD` | DES and TDEA are not part of CNSA 2.0. | AES-256 (CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys) |
| `CKM_DES3_CMAC` | DES and TDEA are not part of CNSA 2.0. | AES-256 (CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys) |
| `CKM_DES3_CMAC_GENERAL` | DES and TDEA are not part of CNSA 2.0. | AES-256 (CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys) |
| `CKM_DES3_ECB` | DES and TDEA are not part of CNSA 2.0. | AES-256 (CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys) |
| `CKM_DES3_KEY_GEN` | DES and TDEA are not part of CNSA 2.0. | AES-256 (CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys) |
| `CKM_DES_CBC` | DES and TDEA are not part of CNSA 2.0. | AES-256 (CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys) |
| `CKM_DES_CBC_PAD` | DES and TDEA are not part of CNSA 2.0. | AES-256 (CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys) |
| `CKM_DES_ECB` | DES and TDEA are not part of CNSA 2.0. | AES-256 (CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys) |
| `CKM_DES_KEY_GEN` | DES and TDEA are not part of CNSA 2.0. | AES-256 (CKM_AES_GCM, or CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP for keys) |

#### DH

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_DH_PKCS_DERIVE` | CNSA 2.0 has no elliptic-curve or finite-field key agreement; ML-KEM-1024 replaces ECDH and DH. | CKM_ML_KEM with an ML-KEM-1024 key |
| `CKM_DH_PKCS_KEY_PAIR_GEN` | CNSA 2.0 has no elliptic-curve or finite-field key agreement; ML-KEM-1024 replaces ECDH and DH. | CKM_ML_KEM with an ML-KEM-1024 key |

#### DSA

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_DSA` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_DSA_KEY_PAIR_GEN` | CNSA 2.0 has no elliptic-curve algorithms; generate ML-DSA-87 or ML-KEM-1024 key pairs instead. | CKM_ML_DSA_KEY_PAIR_GEN or CKM_ML_KEM_KEY_PAIR_GEN |
| `CKM_DSA_SHA1` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_DSA_SHA224` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_DSA_SHA256` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_DSA_SHA384` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_DSA_SHA3_224` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_DSA_SHA3_256` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_DSA_SHA3_384` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_DSA_SHA3_512` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_DSA_SHA512` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |

#### Digest / HMAC

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_SHA224` | CNSA 2.0 allows only SHA-384 and SHA-512. | CKM_SHA384 or CKM_SHA512 |
| `CKM_SHA224_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA224_HMAC_GENERAL` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA224_KEY_GEN` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC keys only for those. | CKM_SHA384_KEY_GEN, CKM_SHA512_KEY_GEN or CKM_GENERIC_SECRET_KEY_GEN |
| `CKM_SHA256` | CNSA 2.0 allows only SHA-384 and SHA-512. | CKM_SHA384 or CKM_SHA512 |
| `CKM_SHA256_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA256_HMAC_GENERAL` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA256_KEY_GEN` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC keys only for those. | CKM_SHA384_KEY_GEN, CKM_SHA512_KEY_GEN or CKM_GENERIC_SECRET_KEY_GEN |
| `CKM_SHA3_224` | CNSA 2.0 allows only SHA-384 and SHA-512. | CKM_SHA384 or CKM_SHA512 |
| `CKM_SHA3_224_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA3_224_HMAC_GENERAL` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA3_224_KEY_GEN` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC keys only for those. | CKM_SHA384_KEY_GEN, CKM_SHA512_KEY_GEN or CKM_GENERIC_SECRET_KEY_GEN |
| `CKM_SHA3_256` | CNSA 2.0 allows only SHA-384 and SHA-512. | CKM_SHA384 or CKM_SHA512 |
| `CKM_SHA3_256_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA3_256_HMAC_GENERAL` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA3_256_KEY_GEN` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC keys only for those. | CKM_SHA384_KEY_GEN, CKM_SHA512_KEY_GEN or CKM_GENERIC_SECRET_KEY_GEN |
| `CKM_SHA3_384` | CNSA 2.0 allows only SHA-384 and SHA-512. | CKM_SHA384 or CKM_SHA512 |
| `CKM_SHA3_384_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA3_384_HMAC_GENERAL` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA3_384_KEY_GEN` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC keys only for those. | CKM_SHA384_KEY_GEN, CKM_SHA512_KEY_GEN or CKM_GENERIC_SECRET_KEY_GEN |
| `CKM_SHA3_512` | CNSA 2.0 allows only SHA-384 and SHA-512. | CKM_SHA384 or CKM_SHA512 |
| `CKM_SHA3_512_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA3_512_HMAC_GENERAL` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA3_512_KEY_GEN` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC keys only for those. | CKM_SHA384_KEY_GEN, CKM_SHA512_KEY_GEN or CKM_GENERIC_SECRET_KEY_GEN |
| `CKM_SHA512_224` | CNSA 2.0 allows only SHA-384 and SHA-512. | CKM_SHA384 or CKM_SHA512 |
| `CKM_SHA512_224_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA512_224_HMAC_GENERAL` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA512_224_KEY_GEN` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC keys only for those. | CKM_SHA384_KEY_GEN, CKM_SHA512_KEY_GEN or CKM_GENERIC_SECRET_KEY_GEN |
| `CKM_SHA512_256` | CNSA 2.0 allows only SHA-384 and SHA-512. | CKM_SHA384 or CKM_SHA512 |
| `CKM_SHA512_256_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA512_256_HMAC_GENERAL` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA512_256_KEY_GEN` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC keys only for those. | CKM_SHA384_KEY_GEN, CKM_SHA512_KEY_GEN or CKM_GENERIC_SECRET_KEY_GEN |
| `CKM_SHA512_T` | CNSA 2.0 allows only SHA-384 and SHA-512. | CKM_SHA384 or CKM_SHA512 |
| `CKM_SHA_1` | CNSA 2.0 allows only SHA-384 and SHA-512. | CKM_SHA384 or CKM_SHA512 |
| `CKM_SHA_1_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA_1_HMAC_GENERAL` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC only over those. | CKM_SHA384_HMAC or CKM_SHA512_HMAC |
| `CKM_SHA_1_KEY_GEN` | CNSA 2.0 allows only SHA-384 and SHA-512, so HMAC keys only for those. | CKM_SHA384_KEY_GEN, CKM_SHA512_KEY_GEN or CKM_GENERIC_SECRET_KEY_GEN |

#### EC

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_ECDH1_COFACTOR_DERIVE` | CNSA 2.0 has no elliptic-curve or finite-field key agreement; ML-KEM-1024 replaces ECDH and DH. | CKM_ML_KEM with an ML-KEM-1024 key |
| `CKM_ECDH1_DERIVE` | CNSA 2.0 has no elliptic-curve or finite-field key agreement; ML-KEM-1024 replaces ECDH and DH. | CKM_ML_KEM with an ML-KEM-1024 key |
| `CKM_ECDSA` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_ECDSA_SHA1` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_ECDSA_SHA224` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_ECDSA_SHA256` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_ECDSA_SHA384` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_ECDSA_SHA3_224` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_ECDSA_SHA3_256` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_ECDSA_SHA3_384` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_ECDSA_SHA3_512` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_ECDSA_SHA512` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_EC_EDWARDS_KEY_PAIR_GEN` | CNSA 2.0 has no elliptic-curve algorithms; generate ML-DSA-87 or ML-KEM-1024 key pairs instead. | CKM_ML_DSA_KEY_PAIR_GEN or CKM_ML_KEM_KEY_PAIR_GEN |
| `CKM_EC_KEY_PAIR_GEN` | CNSA 2.0 has no elliptic-curve algorithms; generate ML-DSA-87 or ML-KEM-1024 key pairs instead. | CKM_ML_DSA_KEY_PAIR_GEN or CKM_ML_KEM_KEY_PAIR_GEN |
| `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` | CNSA 2.0 has no elliptic-curve algorithms; generate ML-DSA-87 or ML-KEM-1024 key pairs instead. | CKM_ML_DSA_KEY_PAIR_GEN or CKM_ML_KEM_KEY_PAIR_GEN |
| `CKM_EDDSA` | CNSA 2.0 has no DSA or elliptic-curve signature; ML-DSA-87 replaces them. | CKM_ML_DSA with an ML-DSA-87 key |

#### KDF

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_PKCS5_PBKD2` | CNSA 2.0 has no password-based key derivation. | CKM_HKDF_DERIVE or an SP 800-108 KDF (CKM_SP800_108_*_KDF) over a 256-bit secret held on the token |

#### Post-quantum

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_HASH_ML_DSA` | CNSA 2.0 allows pure ML-DSA-87 only; the NSA CNSA 2.0 FAQ is reported to see no benefit in pre-hashing over SHA-384/512 with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_ML_DSA_SHA224` | CNSA 2.0 allows pure ML-DSA-87 only; the NSA CNSA 2.0 FAQ is reported to see no benefit in pre-hashing over SHA-384/512 with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_ML_DSA_SHA256` | CNSA 2.0 allows pure ML-DSA-87 only; the NSA CNSA 2.0 FAQ is reported to see no benefit in pre-hashing over SHA-384/512 with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_ML_DSA_SHA384` | CNSA 2.0 allows pure ML-DSA-87 only; the NSA CNSA 2.0 FAQ is reported to see no benefit in pre-hashing over SHA-384/512 with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_ML_DSA_SHA3_224` | CNSA 2.0 allows pure ML-DSA-87 only; the NSA CNSA 2.0 FAQ is reported to see no benefit in pre-hashing over SHA-384/512 with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_ML_DSA_SHA3_256` | CNSA 2.0 allows pure ML-DSA-87 only; the NSA CNSA 2.0 FAQ is reported to see no benefit in pre-hashing over SHA-384/512 with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_ML_DSA_SHA3_384` | CNSA 2.0 allows pure ML-DSA-87 only; the NSA CNSA 2.0 FAQ is reported to see no benefit in pre-hashing over SHA-384/512 with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_ML_DSA_SHA3_512` | CNSA 2.0 allows pure ML-DSA-87 only; the NSA CNSA 2.0 FAQ is reported to see no benefit in pre-hashing over SHA-384/512 with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_ML_DSA_SHA512` | CNSA 2.0 allows pure ML-DSA-87 only; the NSA CNSA 2.0 FAQ is reported to see no benefit in pre-hashing over SHA-384/512 with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_ML_DSA_SHAKE128` | CNSA 2.0 allows pure ML-DSA-87 only; the NSA CNSA 2.0 FAQ is reported to see no benefit in pre-hashing over SHA-384/512 with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_ML_DSA_SHAKE256` | CNSA 2.0 allows pure ML-DSA-87 only; the NSA CNSA 2.0 FAQ is reported to see no benefit in pre-hashing over SHA-384/512 with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_SLH_DSA` | HashSLH-DSA (FIPS 205) is not part of CNSA 2.0. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_SLH_DSA_SHA224` | HashSLH-DSA (FIPS 205) is not part of CNSA 2.0. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_SLH_DSA_SHA256` | HashSLH-DSA (FIPS 205) is not part of CNSA 2.0. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_SLH_DSA_SHA384` | HashSLH-DSA (FIPS 205) is not part of CNSA 2.0. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_SLH_DSA_SHA3_224` | HashSLH-DSA (FIPS 205) is not part of CNSA 2.0. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_SLH_DSA_SHA3_256` | HashSLH-DSA (FIPS 205) is not part of CNSA 2.0. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_SLH_DSA_SHA3_384` | HashSLH-DSA (FIPS 205) is not part of CNSA 2.0. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_SLH_DSA_SHA3_512` | HashSLH-DSA (FIPS 205) is not part of CNSA 2.0. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_SLH_DSA_SHA512` | HashSLH-DSA (FIPS 205) is not part of CNSA 2.0. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_SLH_DSA_SHAKE128` | HashSLH-DSA (FIPS 205) is not part of CNSA 2.0. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_HASH_SLH_DSA_SHAKE256` | HashSLH-DSA (FIPS 205) is not part of CNSA 2.0. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SLH_DSA` | SLH-DSA (FIPS 205) is not part of CNSA 2.0. | CKM_ML_DSA (ML-DSA-87), or CKM_HSS / CKM_XMSS for firmware signing |
| `CKM_SLH_DSA_KEY_PAIR_GEN` | SLH-DSA (FIPS 205) is not part of CNSA 2.0. | CKM_ML_DSA (ML-DSA-87), or CKM_HSS / CKM_XMSS for firmware signing |
| `CKM_XMSSMT` | CNSA 2.0 allows single-tree XMSS, not the multi-tree XMSS^MT (SP 800-208). | CKM_XMSS / CKM_XMSS_KEY_PAIR_GEN |
| `CKM_XMSSMT_KEY_PAIR_GEN` | CNSA 2.0 allows single-tree XMSS, not the multi-tree XMSS^MT (SP 800-208). | CKM_XMSS / CKM_XMSS_KEY_PAIR_GEN |

#### RSA encryption

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_RSA_PKCS_OAEP` | CNSA 2.0 replaces RSA key establishment with ML-KEM-1024. | CKM_ML_KEM with an ML-KEM-1024 key |

#### RSA key generation

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_RSA_PKCS_KEY_PAIR_GEN` | CNSA 2.0 has no RSA; generate ML-DSA-87 or ML-KEM-1024 key pairs instead. | CKM_ML_DSA_KEY_PAIR_GEN or CKM_ML_KEM_KEY_PAIR_GEN |
| `CKM_RSA_X9_31_KEY_PAIR_GEN` | CNSA 2.0 has no RSA; generate ML-DSA-87 or ML-KEM-1024 key pairs instead. | CKM_ML_DSA_KEY_PAIR_GEN or CKM_ML_KEM_KEY_PAIR_GEN |

#### RSA signature

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_RSA_PKCS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87 and RSA key establishment with ML-KEM-1024. | CKM_ML_DSA (ML-DSA-87) to sign, CKM_ML_KEM (ML-KEM-1024) to establish keys |
| `CKM_RSA_PKCS_PSS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_RSA_X_509` | CNSA 2.0 replaces RSA signatures with ML-DSA-87 and RSA key establishment with ML-KEM-1024. | CKM_ML_DSA (ML-DSA-87) to sign, CKM_ML_KEM (ML-KEM-1024) to establish keys |
| `CKM_SHA1_RSA_PKCS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SHA1_RSA_PKCS_PSS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SHA224_RSA_PKCS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SHA224_RSA_PKCS_PSS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SHA256_RSA_PKCS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SHA256_RSA_PKCS_PSS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SHA384_RSA_PKCS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SHA384_RSA_PKCS_PSS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SHA3_224_RSA_PKCS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SHA3_224_RSA_PKCS_PSS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SHA3_256_RSA_PKCS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SHA3_256_RSA_PKCS_PSS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SHA3_384_RSA_PKCS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SHA3_384_RSA_PKCS_PSS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SHA3_512_RSA_PKCS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SHA3_512_RSA_PKCS_PSS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SHA512_RSA_PKCS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |
| `CKM_SHA512_RSA_PKCS_PSS` | CNSA 2.0 replaces RSA signatures with ML-DSA-87. | CKM_ML_DSA with an ML-DSA-87 key |

### Hashes

| Hash | Reason | Alternative |
|---|---|---|
| `MD5` | CNSA 2.0 allows only SHA-384 and SHA-512. | SHA384 or SHA512 |
| `SHA1` | CNSA 2.0 allows only SHA-384 and SHA-512. | SHA384 or SHA512 |
| `SHA224` | CNSA 2.0 allows only SHA-384 and SHA-512. | SHA384 or SHA512 |
| `SHA256` | CNSA 2.0 allows only SHA-384 and SHA-512. | SHA384 or SHA512 |
| `SHA3-256` | CNSA 2.0 allows only SHA-384 and SHA-512. | SHA384 or SHA512 |
| `SHA3-384` | CNSA 2.0 allows only SHA-384 and SHA-512. | SHA384 or SHA512 |
| `SHA3-512` | CNSA 2.0 allows only SHA-384 and SHA-512. | SHA384 or SHA512 |

### EC curves

| Curve | OID | Reason | Alternative |
|---|---|---|---|
| `nistP256` | `1.2.840.10045.3.1.7` | CNSA 2.0 has no elliptic-curve algorithms. | ML-DSA-87 (CKM_ML_DSA_KEY_PAIR_GEN) to sign, ML-KEM-1024 (CKM_ML_KEM_KEY_PAIR_GEN) to establish keys |
| `secp256k1` | `1.3.132.0.10` | CNSA 2.0 has no elliptic-curve algorithms. | ML-DSA-87 (CKM_ML_DSA_KEY_PAIR_GEN) to sign, ML-KEM-1024 (CKM_ML_KEM_KEY_PAIR_GEN) to establish keys |
| `nistP224` | `1.3.132.0.33` | CNSA 2.0 has no elliptic-curve algorithms. | ML-DSA-87 (CKM_ML_DSA_KEY_PAIR_GEN) to sign, ML-KEM-1024 (CKM_ML_KEM_KEY_PAIR_GEN) to establish keys |
| `nistP384` | `1.3.132.0.34` | CNSA 2.0 has no elliptic-curve algorithms. | ML-DSA-87 (CKM_ML_DSA_KEY_PAIR_GEN) to sign, ML-KEM-1024 (CKM_ML_KEM_KEY_PAIR_GEN) to establish keys |
| `nistP521` | `1.3.132.0.35` | CNSA 2.0 has no elliptic-curve algorithms. | ML-DSA-87 (CKM_ML_DSA_KEY_PAIR_GEN) to sign, ML-KEM-1024 (CKM_ML_KEM_KEY_PAIR_GEN) to establish keys |
| `brainpoolP320t1` | `1.3.36.3.3.2.8.1.1.10` | CNSA 2.0 has no elliptic-curve algorithms. | ML-DSA-87 (CKM_ML_DSA_KEY_PAIR_GEN) to sign, ML-KEM-1024 (CKM_ML_KEM_KEY_PAIR_GEN) to establish keys |
| `brainpoolP384r1` | `1.3.36.3.3.2.8.1.1.11` | CNSA 2.0 has no elliptic-curve algorithms. | ML-DSA-87 (CKM_ML_DSA_KEY_PAIR_GEN) to sign, ML-KEM-1024 (CKM_ML_KEM_KEY_PAIR_GEN) to establish keys |
| `brainpoolP384t1` | `1.3.36.3.3.2.8.1.1.12` | CNSA 2.0 has no elliptic-curve algorithms. | ML-DSA-87 (CKM_ML_DSA_KEY_PAIR_GEN) to sign, ML-KEM-1024 (CKM_ML_KEM_KEY_PAIR_GEN) to establish keys |
| `brainpoolP512r1` | `1.3.36.3.3.2.8.1.1.13` | CNSA 2.0 has no elliptic-curve algorithms. | ML-DSA-87 (CKM_ML_DSA_KEY_PAIR_GEN) to sign, ML-KEM-1024 (CKM_ML_KEM_KEY_PAIR_GEN) to establish keys |
| `brainpoolP512t1` | `1.3.36.3.3.2.8.1.1.14` | CNSA 2.0 has no elliptic-curve algorithms. | ML-DSA-87 (CKM_ML_DSA_KEY_PAIR_GEN) to sign, ML-KEM-1024 (CKM_ML_KEM_KEY_PAIR_GEN) to establish keys |
| `brainpoolP256r1` | `1.3.36.3.3.2.8.1.1.7` | CNSA 2.0 has no elliptic-curve algorithms. | ML-DSA-87 (CKM_ML_DSA_KEY_PAIR_GEN) to sign, ML-KEM-1024 (CKM_ML_KEM_KEY_PAIR_GEN) to establish keys |
| `brainpoolP256t1` | `1.3.36.3.3.2.8.1.1.8` | CNSA 2.0 has no elliptic-curve algorithms. | ML-DSA-87 (CKM_ML_DSA_KEY_PAIR_GEN) to sign, ML-KEM-1024 (CKM_ML_KEM_KEY_PAIR_GEN) to establish keys |
| `brainpoolP320r1` | `1.3.36.3.3.2.8.1.1.9` | CNSA 2.0 has no elliptic-curve algorithms. | ML-DSA-87 (CKM_ML_DSA_KEY_PAIR_GEN) to sign, ML-KEM-1024 (CKM_ML_KEM_KEY_PAIR_GEN) to establish keys |

### Key-agreement KDFs

| KDF | Reason | Alternative |
|---|---|---|
| `CKD_SHA224_KDF` | CNSA 2.0 has no elliptic-curve key agreement, so no ECDH KDF is used. | CKM_ML_KEM (ML-KEM-1024), then CKM_HKDF_DERIVE or an SP 800-108 KDF over SHA-384 / SHA-512 |
| `CKD_SHA224_KDF_SP800` | CNSA 2.0 has no elliptic-curve key agreement, so no ECDH KDF is used. | CKM_ML_KEM (ML-KEM-1024), then CKM_HKDF_DERIVE or an SP 800-108 KDF over SHA-384 / SHA-512 |
| `CKD_SHA256_KDF` | CNSA 2.0 has no elliptic-curve key agreement, so no ECDH KDF is used. | CKM_ML_KEM (ML-KEM-1024), then CKM_HKDF_DERIVE or an SP 800-108 KDF over SHA-384 / SHA-512 |
| `CKD_SHA256_KDF_SP800` | CNSA 2.0 has no elliptic-curve key agreement, so no ECDH KDF is used. | CKM_ML_KEM (ML-KEM-1024), then CKM_HKDF_DERIVE or an SP 800-108 KDF over SHA-384 / SHA-512 |
| `CKD_SHA384_KDF` | CNSA 2.0 has no elliptic-curve key agreement, so no ECDH KDF is used. | CKM_ML_KEM (ML-KEM-1024), then CKM_HKDF_DERIVE or an SP 800-108 KDF over SHA-384 / SHA-512 |
| `CKD_SHA384_KDF_SP800` | CNSA 2.0 has no elliptic-curve key agreement, so no ECDH KDF is used. | CKM_ML_KEM (ML-KEM-1024), then CKM_HKDF_DERIVE or an SP 800-108 KDF over SHA-384 / SHA-512 |
| `CKD_SHA3_224_KDF_SP800` | CNSA 2.0 has no elliptic-curve key agreement, so no ECDH KDF is used. | CKM_ML_KEM (ML-KEM-1024), then CKM_HKDF_DERIVE or an SP 800-108 KDF over SHA-384 / SHA-512 |
| `CKD_SHA3_256_KDF` | CNSA 2.0 has no elliptic-curve key agreement, so no ECDH KDF is used. | CKM_ML_KEM (ML-KEM-1024), then CKM_HKDF_DERIVE or an SP 800-108 KDF over SHA-384 / SHA-512 |
| `CKD_SHA3_256_KDF_SP800` | CNSA 2.0 has no elliptic-curve key agreement, so no ECDH KDF is used. | CKM_ML_KEM (ML-KEM-1024), then CKM_HKDF_DERIVE or an SP 800-108 KDF over SHA-384 / SHA-512 |
| `CKD_SHA3_384_KDF` | CNSA 2.0 has no elliptic-curve key agreement, so no ECDH KDF is used. | CKM_ML_KEM (ML-KEM-1024), then CKM_HKDF_DERIVE or an SP 800-108 KDF over SHA-384 / SHA-512 |
| `CKD_SHA3_384_KDF_SP800` | CNSA 2.0 has no elliptic-curve key agreement, so no ECDH KDF is used. | CKM_ML_KEM (ML-KEM-1024), then CKM_HKDF_DERIVE or an SP 800-108 KDF over SHA-384 / SHA-512 |
| `CKD_SHA3_512_KDF` | CNSA 2.0 has no elliptic-curve key agreement, so no ECDH KDF is used. | CKM_ML_KEM (ML-KEM-1024), then CKM_HKDF_DERIVE or an SP 800-108 KDF over SHA-384 / SHA-512 |
| `CKD_SHA3_512_KDF_SP800` | CNSA 2.0 has no elliptic-curve key agreement, so no ECDH KDF is used. | CKM_ML_KEM (ML-KEM-1024), then CKM_HKDF_DERIVE or an SP 800-108 KDF over SHA-384 / SHA-512 |
| `CKD_SHA512_KDF` | CNSA 2.0 has no elliptic-curve key agreement, so no ECDH KDF is used. | CKM_ML_KEM (ML-KEM-1024), then CKM_HKDF_DERIVE or an SP 800-108 KDF over SHA-384 / SHA-512 |
| `CKD_SHA512_KDF_SP800` | CNSA 2.0 has no elliptic-curve key agreement, so no ECDH KDF is used. | CKM_ML_KEM (ML-KEM-1024), then CKM_HKDF_DERIVE or an SP 800-108 KDF over SHA-384 / SHA-512 |

### Key-agreement key types

| Key type | Reason | Alternative |
|---|---|---|
| `CKK_EC` | CNSA 2.0 has no elliptic-curve or finite-field key agreement; ML-KEM replaces ECDH. | CKM_ML_KEM with an ML-KEM-1024 key |
| `CKK_EC_MONTGOMERY` | CNSA 2.0 has no elliptic-curve or finite-field key agreement; ML-KEM replaces ECDH. | CKM_ML_KEM with an ML-KEM-1024 key |

### KDF PRFs

| PRF | Reason | Alternative |
|---|---|---|
| `CKM_AES_CMAC` | This policy allows only HMAC-SHA-384 and HMAC-SHA-512 as the SP 800-108 PRF. | HMAC-SHA-384 or HMAC-SHA-512 |
| `CKM_SHA224` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |
| `CKM_SHA224_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |
| `CKM_SHA256` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |
| `CKM_SHA256_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |
| `CKM_SHA3_224` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |
| `CKM_SHA3_224_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |
| `CKM_SHA3_256` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |
| `CKM_SHA3_256_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |
| `CKM_SHA3_384` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |
| `CKM_SHA3_384_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |
| `CKM_SHA3_512` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |
| `CKM_SHA3_512_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |
| `CKM_SHA512_224` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |
| `CKM_SHA512_224_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |
| `CKM_SHA512_256` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |
| `CKM_SHA512_256_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |
| `CKM_SHA_1` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |
| `CKM_SHA_1_HMAC` | CNSA 2.0 allows only SHA-384 and SHA-512. | HMAC-SHA-384 or HMAC-SHA-512 (or SHA-384 / SHA-512 for HKDF) |

## Known limits

- Cnsa20 restricts what this library sends to the token; it is not a CNSA 2.0 certification or validation of the application or the token.
- LMS (`CKM_HSS`) and XMSS (`CKM_XMSS`) are allowed for any signing. CNSA 2.0 intends them for software and firmware signing; the policy cannot see what is being signed, so restricting them to that use is the application's job.
- XMSS parameter sets are not checked.
- It fails closed: a key whose type, length, parameter set or HSS levels the token does not report (absent, sensitive or unavailable) is refused, so a token that hides these attributes cannot use a compliant key.
- Each keyed operation costs one or two extra `C_GetAttributeValue` calls, because the key is read again on every use rather than cached.
- `C_SetOperationState` restores a saved operation whose own mechanism and key are not inspected; only the key handles passed to it are.
- Keys returned through TLS/SSL3 key-and-MAC parameters are not judged after creation. Cnsa20 refuses those mechanisms, but a policy derived from it that allows them again would not judge those keys.

---

Anything not listed above is denied by default.
