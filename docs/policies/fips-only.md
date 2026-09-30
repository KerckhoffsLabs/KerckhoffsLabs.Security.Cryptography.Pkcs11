# FipsOnly policy catalogue

*Generated from the `FipsOnly` policy catalogue by `PolicyCatalogueMarkdown`; do not edit by hand.*

An allow-list of NIST-approved security functions, per a fixed snapshot of NIST guidance (see the baseline below). Anything not on the list below — including every vendor-defined mechanism — is denied by default, whether or not it also appears in the documented deny list further down this page.

> **`FipsOnly` is not a FIPS 140-3 certification.** It restricts what this library sends to the token; FIPS 140-3 compliance also requires a validated cryptographic module operating in its approved mode.
>
> Baseline: SP 800-131A Rev.2; SP 800-140C Rev.2 / SP 800-140D Rev.2 (CMVP lists of 2026-08-21); FIPS 186-5; SP 800-186; FIPS 203/204/205

## Allowed mechanisms

### AES

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_AES_CBC` | Encrypt, Decrypt | — | — | SP 800-38A (key wrapping: SP 800-38F / SP 800-131A Rev.2 §7) |
| `CKM_AES_CBC_PAD` | Encrypt, Decrypt | — | — | SP 800-38A (key wrapping: SP 800-38F / SP 800-131A Rev.2 §7) |
| `CKM_AES_CCM` | Encrypt, Decrypt, Wrap, Unwrap | — | — | SP 800-38D / SP 800-38C / SP 800-38F |
| `CKM_AES_CFB1` | Encrypt, Decrypt | — | — | SP 800-38A (key wrapping: SP 800-38F / SP 800-131A Rev.2 §7) |
| `CKM_AES_CFB128` | Encrypt, Decrypt | — | — | SP 800-38A (key wrapping: SP 800-38F / SP 800-131A Rev.2 §7) |
| `CKM_AES_CFB64` | Encrypt, Decrypt | — | — | SP 800-38A (key wrapping: SP 800-38F / SP 800-131A Rev.2 §7) |
| `CKM_AES_CFB8` | Encrypt, Decrypt | — | — | SP 800-38A (key wrapping: SP 800-38F / SP 800-131A Rev.2 §7) |
| `CKM_AES_CMAC` | Sign, Verify | — | — | SP 800-38B / SP 800-38D |
| `CKM_AES_CMAC_GENERAL` | Sign, Verify | — | — | SP 800-38B / SP 800-38D |
| `CKM_AES_CTR` | Encrypt, Decrypt | — | — | SP 800-38A (key wrapping: SP 800-38F / SP 800-131A Rev.2 §7) |
| `CKM_AES_CTS` | Encrypt, Decrypt | — | — | SP 800-38A (key wrapping: SP 800-38F / SP 800-131A Rev.2 §7) |
| `CKM_AES_ECB` | Encrypt, Decrypt | — | — | SP 800-38A (key wrapping: SP 800-38F / SP 800-131A Rev.2 §7) |
| `CKM_AES_GCM` | Encrypt, Decrypt, Wrap, Unwrap | — | — | SP 800-38D / SP 800-38C / SP 800-38F |
| `CKM_AES_GMAC` | Sign, Verify | — | — | SP 800-38B / SP 800-38D |
| `CKM_AES_KEY_GEN` | GenerateKey | — | — | SP 800-133 Rev.2 |
| `CKM_AES_KEY_WRAP` | Encrypt, Decrypt, Wrap, Unwrap | — | — | SP 800-38F |
| `CKM_AES_KEY_WRAP_KWP` | Encrypt, Decrypt, Wrap, Unwrap | — | — | SP 800-38F |
| `CKM_AES_OFB` | Encrypt, Decrypt | — | — | SP 800-38A (key wrapping: SP 800-38F / SP 800-131A Rev.2 §7) |
| `CKM_AES_XTS` | Encrypt, Decrypt | — | — | SP 800-38E (storage devices only; key wrapping: SP 800-38F / SP 800-131A Rev.2 §7) |
| `CKM_AES_XTS_KEY_GEN` | GenerateKey | — | — | SP 800-133 Rev.2 |

### DES / TDEA

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_DES3_CBC` | — | Decrypt, Unwrap | — | SP 800-131A Rev.2 §2 / §7 (TDEA encryption and key wrapping disallowed after 2023) |
| `CKM_DES3_CBC_PAD` | — | Decrypt, Unwrap | — | SP 800-131A Rev.2 §2 / §7 (TDEA encryption and key wrapping disallowed after 2023) |
| `CKM_DES3_CMAC` | — | Verify | — | SP 800-131A Rev.2 §10 (TDEA CMAC generation disallowed after 2023) |
| `CKM_DES3_CMAC_GENERAL` | — | Verify | — | SP 800-131A Rev.2 §10 (TDEA CMAC generation disallowed after 2023) |
| `CKM_DES3_ECB` | — | Decrypt, Unwrap | — | SP 800-131A Rev.2 §2 / §7 (TDEA encryption and key wrapping disallowed after 2023) |

### DSA

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_DSA` | — | Verify | — | FIPS 186-5 §4 (DSA signature generation no longer approved) |
| `CKM_DSA_SHA1` | — | Verify | — | FIPS 186-5 §4 (DSA signature generation no longer approved) |
| `CKM_DSA_SHA224` | — | Verify | — | FIPS 186-5 §4 (DSA signature generation no longer approved) |
| `CKM_DSA_SHA256` | — | Verify | — | FIPS 186-5 §4 (DSA signature generation no longer approved) |
| `CKM_DSA_SHA384` | — | Verify | — | FIPS 186-5 §4 (DSA signature generation no longer approved) |
| `CKM_DSA_SHA3_224` | — | Verify | — | FIPS 186-5 §4 (DSA signature generation no longer approved) |
| `CKM_DSA_SHA3_256` | — | Verify | — | FIPS 186-5 §4 (DSA signature generation no longer approved) |
| `CKM_DSA_SHA3_384` | — | Verify | — | FIPS 186-5 §4 (DSA signature generation no longer approved) |
| `CKM_DSA_SHA3_512` | — | Verify | — | FIPS 186-5 §4 (DSA signature generation no longer approved) |
| `CKM_DSA_SHA512` | — | Verify | — | FIPS 186-5 §4 (DSA signature generation no longer approved) |

### Digest / HMAC

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_GENERIC_SECRET_KEY_GEN` | GenerateKey | — | — | SP 800-133 Rev.2 |
| `CKM_SHA224` | Digest | — | — | FIPS 180-4 / FIPS 202 |
| `CKM_SHA224_HMAC` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA224_HMAC_GENERAL` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA224_KEY_GEN` | GenerateKey | — | — | SP 800-133 Rev.2 |
| `CKM_SHA256` | Digest | — | — | FIPS 180-4 / FIPS 202 |
| `CKM_SHA256_HMAC` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA256_HMAC_GENERAL` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA256_KEY_GEN` | GenerateKey | — | — | SP 800-133 Rev.2 |
| `CKM_SHA384` | Digest | — | — | FIPS 180-4 / FIPS 202 |
| `CKM_SHA384_HMAC` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA384_HMAC_GENERAL` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA384_KEY_GEN` | GenerateKey | — | — | SP 800-133 Rev.2 |
| `CKM_SHA3_224` | Digest | — | — | FIPS 180-4 / FIPS 202 |
| `CKM_SHA3_224_HMAC` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA3_224_HMAC_GENERAL` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA3_224_KEY_GEN` | GenerateKey | — | — | SP 800-133 Rev.2 |
| `CKM_SHA3_256` | Digest | — | — | FIPS 180-4 / FIPS 202 |
| `CKM_SHA3_256_HMAC` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA3_256_HMAC_GENERAL` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA3_256_KEY_GEN` | GenerateKey | — | — | SP 800-133 Rev.2 |
| `CKM_SHA3_384` | Digest | — | — | FIPS 180-4 / FIPS 202 |
| `CKM_SHA3_384_HMAC` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA3_384_HMAC_GENERAL` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA3_384_KEY_GEN` | GenerateKey | — | — | SP 800-133 Rev.2 |
| `CKM_SHA3_512` | Digest | — | — | FIPS 180-4 / FIPS 202 |
| `CKM_SHA3_512_HMAC` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA3_512_HMAC_GENERAL` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA3_512_KEY_GEN` | GenerateKey | — | — | SP 800-133 Rev.2 |
| `CKM_SHA512` | Digest | — | — | FIPS 180-4 / FIPS 202 |
| `CKM_SHA512_224` | Digest | — | — | FIPS 180-4 / FIPS 202 |
| `CKM_SHA512_224_HMAC` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA512_224_HMAC_GENERAL` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA512_224_KEY_GEN` | GenerateKey | — | — | SP 800-133 Rev.2 |
| `CKM_SHA512_256` | Digest | — | — | FIPS 180-4 / FIPS 202 |
| `CKM_SHA512_256_HMAC` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA512_256_HMAC_GENERAL` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA512_256_KEY_GEN` | GenerateKey | — | — | SP 800-133 Rev.2 |
| `CKM_SHA512_HMAC` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA512_HMAC_GENERAL` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA512_KEY_GEN` | GenerateKey | — | — | SP 800-133 Rev.2 |
| `CKM_SHA_1` | Digest | — | — | FIPS 180-4 / FIPS 202 |
| `CKM_SHA_1_HMAC` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA_1_HMAC_GENERAL` | Sign, Verify | — | — | FIPS 198-1 / SP 800-131A Rev.2 §10 |
| `CKM_SHA_1_KEY_GEN` | GenerateKey | — | — | SP 800-133 Rev.2 |

### EC

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_ECDH1_COFACTOR_DERIVE` | Derive | — | requires CkmEcdh1DeriveParams whose KDF is on the key-agreement KDF allow-list | SP 800-56A Rev.3 |
| `CKM_ECDH1_DERIVE` | Derive | — | requires CkmEcdh1DeriveParams whose KDF is on the key-agreement KDF allow-list | SP 800-56A Rev.3 |
| `CKM_ECDSA` | Sign, Verify | — | — | FIPS 186-5 §6 |
| `CKM_ECDSA_SHA1` | — | Verify | — | SP 800-131A Rev.2 §9 (SHA-1 signature generation disallowed) |
| `CKM_ECDSA_SHA224` | Sign, Verify | — | — | FIPS 186-5 §6 |
| `CKM_ECDSA_SHA256` | Sign, Verify | — | — | FIPS 186-5 §6 |
| `CKM_ECDSA_SHA384` | Sign, Verify | — | — | FIPS 186-5 §6 |
| `CKM_ECDSA_SHA3_224` | Sign, Verify | — | — | FIPS 186-5 §6 |
| `CKM_ECDSA_SHA3_256` | Sign, Verify | — | — | FIPS 186-5 §6 |
| `CKM_ECDSA_SHA3_384` | Sign, Verify | — | — | FIPS 186-5 §6 |
| `CKM_ECDSA_SHA3_512` | Sign, Verify | — | — | FIPS 186-5 §6 |
| `CKM_ECDSA_SHA512` | Sign, Verify | — | — | FIPS 186-5 §6 |
| `CKM_EC_EDWARDS_KEY_PAIR_GEN` | GenerateKeyPair | — | — | FIPS 186-5 §A.2 / SP 800-186 |
| `CKM_EC_KEY_PAIR_GEN` | GenerateKeyPair | — | — | FIPS 186-5 §A.2 / SP 800-186 |
| `CKM_EDDSA` | Sign, Verify | — | — | FIPS 186-5 §7 |

### KDF

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_HKDF_DERIVE` | Derive | — | requires CkmHkdfParams naming an approved PRF (an approved hash, hash or _HMAC form) | SP 800-56C Rev.2 |
| `CKM_HKDF_KEY_GEN` | GenerateKey | — | — | SP 800-56C Rev.2 |
| `CKM_PKCS5_PBKD2` | Derive, GenerateKey | — | requires CkmPkcs5Pbkd2Params naming an approved PRF (HMAC-SHA-1/224/256/384/512/512-224/512-256) | SP 800-132 |
| `CKM_SP800_108_COUNTER_KDF` | Derive | — | requires CkmSp800108KdfParams naming an approved PRF (HMAC over an approved hash, or AES-CMAC) | SP 800-108r1 |
| `CKM_SP800_108_DOUBLE_PIPELINE_KDF` | Derive | — | requires CkmSp800108KdfParams naming an approved PRF (HMAC over an approved hash, or AES-CMAC) | SP 800-108r1 |
| `CKM_SP800_108_FEEDBACK_KDF` | Derive | — | requires CkmSp800108KdfParams naming an approved PRF (HMAC over an approved hash, or AES-CMAC) | SP 800-108r1 |

### Post-quantum

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_HASH_ML_DSA` | Sign, Verify | — | requires CkmHashPqcSignParams naming a pre-hash of at least 128-bit collision strength | FIPS 204 §5.4 |
| `CKM_HASH_ML_DSA_SHA256` | Sign, Verify | — | — | FIPS 204 |
| `CKM_HASH_ML_DSA_SHA384` | Sign, Verify | — | — | FIPS 204 |
| `CKM_HASH_ML_DSA_SHA3_256` | Sign, Verify | — | — | FIPS 204 |
| `CKM_HASH_ML_DSA_SHA3_384` | Sign, Verify | — | — | FIPS 204 |
| `CKM_HASH_ML_DSA_SHA3_512` | Sign, Verify | — | — | FIPS 204 |
| `CKM_HASH_ML_DSA_SHA512` | Sign, Verify | — | — | FIPS 204 |
| `CKM_HASH_ML_DSA_SHAKE128` | Sign, Verify | — | — | FIPS 204 |
| `CKM_HASH_ML_DSA_SHAKE256` | Sign, Verify | — | — | FIPS 204 |
| `CKM_HASH_SLH_DSA` | Sign, Verify | — | requires CkmHashPqcSignParams naming a pre-hash of at least 128-bit collision strength | FIPS 205 §10 |
| `CKM_HASH_SLH_DSA_SHA256` | Sign, Verify | — | — | FIPS 205 |
| `CKM_HASH_SLH_DSA_SHA384` | Sign, Verify | — | — | FIPS 205 |
| `CKM_HASH_SLH_DSA_SHA3_256` | Sign, Verify | — | — | FIPS 205 |
| `CKM_HASH_SLH_DSA_SHA3_384` | Sign, Verify | — | — | FIPS 205 |
| `CKM_HASH_SLH_DSA_SHA3_512` | Sign, Verify | — | — | FIPS 205 |
| `CKM_HASH_SLH_DSA_SHA512` | Sign, Verify | — | — | FIPS 205 |
| `CKM_HASH_SLH_DSA_SHAKE128` | Sign, Verify | — | — | FIPS 205 |
| `CKM_HASH_SLH_DSA_SHAKE256` | Sign, Verify | — | — | FIPS 205 |
| `CKM_ML_DSA` | Sign, Verify | — | — | FIPS 204 |
| `CKM_ML_DSA_KEY_PAIR_GEN` | GenerateKeyPair | — | — | FIPS 203 / 204 / 205 |
| `CKM_ML_KEM` | Encapsulate, Decapsulate | — | — | FIPS 203 |
| `CKM_ML_KEM_KEY_PAIR_GEN` | GenerateKeyPair | — | — | FIPS 203 / 204 / 205 |
| `CKM_SLH_DSA` | Sign, Verify | — | — | FIPS 205 |
| `CKM_SLH_DSA_KEY_PAIR_GEN` | GenerateKeyPair | — | — | FIPS 203 / 204 / 205 |

### RSA encryption

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_RSA_PKCS_OAEP` | Encrypt, Decrypt, Wrap, Unwrap | — | requires CkmRsaPkcsOaepParams naming an approved hash | SP 800-56B Rev.2 |

### RSA key generation

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_RSA_PKCS_KEY_PAIR_GEN` | GenerateKeyPair | — | — | FIPS 186-5 §A.1 |

### RSA signature

| Mechanism | Operations | Legacy operations | Parameter check | Rationale |
|---|---|---|---|---|
| `CKM_RSA_PKCS` | Sign, Verify | — | — | FIPS 186-5 §5.4 (signatures only: SP 800-131A Rev.2 §6 / Table 5 disallows PKCS#1 v1.5 key transport after 2023; use CKM_RSA_PKCS_OAEP) |
| `CKM_RSA_PKCS_PSS` | Sign, Verify | — | requires CkmRsaPkcsPssParams naming an approved hash, with a salt no longer than that hash | FIPS 186-5 §5.4 |
| `CKM_SHA1_RSA_PKCS` | — | Verify | — | SP 800-131A Rev.2 §9 (SHA-1 signature generation disallowed) |
| `CKM_SHA1_RSA_PKCS_PSS` | — | Verify | (see rationale) | SP 800-131A Rev.2 §9 (SHA-1 signature generation disallowed) |
| `CKM_SHA224_RSA_PKCS` | Sign, Verify | — | — | FIPS 186-5 §5 |
| `CKM_SHA224_RSA_PKCS_PSS` | Sign, Verify | — | the MGF/parameter hash, when given, must be an approved hash | FIPS 186-5 §5.4 |
| `CKM_SHA256_RSA_PKCS` | Sign, Verify | — | — | FIPS 186-5 §5 |
| `CKM_SHA256_RSA_PKCS_PSS` | Sign, Verify | — | the MGF/parameter hash, when given, must be an approved hash | FIPS 186-5 §5.4 |
| `CKM_SHA384_RSA_PKCS` | Sign, Verify | — | — | FIPS 186-5 §5 |
| `CKM_SHA384_RSA_PKCS_PSS` | Sign, Verify | — | the MGF/parameter hash, when given, must be an approved hash | FIPS 186-5 §5.4 |
| `CKM_SHA3_224_RSA_PKCS` | Sign, Verify | — | — | FIPS 186-5 §5 |
| `CKM_SHA3_224_RSA_PKCS_PSS` | Sign, Verify | — | the MGF/parameter hash, when given, must be an approved hash | FIPS 186-5 §5.4 |
| `CKM_SHA3_256_RSA_PKCS` | Sign, Verify | — | — | FIPS 186-5 §5 |
| `CKM_SHA3_256_RSA_PKCS_PSS` | Sign, Verify | — | the MGF/parameter hash, when given, must be an approved hash | FIPS 186-5 §5.4 |
| `CKM_SHA3_384_RSA_PKCS` | Sign, Verify | — | — | FIPS 186-5 §5 |
| `CKM_SHA3_384_RSA_PKCS_PSS` | Sign, Verify | — | the MGF/parameter hash, when given, must be an approved hash | FIPS 186-5 §5.4 |
| `CKM_SHA3_512_RSA_PKCS` | Sign, Verify | — | — | FIPS 186-5 §5 |
| `CKM_SHA3_512_RSA_PKCS_PSS` | Sign, Verify | — | the MGF/parameter hash, when given, must be an approved hash | FIPS 186-5 §5.4 |
| `CKM_SHA512_RSA_PKCS` | Sign, Verify | — | — | FIPS 186-5 §5 |
| `CKM_SHA512_RSA_PKCS_PSS` | Sign, Verify | — | the MGF/parameter hash, when given, must be an approved hash | FIPS 186-5 §5.4 |

## Allowed hashes

| Hash | Operations | Rationale |
|---|---|---|
| `SHA1` | Verify | SP 800-131A Rev.2 §9 (legacy-use verification only; SHA-1 signature generation is no longer approved) |
| `SHA256` | Encrypt, Decrypt, Sign, Verify, Wrap, Unwrap, Derive, Digest, GenerateKey, GenerateKeyPair, Encapsulate, Decapsulate | FIPS 180-4 / FIPS 202 |
| `SHA3-256` | Encrypt, Decrypt, Sign, Verify, Wrap, Unwrap, Derive, Digest, GenerateKey, GenerateKeyPair, Encapsulate, Decapsulate | FIPS 180-4 / FIPS 202 |
| `SHA3-384` | Encrypt, Decrypt, Sign, Verify, Wrap, Unwrap, Derive, Digest, GenerateKey, GenerateKeyPair, Encapsulate, Decapsulate | FIPS 180-4 / FIPS 202 |
| `SHA3-512` | Encrypt, Decrypt, Sign, Verify, Wrap, Unwrap, Derive, Digest, GenerateKey, GenerateKeyPair, Encapsulate, Decapsulate | FIPS 180-4 / FIPS 202 |
| `SHA384` | Encrypt, Decrypt, Sign, Verify, Wrap, Unwrap, Derive, Digest, GenerateKey, GenerateKeyPair, Encapsulate, Decapsulate | FIPS 180-4 / FIPS 202 |
| `SHA512` | Encrypt, Decrypt, Sign, Verify, Wrap, Unwrap, Derive, Digest, GenerateKey, GenerateKeyPair, Encapsulate, Decapsulate | FIPS 180-4 / FIPS 202 |

## Allowed EC curves

| Curve | OID | Rationale |
|---|---|---|
| `nistP256` | `1.2.840.10045.3.1.7` | SP 800-186 §3.2.1.2 / SP 800-131A Rev.2 Table 2 (len(n) >= 224 acceptable) |
| `nistP224` | `1.3.132.0.33` | SP 800-186 §3.2.1.2 / SP 800-131A Rev.2 Table 2 (len(n) >= 224 acceptable) |
| `nistP384` | `1.3.132.0.34` | SP 800-186 §3.2.1.2 / SP 800-131A Rev.2 Table 2 (len(n) >= 224 acceptable) |
| `nistP521` | `1.3.132.0.35` | SP 800-186 §3.2.1.2 / SP 800-131A Rev.2 Table 2 (len(n) >= 224 acceptable) |

## Allowed key-agreement KDFs

| KDF | Rationale |
|---|---|
| `CKD_SHA224_KDF` | SP 800-135 Rev.1 §5.1 (ANSI X9.63 KDF over an approved FIPS 180 hash) |
| `CKD_SHA224_KDF_SP800` | SP 800-56C Rev.2 (one-step KDF) |
| `CKD_SHA256_KDF` | SP 800-135 Rev.1 §5.1 (ANSI X9.63 KDF over an approved FIPS 180 hash) |
| `CKD_SHA256_KDF_SP800` | SP 800-56C Rev.2 (one-step KDF) |
| `CKD_SHA384_KDF` | SP 800-135 Rev.1 §5.1 (ANSI X9.63 KDF over an approved FIPS 180 hash) |
| `CKD_SHA384_KDF_SP800` | SP 800-56C Rev.2 (one-step KDF) |
| `CKD_SHA3_224_KDF_SP800` | SP 800-56C Rev.2 (one-step KDF) |
| `CKD_SHA3_256_KDF_SP800` | SP 800-56C Rev.2 (one-step KDF) |
| `CKD_SHA3_384_KDF_SP800` | SP 800-56C Rev.2 (one-step KDF) |
| `CKD_SHA3_512_KDF_SP800` | SP 800-56C Rev.2 (one-step KDF) |
| `CKD_SHA512_KDF` | SP 800-135 Rev.1 §5.1 (ANSI X9.63 KDF over an approved FIPS 180 hash) |
| `CKD_SHA512_KDF_SP800` | SP 800-56C Rev.2 (one-step KDF) |

## Allowed key-agreement key types

The `CKA_KEY_TYPE` of the existing key an ECDH derivation or KEM uses (`CKM_ECDH1_DERIVE` serves both kinds).

| Key type | Rationale |
|---|---|
| `CKK_EC` | SP 800-56A Rev.3 §5.7.1.2 (ECC CDH over an SP 800-186 prime curve) |

## Allowed KDF PRFs

Per-family allow-list for the PRF named inside PBKDF2 / SP 800-108 / HKDF mechanism parameters.

| KDF family | Allowed PRFs |
|---|---|
| HKDF (CKM_HKDF_DERIVE) | `CKM_SHA224`, `CKM_SHA224_HMAC`, `CKM_SHA256`, `CKM_SHA256_HMAC`, `CKM_SHA384`, `CKM_SHA384_HMAC`, `CKM_SHA3_224`, `CKM_SHA3_224_HMAC`, `CKM_SHA3_256`, `CKM_SHA3_256_HMAC`, `CKM_SHA3_384`, `CKM_SHA3_384_HMAC`, `CKM_SHA3_512`, `CKM_SHA3_512_HMAC`, `CKM_SHA512`, `CKM_SHA512_224`, `CKM_SHA512_224_HMAC`, `CKM_SHA512_256`, `CKM_SHA512_256_HMAC`, `CKM_SHA512_HMAC`, `CKM_SHA_1`, `CKM_SHA_1_HMAC` |
| PBKDF2 (CKM_PKCS5_PBKD2) | `CKP_PKCS5_PBKD2_HMAC_SHA1`, `CKP_PKCS5_PBKD2_HMAC_SHA224`, `CKP_PKCS5_PBKD2_HMAC_SHA256`, `CKP_PKCS5_PBKD2_HMAC_SHA384`, `CKP_PKCS5_PBKD2_HMAC_SHA512`, `CKP_PKCS5_PBKD2_HMAC_SHA512_224`, `CKP_PKCS5_PBKD2_HMAC_SHA512_256` |
| SP 800-108 (CKM_SP800_108_*_KDF) | `CKM_AES_CMAC`, `CKM_SHA224_HMAC`, `CKM_SHA256_HMAC`, `CKM_SHA384_HMAC`, `CKM_SHA3_224_HMAC`, `CKM_SHA3_256_HMAC`, `CKM_SHA3_384_HMAC`, `CKM_SHA3_512_HMAC`, `CKM_SHA512_224_HMAC`, `CKM_SHA512_256_HMAC`, `CKM_SHA512_HMAC`, `CKM_SHA_1_HMAC` |

## Rules

Beyond the allow-lists above, three rules apply: the modulus rule to RSA key-pair generation requests, the template rule to key templates the library creates keys from, and the export rule to every read of secret key material off the token.

| Rule | Rationale |
|---|---|
| RSA key-pair generation modulus | RSA key generation requires a modulus of at least 2048 bits (FIPS 186-5 §5.1 / SP 800-131A Rev.2 §3). |
| Key template (`CKA_SENSITIVE`) | CSPs must not be output in plaintext; a key template with CKA_SENSITIVE=false is refused (FIPS 140-3, ISO/IEC 19790 §7.9). |
| Key-material export | Reading key material off the module in plaintext is not permitted (FIPS 140-3, ISO/IEC 19790 §7.9). |

## Documented refusals

Documentation only: every item below is refused because it is absent from the allow-lists above. This table only explains *why* it was considered and refused, rather than simply never reviewed; removing an entry here never allows the item.

### Mechanisms

#### AES

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_AES_KEY_WRAP_PAD` | Its padding is vendor-defined: some tokens implement RFC 5649 (SP 800-38F KWP), others KW over PKCS#7-padded input, which is not an SP 800-38F method. Whether a given token's wrap is approved cannot be told from the mechanism, so it is not approved. | CKM_AES_KEY_WRAP_KWP (RFC 5649) or CKM_AES_KEY_WRAP |

#### ChaCha20 / Salsa20

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_CHACHA20` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list; ChaCha20-Poly1305 has no FIPS 140-3 validation entry. | CKM_AES_GCM |
| `CKM_CHACHA20_POLY1305` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list; ChaCha20-Poly1305 has no FIPS 140-3 validation entry. | CKM_AES_GCM |

#### DES / TDEA

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_DES_CBC` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_DES_CBC_PAD` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_DES_CFB64` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_DES_CFB8` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_DES_ECB` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_DES_KEY_GEN` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_DES_MAC` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_DES_MAC_GENERAL` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_DES_OFB64` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_DES_OFB8` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |

#### Digest / HMAC

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_MD2` | Not defined by FIPS 180-4 or FIPS 202; MD2 and MD5 are cryptographically broken. | CKM_SHA256 or stronger |
| `CKM_MD5` | Not defined by FIPS 180-4 or FIPS 202; MD2 and MD5 are cryptographically broken. | CKM_SHA256 or stronger |
| `CKM_RIPEMD128` | Not defined by FIPS 180-4 or FIPS 202; MD2 and MD5 are cryptographically broken. | CKM_SHA256 or stronger |
| `CKM_RIPEMD160` | Not defined by FIPS 180-4 or FIPS 202; MD2 and MD5 are cryptographically broken. | CKM_SHA256 or stronger |
| `CKM_SHA512_T` | FIPS 180-4 §5.3.6 approves SHA-512/t only for t = 224 and t = 256, which have their own mechanisms; a caller-chosen truncation has no approval. | CKM_SHA512_224 or CKM_SHA512_256 |

#### EC

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` | SP 800-186 lists no Montgomery curves; X25519/X448 key generation has no FIPS 186-5 / SP 800-186 approval. | CKM_EC_KEY_PAIR_GEN (a NIST prime curve) or CKM_EC_EDWARDS_KEY_PAIR_GEN |

#### Legacy ciphers

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_BLOWFISH_CBC` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_BLOWFISH_CBC_PAD` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_BLOWFISH_KEY_GEN` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST128_CBC` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST128_CBC_PAD` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST128_ECB` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST128_KEY_GEN` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST128_MAC` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST128_MAC_GENERAL` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST3_CBC` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST3_CBC_PAD` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST3_ECB` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST3_KEY_GEN` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST3_MAC` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST3_MAC_GENERAL` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST_CBC` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST_CBC_PAD` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST_ECB` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST_KEY_GEN` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST_MAC` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_CAST_MAC_GENERAL` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_GOST28147` | GOST algorithms (GOST 28147-89, GOST R 34.10/34.11) are Russian national standards, not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | an approved AES cipher, ECDSA signature, or SHA-2/SHA-3 hash |
| `CKM_GOST28147_ECB` | GOST algorithms (GOST 28147-89, GOST R 34.10/34.11) are Russian national standards, not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | an approved AES cipher, ECDSA signature, or SHA-2/SHA-3 hash |
| `CKM_GOST28147_KEY_GEN` | GOST algorithms (GOST 28147-89, GOST R 34.10/34.11) are Russian national standards, not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | an approved AES cipher, ECDSA signature, or SHA-2/SHA-3 hash |
| `CKM_GOST28147_KEY_WRAP` | GOST algorithms (GOST 28147-89, GOST R 34.10/34.11) are Russian national standards, not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | an approved AES cipher, ECDSA signature, or SHA-2/SHA-3 hash |
| `CKM_GOST28147_MAC` | GOST algorithms (GOST 28147-89, GOST R 34.10/34.11) are Russian national standards, not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | an approved AES cipher, ECDSA signature, or SHA-2/SHA-3 hash |
| `CKM_GOSTR3410` | GOST algorithms (GOST 28147-89, GOST R 34.10/34.11) are Russian national standards, not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | an approved AES cipher, ECDSA signature, or SHA-2/SHA-3 hash |
| `CKM_GOSTR3410_DERIVE` | GOST algorithms (GOST 28147-89, GOST R 34.10/34.11) are Russian national standards, not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | an approved AES cipher, ECDSA signature, or SHA-2/SHA-3 hash |
| `CKM_GOSTR3410_KEY_PAIR_GEN` | GOST algorithms (GOST 28147-89, GOST R 34.10/34.11) are Russian national standards, not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | an approved AES cipher, ECDSA signature, or SHA-2/SHA-3 hash |
| `CKM_GOSTR3410_KEY_WRAP` | GOST algorithms (GOST 28147-89, GOST R 34.10/34.11) are Russian national standards, not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | an approved AES cipher, ECDSA signature, or SHA-2/SHA-3 hash |
| `CKM_GOSTR3410_WITH_GOSTR3411` | GOST algorithms (GOST 28147-89, GOST R 34.10/34.11) are Russian national standards, not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | an approved AES cipher, ECDSA signature, or SHA-2/SHA-3 hash |
| `CKM_GOSTR3411` | GOST algorithms (GOST 28147-89, GOST R 34.10/34.11) are Russian national standards, not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | an approved AES cipher, ECDSA signature, or SHA-2/SHA-3 hash |
| `CKM_GOSTR3411_HMAC` | GOST algorithms (GOST 28147-89, GOST R 34.10/34.11) are Russian national standards, not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | an approved AES cipher, ECDSA signature, or SHA-2/SHA-3 hash |
| `CKM_IDEA_CBC` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_IDEA_CBC_PAD` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_IDEA_ECB` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_IDEA_KEY_GEN` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_IDEA_MAC` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_IDEA_MAC_GENERAL` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_RC2_CBC` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_RC2_CBC_PAD` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_RC2_ECB` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_RC2_KEY_GEN` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_RC2_MAC` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_RC2_MAC_GENERAL` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_RC4` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_RC4_KEY_GEN` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_RC5_CBC` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_RC5_CBC_PAD` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_RC5_ECB` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_RC5_KEY_GEN` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_RC5_MAC` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_RC5_MAC_GENERAL` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_SEED_CBC` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_SEED_CBC_PAD` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_SEED_ECB` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_SEED_KEY_GEN` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_SEED_MAC` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_SEED_MAC_GENERAL` | Not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_CBC, CKM_AES_GCM, or CKM_AES_CCM |
| `CKM_SKIPJACK_CBC64` | Skipjack (Clipper/Capstone) was withdrawn and is not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP, or CKM_AES_GCM |
| `CKM_SKIPJACK_CFB16` | Skipjack (Clipper/Capstone) was withdrawn and is not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP, or CKM_AES_GCM |
| `CKM_SKIPJACK_CFB32` | Skipjack (Clipper/Capstone) was withdrawn and is not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP, or CKM_AES_GCM |
| `CKM_SKIPJACK_CFB64` | Skipjack (Clipper/Capstone) was withdrawn and is not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP, or CKM_AES_GCM |
| `CKM_SKIPJACK_CFB8` | Skipjack (Clipper/Capstone) was withdrawn and is not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP, or CKM_AES_GCM |
| `CKM_SKIPJACK_ECB64` | Skipjack (Clipper/Capstone) was withdrawn and is not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP, or CKM_AES_GCM |
| `CKM_SKIPJACK_KEY_GEN` | Skipjack (Clipper/Capstone) was withdrawn and is not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP, or CKM_AES_GCM |
| `CKM_SKIPJACK_OFB64` | Skipjack (Clipper/Capstone) was withdrawn and is not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP, or CKM_AES_GCM |
| `CKM_SKIPJACK_PRIVATE_WRAP` | Skipjack (Clipper/Capstone) was withdrawn and is not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP, or CKM_AES_GCM |
| `CKM_SKIPJACK_RELAYX` | Skipjack (Clipper/Capstone) was withdrawn and is not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP, or CKM_AES_GCM |
| `CKM_SKIPJACK_WRAP` | Skipjack (Clipper/Capstone) was withdrawn and is not on the SP 800-140C Rev.2 CMVP-approved algorithm list. | CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP, or CKM_AES_GCM |

#### Post-quantum

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_HASH_ML_DSA_SHA224` | FIPS 204 §5.4 / FIPS 205 §10 require the pre-hash to give at least 128-bit collision strength; SHA-224 / SHA3-224 give only ~112 bits. | the SHA-256/384/512 or SHA3-256/384/512 pre-hash variants |
| `CKM_HASH_ML_DSA_SHA3_224` | FIPS 204 §5.4 / FIPS 205 §10 require the pre-hash to give at least 128-bit collision strength; SHA-224 / SHA3-224 give only ~112 bits. | the SHA-256/384/512 or SHA3-256/384/512 pre-hash variants |
| `CKM_HASH_SLH_DSA_SHA224` | FIPS 204 §5.4 / FIPS 205 §10 require the pre-hash to give at least 128-bit collision strength; SHA-224 / SHA3-224 give only ~112 bits. | the SHA-256/384/512 or SHA3-256/384/512 pre-hash variants |
| `CKM_HASH_SLH_DSA_SHA3_224` | FIPS 204 §5.4 / FIPS 205 §10 require the pre-hash to give at least 128-bit collision strength; SHA-224 / SHA3-224 give only ~112 bits. | the SHA-256/384/512 or SHA3-256/384/512 pre-hash variants |

#### RSA key generation

| Mechanism | Reason | Alternative |
|---|---|---|
| `CKM_RSA_X9_31_KEY_PAIR_GEN` | FIPS 186-5 withdrew Appendix E; RSA key generation via ANSI X9.31 is no longer an approved method. | CKM_RSA_PKCS_KEY_PAIR_GEN |

### Hashes

| Hash | Reason | Alternative |
|---|---|---|
| `MD5` | Not defined by FIPS 180-4 or FIPS 202; MD5 is cryptographically broken. | SHA256 |

### EC curves

| Curve | OID | Reason | Alternative |
|---|---|---|---|
| `brainpoolP320t1` | `1.3.36.3.3.2.8.1.1.10` | SP 800-186 lists no Brainpool curve (RFC 5639); FIPS 186-5 Appendix A approves only the NIST prime curves. | NistP256, NistP384, or NistP521 |
| `brainpoolP384r1` | `1.3.36.3.3.2.8.1.1.11` | SP 800-186 lists no Brainpool curve (RFC 5639); FIPS 186-5 Appendix A approves only the NIST prime curves. | NistP256, NistP384, or NistP521 |
| `brainpoolP384t1` | `1.3.36.3.3.2.8.1.1.12` | SP 800-186 lists no Brainpool curve (RFC 5639); FIPS 186-5 Appendix A approves only the NIST prime curves. | NistP256, NistP384, or NistP521 |
| `brainpoolP512r1` | `1.3.36.3.3.2.8.1.1.13` | SP 800-186 lists no Brainpool curve (RFC 5639); FIPS 186-5 Appendix A approves only the NIST prime curves. | NistP256, NistP384, or NistP521 |
| `brainpoolP512t1` | `1.3.36.3.3.2.8.1.1.14` | SP 800-186 lists no Brainpool curve (RFC 5639); FIPS 186-5 Appendix A approves only the NIST prime curves. | NistP256, NistP384, or NistP521 |
| `brainpoolP256r1` | `1.3.36.3.3.2.8.1.1.7` | SP 800-186 lists no Brainpool curve (RFC 5639); FIPS 186-5 Appendix A approves only the NIST prime curves. | NistP256, NistP384, or NistP521 |
| `brainpoolP256t1` | `1.3.36.3.3.2.8.1.1.8` | SP 800-186 lists no Brainpool curve (RFC 5639); FIPS 186-5 Appendix A approves only the NIST prime curves. | NistP256, NistP384, or NistP521 |
| `brainpoolP320r1` | `1.3.36.3.3.2.8.1.1.9` | SP 800-186 lists no Brainpool curve (RFC 5639); FIPS 186-5 Appendix A approves only the NIST prime curves. | NistP256, NistP384, or NistP521 |

### Key-agreement KDFs

| KDF | Reason | Alternative |
|---|---|---|
| `CKD_SHA3_224_KDF` | SP 800-135 Rev.1 §5.1 approves the ANSI X9.63 KDF only with a FIPS 180 hash; no SHA-3 variant is defined. | CKD_SHA3_224_KDF_SP800 |
| `CKD_SHA3_256_KDF` | SP 800-135 Rev.1 §5.1 approves the ANSI X9.63 KDF only with a FIPS 180 hash; no SHA-3 variant is defined. | CKD_SHA3_256_KDF_SP800 |
| `CKD_SHA3_384_KDF` | SP 800-135 Rev.1 §5.1 approves the ANSI X9.63 KDF only with a FIPS 180 hash; no SHA-3 variant is defined. | CKD_SHA3_384_KDF_SP800 |
| `CKD_SHA3_512_KDF` | SP 800-135 Rev.1 §5.1 approves the ANSI X9.63 KDF only with a FIPS 180 hash; no SHA-3 variant is defined. | CKD_SHA3_512_KDF_SP800 |

### Key-agreement key types

| Key type | Reason | Alternative |
|---|---|---|
| `CKK_EC_MONTGOMERY` | SP 800-56A Rev.3 specifies no X25519/X448 scheme and SP 800-186 lists no Montgomery curves, so key agreement with an existing X25519/X448 key has no approval. | ECDH with a CKK_EC key on a NIST prime curve |

### KDF PRFs

| PRF | Reason | Alternative |
|---|---|---|
| `CKM_GOSTR3411_HMAC` | GOST R 34.11-94 is a regional (Russian national standard) hash that has not been reviewed for this policy. | an approved PRF (HMAC over an approved hash, or AES-CMAC where the mechanism allows it) |
| `CKP_PKCS5_PBKD2_HMAC_GOSTR3411` | GOST R 34.11-94 is a regional (Russian national standard) hash that has not been reviewed for this policy. | an approved PRF (HMAC over an approved hash, or AES-CMAC where the mechanism allows it) |

## Known limits

- The size and curve of keys already on the token are not inspected: using an existing key that would not pass generation (a short RSA modulus, a weak curve, …) is not refused. Only an ECDH key's type is checked.
- Raw `CKM_ECDSA`, `CKM_RSA_PKCS` and `CKM_RSA_PKCS_PSS` sign a caller-computed digest; the hash that produced it is not visible to the policy.
- FipsOnly restricts what this library sends to the token. FIPS 140-3 compliance also requires a validated cryptographic module operating in its approved mode.

---

Anything not listed above is denied by default.
