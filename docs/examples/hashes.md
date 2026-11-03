# Hashes and HMAC

| Algorithm | Adapters | BCL types |
|---|---|---|
| [SHA-2](sha-2.md) | `SHA256Pkcs11`, `SHA384Pkcs11`, `SHA512Pkcs11` | `SHA256`, `SHA384`, `SHA512` |
| [SHA-3](sha-3.md) | `SHA3_256Pkcs11`, `SHA3_384Pkcs11`, `SHA3_512Pkcs11` | `SHA3_256`, `SHA3_384`, `SHA3_512` |
| [HMAC](hmac.md) | `HMACPkcs11` | `HMACSHA256` and the other `HMAC` types |

A hash takes no key, so hashing public data on a token gains nothing in secrecy, and the BCL is faster.
Use the token's hash when the token must do it: an environment where every cryptographic function has to
run inside a validated module, or a digest that feeds an operation the token performs next. An HMAC key
is a secret, and that is where a token helps: the key never enters your process.

MD5 and SHA-1 are broken; their adapters exist for [legacy interop](legacy.md) only.
