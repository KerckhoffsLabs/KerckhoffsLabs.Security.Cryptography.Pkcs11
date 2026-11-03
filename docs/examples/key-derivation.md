# Key derivation

The library offers the three BCL key-derivation functions over token keys:

| Function | Derives a key from | Adapter | BCL |
|---|---|---|---|
| [HKDF](hkdf.md) (RFC 5869) | key material: a shared secret, a master key | `HkdfPkcs11` | `HKDF` |
| [PBKDF2](pbkdf2.md) (RFC 8018) | a password | `Rfc2898DeriveBytesPkcs11` | `Rfc2898DeriveBytes.Pbkdf2` |
| [SP 800-108](sp800-108.md) counter mode, HMAC | a key-derivation key, a label and a context | `SP800108HmacCounterKdfPkcs11` | `SP800108HmacCounterKdf` |

**Derive into token keys.** Each adapter has overloads that create the derived key on the token from an
`ObjectTemplate`, and overloads that return the derived bytes, like the BCL. The default `Recommended`
policy refuses the byte-returning ones: reading secret key material off the token in the clear defeats
the token, and the policy's export rule refuses it. The examples use the on-token overloads; the derived
keys are AES keys, ready for [AES-GCM](aes-gcm.md).
