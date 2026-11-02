# Key derivation

The library offers the three BCL key-derivation functions over token keys:

| Function | Derives a key from | Adapter | BCL |
|---|---|---|---|
| HKDF (RFC 5869) | key material: a shared secret, a master key | `HkdfPkcs11` | `HKDF` |
| PBKDF2 (RFC 8018) | a password | `Rfc2898DeriveBytesPkcs11` | `Rfc2898DeriveBytes.Pbkdf2` |
| SP 800-108 counter mode, HMAC | a key-derivation key, a label and a context | `SP800108HmacCounterKdfPkcs11` | `SP800108HmacCounterKdf` |

**Derive into token keys.** Each adapter has overloads that create the derived key on the token from an
`ObjectTemplate`, and overloads that return the derived bytes, like the BCL. The default `Recommended`
policy refuses the byte-returning ones: reading secret key material off the token in the clear defeats
the token, and the policy's export rule refuses it. The examples below use the on-token overloads; the
derived keys are AES keys, ready for [AES-GCM](aead.md).

## HKDF — `HkdfPkcs11`

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/KdfExamples.cs#HkdfDeriveAesKey)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/KdfExamples.cs#BclHkdf)]

---

The input key material is a token key that may derive (`CKA_DERIVE`): for example the shared secret of
an [ECDH agreement](elliptic-curves.md#key-agreement-with-ecdh--ecdiffiehellmanpkcs11), which is how that
example uses HKDF. `HkdfPkcs11` also has `Extract`/`ExtractKey` and `Expand`/`ExpandKey` for the two steps
separately. The default policy accepts SHA-256, SHA-384, SHA-512 and SHA3-256/384/512 as the hash.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.HkdfPkcs11>.

## PBKDF2 — `Rfc2898DeriveBytesPkcs11`

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/KdfExamples.cs#Pbkdf2DeriveAesKey)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/KdfExamples.cs#BclPbkdf2)]

---

**What differs from `Rfc2898DeriveBytes`:**

- `Pbkdf2Key` takes the password as a `SecurePassword`, which keeps it in a pinned buffer that is zeroed
  on disposal; create it from characters (`new SecurePassword(chars)`) so no string holds the password.
  See [Secrets in memory](../security-model.md#secrets-in-memory).
- The hash and the iteration count are always explicit, as for the BCL's `Rfc2898DeriveBytes.Pbkdf2`.
- Use the static methods: `Pbkdf2Key` (on the token), or `Pbkdf2` (bytes, refused by the default
  policy). The `Rfc2898DeriveBytesPkcs11` constructors are `[Obsolete]` (`KLPKCS11011`), as all of the
  BCL's `Rfc2898DeriveBytes` constructors are; they remain only to continue one PBKDF2 byte stream across
  several `GetBytes` calls.
- The default policy accepts HMAC-SHA-256, -384 and -512 as the PRF. The iteration count is yours to
  choose: 600 000 for HMAC-SHA-256 follows current OWASP guidance.
- Few tokens implement `CKM_PKCS5_PBKD2`; check the token's mechanism list.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.Rfc2898DeriveBytesPkcs11>.

## SP 800-108 — `SP800108HmacCounterKdfPkcs11`

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/KdfExamples.cs#Sp800108DeriveAesKey)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/KdfExamples.cs#BclSp800108)]

---

Use it to derive many keys from one master key kept on the token, separated by label (the purpose) and
context (the party, tenant or session). It produces the same keys as the BCL's `SP800108HmacCounterKdf`
for the same inputs, so a key derived on the token can be re-derived in software from the same master
key, if your design ever needs that. The default policy accepts HMAC with SHA-256 or stronger.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.SP800108HmacCounterKdfPkcs11>.
