# PBKDF2 — `Rfc2898DeriveBytesPkcs11`

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/KeyDerivation/Pbkdf2Examples.cs#Pbkdf2DeriveAesKey)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/KeyDerivation/Pbkdf2Examples.cs#BclPbkdf2)]

---

**What differs from `Rfc2898DeriveBytes`:**

- `Pbkdf2Key` takes the password as a `SecurePassword`, which keeps it in a pinned buffer that is zeroed
  on disposal; create it from characters (`new SecurePassword(chars)`) so no string holds the password.
  See [Secrets in memory](../guide/security-model.md#secrets-in-memory).
- The hash and the iteration count are always explicit, as for the BCL's `Rfc2898DeriveBytes.Pbkdf2`.
- Use the static methods: `Pbkdf2Key` (on the token), or `Pbkdf2` (bytes, refused by the default
  policy, see [Key derivation](key-derivation.md)). The `Rfc2898DeriveBytesPkcs11` constructors are
  `[Obsolete]` (`KLPKCS11011`), as all of the BCL's `Rfc2898DeriveBytes` constructors are; they remain
  only to continue one PBKDF2 byte stream across several `GetBytes` calls.
- The default policy accepts HMAC-SHA-256, -384 and -512 as the PRF. The iteration count is yours to
  choose: 600 000 for HMAC-SHA-256 follows current OWASP guidance.
- Few tokens implement `CKM_PKCS5_PBKD2`; check the token's mechanism list.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.Rfc2898DeriveBytesPkcs11>.
