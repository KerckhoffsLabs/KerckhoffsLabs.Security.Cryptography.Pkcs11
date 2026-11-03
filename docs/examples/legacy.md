# Legacy algorithms

DES, Triple-DES, RC2, DSA, MD5 and SHA-1 are broken, deprecated or both. Their adapters exist for one
purpose: **reading, verifying or migrating data that already exists.** Never use them to produce new data;
the alternatives are in the table.

| Adapter | Why it is legacy | Use instead | Diagnostic |
|---|---|---|---|
| [`DESPkcs11`](des.md) | 56-bit key, exhaustively breakable | [AES-GCM](aes-gcm.md) | `KLPKCS11003` |
| [`TripleDESPkcs11`](triple-des.md) | deprecated by NIST, 64-bit block (Sweet32) | [AES-GCM](aes-gcm.md) | `KLPKCS11004` |
| [`RC2Pkcs11`](rc2.md) | weak, reduced effective key length | [AES-GCM](aes-gcm.md) | `KLPKCS11005` |
| [`DSAPkcs11`](dsa.md) | disallowed for signing by FIPS 186-5 | [ECDSA](ecdsa.md), [ML-DSA](ml-dsa.md), [RSA-PSS](rsa.md) | `KLPKCS11006` |
| [`MD5Pkcs11`](md5.md) | practical collisions | [SHA-256](sha-2.md) | `KLPKCS11001` |
| [`SHA1Pkcs11`](sha-1.md) | practical collisions (SHAttered) | [SHA-256](sha-2.md) | `KLPKCS11002` |

Every adapter here is `[Obsolete]`, and the default `Recommended` policy refuses its operations. Using one
takes two deliberate steps, both visible in the code:

1. **Suppress exactly the diagnostic, around exactly the line**, with a comment saying why:
   `#pragma warning disable KLPKCS11004` … `#pragma warning restore KLPKCS11004`. Never suppress it for
   the whole project. See [Diagnostics](../diagnostics.md).
2. **Lift the policy for one scoped operation**, with `using (session.UsePolicy(CryptoPolicy.AllowInsecure))`.
   The lease ends with the block, and the session is back under its own policy afterwards. While it is
   open it lifts every check **for the whole session**, on every thread using it, so do the legacy step
   on a session of its own. A session opened under `NistApproved` refuses the lease altogether. Narrower
   still: a policy derived from `Recommended` that allows only the one legacy mechanism for `Decrypt`, as
   the [AES block modes](aes.md) page shows.

The cipher adapters (`TripleDESPkcs11`, `DESPkcs11`, `RC2Pkcs11`) are `SymmetricAlgorithm`s like
[`AesPkcs11`](aes.md): one-shot `DecryptCbc`, `DecryptEcb` and the encrypting counterparts, no
`ICryptoTransform`, no readable `Key`.
