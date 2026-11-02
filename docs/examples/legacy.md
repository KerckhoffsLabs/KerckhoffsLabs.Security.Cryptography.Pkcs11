# Legacy algorithms

DES, Triple-DES, RC2, DSA, MD5 and SHA-1 are broken, deprecated or both. Their adapters exist for one
purpose: **reading, verifying or migrating data that already exists.** Never use them to produce new data;
the alternatives are in the table.

| Adapter | Why it is legacy | Use instead | Diagnostic |
|---|---|---|---|
| `DESPkcs11` | 56-bit key, exhaustively breakable | [AES-GCM](aead.md) | `KLPKCS11003` |
| `TripleDESPkcs11` | deprecated by NIST, 64-bit block (Sweet32) | [AES-GCM](aead.md) | `KLPKCS11004` |
| `RC2Pkcs11` | weak, reduced effective key length | [AES-GCM](aead.md) | `KLPKCS11005` |
| `DSAPkcs11` | disallowed for signing by FIPS 186-5 | [ECDSA](elliptic-curves.md), [ML-DSA](post-quantum.md), [RSA-PSS](rsa.md) | `KLPKCS11006` |
| `MD5Pkcs11` | practical collisions | [SHA-256](hashes.md) | `KLPKCS11001` |
| `SHA1Pkcs11` | practical collisions (SHAttered) | [SHA-256](hashes.md) | `KLPKCS11002` |

Every adapter here is `[Obsolete]`, and the default `Recommended` policy refuses its operations. Using one
takes two deliberate steps, both visible in the code:

1. **Suppress exactly the diagnostic, around exactly the line**, with a comment saying why:
   `#pragma warning disable KLPKCS11004` … `#pragma warning restore KLPKCS11004`. Never suppress it for
   the whole project. See [Diagnostics](../diagnostics.md).
2. **Lift the policy for one scoped operation**, with `using (session.UsePolicy(CryptoPolicy.AllowInsecure))`.
   The lease ends with the block; the session is back under its own policy afterwards. A session opened
   under `NistApproved` refuses the lease altogether.

## Decrypting a Triple-DES archive — `TripleDESPkcs11`

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/LegacyExamples.cs#TripleDesDecryptLegacyArchive)]

Migrate as you read: decrypt the archive, then encrypt what you keep with AES-GCM under a new key, and
retire the 3DES key.

## Decrypting single-DES and RC2 records — `DESPkcs11`, `RC2Pkcs11`

# [DES](#tab/des)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/LegacyExamples.cs#DesDecryptLegacyRecord)]

# [RC2](#tab/rc2)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/LegacyExamples.cs#Rc2DecryptLegacyRecord)]

---

The cipher adapters are `SymmetricAlgorithm`s like [`AesPkcs11`](aes.md): one-shot `DecryptCbc`,
`DecryptEcb` and the encrypting counterparts, no `ICryptoTransform`, no readable `Key`. Many tokens no
longer implement single DES or RC2 at all.

## Verifying an old DSA signature — `DSAPkcs11`

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/LegacyExamples.cs#DsaVerifyLegacySignature)]

Verifying a DSA signature needs only the public key, so a software `DSA` built from
`ExportParameters(false)` works too, off the token.

## MD5 and SHA-1 for a legacy protocol — `MD5Pkcs11`, `SHA1Pkcs11`

# [MD5](#tab/md5)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/LegacyExamples.cs#Md5ChecksumForLegacyProtocol)]

# [SHA-1](#tab/sha1)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/LegacyExamples.cs#Sha1ForLegacyProtocol)]

---

These are for protocols that still name or index data by MD5 or SHA-1, where the hash is an identifier,
not a security guarantee. An attacker can produce two inputs with the same MD5 or SHA-1, so never rely on
either for integrity or signatures. Hashing on a token gains nothing in secrecy; the BCL's `MD5` and
`SHA1` do the same off the token.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.TripleDESPkcs11>,
<xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.DESPkcs11>,
<xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.RC2Pkcs11>,
<xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.DSAPkcs11>,
<xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.MD5Pkcs11>,
<xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.SHA1Pkcs11>.
