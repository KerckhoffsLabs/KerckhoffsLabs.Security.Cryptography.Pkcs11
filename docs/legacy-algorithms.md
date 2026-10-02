# Legacy algorithms

Broken and legacy algorithms stay available for interoperability — decrypting an old archive, verifying an
old signature, talking to a system you cannot change — but never silently. Each is refused twice:

- **at compile time**, by an `[Obsolete]` type or an analyzer, each with its own
  [diagnostic id](diagnostics.md) that you can suppress precisely;
- **at run time**, by the workspace's [crypto policy](crypto-policies.md), which throws
  `CryptoPolicyViolationException` before anything reaches the token.

Suppressing the diagnostic does not change the policy. To use a legacy algorithm, do both: suppress its id
where you use it, and give the workspace a policy that allows the mechanism it uses.

## How to enable one

Derive a policy from `Recommended` that allows exactly the mechanism and operations you need, with the
reason. Prefer `AllowMechanismForLegacyUse` for decrypting or verifying existing data: it allows only
those operations, and refusals report them as legacy use.

```csharp
ComposedCryptoPolicy policy = CryptoPolicy.Recommended.ToBuilder("ArchiveReader")
    .AllowMechanismForLegacyUse(CKM.CKM_DES3_CBC_PAD, [CryptoOperation.Decrypt],
        "Reads the 2009 archive format, which is 3DES-CBC encrypted.")
    .Build();
using var workspace = library.OpenWorkspaceWithPin(tokenLabel, CKU.CKU_USER, pin, policy);
using var key = workspace.OpenKey("archive-key");

#pragma warning disable KLPKCS11004 // Triple-DES: reads the 2009 archive format
using var tdes = new TripleDESPkcs11(key);
byte[] plaintext = tdes.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
#pragma warning restore KLPKCS11004
```

Keep legacy use in its own workspace where you can, so the rest of the application keeps the default
policy. As a last resort for a one-off operation, `workspace.UsePolicy(CryptoPolicy.AllowInsecure)` lifts
the policy for one scoped block; it is refused on a `NistApproved` workspace.

The sections below list, for each legacy algorithm, the mechanisms to allow.

<a id="md5"></a>
## MD5 — `MD5Pkcs11` (KLPKCS11001)

| Use | Allow |
|---|---|
| Digest with `MD5Pkcs11` | `CKM_MD5` for `Digest` |
| An HMAC or signature computed with MD5 | the `CKM_MD5_*` mechanism itself, e.g. `CKM_MD5_HMAC` |

<a id="sha-1"></a>
## SHA-1 — `SHA1Pkcs11` (KLPKCS11002), `HashAlgorithmName.SHA1` (KLPKCS11010)

| Use | Allow |
|---|---|
| Digest with `SHA1Pkcs11` | `CKM_SHA_1` for `Digest` |
| Verify an existing SHA-1 RSA signature | `AllowMechanismForLegacyUse(CKM_SHA1_RSA_PKCS, [Verify], …)` (or `CKM_SHA1_RSA_PKCS_PSS`) |
| An HMAC with SHA-1 | `CKM_SHA_1_HMAC` for `Sign` / `Verify` |
| SHA-1 hashed on the managed side (a pre-hash before a raw signature) | `AllowHash(HashAlgorithmName.SHA1, …)` |

`NistApproved` already allows SHA-1 signature *verification* as legacy use (SP 800-131A).

<a id="des"></a>
## DES — `DESPkcs11` (KLPKCS11003)

`DESPkcs11` uses `CKM_DES_CBC_PAD` (CBC with PKCS#7 padding), `CKM_DES_CBC` (CBC without padding) or
`CKM_DES_ECB` (ECB). Allow the one your data uses, for `Decrypt` (and `Encrypt` only if you must still
produce DES data).

<a id="triple-des"></a>
## Triple-DES — `TripleDESPkcs11` (KLPKCS11004)

`TripleDESPkcs11` uses `CKM_DES3_CBC_PAD`, `CKM_DES3_CBC` or `CKM_DES3_ECB`, as for DES. The example at the
top of this page enables 3DES-CBC decryption.

<a id="rc2"></a>
## RC2 — `RC2Pkcs11` (KLPKCS11005)

`RC2Pkcs11` uses `CKM_RC2_CBC_PAD`, `CKM_RC2_CBC` or `CKM_RC2_ECB`, as for DES.

<a id="dsa"></a>
## DSA — `DSAPkcs11` (KLPKCS11006)

`DSAPkcs11` signs data with the combined `CKM_DSA_SHA*` mechanism for the hash you pass (for example
`CKM_DSA_SHA256` for SHA-256), and falls back to raw `CKM_DSA` over a managed digest when the token lacks
it. Allow both for the operations you need — usually `Verify` only, since FIPS 186-5 no longer allows DSA
signature generation:

```csharp
ComposedCryptoPolicy policy = CryptoPolicy.Recommended.ToBuilder("LegacyVerifier")
    .AllowMechanismForLegacyUse(CKM.CKM_DSA_SHA256, [CryptoOperation.Verify], "Verifies signatures of the old release tooling.")
    .AllowMechanismForLegacyUse(CKM.CKM_DSA, [CryptoOperation.Verify], "Same, on tokens without CKM_DSA_SHA256.")
    .Build();
```

<a id="weak-curves"></a>
## Weak elliptic curves — `Pkcs11ECCurve.NamedCurves` (KLPKCS11007)

Curves below the 128-bit baseline (P-192, P-224, secp192k1, secp224k1, the Brainpool 160/192/224-bit
curves) are refused for key generation. Allow the one curve you need:

```csharp
#pragma warning disable KLPKCS11007 // P-224: fleet devices, until their 2027 refresh
ComposedCryptoPolicy policy = CryptoPolicy.Recommended.ToBuilder("LegacyDevices")
    .AllowCurve(Pkcs11ECCurve.NamedCurves.NistP224, "Fleet devices only support P-224 until their 2027 refresh.")
    .Build();
#pragma warning restore KLPKCS11007
```

Using an existing key on such a curve is not refused; only generating one is.

<a id="rsa-pkcs1-encryption"></a>
## RSA encryption without OAEP (KLPKCS11008)

RSAES-PKCS#1 v1.5 (`CKM_RSA_PKCS`) and raw RSA (`CKM_RSA_X_509`) encryption expose padding oracles. To
decrypt existing v1.5 ciphertext, allow `AllowMechanismForLegacyUse(CKM.CKM_RSA_PKCS, [CryptoOperation.Decrypt], …)`.
RSA PKCS#1 v1.5 *signatures* with a strong hash are allowed by default and need nothing.

<a id="legacy-mechanisms"></a>
## Other legacy mechanisms (KLPKCS11009)

Unauthenticated AES modes (ECB, CBC, CBC-PAD, CTR, CTS, OFB, CFB), the broken hashes, the legacy ciphers
(RC4, SEED, CAST, RC5, Blowfish, Skipjack, …) and the DSA mechanisms are allowed the same way, one
mechanism at a time. For example, AES-CBC for a format that predates AEAD:

```csharp
ComposedCryptoPolicy policy = CryptoPolicy.Recommended.ToBuilder("LegacyFormat")
    .AllowMechanismForLegacyUse(CKM.CKM_AES_CBC_PAD, [CryptoOperation.Decrypt], "Reads v1 files, encrypted AES-CBC.")
    .Build();
```

Each mechanism's reason for refusal and recommended alternative are listed under "Documented refusals" in
[Recommended](policies/recommended.md).
