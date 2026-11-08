# AES block modes

**For new code, use authenticated encryption: [AES-GCM](aes-gcm.md).** CBC, ECB and CFB provide
confidentiality only. A ciphertext can be changed without the change being detected, and CBC with
padding, decrypted where an attacker can see whether decryption failed, is a padding oracle that
reveals the plaintext.

`AesPkcs11` is an `Aes` over a token key, for the formats and protocols that require one of these modes.
The default `Recommended` policy refuses all of them, so using it takes a deliberate, reviewed decision,
which the example records in a policy of its own.

## AES-CBC under a reviewed policy — `AesPkcs11`

### Generating a key

Once, when you provision the token, generate an AES-256 key on it, as a token object under a label. It
stays on the token after the session closes, sensitive and non-extractable, allowed to encrypt and
decrypt only:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/AesModes/AesModeExamples.cs#GenerateArchiveKey)]

The BCL has nothing like this to store: its key is random bytes in your process
(`RandomNumberGenerator.GetBytes(32)`), as on the BCL tab below, and keeping them is up to you.

### Encrypting with the key

In the application, open the key by its label, under the policy the format needs:

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/AesModes/AesModeExamples.cs#CbcPadUnderReviewedPolicy)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/AesModes/AesModeExamples.cs#BclCbcPad)]

---

**Why a derived policy rather than `AllowInsecure`:** `CryptoPolicy.Recommended.ToBuilder(name)` copies
every `Recommended` rule and adds exactly the mechanism you reviewed, for the operations you name, with
your reason attached. Everything else stays refused: the session cannot slip into ECB, a broken hash or a
weak key because CBC was allowed. `UsePolicy(CryptoPolicy.AllowInsecure)` lifts every check, for the whole
session (every thread using it) until the lease is disposed; keep it for a one-off operation on
[legacy data](legacy.md), on a session of its own. See [Using crypto policies](../guide/crypto-policies.md).

**What differs from `Aes.Create()`:**

- `AesPkcs11` wraps a token key; `Key` cannot be read or set, and `GenerateKey` is not supported.
- There is no `ICryptoTransform`: `CreateEncryptor` and `CreateDecryptor` throw `NotSupportedException`.
  Use the one-shot methods, which hand the whole message to the token.
- The one-shot methods map to token mechanisms: `EncryptCbc`/`DecryptCbc` with `PaddingMode.PKCS7` →
  `CKM_AES_CBC_PAD`, with `PaddingMode.None` → `CKM_AES_CBC`; `EncryptEcb`/`DecryptEcb` →
  `CKM_AES_ECB`; `EncryptCfb`/`DecryptCfb` with a 128- or 8-bit feedback size → `CKM_AES_CFB128` /
  `CKM_AES_CFB8`. Each must be allowed by the session's policy, and supported by the token.
- Under the default policy, the same `EncryptCbc` call throws `CryptoPolicyViolationException` before
  anything reaches the token.
- `NistApproved` allows these modes for encrypting data, but not for wrapping keys; see
  [NistApproved](../guide/policies/nist-approved.md).

**If you decrypt CBC from an untrusted source,** authenticate the ciphertext first (a signature or a MAC
over the ciphertext and IV), and reject it before decrypting if that check fails; never let a sender
observe the difference between bad padding and other failures.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.AesPkcs11>.
