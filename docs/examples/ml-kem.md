# ML-KEM — `MLKemPkcs11`

FIPS 203 key establishment; see [Post-quantum cryptography](post-quantum.md) for what the token and the
platform need.

## Generating a key pair

Once, when you provision the token, generate the receiver's ML-KEM-768 key pair on it, as token objects under a label. Both halves
stay on the token after the session closes; the private key is sensitive and non-extractable, and each
half may do only its one job. The example exports the encapsulation key, to publish to senders.

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PostQuantum/MlKemExamples.cs#GenerateMlKemKey)]

The BCL has nothing like this to store: `MLKem.GenerateKey(MLKemAlgorithm.MLKem768)` makes the key pair in your process, as on the BCL tab below, and keeping the private key is up to you.

## Receiving a key

The receiver publishes an encapsulation key; a sender uses it to produce a shared secret and a
ciphertext; the receiver recovers the same secret from the ciphertext. On the PKCS#11 tab the receiver
is the token: it opens its key pair by label, and the secret becomes an AES key on the token, which
decrypts the sender's message:

# [PKCS#11](#tab/pkcs11)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PostQuantum/MlKemExamples.cs#MlKemReceiveAesKey)]

# [System.Security.Cryptography](#tab/bcl)

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PostQuantum/MlKemExamples.cs#BclMlKemReceive)]

---

ML-KEM-768 is the general-purpose choice; ML-KEM-1024 for the highest security category; ML-KEM-512
where size matters most.

**What differs from `MLKem`:**

- The key pair is generated on the token from templates that name the parameter set
  (`CKA_PARAMETER_SET`) and the two roles; there is no `MLKemPkcs11.GenerateKey`. Publish the
  encapsulation key with `ExportEncapsulationKey`, as with the BCL.
- **Decapsulate with `Pkcs11Key.DecapsulateKey`, not `MLKemPkcs11.Decapsulate`.** The BCL-shaped
  `Encapsulate` and `Decapsulate` return the shared secret to your process, so the default
  `Recommended` policy refuses them, as it refuses reading an [ECDH](ecdh.md) secret.
  `DecapsulateKey` (`C_DecapsulateKey`) creates the secret as a token key from your template, here an
  AES key for [AES-GCM](aes-gcm.md). Use `MLKemPkcs11` for `ExportEncapsulationKey` and the other
  public-key members.
- The BCL needs `MLKem.IsSupported`; the adapter needs a token with `CKM_ML_KEM`.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.MLKemPkcs11>,
<xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Pkcs11Key.DecapsulateKey*>.
