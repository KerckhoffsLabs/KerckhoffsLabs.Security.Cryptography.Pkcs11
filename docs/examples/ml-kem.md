# ML-KEM — `MLKemPkcs11`

FIPS 203 key establishment; see [Post-quantum cryptography](post-quantum.md) for what the token and the
platform need.

The receiver publishes an encapsulation key; a sender uses it to produce a shared secret and a
ciphertext; the receiver recovers the same secret from the ciphertext. Here the receiver is the token and
the secret becomes an AES key on it:

[!code-csharp[](../../samples/KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples/PostQuantum/MlKemExamples.cs#MlKemReceiveAesKey)]

**Why `DecapsulateKey` and not `MLKemPkcs11.Decapsulate`?** The BCL-shaped `Encapsulate` and
`Decapsulate` return the shared secret to your process, so the default `Recommended` policy refuses them,
as it refuses reading an [ECDH](ecdh.md) secret. `Pkcs11Key.DecapsulateKey` (`C_DecapsulateKey`) creates
the secret as a token key from your template, here an AES key for [AES-GCM](aes-gcm.md). Use
`MLKemPkcs11` for `ExportEncapsulationKey` and the other public-key members.

ML-KEM-768 is the general-purpose choice; ML-KEM-1024 for the highest security category; ML-KEM-512
where size matters most.

API reference: <xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms.MLKemPkcs11>,
<xref:KerckhoffsLabs.Security.Cryptography.Pkcs11.Pkcs11Key.DecapsulateKey*>.
