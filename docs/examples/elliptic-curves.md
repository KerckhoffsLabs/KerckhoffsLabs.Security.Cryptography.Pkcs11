# Elliptic curves

`ECDsaPkcs11` is an `ECDsa` and `ECDiffieHellmanPkcs11` an `ECDiffieHellman`, both over a token key pair.
Each role has its own key pair: `Pkcs11Session.GenerateEcSigningKeyPair` creates one that can only sign
and verify (ECDSA), and `GenerateEcKeyAgreementKeyPair` one that can only derive (ECDH). Both default to
P-256, and their private keys are sensitive and non-extractable.

| Algorithm | Purpose | Adapter | BCL type |
|---|---|---|---|
| [ECDSA](ecdsa.md) | Signatures | `ECDsaPkcs11` | `ECDsa` |
| [ECDH](ecdh.md) | Key agreement | `ECDiffieHellmanPkcs11` | `ECDiffieHellman` |
