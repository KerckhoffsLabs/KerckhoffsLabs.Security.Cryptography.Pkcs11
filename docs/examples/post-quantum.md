# Post-quantum cryptography

The library supports the three NIST post-quantum standards, each as an adapter over the BCL type of the
same name:

| Standard | Purpose | Adapter | BCL type |
|---|---|---|---|
| [FIPS 203 ML-KEM](ml-kem.md) | Key establishment | `MLKemPkcs11` | `MLKem` |
| [FIPS 204 ML-DSA](ml-dsa.md) | Signatures | `MLDsaPkcs11` | `MLDsa` |
| [FIPS 205 SLH-DSA](slh-dsa.md) | Signatures (hash-based) | `SlhDsaPkcs11` | `SlhDsa` (`[Experimental]`, SYSLIB5006) |

They need a token that implements the PKCS#11 v3.2 mechanisms (`CKM_ML_KEM`, `CKM_ML_DSA`,
`CKM_SLH_DSA`). The BCL counterparts need a platform that supports them (`MLKem.IsSupported` and so on):
OpenSSL 3.5 or later on Linux, a recent Windows. No `Pkcs11Session` helper generates these keys yet, so
the examples build the templates; each names the parameter set and grants each half one role.
