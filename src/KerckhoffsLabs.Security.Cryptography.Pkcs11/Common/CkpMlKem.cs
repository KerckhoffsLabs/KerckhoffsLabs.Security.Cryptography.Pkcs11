namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// ML-KEM parameter-set identifier (FIPS 203 / PKCS#11 v3.2). Used as the value of the
/// <see cref="CKA.CKA_PARAMETER_SET"/> attribute on ML-KEM keys.
/// </summary>
public enum CkpMlKem : uint
{
    /// <summary>ML-KEM-512: NIST security level 1; public key 800 B, ciphertext 768 B.</summary>
    CKP_ML_KEM_512 = 0x00000001,

    /// <summary>ML-KEM-768: NIST security level 3; public key 1184 B, ciphertext 1088 B.</summary>
    CKP_ML_KEM_768 = 0x00000002,

    /// <summary>ML-KEM-1024: NIST security level 5; public key 1568 B, ciphertext 1568 B.</summary>
    CKP_ML_KEM_1024 = 0x00000003,
}
