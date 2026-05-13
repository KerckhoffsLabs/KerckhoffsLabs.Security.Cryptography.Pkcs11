namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// ML-DSA parameter-set identifier (FIPS 204 / PKCS#11 v3.2). Used as the value of the
/// <see cref="CKA.CKA_PARAMETER_SET"/> attribute on ML-DSA keys.
/// </summary>
/// <remarks>
/// The numeric values share their namespace with other CKP_* enums (e.g.
/// <see cref="CkpMlKem"/>, <see cref="CkpSlhDsa"/>) — disambiguation is by the
/// owning CKK key type and the attribute context.
/// </remarks>
public enum CkpMlDsa : uint
{
    /// <summary>ML-DSA-44: NIST security level 2; public key 1312 B, signature 2420 B.</summary>
    CKP_ML_DSA_44 = 0x00000001,

    /// <summary>ML-DSA-65: NIST security level 3; public key 1952 B, signature 3309 B.</summary>
    CKP_ML_DSA_65 = 0x00000002,

    /// <summary>ML-DSA-87: NIST security level 5; public key 2592 B, signature 4627 B.</summary>
    CKP_ML_DSA_87 = 0x00000003,
}
