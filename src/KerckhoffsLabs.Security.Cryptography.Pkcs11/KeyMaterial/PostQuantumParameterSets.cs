using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;

/// <summary>
/// Per parameter set of the FIPS 203/204/205 key types: the <c>SubjectPublicKeyInfo</c> algorithm OID
/// (NIST CSOR, with absent parameters) and the public-key length.
/// </summary>
/// <remarks>
/// OIDs: ML-DSA <c>2.16.840.1.101.3.4.3.17–19</c> (RFC 9881), SLH-DSA <c>2.16.840.1.101.3.4.3.20–31</c>
/// (RFC 9909), ML-KEM <c>2.16.840.1.101.3.4.4.1–3</c>. Lengths: FIPS 204 Table 2, FIPS 205 Table 2
/// (2n bytes), FIPS 203 Table 3.
/// </remarks>
internal static class PostQuantumParameterSets
{
    /// <summary>The OID and public-key length for <paramref name="parameterSet"/> of <paramref name="keyType"/>, or <see langword="null"/> when unrecognized.</summary>
    internal static (string Oid, int PublicKeyLength)? Describe(CKK keyType, ulong parameterSet) => keyType switch
    {
        CKK.CKK_ML_DSA => (CkpMlDsa)parameterSet switch
        {
            CkpMlDsa.CKP_ML_DSA_44 => ("2.16.840.1.101.3.4.3.17", 1312),
            CkpMlDsa.CKP_ML_DSA_65 => ("2.16.840.1.101.3.4.3.18", 1952),
            CkpMlDsa.CKP_ML_DSA_87 => ("2.16.840.1.101.3.4.3.19", 2592),
            _ => null,
        },
        CKK.CKK_SLH_DSA => (CkpSlhDsa)parameterSet switch
        {
            CkpSlhDsa.CKP_SLH_DSA_SHA2_128S => ("2.16.840.1.101.3.4.3.20", 32),
            CkpSlhDsa.CKP_SLH_DSA_SHA2_128F => ("2.16.840.1.101.3.4.3.21", 32),
            CkpSlhDsa.CKP_SLH_DSA_SHA2_192S => ("2.16.840.1.101.3.4.3.22", 48),
            CkpSlhDsa.CKP_SLH_DSA_SHA2_192F => ("2.16.840.1.101.3.4.3.23", 48),
            CkpSlhDsa.CKP_SLH_DSA_SHA2_256S => ("2.16.840.1.101.3.4.3.24", 64),
            CkpSlhDsa.CKP_SLH_DSA_SHA2_256F => ("2.16.840.1.101.3.4.3.25", 64),
            CkpSlhDsa.CKP_SLH_DSA_SHAKE_128S => ("2.16.840.1.101.3.4.3.26", 32),
            CkpSlhDsa.CKP_SLH_DSA_SHAKE_128F => ("2.16.840.1.101.3.4.3.27", 32),
            CkpSlhDsa.CKP_SLH_DSA_SHAKE_192S => ("2.16.840.1.101.3.4.3.28", 48),
            CkpSlhDsa.CKP_SLH_DSA_SHAKE_192F => ("2.16.840.1.101.3.4.3.29", 48),
            CkpSlhDsa.CKP_SLH_DSA_SHAKE_256S => ("2.16.840.1.101.3.4.3.30", 64),
            CkpSlhDsa.CKP_SLH_DSA_SHAKE_256F => ("2.16.840.1.101.3.4.3.31", 64),
            _ => null,
        },
        CKK.CKK_ML_KEM => (CkpMlKem)parameterSet switch
        {
            CkpMlKem.CKP_ML_KEM_512 => ("2.16.840.1.101.3.4.4.1", 800),
            CkpMlKem.CKP_ML_KEM_768 => ("2.16.840.1.101.3.4.4.2", 1184),
            CkpMlKem.CKP_ML_KEM_1024 => ("2.16.840.1.101.3.4.4.3", 1568),
            _ => null,
        },
        _ => null,
    };
}
