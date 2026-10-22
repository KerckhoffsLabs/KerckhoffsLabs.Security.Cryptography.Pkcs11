using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;

/// <summary>
/// Per parameter set of the FIPS 203/204/205 key types: the <c>SubjectPublicKeyInfo</c> algorithm OID
/// (<see cref="Oids.PostQuantum"/>, with absent parameters) and the public-key length.
/// </summary>
/// <remarks>Lengths: FIPS 204 Table 2, FIPS 205 Table 2 (2n bytes), FIPS 203 Table 3.</remarks>
internal static class PostQuantumParameterSets
{
    /// <summary>The OID and public-key length for <paramref name="parameterSet"/> of <paramref name="keyType"/>, or <see langword="null"/> when unrecognized.</summary>
    internal static (string Oid, int PublicKeyLength)? Describe(CKK keyType, ulong parameterSet) => keyType switch
    {
        CKK.CKK_ML_DSA => (CkpMlDsa)parameterSet switch
        {
            CkpMlDsa.CKP_ML_DSA_44 => (Oids.PostQuantum.MlDsa44, 1312),
            CkpMlDsa.CKP_ML_DSA_65 => (Oids.PostQuantum.MlDsa65, 1952),
            CkpMlDsa.CKP_ML_DSA_87 => (Oids.PostQuantum.MlDsa87, 2592),
            _ => null,
        },
        CKK.CKK_SLH_DSA => (CkpSlhDsa)parameterSet switch
        {
            CkpSlhDsa.CKP_SLH_DSA_SHA2_128S => (Oids.PostQuantum.SlhDsaSha2_128s, 32),
            CkpSlhDsa.CKP_SLH_DSA_SHA2_128F => (Oids.PostQuantum.SlhDsaSha2_128f, 32),
            CkpSlhDsa.CKP_SLH_DSA_SHA2_192S => (Oids.PostQuantum.SlhDsaSha2_192s, 48),
            CkpSlhDsa.CKP_SLH_DSA_SHA2_192F => (Oids.PostQuantum.SlhDsaSha2_192f, 48),
            CkpSlhDsa.CKP_SLH_DSA_SHA2_256S => (Oids.PostQuantum.SlhDsaSha2_256s, 64),
            CkpSlhDsa.CKP_SLH_DSA_SHA2_256F => (Oids.PostQuantum.SlhDsaSha2_256f, 64),
            CkpSlhDsa.CKP_SLH_DSA_SHAKE_128S => (Oids.PostQuantum.SlhDsaShake128s, 32),
            CkpSlhDsa.CKP_SLH_DSA_SHAKE_128F => (Oids.PostQuantum.SlhDsaShake128f, 32),
            CkpSlhDsa.CKP_SLH_DSA_SHAKE_192S => (Oids.PostQuantum.SlhDsaShake192s, 48),
            CkpSlhDsa.CKP_SLH_DSA_SHAKE_192F => (Oids.PostQuantum.SlhDsaShake192f, 48),
            CkpSlhDsa.CKP_SLH_DSA_SHAKE_256S => (Oids.PostQuantum.SlhDsaShake256s, 64),
            CkpSlhDsa.CKP_SLH_DSA_SHAKE_256F => (Oids.PostQuantum.SlhDsaShake256f, 64),
            _ => null,
        },
        CKK.CKK_ML_KEM => (CkpMlKem)parameterSet switch
        {
            CkpMlKem.CKP_ML_KEM_512 => (Oids.PostQuantum.MlKem512, 800),
            CkpMlKem.CKP_ML_KEM_768 => (Oids.PostQuantum.MlKem768, 1184),
            CkpMlKem.CKP_ML_KEM_1024 => (Oids.PostQuantum.MlKem1024, 1568),
            _ => null,
        },
        _ => null,
    };

    /// <summary>The key type whose parameter sets include the <c>SubjectPublicKeyInfo</c> algorithm <paramref name="oid"/>, or <see langword="null"/> when it is none of them.</summary>
    internal static CKK? KeyTypeOf(string? oid) => oid switch
    {
        Oids.PostQuantum.MlDsa44 or Oids.PostQuantum.MlDsa65 or Oids.PostQuantum.MlDsa87 => CKK.CKK_ML_DSA,
        Oids.PostQuantum.SlhDsaSha2_128s or Oids.PostQuantum.SlhDsaSha2_128f
            or Oids.PostQuantum.SlhDsaSha2_192s or Oids.PostQuantum.SlhDsaSha2_192f
            or Oids.PostQuantum.SlhDsaSha2_256s or Oids.PostQuantum.SlhDsaSha2_256f
            or Oids.PostQuantum.SlhDsaShake128s or Oids.PostQuantum.SlhDsaShake128f
            or Oids.PostQuantum.SlhDsaShake192s or Oids.PostQuantum.SlhDsaShake192f
            or Oids.PostQuantum.SlhDsaShake256s or Oids.PostQuantum.SlhDsaShake256f => CKK.CKK_SLH_DSA,
        Oids.PostQuantum.MlKem512 or Oids.PostQuantum.MlKem768 or Oids.PostQuantum.MlKem1024 => CKK.CKK_ML_KEM,
        _ => null,
    };
}
