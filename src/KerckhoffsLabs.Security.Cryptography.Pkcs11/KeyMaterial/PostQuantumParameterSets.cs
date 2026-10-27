using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

// SlhDsaAlgorithm is an evaluation-only BCL type in .NET 10 (SYSLIB5006). Only its static parameter-set
// descriptors are read here, which need no platform SLH-DSA support.
#pragma warning disable SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;

/// <summary>
/// Per parameter set of the FIPS 203/204/205 key types: the <c>SubjectPublicKeyInfo</c> algorithm OID
/// (<see cref="Oids.PostQuantum"/>, with absent parameters), the BCL algorithm, and the public-key length.
/// </summary>
/// <remarks>
/// The lengths come from the BCL's descriptors (<see cref="MLDsaAlgorithm.PublicKeySizeInBytes"/>,
/// <see cref="SlhDsaAlgorithm.PublicKeySizeInBytes"/>, <see cref="MLKemAlgorithm.EncapsulationKeySizeInBytes"/>),
/// which are static and available whether or not the platform implements the algorithm.
/// </remarks>
internal static class PostQuantumParameterSets
{
    private sealed record ParameterSet(CKK KeyType, ulong Value, string Oid, object Algorithm, int PublicKeyLength);

    private static readonly ParameterSet[] All =
    [
        MLDsaSet(CkpMlDsa.CKP_ML_DSA_44, Oids.PostQuantum.MlDsa44, MLDsaAlgorithm.MLDsa44),
        MLDsaSet(CkpMlDsa.CKP_ML_DSA_65, Oids.PostQuantum.MlDsa65, MLDsaAlgorithm.MLDsa65),
        MLDsaSet(CkpMlDsa.CKP_ML_DSA_87, Oids.PostQuantum.MlDsa87, MLDsaAlgorithm.MLDsa87),
        SlhDsaSet(CkpSlhDsa.CKP_SLH_DSA_SHA2_128S, Oids.PostQuantum.SlhDsaSha2_128s, SlhDsaAlgorithm.SlhDsaSha2_128s),
        SlhDsaSet(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, Oids.PostQuantum.SlhDsaSha2_128f, SlhDsaAlgorithm.SlhDsaSha2_128f),
        SlhDsaSet(CkpSlhDsa.CKP_SLH_DSA_SHA2_192S, Oids.PostQuantum.SlhDsaSha2_192s, SlhDsaAlgorithm.SlhDsaSha2_192s),
        SlhDsaSet(CkpSlhDsa.CKP_SLH_DSA_SHA2_192F, Oids.PostQuantum.SlhDsaSha2_192f, SlhDsaAlgorithm.SlhDsaSha2_192f),
        SlhDsaSet(CkpSlhDsa.CKP_SLH_DSA_SHA2_256S, Oids.PostQuantum.SlhDsaSha2_256s, SlhDsaAlgorithm.SlhDsaSha2_256s),
        SlhDsaSet(CkpSlhDsa.CKP_SLH_DSA_SHA2_256F, Oids.PostQuantum.SlhDsaSha2_256f, SlhDsaAlgorithm.SlhDsaSha2_256f),
        SlhDsaSet(CkpSlhDsa.CKP_SLH_DSA_SHAKE_128S, Oids.PostQuantum.SlhDsaShake128s, SlhDsaAlgorithm.SlhDsaShake128s),
        SlhDsaSet(CkpSlhDsa.CKP_SLH_DSA_SHAKE_128F, Oids.PostQuantum.SlhDsaShake128f, SlhDsaAlgorithm.SlhDsaShake128f),
        SlhDsaSet(CkpSlhDsa.CKP_SLH_DSA_SHAKE_192S, Oids.PostQuantum.SlhDsaShake192s, SlhDsaAlgorithm.SlhDsaShake192s),
        SlhDsaSet(CkpSlhDsa.CKP_SLH_DSA_SHAKE_192F, Oids.PostQuantum.SlhDsaShake192f, SlhDsaAlgorithm.SlhDsaShake192f),
        SlhDsaSet(CkpSlhDsa.CKP_SLH_DSA_SHAKE_256S, Oids.PostQuantum.SlhDsaShake256s, SlhDsaAlgorithm.SlhDsaShake256s),
        SlhDsaSet(CkpSlhDsa.CKP_SLH_DSA_SHAKE_256F, Oids.PostQuantum.SlhDsaShake256f, SlhDsaAlgorithm.SlhDsaShake256f),
        MLKemSet(CkpMlKem.CKP_ML_KEM_512, Oids.PostQuantum.MlKem512, MLKemAlgorithm.MLKem512),
        MLKemSet(CkpMlKem.CKP_ML_KEM_768, Oids.PostQuantum.MlKem768, MLKemAlgorithm.MLKem768),
        MLKemSet(CkpMlKem.CKP_ML_KEM_1024, Oids.PostQuantum.MlKem1024, MLKemAlgorithm.MLKem1024),
    ];

    /// <summary>The OID and public-key length for <paramref name="parameterSet"/> of <paramref name="keyType"/>, or <see langword="null"/> when unrecognized.</summary>
    internal static (string Oid, int PublicKeyLength)? Describe(CKK keyType, ulong parameterSet)
        => Find(keyType, parameterSet) is { } set ? (set.Oid, set.PublicKeyLength) : null;

    /// <summary>The BCL algorithm for <paramref name="parameterSet"/> of <paramref name="keyType"/>, or <see langword="null"/> when unrecognized.</summary>
    /// <typeparam name="TAlgorithm"><see cref="MLDsaAlgorithm"/>, <see cref="SlhDsaAlgorithm"/> or <see cref="MLKemAlgorithm"/>, matching <paramref name="keyType"/>.</typeparam>
    internal static TAlgorithm? AlgorithmOf<TAlgorithm>(CKK keyType, ulong parameterSet) where TAlgorithm : class
        => Find(keyType, parameterSet)?.Algorithm as TAlgorithm;

    /// <summary>The key type whose parameter sets include the <c>SubjectPublicKeyInfo</c> algorithm <paramref name="oid"/>, or <see langword="null"/> when it is none of them.</summary>
    internal static CKK? KeyTypeOf(string? oid)
        => Array.Find(All, set => set.Oid == oid)?.KeyType;

    private static ParameterSet? Find(CKK keyType, ulong parameterSet)
        => Array.Find(All, set => set.KeyType == keyType && set.Value == parameterSet);

    private static ParameterSet MLDsaSet(CkpMlDsa set, string oid, MLDsaAlgorithm algorithm)
        => new(CKK.CKK_ML_DSA, (ulong)set, oid, algorithm, algorithm.PublicKeySizeInBytes);

    private static ParameterSet SlhDsaSet(CkpSlhDsa set, string oid, SlhDsaAlgorithm algorithm)
        => new(CKK.CKK_SLH_DSA, (ulong)set, oid, algorithm, algorithm.PublicKeySizeInBytes);

    private static ParameterSet MLKemSet(CkpMlKem set, string oid, MLKemAlgorithm algorithm)
        => new(CKK.CKK_ML_KEM, (ulong)set, oid, algorithm, algorithm.EncapsulationKeySizeInBytes);
}
