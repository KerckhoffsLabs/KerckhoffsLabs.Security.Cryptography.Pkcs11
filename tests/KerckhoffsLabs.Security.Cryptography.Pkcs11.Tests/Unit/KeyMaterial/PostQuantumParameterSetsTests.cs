using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;

#pragma warning disable SYSLIB5006 // SLH-DSA is an evaluation-only BCL API.

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.KeyMaterial;

/// <summary>
/// Covers <see cref="PostQuantumParameterSets"/>: every FIPS 203/204/205 parameter set maps to its NIST
/// algorithm OID and to the public-key length the BCL reports, the OID maps back to its key type, and an
/// unknown parameter set, key type or OID gives <see langword="null"/>.
/// </summary>
public sealed class PostQuantumParameterSetsTests
{
    // The OIDs are spelled out here rather than read from Oids.PostQuantum, so a wrong constant fails.
    public static TheoryData<CKK, ulong, string, int> ParameterSets => new()
    {
        { CKK.CKK_ML_DSA, (ulong)CkpMlDsa.CKP_ML_DSA_44, "2.16.840.1.101.3.4.3.17", MLDsaAlgorithm.MLDsa44.PublicKeySizeInBytes },
        { CKK.CKK_ML_DSA, (ulong)CkpMlDsa.CKP_ML_DSA_65, "2.16.840.1.101.3.4.3.18", MLDsaAlgorithm.MLDsa65.PublicKeySizeInBytes },
        { CKK.CKK_ML_DSA, (ulong)CkpMlDsa.CKP_ML_DSA_87, "2.16.840.1.101.3.4.3.19", MLDsaAlgorithm.MLDsa87.PublicKeySizeInBytes },
        { CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_128S, "2.16.840.1.101.3.4.3.20", SlhDsaAlgorithm.SlhDsaSha2_128s.PublicKeySizeInBytes },
        { CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, "2.16.840.1.101.3.4.3.21", SlhDsaAlgorithm.SlhDsaSha2_128f.PublicKeySizeInBytes },
        { CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_192S, "2.16.840.1.101.3.4.3.22", SlhDsaAlgorithm.SlhDsaSha2_192s.PublicKeySizeInBytes },
        { CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_192F, "2.16.840.1.101.3.4.3.23", SlhDsaAlgorithm.SlhDsaSha2_192f.PublicKeySizeInBytes },
        { CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_256S, "2.16.840.1.101.3.4.3.24", SlhDsaAlgorithm.SlhDsaSha2_256s.PublicKeySizeInBytes },
        { CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_256F, "2.16.840.1.101.3.4.3.25", SlhDsaAlgorithm.SlhDsaSha2_256f.PublicKeySizeInBytes },
        { CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHAKE_128S, "2.16.840.1.101.3.4.3.26", SlhDsaAlgorithm.SlhDsaShake128s.PublicKeySizeInBytes },
        { CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHAKE_128F, "2.16.840.1.101.3.4.3.27", SlhDsaAlgorithm.SlhDsaShake128f.PublicKeySizeInBytes },
        { CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHAKE_192S, "2.16.840.1.101.3.4.3.28", SlhDsaAlgorithm.SlhDsaShake192s.PublicKeySizeInBytes },
        { CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHAKE_192F, "2.16.840.1.101.3.4.3.29", SlhDsaAlgorithm.SlhDsaShake192f.PublicKeySizeInBytes },
        { CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHAKE_256S, "2.16.840.1.101.3.4.3.30", SlhDsaAlgorithm.SlhDsaShake256s.PublicKeySizeInBytes },
        { CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHAKE_256F, "2.16.840.1.101.3.4.3.31", SlhDsaAlgorithm.SlhDsaShake256f.PublicKeySizeInBytes },
        { CKK.CKK_ML_KEM, (ulong)CkpMlKem.CKP_ML_KEM_512, "2.16.840.1.101.3.4.4.1", MLKemAlgorithm.MLKem512.EncapsulationKeySizeInBytes },
        { CKK.CKK_ML_KEM, (ulong)CkpMlKem.CKP_ML_KEM_768, "2.16.840.1.101.3.4.4.2", MLKemAlgorithm.MLKem768.EncapsulationKeySizeInBytes },
        { CKK.CKK_ML_KEM, (ulong)CkpMlKem.CKP_ML_KEM_1024, "2.16.840.1.101.3.4.4.3", MLKemAlgorithm.MLKem1024.EncapsulationKeySizeInBytes },
    };

    // Describe and KeyTypeOf are inverses: the OID a parameter set describes leads back to its key type.
    [Theory]
    [MemberData(nameof(ParameterSets))]
    public void Describe_KnownParameterSet_GivesItsOidAndTheBclPublicKeyLength(CKK keyType, ulong parameterSet, string oid, int publicKeyLength)
    {
        (string Oid, int PublicKeyLength) described = Assert.NotNull(PostQuantumParameterSets.Describe(keyType, parameterSet));

        Assert.Equal(oid, described.Oid);
        Assert.Equal(publicKeyLength, described.PublicKeyLength);
        Assert.Equal(keyType, PostQuantumParameterSets.KeyTypeOf(oid));
    }

    // Guards the table above: a CKP_ constant added to an enum but not to Describe fails here.
    [Fact]
    public void Describe_EveryDefinedParameterSet_IsKnown()
    {
        IEnumerable<(CKK KeyType, ulong Set)> all =
        [
            .. Enum.GetValues<CkpMlDsa>().Select(p => (CKK.CKK_ML_DSA, (ulong)p)),
            .. Enum.GetValues<CkpSlhDsa>().Select(p => (CKK.CKK_SLH_DSA, (ulong)p)),
            .. Enum.GetValues<CkpMlKem>().Select(p => (CKK.CKK_ML_KEM, (ulong)p)),
        ];

        Assert.All(all, p => Assert.True(PostQuantumParameterSets.Describe(p.KeyType, p.Set) is not null, $"{p.KeyType} {p.Set}"));
        Assert.Equal(ParameterSets.Count, all.Count());
    }

    // 0 is below every family's first set; the next value is past its last.
    [Theory]
    [InlineData(CKK.CKK_ML_DSA, 0UL)]
    [InlineData(CKK.CKK_ML_DSA, 4UL)]
    [InlineData(CKK.CKK_SLH_DSA, 0UL)]
    [InlineData(CKK.CKK_SLH_DSA, 13UL)]
    [InlineData(CKK.CKK_ML_KEM, 0UL)]
    [InlineData(CKK.CKK_ML_KEM, 4UL)]
    [InlineData(CKK.CKK_ML_KEM, ulong.MaxValue)]
    public void Describe_UnknownParameterSet_GivesNull(CKK keyType, ulong parameterSet)
        => Assert.Null(PostQuantumParameterSets.Describe(keyType, parameterSet));

    // A parameter set is only meaningful for the family it belongs to: CKP_ML_DSA_44 on an RSA or EC key is
    // not a post-quantum key at all.
    [Theory]
    [InlineData(CKK.CKK_RSA)]
    [InlineData(CKK.CKK_EC)]
    [InlineData(CKK.CKK_AES)]
    public void Describe_OtherKeyType_GivesNull(CKK keyType)
        => Assert.Null(PostQuantumParameterSets.Describe(keyType, (ulong)CkpMlDsa.CKP_ML_DSA_44));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("1.2.840.113549.1.1.1")] // rsaEncryption
    [InlineData("1.2.840.10045.2.1")] // id-ecPublicKey
    [InlineData("2.16.840.1.101.3.4.3.16")] // just below id-ml-dsa-44
    [InlineData("2.16.840.1.101.3.4.3.32")] // just past id-slh-dsa-shake-256f
    [InlineData("2.16.840.1.101.3.4.4.4")] // just past id-alg-ml-kem-1024
    [InlineData("2.16.840.1.101.3.4.3.17.0")]
    public void KeyTypeOf_OtherOid_GivesNull(string? oid)
        => Assert.Null(PostQuantumParameterSets.KeyTypeOf(oid));
}
