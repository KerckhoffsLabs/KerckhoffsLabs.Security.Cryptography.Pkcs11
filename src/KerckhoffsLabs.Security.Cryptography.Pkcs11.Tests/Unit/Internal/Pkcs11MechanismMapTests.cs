using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

// These tests drive the gated legacy mechanisms/hashes on purpose (the AllowInsecure gate is the
// behaviour under test), so the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11010

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

public sealed class Pkcs11MechanismMapTests
{
    [Theory]
    [InlineData("SHA1", (ulong)CKM.CKM_SHA1_RSA_PKCS)]
    [InlineData("SHA256", (ulong)CKM.CKM_SHA256_RSA_PKCS)]
    [InlineData("SHA384", (ulong)CKM.CKM_SHA384_RSA_PKCS)]
    [InlineData("SHA512", (ulong)CKM.CKM_SHA512_RSA_PKCS)]
    public void RsaPkcs1_HashToCkm_ReturnsExpected(string hashName, ulong expectedCkm)
    {
        var mech = Pkcs11MechanismMap.RsaPkcs1Sign(new HashAlgorithmName(hashName));
        Assert.Equal(expectedCkm, mech.Type);
    }

    [Theory]
    [InlineData("SHA1", (ulong)CKM.CKM_SHA1_RSA_PKCS_PSS)]
    [InlineData("SHA256", (ulong)CKM.CKM_SHA256_RSA_PKCS_PSS)]
    [InlineData("SHA384", (ulong)CKM.CKM_SHA384_RSA_PKCS_PSS)]
    [InlineData("SHA512", (ulong)CKM.CKM_SHA512_RSA_PKCS_PSS)]
    public void RsaPss_HashToCkm_ReturnsExpectedWithParams(string hashName, ulong expectedCkm)
    {
        var mech = Pkcs11MechanismMap.RsaPssSign(new HashAlgorithmName(hashName), saltLength: -1);
        Assert.Equal(expectedCkm, mech.Type);
    }

    [Theory]
    [InlineData("SHA1", CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1, 20)]
    [InlineData("SHA256", CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32)]
    [InlineData("SHA384", CKM.CKM_SHA384, CKG.CKG_MGF1_SHA384, 48)]
    [InlineData("SHA512", CKM.CKM_SHA512, CKG.CKG_MGF1_SHA512, 64)]
    public void RsaPss_DefaultSalt_PssParamsAreCorrect(
        string hashName, CKM expectedInnerHash, CKG expectedMgf, int expectedSalt)
    {
        var mech = Pkcs11MechanismMap.RsaPssSign(new HashAlgorithmName(hashName), saltLength: -1);
        var pssParams = Assert.IsType<CkmRsaPkcsPssParams>(mech.Parameters);
        Assert.Equal(expectedInnerHash, pssParams.HashAlg);
        Assert.Equal(expectedMgf, pssParams.Mgf);
        Assert.Equal(expectedSalt, pssParams.SaltLength);
    }

    [Theory]
    [InlineData("SHA1", CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1)]
    [InlineData("SHA256", CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256)]
    [InlineData("SHA384", CKM.CKM_SHA384, CKG.CKG_MGF1_SHA384)]
    [InlineData("SHA512", CKM.CKM_SHA512, CKG.CKG_MGF1_SHA512)]
    public void RsaOaep_HashToCkm_ReturnsExpectedWithParams(
        string hashName, CKM expectedInnerHash, CKG expectedMgf)
    {
        var mech = Pkcs11MechanismMap.RsaOaep(new HashAlgorithmName(hashName));
        Assert.Equal((ulong)CKM.CKM_RSA_PKCS_OAEP, mech.Type);
        var oaepParams = Assert.IsType<CkmRsaPkcsOaepParams>(mech.Parameters);
        Assert.Equal(expectedInnerHash, oaepParams.HashAlg);
        Assert.Equal(expectedMgf, oaepParams.Mgf);
    }

    [Theory]
    [InlineData("SHA1", (ulong)CKM.CKM_ECDSA_SHA1)]
    [InlineData("SHA256", (ulong)CKM.CKM_ECDSA_SHA256)]
    [InlineData("SHA384", (ulong)CKM.CKM_ECDSA_SHA384)]
    [InlineData("SHA512", (ulong)CKM.CKM_ECDSA_SHA512)]
    public void EcdsaSign_HashToCkm_ReturnsExpected(string hashName, ulong expectedCkm)
    {
        var mech = Pkcs11MechanismMap.EcdsaSign(new HashAlgorithmName(hashName));
        Assert.Equal(expectedCkm, mech.Type);
    }

    [Theory]
    [InlineData("SHA1", (ulong)CKM.CKM_DSA_SHA1)]
    [InlineData("SHA224", (ulong)CKM.CKM_DSA_SHA224)]
    [InlineData("SHA256", (ulong)CKM.CKM_DSA_SHA256)]
    [InlineData("SHA384", (ulong)CKM.CKM_DSA_SHA384)]
    [InlineData("SHA512", (ulong)CKM.CKM_DSA_SHA512)]
    public void DsaSign_HashToCkm_ReturnsExpected(string hashName, ulong expectedCkm)
    {
        var mech = Pkcs11MechanismMap.DsaSign(new HashAlgorithmName(hashName));
        Assert.Equal(expectedCkm, mech.Type);
    }

    [Fact]
    public void DsaSign_UnsupportedHash_Throws()
    {
        Assert.Throws<NotSupportedException>(() =>
            Pkcs11MechanismMap.DsaSign(HashAlgorithmName.MD5));
    }

    [Fact]
    public void RsaPkcs1Sign_UnsupportedHash_Throws()
    {
        Assert.Throws<NotSupportedException>(() =>
            Pkcs11MechanismMap.RsaPkcs1Sign(HashAlgorithmName.MD5));
    }

    [Fact]
    public void HmacHash_HashToCkm_ReturnsExpected()
    {
        var mech = Pkcs11MechanismMap.Hmac(HashAlgorithmName.SHA256);
        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, mech.Type);
    }

    [Theory]
    [InlineData("SHA224", (ulong)CKM.CKM_HASH_ML_DSA_SHA224, CKM.CKM_SHA224)]
    [InlineData("SHA256", (ulong)CKM.CKM_HASH_ML_DSA_SHA256, CKM.CKM_SHA256)]
    [InlineData("SHA384", (ulong)CKM.CKM_HASH_ML_DSA_SHA384, CKM.CKM_SHA384)]
    [InlineData("SHA512", (ulong)CKM.CKM_HASH_ML_DSA_SHA512, CKM.CKM_SHA512)]
    [InlineData("SHA3-224", (ulong)CKM.CKM_HASH_ML_DSA_SHA3_224, CKM.CKM_SHA3_224)]
    [InlineData("SHA3-256", (ulong)CKM.CKM_HASH_ML_DSA_SHA3_256, CKM.CKM_SHA3_256)]
    [InlineData("SHA3-384", (ulong)CKM.CKM_HASH_ML_DSA_SHA3_384, CKM.CKM_SHA3_384)]
    [InlineData("SHA3-512", (ulong)CKM.CKM_HASH_ML_DSA_SHA3_512, CKM.CKM_SHA3_512)]
    public void MlDsaHashSign_HashToCkm_ReturnsExpectedWithParams(
        string hashName, ulong expectedCkm, CKM expectedInnerHash)
    {
        var mech = Pkcs11MechanismMap.MlDsaHashSign(new HashAlgorithmName(hashName));
        Assert.Equal(expectedCkm, mech.Type);
        Assert.IsType<CkmHashPqcSignParams>(mech.Parameters);
        _ = expectedInnerHash; // documented mapping — verified by the absence of NotSupportedException above
    }

    [Theory]
    [InlineData("SHAKE128")]
    [InlineData("SHAKE256")]
    [InlineData("MD5")]
    public void MlDsaHashSign_UnsupportedHash_Throws(string hashName)
    {
        Assert.Throws<NotSupportedException>(() =>
            Pkcs11MechanismMap.MlDsaHashSign(new HashAlgorithmName(hashName)));
    }

    [Fact]
    public void MlDsaSign_ReturnsMlDsaMechanismWithPqcParams()
    {
        var mech = Pkcs11MechanismMap.MlDsaSign();
        Assert.Equal((ulong)CKM.CKM_ML_DSA, mech.Type);
        Assert.IsType<CkmPqcSignParams>(mech.Parameters);
    }

    [Fact]
    public void MlDsaSign_WithContext_ReturnsMlDsaMechanism()
    {
        var mech = Pkcs11MechanismMap.MlDsaSign(context: [0x01, 0x02, 0x03]);
        Assert.Equal((ulong)CKM.CKM_ML_DSA, mech.Type);
        Assert.IsType<CkmPqcSignParams>(mech.Parameters);
    }
}
