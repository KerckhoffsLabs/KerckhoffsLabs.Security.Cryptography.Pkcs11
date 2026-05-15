using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

public sealed class Pkcs11MechanismMapTests
{
    [Theory]
    [InlineData("SHA1", (ulong)CKM.CKM_SHA1_RSA_PKCS)]
    [InlineData("SHA256", (ulong)CKM.CKM_SHA256_RSA_PKCS)]
    [InlineData("SHA384", (ulong)CKM.CKM_SHA384_RSA_PKCS)]
    [InlineData("SHA512", (ulong)CKM.CKM_SHA512_RSA_PKCS)]
    public void RsaPkcs1_HashToCkm_ReturnsExpected(string hashName, ulong expectedCkm)
    {
        using var mech = Pkcs11MechanismMap.RsaPkcs1Sign(new HashAlgorithmName(hashName));
        Assert.Equal(expectedCkm, mech.Type);
    }

    [Theory]
    [InlineData("SHA1", (ulong)CKM.CKM_SHA1_RSA_PKCS_PSS)]
    [InlineData("SHA256", (ulong)CKM.CKM_SHA256_RSA_PKCS_PSS)]
    [InlineData("SHA384", (ulong)CKM.CKM_SHA384_RSA_PKCS_PSS)]
    [InlineData("SHA512", (ulong)CKM.CKM_SHA512_RSA_PKCS_PSS)]
    public void RsaPss_HashToCkm_ReturnsExpectedWithParams(string hashName, ulong expectedCkm)
    {
        using var mech = Pkcs11MechanismMap.RsaPssSign(new HashAlgorithmName(hashName), saltLength: -1);
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
        using var mech = Pkcs11MechanismMap.RsaPssSign(new HashAlgorithmName(hashName), saltLength: -1);
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
        using var mech = Pkcs11MechanismMap.RsaOaep(new HashAlgorithmName(hashName));
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
        using var mech = Pkcs11MechanismMap.EcdsaSign(new HashAlgorithmName(hashName));
        Assert.Equal(expectedCkm, mech.Type);
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
        using var mech = Pkcs11MechanismMap.Hmac(HashAlgorithmName.SHA256);
        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, mech.Type);
    }
}
