using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public sealed class Pkcs11MechanismMapTests
{
    [Theory]
    [InlineData("SHA1",   (ulong)CKM.CKM_SHA1_RSA_PKCS)]
    [InlineData("SHA256", (ulong)CKM.CKM_SHA256_RSA_PKCS)]
    [InlineData("SHA384", (ulong)CKM.CKM_SHA384_RSA_PKCS)]
    [InlineData("SHA512", (ulong)CKM.CKM_SHA512_RSA_PKCS)]
    public void RsaPkcs1_HashToCkm_ReturnsExpected(string hashName, ulong expectedCkm)
    {
        using var mech = Pkcs11MechanismMap.RsaPkcs1Sign(new HashAlgorithmName(hashName));
        Assert.Equal(expectedCkm, mech.Type);
    }

    [Theory]
    [InlineData("SHA1",   (ulong)CKM.CKM_SHA1_RSA_PKCS_PSS)]
    [InlineData("SHA256", (ulong)CKM.CKM_SHA256_RSA_PKCS_PSS)]
    [InlineData("SHA384", (ulong)CKM.CKM_SHA384_RSA_PKCS_PSS)]
    [InlineData("SHA512", (ulong)CKM.CKM_SHA512_RSA_PKCS_PSS)]
    public void RsaPss_HashToCkm_ReturnsExpectedWithParams(string hashName, ulong expectedCkm)
    {
        using var mech = Pkcs11MechanismMap.RsaPssSign(new HashAlgorithmName(hashName), saltLength: -1);
        Assert.Equal(expectedCkm, mech.Type);
    }

    [Theory]
    [InlineData("SHA1",   (ulong)CKM.CKM_ECDSA_SHA1)]
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
    public void RsaOaep_BuildsMechanismWithParams()
    {
        using var mech = Pkcs11MechanismMap.RsaOaep(HashAlgorithmName.SHA256);
        Assert.Equal((ulong)CKM.CKM_RSA_PKCS_OAEP, mech.Type);
    }

    [Fact]
    public void HmacHash_HashToCkm_ReturnsExpected()
    {
        using var mech = Pkcs11MechanismMap.HmacGeneral(HashAlgorithmName.SHA256);
        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, mech.Type);
    }
}
