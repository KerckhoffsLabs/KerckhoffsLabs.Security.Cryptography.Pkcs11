using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

public sealed class Pkcs1DigestInfoTests
{
    // The DER DigestInfo prefixes (everything before the digest) the BCL's RsaPaddingProcessor signs with: the
    // NIST hash OID with NULL parameters, then the OCTET STRING header for the digest.
    [Theory]
    [InlineData("SHA3-256", CKM.CKM_SHA3_256_RSA_PKCS, 32, "3031300d060960864801650304020805000420")]
    [InlineData("SHA3-384", CKM.CKM_SHA3_384_RSA_PKCS, 48, "3041300d060960864801650304020905000430")]
    [InlineData("SHA3-512", CKM.CKM_SHA3_512_RSA_PKCS, 64, "3051300d060960864801650304020a05000440")]
    public void Encode_Sha3_MatchesTheBclDigestInfo(string hashName, CKM expectedScheme, int length, string expectedPrefix)
    {
        byte[] digest = RandomNumberGenerator.GetBytes(length);

        (CKM scheme, byte[] digestInfo) = Pkcs1DigestInfo.Encode(new HashAlgorithmName(hashName), digest);

        Assert.Equal(expectedScheme, scheme);
        Assert.Equal([.. Convert.FromHexString(expectedPrefix), .. digest], digestInfo);
    }

    [Theory]
    [InlineData("SHA3-256", 32)]
    [InlineData("SHA3-384", 48)]
    [InlineData("SHA3-512", 64)]
    public void Encode_Sha3_DigestOfTheWrongLength_Throws(string hashName, int length) =>
        Assert.Throws<CryptographicException>(() => Pkcs1DigestInfo.Encode(new HashAlgorithmName(hashName), new byte[length - 1]));
}
