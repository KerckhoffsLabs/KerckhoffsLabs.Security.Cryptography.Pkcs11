using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

public sealed class Pkcs1DigestInfoTests
{
    // The DER DigestInfo prefixes (everything before the digest) the BCL's RsaPaddingProcessor signs with: the
    // NIST hash OID with NULL parameters, then the OCTET STRING header for the digest. The SHA-1 and SHA-2 ones
    // are also the T values RFC 8017 §9.2 note 1 lists.
    [Theory]
    [InlineData("SHA1", CKM.CKM_SHA1_RSA_PKCS, 20, "3021300906052b0e03021a05000414")]
    [InlineData("SHA224", CKM.CKM_SHA224_RSA_PKCS, 28, "302d300d06096086480165030402040500041c")]
    [InlineData("SHA256", CKM.CKM_SHA256_RSA_PKCS, 32, "3031300d060960864801650304020105000420")]
    [InlineData("SHA384", CKM.CKM_SHA384_RSA_PKCS, 48, "3041300d060960864801650304020205000430")]
    [InlineData("SHA512", CKM.CKM_SHA512_RSA_PKCS, 64, "3051300d060960864801650304020305000440")]
    [InlineData("SHA3-256", CKM.CKM_SHA3_256_RSA_PKCS, 32, "3031300d060960864801650304020805000420")]
    [InlineData("SHA3-384", CKM.CKM_SHA3_384_RSA_PKCS, 48, "3041300d060960864801650304020905000430")]
    [InlineData("SHA3-512", CKM.CKM_SHA3_512_RSA_PKCS, 64, "3051300d060960864801650304020a05000440")]
    public void Encode_MatchesTheBclDigestInfo(string hashName, CKM expectedScheme, int length, string expectedPrefix)
    {
        byte[] digest = RandomNumberGenerator.GetBytes(length);

        (CKM scheme, byte[] digestInfo) = Pkcs1DigestInfo.Encode(new HashAlgorithmName(hashName), digest);

        Assert.Equal(expectedScheme, scheme);
        Assert.Equal([.. Convert.FromHexString(expectedPrefix), .. digest], digestInfo);
    }

    [Theory]
    [InlineData("SHA1", 20)]
    [InlineData("SHA224", 28)]
    [InlineData("SHA256", 32)]
    [InlineData("SHA384", 48)]
    [InlineData("SHA512", 64)]
    [InlineData("SHA3-256", 32)]
    [InlineData("SHA3-384", 48)]
    [InlineData("SHA3-512", 64)]
    public void Encode_DigestOfTheWrongLength_Throws(string hashName, int length)
    {
        var hash = new HashAlgorithmName(hashName);

        Assert.Throws<CryptographicException>(() => Pkcs1DigestInfo.Encode(hash, new byte[length - 1]));
        Assert.Throws<CryptographicException>(() => Pkcs1DigestInfo.Encode(hash, new byte[length + 1]));
        Assert.Throws<CryptographicException>(() => Pkcs1DigestInfo.Encode(hash, []));
    }

    // MD5 has a DigestInfo in RFC 8017 too, but is not signed. The hash is refused before the digest is looked
    // at, so the digest's length does not change the exception; a name is matched exactly, as the BCL does.
    [Theory]
    [InlineData("MD5", 16)]
    [InlineData("SHA512/256", 32)]
    [InlineData("sha256", 32)]
    [InlineData("", 32)]
    [InlineData("SHAKE256", 0)]
    public void Encode_UnsupportedHash_ThrowsNotSupported(string hashName, int length) =>
        Assert.Throws<NotSupportedException>(() => Pkcs1DigestInfo.Encode(new HashAlgorithmName(hashName), new byte[length]));

    [Fact]
    public void Encode_DefaultHashName_ThrowsNotSupported() =>
        Assert.Throws<NotSupportedException>(() => Pkcs1DigestInfo.Encode(default, new byte[32]));
}
