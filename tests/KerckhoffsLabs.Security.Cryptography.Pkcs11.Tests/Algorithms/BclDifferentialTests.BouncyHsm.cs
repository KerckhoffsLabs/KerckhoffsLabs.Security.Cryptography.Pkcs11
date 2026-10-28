using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>The differential properties over BouncyHsm — thin wrapper over <see cref="BclDifferentialTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class BclDifferentialTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    // No empty message while the server refuses to digest one: see BouncyHsmBackendFixture.BouncyHsmAcceptsEmptyDigest.
    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Digest_MatchesBcl(string hashName) => BclDifferentialTestCases.Assert_Digest_MatchesBcl(_backend, hashName, emptyData: BouncyHsmBackendFixture.BouncyHsmAcceptsEmptyDigest);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Hmac_MatchesBcl(string hashName) => BclDifferentialTestCases.Assert_Hmac_MatchesBcl(_backend, hashName);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [InlineData(PaddingMode.None)]
    [InlineData(PaddingMode.PKCS7)]
    public void AesCbc_MatchesBcl(PaddingMode padding) => BclDifferentialTestCases.Assert_AesCbc_MatchesBcl(_backend, padding);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [InlineData(8)]
    [InlineData(128)]
    public void AesCfb_MatchesBcl(int feedbackSizeInBits) => BclDifferentialTestCases.Assert_AesCfb_MatchesBcl(_backend, feedbackSizeInBits);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesKeyWrapPadded_MatchesBcl() => BclDifferentialTestCases.Assert_AesKeyWrapPadded_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesGcm_MatchesBcl() => BclDifferentialTestCases.Assert_AesGcm_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesCcm_MatchesBcl() => BclDifferentialTestCases.Assert_AesCcm_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ChaCha20Poly1305_MatchesBcl() => BclDifferentialTestCases.Assert_ChaCha20Poly1305_MatchesBcl(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Hkdf_MatchesBcl(string hashName) => BclDifferentialTestCases.Assert_Hkdf_MatchesBcl(_backend, hashName);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Sp800108HmacCounter_MatchesBcl(string hashName) => BclDifferentialTestCases.Assert_Sp800108HmacCounter_MatchesBcl(_backend, hashName);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Pbkdf2_MatchesBcl(string hashName) => BclDifferentialTestCases.Assert_Pbkdf2_MatchesBcl(_backend, hashName);

    // No empty message: the server refuses to sign one with RSA (C_Sign gives CKR_DATA_LEN_RANGE).
    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.RsaSignatureSchemes), MemberType = typeof(PropertyTestSupport))]
    public void RsaSignData_VerifiesWithBcl(string padding, string hashName) => BclDifferentialTestCases.Assert_RsaSignData_VerifiesWithBcl(_backend, padding, hashName, emptyData: false);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void RsaOaep_DecryptsBclCiphertext(string hashName) => BclDifferentialTestCases.Assert_RsaOaep_DecryptsBclCiphertext(_backend, hashName);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.CurvesAndSignatureFormats), MemberType = typeof(PropertyTestSupport))]
    public void EcdsaSignData_VerifiesWithBcl(string curve, DSASignatureFormat format) => BclDifferentialTestCases.Assert_EcdsaSignData_VerifiesWithBcl(_backend, curve, format);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.Curves), MemberType = typeof(PropertyTestSupport))]
    public void Ecdh_AgreesWithBcl(string curve) => BclDifferentialTestCases.Assert_Ecdh_AgreesWithBcl(_backend, curve);

    // No empty message: the server refuses to sign one with ML-DSA (C_Sign gives CKR_DATA_LEN_RANGE).
    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.MlDsaParameterSets), MemberType = typeof(PropertyTestSupport))]
    public void MlDsaSignData_VerifiesWithBcl(CkpMlDsa parameterSet) => BclDifferentialTestCases.Assert_MlDsaSignData_VerifiesWithBcl(_backend, parameterSet, emptyData: false);

    // No empty message: the server refuses to sign one with SLH-DSA (C_Sign gives CKR_DATA_LEN_RANGE).
    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SlhDsaSignData_VerifiesWithBcl() => BclDifferentialTestCases.Assert_SlhDsaSignData_VerifiesWithBcl(_backend, emptyData: false);
}
