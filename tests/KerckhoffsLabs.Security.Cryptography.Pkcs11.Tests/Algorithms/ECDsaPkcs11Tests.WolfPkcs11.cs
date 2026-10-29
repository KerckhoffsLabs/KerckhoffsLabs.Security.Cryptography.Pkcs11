using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>ECDsaPkcs11 over wolfPKCS11 — thin wrapper over <see cref="ECDsaPkcs11TestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class ECDsaPkcs11Tests_WolfPkcs11(WolfPkcs11BackendFixture f)
{
    private readonly WolfPkcs11BackendFixture _backend = f;

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData("P-256", "SHA256")]
    [InlineData("P-256", "SHA384")]
    [InlineData("P-256", "SHA512")]
    [InlineData("P-384", "SHA256")]
    [InlineData("P-384", "SHA384")]
    [InlineData("P-384", "SHA512")]
    [InlineData("P-521", "SHA256")]
    [InlineData("P-521", "SHA384")]
    [InlineData("P-521", "SHA512")]
    public void SignVerifyData_CurveHashMatrix_RoundTrips(string curve, string hashName) => ECDsaPkcs11TestCases.Assert_SignVerifyData_CurveHashMatrix_RoundTrips(_backend, curve, hashName);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void TrySignData_Span_VerifyData_Span_RoundTrips(string curve) => ECDsaPkcs11TestCases.Assert_TrySignData_Span_VerifyData_Span_RoundTrips(_backend, curve);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void TrySignData_Sha224_UnderAllowInsecure_RoundTrips() => ECDsaPkcs11TestCases.Assert_TrySignData_Sha224_UnderAllowInsecure_RoundTrips(_backend, "P-256");

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void TrySignData_Sha224_WithoutAllowInsecure_Throws() => ECDsaPkcs11TestCases.Assert_TrySignData_Sha224_WithoutAllowInsecure_Throws(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void ExportParameters_PublicOnly_FromPublicHandle_ReturnsPoint(string curve) => ECDsaPkcs11TestCases.Assert_ExportParameters_PublicOnly_FromPublicHandle_ReturnsPoint(_backend, curve);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void SignData_VerifiesUnderBclFromExportedPublicKey(string curve) => ECDsaPkcs11TestCases.Assert_SignData_VerifiesUnderBclFromExportedPublicKey(_backend, curve);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData("SHA3-256")]
    [InlineData("SHA3-384")]
    [InlineData("SHA3-512")]
    public void Sha3_SignVerifyData_EveryOverload_RoundTrips(string hashName) => ECDsaPkcs11TestCases.Assert_Sha3_SignVerifyData_EveryOverload_RoundTrips(_backend, hashName);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Sha3_256_WycheproofVector_Verifies_AndTamperedDoesNot() => ECDsaPkcs11TestCases.Assert_Sha3_256_WycheproofVector_Verifies_AndTamperedDoesNot(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Ctor_NonEcKey_Throws() => ECDsaPkcs11TestCases.Assert_Ctor_NonEcKey_Throws(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void VerifyData_SignatureOfTheWrongLength_ReturnsFalse() => ECDsaPkcs11TestCases.Assert_VerifyData_SignatureOfTheWrongLength_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void TrySignData_DestinationTooSmall_ReturnsFalse() => ECDsaPkcs11TestCases.Assert_TrySignData_DestinationTooSmall_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void SignHash_VerifyHash_RoundTrips() => ECDsaPkcs11TestCases.Assert_SignHash_VerifyHash_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void SignHash_NullHash_Throws() => ECDsaPkcs11TestCases.Assert_SignHash_NullHash_Throws(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void VerifyHash_NullArguments_Throw() => ECDsaPkcs11TestCases.Assert_VerifyHash_NullArguments_Throw(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ExportParameters_Private_ThrowsInsecure() => ECDsaPkcs11TestCases.Assert_ExportParameters_Private_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ExportExplicitParameters_Throws() => ECDsaPkcs11TestCases.Assert_ExportExplicitParameters_Throws(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ImportParameters_Throws() => ECDsaPkcs11TestCases.Assert_ImportParameters_Throws(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void GenerateKey_Throws() => ECDsaPkcs11TestCases.Assert_GenerateKey_Throws(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void SignHash_VerifiesUnderBcl(string curve) => ECDsaPkcs11TestCases.Assert_SignHash_VerifiesUnderBcl(_backend, curve);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(ECDsaPkcs11TestCases.PointAtInfinityVectors), MemberType = typeof(ECDsaPkcs11TestCases))]
    public void VerifyData_PointAtInfinityVector_ReturnsFalse(int tcId, string publicKey, string signature)
        => ECDsaPkcs11TestCases.Assert_VerifyData_PointAtInfinityVector_ReturnsFalse(_backend, tcId, publicKey, signature);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData("secp224k1/352")]
    [InlineData("secp224k1/1")]
    [InlineData("secp160r1/351")]
    [InlineData("secp160r1/1")]
    public void VerifyHash_DerSignature_OrderLongerThanField_Verifies(string vector) => ECDsaPkcs11TestCases.Assert_VerifyHash_DerSignature_OrderLongerThanField_Verifies(_backend, vector);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData("secp224k1/352")]
    [InlineData("secp160r1/351")]
    public void VerifyHash_P1363_OrderLongerThanField_TakesTheOrdersLength(string vector) => ECDsaPkcs11TestCases.Assert_VerifyHash_P1363_OrderLongerThanField_TakesTheOrdersLength(_backend, vector);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void VerifyHash_DerZeroSignature_ReturnsFalse() => ECDsaPkcs11TestCases.Assert_VerifyHash_DerZeroSignature_ReturnsFalse(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData("secp224k1")]
    [InlineData("secp160r1")]
    public void SignHash_OrderLongerThanField_RoundTrips(string curve) => ECDsaPkcs11TestCases.Assert_SignHash_OrderLongerThanField_RoundTrips(_backend, curve);
}
