using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>ECDsaPkcs11 over BouncyHsm — thin wrapper over <see cref="ECDsaPkcs11TestCases"/>.
/// The curve-parameterized cases run at P-256, as on Kryoptic and opencryptoki; SoftHSM's wrapper covers P-384 and P-521.</summary>
[Collection("BouncyHsm")]
public sealed class ECDsaPkcs11Tests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [InlineData("P-256", "SHA256")]
    [InlineData("P-256", "SHA384")]
    [InlineData("P-256", "SHA512")]
    public void SignVerifyData_CurveHashMatrix_RoundTrips(string curve, string hashName) => ECDsaPkcs11TestCases.Assert_SignVerifyData_CurveHashMatrix_RoundTrips(_backend, curve, hashName);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void TrySignData_Span_VerifyData_Span_RoundTrips() => ECDsaPkcs11TestCases.Assert_TrySignData_Span_VerifyData_Span_RoundTrips(_backend, "P-256");

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ExportParameters_PublicOnly_FromPublicHandle_ReturnsPoint() => ECDsaPkcs11TestCases.Assert_ExportParameters_PublicOnly_FromPublicHandle_ReturnsPoint(_backend, "P-256");

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SignData_VerifiesUnderBclFromExportedPublicKey() => ECDsaPkcs11TestCases.Assert_SignData_VerifiesUnderBclFromExportedPublicKey(_backend, "P-256");

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Ctor_NonEcKey_Throws() => ECDsaPkcs11TestCases.Assert_Ctor_NonEcKey_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void VerifyData_SignatureOfTheWrongLength_ReturnsFalse() => ECDsaPkcs11TestCases.Assert_VerifyData_SignatureOfTheWrongLength_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void TrySignData_DestinationTooSmall_ReturnsFalse() => ECDsaPkcs11TestCases.Assert_TrySignData_DestinationTooSmall_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SignHash_VerifyHash_RoundTrips() => ECDsaPkcs11TestCases.Assert_SignHash_VerifyHash_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SignHash_NullHash_Throws() => ECDsaPkcs11TestCases.Assert_SignHash_NullHash_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void VerifyHash_NullArguments_Throw() => ECDsaPkcs11TestCases.Assert_VerifyHash_NullArguments_Throw(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ExportParameters_Private_ThrowsInsecure() => ECDsaPkcs11TestCases.Assert_ExportParameters_Private_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ExportExplicitParameters_Throws() => ECDsaPkcs11TestCases.Assert_ExportExplicitParameters_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ImportParameters_Throws() => ECDsaPkcs11TestCases.Assert_ImportParameters_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void GenerateKey_Throws() => ECDsaPkcs11TestCases.Assert_GenerateKey_Throws(_backend);

    // secp160r1 and secp224k1, whose group order is one bit longer than the field; not every backend
    // implements them.
    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [InlineData("secp224k1/352")]
    [InlineData("secp224k1/1")]
    [InlineData("secp160r1/351")]
    [InlineData("secp160r1/1")]
    public void VerifyHash_DerSignature_OrderLongerThanField_Verifies(string vector) => ECDsaPkcs11TestCases.Assert_VerifyHash_DerSignature_OrderLongerThanField_Verifies(_backend, vector);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void VerifyHash_DerZeroSignature_ReturnsFalse() => ECDsaPkcs11TestCases.Assert_VerifyHash_DerZeroSignature_ReturnsFalse(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [InlineData("secp224k1")]
    [InlineData("secp160r1")]
    public void SignHash_OrderLongerThanField_RoundTrips(string curve) => ECDsaPkcs11TestCases.Assert_SignHash_OrderLongerThanField_RoundTrips(_backend, curve);
}
