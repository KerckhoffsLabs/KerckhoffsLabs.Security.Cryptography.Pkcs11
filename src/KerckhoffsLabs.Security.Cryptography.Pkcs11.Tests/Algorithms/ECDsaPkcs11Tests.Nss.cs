using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>ECDsaPkcs11 over opencryptoki — thin wrapper over <see cref="ECDsaPkcs11TestCases"/>.
/// opencryptoki's software token implements P-256 here, so the curve-parameterized cases run at P-256.</summary>
[Collection("Nss")]
public sealed class ECDsaPkcs11Tests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;
    public static bool Available => NssBackendFixture.NssAvailable;

    [ConditionalTheory(nameof(Available))]
    [InlineData("P-256", "SHA256")]
    [InlineData("P-256", "SHA384")]
    [InlineData("P-256", "SHA512")]
    public void SignVerifyData_CurveHashMatrix_RoundTrips(string curve, string hashName) => ECDsaPkcs11TestCases.Assert_SignVerifyData_CurveHashMatrix_RoundTrips(_backend, curve, hashName);

    [ConditionalFact(nameof(Available))]
    public void TrySignData_Span_VerifyData_Span_RoundTrips() => ECDsaPkcs11TestCases.Assert_TrySignData_Span_VerifyData_Span_RoundTrips(_backend, "P-256");

    [ConditionalFact(nameof(Available))]
    public void ExportParameters_PublicOnly_FromPublicHandle_ReturnsPoint() => ECDsaPkcs11TestCases.Assert_ExportParameters_PublicOnly_FromPublicHandle_ReturnsPoint(_backend, "P-256");

    [ConditionalFact(nameof(Available))]
    public void SignData_VerifiesUnderBclFromExportedPublicKey() => ECDsaPkcs11TestCases.Assert_SignData_VerifiesUnderBclFromExportedPublicKey(_backend, "P-256");

    [ConditionalFact(nameof(Available))]
    public void Ctor_NonEcKey_Throws() => ECDsaPkcs11TestCases.Assert_Ctor_NonEcKey_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void TrySignData_DestinationTooSmall_ReturnsFalse() => ECDsaPkcs11TestCases.Assert_TrySignData_DestinationTooSmall_ReturnsFalse(_backend);

    [ConditionalFact(nameof(Available))]
    public void SignHash_VerifyHash_RoundTrips() => ECDsaPkcs11TestCases.Assert_SignHash_VerifyHash_RoundTrips(_backend);

    [ConditionalFact(nameof(Available))]
    public void SignHash_NullHash_Throws() => ECDsaPkcs11TestCases.Assert_SignHash_NullHash_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void VerifyHash_NullArguments_Throw() => ECDsaPkcs11TestCases.Assert_VerifyHash_NullArguments_Throw(_backend);

    [ConditionalFact(nameof(Available))]
    public void ExportParameters_Private_ThrowsInsecure() => ECDsaPkcs11TestCases.Assert_ExportParameters_Private_ThrowsInsecure(_backend);

    [ConditionalFact(nameof(Available))]
    public void ExportExplicitParameters_Throws() => ECDsaPkcs11TestCases.Assert_ExportExplicitParameters_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void ImportParameters_Throws() => ECDsaPkcs11TestCases.Assert_ImportParameters_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void GenerateKey_Throws() => ECDsaPkcs11TestCases.Assert_GenerateKey_Throws(_backend);
}
