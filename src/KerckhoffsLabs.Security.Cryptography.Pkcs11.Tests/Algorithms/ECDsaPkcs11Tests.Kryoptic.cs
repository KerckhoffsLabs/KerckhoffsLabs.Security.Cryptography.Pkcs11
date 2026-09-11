using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>ECDsaPkcs11 over Kryoptic — thin wrapper over <see cref="ECDsaPkcs11TestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class ECDsaPkcs11Tests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;
    public static bool KryopticAvailable => KryopticBackendFixture.KryopticAvailable;

    [ConditionalTheory(nameof(KryopticAvailable))]
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

    [ConditionalTheory(nameof(KryopticAvailable))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void TrySignData_Span_VerifyData_Span_RoundTrips(string curve) => ECDsaPkcs11TestCases.Assert_TrySignData_Span_VerifyData_Span_RoundTrips(_backend, curve);

    [ConditionalTheory(nameof(KryopticAvailable))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void ExportParameters_PublicOnly_FromPublicHandle_ReturnsPoint(string curve) => ECDsaPkcs11TestCases.Assert_ExportParameters_PublicOnly_FromPublicHandle_ReturnsPoint(_backend, curve);

    [ConditionalTheory(nameof(KryopticAvailable))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void SignData_VerifiesUnderBclFromExportedPublicKey(string curve) => ECDsaPkcs11TestCases.Assert_SignData_VerifiesUnderBclFromExportedPublicKey(_backend, curve);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Ctor_NonEcKey_Throws() => ECDsaPkcs11TestCases.Assert_Ctor_NonEcKey_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void TrySignData_DestinationTooSmall_ReturnsFalse() => ECDsaPkcs11TestCases.Assert_TrySignData_DestinationTooSmall_ReturnsFalse(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void SignHash_VerifyHash_RoundTrips() => ECDsaPkcs11TestCases.Assert_SignHash_VerifyHash_RoundTrips(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void SignHash_NullHash_Throws() => ECDsaPkcs11TestCases.Assert_SignHash_NullHash_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void VerifyHash_NullArguments_Throw() => ECDsaPkcs11TestCases.Assert_VerifyHash_NullArguments_Throw(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ExportParameters_Private_ThrowsInsecure() => ECDsaPkcs11TestCases.Assert_ExportParameters_Private_ThrowsInsecure(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ExportExplicitParameters_Throws() => ECDsaPkcs11TestCases.Assert_ExportExplicitParameters_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ImportParameters_Throws() => ECDsaPkcs11TestCases.Assert_ImportParameters_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void GenerateKey_Throws() => ECDsaPkcs11TestCases.Assert_GenerateKey_Throws(_backend);
}
