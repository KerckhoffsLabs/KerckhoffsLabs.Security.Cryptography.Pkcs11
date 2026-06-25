using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>DSAPkcs11 over OpenCryptoki — thin wrapper over <see cref="DSAPkcs11TestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class DSAPkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    [ConditionalTheory(nameof(Available))]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void SignVerifyData_AcrossHashAlgorithms_RoundTrips(string hashName) => DSAPkcs11TestCases.Assert_SignVerifyData_AcrossHashAlgorithms_RoundTrips(_backend, hashName);

    [ConditionalFact(nameof(Available))]
    public void Ctor_NonDsaKey_Throws() => DSAPkcs11TestCases.Assert_Ctor_NonDsaKey_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void SignVerifyData_RoundTrips() => DSAPkcs11TestCases.Assert_SignVerifyData_RoundTrips(_backend);

    [ConditionalFact(nameof(Available))]
    public void SignData_GatedByDefault_Throws() => DSAPkcs11TestCases.Assert_SignData_GatedByDefault_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void SignData_VerifiesUnderBclWithExportedPublicKey() => DSAPkcs11TestCases.Assert_SignData_VerifiesUnderBclWithExportedPublicKey(_backend);

    [ConditionalFact(nameof(Available))]
    public void CreateSignature_VerifySignature_OverHash_RoundTrips() => DSAPkcs11TestCases.Assert_CreateSignature_VerifySignature_OverHash_RoundTrips(_backend);

    [ConditionalFact(nameof(Available))]
    public void ExportParameters_ReturnsProvidedDomain() => DSAPkcs11TestCases.Assert_ExportParameters_ReturnsProvidedDomain(_backend);

    [ConditionalFact(nameof(Available))]
    public void ExportParameters_Private_ThrowsInsecure() => DSAPkcs11TestCases.Assert_ExportParameters_Private_ThrowsInsecure(_backend);

    [ConditionalFact(nameof(Available))]
    public void ImportParameters_NotSupported() => DSAPkcs11TestCases.Assert_ImportParameters_NotSupported(_backend);
}
