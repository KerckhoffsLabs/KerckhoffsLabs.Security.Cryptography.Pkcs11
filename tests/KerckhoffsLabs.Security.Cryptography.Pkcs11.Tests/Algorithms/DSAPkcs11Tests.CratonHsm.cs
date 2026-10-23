using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>DSAPkcs11 over Craton HSM — thin wrapper over <see cref="DSAPkcs11TestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class DSAPkcs11Tests_CratonHsm(CratonHsmBackendFixture f)
{
    private readonly CratonHsmBackendFixture _backend = f;

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void SignVerifyData_AcrossHashAlgorithms_RoundTrips(string hashName) => DSAPkcs11TestCases.Assert_SignVerifyData_AcrossHashAlgorithms_RoundTrips(_backend, hashName);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void TrySignData_VerifyDataSpan_RoundTrips_AndRejectsTampering(string hashName) => DSAPkcs11TestCases.Assert_TrySignData_VerifyDataSpan_RoundTrips_AndRejectsTampering(_backend, hashName);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Ctor_NonDsaKey_Throws() => DSAPkcs11TestCases.Assert_Ctor_NonDsaKey_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void SignVerifyData_RoundTrips() => DSAPkcs11TestCases.Assert_SignVerifyData_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void SignData_GatedByDefault_Throws() => DSAPkcs11TestCases.Assert_SignData_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void SignData_VerifiesUnderBclWithExportedPublicKey() => DSAPkcs11TestCases.Assert_SignData_VerifiesUnderBclWithExportedPublicKey(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void CreateSignature_VerifySignature_OverHash_RoundTrips() => DSAPkcs11TestCases.Assert_CreateSignature_VerifySignature_OverHash_RoundTrips(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [InlineData(DSASignatureFormat.IeeeP1363FixedFieldConcatenation)]
    [InlineData(DSASignatureFormat.Rfc3279DerSequence)]
    public void VerifyWithSignatureFormat_AcceptsBothFormats_AndRejectsTampering(DSASignatureFormat format) => DSAPkcs11TestCases.Assert_VerifyWithSignatureFormat_AcceptsBothFormats_AndRejectsTampering(_backend, format);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void VerifyWithSignatureFormat_MalformedSignature_ReturnsFalse() => DSAPkcs11TestCases.Assert_VerifyWithSignatureFormat_MalformedSignature_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ExportParameters_ReturnsProvidedDomain() => DSAPkcs11TestCases.Assert_ExportParameters_ReturnsProvidedDomain(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ExportParameters_Private_ThrowsInsecure() => DSAPkcs11TestCases.Assert_ExportParameters_Private_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ImportParameters_NotSupported() => DSAPkcs11TestCases.Assert_ImportParameters_NotSupported(_backend);
}
