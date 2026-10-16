using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>DSAPkcs11 over SoftHsm — thin wrapper over <see cref="DSAPkcs11TestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class DSAPkcs11Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    // SHA-224 is deliberately absent here: DSA.SignData(byte[], HashAlgorithmName) is a non-virtual
    // BCL convenience overload that hashes internally via CryptographicOperations.HashData before ever
    // reaching DSAPkcs11's override, and the BCL itself has no SHA-224 support -- so this entry point
    // can never work with SHA224 on any backend, regardless of what the token supports. See
    // TrySignData_VerifyDataSpan_RoundTrips_AndRejectsTampering below, which calls DSAPkcs11's own
    // virtual TrySignData/VerifyData overrides directly and does exercise SHA224 (SoftHSM's
    // SoftHSM.cpp dispatches CKM_DSA_SHA224 to a real AsymMech::DSA_SHA224 sign/verify implementation,
    // so DSAPkcs11.SignDataInternal/VerifyData's SupportsMechanism check takes the combined on-token
    // path here, never reaching the managed-fallback HashData that has no SHA224 case).
    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void SignVerifyData_AcrossHashAlgorithms_RoundTrips(string hashName) => DSAPkcs11TestCases.Assert_SignVerifyData_AcrossHashAlgorithms_RoundTrips(_backend, hashName);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [InlineData("SHA224")]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void TrySignData_VerifyDataSpan_RoundTrips_AndRejectsTampering(string hashName) => DSAPkcs11TestCases.Assert_TrySignData_VerifyDataSpan_RoundTrips_AndRejectsTampering(_backend, hashName);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Ctor_NonDsaKey_Throws() => DSAPkcs11TestCases.Assert_Ctor_NonDsaKey_Throws(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void SignVerifyData_RoundTrips() => DSAPkcs11TestCases.Assert_SignVerifyData_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void SignData_GatedByDefault_Throws() => DSAPkcs11TestCases.Assert_SignData_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void SignData_VerifiesUnderBclWithExportedPublicKey() => DSAPkcs11TestCases.Assert_SignData_VerifiesUnderBclWithExportedPublicKey(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void CreateSignature_VerifySignature_OverHash_RoundTrips() => DSAPkcs11TestCases.Assert_CreateSignature_VerifySignature_OverHash_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ExportParameters_ReturnsProvidedDomain() => DSAPkcs11TestCases.Assert_ExportParameters_ReturnsProvidedDomain(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ExportParameters_Private_ThrowsInsecure() => DSAPkcs11TestCases.Assert_ExportParameters_Private_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ImportParameters_NotSupported() => DSAPkcs11TestCases.Assert_ImportParameters_NotSupported(_backend);
}
