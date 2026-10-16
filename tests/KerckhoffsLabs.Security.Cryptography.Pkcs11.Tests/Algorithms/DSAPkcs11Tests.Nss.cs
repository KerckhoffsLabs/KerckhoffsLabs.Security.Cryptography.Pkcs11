using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>DSAPkcs11 over NSS — thin wrapper over <see cref="DSAPkcs11TestCases"/>.</summary>
[Collection("Nss")]
public sealed class DSAPkcs11Tests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    // SHA-224 is deliberately absent here: DSA.SignData(byte[], HashAlgorithmName) is a non-virtual
    // BCL convenience overload that hashes internally via CryptographicOperations.HashData before ever
    // reaching DSAPkcs11's override, and the BCL itself has no SHA-224 support -- so this entry point
    // can never work with SHA224 on any backend, regardless of what the token supports. See
    // TrySignData_VerifyDataSpan_RoundTrips_AndRejectsTampering below, which calls DSAPkcs11's own
    // virtual TrySignData/VerifyData overrides directly and does exercise SHA224 (NSS's pkcs11.c
    // registers CKM_DSA_SHA224 in its real mechanism-info table -- unlike Kryoptic, whose only
    // "support" is a debug name<->constant lookup table with no dsa.rs behind it -- so
    // DSAPkcs11.SignDataInternal/VerifyData's SupportsMechanism check takes the combined on-token path
    // here, never reaching the managed-fallback HashData that has no SHA224 case).
    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void SignVerifyData_AcrossHashAlgorithms_RoundTrips(string hashName) => DSAPkcs11TestCases.Assert_SignVerifyData_AcrossHashAlgorithms_RoundTrips(_backend, hashName);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [InlineData("SHA224")]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void TrySignData_VerifyDataSpan_RoundTrips_AndRejectsTampering(string hashName) => DSAPkcs11TestCases.Assert_TrySignData_VerifyDataSpan_RoundTrips_AndRejectsTampering(_backend, hashName);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Ctor_NonDsaKey_Throws() => DSAPkcs11TestCases.Assert_Ctor_NonDsaKey_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void SignVerifyData_RoundTrips() => DSAPkcs11TestCases.Assert_SignVerifyData_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void SignData_GatedByDefault_Throws() => DSAPkcs11TestCases.Assert_SignData_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void SignData_VerifiesUnderBclWithExportedPublicKey() => DSAPkcs11TestCases.Assert_SignData_VerifiesUnderBclWithExportedPublicKey(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void CreateSignature_VerifySignature_OverHash_RoundTrips() => DSAPkcs11TestCases.Assert_CreateSignature_VerifySignature_OverHash_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ExportParameters_ReturnsProvidedDomain() => DSAPkcs11TestCases.Assert_ExportParameters_ReturnsProvidedDomain(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ExportParameters_Private_ThrowsInsecure() => DSAPkcs11TestCases.Assert_ExportParameters_Private_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ImportParameters_NotSupported() => DSAPkcs11TestCases.Assert_ImportParameters_NotSupported(_backend);
}
