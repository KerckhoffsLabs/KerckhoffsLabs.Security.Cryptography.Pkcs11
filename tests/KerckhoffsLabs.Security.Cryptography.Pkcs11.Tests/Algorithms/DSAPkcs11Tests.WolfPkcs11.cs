using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>DSAPkcs11 over wolfPKCS11 — thin wrapper over <see cref="DSAPkcs11TestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class DSAPkcs11Tests_WolfPkcs11(WolfPkcs11BackendFixture f)
{
    private readonly WolfPkcs11BackendFixture _backend = f;

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData("SHA224")]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void SignVerifyData_AcrossHashAlgorithms_RoundTrips(string hashName) => DSAPkcs11TestCases.Assert_SignVerifyData_AcrossHashAlgorithms_RoundTrips(_backend, hashName);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData("SHA224")]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void TrySignData_VerifyDataSpan_RoundTrips_AndRejectsTampering(string hashName) => DSAPkcs11TestCases.Assert_TrySignData_VerifyDataSpan_RoundTrips_AndRejectsTampering(_backend, hashName);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Ctor_NonDsaKey_Throws() => DSAPkcs11TestCases.Assert_Ctor_NonDsaKey_Throws(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void SignVerifyData_RoundTrips() => DSAPkcs11TestCases.Assert_SignVerifyData_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void SignData_GatedByDefault_Throws() => DSAPkcs11TestCases.Assert_SignData_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void SignData_VerifiesUnderBclWithExportedPublicKey() => DSAPkcs11TestCases.Assert_SignData_VerifiesUnderBclWithExportedPublicKey(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void CreateSignature_VerifySignature_OverHash_RoundTrips() => DSAPkcs11TestCases.Assert_CreateSignature_VerifySignature_OverHash_RoundTrips(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData(DSASignatureFormat.IeeeP1363FixedFieldConcatenation)]
    [InlineData(DSASignatureFormat.Rfc3279DerSequence)]
    public void VerifyWithSignatureFormat_AcceptsBothFormats_AndRejectsTampering(DSASignatureFormat format) => DSAPkcs11TestCases.Assert_VerifyWithSignatureFormat_AcceptsBothFormats_AndRejectsTampering(_backend, format);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void VerifyWithSignatureFormat_MalformedSignature_ReturnsFalse() => DSAPkcs11TestCases.Assert_VerifyWithSignatureFormat_MalformedSignature_ReturnsFalse(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData(DSASignatureFormat.IeeeP1363FixedFieldConcatenation)]
    [InlineData(DSASignatureFormat.Rfc3279DerSequence)]
    public void Sha224_EveryOverload_RoundTrips_AndRejectsTampering(DSASignatureFormat format) => DSAPkcs11TestCases.Assert_Sha224_EveryOverload_RoundTrips_AndRejectsTampering(_backend, format);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Sha224_WycheproofVector_Verifies_AndTamperedDoesNot() => DSAPkcs11TestCases.Assert_Sha224_WycheproofVector_Verifies_AndTamperedDoesNot(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ExportParameters_ReturnsProvidedDomain() => DSAPkcs11TestCases.Assert_ExportParameters_ReturnsProvidedDomain(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ExportParameters_Private_ThrowsInsecure() => DSAPkcs11TestCases.Assert_ExportParameters_Private_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ImportParameters_NotSupported() => DSAPkcs11TestCases.Assert_ImportParameters_NotSupported(_backend);
}
