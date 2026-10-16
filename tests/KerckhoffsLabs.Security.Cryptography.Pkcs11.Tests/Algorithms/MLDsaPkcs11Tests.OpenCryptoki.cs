using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>MLDsaPkcs11 over OpenCryptoki — thin wrapper over <see cref="MLDsaPkcs11TestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class MLDsaPkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [InlineData(CkpMlDsa.CKP_ML_DSA_44)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_65)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_87)]
    public void SignVerifyData_RoundTrips(CkpMlDsa parameterSet) => MLDsaPkcs11TestCases.Assert_SignVerifyData_RoundTrips(_backend, parameterSet);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [InlineData(CkpMlDsa.CKP_ML_DSA_44)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_65)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_87)]
    public void SignData_VerifiesWithBcl(CkpMlDsa parameterSet) => MLDsaPkcs11TestCases.Assert_SignData_VerifiesWithBcl(_backend, parameterSet);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Ctor_NonMlDsaKey_Throws() => MLDsaPkcs11TestCases.Assert_Ctor_NonMlDsaKey_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void SignVerifyData_WithContext_RoundTrips() => MLDsaPkcs11TestCases.Assert_SignVerifyData_WithContext_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void SignData_ContextTooLong_Throws() => MLDsaPkcs11TestCases.Assert_SignData_ContextTooLong_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void SignMu_Throws() => MLDsaPkcs11TestCases.Assert_SignMu_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void VerifyMu_Throws() => MLDsaPkcs11TestCases.Assert_VerifyMu_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void ExportMLDsaPublicKey_ReturnsStandardEncoding() => MLDsaPkcs11TestCases.Assert_ExportMLDsaPublicKey_ReturnsStandardEncoding(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void ExportMLDsaPrivateKey_ThrowsInsecure() => MLDsaPkcs11TestCases.Assert_ExportMLDsaPrivateKey_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void ExportMLDsaPrivateSeed_ThrowsInsecure() => MLDsaPkcs11TestCases.Assert_ExportMLDsaPrivateSeed_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() => MLDsaPkcs11TestCases.Assert_ExportPkcs8PrivateKey_ThrowsInsecure(_backend);
}
