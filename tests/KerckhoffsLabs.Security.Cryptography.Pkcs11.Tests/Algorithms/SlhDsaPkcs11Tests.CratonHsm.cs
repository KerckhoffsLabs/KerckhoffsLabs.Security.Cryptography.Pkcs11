using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SlhDsaPkcs11 over Craton HSM — thin wrapper over <see cref="SlhDsaPkcs11TestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class SlhDsaPkcs11Tests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_128S)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHAKE_128S)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHAKE_128F)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_192S)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHAKE_192S)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_192F)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHAKE_192F)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_256S)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHAKE_256S)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_256F)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHAKE_256F)]
    public void SignVerifyData_RoundTrips(CkpSlhDsa parameterSet) => SlhDsaPkcs11TestCases.Assert_SignVerifyData_RoundTrips(_backend, parameterSet);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Ctor_NonSlhDsaKey_Throws() => SlhDsaPkcs11TestCases.Assert_Ctor_NonSlhDsaKey_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void SignVerifyData_WithContext_RoundTrips() => SlhDsaPkcs11TestCases.Assert_SignVerifyData_WithContext_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void SignData_ContextTooLong_Throws() => SlhDsaPkcs11TestCases.Assert_SignData_ContextTooLong_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ExportSlhDsaPublicKey_ReturnsStandardEncoding() => SlhDsaPkcs11TestCases.Assert_ExportSlhDsaPublicKey_ReturnsStandardEncoding(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ExportSlhDsaPrivateKey_ThrowsInsecure() => SlhDsaPkcs11TestCases.Assert_ExportSlhDsaPrivateKey_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() => SlhDsaPkcs11TestCases.Assert_ExportPkcs8PrivateKey_ThrowsInsecure(_backend);
}
