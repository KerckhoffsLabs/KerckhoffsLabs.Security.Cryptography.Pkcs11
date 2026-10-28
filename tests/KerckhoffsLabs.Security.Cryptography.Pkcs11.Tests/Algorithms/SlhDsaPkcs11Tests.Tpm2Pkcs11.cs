using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SlhDsaPkcs11 over tpm2-pkcs11 — thin wrapper over <see cref="SlhDsaPkcs11TestCases"/>.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class SlhDsaPkcs11Tests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
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

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#564: C_GenerateKey is not implemented")]
    public void Ctor_NonSlhDsaKey_Throws() => SlhDsaPkcs11TestCases.Assert_Ctor_NonSlhDsaKey_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void SignVerifyData_WithContext_RoundTrips() => SlhDsaPkcs11TestCases.Assert_SignVerifyData_WithContext_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void SignData_ContextTooLong_Throws() => SlhDsaPkcs11TestCases.Assert_SignData_ContextTooLong_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ExportSlhDsaPublicKey_ReturnsStandardEncoding() => SlhDsaPkcs11TestCases.Assert_ExportSlhDsaPublicKey_ReturnsStandardEncoding(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ExportSlhDsaPrivateKey_ThrowsInsecure() => SlhDsaPkcs11TestCases.Assert_ExportSlhDsaPrivateKey_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() => SlhDsaPkcs11TestCases.Assert_ExportPkcs8PrivateKey_ThrowsInsecure(_backend);
}
