using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SlhDsaPkcs11 over Kryoptic — thin wrapper over <see cref="SlhDsaPkcs11TestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class SlhDsaPkcs11Tests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;
    public static bool KryopticAvailable => KryopticBackendFixture.KryopticAvailable;

    [ConditionalTheory(nameof(KryopticAvailable))]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_128S)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_192F)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHAKE_256S)]
    public void SignVerifyData_RoundTrips(CkpSlhDsa parameterSet) => SlhDsaPkcs11TestCases.Assert_SignVerifyData_RoundTrips(_backend, parameterSet);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Ctor_NonSlhDsaKey_Throws() => SlhDsaPkcs11TestCases.Assert_Ctor_NonSlhDsaKey_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void SignVerifyData_WithContext_RoundTrips() => SlhDsaPkcs11TestCases.Assert_SignVerifyData_WithContext_RoundTrips(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void SignData_ContextTooLong_Throws() => SlhDsaPkcs11TestCases.Assert_SignData_ContextTooLong_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ExportSlhDsaPublicKey_ReturnsStandardEncoding() => SlhDsaPkcs11TestCases.Assert_ExportSlhDsaPublicKey_ReturnsStandardEncoding(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ExportSlhDsaPrivateKey_ThrowsInsecure() => SlhDsaPkcs11TestCases.Assert_ExportSlhDsaPrivateKey_ThrowsInsecure(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() => SlhDsaPkcs11TestCases.Assert_ExportPkcs8PrivateKey_ThrowsInsecure(_backend);
}
