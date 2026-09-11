using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>MLDsaPkcs11 over Kryoptic — thin wrapper over <see cref="MLDsaPkcs11TestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class MLDsaPkcs11Tests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;
    public static bool KryopticAvailable => KryopticBackendFixture.KryopticAvailable;

    [ConditionalTheory(nameof(KryopticAvailable))]
    [InlineData(CkpMlDsa.CKP_ML_DSA_44)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_65)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_87)]
    public void SignVerifyData_RoundTrips(CkpMlDsa parameterSet) => MLDsaPkcs11TestCases.Assert_SignVerifyData_RoundTrips(_backend, parameterSet);

    [ConditionalTheory(nameof(KryopticAvailable))]
    [InlineData(CkpMlDsa.CKP_ML_DSA_44)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_65)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_87)]
    public void SignData_VerifiesWithBcl(CkpMlDsa parameterSet) => MLDsaPkcs11TestCases.Assert_SignData_VerifiesWithBcl(_backend, parameterSet);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Ctor_NonMlDsaKey_Throws() => MLDsaPkcs11TestCases.Assert_Ctor_NonMlDsaKey_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void SignVerifyData_WithContext_RoundTrips() => MLDsaPkcs11TestCases.Assert_SignVerifyData_WithContext_RoundTrips(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void SignData_ContextTooLong_Throws() => MLDsaPkcs11TestCases.Assert_SignData_ContextTooLong_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void SignMu_Throws() => MLDsaPkcs11TestCases.Assert_SignMu_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void VerifyMu_Throws() => MLDsaPkcs11TestCases.Assert_VerifyMu_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ExportMLDsaPublicKey_ReturnsStandardEncoding() => MLDsaPkcs11TestCases.Assert_ExportMLDsaPublicKey_ReturnsStandardEncoding(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ExportMLDsaPrivateKey_ThrowsInsecure() => MLDsaPkcs11TestCases.Assert_ExportMLDsaPrivateKey_ThrowsInsecure(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ExportMLDsaPrivateSeed_ThrowsInsecure() => MLDsaPkcs11TestCases.Assert_ExportMLDsaPrivateSeed_ThrowsInsecure(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() => MLDsaPkcs11TestCases.Assert_ExportPkcs8PrivateKey_ThrowsInsecure(_backend);
}
