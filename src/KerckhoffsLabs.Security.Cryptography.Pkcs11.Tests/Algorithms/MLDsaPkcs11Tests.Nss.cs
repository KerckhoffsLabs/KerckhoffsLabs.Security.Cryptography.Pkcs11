using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// MLDsaPkcs11 over NSS — thin wrapper over <see cref="MLDsaPkcs11TestCases"/>.
/// </summary>
/// <remarks>
/// Every case here currently skips: NSS's softoken doesn't advertise <c>CKM_ML_DSA</c> at runtime.
/// <c>lib/softoken/pkcs11.c</c> gates the mechanism-table entries behind <c>#ifdef NSS_ENABLE_ML_DSA</c>
/// (comment: "don't advertize ML_DSA support until we have it working in freebl"), and that define isn't
/// wired to any build.sh/gyp flag in this NSS release. Even forcing it wouldn't help — every function in
/// <c>lib/freebl/ml_dsa.c</c> (SignInit/Update/Final, VerifyInit/Update/Final, NewKey) is a placeholder
/// that unconditionally returns <c>SECFailure</c>. This is a real, currently-unimplemented gap in NSS
/// itself, not a bug here; the tests will start passing once a future NSS release ships a working
/// freebl ML-DSA implementation with the mechanism enabled by default.
/// </remarks>
[Collection("Nss")]
public sealed class MLDsaPkcs11Tests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;
    public static bool Available => NssBackendFixture.NssAvailable;

    [ConditionalTheory(nameof(Available))]
    [InlineData(CkpMlDsa.CKP_ML_DSA_44)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_65)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_87)]
    public void SignVerifyData_RoundTrips(CkpMlDsa parameterSet) => MLDsaPkcs11TestCases.Assert_SignVerifyData_RoundTrips(_backend, parameterSet);

    [ConditionalTheory(nameof(Available))]
    [InlineData(CkpMlDsa.CKP_ML_DSA_44)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_65)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_87)]
    public void SignData_VerifiesWithBcl(CkpMlDsa parameterSet) => MLDsaPkcs11TestCases.Assert_SignData_VerifiesWithBcl(_backend, parameterSet);

    [ConditionalFact(nameof(Available))]
    public void Ctor_NonMlDsaKey_Throws() => MLDsaPkcs11TestCases.Assert_Ctor_NonMlDsaKey_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void SignVerifyData_WithContext_RoundTrips() => MLDsaPkcs11TestCases.Assert_SignVerifyData_WithContext_RoundTrips(_backend);

    [ConditionalFact(nameof(Available))]
    public void SignData_ContextTooLong_Throws() => MLDsaPkcs11TestCases.Assert_SignData_ContextTooLong_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void SignMu_Throws() => MLDsaPkcs11TestCases.Assert_SignMu_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void VerifyMu_Throws() => MLDsaPkcs11TestCases.Assert_VerifyMu_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void ExportMLDsaPublicKey_ReturnsStandardEncoding() => MLDsaPkcs11TestCases.Assert_ExportMLDsaPublicKey_ReturnsStandardEncoding(_backend);

    [ConditionalFact(nameof(Available))]
    public void ExportMLDsaPrivateKey_ThrowsInsecure() => MLDsaPkcs11TestCases.Assert_ExportMLDsaPrivateKey_ThrowsInsecure(_backend);

    [ConditionalFact(nameof(Available))]
    public void ExportMLDsaPrivateSeed_ThrowsInsecure() => MLDsaPkcs11TestCases.Assert_ExportMLDsaPrivateSeed_ThrowsInsecure(_backend);

    [ConditionalFact(nameof(Available))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() => MLDsaPkcs11TestCases.Assert_ExportPkcs8PrivateKey_ThrowsInsecure(_backend);
}
