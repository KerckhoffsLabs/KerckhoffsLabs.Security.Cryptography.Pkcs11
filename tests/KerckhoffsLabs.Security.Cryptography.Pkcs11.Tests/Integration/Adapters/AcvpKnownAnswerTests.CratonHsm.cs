using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

/// <summary>ML-KEM and ML-DSA known answers from NIST ACVP over CratonHsm — thin wrapper over <see cref="AcvpKnownAnswerTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class AcvpKnownAnswerTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    public static bool CratonHsmAvailable => CratonHsmBackendFixture.CratonHsmAvailable;

    // Craton HSM imports an ML-DSA or SLH-DSA key but cannot use it: C_Sign with an imported private key answers
    // CKR_KEY_TYPE_INCONSISTENT, and C_Verify with an imported public key CKR_KEY_HANDLE_INVALID (seen in CI), as its
    // imported Ed448 keys do. Its imported ML-KEM keys work, so the ML-KEM cases run.
    public static bool CratonHsmUsesImportedPqcSignatureKeys => false;

    [Theory(SkipUnless = nameof(CratonHsmAvailable), Skip = "Requires " + nameof(CratonHsmAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.MlKemDecapsulationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void MlKem_Decapsulation_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_MlKem_Decapsulation_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(CratonHsmUsesImportedPqcSignatureKeys), Skip = "Requires " + nameof(CratonHsmUsesImportedPqcSignatureKeys))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.MlDsaPureVerificationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void MlDsa_PureVerification_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_MlDsa_PureVerification_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(CratonHsmUsesImportedPqcSignatureKeys), Skip = "Requires " + nameof(CratonHsmUsesImportedPqcSignatureKeys))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.MlDsaPreHashVerificationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void MlDsa_PreHashVerification_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_MlDsa_PreHashVerification_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(CratonHsmUsesImportedPqcSignatureKeys), Skip = "Requires " + nameof(CratonHsmUsesImportedPqcSignatureKeys))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.MlDsaDeterministicSignatureCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void MlDsa_DeterministicSignature_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_MlDsa_DeterministicSignature_Acvp(_backend, parameterSet, tcId);
}
