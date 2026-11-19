using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

/// <summary>ML-KEM, ML-DSA and SLH-DSA known answers from NIST ACVP, and ML-DSA verification from Wycheproof, over BouncyHsm — thin wrapper over <see cref="AcvpKnownAnswerTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class AcvpKnownAnswerTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.MlKemDecapsulationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void MlKem_Decapsulation_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_MlKem_Decapsulation_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.MlDsaPureVerificationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void MlDsa_PureVerification_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_MlDsa_PureVerification_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(WycheproofMlDsaTestCases.ParameterSets), MemberType = typeof(WycheproofMlDsaTestCases))]
    // BouncyHsm takes an ML-DSA public key one byte short or long, then answers C_Verify with CKR_GENERAL_ERROR. It
    // refuses to verify an empty message with CKR_DATA_LEN_RANGE (VerifyState, "Verify empty data"), though FIPS 204
    // signs one like any other, so the valid signatures over "" fail. A context over 255 bytes never reaches it. Reported as
    // harrison314/BouncyHsm#155 (key length) and harrison314/BouncyHsm#154 (empty message).
    public void MlDsa_Verification_Wycheproof(string parameterSet) =>
        WycheproofMlDsaTestCases.Assert_MlDsa_Verification_Wycheproof(_backend, parameterSet, v =>
            v.Flags.Contains("IncorrectPublicKeyLength") ? "BouncyHsm imports a public key of the wrong length; C_Verify then answers CKR_GENERAL_ERROR (harrison314/BouncyHsm#155)."
            : v.Message.Length == 0 && v.Context.Length <= 255 ? "BouncyHsm refuses to verify an empty message (CKR_DATA_LEN_RANGE) (harrison314/BouncyHsm#154)."
            : null);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.MlDsaPreHashVerificationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void MlDsa_PreHashVerification_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_MlDsa_PreHashVerification_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.MlDsaDeterministicSignatureCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void MlDsa_DeterministicSignature_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_MlDsa_DeterministicSignature_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.SlhDsaPureVerificationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void SlhDsa_PureVerification_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_SlhDsa_PureVerification_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.SlhDsaPreHashVerificationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void SlhDsa_PreHashVerification_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_SlhDsa_PreHashVerification_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.SlhDsaDeterministicSignatureCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void SlhDsa_DeterministicSignature_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_SlhDsa_DeterministicSignature_Acvp(_backend, parameterSet, tcId);
}
