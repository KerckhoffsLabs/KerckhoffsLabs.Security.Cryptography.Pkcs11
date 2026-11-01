using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

/// <summary>ML-KEM, ML-DSA and SLH-DSA known answers from NIST ACVP over Kryoptic — thin wrapper over <see cref="AcvpKnownAnswerTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class AcvpKnownAnswerTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    public static bool KryopticAvailable => KryopticBackendFixture.KryopticAvailable;

    [Theory(SkipUnless = nameof(KryopticAvailable), Skip = "Requires " + nameof(KryopticAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.MlKemDecapsulationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void MlKem_Decapsulation_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_MlKem_Decapsulation_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(KryopticAvailable), Skip = "Requires " + nameof(KryopticAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.MlDsaPureVerificationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void MlDsa_PureVerification_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_MlDsa_PureVerification_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(KryopticAvailable), Skip = "Requires " + nameof(KryopticAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.MlDsaPreHashVerificationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void MlDsa_PreHashVerification_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_MlDsa_PreHashVerification_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(KryopticAvailable), Skip = "Requires " + nameof(KryopticAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.MlDsaDeterministicSignatureCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void MlDsa_DeterministicSignature_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_MlDsa_DeterministicSignature_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(KryopticAvailable), Skip = "Requires " + nameof(KryopticAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.SlhDsaPureVerificationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void SlhDsa_PureVerification_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_SlhDsa_PureVerification_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(KryopticAvailable), Skip = "Requires " + nameof(KryopticAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.SlhDsaPreHashVerificationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void SlhDsa_PreHashVerification_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_SlhDsa_PreHashVerification_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(KryopticAvailable), Skip = "Requires " + nameof(KryopticAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.SlhDsaDeterministicSignatureCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void SlhDsa_DeterministicSignature_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_SlhDsa_DeterministicSignature_Acvp(_backend, parameterSet, tcId);
}
