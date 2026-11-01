using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

/// <summary>ML-KEM, ML-DSA and SLH-DSA known answers from NIST ACVP over Nss — thin wrapper over <see cref="AcvpKnownAnswerTestCases"/>.</summary>
[Collection("Nss")]
public sealed class AcvpKnownAnswerTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(NssBackendFixture.ClassicAesGcmAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ClassicAesGcmAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.MlKemDecapsulationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void MlKem_Decapsulation_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_MlKem_Decapsulation_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(NssBackendFixture.ClassicAesGcmAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ClassicAesGcmAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.MlDsaPureVerificationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void MlDsa_PureVerification_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_MlDsa_PureVerification_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(NssBackendFixture.ClassicAesGcmAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ClassicAesGcmAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.MlDsaPreHashVerificationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void MlDsa_PreHashVerification_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_MlDsa_PreHashVerification_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(NssBackendFixture.ClassicAesGcmAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ClassicAesGcmAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.MlDsaDeterministicSignatureCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void MlDsa_DeterministicSignature_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_MlDsa_DeterministicSignature_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(NssBackendFixture.ClassicAesGcmAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ClassicAesGcmAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.SlhDsaPureVerificationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void SlhDsa_PureVerification_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_SlhDsa_PureVerification_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(NssBackendFixture.ClassicAesGcmAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ClassicAesGcmAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.SlhDsaPreHashVerificationCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void SlhDsa_PreHashVerification_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_SlhDsa_PreHashVerification_Acvp(_backend, parameterSet, tcId);

    [Theory(SkipUnless = nameof(NssBackendFixture.ClassicAesGcmAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ClassicAesGcmAvailable))]
    [MemberData(nameof(AcvpKnownAnswerTestCases.SlhDsaDeterministicSignatureCases), MemberType = typeof(AcvpKnownAnswerTestCases))]
    public void SlhDsa_DeterministicSignature_Acvp(string parameterSet, int tcId) => AcvpKnownAnswerTestCases.Assert_SlhDsa_DeterministicSignature_Acvp(_backend, parameterSet, tcId);
}
