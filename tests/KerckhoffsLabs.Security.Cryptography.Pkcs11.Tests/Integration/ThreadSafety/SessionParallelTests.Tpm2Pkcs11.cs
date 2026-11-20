using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.ThreadSafety;

/// <summary>Cross-session concurrency over tpm2-pkcs11 — thin wrapper over <see cref="SessionParallelTestCases"/>.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class SessionParallelTests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#564: C_GenerateKey is not implemented")]
    public void ParallelSessions_GenerateFindAndDestroyOwnKeys() =>
        SessionParallelTestCases.Assert_ParallelSessions_GenerateFindAndDestroyOwnKeys(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#564: C_GenerateKey is not implemented")]
    public void ClosingSessionsWithLiveObjects_WhileOtherSessionsSearch_LeavesNoObjectsBehind() =>
        SessionParallelTestCases.Assert_ClosingSessionsWithLiveObjects_WhileOtherSessionsSearch_LeavesNoObjectsBehind(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#564: C_GenerateKey is not implemented")]
    public async Task Dispose_RacingInFlightCallsOnTheSameSession_NeverReachesAClosedSession() =>
        await SessionParallelTestCases.Assert_Dispose_RacingInFlightCallsOnTheSameSession_NeverReachesAClosedSession(_backend);
}
