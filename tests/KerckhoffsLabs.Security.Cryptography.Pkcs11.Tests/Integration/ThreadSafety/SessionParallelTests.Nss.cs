using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.ThreadSafety;

/// <summary>Cross-session concurrency over NSS softoken — thin wrapper over <see cref="SessionParallelTestCases"/>.</summary>
[Collection("Nss")]
public sealed class SessionParallelTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ParallelSessions_GenerateFindAndDestroyOwnKeys() =>
        SessionParallelTestCases.Assert_ParallelSessions_GenerateFindAndDestroyOwnKeys(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ClosingSessionsWithLiveObjects_WhileOtherSessionsSearch_LeavesNoObjectsBehind() =>
        SessionParallelTestCases.Assert_ClosingSessionsWithLiveObjects_WhileOtherSessionsSearch_LeavesNoObjectsBehind(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public async Task Dispose_RacingInFlightCallsOnTheSameSession_NeverReachesAClosedSession() =>
        await SessionParallelTestCases.Assert_Dispose_RacingInFlightCallsOnTheSameSession_NeverReachesAClosedSession(_backend);
}
