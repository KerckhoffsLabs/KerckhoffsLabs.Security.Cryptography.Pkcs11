using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.ThreadSafety;

/// <summary>Cross-session concurrency over wolfPKCS11 — thin wrapper over <see cref="SessionParallelTestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class SessionParallelTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ParallelSessions_GenerateFindAndDestroyOwnKeys() =>
        SessionParallelTestCases.Assert_ParallelSessions_GenerateFindAndDestroyOwnKeys(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ClosingSessionsWithLiveObjects_WhileOtherSessionsSearch_LeavesNoObjectsBehind() =>
        SessionParallelTestCases.Assert_ClosingSessionsWithLiveObjects_WhileOtherSessionsSearch_LeavesNoObjectsBehind(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public async Task Dispose_RacingInFlightCallsOnTheSameSession_NeverReachesAClosedSession() =>
        await SessionParallelTestCases.Assert_Dispose_RacingInFlightCallsOnTheSameSession_NeverReachesAClosedSession(_backend);
}
