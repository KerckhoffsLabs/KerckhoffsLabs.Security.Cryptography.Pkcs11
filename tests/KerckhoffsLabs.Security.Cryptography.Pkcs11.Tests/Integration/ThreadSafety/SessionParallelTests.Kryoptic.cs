using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.ThreadSafety;

/// <summary>Cross-session concurrency over Kryoptic — thin wrapper over <see cref="SessionParallelTestCases"/>.</summary>
/// <remarks>Only the single-session case runs here: the multi-session ones need several sessions logged in at once, but <c>OpenSession</c> logs every session in, and on a login-required token login state is shared by all of an application's sessions (PKCS#11 v3.2 §5.6), so the second C_Login returns CKR_USER_ALREADY_LOGGED_IN.</remarks>
[Collection("Kryoptic")]
public sealed class SessionParallelTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public async Task Dispose_RacingInFlightCallsOnTheSameSession_NeverReachesAClosedSession() =>
        await SessionParallelTestCases.Assert_Dispose_RacingInFlightCallsOnTheSameSession_NeverReachesAClosedSession(_backend);
}
