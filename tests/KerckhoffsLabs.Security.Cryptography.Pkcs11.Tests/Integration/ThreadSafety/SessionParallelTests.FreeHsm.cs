using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.ThreadSafety;

/// <summary>Cross-session concurrency over FreeHSM — thin wrapper over <see cref="SessionParallelTestCases"/>.</summary>
/// <remarks>Only the single-session case runs here: the multi-session ones need several sessions logged in at once, but <c>OpenSession</c> logs every session in, and on a login-required token login state is shared by all of an application's sessions (PKCS#11 v3.2 §5.6), so the second C_Login returns CKR_USER_ALREADY_LOGGED_IN.</remarks>
[Collection("FreeHsm")]
public sealed class SessionParallelTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public async Task Dispose_RacingInFlightCallsOnTheSameSession_NeverReachesAClosedSession() =>
        await SessionParallelTestCases.Assert_Dispose_RacingInFlightCallsOnTheSameSession_NeverReachesAClosedSession(_backend);
}
