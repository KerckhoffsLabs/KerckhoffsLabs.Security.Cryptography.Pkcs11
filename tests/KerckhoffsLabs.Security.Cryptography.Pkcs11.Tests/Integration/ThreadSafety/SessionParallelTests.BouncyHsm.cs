using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.ThreadSafety;

/// <summary>Cross-session concurrency over BouncyHsm — thin wrapper over <see cref="SessionParallelTestCases"/>.</summary>
/// <remarks>Only the single-session case runs here: the multi-session ones need several sessions logged in at once, but <c>OpenSession</c> logs every session in, and on a login-required token login state is shared by all of an application's sessions (PKCS#11 v3.2 §5.6), so the second C_Login returns CKR_USER_ALREADY_LOGGED_IN. BouncyHsm counted logins per session until harrison314/BouncyHsm#121, so they ran here before.</remarks>
[Collection("BouncyHsm")]
public sealed class SessionParallelTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public async Task Dispose_RacingInFlightCallsOnTheSameSession_NeverReachesAClosedSession() =>
        await SessionParallelTestCases.Assert_Dispose_RacingInFlightCallsOnTheSameSession_NeverReachesAClosedSession(_backend);
}
